import datetime as dt
import itertools

from velodrome.lock8.dynamodb import attributes, key_schema, try_delete_tables
from velodrome.lock8.metrics import (
    METRICS, DropzoneMetric, OrganizationMetric, Resolution, UserMetric,
    ZoneMetric,
)


def table_for_metric(metric_name: str, resolution: Resolution,
                     schema: dict) -> dict:
    return {
        "TableName": METRICS[metric_name]._get_full_table_name(resolution),
        **PROVISIONED_THROUGHPUT,
        **schema
    }


PROVISIONED_THROUGHPUT = {
    "ProvisionedThroughput": {
        "ReadCapacityUnits": 5,
        "WriteCapacityUnits": 5
    }
}

ORGANIZATION_DATE_SECONDARY_INDEX = {
    "IndexName": "organization-date-index",
    **key_schema(hash="organization", range="date"),
    "Projection": {"ProjectionType": "ALL"},
    **PROVISIONED_THROUGHPUT
}

USER_DATE_SECONDARY_INDEX = {
    "IndexName": "user-date-index",
    **key_schema(hash="user", range="date"),
    "Projection": {"ProjectionType": "ALL"},
    **PROVISIONED_THROUGHPUT
}

ORGANIZATION_DATE_SECONDARY_INDICES = {
    "GlobalSecondaryIndexes": [
        ORGANIZATION_DATE_SECONDARY_INDEX
    ]
}
USER_DATE_SECONDARY_INDICES = {
    "GlobalSecondaryIndexes": [
        ORGANIZATION_DATE_SECONDARY_INDEX,
        USER_DATE_SECONDARY_INDEX
    ]
}

ORGANIZATION_TABLES = [
    table_for_metric(metric_name + version, time, {
        **attributes(date="N", organization="S"),
        **key_schema(hash="organization", range="date"),
    })
    for (metric_name, version, time) in itertools.product(
        ['distance', 'trips', 'time'], ('', '-v2'),
        Resolution.above_minute())
]

USERS_DISTANCE_TABLES = [
    table_for_metric('users-distance' + version, time, {
        **attributes(date="N", organization="S", user="S",
                     user_organization="S"),
        **key_schema(hash="user_organization", range="date"),
        **USER_DATE_SECONDARY_INDICES
    })
    for (version, time) in itertools.product(
        ('', '-v2'),
        Resolution.above_hour())
]

ZONES_BICYCLES_TABLES = [
    table_for_metric('zones-bicycles', time, {
        **attributes(date="N", zone="S", organization="S"),
        **key_schema(hash="zone", range="date"),
        **ORGANIZATION_DATE_SECONDARY_INDICES,
    })
    for time in Resolution.above_minute()
]

BICYCLES_TABLES = [
    table_for_metric(metric_name + version, time, {
        **attributes(bicycle="S", date="N", organization="S"),
        **key_schema(hash="bicycle", range="date"),
        **ORGANIZATION_DATE_SECONDARY_INDICES,
    })
    for (metric_name, version, time) in itertools.product(
        ['bicycles-distance', 'bicycles-trips', 'bicycles-time'],
        ('', '-v2'),
        Resolution.above_hour())
]

DROPZONE_TRAFFIC_TABLES = [
    table_for_metric('dropzone-metrics-v2', time, {
        **attributes(zone="S", date="N", organization="S"),
        **key_schema(hash="zone", range="date"),
        **ORGANIZATION_DATE_SECONDARY_INDICES
    })
    for time in Resolution.below_year()
]

DDB_TABLES = (
    ORGANIZATION_TABLES +
    USERS_DISTANCE_TABLES +
    BICYCLES_TABLES +
    ZONES_BICYCLES_TABLES +
    DROPZONE_TRAFFIC_TABLES
)


def get_ddbtable_meta(metric, resolution: Resolution) -> dict:
    table_name = metric._get_full_table_name(resolution)
    table_meta = [t for t in DDB_TABLES if t['TableName'] == table_name]
    assert len(table_meta) == 1
    return table_meta[0]


def create_ddb_tables(metric, resolution: Resolution = None) -> list:
    """(Re-)create DynamoDB table(s).

    For a given metric all the tables for its resolutions will be created.
    Any existing table will be tried to get deleted before.  This might fail
    in case of insufficient permissions.
    """
    from velodrome.lock8.dynamodb import dynamodb

    # Handle list of resolutions recursively (None => all).
    if resolution is None:
        return [create_ddb_tables(metric, resolution)[0]
                for resolution in (
                    metric.resolutions if resolution is None else resolution
               )]

    table_meta = get_ddbtable_meta(metric, resolution)
    table = metric._get_table(resolution)
    try_delete_tables([table])
    dynamodb.create_table(**dict(table_meta, TableName=table.name))
    return [table]


def dt_to_ddb(dt, resolution: Resolution) -> int:
    """Convert a datetime to an int for DynamoDB."""
    return int(resolution.strftime(dt))


def ddb_put_item(metric, item: dict, date: dt.datetime, resolutions=None,
                 action_update=False):
    """Put an item into DynamoDB for every resolution."""
    value_name = metric.value_name
    value = item[value_name]
    if resolutions is None:
        resolutions = metric.resolutions

    expression_attribute_values = {
        ':n': value
    }
    expression_attribute_names_args = {}
    key = item.copy()
    organization = key['organization']
    del key[value_name]

    if isinstance(metric, OrganizationMetric):
        if action_update:
            update_expression = 'ADD {} :n'.format(value_name)
        else:
            update_expression = 'SET {} = :n'.format(value_name)
    else:
        if action_update:
            update_expression = 'ADD {} :n SET organization = :o'.format(
                value_name)
        else:
            update_expression = 'SET {} = :n, organization = :o'.format(
                value_name)
        expression_attribute_values[':o'] = key.pop('organization')

        if isinstance(metric, UserMetric):
            user = key.pop('user')
            key['user_organization'] = f'{user}_{organization}'
            update_expression += ', #user = :u'
            expression_attribute_values[':u'] = user
            expression_attribute_names_args['ExpressionAttributeNames'] = {
                '#user': 'user'}

        if isinstance(metric, ZoneMetric):
            zone_type = key.pop('zone_type', None)
            if zone_type:
                update_expression += ', zone_type = :zt'
                expression_attribute_values[':zt'] = zone_type

        if isinstance(metric, DropzoneMetric):
            update_expression += ', min_bicycles = :mib, max_bicycles = :mab'
            expression_attribute_values[':mib'] = key.pop('min_bicycles')
            expression_attribute_values[':mab'] = key.pop('max_bicycles')

    for resolution in resolutions:
        key['date'] = dt_to_ddb(date, resolution)
        metric._get_table(resolution).update_item(
            Key=key,
            UpdateExpression=update_expression,
            ExpressionAttributeValues=expression_attribute_values,
            **expression_attribute_names_args)


def ddb_update_item(*args, **kwargs):
    kwargs['action_update'] = True
    return ddb_put_item(*args, **kwargs)


def get_iso8601_strftime_for_resolution(resolution: Resolution):
    resolution_to_strftime = {
        Resolution.MINUTE: '%Y-%m-%dT%H:00%M:00',
        Resolution.HOUR: '%Y-%m-%dT%H:00',
        Resolution.DAY: '%Y-%m-%d',
        Resolution.MONTH: '%Y-%m',
        Resolution.YEAR: '%Y',
    }
    return resolution_to_strftime[resolution]


def rename_key(key):
    return 'value' if key in ['distance', 'seconds', 'trips'] else key
