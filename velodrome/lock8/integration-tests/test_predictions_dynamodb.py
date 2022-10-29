import datetime as dt

from velodrome.lock8.dynamodb import attributes, key_schema
from velodrome.lock8.predictions import PREDICTIONS

DEFAULT_PROVISIONED_THROUGHPUT = {
    'ProvisionedThroughput': {
        'ReadCapacityUnits': 5,
        'WriteCapacityUnits': 5
    }
}

SCHEMA = {
    'TableName': 'dropzone-predictions-absolute',
    **attributes(
        dropzone_uuid='S',
        pred_made_at='S',
        organization_uuid='S'),
    **key_schema(hash='dropzone_uuid', range='pred_made_at'),
    'GlobalSecondaryIndexes': [{
        'IndexName': 'organization_uuid-pred_made_at-index',
        **key_schema(hash='organization_uuid', range='pred_made_at'),
        'Projection': {'ProjectionType': 'ALL'},
        **DEFAULT_PROVISIONED_THROUGHPUT
    }],
    **DEFAULT_PROVISIONED_THROUGHPUT
}

DELTA_10_MINUTES = dt.timedelta(minutes=10)


def test_get_latest_predictions_for_org(ddb_table_from_schema, org, at_2000,
                                        zone):
    table = ddb_table_from_schema(SCHEMA)
    prediction = PREDICTIONS['bicycles-in-dropzones']
    now = dt.datetime.now().replace(microsecond=0, tzinfo=None)

    assert prediction.get_values(org) == {'values': []}

    table.put_item(Item={
        'organization_uuid': str(org.uuid),
        'dropzone_uuid': str(zone.uuid),
        'pred_made_at': prediction._format_datetime(now),
        'median': [1, 2, 3],
        'q25': [4, 5, 6],
        'q75': [7, 8, 9],
        'pred_frequency': DELTA_10_MINUTES.seconds})

    assert prediction.get_values(org) == {'values': [{
        'zone': str(zone.uuid),
        'predictions': [
            {'date': now + DELTA_10_MINUTES,
             'median': 1.0, 'q25': 4.0, 'q75': 7.0},
            {'date': now + DELTA_10_MINUTES * 2,
             'median': 2.0, 'q25': 5.0, 'q75': 8.0},
            {'date': now + DELTA_10_MINUTES * 3,
             'median': 3.0, 'q25': 6.0, 'q75': 9.0},
        ]}
    ]}


def test_get_latest_predictions_for_zone(ddb_table_from_schema, org, at_2000,
                                         zone, zone_somewhere):
    table = ddb_table_from_schema(SCHEMA)
    prediction = PREDICTIONS['bicycles-in-dropzones']
    now = dt.datetime.now().replace(microsecond=0, tzinfo=None)

    table.put_item(Item={
        'organization_uuid': str(org.uuid),
        'dropzone_uuid': str(zone.uuid),
        'pred_made_at': prediction._format_datetime(now),
        'median': [11, 12],
        'q25': [13, 14],
        'q75': [15, 16],
        'pred_frequency': DELTA_10_MINUTES.seconds})

    assert prediction.get_values(org, zone) == {'values': [{
        'zone': str(zone.uuid),
        'predictions': [
            {'date': now + DELTA_10_MINUTES,
             'median': 11.0, 'q25': 13.0, 'q75': 15.0},
            {'date': now + DELTA_10_MINUTES * 2,
             'median': 12.0, 'q25': 14.0, 'q75': 16.0},
        ]}
    ]}

    assert prediction.get_values(org, zone_somewhere) == {'values': []}

    table.put_item(Item={
        'organization_uuid': str(org.uuid),
        'dropzone_uuid': str(zone_somewhere.uuid),
        'pred_made_at': prediction._format_datetime(now),
        'median': [21, 22],
        'q25': [23, 24],
        'q75': [25, 26],
        'pred_frequency': DELTA_10_MINUTES.seconds})

    assert prediction.get_values(org, zone_somewhere) == {'values': [{
        'zone': str(zone_somewhere.uuid),
        'predictions': [
            {'date': now + DELTA_10_MINUTES,
             'median': 21.0, 'q25': 23.0, 'q75': 25.0},
            {'date': now + DELTA_10_MINUTES * 2,
             'median': 22.0, 'q25': 24.0, 'q75': 26.0},
        ]}
    ]}

    def zone_key(item):
        return item['zone']

    assert sorted(prediction.get_values(org)['values'], key=zone_key) == \
        sorted([{'zone': str(zone.uuid),
                 'predictions': [
                    {'date': now + DELTA_10_MINUTES,
                     'median': 11.0, 'q25': 13.0, 'q75': 15.0},
                    {'date': now + DELTA_10_MINUTES * 2,
                     'median': 12.0, 'q25': 14.0, 'q75': 16.0}]},
                {'zone': str(zone_somewhere.uuid),
                 'predictions': [
                    {'date': now + DELTA_10_MINUTES,
                     'median': 21.0, 'q25': 23.0, 'q75': 25.0},
                    {'date': now + DELTA_10_MINUTES * 2,
                     'median': 22.0, 'q25': 24.0, 'q75': 26.0}]}],
               key=zone_key)


def test_get_predictions_for_org_at_date(ddb_table_from_schema, org, zone):
    table = ddb_table_from_schema(SCHEMA)
    prediction = PREDICTIONS['bicycles-in-dropzones']
    at_2017_9_1_10_00 = dt.datetime(2017, 9, 1, 10, 0)
    at_2017_9_1_11_00 = dt.datetime(2017, 9, 1, 11, 0)

    table.put_item(Item={
        'organization_uuid': str(org.uuid),
        'dropzone_uuid': str(zone.uuid),
        'pred_made_at': prediction._format_datetime(at_2017_9_1_10_00),
        'median': [1, 2],
        'q25': [3, 4],
        'q75': [5, 6],
        'pred_frequency': DELTA_10_MINUTES.seconds})

    table.put_item(Item={
        'organization_uuid': str(org.uuid),
        'dropzone_uuid': str(zone.uuid),
        'pred_made_at': prediction._format_datetime(at_2017_9_1_11_00),
        'median': [7],
        'q25': [8],
        'q75': [9],
        'pred_frequency': DELTA_10_MINUTES.seconds})

    assert prediction.get_values(org, made_at=at_2017_9_1_10_00) == \
        {'values': [{
            'zone': str(zone.uuid),
            'predictions': [
                {'date': at_2017_9_1_10_00 + DELTA_10_MINUTES,
                 'median': 1.0, 'q25': 3.0, 'q75': 5.0},
                {'date': at_2017_9_1_10_00 + DELTA_10_MINUTES * 2,
                 'median': 2.0, 'q25': 4.0, 'q75': 6.0}
            ]}
        ]}

    assert prediction.get_values(org, made_at=at_2017_9_1_11_00) == \
        {'values': [{
            'zone': str(zone.uuid),
            'predictions': [
                {'date': at_2017_9_1_11_00 + DELTA_10_MINUTES,
                 'median': 7.0, 'q25': 8.0, 'q75': 9.0}
            ]}
        ]}


def test_get_partial_predictions_for_org(ddb_table_from_schema, org, zone,
                                         at_2000):
    table = ddb_table_from_schema(SCHEMA)
    prediction = PREDICTIONS['bicycles-in-dropzones']
    now = dt.datetime.now().replace(microsecond=0, tzinfo=None)

    table.put_item(Item={
        'organization_uuid': str(org.uuid),
        'dropzone_uuid': str(zone.uuid),
        'pred_made_at': prediction._format_datetime(now),
        'median': [10 + i for i in range(0, 144)],
        'q25': [20 + i for i in range(0, 144)],
        'q75': [30 + i for i in range(0, 144)],
        'pred_frequency': DELTA_10_MINUTES.seconds})

    assert prediction.get_values(org) == {'values': [{
        'zone': str(zone.uuid),
        'predictions': [
            {'date': now + DELTA_10_MINUTES * (i + 1),
             'median': 10.0 + i, 'q25': 20.0 + i, 'q75': 30.0 + i}
            for i in range(0, 144)
        ]}
    ]}

    assert prediction.get_values(org, period=10) == {'values': [{
        'zone': str(zone.uuid),
        'predictions': [
            {'date': now + DELTA_10_MINUTES * (i + 1),
             'median': 10.0 + i, 'q25': 20.0 + i, 'q75': 30.0 + i}
            for i in range(0, 60)
        ]}
    ]}


def test_get_predictions_with_different_deltas(ddb_table_from_schema, org,
                                               zone, zone_somewhere, at_2000):
    table = ddb_table_from_schema(SCHEMA)
    prediction = PREDICTIONS['bicycles-in-dropzones']
    now = dt.datetime.now().replace(microsecond=0, tzinfo=None)

    delta_20_minutes = dt.timedelta(minutes=20)

    table.put_item(Item={
        'organization_uuid': str(org.uuid),
        'dropzone_uuid': str(zone.uuid),
        'pred_made_at': prediction._format_datetime(now),
        'median': [10 + i for i in range(0, 72)],
        'q25': [20 + i for i in range(0, 72)],
        'q75': [30 + i for i in range(0, 72)],
        'pred_frequency': delta_20_minutes.seconds})

    assert prediction.get_values(org, zone=zone) == {'values': [{
        'zone': str(zone.uuid),
        'predictions': [
            {'date': now + delta_20_minutes * (i + 1),
             'median': 10.0 + i, 'q25': 20.0 + i, 'q75': 30.0 + i}
            for i in range(0, 72)
        ]}
    ]}

    delta_30_minutes = dt.timedelta(minutes=20)

    table.put_item(Item={
        'organization_uuid': str(org.uuid),
        'dropzone_uuid': str(zone_somewhere.uuid),
        'pred_made_at': prediction._format_datetime(now),
        'median': [10 + i for i in range(0, 48)],
        'q25': [20 + i for i in range(0, 48)],
        'q75': [30 + i for i in range(0, 48)],
        'pred_frequency': delta_30_minutes.seconds})

    assert prediction.get_values(org, zone=zone_somewhere) == {'values': [{
        'zone': str(zone_somewhere.uuid),
        'predictions': [
            {'date': now + delta_20_minutes * (i + 1),
             'median': 10.0 + i, 'q25': 20.0 + i, 'q75': 30.0 + i}
            for i in range(0, 48)
        ]}
    ]}
