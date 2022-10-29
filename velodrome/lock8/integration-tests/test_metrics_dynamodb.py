"""Tests against a real DynamoDB, if `--dynamodb-test-url` is provided."""

import datetime as dt
from decimal import Decimal

from velodrome.lock8.tests.utils import sorted_dicts


def test_all_ddb_tables_defined():
    from velodrome.lock8.metrics import METRICS
    from velodrome.lock8.metrics.test_utils import DDB_TABLES

    ddb_tablenames = [t['TableName'] for t in DDB_TABLES]
    metrics_tablenames = sorted(set(
        metric._get_full_table_name(resolution)
        for metric in METRICS.values()
        for resolution in metric.resolutions))
    assert sorted(ddb_tablenames) == metrics_tablenames


EMPTY_RESPONSE_DATA = {'current': 0, 'total': 0, 'values': []}


def test_get_metrics_day(ddb_table_for_metric, org, dt2016):
    from velodrome.lock8.metrics import METRICS, Resolution
    from velodrome.lock8.metrics.test_utils import ddb_update_item

    metric = METRICS['distance']
    ddb_table_for_metric(metric)

    args = [org, Resolution.DAY, dt2016, dt2016]
    assert metric.get_values(*args) == EMPTY_RESPONSE_DATA

    ddb_update_item(metric, date=dt2016, item={
        'organization': str(org.uuid),
        'distance': 5000,
    })
    yesterday = dt2016 - dt.timedelta(hours=25)
    ddb_update_item(metric, date=yesterday, item={
        'organization': str(org.uuid),
        'distance': 2346,
    })
    assert metric.get_values(*args) == {
        'current': 5.0,
        'total': 7.35,
        'values': [
            {'date': dt2016.strftime('%Y-%m-%d'), 'value': 5.0}]}

    args[2] = yesterday
    assert metric.get_values(*args) == {
        'current': 5.0,
        'total': 7.35,
        'values': [
            {'date': yesterday.strftime('%Y-%m-%d'), 'value': 2.35},
            {'date': dt2016.strftime('%Y-%m-%d'), 'value': 5.0}]}


def test_get_metrics_year(ddb_table_for_metric, org, today):
    from velodrome.lock8.metrics import METRICS, Resolution
    from velodrome.lock8.metrics.test_utils import ddb_update_item

    metric = METRICS['distance']
    ddb_table_for_metric(metric)

    start = dt.date(today.year, 1, 1)
    end = dt.date(today.year, 12, 31)
    args = [org, Resolution.DAY, start, end]
    assert metric.get_values(*args) == EMPTY_RESPONSE_DATA

    ddb_update_item(metric, date=today, item={
        'organization': str(org.uuid),
        'distance': Decimal(5000),
    })
    assert metric.get_values(*args) == {'current': 5.0, 'total': 5.0,
                                        'values': [{
                                            'date': today.strftime('%Y-%m-%d'),
                                            'value': 5.0}]}


def test_get_metrics_hour(ddb_table_for_metric, org, today):
    from velodrome.lock8.metrics import METRICS, Resolution
    from velodrome.lock8.metrics.test_utils import ddb_update_item

    metric = METRICS['distance']
    ddb_table_for_metric(metric)

    start = end = today
    args = [org, Resolution.HOUR, start, end]
    assert metric.get_values(*args) == EMPTY_RESPONSE_DATA

    ddb_update_item(metric, date=today, item={
        'organization': str(org.uuid),
        'distance': Decimal(42000),
    })
    assert metric.get_values(*args) == {
        'current': 42.0, 'total': 42.0,
        'values': [{
            'date': today.strftime('%Y-%m-%dT%H:00'),
            'value': 42.0}]}


def test_get_metrics_multiple(ddb_table_for_metric, org, dt2016):
    from velodrome.lock8.metrics import METRICS, Resolution
    from velodrome.lock8.metrics.test_utils import ddb_update_item

    metric = METRICS['distance']
    ddb_table_for_metric(metric)

    start = dt2016.replace(hour=0)
    end = dt2016.replace(hour=2)
    args = [org, Resolution.HOUR, start, end]

    ddb_update_item(metric, date=dt2016.replace(hour=1), item={
        'organization': str(org.uuid),
        'distance': Decimal(42000),
    })
    ddb_update_item(metric, date=dt2016.replace(hour=2), item={
        'organization': str(org.uuid),
        'distance': Decimal(23000),
    })
    expected = {'current': Decimal(65),
                'total': Decimal('65'),
                'values': [{
                    'date': dt2016.strftime('%Y-%m-%dT01:00'),
                    'value': Decimal('42')
                }, {
                    'date': dt2016.strftime('%Y-%m-%dT02:00'),
                    'value': Decimal('23')}]}
    assert metric.get_values(*args) == expected

    ddb_update_item(metric, date=dt2016 - dt.timedelta(hours=25), item={
        'organization': str(org.uuid),
        'distance': Decimal(17000),
    })
    response = metric.get_values(*args)
    assert response['values'] == expected['values']
    assert response['current'] == expected['current']
    assert response['total'] == 82.0

    ddb_update_item(metric, date=dt2016 - dt.timedelta(hours=24), item={
        'organization': str(org.uuid),
        'distance': Decimal(11000),
    })
    response = metric.get_values(*args)
    assert response['total'] == 82.0 + 11.0
    assert response['current'] == 65.0 + 11.0
    assert response['values'] == expected['values']


def test_get_metrics_from_dynamodb_two_projections(ddb_table_for_metric, org,
                                                   alice, dt2016):
    from velodrome.lock8.metrics import METRICS, Resolution
    from velodrome.lock8.metrics.test_utils import ddb_update_item

    metric = METRICS['users-distance-v2']
    ddb_table_for_metric(metric)

    ddb_update_item(metric, date=dt2016.replace(hour=1), item={
        'user_organization': f'{str(org.uuid)}_{str(alice.uuid)}',
        'organization': str(org.uuid),
        'user': str(alice.uuid),
        'distance': Decimal(12345),
    })
    ddb_update_item(metric, date=dt2016.replace(hour=2), item={
        'user_organization': f'{str(org.uuid)}_{str(alice.uuid)}',
        'organization': str(org.uuid),
        'user': str(alice.uuid),
        'distance': Decimal(54321),
    })

    data = metric.get_values(org, Resolution.DAY, dt2016, dt2016)
    assert data == {'values': [{'date': dt2016.strftime('%Y-%m-%d'),
                                'value': 66.67,
                                'user': str(alice.uuid)}]}


def test_unset_zone_type(ddb_table_for_metric, dt2016, zone):
    from velodrome.lock8.metrics import METRICS, Resolution
    from velodrome.lock8.metrics.test_utils import ddb_update_item

    org = zone.organization
    metric = METRICS['zones-bicycles']
    ddb_table_for_metric(metric)
    ddb_update_item(metric, date=dt2016, item={
        'zone': 'None',
        'organization': str(org.uuid),
        'bicycles': 12,
    })
    ddb_update_item(metric, date=dt2016, item={
        'zone': str(zone.uuid),
        'zone_type': str(zone.type),
        'organization': str(org.uuid),
        'bicycles': 34,
    })
    response = metric.get_values(org, Resolution.DAY, dt2016, dt2016)
    assert sorted_dicts(response['values']) == sorted_dicts([
        {'zone': str(zone.uuid), 'zone_type': zone.type,
         'bicycles': Decimal(34), 'date': '2016-06-01'},
        {'zone': None, 'bicycles': Decimal(12), 'date': '2016-06-01'},
    ])


def test_metrics_for_bicycles(ddb_table_for_metric, bicycle, another_bicycle,
                              dt2016):
    from velodrome.lock8.metrics import (
        METRICS, get_distance_for_bicycles_since
    )
    from velodrome.lock8.metrics.test_utils import ddb_update_item

    metric = METRICS['bicycles-distance-v2']
    ddb_table_for_metric(metric)

    bicycle_uuid = str(bicycle.uuid)
    another_bicycle_uuid = str(another_bicycle.uuid)

    ddb_update_item(metric, date=dt2016, item={
        'bicycle': bicycle_uuid,
        'organization': str(bicycle.organization.uuid),
        'distance': 2237,
    })
    assert get_distance_for_bicycles_since([bicycle_uuid], dt2016) == {
        bicycle_uuid: 2.24}

    ddb_update_item(metric, date=dt2016, item={
        'bicycle': bicycle_uuid,
        'organization': str(bicycle.organization.uuid),
        'distance': 1000,
    })
    assert get_distance_for_bicycles_since([bicycle_uuid], dt2016) == {
        bicycle_uuid: 3.24}

    ddb_update_item(metric, date=dt2016, item={
        'bicycle': another_bicycle_uuid,
        'organization': str(another_bicycle.organization.uuid),
        'distance': 420,
    })
    assert get_distance_for_bicycles_since([bicycle_uuid], dt2016) == {
        bicycle_uuid: 3.24}
    assert get_distance_for_bicycles_since([another_bicycle_uuid,
                                            bicycle_uuid], dt2016) == {
        another_bicycle_uuid: 0.42,
        bicycle_uuid: 3.24}
