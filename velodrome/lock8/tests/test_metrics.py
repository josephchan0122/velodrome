"""Tests with mocked DynamoDB."""
import uuid

from django.db import connection
from django.test.utils import CaptureQueriesContext
import pytest

from velodrome.lock8.utils import reverse_query


def test_get_ddbtable_wrapped_name(settings, monkeypatch):
    from velodrome.lock8.dynamodb import get_ddbtable_wrapped_name

    settings.DYNAMODB_TABLE_SUFFIX = 'test'
    assert get_ddbtable_wrapped_name('foo',
                                     is_testing=False) == 'foo-test'

    monkeypatch.setenv('PYTEST_XDIST_WORKER', 'gw1')
    assert get_ddbtable_wrapped_name('foo',
                                     is_testing=True) == 'test__gw1__foo-test'
    monkeypatch.delenv('PYTEST_XDIST_WORKER')

    settings.IS_TESTER = False
    assert get_ddbtable_wrapped_name('foo') == 'foo-test'

    settings.IS_TESTER = True
    assert get_ddbtable_wrapped_name('foo') == 'test__foo-test'

    settings.DYNAMODB_TABLE_SUFFIX = 'prod'
    assert get_ddbtable_wrapped_name('foo') == 'test__foo-prod'

    settings.IS_TESTER = False
    assert get_ddbtable_wrapped_name('foo') == 'foo-prod'


def test_convert_metric_timestamp_to_RFC():
    from velodrome.lock8.metrics import convert_metric_timestamp_to_RFC

    assert convert_metric_timestamp_to_RFC('201502290101') == (
        '2015-02-29T01:01')
    assert convert_metric_timestamp_to_RFC('2015022901') == '2015-02-29T01:00'
    assert convert_metric_timestamp_to_RFC('20150229') == '2015-02-29'
    assert convert_metric_timestamp_to_RFC('201502') == '2015-02'
    assert convert_metric_timestamp_to_RFC('2015') == '2015'
    with pytest.raises(ValueError):
        convert_metric_timestamp_to_RFC('15')


def test_get_metrics_for_today(mocked_ddb, mocker, org, settings, today):
    from velodrome.lock8.metrics import METRICS, Resolution
    from velodrome.lock8.dynamodb import (
        recursive_get_expression, get_ddbtable_wrapped_name
    )

    table = mocker.Mock()
    table.query.return_value = {
        'Count': 1,
        'Items': [{
            'distance': 12345,
        }]}
    mocked_ddb.Table.return_value = table

    response = METRICS['distance'].get_values(
        org, Resolution.DAY, today, today)

    assert response == {'values': [{'value': 12.35}],
                        'total': 12.35, 'current': 12.35}
    assert mocked_ddb.Table.call_count == 3
    assert (mocked_ddb.Table.call_args_list[0][0] ==
            (get_ddbtable_wrapped_name('distance-meters-ridden-day'),))
    assert (mocked_ddb.Table.call_args_list[1][0] ==
            (get_ddbtable_wrapped_name('distance-meters-ridden-hour'),))
    assert (mocked_ddb.Table.call_args_list[2][0] ==
            (get_ddbtable_wrapped_name('distance-meters-ridden-year'),))

    args = table.query.call_args_list[0][1]

    assert args['ExpressionAttributeNames'] == {'#date': 'date'}
    assert args['ProjectionExpression'] in ['#date,distance', 'distance,#date']

    date = int(today.strftime('%Y%m%d'))
    assert recursive_get_expression(args['KeyConditionExpression']) == {
        'operator': 'AND', 'format': '({0} {operator} {1})',
        'values': ({'operator': '=',
                    'format': '{0} {operator} {1}',
                    'values': ('Key: organization', str(org.uuid))},
                   {'operator': 'BETWEEN',
                    'format': '{0} {operator} {1} AND {2}',
                    'values': ('Key: date', date, date)})}


def test_annotate_values_with_user_name(alice, bob, rf):
    from velodrome.lock8.metrics import annotate_values

    request = rf.request()

    values = [
        {'user': str(alice.uuid)},
        {'user': str(bob.uuid)},
    ]
    alice_url = ('http://testserver' + reverse_query(
        'lock8:user-detail',
        kwargs={'uuid': alice.uuid}))
    bob_url = ('http://testserver' + reverse_query(
        'lock8:user-detail',
        kwargs={'uuid': bob.uuid}))
    with CaptureQueriesContext(connection) as capture:
        new = annotate_values(values, 'user', type(alice).objects, request)
    assert len(capture.captured_queries) == 1
    assert new == [
        {'user': alice_url,
         'user_name': alice.display_name},
        {'user': bob_url,
         'user_name': bob.display_name}]


def test_annotate_values_with_bicycle_name(bicycle, another_bicycle, rf):
    from velodrome.lock8.metrics import annotate_values

    request = rf.request()

    _uuid = uuid.UUID(int=0)
    values = [
        {'bicycle': str(bicycle.uuid)},
        {'bicycle': str(another_bicycle.uuid)},
        {'bicycle': 'INVALID-UUID'},
        {'bicycle': str(_uuid)},
    ]
    with CaptureQueriesContext(connection) as capture:
        new = annotate_values(values, 'bicycle', type(bicycle).objects,
                              request)
    assert len(capture.captured_queries) == 1
    assert new == [
        {'bicycle': bicycle.get_absolute_uri(request),
         'bicycle_name': bicycle.name},
        {'bicycle': another_bicycle.get_absolute_uri(request),
         'bicycle_name': another_bicycle.name},
        {'bicycle': None, 'bicycle_name': None},
        {'bicycle': None, 'bicycle_name': None}]


def test_ddb_put_item(mocker_copy, org, at_2000, bicycle):
    # FIXME: Will NOT work with pytest_mock > 3.2.0
    from unittest.mock import call
    from velodrome.lock8.metrics import (METRICS, Resolution)
    from velodrome.lock8.metrics.test_utils import ddb_put_item, dt_to_ddb

    get_ddbtable = mocker_copy.patch('velodrome.lock8.metrics.get_ddbtable')

    metric = METRICS['distance']
    ddb_put_item(metric, {'organization': str(org.uuid),
                          'distance': 2237}, at_2000)

    assert get_ddbtable.call_args_list == [
        call('distance-meters-ridden-hour'),
        call('distance-meters-ridden-day'),
        call('distance-meters-ridden-month'),
        call('distance-meters-ridden-year')]

    assert get_ddbtable().update_item.call_args_list == [
        call(ExpressionAttributeValues={':n': 2237},
             Key={'organization': str(org.uuid),
                  'date': dt_to_ddb(at_2000, resolution)},
             UpdateExpression='SET distance = :n')
        for resolution in Resolution.above_minute()
    ]

    get_ddbtable = mocker_copy.patch('velodrome.lock8.metrics.get_ddbtable')
    metric = METRICS['bicycles-distance-v2']
    ddb_put_item(metric, {'organization': str(org.uuid),
                          'bicycle': str(bicycle.uuid),
                          'distance': 1234}, at_2000)

    assert get_ddbtable.call_args_list == [
        call('v2-bicycle-distance-meters-ridden-day'),
        call('v2-bicycle-distance-meters-ridden-month'),
        call('v2-bicycle-distance-meters-ridden-year')]

    assert get_ddbtable().update_item.call_args_list == [
        call(ExpressionAttributeValues={':n': 1234, ':o': str(org.uuid)},
             Key={'bicycle': str(bicycle.uuid),
                  'date': dt_to_ddb(at_2000, resolution)},
             UpdateExpression='SET distance = :n, organization = :o')
        for resolution in Resolution.above_hour()
    ]


def test_try_delete_tables(ddb_table_for_metric, caplog):
    from velodrome.lock8.metrics import (METRICS, Resolution)
    from velodrome.lock8.dynamodb import try_delete_tables

    ddb_tables = ddb_table_for_metric(METRICS['distance'], Resolution.DAY)

    try_delete_tables([])
    with pytest.raises(Exception):
        try_delete_tables(['foo'])

    try_delete_tables(ddb_tables)

    log_before = caplog.records[:]
    try_delete_tables(ddb_tables)
    log_after = [x for x in caplog.records if x not in log_before]
    assert len([x for x in log_after if x.message.startswith(
        'Could not delete DynamoDB table: An error occurred')]) == 1


def test_metrics_queryset_like_immutable_filter():
    from velodrome.lock8.metrics import (
        METRICS, MetricsQuerysetLike, Resolution
    )

    queryset_props = ['_metric', '_organization', '_resolution', '_start',
                      '_end', '_kwrags']

    qs1 = MetricsQuerysetLike()
    assert all(getattr(qs1, attr, None) is None for attr in queryset_props)

    qs2 = qs1.filter(metric_name='distance',
                     resolution=Resolution.DAY)
    assert qs2._metric == METRICS['distance']
    assert qs2._resolution == Resolution.DAY
    assert all(getattr(qs1, attr, None) is None for attr in queryset_props)
