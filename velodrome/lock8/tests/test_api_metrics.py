import datetime as dt
from decimal import Decimal
import uuid

from freezegun import freeze_time
import pytest
from rest_framework import status

from velodrome.lock8.conftest import NOW
from velodrome.lock8.metrics import (
    METRICS, BicycleMetric, OrganizationMetric, Resolution, ZoneMetric,
)
from velodrome.lock8.utils import reverse_query


def reverse_query_metric(metric_name, args):
    return reverse_query(
        'lock8:metric_value-list',
        kwargs={'metric_name': metric_name},
        query_kwargs=args)


@pytest.fixture(params=[r.value for r in Resolution.above_minute()])
def url_distance_all(request, org):
    return reverse_query_metric('distance', {
        'organization': org.uuid,
        'resolution': request.param,
        'start': NOW - dt.timedelta(days=1),
        'end': NOW,
    })


def test_required_params(mocked_query_table, drf_fleet_operator, org):
    query_args = {}
    url = reverse_query_metric('distance', query_args)
    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {
        'detail': {'organization': [{'message': 'This field is required.',
                                     'code': 'required'}],
                   'resolution': [{'message': 'This field is required.',
                                   'code': 'required'}]}}

    query_args['organization'] = 'foo'
    url = reverse_query_metric('distance', query_args)
    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {'detail': {
        'organization': [{'message': 'Must be a valid UUID.',
                          'code': 'invalid'}],
        'resolution': [{'message': 'This field is required.',
                        'code': 'required'}]}}

    query_args['resolution'] = Resolution.DAY.value
    url = reverse_query_metric('distance', query_args)
    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {'detail': {
        'organization': [{'message': 'Must be a valid UUID.',
                          'code': 'invalid'}]}}

    query_args['start'] = '2016'
    url = reverse_query_metric('distance', query_args)
    drf_fleet_operator.assert_status(
        url, status.HTTP_400_BAD_REQUEST,
        {'detail': {
            'organization': [{'message': 'Must be a valid UUID.',
                              'code': 'invalid'}],
            'start': [
                {'message': 'Datetime has wrong format.'
                 ' Use one of these formats'
                 ' instead: YYYY-MM-DDThh:mm[:ss[.uuuuuu]][+HH:MM|-HH:MM|Z].',
                 'code': 'invalid'}]}})

    del query_args['start']
    query_args['organization'] = str(org.uuid)
    url = reverse_query_metric('distance', query_args)
    drf_fleet_operator.assert_success(url)


@pytest.mark.parametrize('resolution', Resolution.above_minute())
def test_default_start_end(at_2000, mocker, resolution, mocked_query_table,
                           drf_fleet_operator, org):
    import velodrome
    from velodrome.lock8.metrics import START_DELTA_FOR_RESOLUTION

    patched = mocker.patch.object(
        velodrome.lock8.metrics.OrganizationMetric,
        'get_values',
        return_value={'values': []})

    url = reverse_query_metric('distance', {
        'organization': str(org.uuid),
        'resolution': resolution.value
    })

    # 2027 allows to go back ten years (for resolution "year").
    dt2027 = dt.datetime(2027, 2, 1, tzinfo=dt.timezone.utc)
    with freeze_time(dt2027):
        drf_fleet_operator.get(url)
    assert patched.call_args[0][2] == (
        dt2027 - dt.timedelta(days=START_DELTA_FOR_RESOLUTION[resolution]))
    assert patched.call_args[0][3] == dt2027

    dt2016 = dt.datetime(2016, 6, 1, tzinfo=dt.timezone.utc)
    with freeze_time(dt2016):
        drf_fleet_operator.get(url)

    if resolution in [Resolution.MONTH, Resolution.YEAR]:
        assert patched.call_args[0][2] == dt2016.replace(month=1)
    else:
        assert patched.call_args[0][2] == (
            dt2016 - dt.timedelta(days=START_DELTA_FOR_RESOLUTION[resolution]))
    assert patched.call_args[0][3] == dt2016


@pytest.mark.parametrize(
    'metric_name',
    (name for name, metric in METRICS.items()
     if metric.value_name is not None))
def test_ok_with_params_single_projection(metric_name, mocked_query_table,
                                          drf_fleet_operator, org, alice, rf):
    from velodrome.lock8.metrics import (
        annotate_all_values, default_parse_metric_value
    )
    from velodrome.lock8.metrics.test_utils import rename_key

    metric = METRICS[metric_name]
    value_name = metric.value_name
    now_minus_hour = NOW - dt.timedelta(hours=1)

    mocked_query_table.side_effect.values = [('date', value_name), [
        (now_minus_hour, 789),
        (NOW, 12345)
    ]]

    url = reverse_query_metric(metric.name, {
        'organization': org.uuid,
        'resolution': Resolution.DAY.value,
        'start': NOW - dt.timedelta(days=1),
        'end': NOW,
    })

    rows = mocked_query_table.side_effect.values[1]

    expected = {'values': [
        {
            'date': now_minus_hour.strftime('%Y-%m-%d'),
            rename_key(value_name):
                default_parse_metric_value(value_name, 789),
        },
        {
            'date': NOW.strftime('%Y-%m-%d'),
            rename_key(value_name):
                default_parse_metric_value(value_name, 12345),
        },
    ]}

    if isinstance(metric, OrganizationMetric):
        expected['current'] = default_parse_metric_value(value_name, 13134)
        expected['total'] = default_parse_metric_value(
            value_name, sum(x for _, x in rows))

    expected['values'] = annotate_all_values(expected['values'], rf.request())

    drf_fleet_operator.assert_success(url, expected)


@pytest.mark.parametrize('metric_name', ['users-distance', 'users-unique'])
@pytest.mark.parametrize('resolution', Resolution.above_hour())
def test_users(mocked_query_table, metric_name, resolution, drf_fleet_operator,
               org, alice, bob, rf):

    from velodrome.lock8.metrics.test_utils import (
        get_iso8601_strftime_for_resolution
    )

    rf_request = rf.request()
    mocked_data = [(str(alice.uuid), alice.get_absolute_uri(rf_request),
                    alice.display_name, 12345),
                   (str(bob.uuid), bob.get_absolute_uri(rf_request),
                    bob.display_name, 54321),
                   ('INVALID-UUID', None, None, 9876),
                   (uuid.UUID(int=0), None, None, 2345)]

    ddb_now = resolution.strftime(NOW)

    def query_table(table, query, select):
        actual_resolution = Resolution(table.name.split('-')[-2])
        assert actual_resolution == (
            Resolution.HOUR if select == 'current' else resolution)
        return {
            'Items': [{k: v for k, v in (
                ('date', ddb_now),
                ('user', user_uuid),
                ('distance', distance),
            ) if k != 'distance' or metric_name != 'users-unique'}
                      for user_uuid, _, user_display_name, distance
                      in mocked_data],
            'Count': len(mocked_data),
        }
    mocked_query_table.side_effect = query_table

    url = reverse_query_metric(metric_name, {
        'organization': org.uuid,
        'resolution': resolution.value,
        'start': NOW - dt.timedelta(days=1),
        'end': NOW
    })

    expected_data = {
        'values': [{k: v for k, v in (
            ('user', user_url),
            ('date', NOW.strftime(
                get_iso8601_strftime_for_resolution(resolution))),
            ('value', round(distance/1000, 2)),
            ('user_name', user_display_name),
        ) if k != 'value' or metric_name != 'users-unique'}
                   for _, user_url, user_display_name, distance
                   in mocked_data]}

    drf_fleet_operator.assert_success(url, expected_data)


def test_users_filter(ddb_table_for_metric, org, drf_fleet_operator,
                      dt2016, alice, rf):
    from velodrome.lock8.metrics.test_utils import ddb_update_item

    metric = METRICS['users-distance']
    ddb_table_for_metric(metric)
    ddb_update_item(metric, date=dt2016, item={
        'user': str(alice.uuid),
        'organization': str(org.uuid),
        'distance': 2237,
    })
    url = reverse_query_metric(metric.name, {
        'user': alice.uuid,
        'organization': org.uuid,
        'resolution': Resolution.YEAR.value
    })
    drf_fleet_operator.assert_values(url, [
        {'user': alice.get_absolute_uri(rf.request()),
         'user_name': alice.display_name,
         'date': '2016',
         'value': 2.24}])


@pytest.mark.parametrize(
    'metric_name',
    sorted(name for name, metric in METRICS.items()
           if isinstance(metric, BicycleMetric)))
@pytest.mark.parametrize('resolution', Resolution.above_hour())
def test_bicycles(mocked_query_table, metric_name, resolution,
                  drf_fleet_operator, org):

    url = reverse_query_metric(metric_name, {
        'organization': org.uuid,
        'resolution': resolution.value,
        'start': NOW - dt.timedelta(days=1),
        'end': NOW
    })

    expected_data = mocked_query_table.side_effect.expected_data(resolution)
    drf_fleet_operator.assert_success(url, expected_data)


@pytest.mark.parametrize(
    'metric_name',
    sorted(name for name, metric in METRICS.items()
           if isinstance(metric, BicycleMetric)))
@pytest.mark.parametrize('resolution', Resolution.above_hour())
def test_bicycles_with_spectator(mocked_query_table, metric_name, resolution,
                                 drf_spectator, org):

    url = reverse_query_metric(metric_name, {
        'organization': org.uuid,
        'resolution': resolution.value,
        'start': NOW - dt.timedelta(days=1),
        'end': NOW
    })

    expected_data = mocked_query_table.side_effect.expected_data(resolution)
    drf_spectator.assert_success(url, expected_data)


@pytest.mark.parametrize(
    'metric_name',
    sorted(name for name, metric in METRICS.items()
           if isinstance(metric, BicycleMetric)))
@pytest.mark.parametrize('resolution', [Resolution.DAY])
def test_bicycles_filter(mocked_query_table, metric_name, resolution,
                         drf_fleet_operator, org):
    from velodrome.lock8.dynamodb import recursive_get_expression
    from velodrome.lock8.metrics.test_utils import dt_to_ddb

    dt_start, dt_end = NOW - dt.timedelta(days=1), NOW
    url = reverse_query_metric(metric_name, {
        'organization': org.uuid,
        'resolution': resolution.value,
        'start': dt_start,
        'end': dt_end
    })

    response = drf_fleet_operator.assert_success(url)
    assert len(response.data['values']) == 3

    url = '&'.join([url, 'bicycle=00000000-0000-0000-0000-000000000065'])
    response = drf_fleet_operator.assert_success(url)

    assert len(mocked_query_table.call_args_list) == 2

    ddb_start = dt_to_ddb(dt_start, resolution)
    ddb_end = dt_to_ddb(dt_end, resolution)

    query_expression = recursive_get_expression(
        mocked_query_table.call_args_list[0][0][1]['KeyConditionExpression'])
    assert query_expression == {
        'format': '({0} {operator} {1})', 'operator': 'AND',
        'values': ({
            'format': '{0} {operator} {1}',
            'operator': '=',
            'values': ('Key: organization', str(org.uuid))},
         {'format': '{0} {operator} {1} AND {2}', 'operator': 'BETWEEN',
          'values': ('Key: date', ddb_start, ddb_end)})}

    query_expression = recursive_get_expression(
        mocked_query_table.call_args_list[1][0][1]['KeyConditionExpression'])
    assert query_expression == {
        'values': ({
            'values': ('Key: bicycle',
                       '00000000-0000-0000-0000-000000000065'),
            'operator': '=',
            'format': '{0} {operator} {1}'}, {
                'values': ('Key: date', ddb_start, ddb_end),
                'operator': 'BETWEEN',
                'format': '{0} {operator} {1} AND {2}'}),
        'operator': 'AND', 'format': '({0} {operator} {1})'}


@pytest.mark.parametrize('metric_name', ['dropzone-metrics-v2'])
def test_dropzone_metrics(ddb_table_for_metric, metric_name, dt2016,
                          drf_fleet_operator, org, zone, zone2, rf):

    from velodrome.lock8.metrics.test_utils import ddb_update_item

    metric = METRICS[metric_name]
    ddb_table_for_metric(metric)
    ddb_update_item(metric, date=dt2016, item={
        'zone': str(zone.uuid),
        'organization': str(org.uuid),
        'avg_bicycles': Decimal('2237.3'),
        'max_bicycles': 2499,
        'min_bicycles': 1501
    })
    ddb_update_item(metric, date=dt2016, item={
        'zone': str(zone2.uuid),
        'organization': str(org.uuid),
        'avg_bicycles': Decimal('2238.4'),
        'max_bicycles': 2500,
        'min_bicycles': 1500
    })
    url = reverse_query_metric(metric.name, {
        'organization': org.uuid,
        'resolution': Resolution.MINUTE.value
    })
    drf_fleet_operator.assert_values(url, [
        {'zone': zone.get_absolute_uri(rf.request()),
         'zone_name': zone.display_name,
         'date': '2016-06-01T20:15',
         'avg_bicycles': Decimal('2237.3'),
         'max_bicycles': 2499,
         'min_bicycles': 1501},
        {'zone': zone2.get_absolute_uri(rf.request()),
         'zone_name': zone2.display_name,
         'date': '2016-06-01T20:15',
         'avg_bicycles': Decimal('2238.4'),
         'max_bicycles': 2500,
         'min_bicycles': 1500}])

    dt_start, dt_end = dt2016 - dt.timedelta(days=31), dt2016
    url = reverse_query_metric(metric_name, {
        'organization': org.uuid,
        'zone': zone2.uuid,
        'resolution': Resolution.MONTH.value,
        'start': dt_start,
        'end': dt_end
    })

    drf_fleet_operator.assert_values(url, [
        {'zone': zone2.get_absolute_uri(rf.request()),
         'zone_name': zone2.display_name,
         'date': '2016-06',
         'avg_bicycles': Decimal('2238.4'),
         'max_bicycles': 2500,
         'min_bicycles': 1500}])


def test_ok_with_params_integration(ddb_table_for_metric, drf_fleet_operator,
                                    url_distance_all):
    metric = METRICS['distance']
    ddb_table_for_metric(metric)
    response = drf_fleet_operator.get(url_distance_all)
    assert response.data == {'current': 0, 'total': 0, 'values': []}
    assert response.status_code == status.HTTP_200_OK


def test_another_org_forbidden(drf_another_fleet_operator,
                               mocked_query_table, url_distance_all):
    drf_another_fleet_operator.assert_status(url_distance_all,
                                             status.HTTP_403_FORBIDDEN)


def test_org_forbidden_without_feature(drf_fleet_operator,
                                       mocked_query_table, url_distance_all,
                                       analytics_feature, org):

    analytics_feature.activate()
    analytics_feature.organizations.remove(org)

    drf_fleet_operator.assert_status(url_distance_all,
                                     status.HTTP_403_FORBIDDEN)


def test_invalid_start_end(drf_fleet_operator, org):
    url = reverse_query_metric('distance', {
        'organization': org.uuid,
        'resolution': Resolution.DAY.value,
        'start': -1,
        'end': 'foo'
    })
    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert 'start' in response.data['detail']
    assert 'end' in response.data['detail']


@pytest.mark.parametrize(
    'metric_name',
    sorted(name for name, metric in METRICS.items()
           if Resolution.HOUR not in metric.resolutions))  # noqa
def test_no_hour_for_private(metric_name, drf_fleet_operator, org):
    url = reverse_query_metric(metric_name, {
        'organization': str(org.uuid),
        'start': NOW,
        'end': NOW,
        'resolution': Resolution.HOUR.value,
    })
    drf_fleet_operator.assert_400(url, {
        'resolution': [
            {'message':
                'Invalid value "hour" for metric "{}".'.format(metric_name),
             'code': 'invalid'}]})


@pytest.mark.parametrize(
    'metric_name',
    sorted(name for name, metric in METRICS.items()
           if Resolution.HOUR in metric.resolutions))  # noqa
def test_hour_for_non_private(metric_name, mocked_query_table,
                              drf_fleet_operator, org):
    url = reverse_query_metric(metric_name, {
        'organization': str(org.uuid),
        'start': NOW,
        'end': NOW,
        'resolution': Resolution.HOUR.value,
    })
    drf_fleet_operator.assert_success(url)


@pytest.fixture(params=[Resolution.DAY.value, Resolution.HOUR.value])
def csv_query_kwargs(request, mocked_query_table, at_2000, org):
    projection, rows = mocked_query_table.side_effect.default_values()
    start = [v for k, v in zip(projection, rows[0]) if k == 'date'][0]
    return {
        'organization': org.uuid,
        'start': start,
        'end': at_2000,
        'resolution': request.param,
    }


def test_csv_view_empty(at_2000, org, drf_fleet_operator, mocked_query_table,
                        csv_content_type, csv_query_kwargs):
    content_type, delimiter = csv_content_type
    mocked_query_table.side_effect.values = [['distance'], []]
    url = reverse_query_metric('distance', csv_query_kwargs)
    ctv_header = '{}; version=1.0'.format(content_type)
    response = drf_fleet_operator.get(url, HTTP_ACCEPT=ctv_header)
    assert response.status_code == status.HTTP_200_OK, response.data
    assert response['Content-Type'] == '{}; charset=utf-8'.format(content_type)
    assert response.content.decode() == ''


def test_csv_view(at_2000, mocked_query_table, drf_fleet_operator,
                  csv_content_type, csv_query_kwargs):
    from velodrome.lock8.metrics.test_utils import (
        get_iso8601_strftime_for_resolution
    )

    content_type, delimiter = csv_content_type
    resolution = Resolution(csv_query_kwargs['resolution'])

    ctv_header = '{}; version=1.0'.format(content_type)

    url = reverse_query_metric('distance', csv_query_kwargs)
    response = drf_fleet_operator.get(url, HTTP_ACCEPT=ctv_header)
    assert response.status_code == status.HTTP_200_OK
    assert response['Content-Type'] == '{}; charset=utf-8'.format(content_type)
    ftime = get_iso8601_strftime_for_resolution(resolution)

    projection, rows = mocked_query_table.side_effect.default_values()
    values_with_keys = [dict(zip(projection, row)) for row in rows]
    assert response.content.decode() == (
        '\r\n'.join(
            delimiter.join(row) for row in (
                (('date', 'value'),) + tuple(
                    (row['date'].strftime(ftime),
                        str(round(row['distance']/1000, 2)))
                    for row in values_with_keys))
        ) +
        '\r\n')


def test_csv_view_forbidden_for_renter(csv_query_kwargs, csv_content_type,
                                       drf_alice):
    content_type, _ = csv_content_type
    url = reverse_query_metric('distance', csv_query_kwargs)
    response = drf_alice.get(url, HTTP_ACCEPT='{}; version=1.0'.format(
        content_type))
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_metrics_view_index(mocked_query_table, drf_fleet_operator, org):
    drf_fleet_operator.assert_success(
        reverse_query_metric('distance', {
            'organization': org.uuid,
            'resolution': Resolution.DAY.value
        }))


def test_metrics_view_400_for_unknown(drf_fleet_operator, org):
    # NOTE: does not use exception's value for 'detail'.
    drf_fleet_operator.assert_status(
        reverse_query_metric('DOESNOTEXIST', {
            'organization': str(org.uuid),
            'resolution': Resolution.DAY.value
        }),
        status.HTTP_400_BAD_REQUEST,
        {'detail': {
            'metric_name': [{'message': "Metric 'DOESNOTEXIST' not found.",
                             'code': 'invalid'}]}})


def test_start_precedes_end(mocked_query_table, drf_fleet_operator, org):
    url = reverse_query_metric('distance', {
        'start': dt.datetime(2016, 1, 1),
        'end': dt.datetime(2015, 1, 1),
        'organization': org.uuid,
        'resolution': Resolution.YEAR.value
    })
    drf_fleet_operator.assert_400(url, {
        'start': [{'message': "'start' needs to be earlier than 'end'",
                   'code': 'invalid'}]})


def test_zones_by_anonymous_user(drf_client, org):
    start = dt.datetime(2016, 5, 31, 16, 11)
    end = dt.datetime(2016, 6, 1, 19, 20)
    url = reverse_query_metric('zones_bicycles', {
        'organization': org.uuid,
        'resolution': Resolution.DAY.value,
        'start': start,
        'end': end
    })

    response = drf_client.get(url)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


@pytest.mark.parametrize(
    'metric_name',
    sorted(name for name, metric in METRICS.items()
           if isinstance(metric, ZoneMetric)))
@pytest.mark.parametrize('resolution', [Resolution.DAY])
def test_zones_filter(mocked_query_table, metric_name, resolution,
                      drf_fleet_operator, org):
    from velodrome.lock8.dynamodb import recursive_get_expression
    from velodrome.lock8.metrics.test_utils import dt_to_ddb

    dt_start, dt_end = NOW - dt.timedelta(days=1), NOW
    url = reverse_query_metric(metric_name, {
        'organization': org.uuid,
        'resolution': resolution.value,
        'start': dt_start,
        'end': dt_end
    })

    response = drf_fleet_operator.assert_success(url)
    assert len(response.data['values']) == 3

    url = '&'.join([url, 'zone=00000000-0000-0000-0000-000000000265'])
    response = drf_fleet_operator.assert_success(url)

    assert len(mocked_query_table.call_args_list) == 2

    ddb_start = dt_to_ddb(dt_start, resolution)
    ddb_end = dt_to_ddb(dt_end, resolution)

    query_expression = recursive_get_expression(
        mocked_query_table.call_args_list[0][0][1]['KeyConditionExpression'])
    assert query_expression == {
        'format': '({0} {operator} {1})', 'operator': 'AND',
        'values': ({
            'format': '{0} {operator} {1}',
            'operator': '=',
            'values': ('Key: organization', str(org.uuid))},
         {'format': '{0} {operator} {1} AND {2}', 'operator': 'BETWEEN',
          'values': ('Key: date', ddb_start, ddb_end)})}

    query_expression = recursive_get_expression(
        mocked_query_table.call_args_list[1][0][1]['KeyConditionExpression'])
    assert query_expression == {
        'values': ({
            'values': ('Key: zone',
                       '00000000-0000-0000-0000-000000000265'),
            'operator': '=',
            'format': '{0} {operator} {1}'}, {
                'values': ('Key: date', ddb_start, ddb_end),
                'operator': 'BETWEEN',
                'format': '{0} {operator} {1} AND {2}'}),
        'operator': 'AND', 'format': '({0} {operator} {1})'}


def test_distance_should_ignore_bicycle_filter(ddb_table_for_metric, org,
                                               drf_fleet_operator):
    """This needs to be unmocked to get through to DynamoDB."""

    ddb_table_for_metric(METRICS['distance'])
    url = reverse_query_metric('distance', {
        'bicycle': org.uuid,
        'organization': org.uuid,
        'resolution': Resolution.YEAR.value
    })
    drf_fleet_operator.assert_success(url)


def test_bicycles_with_bicycle_filter(ddb_table_for_metric, org,
                                      drf_fleet_operator, dt2016, bicycle, rf):
    from velodrome.lock8.metrics.test_utils import ddb_update_item

    metric = METRICS['bicycles-distance-v2']
    ddb_table_for_metric(metric)
    ddb_update_item(metric, date=dt2016, item={
        'bicycle': str(bicycle.uuid),
        'organization': str(org.uuid),
        'distance': 2237,
    })
    url = reverse_query_metric(metric.name, {
        'bicycle': bicycle.uuid,
        'organization': org.uuid,
        'resolution': Resolution.YEAR.value
    })
    drf_fleet_operator.assert_values(url, [
        {'bicycle': bicycle.get_absolute_uri(rf.request()),
         'bicycle_name': 'bicycle',
         'date': '2016',
         'value': 2.24}])


def test_documentation_generation():
    from velodrome.lock8.metrics import (
        MetricsFilterBackend, MetricsInputSerializer
    )
    backend = MetricsFilterBackend()
    serializer = MetricsInputSerializer()
    fields = backend.get_schema_fields(None)
    assert len(fields) == len(serializer.fields.values())
    for expected, actual in zip(fields, serializer.fields.values()):
        assert expected.name == actual.field_name
        assert expected.location == 'query'
        assert expected.required == actual.required
