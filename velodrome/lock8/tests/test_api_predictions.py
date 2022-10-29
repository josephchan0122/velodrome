import datetime as dt

import pytest
from rest_framework import status

from velodrome.lock8.utils import reverse_query

DELTA_10_MINUTES = dt.timedelta(minutes=10)


@pytest.fixture
def dropzone_prediction_mock(org, zone, zone_somewhere, at_2000, at_1900):
    from velodrome.lock8.predictions import PREDICTIONS
    from unittest.mock import patch

    def generate_predictions(zones, start_time, period):
        return [{'zone': str(z.uuid),
                 'predictions': [
                    {'date': start_time + DELTA_10_MINUTES * (i + 1),
                     'median': i, 'q25': i, 'q75': i}
                    for i in range(0, period * 6)]}
                for z in zones]

    class MockDropzonePrediction:
        def get_values(self, org_arg, zone_arg=None, made_at=None,
                       period=None):
            assert org_arg == org, \
                'Invalid organization used with dropzone predictions mock'
            assert zone_arg in [None, zone, zone_somewhere], \
                'Invalid zone used with dropzone predictions mock'

            if not made_at:
                made_at = at_2000
            if not period:
                period = 72

            if made_at not in [at_2000, at_1900]:
                return {'values': []}

            if zone_arg:
                zones = [zone_arg]
            else:
                zones = [zone, zone_somewhere]

            return {'values': generate_predictions(zones, made_at, period)}

    mock_predictions = {
        'bicycles-in-dropzones': MockDropzonePrediction(),
    }

    with patch.dict(PREDICTIONS, mock_predictions):
        yield


def reverse_query_prediction(prediction_name, args):
    return reverse_query(
        'lock8:prediction_value-list',
        kwargs={'prediction_name': prediction_name},
        query_kwargs=args)


def get_zone_url(zone):
    return 'http://testserver' + reverse_query(
        'lock8:zone-detail', kwargs={'uuid': zone.uuid})


def test_required_params(dropzone_prediction_mock, drf_fleet_operator, org):
    query_args = {}

    url = reverse_query_prediction('bicycles-in-dropzones', query_args)
    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {
        'detail': {'organization': [{'message': 'This field is required.',
                                     'code': 'required'}]}}

    query_args['organization'] = 'foo'
    url = reverse_query_prediction('bicycles-in-dropzones', query_args)
    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {'detail': {
        'organization': [{'message': 'Must be a valid UUID.',
                          'code': 'invalid'}]}}

    query_args['organization'] = str(org.uuid)
    url = reverse_query_prediction('bicycles-in-dropzones', query_args)
    drf_fleet_operator.assert_success(url)

    url = reverse_query_prediction('non-existent-prediction', query_args)
    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {
        'detail': {'prediction_name': [
            {'message': 'Prediction \'non-existent-prediction\' not found',
             'code': 'invalid'}]}}

    query_args['made_at'] = '2016'
    url = reverse_query_prediction('bicycles-in-dropzones', query_args)
    drf_fleet_operator.assert_status(
        url, status.HTTP_400_BAD_REQUEST,
        {'detail': {
            'made_at': [
                {'message': 'Datetime has wrong format.'
                 ' Use one of these formats'
                 ' instead: YYYY-MM-DDThh:mm[:ss[.uuuuuu]][+HH:MM|-HH:MM|Z].',
                 'code': 'invalid'}]}})
    del query_args['made_at']

    query_args['zone'] = 'bar'
    url = reverse_query_prediction('bicycles-in-dropzones', query_args)
    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {'detail': {
        'zone': [{'message': 'Must be a valid UUID.',
                  'code': 'invalid'}]}}
    del query_args['zone']

    query_args['period'] = 73
    url = reverse_query_prediction('bicycles-in-dropzones', query_args)
    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {'detail': {
        'period': [{
            'message': 'Ensure this value is less than or equal to 72.',
            'code': 'max_value'}]}}
    del query_args['period']


def test_required_permissions(dropzone_prediction_mock, org, zone,
                              another_zone, drf_another_fleet_operator,
                              drf_fleet_operator):
    query_args = {'organization': str(org.uuid)}
    url = reverse_query_prediction('bicycles-in-dropzones', query_args)
    response = drf_another_fleet_operator.get(url)
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.data == {
        'detail': {'non_field_errors': [
            {'message': 'You do not have permission to perform this action.',
             'code': 'permission_denied'}]}}

    query_args['zone'] = str(another_zone.uuid)
    url = reverse_query_prediction('bicycles-in-dropzones', query_args)
    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_403_FORBIDDEN
    assert response.data == {
        'detail': {'non_field_errors': [
            {'message': 'You do not have permission to perform this action.',
             'code': 'permission_denied'}]}}

    query_args['zone'] = str(zone.uuid)
    url = reverse_query_prediction('bicycles-in-dropzones', query_args)
    drf_fleet_operator.assert_success(url)


def test_select_predictions(dropzone_prediction_mock, org, zone, at_1900,
                            zone_somewhere, drf_fleet_operator, at_2000):
    url = reverse_query_prediction('bicycles-in-dropzones', {
        'organization': str(org.uuid)})
    drf_fleet_operator.assert_success(url, {'values': [{
        'zone': get_zone_url(z),
        'zone_name': z.name,
        'predictions': [
            {'date': at_2000 + DELTA_10_MINUTES * (i+1),
             'median': i, 'q25': i, 'q75': i}
            for i in range(0, 432)]}
        for z in [zone, zone_somewhere]
    ]})

    url = reverse_query_prediction('bicycles-in-dropzones', {
        'organization': str(org.uuid),
        'period': 10})
    drf_fleet_operator.assert_success(url, {'values': [{
        'zone': get_zone_url(z),
        'zone_name': z.name,
        'predictions': [
            {'date': at_2000 + DELTA_10_MINUTES * (i+1),
             'median': i, 'q25': i, 'q75': i}
            for i in range(0, 60)]}
        for z in [zone, zone_somewhere]
    ]})

    url = reverse_query_prediction('bicycles-in-dropzones', {
        'organization': str(org.uuid),
        'period': 10,
        'zone': str(zone.uuid)})
    drf_fleet_operator.assert_success(url, {'values': [{
        'zone': get_zone_url(zone),
        'zone_name': zone.name,
        'predictions': [
            {'date': at_2000 + DELTA_10_MINUTES * (i+1),
             'median': i, 'q25': i, 'q75': i}
            for i in range(0, 60)]}
    ]})

    url = reverse_query_prediction('bicycles-in-dropzones', {
        'organization': str(org.uuid),
        'period': 10,
        'zone': str(zone.uuid),
        'made_at': at_1900})
    drf_fleet_operator.assert_success(url, {'values': [{
        'zone': get_zone_url(zone),
        'zone_name': zone.name,
        'predictions': [
            {'date': at_1900 + DELTA_10_MINUTES * (i+1),
             'median': i, 'q25': i, 'q75': i}
            for i in range(0, 60)]}
    ]})

    url = reverse_query_prediction('bicycles-in-dropzones', {
        'organization': str(org.uuid),
        'period': 10,
        'zone': str(zone.uuid),
        'made_at': at_1900 - dt.timedelta(hours=1)})
    drf_fleet_operator.assert_success(url, {'values': []})


def test_csv_view(dropzone_prediction_mock, org, at_2000, drf_fleet_operator,
                  zone, csv_content_type):
    content_type, delimiter = csv_content_type
    ctv_header = '{}; version=1.0'.format(content_type)
    ct_header = '{}; charset=utf-8'.format(content_type)

    url = reverse_query_prediction('bicycles-in-dropzones', {
        'organization': str(org.uuid),
        'zone': str(zone.uuid),
        'period': 1})
    response = drf_fleet_operator.get(url, HTTP_ACCEPT=ctv_header)
    assert response.status_code == status.HTTP_200_OK
    assert response['Content-Type'] == ct_header

    zone_url = get_zone_url(zone)
    header = ('date', 'median', 'q25', 'q75', 'zone', 'zone_name')
    assert response.content.decode() == (
        '\r\n'.join(
            delimiter.join(row) for row in (
                (header,) + tuple(
                    (str(at_2000 + DELTA_10_MINUTES * (i + 1)),
                     str(i), str(i), str(i),
                     zone_url, zone.name)
                    for i in range(0, 6)))
        ) + '\r\n')


def test_documentation_generation():
    from velodrome.lock8.predictions import (
        PredictionsFilterBackend, PredictionsInputSerializer
    )
    backend = PredictionsFilterBackend()
    serializer = PredictionsInputSerializer()
    fields = backend.get_schema_fields(None)
    assert len(fields) == len(serializer.fields.values())
    for expected, actual in zip(fields, serializer.fields.values()):
        assert expected.name == actual.field_name
        assert expected.location == 'query'
        assert expected.required == actual.required
