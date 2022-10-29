import datetime as dt
import time
import uuid

from django.utils import timezone
import jwt
import pytest
from rest_framework import status
from rest_framework.test import APIClient

from velodrome.lock8.conftest import decorated_drf_client
from velodrome.lock8.utils import reverse_query


@pytest.fixture
@decorated_drf_client
def drf_tsp(client_app, settings):
    now = timezone.now()
    payload = {'user_id': client_app.name,
               'iss': 'sts-dev',
               'organization': str(client_app.organization.uuid),
               'scopes': ['bicycle:read', 'bicycle:write'],
               'exp': now + dt.timedelta(minutes=30),
               'iat': now}
    sts_jwt = jwt.encode(payload, settings.JWT_SECRET_KEY,
                         algorithm='HS512').decode()
    drf_tsp = APIClient(HTTP_ACCEPT='application/json; version=1.0')
    drf_tsp.credentials(HTTP_AUTHORIZATION='JWT ' + sts_jwt)
    drf_tsp.user = client_app.user
    return drf_tsp


@pytest.fixture
def another_client_app(request, another_org, owner):
    from velodrome.lock8.models import Affiliation, ClientApp, User

    inactive_user = User.objects.create(
        username='{}:{}'.format(another_org.uuid, request.fixturename)
    )
    Affiliation.objects.create(organization=another_org,
                               user=inactive_user,
                               role=Affiliation.ADMIN)

    remote_uuid = uuid.uuid4()
    return ClientApp.objects.create(
        name=request.fixturename,
        organization=another_org,
        scopes=[s[0] for s in ClientApp.SCOPES],
        remote_uuid=remote_uuid,
        user=inactive_user,
        owner=owner,
    )


@pytest.fixture
@decorated_drf_client
def another_drf_tsp(another_client_app, settings):
    now = timezone.now()
    payload = {'user_id': another_client_app.name,
               'iss': 'sts-dev',
               'organization': str(another_client_app.organization.uuid),
               'scopes': ['bicycle:read', 'bicycle:write'],
               'exp': now + dt.timedelta(minutes=30),
               'iat': now}
    sts_jwt = jwt.encode(payload, settings.JWT_SECRET_KEY,
                         algorithm='HS512').decode()
    drf_tsp = APIClient(HTTP_ACCEPT='application/json; version=1.0')
    drf_tsp.credentials(HTTP_AUTHORIZATION='JWT ' + sts_jwt)
    drf_tsp.user = another_client_app.user
    return drf_tsp


def test_get_booking_options(drf_tsp, bicycle_available, another_bicycle,
                             another_drf_tsp, create_gps_tracking,
                             bicycle_without_lock):

    another_bicycle.declare_available()
    create_gps_tracking(
        bicycle_available.lock, 13.403145, 52.527433,
        time_stamp=int(time.time()))
    create_gps_tracking(
        another_bicycle.lock, 13.403145, 52.527433,
        time_stamp=int(time.time()))
    # Assert 0 results on wrong mode (TAXI)
    query_params = {'mode': 'TAXI', 'startTime': 1507104729,
                    'from': "{\"lat\": 60.3210549, \"lon\": 24.9506771}"}
    response = drf_tsp.assert_success(
        reverse_query('tsp:booking-options-list', query_params),
        {'options': []})

    time_ = int(time.time())
    query_params = {
        'mode': 'BICYCLE',
        'from': "{\"lat\": 60.3210549, \"lon\": 24.9506771}",
        'startTime': time_,
    }
    response = drf_tsp.get(
        reverse_query('tsp:booking-options-list', query_params), format='json')
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {
        'options': [{
            'leg': {
                'agencyId': 'noa',
                'mode': 'BICYCLE',
                'startTime': time_,
                'endTime': time_,
                'from': {'lat': 52.527433, 'lon': 13.403145},
                'to': {'lat': 52.527433, 'lon': 13.403145}},
            'meta': {
                'MODE_BICYCLE': {},
                'noa': {
                    'bicycle_uuid': str(bicycle_available.uuid),
                    'bicycle_distance': {
                        'length': 1117151.9136145498, 'unit': 'm'
                    }
                }
            },
            'terms': {'price': {'amount': 0, 'currency': 'EUR'}},
        }]
    }

    response = another_drf_tsp.get(
        reverse_query('tsp:booking-options-list', query_params), format='json')
    assert response.status_code == status.HTTP_200_OK
    assert len(response.json()['options']) == 1
    assert response.json()['options'][0][
        'meta']['noa']['bicycle_uuid'] == str(another_bicycle.uuid)


@pytest.mark.parametrize('query_params, expected', (
    ({}, "'mode' is a required property"),
    ({'mode': 'BICYCLE'},
     "'startTime' is a required property"),
    ({'mode': 'BICYCLE', 'startTime': 1507104729},
     "'from' is a required property"),
    ({'mode': 'BICYCLE', 'startTime': 1507104729,
      'from': "{'lat': 60.3210549, 'lon': 24.9506771}"},
     "Expecting property name enclosed in double quotes"),
    ({'mode': 'BICYCLE', 'startTime': 1507104729,
      'from': "{\"lat\": 60.3210549}"},
     "'lon' is a required property"),
    ({'mode': 'BICYCLE', 'startTime': 0,
      'from': "{\"lat\": 60.3210549, \"lon\": 24.9506771}"},
     "0 is less than the minimum of 1451606400"),
    ({'mode': 'BICYCLE', 'startTime': 0,
      'from': "{\"lat\": \"60.3210549\", \"lon\": \"24.9506771\"}"},
     "0 is less than the minimum of 1451606400"),
))
def test_get_booking_options_errors(drf_tsp, query_params, expected):
    url = reverse_query('tsp:booking-options-list', query_params)
    response = drf_tsp.get(url, format='json')
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json() == {
        'detail': {
            'non_field_errors': [
                {'code': 'parse_error', 'message': expected}]
        }
    }


def test_crud_bookings(drf_tsp, axa_bicycle, create_gps_tracking, lock,
                       active_requests_mock, axalock, another_bicycle,
                       another_drf_tsp):
    from velodrome.lock8.models import RentalSession
    another_bicycle.declare_available()
    create_gps_tracking(
        another_bicycle.lock, 13.403145, 52.527433,
        time_stamp=int(time.time()))

    axa_bicycle.lock = lock
    create_gps_tracking(axa_bicycle, 13.403145, 52.527433,
                        time_stamp=int(time.time()), activate=False)
    active_requests_mock.register_uri(
        'PUT',
        axalock.remote_url + '/slots/0',
        json={
            'now': '2017-01-24T18:30:39.485940+00:00',
            'result': {
                'ekey': 'some-key',
                'modified': '2017-01-24T18:30:38.918580',
                'passkey': 'some-otps-1-2-3-4-5-6-7-8',
                'passkey_type': 'otp',
                'segmented': True,
                'sequence': 23,
                'slot_position': 1,
                'tag': None},
            "status": "success"},
    )

    time_ = int(time.time())
    payload = {
        'leg': {
            'from': {'lat': 60.3210549, 'lon': 24.9506771},
            'to': {'lat': 60.3210549, 'lon': 24.9506771},
            'startTime': time_,
            'endTime': time_,
            'mode': 'BICYCLE',
        },
        'meta': {
            'MODE_BICYCLE': {},
            'noa': {
                'bicycle_uuid': str(axa_bicycle.uuid),
            }
        },
        'customer': {
            'id': 'abc123',
            'firstName': 'Maggie',
            'lastName': 'Simpson',
            'phone': '555-0909',
            'email': 'maggie@simpsons.net',
        }
    }
    another_drf_tsp.assert_status(
        reverse_query('tsp:booking-list'), status.HTTP_404_NOT_FOUND,
        data=payload, format='json')

    response = drf_tsp.post(
        reverse_query('tsp:booking-list'), data=payload, format='json')
    assert response.status_code == status.HTTP_201_CREATED
    rental_session = RentalSession.objects.filter(
        user=drf_tsp.user, bicycle=axa_bicycle).first()

    expected = {
        'leg': {**payload['leg'], **{
            'agencyId': 'noa',
            'from': {'lat': 52.527433, 'lon': 13.403145},
            'to': {'lat': 52.527433, 'lon': 13.403145},
        }},
        'terms': {'price': {'amount': 0, 'currency': 'EUR'}},
        'token': {},
        'meta': {
            'MODE_BICYCLE': {},
            'noa': {
                'bicycle_uuid': str(axa_bicycle.uuid),
                'bicycle_distance': {
                    'length': 1117151.9136145498, 'unit': 'm',
                },
                'axa_lock': {'ekey': 'some-key',
                             'expiration': '2017-01-24T19:30:39Z',
                             'otps': ['some', 'otps', '1', '2', '3', '4', '5',
                                      '6', '7', '8']},
            }
        },
        'customer': payload['customer'],
        'tspId': str(rental_session.uuid),
    }
    assert response.json() == expected
    rental_session.refresh_from_db()
    assert rental_session.state == 'new'

    booking_url = reverse_query(
        'tsp:booking-detail', kwargs={'tspId': str(rental_session.uuid)})

    expected.pop('leg')
    expected.pop('customer')
    expected['meta']['noa'] = {'bicycle_uuid': str(axa_bicycle.uuid)}
    expected['state'] = 'ACTIVATED'
    drf_tsp.assert_success(booking_url, expected)

    another_drf_tsp.assert_403(booking_url)
    another_drf_tsp.assert_status(booking_url, status.HTTP_403_FORBIDDEN,
                                  method='delete')

    response = drf_tsp.delete(booking_url)
    assert response.status_code == status.HTTP_200_OK
    assert response.json() == {'state': 'CANCELLED'}

    rental_session.refresh_from_db()
    assert rental_session.state == 'closed'


valid_leg = {'from': {'lat': 60.1, 'lon': 50.1},
             'to': {'lat': 61.1, 'lon': 51.1},
             'startTime': 1507104729, 'endTime': 1507104729,
             'mode': 'BICYCLE'}


valid_customer = {
    'firstName': 'Joe', 'lastName': 'Doe', 'phone': '555', 'email': ''}


@pytest.mark.parametrize('payload, expected', (
    ({}, "'leg' is a required property"),
    ({'leg': 'test'}, "'test' is not valid under any of the given schemas"),
    ({'leg': valid_leg}, "'meta' is a required property"),
    ({'leg': valid_leg, 'meta': {}}, "'customer' is a required property"),
    ({'leg': valid_leg, 'meta': {}, 'customer': {}},
     "'firstName' is a required property"),
    ({'leg': valid_leg, 'meta': {}, 'customer': {'firstName': 'Joe'}},
     "'lastName' is a required property"),
    ({'leg': valid_leg, 'meta': {},
      'customer': {'firstName': 'Joe', 'lastName': 'Doe'}},
     "'phone' is a required property"),
    ({'leg': valid_leg, 'meta': {},
      'customer': {'firstName': 'Joe', 'lastName': 'Doe', 'phone': '555'}},
     "'email' is a required property"),
    ({'leg': valid_leg, 'customer': valid_customer, 'meta': {}},
     {'detail': {
         'MODE_BICYCLE': [{'code': 'required',
                           'message': 'This field is required.'}],
         'noa': [{'code': 'required', 'message': 'This field is required.'}]}}
     ),
    ({'leg': valid_leg, 'customer': valid_customer,
      'meta': {'MODE_BICYCLE': {}}},
     {'detail': {
         'noa': [{'code': 'required', 'message': 'This field is required.'}]}}
     ),
    ({'leg': valid_leg, 'customer': valid_customer,
      'meta': {'noa': {}}},
     {'detail': {
         'MODE_BICYCLE': [{'code': 'required',
                           'message': 'This field is required.'}],
         'noa': {'bicycle_uuid': [{'code': 'required',
                                   'message': 'This field is required.'}]}}}
     ),
))
def test_create_booking_errors(drf_tsp, payload, expected):
    def assert_error(error, expected):
        if isinstance(expected, str):
            assert error == {'detail': {
                'non_field_errors': [
                    {'code': 'parse_error', 'message': expected}]
                }
            }
        else:
            assert error == expected

    url = reverse_query('tsp:booking-list')
    response = drf_tsp.post(url, data=payload, format='json')
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert_error(response.json(), expected)


def test_tsp_security(drf_client, drf_tsp, drf_alice):
    calls = (
        ('get', reverse_query('tsp:booking-options-list')),
        ('get',
         reverse_query('tsp:booking-detail', kwargs={'tspId': 'invaliduuid'})),
        ('delete',
         reverse_query('tsp:booking-detail', kwargs={'tspId': 'invaliduuid'})),
    )
    client_status_pairs = (
        (drf_client, calls, status.HTTP_401_UNAUTHORIZED),
        (drf_alice, calls, status.HTTP_403_FORBIDDEN),
        (drf_tsp, calls, status.HTTP_400_BAD_REQUEST),
    )
    for client, calls, http_status in client_status_pairs:
        for call in calls:
            method, url = call
            client.assert_status(url, http_status, method=method)

    calls = (
        ('post', reverse_query('tsp:booking-options-list')),
        ('put', reverse_query('tsp:booking-options-list')),
        ('delete', reverse_query('tsp:booking-options-list')),
        ('put',
         reverse_query('tsp:booking-detail', kwargs={'tspId': 'invaliduuid'})),
        ('patch',
         reverse_query('tsp:booking-detail', kwargs={'tspId': 'invaliduuid'})),
    )
    client_status_pairs = (
        (drf_client, calls, status.HTTP_401_UNAUTHORIZED),
        (drf_alice, calls, status.HTTP_403_FORBIDDEN),
        (drf_tsp, calls, status.HTTP_404_NOT_FOUND),
    )
    for client, calls, http_status in client_status_pairs:
        for call in calls:
            method, url = call
            client.assert_status(url, http_status, method=method)
