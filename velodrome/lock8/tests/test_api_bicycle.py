import datetime as dt
import itertools
import urllib.parse
import uuid

from django.contrib.gis.geos.collections import MultiPolygon, Point, Polygon
from django.core.cache import caches
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from freezegun import freeze_time
import jwt
import pytest
from rest_framework import status

from velodrome.lock8.models import DSS_FIELDS, TRACKING_FIELDS
from velodrome.lock8.utils import reverse_query


def test_crud_on_bicycle(drf_fleet_operator, owner, org, city_bike,
                         bicycle_model, lock, photo, create_dss_tracking):
    from velodrome.lock8.models import Bicycle

    url = reverse_query('lock8:bicycle-list')
    bicycle_type_url = reverse_query('lock8:bicycle_type-detail',
                                     kwargs={'uuid': city_bike.uuid})
    bicycle_model_url = reverse_query('lock8:bicycle_model-detail',
                                      kwargs={'uuid': bicycle_model.uuid})
    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})

    response = drf_fleet_operator.post(url, data={
        'name': 'Bicycle',
        'description': 'Bla\nBla',
        'model': bicycle_model_url,
        'organization': organization_url,
    })
    assert response.status_code == status.HTTP_201_CREATED, response.data

    bike_uuid = response.data['uuid']
    bicycle = Bicycle.objects.get(uuid=bike_uuid)

    assert response.data == {
        'uuid': bike_uuid,
        'name': 'Bicycle',
        'note': None,
        'description': 'Bla\nBla',
        'model': 'http://testserver' + bicycle_model_url,
        'bleid': None,
        'device_type': None,
        'lock': None,
        'image_url': None,
        'latest_gps_timestamp': None,
        'latitude': None,
        'longitude': None,
        'latest_gps_accuracy': None,
        'latest_gps_pdop': None,
        'estimated_state_of_charge': None,
        'state_of_charge': None,
        'last_cellular_update': None,
        'bicycle_model_name': 'bicycle_model',
        'organization': 'http://testserver' + organization_url,
        'devices': {},
        'distance': None,
        'url': 'http://testserver' + reverse_query('lock8:bicycle-detail',
                                                   kwargs={'uuid': bike_uuid}),
        'state': 'in_maintenance',
        'concurrency_version': bicycle.concurrency_version,
        'serial_number': '',
        'reservation': None,
        'rental_session': None,
        'modified': bicycle.modified.isoformat()[:-13] + 'Z',
        'created': bicycle.created.isoformat()[:-13] + 'Z',
        'short_id': bicycle.short_id,
        'tags': [],
    }

    # name is mandatory
    response = drf_fleet_operator.post(url, data={
        'description': 'Bla\nBla',
        'type': bicycle_type_url,
        'organization': organization_url,
    })
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data['detail']['name'] == [
        {'message': 'This field is required.',
         'code': 'required'}]

    # check bicycle in list
    url = reverse_query('lock8:bicycle-list')
    response = drf_fleet_operator.assert_success(url)
    assert len(response.data['results']) == 1

    # assign the lock
    lock.provision()
    bicycle.lock = lock
    bicycle.save()

    create_dss_tracking(bicycle, 98.587890625,
                        activate=False,
                        attributes={'voltage': 4320,
                                    'firmware_version_tag': '1.1.3'})

    detail_url = reverse_query('lock8:bicycle-detail',
                               kwargs={'uuid': bike_uuid})
    response = drf_fleet_operator.assert_success(detail_url)
    assert response.data['bleid'] == lock.bleid
    assert response.data['state_of_charge'] is None

    # assign the photo
    bicycle_model.photo = photo
    bicycle_model.save()
    bicycle.model = bicycle_model
    bicycle.save()

    response = drf_fleet_operator.assert_success(detail_url)
    assert response.data['image_url'].startswith(
        'http://127.0.0.1:8000/photos/')

    # modify the bicycle
    response = drf_fleet_operator.patch(detail_url, data={'name': 'Bike-2'})
    assert response.status_code == status.HTTP_200_OK
    assert response.data['name'] == 'Bike-2'

    # activate the lock
    lock.activate()
    response = drf_fleet_operator.assert_success(detail_url)
    assert response.data['state_of_charge'] is None

    # delete the bicycle
    response = drf_fleet_operator.delete(detail_url)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    with pytest.raises(Bicycle.DoesNotExist):
        bicycle.refresh_from_db()

    # check bicycle not in list
    url = reverse_query('lock8:bicycle-list')
    response = drf_fleet_operator.assert_success(url)
    assert not response.data['results']


def test_operator_cannot_create_bicycle_in_another_org(
        drf_another_fleet_operator, org):
    from velodrome.lock8.models import Bicycle

    url = reverse_query('lock8:bicycle-list')
    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})

    response = drf_another_fleet_operator.post(url, data={
        'name': 'Bicycle',
        'organization': organization_url,
    })
    assert not Bicycle.objects.count()
    assert response.status_code == status.HTTP_403_FORBIDDEN, response.data


def test_operator_cannot_update_bicycle_in_another_org(
        drf_another_fleet_operator, another_bicycle, org):
    url = reverse_query('lock8:bicycle-detail',
                        kwargs={'uuid': another_bicycle.uuid})
    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})

    response = drf_another_fleet_operator.patch(url, data={
        'organization': organization_url,
    })
    assert response.status_code == status.HTTP_403_FORBIDDEN, response.data


def test_crud_on_bicycle_tracking(drf_fleet_operator, bicycle, active_lock,
                                  create_gps_tracking):
    create_gps_tracking(active_lock, 13.403145, 52.527433,
                        attributes={'gps_utm_zone': -7.530941473730957e-14,
                                    'gps_accuracy': 30807.1328125,
                                    'time_stamp': 1428509326})
    bicycle.refresh_from_db()
    bicycle.public_tracking.refresh_from_db()

    url = reverse_query('lock8:bicycle-detail',
                        kwargs={'uuid': bicycle.uuid})
    response = drf_fleet_operator.assert_success(url)
    assert response.data['latitude'] == 52.527433, response.data
    assert response.data['longitude'] == 13.403145
    assert response.data['latest_gps_accuracy'] == 30807.1328125
    assert response.data['latest_gps_timestamp'] == '2015-04-08T16:08:46Z'


def test_bicycle_locked_status(drf_fleet_operator, bicycle):
    bicycle.refresh_from_db()
    url = reverse_query('lock8:bicycle-bicycle-lock-status', kwargs={'uuid': bicycle.uuid})
    response = drf_fleet_operator.post(url, {'locked': True})
    print(response.data)
    assert response.status_code == status.HTTP_206_PARTIAL_CONTENT
    bicycle.refresh_from_db()
    assert bicycle.locked == True

    response = drf_fleet_operator.post(url, {'locked': False})
    assert response.status_code == status.HTTP_206_PARTIAL_CONTENT
    bicycle.refresh_from_db()
    assert bicycle.locked == False


def test_bicycle_creation_with_lock(drf_fleet_operator, owner, org,
                                    bicycle_model, lock):
    url = reverse_query('lock8:bicycle-list')
    lock.provision()
    bicycle_model_url = reverse_query('lock8:bicycle_model-detail',
                                      kwargs={'uuid': bicycle_model.uuid})
    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})
    lock_url = reverse_query('lock8:lock-detail',
                             kwargs={'uuid': lock.uuid})

    response = drf_fleet_operator.post(url, data={
        'name': 'Bicycle',
        'description': 'Bla\nBla',
        'model': bicycle_model_url,
        'organization': organization_url,
        'lock': lock_url,
    })
    assert response.status_code == status.HTTP_201_CREATED, response.data


def test_bicycle_creation_with_axa_lock(drf_fleet_operator, owner, org,
                                        bicycle_model, axalock):
    from velodrome.lock8.models import Bicycle

    url = reverse_query('lock8:bicycle-list')
    bicycle_model_url = reverse_query('lock8:bicycle_model-detail',
                                      kwargs={'uuid': bicycle_model.uuid})
    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})
    axalock_url = reverse_query('lock8:axa_lock-detail',
                                kwargs={'uuid': axalock.uuid})

    response = drf_fleet_operator.post(url, data={
        'name': 'Bicycle',
        'description': 'Bla\nBla',
        'model': bicycle_model_url,
        'organization': organization_url,
        'axa_lock': axalock_url,
    })
    assert response.status_code == status.HTTP_201_CREATED, response.data
    bicycle = Bicycle.objects.get()
    assert bicycle.axa_lock == axalock


def test_bicycle_pairing_with_axa_lock_error(drf_fleet_operator, bicycle,
                                             axalock):
    url = reverse_query('lock8:bicycle-detail', kwargs={'uuid': bicycle.uuid})
    axalock_url = reverse_query('lock8:axa_lock-detail',
                                kwargs={'uuid': axalock.uuid})

    bicycle.declare_available()
    response = drf_fleet_operator.patch(url, data={
        'axa_lock': axalock_url,
    })
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.parametrize('with_tracking,count', [*itertools.product(
    (True, False), (0, 1))])
def test_bicycle_stats(drf_fleet_operator, bicycle, mocked_ddb, mocker,
                       create_gps_tracking, active_lock, with_tracking, count):
    url = reverse_query('lock8:bicycle-stats', kwargs={'uuid': bicycle.uuid})

    table = mocker.Mock()
    table.query.return_value = {
        'Count': count,
        'Items': [{
            'distance': 10.123,
        }]}

    mocked_ddb.Table.return_value = table
    if with_tracking:
        create_gps_tracking(bicycle, 1, 2)
        bicycle.refresh_from_db()

    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_200_OK, response.data
    assert response.data == {
        'total_distance': 10 if count else 0,
        'last_cellular_update': (bicycle
                                 .public_tracking
                                 .modified.isoformat()[:-13] + 'Z'
                                 if with_tracking else None)}


def test_transitions_on_bicycle(drf_fleet_operator, drf_alice, owner,
                                fleet_operator, org, bicycle, alice,
                                renting_scheme, lock, axalock, caplog):
    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})
    lock_url = reverse_query('lock8:lock-detail',
                             kwargs={'uuid': lock.uuid})
    axa_lock_url = reverse_query('lock8:axa_lock-detail',
                                 kwargs={'uuid': axalock.uuid})
    bicycle_url = reverse_query('lock8:bicycle-detail',
                                kwargs={'uuid': bicycle.uuid})
    alice_url = reverse_query('lock8:user-detail',
                              kwargs={'uuid': str(alice.uuid)})

    bicycle.axa_lock = axalock
    bicycle.save()

    org.is_open_fleet = True
    org.save()

    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle.uuid})
    response = drf_fleet_operator.post(url, data={'type': 'declare_available'})
    assert response.status_code == status.HTTP_200_OK
    assert response.data['state'] == 'available'

    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle.uuid})
    response = drf_fleet_operator.post(url,
                                       data={'type': 'put_in_maintenance'})
    assert response.status_code == status.HTTP_200_OK
    assert response.data['state'] == 'in_maintenance'

    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle.uuid})
    response = drf_fleet_operator.post(url, data={'type': 'declare_lost'})
    assert response.status_code == status.HTTP_200_OK
    assert response.data['state'] == 'lost'

    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle.uuid})
    response = drf_fleet_operator.post(url, data={'type': 'declare_available'})
    assert response.status_code == status.HTTP_200_OK
    assert response.data['state'] == 'available'

    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle.uuid})
    response = drf_fleet_operator.post(url, data={'type': 'reserve',
                                                  'user': alice_url})
    assert response.status_code == status.HTTP_200_OK
    assert response.data['state'] == 'reserved'
    bicycle.refresh_from_db()

    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle.uuid})
    response = drf_fleet_operator.post(url,
                                       data={'type': 'cancel_reservation'})
    assert response.status_code == status.HTTP_200_OK
    assert response.data['state'] == 'available'
    bicycle.refresh_from_db()

    # without user parameter, fallback on current user (by).
    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle.uuid})
    response = drf_alice.post(url, data={'type': 'reserve'})
    assert response.status_code == status.HTTP_200_OK, response.data
    bicycle.refresh_from_db()
    bicycle.cancel_reservation()

    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle.uuid})
    response = drf_alice.post(url, data={'type': 'reserve',
                                         'user': alice_url})
    assert response.status_code == status.HTTP_200_OK
    assert response.data['state'] == 'reserved'
    bicycle.refresh_from_db()
    reservation = bicycle.active_reservation

    url = reverse_query('lock8:bicycle-detail',
                        {'assignee': str(alice.uuid)},
                        {'uuid': bicycle.uuid})
    reservation_url = reverse_query('lock8:reservation-detail',
                                    kwargs={'uuid': reservation.uuid})
    response = drf_alice.assert_success(url)
    assert response.data == {
        'uuid': str(bicycle.uuid),
        'name': 'bicycle',
        'note': None,
        'description': '',
        'model': None,
        'bleid': lock.bleid,
        'device_type': 'lock',
        'lock': 'http://testserver' + lock_url,
        'image_url': None,
        'latest_gps_timestamp': None,
        'latitude': None,
        'longitude': None,
        'latest_gps_accuracy': None,
        'latest_gps_pdop': None,
        'estimated_state_of_charge': None,
        'state_of_charge': None,
        'last_cellular_update': None,
        'bicycle_model_name': None,
        'organization': 'http://testserver' + organization_url,
        'url': 'http://testserver' + reverse_query(
            'lock8:bicycle-detail',
            kwargs={'uuid': str(bicycle.uuid)}),
        'state': 'reserved',
        'concurrency_version': bicycle.concurrency_version,
        'serial_number': 'bicycle',
        'reservation': {
            'url': 'http://testserver' + reservation_url,
            'uuid': str(reservation.uuid),
            'user': 'http://testserver' + alice_url,
            'bicycle': 'http://testserver' + bicycle_url,
            'duration': renting_scheme.max_reservation_duration.seconds,
            'state': 'new',
            'concurrency_version': reservation.concurrency_version,
            'created': reservation.created.isoformat()[:-13] + 'Z',
            'modified': reservation.modified.isoformat()[:-13] + 'Z',
        },
        'rental_session': None,
        'devices': {
            'tracker': {
                'bleid': lock.bleid,
                'url': 'http://testserver' + lock_url,
                'manufacturer': 'noa',
                'paired_at': bicycle.lock.paired_at.isoformat()[:-13] + 'Z',
            },
            'lock': {
                'manufacturer': 'axa',
                'url': 'http://testserver' + axa_lock_url,
                'bleid': 'AXA:134D90B794994B6753E7',
                'paired_at': bicycle.axa_lock.paired_at.isoformat()[:-13] + 'Z',  # noqa: E501
            }
        },
        'distance': None,
        'modified': bicycle.modified.isoformat()[:-13] + 'Z',
        'created': bicycle.created.isoformat()[:-13] + 'Z',
        'short_id': bicycle.short_id,
        'tags': [],
    }

    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle.uuid})
    response = drf_alice.post(url, data={'type': 'rent',
                                         'user': alice_url})
    assert response.status_code == status.HTTP_200_OK, response.data
    assert response.data['state'] == 'rented'
    bicycle.refresh_from_db()

    rental_session = bicycle.active_rental_session
    rental_session_url = reverse_query('lock8:rental_session-detail',
                                       kwargs={'uuid': rental_session.uuid})

    url = reverse_query('lock8:bicycle-detail',
                        {'assigned_to': str(alice.uuid)},
                        {'uuid': bicycle.uuid})
    drf_alice.assert_success(url, {
        'uuid': str(bicycle.uuid),
        'name': 'bicycle',
        'note': None,
        'description': '',
        'model': None,
        'bleid': lock.bleid,
        'device_type': 'lock',
        'lock': 'http://testserver' + lock_url,
        'image_url': None,
        'latest_gps_timestamp': None,
        'latitude': None,
        'longitude': None,
        'latest_gps_accuracy': None,
        'latest_gps_pdop': None,
        'estimated_state_of_charge': None,
        'state_of_charge': None,
        'last_cellular_update': None,
        'bicycle_model_name': None,
        'organization': 'http://testserver' + organization_url,
        'url': 'http://testserver' + reverse_query(
            'lock8:bicycle-detail',
            kwargs={'uuid': str(bicycle.uuid)}),
        'state': 'rented',
        'concurrency_version': bicycle.concurrency_version,
        'serial_number': 'bicycle',
        'reservation': None,
        'rental_session': {
            'url': 'http://testserver' + rental_session_url,
            'uuid': str(rental_session.uuid),
            'user': 'http://testserver' + alice_url,
            'duration_of_rental_session': None,
            'cents': None,
            'currency': None,
            'subscription_plan': None,
            'pricing_scheme': None,
            'created': rental_session.created.isoformat()[:-13] + 'Z',
            'state': 'new',
            'concurrency_version': rental_session.concurrency_version,
            'bicycle': 'http://testserver' + bicycle_url,
            'modified': rental_session.modified.isoformat()[:-13] + 'Z',
        },
        'devices': {
            'tracker': {
                'bleid': lock.bleid,
                'url': 'http://testserver' + lock_url,
                'manufacturer': 'noa',
                'paired_at': bicycle.lock.paired_at.isoformat()[:-13] + 'Z',
            },
            'lock': {
                'manufacturer': 'axa',
                'url': 'http://testserver' + axa_lock_url,
                'bleid': 'AXA:134D90B794994B6753E7',
                'paired_at': bicycle.axa_lock.paired_at.isoformat()[:-13] + 'Z',  # noqa: E501
            }},
        'distance': None,
        'modified': bicycle.modified.isoformat()[:-13] + 'Z',
        'created': bicycle.created.isoformat()[:-13] + 'Z',
        'short_id': bicycle.short_id,
        'tags': [],
    })

    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle.uuid})
    response = drf_alice.post(url, data={'type': 'return'})
    assert response.status_code == status.HTTP_200_OK
    assert response.data['state'] == 'available'

    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle.uuid})
    response = drf_fleet_operator.post(url, data={'type': 'reserve',
                                                  'user': alice_url,
                                                  'duration': 8 * 60})
    assert response.status_code == status.HTTP_200_OK, response.data
    assert response.data['state'] == 'reserved'
    assert response.data['reservation']

    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle.uuid})
    response = drf_fleet_operator.post(url, data={'type': 'rent',
                                                  'user': alice_url})
    assert response.status_code == status.HTTP_200_OK, response.data
    assert response.data['state'] == 'rented'
    assert response.data['rental_session']

    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle.uuid})
    response = drf_fleet_operator.post(url, data={'type': 'return'})
    assert response.status_code == status.HTTP_200_OK, response.data
    assert response.data['state'] == 'available'

    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle.uuid})
    response = drf_fleet_operator.post(url,
                                       data={'type': 'put_in_maintenance'})
    assert response.status_code == status.HTTP_200_OK, response.data
    assert response.data['state'] == 'in_maintenance'

    response = drf_fleet_operator.post(url, data={'type': 'retire'})
    assert response.status_code == status.HTTP_400_BAD_REQUEST, response.data
    assert response.data == {
        'detail': {'non_field_errors': [
            {'code': 'invalid',
             'message': 'Lock must be unpaired before retiring this Bicycle.'}
        ]}}

    bicycle.refresh_from_db()
    bicycle.lock = None
    bicycle.save()

    response = drf_fleet_operator.post(url, data={'type': 'retire'})
    assert response.status_code == status.HTTP_400_BAD_REQUEST, response.data
    assert response.data == {
        'detail': {'non_field_errors': [
            {'code': 'invalid',
             'message': 'Axa Lock must be unpaired before retiring'
                        ' this Bicycle.'}
        ]}}

    bicycle.refresh_from_db()
    bicycle.axa_lock = None
    bicycle.save()

    response = drf_fleet_operator.post(url, data={'type': 'retire'})
    assert response.data['state'] == 'retired', response.data

    assert caplog.record_tuples[-1] == (
        'velodrome.lock8.views', 20,
        'Calling action retire for Bicycle %s: dry_run=0, by=%s' % (
            bicycle.uuid, drf_fleet_operator.user.uuid))


def test_state_security_for_bicycle(drf_fleet_operator, drf_alice,
                                    fleet_operator, org, alice, bicycle, bob):
    from velodrome.lock8.models import Affiliation

    Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.RENTER)

    url = reverse_query('lock8:bicycle-list')
    drf_alice.assert_count(url, 0)

    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle.uuid})
    response = drf_fleet_operator.post(url, data={'type': 'declare_available'})
    assert response.status_code == status.HTTP_200_OK, response.data
    assert response.data['state'] == 'available'

    url = reverse_query('lock8:bicycle-list')
    drf_alice.assert_count(url, 1)

    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle.uuid})
    response = drf_fleet_operator.post(url,
                                       data={'type': 'put_in_maintenance'})
    assert response.status_code == status.HTTP_200_OK
    assert response.data['state'] == 'in_maintenance'

    url = reverse_query('lock8:bicycle-list')
    drf_alice.assert_count(url, 0)

    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle.uuid})
    response = drf_fleet_operator.post(url, data={'type': 'declare_lost'})
    assert response.status_code == status.HTTP_200_OK
    assert response.data['state'] == 'lost'

    url = reverse_query('lock8:bicycle-list')
    drf_alice.assert_count(url, 0)

    bicycle.refresh_from_db()
    bicycle.declare_available()
    bicycle.reserve(user=bob, by=fleet_operator)

    url = reverse_query('lock8:bicycle-list')
    drf_alice.assert_count(url, 0)

    bicycle.rent(user=bob, by=fleet_operator)

    url = reverse_query('lock8:bicycle-list')
    drf_alice.assert_count(url, 0)


def test_bicycle_list_closed_fleet(drf_alice, org, alice, bicycle, bob):
    from velodrome.lock8.models import Affiliation

    bicycle.declare_available()

    url = reverse_query('lock8:bicycle-list')
    drf_alice.assert_count(url, 0)

    org.is_open_fleet = True
    org.save()

    drf_alice.assert_count(url, 1)

    org.is_open_fleet = False
    org.save()

    Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.RENTER)

    url = reverse_query('lock8:bicycle-list')
    drf_alice.assert_count(url, 1)


def test_bicycle_list_open_fleet_anonymous(drf_client, org, bicycle):
    org.is_open_fleet = True
    org.save()

    url = reverse_query('lock8:bicycle-list')
    drf_client.assert_count(url, 0)

    bicycle.declare_available()

    drf_client.assert_count(url, 1)


def test_bicycle_list_closed_fleet_anonymous(drf_client, org, bicycle):
    url = reverse_query('lock8:bicycle-list')
    drf_client.assert_count(url, 0)

    bicycle.declare_available()

    drf_client.assert_count(url, 0)


def test_bicycle_list_when_fleet_operator_and_renter(drf_alice, org, alice,
                                                     bicycle, another_org,
                                                     another_bicycle):
    from velodrome.lock8.models import Affiliation

    Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.FLEET_OPERATOR,
    )
    Affiliation.objects.create(
        user=alice,
        organization=another_org,
        role=Affiliation.RENTER,
    )

    another_bicycle.declare_available()

    url = reverse_query('lock8:bicycle-list')
    drf_alice.assert_count(url, 2)

    url = reverse_query('lock8:bicycle-list',
                        {'organization': org.uuid})
    drf_alice.assert_count(url, 1)

    url = reverse_query('lock8:bicycle-list',
                        {'organization': another_org.uuid})
    drf_alice.assert_count(url, 1)


def test_bicycle_list_when_renter(drf_renter, renter, bicycle):
    bicycle.declare_available()
    bicycle.rent(by=renter)

    url = reverse_query('lock8:bicycle-list')
    drf_renter.assert_count(url, 1)


def test_bicycle_list_when_hidden(drf_client, drf_renter, drf_fleet_operator,
                                  renter, bicycle, bicycle_model, org):
    bicycle.model = bicycle_model
    org.is_open_fleet = True
    org.save()

    bicycle.declare_available()
    url = reverse_query('lock8:bicycle-list')

    drf_client.assert_count(url, 1)
    drf_renter.assert_count(url, 1)
    drf_fleet_operator.assert_count(url, 1)

    bicycle.model.hidden = True
    bicycle.model.save()

    drf_client.assert_count(url, 0)
    drf_renter.assert_count(url, 0)
    drf_fleet_operator.assert_count(url, 1)


def test_bicycle_admin_actions_when_hidden(drf_renter, drf_fleet_operator,
                                           bicycle, bicycle_model, org):
    bicycle.model = bicycle_model
    org.is_open_fleet = True
    org.save()
    bicycle.model.hidden = True
    bicycle.model.save()

    url = reverse_query('lock8:bicycle-actions', kwargs={'uuid': bicycle.uuid})

    action = 'declare_available'
    drf_fleet_operator.assert_success(url, data={'type': action})
    drf_renter.assert_403(url, data={'type': action})

    action = 'put_in_maintenance'
    drf_fleet_operator.assert_success(url, data={'type': action})
    drf_renter.assert_404(url, data={'type': action})

    action = 'declare_lost'
    drf_fleet_operator.assert_success(url, data={'type': action})
    drf_renter.assert_404(url, data={'type': action})


def test_bicycle_actions_when_hidden(drf_renter, bicycle_model, bicycle,
                                     drf_fleet_operator, org):
    bicycle.model = bicycle_model
    org.is_open_fleet = True
    org.save()
    bicycle.declare_available()
    bicycle.model.hidden = True
    bicycle.model.save()

    url = reverse_query('lock8:bicycle-actions', kwargs={'uuid': bicycle.uuid})
    renter_actions = ('reserve', 'cancel_reservation', 'reserve', 'rent')
    for action in renter_actions:
        drf_renter.assert_404(url, data={'type': action})
        drf_fleet_operator.assert_success(url, data={'type': action})


@pytest.mark.parametrize('param,query_count', (
        ('drf_fleet_operator', 13), ('drf_admin', 13), ('drf_renter', 12),
        ('with_another_bicycle', 14)))
def test_bicycle_list_number_of_queries_base(request, param, query_count,
                                             bicycle, bicycle_model, photo,
                                             gps_tracking, dss_tracking):
    if param == 'with_another_bicycle':
        drf_client = request.getfixturevalue('drf_fleet_operator')
        request.getfixturevalue('bicycle2')
        expected_count = 2
    else:
        drf_client = request.getfixturevalue(param)
        expected_count = 1
    drf_client.use_jwt_auth()
    bicycle_model.photo = photo
    bicycle_model.save()
    bicycle.refresh_from_db()
    bicycle.model = bicycle_model
    bicycle.save()

    url = reverse_query('lock8:bicycle-list')
    with CaptureQueriesContext(connection) as capture:
        drf_client.assert_count(url, expected_count)
    assert len(capture.captured_queries) == query_count, '\n\n'.join(
        q['sql'] for q in capture.captured_queries)


def test_bicycle_list_number_of_queries_with_list_filters(drf_fleet_operator,
                                                          bicycle):
    drf_fleet_operator.use_jwt_auth()

    url = reverse_query('lock8:bicycle-list', {'fields': 'name'})
    with CaptureQueriesContext(connection) as capture:
        drf_fleet_operator.assert_count(url, 1)
    assert len(capture.captured_queries) == 9, '\n\n'.join(
        q['sql'] for q in capture.captured_queries)


@pytest.fixture(params=TRACKING_FIELDS)
def dss_or_gps_field(request, bicycle):
    if request.param in DSS_FIELDS:
        request.getfixturevalue('dss_tracking')
    else:
        request.getfixturevalue('gps_tracking')
    return request.param


def test_bicycle_list_number_of_queries_with_field(dss_or_gps_field,
                                                   drf_fleet_operator):
    drf_fleet_operator.use_jwt_auth()

    url = reverse_query('lock8:bicycle-list', {'fields': dss_or_gps_field})
    with CaptureQueriesContext(connection) as capture:
        drf_fleet_operator.assert_count(url, 1)
    assert len(capture.captured_queries) == 9, '\n\n'.join(
        q['sql'] for q in capture.captured_queries)


def test_filtering_on_bicycle(drf_alice, drf_fleet_operator, fleet_operator,
                              bicycle, org, owner, another_org, alice, bob,
                              active_lock, create_gps_tracking,
                              create_dss_tracking):
    from velodrome.lock8.models import Bicycle

    url = reverse_query('lock8:bicycle-list', {'state': 'in_maintenance'})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:bicycle-list', {'state': 'reserved'})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:bicycle-list',
                        {'organization': str(another_org.uuid)})
    response = drf_fleet_operator.assert_success(url)
    assert len(response.data['results']) == 0

    bicycle_2 = Bicycle.objects.create(name='bb',
                                       organization=org,
                                       owner=owner)
    with freeze_time(timezone.now() + dt.timedelta(seconds=1)):
        bicycle_2.declare_lost()

    url = reverse_query('lock8:bicycle-list') + '?' + urllib.parse.urlencode(
        {'state': 'in_maintenance'}) + '&' + urllib.parse.urlencode(
        {'state': 'lost'}
    )
    drf_fleet_operator.assert_count(url, 2)

    url = reverse_query('lock8:bicycle-list', {'name': 'NOT A BIKE'})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:bicycle-list',
                        {'name': bicycle.name[:-1].upper()})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:bicycle-list', {'assignee': str(alice.uuid)})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:bicycle-list',
                        {'modified_since': bicycle.modified.timestamp()})
    drf_fleet_operator.assert_count(url, 2)

    url = reverse_query('lock8:bicycle-list',
                        {'modified_since': bicycle_2.modified.timestamp()})
    drf_fleet_operator.assert_count(url, 1)

    timestamp = timezone.now() + dt.timedelta(seconds=2)
    with freeze_time(timestamp):
        create_gps_tracking(active_lock, 13.403145, 52.527433)
    with freeze_time(timestamp + dt.timedelta(seconds=1)):
        create_dss_tracking(active_lock, 50.)

    tstamp = (timestamp - dt.timedelta(seconds=1.2)).timestamp()
    url = reverse_query('lock8:bicycle-list', {'modified_since': tstamp})
    drf_fleet_operator.assert_count(url, 1)

    bbox_points1 = {'bbox': '13.3683645,52.5062991,13.4240352,52.5390943'}
    url = reverse_query('lock8:bicycle-list', bbox_points1)
    drf_fleet_operator.assert_count(url, 1)

    bbox_points2 = {'bbox': '-0.0903313,51.5106892,-0.09256,51.50701'}
    url = reverse_query('lock8:bicycle-list', bbox_points2)
    drf_fleet_operator.assert_count(url, 0)

    bicycle.refresh_from_db()
    bicycle.reserve(by=alice, user=alice)

    url = reverse_query('lock8:bicycle-list', {'assignee': str(alice.uuid)})
    drf_alice.assert_count(url, 1)

    bicycle.rent(by=alice, user=alice)

    drf_alice.assert_count(url, 1)

    bicycle.return_()

    drf_alice.assert_count(url, 0)

    url = reverse_query('lock8:bicycle-list', {'short_id': bicycle.short_id})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:bicycle-list', {'short_id': 'anything'})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:bicycle-list', {'device_type': 'tracker'})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:bicycle-list', {'device_type': 'lock'})
    drf_fleet_operator.assert_count(url, 1)


def test_filtering_on_bicycle_assignee_non_matching_uuid(
        drf_fleet_operator, fleet_operator, bicycle, non_matching_uuid):
    url = reverse_query('lock8:bicycle-list', {'assignee': non_matching_uuid})
    drf_fleet_operator.assert_count(url, 0)


def test_filtering_on_bicycle_bbox_failure(drf_fleet_operator):
    bbox_points = {'bbox': ',,,'}
    url = reverse_query('lock8:bicycle-list', bbox_points)
    drf_fleet_operator.assert_400(url, {
        'bbox': [{'code': 'invalid',
                  'message': 'value must be a comma separated list of '
                             'floats'}]})

    bbox_points1 = {'bbox': '13.3683645,52.5062991,13.4240352,52.5390943'}
    url = reverse_query('lock8:bicycle-list', bbox_points1)
    drf_fleet_operator.assert_count(url, 0)

    # Infinity is still valid float value, but not valid lat/lon
    bbox_points2 = {'bbox': 'Infinity,Infinity,-Infinity,-Infinity'}
    url = reverse_query('lock8:bicycle-list', bbox_points2)
    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_400_BAD_REQUEST, response


def test_filtering_bicycle_on_created_after(drf_admin, yesterday, bicycle,
                                            today, another_bicycle):
    assert yesterday <= bicycle.created < today <= another_bicycle.created

    url = reverse_query('lock8:bicycle-list', {
        'created_after': today.timestamp() + 1})
    drf_admin.assert_count(url, 0)

    url = reverse_query('lock8:bicycle-list', {
        'created_after': yesterday.timestamp() + 1})
    drf_admin.assert_count(url, 1)

    url = reverse_query('lock8:bicycle-list', {
        'created_after': (yesterday.timestamp() - 1)})
    drf_admin.assert_count(url, 2)


def test_filtering_bicycle_on_alerts(drf_fleet_operator, bicycle_without_lock,
                                     org, bicycle_model):
    from velodrome.lock8.models import Affiliation, Alert

    url = reverse_query('lock8:bicycle-list', {'with_alerts': 'false'})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:bicycle-list', {'with_alerts': 'true'})
    drf_fleet_operator.assert_count(url, 0)

    alert = Alert.objects.create(
        organization=org,
        alert_type=Alert.RIDE_OUTSIDE_SERVICE_AREA,
        roles=[Affiliation.FLEET_OPERATOR],
        causality=bicycle_without_lock,
    )
    drf_fleet_operator.assert_count(url, 1)

    alert.stop()

    drf_fleet_operator.assert_count(url, 0)


def test_filtering_bicycle_on_alert_type(drf_fleet_operator, bicycle, org):
    from velodrome.lock8.models import Affiliation, Alert

    url = reverse_query('lock8:bicycle-list',
                        {'alert_type': Alert.RIDE_OUTSIDE_SERVICE_AREA})
    drf_fleet_operator.assert_count(url, 0)

    alert = Alert.objects.create(
        organization=org,
        alert_type=Alert.RIDE_OUTSIDE_SERVICE_AREA,
        roles=[Affiliation.FLEET_OPERATOR],
        causality=bicycle,
    )
    drf_fleet_operator.assert_count(url, 1)

    alert.stop()

    drf_fleet_operator.assert_count(url, 0)


def test_filtering_bicycle_on_alert_from_lock(drf_fleet_operator, bicycle,
                                              org):
    from velodrome.lock8.models import Affiliation, Alert

    url = reverse_query('lock8:bicycle-list', {'with_alerts': 'true'})
    drf_fleet_operator.assert_count(url, 0)

    Alert.objects.create(
        organization=org,
        alert_type=Alert.LOW_BATTERY,
        roles=[Affiliation.FLEET_OPERATOR],
        causality=bicycle.lock,
    )
    drf_fleet_operator.assert_count(url, 1)


def test_filtering_bicycle_on_model(drf_fleet_operator, bicycle, org,
                                    bicycle_model, non_matching_uuid,
                                    another_bicycle_model, another_bicycle,
                                    ):
    bicycle.model = bicycle_model
    bicycle.save()

    another_bicycle.model = another_bicycle_model
    another_bicycle.save()

    url = reverse_query('lock8:bicycle-list', {'model': non_matching_uuid})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:bicycle-list', {'model': bicycle_model.uuid})
    drf_fleet_operator.assert_count(url, 1)

    url = (reverse_query('lock8:bicycle-list') + f'?model={bicycle_model.uuid}'
                                                 f'&model={another_bicycle_model.uuid}')
    drf_fleet_operator.assert_count(url, 1)

    another_bicycle.organization = org
    another_bicycle_model.organization = org
    another_bicycle_model.save()
    another_bicycle.save()
    url = (reverse_query('lock8:bicycle-list') + f'?model={bicycle_model.uuid}'
                                                 f'&model={another_bicycle_model.uuid}')
    drf_fleet_operator.assert_count(url, 2)


def test_filtering_bicycle_on_has_lock(drf_fleet_operator, bicycle,
                                       lock):
    url = reverse_query('lock8:bicycle-list', {'has_lock': True})
    drf_fleet_operator.assert_count(url, 1)

    bicycle.lock = None
    bicycle.save()

    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:bicycle-list', {'has_lock': False})
    drf_fleet_operator.assert_count(url, 1)


def test_filtering_bicycle_query(
        drf_fleet_operator, bicycle, lock, with_db_plugins
):
    bicycle.description = 'ülÜberlu'
    bicycle.serial_number = '00001'
    bicycle.save()

    url = reverse_query('lock8:bicycle-list', {'query': 'ülÜ'})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:bicycle-list', {'query': 'ulu'})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:bicycle-list', {'query': lock.bleid[3:8]})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:bicycle-list', {'query': bicycle.name[2:5]})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:bicycle-list', {'query': '01'})
    drf_fleet_operator.assert_count(url, 1)


def test_filtering_bicycle_serial_number(drf_fleet_operator, bicycle,
                                         lock, another_bicycle, org):
    another_bicycle.organization = org
    another_bicycle.lock.organization = org
    another_bicycle.save()
    another_bicycle.lock.save()

    bicycle.serial_number = '00001'
    bicycle.save()

    url = reverse_query('lock8:bicycle-list', {'serial_number': '666'})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:bicycle-list', {'serial_number': '00001'})
    drf_fleet_operator.assert_count(url, 1)


def test_filtering_bicycle_state__exclude(drf_fleet_operator, bicycle,
                                          bicycle2):
    url = reverse_query('lock8:bicycle-list')
    drf_fleet_operator.assert_count(url, 2)

    url = reverse_query('lock8:bicycle-list',
                        {'state__exclude': bicycle.state})
    drf_fleet_operator.assert_count(url, 0)

    bicycle2.declare_available()

    url = '?'.join((
        reverse_query('lock8:bicycle-list'),
        'state__exclude={}&state__exclude={}'.format(bicycle.state,
                                                     bicycle2.state)))
    drf_fleet_operator.assert_count(url, 0)


def test_filtering_bicycle_zone(drf_fleet_operator, bicycle, bicycle2, zone,
                                active_lock, middle_of_central_park,
                                middle_of_theodore_roosevelt_park,
                                create_gps_tracking, central_park):
    url = reverse_query('lock8:bicycle-list')
    drf_fleet_operator.assert_count(url, 2)

    url = reverse_query('lock8:bicycle-list', {'zone': zone.uuid})
    drf_fleet_operator.assert_count(url, 0)

    create_gps_tracking(bicycle, *middle_of_central_park.tuple)
    create_gps_tracking(bicycle2, *middle_of_theodore_roosevelt_park.tuple,
                        attributes={'gps_accuracy': 5, 'gps_pdop': '0.667'})

    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:bicycle-list', {'zone': uuid.uuid4()})
    drf_fleet_operator.assert_count(url, 0)

    # slightly away from the perimeter of central park
    lon, lat = central_park[0][0][0]
    create_gps_tracking(bicycle, lon, lat + 1 / 1e6,
                        attributes={'gps_accuracy': .5})
    url = reverse_query('lock8:bicycle-list', {'zone': zone.uuid})
    drf_fleet_operator.assert_count(url, 1)


def test_filtering_bicycle_zone_regression_test(drf_fleet_operator, bicycle,
                                                owner, org,
                                                create_gps_tracking):
    from velodrome.lock8.models import Zone

    zone_in_nh = Zone.objects.create(
        organization=org,
        owner=owner,
        name='nh',
        type=Zone.DROP,
        polygon=MultiPolygon(
            [
                Polygon(
                    [
                        Point(-72.9232174158096, 41.3071972967068),
                        Point(-72.9228097200394, 41.3078299487004),
                        Point(-72.9217529296875, 41.3073947492618),
                        Point(-72.9222410917282, 41.306754033691),
                        Point(-72.9232174158096, 41.3071972967068),
                    ]
                )
            ]
        )
    )
    # not in the zone
    create_gps_tracking(bicycle, -72.923204, 41.306804)
    url = reverse_query('lock8:bicycle-list', {'zone': zone_in_nh.uuid})
    drf_fleet_operator.assert_count(url, 0)


@pytest.mark.parametrize('resource', ['Alert', 'Feedback', 'Task'])
def test_bbox_filtering_task_alert_feedback(drf_fleet_operator, bicycle,
                                            another_bicycle, org, active_lock,
                                            resource, owner, alice, bob,
                                            another_lock, create_gps_tracking):
    from django.apps import apps
    from velodrome.lock8.models import Affiliation, Alert

    model = apps.get_model('lock8', resource)
    endpoint = 'lock8:{}-list'.format(resource.lower())

    another_lock.activate()
    another_bicycle.organization = org
    another_bicycle.lock.organization = org
    another_bicycle.lock.save()
    another_bicycle.save()

    if resource == 'Feedback':
        f1 = {'organization': org, 'causality': bicycle, 'owner': owner,
              'user': alice}
        f2 = {'organization': org, 'causality': another_bicycle,
              'owner': owner, 'user': bob}
    elif resource == 'Alert':
        f1 = {'organization': org, 'causality': bicycle,
              'roles': [Affiliation.FLEET_OPERATOR],
              'alert_type': Alert.LOW_BATTERY}
        f2 = {'organization': org, 'causality': another_bicycle,
              'roles': [Affiliation.FLEET_OPERATOR],
              'alert_type': Alert.LOW_BATTERY}
    else:
        f1 = {'organization': org, 'causality': bicycle, 'owner': owner}
        f2 = {'organization': org, 'causality': another_bicycle,
              'owner': owner}

    r1 = model.objects.create(**f1)
    r2 = model.objects.create(**f2)

    drf_fleet_operator.assert_count(reverse_query('lock8:bicycle-list'), 2)
    drf_fleet_operator.assert_count(reverse_query(endpoint), 2)

    create_gps_tracking(active_lock, 13.403145, 52.527433,
                        attributes={'gps_utm_zone': -7.530941473730957e-14,
                                    'gps_accuracy': 30807.1328125})

    create_gps_tracking(another_bicycle, 12.403145, 51.527433,
                        attributes={'gps_utm_zone': -7.530941473730957e-14,
                                    'gps_accuracy': 30807.1328125})

    url = reverse_query(
        endpoint, {'bbox': '13.3683645,52.5062991,13.4240352,52.5390943'}
    )
    response = drf_fleet_operator.assert_count(url, 1)
    assert response.data['results'][0]['uuid'] == str(r1.uuid)

    url = reverse_query(
        endpoint, {'bbox': '12.3683645,51.5062991,12.4240352,51.5390943'}
    )
    response = drf_fleet_operator.assert_count(url, 1)
    assert response.data['results'][0]['uuid'] == str(r2.uuid)

    url = reverse_query(endpoint, {'bbox': '666,666,666,666'})
    drf_fleet_operator.assert_count(url, 0)


@pytest.mark.parametrize('asset', ['bicycle', 'lock'])
def test_sorting_on_bicycle_and_lock(asset, drf_fleet_operator, owner, org,
                                     create_dss_tracking, create_gps_tracking):
    from velodrome.lock8.models import Bicycle, Lock

    endpoint = 'lock8:{}-list'.format(asset)
    asset_attr = 'name' if asset == 'bicycle' else 'serial_number'

    expected = []
    for i, name in enumerate('abcd'):
        lock = Lock.objects.create(
            owner=owner,
            organization=org,
            counter=20 + i,
            serial_number='010101{}'.format(20 + i),
            imei='35978502801587{}'.format(i),
            iccid='8946204604400010867{}'.format(i + 2),
            sid='f6cefb7474f291997c6a30303130383{}'.format(i),
            bleid='4c4f434b385f3030303030303130383{}'.format(i),
            randblock='a' * 2048,
        )
        lock.provision()
        lock.activate()
        bicycle = Bicycle.objects.create(
            owner=owner,
            organization=org,
            name=name,
            lock=lock,
        )
        expected.append(bicycle.name if asset == 'bicycle' else
                        lock.serial_number)

    def assert_order(response, order):
        assert response.data['count'] == len(order)
        assert ([expected[i] for i in order] ==
                [x[asset_attr] for x in response.data['results']])

    url = reverse_query(endpoint, {'ordering': asset_attr})
    response = drf_fleet_operator.assert_success(url)
    assert_order(response, [0, 1, 2, 3])

    url = reverse_query(endpoint, {'ordering': '-{}'.format(asset_attr)})
    response = drf_fleet_operator.assert_success(url)
    assert_order(response, [3, 2, 1, 0])

    bicycle_a = Bicycle.objects.get(name='a')
    bicycle_b = Bicycle.objects.get(name='b')
    bicycle_c = Bicycle.objects.get(name='c')
    create_dss_tracking(bicycle_a, state_of_charge=75.0)
    create_dss_tracking(bicycle_b, state_of_charge=50.0)
    create_dss_tracking(bicycle_c, state_of_charge=100.0)

    url = reverse_query(endpoint, {'ordering': 'state_of_charge'})
    response = drf_fleet_operator.assert_success(url)
    assert_order(response, [1, 0, 2, 3])

    url = reverse_query(endpoint, {'ordering': '-state_of_charge'})
    response = drf_fleet_operator.assert_success(url)
    assert_order(response, [2, 0, 1, 3])

    with freeze_time(timezone.now() + dt.timedelta(seconds=1)):
        create_gps_tracking(bicycle_a, 13.377850, 52.516260)
    with freeze_time(timezone.now() + dt.timedelta(seconds=2)):
        create_gps_tracking(bicycle_b, 13.377861, 52.516271)
    with freeze_time(timezone.now() + dt.timedelta(seconds=3)):
        create_gps_tracking(bicycle_c, 13.378862, 52.516372)

    url = reverse_query(endpoint, {'ordering': 'latest_gps_timestamp'})
    response = drf_fleet_operator.assert_success(url)
    assert_order(response, [0, 1, 2, 3])

    url = reverse_query(endpoint, {'ordering': '-latest_gps_timestamp'})
    response = drf_fleet_operator.assert_success(url)
    assert_order(response, [2, 1, 0, 3])

    url = reverse_query(endpoint, {'ordering': 'created'})
    response = drf_fleet_operator.assert_success(url)
    assert_order(response, [0, 1, 2, 3])

    url = reverse_query(endpoint, {'ordering': '-created'})
    response = drf_fleet_operator.assert_success(url)
    assert_order(response, [3, 2, 1, 0])

    url = reverse_query(endpoint, {'ordering': 'modified'})
    response = drf_fleet_operator.assert_success(url)
    assert_order(response, [3, 0, 1, 2])

    url = reverse_query(endpoint, {'ordering': '-modified'})
    response = drf_fleet_operator.assert_success(url)
    assert_order(response, [2, 1, 0, 3])

    url = reverse_query(endpoint, {'ordering': 'last_cellular_update'})
    response = drf_fleet_operator.assert_success(url)
    assert_order(response, [0, 1, 2, 3])

    url = reverse_query(endpoint, {'ordering': '-last_cellular_update'})
    response = drf_fleet_operator.assert_success(url)
    assert_order(response, [2, 1, 0, 3])

    if asset == 'bicycle':
        url = reverse_query(endpoint,
                            {'ordering': 'distance',
                             'bbox': '11.5192,51.7678,15.3094,53.1731'})
        response = drf_fleet_operator.assert_success(url)
        assert_order(response, [2, 0, 1])

        url = reverse_query(endpoint,
                            {'ordering': '-distance',
                             'bbox': '11.5192,51.7678,15.3094,53.1731'})
        response = drf_fleet_operator.assert_success(url)
        assert_order(response, [1, 0, 2])

        url = reverse_query(endpoint, {'ordering': 'distance'})
        drf_fleet_operator.assert_400(url)

        url = reverse_query(endpoint, {'ordering': '-distance'})
        drf_fleet_operator.assert_400(url)


@pytest.mark.parametrize('asset', ['bicycle', 'lock'])
def test_filtering_bicycle_on_state_of_charge(asset, drf_fleet_operator, owner,
                                              org, create_dss_tracking):
    from velodrome.lock8.models import Bicycle, Lock

    endpoint = 'lock8:{}-list'.format(asset)

    for i, name in enumerate('abcd'):
        lock = Lock.objects.create(
            owner=owner,
            organization=org,
            counter=20 + i,
            serial_number='010101{}'.format(20 + i),
            imei='35978502801587{}'.format(i),
            iccid='8946204604400010867{}'.format(i + 2),
            sid='f6cefb7474f291997c6a30303130383{}'.format(i),
            bleid='4c4f434b385f3030303030303130383{}'.format(i),
            randblock='a' * 2048,
        )
        lock.provision()
        lock.activate()
        Bicycle.objects.create(
            owner=owner,
            organization=org,
            name=name,
            lock=lock,
        )
    bicycle_a = Bicycle.objects.get(name='a')
    bicycle_b = Bicycle.objects.get(name='b')
    bicycle_c = Bicycle.objects.get(name='c')
    create_dss_tracking(bicycle_a, state_of_charge=75.0)
    create_dss_tracking(bicycle_b, state_of_charge=50.0)
    create_dss_tracking(bicycle_c, state_of_charge=100.0)

    url = reverse_query(endpoint, {'max_state_of_charge': 75})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query(endpoint, {'min_state_of_charge': 75})
    drf_fleet_operator.assert_count(url, 2)


def test_csv_view_bicycle(drf_alice, drf_fleet_operator, bicycle, org,
                          active_lock, gps_tracking_on_bicycle):
    gps_tracking = bicycle.public_tracking

    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})
    lock_url = reverse_query('lock8:lock-detail',
                             kwargs={'uuid': active_lock.uuid})
    bicycle_url = reverse_query('lock8:bicycle-detail',
                                kwargs={'uuid': bicycle.uuid})

    url = reverse_query('lock8:bicycle-list')
    response = drf_fleet_operator.get(url, HTTP_ACCEPT='text/csv; version=1.0')
    assert response.status_code == status.HTTP_200_OK, response
    assert response.get('content-type') == 'text/csv; charset=utf-8'
    lon, lat = gps_tracking.point.tuple
    expected_field_names = (
        'bicycle_model_name', 'bleid', 'concurrency_version', 'created',
        'description', 'device_type',
        'devices.lock.bleid', 'devices.lock.manufacturer',
        'devices.lock.paired_at', 'devices.lock.url',
        'distance',
        'estimated_state_of_charge',
        'image_url',
        'last_cellular_update',
        'latest_gps_accuracy',
        'latest_gps_pdop',
        'latest_gps_timestamp', 'latitude',
        'lock', 'longitude', 'model',
        'modified', 'name', 'note',
        'organization', 'rental_session', 'reservation',
        'serial_number', 'short_id', 'state',
        'state_of_charge', 'url', 'uuid',)
    content = response.content.decode()
    content_field_names = tuple(content.partition('\r\n')[0].split(','))
    assert content_field_names == expected_field_names
    assert content == '\r\n'.join((','.join(row) for row in (
        expected_field_names,
        ('', active_lock.bleid, str(bicycle.concurrency_version),
         bicycle.created.isoformat()[:-13] + 'Z', '', 'lock',
         active_lock.bleid, 'noa',
         active_lock.paired_at.isoformat()[:-13] + 'Z',
         'http://testserver' + lock_url,
         '',  # distance
         '',  # estimated_state_of_charge
         '',  # image_url
         bicycle.public_tracking.modified.isoformat()[:-13] + 'Z',
         '',  # latest_gps_accuracy
         '',  # latest_gps_pdop
         gps_tracking.timestamp.isoformat()[:-13] + 'Z', str(lat),
         'http://testserver' + lock_url, str(lon), '',
         bicycle.modified.isoformat()[:-13] + 'Z', 'bicycle', '',
         'http://testserver' + organization_url, '', '', 'bicycle',
         bicycle.short_id, 'available', '',
         'http://testserver' + bicycle_url, str(bicycle.uuid)),
        (),
    )))

    url = reverse_query('lock8:bicycle-list')
    response = drf_alice.get(url, HTTP_ACCEPT='text/csv; version=1.0')
    assert response.status_code == status.HTTP_200_OK


def test_assign_lock_to_bicycle(drf_fleet_operator, owner, org,
                                bicycle, lock):
    paired_first_time = lock.paired_at
    bicycle.lock = None
    bicycle.save()

    url = reverse_query('lock8:bicycle-detail', kwargs={'uuid': bicycle.uuid})
    lock_url = reverse_query('lock8:lock-detail', kwargs={'uuid': lock.uuid})
    response = drf_fleet_operator.patch(url, data={'lock': lock_url})
    assert response.status_code == status.HTTP_200_OK, response.data

    bicycle.refresh_from_db()
    assert bicycle.lock == lock
    assert lock.paired_at > paired_first_time


def test_assign_lock_to_bicycle_fail(drf_fleet_operator, owner, org,
                                     bicycle, lock):
    bicycle.declare_available()
    bicycle.lock = None
    bicycle.save()

    url = reverse_query('lock8:bicycle-detail', kwargs={'uuid': bicycle.uuid})
    lock_url = reverse_query('lock8:lock-detail', kwargs={'uuid': lock.uuid})
    response = drf_fleet_operator.patch(url, data={'lock': lock_url})
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data['detail'] == {'lock': [
        {'message': 'Can not modify lock assignment if Bicycle is not'
                    ' in maintenance state or retired state.',
         'code': 'inconsistent'}]}

    bicycle.refresh_from_db()
    assert bicycle.lock is None


def test_unassign_lock_to_bicycle(drf_fleet_operator, bicycle):
    url = reverse_query('lock8:bicycle-detail', kwargs={'uuid': bicycle.uuid})
    response = drf_fleet_operator.patch(url, {'lock': None}, format='json')
    assert response.status_code == status.HTTP_200_OK, response.data

    bicycle.refresh_from_db()
    assert bicycle.lock is None


def test_bicycle_log_assigning_lock_to_bicycle(drf_fleet_operator, bicycle,
                                               lock, another_lock):
    from velodrome.lock8.models import LockConnection
    last_connection = (
        LockConnection.objects
            .filter(bicycle=bicycle)
            .order_by('-paired')
            .first()
    )
    first_conn_id = last_connection.pk
    assert bicycle.lock == lock
    assert last_connection.lock == lock
    assert bicycle.lock.paired_at == last_connection.paired
    assert last_connection.detached is None

    first_time_paired = bicycle.lock.paired_at
    bicycle.lock = None
    bicycle.save()
    bicycle.refresh_from_db()
    last_connection = (
        LockConnection.objects
            .filter(bicycle=bicycle)
            .order_by('-paired')
            .first()
    )
    # Same log entry, but with detached date:
    assert last_connection.pk == first_conn_id
    assert bicycle.lock is None
    assert last_connection.lock == lock
    assert last_connection.paired == first_time_paired
    assert last_connection.detached is not None
    assert last_connection.detached > last_connection.paired

    bicycle.lock = another_lock
    bicycle.save()
    bicycle.refresh_from_db()
    last_connection = (
        LockConnection.objects
            .filter(bicycle=bicycle)
            .order_by('-paired')
            .first()
    )
    # Prev date range was already closed, started new:
    assert last_connection.pk != first_conn_id
    assert bicycle.lock == another_lock
    assert last_connection.lock == another_lock
    assert bicycle.lock.paired_at == last_connection.paired
    assert bicycle.lock.paired_at > first_time_paired
    assert last_connection.detached is None


def test_bicycle_shared_secret_access(drf_admin, drf_alice, lock, bicycle, org,
                                      alice, drf_bob, bob):
    from velodrome.lock8.models import Affiliation, SharedSecret

    url = reverse_query('lock8:bicycle-shared-secret',
                        kwargs={'uuid': bicycle.uuid})

    Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.RENTER)
    Affiliation.objects.create(
        organization=org,
        user=bob,
        role=Affiliation.RENTER)

    bicycle.declare_available()
    lock.shared_secret = SharedSecret.objects.create()
    lock.save()

    bicycle.reserve(by=alice)

    drf_admin.assert_success(url)
    drf_alice.assert_status(url, status.HTTP_404_NOT_FOUND)
    drf_bob.assert_status(url, status.HTTP_404_NOT_FOUND)

    bicycle.rent(by=alice)

    caches['default'].clear()
    drf_admin.assert_success(url)
    drf_alice.assert_success(url)
    drf_bob.assert_status(url, status.HTTP_404_NOT_FOUND)

    bicycle.return_(by=alice)

    caches['default'].clear()
    drf_admin.assert_success(url)
    drf_alice.assert_status(url, status.HTTP_404_NOT_FOUND)
    drf_bob.assert_status(url, status.HTTP_404_NOT_FOUND)


def test_bicycle_shared_secret_404_and_throttling(request, drf_admin, lock,
                                                  bicycle):
    url = reverse_query('lock8:bicycle-shared-secret',
                        kwargs={'uuid': bicycle.uuid})
    drf_admin.assert_status(url, status.HTTP_404_NOT_FOUND)
    request.getfixturevalue('shared_secret')
    drf_admin.assert_success(url)


def test_crud_photo(owner, drf_fleet_operator, org, b64_image,
                    settings, another_org):
    from velodrome.lock8.models import Photo

    url = reverse_query('lock8:photo-list')

    org_url = reverse_query('lock8:organization-detail',
                            kwargs={'uuid': org.uuid})

    # create failed because image is mandatory
    response = drf_fleet_operator.post(url, data={
        'organization': org_url,
    }, format='json')
    assert response.status_code == status.HTTP_400_BAD_REQUEST

    # create
    response = drf_fleet_operator.post(url, data={
        'organization': org_url,
        'image': b64_image,
    }, format='json')
    assert response.status_code == status.HTTP_201_CREATED, response.data
    photo = Photo.objects.get()
    assert photo.image.url.startswith('http://127.0.0.1:8000/photos/')

    url = reverse_query('lock8:photo-detail', kwargs={'uuid': photo.uuid})
    assert response.data == {
        'uuid': str(photo.uuid),
        'organization': 'http://testserver' + org_url,
        'url': 'http://testserver' + url,
        'image': photo.image.url,
        'state': 'new',
        'concurrency_version': photo.concurrency_version,
        'created': photo.created.isoformat()[:-13] + 'Z',
        'modified': photo.modified.isoformat()[:-13] + 'Z',
    }
    url = reverse_query('lock8:photo-list',
                        {'organization': str(another_org.uuid)})
    drf_fleet_operator.assert_count(url, 0)

    # edit
    url = reverse_query('lock8:photo-detail', kwargs={'uuid': photo.uuid})
    response = drf_fleet_operator.patch(url,
                                        data={'organization': org_url},
                                        format='json')
    assert response.status_code == status.HTTP_200_OK

    # delete
    url = reverse_query('lock8:photo-detail', kwargs={'uuid': photo.uuid})
    response = drf_fleet_operator.delete(url)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    with pytest.raises(Photo.DoesNotExist):
        photo.refresh_from_db()


def test_assign_a_photo_to_bicycle(drf_fleet_operator, bicycle, photo,
                                   bicycle_model):
    bicycle_url = reverse_query('lock8:bicycle-detail',
                                kwargs={'uuid': bicycle.uuid})
    photo_url = reverse_query('lock8:photo-detail',
                              kwargs={'uuid': photo.uuid})
    model_url = reverse_query('lock8:bicycle_model-detail',
                              kwargs={'uuid': bicycle_model.uuid})

    response = drf_fleet_operator.patch(model_url, data={'photo': photo_url},
                                        format='json')
    assert response.status_code == status.HTTP_200_OK

    response = drf_fleet_operator.patch(bicycle_url, data={'model': model_url},
                                        format='json')
    assert response.status_code == status.HTTP_200_OK

    bicycle.refresh_from_db()
    assert bicycle.model == bicycle_model

    bicycle_model.refresh_from_db()
    assert bicycle_model.photo == photo


def test_bicycle_type_pagination(drf_fleet_operator, owner, bicycle_types):
    from velodrome.lock8.models import BicycleType

    original_count = BicycleType.objects.all().count()
    page_size = 2
    assert original_count > page_size

    url = reverse_query('lock8:bicycle_type-list', {'page_size': page_size})
    response = drf_fleet_operator.assert_count(url, original_count)
    assert len(response.data['results']) == page_size


def test_filtering_bicycle_on_bleid(drf_fleet_operator, bicycle, axa_bicycle):
    lock, axa_lock = bicycle.lock, axa_bicycle.axa_lock

    url = reverse_query('lock8:bicycle-list', {'bleid': lock.bleid})
    response = drf_fleet_operator.assert_count(url, 1)
    assert response.data['results'][0]['uuid'] == str(bicycle.uuid)

    assert axa_lock.bleid.startswith('AXA:')
    url = reverse_query('lock8:bicycle-list', {'bleid': '{}'.format(
        axa_lock.bleid)})
    response = drf_fleet_operator.assert_count(url, 1)
    assert response.data['results'][0]['uuid'] == str(axa_bicycle.uuid)


@pytest.mark.parametrize('score, filter_, expected_count', [
    (50, 60, 0),
    (50, 30, 1),
    (0, 0, 1),
    (100, 100, 1),
])
def test_filtering_on_needs_attention(drf_fleet_operator, bicycle, active_lock,
                                      score, filter_, expected_count):
    from velodrome.lock8.models import BicycleMetaData

    BicycleMetaData.objects.create(
        bicycle=bicycle,
        needs_attention_score=score)
    url = reverse_query('lock8:bicycle-list', {'needs_attention': filter_})

    drf_fleet_operator.assert_count(url, expected_count)


@pytest.mark.parametrize('score, filter_, expected_count', [
    (50, 60, 0),
    (50, 30, 1),
    (0, 0, 1),
    (100, 100, 1),
])
def test_filtering_on_recoverability(drf_fleet_operator, bicycle, active_lock,
                                     score, filter_, expected_count):
    from velodrome.lock8.models import BicycleMetaData

    BicycleMetaData.objects.create(
        bicycle=bicycle,
        recoverability_score=score)
    url = reverse_query('lock8:bicycle-list', {'recoverable': filter_})

    drf_fleet_operator.assert_count(url, expected_count)


def test_return_outside_dropzone_error_code(
        settings, mocker, bicycle, drf_alice, zone, alice, active_lock,
        organization_preference, create_gps_tracking):
    settings.ENVIRONMENT = 'prod'

    m_sentry_client = mocker.patch('velodrome.lock8.utils.get_sentry_client')

    organization_preference.allow_returning_bicycle_outside_drop_zone = False
    organization_preference.save()
    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle.uuid})
    bicycle.declare_available()
    bicycle.rent(by=alice)
    create_gps_tracking(active_lock, 13.3761745, 52.516384,
                        attributes={'gps_utm_zone': -7.530941473730957e-14,
                                    'gps_accuracy': 30.1328125,
                                    'time_stamp': 1428509327})

    response = drf_alice.post(url, data={'type': 'return'})
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {
        'detail': {'non_field_errors': [
            {'code': 'outside_dropzone',
             'message': 'This bicycle is not allowed to be returned here.'}]}}

    assert m_sentry_client().capture.call_count == 1
    assert m_sentry_client().capture.call_args[0] == (
        'raven.events.Exception',)
    assert 'exc_info' in m_sentry_client().capture.call_args[1]


def test_client_app_can_rent_as_many_bicyle(client_app, drf_client, bicycle,
                                            bicycle2, settings):
    bicycle.declare_available()
    bicycle2.declare_available()

    now = timezone.now()
    payload = {'user_id': client_app.name,
               'iss': 'sts-dev',
               'organization': str(client_app.organization.uuid),
               'scopes': ['bicycle:read', 'bicycle:write'],
               'exp': now + dt.timedelta(minutes=30),
               'iat': now}
    sts_jwt = jwt.encode(payload, settings.JWT_SECRET_KEY,
                         algorithm='HS512').decode()
    drf_client.credentials(HTTP_AUTHORIZATION='JWT ' + sts_jwt)

    url = reverse_query('lock8:bicycle-actions', kwargs={'uuid': bicycle.uuid})
    response = drf_client.post(url, data={'type': 'rent'})
    assert response.status_code == status.HTTP_200_OK, response.data

    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle2.uuid})
    response = drf_client.post(url, data={'type': 'rent'})
    assert response.status_code == status.HTTP_200_OK, response.data


def test_bicycle_return_dry_run(drf_renter, renter, bicycle):
    bicycle.declare_available()
    bicycle.rent(by=renter)

    url = reverse_query('lock8:bicycle-actions', kwargs={'uuid': bicycle.uuid})
    response = drf_renter.post(url, data={'type': 'return', 'dry_run': True})
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert not response.content
    bicycle.refresh_from_db()
    assert bicycle.state == 'rented'


def test_return_outside_dropzone_dry_run(bicycle, drf_alice, zone, alice,
                                         active_lock,
                                         organization_preference,
                                         create_gps_tracking):
    organization_preference.allow_returning_bicycle_outside_drop_zone = False
    organization_preference.save()
    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle.uuid})
    bicycle.declare_available()
    bicycle.rent(by=alice)
    create_gps_tracking(active_lock, 13.3761745, 52.516384,
                        attributes={'gps_utm_zone': -7.530941473730957e-14,
                                    'gps_accuracy': 30.1328125,
                                    'time_stamp': 1428509327})

    response = drf_alice.post(url, data={'type': 'return', 'dry_run': True})
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {
        'detail': {'non_field_errors': [
            {'code': 'outside_dropzone',
             'message': 'This bicycle is not allowed to be returned here.'}]}}


def test_app_download_url(bicycle_available, drf_client, org_open_fleet):
    url = reverse_query('lock8:bicycle-detail',
                        query_kwargs={'fields': 'app_download_url'},
                        kwargs={'uuid': bicycle_available.uuid})
    response = drf_client.assert_success(url)
    assert response.data == {'app_download_url': None}

    org_open_fleet.app_download_url = 'custom'
    org_open_fleet.save()
    bicycle_available.refresh_from_db()
    response = drf_client.assert_success(url)
    assert response.data == {'app_download_url': 'custom'}


def test_disable_pagination(drf_fleet_operator, bicycle, bicycle2, mocker):
    import velodrome.lock8.pagination
    mocker.patch.object(
        velodrome.lock8.pagination.PageNumberPagination,
        'page_size',
        1
    )

    url = reverse_query('lock8:bicycle-list')
    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert response.data['count'] == 2
    assert response.data['next'] is not None

    url = reverse_query('lock8:bicycle-list', query_kwargs=dict(no_page=1))
    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert len(response.data) == 2


def test_multiple_org_support(drf_admin, bicycle, bicycle2, another_bicycle):
    response = drf_admin.get(
        reverse_query(
            'lock8:bicycle-list',
            query_kwargs=dict(
                organization=str(bicycle.organization.uuid)
            )
        )
    )
    assert response.status_code == status.HTTP_200_OK, response.data
    assert len(response.data['results']) == 2

    # Lets pass the same single organization uuid to the multiple org filter
    response = drf_admin.get(
        reverse_query(
            'lock8:bicycle-list',
            query_kwargs=dict(
                organizations=str(bicycle.organization.uuid)
            )
        )
    )
    assert response.status_code == status.HTTP_200_OK, response.data
    assert len(response.data['results']) == 2

    response = drf_admin.get(
        reverse_query(
            'lock8:bicycle-list',
            query_kwargs=dict(
                organization=str(another_bicycle.organization.uuid)
            )
        )
    )
    assert response.status_code == status.HTTP_200_OK, response.data
    assert len(response.data['results']) == 1

    response = drf_admin.get(
        reverse_query(
            'lock8:bicycle-list',
            query_kwargs=dict(
                organizations=",".join(
                    map(str, [bicycle.organization.uuid,
                              another_bicycle.organization.uuid])
                )
            )
        )
    )
    assert response.status_code == status.HTTP_200_OK, response.data
    assert len(response.data['results']) == 3
