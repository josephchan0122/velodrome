from datetime import timedelta

from django.utils import timezone
from freezegun import freeze_time
import pytest
from rest_framework_gis.fields import GeoJsonDict

from velodrome.lock8.utils import reverse_query


def test_trips_no_create(drf_fleet_operator, org):
    url = reverse_query('lock8:trip-list')
    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})

    response = drf_fleet_operator.post(url, data={
        'organization': organization_url,
    })
    drf_fleet_operator.assert_403(response)


@pytest.mark.parametrize('created_offset', (0, 1))
def test_trips_basic(created_offset, drf_fleet_operator, org,
                     trip_brandenburger_tor_2_siegessaeule, bicycle):
    trip = trip_brandenburger_tor_2_siegessaeule
    trip_uuid = str(trip.uuid)
    url = reverse_query('lock8:trip-list', {
            'created_after': int(trip.created.timestamp()) + created_offset})
    bicycle_url = reverse_query('lock8:bicycle-detail',
                                kwargs={'uuid': bicycle.uuid})
    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})
    response = drf_fleet_operator.assert_count(url, int(created_offset == 0))
    if not created_offset:
        assert response.data['results'][0] == dict({
            'asset_state': 'in_service',
            'bicycle': 'http://testserver' + bicycle_url,
            'created': trip.created.isoformat()[:-13] + 'Z',
            'distance_m': 1893,
            'duration': '00:15:00',
            'start_date': trip.start_date.isoformat()[:-13] + 'Z',
            'end_date': trip.end_date.isoformat()[:-13] + 'Z',
            'modified': trip.modified.isoformat()[:-13] + 'Z',
            'organization': 'http://testserver' + organization_url,
            'snapped_route': GeoJsonDict([('type', 'LineString'),
                                          ('coordinates', [
                                              [13.37785, 52.51626],
                                              [13.37187, 52.51597],
                                              [13.37186, 52.51593],
                                              [13.37185, 52.51599],
                                              [13.37182, 52.51593],
                                              [13.359307, 52.515254],
                                              [13.35006, 52.5145]])]),
            'route': GeoJsonDict([('type', 'LineString'),
                                  ('coordinates', [
                                      [13.37785, 52.51626],
                                      [13.37187, 52.51597],
                                      [13.37186, 52.51593],
                                      [13.37185, 52.51599],
                                      [13.37182, 52.51593],
                                      [13.359307, 52.515254],
                                      [13.35006, 52.5145]])]),
            'serial_number': '',
            'type': 'regular',
            'uuid': str(trip.uuid),
            'url': 'http://testserver' + reverse_query(
                'lock8:trip-detail', kwargs={'uuid': trip_uuid}),
        })


def test_trips_admin(drf_admin, trip):
    url = reverse_query('lock8:trip-list')
    response = drf_admin.assert_count(url, 1)
    assert response.data['results'][0]['is_valid'] is True


@pytest.mark.parametrize('offset', (0, 1))
def test_trips_filter_start_end_date(offset, drf_fleet_operator, org, trip):
    url = reverse_query('lock8:trip-list', {
            'started_after': int(trip.start_date.timestamp()) + offset})
    drf_fleet_operator.assert_count(url, int(offset == 0))

    url = reverse_query('lock8:trip-list', {
            'ended_before': int(trip.end_date.timestamp()) + offset})
    drf_fleet_operator.assert_count(url, int(offset != 0))


def test_trips_filter_organization(drf_fleet_operator,
                                   drf_another_fleet_operator,
                                   trip, another_trip, org, another_org):
    org_url = 'http://testserver' + reverse_query('lock8:organization-detail',
                                                  kwargs={'uuid': org.uuid})
    another_org_url = 'http://testserver' + reverse_query(
        'lock8:organization-detail', kwargs={'uuid': another_org.uuid})

    url = reverse_query('lock8:trip-list')
    response = drf_fleet_operator.assert_count(url, 1)
    assert response.data['results'][0]['organization'] == org_url

    url = reverse_query('lock8:trip-list', {
        'organization': str(org.uuid)})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:trip-list', {
        'organization': str(another_org.uuid)})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:trip-list', {
        'organization': str(another_org.uuid)})
    response = drf_another_fleet_operator.assert_count(url, 1)
    assert response.data['results'][0]['organization'] == another_org_url


def test_trips_filter_bicycle(drf_fleet_operator, trip, bicycle,
                              another_bicycle):

    url = reverse_query('lock8:trip-list')
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:trip-list', {'bicycle': bicycle.uuid})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:trip-list', {'bicycle': another_bicycle.uuid})
    drf_fleet_operator.assert_count(url, 0)


@pytest.mark.parametrize('trip_type', ('trip', 'unfinished_trip'))
def test_trips_filter_rental_session(trip_type, drf_renter, bicycle, request,
                                     non_matching_uuid, drf_bob, org):
    from velodrome.lock8.models import Affiliation

    bicycle.declare_available()

    url = reverse_query('lock8:trip-list')
    drf_renter.assert_count(url, 0)

    renter = drf_renter.user

    with freeze_time(timezone.now() - timedelta(minutes=15, seconds=2)):
        bicycle.rent(by=renter)
    rental_session = bicycle.active_rental_session
    request.getfixturevalue(trip_type)
    bicycle.return_(by=renter)

    url = reverse_query('lock8:trip-list')
    drf_renter.assert_count(url, 1)

    url = reverse_query('lock8:trip-list',
                        {'rental_session': rental_session.uuid})
    drf_renter.assert_count(url, 1)
    drf_bob.assert_count(url, 0)

    bicycle.rent(by=renter)
    drf_renter.assert_count(url, 1)
    drf_bob.assert_count(url, 0)

    bob = drf_bob.user
    Affiliation.objects.create(organization=org,
                               user=bob,
                               role=Affiliation.RENTER)
    drf_bob.assert_count(url, 0)

    url = reverse_query('lock8:trip-list',
                        {'rental_session': 'INVALID'})
    drf_renter.assert_400(url, {
        'rental_session': [{'code': 'invalid',
                            'message': 'Enter a valid UUID.'}]})

    url = reverse_query('lock8:trip-list',
                        {'rental_session': non_matching_uuid})
    drf_renter.assert_count(url, 0)


@pytest.mark.parametrize('seconds,count', ((299, 1), (300, 0)))
def test_trips_filter_rental_session_finishes_before_end_of_trip(
        seconds, count, drf_renter, bicycle, request, org):

    bicycle.declare_available()

    renter = drf_renter.user

    with freeze_time(timezone.now() - timedelta(minutes=15, seconds=2)):
        bicycle.rent(by=renter)
    rental_session = bicycle.active_rental_session
    trip = request.getfixturevalue('trip')
    with freeze_time(trip.end_date - timedelta(seconds=seconds)):
        bicycle.return_(by=renter)

    url = reverse_query('lock8:trip-list')
    drf_renter.assert_count(url, count)

    url = reverse_query('lock8:trip-list',
                        {'rental_session': rental_session.uuid})
    drf_renter.assert_count(url, count)


def test_trips_filter_include_invalid_admin(drf_admin, drf_fleet_operator,
                                            trip, trip_without_duration):
    url = reverse_query('lock8:trip-list')
    drf_admin.assert_count(url, 1)
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:trip-list', {'include_invalid': 'True'})
    drf_admin.assert_count(url, 2)
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:trip-list', {'include_invalid': 'False'})
    drf_admin.assert_count(url, 1)
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:trip-list', {'include_invalid': 'invalid'})
    drf_admin.assert_400(url, {
        'include_invalid': [
            {'code': 'invalid',
             'message': 'value must be True, true, 1, or False, false, 0'}]})
    drf_fleet_operator.assert_count(url, 1)


def test_trips_filter_include_invalid_renter(drf_renter, bicycle_rented,
                                             writable_trip):
    url = reverse_query('lock8:trip-list')
    drf_renter.assert_count(url, 0)

    url = reverse_query('lock8:trip-list', {'include_invalid': 'True'})
    drf_renter.assert_count(url, 0)

    url = reverse_query('lock8:trip-list', {'include_invalid': 'False'})
    drf_renter.assert_count(url, 0)

    writable_trip.is_valid = False
    writable_trip.save()

    url = reverse_query('lock8:trip-list')
    drf_renter.assert_count(url, 0)

    url = reverse_query('lock8:trip-list', {'include_invalid': 'True'})
    drf_renter.assert_count(url, 0)

    url = reverse_query('lock8:trip-list', {'include_invalid': 'False'})
    drf_renter.assert_count(url, 0)


def test_trips_filter_include_invalid_request_wo_user():
    from django.test.client import RequestFactory
    from velodrome.lock8.filters import TripFilter

    request = RequestFactory()
    TripFilter(request=request)


@pytest.mark.parametrize('asset_state', ('in_service', 'in_maintenance',
                                         'private'))
def test_trips_asset_state(asset_state, drf_admin, drf_fleet_operator,
                           drf_renter, bicycle_rented, writable_trip):
    writable_trip.asset_state = asset_state
    writable_trip.save()

    url = reverse_query('lock8:trip-list')

    if asset_state == 'private':
        drf_admin.assert_count(url, 1)
        drf_fleet_operator.assert_count(url, 0)
        drf_renter.assert_count(url, 0)
    elif asset_state == 'in_maintenance':
        drf_admin.assert_count(url, 1)
        drf_fleet_operator.assert_count(url, 1)
        drf_renter.assert_count(url, 0)
    elif asset_state == 'in_service':
        drf_admin.assert_count(url, 1)
        drf_fleet_operator.assert_count(url, 1)
        drf_renter.assert_count(url, 0)


def test_trips_filter_asset_state(bicycle, get_trip, drf_admin,
                                  drf_fleet_operator, drf_renter):
    trip_in_service = get_trip(bicycle, asset_state='in_service')
    trip_in_maintenance = get_trip(bicycle,
                                   asset_state='in_maintenance')
    trip_private = get_trip(bicycle, asset_state='private')

    url_in_service = reverse_query('lock8:trip-list', {
        'asset_state': 'in_service'})
    url_in_maintenance = reverse_query('lock8:trip-list', {
        'asset_state': 'in_maintenance'})
    url_private = reverse_query('lock8:trip-list', {
        'asset_state': 'private'})
    url_all = reverse_query('lock8:trip-list', (
        ('asset_state', 'in_service'),
        ('asset_state', 'in_maintenance'),
        ('asset_state', 'private')))

    drf_admin.assert_count(url_all, 3)
    response = drf_admin.assert_count(url_private, 1)
    assert response.data['results'][0]['uuid'] == str(trip_private.uuid)
    response = drf_admin.assert_count(url_in_maintenance, 1)
    assert response.data['results'][0]['uuid'] == str(trip_in_maintenance.uuid)
    response = drf_admin.assert_count(url_in_service, 1)
    assert response.data['results'][0]['uuid'] == str(trip_in_service.uuid)

    drf_fleet_operator.assert_count(url_all, 2)
    drf_fleet_operator.assert_count(url_private, 0)
    drf_fleet_operator.assert_count(url_in_maintenance, 1)
    drf_fleet_operator.assert_count(url_in_service, 1)

    # Renter is not allowed to see any trips currently.
    drf_renter.assert_count(url_all, 0)
    drf_renter.assert_count(url_private, 0)
    drf_renter.assert_count(url_in_maintenance, 0)
    drf_renter.assert_count(url_in_service, 0)


def test_trips_filter_type(bicycle, get_trip, drf_admin, drf_fleet_operator,
                           drf_renter):
    trip_regular = get_trip(bicycle, type='regular')
    trip_suspicious = get_trip(bicycle, type='suspicious')

    url_regular = reverse_query('lock8:trip-list', {
        'type': 'regular'})
    url_suspicious = reverse_query('lock8:trip-list', {
        'type': 'suspicious'})
    url_all = reverse_query('lock8:trip-list')

    drf_admin.assert_count(url_all, 2)
    response = drf_admin.assert_count(url_regular, 1)
    assert response.data['results'][0]['uuid'] == str(trip_regular.uuid)
    response = drf_admin.assert_count(url_suspicious, 1)
    assert response.data['results'][0]['uuid'] == str(trip_suspicious.uuid)

    drf_fleet_operator.assert_count(url_all, 2)
    drf_fleet_operator.assert_count(url_regular, 1)
    drf_fleet_operator.assert_count(url_suspicious, 1)

    # Renter is not allowed to see any trips currently.
    drf_renter.assert_count(url_all, 0)
    drf_renter.assert_count(url_regular, 0)
    drf_renter.assert_count(url_suspicious, 0)


def test_trips_unfinished(bicycle, trip, unfinished_trip, drf_fleet_operator,
                          drf_renter, drf_admin):
    url = reverse_query('lock8:trip-list')

    bicycle.declare_available()

    drf_admin.assert_count(url, 2)
    drf_fleet_operator.assert_count(url, 2)
    drf_renter.assert_count(url, 0)
