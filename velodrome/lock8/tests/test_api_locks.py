import datetime as dt
import hashlib
import json

from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from freezegun import freeze_time
import pytest
from rest_framework import status
from rest_framework_jwt import utils

from velodrome.lock8.jwt_extensions import jwt_payload_handler
from velodrome.lock8.utils import reverse_query


def test_lock_creation_is_allowed(drf_admin, root_org):
    from velodrome.lock8.models import Lock

    url = reverse_query('lock8:lock-list')
    response = drf_admin.post(url, data={
        'counter': 13,
        'serial_number': '01010113',
        'imei': '9' * 15,
        'iccid': '89462046044000108670',
        'bleid': '4c4f434b385f30303030303031303835',
        'type': 'tracker',
    })
    assert response.status_code == status.HTTP_201_CREATED, response.data

    lock = Lock.objects.latest()

    detail_url = reverse_query('lock8:lock-detail', kwargs={'uuid': lock.uuid})
    org_url = reverse_query('lock8:organization-detail',
                            kwargs={'uuid': root_org.uuid})
    assert response.data == {
        'uuid': str(lock.uuid),
        'url': 'http://testserver' + detail_url,
        'counter': 13,
        'serial_number': '01010113',
        'imei': '9' * 15,
        'iccid': '89462046044000108670',
        'bleid':  '4c4f434b385f30303030303031303835',
        'bicycle': None,
        'estimated_state_of_charge': None,
        'state_of_charge': None,
        'type': 'tracker',
        'latitude': None,
        'longitude': None,
        'latest_gps_accuracy': None,
        'latest_gps_pdop': None,
        'latest_gps_timestamp': None,
        'voltage': None,
        'organization': 'http://testserver' + org_url,
        'shared_secret': lock.shared_secret.b64_value,
        'state': 'new',
        'firmware_version': None,
        'locked_state': 'unlocked',
        'created': lock.created.isoformat()[:-13] + 'Z',
        'modified': lock.modified.isoformat()[:-13] + 'Z',
        'concurrency_version': lock.concurrency_version,
    }

    lock.firmware_versions = {'mercury': 'bar'}
    lock.save()

    response = drf_admin.get(detail_url)
    assert response.status_code == status.HTTP_200_OK
    assert response.data['firmware_version'] == 'bar'


def test_state_security_for_lock(drf_client, drf_alice, drf_fleet_operator,
                                 org, alice, lock, admin_user):
    from velodrome.lock8.models import Affiliation

    Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.RENTER)

    url = reverse_query('lock8:lock-list')
    drf_alice.assert_status(url, status.HTTP_403_FORBIDDEN)

    url = reverse_query('lock8:lock-list')
    drf_fleet_operator.assert_count(url, 1)

    drf_client.credentials(
        HTTP_AUTHORIZATION='JWT ' + utils.jwt_encode_handler(
            jwt_payload_handler(admin_user)))
    url = reverse_query('lock8:lock-actions',
                        kwargs={'uuid': lock.uuid})
    response = drf_client.post(url, data={'type': 'provision'})
    assert response.status_code == status.HTTP_200_OK
    assert response.data['state'] == 'provisioned'

    url = reverse_query('lock8:lock-list')
    drf_fleet_operator.assert_count(url, 1)

    lock.refresh_from_db()
    lock.activate()

    url = reverse_query('lock8:lock-actions',
                        kwargs={'uuid': lock.uuid})
    response = drf_fleet_operator.post(url,
                                       data={'type': 'put_in_maintenance'})
    assert response.status_code == status.HTTP_200_OK
    assert response.data['state'] == 'in_maintenance'

    url = reverse_query('lock8:lock-list')
    drf_alice.assert_status(url, status.HTTP_403_FORBIDDEN)

    url = reverse_query('lock8:lock-actions',
                        kwargs={'uuid': lock.uuid})
    response = drf_fleet_operator.post(url, data={'type': 'restore'})
    assert response.status_code == status.HTTP_200_OK
    assert response.data['state'] == 'active'

    url = reverse_query('lock8:lock-list')
    drf_alice.assert_status(url, status.HTTP_403_FORBIDDEN)


def test_list_lock_as_fleet_operator_and_parent_renter(
        drf_fleet_operator, fleet_operator, org, lock, root_org):
    from velodrome.lock8.models import Affiliation

    Affiliation.objects.create(
        organization=root_org,
        user=fleet_operator,
        role=Affiliation.RENTER)
    lock.provision()

    url = reverse_query('lock8:lock-list')
    drf_fleet_operator.assert_count(url, 1)


def test_crud_on_lock_inactive(drf_fleet_operator, drf_admin, org, lock,
                               dss_tracking):

    url = reverse_query('lock8:lock-list')
    response = drf_fleet_operator.post(url, data={})
    assert response.status_code == status.HTTP_403_FORBIDDEN

    url = reverse_query('lock8:lock-list')
    drf_fleet_operator.assert_count(url, 1)

    lock.provision()

    url = reverse_query('lock8:lock-list')
    response = drf_fleet_operator.assert_success(url)
    assert len(response.data['results']) == 1

    detail_url = reverse_query('lock8:lock-detail', kwargs={'uuid': lock.uuid})
    org_url = reverse_query('lock8:organization-detail',
                            kwargs={'uuid': org.uuid})
    firmware_version = lock.firmware_versions['mercury']
    tracking = lock.private_tracking
    drf_fleet_operator.assert_success(detail_url, {
        'counter': lock.counter,
        'serial_number': lock.serial_number,
        'bleid': lock.bleid,
        'imei': lock.imei,
        'iccid': lock.iccid,
        'latitude': None,
        'longitude': None,
        'latest_gps_accuracy': None,
        'latest_gps_pdop': None,
        'latest_gps_timestamp': None,
        'voltage': tracking.voltage,
        'estimated_state_of_charge': None,
        'state_of_charge': None,
        'bicycle': None,
        'organization': 'http://testserver' + org_url,
        'type': 'lock',
        'uuid': str(lock.uuid),
        'state': 'provisioned',
        'firmware_version': firmware_version,
        'shared_secret': None,
        'locked_state': 'unlocked',
        'concurrency_version': lock.concurrency_version,
        'url': 'http://testserver' + detail_url,
        'modified': lock.modified.isoformat()[:-13] + 'Z',
        'created': lock.created.isoformat()[:-13] + 'Z',
    })

    lock.refresh_from_db()
    lock.activate()

    drf_admin.assert_success(detail_url, {
        'counter': lock.counter,
        'serial_number': lock.serial_number,
        'bleid': lock.bleid,
        'imei': lock.imei,
        'iccid': lock.iccid,
        'latitude': None,
        'longitude': None,
        'latest_gps_accuracy': None,
        'latest_gps_pdop': None,
        'latest_gps_timestamp': None,
        'voltage': tracking.voltage,
        'estimated_state_of_charge': tracking.state_of_charge,
        'state_of_charge': tracking.state_of_charge,
        'bicycle': None,
        'organization': 'http://testserver' + org_url,
        'type': 'lock',
        'uuid': str(lock.uuid),
        'state': 'active',
        'firmware_version': firmware_version,
        'shared_secret': None,
        'locked_state': 'unlocked',
        'concurrency_version': lock.concurrency_version,
        'url': 'http://testserver' + detail_url,
        'modified': lock.modified.isoformat()[:-13] + 'Z',
        'created': lock.created.isoformat()[:-13] + 'Z',
    })
    url = reverse_query('lock8:lock-actions',
                        kwargs={'uuid': lock.uuid})
    response = drf_admin.post(url, data={'type': 'put_in_maintenance'})
    assert response.status_code == status.HTTP_200_OK

    lock.refresh_from_db()
    assert lock.state == 'in_maintenance'

    response = drf_fleet_operator.post(url, data={'type': 'restore'})
    assert response.status_code == status.HTTP_200_OK
    lock.refresh_from_db()
    assert lock.state == 'active'

    lock.put_in_maintenance()

    response = drf_admin.post(url, data={'type': 'decommission'})
    assert response.status_code == status.HTTP_200_OK, response.data
    lock.refresh_from_db()
    assert lock.state == 'decommissioned'

    response = drf_admin.put(detail_url, data={
        'imei': '359785028015876',
        'iccid': '89462046044000108670',
        'bleid': lock.bleid,
        'counter': 12,
        'serial_number': '01010112'}, format='json')
    assert response.status_code == status.HTTP_200_OK

    response = drf_admin.patch(detail_url)
    assert response.status_code == status.HTTP_200_OK, response.data

    response = drf_admin.delete(detail_url)
    assert response.status_code == status.HTTP_204_NO_CONTENT


def test_crud_on_lock_serialized(drf_admin, org, lock, dss_tracking):
    """Validate serialized response.

    This gets tested once (for locks only) to ensure the serializer chain is
    correctly encoding `None` as `null`.
    """
    from velodrome import VERSION
    tracking = lock.private_tracking

    lock.provision()

    url = reverse_query('lock8:lock-detail', kwargs={'uuid': lock.uuid})
    org_url = reverse_query('lock8:organization-detail',
                            kwargs={'uuid': org.uuid})
    firmware_version = tracking.attributes.get('firmware_version_tag')
    lock_created_iso = lock.created.isoformat()[:-13] + 'Z'
    lock_modified_iso = lock.modified.isoformat()[:-13] + 'Z'
    now = timezone.now()

    with freeze_time(now):
        response = drf_admin.assert_success(url)

    serialized_response = response.serialize().decode('utf-8')
    header, _, body = serialized_response.partition('\r\n\r\n')
    sorted_header = '\r\n'.join(sorted(header.split('\r\n')))

    json_values = {
        k: json.dumps(v) for k, v in dict(
            firmware_version=firmware_version,
            lock_concurrency_version=lock.concurrency_version,
            lock_created_iso=lock_created_iso,
            lock_modified_iso=lock_modified_iso,
            lock_uuid=str(lock.uuid),
            lock_counter=lock.counter,
            lock_serial_number=lock.serial_number,
            lock_imei=lock.imei,
            lock_iccid=lock.iccid,
            lock_bleid=lock.bleid,
            state_of_charge=tracking.state_of_charge,
            tracking_voltage=tracking.voltage,
            shared_secret=None,
        ).items()}
    assert body == (
        '{{'

        # XXX: would be nice to keep the order?! (via
        # MetaclassForLatestTrackings).
        '"latitude":null,'
        '"longitude":null,'
        '"latest_gps_accuracy":null,'
        '"latest_gps_timestamp":null,'
        '"latest_gps_pdop":null,'
        '"state_of_charge":{state_of_charge},'
        '"estimated_state_of_charge":{state_of_charge},'

        '"counter":{lock_counter},'
        '"serial_number":{lock_serial_number},'
        '"imei":{lock_imei},'
        '"iccid":{lock_iccid},'
        '"bleid":{lock_bleid},'
        '"voltage":{tracking_voltage},'
        '"organization":"http://testserver{org_uri}",'
        '"bicycle":null,'
        '"type":"lock",'
        '"firmware_version":{firmware_version},'
        '"locked_state":"unlocked",'
        '"shared_secret":null,'
        '"uuid":{lock_uuid},'
        '"url":"http://testserver{lock_uri}",'
        '"created":{lock_created_iso},'
        '"modified":{lock_modified_iso},'
        '"concurrency_version":{lock_concurrency_version},'
        '"state":"provisioned"'
        '}}').format(**dict(json_values, lock_uri=url, org_uri=org_url))

    h = hashlib.new('md5')
    h.update(body.encode())
    assert sorted_header == '\r\n'.join([
        'Allow: GET, PUT, PATCH, DELETE, HEAD, OPTIONS',
        'Content-Length: 781',
        'Content-Type: application/json',
        f'ETag: "{h.hexdigest()}"',
        'Vary: Accept, Cookie, Origin',
        'X-Frame-Options: SAMEORIGIN',
        f'X-Noa-Version: {VERSION}',
    ])


def test_lock_estimated_state_of_charge_admin(admin_user,
                                              create_dss_tracking, lock):
    from velodrome.lock8.conftest import get_drf_client_for_user

    create_dss_tracking(lock, 50., time_stamp=0)

    url = reverse_query('lock8:lock-detail', kwargs={'uuid': lock.uuid})

    drf_client = get_drf_client_for_user(admin_user)
    response = drf_client.assert_success(url)
    assert response.data['estimated_state_of_charge'] is None

    drf_client.use_jwt_auth()
    response = drf_client.assert_success(url)
    assert response.data['estimated_state_of_charge'] == 0


def test_lock_estimated_state_of_charge_fleetop(drf_fleet_operator, lock,
                                                create_dss_tracking):
    create_dss_tracking(lock, 50., time_stamp=0)
    url = reverse_query('lock8:lock-detail', kwargs={'uuid': lock.uuid})
    response = drf_fleet_operator.assert_success(url)
    assert response.data['estimated_state_of_charge'] is None


def test_lock_list_performance(drf_client, lock, admin_user,
                               gps_tracking, dss_tracking):

    drf_client.credentials(
        HTTP_AUTHORIZATION='JWT ' + utils.jwt_encode_handler(
            jwt_payload_handler(admin_user)))

    url = reverse_query('lock8:lock-list')
    with CaptureQueriesContext(connection) as capture:
        drf_client.assert_count(url, 1)
    assert len(capture.captured_queries) == 7, '\n\n'.join(
        q['sql'] for q in capture.captured_queries)


def test_filtering_on_lock(drf_admin, owner, org, active_lock, bicycle,
                           another_org, create_gps_tracking):

    url = reverse_query('lock8:lock-list')
    drf_admin.assert_count(url, 1)

    url = reverse_query('lock8:lock-list', {'available': True})
    drf_admin.assert_count(url, 0)

    bicycle.lock = None
    bicycle.save()

    url = reverse_query('lock8:lock-list', {'available': True})
    drf_admin.assert_count(url, 1)

    url = reverse_query('lock8:lock-list', {'state': 'active'})
    drf_admin.assert_count(url, 1)

    url = reverse_query('lock8:lock-list', {'state': 'provisioned'})
    drf_admin.assert_count(url, 0)

    url = reverse_query('lock8:lock-list',
                        {'organization': str(another_org.uuid)})
    drf_admin.assert_count(url, 0)

    url = reverse_query('lock8:lock-list', {'bleid': 'NOT A BLEID'})
    drf_admin.assert_count(url, 0)

    url = reverse_query('lock8:lock-list',
                        {'bleid': active_lock.bleid[:-1].upper()})
    drf_admin.assert_count(url, 1)

    url = reverse_query('lock8:lock-list', {'bleid': active_lock.bleid})
    drf_admin.assert_count(url, 1)

    url = reverse_query('lock8:lock-list', {'imei': active_lock.imei})
    drf_admin.assert_count(url, 1)

    url = reverse_query('lock8:lock-list', {'imei': 'not an IMEI'})
    drf_admin.assert_count(url, 0)

    bbox_points = {'bbox': '13.3683645,52.5062991,13.4240352,52.5390943'}
    url = reverse_query('lock8:lock-list', bbox_points)
    drf_admin.assert_count(url, 0)

    timestamp = timezone.now() + dt.timedelta(seconds=2)
    create_gps_tracking(active_lock, 13.403145, 52.527433,
                        time_stamp=timestamp.timestamp())

    bbox_points = {'bbox': '13.3683645,52.5062991,13.4240352,52.5390943'}
    url = reverse_query('lock8:lock-list', bbox_points)
    drf_admin.assert_count(url, 1)

    url = reverse_query('lock8:lock-list', {'type': 'lock'})
    drf_admin.assert_count(url, 1)

    url = reverse_query('lock8:lock-list', {'type': 'tracker'})
    drf_admin.assert_count(url, 0)


@pytest.mark.parametrize('query,count', (
    ('XX', 0),
    ('8502801', 1),  # iemi
    ('4400010', 1),  # iccid
    ('385f3030303030', 1),  # bleid
    ('1', 1),  # serial_number
    ('12', 1),  # counter
))
def test_lock_filtering_full_text(drf_client, owner, org, lock,
                                  admin_user, bicycle, another_org, alice,
                                  query, count):

    drf_client.credentials(
        HTTP_AUTHORIZATION='JWT ' + utils.jwt_encode_handler(
            jwt_payload_handler(admin_user)))

    url = reverse_query('lock8:lock-list', {'query': query})
    drf_client.assert_count(url, count)


def test_lock_ordering(drf_admin, lock, another_lock):

    url = reverse_query('lock8:lock-list', {'ordering': 'serial_number'})
    response = drf_admin.assert_count(url, 2)

    assert [res['uuid'] for res in response.data['results']] == [
        str(another_lock.uuid), str(lock.uuid)]

    url = reverse_query('lock8:lock-list', {'ordering': '-serial_number'})
    response = drf_admin.assert_count(url, 2)

    assert [res['uuid'] for res in response.data['results']] == [
        str(lock.uuid), str(another_lock.uuid)]


def test_filter_on_lock_breach(drf_alice, org, lock):
    """
    regression: an orphan user could access all locks.
    """

    url = reverse_query('lock8:lock-list', {'organization': str(org.uuid)})
    drf_alice.assert_status(url, status.HTTP_403_FORBIDDEN)

    url = reverse_query('lock8:lock-list', {'organization': ''})
    drf_alice.assert_status(url, status.HTTP_403_FORBIDDEN)


def test_lock_sorting_on_state_of_charge(lock, another_lock, drf_admin,
                                         create_dss_tracking):
    create_dss_tracking(lock, 99.)
    create_dss_tracking(another_lock, 33.)

    url = reverse_query('lock8:lock-list', {'ordering': 'state_of_charge'})

    response = drf_admin.assert_success(url)
    assert [r['uuid'] for r in response.data['results']] == [
        str(another_lock.uuid),
        str(lock.uuid)
    ]
    url = reverse_query('lock8:lock-list', {'ordering': '-state_of_charge'})

    response = drf_admin.assert_success(url)
    assert [r['uuid'] for r in response.data['results']] == [
        str(lock.uuid),
        str(another_lock.uuid)
    ]


def test_list_on_lock_disfunction(drf_client, org, lock, admin_user,
                                  another_org):
    """
    regresssion: If you are Admin of multiple organization, only the locks
    that belongs to the first one was displayed. First one are defined by
    modification dates of Organizations and Affiliations in this scenario.
    """
    from velodrome.lock8.models import Affiliation
    Affiliation.objects.create(user=admin_user,
                               organization=org,
                               role='admin'
                               )
    Affiliation.objects.create(user=admin_user,
                               organization=another_org,
                               role='admin'
                               )
    drf_client.credentials(
        HTTP_AUTHORIZATION='JWT ' + utils.jwt_encode_handler(
            jwt_payload_handler(admin_user)))

    url = reverse_query('lock8:lock-list', {'organization': str(org.uuid)})
    drf_client.assert_count(url, 1)


def test_list_filter_by_multiple_serial_numbers(lock, lock2, lock3,
                                                drf_fleet_operator):
    expected_serial_numbers = [item.serial_number for item in [lock, lock2]]
    url = reverse_query('lock8:lock-list', {
        'serial_number': ','.join(expected_serial_numbers)
    })
    results = drf_fleet_operator.assert_count(url, 2).data['results']
    actual_serial_numbers = [r['serial_number'] for r in results]
    assert sorted(actual_serial_numbers) == sorted(expected_serial_numbers)


def test_fleet_operator_can_interact_with_lock(drf_fleet_operator, org,
                                               owner, lock):
    lock.provision()
    lock.activate()

    url = reverse_query('lock8:lock-detail', kwargs={'uuid': lock.uuid})
    drf_fleet_operator.assert_success(url)

    url = reverse_query('lock8:lock-actions', kwargs={'uuid': lock.uuid})
    response = drf_fleet_operator.post(url,
                                       data={'type': 'put_in_maintenance'})
    assert response.status_code == status.HTTP_200_OK, response.data
    assert response.data['state'] == 'in_maintenance'

    response = drf_fleet_operator.post(url, data={'type': 'restore'})
    assert response.status_code == status.HTTP_200_OK, response.data
    assert response.data['state'] == 'active'


def test_lock_transitions(drf_admin, lock):
    lock.provision()
    url = reverse_query('lock8:lock-transitions', kwargs={'uuid': lock.uuid})
    drf_admin.assert_count(url, 1)
