import datetime as dt
import uuid

from django.utils import timezone
from freezegun import freeze_time
import pytest
from rest_framework import status

from velodrome.lock8.utils import reverse_query


def test_crud_axa_lock(drf_admin, org, active_requests_mock, settings):
    from velodrome.lock8.models import AxaLock

    url = reverse_query('lock8:axa_lock-list')
    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})

    claim_code = uuid.uuid4()
    response = drf_admin.post(url, {'organization': organization_url,
                                    'uid': '134D90B794994B6753E7',
                                    'claim_code_at_creation': claim_code})

    axa_lock = AxaLock.objects.get()
    detail_url = reverse_query('lock8:axa_lock-detail',
                               kwargs={'uuid': axa_lock.uuid})
    assert response.status_code == status.HTTP_201_CREATED
    assert response.data == {
        'organization': 'http://testserver' + organization_url,
        'url': 'http://testserver' + detail_url,
        'uuid': str(axa_lock.uuid),
        'remote_id': None,
        'uid': '134D90B794994B6753E7',
        'attributes': {},
        'state': 'new',
        'created': axa_lock.created.isoformat()[:-13] + 'Z',
        'modified': axa_lock.modified.isoformat()[:-13] + 'Z',
        'concurrency_version': axa_lock.concurrency_version,
        'bleid': axa_lock.bleid,
    }

    url_action = reverse_query('lock8:axa_lock-actions',
                               kwargs={'uuid': axa_lock.uuid})

    active_requests_mock.register_uri(
        'POST',
        settings.KEY_SAFE_BASE_URI + '/locks',
        json={
            "now": "2016-01-12T22:27:27.675145+00:00",
            "result": {
                "created": "2016-01-11T20:29:02.866292",
                "firmware_modified": "2016-01-11T20:29:02.893996",
                "firmware_version": "1.00",
                "hardware_model": "PCB/eRL2",
                "hardware_version": "1.1",
                "id": 5785905063264256,
                "key": "ahFkZXZ-a2V5c2FmZS1jbG91ZHIRCxIETG9jaxiAgICAgMijCgw",
                "lock_model": "eRL",
                "lock_status": "active",
                "lock_uid": "c32a9cdf35194ddeb6f6",
                "lock_version": "1.0",
                "mac_address": "32453311fdaa",
                "modified": "2016-01-11T23:07:48.215889",
                "nr_of_slots": 3,
                "reference": None,
                "software_modified": "2016-01-11T20:29:03.699398",
                "software_version": "1.00"
            },
            "status": "success"})
    response = drf_admin.post(url_action, {'type': 'claim'})
    assert response.status_code == status.HTTP_200_OK

    axa_lock.refresh_from_db()

    assert axa_lock.state == 'claimed'

    active_requests_mock.register_uri(
        'PUT',
        settings.KEY_SAFE_BASE_URI + '/locks/{}/status'.format(
            axa_lock.remote_id),
        json={
            "now": "2016-01-12T22:27:27.675145+00:00",
            "claim_code": "73530bb081a048c38de1603efd640983",
            "result": {
                "created": "2016-01-11T20:29:02.866292",
                "claim_code": "73530bb081a048c38de1603efd640983",
                "firmware_modified": "2016-01-11T20:29:02.893996",
                "firmware_version": "1.00",
                "hardware_model": "PCB/eRL2",
                "hardware_version": "1.1",
                "id": 5785905063264256,
                "key": "ahFkZXZ-a2V5c2FmZS1jbG91ZHIRCxIETG9jaxiAgICAgMijCgw",
                "lock_model": "eRL",
                "lock_status": "active",
                "lock_uid": "c32a9cdf35194ddeb6f6",
                "lock_version": "1.0",
                "mac_address": "32453311fdaa",
                "modified": "2016-01-11T23:07:48.215889",
                "nr_of_slots": 3,
                "reference": None,
                "software_modified": "2016-01-11T20:29:03.699398",
                "software_version": "1.00"
            },
            "status": "success"})

    response = drf_admin.post(url_action, {'type': 'declare_transferable'})
    assert response.status_code == status.HTTP_200_OK, response.data

    axa_lock.refresh_from_db()

    assert axa_lock.state == 'transferable'
    assert axa_lock.claim_code == '73530bb081a048c38de1603efd640983'


def test_axa_lock_set_stored(drf_admin, drf_fleet_operator, org,
                             axalock, active_requests_mock, settings):
    from velodrome.lock8.models import AxaLockStates

    # To declare lock stored
    active_requests_mock.register_uri(
        'PUT',
        settings.KEY_SAFE_BASE_URI + '/locks/{}/status'.format(
            axalock.remote_id
        ),
        json={
            "now": "2016-01-12T22:27:27.675145+00:00",
            "claim_code": "73530bb081a048c38de1603efd640983",
            "result": {
                "created": "2016-01-11T20:29:02.866292",
                "claim_code": "73530bb081a048c38de1603efd640983",
                "firmware_modified": "2016-01-11T20:29:02.893996",
                "firmware_version": "1.00",
                "hardware_model": "PCB/eRL2",
                "hardware_version": "1.1",
                "id": 5785905063264256,
                "key": "ahFkZXZ-a2V5c2FmZS1jbG91ZHIRCxIETG9jaxiAgICAgMijCgw",
                "lock_model": "eRL",
                "lock_status": "active",
                "lock_uid": "c32a9cdf35194ddeb6f6",
                "lock_version": "1.0",
                "mac_address": "32453311fdaa",
                "modified": "2016-01-11T23:07:48.215889",
                "nr_of_slots": 3,
                "reference": None,
                "software_modified": "2016-01-11T20:29:03.699398",
                "software_version": "1.00"
            },
            "status": "success"})

    url_action = reverse_query(
        'lock8:axa_lock-actions',
        kwargs={'uuid': axalock.uuid}
    )
    response = drf_admin.post(url_action, {'type': 'declare_stored'})
    assert response.status_code == status.HTTP_200_OK, response.data
    axalock.refresh_from_db()
    assert axalock.state == AxaLockStates.STORED.value


def test_axa_lock_filters(drf_admin, axalock):
    url = reverse_query('lock8:axa_lock-list', {'bleid': axalock.bleid})
    drf_admin.assert_count(url, 1)
    url = reverse_query('lock8:axa_lock-list', {'bleid': 'AXA:NONEXISTING'})
    drf_admin.assert_count(url, 0)
    url = reverse_query('lock8:axa_lock-list', {'bleid': 'INVALID'})
    drf_admin.assert_400(url, {'bleid': [{
        'code': 'invalid', 'message': 'AxaLock bleids start with "AXA:"'}]})


@pytest.fixture
def axa_ekey_otps():
    ekey = ('60121260c5bd945bf2067b853e16ed66a252d273-'
            '72126a05be2f3ff59394d5604ad4240bc37d95b9-'
            '8412add945a89014f7c1aecf4d0ff5a3786e945b-'
            '96127a2fa69b040e38af0973b355117be5e0c371-'
            'a812bb5340b3a6ce3ac42dfe51970878ec9eca56-'
            'ba0837eb0792552b9599')
    otps = ['5212ba8489377e58bd1f5acd91c45126237d576b',
            '5212968fbbf25fbe85c8f67225c4e087bddcd9ee',
            '521268b7af3792fabdaa45f127b8e56b01d2e94d',
            '52124f184222dba98cb70de9184c2ef87f597f31',
            '5212e143b3e55e294d1d5c40b8d84759d12f3687',
            '52124b7056b2601723fa7b673673d652a3f94517',
            '5212fe0ede0657dd7654cb3faae2f1ecc7050fd4',
            '52129bd8b296cfbafd215f270396a3532eca1472',
            '5212834666e7bf0e087e2047558d62043347845b',
            '5212dab8351079a7be3f5bcd38b518316a13904f',
            '5212adf47b0607cdfa34480d9ff40f77927bf591']
    return ekey, otps


@pytest.mark.parametrize('slot', (None, 3))
def test_fleet_operator_obtain_ekey(slot, drf_fleet_operator, axalock,
                                    active_requests_mock, axa_ekey_otps,
                                    mocker):
    mocker.patch('velodrome.lock8.views.get_next_ekey_slot', return_value=0)
    ekey, otps = axa_ekey_otps

    active_requests_mock.register_uri(
        'PUT',
        axalock.remote_url + '/slots/%d' % (0 if slot is None else slot),
        json={
            'now': '2017-01-24T18:30:39.485940+00:00',
            'result': {
                'ekey': ekey,
                'modified': '2017-01-24T18:30:38.918580',
                'passkey': '-'.join(otps),
                'passkey_type': 'otp',
                'segmented': True,
                'sequence': 23,
                'slot_position': slot,
                'tag': None},
            "status": "success"},
    )
    query_kwargs = {'number': 11, 'hours': 1}
    if slot is not None:
        query_kwargs['slot'] = slot
    url = reverse_query('lock8:axa_lock-otp', query_kwargs, kwargs={
        'uuid': axalock.uuid})
    drf_fleet_operator.assert_success(url, {
        'ekey': ekey,
        'otps': otps,
        'expiration': '2017-01-24T19:30:39Z'})


@pytest.mark.slow
def test_renter_obtain_ekey(drf_renter, axalock, bicycle, bicycle2,
                            active_requests_mock, alice, axa_ekey_otps,
                            mocker, caplog):
    from rest_framework.exceptions import Throttled
    from rest_framework.settings import api_settings
    from velodrome.lock8.utils import get_exc_fingerprint_for_sentry

    mocker.patch('velodrome.lock8.views.get_next_ekey_slot', return_value=0)
    ekey, otps = axa_ekey_otps

    bicycle.declare_available()
    bicycle.rent(by=alice)
    url = reverse_query('lock8:bicycle-otp', {'number': 11, 'slot': 3},
                        kwargs={'uuid': bicycle.uuid})
    drf_renter.assert_status(url, status.HTTP_404_NOT_FOUND)

    bicycle.axa_lock = axalock
    bicycle.save()
    active_requests_mock.register_uri(
        'PUT',
        axalock.remote_url + '/slots/3',
        json={
            'now': '2017-02-01T18:29:33.278220+00:00',
            'result': {
                'ekey': ekey,
                'modified': '2017-02-01T18:29:32.784500',
                'passkey': '-'.join(otps),
                'passkey_type': 'otp',
                'segmented': True,
                'sequence': 35,
                'slot_position': 2,  # trigger warning.
                'tag': None,
            },
            'status': 'success'},
    )
    with freeze_time(timezone.now() + dt.timedelta(minutes=2)):
        drf_renter.assert_success(url, {
            'ekey': ekey,
            'otps': otps,
            'expiration': '2017-02-01T20:29:33Z'})

        assert ('velodrome.lock8.models', 30,
                'Unexpected slot_position in response (2 != 3).'
                ) in caplog.record_tuples

        # Test rate throttling.
        m = mocker.spy(api_settings, "EXCEPTION_HANDLER")
        for i in range(0, 5):
            drf_renter.assert_success(url)
        response = drf_renter.assert_status(url,
                                            status.HTTP_429_TOO_MANY_REQUESTS)
        assert response.data['detail'] == {
            'non_field_errors': [{'code': 'throttled',
                                  'message': 'Request was throttled. Expected '
                                  'available in 60 seconds.'}]}

        assert len(m.call_args_list) == 1
        exc = m.call_args_list[0][0][0]
        assert isinstance(exc, Throttled)
        assert get_exc_fingerprint_for_sentry(exc) == ['{{ default }}']

    # Move AxaLock to bicycle2.
    bicycle.return_(by=alice)
    bicycle.axa_lock = None
    bicycle.save()
    bicycle2.axa_lock = axalock
    bicycle2.declare_available()
    bicycle2.rent(by=alice)

    url = reverse_query('lock8:bicycle-otp', query_kwargs={'number': 11},
                        kwargs={'uuid': bicycle2.uuid})

    # Uses slot 0 now.
    m_keysafe = active_requests_mock.register_uri(
        'PUT',
        axalock.remote_url + '/slots/0',
        json={
            'now': '2017-02-01T18:29:33.278220+00:00',
            'result': {
                'ekey': ekey,
                'modified': '2017-02-01T18:29:32.784500',
                'passkey': '-'.join(otps),
                'passkey_type': 'otp',
                'segmented': True,
                'sequence': 35,
                'slot_position': 0,
                'tag': None,
            },
            'status': 'success'},
    )
    drf_renter.assert_success(url)
    assert m_keysafe.call_count == 1
    for i in range(0, 5):
        drf_renter.assert_success(url)
    drf_renter.assert_status(url, status.HTTP_429_TOO_MANY_REQUESTS)


def test_axa_lock_transitions(drf_admin, axalock):
    url = reverse_query('lock8:axa_lock-transitions',
                        kwargs={'uuid': axalock.uuid})
    drf_admin.assert_success(url)


def test_renter_update_health_status(drf_renter, axalock, bicycle,
                                     active_requests_mock, alice, mocker):
    url = reverse_query('lock8:bicycle-report-axa-lock-status',
                        kwargs={'uuid': bicycle.uuid})
    bicycle.declare_available()
    bicycle.rent(by=alice)
    response = drf_renter.post(url)
    assert response.status_code == status.HTTP_404_NOT_FOUND

    bicycle.axa_lock = axalock
    bicycle.save()
    active_requests_mock.register_uri(
        'PUT',
        axalock.remote_url + '/health',
        json={
            'now': '2017-02-01T18:29:33.278220+00:00',
            'result': {
                'battery_assessment': 'green',
                'battery_assessment_remarks': '',
                'cycles_performed': 126,
                'modified': '2017-02-01T18:29:33.278220+00:00'
            },
            'status': 'success'},
    )
    response = drf_renter.post(url, {
        'lock_health_msg': "191232453311fdaa1010010056b7bb3e2956af45"})
    assert response.status_code == status.HTTP_204_NO_CONTENT

    axalock.refresh_from_db()
    assert axalock.battery_assessment == 'green'
    assert axalock.battery_assessment_remarks == ''
    assert axalock.cycles_performed == 126


def test_fleet_operator_update_health_status(drf_fleet_operator, axalock,
                                             active_requests_mock, mocker):

    active_requests_mock.register_uri(
        'PUT',
        axalock.remote_url + '/health',
        json={
            'now': '2017-02-01T18:29:33.278220+00:00',
            'result': {
                'battery_assessment': 'green',
                'battery_assessment_remarks': '',
                'cycles_performed': 126,
                'modified': '2017-02-01T18:29:33.278220+00:00'
            },
            'status': 'success'},
    )
    url = reverse_query('lock8:axa_lock-report-axa-lock-status',
                        kwargs={'uuid': axalock.uuid})
    response = drf_fleet_operator.post(url, {
        'lock_health_msg': "191232453311fdaa1010010056b7bb3e2956af45"})
    assert response.status_code == status.HTTP_204_NO_CONTENT

    axalock.refresh_from_db()
    assert axalock.battery_assessment == 'green'
    assert axalock.battery_assessment_remarks == ''
    assert axalock.cycles_performed == 126
