import uuid


def test_axa_lock_model(org, owner, active_requests_mock, settings):
    from velodrome.lock8.models import AxaLock

    claim_code = uuid.uuid4()
    axa_lock = AxaLock.objects.create(
        organization=org,
        owner=owner,
        uid='134D90B794994B6753E7',
        claim_code_at_creation=claim_code,
    )
    assert axa_lock.state == 'new'

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
    axa_lock.claim()
    axa_lock.refresh_from_db()
    assert axa_lock.state == 'claimed'
    assert axa_lock.remote_id == 5785905063264256
    assert axa_lock.attributes
    assert axa_lock.key == (
        'ahFkZXZ-a2V5c2FmZS1jbG91ZHIRCxIETG9jaxiAgICAgMijCgw')

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
    axa_lock.declare_transferable()
    axa_lock.refresh_from_db()
    assert axa_lock.state == 'transferable'
    assert axa_lock.claim_code == '73530bb081a048c38de1603efd640983'


def test_axa_lock_sync(axalock, active_requests_mock, settings):
    active_requests_mock.register_uri(
        'GET',
        settings.KEY_SAFE_BASE_URI + '/locks/' + str(axalock.remote_id),
        [{'json': {
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
            "status": "success"}}],
    )
    axalock.sync()

    assert axalock.attributes == {
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
    }
