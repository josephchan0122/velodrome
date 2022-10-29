import json

from django.db.utils import InterfaceError
from django.urls import reverse
from django_redis import get_redis_connection
from pinax.stripe.models import Customer, Event, EventProcessingException
import pytest

pytestmark = pytest.mark.django_db


def test_is_there_is_update_no_target(lock, firmware_mercury):
    from velodrome.lock8.utils import handle_firmware_available_request

    firmware_mercury.provision()

    assert firmware_mercury.version == '1.1.1'

    answer = handle_firmware_available_request(lock.serial_number, b'1.1.1')
    assert answer == 1

    answer = handle_firmware_available_request(lock.serial_number, b'1.1.2')
    assert answer == 1


def test_is_there_is_update_mercury(lock, firmware_mercury,
                                    firmware_mercury_update, owner,
                                    django_assert_num_queries):
    from velodrome.lock8.utils import handle_firmware_available_request
    from velodrome.lock8.models import LockFirmwareUpdate

    firmware_mercury.provision()

    # Assign firmwares: current and update.
    LockFirmwareUpdate.objects.create(lock=lock,
                                      firmware=firmware_mercury_update,
                                      owner=owner)

    assert lock.firmware_versions == {}
    answer = handle_firmware_available_request(
        lock.serial_number,
        firmware_mercury.version,
    )
    assert answer == 1

    lock.refresh_from_db()
    assert lock.firmware_versions == {
        'mercury': firmware_mercury.version,
    }

    firmware_mercury_update.provision()
    with django_assert_num_queries(2):
        answer = handle_firmware_available_request(
            lock.serial_number,
            firmware_mercury.version,
        )
    assert answer == 2

    answer = handle_firmware_available_request(
        lock.serial_number,
        firmware_mercury_update.version,
    )
    assert answer == 1


def test_is_there_is_update_mercury_wo_race_condition(lock, firmware_mercury,
                                                      firmware_mercury_update,
                                                      owner, monkeypatch,
                                                      mocker):
    from velodrome.lock8.utils import handle_firmware_available_request
    from velodrome.lock8.models import Lock, LockFirmwareUpdate

    firmware_mercury.provision()

    # Assign firmwares: current and update.
    LockFirmwareUpdate.objects.create(lock=lock,
                                      firmware=firmware_mercury_update,
                                      owner=owner)

    assert lock.firmware_versions == {}
    old_lock = Lock.objects.get(pk=lock.pk)
    lock.firmware_versions['mercury'] = 'something'
    lock.save()

    mock = mocker.Mock(return_value=old_lock)
    monkeypatch.setattr(Lock.objects, 'get', mock)

    answer = handle_firmware_available_request(
        lock.serial_number,
        firmware_mercury.version,
    )
    assert answer == 1

    lock.refresh_from_db()
    assert lock.firmware_versions == {
        'mercury': firmware_mercury.version,
    }


def test_handle_firmware_available_request_without_lock():
    from velodrome.lock8.utils import handle_firmware_available_request
    answer = handle_firmware_available_request(
                '1',
                '',
            )

    assert answer == 1

    answer = handle_firmware_available_request(
                None,
                '1',
            )
    assert answer == 1


def test_handle_firmware_available_request_keeps_existing(lock,
                                                          firmware_mercury):
    from velodrome.lock8.utils import handle_firmware_available_request

    assert lock.firmware_versions == {}
    lock.firmware_versions = {
        'mercury': 'mercury1',
        'something_else': '1',
    }
    lock.save()
    answer = handle_firmware_available_request(
                lock.serial_number,
                firmware_mercury.version,
            )
    assert answer == 1

    lock.refresh_from_db()
    assert lock.firmware_versions == {
        'mercury': firmware_mercury.version,
        'something_else': '1',
    }


def test_mercury_download(lock, firmware_mercury, empty_firmware_mercury,
                          owner):
    from velodrome.lock8.models import LockFirmwareUpdate
    from velodrome.lock8.utils import handle_mercury_download

    empty_firmware_mercury.provision()

    result = handle_mercury_download(lock.serial_number)
    assert result == b'\0'

    LockFirmwareUpdate.objects.create(lock=lock,
                                      firmware=firmware_mercury,
                                      owner=owner)
    firmware_mercury.provision()

    result = handle_mercury_download(lock.serial_number)
    assert result == b'abcd'


def test_rpc_message_handler(rpc_message_handler, mocker, monkeypatch):
    import velodrome.lock8.utils

    mock = mocker.Mock()
    monkeypatch.setattr(velodrome.lock8.utils,
                        'handle_firmware_available_request', mock)
    rpc_message_handler.is_there_is_update(0, 1)
    mock.assert_called_with(0, 1)

    mock = mocker.spy(velodrome.lock8.utils, 'handle_mercury_download')
    rpc_message_handler.get_binary_for_mercury(0)
    mock.assert_called_with(0)


def test_rpc_message_handler_exception(rpc_message_handler, mocker, caplog):
    class CustomException(Exception):
        pass

    mocker.patch('velodrome.lock8.utils.handle_mercury_download',
                 side_effect=CustomException('Custom'))
    with pytest.raises(CustomException):
        rpc_message_handler.get_binary_for_mercury(0)
    assert [(r.levelname, r.message) for r in caplog.records] == [
        ('INFO',
         "Calling get_binary_for_mercury with {'serial_number': 0}."),
        ('ERROR',
         "Exception in RPCMessageHandler.get_binary_for_mercury: Custom")]


def test_rpc_message_handler_with_binary(rpc_message_handler, mocker, owner,
                                         lock, firmware_mercury, caplog):
    import velodrome.lock8.utils
    from velodrome.lock8.models import LockFirmwareUpdate

    mock = mocker.spy(velodrome.lock8.utils, 'handle_mercury_download')

    rpc_message_handler.get_binary_for_mercury(lock.serial_number)
    mock.assert_called_with(lock.serial_number)
    assert ["Calling get_binary_for_mercury with {}.".format({
                'serial_number': lock.serial_number}),
            "Returning: 1 byte."] == [rec.message for rec in caplog.records]
    caplog.clear()

    firmware_mercury.provision()
    LockFirmwareUpdate.objects.create(lock=lock,
                                      firmware=firmware_mercury,
                                      owner=owner)
    rpc_message_handler.get_binary_for_mercury(lock.serial_number)
    mock.assert_called_with(lock.serial_number)
    assert ["Calling get_binary_for_mercury with {}.".format({
                'serial_number': lock.serial_number}),
            "Returning: {} bytes.".format(len(firmware_mercury.binary.read()))
            ] == [rec.message for rec in caplog.records]


def test_rpc_message_handler_connection_already_closed(
        rpc_message_handler, mocker):
    import velodrome.lock8.utils
    mocked = mocker.patch('velodrome.lock8.utils.handle_mercury_download',
                          side_effect=[
                              InterfaceError('connection already closed'),
                              True,
                          ])
    spy = mocker.spy(velodrome.lock8.utils.connection, 'close')
    rpc_message_handler.get_binary_for_mercury(0)
    spy.assert_called_once()
    assert mocked.call_count == 2


def test_reverse_query():
    from velodrome.lock8.utils import reverse_query

    url = reverse('lock8:lock-detail', kwargs={'uuid': 1})
    assert reverse_query('lock8:lock-detail', {}, {'uuid': 1}) == url

    url = reverse('lock8:lock-detail', kwargs={'uuid': 1}) + '?q=1'
    assert reverse_query('lock8:lock-detail', {'q': 1}, {'uuid': 1}) == url

    url = reverse('lock8:lock-detail', kwargs={'uuid': 1}) + '?foo=1&foo=2'
    assert reverse_query('lock8:lock-detail', (('foo', 1), ('foo', 2)),
                         {'uuid': 1}) == url

    with pytest.raises(ImportError) as e:
        reverse_query('lock8:lock-detail', {'q': 1}, {'uuid': 1},
                      urlconf="non-existing")
    assert e.value.msg == "No module named 'non-existing'"


@pytest.mark.parametrize('with_account', (None, True, False))
def test_ingest_stripe_event(with_account, request, customer_json,
                             active_requests_mock, mocker, caplog):
    from velodrome.lock8.utils import ingest_stripe_event
    data = {'id': 'evt_023456789',
            'type': 'customer.updated',
            'pending_webhooks': 1,
            'livemode': False,
            'object': 'event',
            'data': {'object': customer_json}}

    stripe_account = None
    if with_account:
        stripe_account = request.getfixturevalue('stripe_account')
        data['account'] = stripe_account.stripe_id
    elif with_account is None:
        data['account'] = 'acct_nonexisting'

    active_requests_mock.get('https://api.stripe.com/v1/events/evt_023456789',
                             text=json.dumps(data))

    class CustomException(Exception):
        pass
    mocker.patch('pinax.stripe.actions.events.add_event',
                 side_effect=CustomException('CustomException-string', 2))
    ingest_stripe_event(data)
    e = EventProcessingException.objects.get()
    assert e.message == "CustomException('CustomException-string', 2)"
    assert 'evt_023456789' in e.data
    assert not Event.objects.exists()

    assert not Customer.objects.exists()

    mocker.stopall()
    ingest_stripe_event(data)
    event = Event.objects.get()
    assert event.validated_message == data

    if with_account:
        assert event.stripe_account == stripe_account
    elif with_account is None:
        assert event.stripe_account.stripe_id == 'acct_nonexisting'

    Customer.objects.get(
        stripe_id=customer_json['id'],
        stripe_account__stripe_id=data.get('account'),
    )

    ingest_stripe_event(data)
    assert Event.objects.count() == 1
    e = EventProcessingException.objects.get(
        message='Duplicate event record.')
    assert 'evt_023456789' in e.data

    msgs = [(rec.levelname, rec.message) for rec in caplog.records]
    assert msgs[0] == (
        'ERROR', "ingest_stripe_event: customer.updated: "
        "CustomException('CustomException-string', 2)")


def test_ingest_stripe_event_without_event_type(
        customer_json, customer, active_requests_mock, mocker, caplog):
    from velodrome.lock8.utils import ingest_stripe_event
    data = {'id': 'evt_023456789',
            'pending_webhooks': 1,
            'livemode': False,
            'object': 'event',
            'data': {'object': customer_json}}

    ingest_stripe_event(data)
    e = EventProcessingException.objects.get()
    assert e.message in ("KeyError('type',)", "KeyError('type')")
    assert 'evt_023456789' in e.data
    assert not Event.objects.exists()

    msgs = [(rec.levelname, rec.message) for rec in caplog.records]
    assert msgs[0] in (
        ('ERROR', "ingest_stripe_event: unknown event: KeyError('type',)"),
        ('ERROR', "ingest_stripe_event: unknown event: KeyError('type')")
    )


def test_ingest_stripe_event_checks_livemode():
    from velodrome.lock8.utils import ingest_stripe_event
    data = {'livemode': True}

    ingest_stripe_event(data)

    e = EventProcessingException.objects.get()
    assert e.message in (
        "RuntimeError('Received unexpected Stripe event: livemode=True/settings=False',)",  # noqa: E501
        "RuntimeError('Received unexpected Stripe event: livemode=True/settings=False')"  # noqa: E501
    )


def test_clustering(create_gps_tracking, bicycle):
    from velodrome.lock8.models import ReadonlyTracking
    from velodrome.lock8.utils import ClusterWithin

    assert not ReadonlyTracking.objects.count()

    # Create points only once. Could be a module scoped fixture, but involves
    # refactoring.
    for point in ((0, 0), (1, 1), (5, 5), (4, 4), (6, 6), (7, 7)):
        lon, lat = point
        create_gps_tracking(bicycle, lon, lat)

    for (distance, expected_count) in (
            (10, 1),
            (3, 2),
            (1, 6),
            (.1, 6),
    ):
        polys = (ReadonlyTracking.objects
                 .annotate(clusters=ClusterWithin('point', distance=distance))
                 .values('clusters')
                 .order_by())
        assert len(polys) == expected_count


@pytest.mark.parametrize('stored,expected', [
    (None, 0),
    (1, 1),
    (3, 0),
])
def test_get_next_ekey_slot(axalock, stored, expected):
    from velodrome.lock8.utils import get_next_ekey_slot
    redis = get_redis_connection('default')
    slot_key = 'ekey-slot-{}'.format(axalock.uuid)
    if stored:
        redis.set(slot_key, stored)
    value = get_next_ekey_slot(axalock)
    assert value == expected

    next_value = get_next_ekey_slot(axalock)
    if stored == 3:
        assert next_value == 0
    else:
        assert next_value == expected + 1


@pytest.mark.parametrize('with_metadata', [True, False])
def test_update_bicycle_metadata(bicycle, with_metadata):
    from velodrome.lock8.models import BicycleMetaData
    from velodrome.lock8.utils import update_bicycle_metadata

    if with_metadata:
        BicycleMetaData.objects.create(bicycle=bicycle)
    update_bicycle_metadata({'uuid': bicycle.uuid,
                             'version': 'v1',
                             'properties': {'recoverability_score': 34,
                                            'needs_attention_score': 78}})

    bicycle.metadata.refresh_from_db()
    assert bicycle.metadata.recoverability_score == 34
    assert bicycle.metadata.needs_attention_score == 78


def test_update_bicycle_metadata_error(non_matching_uuid):
    from velodrome.lock8.models import Bicycle
    from velodrome.lock8.utils import update_bicycle_metadata

    with pytest.raises(Bicycle.DoesNotExist):
        update_bicycle_metadata({'uuid': non_matching_uuid,
                                 'version': 'v1',
                                 'properties': {'recoverability_score': 34,
                                                'needs_attention_score': 78}})


def test_notification_message_uri_builder(alice, bicycle):
    from velodrome.lock8.utils import build_frontend_uri
    assert build_frontend_uri('users', alice.uuid) == (
            f'https://fms.noa.one/users/{str(alice.uuid)}'
        )
    assert build_frontend_uri(
        'bicycles', bicycle.uuid) == (
                f'https://fms.noa.one/bicycles/{str(bicycle.uuid)}'
        )


def test_create_affiliations_if_whitelisted(alice, org):
    from velodrome.lock8.utils import create_affiliations_if_whitelisted

    org.allowed_signup_domain_names = [alice.email.split('@')[1]]
    org.save()

    create_affiliations_if_whitelisted(alice)
    assert alice.organizations.get() == org


def test_create_affiliations_if_whitelisted_but_whitelabel(alice, org):
    from velodrome.lock8.utils import create_affiliations_if_whitelisted

    assert not alice.organizations.exists()

    alice.organization = org
    alice.save()

    create_affiliations_if_whitelisted(alice)
    assert not alice.organizations.exists()
