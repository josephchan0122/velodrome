from copy import deepcopy
import datetime as dt
from decimal import Decimal
import json
import uuid

from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.test.utils import CaptureQueriesContext
from django.utils import timezone as django_timezone
from django_redis import get_redis_connection
from freezegun import freeze_time
import pytest
from reversion.models import Version
import reversion.revisions
import stripe


@pytest.fixture
def webhook_customer_source_created(customer, mocker):
    from pinax.stripe.models import Event
    from pinax.stripe.webhooks import CustomerSourceCreatedWebhook

    event = Event.objects.create(
        kind=CustomerSourceCreatedWebhook.name,
        webhook_message={
            "id": "evt_source_created",
            "object": "event",
            "account": customer.stripe_account.stripe_id,
            "api_version": "2017-08-15",
            "created": 1525781014,
            "data": {
                "object": {
                    "id": "src_new_source",
                    "object": "source",
                    "amount": None,
                    "card": {
                        "exp_month": 12,
                        "exp_year": 2020,
                        "brand": "Visa",
                        "card_automatically_updated": False,
                        "country": "US",
                        "cvc_check": "pass",
                        "fingerprint": "FP",
                        "funding": "credit",
                        "last4": "1234",
                        "three_d_secure": "optional",
                        "address_line1_check": None,
                        "address_zip_check": None,
                        "tokenization_method": None,
                        "dynamic_last4": None
                    },
                    "client_secret": "src_client_secret_SECRET",
                    "created": 1525781011,
                    "currency": None,
                    "customer": customer.stripe_id,
                    "flow": "none",
                    "livemode": True,
                    "metadata": {},
                    "owner": {
                        "address": {
                            "city": None,
                            "country": "US",
                            "line1": None,
                            "line2": None,
                            "postal_code": None,
                            "state": None
                        },
                        "email": None,
                        "name": None,
                        "phone": None,
                        "verified_address": None,
                        "verified_email": None,
                        "verified_name": None,
                        "verified_phone": None
                    },
                    "statement_descriptor": None,
                    "status": "chargeable",
                    "type": "card",
                    "usage": "reusable"
                }
            },
            "livemode": True,
            "pending_webhooks": 1,
            "request": {
                "id": "req_QT79AmQEp9gkie",
                "idempotency_key": None
            },
            "type": "customer.source.created"
        },
        valid=True,
        processed=False,
    )
    event.validated_message = event.webhook_message
    event.stripe_account = customer.stripe_account

    webhook = CustomerSourceCreatedWebhook(event)
    return webhook


def test_bicycle_model_base(org, owner, lock, city_bike, create_gps_tracking,
                            create_dss_tracking):
    from velodrome.lock8.models import Bicycle

    bicycle = Bicycle.objects.create(organization=org,
                                     owner=owner,
                                     reference='City-00012',
                                     name='Pretty Bike')

    with pytest.raises(ValidationError):
        # Because there is no lock.
        bicycle.declare_available()

    assert bicycle.organization == org
    assert bicycle.owner == owner
    assert bicycle.reference == 'City-00012'
    assert bicycle.name == 'Pretty Bike'
    assert bicycle.state == 'in_maintenance'
    assert bicycle.latitude is None
    assert bicycle.longitude is None
    assert bicycle.lock is None
    assert bicycle.state_of_charge is None
    assert bicycle.estimated_state_of_charge is None
    assert bicycle.is_cycling_within_service_area
    assert bicycle.time_stamp is None

    create_gps_tracking(lock, 13.403145, 52.527433, time_stamp=1428509326)

    bicycle = Bicycle.objects.get(pk=bicycle.pk)

    assert bicycle.latest_gps_timestamp is None
    assert bicycle.private_tracking is None
    assert bicycle.latitude is None
    assert bicycle.longitude is None

    bicycle = Bicycle.objects.get(pk=bicycle.pk)

    bicycle.lock = lock
    lock.provision()
    bicycle.save()

    create_gps_tracking(lock, 13.403146, 52.527434, time_stamp=1428509327)

    bicycle = Bicycle.objects.get(pk=bicycle.pk)
    with CaptureQueriesContext(connection) as capture:
        bicycle.private_tracking
    assert bicycle.latest_gps_timestamp == dt.datetime.fromtimestamp(
        1428509327, tz=dt.timezone.utc)
    assert bicycle.latitude == 52.527434
    assert bicycle.longitude == 13.403146
    assert len(capture.captured_queries) == 1

    bicycle = Bicycle.objects.select_related(
        'private_tracking').get(pk=bicycle.pk)
    with CaptureQueriesContext(connection) as capture:
        bicycle.private_tracking
    assert not capture.captured_queries

    create_dss_tracking(lock, 33., time_stamp=1428509327)
    bicycle.private_tracking.refresh_from_db()

    assert bicycle.state_of_charge == 33.

    bicycle.put_in_maintenance()
    assert bicycle.state == 'in_maintenance'

    bicycle.declare_lost()
    assert bicycle.state == 'lost'

    bicycle.put_in_maintenance()
    assert bicycle.state == 'in_maintenance'

    bicycle.declare_lost()
    assert bicycle.state == 'lost'

    bicycle.declare_unrecoverable()
    assert bicycle.state == 'unrecoverable'

    bicycle.declare_available()
    assert bicycle.state == 'available'

    now = django_timezone.now()
    with freeze_time(now):
        create_dss_tracking(lock, 33., time_stamp=now.timestamp())
        bicycle.private_tracking.refresh_from_db()

        with freeze_time(now + dt.timedelta(hours=20)):
            assert bicycle.estimated_state_of_charge == 32.

        with freeze_time(now + dt.timedelta(hours=60)):
            assert bicycle.estimated_state_of_charge == 30.

        with freeze_time(now - dt.timedelta(hours=20)):
            assert bicycle.estimated_state_of_charge == 33.

        with freeze_time(now + dt.timedelta(hours=666)):
            assert bicycle.estimated_state_of_charge == 0.


def test_can_create_bicycle_with_lock(lock, owner, org, gps_tracking):
    from velodrome.lock8.models import Bicycle

    bicycle = Bicycle(organization=org,
                      owner=owner,
                      name='Pretty Bike',
                      )
    bicycle.lock = lock
    bicycle.save()
    lock.provision()
    bicycle.save()


def test_cant_pair_lock_from_another_org(bicycle, another_lock):
    bicycle.lock = another_lock
    with pytest.raises(ValidationError):
        bicycle.full_clean()


def test_cant_rent_more_than_max_allowed_bicycles_per_renter(
        organization_preference, bicycle, alice, lock, bob, org):
    from velodrome.lock8.models import Affiliation

    Affiliation.objects.create(user=bob,
                               organization=org)

    organization_preference.max_allowed_bicycles_per_renter = 2
    organization_preference.save()

    bicycle2 = deepcopy(bicycle)
    bicycle3 = deepcopy(bicycle)

    lock2 = deepcopy(lock)
    lock3 = deepcopy(lock)

    lock2.pk = None
    lock2.uuid = uuid.uuid4()
    lock2.serial_number = '2'
    lock2.bleid = lock.bleid[:-1] + '2'
    lock2.imei = lock.imei[:-1] + '2'
    lock2.iccid = lock.iccid[:-1] + '2'
    lock2.save()

    lock3.pk = None
    lock3.uuid = uuid.uuid4()
    lock3.serial_number = '3'
    lock3.bleid = lock.bleid[:-1] + '3'
    lock3.imei = lock.imei[:-1] + '3'
    lock3.iccid = lock.iccid[:-1] + '3'
    lock3.save()

    assert lock != lock2 != lock3

    bicycle2.pk = None
    bicycle2.name = 'bicycle2'
    bicycle2.uuid = uuid.uuid4()
    bicycle2.short_id = '2'
    bicycle2.lock = lock2
    bicycle2.save()

    bicycle3.pk = None
    bicycle3.name = 'bicycle3'
    bicycle3.uuid = uuid.uuid4()
    bicycle3.short_id = '3'
    bicycle3.lock = lock3
    bicycle3.save()

    bicycle.declare_available()
    bicycle2.declare_available()
    bicycle3.declare_available()

    bicycle.reserve(by=alice)
    bicycle2.reserve(by=alice)

    with pytest.raises(ValidationError) as exc:
        bicycle.rent(by=bob)
    assert 'This bicycle is already reserved.' in str(exc.value)

    with pytest.raises(ValidationError) as exc:
        bicycle3.reserve(by=alice)
    assert 'You already have 2 active reservations.' in str(exc.value)
    assert exc.value.code == 'too_many_reservations'

    with pytest.raises(ValidationError) as exc:
        bicycle3.rent(by=alice)
    assert 'You already have 2 active reservations.' in str(exc.value)
    assert exc.value.code == 'too_many_reservations'

    bicycle.rent(by=alice)
    bicycle2.rent(by=alice)

    with pytest.raises(ValidationError) as exc:
        bicycle3.rent(by=alice)
    assert 'You already have 2 active rental sessions.' in str(exc.value)
    assert exc.value.code == 'too_many_rentalsessions'

    with pytest.raises(ValidationError) as exc:
        bicycle3.reserve(by=alice)
    assert 'You already have 2 active rental sessions.' in str(exc.value)
    assert exc.value.code == 'too_many_rentalsessions'


def test_bicycle_transitions(owner, alice, bicycle, org, another_bicycle,
                             axalock):
    from velodrome.lock8.models import RentingScheme

    another_bicycle.declare_available()

    assert bicycle.latest_transition_by is None
    assert bicycle.state == 'in_maintenance'
    assert len(bicycle.active_reservations) == 0
    assert bicycle.active_reservation is None
    assert bicycle.active_rental_session is None
    assert len(bicycle.active_rental_sessions) == 0

    bicycle.declare_available(by=owner)
    assert bicycle.latest_transition_by == owner
    assert bicycle.state == 'available'
    assert len(bicycle.active_reservations) == 0
    assert bicycle.active_rental_session is None
    assert len(bicycle.active_rental_sessions) == 0

    bicycle.reserve(by=alice, user=alice)
    assert bicycle.latest_transition_by == alice
    assert bicycle.state == 'reserved'
    assert len(bicycle.active_reservations) == 1
    assert bicycle.active_reservation is not None
    assert bicycle.active_rental_session is None
    assert len(bicycle.active_rental_sessions) == 0

    with pytest.raises(ValidationError):
        another_bicycle.reserve(by=alice)

    with pytest.raises(ValidationError):
        another_bicycle.rent(by=alice)

    bicycle.cancel_reservation(by=alice)
    assert bicycle.latest_transition_by == alice
    assert bicycle.state == 'available'
    assert len(bicycle.active_reservations) == 0
    assert len(bicycle.active_rental_sessions) == 0
    assert bicycle.active_reservation is None
    assert bicycle.active_rental_session is None

    bicycle.reserve(by=alice, user=alice)
    assert bicycle.latest_transition_by == alice
    assert bicycle.state == 'reserved'
    assert len(bicycle.active_reservations) == 1
    assert len(bicycle.active_rental_sessions) == 0
    assert bicycle.active_reservation is not None
    assert bicycle.active_rental_session is None

    bicycle.rent(by=alice, user=alice)
    assert bicycle.latest_transition_by == alice
    assert bicycle.state == 'rented'
    assert len(bicycle.active_reservations) == 0
    assert len(bicycle.active_rental_sessions) == 1
    assert bicycle.active_reservation is None
    assert bicycle.active_rental_session is not None

    with pytest.raises(ValidationError):
        another_bicycle.reserve(by=alice)

    with pytest.raises(ValidationError):
        another_bicycle.rent(by=alice)

    bicycle.return_(by=alice)
    assert bicycle.latest_transition_by == alice
    assert bicycle.state == 'available'
    assert len(bicycle.active_reservations) == 0
    assert len(bicycle.active_rental_sessions) == 0
    assert bicycle.active_rental_session is None

    bicycle.declare_lost(by=owner)
    assert bicycle.latest_transition_by == owner
    assert bicycle.state == 'lost'
    assert len(bicycle.active_reservations) == 0
    assert len(bicycle.active_rental_sessions) == 0
    assert bicycle.active_rental_session is None

    bicycle.declare_available(by=owner)
    assert bicycle.latest_transition_by == owner
    assert bicycle.state == 'available'
    assert len(bicycle.active_reservations) == 0
    assert len(bicycle.active_rental_sessions) == 0
    assert bicycle.active_rental_session is None

    bicycle.rent(by=alice, user=alice)
    assert bicycle.latest_transition_by == alice
    assert bicycle.state == 'rented'
    assert len(bicycle.active_reservations) == 0
    assert len(bicycle.active_rental_sessions) == 1
    assert bicycle.active_rental_session is not None

    bicycle.return_(by=owner)
    assert bicycle.latest_transition_by == owner
    assert bicycle.state == 'available'
    assert len(bicycle.active_reservations) == 0
    assert len(bicycle.active_rental_sessions) == 0
    assert bicycle.active_rental_session is None

    RentingScheme.objects.create(
        owner=owner,
        organization=org,
        max_reservation_duration=dt.timedelta(minutes=1),
    )

    # the second RentingScheme takes precedence because it apply
    # to the bicycle directly, not only the organization.
    RentingScheme.objects.create(
        owner=owner,
        organization=org,
        max_reservation_duration=dt.timedelta(minutes=2),
        bicycle=bicycle,
    )
    bicycle.reserve(by=alice, user=alice)
    assert bicycle.latest_transition_by == alice
    assert bicycle.state == 'reserved'
    assert len(bicycle.active_reservations) == 1
    assert len(bicycle.active_rental_sessions) == 0
    assert bicycle.active_rental_session is None

    bicycle.force_put_in_maintenance()
    assert bicycle.state == 'in_maintenance'

    with pytest.raises(ValidationError):
        bicycle.retire()

    bicycle.lock = None
    bicycle.axa_lock = axalock

    with pytest.raises(ValidationError):
        bicycle.retire()

    bicycle.axa_lock = None

    bicycle.retire()
    assert bicycle.state == 'retired'

    bicycle.force_put_in_maintenance()
    assert bicycle.state == 'in_maintenance'

    bicycle.take_over()
    assert bicycle.state == 'in_maintenance'


def test_rent_with_unexpected_pricingscheme_or_subplan(
        bicycle_available, renter):
    assert not bicycle_available.organization.uses_payments
    with pytest.raises(ValidationError) as excinfo:
        bicycle_available.rent(by=renter, subscription_plan=object())
    assert excinfo.value.message_dict == {
        'subscription_plan': ['The organization does not use payments.']}

    with pytest.raises(ValidationError) as excinfo:
        bicycle_available.rent(by=renter, pricing_scheme=object())
    assert excinfo.value.message_dict == {
        'pricing_scheme': ['The organization does not use payments.']}


def test_renter_can_rent_several_bicycles(owner, alice, bicycle,
                                          org, another_bicycle,
                                          organization_preference,
                                          another_organization_preference):
    """
    Alice can reserve and rent two Bicycles at the same time.
    """
    organization_preference.max_allowed_bicycles_per_renter = 2
    organization_preference.save()

    another_organization_preference.max_allowed_bicycles_per_renter = 2
    another_organization_preference.save()

    bicycle.declare_available()
    another_bicycle.declare_available()

    bicycle.reserve(by=alice)
    another_bicycle.reserve(by=alice)

    bicycle.rent(by=alice)
    another_bicycle.rent(by=alice)


def test_bicycle_deletion_free_the_lock(owner, alice, bicycle, lock):
    from velodrome.lock8.models import Bicycle, Lock

    bicycle.lock = lock
    bicycle.save()

    bicycle.delete()

    lock = Lock.objects.get(pk=lock.pk)
    with pytest.raises(Bicycle.DoesNotExist):
        lock.bicycle


def test_bicycle_is_within_dropzone_with_accuracy(
        bicycle, zone, middle_of_central_park,
        middle_of_theodore_roosevelt_park, active_lock, alice,
        create_gps_tracking):
    from velodrome.lock8.models import Bicycle

    with freeze_time(dt.datetime.fromtimestamp(1428509326,
                                               tz=dt.timezone.utc)):
        create_gps_tracking(bicycle, *middle_of_central_park.tuple)

        zone.created = dt.datetime.now().replace(tzinfo=dt.timezone.utc)
        zone.save()

    assert bicycle.is_allowed_to_be_dropped

    lon, lat = middle_of_theodore_roosevelt_park.tuple
    create_gps_tracking(bicycle, lon, lat, attributes={
        'serial_number': active_lock.serial_number,
        'time_stamp': 1428509327,
        'gps_utm_zone': -7.530941473730957e-14,
        'gps_accuracy': 0})
    bicycle = Bicycle.objects.get(pk=bicycle.pk)
    assert not bicycle.is_allowed_to_be_dropped

    body = {'time_stamp': 1428509328,
            'gps_utm_zone': -7.530941473730957e-14,
            'gps_accuracy': 150,
            'gps_pdop': 2,
            }

    create_gps_tracking(active_lock, lon, lat, attributes=body)
    bicycle = Bicycle.objects.get(pk=bicycle.pk)
    assert bicycle.is_allowed_to_be_dropped


def test_bicycle_is_within_dropzone(bicycle, zone, middle_of_central_park,
                                    active_lock, alice, zone_somewhere,
                                    organization_preference,
                                    create_gps_tracking):
    from velodrome.lock8.models import Bicycle
    from velodrome.lock8.models import Alert

    organization_preference.allow_returning_bicycle_outside_drop_zone = False
    organization_preference.save()

    create_gps_tracking(active_lock, *middle_of_central_park,
                        time_stamp=1428509326,
                        attributes={'gps_accuracy': 30.1328125})

    bicycle.rent(by=alice)
    bicycle.return_()

    create_gps_tracking(active_lock, 52.516384, 13.3761745,
                        time_stamp=1428509327,
                        attributes={'gps_accuracy': 30.1328125})

    bicycle = Bicycle.objects.get(pk=bicycle.pk)
    bicycle.rent(by=alice)

    with pytest.raises(ValidationError) as exc:
        bicycle.return_(by=alice)
    exc.match('This bicycle is not allowed to be returned here.')
    assert exc.value.code == 'outside_dropzone'

    alert_type = Alert.ZONE_LOW_THRESHOLD_TRIGGERED
    assert Alert.objects.filter(alert_type=alert_type).count() == 1
    assert Alert.objects.all().count() == 1


def test_bicycle_can_be_returned_outside_dropzone(
        bicycle, zone, org, owner, middle_of_central_park, active_lock, alice,
        fleet_operator, zone_somewhere,
        create_gps_tracking):
    from velodrome.lock8.models import (
        Bicycle, Alert, OrganizationPreference)

    OrganizationPreference.objects.create(
        owner=owner,
        organization=org,
        allow_returning_bicycle_outside_drop_zone=True,
        currency='usd',
    )

    create_gps_tracking(active_lock, 52.516384, 13.3761745,
                        time_stamp=1428509327)

    bicycle = Bicycle.objects.get(pk=bicycle.pk)
    bicycle.rent(by=alice)

    bicycle.return_(by=alice)

    alert = Alert.objects.get()
    assert alert.alert_type == Alert.RETURN_OUTSIDE_DROP_ZONE

    bicycle.rent(by=alice)
    bicycle.return_(by=alice)

    alert = Alert.objects.get()
    assert alert.context['location'] == {
        'coordinates': [52.516384, 13.3761745],
        'type': 'Point'}

    bicycle.refresh_from_db()
    bicycle.rent(by=alice)

    create_gps_tracking(active_lock, *middle_of_central_park,
                        time_stamp=1428509328)

    bicycle = Bicycle.objects.get(pk=bicycle.pk)
    bicycle.return_(by=alice)

    alert.refresh_from_db()
    assert alert.state == 'stopped'


def test_bicycle_can_be_dropped_in_maintenance_zone(
        bicycle, zone, maintenance_zone, middle_of_somewhere, active_lock,
        alice, create_gps_tracking, organization_preference):
    from velodrome.lock8.models import Alert

    organization_preference.allow_returning_bicycle_outside_drop_zone = False
    organization_preference.save()
    create_gps_tracking(bicycle, *middle_of_somewhere.tuple)

    bicycle.rent(by=alice)
    bicycle.return_(by=alice)
    assert not Alert.objects.exists()


@pytest.mark.parametrize('lock_on_bicycle', (False, True))
def test_bicycle_assign_latest_tracking_with_lock(
        lock_on_bicycle, bicycle_without_lock, lock,
        create_gps_tracking, create_dss_tracking):

    bicycle = bicycle_without_lock
    assert bicycle.state_of_charge is None

    if lock_on_bicycle:
        lock.provision()
        bicycle.lock = lock
        bicycle.save()

    create_gps_tracking(lock, 1, 1)
    create_dss_tracking(lock, 50)

    if lock_on_bicycle:
        assert bicycle.state_of_charge is not None
    else:
        assert bicycle.state_of_charge is None


def test_bicycle_assign_latest_tracking_ignores_revisions(
        bicycle_or_lock, middle_of_central_park, active_lock,
        create_gps_tracking):
    assert reversion.revisions.is_registered(bicycle_or_lock.__class__)

    ctype = ContentType.objects.get_for_model(bicycle_or_lock.__class__)
    with pytest.raises(Version.DoesNotExist):
        Version.objects.get(content_type=ctype, object_id=bicycle_or_lock.pk)

    with reversion.revisions.create_revision():
        create_gps_tracking(bicycle_or_lock,
                            *middle_of_central_park.tuple,
                            activate=False, declare_available=False)

    with pytest.raises(Version.DoesNotExist):
        Version.objects.get(content_type=ctype, object_id=bicycle_or_lock.pk)

    with reversion.revisions.create_revision():
        bicycle_or_lock.save()

    assert Version.objects.filter(
        content_type=ctype, object_id=bicycle_or_lock.pk).count() == 1


def test_bicycle_assign_trackings_without_lock(bicycle_without_lock,
                                               gps_tracking):
    from velodrome.lock8.conftest import assign_trackings
    assign_trackings(bicycle_without_lock, gps_tracking.attributes, 'GPS')
    assert (bicycle_without_lock.private_tracking.attributes ==
            gps_tracking.attributes)


@pytest.mark.parametrize('new_state_of_charge', (None, 5))
def test_bicycle_with_dss_state_of_charge_missing(bicycle, active_lock,
                                                  request,
                                                  new_state_of_charge,
                                                  create_dss_tracking):
    """It happens some DSS don't have state_of_charge entries.
    The parametrization is there to ensure that the refresh_from_db is used
    correctly."""

    assert bicycle.state_of_charge is None

    request.getfixturevalue('dss_tracking')
    previous_state_of_charge = bicycle.state_of_charge
    assert previous_state_of_charge

    create_dss_tracking(active_lock, new_state_of_charge, event=10)
    bicycle.private_tracking.refresh_from_db()

    if new_state_of_charge is None:
        assert bicycle.state_of_charge == previous_state_of_charge
    else:
        assert bicycle.state_of_charge == new_state_of_charge


@pytest.mark.skip(reason='publish_updates on save is disabled')
def test_bicycle_updates_are_published(bicycle, org, commit_success):
    redis = get_redis_connection('publisher')

    pubsub = redis.pubsub()
    channel = '/{}/admin/bicycles/{}/'.format(org.uuid, bicycle.uuid)
    pubsub.subscribe(channel)
    message = pubsub.get_message()
    assert message == {'channel': channel.encode('utf-8'),
                       'data': 1,
                       'pattern': None,
                       'type': 'subscribe'}
    bicycle.save()
    commit_success()

    message = pubsub.get_message()
    assert sorted(list(message.keys())) == ['channel', 'data',
                                            'pattern', 'type']
    assert message['channel'] == channel.encode('utf-8')
    assert message['pattern'] is None
    assert message['type'] == 'message'

    assert json.loads(message['data'].decode('utf-8')) == {
        'topic': '/{}/admin/bicycles/{}/'.format(org.uuid, bicycle.uuid),
        'sender': 'bicycle',
        'message': {
            'name': bicycle.name,
            'description': '',
            'bleid': bicycle.lock.bleid,
            'device_type': 'lock',
            'image_url': None,
            'reservation': None,
            'rental_session': None,
            'short_id': bicycle.short_id,
            'bicycle_model_name': None,
            'serial_number': 'bicycle',
            'latitude': None,
            'longitude': None,
            'latest_gps_accuracy': None,
            'latest_gps_pdop': None,
            'latest_gps_timestamp': None,
            'state_of_charge': None,
            'estimated_state_of_charge': None,
            'last_cellular_update': None,
            'devices': {'lock': {'bleid': bicycle.lock.bleid,
                                 'manufacturer': 'noa'}},
            'distance': None,
            'state': bicycle.state,
            'uuid': str(bicycle.uuid),
            'created': bicycle.created.isoformat()[:-13] + 'Z',
            'modified': bicycle.modified.isoformat()[:-13] + 'Z',
            'concurrency_version': bicycle.concurrency_version,
        }}


def test_bicycle_publish_on_commit_queries(mocker, bicycle):
    import velodrome
    from velodrome.lock8.models import publish_update_on_commit

    m = mocker.spy(velodrome.lock8.models.BicycleQuerySet, 'prefetch_active')
    with CaptureQueriesContext(connection) as capture:
        publish_update_on_commit(bicycle)
    # TODO: Unstable behaviour here: difference between local and travis
    assert len(capture.captured_queries) in (10, 11), '\n\n'.join(
        q['sql'] for q in capture.captured_queries)
    assert m.call_count == 1


# XXX: needs test for True case.
def test_build_publisher_topics_bicycle(bicycle, root_org, org, alice):
    from velodrome.lock8.dispatchers import build_publisher_topics

    assert sorted(build_publisher_topics(bicycle)) == sorted([
        ('/{}/admin/bicycles/{}/'.format(org.uuid, bicycle.uuid), False),
        ('/{}/{}/admin/bicycles/{}/'.format(
            root_org.uuid, org.uuid, bicycle.uuid), False),
        ('/{}/fleet_operator/bicycles/{}/'.format(
            org.uuid, bicycle.uuid), False),
        ('/{}/{}/fleet_operator/bicycles/{}/'.format(
            root_org.uuid, org.uuid, bicycle.uuid), False),
        ('/{}/mechanic/bicycles/{}/'.format(org.uuid, bicycle.uuid), False),
        ('/{}/{}/mechanic/bicycles/{}/'.format(
            root_org.uuid, org.uuid, bicycle.uuid), False),
    ])

    bicycle.declare_available()
    org.is_open_fleet = True
    org.save()

    assert sorted(build_publisher_topics(bicycle)) == sorted([
        ('/{}/admin/bicycles/{}/'.format(org.uuid, bicycle.uuid), False),
        ('/{}/{}/admin/bicycles/{}/'.format(
            root_org.uuid, org.uuid, bicycle.uuid), False),
        ('/{}/fleet_operator/bicycles/{}/'.format(
            org.uuid, bicycle.uuid), False),
        ('/{}/{}/fleet_operator/bicycles/{}/'.format(
            root_org.uuid, org.uuid, bicycle.uuid), False),
        ('/{}/mechanic/bicycles/{}/'.format(org.uuid, bicycle.uuid), False),
        ('/{}/{}/mechanic/bicycles/{}/'.format(
            root_org.uuid, org.uuid, bicycle.uuid), False),
        ('/{}/public/bicycles/{}/'.format(org.uuid, bicycle.uuid), False),
        ('/{}/{}/public/bicycles/{}/'.format(
            root_org.uuid, org.uuid, bicycle.uuid), False),
        ('/{}/renter/bicycles/{}/'.format(org.uuid, bicycle.uuid), False),
        ('/{}/{}/renter/bicycles/{}/'.format(
            root_org.uuid, org.uuid, bicycle.uuid), False),
    ])

    bicycle.reserve(by=alice)
    assert sorted(build_publisher_topics(bicycle)) == sorted([
        ('/{}/admin/bicycles/{}/'.format(org.uuid, bicycle.uuid), False),
        ('/{}/{}/admin/bicycles/{}/'.format(
            root_org.uuid, org.uuid, bicycle.uuid), False),
        ('/{}/fleet_operator/bicycles/{}/'.format(
            org.uuid, bicycle.uuid), False),
        ('/{}/{}/fleet_operator/bicycles/{}/'.format(
            root_org.uuid, org.uuid, bicycle.uuid), False),
        ('/{}/mechanic/bicycles/{}/'.format(org.uuid, bicycle.uuid), False),
        ('/{}/{}/mechanic/bicycles/{}/'.format(
            root_org.uuid, org.uuid, bicycle.uuid), False),
        ('/{}/{}/bicycles/{}/'.format(
            org.uuid, alice.uuid, bicycle.uuid), False),
        ('/{}/{}/{}/bicycles/{}/'.format(
            root_org.uuid, org.uuid, alice.uuid, bicycle.uuid), False),
    ])

    bicycle.rent(by=alice)
    assert sorted(build_publisher_topics(bicycle)) == sorted([
        ('/{}/admin/bicycles/{}/'.format(org.uuid, bicycle.uuid), False),
        ('/{}/{}/admin/bicycles/{}/'.format(
            root_org.uuid, org.uuid, bicycle.uuid), False),
        ('/{}/fleet_operator/bicycles/{}/'.format(
            org.uuid, bicycle.uuid), False),
        ('/{}/{}/fleet_operator/bicycles/{}/'.format(
            root_org.uuid, org.uuid, bicycle.uuid), False),
        ('/{}/mechanic/bicycles/{}/'.format(org.uuid, bicycle.uuid), False),
        ('/{}/{}/mechanic/bicycles/{}/'.format(
            root_org.uuid, org.uuid, bicycle.uuid), False),
        ('/{}/{}/bicycles/{}/'.format(
            org.uuid, alice.uuid, bicycle.uuid), False),
        ('/{}/{}/{}/bicycles/{}/'.format(
            root_org.uuid, org.uuid, alice.uuid, bicycle.uuid), False),
    ])


def test_bicycle_state_leaving(bicycle, org, renter, commit_success,
                               uses_publish_updates):
    redis = get_redis_connection('publisher')
    bicycle.declare_available()
    commit_success()

    pubsub = redis.pubsub()
    channel = '/{}/renter/bicycles/{}/'.format(org.uuid, bicycle.uuid)
    pubsub.subscribe(channel)
    message = pubsub.get_message()
    assert message == {'channel': channel.encode('utf-8'),
                       'data': 1,
                       'pattern': None,
                       'type': 'subscribe'}
    bicycle.rent(by=renter)
    commit_success()

    message = pubsub.get_message()
    assert sorted(list(message.keys())) == ['channel', 'data',
                                            'pattern', 'type']
    assert message['channel'] == channel.encode('utf-8')
    assert message['pattern'] is None
    assert message['type'] == 'message'

    assert json.loads(message['data'].decode('utf-8')) == {
        'topic': '/{}/renter/bicycles/{}/'.format(org.uuid, bicycle.uuid),
        'sender': 'bicycle_leaving_state',
        'message': {
            'state': 'available',
        }}


def test_bicycles_distance(bicycle, gps_tracking, middle_of_central_park):
    from velodrome.lock8.models import Bicycle

    b = (Bicycle.objects.annotate_with_distance(middle_of_central_park,
                                                'private_tracking__point')
         .first())
    assert b == bicycle
    assert b.raw_distance.km == 8636.91951354917


def test_retire_bicycle_stop_causative(bicycle, alert_stolen_bicycle,
                                       task_stolen_bicycle, feedback,
                                       fleet_operator):

    bicycle.lock = None
    bicycle.retire(by=fleet_operator)

    alert_stolen_bicycle.refresh_from_db()
    assert alert_stolen_bicycle.state == 'stopped'
    assert alert_stolen_bicycle.latest_transition_by == fleet_operator

    task_stolen_bicycle.refresh_from_db()
    assert task_stolen_bicycle.state == 'cancelled'
    assert task_stolen_bicycle.latest_transition_by == fleet_operator

    feedback.refresh_from_db()
    assert feedback.state == 'discarded'
    assert feedback.latest_transition_by == fleet_operator


def test_bicyle_found_clear_alert(bicycle, request):
    from velodrome.lock8.models import AlertStates
    bicycle.declare_lost()

    alert_lost_bicycle_reported = request.getfixturevalue(
        'alert_lost_bicycle_reported')

    bicycle.put_in_maintenance()

    alert_lost_bicycle_reported.refresh_from_db()
    assert alert_lost_bicycle_reported.state == AlertStates.STOPPED.value


def test_bicyle_declared_lost_stop_alerts(bicycle,
                                          alert_lost_bicycle_reported):
    from velodrome.lock8.models import AlertStates

    assert alert_lost_bicycle_reported.state == AlertStates.NEW.value

    bicycle.declare_lost()

    alert_lost_bicycle_reported.refresh_from_db()
    assert alert_lost_bicycle_reported.state == AlertStates.STOPPED.value


@pytest.mark.parametrize('transition', [
    'declare_lost',
    'put_in_maintenance',
])
def test_bicycle_change_state_clear_too_long_idle(bicycle,
                                                  alert_too_long_idle,
                                                  transition):
    bicycle.declare_available()

    assert alert_too_long_idle.state == 'new'

    getattr(bicycle, transition)()

    alert_too_long_idle.refresh_from_db()

    assert alert_too_long_idle.state == 'stopped'


def test_bicycle_return_dry_run(bicycle, renter):
    bicycle.declare_available()
    bicycle.rent(by=renter)
    bicycle.return_(by=renter, dry_run=True)
    assert bicycle.state == 'rented'


@pytest.mark.uses_payments
def test_bicycle_cannot_be_rented_with_oustanding_payments(
        mocker, renter, bicycle_available, pricing_scheme,
        customer_chargable):
    m = mocker.patch('velodrome.lock8.models.User.get_debt_for_rentals',
                     return_value=({'eur': [(100, [object])]}, True))

    with pytest.raises(ValidationError) as detail:
        bicycle_available.rent(
            by=renter,
            pricing_scheme=pricing_scheme,
        )
    assert (('user_has_pending_payments',
             'There is one outstanding payment.') == (
             detail.value.code, detail.value.message)), detail
    assert m.call_count == 1


@pytest.mark.uses_payments
def test_bicycle_can_be_rented_with_oustanding_payments_but_no_pricing_scheme(
        mocker, renter, bicycle_available):
    m = mocker.patch('velodrome.lock8.models.User.get_unpaid_rentalsessions',
                     autospec=True, return_value=mocker.Mock(
                         **{'count.return_value': 1}))
    bicycle_available.rent(by=renter)
    assert m.call_count == 0


@pytest.mark.uses_payments
def test_bicycle_can_be_rented_with_oustanding_payments_and_new_source(
        mocker, now, renter, bicycle_available, bicycle2, bicycle3,
        pricing_scheme, customer_chargable, commit_success,
        caplog, webhook_customer_source_created):
    from pinax.stripe.models import Charge, EventProcessingException

    # Generate failed charge in the past.
    bicycle2.declare_available()
    with freeze_time(now - dt.timedelta(hours=3)):
        bicycle2.rent(
            by=renter,
            pricing_scheme=pricing_scheme,
        )
    failed_rental_session = bicycle2.active_rental_session
    bicycle2.return_(by=renter)
    assert failed_rental_session.cents is None
    m_capture = mocker.patch('pinax.stripe.actions.charges.capture')

    # Simulate failure when creating the charge.
    m_charges_create = mocker.patch('pinax.stripe.actions.charges.create',
                                    side_effect=Exception('new_charge_failed'))
    with pytest.raises(Exception, match='new_charge_failed'):
        commit_success()
    assert m_capture.call_count == 1

    failed_rental_session.refresh_from_db()

    assert failed_rental_session.cents == 300
    assert failed_rental_session.payment_state == 'failed'
    assert failed_rental_session.charge.amount == Decimal(2)
    assert failed_rental_session.charge.paid is True
    assert failed_rental_session.charge.captured is False

    assert caplog.record_tuples[-1] == (
        'velodrome.lock8.models', 40,
        'Failed to create new charge, capturing existing one.')

    # Simulate success for capturing the 2h charge.
    failed_rental_session.charge.captured = True
    failed_rental_session.charge.save()

    # Generate a second failed charge in the past (not partially captured and
    # in another currency).
    failed_rental_session_2 = failed_rental_session
    failed_rental_session_2.pk = None
    failed_rental_session_2.currency = 'usd'

    new_charge = failed_rental_session_2.charge
    new_charge.pk = None
    new_charge.stripe_id = 'ch_failed_rental_session_2'
    new_charge.paid = False
    new_charge.save()

    failed_rental_session_2.charge = new_charge
    failed_rental_session_2.uuid = uuid.uuid4()
    failed_rental_session_2.save()

    assert failed_rental_session.cents == 300
    assert failed_rental_session.payment_state == 'failed'
    assert failed_rental_session.charge.amount == Decimal(2)

    # Renting now fails.
    with pytest.raises(ValidationError) as detail:
        bicycle_available.rent(
            by=renter,
            pricing_scheme=pricing_scheme,
        )
    assert (('user_has_pending_payments',
             'There are 2 outstanding payments.') == (
             detail.value.code, detail.value.message)), detail
    assert bicycle_available.state == 'available'

    mocker.patch('pinax.stripe.actions.sources.sync_payment_source_from_stripe_data')  # noqa: E501

    webhook = webhook_customer_source_created
    m_validate = mocker.patch.object(webhook, 'validate')

    # pinax.stripe.actions.charges.create is still patched to raise.
    webhook.process()
    assert m_validate.call_count == 1
    assert EventProcessingException.objects.exists() is False
    assert caplog.record_tuples[-1] in (
        (
            'velodrome.lock8.models', 40,
            "transfer_failed_payments: Exception('new_charge_failed',)"
        ),
        (
            'velodrome.lock8.models', 40,
            "transfer_failed_payments: Exception('new_charge_failed')"
        )
    )

    m_charges_create.side_effect = stripe.error.StripeError
    assert webhook.event.processed
    webhook.event.processed = False
    webhook.process()
    assert EventProcessingException.objects.exists() is False
    assert caplog.record_tuples[-1] == (
        'velodrome.lock8.models', 40,
        'transfer_failed_payments: StripeError(message=None, '
        'http_status=None, request_id=None)')

    # Therefore renting still fails.
    with pytest.raises(ValidationError) as detail:
        bicycle_available.rent(
            by=renter,
            pricing_scheme=pricing_scheme,
        )
    assert (('user_has_pending_payments',
             'There are 2 outstanding payments.') == (
             detail.value.code, detail.value.message)), detail
    assert bicycle_available.state == 'available'

    # Re-process the webhook without any exception.
    m_charges_create.side_effect = None
    m_retrieve = mocker.patch('stripe.Charge.retrieve')
    assert webhook.event.processed
    webhook.event.processed = False
    webhook.process()
    assert m_retrieve.call_count == 2
    assert m_retrieve().metadata.update.call_count == 2
    assert m_retrieve().save.call_count == 2

    # Should create one for the full amount (3€).
    assert m_charges_create.call_args_list[-2][1]['amount'] == Decimal('3')
    assert m_charges_create.call_args_list[-2][1]['currency'] == 'usd'

    # Should create only 1€ (3€ - 2€ (from capturing the existing one)).
    assert m_charges_create.call_args_list[-1][1]['amount'] == Decimal('1')
    assert m_charges_create.call_args_list[-1][1]['currency'] == 'eur'

    # Renting now works.
    m_charges_create.return_value = Charge.objects.create()
    bicycle_available.rent(
        by=renter,
        pricing_scheme=pricing_scheme,
    )

    failed_rental_session.refresh_from_db()
    assert failed_rental_session.payment_state == 'transferred'


@pytest.mark.uses_payments
def test_transfer_failed_payments_without_charge(
        unpaid_rentalsession, customer_chargable, mocker, caplog):
    from pinax.stripe.models import Charge

    renter = unpaid_rentalsession.user
    rentalsession = renter.get_unpaid_rentalsessions().get()
    assert rentalsession.payment_state == 'failed'

    charges_capture = mocker.patch('pinax.stripe.actions.charges.capture')

    # Test error when capturing new charge in the end.
    charges_capture.side_effect = Exception('custom_error')
    renter.transfer_failed_payments(customer=customer_chargable,
                                    stripe_card_id='src_new_source')
    assert caplog.record_tuples[-3] in (
        (
            'velodrome.lock8.models', 40,
            "transfer_failed_payments: Exception('custom_error',)"
        ),
        (
            'velodrome.lock8.models', 40,
            "transfer_failed_payments: Exception('custom_error')"
        )
    )
    assert caplog.record_tuples[-1][0] == 'velodrome.lock8.models'
    assert caplog.record_tuples[-1][1] == 40
    assert caplog.record_tuples[-1][2].startswith(
        'transfer_failed_payments: failed to refund: APIConnectionError')
    rentalsession.refresh_from_db()
    assert rentalsession.payment_state == 'failed'
    assert rentalsession.charge is None
    assert renter.get_unpaid_rentalsessions().count() == 1
    uncaptured_charge = Charge.objects.get()
    assert uncaptured_charge.captured is False

    # Now let it succeed.
    charges_capture.reset_mock()
    charges_capture.side_effect = None
    renter.transfer_failed_payments(customer=customer_chargable,
                                    stripe_card_id='src_new_source')
    rentalsession.refresh_from_db()
    assert rentalsession.payment_state == 'transferred'
    assert renter.get_unpaid_rentalsessions().count() == 0
    assert charges_capture.call_count == 1

    charge = rentalsession.charge
    assert charge.amount == Decimal('0.99')
    assert charge.source == 'src_new_source'


@pytest.mark.uses_payments
def test_transfer_failed_payments_with_invalid_request_for_capture_false(
        unpaid_rentalsession, customer_chargable, mocker, caplog):
    from stripe.error import InvalidRequestError

    renter = unpaid_rentalsession.user

    charges_create = mocker.patch('pinax.stripe.actions.charges.create')
    charges_create.side_effect = (
        InvalidRequestError(
            message='You cannot pass capture=false for this payment type.',
            param=None),
        True)
    renter.transfer_failed_payments(customer=customer_chargable,
                                    stripe_card_id='src_new_source')
    assert [x[1]['capture'] for x in charges_create.call_args_list] == [
        False, True]
    assert caplog.record_tuples[-1] == (
        'velodrome.lock8.models', 30,
        "transfer_failed_payments: cannot refund: 'bool' object has no attribute 'stripe_id'")  # noqa: E501


@pytest.mark.uses_payments
def test_transfer_failed_payments_with_invalid_request_for_capture_false_2(
        unpaid_rentalsession, customer_chargable, mocker, caplog):
    from stripe.error import InvalidRequestError

    renter = unpaid_rentalsession.user

    charges_create = mocker.patch('pinax.stripe.actions.charges.create')
    charges_create.side_effect = (
        InvalidRequestError(
            message='You cannot pass capture=false for this payment type.',
            param=None),
        Exception('custom_error'))
    renter.transfer_failed_payments(customer=customer_chargable,
                                    stripe_card_id='src_new_source')
    assert [x[1]['capture'] for x in charges_create.call_args_list] == [
        False, True]
    assert caplog.record_tuples[-1] in (
        (
            'velodrome.lock8.models', 40,
            "transfer_failed_payments: Exception('custom_error',)"
        ),
        (
            'velodrome.lock8.models', 40,
            "transfer_failed_payments: Exception('custom_error')"
        ),
    )


@pytest.mark.uses_payments
def test_transfer_failed_payments_with_invalid_request_for_capture_false_3(
        unpaid_rentalsession, customer_chargable, mocker, caplog):
    from pinax.stripe.models import Charge
    from stripe.error import InvalidRequestError

    renter = unpaid_rentalsession.user

    charges_create = mocker.patch('pinax.stripe.actions.charges.create')
    charges_create.side_effect = (
        InvalidRequestError(
            message='You cannot pass capture=false for this payment type.',
            param=None),
        Charge.objects.create(stripe_id='ch_XXX'))
    renter.transfer_failed_payments(customer=customer_chargable,
                                    stripe_card_id='src_new_source')
    assert [x[1]['capture'] for x in charges_create.call_args_list] == [
        False, True]
    assert caplog.record_tuples[-1] == (
        'velodrome.lock8.models', 20,
        'transfer_failed_payments: created charge ch_XXX')


@pytest.mark.uses_payments
def test_bicycle_can_be_rented_with_oustanding_payments_and_retry(
        bicycle_available, unpaid_rentalsession, pricing_scheme,
        customer_chargable, mocker, commit_success):
    from pinax.stripe.models import Charge

    renter = unpaid_rentalsession.user
    failed_rentalsession = renter.get_unpaid_rentalsessions().get()
    assert failed_rentalsession.payment_state == 'failed'

    # dry_run=True does not retry failed payments.
    with pytest.raises(ValidationError) as excinfo:
        bicycle_available.rent(by=renter,
                               pricing_scheme=pricing_scheme,
                               dry_run=True)
    assert excinfo.value.code == 'user_has_pending_payments'
    assert renter.get_unpaid_rentalsessions().exists()

    # Exceptions get logged, raises ValidationError.
    with mocker.mock_module.patch.object(renter, 'retry_failed_payments',
                                         side_effect=Exception('custom_exc')):
        with pytest.raises(ValidationError) as excinfo:
            bicycle_available.rent(by=renter,
                                   pricing_scheme=pricing_scheme)
    assert excinfo.value.code == 'user_has_pending_payments'
    assert renter.get_unpaid_rentalsessions().exists()

    m_retry_failed_payments = mocker.spy(renter, 'retry_failed_payments')
    m_transfer_failed_payments = mocker.spy(renter, 'transfer_failed_payments')

    # Without chargeable sources renting fails.
    with pytest.raises(ValidationError) as excinfo:
        bicycle_available.rent(by=renter,
                               pricing_scheme=pricing_scheme)
    assert excinfo.value.code == 'user_has_pending_payments'
    assert renter.get_unpaid_rentalsessions().exists()

    assert m_retry_failed_payments.call_count == 1
    assert m_transfer_failed_payments.call_count == 0

    # Mock sources for customer, only one being chargeable.
    sources = stripe.api_resources.list_object.ListObject()
    sources.update({
        'data': [
            stripe.Source.construct_from({
                'id': 'src_1D7l1zEsFcHZcT2Da2YDu0Kx',
                'status': 'pending',
                'type': 'ach_credit_transfer',
                'usage': 'reusable'
            }, 'stripe_api_key'),
            stripe.Source.construct_from({
                'id': 'src_1D7q8PEsFcHZcT2D2VKn2Ag8',
                'status': 'chargeable',
                'type': 'card',
                'usage': 'reusable'
            }, 'stripe_api_key'),
            stripe.Source.construct_from({
                'brand': 'MasterCard',
                'funding': 'prepaid',
                'id': 'card_XXX',
                'object': 'card',
            }, 'stripe_api_key'),
        ]})
    customer_with_sources = renter.customers.first()
    mocker.patch.object(customer_with_sources.stripe_customer, 'sources',
                        sources)
    mocker.patch.object(renter, 'get_customer',
                        return_value=customer_with_sources)

    # Successfully retried payments get transferred.
    charges_capture = mocker.patch('pinax.stripe.actions.charges.capture')
    bicycle_available.rent(by=renter,
                           pricing_scheme=pricing_scheme)
    failed_rentalsession.refresh_from_db()
    assert failed_rentalsession.payment_state == 'transferred'
    assert not renter.get_unpaid_rentalsessions().exists()
    assert charges_capture.call_count == 1
    assert m_retry_failed_payments.call_count == 2
    assert m_transfer_failed_payments.call_count == 1

    assert [x.amount for x in Charge.objects.all()] == [
        Decimal('0.99')]
    assert renter.get_paid_rentalsessions().count() == 1

    # Close rental session without any costs.
    bicycle_available.return_()
    # renter.active_rental_session.close()
    assert renter.get_paid_rentalsessions().count() == 1
    assert [(x.payment_state,
             x.cents) for x in renter.rental_sessions.all()] == [
        ('processed', 0), ('transferred', 99)]

    # Create rental session with costs.
    bicycle_available.rent(by=renter,
                           pricing_scheme=pricing_scheme)
    with freeze_time(django_timezone.now() + dt.timedelta(hours=1)):
        bicycle_available.return_()
    assert renter.get_paid_rentalsessions().count() == 1
    assert [(x.payment_state,
             x.cents) for x in renter.rental_sessions.all()] == [
        ('pending', 100), ('processed', 0), ('transferred', 99)]

    commit_success()
    assert renter.get_paid_rentalsessions().count() == 2
    assert [x.amount for x in Charge.objects.all().order_by('pk')] == [
        Decimal('0.99'), Decimal('1.00')]
    assert [(x.payment_state,
             x.cents) for x in renter.rental_sessions.all()] == [
        ('processed', 100), ('processed', 0), ('transferred', 99)]


@pytest.mark.uses_payments
def test_bicycle_can_be_rented_with_oustanding_payments_below_minimum(
        bicycle_available, unpaid_rentalsession, pricing_scheme,
        customer_chargable, caplog):

    unpaid_rentalsession.cents = 49
    unpaid_rentalsession.save()

    renter = unpaid_rentalsession.user
    failed_rentalsession = renter.get_unpaid_rentalsessions().get()
    assert failed_rentalsession.payment_state == 'failed'

    with transaction.atomic():
        bicycle_available.rent(by=renter,
                               pricing_scheme=pricing_scheme,
                               dry_run=True)
    assert caplog.record_tuples == []

    bicycle_available.rent(by=renter,
                           pricing_scheme=pricing_scheme)
    assert caplog.record_tuples[0] == (
        'velodrome.lock8.models', 20,
        "Not retrying failed payments: {'eur': [49, [%r]]}" % (
            unpaid_rentalsession))
