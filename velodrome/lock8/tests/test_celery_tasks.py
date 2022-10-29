from datetime import timedelta
import functools
import itertools

from concurrency.exceptions import RecordModifiedError
from django.utils.timezone import now
from freezegun import freeze_time
import pytest


@pytest.fixture(params=('normal', 'raises'))
def param_maybe_raising_reservation(request):
    def activate(obj):
        if request.param == 'normal':
            return False

        def side_effect(*args, **kwargs):
            raise RecordModifiedError(target=kwargs['target'])

        mocker = request.getfixturevalue('mocker')
        mocker.patch('velodrome.lock8.models.Reservation.save',
                     side_effect=functools.partial(side_effect, target=obj))
        return True
    return activate


def test_alert_tracking_not_received_no_alert(lock, another_lock, org, bicycle,
                                              fleet_operator, another_bicycle,
                                              create_dss_tracking):
    from velodrome.lock8.models import Alert
    from velodrome.celery import alert_tracking_not_received

    lock.activate()
    another_lock.activate()

    create_dss_tracking(lock, 50.,
                        time_stamp=(now() - timedelta(hours=1)).timestamp())

    # this one should be discarded because it affects another_lock
    create_dss_tracking(another_lock, 50)

    alert_tracking_not_received()

    assert Alert.objects.all().count() == 0


def test_alert_tracking_not_received_raise_alert(lock, another_lock, org,
                                                 bicycle, another_bicycle,
                                                 create_dss_tracking):
    from velodrome.lock8.models import Alert
    from velodrome.celery import alert_tracking_not_received

    lock.activate()
    another_lock.activate()
    bicycle.declare_available()

    create_dss_tracking(lock, 50,
                        attributes={'time_stamp': (
                            now() - timedelta(hours=25)).timestamp(),
                                    'system_status': 4})

    # this one should be discarded because it is affected to another_lock
    create_dss_tracking(another_lock, 50,
                        attributes={'time_stamp': now().timestamp(),
                                    'system_status': 4})

    alert_tracking_not_received()

    assert Alert.objects.all().count() == 1


def test_alert_tracking_not_received_no_alert_because_gps(lock, org, bicycle,
                                                          create_gps_tracking):

    from velodrome.lock8.models import Alert
    from velodrome.celery import alert_tracking_not_received

    lock.activate()
    bicycle.declare_available()
    create_gps_tracking(lock, 1, 0,
                        time_stamp=(now() - timedelta(hours=23)).timestamp())

    create_gps_tracking(lock, 1, 0,
                        time_stamp=(now() - timedelta(hours=25)).timestamp())

    alert_tracking_not_received()

    assert Alert.objects.all().count() == 0


def test_alert_tracking_not_received_no_alert_because_no_bicycle(
        lock, org, create_dss_tracking):
    from velodrome.lock8.models import Alert
    from velodrome.celery import alert_tracking_not_received

    lock.provision()

    create_dss_tracking(lock, 20,
                        time_stamp=(now() - timedelta(minutes=1)).timestamp())

    alert_tracking_not_received()

    assert Alert.objects.all().count() == 0


def test_alert_tracking_not_received(
        lock, another_lock, settings, org, bicycle, fleet_operator, root_org,
        owner, mailoutbox, create_dss_tracking, commit_success):
    from velodrome.lock8.models import Affiliation, Alert
    from velodrome.celery import alert_tracking_not_received

    lock.activate()
    bicycle.declare_available()
    another_lock.provision()
    another_lock.activate()

    preference = root_org.active_preference
    preference.allowed_email_alert_types = [Alert.NO_TRACKING_RECEIVED_SINCE]
    preference.save()

    assert Alert.objects.all().count() == 0

    create_dss_tracking(lock, 50,
                        time_stamp=(now() - timedelta(hours=25)).timestamp())

    # create a second one and make sure only one Alert is created, not
    # two
    create_dss_tracking(lock, 50,
                        time_stamp=(
                            now() - timedelta(hours=24, minutes=9)
                        ).timestamp())

    alert_tracking_not_received()

    alert = Alert.objects.get()

    assert (alert.alert_type ==
            Alert.NO_TRACKING_RECEIVED_SINCE)
    assert alert.causality == lock
    assert alert.organization == org
    assert alert.roles == [Affiliation.FLEET_OPERATOR]
    assert (alert.message ==
            'More than a day since the last periodic update.')

    commit_success()
    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.subject == '[Noa Alert] Device Not Reporting: bicycle [org]'
    assert email.recipients() == ['fleet_operator@example.com']


def test_alert_tracking_not_received_with_unactive_lock(bicycle, org, owner,
                                                        create_dss_tracking):
    from velodrome.lock8.models import Alert, DeviceEvents, Lock
    from velodrome.celery import alert_tracking_not_received

    assert Alert.objects.all().count() == 0

    with freeze_time(now() - timedelta(hours=25)):
        lock = Lock.objects.create(owner=owner,
                                   organization=org,
                                   counter=12,
                                   serial_number='11020112',
                                   imei='459785028015888',
                                   iccid='99462046044000108788',
                                   sid='b6cefb7474f291997c6a303031303888',
                                   bleid='ec4f434b385f3030303030303130888',
                                   randblock='a' * 2048)
        create_dss_tracking(lock, 50, event=DeviceEvents.INIT.value,
                            activate=False)
    assert lock.state == 'provisioned'
    assert lock.public_tracking is None
    lock.activate()
    assert lock.state == 'active'
    bicycle.lock = lock
    bicycle.declare_available()

    alert_tracking_not_received()

    assert not Alert.objects.exists()


def test_zone_threshold_alert(org, bicycle, bicycle2, bicycle3, zone, lock,
                              alice, organization_preference, fleet_operator,
                              active_lock, create_gps_tracking, commit_success,
                              lock2, lock3, middle_of_central_park,
                              bob, mailoutbox):
    from velodrome.celery import start_zone_alert_thresholds
    from velodrome.lock8.models import Alert, Affiliation, Zone
    organization_preference.allow_returning_bicycle_outside_drop_zone = False
    organization_preference.save()
    zone.low_threshold = 1
    zone.high_threshold = 2
    zone.save()
    lock2.activate()
    lock3.activate()
    bicycle.declare_available()
    bicycle2.declare_available()
    bicycle3.declare_available()
    create_gps_tracking(active_lock, *middle_of_central_park,
                        time_stamp=1428509326,
                        attributes={'gps_accuracy': 30.1328125})
    create_gps_tracking(lock2, *middle_of_central_park,
                        time_stamp=1428509326,
                        attributes={'gps_accuracy': 30.1328125})
    create_gps_tracking(lock3, *middle_of_central_park,
                        time_stamp=1428509326,
                        attributes={'gps_accuracy': 30.1328125})

    start_zone_alert_thresholds(zone.id)

    alert = Alert.objects.get()
    assert Alert.objects.count() == 1
    assert alert.alert_type == Alert.ZONE_HIGH_THRESHOLD_TRIGGERED
    assert alert.causality == zone
    assert alert.organization == org
    assert alert.roles == [Affiliation.FLEET_OPERATOR]
    assert (alert.message == f'Zone {zone.name} has a high threshold alert')
    long, lat = zone.polygon.centroid.coords
    assert alert.context == {'amount': 3,
                             'zone_uuid': str(zone.uuid),
                             'zone_name': zone.name,
                             'zone_type': zone.type,
                             'location': {
                                 'type': 'Point',
                                 'coordinates': [long, lat]}
                             }
    commit_success()
    email = mailoutbox[0]
    assert len(mailoutbox) == 1
    assert email.subject == '[Noa Alert] Zone has reached a high threshold: Central Park [org]' # noqa E501
    assert email.recipients() == ['fleet_operator@example.com']

    start_zone_alert_thresholds(zone.id)
    assert Alert.objects.count() == 1

    not_found_zone_id = 30
    with pytest.raises(Zone.DoesNotExist):
        start_zone_alert_thresholds(not_found_zone_id)
    assert Alert.objects.count() == 1

    bicycle.rent(by=alice)
    bicycle2.rent(by=bob)
    bicycle2.return_()
    assert Alert.objects.count() == 2


def test_zone_threshold_bike_return(org, bicycle, bicycle2, bicycle3, zone,
                                    middle_of_central_park, commit_success,
                                    organization_preference, active_lock,
                                    lock2, lock3, create_gps_tracking, alice,
                                    bob):
    from velodrome.lock8.models import Alert
    zone.low_threshold = 1
    zone.high_threshold = 2
    zone.save()
    organization_preference.allow_returning_bicycle_outside_drop_zone = False
    organization_preference.save()
    create_gps_tracking(active_lock, *middle_of_central_park,
                        time_stamp=1428509326,
                        attributes={'gps_accuracy': 30.1328125})
    bicycle.rent(by=alice)

    bicycle.return_()

    assert Alert.objects.count() == 1
    assert Alert.objects.filter(
        zones__uuid=zone.uuid,
        alert_type=Alert.ZONE_LOW_THRESHOLD_TRIGGERED).count() == 1

    create_gps_tracking(lock2, *middle_of_central_park,
                        time_stamp=1428509326,
                        attributes={'gps_accuracy': 30.1328125})
    bicycle2.rent(by=bob)

    bicycle2.return_()

    create_gps_tracking(lock3, *middle_of_central_park,
                        time_stamp=1428509326,
                        attributes={'gps_accuracy': 30.1328125})
    bicycle3.rent(by=alice)

    bicycle3.return_()

    assert Alert.objects.all().count() == 2
    assert Alert.objects.filter(
        zones__uuid=zone.uuid,
        alert_type=Alert.ZONE_HIGH_THRESHOLD_TRIGGERED).count() == 1


def test_reservation_expiration_simple(bicycle, alice, org, renting_scheme):
    from velodrome.celery import expire_outdated_reservation
    from velodrome.lock8.models import ReservationStates

    org.is_open_fleet = True
    org.save()

    assert renting_scheme in bicycle.eligible_renting_schemes

    renting_scheme.max_reservation_duration = timedelta(microseconds=2)
    renting_scheme.save()

    with freeze_time(now() - timedelta(seconds=10)):
        bicycle.declare_available()
        bicycle.reserve(by=alice, user=alice)

    assert bicycle.active_reservation is not None
    reservation = bicycle.active_reservation

    assert reservation.created < (now() -
                                  renting_scheme.max_reservation_duration)

    expire_outdated_reservation()

    bicycle.refresh_from_db()

    assert bicycle.state == 'available'
    assert bicycle.active_reservation is None
    assert bicycle.reservations.filter(
        state=ReservationStates.EXPIRED.value).count() == 1


def test_reservation_expiration_with_canceled(param_maybe_raising_reservation,
                                              bicycle, alice, org,
                                              renting_scheme):
    from velodrome.celery import expire_outdated_reservation
    from velodrome.lock8.models import ReservationStates

    org.is_open_fleet = True
    org.save()

    assert renting_scheme in bicycle.eligible_renting_schemes

    renting_scheme.max_reservation_duration = timedelta(microseconds=2)
    renting_scheme.save()

    with freeze_time(now() - timedelta(seconds=20)):
        bicycle.declare_available()
        bicycle.reserve(by=alice, user=alice)
        bicycle.cancel_reservation()
    with freeze_time(now() - timedelta(seconds=10)):
        bicycle.reserve(by=alice, user=alice)
    assert bicycle.active_reservation is not None

    raising = param_maybe_raising_reservation(bicycle.active_reservation)
    expire_outdated_reservation()

    bicycle.refresh_from_db()
    if raising:
        assert bicycle.state == 'reserved'
    else:
        assert bicycle.state == 'available'
        assert bicycle.active_reservation is None
        assert bicycle.reservations.filter(
            state=ReservationStates.EXPIRED.value).count() == 1


def test_reservation_expiration_renting_scheme_bicycle(bicycle, alice, org,
                                                       owner):
    from velodrome.celery import expire_outdated_reservation
    from velodrome.lock8.models import RentingScheme, ReservationStates

    org.is_open_fleet = True
    org.save()

    assert not bicycle.eligible_renting_schemes.exists()

    renting_scheme = RentingScheme.objects.create(
        owner=owner,
        organization=org,
        bicycle=bicycle,
        max_reservation_duration=timedelta(microseconds=2),
    )
    assert bicycle.eligible_renting_schemes.exists()

    renting_scheme.max_reservation_duration = timedelta(microseconds=2)
    renting_scheme.save()

    with freeze_time(now() - timedelta(seconds=10)):
        bicycle.declare_available()
        bicycle.reserve(by=alice, user=alice)

    assert bicycle.active_reservation is not None
    reservation = bicycle.active_reservation

    assert reservation.created < (now() -
                                  renting_scheme.max_reservation_duration)

    expire_outdated_reservation()

    bicycle.refresh_from_db()

    assert bicycle.state == 'available'
    assert bicycle.active_reservation is None
    assert bicycle.reservations.filter(
        state=ReservationStates.EXPIRED.value).count() == 1


def test_reservation_expiration_default(settings, bicycle, alice, org):
    from velodrome.celery import expire_outdated_reservation

    org.is_open_fleet = True
    org.save()

    assert not bicycle.eligible_renting_schemes.exists()

    bicycle.declare_available()
    bicycle.reserve(by=alice, user=alice)

    assert bicycle.active_reservation is not None

    expire_outdated_reservation()

    bicycle.refresh_from_db()

    assert bicycle.state == 'reserved'

    with freeze_time(now() + settings.DEFAULT_MAX_RESERVATION_DURATION):
        expire_outdated_reservation()
        bicycle.refresh_from_db()
        assert bicycle.state == 'reserved'


@pytest.mark.parametrize('points', (
    (),
    ((0.1, 0), (0.100_000_000_1, 0)),
    ((-122.033666, 37.391331), (-122.033666, 37.391331))
))
def test_idle_bicycle_triggers_alert(points, bicycle_available,
                                     create_gps_tracking):
    from velodrome.lock8.models import Alert
    from velodrome.celery import alert_idle_bicycles

    if points:
        create_gps_tracking(bicycle_available, *(points[0]),
                            time_stamp=(now() - timedelta(days=7)).timestamp())
        create_gps_tracking(bicycle_available, *(points[1]),
                            time_stamp=(now() - timedelta(days=3)).timestamp())

    alert_idle_bicycles()
    alert = bicycle_available.alerts.get()
    assert alert.alert_type == Alert.BICYCLE_IDLE_FOR_TOO_LONG
    assert alert.causality == bicycle_available
    assert alert.message == 'This Bicycle is idle for more than 15 days'


def test_idle_bicycle_no_triggers_alert(bicycle, lock, kitkat_to_office):
    from velodrome.lock8.models import Alert
    from velodrome.celery import alert_idle_bicycles

    alert_idle_bicycles()
    with pytest.raises(Alert.DoesNotExist):
        bicycle.alerts.get()


def test_bmmr_recurring_task_is_due(bmmr_recurring, today, mechanic1,
                                    commit_success):
    from velodrome.celery import notify_idle_bmmr_tasks
    from velodrome.lock8.models import NotificationMessageStates

    assert not mechanic1.notification_messages.exists()
    notify_idle_bmmr_tasks()
    assert not mechanic1.notification_messages.exists()

    task_due_today = today + timedelta(days=5, hours=4)
    with freeze_time(task_due_today):
        notify_idle_bmmr_tasks()
        commit_success()
    notf = mechanic1.notification_messages.first()
    assert notf.state == NotificationMessageStates.SENT.value
    assert notf.causality.maintenance_rule == bmmr_recurring


def test_bmmr_fixed_task_is_due(bmmr_fixed, today, mechanic1, commit_success):
    from velodrome.celery import notify_idle_bmmr_tasks
    from velodrome.lock8.models import NotificationMessageStates

    assert not mechanic1.notification_messages.exists()
    notify_idle_bmmr_tasks()
    assert not mechanic1.notification_messages.exists()

    task_due_today = today + timedelta(days=15, hours=4)
    with freeze_time(task_due_today):
        notify_idle_bmmr_tasks()
        commit_success()
    notf = mechanic1.notification_messages.first()
    assert notf.state == NotificationMessageStates.SENT.value
    assert notf.causality.maintenance_rule == bmmr_fixed


def test_bmmr_distance_task_is_due(bmmr_distance, today, mechanic1,
                                   bicycles_with_models, mocker,
                                   commit_success):
    from velodrome.celery import notify_idle_bmmr_tasks
    from velodrome.lock8.models import NotificationMessageStates

    bicycle1, bicycle2 = bicycles_with_models

    target = 'velodrome.lock8.models.get_distance_for_bicycles_since'

    ret = {str(bicycle1.uuid): 35.5, str(bicycle2.uuid): 55.2}
    mocker.patch(target, return_value=ret)
    notify_idle_bmmr_tasks()
    assert not mechanic1.notification_messages.exists()

    ret = {str(bicycle1.uuid): 999., str(bicycle2.uuid): 1000.}
    mocker.patch(target, return_value=ret)
    notify_idle_bmmr_tasks()
    commit_success()

    num_bicycles_to_maintain = bmmr_distance.bicycle_model.bicycles.count()
    assert num_bicycles_to_maintain == 2

    assert mechanic1.notification_messages.count() == num_bicycles_to_maintain
    assert all(notf.state == NotificationMessageStates.SENT.value and
               notf.causality.maintenance_rule == bmmr_distance for
               notf in mechanic1.notification_messages.all())


def test_due_task_does_not_resend(bmmr_fixed, today, mechanic1,
                                  commit_success):
    from velodrome.celery import notify_idle_bmmr_tasks
    from velodrome.lock8.models import NotificationMessage

    task_due_today = today + timedelta(days=15, hours=2)
    with freeze_time(task_due_today):
        notify_idle_bmmr_tasks()
    commit_success()

    assert NotificationMessage.objects.count() == 2
    with freeze_time(task_due_today):
        notify_idle_bmmr_tasks()
        commit_success()
    assert NotificationMessage.objects.count() == 2


def test_completed_tasks_are_excluded(bmmr_fixed, today, mechanic1,
                                      commit_success):
    from velodrome.celery import notify_idle_bmmr_tasks
    from velodrome.lock8.models import NotificationMessage, Task, TaskStates

    task1 = Task.objects.first()
    task1.complete()
    task1.refresh_from_db()
    assert task1.state == TaskStates.COMPLETED.value

    task_due_today = today + timedelta(days=15, hours=2)
    with freeze_time(task_due_today):
        notify_idle_bmmr_tasks()
        commit_success()

    assert NotificationMessage.objects.count() == 1


def test_tasks_store_is_due(mocker, bmmr_fixed, bmmr_recurring,
                            bmmr_distance, bicycle, task1):
    from velodrome.celery import notify_idle_bmmr_tasks

    target = 'velodrome.lock8.models.get_distance_for_bicycles_since'
    mocker.patch(target, return_value={})

    recurring_task = bmmr_recurring.tasks.first()

    notify_idle_bmmr_tasks()
    recurring_task.refresh_from_db()
    assert recurring_task.is_due is False

    task_is_due = now() + timedelta(days=5, hours=1)
    with freeze_time(task_is_due):
        notify_idle_bmmr_tasks()
        recurring_task.refresh_from_db()
        assert recurring_task.is_due is True

    fixed_task = bmmr_fixed.tasks.first()

    notify_idle_bmmr_tasks()
    fixed_task.refresh_from_db()
    assert fixed_task.is_due is False

    task_is_due = bmmr_fixed.fixed_date + timedelta(hours=2)
    with freeze_time(task_is_due):
        notify_idle_bmmr_tasks()
        fixed_task.refresh_from_db()
        assert fixed_task.is_due is True

    dist_task = bmmr_distance.tasks.first()
    bicycle_uuid = str(dist_task.causality.uuid)

    under_dist = dist_task.maintenance_rule.distance - 100
    mocker.patch(target, return_value={bicycle_uuid: under_dist})
    notify_idle_bmmr_tasks()
    dist_task.refresh_from_db()
    assert dist_task.is_due is False

    over_dist = dist_task.maintenance_rule.distance + 100
    mocker.patch(target, return_value={bicycle_uuid: over_dist})
    notify_idle_bmmr_tasks()
    dist_task.refresh_from_db()
    assert dist_task.is_due is True


def test_cancelled_tasks_dont_notify(bmmr_fixed, bicycle,
                                     mechanic1, mocker, commit_success):
    from velodrome.celery import notify_idle_bmmr_tasks

    target = 'velodrome.lock8.models.get_distance_for_bicycles_since'
    mocker.patch(target, return_value={})

    assert bmmr_fixed.tasks.count() == 2

    task = bmmr_fixed.tasks.first()
    task.cancel()
    assert mechanic1.notification_messages.count() == 0

    past_due_date = bmmr_fixed.fixed_date + timedelta(days=3)
    with freeze_time(past_due_date):
        notify_idle_bmmr_tasks()
        commit_success()

    # 2 tasks - 1 (cancelled)
    assert mechanic1.notification_messages.count() == 1


def test_bmmr_fixed_date_auto_deactivates(bmmr_fixed, bmmr_recurring,
                                          bmmr_distance, bicycle_model,
                                          today):
    from velodrome.celery import deactivate_overdue_maintenance_rules
    from velodrome.lock8.models import (
        BicycleModelMaintenanceRule as BMMR,
        BicycleModelMaintenanceRuleStates as BMMRStates
    )

    bmmr = BMMR.objects.create(bicycle_model=bicycle_model, fixed_date=today)
    bmmr.deactivate()

    assert all(bmmr.state == BMMRStates.ACTIVE.value
               for bmmr in (bmmr_distance, bmmr_recurring, bmmr_fixed))

    not_due_yet = bmmr_fixed.fixed_date - timedelta(days=1)
    with freeze_time(not_due_yet):
        deactivate_overdue_maintenance_rules()

    bmmr_fixed.refresh_from_db()
    assert bmmr_fixed.state == BMMRStates.ACTIVE.value

    past_due_date = bmmr_fixed.fixed_date + timedelta(days=3)
    with freeze_time(past_due_date):
        deactivate_overdue_maintenance_rules()

    for bmmr in (bmmr_distance, bmmr_recurring, bmmr_fixed):
        bmmr.refresh_from_db()

    assert bmmr_fixed.state == BMMRStates.DEACTIVATED.value
    assert all(bmmr.state == BMMRStates.ACTIVE.value
               for bmmr in (bmmr_distance, bmmr_recurring))


def test_bmmr_create_missing_tasks_correct_states(bmmr_fixed,
                                                  bicycle_model,
                                                  mechanic1, mechanic2):
    assert bmmr_fixed.tasks.count() == 2
    bmmr_fixed.deactivate()

    t1, t2 = bmmr_fixed.tasks.all()

    t1.assign(mechanic1)
    t1.cancel()

    t2.assign(mechanic2)

    bmmr_fixed.create_missing_tasks()
    assert bmmr_fixed.tasks.count() == 3


def test_lock_bulk_creation(org, owner, monkeypatch, mailoutbox):
    from velodrome.lock8.models import Lock
    import velodrome.celery
    from velodrome.celery import bulk_lock_creation

    bulk_lock_creation(owner.pk, 999999999-10, 999999999, None)

    m = mailoutbox[0]
    assert 'treated: 10' in m.body
    assert 'skipped: 0' in m.body
    assert 'errors: 0' in m.body
    assert Lock.objects.filter(
        counter__range=(999999999-10, 999999999)).count() == 10

    bulk_lock_creation(owner.pk, 999999999-20, 999999999, None)

    m = mailoutbox[1]
    assert 'treated: 10' in m.body
    assert 'skipped: 10' in m.body
    assert 'errors: 0' in m.body
    assert Lock.objects.filter(
        counter__range=(999999999-20, 999999999)).count() == 20

    def wow_such_random(length=0, **kwargs):
        return 'b' * length

    monkeypatch.setattr(velodrome.celery, 'get_random_string', wow_such_random)

    bulk_lock_creation(owner.pk, 999999999-30, 999999999-20, None)

    m = mailoutbox[2]
    assert 'treated: 0' in m.body
    assert 'skipped: 0' in m.body
    assert 'errors: 10' in m.body


def test_auto_stop_lost_reported_alerts(alert_lost_bicycle_reported):
    from velodrome.celery import stop_lost_bicycle_reported_alerts
    assert alert_lost_bicycle_reported.state == 'new'

    stop_lost_bicycle_reported_alerts()
    alert_lost_bicycle_reported.refresh_from_db()
    assert alert_lost_bicycle_reported.state == 'new'

    with freeze_time(now() + timedelta(weeks=2, hours=1)):
        stop_lost_bicycle_reported_alerts()

    alert_lost_bicycle_reported.refresh_from_db()
    assert alert_lost_bicycle_reported.state == 'stopped'


@pytest.mark.parametrize(
    'trigger, longer_pref_duration, rent_before_gps, with_gps',
    [*itertools.product((
        'with_pricing_scheme',
        'with_pricing_scheme_bicycle_model',
        'with_subscription_plan',
        'with_pricing_scheme_on_subscription_plan',
        'without_payment'),
        ('longer_pref_duration', 'no_longer_pref_duration'),
        ('rent_before_gps', 'no_rent_before_gps'),
        ('with_gps', 'without_gps'),
    )],
)
@pytest.mark.uses_payments
def test_timeout_expired_rental_sessions(
        trigger, longer_pref_duration, rent_before_gps, with_gps, request,
        bicycle, alice, customer_chargable, active_lock):
    from velodrome.celery import timeout_expired_rental_sessions
    from velodrome.lock8.models import Alert

    bicycle.declare_available()

    if trigger != 'without_payment':
        request.getfixturevalue('alice_card')

    rent_before_gps = rent_before_gps == 'rent_before_gps'
    longer_pref_duration = longer_pref_duration == 'longer_pref_duration'
    with_gps = with_gps == 'with_gps'

    rent_kwargs = {}
    if trigger == 'with_pricing_scheme':
        rent_kwargs['pricing_scheme'] = request.getfixturevalue(
            'pricing_scheme')
        expect_expire = False
    elif trigger == 'with_pricing_scheme_bicycle_model':
        rent_kwargs['pricing_scheme'] = request.getfixturevalue(
            'pricing_scheme_bicycle_model')
        bicycle.model = request.getfixturevalue('bicycle_model')
        bicycle.save()
        expect_expire = False
    elif trigger == 'with_subscription_plan':
        rent_kwargs['subscription_plan'] = request.getfixturevalue(
            'subscription_plan')
        request.getfixturevalue('subscription')
        expect_expire = not longer_pref_duration and rent_before_gps
    elif trigger == 'with_pricing_scheme_on_subscription_plan':
        rent_kwargs['subscription_plan'] = request.getfixturevalue(
            'subscription_plan_with_pricing_scheme')
        request.getfixturevalue('subscription')
        expect_expire = False
    else:  # trigger == 'without_payment':
        expect_expire = not longer_pref_duration and rent_before_gps

    if rent_before_gps:
        with freeze_time(now() - timedelta(minutes=31)):
            bicycle.rent(by=alice, **rent_kwargs)
    else:
        bicycle.rent(by=alice, **rent_kwargs)
        timeout_expired_rental_sessions()
        bicycle.refresh_from_db()
        assert bicycle.state == 'rented'

    if trigger in ('with_pricing_scheme',
                   'with_pricing_scheme_on_subscription_plan'):
        with pytest.raises(ValueError) as exc:
            bicycle.expire_rental_session()
        assert exc.value.args == ('Expiration forbidden.',)

    if longer_pref_duration:
        org_pref = request.getfixturevalue('organization_preference')
        org_pref.max_inactive_rental_session_duration = timedelta(minutes=60)
        org_pref.save()

    if with_gps:
        create_gps_tracking = request.getfixturevalue('create_gps_tracking')
        with freeze_time(now() - timedelta(minutes=30)):
            create_gps_tracking(bicycle, 1, 2)

    timeout_expired_rental_sessions()

    bicycle.refresh_from_db()

    if expect_expire:
        assert bicycle.state == 'available'
        alert = bicycle.alerts.get(alert_type=Alert.BICYCLE_LEFT_UNLOCKED)
        assert alert.context['renter'] == {'display_name': alice.display_name,
                                           'uuid': str(alice.uuid)}
        if with_gps:
            assert alert.context['location'] == {'type': 'Point',
                                                 'coordinates': [1.0, 2.0]}
    else:
        # remain unchanged
        assert bicycle.state == 'rented'


def test_send_support_email_task(support_ticket, mocker):
    from velodrome.celery import send_support_email_task
    from velodrome.lock8.models import SupportTicket

    send_mock = mocker.patch(
        'velodrome.lock8.models.SupportTicket.send_support_email')

    assert send_support_email_task(support_ticket.id) is None
    assert send_mock.called

    with pytest.raises(SupportTicket.DoesNotExist):
        send_support_email_task(support_ticket.id + 1)


@pytest.mark.parametrize('is_local', [True, False])
def test_renew_refresh_tokens_social(refresh_token, settings, is_local):
    from refreshtoken.models import RefreshToken
    from velodrome.celery import renew_refresh_tokens

    if is_local:
        refresh_token.app = 'local'
        refresh_token.save()
    with freeze_time(now() + settings.JWT_REFRESH_TOKEN_MAX_DURATION +
                     timedelta(seconds=1)):
        renew_refresh_tokens()
    with pytest.raises(RefreshToken.DoesNotExist):
        refresh_token.refresh_from_db()
    RefreshToken.objects.get(user=refresh_token.user)


def test_stop_zone_alerts(alert_zone_threshold, org, zone, commit_success):
    from velodrome.celery import stop_zone_alerts
    from velodrome.lock8.models import Alert, AlertStates, Affiliation
    from django.db.models.query import Q

    stopped_state = Q(state=AlertStates.STOPPED.value)
    alert_type = Q(alert_type=alert_zone_threshold.alert_type)

    stop_zone_alerts()
    with freeze_time(now() - timedelta(minutes=60)):
        Alert.objects.create(organization=org,
                             alert_type=alert_zone_threshold.alert_type,
                             causality=zone,
                             roles=[Affiliation.FLEET_OPERATOR])
    assert Alert.objects.filter(alert_type).count() == 2
    assert Alert.objects.count() == 2

    stop_zone_alerts()
    with freeze_time(now() - timedelta(minutes=60)):
        Alert.objects.create(organization=org,
                             alert_type=alert_zone_threshold.alert_type,
                             causality=zone,
                             roles=[Affiliation.FLEET_OPERATOR])
    stop_zone_alerts()
    assert Alert.objects.filter(alert_type, stopped_state).count() == 2
    assert Alert.objects.count() == 3
