from django.core.exceptions import ValidationError
import pytest


def test_alert_escalation(alert, alice, org):
    from velodrome.lock8.models import Affiliation, FeedbackCategory, Task

    alert.escalate(by=alice, description='wow',
                   severity=FeedbackCategory.SEVERITY_LOW)

    assert alert.state == 'escalated'

    task = Task.objects.get()
    assert task.assignor == alice
    assert task.context == {'description': 'wow'}
    assert task.role == Affiliation.FLEET_OPERATOR
    assert task.causality == alert
    assert task.organization == org


def test_alert_manual_escalation_and_task_cancellation(alert, alice, org):
    from velodrome.lock8.models import FeedbackCategory, Task

    alert.escalate(by=alice, description='wow',
                   severity=FeedbackCategory.SEVERITY_LOW)

    assert alert.state == 'escalated'

    task = Task.objects.get()
    assert task.assignor == alice
    assert task.causality == alert
    assert task.state == 'unassigned'

    alert.stop()

    task.refresh_from_db()
    assert task.state == 'unassigned'


def test_alert_rule_escalation_and_task_cancellation(alert, org):
    from velodrome.lock8.models import FeedbackCategory, Task

    alert.escalate(description='wow',
                   severity=FeedbackCategory.SEVERITY_LOW)

    assert alert.state == 'escalated'

    task = Task.objects.get()
    assert task.causality == alert
    assert task.assignor is None
    assert task.state == 'unassigned'

    alert.stop()

    task.refresh_from_db()
    assert task.state == 'cancelled'


def test_alert_to_role_mapping(organization_preference, bicycle):
    from velodrome.lock8.models import (
        Affiliation, Alert, maybe_create_and_send_alert
    )

    mapping = {Alert.LOW_BATTERY: [Affiliation.SECURITY]}
    organization_preference.alert_type_to_role_mapping = mapping
    organization_preference.save()

    assert Alert.objects.count() == 0

    maybe_create_and_send_alert(
        bicycle.lock, Alert.LOW_BATTERY,
        'John Fahey is good at guitar.',
        default_roles=[Affiliation.MECHANIC]
    )

    alert = Alert.objects.get()
    assert alert.role == ''
    assert alert.roles == [Affiliation.SECURITY]


def test_battery_low_alert(lock, org, bicycle, settings,
                           fleet_operator, bicycle_model,
                           organization_preference, mailoutbox,
                           create_dss_tracking, commit_success):
    from velodrome.lock8.models import (
        Affiliation, Alert, NotificationMessage, maybe_create_and_send_alert
    )

    bicycle.model = bicycle_model
    bicycle.save()
    bicycle.declare_available()

    # Set tracking with low battery level to be the latest for the lock
    create_dss_tracking(lock, 19, attributes={'time_stamp': 0})

    maybe_create_and_send_alert(lock, Alert.LOW_BATTERY,
                                default_roles=[Affiliation.FLEET_OPERATOR])

    alert = Alert.objects.get()
    assert alert.causality == lock
    assert alert.roles == ['fleet_operator']
    assert alert.organization == org
    assert alert.alert_type == 'lock.bat.low'
    assert alert.message == "Causality: lock %s | Type: %s" % (
            lock.uuid, Alert.LOW_BATTERY)
    assert alert.state == 'new'
    assert alert.extra['state_of_charge'] == 19

    commit_success()
    assert NotificationMessage.objects.count() == 1

    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.subject == '[Noa Alert] Low Battery: bicycle [org]'

    assert email.recipients() == ['fleet_operator@example.com']


def test_battery_low_alert_with_inactive_user(
        lock, org, bicycle, settings, fleet_operator,
        bicycle_model, organization_preference, mailoutbox,
        create_dss_tracking):
    from velodrome.lock8.models import (
        Affiliation, Alert, NotificationMessage, maybe_create_and_send_alert
    )

    fleet_operator.is_active = False
    fleet_operator.save()
    bicycle.model = bicycle_model
    bicycle.save()
    bicycle.declare_available()

    # Set tracking with low battery level to be the latest for the lock
    create_dss_tracking(lock, 19, attributes={'time_stamp': 0})

    maybe_create_and_send_alert(lock, Alert.LOW_BATTERY,
                                default_roles=[Affiliation.FLEET_OPERATOR])

    assert NotificationMessage.objects.count() == 0


def test_alert_extra_without_annotated_queryset(alert_stolen_bicycle, bicycle):
    assert alert_stolen_bicycle.extra == {
        'bicycle_gps_accuracy': None,
        'bicycle_model_name': None,
        'bicycle_model_photo': None,
        'bicycle_name': bicycle.name,
        'bicycle_state': 'in_maintenance',
        'bicycle_uuid': str(bicycle.uuid),
        'lock_uuid': str(bicycle.lock.uuid),
        'lock_bleid': bicycle.lock.bleid,
    }


def test_alert_model_display_time_without_pref(request, dt2016, alert):
    assert alert.display_time == 'Wed, 01 Jun 2016 20:15:42 UTC'

    prefs = request.getfixturevalue('organization_preference')
    prefs.timezone = 'Europe/Berlin'
    prefs.save()
    assert alert.display_time == 'Wed, 01 Jun 2016 22:15:42 Europe/Berlin'


@pytest.mark.parametrize('param_rental', ['with_rental', 'without_rental'])
@pytest.mark.parametrize('param_zone', ['with_zone', 'without_zone'])
def test_ride_outside_cycling_zone_alert(
        request, param_rental, param_zone, org, bicycle,
        middle_of_central_park, bicycle_model, organization_preference,
        mailoutbox, alice, commit_success, fleet_operator):
    from velodrome.lock8.models import (
        Affiliation, Alert, NotificationMessage, maybe_create_and_send_alert)

    with_rental = param_rental == 'with_rental'
    bicycle.model = bicycle_model
    bicycle.save()
    bicycle.declare_available()

    alert_kwargs = {
        'context': {},
        'default_roles': [Affiliation.FLEET_OPERATOR],
    }
    if with_rental:
        bicycle.rent(by=alice)
        alert_kwargs['user'] = alice

    if param_zone == 'with_zone':
        zone2 = request.getfixturevalue('zone2')
        alert_kwargs['context']['zone_uuid'] = str(zone2.uuid)
    assert Alert.objects.count() == 0

    assert maybe_create_and_send_alert(bicycle,
                                       Alert.RIDE_OUTSIDE_SERVICE_AREA,
                                       **alert_kwargs)
    assert Alert.objects.count() == 1
    alert = Alert.objects.get()
    assert alert.causality == bicycle
    assert alert.roles == alert_kwargs['default_roles']
    assert alert.organization == org
    assert alert.alert_type == 'bicycle.ride_outside'
    assert alert.message == ('Causality: bicycle {} |'
                             ' Type: bicycle.ride_outside'.format(
                                 bicycle.uuid))
    assert alert.state == 'new'
    if with_rental:
        assert alert.user == alice

    commit_success()
    assert NotificationMessage.objects.count() == (2 if with_rental else 1)
    assert len(mailoutbox) == 1

    email = mailoutbox.pop()
    assert email.recipients() == ['fleet_operator@example.com']
    assert email.subject == '[Noa Alert] Outside Service Area: bicycle [org]'

    assert len(email.alternatives) == 1
    html = email.alternatives[0][0]
    if param_zone == 'with_zone':
        assert '<h3>Bicycle {} is riding outside service area {}.</h3>'.format(
            bicycle.name, zone2.name) in html
    else:
        assert '<h3>Bicycle {} is riding outside service area.</h3>'.format(
            bicycle.name) in html
    assert ('<li>\n<strong>Time</strong>: {}</li>'.format(alert.display_time)
            in html)
    assert alert.frontend_uri in html
    assert '</html>' in html

    assert ' - Time: {}'.format(alert.display_time) in email.body
    assert alert.frontend_uri in email.body
    if with_rental:
        notification_message = NotificationMessage.objects.get(user=alice)
        assert notification_message.state == 'sent'
        assert notification_message.causality == alert


def test_email_dispatching(bicycle, active_lock, bicycle_model, org,
                           with_email, fleet_operator, alert_type,
                           commit_success, zone):
    from velodrome.lock8.models import (
        Affiliation, Alert, maybe_create_and_send_alert)
    bicycle.model = bicycle_model
    bicycle.save()
    bicycle.declare_available()

    alert_type, *_ = alert_type.partition('+')
    if alert_type.startswith('bicycle.'):
        causality = bicycle
    elif alert_type.startswith('zone.'):
        causality = zone
    else:
        assert alert_type.startswith('lock.')
        causality = active_lock

    maybe_create_and_send_alert(causality, alert_type,
                                default_roles=[Affiliation.FLEET_OPERATOR])
    assert Alert.objects.count() == 1
    alert = Alert.objects.get()
    description = next(d for i, d in Alert.TYPES if i == alert_type)

    assert alert.causality == causality
    assert alert.roles == ['fleet_operator']
    assert alert.user is None
    assert alert.state == 'new'
    assert alert.organization == org
    assert alert.message == 'Causality: {} {} | Type: {}'.format(
        causality.__class__.__name__.lower(),
        causality.uuid,
        alert_type)
    assert alert.description == description

    commit_success()
    with_email, mailoutbox = with_email
    if with_email:
        assert len(mailoutbox) == 1
        email = mailoutbox[0]
        if alert_type.startswith('lock.'):
            assert alert.context == {}
        if alert_type.startswith('bicycle.'):
            assert alert.context == {}
            assert email.subject == '[Noa Alert] {}: bicycle [org]'.format(
                description)
        if alert_type.startswith('zone.'):
            long, lat = zone.polygon.centroid.coords
            assert alert.context == {'location': {'coordinates': [long, lat],
                                                  'type': 'Point'}}
            assert email.subject == '[Noa Alert] {}: {} [org]'.format(
                description, causality.name)
        assert email.recipients() == ['fleet_operator@example.com']
        if alert.alert_type == Alert.RIDE_OUTSIDE_SERVICE_AREA:
            assert email.body.startswith(
                'Bicycle bicycle is riding outside service area.\n - Time:')


def test_alert_validation_error_for_wrong_type(org, lock, bicycle, alice):
    from velodrome.lock8.models import Alert, maybe_create_and_send_alert

    with pytest.raises(ValidationError) as e:
        maybe_create_and_send_alert(
            causality=lock, alert_type=Alert.RIDE_OUTSIDE_SERVICE_AREA,
            user=alice)
    assert e.value.messages == [
        'Alert of type bicycle.ride_outside must not have Lock causality.']

    with pytest.raises(ValidationError) as e:
        maybe_create_and_send_alert(
            causality=bicycle, alert_type=Alert.LOW_BATTERY, user=alice)
    assert e.value.messages == [
        'Alert of type lock.bat.low must not have Bicycle causality.']


def test_alert_silencing(drf_fleet_operator, fleet_operator, org, alert,
                         bicycle):
    from velodrome.lock8.models import AlertStates, maybe_create_and_send_alert

    alert.silence()
    assert alert.state == AlertStates.SILENCED.value

    created = maybe_create_and_send_alert(
        alert.causality, alert_type=alert.alert_type)
    assert not created
    alert.stop()
    assert alert.state == AlertStates.STOPPED.value
    created = maybe_create_and_send_alert(
        alert.causality, alert_type=alert.alert_type)
    assert created


def test_alert_use_causality_info(bicycle, create_gps_tracking,
                                  middle_of_central_park):
    from velodrome.lock8.models import Alert, maybe_create_and_send_alert

    create_gps_tracking(bicycle, *middle_of_central_park)
    alert = maybe_create_and_send_alert(bicycle,
                                        Alert.RIDE_OUTSIDE_SERVICE_AREA)
    assert alert.extra['location'] == {'type': 'Point',
                                       'coordinates': (
                                           -73.961900369117, 40.7874455)}


@pytest.mark.parametrize('transition', [
    'declare_available',
    'declare_lost'])
def test_auto_stop_lost_bicycle_reported(
        bicycle, alert_lost_bicycle_reported, transition):
    assert alert_lost_bicycle_reported.state == 'new'
    getattr(bicycle, transition)()

    alert_lost_bicycle_reported.refresh_from_db()
    assert alert_lost_bicycle_reported.state == 'stopped'


def test_auto_stop_lost_bicycle_reported_when_put_in_maintenance(
        bicycle_available, alert_lost_bicycle_reported):
    assert alert_lost_bicycle_reported.state == 'new'
    bicycle_available.put_in_maintenance()
    alert_lost_bicycle_reported.refresh_from_db()
    assert alert_lost_bicycle_reported.state == 'stopped'


def test_silence_stop_lost_bicycle_reported(alert_lost_bicycle_reported):
    alert_lost_bicycle_reported.silence()
    assert alert_lost_bicycle_reported.state == 'stopped'


def test_alert_bicycle_left_unlocked_stop_on_new_rental(
        commit_success, caplog, bicycle, alert_bicycle_left_unlocked, renter):
    bicycle.declare_available()
    bicycle.rent(by=renter)
    alert_bicycle_left_unlocked.refresh_from_db()
    assert alert_bicycle_left_unlocked.state == 'new'
    commit_success()
    alert_bicycle_left_unlocked.refresh_from_db()
    assert alert_bicycle_left_unlocked.state == 'stopped'
    assert (
        "velodrome.celery", 20,
        "rent: stopping 1 alerts for bicycle=%s" % (bicycle.uuid),
    ) in caplog.record_tuples


def test_oosa_alerts_are_stopped_when_in_maintenance(
        bicycle, alert_ride_outside_service_area):
    assert alert_ride_outside_service_area.state == 'new'
    bicycle.take_over()
    alert_ride_outside_service_area.refresh_from_db()
    assert alert_ride_outside_service_area.state == 'stopped'
