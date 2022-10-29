from django.core.exceptions import ValidationError
from django.db.models import ProtectedError
from django.utils import timezone as django_timezone
import pytest


def test_task_created_on_bicycle_model_pref(bicycle_model, lock, org, bicycle):
    from velodrome.lock8.models import (
        Affiliation, Alert, FeedbackCategory, Task, maybe_create_and_send_alert
    )

    bicycle_model.alert_types_to_task = {
        Alert.LOW_BATTERY: FeedbackCategory.SEVERITY_LOW}
    bicycle_model.save()
    bicycle.model = bicycle_model
    bicycle.declare_available()

    maybe_create_and_send_alert(
            lock, Alert.LOW_BATTERY,
            default_roles=[Affiliation.FLEET_OPERATOR])

    alert = Alert.objects.get()
    assert alert.causality == lock
    assert alert.alert_type == 'lock.bat.low'
    assert alert.state == 'escalated'

    task = Task.objects.get()
    assert task.causality == alert
    assert task.organization == org
    assert task.role == alert.roles[0]
    assert task.severity == 'low'


@pytest.mark.parametrize('with_preferred', (True, False))
def test_task_created_and_assigned_on_zone(bicycle_model, lock,
                                           org, bicycle, mechanic1, zone,
                                           with_preferred,
                                           middle_of_central_park,
                                           mechanic2, create_gps_tracking):
    from velodrome.lock8.models import (
        Affiliation, Alert, FeedbackCategory, Task,
        maybe_create_and_send_alert
    )

    lock.activate()
    bicycle_model.alert_types_to_task = {
        Alert.LOW_BATTERY: FeedbackCategory.SEVERITY_LOW}
    bicycle_model.save()
    bicycle.model = bicycle_model
    bicycle.declare_available()

    if with_preferred:
        zone.preferred_mechanic = mechanic1
        zone.save()

    # let's locate the Bicycle in Central Park.
    create_gps_tracking(lock, *middle_of_central_park)

    # Trig the Alarm
    maybe_create_and_send_alert(
            lock, Alert.LOW_BATTERY,
            default_roles=[Affiliation.FLEET_OPERATOR])

    alert = Alert.objects.get()
    assert alert.causality == lock
    assert alert.alert_type == 'lock.bat.low'
    assert alert.state == 'escalated'

    task = Task.objects.get()
    assert task.causality == alert
    assert task.organization == org
    assert task.severity == 'low'
    if with_preferred:
        assert task.assignee == mechanic1

        assert task.role == Affiliation.FLEET_OPERATOR
        task.assign(mechanic2)
    else:
        assert task.role == alert.roles[0]


@pytest.mark.parametrize('distance, expected', (
    (.22, 665.78),
    (.44, 665.56),
    (35., 631),
    (666., 0),
    (667., 0)
))
def test_tasks_get_remaining_distance(bmmr_distance, bicycle, mocker,
                                      distance, expected):
    target = 'velodrome.lock8.models.get_distance_for_bicycles_since'
    ret = {str(bicycle.uuid): distance}
    mocker.patch(target, return_value=ret)
    assert bicycle.tasks.get().get_remaining_distance() == expected


def test_tasks_remaining_distance_no_metrics(bmmr_distance, bicycle, mocker):
    target = 'velodrome.lock8.models.get_distance_for_bicycles_since'
    mocker.patch(target, return_value={})
    assert bicycle.tasks.get().get_remaining_distance() is None


def test_task_model(org, fleet_operator, alert, with_email, commit_success):
    from velodrome.lock8.models import (
        Affiliation, FeedbackCategory, Task, TaskStates
    )

    now = django_timezone.now()
    task = Task.objects.create(
        owner=fleet_operator,
        organization=org,
        assignor=fleet_operator,
        role=Affiliation.MECHANIC,
        due=now,
        context={'alert_type': alert.alert_type},
        causality=alert,
        severity=FeedbackCategory.SEVERITY_MEDIUM
    )

    assert task.organization == org
    assert task.assignor == fleet_operator
    assert not task.assignee
    assert task.due == now
    assert task.context == {'alert_type': alert.alert_type}
    assert task.causality == alert
    assert task.state == TaskStates.UNASSIGNED.value
    assert task.severity == FeedbackCategory.SEVERITY_MEDIUM

    task.complete()
    assert task.state == TaskStates.COMPLETED.value
    commit_success()
    with_email, mailoutbox = with_email
    if with_email:
        assert mailoutbox[0].subject == '[TASK] completed'


def test_task_model_creation_alerts(fleet_operator, mechanic1, mechanic2,
                                    task1, another_mechanic, with_email,
                                    commit_success):
    from velodrome.lock8.models import NotificationMessage

    assert fleet_operator.created_tasks.get() == task1
    assert all(p.assigned_tasks.count() == 0 for p in (
        fleet_operator, mechanic1, mechanic2, another_mechanic
    ))

    commit_success()
    assert NotificationMessage.objects.count() == 2


def test_task_model_transitions(another_mechanic, mechanic1, mechanic2,
                                fleet_operator, task1, today, commit_success):
    from velodrome.lock8.models import (
        NotificationMessage,
        NotificationMessageStates,
        TaskStates
    )

    commit_success()
    messages = NotificationMessage.objects.all()
    assert messages.count() == 2
    assert all(m.causality == task1 for m in messages)

    with pytest.raises(ValidationError) as e:
        task1.assign(another_mechanic)
    assert e.value.messages == [
        'Cannot assign Task to Clint Eastwood.'
        ' No existing affiliation.'
    ]

    assert task1.state == TaskStates.UNASSIGNED.value
    task1.assign(mechanic2)
    assert task1.state == TaskStates.ASSIGNED.value
    commit_success()

    assert NotificationMessage.objects.count() == 3
    assert NotificationMessage.objects.filter(
        state='acknowledged', user=mechanic1,
    ).count() == 1

    assert mechanic2.assigned_tasks.get() == task1
    messages = mechanic2.notification_messages.all()
    assert messages.count() == 2
    assert all(m.causality == task1 for m in messages)

    assert task1.state == TaskStates.ASSIGNED.value
    task1.assign(mechanic1)
    assert task1.state == TaskStates.ASSIGNED.value
    commit_success()

    ackd_messages = mechanic2.notification_messages.all()
    assert all([
        m.state == NotificationMessageStates.ACKNOWLEDGED.value
        for m in ackd_messages
    ])

    assert NotificationMessage.objects.count() == 4

    assert not mechanic2.assigned_tasks.exists()
    assert mechanic1.assigned_tasks.get() == task1

    messages = mechanic1.notification_messages.all()
    assert messages.count() == 2
    assert all(m.causality == task1 for m in messages)

    task1.complete()
    commit_success()
    assert task1.state == TaskStates.COMPLETED.value
    assert task1.completed_at == today

    assert NotificationMessage.objects.count() == 5

    message = fleet_operator.notification_messages.get()
    assert message.causality == task1
    assert message.causality.state == TaskStates.COMPLETED.value

    assert all(
        m.state == NotificationMessageStates.ACKNOWLEDGED.value
        for m in (list(mechanic1.notification_messages.all()) +
                  list(mechanic2.notification_messages.all()))
    )


def test_task_model_cancel(fleet_operator, mechanic1, task1, with_email,
                           commit_success):
    from django_fsm import TransitionNotAllowed
    from velodrome.lock8.models import TaskStates

    task1.assign(assignee=mechanic1)
    commit_success()
    assert mechanic1.notification_messages.count() == 2

    task1.cancel()
    assert task1.state == TaskStates.CANCELLED.value

    with pytest.raises(TransitionNotAllowed):
        task1.assign(mechanic1)

    with pytest.raises(TransitionNotAllowed):
        task1.unassign()

    with pytest.raises(TransitionNotAllowed):
        task1.complete()

    with pytest.raises(TransitionNotAllowed):
        task1.cancel()

    commit_success()
    assert mechanic1.notification_messages.count() == 3

    with_email, mailoutbox = with_email
    if with_email:
        mechanic_mail = mailoutbox[-2]
        fleet_op_mail = mailoutbox[-1]

        assert mechanic_mail.subject == '[TASK] cancelled'
        assert mechanic_mail.to == [mechanic1.email]

        assert fleet_op_mail.subject == '[TASK] cancelled'
        assert fleet_op_mail.to == [fleet_operator.email]


def test_task_model_unassign(another_mechanic, mechanic1,
                             fleet_operator, task1, commit_success):
    from velodrome.lock8.models import (
        NotificationMessageStates,
        TaskStates
    )
    commit_success()
    assert task1.state == TaskStates.UNASSIGNED.value
    task1.assign(mechanic1)
    commit_success()

    notf1, notf2 = mechanic1.notification_messages.all()
    assert notf1.state == NotificationMessageStates.ACKNOWLEDGED.value
    assert notf2.state == NotificationMessageStates.SENT.value

    assert mechanic1.assigned_tasks.get() == task1
    task1.unassign()
    assert not mechanic1.assigned_tasks.exists()

    notf2.refresh_from_db()
    assert notf2.state == NotificationMessageStates.ACKNOWLEDGED.value

    assert mechanic1.notification_messages.count() == 2
    task1.assign(mechanic1)
    commit_success()
    assert mechanic1.notification_messages.count() == 3


def test_task_model_on_delete_organization(task1, org):
    from velodrome.lock8.models import Lock, Task

    Lock.objects.all().delete()
    org.delete()
    with pytest.raises(Task.DoesNotExist):
        task1.refresh_from_db()


def test_task_model_on_delete_protect_assignor(task1, fleet_operator,
                                               another_fleet_operator):
    task1.owner = another_fleet_operator  # owner is protected
    task1.save()
    assert task1.assignor == fleet_operator
    with pytest.raises(ProtectedError):
        fleet_operator.delete()


def test_task_model_on_delete_protect_assignee(task1, mechanic1):
    task1.assign(mechanic1)
    assert task1.assignee == mechanic1
    with pytest.raises(ProtectedError):
        mechanic1.delete()


def test_task_model_on_delete_rule_protect(mechanic1, bmmr_fixed):
    from velodrome.lock8.models import Task
    assert Task.objects.count() == 2
    with pytest.raises(ProtectedError):
        bmmr_fixed.delete()


def test_task_escalate_doesnt_create(bicycle_model, lock, bicycle):
    from velodrome.lock8.models import (
        Affiliation, Alert, FeedbackCategory, Task, maybe_create_and_send_alert
    )

    bicycle_model.alert_types_to_task = {
        Alert.LOW_BATTERY: FeedbackCategory.SEVERITY_LOW
    }
    bicycle_model.save()
    bicycle.model = bicycle_model
    bicycle.declare_available()

    assert Task.objects.count() == 0
    maybe_create_and_send_alert(
            lock, Alert.LOW_BATTERY,
            default_roles=[Affiliation.FLEET_OPERATOR])
    assert Task.objects.count() == 1
    maybe_create_and_send_alert(
            lock, Alert.LOW_BATTERY,
            default_roles=[Affiliation.FLEET_OPERATOR])
    assert Task.objects.count() == 1


def test_task_escalate_handles_none_location(bicycle_model, lock, bicycle):
    from velodrome.lock8.models import (
        Affiliation, Alert, FeedbackCategory, Task,
        maybe_create_and_send_alert, PublicTracking)

    bicycle_model.alert_types_to_task = {
        Alert.LOW_BATTERY: FeedbackCategory.SEVERITY_LOW
    }
    bicycle_model.save()
    bicycle.model = bicycle_model
    bicycle.declare_available()

    lock.public_tracking = PublicTracking.objects.create(attributes={})
    maybe_create_and_send_alert(lock, Alert.LOW_BATTERY,
                                default_roles=[Affiliation.FLEET_OPERATOR])
    assert Task.objects.get().assignee is None
