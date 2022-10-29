from datetime import timedelta
from unittest import mock


def test_send_feedback_email_dispatch(feedback, notification_message,
                                      with_email, settings):
    from velodrome.lock8.dispatchers import (
        send_notification_message_dispatcher)
    with_email, mailoutbox = with_email
    if with_email:
        send_notification_message_dispatcher(feedback,
                                             notification_message)
        email = mailoutbox[0]
        assert email.to == [notification_message.user.email]
        assert email.subject == '[FEEDBACK] reported by {}'.format(
            feedback.user.display_name
        )


def test_send_task_email_dispatch(fleet_operator, mechanic1, mechanic2, task1,
                                  with_email, settings,
                                  commit_success):
    from velodrome.lock8.dispatchers import (
        send_notification_message_dispatcher)
    from velodrome.lock8.models import TaskStates

    with_email, mailoutbox = with_email

    def assert_payload(mock_target, task, msg, called_with):
        with mock.patch(mock_target) as patched:
            send_notification_message_dispatcher(task, msg)
        if isinstance(called_with, dict):
            patched.assert_called_with(**called_with)
        else:
            patched.assert_called_with(*called_with[0], **called_with[1])

    def assert_email(to, subject, merge_vars):
        email = mailoutbox[-1]
        assert email.to == to
        assert email.subject == subject
        assert email.global_merge_vars == merge_vars

    assert task1.state == TaskStates.UNASSIGNED.value
    commit_success()
    message = mechanic2.notification_messages.get()
    if with_email:
        send_notification_message_dispatcher(task1, message)
        to = [mechanic2.email]
        subject = '[TASK] created by {}'.format(task1.assignor.display_name)
        merge_vars = dict(assignor_name=task1.assignor.display_name)
        assert_email(to, subject, merge_vars)

    task1.assign(mechanic2)
    assert task1.state == TaskStates.ASSIGNED.value
    message = mechanic2.notification_messages.last()

    if with_email:
        send_notification_message_dispatcher(task1, message)
        to = [mechanic2.email]
        subject = '[TASK] assigned'
        merge_vars = dict(assignee_name=task1.assignee.display_name)
        assert_email(to, subject, merge_vars)

    task1.complete()
    assert task1.state == TaskStates.COMPLETED.value
    commit_success()
    message = fleet_operator.notification_messages.last()

    if with_email:
        send_notification_message_dispatcher(task1, message)
        to = [fleet_operator.email]
        subject = '[TASK] completed by {}'.format(mechanic2.display_name)
        merge_vars = dict(assignee_name=task1.assignee.display_name)
        assert_email(to, subject, merge_vars)


def test_send_task_email_new_to_completed_dispatch(fleet_operator, task1,
                                                   with_email, commit_success):
    from velodrome.lock8.models import TaskStates
    from velodrome.lock8.dispatchers import (
        send_notification_message_dispatcher)

    assert task1.state == TaskStates.UNASSIGNED.value
    task1.complete()
    assert task1.state == TaskStates.COMPLETED.value
    commit_success()

    message = fleet_operator.notification_messages.last()
    send_notification_message_dispatcher(task1, message)

    with_email, mailoutbox = with_email
    if with_email:
        email = mailoutbox[-1]
        assert email.to == [fleet_operator.email]
        assert email.subject == '[TASK] completed'
        assert not email.global_merge_vars


def test_no_send_task_email_when_no_assignor(another_mechanic, mechanic1,
                                             mechanic2, task1, fleet_operator,
                                             organization_preference,
                                             mailoutbox, commit_success):
    commit_success()
    organization_preference.send_task_per_email = True
    organization_preference.save()

    task1.assignor = None
    task1.save()

    assert len(mailoutbox) == 0
    task1.assign(mechanic1)
    commit_success()
    assert len(mailoutbox) == 1
    task1.complete()
    commit_success()
    assert len(mailoutbox) == 1


def test_send_assignee_has_precedence_over_role(
        mechanic1, fleet_operator, mailoutbox, organization_preference, today,
        org, alert, commit_success):
    from velodrome.lock8.models import Affiliation, FeedbackCategory, Task

    organization_preference.send_task_per_email = True
    organization_preference.save()

    Task.objects.create(
        owner=fleet_operator,
        organization=org,
        assignor=fleet_operator,
        assignee=mechanic1,
        role=Affiliation.MECHANIC,
        due=today,
        context={'alert_type': alert.alert_type},
        causality=alert,
        severity=FeedbackCategory.SEVERITY_MEDIUM
    )
    commit_success()

    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.to == [mechanic1.email]


def test_no_send_task_with_bmmr_causality(bicycle_model, mechanic1,
                                          mechanic2, organization_preference,
                                          bicycles_with_models, mailoutbox):
    from velodrome.lock8.models import (
        BicycleModelMaintenanceRule as BMMR,
        FeedbackCategory, NotificationMessage,
        Task
    )

    organization_preference.send_task_per_email = True
    organization_preference.save()

    BMMR.objects.create(
        bicycle_model=bicycle_model,
        recurring_time=timedelta(days=2),
        severity=FeedbackCategory.SEVERITY_MEDIUM
    )
    assert NotificationMessage.objects.count() == 0
    assert len(mailoutbox) == 0
    assert Task.objects.count() == 2


def test_send_task_with_bmmr_assign_complete(
        bicycle_model, mechanic1, mechanic2, fleet_operator,
        organization_preference, bicycle, mailoutbox, commit_success):
    from velodrome.lock8.models import (
        BicycleModelMaintenanceRule as BMMR,
        FeedbackCategory, Task
    )

    bicycle.model = bicycle_model
    bicycle.save()

    organization_preference.send_task_per_email = True
    organization_preference.save()

    BMMR.objects.create(
        bicycle_model=bicycle_model,
        recurring_time=timedelta(days=2),
        severity=FeedbackCategory.SEVERITY_MEDIUM
    )
    task = Task.objects.get()

    assert mechanic1.notification_messages.count() == 0
    task.assign(mechanic1)
    commit_success()
    assert mechanic1.notification_messages.count() == 1
    assert mechanic2.notification_messages.count() == 0

    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.to == [mechanic1.email]
    assert email.subject == '[TASK] assigned'

    task.complete()
    assert fleet_operator.notification_messages.count() == 0
    assert mechanic1.notification_messages.count() == 1
    assert mechanic2.notification_messages.count() == 0


def test_alert_dispatch_email_only(organization_preference, org, lock,
                                   mechanic1, mechanic2, alert, bicycle,
                                   mailoutbox):
    from velodrome.lock8.models import Affiliation, Alert

    organization_preference.allowed_email_alert_types = [Alert.LOW_BATTERY]
    organization_preference.save()

    alert.roles = [Affiliation.MECHANIC]
    alert.save()
    alert.send()

    assert len(mailoutbox) == 2
    m1, m2 = mailoutbox
    assert m1.to == [mechanic2.email]
    assert m2.to == [mechanic1.email]


def test_alert_dispatch_no_email_or_push(organization_preference, org, lock,
                                         mechanic1, mechanic2, alert,
                                         mailoutbox):
    from velodrome.lock8.models import Affiliation

    organization_preference.allowed_email_alert_types = []
    organization_preference.save()

    alert.roles = [Affiliation.MECHANIC]
    alert.save()
    alert.send()

    assert len(mailoutbox) == 0
