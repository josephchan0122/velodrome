import django_fsm
import pytest


def test_feedback_model(alice, org, owner, photo, bicycle, fleet_operator,
                        organization_preference, another_feedback, with_email,
                        commit_success):
    from velodrome.lock8.models import (
        Feedback, FeedbackCategory,
        FeedbackStates, NotificationMessage, Task
    )

    feedback = Feedback.objects.create(
        owner=owner,
        organization=org,
        user=alice,
        image=photo.image,
        message='It blew up.',
        causality=bicycle,
        severity=FeedbackCategory.SEVERITY_LOW
    )
    commit_success()

    assert feedback.organization == org
    assert feedback.user == alice
    assert feedback.image == photo.image
    assert feedback.message == 'It blew up.'
    assert feedback.state == FeedbackStates.NEW.value
    assert feedback.causality == bicycle
    assert feedback.severity == FeedbackCategory.SEVERITY_LOW

    notification = NotificationMessage.objects.get(user=fleet_operator)
    assert notification.causality == feedback

    assert notification.user == fleet_operator
    fleet_operator.delete()
    with pytest.raises(NotificationMessage.DoesNotExist):
        notification.refresh_from_db()

    with_email, mailoutbox = with_email
    if with_email:
        assert len(mailoutbox) == 1
        email = mailoutbox[0]
        assert email.global_merge_vars == {
            'user_name': feedback.user.display_name,
            'image': feedback.image.url,
            'user_link': f'https://fms.noa.one/users/{str(alice.uuid)}',
            'message': feedback.message,
        }

    feedback.escalate(severity=FeedbackCategory.SEVERITY_HIGH)
    feedback.refresh_from_db()
    assert feedback.state == FeedbackStates.ESCALATED.value
    with pytest.raises(django_fsm.TransitionNotAllowed):
        feedback.discard()
    assert feedback.transitions.count() == 1

    task = Task.objects.get(object_id=feedback.id)
    assert task.severity == FeedbackCategory.SEVERITY_HIGH

    another_feedback.discard()
    another_feedback.refresh_from_db()
    assert another_feedback.state == FeedbackStates.DISCARDED.value
    assert another_feedback.transitions.count() == 1


def test_feedback_auto_escalates_to_task(alice, fleet_operator, org, owner,
                                         photo, bicycle, mechanic1,
                                         bicycle_model, with_email,
                                         commit_success):
    from velodrome.lock8.models import (
        Affiliation, Feedback, FeedbackCategory, NotificationMessage, Task
    )

    bicycle.model = bicycle_model
    bicycle.save()

    fctree = org.get_feedback_category_tree()
    leaf = fctree.get_leafnodes().get(name='front-wheel')
    leaf.severity = FeedbackCategory.SEVERITY_HIGH
    leaf.save()
    feedback = Feedback.objects.create(
        owner=owner,
        organization=org,
        user=alice,
        causality=bicycle,
        category=leaf,
        severity=leaf.severity
    )

    with pytest.raises(NotificationMessage.DoesNotExist):
        NotificationMessage.objects.get(user=fleet_operator)

    task = Task.objects.get()
    assert task.organization == org
    assert task.causality == feedback
    assert task.role == Affiliation.MECHANIC
    assert task.causality.causality == bicycle
    assert task.severity == leaf.severity

    commit_success()
    nmessage = NotificationMessage.objects.get()
    assert nmessage.causality == task
    with_email, mailoutbox = with_email
    if with_email:
        assert len(mailoutbox) == 1
        assert mailoutbox[0].subject == (
            '[TASK] created based on Feedback of Alice Cooper'
        )


@pytest.mark.parametrize('org_severity_pref, leaf_severity', (
    ('medium', 'low'),
    ('high', 'low'),
    ('high', 'medium'),
))
def test_feedback_no_escalate_based_on_org_pref(alice, bicycle, org, owner,
                                                bicycle_model,
                                                front_wheel_category,
                                                org_severity_pref,
                                                leaf_severity):
    from velodrome.lock8.models import Feedback, Task

    front_wheel_category.severity = leaf_severity
    front_wheel_category.save()

    bicycle_model.feedback_auto_escalate_severity = org_severity_pref
    bicycle_model.save()

    feedback = Feedback.objects.create(
        owner=owner,
        user=alice,
        organization=org,
        category=front_wheel_category,
        causality=bicycle
    )
    with pytest.raises(Task.DoesNotExist):
        Task.objects.get(object_id=feedback.pk)


@pytest.mark.parametrize('org_severity_pref, leaf_severity', (
    ('low', 'low'),
    ('low', 'medium'),
    ('low', 'high'),
    ('medium', 'medium'),
    ('medium', 'high'),
    ('high', 'high'),
))
def test_feedback_escalate_based_on_org_pref(alice, bicycle, org, owner,
                                             bicycle_model,
                                             front_wheel_category,
                                             org_severity_pref,
                                             leaf_severity):
    from velodrome.lock8.models import Feedback, Task

    front_wheel_category.severity = leaf_severity
    front_wheel_category.save()

    bicycle_model.feedback_auto_escalate_severity = org_severity_pref
    bicycle_model.save()
    bicycle.model = bicycle_model
    bicycle.save()

    feedback = Feedback.objects.create(
        owner=owner,
        user=alice,
        organization=org,
        category=front_wheel_category,
        severity=leaf_severity,
        causality=bicycle
    )
    assert Task.objects.filter(object_id=feedback.pk).exists()
