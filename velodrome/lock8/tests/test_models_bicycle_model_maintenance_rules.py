from datetime import timedelta
import uuid

from django.core.exceptions import ValidationError
from django.db.models import Q
from freezegun import freeze_time
import pytest


def test_bicycle_model_maintenance_rules_no_tasks_created(bicycle_model,
                                                          today):
    from velodrome.lock8.models import (
        Bicycle, BicycleModelMaintenanceRule as BMMR, Task
    )
    Bicycle.objects.all().delete()
    BMMR.objects.create(bicycle_model=bicycle_model,
                        fixed_date=today+timedelta(days=1))
    assert not Task.objects.exists()


@pytest.mark.parametrize('bmmr_type', ['fixed', 'distance', 'recurring'])
def test_bicycle_model_maintenance_rules(bicycle_model, today,
                                         bicycles_with_models,
                                         bmmr_type, mailoutbox):
    from velodrome.lock8.models import (
        BicycleModelMaintenanceRule as BMMR,
        NotificationMessage, Task
    )
    bicycle1, bicycle2 = bicycles_with_models

    if bmmr_type == 'fixed':
        in_15_days = today + timedelta(days=15)
        bmmr = BMMR.objects.create(bicycle_model=bicycle_model,
                                   fixed_date=in_15_days,
                                   description='The Rule always rules',
                                   )
    if bmmr_type == 'distance':
        bmmr = BMMR.objects.create(bicycle_model=bicycle_model,
                                   distance=666,
                                   description='The Rule always rules',
                                   )
    if bmmr_type == 'recurring':
        bmmr = BMMR.objects.create(bicycle_model=bicycle_model,
                                   recurring_time=timedelta(days=5),
                                   description='The Rule always rules',
                                   )

    assert Task.objects.count() == 2

    t1 = Task.objects.get(bicycles=bicycle1)
    t2 = Task.objects.get(bicycles=bicycle2)
    assert t1.maintenance_rule == bmmr
    assert t1.context == {'description': 'The Rule always rules'}
    assert t2.maintenance_rule == bmmr
    assert t2.context == {'description': 'The Rule always rules'}

    assert NotificationMessage.objects.count() == 0
    assert len(mailoutbox) == 0


def test_bicycle_model_maintenance_rules_validation(bicycle_model, today):
    from velodrome.lock8.models import BicycleModelMaintenanceRule

    with pytest.raises(ValidationError) as verr:
        BicycleModelMaintenanceRule(bicycle_model=bicycle_model).clean()
    assert verr.value.messages[0] == (
        'Rule must set one of the following fields: '
        'fixed_date, recurring_time, distance'
    )

    with pytest.raises(ValidationError) as verr:
        BicycleModelMaintenanceRule(
            bicycle_model=bicycle_model, fixed_date=today,
            recurring_time=timedelta(seconds=1)
        ).clean()
    assert verr.value.messages[0] == (
        'Rule cannot set both fixed_date and recurring_time fields'
    )

    with pytest.raises(ValidationError) as verr:
        BicycleModelMaintenanceRule(
            bicycle_model=bicycle_model,
            fixed_date=today, distance=666
        ).clean()
    assert verr.value.messages[0] == (
        'Rule cannot set fixed_date and distance fields'
    )

    with pytest.raises(ValidationError) as verr:
        BicycleModelMaintenanceRule(
            bicycle_model=bicycle_model,
            recurring_time=timedelta(seconds=1),
            distance=666
        ).clean()
    assert verr.value.messages[0] == (
        'Rule cannot set recurring_time and distance fields'
    )


def test_bicycle_model_maintenance_rules_due_date(bicycle_model,
                                                  bmmr_recurring,
                                                  bmmr_fixed,
                                                  today, task1,
                                                  bicycle):
    from velodrome.lock8.models import (
        BicycleModelMaintenanceRule as BMMR, Task
    )

    fixed_task = Task.objects.get(
        bicycles=bicycle, maintenance_rule__fixed_date__isnull=False
    )
    assert fixed_task.get_due_date() == today + timedelta(days=15)

    rec_task = Task.objects.get(
        maintenance_rule=bmmr_recurring, bicycles=bicycle
    )
    computed_due_date = rec_task.created + bmmr_recurring.recurring_time
    assert rec_task.get_due_date() == computed_due_date

    four_days_early = today + timedelta(days=1)
    with freeze_time(four_days_early):
        computed_due_date = four_days_early + timedelta(days=4)
        assert rec_task.get_due_date() == computed_due_date

    two_days_early = today + timedelta(days=3)
    with freeze_time(two_days_early):
        computed_due_date = two_days_early + timedelta(days=2)
        assert rec_task.get_due_date() == computed_due_date

    due_today = today + timedelta(days=5)
    with freeze_time(due_today):
        assert rec_task.get_due_date() == due_today

    when_it_was_due = today + bmmr_recurring.recurring_time
    overdue_by_5_days = today + timedelta(days=10)
    with freeze_time(overdue_by_5_days):
        assert rec_task.get_due_date() == when_it_was_due

    task1.due = None
    task1.save()
    assert task1.get_due_date() is None

    bmmr = BMMR.objects.create(bicycle_model=bicycle_model, distance=666)
    task1.causality = bmmr
    task1.save()
    assert task1.get_due_date() is None


def test_bicycle_model_maintenance_rules_on_delete(bicycle_model,
                                                   bmmr_recurring,
                                                   bmmr_fixed):
    from velodrome.lock8.models import (
        Bicycle, BicycleModelMaintenanceRule as BMMR
    )

    Bicycle.objects.all().delete()
    bicycle_model.delete()
    for bmmr in (bmmr_recurring, bmmr_fixed):
        with pytest.raises(BMMR.DoesNotExist):
            bmmr.refresh_from_db()


def test_bicycle_model_maintenance_rules_recurring_task(bicycle_model,
                                                        today, bicycle):
    from velodrome.lock8.models import (
        BicycleModelMaintenanceRule as BMMR,
        FeedbackCategory, Task
    )
    bicycle.model = bicycle_model
    bicycle.save()

    bmmr = BMMR.objects.create(
        bicycle_model=bicycle_model,
        description='foo',
        recurring_time=timedelta(days=2),
        severity=FeedbackCategory.SEVERITY_MEDIUM
    )

    fs = {'state': 'unassigned',
          'maintenance_rule': bmmr,
          'bicycles': bicycle}

    first_task = Task.objects.get(**fs)
    on_time = today + timedelta(days=2)
    with freeze_time(on_time):
        first_task.complete()

    second_task = Task.objects.get(**fs)
    assert second_task.get_due_date() == on_time + timedelta(days=2)

    one_day_early = on_time + timedelta(days=1)
    with freeze_time(one_day_early):
        second_task.complete()

    third_task = Task.objects.get(**fs)
    assert third_task.get_due_date() == one_day_early + timedelta(days=2)

    one_day_late = one_day_early + timedelta(days=3)
    with freeze_time(one_day_late):
        third_task.complete()

    fourth_task = Task.objects.get(**fs)
    assert fourth_task.get_due_date() == one_day_late + timedelta(days=2)


def test_bicycle_model_maintenance_rules_deactivated(bicycle_model,
                                                     today, bicycle):
    from velodrome.lock8.models import (
        BicycleModelMaintenanceRule as BMMR,
        FeedbackCategory, TaskStates
    )
    bicycle.model = bicycle_model
    bicycle.save()

    bmmr = BMMR.objects.create(
        bicycle_model=bicycle_model,
        description='foo',
        recurring_time=timedelta(days=2),
        severity=FeedbackCategory.SEVERITY_MEDIUM
    )

    task1 = bmmr.tasks.get()
    bmmr.deactivate()
    task1.refresh_from_db()
    assert task1.state == TaskStates.UNASSIGNED.value
    bmmr.activate()

    bmmr.deactivate(cancel_tasks=True)
    task1.refresh_from_db()
    assert task1.state == TaskStates.CANCELLED.value

    bmmr.activate()
    task2 = bmmr.tasks.get(~Q(id=task1.id))
    task2.complete()
    bmmr.deactivate(cancel_tasks=True)


def test_bicycle_model_maintenance_rules_recurring_dist_task(bicycle_model,
                                                             today, bicycle):
    from velodrome.lock8.models import (
        BicycleModelMaintenanceRule as BMMR, Task
    )
    bicycle.model = bicycle_model
    bicycle.save()

    bmmr = BMMR.objects.create(bicycle_model=bicycle_model, distance=10)
    fs = {'state': 'unassigned', 'maintenance_rule': bmmr, 'bicycles': bicycle}

    Task.objects.get(**fs).complete()
    Task.objects.get(**fs).complete()
    third_task = Task.objects.get(**fs)
    assert third_task.maintenance_rule.distance == 10
    assert Task.objects.filter(maintenance_rule=bmmr).count() == 3


def test_bicycle_model_maintenance_rules_extra_task_not_created(bicycle_model,
                                                                today,
                                                                mechanic1,
                                                                bicycle):
    from velodrome.lock8.models import (
        BicycleModelMaintenanceRule as BMMR, Task
    )
    bicycle.model = bicycle_model
    bicycle.save()

    bmmr = BMMR.objects.create(bicycle_model=bicycle_model,
                               recurring_time=timedelta(days=2))
    assert Task.objects.count() == 1
    first_task = Task.objects.get(state='unassigned', maintenance_rule=bmmr)
    first_task.assign(assignee=mechanic1)
    assert Task.objects.count() == 1


def test_lost_bicycles_dont_get_tasks(bicycles_with_models, bicycle_model,
                                      bicycle):
    from velodrome.lock8.models import (
        BicycleModelMaintenanceRule as BMMR,
        Task
    )

    bicycle1, _ = bicycles_with_models
    bicycle1.declare_lost()

    bmmr = BMMR.objects.create(
        bicycle_model=bicycle_model,
        recurring_time=timedelta(days=2)
    )
    assert bmmr.bicycle_model.bicycles.count() == 2
    assert Task.objects.count() == 1


def test_bicycles_with_other_org_dont_get_tasks(bicycles_with_models,
                                                bicycle_model, bicycle,
                                                another_bicycle_model,
                                                another_bicycle, org):
    from velodrome.lock8.models import (
        BicycleModelMaintenanceRule as BMMR,
        Task
    )

    another_bicycle.model = another_bicycle_model
    another_bicycle.save()

    BMMR.objects.create(
        bicycle_model=bicycle_model,
        recurring_time=timedelta(days=2)
    )
    tasks = Task.objects.all()
    assert tasks.count() == 2
    assert all((t.organization == org for t in tasks))


def test_bicycle_model_maintenance_rules_reactivated(bicycle_model, today,
                                                     bicycle):
    from velodrome.lock8.models import (
        Bicycle,
        BicycleModelMaintenanceRule as BMMR,
        FeedbackCategory, Task
    )
    bicycle.model = bicycle_model
    bicycle.save()
    bicycle1 = Bicycle.objects.get(pk=bicycle.pk)
    bicycle.pk = None
    bicycle.uuid = uuid.uuid4()
    bicycle.lock = None
    bicycle.short_id = 'abc'
    bicycle.name = 'bicycle2'
    bicycle.save()
    bicycle2 = Bicycle.objects.get(pk=bicycle.pk)

    bmmr = BMMR.objects.create(
        bicycle_model=bicycle_model,
        description='foo',
        recurring_time=timedelta(days=2),
        severity=FeedbackCategory.SEVERITY_MEDIUM
    )
    BMMR.objects.create(
        bicycle_model=bicycle_model,
        description='foo',
        recurring_time=timedelta(days=2),
        severity=FeedbackCategory.SEVERITY_MEDIUM
    )

    fs = {'state': 'unassigned',
          'maintenance_rule': bmmr,
          'bicycles': bicycle1}
    bmmr.deactivate()

    assert bicycle1.tasks.filter(state='unassigned').count() == 2
    assert bicycle1.tasks.filter(state='completed').count() == 0
    assert bicycle2.tasks.filter(state='unassigned').count() == 2
    assert bicycle2.tasks.filter(state='completed').count() == 0

    task = Task.objects.get(**fs)
    on_time = today + timedelta(days=2)
    with freeze_time(on_time):
        task.complete()

    assert bicycle1.tasks.filter(state='unassigned').count() == 1
    assert bicycle1.tasks.filter(state='completed').count() == 1
    assert bicycle2.tasks.filter(state='unassigned').count() == 2
    assert bicycle2.tasks.filter(state='completed').count() == 0

    bmmr.activate()

    assert bicycle1.tasks.filter(state='unassigned').count() == 2
    assert bicycle1.tasks.filter(state='completed').count() == 1
    assert bicycle2.tasks.filter(state='unassigned').count() == 2
    assert bicycle2.tasks.filter(state='completed').count() == 0

    bmmr.deactivate()

    task = Task.objects.get(state='unassigned',
                            maintenance_rule=bmmr,
                            bicycles=bicycle2)
    on_time = today + timedelta(days=2)
    with freeze_time(on_time):
        task.complete()

    assert bicycle1.tasks.filter(state='unassigned').count() == 2
    assert bicycle1.tasks.filter(state='completed').count() == 1
    assert bicycle2.tasks.filter(state='unassigned').count() == 1
    assert bicycle2.tasks.filter(state='completed').count() == 1

    bmmr.activate()

    assert bicycle1.tasks.filter(state='unassigned').count() == 2
    assert bicycle1.tasks.filter(state='completed').count() == 1
    assert bicycle2.tasks.filter(state='unassigned').count() == 2
    assert bicycle2.tasks.filter(state='completed').count() == 1


def test_bmmr_model_reactivate_with_cancelled_tasks(bmmr_fixed):
    assert bmmr_fixed.tasks.count() == 2
    bmmr_fixed.deactivate()
    bmmr_fixed.create_missing_tasks()
    assert bmmr_fixed.tasks.count() == 2


def test_start_future_bmmr(bicycle, bicycle_model, today):
    from velodrome.celery import start_future_bmmr
    from velodrome.lock8.models import (
        BicycleModelMaintenanceRule as BMMR,
        FeedbackCategory,
    )
    bicycle.model = bicycle_model
    bicycle.save()

    bmmr = BMMR.objects.create(
        bicycle_model=bicycle_model,
        description='foo',
        recurring_time=timedelta(days=2),
        severity=FeedbackCategory.SEVERITY_MEDIUM,
        start_date=today + timedelta(days=2),
    )

    assert bmmr.tasks.count() == 0

    with freeze_time(today + timedelta(days=2)):
        start_future_bmmr()

    assert bmmr.tasks.count() == 1
