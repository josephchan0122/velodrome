import datetime as dt
import uuid

from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from freezegun import freeze_time
from rest_framework import status

from velodrome.lock8.utils import reverse_query


def test_tasks_due_computed_or_given_by_client(drf_fleet_operator, task1,
                                               today, bicycle_model,
                                               bicycle, mocker):
    from velodrome.lock8.models import (
        BicycleModelMaintenanceRule as BMMR,
        FeedbackCategory, Task
    )

    bicycle.model = bicycle_model
    bicycle.save()

    detail_url = reverse_query(
        'lock8:task-detail', kwargs={'uuid': task1.uuid}
    )
    response = drf_fleet_operator.assert_success(detail_url)
    assert response.data['due'] == today.isoformat()[:-13] + 'Z'

    bmmr = BMMR.objects.create(
        bicycle_model=bicycle_model,
        description='foo',
        recurring_time=dt.timedelta(days=5),
        severity=FeedbackCategory.SEVERITY_MEDIUM
    )
    task = Task.objects.get(maintenance_rule=bmmr)
    mocker.patch('velodrome.lock8.models.get_distance_for_bicycles_since',
                 return_value={})
    detail_url = reverse_query('lock8:task-detail', kwargs={'uuid': task.uuid})
    response = drf_fleet_operator.assert_success(detail_url)
    assert response.data['due'] == (
        today + dt.timedelta(days=5)).isoformat()[:-13] + 'Z'


def test_task_bmmr_causality_not_writable(drf_fleet_operator, task1,
                                          bmmr_fixed, org, bicycle_model,
                                          bicycle):
    from velodrome.lock8.models import Affiliation, FeedbackCategory
    org_url = reverse_query(
        'lock8:organization-detail', kwargs={'uuid': org.uuid}
    )
    bmmr_url = reverse_query(
        'lock8:maintenance_rule-detail',
        kwargs={
            'uuid': bmmr_fixed.uuid,
            'parent_lookup_uuid': bicycle_model.uuid
        }
    )
    bicycle_url = reverse_query('lock8:bicycle-detail',
                                kwargs={'uuid': bicycle.uuid})
    url = reverse_query('lock8:task-list')
    response = drf_fleet_operator.post(url, data={
        'organization': org_url,
        'severity': FeedbackCategory.SEVERITY_MEDIUM,
        'role': Affiliation.MECHANIC,
        'maintenance_rule': bmmr_url,
        'causality': bicycle_url,
    }, format='json')
    assert response.data['maintenance_rule'] is None


def test_crud_tasks(drf_fleet_operator, bicycle, lock, org, owner,
                    fleet_operator, mechanic1, today):
    from velodrome.lock8.models import Affiliation, FeedbackCategory, Task
    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})
    user_url = reverse_query('lock8:user-detail',
                             kwargs={'uuid': fleet_operator.uuid})
    mechanic_url = reverse_query('lock8:user-detail',
                                 kwargs={'uuid': mechanic1.uuid})
    bicycle_url = reverse_query('lock8:bicycle-detail',
                                kwargs={'uuid': bicycle.uuid})
    url = reverse_query('lock8:task-list')
    response = drf_fleet_operator.post(url, data={
        'organization': organization_url,
        'severity': 'medium',
        'role': 'mechanic',
        'causality': bicycle_url,
    }, format='json')
    assert response.status_code == status.HTTP_201_CREATED, response.data

    task = Task.objects.get(uuid=response.data['uuid'])
    assert task.organization == org
    assert task.severity == FeedbackCategory.SEVERITY_MEDIUM
    assert task.role == Affiliation.MECHANIC
    assert task.context == {}
    assert task.causality == bicycle
    assert task.due is None
    assert task.assignee is None
    assert task.assignor == fleet_operator
    assert task.owner == fleet_operator
    assert task.state == 'unassigned'

    detail_url = reverse_query('lock8:task-detail', kwargs={'uuid': task.uuid})
    response = drf_fleet_operator.assert_success(detail_url, {
        'organization': 'http://testserver' + organization_url,
        'url': 'http://testserver' + detail_url,
        'uuid': str(task.uuid),
        'severity': 'medium',
        'due': None,
        'is_due': True,
        'completed_at': None,
        'remaining_distance': None,
        'role': 'mechanic',
        'bicycle': 'http://testserver' + bicycle_url,
        'causality': 'http://testserver' + bicycle_url,
        'causality_resource_type': 'bicycle',
        'causality_info': {'resource_type': 'bicycle'},
        'assignor': 'http://testserver' + user_url,
        'assignee': None,
        'context': {},
        'state': 'unassigned',
        'created': task.created.isoformat()[:-13] + 'Z',
        'modified': task.modified.isoformat()[:-13] + 'Z',
        'concurrency_version': task.concurrency_version,
        'bicycle_uuid': str(bicycle.uuid),
        'maintenance_rule': None,
    })

    response = drf_fleet_operator.patch(detail_url,
                                        data={'context':
                                              {'description': 'bla'}},
                                        format='json')
    assert response.status_code == status.HTTP_200_OK
    task.refresh_from_db()
    assert task.context == {'description': 'bla'}

    action_url = reverse_query('lock8:task-actions',
                               kwargs={'uuid': task.uuid})
    response = drf_fleet_operator.post(action_url, data={
        'type': 'assign',
        'assignee': mechanic_url,
    })
    assert response.status_code == status.HTTP_200_OK
    task.refresh_from_db()
    assert task.assignee == mechanic1
    assert task.state == 'assigned'

    task.complete()
    response = drf_fleet_operator.get(detail_url)
    assert response.data['completed_at'] == (
        task.completed_at.isoformat()[:-13] + 'Z'
    )

    response = drf_fleet_operator.delete(detail_url)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_task_causality_info(drf_fleet_operator, task1):
    detail_url = reverse_query('lock8:task-detail', kwargs={'uuid':
                                                            task1.uuid})
    response = drf_fleet_operator.assert_success(detail_url)
    assert response.data['causality_info'] == {
        'alert_type': task1.causality.alert_type,
        'resource_type': 'alert',
    }


def test_task_empty_view_permissions(drf_mechanic1):
    url = reverse_query('lock8:task-list')
    drf_mechanic1.assert_count(url, 0)


def test_task_filtering_organization(drf_fleet_operator, task1, org,
                                     another_org):
    url = reverse_query('lock8:task-list', {'organization': org.uuid})
    drf_fleet_operator.assert_count(url, 1)
    url = reverse_query('lock8:task-list', {'organization': another_org.uuid})
    drf_fleet_operator.assert_count(url, 0)


def test_task_filtering_assignor(drf_fleet_operator, task1, fleet_operator,
                                 mechanic1):
    url = reverse_query('lock8:task-list', {'assignor': fleet_operator.uuid})
    drf_fleet_operator.assert_count(url, 1)
    url = reverse_query('lock8:task-list', {'assignor': mechanic1.uuid})
    drf_fleet_operator.assert_count(url, 0)


def test_task_filtering_assignee(drf_fleet_operator, task1, fleet_operator,
                                 mechanic1):
    task1.assign(assignee=mechanic1)
    url = reverse_query('lock8:task-list', {'assignee': fleet_operator.uuid})
    drf_fleet_operator.assert_count(url, 0)
    url = reverse_query('lock8:task-list', {'assignee': mechanic1.uuid})
    drf_fleet_operator.assert_count(url, 1)


def test_task_filtering_role(drf_fleet_operator, task1):
    url = reverse_query('lock8:task-list', {'role': 'admin'})
    drf_fleet_operator.assert_count(url, 0)
    url = reverse_query('lock8:task-list', {'role': 'mechanic'})
    drf_fleet_operator.assert_count(url, 1)


def test_task_filtering_severity(drf_fleet_operator, task1):
    url = reverse_query('lock8:task-list', {'severity': 'low'})
    drf_fleet_operator.assert_count(url, 0)
    url = reverse_query('lock8:task-list', {'severity': 'high'})
    drf_fleet_operator.assert_count(url, 1)


def test_task_filtering_state(drf_fleet_operator, task1, mechanic1):
    url = reverse_query('lock8:task-list', {'state': 'assigned'})
    drf_fleet_operator.assert_count(url, 0)

    task1.assign(assignee=mechanic1)

    url = reverse_query('lock8:task-list', {'state': 'assigned'})
    drf_fleet_operator.assert_count(url, 1)


def test_task_filtering_causality(drf_fleet_operator, task1, bicycle, lock,
                                  alert, feedback, another_bicycle):
    url = reverse_query('lock8:task-list', {'causality': lock.uuid})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:task-list', {'causality': bicycle.uuid})
    drf_fleet_operator.assert_count(url, 1)

    task1.causality = bicycle
    task1.save()

    drf_fleet_operator.assert_count(url, 1)

    task1.causality = feedback
    task1.save()

    response = drf_fleet_operator.assert_count(url, 1)
    assert response.data['results'][0]['causality_info'] == {
        'severity': 'high', 'resource_type': 'feedback'}

    feedback.causality = lock
    feedback.save()
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:task-list', {'causality': another_bicycle.uuid})
    drf_fleet_operator.assert_count(url, 0)


def test_task_filtering_bicycle_model(drf_fleet_operator, bmmr_fixed,
                                      bicycle_model, task1,
                                      another_bicycle_model, org):
    another_bicycle_model.organization = org
    another_bicycle_model.save()
    another_bicycle_model.refresh_from_db()

    url = reverse_query('lock8:task-list')
    drf_fleet_operator.assert_count(url, 3)

    url = reverse_query(
        'lock8:task-list',
        {'bicycle_model': bicycle_model.uuid}
    )
    drf_fleet_operator.assert_count(url, 2)

    bmmr_fixed.bicycle_model = another_bicycle_model
    bmmr_fixed.save()

    url = reverse_query(
        'lock8:task-list',
        {'bicycle_model': bicycle_model.uuid}
    )
    drf_fleet_operator.assert_count(url, 0)


def test_task_filtering_bicycle(drf_fleet_operator, bmmr_fixed,
                                bmmr_recurring, non_matching_uuid,
                                bicycle, bicycle_without_lock,
                                another_bicycle):
    url = reverse_query('lock8:task-list')
    drf_fleet_operator.assert_count(url, 4)

    url = reverse_query('lock8:task-list',
                        {'bicycle': str(bicycle.uuid)})
    drf_fleet_operator.assert_count(url, 2)

    url = reverse_query('lock8:task-list', (
        ('bicycle', bicycle.uuid),
        ('bicycle', bicycle_without_lock.uuid),
    ))
    drf_fleet_operator.assert_count(url, 4)

    url = reverse_query('lock8:task-list', (
        ('bicycle', str(bicycle.uuid)),
        ('bicycle', str(another_bicycle.uuid)),
        ('bicycle', non_matching_uuid)))
    drf_fleet_operator.assert_count(url, 2)

    url = reverse_query('lock8:task-list', (
        ('bicycle', non_matching_uuid),))
    drf_fleet_operator.assert_count(url, 0)


def test_task_filtering_bmmr(drf_fleet_operator, bmmr_fixed,
                             bmmr_recurring, non_matching_uuid):
    url = reverse_query('lock8:task-list')
    drf_fleet_operator.assert_count(url, 4)

    url = reverse_query('lock8:task-list',
                        {'maintenance_rule': str(bmmr_recurring.uuid)})
    drf_fleet_operator.assert_count(url, 2)

    url = reverse_query('lock8:task-list',
                        {'maintenance_rule': non_matching_uuid})
    drf_fleet_operator.assert_count(url, 0)


def test_task_filtering_bbox(drf_fleet_operator, bicycle, active_lock, org,
                             owner, create_gps_tracking):
    from velodrome.lock8.models import Task

    Task.objects.create(organization=org,
                        owner=owner,
                        causality=bicycle)

    timestamp = timezone.now() + dt.timedelta(seconds=2)
    create_gps_tracking(active_lock, 13.403145, 52.527433,
                        attributes={'time_stamp': timestamp.timestamp()})
    bbox_points1 = {'bbox': '13.3683645,52.5062991,13.4240352,52.5390943'}
    url = reverse_query('lock8:task-list', bbox_points1)
    drf_fleet_operator.assert_count(url, 1)

    bbox_points2 = {'bbox': '-0.0903313,51.5106892,-0.09256,51.50701'}
    url = reverse_query('lock8:task-list', bbox_points2)
    drf_fleet_operator.assert_count(url, 0)


def test_task_filtering_is_due(drf_fleet_operator, bmmr_fixed,
                               bmmr_recurring, bmmr_distance,
                               mocker, bicycle):
    from velodrome.celery import notify_idle_bmmr_tasks

    target = 'velodrome.lock8.models.get_distance_for_bicycles_since'
    mocker.patch(target, return_value={})

    url = reverse_query('lock8:task-list', {'is_due': False})
    drf_fleet_operator.assert_count(url, 6)

    late_one_day = bmmr_recurring.recurring_time + dt.timedelta(days=1)
    with freeze_time(timezone.now() + late_one_day):
        notify_idle_bmmr_tasks()
        url = reverse_query('lock8:task-list', {'is_due': True})
        drf_fleet_operator.assert_count(url, 2)


def test_task_no_bicycle_uuid_field(drf_fleet_operator, task1):
    url = reverse_query('lock8:task-detail', kwargs={'uuid': task1.uuid})
    response = drf_fleet_operator.get(url)
    assert response.data['bicycle_uuid'] is None


def test_task_db_queries(drf_fleet_operator, task1, org, bmmr_recurring,
                         commit_success):
    task1.bicycle_model_maintenance_rule = bmmr_recurring
    task1.save()

    task1.pk = None
    task1.uuid = uuid.uuid4()
    task1.save()
    task1.complete()
    commit_success()

    # Clear ContentType cache, to make this test predictable (when run alone)
    ContentType.objects.clear_cache()

    url = reverse_query('lock8:task-list')
    with CaptureQueriesContext(connection) as capture:
        response = drf_fleet_operator.assert_success(url)
    assert len(capture.captured_queries) == 18, '\n\n'.join(
        q['sql'] for q in capture.captured_queries)
    assert response.data['count'] == 4


def test_task_assign_wo_assignee_400(drf_fleet_operator, task1):
    action_url = reverse_query('lock8:task-actions',
                               kwargs={'uuid': task1.uuid})
    response = drf_fleet_operator.post(action_url, data={
        'type': 'assign',
    })
    assert response.status_code == status.HTTP_400_BAD_REQUEST
