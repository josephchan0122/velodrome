import datetime as dt
import uuid

from rest_framework import status

from velodrome.lock8.utils import reverse_query


def test_crud_on_bmmr(bicycle_model, drf_fleet_operator, org,
                      bmmr_fixed, another_bicycle_model,
                      bmmr_recurring):
    from velodrome.lock8.models import (
        Affiliation, BicycleModelMaintenanceRule as BMMR,
        FeedbackCategory, Task
    )

    bmmr_url = reverse_query(
        'lock8:maintenance_rule-list',
        kwargs={'parent_lookup_uuid': bicycle_model.uuid}
    )

    bmmr_fixed.bicycle_model = another_bicycle_model
    bmmr_fixed.save()

    drf_fleet_operator.assert_count(bmmr_url, 1)

    response = drf_fleet_operator.post(bmmr_url, data={
        'description': 'foo',
        'note': 'bar',
        'distance': 42,
        'severity': FeedbackCategory.SEVERITY_LOW,
    }, format='json')
    assert response.status_code == status.HTTP_201_CREATED

    bmmr = BMMR.objects.get(distance=42)
    bmmr_detail_url = reverse_query(
        'lock8:maintenance_rule-detail',
        kwargs={
            'uuid': bmmr.uuid,
            'parent_lookup_uuid': bicycle_model.uuid
        }
    )
    bmmr_data = {
        'recurring_time': None,
        'distance': 42,
        'url': 'http://testserver{}'.format(bmmr_detail_url),
        'description': 'foo',
        'created': bmmr.created.isoformat()[:-13] + 'Z',
        'modified': bmmr.modified.isoformat()[:-13] + 'Z',
        'fixed_date': None,
        'start_date': bmmr.start_date.isoformat()[:-13] + 'Z',
        'note': 'bar',
        'role': Affiliation.MECHANIC,
        'concurrency_version': bmmr.concurrency_version,
        'severity': FeedbackCategory.SEVERITY_LOW,
        'uuid': str(bmmr.uuid)
    }
    assert response.data == bmmr_data

    response = drf_fleet_operator.assert_success(bmmr_detail_url)
    assert response.data == bmmr_data

    response = drf_fleet_operator.patch(bmmr_detail_url, data={'note': 'baz'})
    assert response.status_code == status.HTTP_200_OK
    assert response.data['note'] == 'baz'

    response = drf_fleet_operator.put(
        bmmr_detail_url,
        data={'description': 'bork'},
        format='json'
    )
    assert response.status_code == status.HTTP_200_OK
    assert response.data['description'] == 'bork'

    bmmr_action_url = reverse_query(
        'lock8:maintenance_rule-actions',
        kwargs={
            'uuid': bmmr.uuid,
            'parent_lookup_uuid': bicycle_model.uuid
        }
    )
    response = drf_fleet_operator.post(bmmr_action_url,
                                       data={'type': 'deactivate'},
                                       format='json')
    assert response.status_code == status.HTTP_200_OK

    bmmr.refresh_from_db()
    assert bmmr.state == 'deactivated'

    bmmr.distance = None
    bmmr.recurring_time = dt.timedelta(hours=24)
    bmmr.save()
    response = drf_fleet_operator.get(bmmr_detail_url)
    assert response.data['recurring_time'] == 86400

    Task.objects.all().delete()
    response = drf_fleet_operator.delete(bmmr_detail_url)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_filtering_bmmr_severity(drf_fleet_operator, bmmr_fixed,
                                 bmmr_recurring, bmmr_distance,
                                 bicycle_model):
    from velodrome.lock8.models import FeedbackCategory

    url = reverse_query(
        'lock8:maintenance_rule-list',
        query_kwargs={'severity': FeedbackCategory.SEVERITY_MEDIUM},
        kwargs={'parent_lookup_uuid': bicycle_model.uuid}
    )
    drf_fleet_operator.assert_count(url, 2)

    url = reverse_query(
        'lock8:maintenance_rule-list',
        query_kwargs={'severity': FeedbackCategory.SEVERITY_LOW},
        kwargs={'parent_lookup_uuid': bicycle_model.uuid}
    )
    drf_fleet_operator.assert_count(url, 1)


def test_filtering_bmmr_role(drf_fleet_operator, bmmr_fixed,
                             bmmr_recurring, bmmr_distance,
                             bicycle_model):
    from velodrome.lock8.models import Affiliation

    url = reverse_query(
        'lock8:maintenance_rule-list',
        query_kwargs={'role': Affiliation.MECHANIC},
        kwargs={'parent_lookup_uuid': bicycle_model.uuid}
    )
    drf_fleet_operator.assert_count(url, 3)

    url = reverse_query(
        'lock8:maintenance_rule-list',
        query_kwargs={'role': Affiliation.RENTER},
        kwargs={'parent_lookup_uuid': bicycle_model.uuid}
    )
    drf_fleet_operator.assert_count(url, 0)


def test_filtering_bmmr_state(drf_fleet_operator, bmmr_fixed,
                              bmmr_recurring, bmmr_distance,
                              bicycle_model):

    url = reverse_query(
        'lock8:maintenance_rule-list',
        query_kwargs={'state': 'active'},
        kwargs={'parent_lookup_uuid': bicycle_model.uuid}
    )
    drf_fleet_operator.assert_count(url, 3)

    url = reverse_query(
        'lock8:maintenance_rule-list',
        query_kwargs={'state': 'deactivated'},
        kwargs={'parent_lookup_uuid': bicycle_model.uuid}
    )
    drf_fleet_operator.assert_count(url, 0)


def test_list_bmmr_with_several_models(drf_fleet_operator, bmmr_fixed,
                                       bmmr_recurring, bmmr_distance,
                                       bicycle_model):

    from velodrome.lock8.models import (
        BicycleModel, BicycleModelMaintenanceRule)

    bicycle_model2 = BicycleModel.objects.get(pk=bicycle_model.pk)
    bicycle_model2.pk = None
    bicycle_model2.uuid = uuid.uuid4()
    bicycle_model2.save()

    bmmr_fixed2 = BicycleModelMaintenanceRule.objects.get(pk=bmmr_fixed.pk)
    bmmr_fixed2.pk = None
    bmmr_fixed2.uuid = uuid.uuid4()
    bmmr_fixed2.bicycle_model = bicycle_model2
    bmmr_fixed2.save()

    url = reverse_query(
        'lock8:maintenance_rule-list',
        kwargs={'parent_lookup_uuid': bicycle_model.uuid}
    )
    drf_fleet_operator.assert_count(url, 3)

    url = reverse_query(
        'lock8:maintenance_rule-list',
        kwargs={'parent_lookup_uuid': bicycle_model2.uuid}
    )
    drf_fleet_operator.assert_count(url, 1)


def test_patch_bmmr_time_values(drf_fleet_operator, bicycle_model,
                                bmmr_recurring, today):
    bmmr_url = reverse_query(
        'lock8:maintenance_rule-detail',
        kwargs={
            'uuid': bmmr_recurring.uuid,
            'parent_lookup_uuid': bicycle_model.uuid
        }
    )

    response = drf_fleet_operator.patch(bmmr_url, data={
        'fixed_date': today + dt.timedelta(days=3),
        'recurring_time': None
    }, format='json')
    assert response.status_code == status.HTTP_200_OK

    response = drf_fleet_operator.patch(bmmr_url, data={
        'recurring_time': dt.timedelta(days=4).total_seconds(),
        'fixed_date': None
    }, format='json')
    assert response.status_code == status.HTTP_200_OK

    response = drf_fleet_operator.patch(bmmr_url, data={
        'distance': 666,
        'recurring_time': None
    }, format='json')
    assert response.status_code == status.HTTP_200_OK


def test_bmmr_deactivate_cancels_tasks(drf_fleet_operator, bicycle_model,
                                       bmmr_fixed):
    from velodrome.lock8.models import TaskStates

    bmmr_action_url = reverse_query(
        'lock8:maintenance_rule-actions',
        kwargs={'uuid': bmmr_fixed.uuid,
                'parent_lookup_uuid': bicycle_model.uuid}
    )
    assert bmmr_fixed.tasks.count() == 2
    assert all([t.state == TaskStates.UNASSIGNED.value
                for t in bmmr_fixed.tasks.all()])

    response = drf_fleet_operator.post(bmmr_action_url,
                                       data={'type': 'deactivate',
                                             'cancel_tasks': True},
                                       format='json')
    assert response.status_code == status.HTTP_200_OK

    assert all([t.state == TaskStates.CANCELLED.value
                for t in bmmr_fixed.tasks.all()])
