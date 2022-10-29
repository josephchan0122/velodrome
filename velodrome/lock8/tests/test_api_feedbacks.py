from django.db import connection
from django.test.utils import CaptureQueriesContext
import pytest
from rest_framework import status

from velodrome.lock8.utils import reverse_query


def test_crud_feedback(drf_fleet_operator, org, feedback,
                       drf_another_fleet_operator, drf_bob, drf_alice,
                       drf_admin, alice, another_feedback,
                       front_wheel_category):
    from velodrome.lock8.models import (
        Affiliation, Feedback, FeedbackCategory, Task)
    fback_list_url = reverse_query('lock8:feedback-list')

    drf_admin.assert_count(fback_list_url, 2)

    for user in (drf_fleet_operator, drf_alice):
        response = user.assert_count(fback_list_url, 1)
        assert response.data['results'][0]['message'] == 'It blew up.'

    for user in (drf_another_fleet_operator, drf_bob):
        response = user.assert_count(fback_list_url, 1)
        assert response.data['results'][0]['message'] == 'It melted.'

    org_url = reverse_query('lock8:organization-detail',
                            kwargs={'uuid': org.uuid})
    bicycle_url = reverse_query(
        'lock8:bicycle-detail',
        kwargs={'uuid': feedback.causality.uuid}
    )
    category_url = reverse_query('lock8:feedback_category-detail',
                                 kwargs={'uuid': front_wheel_category.uuid})
    response = drf_alice.post(fback_list_url, data={
        'organization': org_url,
        'message': 'Flat tire',
        'causality': bicycle_url,
        'severity': FeedbackCategory.SEVERITY_LOW,
        'category': category_url,
    }, format='json')
    assert response.status_code == status.HTTP_201_CREATED, response.data

    user_url = reverse_query('lock8:user-detail', kwargs={'uuid': alice.uuid})
    fback_detail_url = reverse_query(
        'lock8:feedback-detail',
        kwargs={'uuid': feedback.uuid}
    )

    drf_fleet_operator.assert_success(fback_detail_url, {
        'organization': 'http://testserver{}'.format(org_url),
        'user': 'http://testserver{}'.format(user_url),
        'image': feedback.image.url,
        'message': feedback.message,
        'causality': 'http://testserver{}'.format(bicycle_url),
        'bicycle': 'http://testserver{}'.format(bicycle_url),
        'causality_resource_type': 'bicycle',
        'causality_info': {'resource_type': 'bicycle'},
        'category': 'http://testserver{}'.format(category_url),
        'uuid': str(feedback.uuid),
        'url': 'http://testserver{}'.format(fback_detail_url),
        'created': feedback.created.isoformat()[:-13] + 'Z',
        'modified': feedback.modified.isoformat()[:-13] + 'Z',
        'concurrency_version': feedback.concurrency_version,
        'state': feedback.state,
        'severity': FeedbackCategory.SEVERITY_HIGH,
    })

    action_url = reverse_query(
        'lock8:feedback-actions',
        kwargs={'uuid': feedback.uuid}
    )
    response = drf_fleet_operator.post(
        action_url,
        data={
            'type': 'escalate',
            'severity': FeedbackCategory.SEVERITY_LOW,
            'role': Affiliation.ADMIN
        }
    )
    assert response.status_code == status.HTTP_200_OK
    feedback.refresh_from_db()
    assert feedback.state == 'escalated'

    task = Task.objects.get(object_id=feedback.id)
    assert task.severity == FeedbackCategory.SEVERITY_LOW
    assert task.role == Affiliation.ADMIN

    response = drf_fleet_operator.patch(action_url)
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    response = drf_fleet_operator.delete(action_url)
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    action_url = reverse_query(
        'lock8:feedback-actions',
        kwargs={'uuid': another_feedback.uuid}
    )
    response = drf_another_fleet_operator.post(
        action_url, data={'type': 'discard'}
    )
    assert response.status_code == status.HTTP_200_OK
    another_feedback.refresh_from_db()
    assert another_feedback.state == 'discarded'

    response = drf_fleet_operator.delete(fback_detail_url)
    assert response.status_code == status.HTTP_204_NO_CONTENT
    with pytest.raises(Feedback.DoesNotExist):
        feedback.refresh_from_db()


def test_feedback_filtering(drf_fleet_operator, feedback, org,
                            non_matching_uuid):
    url = reverse_query('lock8:feedback-list', {'organization': org.uuid})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:feedback-list', {'state': 'escalated'})
    drf_fleet_operator.assert_count(url, 0)

    feedback.escalate()

    url = reverse_query('lock8:feedback-list', {'state': 'escalated'})
    drf_fleet_operator.assert_count(url, 1)


def test_feedback_filtering_by_bicycle(drf_fleet_operator, non_matching_uuid,
                                       feedback, feedback2):
    url = reverse_query('lock8:feedback-list',
                        {'bicycle': str(feedback.causality.uuid)})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:feedback-list',
                        (('bicycle', feedback.causality.uuid),
                         ('bicycle', feedback2.causality.uuid)))
    drf_fleet_operator.assert_count(url, 2)

    url = reverse_query('lock8:feedback-list',
                        {'bicycle': non_matching_uuid})
    drf_fleet_operator.assert_count(url, 0)


def test_feedback_filtering_category(drf_fleet_operator, feedback, org,
                                     bicycle_category, front_wheel_category):
    url = reverse_query('lock8:feedback-list', query_kwargs={'category': 'X'})
    drf_fleet_operator.assert_400(url,
                                  {'category': [
                                      {'message': 'Enter a valid UUID.',
                                       'code': 'invalid'}]})
    url = reverse_query('lock8:feedback-list',
                        query_kwargs={'category': front_wheel_category.uuid})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:feedback-list',
                        query_kwargs={'category': bicycle_category.uuid})
    drf_fleet_operator.assert_count(url, 1)


def test_feedback_number_of_queries(drf_fleet_operator, feedback,
                                    commit_success):
    drf_fleet_operator.use_jwt_auth()
    url = reverse_query('lock8:feedback-list')
    commit_success()
    with CaptureQueriesContext(connection) as capture:
        drf_fleet_operator.assert_count(url, 1)
    assert len(capture.captured_queries) == 8, '\n\n'.join(
        q['sql'] for q in capture.captured_queries)


def test_crud_feedback_category(drf_fleet_operator, drf_alice,
                                bicycle_category, front_wheel_category):
    url = reverse_query('lock8:feedback_category-list')

    drf_fleet_operator.assert_count(url, 13)
    drf_alice.assert_count(url, 10)

    detail_url = reverse_query('lock8:feedback_category-detail',
                               kwargs={'uuid': bicycle_category.uuid})
    drf_fleet_operator.assert_success(detail_url)
    drf_alice.assert_status(detail_url, status.HTTP_404_NOT_FOUND)

    detail_url = reverse_query('lock8:feedback_category-detail',
                               kwargs={'uuid': front_wheel_category.uuid})
    drf_fleet_operator.assert_success(detail_url)
    drf_alice.assert_success(detail_url)


def test_feedback_category_filtering_name(drf_fleet_operator,
                                          front_wheel_category):
    url = reverse_query('lock8:feedback_category-list',
                        query_kwargs={'name': 'nope'})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:feedback_category-list',
                        query_kwargs={'name': front_wheel_category.name})
    drf_fleet_operator.assert_count(url, 1)
