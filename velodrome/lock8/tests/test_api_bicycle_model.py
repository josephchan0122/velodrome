import pytest
from rest_framework import status

from velodrome.lock8.utils import reverse_query


def test_crud_on_bicycle_model(drf_fleet_operator, owner, org,
                               city_bike, photo, image):
    from velodrome.lock8.models import BicycleModel

    url = reverse_query('lock8:bicycle_model-list')
    bicycle_type_url = reverse_query('lock8:bicycle_type-detail',
                                     kwargs={'uuid': city_bike.uuid})
    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})

    response = drf_fleet_operator.post(url, data={
        'name': 'Bicycle model',
        'description': 'Bla\nBla',
        'type': bicycle_type_url,
        'organization': organization_url,
    })
    assert response.status_code == status.HTTP_201_CREATED

    bicycle_model = BicycleModel.objects.get()
    bicycle_model_url = reverse_query('lock8:bicycle_model-detail',
                                      kwargs={'uuid': bicycle_model.uuid})
    assert response.data == {
        'uuid': str(bicycle_model.uuid),
        'name': 'Bicycle model',
        'url': 'http://testserver' + bicycle_model_url,
        'photo': None,
        'photo_url': None,
        'organization': 'http://testserver' + organization_url,
        'type': 'http://testserver' + bicycle_type_url,
        'bicycle_count': 0,
        'alert_types_to_task': {},
        'feedback_auto_escalate_severity': None,
        'state': 'new',
        'concurrency_version': bicycle_model.concurrency_version,
        'modified': bicycle_model.modified.isoformat()[:-13] + 'Z',
        'created': bicycle_model.created.isoformat()[:-13] + 'Z',
    }

    response = drf_fleet_operator.patch(bicycle_model_url,
                                        data={'name': 'BBB',
                                              'alert_types_to_task': {}},
                                        format='json')
    assert response.status_code == status.HTTP_200_OK

    bicycle_model.refresh_from_db()
    assert bicycle_model.name == 'BBB'

    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert response.data['count'] == 1

    response = drf_fleet_operator.delete(bicycle_model_url)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    with pytest.raises(BicycleModel.DoesNotExist):
        bicycle_model.refresh_from_db()

    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert response.data['count'] == 0


def test_delete_bicycle_model_related_with_bicycle(drf_fleet_operator,
                                                   bicycle, bicycle_model):
    bicycle.model = bicycle_model
    bicycle.save()

    bicycle_model_url = reverse_query('lock8:bicycle_model-detail',
                                      kwargs={'uuid': bicycle_model.uuid})

    response = drf_fleet_operator.delete(bicycle_model_url)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data['detail']['non_field_errors'] == [
        {'message': 'Some Bicycles are still bound to this Model',
         'code': 'invalid'}]


def test_filering_bicycle_model(drf_fleet_operator, owner, org,
                                another_org, bicycle_model):

    url = reverse_query('lock8:bicycle_model-list',
                        query_kwargs={'organization': org.uuid})
    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert response.data['count'] == 1

    url = reverse_query('lock8:bicycle_model-list',
                        query_kwargs={'organization': another_org.uuid})
    response = drf_fleet_operator.assert_success(url)
    assert response.data['count'] == 0
