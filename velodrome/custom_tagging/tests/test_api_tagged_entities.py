import pytest
from rest_framework import status

from velodrome.lock8.utils import reverse_query


@pytest.mark.django_db(databases=["default", "trackings"])
def test_filter_bicycles_by_tag(drf_fleet_operator,
                                bicycle, bicycle2, another_bicycle,
                                fixme_tag, fixme_tag_applied_to_bicycle):
    response = drf_fleet_operator.get(
        reverse_query(
            'lock8:bicycle-list',
            query_kwargs=dict(tag=fixme_tag.name)
        )
    )
    assert response.status_code == status.HTTP_200_OK, response.data
    assert len(response.data['results']) == 1

    response = drf_fleet_operator.get(
        reverse_query(
            'lock8:bicycle-list',
            query_kwargs=dict(tag=str(fixme_tag.uuid))
        )
    )
    assert response.status_code == status.HTTP_200_OK, response.data
    assert len(response.data['results']) == 1


@pytest.mark.django_db(databases=["default", "trackings"])
def test_bicycle_annotated_with_tags(drf_fleet_operator,
                                     bicycle, bicycle2, another_bicycle,
                                     fixme_tag, fixme_tag_applied_to_bicycle):
    response = drf_fleet_operator.get(
        reverse_query(
            'lock8:bicycle-list',
            query_kwargs=dict(tag=fixme_tag.name)
        )
    )
    assert response.status_code == status.HTTP_200_OK, response.data
    assert 'tags' in response.data['results'][0]
    assert len(response.data['results'][0]['tags']) == 1

    tag_info = response.data['results'][0]['tags'][0]
    assert tag_info['uuid'] == str(fixme_tag_applied_to_bicycle.uuid)
    assert tag_info['tag_declaration_name'] == fixme_tag.name
    assert tag_info['tag_declaration_uuid'] == str(fixme_tag.uuid)
