import pytest
from rest_framework import status

from velodrome.lock8.utils import reverse_query


@pytest.mark.django_db(databases=["default", "trackings"])
def test_crud_tag_group(org, drf_admin, drf_fleet_operator,
                        drf_another_fleet_operator, maintenance_tag_group):

    from velodrome.custom_tagging.models import TagGroup

    # Tag groups can be viewed not only by lock8 admins
    list_url = reverse_query('custom-tagging:tag_group-list')
    drf_fleet_operator.assert_count(list_url, 1)
    drf_another_fleet_operator.assert_count(list_url, 1)  # org independent!

    # But they are editable only by admins as long as it's not org level thing
    group_data = {
        'name': 'Color',
        'description': 'Color of the bike',
    }
    response = drf_fleet_operator.post(list_url, data=group_data)
    assert response.status_code == status.HTTP_403_FORBIDDEN, response.data

    response = drf_admin.post(list_url, data=group_data)
    assert response.status_code == status.HTTP_201_CREATED, response.data
    assert TagGroup.objects.count() == 2

    # There can be only one: name of TagGroup must be unique
    response = drf_admin.post(list_url, data=group_data)
    assert response.status_code == status.HTTP_400_BAD_REQUEST, response.data
    assert TagGroup.objects.count() == 2

    # Groups can be updated only by lock8 admins
    color_tag_group = TagGroup.objects.latest()
    detail_url = reverse_query(
        'custom-tagging:tag_group-detail',
        kwargs={'uuid': color_tag_group.uuid}
    )
    group_data = {
        'name': 'Color',
        'description': 'Color of the saddle',
    }
    response = drf_fleet_operator.patch(detail_url, data=group_data)
    assert response.status_code == status.HTTP_403_FORBIDDEN, response.data

    response = drf_admin.patch(detail_url, data=group_data)
    assert response.status_code == status.HTTP_200_OK, response.data
    color_tag_group.refresh_from_db()
    assert color_tag_group.description == 'Color of the saddle'

    # Groups can be deleted only by lock8 admins
    response = drf_fleet_operator.delete(detail_url)
    assert response.status_code == status.HTTP_403_FORBIDDEN, response.data

    response = drf_admin.delete(detail_url)
    assert response.status_code == status.HTTP_204_NO_CONTENT, response.data
    assert TagGroup.objects.count() == 1


@pytest.mark.django_db(databases=["default", "trackings"])
def test_crud_tag_declaration(org, drf_mechanic1, drf_fleet_operator,
                              drf_another_fleet_operator,
                              maintenance_tag_group, fixme_tag):

    from velodrome.custom_tagging.models import TagDeclaration

    # Tag declarations can be viewed by fleet operators
    list_url = reverse_query('custom-tagging:tag_declaration-list')
    drf_fleet_operator.assert_count(list_url, 1)
    drf_another_fleet_operator.assert_count(list_url, 0)

    # And can be edited at least by fleet operators too
    group_url = reverse_query(
        'custom-tagging:tag_group-detail',
        kwargs={'uuid': maintenance_tag_group.uuid}
    )
    org_url = reverse_query(
        'lock8:organization-detail',
        kwargs={'uuid': org.uuid}
    )
    declaration_data = {
        'name': 'Would not fix',
        'group': group_url,
        'organization': org_url,
    }
    response = drf_mechanic1.post(list_url, data=declaration_data)
    assert response.status_code == status.HTTP_403_FORBIDDEN, response.data

    declaration_data['name'] = 'Will be fixed'
    response = drf_fleet_operator.post(list_url, data=declaration_data)
    assert response.status_code == status.HTTP_201_CREATED, response.data
    assert TagDeclaration.objects.count() == 2

    # There can be only one: name of TagDeclaration must be unique
    response = drf_fleet_operator.post(list_url, data=declaration_data)
    assert response.status_code == status.HTTP_400_BAD_REQUEST, response.data
    assert TagDeclaration.objects.count() == 2

    # Tag declarations can be updated at least by fleet operators
    will_fix_tag = TagDeclaration.objects.latest()
    detail_url = reverse_query(
        'custom-tagging:tag_declaration-detail',
        kwargs={'uuid': will_fix_tag.uuid}
    )
    updated_data = {
        'description': 'Very important info',
    }
    response = drf_mechanic1.patch(detail_url, data=updated_data)
    assert response.status_code == status.HTTP_403_FORBIDDEN, response.data

    response = drf_fleet_operator.patch(detail_url, data=updated_data)
    assert response.status_code == status.HTTP_200_OK, response.data
    will_fix_tag.refresh_from_db()
    assert will_fix_tag.description == 'Very important info'

    # TagDeclaration can be deleted at least by fleet operators
    response = drf_mechanic1.delete(detail_url)
    assert response.status_code == status.HTTP_403_FORBIDDEN, response.data

    response = drf_fleet_operator.delete(detail_url)
    assert response.status_code == status.HTTP_204_NO_CONTENT, response.data
    assert TagDeclaration.objects.count() == 1


@pytest.mark.django_db(databases=["default", "trackings"])
def test_crud_tag_bicycle(drf_another_fleet_operator, drf_mechanic1,
                          bicycle, org, another_org, fixme_tag):

    from velodrome.custom_tagging.models import TagInstance

    list_url = reverse_query('custom-tagging:tag_instance-list')

    fixme_tag_url = reverse_query(
        'custom-tagging:tag_declaration-detail',
        kwargs={'uuid': fixme_tag.uuid}
    )
    bicycle_url = reverse_query(
        'lock8:bicycle-detail',
        kwargs={'uuid': bicycle.uuid}
    )

    fixme_tag_data = {
        'declaration': fixme_tag_url,
        'target': bicycle_url,
    }
    assert TagInstance.objects.count() == 0
    assert bicycle.tags.count() == 0

    # Objects can be tagged by technical staff
    response = drf_mechanic1.post(list_url, data=fixme_tag_data)
    assert response.status_code == status.HTTP_201_CREATED, response.data
    assert TagInstance.objects.count() == 1
    assert bicycle.tags.count() == 1

    # Tag declarations of specific org can be viewed by technical staff
    drf_mechanic1.assert_count(list_url, 1)
    drf_another_fleet_operator.assert_count(list_url, 0)

    fixme_tag_instance = TagInstance.objects.latest()
    detail_url = reverse_query(
        'custom-tagging:tag_instance-detail',
        kwargs={'uuid': fixme_tag_instance.uuid}
    )

    # Tag can be removed from an object by technical staff
    response = drf_mechanic1.delete(detail_url)
    assert response.status_code == status.HTTP_204_NO_CONTENT, response.data
    assert TagInstance.objects.count() == 0


@pytest.mark.django_db(databases=["default", "trackings"])
def test_extended_group_info(org, drf_admin, drf_fleet_operator,
                             drf_another_fleet_operator,
                             maintenance_tag_group, fixme_tag, another_tag):
    url = reverse_query(
        'custom-tagging:tag_group-detail',
        kwargs={'uuid': maintenance_tag_group.uuid}
    )

    # Each user should see only his own org's declarations in tag groups
    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_200_OK, response.data
    assert 'declarations' in response.data
    assert len(response.data['declarations']) == 1

    tag_declaration_info = response.data['declarations'][0]
    assert tag_declaration_info['uuid'] == str(fixme_tag.uuid)
    assert tag_declaration_info['name'] == fixme_tag.name
    assert tag_declaration_info['description'] == str(fixme_tag.description)
    assert tag_declaration_info['color'] == '#2596BE'

    # Another org's operator will see another tag declaration only
    response = drf_another_fleet_operator.get(url)
    assert response.status_code == status.HTTP_200_OK, response.data
    assert 'declarations' in response.data
    assert len(response.data['declarations']) == 1

    tag_declaration_info = response.data['declarations'][0]
    assert tag_declaration_info['uuid'] == str(another_tag.uuid)
    assert tag_declaration_info['name'] == another_tag.name
    assert tag_declaration_info['description'] == str(another_tag.description)
    assert tag_declaration_info['color'] == '#E28743'

    # Admin can see all declarations
    response = drf_admin.get(url)
    assert 'declarations' in response.data
    assert len(response.data['declarations']) == 2
