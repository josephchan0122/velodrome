import uuid

import pytest
import requests_mock
from rest_framework import status

from velodrome.lock8.utils import reverse_query


def test_client_app_crud(org, drf_fleet_operator, settings):
    from velodrome.lock8.models import Affiliation, ClientApp

    url = reverse_query('lock8:client_app-list')
    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})

    remote_uuid = uuid.uuid4()
    name = 'My awesome third party app'
    label = 'label'
    scopes = ['bicycle:read', 'trip:read']
    with requests_mock.Mocker() as m:
        m.post(settings.STS_BASE_URL + '/client_apps/',
               status_code=201,
               json={'uuid': str(remote_uuid),
                     'name': name,
                     'label': label,
                     'organization_uuid': str(org.uuid),
                     'scopes': scopes,
                     'private_key': '-----BEGIN PRIVATE KEY-----'})
        response = drf_fleet_operator.post(url, data={
            'organization': organization_url,
            'label': label,
            'name': name,
            'scopes': scopes})

    assert response.status_code == status.HTTP_201_CREATED

    client_app = ClientApp.objects.get()
    assert client_app.name == name
    assert client_app.scopes == scopes
    assert client_app.organization == org
    assert client_app.remote_uuid == remote_uuid
    assert not client_app.user.is_active
    assert client_app.user.organizations.filter(
        affiliation__role=Affiliation.ADMIN).get() == org

    detail_url = reverse_query('lock8:client_app-detail',
                               kwargs={'uuid': client_app.uuid})
    assert response.data == {
        'uuid': str(client_app.uuid),
        'name': name,
        'label': label,
        'scopes': scopes,
        'organization': 'http://testserver' + organization_url,
        'private_key': '-----BEGIN PRIVATE KEY-----',
        'url': 'http://testserver' + detail_url,
        'created': client_app.created.isoformat()[:-13] + 'Z',
        'modified': client_app.modified.isoformat()[:-13] + 'Z',
        'concurrency_version': client_app.concurrency_version,
    }

    response = drf_fleet_operator.assert_success(detail_url)
    assert response.data == {
        'uuid': str(client_app.uuid),
        'name': name,
        'label': label,
        'scopes': scopes,
        'organization': 'http://testserver' + organization_url,
        'url': 'http://testserver' + detail_url,
        'created': client_app.created.isoformat()[:-13] + 'Z',
        'modified': client_app.modified.isoformat()[:-13] + 'Z',
        'concurrency_version': client_app.concurrency_version,
    }

    def callback(request, context):
        assert request.headers['Authorization'] == f'Token {settings.STS_AUTH_TOKEN}'  # noqa

    with requests_mock.Mocker() as m:
        m.register_uri(
            'PATCH',
            client_app.remote_url,
            text=callback,
            status_code=200,
        )
        response = drf_fleet_operator.patch(
            detail_url,
            data={'scopes': []}, format='json')
    assert response.status_code == status.HTTP_200_OK, response.data
    client_app.refresh_from_db()
    assert client_app.scopes == []

    with requests_mock.Mocker() as m:
        m.patch(client_app.remote_url)
        response = drf_fleet_operator.patch(
            detail_url,
            data={'scopes': ['trip:read']})
    assert response.status_code == status.HTTP_200_OK, response.data
    client_app.refresh_from_db()
    assert client_app.scopes == ['trip:read']

    with requests_mock.Mocker() as m:
        m.delete(client_app.remote_url, status_code=204)
        response = drf_fleet_operator.delete(detail_url)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    with pytest.raises(ClientApp.DoesNotExist):
        ClientApp.objects.get()


def test_update_client_update_org(client_app, drf_fleet_operator,
                                  another_org, org):
    detail_url = reverse_query('lock8:client_app-detail',
                               kwargs={'uuid': client_app.uuid})
    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': another_org.uuid})

    response = drf_fleet_operator.patch(
        detail_url,
        data={'organization': organization_url},
        format='json')
    assert response.status_code == 200
    client_app.refresh_from_db()

    assert client_app.organization == org


def test_update_client_update_name(client_app, drf_fleet_operator):
    detail_url = reverse_query('lock8:client_app-detail',
                               kwargs={'uuid': client_app.uuid})

    response = drf_fleet_operator.patch(
        detail_url,
        data={'name': 'Change the name'},
        format='json')
    assert response.status_code == 200
    client_app.refresh_from_db()

    assert client_app.name == 'client_app'


def test_client_app_station_failed_creation(org, drf_fleet_operator, settings):
    url = reverse_query('lock8:client_app-list')
    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})

    name = 'My awesome third party app'
    scopes = ['bicycle:read', 'trip:read']
    with requests_mock.Mocker() as m:
        m.post(settings.STS_BASE_URL + '/client_apps/',
               status_code=401,
               json={'error': 'unauthorized'})
        response = drf_fleet_operator.post(url, data={
            'organization': organization_url,
            'name': name,
            'label': 'label',
            'scopes': scopes})

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert response.data == {'detail': {
        'non_field_errors': [{'code': 'unauthorized',
                              'message': 'Internal Server Error.'}]}}


def test_client_app_station_failed_update(org, drf_fleet_operator, client_app):
    url = reverse_query('lock8:client_app-detail',
                        kwargs={'uuid': client_app.uuid})

    scopes = ['bicycle:read', 'trip:read']
    with requests_mock.Mocker() as m:
        m.patch(client_app.remote_url,
                status_code=401,
                json={'error': 'unauthorized'})
        response = drf_fleet_operator.patch(url, data={'scopes': scopes})

    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR
    assert response.data == {'detail': {
        'non_field_errors': [{'code': 'unauthorized',
                              'message': 'Internal Server Error.'}]}}


def test_client_app_crud_wo_scopes_label(org, drf_fleet_operator, settings):
    url = reverse_query('lock8:client_app-list')
    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})

    remote_uuid = uuid.uuid4()
    name = 'My awesome third party app'
    with requests_mock.Mocker() as m:
        m.post(settings.STS_BASE_URL + '/client_apps/',
               status_code=201,
               json={'uuid': str(remote_uuid),
                     'name': name,
                     'label': None,
                     'organization_uuid': str(org.uuid),
                     'scopes': [],
                     'private_key': '-----BEGIN PRIVATE KEY-----'})
        response = drf_fleet_operator.post(url, data={
            'organization': organization_url,
            'name': name,
            })

    assert response.status_code == status.HTTP_201_CREATED
