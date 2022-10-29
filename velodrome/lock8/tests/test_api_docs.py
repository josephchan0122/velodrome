import pytest
from rest_framework import status

from velodrome.lock8.utils import reverse_query

pytestmark = pytest.mark.slow


def test_docs_media_types_and_index(db, client):
    url = reverse_query('api-docs')
    # Returns HTML (Swagger) for browsers, not requiring a version.
    response = client.get(url, HTTP_ACCEPT='text/html')
    assert response.status_code == status.HTTP_200_OK
    assert response.accepted_media_type == 'text/html'

    response = client.get(url, HTTP_ACCEPT='*/*; version=1.0')
    assert response.status_code == status.HTTP_200_OK
    assert response.accepted_media_type == 'text/html;version=1.0'  # noqa
    doc = response.data
    assert doc['info']['title'] == 'Velodrome API'
    assert doc['host'] == 'testserver'


def test_schema(client, db):
    url = reverse_query('schema-json', kwargs={'format': '.json'})
    response = client.get(url)
    assert response.status_code == 200
    paths = response.json()['paths']

    # End-to-end test for params in custom api_view.
    clusters_params = paths['/api/clusters/']['get']['parameters']
    assert clusters_params == [
        {'name': 'bbox', 'in': 'query',
         'description': 'South-West then North-East corners of the box (csv).',
         'required': True, 'type': 'string',
         'pattern': '^-?[0-9\\.]+,-?[0-9\\.]+,-?[0-9\\.]+,-?[0-9\\.]+$',
         'minLength': 1},
        {'name': 'include_state', 'in': 'query',
         'description': 'Include state field in response?',
         'required': False, 'type': 'boolean', 'default': False},
        {'name': 'include_model', 'in': 'query',
         'description': 'Include model field in response?'
         ' exclusive from include_state.',
         'required': False, 'type': 'boolean', 'default': False},
        {'name': 'organizations', 'in': 'query',
         'description': 'List of organizations filter for bicycles',
         'required': False, 'type': 'string', 'default': ''},
    ]

    axalock_otp_params = paths[
        '/api/axa_locks/{uuid}/otp/'
    ]['get']['parameters']
    assert [x['name'] for x in axalock_otp_params] == [
        'number', 'hours', 'slot']
