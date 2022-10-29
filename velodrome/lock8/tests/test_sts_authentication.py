import datetime as dt

from django.conf import settings
from django.urls.exceptions import NoReverseMatch
from django.utils import timezone
import jwt
import pytest
from rest_framework import status

from velodrome.lock8.router import router
from velodrome.lock8.utils import reverse_query


def test_sts_auth_handler_access(client_app, drf_client, bicycle):
    now = timezone.now()
    payload = {'user_id': client_app.name,
               'iss': 'sts-dev',
               'organization': str(client_app.organization.uuid),
               'scopes': ['bicycle:read'],
               'exp': now + dt.timedelta(minutes=30),
               'iat': now}
    sts_jwt = jwt.encode(payload, settings.JWT_SECRET_KEY,
                         algorithm='HS512').decode()
    drf_client.credentials(HTTP_AUTHORIZATION='JWT ' + sts_jwt)
    url = reverse_query('lock8:bicycle-list')
    drf_client.assert_count(url, 1)


def test_sts_auth_handler_denied(client_app, drf_client, bicycle):
    now = timezone.now()
    payload = {'user_id': client_app.name,
               'iss': 'sts-dev',
               'organization': str(client_app.organization.uuid),
               'scopes': ['bicycle:read'],
               'exp': now + dt.timedelta(minutes=30),
               'iat': now}
    sts_jwt = jwt.encode(payload, settings.JWT_SECRET_KEY,
                         algorithm='HS512').decode()
    drf_client.credentials(HTTP_AUTHORIZATION='JWT ' + sts_jwt)
    url = reverse_query('lock8:trip-list')
    response = drf_client.get(url)
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_sts_unexpected_iss(client_app, drf_client, bicycle, settings):
    now = timezone.now()
    payload = {'user_id': client_app.name,
               'iss': 'sts-unexpected',
               'organization': str(client_app.organization.uuid),
               'scopes': ['bicycle:read'],
               'exp': now + dt.timedelta(minutes=30),
               'iat': now}
    sts_jwt = jwt.encode(payload, settings.JWT_SECRET_KEY,
                         algorithm='HS512').decode()
    drf_client.credentials(HTTP_AUTHORIZATION='JWT ' + sts_jwt)
    url = reverse_query('lock8:bicycle-list')
    drf_client.assert_status(url, status.HTTP_401_UNAUTHORIZED, {'detail': {
        'non_field_errors': [{
            'code': 'authentication_failed',
            'message': 'Unexpected JWT iss for STS (expected %s)' % (
                settings.STS_JWT_ISSUER)}]}})


@pytest.mark.parametrize('scopes,perms,expected', [
    (['bicycle:read'], [], True),
    ([], ['lock8.view_bicycle'], False),
    (['bicycle:read'], ['lock8.view_bicycle'], True),
    (['bicycle:read'], ['lock8.view_bicycle_transitions'], True),
    (['trip:read'], ['lock8.view_trip'], True),
    (['organization:read'], ['lock8.view_organization'], True),
    (['bicycle:doesnotexist'], ['lock8.view_bicycle'], False),
    (['bicycle:write'], ['lock8.rent_bicycle'], True),
    (['bicycle:write'], ['lock8.return_bicycle'], True),
    (['bicycle:read'], ['lock8.view_bicycle_otp'], True),
    (['lock:write'], ['lock8.add_lock'], True),
    (['lock:write'], ['lock8.add_lock', 'lock8.change_lock'], False),
    (['zone:read'], ['lock8.view_zone'], True),
    (['zone:write'], ['lock8.add_zone', 'lock8.change_zone'], True),
    (['support-ticket:read'], ['lock8.view_supportticket'], True),
    (['support-ticket:write'], ['lock8.add_supportticket'], True),
    (['support-ticket:write'], ['lock8.change_supportticket'], True),
    (['support-ticket:write'], ['lock8.delete_supportticket'], True),
])
def test_check_scopes_are_allowed(scopes, perms, expected, mocker):
    from velodrome.lock8.permissions import check_scopes_are_allowed

    request = mocker.Mock()
    request.auth = {'scopes': scopes}
    assert check_scopes_are_allowed(request, perms) is expected


@pytest.mark.parametrize('scopes, expected', [
    (['bicycle:read'], False),
    (['bicycle:write'], True),
    (['bicycle:read', 'bicycle:write'], True),
])
def test_sts_auth_handler_actions(client_app, drf_client, bicycle, scopes,
                                  expected):
    bicycle.declare_available()

    now = timezone.now()
    payload = {'user_id': client_app.name,
               'iss': 'sts-dev',
               'organization': str(client_app.organization.uuid),
               'scopes': scopes,
               'exp': now + dt.timedelta(minutes=30),
               'iat': now}
    sts_jwt = jwt.encode(payload, settings.JWT_SECRET_KEY,
                         algorithm='HS512').decode()
    drf_client.credentials(HTTP_AUTHORIZATION='JWT ' + sts_jwt)

    url = reverse_query('lock8:bicycle-actions', kwargs={'uuid': bicycle.uuid})
    response = drf_client.post(url, data={'type': 'rent'})
    if expected:
        assert response.status_code == status.HTTP_200_OK, response.data
    else:
        assert response.status_code == status.HTTP_403_FORBIDDEN


def test_sts_auth_expired(client_app, drf_client, bicycle):
    now = timezone.now()
    payload = {'user_id': client_app.name,
               'iss': 'sts-dev',
               'organization': str(client_app.organization.uuid),
               'scopes': ['bicycle:read'],
               'exp': now - dt.timedelta(minutes=30),
               'iat': now}
    sts_jwt = jwt.encode(payload, settings.JWT_SECRET_KEY,
                         algorithm='HS512').decode()
    drf_client.credentials(HTTP_AUTHORIZATION='JWT ' + sts_jwt)
    url = reverse_query('lock8:trip-list')
    response = drf_client.get(url)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.data == {'detail': {
        'non_field_errors': [{'code': 'authentication_failed',
                              'message': 'Signature has expired.'}]}}


def test_sts_auth_decode_error(client_app, drf_client, bicycle):
    now = timezone.now()
    payload = {'user_id': client_app.name,
               'iss': 'sts-dev',
               'organization': str(client_app.organization.uuid),
               'scopes': ['bicycle:read'],
               'exp': now + dt.timedelta(minutes=30),
               'iat': now}
    sts_jwt = jwt.encode(payload, settings.JWT_SECRET_KEY + 'a',
                         algorithm='HS512').decode()
    drf_client.credentials(HTTP_AUTHORIZATION='JWT ' + sts_jwt)
    url = reverse_query('lock8:trip-list')
    response = drf_client.get(url)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.data == {'detail': {
        'non_field_errors': [{'code': 'authentication_failed',
                              'message': 'Error decoding signature.'}]}}


def test_sts_auth_no_client_app(client_app, drf_client, bicycle):
    now = timezone.now()
    payload = {'user_id': '',
               'iss': 'sts-dev',
               'organization': str(client_app.organization.uuid),
               'scopes': ['bicycle:read'],
               'exp': now + dt.timedelta(minutes=30),
               'iat': now}
    sts_jwt = jwt.encode(payload, settings.JWT_SECRET_KEY,
                         algorithm='HS512').decode()
    drf_client.credentials(HTTP_AUTHORIZATION='JWT ' + sts_jwt)
    url = reverse_query('lock8:trip-list')
    response = drf_client.get(url)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED
    assert response.data == {'detail': {
        'non_field_errors': [{'code': 'authentication_failed',
                              'message': 'Invalid client application account.'}
                             ]}}


url_names = sorted(set(url_pattern.name for url_pattern in router.urls
                       if not url_pattern.name.endswith('detail')))


@pytest.mark.parametrize('url_name', url_names, ids=list(url_names))
def test_sts_auth_no_scopes(client_app, drf_client, bicycle, url_name):
    now = timezone.now()
    payload = {'user_id': client_app.name,
               'iss': 'sts-dev',
               'organization': str(client_app.organization.uuid),
               'scopes': [],
               'exp': now + dt.timedelta(minutes=30),
               'iat': now}
    sts_jwt = jwt.encode(payload, settings.JWT_SECRET_KEY,
                         algorithm='HS512').decode()
    drf_client.credentials(HTTP_AUTHORIZATION='JWT ' + sts_jwt)

    try:
        url = reverse_query('lock8:{}'.format(url_name))
    except NoReverseMatch:
        return
    response = drf_client.get(url)
    if url_name == 'api-root':
        assert response.status_code == status.HTTP_200_OK
    else:
        assert response.status_code in (status.HTTP_401_UNAUTHORIZED,
                                        status.HTTP_403_FORBIDDEN,
                                        status.HTTP_406_NOT_ACCEPTABLE)


def test_sts_auth_no_scopes_detail(client_app, drf_client, bicycle, mocker):
    import velodrome.lock8.permissions
    now = timezone.now()
    payload = {'user_id': client_app.name,
               'iss': 'sts-dev',
               'organization': str(client_app.organization.uuid),
               'scopes': [],
               'exp': now + dt.timedelta(minutes=30),
               'iat': now}
    sts_jwt = jwt.encode(payload, settings.JWT_SECRET_KEY,
                         algorithm='HS512').decode()
    drf_client.credentials(HTTP_AUTHORIZATION='JWT ' + sts_jwt)

    called = False

    def side_effect(request, perms):
        nonlocal called
        if called:
            return False
        called = True
        return True

    url = reverse_query('lock8:bicycle-detail', kwargs={'uuid': bicycle.uuid})
    mocker.patch.object(velodrome.lock8.permissions,
                        'check_scopes_are_allowed',
                        side_effect=side_effect)
    response = drf_client.get(url)
    assert response.status_code == status.HTTP_404_NOT_FOUND
