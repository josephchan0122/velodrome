from django.db import connection
from django.http.response import HttpResponse
from django.test.utils import CaptureQueriesContext
import pytest
from rest_framework import status

from velodrome.lock8.utils import reverse_query


@pytest.mark.django_db
def test_elb_health_check_middleware_200(client):
    with CaptureQueriesContext(connection) as capture:
        response = client.get('/_elb')
    assert len(capture.captured_queries) == 1, '\n\n'.join(
        q['sql'] for q in capture.captured_queries)
    assert response.status_code == status.HTTP_200_OK
    assert response.content == b''
    assert response.get('content-length') == '0'


@pytest.mark.django_db
def test_elb_health_check_middleware_503(mocker, client):
    import velodrome.lock8.middleware

    mock = mocker.patch.object(velodrome.lock8.middleware.connection, 'cursor',
                               side_effect=Exception)

    response = client.get('/_elb')
    assert response.status_code == status.HTTP_503_SERVICE_UNAVAILABLE
    assert response.content == b''
    assert response.get('content-length') == '0'
    assert mock.call_count == 1


def test_ddt_middleware_normal(db, client, mocker):
    response = client.get('/api/', HTTP_ACCEPT='text/html')
    assert response.status_code == status.HTTP_200_OK
    assert (b'<title>Noa Api \xe2\x80\x93 Django REST framework</title>' in
            response.content)
    assert b'djDebugToolbar' not in response.content


def test_ddt_middleware_debuguser_group(db, client, admin_user, debug_group,
                                        settings, mocker):
    import debug_toolbar.middleware

    settings.DEBUG_TOOLBAR_PANELS = []  # For performance reasons.

    admin_user.groups.add(debug_group)
    admin_user.save()
    client.force_login(admin_user,
                       backend='velodrome.lock8.authentication.ModelBackend')

    ddt_show_toolbar = mocker.spy(debug_toolbar.middleware, 'show_toolbar')
    url = reverse_query('lock8:jwt-login')
    response = client.get(url, HTTP_ACCEPT='text/html')
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED
    assert b'<title>Obtain Local Json Web Token' in response.content
    assert response.content.count(b'id="djDebugToolbar"') == 1
    assert response['Vary'] == 'Accept, Cookie, Origin'
    assert ddt_show_toolbar.call_count == 1

    url = reverse_query('lock8:jwt-login', {'use_ddt': 1})
    response = client.get(url, HTTP_ACCEPT='text/html')
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED
    assert b'<title>Obtain Local Json Web Token' in response.content
    assert b'djDebugToolbar' in response.content
    assert ddt_show_toolbar.call_count == 2

    url = reverse_query('lock8:jwt-login', {'use_ddt': 0})
    response = client.get(url, HTTP_ACCEPT='text/html')
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED
    assert b'<title>Obtain Local Json Web Token' in response.content
    assert b'djDebugToolbar' not in response.content
    assert ddt_show_toolbar.call_count == 2


def test_ddt_middleware_debuguser_internaldebug(db, client, admin_user,
                                                debug_group, settings):
    settings.DEBUG_TOOLBAR_PANELS = []  # For performance reasons.
    settings.INTERNAL_IPS = ['127.0.0.1']
    settings.DEBUG = True

    admin_user.groups.add(debug_group)
    admin_user.save()
    client.force_login(admin_user,
                       backend='velodrome.lock8.authentication.ModelBackend')

    url = reverse_query('lock8:jwt-login')
    response = client.get(url, HTTP_ACCEPT='text/html',
                          HTTP_ACCEPT_ENCODING='gzip')
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED
    content = response.content
    assert (b'<title>Obtain Local Json Web Token' in content)
    assert b'djDebugToolbar' in content

    admin_user.groups.add(debug_group)
    admin_user.save()
    client.force_login(admin_user,
                       backend='velodrome.lock8.authentication.ModelBackend')
    response = client.get(url, HTTP_ACCEPT='text/html',
                          HTTP_ACCEPT_ENCODING='gzip')
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED
    content = response.content
    assert (b'<title>Obtain Local Json Web Token' in content)
    assert content.count(b'id="djDebugToolbar"') == 1


@pytest.mark.django_db
def test_version_middleware(mocker, client):
    import velodrome

    url = reverse_query('lock8:api-root')

    response = client.get(url, HTTP_ACCEPT='text/html')
    assert response.status_code == status.HTTP_200_OK, response.data
    assert response['X-Noa-Version'] == velodrome.VERSION

    fake_version = '0.1.42'
    mocker.patch('velodrome.VERSION', fake_version)

    response = client.get(url, HTTP_ACCEPT='text/html')
    assert response.status_code == status.HTTP_200_OK
    assert response['X-Noa-Version'] == fake_version


@pytest.mark.django_db
def test_middleware_ec2instance(rf, settings):
    from velodrome.lock8.middleware import EC2InstanceIdMiddleware

    def get_response(request):
        return HttpResponse(b'pong')

    m = EC2InstanceIdMiddleware(get_response)

    settings.EC2_INSTANCE_ID = 'i-mock-id-no-mixin'
    response = m(rf.request())
    assert response.status_code == status.HTTP_200_OK, response.data
    assert response.content == b'pong'
    assert response['X-Noa-From'] == 'i-mock-id-no-mixin'
