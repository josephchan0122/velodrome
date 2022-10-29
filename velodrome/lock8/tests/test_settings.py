import os
import sys

from django.core.exceptions import PermissionDenied
import pytest
from raven.contrib.django.models import get_client as get_sentry_client
from raven.transport.http import HTTPTransport

from velodrome.lock8.utils import reverse_query


@pytest.fixture
def massage_settings_path(mocker, monkeypatch):
    """Re-import settings anew, and restore them afterwards.

    This is required for DJANGO_CONFIGURATION to have an effect."""
    from django.conf import settings
    assert settings.configured
    orig_settings = settings

    restore = []
    reload_modules = ['velodrome.settings', 'velodrome.urls', 'django.conf']
    for m in reload_modules:
        try:
            restore.append((m, sys.modules.pop(m)))
        except KeyError:  # pragma: no cover
            pass

    # Reload, but keep some settings.
    # (see django.test.utils.setup_test_environment).
    from django.conf import settings
    for k in ('SECURE_SSL_REDIRECT', 'ALLOWED_HOSTS'):
        setattr(settings, k, getattr(orig_settings, k))

    unpatch = []
    for name in [x for x in sys.modules
                 if x not in reload_modules and hasattr(sys.modules[x],
                                                        'settings')]:
        sc = sys.modules[name].settings.__class__
        if '{}.{}'.format(sc.__module__, sc.__name__) in (
                'django.conf.UserSettingsHolder',  # with override_settings
                'django.conf.Settings',
        ):
            unpatch.append(name)
            setattr(sys.modules[name], 'settings', settings)

    # Re-setup Django for logging config.
    import django
    django.setup()

    from django.apps import apps
    import reversion

    settings.SILKY_INTERCEPT_FUNC = lambda user: False

    from django.urls.base import clear_url_caches
    clear_url_caches()

    # Skip this during tests (for performance).
    mocker.patch('velodrome.lock8.apps.Lock8Config'
                 '._notify_sentry_for_new_release')
    monkeypatch.setenv('VELODROME_SKIP_TRACKINGS_DB', 'true')

    revision_models = list(reversion.revisions.get_registered_models())
    for m in revision_models:
        reversion.revisions.unregister(m)

    try:
        apps.set_installed_apps(settings.INSTALLED_APPS)
        yield settings
    finally:
        apps.unset_installed_apps()

    for k, v in restore:
        sys.modules[k] = v

    for k in unpatch:
        assert sys.modules[k].settings is settings
        sys.modules[k].settings = orig_settings

    from django.conf import settings
    settings._wrapped = orig_settings._wrapped

    # Re-setup Django for logging config.
    django.setup()


@pytest.fixture
def dev(request, mocker):
    mocker.patch.dict(os.environ, clear=False,
                      DJANGO_CONFIGURATION='Dev')
    return request.getfixturevalue('massage_settings_path')


@pytest.fixture
def massage_settings_path_with_monitoring(request, mocker):
    # For performance and missing .git in test image.
    mocker.patch('raven.fetch_git_sha')

    settings = request.getfixturevalue('massage_settings_path')
    settings.SENTRY_TRANSPORT = 'raven.transport.http.HTTPTransport'
    yield settings


@pytest.fixture
def prod(request, mocker):
    mocker.patch.dict(os.environ, clear=False,
                      DJANGO_CONFIGURATION='Production')
    return request.getfixturevalue('massage_settings_path_with_monitoring')


@pytest.fixture
def tester(request, mocker):
    mocker.patch.dict(os.environ, clear=False,
                      DJANGO_CONFIGURATION='Tester')
    return request.getfixturevalue('massage_settings_path')


@pytest.fixture
def testing(request, mocker):
    mocker.patch.dict(os.environ, clear=False,
                      DJANGO_CONFIGURATION='Testing')
    return request.getfixturevalue('massage_settings_path_with_monitoring')


@pytest.fixture
def travis(request, mocker):
    mocker.patch.dict(os.environ, clear=False,
                      DJANGO_CONFIGURATION='Travis')
    return request.getfixturevalue('massage_settings_path')


def test_s3_storage_not_querystring_auth():
    from storages.backends.s3boto3 import S3Boto3Storage
    storage = S3Boto3Storage()
    assert storage.querystring_auth is False


def test_ddt_for_Dev(dev):
    assert 'debug_toolbar' in dev.INSTALLED_APPS


def test_ddt_for_Testing(testing):
    assert 'debug_toolbar' in testing.INSTALLED_APPS


def test_ddt_not_for_Prod(prod):
    assert 'debug_toolbar' in prod.INSTALLED_APPS


def test_middleware_classes_dev(dev):
    assert ('debug_toolbar.middleware.DebugToolbarMiddleware'
            in dev.MIDDLEWARE)


def test_middleware_classes_production(prod):
    assert 'debug_toolbar.middleware.DebugToolbarMiddleware' \
        not in prod.MIDDLEWARE[0]


def test_uses_ddt_defaults(dev):
    from debug_toolbar import settings as dt_settings
    assert (not hasattr(dev, 'DEBUG_TOOLBAR_PANELS') or
            set(dt_settings.PANELS_DEFAULTS).issubset(
                dev.DEBUG_TOOLBAR_PANELS))


@pytest.mark.parametrize('env,expected', (('dev', False),
                                          ('tester', True),
                                          ('travis', True),
                                          ('testing', False),
                                          ('prod', False)))
def test_IS_TESTER_dev(request, env, expected):
    env = request.getfixturevalue(env)
    assert env.IS_TESTER == expected


def test_db_routing_trackings(dev):
    from velodrome.lock8.db_routers import LoadBalancerRouter
    from velodrome.lock8.models import ReadonlyTracking

    router = LoadBalancerRouter()

    assert router.db_for_read(ReadonlyTracking) == dev.TRACKINGS_DB
    with pytest.raises(PermissionDenied) as exc:
        router.db_for_write(ReadonlyTracking) == 'default'
    assert exc.value.args == ('db_for_write with readonlytracking',)


@pytest.mark.skip(reason='Looking why pytest is hanged')
def test_trackings_db_removed_on_error(testing, db, caplog, mocker,
                                       monkeypatch):
    from django.apps import apps
    from django.db import ConnectionHandler
    import django.db

    monkeypatch.delenv('VELODROME_SKIP_TRACKINGS_DB')

    app = apps.get_app_config('lock8')

    connections = ConnectionHandler()
    conn = connections['trackings']

    mocker.patch.object(django.db, 'connections', connections)

    settings_dict = conn.settings_dict.copy()
    settings_dict['PORT'] = 23
    settings_dict['OPTIONS']['connect_timeout'] = 1
    broken_conn = conn.__class__(
        settings_dict,
        alias='trackings'
    )
    # No more setting allow_thread_sharing as a parameter for DatabaseWrapper
    # See the release notes https://docs.djangoproject.com/en/3.1/releases/2.2/
    #
    # Based on the thread-shareability management difference between versions:
    # 1.8 https://docs.djangoproject.com/en/1.8/_modules/django/test/testcases/
    # 2.2 https://docs.djangoproject.com/en/2.2/_modules/django/test/testcases/
    if broken_conn.allow_thread_sharing:
        broken_conn.dec_thread_sharing()
    connections['trackings'] = broken_conn

    # Access it here to trigger loading already.
    assert 'trackings' in testing.DATABASES

    caplog.clear()
    m_sentry_emit = mocker.patch('velodrome.logging.SentryHandler.emit')
    app.verify_trackings_connection()
    record = m_sentry_emit.call_args_list[-1][0][0]
    assert record.message.startswith(
        'Could not connect to trackings DB, removing it from known databases:')
    assert m_sentry_emit.call_count == 1

    assert 'trackings' not in connections
    assert 'trackings' not in connections.databases
    assert 'trackings' not in testing.DATABASES

    log_messages = [rec.message for rec in caplog.records]
    assert any(x.startswith('Could not connect to trackings DB, ')
               for x in log_messages)


def test_trackings_db_removed_on_error_restored(settings):
    from django.db import connections

    conn = connections['trackings']
    assert conn.settings_dict['PORT'] != 23
    assert 'trackings' in settings.DATABASES
    assert 'trackings' in connections.databases


@pytest.mark.parametrize('env,expected', (('dev', False),
                                          ('tester', False),
                                          ('travis', False),
                                          ('testing', True),
                                          ('prod', True)))
def test_logging_testing(request, env, expected):
    env = request.getfixturevalue(env)
    handlers = env.LOGGING['root']['handlers']
    assert ('sentry' in handlers) == expected


def test_logging_boto(mocker, prod):
    import logging
    import velodrome.logging

    mock_filter_sentry = mocker.spy(velodrome.logging.SentryHandler, 'filter')
    mock_emit_sentry = mocker.spy(velodrome.logging.SentryHandler, 'emit')

    logger = logging.getLogger('boto.connection')
    assert not logger.propagate
    logger.error('boto error')

    assert not mock_filter_sentry.call_args
    assert not mock_emit_sentry.call_args


@pytest.mark.skip(reason='Django logger API was changed in 2.1, rewrite test!')
def test_logging_sentry_500(mocker, prod, drf_admin):
    """Test that SentryHandler filters out exceptions (reported already)."""
    import velodrome.logging

    # Patch out capture to not cause errors with missing auth mainly.
    sentry_client = get_sentry_client()
    m_capture = mocker.patch.object(sentry_client, 'capture')

    prod.SECURE_SSL_REDIRECT = False

    mock_filter = mocker.spy(velodrome.logging.SentryHandler, 'filter')
    mock_emit = mocker.patch.object(velodrome.logging.SentryHandler, 'emit')

    with pytest.raises(ZeroDivisionError):
        drf_admin.get(reverse_query('lock8:500plz'))

    with pytest.raises(ZeroDivisionError):
        drf_admin.get(reverse_query('admin_500plz'))

    response = mock_filter.call_args[0][1].msg

    assert (response == 'Internal Server Error: %s' or
            response.startswith('Request for "%s" took longer than '))

    assert not mock_emit.call_args

    assert m_capture.call_count == 2


def test_db_routing_trips(dev):
    from velodrome.lock8.db_routers import LoadBalancerRouter
    from velodrome.lock8.models import Trip

    router = LoadBalancerRouter()

    assert router.db_for_read(Trip) == dev.TRACKINGS_DB
    with pytest.raises(PermissionDenied) as exc:
        router.db_for_write(Trip) == 'default'
    assert exc.value.args == ('db_for_write with trip',)


def test_middleware_headers_testing_get(db, testing, client):
    testing.SECURE_SSL_REDIRECT = False

    url = reverse_query('lock8:api-root')
    response = client.get(url, HTTP_ACCEPT='text/html')
    assert response['X-Noa-From'] == 'id-testme'
    assert len(response.wsgi_request.id)
    assert response['X-Noa-RequestId'] == response.wsgi_request.id
    assert response.status_code == 200, response.data
    assert [header[0] for header in response.items()] == [
        'Content-Type', 'Vary', 'Allow', 'X-Frame-Options', 'ETag',
        'Content-Length', 'X-Noa-Version', 'X-Noa-RequestId', 'X-Noa-From']


def test_middleware_headers_testing_get_origin_etag(
        request, drf_fleet_operator, testing):
    testing.SECURE_SSL_REDIRECT = False

    client = drf_fleet_operator

    url = reverse_query('lock8:bicycle-list')
    response = client.get(url,
                          HTTP_ACCEPT='application/json; version=1.0',
                          HTTP_ORIGIN='https://fms.noa.one/')
    assert response.status_code == 200, response.data
    assert response['Vary'] == 'Accept, Cookie, Origin'
    etag = response['ETag']
    response = client.get(url,
                          HTTP_ACCEPT='application/json; version=1.0',
                          HTTP_ORIGIN='https://fms.noa.one/',
                          HTTP_IF_NONE_MATCH=etag)
    assert response.status_code == 304, response.data
    assert response['Vary'] == 'Accept, Cookie, Origin'
    assert response['ETag'] == etag
    assert response['Access-Control-Allow-Credentials'] == 'true'
    assert response['Access-Control-Allow-Origin'] == 'https://fms.noa.one/'
    assert response['Content-Length'] == '0'

    drf_fleet_operator = request.getfixturevalue('drf_fleet_operator')
    response = client.get(url,
                          HTTP_ACCEPT='application/json; version=1.0',
                          HTTP_ORIGIN='https://fms.noa.one/',
                          HTTP_IF_NONE_MATCH=etag)
    assert response.status_code == 304, response.data
    request.getfixturevalue('bicycle')
    response = client.get(url,
                          HTTP_ACCEPT='application/json; version=1.0',
                          HTTP_ORIGIN='https://fms.noa.one/')
    assert response.status_code == 200, response.data


def test_middleware_headers_testing_options(db, testing, client):
    testing.SECURE_SSL_REDIRECT = False

    url = reverse_query('lock8:bicycle-list')
    response = client.options(url, HTTP_ACCEPT='application/json; version=1.0')
    assert response['X-Noa-From'] == 'id-testme'
    assert len(response.wsgi_request.id)
    assert response['X-Noa-RequestId'] == response.wsgi_request.id
    assert response.status_code == 200, response.data
    assert [header[0] for header in response.items()] == [
        'Content-Type', 'Vary', 'Allow', 'X-Frame-Options', 'Content-Length',
        'X-Noa-Version', 'X-Noa-RequestId', 'X-Noa-From']


@pytest.mark.parametrize('user', (None, 'renter'))
def test_sentry_exception(request, user, db, client, prod, urls_for_tests,
                          mocker):
    import log_request_id

    if user is not None:
        user = request.getfixturevalue(user)
        client.force_login(user)

    sentry_client = get_sentry_client()
    assert sentry_client.is_enabled()

    assert issubclass(sentry_client.remote._transport_cls, HTTPTransport)
    spy = mocker.spy(sentry_client, 'update_data_from_request')

    m_send = mocker.patch.object(sentry_client, 'send')

    # For performance reasons.
    m_get_module_versions = mocker.patch.object(
        sentry_client, 'get_module_versions')

    prod.SECURE_SSL_REDIRECT = False

    url = reverse_query('exception')
    with pytest.raises(Exception) as e:
        client.get(url)
    request_id = log_request_id.local.request_id
    assert e.value.args[0].id == request_id

    assert spy.call_count == 2
    request = spy.call_args[0][0]
    assert request.id == request_id

    assert m_get_module_versions.call_count == 1

    assert m_send.call_count == 1
    send_extra = m_send.call_args[1]['extra']
    assert send_extra['some'] == {'extra': 'information'}

    send_user_info = m_send.call_args[1]['user']
    if user is None:
        assert 'organizations' not in send_user_info
    else:
        assert send_user_info['email'] == 'alice@example.com'
        affs = []
        orgs = []
        for aff in user.affiliations.all():
            affs.append((aff.organization, aff.role))
            orgs.append(aff.organization)

        assert send_user_info['affiliations'] == affs
        assert m_send.call_args[1]["tags"]["orgs"] == str(orgs)


def test_api_exception_handler_calls_sentry(mocker, prod, drf_client):
    from velodrome.lock8.utils import api_exception_handler
    from django.core.exceptions import ValidationError as DjangoValidationError

    sentry_client = get_sentry_client()

    m_send = mocker.patch.object(sentry_client, 'send')
    # For performance reasons.
    mocker.patch.object(sentry_client, 'get_module_versions')

    error = DjangoValidationError('boom', code='error_code')
    response = api_exception_handler(error, {})
    assert response.status_code == 400
    assert response.data == {
        'detail': {'non_field_errors': [{
            'message': 'boom', 'code': 'error_code'}]}}

    exc_repr = (
        "ValidationError({'non_field_errors': "
        "[ErrorDetail(string='boom', code='error_code')]}, 'error_code')"
    )
    msg = 'APIException (400): ' + exc_repr
    assert m_send.call_count == 1
    assert m_send.call_args_list[0][1]['message'] == msg
    assert m_send.call_args_list[0][1]['fingerprint'] == [
        '{{ default }}', exc_repr]
    assert 'exception' not in m_send.call_args_list[0][1]

    # Test exception being added through exception handler.
    drf_client.assert_400(reverse_query('lock8:jwt-login'), data={})
    exc_repr = (
        "ValidationError({'non_field_errors': "
        "[ErrorDetail(string='boom', code='error_code')]}, 'error_code')"
    )
    data = m_send.call_args_list
    msg_parts = list(map(str, (item[1] for item in data)))
    with_took_longer = any("took longer" in msg for msg in msg_parts)
    is_correct = (
        m_send.call_count == 3 or (
            m_send.call_count > 3 or with_took_longer
        )
    )
    assert is_correct, 'All context: {}'.format(
        # travis info
        '\n--------------------\n'.join(msg_parts)
    )

    assert data[1][1]['message'].startswith(
        'APIException (400): ValidationError')
    exc = data[1][1]['exception']
    assert exc['values'][0]['module'] == 'rest_framework.exceptions'
    assert len(exc['values']) == 1


def test_validationerror_before_rollback(mocker, prod, drf_client):
    from velodrome.lock8.utils import api_exception_handler
    from rest_framework import exceptions

    # Patch out capture to not cause errors with missing auth mainly.
    sentry_client = get_sentry_client()
    mocker.patch.object(sentry_client, 'capture')

    # For performance reasons.
    mocker.patch.object(sentry_client, 'get_module_versions')

    repr_called = False

    class CustomValidationError(exceptions.ValidationError):
        def __repr__(self):
            nonlocal repr_called
            from velodrome.lock8.models import User

            User.objects.exists()
            repr_called = True
            return super().__repr__()

    from django.db import transaction
    with transaction.atomic():
        error = CustomValidationError('boom', code='error_code')
        response = api_exception_handler(error, {})

    assert response.status_code == 400
    assert repr_called


def test_api_exception_handler_invalid_coupon(mocker, prod, drf_client):
    from velodrome.lock8.utils import api_exception_handler
    import rest_framework

    sentry_client = get_sentry_client()

    m_send = mocker.patch.object(sentry_client, 'send')
    # For performance reasons.
    mocker.patch.object(sentry_client, 'get_module_versions')

    error = rest_framework.exceptions.ValidationError(
        {'coupon': ['No such coupon: car free day 2018']},
        code='invalid_coupon',
    )
    response = api_exception_handler(error, {})
    assert response.status_code == 400
    assert m_send.call_count == 1
    assert m_send.call_args_list[0][1]['fingerprint'] == [
        'validationerror_invalid_coupon']
    assert 'exception' not in m_send.call_args_list[0][1]


def test_logs_slow_requests(caplog, mocker, prod, drf_admin,
                            bicycle_available, settings):
    """
    The goal of this is to check for slow api calls
    regardless of if it's 1 second or more
    """
    import re
    sentry_client = get_sentry_client()
    m_send = mocker.patch.object(sentry_client, 'send')
    # For performance reasons.
    mocker.patch.object(sentry_client, 'get_module_versions')

    settings.SENTRY_SLOW_REQUEST_DURATION_THRESHOLD = 1.0
    url = reverse_query(
        'lock8:sleepplz',
        {'seconds': settings.SENTRY_SLOW_REQUEST_DURATION_THRESHOLD + 0.1}
    )
    drf_admin.assert_success(url)

    record = caplog.record_tuples[-1]
    assert record[0:2] == ('velodrome.lock8.middleware', 30)
    assert record[2].startswith('Request for "/api/sleepplz" took longer than')

    send_kwargs = m_send.call_args[1]
    match_any_duration = r"\['duration-[0-9]+', '/api/sleepplz'\]"
    assert re.match(match_any_duration, str(send_kwargs['fingerprint']))
    assert int(send_kwargs['tags']['duration'])

    # View with action/params.
    bicycle = bicycle_available
    orig_rent = bicycle.rent

    def slow_rent(self, *args, **kwargs):
        import time
        time.sleep(1)
        orig_rent(*args, **kwargs)

    mocker.patch('velodrome.lock8.models.Bicycle.rent', slow_rent)

    url = reverse_query('lock8:bicycle-actions', kwargs={'uuid': bicycle.uuid})
    drf_admin.assert_status(url, 204, data={'type': 'rent', 'dry_run': True})

    record = caplog.record_tuples[-1]
    assert record[0:2] == ('velodrome.lock8.middleware', 30)
    assert record[2].startswith(
        'Request for "/api/bicycles/{uuid}/actions/: action rent (dry_run)" '
        'took longer than 1s:')

    send_kwargs = m_send.call_args[1]
    assert send_kwargs['fingerprint'] == [
        'duration-1', '/api/bicycles/{uuid}/actions/: action rent (dry_run)']
    assert send_kwargs['tags']['duration'] == '1'
