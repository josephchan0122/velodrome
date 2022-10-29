from rest_framework.test import APIRequestFactory

from velodrome.lock8.handlers import handler500
from velodrome.lock8.utils import api_exception_handler

factory = APIRequestFactory()


def test_custom_client_500_handler():
    request = factory.post('/api/', content_type='application/json')
    setattr(request, 'sentry', {'id': 666})  # fake Sentry ID
    request.id = 42

    response = handler500(request)
    html = str(response.serialize())
    assert 'administration' not in html
    assert 'reference this error as <strong>42/666</strong>' in html

    request.id = 'a5c1b1841ff24504a0c5ec94cf1f0a5c'
    response = handler500(request)
    html = str(response.serialize())
    assert 'administration' not in html
    assert 'reference this error as <strong>{}/{}</strong>'.format(
        request.id, request.sentry['id']) in html


def test_custom_admin_500_handler():
    request = factory.post('/admin/', content_type='text/html')
    setattr(request, 'sentry', {'id': 666})  # fake Sentry ID
    request.id = 23

    response = handler500(request, 'admin/500.html')
    html = str(response.serialize())
    assert 'administration' in html
    assert 'reference this error as <strong>23/666</strong>' in html

    request.id = 'a5c1b1841ff24504a0c5ec94cf1f0a5c'
    response = handler500(request, 'admin/500.html')
    html = str(response.serialize())
    assert 'administration' in html
    assert 'reference this error as <strong>{}/{}</strong>'.format(
        request.id, request.sentry['id']) in html


def test_api_exception_handler_base():
    from django.http import Http404
    from django.core.exceptions import PermissionDenied

    assert api_exception_handler(Exception(), {}) is None

    error = Http404()
    response = api_exception_handler(error, {})
    assert response.status_code == 404
    assert response.data == {
        'detail': {'non_field_errors': [
            {'code': 'not_found',
             'message': 'Not found.'}]}}

    error = Http404('Something was not found.')
    response = api_exception_handler(error, {})
    assert response.status_code == 404
    assert response.data == {
        'detail': {'non_field_errors': [
            {'code': 'not_found',
             'message': 'Something was not found.'}]}}

    error = PermissionDenied()
    response = api_exception_handler(error, {})
    assert response.status_code == 403
    assert response.data == {
        'detail': {'non_field_errors': [
            {'code': 'permission_denied',
             'message': 'Permission denied.'}]}}


def test_api_exception_handler_django_validationerror():
    from django.core.exceptions import ValidationError as DjangoValidationError

    error = DjangoValidationError('boom')
    response = api_exception_handler(error, {})
    assert response.status_code == 400
    assert response.data == {
        'detail': {'non_field_errors': [{
            'message': 'boom', 'code': 'invalid'}]}}

    error = DjangoValidationError({'field': ['msg1', 'msg2']})
    response = api_exception_handler(error, {})
    assert response.status_code == 400
    assert response.data == {
        'detail': {'field': [{'code': 'invalid', 'message': 'msg1'},
                             {'code': 'invalid', 'message': 'msg2'}]}}

    error = DjangoValidationError({'field': [
        DjangoValidationError('msg3', code='code3'),
        'msg2']})
    response = api_exception_handler(error, {})
    assert response.status_code == 400
    assert response.data == {
        'detail': {'field': [{'code': 'code3', 'message': 'msg3'},
                             {'code': 'invalid', 'message': 'msg2'}]}}

    error = DjangoValidationError('msg', code='custom_code')
    response = api_exception_handler(error, {})
    assert response.status_code == 400
    assert response.data == {
        'detail': {'non_field_errors': [{'code': 'custom_code',
                                         'message': 'msg'}]}}

    error = DjangoValidationError(['msg1', 'msg2'])
    response = api_exception_handler(error, {})
    assert response.status_code == 400
    assert response.data == {
        'detail': {'non_field_errors': [
            {'code': 'invalid', 'message': 'msg1'},
            {'code': 'invalid', 'message': 'msg2'}]}}

    error = DjangoValidationError([DjangoValidationError('msg1', code='code1'),
                                   'msg2'])
    response = api_exception_handler(error, {})
    assert response.status_code == 400
    assert response.data == {
        'detail': {'non_field_errors': [
            {'code': 'code1', 'message': 'msg1'},
            {'code': 'invalid', 'message': 'msg2'}]}}

    error = DjangoValidationError('msg with %(param)s.',
                                  code='password_too_similar',
                                  params={'param': 'param_value'})
    response = api_exception_handler(error, {})
    assert response.status_code == 400
    assert response.data == {
        'detail': {'non_field_errors': [
            {'code': 'password_too_similar',
             'message': 'msg with param_value.'}]}}

    error = DjangoValidationError({
        'field': DjangoValidationError('msg with %(param)s.',
                                       code='password_too_similar',
                                       params={'param': 'param_value'})})
    response = api_exception_handler(error, {})
    assert response.status_code == 400
    assert response.data == {
        'detail': {'field': [
            {'code': 'password_too_similar',
             'message': 'msg with param_value.'}]}}
