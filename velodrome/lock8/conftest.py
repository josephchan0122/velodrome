import base64
from collections import OrderedDict
import contextlib
import copy
import datetime as dt
from datetime import timedelta
from functools import partial, wraps
import io
from itertools import chain, repeat
import json
import os
import random
import re
import string
import unittest
import urllib
from urllib.parse import urlencode
import uuid
import warnings

from concurrency.api import disable_concurrency
from django.conf import settings
from django.contrib.gis.geos.collections import (
    LineString, MultiPolygon, Point, Polygon,
)
from django.contrib.sites.models import Site
from django.core.cache import caches
from django.core.files import File
from django.core.files.images import ImageFile
from django.db import connection, connections
from django.db.models.signals import post_save
import django.test.client
from django.urls import reverse
from django.utils import timezone
from freezegun import freeze_time
from pinax.stripe.models import Account, Plan, Subscription
import pytest
import requests_mock
from rest_framework import status
from rest_framework.response import Response
from rest_framework.test import APIClient
from rest_framework_jwt.utils import jwt_encode_handler
from reversion import revisions

import velodrome
from velodrome.lock8.dynamodb import dynamodb, get_ddbtable, try_delete_tables
from velodrome.lock8.jwt_extensions import jwt_payload_handler
from velodrome.lock8.metrics.test_utils import create_ddb_tables
from velodrome.lock8.tests.utils import sorted_dicts

NOW = timezone.now()

warnings.simplefilter("error", RuntimeWarning)


class CommitOnSuccessClientMixin:
    commit_db_on_successful_response = False

    def request(self, *args, **kwargs):
        response = super().request(*args, **kwargs)

        if self.commit_db_on_successful_response:
            if response.status_code >= 200 and response.status_code <= 400:
                _commit_success()

        return response


class CustomClient(CommitOnSuccessClientMixin, django.test.client.Client):
    pass


class CustomAPIClient(CommitOnSuccessClientMixin, APIClient):
    pass


def pytest_collection_modifyitems(items):
    """Apply marker for tests using the DB.

    Ref: https://github.com/pytest-dev/pytest-django/issues/368"""

    for item in items:
        if item.get_closest_marker('db'):
            continue
        if (item.get_closest_marker('django_db') or
                any(i in item.fixturenames
                    for i in ('db', 'transactional_db'))):
            item.add_marker(pytest.mark.db)


@pytest.mark.slow
def transactional_db(transactional_db):
    pass


class ReadOnlyDict(dict):
    def __readonly__(self, *args, **kwargs):
        raise RuntimeError('Cannot modify ReadOnlyDict')  # pragma: no cover
    __setitem__ = __readonly__
    __delitem__ = __readonly__
    pop = __readonly__
    popitem = __readonly__
    clear = __readonly__
    update = __readonly__
    setdefault = __readonly__
    del __readonly__
    __copy__ = dict.copy
    __deepcopy__ = copy._deepcopy_dispatch.get(dict)


@pytest.fixture
def now():
    return NOW


@pytest.fixture
def client_with_csrf():
    return CustomClient(enforce_csrf_checks=True)


@pytest.fixture
def client_with_html_accept():
    """A Django test client instance, simulating a browser."""

    return CustomClient(HTTP_ACCEPT='text/html,application/xhtml+xml,'
                                    'application/xml;q=0.9,*/*;q=0.8')


@pytest.fixture
def multi_db():
    """Signalling fixture for pytest_generate_tests in our plugin."""


@pytest.fixture
def with_db_plugins():
    """Apply plugins.
    """
    with connection.cursor() as cursor:
        cursor.execute("""
        CREATE EXTENSION IF NOT EXISTS unaccent;
        CREATE EXTENSION IF NOT EXISTS pg_trgm;
        """)


@pytest.fixture
def mocker_copy(mocker):
    """A mocker that copies args by default (via `new_callable`)."""
    class CopyingMock(unittest.mock.MagicMock):
        def __call__(self, *args, **kwargs):
            args = copy.deepcopy(args)
            kwargs = copy.deepcopy(kwargs)
            return super(CopyingMock, self).__call__(*args, **kwargs)

    mocker.patch._start_patch = partial(mocker.patch._start_patch,
                                        new_callable=CopyingMock)
    return mocker


def cast_to_dict(data):
    if isinstance(data, OrderedDict):
        data = dict(data)
        for key, value in data.items():
            data[key] = cast_to_dict(value)
    elif isinstance(data, dict):
        for key, value in data.items():
            data[key] = cast_to_dict(value)
    elif isinstance(data, list):
        data = [cast_to_dict(value) for value in data]

    return data


def decorated_drf_client(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        from pprint import pformat

        drf_client = f(*args, **kwargs)

        def assert_status(url_or_response, expected_status,
                          expected_data=None, data=None, method=None,
                          format=None):
            __tracebackhide__ = True
            drf_kwargs = {}
            if method is None:
                method = 'get' if data is None else 'post'
            if format is not None:
                drf_kwargs['format'] = format
            if isinstance(url_or_response, Response):
                response = url_or_response
            else:
                response = getattr(drf_client, method)(url_or_response,
                                                       data=data,
                                                       **drf_kwargs)
            assert response.status_code == expected_status, (
                'Response is not of status {}, but {} ({}):\n{}'.format(
                    expected_status, response.status_code,
                    response.status_text, pformat(response.data)))
            if expected_data is not None:
                assert cast_to_dict(response.data) == expected_data
            return response
        drf_client.assert_status = assert_status

        def assert_success(url_or_response, expected_data=None, data=None,
                           method=None, format=None):
            __tracebackhide__ = True
            return assert_status(url_or_response, status.HTTP_200_OK,
                                 expected_data, data, method, format=format)
        drf_client.assert_success = assert_success

        def assert_count(url_or_response, expected_count, data=None,
                         method=None):
            __tracebackhide__ = True
            response = assert_success(url_or_response, data=data,
                                      method=method)
            assert response.data['count'] == expected_count, (
                'Expected count of {}, but got {}:\n{}'.format(
                    expected_count, response.data['count'],
                    pformat(response.data)))
            return response
        drf_client.assert_count = assert_count

        def assert_values(url_or_response, expected_values, data=None,
                          method=None):
            """Assert certain values for metrics endpoints."""
            __tracebackhide__ = True
            response = assert_success(url_or_response, data=data,
                                      method=method)
            assert list(response.data.keys()) == ['values']
            assert (sorted_dicts(response.data['values'],
                                 keys=['date', 'zone']) ==
                    sorted_dicts(expected_values,
                                 keys=['date', 'zone']))
            return response
        drf_client.assert_values = assert_values

        def assert_values_has_data(url_or_response,
                                   expected_values: dict,
                                   expected_status=status.HTTP_200_OK,
                                   data=None,
                                   method=None):
            __tracebackhide__ = True
            response = assert_success(url_or_response, data=data,
                                      method=method)
            assert response.status_code == expected_status, (
                'Response is not of status {}, but {} ({}):\n{}'.format(
                    expected_status, response.status_code,
                    response.status_text, pformat(response.data)))
            actual_data = [x for x in response.data.keys()
                           for y in expected_values.keys() if y == x]
            assert (sorted_dicts(actual_data,
                                 keys=['date', 'zone']) ==
                    sorted_dicts(expected_values,
                                 keys=['date', 'zone']))
            return response
        drf_client.assert_values_has_data = assert_values_has_data

        def assert_created(url_or_response, expected_data=None, data=None,
                           method='post', format='json'):
            __tracebackhide__ = True
            return assert_status(url_or_response, status.HTTP_201_CREATED,
                                 expected_data, data, method, format=format)
        drf_client.assert_created = assert_created

        def assert_400(url_or_response, expected_detail=None, data=None,
                       method=None, format=None):
            __tracebackhide__ = True
            expected_data = {
                'detail': expected_detail
            } if expected_detail is not None else None
            return assert_status(
                url_or_response, status.HTTP_400_BAD_REQUEST,
                expected_data=expected_data, data=data, method=method,
                format=format)
        drf_client.assert_400 = assert_400

        def assert_404(url_or_response, expected_detail=None, data=None,
                       method=None):
            __tracebackhide__ = True
            expected_data = {
                'detail': expected_detail
            } if expected_detail is not None else None
            return assert_status(url_or_response, status.HTTP_404_NOT_FOUND,
                                 expected_data, data=data, method=method)
        drf_client.assert_404 = assert_404

        def assert_403(url_or_response, expected_data=None, data=None,
                       method=None):
            __tracebackhide__ = True
            if expected_data is None:
                expected_data = {'detail': {'non_field_errors': [{
                    'code': 'permission_denied',
                    'message': ('You do not have permission '
                                'to perform this action.')}]}}
            return assert_status(url_or_response, status.HTTP_403_FORBIDDEN,
                                 expected_data, data=data, method=method)
        drf_client.assert_403 = assert_403

        def assert_invalid_choice(url_or_response, field_name, value):
            __tracebackhide__ = True
            assert_400(url_or_response, {
                field_name: [
                    {'message': 'Select a valid choice.'
                     ' {} is not one of the available choices.'.format(value),
                     'code': 'invalid_choice'}]})
        drf_client.assert_invalid_choice = assert_invalid_choice

        return drf_client
    return wrapper


@pytest.fixture
@decorated_drf_client
def drf_client(db):
    return CustomAPIClient(HTTP_ACCEPT='application/json; version=1.0')


@pytest.fixture
@decorated_drf_client
def drf_token_admin(admin_user):
    from rest_framework.authtoken.models import Token

    token = Token.objects.create(user=admin_user)

    drf_client = CustomAPIClient(HTTP_ACCEPT='application/json; version=1.0')
    drf_client.credentials(HTTP_AUTHORIZATION='Token ' + token.key)
    drf_client.user = admin_user
    return drf_client


@pytest.fixture
def owner(request, db):
    from velodrome.lock8.models import User
    return User.objects.create(
        username=request.fixturename,
        email='{}@example.com'.format(request.fixturename))


@pytest.fixture
def anon():
    from django.contrib.auth.models import AnonymousUser
    return AnonymousUser()


@pytest.fixture
def fleet_operator(request, org):
    from velodrome.lock8.models import (
        Affiliation, User, create_stripe_customer)
    from velodrome.lock8.utils import disable_signal
    user = User.objects.create(
        username=request.fixturename,
        email='{}@example.com'.format(request.fixturename))
    with disable_signal(post_save, create_stripe_customer, Affiliation):
        Affiliation.objects.create(user=user,
                                   organization=org,
                                   role=Affiliation.FLEET_OPERATOR)
    return user


@pytest.fixture
def fleet_admin(request, org):
    from velodrome.lock8.models import Affiliation, User
    user = User.objects.create(
        username=request.fixturename,
        email='{}@example.com'.format(request.fixturename))
    Affiliation.objects.create(user=user,
                               organization=org,
                               role=Affiliation.ADMIN)
    return user


@pytest.fixture
def spectator(request, org):
    from velodrome.lock8.models import Affiliation, User
    user = User.objects.create(
        username=request.fixturename,
        email='{}@example.com'.format(request.fixturename))
    Affiliation.objects.create(user=user,
                               organization=org,
                               role=Affiliation.SPECTATOR)
    return user


@pytest.fixture
def production_software(request, root_org):
    from velodrome.lock8.models import Affiliation, User
    user = User.objects.create(
        username=request.fixturename,
        email='{}@example.com'.format(request.fixturename))
    Affiliation.objects.create(user=user,
                               organization=root_org,
                               role=Affiliation.PRODUCTION_SOFTWARE)
    return user


@pytest.fixture
def supervisor(request, org):
    from velodrome.lock8.models import (
        Affiliation,
        create_stripe_customer,
        User,
    )
    from velodrome.lock8.utils import disable_signal
    user = User.objects.create(
        username=request.fixturename,
        email='{}@example.com'.format(request.fixturename)
    )
    with disable_signal(post_save, create_stripe_customer, Affiliation):
        Affiliation.objects.create(
            user=user,
            organization=org,
            role=Affiliation.SUPERVISOR
        )
    return user


@decorated_drf_client
def get_drf_client_for_user(user):
    drf_client = CustomAPIClient(HTTP_ACCEPT='application/json; version=1.0')
    drf_client.force_authenticate(user=user)

    def use_jwt_auth():
        drf_client.force_authenticate()
        drf_client.logout()
        drf_client.credentials(
            HTTP_AUTHORIZATION='JWT ' + jwt_encode_handler(
                jwt_payload_handler(user)))
    drf_client.use_jwt_auth = use_jwt_auth

    drf_client.user = user

    return drf_client


@pytest.fixture
def drf_fleet_operator(fleet_operator):
    # performance optimization
    fleet_operator.is_admin_of_lock8 = False
    return get_drf_client_for_user(fleet_operator)


@pytest.fixture
def drf_alice(alice):
    # performance optimization
    alice.is_admin_of_lock8 = False
    return get_drf_client_for_user(alice)


@pytest.fixture
def drf_mechanic1(mechanic1):
    return get_drf_client_for_user(mechanic1)


@pytest.fixture
def drf_bob(bob):
    bob.is_admin_of_lock8 = False
    return get_drf_client_for_user(bob)


@pytest.fixture
def drf_admin(admin_user):
    # Performance hack to not use JWT auth.
    admin_user.is_admin_of_lock8 = True
    return get_drf_client_for_user(admin_user)


@pytest.fixture
def drf_another_fleet_operator(another_fleet_operator):
    # Performance hack to not use JWT auth.
    another_fleet_operator.is_admin_of_lock8 = False
    return get_drf_client_for_user(another_fleet_operator)


@pytest.fixture
def drf_spectator(spectator):
    return get_drf_client_for_user(spectator)


@pytest.fixture
def drf_renter(renter):
    # performance optimization
    renter.is_admin_of_lock8 = False
    return get_drf_client_for_user(renter)


@pytest.fixture
def drf_supervisor(supervisor):
    # Performance hack to not use JWT auth.
    supervisor.is_admin_of_lock8 = False
    return get_drf_client_for_user(supervisor)


@pytest.fixture
def stripe_account():
    return Account.objects.create(stripe_id='acc_org')


@pytest.fixture
def org(request, owner, root_org):
    from velodrome.lock8.models import Organization
    if 'uses_payments' in request.keywords:
        return request.getfixturevalue('org_with_payments')
    return Organization.objects.create(name=request.fixturename,
                                       parent=root_org,
                                       owner=owner)


@pytest.fixture
def org_open_fleet(org):
    org.is_open_fleet = True
    org.save()
    return org


@pytest.fixture
def org_with_payments(request, owner, root_org):
    from velodrome.lock8.models import Organization
    stripe_account = request.getfixturevalue('stripe_account')
    return Organization.objects.create(name=request.fixturename,
                                       parent=root_org,
                                       stripe_account=stripe_account,
                                       owner=owner)


@pytest.fixture
def sub_org(request, owner, org):
    from velodrome.lock8.models import Organization
    return Organization.objects.create(name=request.fixturename,
                                       parent=org,
                                       owner=owner)


@pytest.fixture
def another_fleet_operator(request, another_org):
    from velodrome.lock8.models import Affiliation, User
    user = User.objects.create(
        username=request.fixturename,
        email='{}@example.com'.format(request.fixturename))
    Affiliation.objects.create(user=user,
                               organization=another_org,
                               role=Affiliation.FLEET_OPERATOR)
    return user


@pytest.fixture
def another_org(request, owner, root_org):
    from velodrome.lock8.models import Organization
    return Organization.objects.create(
        name=request.fixturename,
        parent=root_org,
        owner=owner)


@pytest.fixture
def alice(request, owner):
    from velodrome.lock8.models import User
    alice = User.objects.create(
        username=request.fixturename,
        email='{}@example.com'.format(request.fixturename),
        first_name='Alice',
        last_name='Cooper',
        owner=owner,
    )
    alice.set_password('pwd_' + request.fixturename)
    alice.save()
    return alice


@pytest.fixture
def renter(alice, org):
    from velodrome.lock8.models import Affiliation, create_stripe_customer
    from velodrome.lock8.utils import disable_signal
    with disable_signal(post_save, create_stripe_customer, Affiliation):
        Affiliation.objects.create(
            organization=org,
            user=alice,
            role=Affiliation.RENTER)
    return alice


@pytest.fixture
def another_renter(bob, another_org):
    from velodrome.lock8.models import Affiliation, create_stripe_customer
    from velodrome.lock8.utils import disable_signal
    with disable_signal(post_save, create_stripe_customer, Affiliation):
        Affiliation.objects.create(
            organization=another_org,
            user=bob,
            role=Affiliation.RENTER)
    return bob


@pytest.fixture
def renter_and_admin_user(renter, root_org):
    from velodrome.lock8.models import Affiliation
    Affiliation.objects.create(organization=root_org,
                               user=renter,
                               role=Affiliation.ADMIN)
    return renter


@pytest.fixture
def admin_user_and_renter(admin_user, org):
    from velodrome.lock8.models import Affiliation
    Affiliation.objects.create(organization=org,
                               user=admin_user,
                               role=Affiliation.RENTER)
    return admin_user


@pytest.fixture
def admin_of_org_and_admin_user(admin_user_of_org, root_org):
    from velodrome.lock8.models import Affiliation
    Affiliation.objects.create(organization=root_org,
                               user=admin_user_of_org,
                               role=Affiliation.ADMIN)
    return admin_user_of_org


@pytest.fixture(params=['lock8_facebook_oauth2', 'lock8_google_oauth2'])
def social_provider(request):
    return request.param


@pytest.fixture
def social_alice(alice, social_provider):
    from social_django.models import UserSocialAuth

    UserSocialAuth.create_social_auth(alice, uuid.uuid4(), social_provider)
    return alice


@pytest.fixture
def mechanic1(request, org):
    from velodrome.lock8.models import Affiliation, User
    james_brown = User.objects.create(
        username=request.fixturename,
        email='{}@example.com'.format(request.fixturename),
        first_name='James',
        last_name='Brown',
    )
    Affiliation.objects.create(
        organization=org,
        user=james_brown,
        role=Affiliation.MECHANIC)
    return james_brown


@pytest.fixture
def mechanic2(request, org):
    from velodrome.lock8.models import Affiliation, User
    michael_jackson = User.objects.create(
        username=request.fixturename,
        email='{}@example.com'.format(request.fixturename),
        first_name='Michael',
        last_name='Jackson',
    )
    Affiliation.objects.create(
        organization=org,
        user=michael_jackson,
        role=Affiliation.MECHANIC)
    return michael_jackson


@pytest.fixture
def another_mechanic(request, another_org):
    from velodrome.lock8.models import Affiliation, User
    clint_eastwood = User.objects.create(
        username=request.fixturename,
        email='{}@example.com'.format(request.fixturename),
        first_name='Clint',
        last_name='Eastwood',
    )
    Affiliation.objects.create(
        organization=another_org,
        user=clint_eastwood,
        role=Affiliation.MECHANIC)
    return clint_eastwood


@pytest.fixture
def security1(request, org):
    from velodrome.lock8.models import Affiliation, User
    son_house = User.objects.create(
        username=request.fixturename,
        email='{}@example.com'.format(request.fixturename),
        first_name='Son',
        last_name='House',
    )
    Affiliation.objects.create(
        organization=org,
        user=son_house,
        role=Affiliation.SECURITY)
    return son_house


@pytest.fixture
def bob(request, db):
    from velodrome.lock8.models import User
    return User.objects.create(
        username=request.fixturename,
        email='{}@example.com'.format(request.fixturename),
        first_name='Bob',
        last_name='Sponge',
    )


@pytest.fixture(scope='session')
def customer_base_json():
    return ReadOnlyDict({
        'id': 'cus_7UkUzpBtATnab9',
        'object': 'customer',
        'account_balance': 0,
        'currency': 'usd',
        'delinquent': False,
        'default_source': None,
        'sources': {
            'object': 'list',
            'data': [],
            'has_more': False,
            'total_count': 0,
            'url': '/v1/customers/cus_7UkUzpBtATnab9/sources'
        },
        'subscriptions': {
            'object': 'list',
            'data': [],
            'has_more': False,
            'total_count': 0,
            'url': '/v1/customers/cus_7UkUzpBtATnab9/subscriptions',
        },
    })


@pytest.fixture
def alice_card_json():
    return ReadOnlyDict({
        'id': 'card_178AAbEWnIuOzoofkj3g3Pf1',
        'object': 'card',
        'address_city': None,
        'address_country': None,
        'address_line1': None,
        'address_line1_check': None,
        'address_line2': None,
        'address_state': None,
        'address_zip': None,
        'address_zip_check': None,
        'brand': 'Visa',
        'country': 'US',
        'customer': 'cus_7UkUzpBtATnab9',
        'cvc_check': 'pass',
        'dynamic_last4': None,
        'exp_month': 1,
        'exp_year': 2016,
        'funding': 'credit',
        'last4': '4242',
        'metadata': {},
        'name': 'Alice card name',
        'tokenization_method': None,
        'fingerprint': 'abc'})


@pytest.fixture
def customer_json(customer_base_json):
    yield customer_base_json.copy()


@pytest.fixture
def mock_stripe_customer(customer_json, active_requests_mock):
    active_requests_mock.post('https://api.stripe.com/v1/customers',
                              json=customer_json)
    active_requests_mock.get(
        'https://api.stripe.com/v1/customers/cus_7UkUzpBtATnab9',
        text=json.dumps(customer_json))


@pytest.fixture
def customer(mock_stripe_customer, alice, org_with_payments):
    return alice.get_or_create_customer(org_with_payments)[0]


@pytest.fixture
def stripe_charge_from_source_json():
    """
    JSON response for a Stripe Charge.

    Based on stripe.Charge.create(amount=1000, currency='eur',
                                  source='tok_bypassPending', capture=False)
    """
    stripe_charge_count = 0

    class CallableReadOnlyDict(ReadOnlyDict):
        def __call__(self, request, context):
            """Create a Charge response with the amount that was given."""
            response = self.copy()

            if request._request.method == 'POST':
                # Use custom/incrementing stripe_id.
                nonlocal stripe_charge_count
                stripe_charge_count = stripe_charge_count + 1

                stripe_id = 'ch_fromsource_%d' % stripe_charge_count

                posted_body = dict(urllib.parse.parse_qsl(request.text))
                response['amount'] = int(posted_body['amount'])
                if 'source' in posted_body:
                    response['source']['id'] = posted_body['source']
                response['captured'] = posted_body['capture']
                response['customer'] = posted_body['customer']
            else:
                stripe_id = re.sub('^/v1/charges/', '', request.path)
                assert stripe_id

            response['id'] = stripe_id
            response['refunds']['url'].replace('ch_1BLXscHYHi8xLOaJ6Fkup2WZ',
                                               stripe_id)
            return response

    return CallableReadOnlyDict({
        'amount': 1000,
        'amount_refunded': 0,
        'application': 'ca_BJvTzxOFnn5jaDOvCW4wFKbO0YOhviGh',
        'application_fee': None,
        'balance_transaction': None,
        'captured': False,
        'created': 1510064202,
        'currency': 'eur',
        'customer': 'cus_7UkUzpBtATnab9',
        'description': None,
        'destination': None,
        'dispute': None,
        'failure_code': None,
        'failure_message': None,
        'fraud_details': {},
        'id': 'ch_1BLXscHYHi8xLOaJ6Fkup2WZ',
        'invoice': None,
        'livemode': False,
        'metadata': {},
        'object': 'charge',
        'on_behalf_of': None,
        'order': None,
        'outcome': {'network_status': 'approved_by_network',
                    'reason': None,
                    'risk_level': 'normal',
                    'seller_message': 'Payment complete.',
                    'type': 'authorized'},
        'paid': True,
        'receipt_email': None,
        'receipt_number': None,
        'refunded': False,
        'refunds': {'data': [],
                    'has_more': False,
                    'object': 'list',
                    'total_count': 0,
                    'url': '/v1/charges/ch_1BLXscHYHi8xLOaJ6Fkup2WZ/refunds'},
        'review': None,
        'shipping': None,
        'source': {'address_city': None,
                   'address_country': None,
                   'address_line1': None,
                   'address_line1_check': None,
                   'address_line2': None,
                   'address_state': None,
                   'address_zip': None,
                   'address_zip_check': None,
                   'brand': 'Visa',
                   'country': 'US',
                   'customer': 'cus_7UkUzpBtATnab9',
                   'cvc_check': None,
                   'dynamic_last4': None,
                   'exp_month': 4,
                   'exp_year': 2024,
                   'fingerprint': 'UsniBv13jz6VRKQT',
                   'funding': 'credit',
                   'id': 'card_1BIggxHYHi8xLOaJ0HhpO6L7',
                   'last4': '4242',
                   'metadata': {},
                   'name': None,
                   'object': 'card',
                   'tokenization_method': None},
        'source_transfer': None,
        'statement_descriptor': None,
        'status': 'succeeded',
        'transfer_group': None})


@pytest.fixture
def mock_stripe_customer_chargable(
        active_requests_mock, stripe_charge_from_source_json):

    active_requests_mock.post('https://api.stripe.com/v1/charges',
                              json=stripe_charge_from_source_json)


@pytest.fixture
def customer_chargable(mock_stripe_customer_chargable, customer):
    return customer


@pytest.fixture
def alice_card(customer, alice_card_json):
    from pinax.stripe.actions.sources import sync_card

    return sync_card(customer, alice_card_json)


@pytest.fixture
def plan():
    return Plan.objects.create(stripe_id='stripe_plan_id',
                               amount=1,
                               interval_count=1,
                               currency='eur')


@pytest.fixture
def second_stripe_plan(active_requests_mock):
    from velodrome.lock8.models import SubscriptionPlan

    plan = Plan.objects.create(
        stripe_id='second_stripe_plan_id',
        name='second_subscription_plan',
        amount=10,
        statement_descriptor='SECOND PLAN',
        trial_period_days=0,
        interval=SubscriptionPlan.MONTH,
        interval_count=1,
        metadata={},
        currency='eur')
    active_requests_mock.get(
        'https://api.stripe.com/v1/plans/second_stripe_plan_id', json={
            'id': plan.stripe_id,
            'object': 'plan',
            'amount': int(plan.amount * 100),
            'created': 1510562848,
            'currency': plan.currency,
            'interval': plan.interval,
            'interval_count': plan.interval_count,
            'livemode': False,
            'metadata': plan.metadata,
            'name': plan.name,
            'statement_descriptor': plan.statement_descriptor,
            'trial_period_days': plan.trial_period_days,
        })
    return plan


@pytest.fixture
def alice_subscription(customer, subscription_plan, active_requests_mock):
    """TODO: merge with subscription"""
    plan = subscription_plan.plan
    alice_subscription = Subscription.objects.create(
        stripe_id='sub_7fCa7LZ9yzao5d', customer=customer, plan=plan,
        quantity=1, status='active', start=NOW)
    subscription_json = {
        "id": alice_subscription.stripe_id,
        "object": "subscription",
        "application_fee_percent": None,
        "cancel_at_period_end": False,
        "canceled_at": None,
        "current_period_end": 1452854186,
        "current_period_start": 1451990186,
        "customer": "cus_7UkUzpBtATnab9",
        "discount": None,
        "ended_at": None,
        "metadata": {
        },
        "plan": {
            "id": "{}-org#177-monthly plan".format(settings.ENVIRONMENT),
            "object": "plan",
            "amount": 39,
            "created": 1449668959,
            "currency": "eur",
            "interval": "month",
            "interval_count": 2,
            "livemode": False,
            "metadata": {
            },
            "name": "monthly plan",
            "statement_descriptor": None,
            "trial_period_days": 10
        },
        "quantity": 2,
        "start": 1451990186,
        "status": "trialing",
        "tax_percent": None,
        "trial_end": 1452854186,
        "trial_start": 1451990186
    }
    active_requests_mock.get(
        'https://api.stripe.com/v1/subscriptions/sub_7fCa7LZ9yzao5d',
        json=subscription_json)
    return alice_subscription


@pytest.fixture
def lock(owner, org):
    from velodrome.lock8.models import Lock
    return Lock.objects.create(owner=owner,
                               organization=org,
                               counter=12,
                               serial_number='01020112',
                               imei='359785028015888',
                               iccid='89462046044000108788',
                               sid='f6cefb7474f291997c6a303031303888',
                               bleid='4c4f434b385f3030303030303130888',
                               randblock='a' * 2048)


@pytest.fixture
def active_lock(lock):
    if 'provision' in (t.name for t in lock.get_available_state_transitions()):
        lock.provision()
    lock.activate()
    return lock


@pytest.fixture
def another_lock(owner, another_org):
    from velodrome.lock8.models import Lock
    return Lock.objects.create(owner=owner,
                               organization=another_org,
                               counter=13,
                               serial_number='01010113',
                               imei='359785028015877',
                               iccid='89462046044000108671',
                               sid='f6cefb7474f291997c6a303031303836',
                               bleid='4c4f434b385f30303030303031303836',
                               randblock='b' * 2048,
                               )


@pytest.fixture
def lock2(owner, org):
    from velodrome.lock8.models import Lock
    return Lock.objects.create(owner=owner,
                               organization=org,
                               counter=14,
                               serial_number='_14',
                               imei='359785028015878',
                               iccid='89462046044000108672',
                               sid='f6cefb7474f291997c6a303031303837',
                               bleid='4c4f434b385f30303030303031303837',
                               randblock='c' * 2048)


@pytest.fixture
def lock3(owner, org):
    from velodrome.lock8.models import Lock
    return Lock.objects.create(owner=owner,
                               organization=org,
                               counter=15,
                               serial_number='_15',
                               imei='359785028015879',
                               iccid='89462046044000108673',
                               sid='f6cefb7474f291997c6a303031303838',
                               bleid='4c4f434b385f30303030303031303838',
                               randblock='c' * 2048)


@pytest.fixture
def lock4(owner, org):
    from velodrome.lock8.models import Lock
    return Lock.objects.create(owner=owner,
                               organization=org,
                               counter=16,
                               serial_number='_16',
                               imei='359785028015880',
                               iccid='89462046044000108674',
                               sid='f6cefb7474f291997c6a303031303839',
                               bleid='4c4f434b385f30303030303031303839',
                               randblock='c' * 2048)


@pytest.fixture
def lock5(owner, org):
    from velodrome.lock8.models import Lock
    return Lock.objects.create(owner=owner,
                               organization=org,
                               counter=17,
                               serial_number='_17',
                               imei='359785028015881',
                               iccid='89462046044000108675',
                               sid='f6cefb7474f291997c6a303031303840',
                               bleid='4c4f434b385f30303030303031303840',
                               randblock='c' * 2048)


@pytest.fixture
def axalock(org, owner, active_requests_mock, settings):
    from velodrome.lock8.models import AxaLock

    claim_code = uuid.uuid4()

    axa_lock = AxaLock.objects.create(
        organization=org,
        owner=owner,
        uid='134D90B794994B6753E7',
        claim_code_at_creation=claim_code,
    )
    active_requests_mock.register_uri(
        'POST',
        settings.KEY_SAFE_BASE_URI + '/locks',
        json={
            "now": "2016-01-12T22:27:27.675145+00:00",
            "result": {
                "created": "2016-01-11T20:29:02.866292",
                "firmware_modified": "2016-01-11T20:29:02.893996",
                "firmware_version": "1.00",
                "hardware_model": "PCB/eRL2",
                "hardware_version": "1.1",
                "id": 5785905063264256,
                "key": "ahFkZXZ-a2V5c2FmZS1jbG91ZHIRCxIETG9jaxiAgICAgMijCgw",
                "lock_model": "eRL",
                "lock_status": "active",
                "lock_uid": "c32a9cdf35194ddeb6f6",
                "lock_version": "1.0",
                "mac_address": "32453311fdaa",
                "modified": "2016-01-11T23:07:48.215889",
                "nr_of_slots": 3,
                "reference": None,
                "software_modified": "2016-01-11T20:29:03.699398",
                "software_version": "1.00"
            },
            "status": "success"})
    axa_lock.claim()
    return axa_lock


@pytest.fixture
def root_admin(db):
    from velodrome.lock8.models import User
    user, _ = User.objects.get_or_create(username='root_admin',
                                         email='development@lock8.me')
    user.is_superuser = True
    user.is_staff = True
    user.set_password('password')
    user.save()
    return user


@pytest.fixture
def drf_root_admin(root_admin):
    # performance optimization
    root_admin.is_admin_of_lock8 = True
    return get_drf_client_for_user(root_admin)


@pytest.fixture
def django_admin_user(admin_user):
    admin_user.is_superuser = False
    admin_user.is_staff = True
    admin_user.set_password('password')
    admin_user.save()
    return admin_user


@pytest.fixture
def debug_group(db):
    from django.contrib.auth.models import Group
    group, _ = Group.objects.get_or_create(name='Debug')
    return group


@pytest.fixture
def django_admin_client(django_admin_user):
    """A Django test client logged in as admin user of the lock8 org."""
    client = CustomClient()
    client.login(username=django_admin_user.username, password='password')
    client.user = django_admin_user
    return client


@pytest.fixture
def django_admin_rf(admin_user):
    class RequestFactoryWithUser(django.test.client.RequestFactory):
        def __init__(self, *args, **kwargs):
            self.user = kwargs.pop('user')
            super().__init__(*args, **kwargs)

        def request(self, **request):
            r = super().request(**request)
            r.user = self.user
            return r

    def rf(user=None):
        return RequestFactoryWithUser(user=user if user else admin_user)
    return rf


@pytest.fixture
def root_org(request, db, root_admin):
    from velodrome.lock8.models import (
        FeedbackCategory, Organization, OrganizationPreference,
    )
    try:
        org = Organization.objects.get(level=0)
    except Organization.DoesNotExist:
        from velodrome.lock8.migration_utils import (
            create_root_org, create_root_feedback_categories,
            set_root_org_values
        )
        org = create_root_org(Organization, root_admin)
        create_root_feedback_categories(Organization, FeedbackCategory)
        org.refresh_from_db()
        set_root_org_values(org, root_admin, OrganizationPreference)
        org.refresh_from_db()
    else:
        # Set cache for get_root_org for predictable tests.
        Organization._root_org = org
    return org


@pytest.fixture
def admin_user(request, root_org):
    from velodrome.lock8.models import Affiliation, User
    user = User.objects.create(username=request.fixturename,
                               email='{}@lock8.me'.format(request.fixturename))
    Affiliation.objects.create(user=user,
                               organization=root_org,
                               role='admin')
    return user


@pytest.fixture
def admin_user_of_org(request, org):
    from velodrome.lock8.models import Affiliation, User
    user = User.objects.create(username=request.fixturename,
                               email='{}@lock8.me'.format(request.fixturename))
    Affiliation.objects.create(user=user,
                               organization=org,
                               role='admin')
    return user


@pytest.fixture
def bicycle_types(root_admin):
    from velodrome.lock8.migration_utils import create_bicycle_types
    from velodrome.lock8.models import BicycleType
    create_bicycle_types(BicycleType, root_admin)


@pytest.fixture
def city_bike(bicycle_types):
    from velodrome.lock8.models import BicycleType
    return BicycleType.objects.get(reference='city_bike')


@pytest.fixture
def bicycle_model(request, owner, org, city_bike):
    from velodrome.lock8.models import BicycleModel, FeedbackCategory
    return BicycleModel.objects.create(
        organization=org,
        owner=owner,
        type=city_bike,
        feedback_auto_escalate_severity=FeedbackCategory.SEVERITY_MEDIUM,
        name=request.fixturename)


@pytest.fixture
def another_bicycle_model(request, owner, another_org, city_bike):
    from velodrome.lock8.models import BicycleModel
    return BicycleModel.objects.create(
        organization=another_org,
        owner=owner,
        type=city_bike,
        name=request.fixturename)


@pytest.fixture
def bicycles_with_models(bicycle_model, bicycle, bicycle_without_lock):
    bicycles = bicycle, bicycle_without_lock
    for bicycle in bicycles:
        bicycle.model = bicycle_model
        bicycle.save()
    return bicycles


@pytest.fixture
def bmmr_recurring(bicycle_model, bicycles_with_models, today):
    from velodrome.lock8.models import (
        BicycleModelMaintenanceRule, FeedbackCategory
    )
    return BicycleModelMaintenanceRule.objects.create(
        bicycle_model=bicycle_model,
        description='foo',
        recurring_time=timedelta(days=5),
        severity=FeedbackCategory.SEVERITY_MEDIUM
    )


@pytest.fixture
def bmmr_fixed(bicycle_model, bicycles_with_models, today):
    from velodrome.lock8.models import (
        BicycleModelMaintenanceRule, FeedbackCategory
    )
    return BicycleModelMaintenanceRule.objects.create(
        bicycle_model=bicycle_model,
        description='bar',
        fixed_date=today + timedelta(days=15),
        severity=FeedbackCategory.SEVERITY_MEDIUM
    )


@pytest.fixture
def bmmr_distance(bicycle_model, bicycles_with_models, today):
    from velodrome.lock8.models import (
        BicycleModelMaintenanceRule, FeedbackCategory
    )
    return BicycleModelMaintenanceRule.objects.create(
        bicycle_model=bicycle_model,
        description='baz', distance=666,
        severity=FeedbackCategory.SEVERITY_LOW
    )


@pytest.fixture
def bicycle_without_lock(request, owner, org):
    from velodrome.lock8.models import Bicycle
    return Bicycle.objects.create(organization=org,
                                  owner=owner,
                                  name=request.fixturename)


@pytest.fixture
def bicycle(request, owner, org, lock):
    from velodrome.lock8.models import Bicycle
    if 'provision' in (t.name for t in lock.get_available_state_transitions()):
        lock.provision()
    return Bicycle.objects.create(organization=org,
                                  owner=owner,
                                  lock=lock,
                                  name=request.fixturename,
                                  serial_number=request.fixturename,
                                  )


@pytest.fixture
def bicycle2(request, owner, org, lock2):
    from velodrome.lock8.models import Bicycle
    lock2.provision()
    return Bicycle.objects.create(organization=org,
                                  owner=owner,
                                  lock=lock2,
                                  name=request.fixturename,
                                  serial_number=request.fixturename,
                                  )


@pytest.fixture
def bicycle3(request, owner, org, lock3):
    from velodrome.lock8.models import Bicycle
    lock3.provision()
    return Bicycle.objects.create(organization=org,
                                  owner=owner,
                                  lock=lock3,
                                  name=request.fixturename,
                                  serial_number=request.fixturename,
                                  )


@pytest.fixture
def bicycle4(request, owner, org, lock4):
    from velodrome.lock8.models import Bicycle
    lock4.provision()
    return Bicycle.objects.create(organization=org,
                                  owner=owner,
                                  lock=lock4,
                                  name=request.fixturename,
                                  serial_number=request.fixturename,
                                  )


@pytest.fixture
def bicycle5(request, owner, org, lock5):
    from velodrome.lock8.models import Bicycle
    lock5.provision()
    return Bicycle.objects.create(organization=org,
                                  owner=owner,
                                  lock=lock5,
                                  name=request.fixturename,
                                  serial_number=request.fixturename,
                                  )


@pytest.fixture
def bicycle_available(active_lock, bicycle):
    bicycle.declare_available()
    return bicycle


@pytest.fixture
def bicycle_rented(bicycle, renter):
    bicycle.declare_available()
    bicycle.rent(by=renter)
    return bicycle


@pytest.fixture
def another_bicycle(owner, another_org, another_lock):
    from velodrome.lock8.models import Bicycle
    another_lock.provision()
    return Bicycle.objects.create(organization=another_org,
                                  owner=owner,
                                  lock=another_lock)


@pytest.fixture
def axa_bicycle(request, owner, org, axalock):
    from velodrome.lock8.models import Bicycle
    return Bicycle.objects.create(organization=org,
                                  owner=owner,
                                  axa_lock=axalock,
                                  name=request.fixturename,
                                  serial_number=request.fixturename)


@pytest.fixture
def address(request, owner, org):
    from velodrome.lock8.models import Address
    return Address.objects.create(organization=org,
                                  owner=owner,
                                  text_address=request.fixturename)


def get_image(image_ext):
    image_path = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                              'tests/media',
                              '14577625967_b1ee16fd4f_q.{}'.format(image_ext))
    return open(image_path, 'rb')


@pytest.fixture
def image(image_ext):
    with get_image(image_ext) as open_file:
        yield ImageFile(
            open_file,
            name='photos/14577625967_b1ee16fd4f_q.{}'.format(image_ext))


@pytest.fixture
def b64_image(image_ext):
    with get_image(image_ext) as open_file:
        return base64.b64encode(open_file.read()).decode()


@pytest.fixture
def photo(image, org, owner):
    from velodrome.lock8.models import Photo

    return Photo.objects.create(
        organization=org,
        owner=owner,
        image=image,
    )


@pytest.fixture
def another_photo(image, another_org, owner):
    from velodrome.lock8.models import Photo

    return Photo.objects.create(
        organization=another_org,
        owner=owner,
        image=image,
    )


@pytest.fixture
def fb_bicycle_file():
    path = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                        'tests/media',
                        'FB_test_bulk_import.xlsx')
    with open(path, 'rb') as open_file:
        yield open_file


@pytest.fixture
def lock_bleid_list_file():
    path = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                        'tests/media', 'bulk_lock_org_update.xlsx')
    with open(path, 'rb') as open_file:
        yield open_file


@pytest.fixture
def lock_bleid_list_error_file():
    path = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                        'tests/media', 'bulk_lock_org_update_error.xlsx')
    with open(path, 'rb') as open_file:
        yield open_file


@pytest.fixture
def generic_bicycle_file():
    path = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                        'tests/media',
                        'generic_bicycle_import.xlsx')
    with open(path, 'rb') as open_file:
        yield open_file


@pytest.fixture
def generic_bicycle_error_file():
    path = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                        'tests/media',
                        'generic_bicycle_import_error.xlsx')
    with open(path, 'rb') as open_file:
        yield open_file


@pytest.fixture
def assign_devices_to_bicycles_file():
    path = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                        'tests/media',
                        'assign_devices_to_bicycles.xlsx')
    with open(path, 'rb') as open_file:
        yield open_file


@pytest.fixture
def assign_devices_to_bicycles_error_file():
    path = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                        'tests/media',
                        'assign_devices_to_bicycles_error.xlsx')
    with open(path, 'rb') as open_file:
        yield open_file


@pytest.fixture
def claim_axa_locks_file():
    path = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                        'tests/media/claim_axa_locks.xlsx')
    with open(path, 'rb') as open_file:
        yield open_file


@pytest.fixture
def claim_axa_locks_error_file():
    path = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                        'tests/media/claim_axa_locks_error.xlsx')
    with open(path, 'rb') as open_file:
        yield open_file


@pytest.fixture
def tracking(lock):
    from velodrome.lock8.models import Tracking
    attributes = {
        'time_stamp': timezone.now().timestamp(),
        'serial_number': lock.serial_number,
    }
    return Tracking.objects.create(attributes=attributes,
                                   tracking_type=Tracking.GPS_LOCATION_MESSAGE)


@pytest.fixture
def writable_trackings_db(mocker, db, multi_db):
    @contextlib.contextmanager
    def writable_cm():
        from django.conf import settings
        from velodrome.lock8.db_routers import LoadBalancerRouter

        def db_for_write(self, model, **hints):
            if model._meta.model_name in ('readonlytracking', 'trip'):
                return settings.TRACKINGS_DB
            return 'default'  # pragma: no cover
        with mocker.mock_module.patch.object(LoadBalancerRouter,
                                             'db_for_write', db_for_write):
            yield
    return writable_cm


@pytest.fixture
def get_readonlytracking(writable_trackings_db, lock):
    from velodrome.lock8.models import ReadonlyTracking

    def inner(lock, **kwargs):
        attributes = {'time_stamp': timezone.now().timestamp(),
                      'serial_number': lock.serial_number}
        with writable_trackings_db():
            return ReadonlyTracking.objects.create(
                uuid=uuid.uuid4(),
                timestamp=timezone.now(),
                attributes=attributes,
                **kwargs)
    return inner


@pytest.fixture
def readonlytracking(get_readonlytracking, lock):
    from velodrome.lock8.models import Tracking

    return get_readonlytracking(lock, **{
        'point': Point([-73.961900369117, 40.7874455]),
        'tracking_type': Tracking.GPS_LOCATION_MESSAGE
    })


@pytest.fixture
def readonlytracking_dss(get_readonlytracking, lock):
    from velodrome.lock8.models import Tracking

    return get_readonlytracking(lock, **{
        'tracking_type': Tracking.DEVICE_SYSTEM_STATUS_MESSAGE
    })


@pytest.fixture
def get_trip(writable_trackings_db, bicycle):
    from velodrome.lock8.models import Trip

    def inner(bicycle, **kwargs):
        options = {
            'uuid': uuid.uuid4(),
            'is_valid': True,
            'bicycle_uuid': bicycle.uuid,
            'start_date': (timezone.now() - timedelta(minutes=15, seconds=1)),
            'end_date': (timezone.now() - timedelta(seconds=1)),
            'duration': dt.timedelta(minutes=15),
            'distance_m': 5000,
            'organization_uuid': bicycle.organization.uuid,
            'asset_state': Trip.ASSET_IN_SERVICE,
            'type': Trip.TYPE_REGULAR
        }
        options.update(**kwargs)
        with writable_trackings_db():
            return Trip.objects.create(**options)
    return inner


@pytest.fixture
def trip(get_trip, bicycle):
    return get_trip(bicycle)


@pytest.fixture
def writable_trip(writable_trackings_db, trip):
    with writable_trackings_db():
        yield trip


@pytest.fixture
def unfinished_trip(get_trip, bicycle):
    return get_trip(bicycle,
                    duration=None,
                    end_date=None,
                    is_valid=None,
                    route=None)


@pytest.fixture
def another_trip(writable_trackings_db, bicycle, another_org):
    from velodrome.lock8.models import Trip

    with writable_trackings_db():
        return Trip.objects.create(
            uuid=uuid.uuid4(),
            is_valid=True,
            bicycle_uuid=bicycle.uuid,
            start_date=(timezone.now() - timedelta(minutes=15, seconds=1)),
            end_date=(timezone.now() - timedelta(seconds=1)),
            duration=dt.timedelta(minutes=15),
            distance_m=5000,
            organization_uuid=another_org.uuid,
            asset_state=Trip.ASSET_IN_SERVICE,
            type=Trip.TYPE_REGULAR)


@pytest.fixture
def trip_without_duration(writable_trackings_db, bicycle, org):
    from velodrome.lock8.models import Trip

    with writable_trackings_db():
        return Trip.objects.create(
            uuid=uuid.uuid4(),
            is_valid=False,
            bicycle_uuid=bicycle.uuid,
            start_date=(timezone.now() - timedelta(minutes=5)),
            end_date=(timezone.now() - timedelta(seconds=1)),
            distance_m=100,
            organization_uuid=org.uuid,
            asset_state=Trip.ASSET_IN_SERVICE,
            type=Trip.TYPE_REGULAR)


@pytest.fixture
def trip_with_invalid_bicycle(writable_trackings_db, org):
    from velodrome.lock8.models import Trip

    invalid_uuid = uuid.uuid4()
    with writable_trackings_db():
        return Trip.objects.create(
            uuid=uuid.uuid4(),
            is_valid=True,
            bicycle_uuid=invalid_uuid,
            start_date=(timezone.now() - timedelta(minutes=4)),
            end_date=(timezone.now() - timedelta(seconds=2)),
            distance_m=123,
            organization_uuid=org.uuid,
            asset_state=Trip.ASSET_IN_SERVICE,
            type=Trip.TYPE_REGULAR)


@pytest.fixture
def trip_brandenburger_tor_2_siegessaeule(writable_trackings_db, bicycle, org):
    from velodrome.lock8.models import Trip

    route = LineString(*BIKELINES['brandenbuger_tor_2_siegessaeule'])
    with writable_trackings_db():
        return Trip.objects.create(
            uuid=uuid.uuid4(),
            organization_uuid=org.uuid,
            is_valid=True,
            bicycle_uuid=bicycle.uuid,
            start_date=(timezone.now() - timedelta(minutes=15, seconds=1)),
            end_date=(timezone.now() - timedelta(seconds=1)),
            duration=dt.timedelta(minutes=15),
            distance_m=1893,
            route=route,
            snapped_route=route,
            asset_state=Trip.ASSET_IN_SERVICE,
            type=Trip.TYPE_REGULAR)


@pytest.fixture
def gps_tracking(lock, middle_of_somewhere, create_gps_tracking):
    return create_gps_tracking(lock, *middle_of_somewhere)


def assign_trackings(self, message, tracking_type):
    from velodrome.lock8.models import (
        PUBLIC_LOCKSTATES, Bicycle, PrivateTracking, PublicTracking, Tracking)

    if message.get('time_stamp') is None:
        timestamp = timezone.now()
    else:
        timestamp = dt.datetime.fromtimestamp(
            float(message['time_stamp']), tz=dt.timezone.utc)
    if self.private_tracking is None:
        self.private_tracking = PrivateTracking.objects.create(
            attributes=message)
    else:
        if self.private_tracking.timestamp is not None:
            if tracking_type == Tracking.GPS_LOCATION_MESSAGE:
                compare_ts = self.private_tracking.gps_timestamp
            else:
                compare_ts = self.private_tracking.timestamp
            if compare_ts is not None and timestamp < compare_ts:
                return
        self.private_tracking.attributes.update(message)
    save = ['private_tracking']

    if isinstance(self, Bicycle):
        lock = self.lock
        if lock is None:
            return
    else:
        lock = self

    if lock.state in PUBLIC_LOCKSTATES:
        if self.public_tracking is None:
            self.public_tracking = PublicTracking.objects.create(
                attributes=message)
        else:
            self.public_tracking.attributes.update(message)
        save += ['public_tracking']

    if tracking_type == Tracking.GPS_LOCATION_MESSAGE:
        for t in save:
            getattr(self, t).gps_timestamp = timestamp

    for t in save:
        with disable_concurrency(t):
            getattr(self, t).save()

    with revisions.create_revision(manage_manually=True):
        with disable_concurrency(self):
            self.save(update_fields=['modified'] + save)


def ingest_tracking(payload):
    from .models import (
        BaseTracking, Bicycle, DeviceEvents, DeviceLockStatus, Lock,
        LockLockedStates)

    message = payload['message']
    serial_number = message['serial_number']
    tracking_type = payload['type']

    if (tracking_type == BaseTracking.GPS_LOCATION_MESSAGE and
            message.get('time_stamp') is not None and
            message.get('time_stamp') > (
                timezone.now() + settings.DISCARD_FUTURE_TRACKING_DURATION
            ).timestamp()):
        # discard trackings too far in future
        return
    lock = Lock.objects.select_for_update().get(serial_number=serial_number)

    try:
        bicycle = Bicycle.objects.select_for_update().get(lock=lock)
    except Bicycle.DoesNotExist:
        bicycle = None

    event = message.get('event')

    if event == DeviceEvents.INIT.value:
        states = lock.get_available_state_transitions()
        if 'provision' in (s.name for s in states):
            lock.provision()

    assign_trackings(lock, message, tracking_type)
    if bicycle is not None:
        assign_trackings(bicycle, message, tracking_type)

    firmware_version_tag = message.get('firmware_version_tag')
    if (firmware_version_tag is not None and
            lock.firmware_versions.get('mercury') !=
            firmware_version_tag):
        lock.firmware_versions['mercury'] = firmware_version_tag
        lock.save(update_fields=('firmware_versions', 'modified'))

    if tracking_type == BaseTracking.DEVICE_SYSTEM_STATUS_MESSAGE:
        lock_status = message.get('lock_status')
        if (event == DeviceEvents.LOCKING.value and
                lock_status == DeviceLockStatus.LOCKED.value and
                lock.locked_state == LockLockedStates.UNLOCKED.value):
            lock.lock()
        elif (event == DeviceEvents.LOCKING.value and
                lock_status == DeviceLockStatus.UNLOCKED.value and
                lock.locked_state == LockLockedStates.LOCKED.value):
            lock.unlock()


@pytest.fixture
def create_gps_tracking(writable_trackings_db):
    def inner(bicycle_or_lock, longitude, latitude, time_stamp=None,
              attributes=None, activate=True, declare_available=True):
        from velodrome.lock8.models import (GPS_LOCATION_MESSAGE, Bicycle,
                                            ReadonlyTracking)
        if isinstance(bicycle_or_lock, Bicycle):
            bicycle = bicycle_or_lock
            lock = bicycle.lock
        else:
            lock = bicycle_or_lock
            try:
                bicycle = lock.bicycle
            except Bicycle.DoesNotExist:
                bicycle = None

        if activate and 'activate' in (
                t.name for t in lock.get_available_state_transitions()):
            lock.activate()
        if (bicycle is not None and declare_available and
                'declare_available' in (
                    t.name for t in bicycle.get_available_state_transitions()
                )):
            bicycle.declare_available()

        if time_stamp is None:
            time_stamp = timezone.now().timestamp()
        attributes = dict({
            'serial_number': lock.serial_number,
            'time_stamp': time_stamp,
            'gps_longitude': longitude * 1e6,
            'gps_latitude': latitude * 1e6}, **(
                attributes if attributes else {}))

        tracking_kwargs = {
            'uuid': uuid.uuid4(),
            'timestamp': dt.datetime.fromtimestamp(attributes['time_stamp'],
                                                   tz=dt.timezone.utc),
            'bicycle_uuid': bicycle.uuid if bicycle is not None else None,
            'organization_uuid': lock.organization.uuid,
            'attributes': attributes,
            'tracking_type': GPS_LOCATION_MESSAGE,
            'point': Point(longitude, latitude),
        }
        with writable_trackings_db():
            tracking = ReadonlyTracking.objects.create(**tracking_kwargs)
        ingest_tracking({'message': attributes,
                         'type': GPS_LOCATION_MESSAGE,
                         '_timestamp': timezone.now().timestamp(),
                         '_uuid': str(uuid.uuid4())})
        if bicycle is not None:
            bicycle.refresh_from_db()
        lock.refresh_from_db()
        return tracking
    return inner


@pytest.fixture
def create_dss_tracking(writable_trackings_db):
    def inner(bicycle_or_lock, state_of_charge, event=None, time_stamp=None,
              attributes=None,
              activate=True, declare_available=True):
        from velodrome.lock8.models import (
            DEVICE_SYSTEM_STATUS_MESSAGE, DeviceEvents, Bicycle,
            ReadonlyTracking)

        if isinstance(bicycle_or_lock, Bicycle):
            bicycle = bicycle_or_lock
            lock = bicycle.lock
        else:
            lock = bicycle_or_lock
            try:
                bicycle = lock.bicycle
            except Bicycle.DoesNotExist:
                bicycle = None

        if activate and 'activate' in (
                t.name for t in lock.get_available_state_transitions()):
            lock.activate()
        if (bicycle is not None and declare_available and
                'declare_available' in (
                    t.name for t in bicycle.get_available_state_transitions()
                )):
            bicycle.declare_available()
        if event is None:
            event = DeviceEvents.CYCLING_STARTED.value
        if time_stamp is None:
            time_stamp = timezone.now().timestamp()
        attributes = dict({
            'serial_number': lock.serial_number,
            'time_stamp': time_stamp,
            'event': event}, **(attributes if attributes else {}))
        if state_of_charge is not None:
            attributes['state_of_charge'] = state_of_charge

        tracking_kwargs = {
            'uuid': uuid.uuid4(),
            'timestamp': dt.datetime.fromtimestamp(attributes['time_stamp'],
                                                   tz=dt.timezone.utc),
            'bicycle_uuid': bicycle.uuid if bicycle is not None else None,
            'organization_uuid': lock.organization.uuid,
            'attributes': attributes,
            'tracking_type': DEVICE_SYSTEM_STATUS_MESSAGE,
        }
        with writable_trackings_db():
            tracking = ReadonlyTracking.objects.create(**tracking_kwargs)
        ingest_tracking({'message': attributes,
                         'type': DEVICE_SYSTEM_STATUS_MESSAGE,
                         '_uuid': str(uuid.uuid4()),
                         '_timestamp': timezone.now().timestamp()
                         })
        if bicycle is not None:
            bicycle.refresh_from_db()
        lock.refresh_from_db()
        return tracking
    return inner


@pytest.fixture
def gps_tracking_on_bicycle(bicycle, gps_tracking):
    bicycle.refresh_from_db()
    return gps_tracking


@pytest.fixture
def invitation(org, alice, owner):
    from velodrome.lock8.models import Invitation
    return Invitation.objects.create(
        organization=org,
        email=alice.email,
        owner=owner,
    )


@pytest.fixture
def refresh_token(alice):
    from refreshtoken.models import RefreshToken
    return RefreshToken.objects.create(
        user=alice,
        app='test',
    )


@pytest.fixture(scope='session')
def central_park():
    """
    http://nominatim.openstreetmap.org/
        search/central%20park?polygon=1&format=xml
    """
    return MultiPolygon([Polygon([Point(list(map(float, point))) for point in
                         [["-73.981297", "40.7685782"],
                          ["-73.9812421", "40.7686381"],
                          ["-73.980821", "40.7692536"],
                          ["-73.9783707", "40.7726211"],
                          ["-73.9770964", "40.7743723"],
                          ["-73.9757383", "40.7762391"],
                          ["-73.9582983", "40.8002063"],
                          ["-73.9581209", "40.8002149"],
                          ["-73.9580083", "40.8002271"],
                          ["-73.9578826", "40.8002631"],
                          ["-73.9577669", "40.8003367"],
                          ["-73.9577186", "40.8003814"],
                          ["-73.9497095", "40.7969917"],
                          ["-73.9497162", "40.7969425"],
                          ["-73.9497166", "40.7968837"],
                          ["-73.9497186", "40.796838"],
                          ["-73.9497075", "40.7967616"],
                          ["-73.9496757", "40.7966888"],
                          ["-73.9496292", "40.7966412"],
                          ["-73.949557", "40.79659"],
                          ["-73.9628768", "40.778301"],
                          ["-73.9632625", "40.7777714"],
                          ["-73.9633108", "40.7777148"],
                          ["-73.9724948", "40.7650918"],
                          ["-73.9732367", "40.7653987"],
                          ["-73.9737104", "40.7647739"],
                          ["-73.9793668", "40.767163"],
                          ["-73.9810177", "40.7678443"],
                          ["-73.9809824", "40.7678988"],
                          ["-73.9809708", "40.7679534"],
                          ["-73.9809571", "40.7680187"],
                          ["-73.9808932", "40.7680086"],
                          ["-73.9808901", "40.7680668"],
                          ["-73.9808879", "40.7681073"],
                          ["-73.9809092", "40.7682121"],
                          ["-73.9808826", "40.7682181"],
                          ["-73.9809079", "40.7682967"],
                          ["-73.9809212", "40.7682936"],
                          ["-73.9809651", "40.7684004"],
                          ["-73.9810568", "40.7683631"],
                          ["-73.9810728", "40.7683834"],
                          ["-73.9811233", "40.7684477"],
                          ["-73.9811991", "40.7685112"],
                          ["-73.981297", "40.7685782"]]])])


@pytest.fixture(scope='session')
def somewhere():
    return MultiPolygon([Polygon([Point(list(map(float, point))) for point in
                         [["0", "1"],
                          ["1", "2"],
                          ["2", "1"],
                          ["0", "1"],
                          ]])])


@pytest.fixture(scope='session')
def middle_of_somewhere():
    return Point([1.0, 1.5])


@pytest.fixture(scope='session')
def middle_of_central_park():
    return Point([-73.961900369117, 40.7874455], srid=4326)


@pytest.fixture
def middle_of_theodore_roosevelt_park():
    """
    This is next to central park. few meters away.
    """
    return Point(-73.97479, 40.78159)


@pytest.fixture
def side_of_thedore_roosevelt_park():
    """Right next to the center of Theodore Roosevelt Park"""
    return Point(-73.9753611, 40.782553)


@pytest.fixture
def zone(central_park, org, owner):
    from velodrome.lock8.models import Zone

    return Zone.objects.create(
        organization=org,
        owner=owner,
        name='Central Park',
        polygon=central_park,
        low_threshold=1,
        high_threshold=10
    )


@pytest.fixture
def another_zone(central_park, another_org, owner):
    from velodrome.lock8.models import Zone

    return Zone.objects.create(
        organization=another_org,
        owner=owner,
        name='Central Park',
        polygon=central_park)


@pytest.fixture
def maintenance_zone(somewhere, org, owner):
    from velodrome.lock8.models import Zone

    return Zone.objects.create(
        organization=org,
        owner=owner,
        name='Somewhere [maintenance]',
        polygon=somewhere,
        type=Zone.MAINTENANCE,
    )


@pytest.fixture
def zone2(central_park, org, owner):
    from velodrome.lock8.models import Zone

    return Zone.objects.create(type=Zone.SERVICE,
                               organization=org,
                               owner=owner,
                               name='Central Park (Service)',
                               polygon=central_park)


@pytest.fixture
def zone_somewhere(somewhere, org, owner):
    from velodrome.lock8.models import Zone

    return Zone.objects.create(
        organization=org,
        owner=owner,
        name='Somewhere',
        polygon=somewhere)


@pytest.fixture
def renting_scheme(org, owner):
    from velodrome.lock8.models import RentingScheme

    return RentingScheme.objects.create(
        organization=org,
        owner=owner,
        max_reservation_duration=timedelta(minutes=15),
    )


@pytest.fixture
def another_renting_scheme(another_org, owner):
    from velodrome.lock8.models import RentingScheme

    return RentingScheme.objects.create(
        organization=another_org,
        owner=owner,
        max_reservation_duration=timedelta(minutes=20),
    )


@pytest.fixture
def dss_tracking(lock, create_dss_tracking):
    create_dss_tracking(lock, 98.587890625,
                        event=10,
                        attributes={'voltage': '4320',
                                    'firmware_version_tag': '1.1.3'})


# A list of GPS lines (bike tracks).
# TODO: This needs to be cleaned up / generalized..
BIKELINES = {
    # Known distance between Brandenbuger Tor and Siegessäule.
    # 1.893 km(?).  One track.  Two Trips.
    'brandenbuger_tor_2_siegessaeule': (
        (13.377850, 52.516260),  # brandenburger
        (13.371870, 52.515970),  # pause
        (13.371860, 52.515930),  # pause
        (13.371850, 52.515990),  # pause
        (13.371820, 52.515930),  # pause
        (13.359307, 52.515254),  # waypoint
        (13.350060, 52.514500),),  # siegessäule
    'kitkat_to_office': (
        (13.41742, 52.51038), (13.41732, 52.51041),
        (13.4173, 52.51044), (13.4173, 52.51047),
        (13.41746, 52.51073), (13.41644, 52.51097),
        (13.41689, 52.51186), (13.41719, 52.51245),
        (13.41763, 52.5134), (13.4177, 52.51364),
        (13.41775, 52.51369), (13.41779, 52.51393),
        (13.41803, 52.51497), (13.41815, 52.5154),
        (13.41824, 52.51566), (13.41829, 52.5165),
        (13.41828, 52.51695), (13.41819, 52.51743),
        (13.41809, 52.51775), (13.41795, 52.51807),
        (13.41771, 52.5185), (13.41733, 52.51899),
        (13.4169, 52.51946), (13.41649, 52.51983),
        (13.41604, 52.52021), (13.41574, 52.52049),
        (13.41537, 52.5208), (13.41516, 52.52102),
        (13.41534, 52.52117), (13.41585, 52.52163),
        (13.41621, 52.52201), (13.41536, 52.52244),
        (13.41514, 52.52255), (13.41266, 52.52369),
        (13.41228, 52.52385), (13.41213, 52.52388),
        (13.41132, 52.52391), (13.40964, 52.52398),
        (13.40919, 52.52407), (13.4088, 52.52421),
        (13.40714, 52.52481), (13.40691, 52.52487),
        (13.4066, 52.52492), (13.40627, 52.52494),
        (13.40609, 52.525), (13.40378, 52.52604),
        (13.40368, 52.52607), (13.40365, 52.52615),
        (13.40348, 52.52676), (13.40326, 52.52721),
        (13.403, 52.52754)),
}


@pytest.fixture
def dt2016():
    dt2016 = dt.datetime(2016, 6, 1, 20, 15, 42, 32, tzinfo=dt.timezone.utc)
    with freeze_time(dt2016):
        yield dt2016


@pytest.fixture
def at_2000():
    time = timezone.now().replace(hour=20, minute=0, second=0)
    with freeze_time(time):
        yield time


@pytest.fixture
def at_1900():
    time = timezone.now().replace(hour=19, minute=0, second=0)
    with freeze_time(time):
        yield time


@pytest.fixture
def yesterday():
    time = NOW - timedelta(days=1)
    with freeze_time(time):
        yield time


@pytest.fixture
def today():
    with freeze_time(NOW):
        yield NOW


def create_trackings(pytest_request, bicycle, create_gps_tracking):
    """Create a list of trackings for the given line of points."""
    name = pytest_request.fixturename
    line = BIKELINES[name]
    delta = timedelta(seconds=10)

    start = timezone.now()

    for index, point in enumerate(line, start=1):
        create_gps_tracking(bicycle, *point,
                            time_stamp=(start + delta * index).timestamp())


@pytest.fixture
def kitkat_to_office(request, bicycle, create_gps_tracking):
    return create_trackings(request, bicycle, create_gps_tracking)


@pytest.fixture
def gps_tracking_seven_days(lock, create_gps_tracking, middle_of_somewhere):
    for index in range(1, 8):
        hours = 1
        while True:
            create_gps_tracking(
                lock, *middle_of_somewhere,
                attributes={'time_stamp': (timezone.now() - timedelta(
                    days=index, hours=hours)).timestamp()})
            if index % 2 == 0 and hours:
                hours = 0
                continue
            else:
                hours = 1
                break


@pytest.fixture
def organization_preference(request, org, owner):
    from velodrome.lock8.models import Alert, OrganizationPreference

    return OrganizationPreference.objects.create(
        owner=owner,
        organization=org,
        name=request.fixturename,
        allowed_email_alert_types=[t for t, _ in Alert.TYPES],
        currency='usd',
    )


@pytest.fixture
def another_organization_preference(request, another_org, owner):
    from velodrome.lock8.models import Alert, OrganizationPreference

    return OrganizationPreference.objects.create(
        owner=owner,
        organization=another_org,
        name=request.fixturename,
        allowed_email_alert_types=[t for t, _ in Alert.TYPES],
        currency='eur',
    )


@pytest.fixture
def alert(request, org, lock, owner):
    from velodrome.lock8.models import Affiliation, Alert
    return Alert.objects.create(
        organization=org,
        alert_type=Alert.LOW_BATTERY,
        causality=lock,
        roles=[Affiliation.FLEET_OPERATOR],
        message=request.fixturename,
        owner=owner,
    )


@pytest.fixture(params=('high_threshold', 'low_threshold'))
def alert_zone_threshold(request, org, zone, owner):
    from velodrome.lock8.models import Affiliation, Alert

    return Alert.objects.create(
        organization=org,
        alert_type=Alert.ZONE_HIGH_THRESHOLD_TRIGGERED
        if request.param == 'high_threshold'
        else Alert.ZONE_LOW_THRESHOLD_TRIGGERED,
        causality=zone,
        roles=[Affiliation.FLEET_OPERATOR],
        message=request.fixturename,
        owner=owner,
    )


@pytest.fixture
def alert_stolen_bicycle(request, org, bicycle):
    from velodrome.lock8.models import Affiliation, Alert
    return Alert.objects.create(
        organization=org,
        alert_type=Alert.BICYCLE_STOLEN,
        causality=bicycle,
        roles=[Affiliation.FLEET_OPERATOR],
        message=request.fixturename,
    )


@pytest.fixture
def alert2(request, org, lock2):
    from velodrome.lock8.models import Affiliation, Alert
    return Alert.objects.create(
        organization=org,
        alert_type=Alert.LOW_BATTERY,
        causality=lock2,
        roles=[Affiliation.FLEET_OPERATOR],
        message=request.fixturename,
    )


@pytest.fixture
def alert_wo_bicycle(request, org, lock):
    from velodrome.lock8.models import Affiliation, Alert
    return Alert.objects.create(
        organization=org,
        alert_type=Alert.LOW_BATTERY,
        causality=lock,
        roles=[Affiliation.FLEET_OPERATOR],
        message=request.fixturename,
    )


@pytest.fixture
def alert_lost_bicycle_reported(request, org, bicycle):
    from velodrome.lock8.models import Affiliation, Alert
    return Alert.objects.create(
        organization=org,
        alert_type=Alert.LOST_BICYCLE_REPORTED,
        causality=bicycle,
        roles=[Affiliation.FLEET_OPERATOR],
        message=request.fixturename,
    )


@pytest.fixture
def another_alert(request, another_org, another_lock):
    from velodrome.lock8.models import Affiliation, Alert
    return Alert.objects.create(
        organization=another_org,
        alert_type=Alert.LOW_BATTERY,
        causality=another_lock,
        roles=[Affiliation.FLEET_OPERATOR],
        message=request.fixturename,
    )


@pytest.fixture
def alert_too_long_idle(request, org, bicycle):
    from velodrome.lock8.models import Affiliation, Alert
    return Alert.objects.create(
        organization=org,
        alert_type=Alert.BICYCLE_IDLE_FOR_TOO_LONG,
        causality=bicycle,
        roles=[Affiliation.FLEET_OPERATOR],
        message=request.fixturename,
    )


@pytest.fixture
def alert_ride_outside_service_area(request, org, bicycle):
    from velodrome.lock8.models import Affiliation, Alert
    return Alert.objects.create(
        organization=org,
        alert_type=Alert.RIDE_OUTSIDE_SERVICE_AREA,
        causality=bicycle,
        roles=[Affiliation.FLEET_OPERATOR],
        message=request.fixturename,
    )


@pytest.fixture
def alert_bicycle_left_unlocked(request, org, bicycle):
    from velodrome.lock8.models import Affiliation, Alert
    return Alert.objects.create(
        organization=org,
        alert_type=Alert.BICYCLE_LEFT_UNLOCKED,
        causality=bicycle,
        roles=[Affiliation.FLEET_OPERATOR],
        message=request.fixturename,
    )


@pytest.fixture
def notification_message(fleet_operator, alert):
    from velodrome.lock8.models import NotificationMessage
    return NotificationMessage.objects.create(
        user=fleet_operator,
        causality=alert,
    )


@pytest.fixture
def support_ticket(org, alice, bicycle):
    from velodrome.lock8.models import SupportTicket
    return SupportTicket.objects.create(
        organization=org,
        owner=alice,
        message='Good news everyone!',
        bicycle=bicycle,
        location=Point(5, 23),
        category=SupportTicket.REQUEST_BICYCLE,
    )


@pytest.fixture
def another_support_ticket(another_org, bob, another_bicycle):
    from velodrome.lock8.models import SupportTicket, SupportTicketStates
    return SupportTicket.objects.create(
        organization=another_org,
        owner=bob,
        message='One art, please.',
        bicycle=another_bicycle,
        category=SupportTicket.LOST_BICYCLE,
        state=SupportTicketStates.PENDING,
    )


@pytest.fixture
def feedback(owner, org, alice, image, bicycle, front_wheel_category):
    from velodrome.lock8.models import Feedback, FeedbackCategory
    return Feedback.objects.create(
        owner=owner,
        organization=org,
        user=alice,
        image=image,
        message='It blew up.',
        causality=bicycle,
        category=front_wheel_category,
        severity=FeedbackCategory.SEVERITY_HIGH,
    )


@pytest.fixture
def feedback2(owner, org, bob, image, bicycle2, front_wheel_category):
    from velodrome.lock8.models import Feedback, FeedbackCategory
    return Feedback.objects.create(
        owner=owner,
        organization=org,
        user=bob,
        image=image,
        message='It is dirty.',
        causality=bicycle2,
        category=front_wheel_category,
        severity=FeedbackCategory.SEVERITY_LOW
    )


@pytest.fixture
def another_feedback(owner, another_org, bob, image, another_bicycle):
    from velodrome.lock8.models import Feedback, FeedbackCategory
    return Feedback.objects.create(
        owner=owner,
        organization=another_org,
        user=bob,
        image=image,
        message='It melted.',
        causality=another_bicycle,
        severity=FeedbackCategory.SEVERITY_LOW
    )


@pytest.fixture
def task1(alert, fleet_operator, org, today):
    from velodrome.lock8.models import Affiliation, FeedbackCategory, Task
    return Task.objects.create(
        owner=fleet_operator,
        organization=org,
        assignor=fleet_operator,
        role=Affiliation.MECHANIC,
        due=today,
        context={'alert_type': alert.alert_type},
        causality=alert,
        severity=FeedbackCategory.SEVERITY_HIGH,
    )


@pytest.fixture
def task_stolen_bicycle(bicycle, fleet_operator, org, today):
    from velodrome.lock8.models import Affiliation, FeedbackCategory, Task
    return Task.objects.create(
        owner=fleet_operator,
        organization=org,
        assignor=fleet_operator,
        role=Affiliation.MECHANIC,
        due=today,
        causality=bicycle,
        severity=FeedbackCategory.SEVERITY_HIGH,
    )


@pytest.fixture
def another_task(another_alert, another_fleet_operator, another_org):
    from velodrome.lock8.models import Affiliation, Task
    return Task.objects.create(
        owner=another_fleet_operator,
        organization=another_org,
        assignor=another_fleet_operator,
        role=Affiliation.MECHANIC,
        due=NOW,
        context={'alert_type': another_alert.alert_type},
        causality=another_alert
    )


@pytest.fixture
def terms_of_service_version(owner, org):
    from velodrome.lock8.models import TermsOfServiceVersion
    tos_version = TermsOfServiceVersion.objects.create(
        organization=org, label='test tos version')
    return tos_version


@pytest.fixture
def terms_of_service(owner, org, terms_of_service_version):
    from velodrome.lock8.models import TermsOfService
    return TermsOfService.objects.create(
        owner=owner,
        organization=org,
        version=terms_of_service_version,
        tos_url='http://example.org',
        language='en',
        content='Test TOS content',
    )


def _assert_no_firmware_binaries():
    __tracebackhide__ = True

    from django.conf import settings
    path = os.path.join(settings.MEDIA_ROOT, 'firmwares')
    if not os.path.exists(path):
        return True
    binaries = os.listdir(path)
    assert not binaries, 'No firmware binaries in {}'.format(path)


@pytest.fixture(scope='function')
def get_firmware_hex(request):
    worker_id = os.environ.get('PYTEST_XDIST_WORKER')
    if worker_id:
        settings = request.getfixturevalue('settings')
        settings.MEDIA_ROOT = settings.MEDIA_ROOT + '_' + worker_id
    _assert_no_firmware_binaries()

    def inner(name=None):
        name = name if name else request.fixturename
        return File(io.BytesIO(b'abcd'), name)
    yield inner

    _assert_no_firmware_binaries()


@pytest.fixture(scope='session')
def b64_firmware_hex():
    decoded = base64.b64encode(b'abcd').decode()
    payload = "filename:{};base64,{}".format('b64_firmware_hex', decoded)
    return payload


@pytest.fixture
def firmware_mercury(get_firmware_hex, owner, org):
    from velodrome.lock8.models import Firmware

    fw = Firmware.objects.create(
        owner=owner,
        organization=org,
        chip=Firmware.MERCURY,
        version='1.1.1',
        binary=get_firmware_hex('fw_mercury'),
    )
    yield fw
    with disable_concurrency(Firmware):
        fw.binary.delete()


@pytest.fixture
def firmware_mercury_update(get_firmware_hex, owner, org):
    from velodrome.lock8.models import Firmware
    fw = Firmware.objects.create(
        owner=owner,
        organization=org,
        chip=Firmware.MERCURY,
        version='1.1.2',
        binary=get_firmware_hex('fw_mercury_update'),
    )
    yield fw
    with disable_concurrency(Firmware):
        fw.binary.delete()


@pytest.fixture
def empty_firmware_mercury(get_firmware_hex, owner, org):
    from velodrome.lock8.models import Firmware
    fw = Firmware.objects.create(
        owner=owner,
        organization=org,
        chip=Firmware.MERCURY,
        version='1.1.2',
        binary=get_firmware_hex('fw_empty_mercury'),
    )
    yield fw
    with disable_concurrency(Firmware):
        fw.binary.delete()


@pytest.fixture(scope='session')
def facebook_user_data_body():
    return json.dumps({
        'username': 'foobar',
        'first_name': 'Foo',
        'last_name': 'Bar',
        'email': 'foo@bar.com',
        'verified': True,
        'name': 'Foo Bar',
        'gender': 'male',
        'updated_time': '2013-02-13T14:59:42+0000',
        'link': 'http://www.facebook.com/foobar',
        'id': '110011001100010'
    })


@pytest.fixture(scope='session')
def google_user_data_body():
    return json.dumps({
        'profile': 'https://plus.google.com/101010101010101010101',
        'family_name': 'Bar',
        'sub': '101010101010101010101',
        'picture': 'https://lh5.googleusercontent.com/-ui-GqpNh5Ms/'
                   'AAAAAAAAAAI/AAAAAAAAAZw/a7puhHMO_fg/photo.jpg',
        'locale': 'en',
        'email_verified': True,
        'given_name': 'Foo',
        'email': 'foo@bar.com',
        'name': 'Foo Bar',
    })


@pytest.fixture(scope='session')
def google_me_url():
    return 'https://www.googleapis.com/oauth2/v3/userinfo'


@pytest.fixture(scope='session')
def facebook_me_url():
    from social_core.backends.facebook import API_VERSION, FacebookOAuth2
    assert (FacebookOAuth2.USER_DATA_URL.format(version=API_VERSION) ==
            'https://graph.facebook.com/v3.2/me')
    return FacebookOAuth2.USER_DATA_URL.format(version=API_VERSION)


@pytest.fixture(params=('bicycle', 'lock'))
def bicycle_or_lock(request, bicycle, lock):
    return bicycle if request.param == 'bicycle' else lock


@pytest.fixture
def front_wheel_category():
    from velodrome.lock8.models import FeedbackCategory
    return FeedbackCategory.objects.get(name='front-wheel')


@pytest.fixture
def bicycle_category():
    from velodrome.lock8.models import FeedbackCategory
    return FeedbackCategory.objects.get(name='bicycle')


@pytest.fixture
def rpc_message_handler():
    from velodrome.lock8.utils import RPCMessageHandler
    return RPCMessageHandler()


@pytest.fixture(scope='session')
def random_marker():
    return ''.join(random.choice(string.ascii_letters) for i in range(12))


@pytest.fixture(params=('with_email', 'without_email'))
def with_email(request):
    if request.param == 'with_email':
        organization_preference = request.getfixturevalue(
            'organization_preference')
        organization_preference.send_support_ticket_per_email = True
        organization_preference.send_feedback_per_email = True
        organization_preference.send_task_per_email = True
        organization_preference.support_email = 'support@example.com'
        organization_preference.save()
        return True, request.getfixturevalue('mailoutbox')
    return False, []


@pytest.fixture
def feature(org, owner):
    from velodrome.lock8.models import Feature
    feature = Feature.objects.create(
        owner=owner,
        name='feature')
    feature.organizations.add(org)
    return feature


@pytest.fixture
def analytics_feature(org, owner):
    from velodrome.lock8.models import Feature
    feature = Feature.objects.create(
        owner=owner,
        name='analytics')
    feature.organizations.add(org)
    return feature


def oauth_login_flow(client, url=None, customer_json=None, encoded=None,
                     user_data_body=None, active_requests_mock=None):
    from velodrome.lock8.models import User
    active_requests_mock.post(
        'https://api.stripe.com/v1/customers', json=customer_json)
    active_requests_mock.get(encoded, text=user_data_body)
    resp = client.post(url, data=json.dumps({'access_token': 'a'*10}),
                       content_type='application/json',
                       HTTP_ACCEPT='application/json; version=1.0')
    users = User.objects.filter(email='foo@bar.com')
    return users if users.count() > 1 else users.get(), resp


@pytest.fixture
def login_alice_with_google(db, customer_json, google_me_url,
                            google_user_data_body, active_requests_mock):
    url = reverse('lock8:tokeninfo', kwargs={'backend': 'lock8_google_oauth2'})
    return partial(
        oauth_login_flow,
        url=url,
        customer_json=customer_json,
        encoded=google_me_url,
        user_data_body=google_user_data_body,
        active_requests_mock=active_requests_mock,
    )


@pytest.fixture
def login_alice_with_facebook(db, customer_json, facebook_me_url,
                              settings, facebook_user_data_body,
                              active_requests_mock):
    settings.SOCIAL_AUTH_LOCK8_FACEBOOK_OAUTH2_KEY = 'abcd'
    settings.SOCIAL_AUTH_LOCK8_FACEBOOK_OAUTH2_SECRET = 'abcd'
    encoded = urlencode({
        'access_token': 'a'*10,
        'appsecret_proof':
        'f665d37f0180a8948fd2fd894'
        'bef89bb0a4cf0ce16e4bddb33'
        '39fc618af85dd1'
    })
    url = reverse(
        'lock8:tokeninfo', kwargs={'backend': 'lock8_facebook_oauth2'}
    )
    return partial(
        oauth_login_flow,
        url=url,
        customer_json=customer_json,
        encoded='?'.join((facebook_me_url, encoded)),
        user_data_body=facebook_user_data_body,
        active_requests_mock=active_requests_mock,
    )


@pytest.fixture
def mocked_query_table(request, mocker, monkeypatch, rf):
    """Return a monkeypatched `query_table` method for DynamoDB.

    The default list of distance/date pairs can be overridden on the return
    value's `.side_effect.values` list."""
    import velodrome.lock8.metrics
    from velodrome.lock8.metrics import (
        METRICS, annotate_all_values, default_parse_metric_value, Resolution
    )
    from velodrome.lock8.metrics.test_utils import (
        get_iso8601_strftime_for_resolution, rename_key
    )
    from velodrome.lock8.models import Zone

    UNSET = object
    mocked_request = rf.request()

    def default_values():
        metric_name = query_table.metric if query_table.metric else (
            request.getfixturevalue('metric_name') if 'metric_name' in
            request.fixturenames else 'distance')
        projection = METRICS[metric_name].projection
        dates = [timezone.make_aware(dt.datetime(2015, 12, 6, 0, 0, 7)),
                 timezone.make_aware(dt.datetime(2016, 1, 3, 13, 37)),
                 timezone.make_aware(dt.datetime(2016, 2, 6, 0, 1, 2))]
        rows = []
        values = {
            'distance': ([42, 12345, 4321][x % 3] + x for x in range(1, 100)),
            'seconds': ([7, 13, 101][x % 3] + x for x in range(1, 100)),
            'trips': (x for x in range(1, 100)),
            'user': (str(uuid.UUID(int=x)) for x in range(1, 100)),
            'bicycle': (str(uuid.UUID(int=(x + 100))) for x in range(1, 100)),
            'zone': ('None' if x == 1 else str(uuid.UUID(int=(x + 199)))
                     for x in range(1, 100)),
            'zone_type': chain([UNSET], chain.from_iterable(repeat([
                Zone.DROP, Zone.SERVICE], 50))),
            'bicycles': (x + 2000 for x in range(1, 100)),
            'avg_bicycles': (x + 1.5 for x in range(1, 100)),
            'min_bicycles': (x for x in range(1, 100)),
            'max_bicycles': (x + 10 for x in range(1, 100))
        }
        for date in dates:
            row = []
            for p in projection:
                if p == 'date':
                    row.append(date)
                else:
                    row.append(next(values[p]))
            rows += [row]
        return [projection, rows]

    def zip_without_unset(projection, values):
        return dict(filter(lambda x: x[1] is not UNSET,
                           zip(projection, values)))

    def expected_data(resolution: Resolution) -> dict:
        projection, rows = query_table.values or query_table.default_values()
        values_with_keys = [zip_without_unset(projection, row) for row in rows]
        ftime = get_iso8601_strftime_for_resolution(resolution)
        values_without_annotations = [{
            rename_key(key):
                value.strftime(ftime)
                if key == 'date'
                else default_parse_metric_value(key, value)
            for key, value in row.items()
        } for row in values_with_keys]
        return {
            'values': annotate_all_values(
                values_without_annotations, mocked_request)
        }

    def query_table(table, query, select):
        resolution = Resolution(table.name.split('-')[-2])
        names, rows = query_table.values or query_table.default_values()
        value_name = [name for name in names if name != 'date'][0]
        values_with_keys = [zip_without_unset(names, row) for row in rows]

        if rows:
            assert all(len(row) == len(names) for row in rows)

        if select == 'values':
            return {
                'Items': [{
                    key:
                        resolution.strftime(value)
                        if key == 'date'
                        else value
                    for key, value in row.items()
                } for row in values_with_keys],
                'Count': len(rows)
            }

        if select == 'current':
            return {
                'Items': [{
                    value_name: sum(
                        row[value_name] for row in values_with_keys
                        if (NOW - row['date']) < dt.timedelta(hours=25))
                }],
                'Count': 1
            }

        if select == 'total':
            return {
                'Items': [{
                    value_name:
                        sum(row[value_name] for row in values_with_keys)
                }],
                'Count': 1
            }

        raise NotImplementedError("Invalid select: {}".format(select))

    query_table.metric = None
    query_table.values = None
    query_table.default_values = default_values
    query_table.expected_data = expected_data
    query_table.metric = None

    mocked_query_table = mocker.Mock()
    mocked_query_table.side_effect = query_table

    monkeypatch.setattr(velodrome.lock8.metrics, 'query_table',
                        mocked_query_table)

    return mocked_query_table


@pytest.fixture
def site(settings):
    site = Site.objects.get(pk=settings.SITE_ID)
    site.domain = 'api-dev.lock8.me'
    site.name = 'api-dev'
    site.save()
    return site


@pytest.fixture(scope='session')
def stripe_plan_detail():
    from django.conf import settings
    env = settings.ENVIRONMENT
    url = 'https://api.stripe.com/v1/plans/{}-org.*'.format(env)
    return re.compile(url)


@pytest.fixture
def mocked_ddb(mocker, monkeypatch):
    "Monkeypatch DynamoDB with a mock."
    ddb = mocker.Mock(dynamodb)
    monkeypatch.setattr(velodrome.lock8.dynamodb, 'dynamodb', ddb)
    return ddb


@pytest.fixture
def ddb_table_for_metric(dynamodb_integration_test):
    """Setup specific testing table(s) for a single metric with DynamoDB."""

    created_tables = []

    def f(metric=None, resolution=None):
        with freeze_time(NOW):
            tables = create_ddb_tables(metric, resolution)
        created_tables.extend(tables)
        return tables

    yield f
    try_delete_tables(created_tables)


@pytest.fixture
def ddb_table_from_schema(dynamodb_integration_test):
    from velodrome.lock8.dynamodb import dynamodb

    created_tables = []

    def f(schema):
        with freeze_time(NOW):
            table = get_ddbtable(schema['TableName'])
            try_delete_tables([table])
            dynamodb.create_table(**dict(schema, TableName=table.name))
        created_tables.append(table)
        return table

    yield f
    try_delete_tables(created_tables)


@pytest.fixture
def auto_login_code(alice):
    from django.conf import settings
    from velodrome.lock8.utils import generate_auto_login_code

    code = generate_auto_login_code()
    auth_code_cache = caches['auth_codes']
    ttl = settings.AUTO_LOGIN_CODE_EXPIRY.total_seconds()
    auth_code_cache.set(code, str(alice.uuid), ttl)
    return code


@pytest.fixture(autouse=True)
def active_requests_mock():
    with requests_mock.Mocker() as m:
        m.get('https://fonts.googleapis.com/css?'
              'family=Source+Serif+Pro:400,600', text='')
        m.get('https://fonts.googleapis.com/css?'
              'family=Source+Sans+Pro:400,600', text='')
        m.get('http://169.254.169.254/latest/meta-data/instance-id',
              text='id-testme')
        yield m


@pytest.fixture
def lock_firmware_update(lock, firmware_mercury, owner):
    from velodrome.lock8.models import LockFirmwareUpdate

    return LockFirmwareUpdate.objects.create(
        lock=lock, firmware=firmware_mercury, owner=owner
    )


@pytest.fixture
def another_lock_firmware_update(another_lock, owner, another_org,
                                 get_firmware_hex):
    from velodrome.lock8.models import Firmware, LockFirmwareUpdate

    f1 = Firmware.objects.create(
        owner=owner, organization=another_org,
        chip=Firmware.MERCURY, version='1.1.1',
        binary=get_firmware_hex('fw_another_update'),
    )
    yield LockFirmwareUpdate.objects.create(
        lock=another_lock, firmware=f1, owner=owner
    )
    f1.binary.delete()


@pytest.fixture(scope='session')
def non_matching_uuid():
    return str(uuid.uuid4())


@pytest.fixture
def shared_secret(lock):
    from velodrome.lock8.models import SharedSecret

    lock.shared_secret = SharedSecret.objects.create()
    lock.save()
    return lock.shared_secret


def _commit_success():
    with unittest.mock.patch(
            'django.db.backends.base.base.BaseDatabaseWrapper.validate_no_atomic_block',  # noqa: E501
            lambda x: False):
        for conn_name in connections:
            conn = connections[conn_name]
            conn.run_and_clear_commit_hooks()


@pytest.fixture
def commit_success():
    """
    Trigger commit() success event manually, for non-transactional_db tests
    that need it.
    """
    return _commit_success


@pytest.fixture
def urls_for_tests():
    """Setup test urls, based on pytest-django's marker."""
    import django.conf
    from django.urls import clear_url_caches, set_urlconf

    original_urlconf = django.conf.settings.ROOT_URLCONF
    django.conf.settings.ROOT_URLCONF = 'velodrome.lock8.tests.urls'
    clear_url_caches()
    set_urlconf(None)

    yield

    django.conf.settings.ROOT_URLCONF = original_urlconf
    # Copy the pattern from
    # https://github.com/django/django/blob/master/django/test/signals.py#L152
    clear_url_caches()
    set_urlconf(None)


@pytest.fixture
def client_app(request, org, owner):
    from velodrome.lock8.models import Affiliation, ClientApp, User

    inactive_user = User.objects.create(
        username='{}:{}'.format(org.uuid, request.fixturename)
    )
    Affiliation.objects.create(organization=org,
                               user=inactive_user,
                               role=Affiliation.ADMIN)

    remote_uuid = uuid.uuid4()
    return ClientApp.objects.create(
        name=request.fixturename,
        organization=org,
        scopes=[s[0] for s in ClientApp.SCOPES],
        remote_uuid=remote_uuid,
        user=inactive_user,
        owner=owner,
    )


@pytest.fixture
def pricing_scheme(request, org_with_payments, owner):
    from velodrome.lock8.models import PricingScheme

    pricing_scheme = PricingScheme.objects.create(
        name=request.fixturename,
        organization=org_with_payments,
        owner=owner,
        time_ranges=(
            (0, 30, 0, False, 0),
            (30, None, 100, False, 60),
        ),
        max_daily_charged_cents=2000,
        description={'en': {
            'title': 'title',
            'description': 'description',
            'fine_print': 'fine_print',
            'short_description': 'short_description',
        }}
    )
    pricing_scheme.provision()
    return pricing_scheme


@pytest.fixture
def pricing_scheme_bicycle_model(request, pricing_scheme, bicycle_model):
    pricing_scheme.bicycle_model = bicycle_model
    pricing_scheme.save()
    return pricing_scheme


@pytest.fixture
def subscription_plan(request, active_requests_mock, org_with_payments,
                      owner, stripe_plan_detail):
    from velodrome.lock8.models import SubscriptionPlan

    active_requests_mock.register_uri(
        'GET', stripe_plan_detail, json={
            'id': 'gold',
            'object': 'plan',
        })
    active_requests_mock.register_uri(
        'POST', 'https://api.stripe.com/v1/plans/gold', json={
            'id': 'gold',
            'object': 'plan',
        })
    subscription_plan = SubscriptionPlan.objects.create(
        owner=owner,
        organization=org_with_payments,
        name=request.fixturename,
        interval=SubscriptionPlan.WEEK,
        cents=500,
        trial_period_days=0,
    )
    subscription_plan.provision()
    subscription_plan.refresh_from_db()
    return subscription_plan


@pytest.fixture
def second_subscription_plan(request, second_stripe_plan, org_with_payments,
                             owner):
    from velodrome.lock8.models import SubscriptionPlan

    subscription_plan = SubscriptionPlan.objects.create(
        plan=second_stripe_plan,
        owner=owner,
        organization=org_with_payments,
        name=request.fixturename,
        interval=SubscriptionPlan.MONTH,
        cents=int(second_stripe_plan.amount * 100),
        trial_period_days=second_stripe_plan.trial_period_days,
        statement_descriptor=second_stripe_plan.statement_descriptor,
    )
    subscription_plan.provision()
    subscription_plan.refresh_from_db()
    return subscription_plan


@pytest.fixture
def subscription(subscription_plan, customer):
    return Subscription.objects.create(
        stripe_id='sub_test1',
        customer=customer,
        plan=subscription_plan.plan,
        quantity=1,
        start=timezone.now(),
        status='active',
    )


@pytest.fixture
def second_subscription(second_subscription_plan, customer):
    Subscription.objects.create(
        stripe_id='sub_test2',
        customer=customer,
        plan=second_subscription_plan.plan,
        quantity=1,
        start=timezone.now(),
        status='active')


@pytest.fixture
def subscription_json(subscription_plan):
    return ReadOnlyDict({
        "id": "sub_test1",
        "object": "subscription",
        "application_fee_percent": None,
        "cancel_at_period_end": False,
        "canceled_at": None,
        "current_period_end": 1452854186,
        "current_period_start": 1451990186,
        "customer": "cus_7UkUzpBtATnab9",
        "discount": {
            "object": "discount",
            "coupon": {
                "id": "25OFF",
                "object": "coupon",
                "amount_off": None,
                "created": 1508919722,
                "currency": "eur",
                "duration": "repeating",
                "duration_in_months": 3,
                "livemode": False,
                "max_redemptions": None,
                "metadata": {
                },
                "percent_off": 25,
                "redeem_by": None,
                "times_redeemed": 0,
                "valid": True,
            },
            "customer": "cus_Be2Dcc4xJHodVx",
            "end": 1516868522,
            "start": 1508919722,
            "subscription": "sub_test1",
        },
        "ended_at": None,
        "metadata": {
        },
        "plan": {
            "id": subscription_plan.plan.stripe_id,
            "object": "plan",
            "amount": 39,
            "created": 1449668959,
            "currency": "eur",
            "interval": "month",
            "interval_count": 2,
            "livemode": False,
            "metadata": {
            },
            "name": subscription_plan.plan.name,
            "statement_descriptor": None,
            "trial_period_days": 10
        },
        "quantity": 2,
        "start": 1451990186,
        "status": "trialing",
        "tax_percent": None,
        "trial_end": 1452854186,
        "trial_start": 1451990186
    })


@pytest.fixture
def refund_charge_json():
    return {
        'id': 're_1Bn2sxEWnIuOzoofSGpxzQUm',
        'object': 'refund',
        'amount': 'REPLACE ME',
        'balance_transaction': None,
        'charge': 'REPLACE ME',
        'created': 1516618243,
        'currency': 'usd',
        'metadata': {},
        'reason': None,
        'receipt_number': None,
        'status': 'succeeded',
    }


@pytest.fixture
def subscription_plan_with_pricing_scheme(request, subscription_plan,
                                          pricing_scheme):
    subscription_plan.pricing_scheme = pricing_scheme
    subscription_plan.save()
    return subscription_plan


@pytest.fixture(params=[('text/csv', ','),
                        ('text/tab-separated-values', '\t')],
                ids=['csv', 'tsv'])
def csv_content_type(request):
    return request.param


@pytest.fixture
def mocked_redis_incr(mocker):
    """
    Mock django_redis' incr to not require lupa during tests for fakeredis'
    eval.
    """
    from velodrome.lock8.authentication import failed_logins_cache

    def mocked_incr(self, key, *args, **kwargs):
        cur = failed_logins_cache.get(key, 0)
        new = cur + 1
        failed_logins_cache.set(key, new)
        return new

    p = mocker.patch('django_redis.cache.RedisCache.incr', autospec=True,
                     side_effect=mocked_incr)
    yield p
    assert p.call_count


@pytest.fixture
def mocked_redis_incr_with_cleared_cache(mocked_redis_incr):
    from velodrome.lock8.authentication import failed_logins_cache

    failed_logins_cache.clear()
    return mocked_redis_incr


@pytest.fixture
def unpaid_rentalsession(owner, renter, bicycle):
    from velodrome.lock8.models import (
        RentalSession, RentalSessionStates, RentalSessionPaymentStates)

    return RentalSession.objects.create(
        owner=owner,
        user=renter,
        bicycle=bicycle,
        state=RentalSessionStates.CLOSED.value,
        payment_state=RentalSessionPaymentStates.FAILED.value,
        cents=99,
        currency='eur',
    )
