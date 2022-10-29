import datetime as dt
import json
from urllib.parse import parse_qsl, unquote, unquote_plus, urlencode, urlparse

from django.conf import settings
from django.contrib.auth.signals import user_logged_in
from django.contrib.auth.tokens import default_token_generator
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import connection
from django.db.models import Q
from django.test.utils import CaptureQueriesContext
from django.urls.exceptions import NoReverseMatch
from django.utils import timezone
from freezegun import freeze_time
from pinax.stripe.models import Customer
import pytest
from refreshtoken.models import RefreshToken
from rest_framework import status
from rest_framework.exceptions import ErrorDetail
from rest_framework_jwt.utils import jwt_encode_handler
from social_django.models import UserSocialAuth

from velodrome.lock8.exceptions import DuplicateContentError
from velodrome.lock8.jwt_extensions import jwt_payload_handler
from velodrome.lock8.utils import reverse_query


def test_crud_user(drf_fleet_operator, alice, org, drf_alice, drf_admin):
    from velodrome.lock8.models import Affiliation

    drf_alice.use_jwt_auth()

    Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER,
    )
    url = reverse_query('lock8:user-list')
    response = drf_fleet_operator.assert_count(url, 2)
    alice_result = next(r for r in response.data['results']
                        if r['uuid'] == str(alice.uuid))

    assert alice_result == {
        'uuid': str(alice.uuid),
        'username': 'alice',
        'email': 'alice@example.com',
        'first_name': 'Alice',
        'last_name': 'Cooper',
        'display_name': 'Alice Cooper',
        'url': 'http://testserver' + reverse_query(
            'lock8:user-detail', kwargs={'uuid': alice.uuid}),
        'avatar': None,
        'phone_numbers': None,
        'state': 'new',
        'concurrency_version': alice.concurrency_version,
        'modified': alice.modified.isoformat()[:-13] + 'Z',
        'created': alice.created.isoformat()[:-13] + 'Z',
        'last_login': None,
        'is_local': True,
    }

    url = reverse_query('lock8:user-list')
    response = drf_fleet_operator.post(url)
    assert response.status_code == status.HTTP_403_FORBIDDEN

    url = reverse_query('lock8:user-detail', kwargs={'uuid': alice.uuid})
    response = drf_alice.patch(url, data={'first_name': 'clara'})
    assert response.status_code == status.HTTP_200_OK

    alice.refresh_from_db()
    assert alice.first_name == 'clara'

    data = alice_result.copy()
    del data['concurrency_version']
    del data['modified']
    del data['created']
    del data['last_login']
    del data['url']
    del data['avatar']
    # Since Django 2.1 there is additional serialization of `data` content,
    # by default in case `data` is dict. Since 2.2 it was extended to support
    # also lists and tuples, but looks like not OrderedDict. So doing
    # json.dump() to `data` manually does the trick. Otherwise we can pass
    # format='json' here. See docs:
    # https://docs.djangoproject.com/en/2.2/topics/testing/tools/#django.test.Client.post  # noqa
    response = drf_alice.put(url, data=data, format='json')
    assert response.status_code == status.HTTP_200_OK, response.data

    url = reverse_query('lock8:user-actions', kwargs={'uuid': alice.uuid})
    response = drf_fleet_operator.post(url, data={'type': 'disable'})
    assert response.status_code == status.HTTP_200_OK
    alice.refresh_from_db()
    assert alice.state == 'disabled'
    assert not alice.is_active

    drf_fleet_operator.assert_404(url, data={'type': 'enable'})

    response = drf_admin.post(url, data={'type': 'enable'})
    assert response.status_code == status.HTTP_200_OK
    alice.refresh_from_db()
    assert alice.state == 'new'
    assert alice.is_active

    url = reverse_query('lock8:user-detail', kwargs={'uuid': alice.uuid})
    response = drf_alice.delete(url)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    alice.refresh_from_db()
    assert alice.is_active is False

    url = reverse_query('lock8:user-list')
    drf_fleet_operator.assert_count(url, 1)

    # alice can't login any longer.
    drf_alice.assert_status(url, 401)


def test_user_list_queries(org, drf_fleet_operator, alice, bob):
    from velodrome.lock8.models import Affiliation
    filtered_url = reverse_query('lock8:user-list',
                                 {'organization': str(org.uuid)})
    url = reverse_query('lock8:user-list')
    with CaptureQueriesContext(connection) as capture:
        drf_fleet_operator.assert_count(url, 1)
    assert len(capture.captured_queries) == 8
    with CaptureQueriesContext(connection) as capture:
        drf_fleet_operator.assert_count(filtered_url, 1)
    assert len(capture.captured_queries) == 11

    Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER,
    )
    with CaptureQueriesContext(connection) as capture:
        drf_fleet_operator.assert_count(url, 2)
    assert len(capture.captured_queries) == 8
    with CaptureQueriesContext(connection) as capture:
        drf_fleet_operator.assert_count(filtered_url, 2)
    assert len(capture.captured_queries) == 11


def test_user_filtering_email(drf_fleet_operator, alice, org):
    from velodrome.lock8.models import Affiliation

    url = reverse_query('lock8:user-list')
    drf_fleet_operator.assert_count(url, 1)

    Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER,
    )

    url = reverse_query('lock8:user-list')
    drf_fleet_operator.assert_count(url, 2)

    url = reverse_query('lock8:user-list', {'email': alice.email[:-3]})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:user-list', {'email': alice.email})
    drf_fleet_operator.assert_count(url, 1)


def test_user_filtering_organization(drf_fleet_operator, alice, org,
                                     another_org, fleet_operator):
    from velodrome.lock8.models import Affiliation
    Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER,
    )
    Affiliation.objects.create(
        user=alice,
        organization=another_org,
        role=Affiliation.RENTER,
    )
    Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.MECHANIC,
    )
    url = reverse_query('lock8:user-list',
                        {'organization': str(another_org.uuid)})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:user-list', {'organization': str(org.uuid)})
    response = drf_fleet_operator.assert_count(url, 2)

    expected = {str(alice.uuid): ['mechanic', 'renter'],
                str(fleet_operator.uuid): ['fleet_operator']}
    for result in response.data['results']:
        assert result['uuid'] in expected
        assert result['roles'] == expected[result['uuid']]


def test_user_filtering_multiple_organizations(
        owner, org, another_org, drf_fleet_operator, another_renter,
):
    from velodrome.lock8.models import Affiliation, Organization, User

    # Let's create two sub-orgs under the org, one mechanic per sub-org
    sub_orgs = {}
    sub_users = {}
    for i in range(1, 3):
        sub_orgs[i] = Organization.objects.create(
            owner=owner,
            name=f'sub{i}',
            parent=org,
        )
        sub_users[i] = User.objects.create(
            username=f'u{i}',
            email=f'u{i}@example.com'
        )
        Affiliation.objects.create(
            organization=sub_orgs[i],
            user=sub_users[i],
            role=Affiliation.MECHANIC
        )
    # One of the mechanics also will be a renter
    Affiliation.objects.create(
        organization=sub_orgs[1],
        user=sub_users[1],
        role=Affiliation.RENTER
    )

    expected_roles = {
        'u1': ['renter', 'mechanic'],
        'u2': ['mechanic'],
    }

    # Let's pass single org in the multi-org filter
    for i, sub_org in sub_orgs.items():
        url = reverse_query(
            'lock8:user-list',
            query_kwargs=dict(
                organizations=str(sub_org.uuid)
            )
        )
        response = drf_fleet_operator.assert_count(url, 1)
        for item in response.data['results']:
            assert item['roles'] == expected_roles[item['username']]

    # Top-level org operator should see them both
    url = reverse_query(
        'lock8:user-list',
        query_kwargs=dict(
            organizations=','.join([str(x.uuid) for _, x in sub_orgs.items()])
        )
    )
    response = drf_fleet_operator.assert_count(url, 2)
    for item in response.data['results']:
        assert item['roles'] == expected_roles[item['username']]


def test_user_filtering_role(drf_fleet_operator, renter, org, another_org):
    from velodrome.lock8.models import Affiliation

    url = reverse_query('lock8:user-list', {'role': 'admin'})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:user-list', {'role': 'renter'})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:user-list', {'role': 'fleet_operator'})
    drf_fleet_operator.assert_count(url, 1)

    # Being fleet_operator on another org should not include it.
    Affiliation.objects.create(
        user=renter,
        organization=another_org,
        role=Affiliation.FLEET_OPERATOR,
    )
    url = reverse_query('lock8:user-list', {'organization': org.uuid,
                                            'role': 'fleet_operator'})
    drf_fleet_operator.assert_count(url, 1)


def test_user_filtering_uuid(drf_fleet_operator, alice, org, bob):
    from velodrome.lock8.models import Affiliation

    url = reverse_query('lock8:user-list')
    drf_fleet_operator.assert_count(url, 1)

    Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER,
    )
    Affiliation.objects.create(
        user=bob,
        organization=org,
        role=Affiliation.RENTER,
    )

    url = reverse_query('lock8:user-list')
    drf_fleet_operator.assert_count(url, 3)

    url = reverse_query('lock8:user-list',
                        {'uuid': ','.join(map(str, (alice.uuid, bob.uuid)))})
    drf_fleet_operator.assert_count(url, 2)


def test_user_ordering_last_login(drf_fleet_operator, alice, org,
                                  fleet_operator):
    from velodrome.lock8.models import Affiliation
    Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER,
    )
    user_logged_in.send(alice.__class__, user=alice)

    url = reverse_query('lock8:user-list', {'ordering': '-last_login'})
    response = drf_fleet_operator.assert_success(url)
    assert [r['username'] for r in response.data['results']] == [
        alice.username, fleet_operator.username]

    url = reverse_query('lock8:user-list', {'ordering': 'last_login'})
    response = drf_fleet_operator.assert_success(url)
    assert [r['username'] for r in response.data['results']] == [
        alice.username, fleet_operator.username]

    user_logged_in.send(alice.__class__, user=fleet_operator)

    url = reverse_query('lock8:user-list', {'ordering': 'last_login'})
    response = drf_fleet_operator.assert_success(url)
    assert [r['username'] for r in response.data['results']] == [
        alice.username, fleet_operator.username]


def test_user_list_no_duplicate(drf_fleet_operator, fleet_operator, alice, org,
                                another_org):
    from velodrome.lock8.models import Affiliation
    Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER,
    )
    Affiliation.objects.create(
        user=fleet_operator,
        organization=another_org,
        role=Affiliation.RENTER,
    )
    url = reverse_query('lock8:user-list')
    drf_fleet_operator.assert_count(url, 2)


def test_user_no_deleted_affiliations(drf_fleet_operator, fleet_operator,
                                      alice, org):
    """
    test that no deleted affiliations are returned
    """
    from velodrome.lock8.models import Affiliation
    Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER,
    )
    affiliation = Affiliation.objects.create(
        user=fleet_operator,
        organization=org,
        role=Affiliation.ADMIN,
    )
    affiliation.delete()
    url = reverse_query('lock8:user-detail', kwargs={'uuid': str(alice.uuid)})
    drf_fleet_operator.assert_success(url)


def test_userlist_no_deleted_affiliations_for_admin_and_fleet_operator(
        drf_admin, drf_fleet_operator, alice, org, another_org):
    from velodrome.lock8.models import Affiliation
    Affiliation.objects.create(
        user=alice,
        organization=another_org,
        role=Affiliation.RENTER,
    )

    # Create and delete an affiliation to org.
    affiliation = Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER,
    )
    affiliation.delete()

    # Request from fleet_operator.
    url = reverse_query('lock8:user-list', {'organization': org.uuid})
    response = drf_fleet_operator.assert_success(url)
    assert str(alice.uuid) not in (r['uuid'] for r in response.data['results'])

    # Request from admin_user.
    url = reverse_query('lock8:user-list', {'organization': org.uuid})
    response = drf_admin.assert_success(url)
    assert str(alice.uuid) not in (r['uuid'] for r in response.data['results'])


def test_user_filtering_full_text(
    drf_fleet_operator, org, fleet_operator, alice, with_db_plugins
):
    from velodrome.lock8.models import Affiliation
    Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER,
    )
    url = reverse_query('lock8:user-list',
                        {'query': f'{alice.last_name} {alice.first_name}'})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:user-list',
                        {'query': f'{alice.first_name} {alice.last_name}'})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:user-list', {'query': alice.email})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:user-list', {'query': alice.email[:3]})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:user-list', {'query': alice.first_name[:3]})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:user-list', {'query': alice.last_name[:3]})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:user-list', {'query': 'Ecila'})
    drf_fleet_operator.assert_count(url, 0)

    alice.last_name = 'Ürlu'
    alice.username = 'Repooc'
    alice.save()

    url = reverse_query('lock8:user-list', {'query': 'ü'})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:user-list', {'query': 'ú'})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:user-list', {'query': alice.username})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:user-list', {'query': alice.username[:3]})
    drf_fleet_operator.assert_count(url, 1)


def test_user_dont_show_up_filtered_by_org_with_deleted_affiliation(
        drf_fleet_operator, alice, org):

    from velodrome.lock8.models import Affiliation

    affiliation = Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER)
    affiliation.delete()

    url = reverse_query('lock8:user-list', {'organization': org.uuid})
    response = drf_fleet_operator.assert_success(url)
    assert str(alice.uuid) not in (r['uuid'] for r in response.data['results'])


def test_user_dont_show_up_filtered_by_role_with_deleted_affiliation(
        drf_fleet_operator, alice, org):

    from velodrome.lock8.models import Affiliation

    affiliation = Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER)
    affiliation.delete()
    url = reverse_query('lock8:user-list', {'role': Affiliation.RENTER})
    response = drf_fleet_operator.assert_success(url)
    assert str(alice.uuid) not in (r['uuid'] for r in response.data['results'])


def test_crud_user_profile(drf_fleet_operator, alice, org, bob):
    from velodrome.lock8.models import Affiliation

    Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER,
    )
    url = reverse_query('lock8:user_profile-list',
                        kwargs={'parent_lookup_uuid': alice.uuid})
    drf_fleet_operator.assert_count(url, 0)

    response = drf_fleet_operator.post(url, format='json', data={
        'phone_numbers': {'mobile': '012'}})
    assert response.status_code == status.HTTP_201_CREATED

    alice.refresh_from_db()
    assert str(alice.profile.uuid) == response.data['uuid']
    assert alice.profile.phone_numbers == {'mobile': '012'}

    response = drf_fleet_operator.post(url,
                                       data={'display_name': 'New name'},
                                       format='json')
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {'detail': {
        'phone_numbers': [{
            'message': 'This field is required.',
            'code': 'required'}]}}

    url = reverse_query('lock8:user_profile-detail',
                        kwargs={'parent_lookup_uuid': alice.uuid,
                                'uuid': alice.profile.uuid})
    drf_fleet_operator.assert_success(url, {
        'uuid': str(alice.profile.uuid),
        'url': 'http://testserver' + url,
        'phone_numbers': {'mobile': '012'},
        'state': 'new',
        'concurrency_version': alice.profile.concurrency_version,
        'modified': alice.profile.modified.isoformat()[:-13] + 'Z',
        'created': alice.profile.created.isoformat()[:-13] + 'Z',
    })

    url = reverse_query('lock8:user_profile-detail',
                        kwargs={'parent_lookup_uuid': alice.uuid,
                                'uuid': alice.profile.uuid})
    response = drf_fleet_operator.patch(url, format='json', data={
        'phone_numbers': {'mobile': '9876'}})
    assert response.status_code == 200

    alice.refresh_from_db()
    alice.profile.refresh_from_db()

    assert alice.profile.phone_numbers == {'mobile': '9876'}

    url = reverse_query('lock8:user_profile-detail',
                        kwargs={'parent_lookup_uuid': alice.uuid,
                                'uuid': alice.profile.uuid})
    response = drf_fleet_operator.delete(url)
    assert response.status_code == 204

    alice.refresh_from_db()

    assert alice.profile is None


def test_user_profile_forbidden(drf_fleet_operator, bob, owner, org):
    from velodrome.lock8.models import UserProfile

    bob_profile = UserProfile.objects.create(
        owner=owner,
        )
    bob.profile = bob_profile
    bob.save()

    url = reverse_query('lock8:user-detail',
                        kwargs={'uuid': bob.uuid})
    drf_fleet_operator.assert_status(url, 404)

    url = reverse_query('lock8:user_profile-detail',
                        kwargs={'parent_lookup_uuid': bob.uuid,
                                'uuid': bob.profile.uuid})
    drf_fleet_operator.assert_status(url, 404)


def test_user_password_change(drf_alice, alice):
    url = reverse_query('lock8:user-change-password',
                        kwargs={'uuid': alice.uuid})
    response = drf_alice.post(url, data={'old_password': 'pwd_alice',
                                         'new_password': 'ecila'})
    assert response.status_code == status.HTTP_400_BAD_REQUEST, response.data
    assert response.data == {'detail': {'new_password': [
        {'message': 'The password is too similar to the username.',
         'code': 'password_too_similar'},
        {'message': 'This password is too short. '
         'It must contain at least 8 characters.',
         'code': 'password_too_short'}]}}

    new_pwd = 'correct horse battery staple'
    response = drf_alice.post(url, data={'old_password': 'pwd_alice',
                                         'new_password': new_pwd})
    assert response.status_code == status.HTTP_204_NO_CONTENT, response.data

    alice.refresh_from_db()
    assert alice.check_password(new_pwd)


def test_user_password_change_failed(drf_alice, alice):
    url = reverse_query('lock8:user-change-password',
                        kwargs={'uuid': alice.uuid})
    response = drf_alice.post(url,
                              data={'old_password': 'I forgot my password',
                                    'new_password': '1323445678'})
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data['detail'] == {
        'old_password': [{'message': 'Invalid credentials.',
                          'code': 'invalid_credentials'}],
        'new_password': [{'message': 'This password is entirely numeric.',
                          'code': 'password_entirely_numeric'}]
    }


def test_user_reset_refresh_tokens(drf_alice, alice, refresh_token):
    url = reverse_query('lock8:user-reset-refresh-tokens',
                        kwargs={'uuid': alice.uuid})
    response = drf_alice.post(url)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    with pytest.raises(RefreshToken.DoesNotExist):
        refresh_token.refresh_from_db()

    assert alice.refresh_tokens.count() == 1


@pytest.mark.parametrize('activate_method', ('GET', 'POST'))
@pytest.mark.parametrize('param_first_name', ('with_first_name',
                                              'without_first_name'))
def test_email_register_activate_and_login(param_first_name, activate_method,
                                           drf_client, mailoutbox, root_org):
    from django.conf import settings
    from django.core.cache import caches
    from velodrome.lock8.models import User

    drf_client.commit_db_on_successful_response = True

    with_first_name = param_first_name == 'with_first_name'
    email = 'rms@fsf.org'
    first_name = 'Richard' if with_first_name else ''
    password = '1wsuper1Secet2Password;'
    url = reverse_query('lock8:register')

    response = drf_client.post(url, data={
        'email': email,
        'password': password,
        'first_name': first_name,
        'last_name': 'Stallman'})
    assert response.status_code == status.HTTP_204_NO_CONTENT

    u1 = User.objects.get(email=email)
    assert u1.check_password(password)
    assert not u1.is_active

    assert len(mailoutbox) == 1
    activation_mail = mailoutbox[0]
    assert activation_mail.subject == (
        f'Noa - {settings.ACTIVATION_EMAIL_SUBJECT}')
    if with_first_name:
        assert activation_mail.body.startswith("Richard,\n\nwelcome")
    else:
        assert activation_mail.body.startswith('Welcome')

    token = default_token_generator.make_token(u1)
    user_uuid = str(u1.uuid)

    activation_url = next(filter(
        lambda x: x.startswith('{}?'.format(settings.FRONTEND_ACTIVATE_URL)),
        activation_mail.body.split('\n')
    ))
    parsed_url = urlparse(activation_url)
    assert parsed_url.path == '/account/activate'
    assert parsed_url.query == 'uuid={}&amp;token={}'.format(user_uuid, token)

    kwargs = {'uuid': user_uuid, 'token': token}
    if activate_method == 'GET':
        activation_url = reverse_query('lock8:activate', kwargs=kwargs)

        response = drf_client.get(activation_url)
        assert response.status_code == status.HTTP_302_FOUND
        assert response.has_header('Cache-Control')
        # Verify code.
        parsed_url = urlparse(response.url)
        parsed_query = dict(parse_qsl(parsed_url.query))
        code = unquote(parsed_query['code'])
    elif activate_method == 'POST':
        activation_url = reverse_query('lock8:activate')
        response = drf_client.post(activation_url, data=kwargs)
        assert response.status_code == status.HTTP_200_OK, response.data
        code = response.data['code']
    else:  # pragma: no cover
        raise RuntimeError('Unexpected activate_method')

    auth_code_cache = caches['auth_codes']
    assert code in auth_code_cache
    assert auth_code_cache.get(code) == user_uuid

    u1.refresh_from_db()
    assert u1.is_active

    url = reverse_query('lock8:jwt-login')
    response = drf_client.assert_success(url, data={
        'email': email,
        'password': password
    })
    assert 'token' in response.data
    assert 'refresh_token' in response.data
    assert response.data['refresh_token'] is not None

    url = reverse_query('lock8:bicycle-list')
    drf_client.credentials(
        HTTP_AUTHORIZATION='JWT ' + jwt_encode_handler(
            jwt_payload_handler(u1)
        )
    )
    drf_client.assert_success(url)


def test_email_register_invalid_details(drf_client):
    email = 'INVALID-EMAIL'
    password = 'super1Secret2Password'
    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': email, 'password': password
    })
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_email_register_no_login_when_not_activated(
        drf_client, root_org, mocked_redis_incr_with_cleared_cache):
    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman'
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT

    url = reverse_query('lock8:jwt-login')
    drf_client.assert_400(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
    }, expected_detail={
        'non_field_errors': [
            {'message': 'Invalid credentials.',
             'code': 'invalid_credentials'}]})
    assert mocked_redis_incr_with_cleared_cache.call_count == 1


@pytest.mark.parametrize('activate_method', ('GET', 'POST', 'deprecated_POST',
                                             'deprecated_POST_without_data'))
def test_email_register_invalid_activation_token(activate_method, drf_client):
    from django.conf import settings
    from django.core.cache import caches
    from velodrome.lock8.models import User

    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman'
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT

    u1 = User.objects.get(email='rms@fsf.org')
    token = default_token_generator.make_token(u1)

    kwargs = {'uuid': str(u1.uuid), 'token': token}
    with freeze_time(timezone.now() + dt.timedelta(seconds=1)):
        if activate_method == 'GET':
            url = reverse_query('lock8:activate', kwargs=kwargs)
            response = drf_client.get(url)
            assert response.status_code == status.HTTP_302_FOUND
        else:
            data = kwargs
            if activate_method == 'deprecated_POST':
                url = reverse_query('lock8:activate', kwargs=kwargs)
            elif activate_method == 'deprecated_POST_without_data':
                url = reverse_query('lock8:activate', kwargs=kwargs)
                data = {}
            else:
                url = reverse_query('lock8:activate')
            response = drf_client.post(url, data=data, format='json')
            assert response.status_code == status.HTTP_200_OK, response.data
            code = response.data['code']
            auth_code_cache = caches['auth_codes']
            assert code in auth_code_cache
            assert auth_code_cache.get(code) == str(u1.uuid)

    expected_errors = {'token': [{'code': 'already_activated',
                                  'message': 'Stale token for given user.'}]}
    if activate_method == 'GET':
        url = reverse_query('lock8:activate', kwargs=kwargs)
        response = drf_client.get(url)
        assert response.status_code == status.HTTP_302_FOUND
        url, errors = response.get('Location').split('?errors=')
        assert url == settings.FRONTEND_ACTIVATE_URL
        assert json.loads(unquote_plus(errors)) == expected_errors
    else:
        data = kwargs
        if activate_method == 'deprecated_POST':
            url = reverse_query('lock8:activate', kwargs=kwargs)
        elif activate_method == 'deprecated_POST_without_data':
            url = reverse_query('lock8:activate', kwargs=kwargs)
            data = {}
        else:
            url = reverse_query('lock8:activate')
        response = drf_client.post(url, data=data, format='json')
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.data == {'detail': expected_errors}


def test_email_register_stale_activation_token(drf_client):
    from django.core.cache import caches
    from velodrome.lock8.models import User

    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman'
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT

    u1 = User.objects.get(email='rms@fsf.org')
    url = reverse_query('lock8:activate')
    now = timezone.now()
    with freeze_time(now):
        token = default_token_generator.make_token(u1)
        data = {'uuid': str(u1.uuid), 'token': token}
        response = drf_client.post(url, data=data)
    assert response.status_code == status.HTTP_200_OK, response.data
    code = response.data['code']
    auth_code_cache = caches['auth_codes']
    assert code in auth_code_cache
    assert auth_code_cache.get(code) == str(u1.uuid)

    with freeze_time(now):
        response = drf_client.post(url, data=data)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {'detail': {
        'token': [{'code': 'already_activated',
                   'message': 'Stale token for given user.'}]}}


def test_email_register_with_org_uuid(drf_client, org, another_org,
                                      mailoutbox):
    from velodrome.lock8.models import User

    drf_client.commit_db_on_successful_response = True

    org.is_open_fleet = True
    org.is_whitelabel = True
    org.save()
    another_org.is_open_fleet = True
    another_org.is_whitelabel = True
    another_org.save()

    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman',
        'organization_uuid': org.uuid,
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert [x.subject for x in mailoutbox] == [
        f'org - {settings.ACTIVATION_EMAIL_SUBJECT}']

    mailoutbox[:] = []
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman',
        'organization_uuid': org.uuid,
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert [x.subject for x in mailoutbox] == [
        f'org - {settings.ACTIVATION_EMAIL_SUBJECT}']

    user = User.objects.get(email='rms@fsf.org')
    assert str(org.uuid) in user.username
    assert user.organizations.get(affiliation__role='renter') == org
    assert user.organization == org
    user.is_active = True
    user.save()

    mailoutbox[:] = []
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman',
        'organization_uuid': org.uuid,
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert [x.subject for x in mailoutbox] == [
        f'org - {settings.SUSPICIOUS_REGISTRATION_EMAIL_SUBJECT}']

    url = reverse_query('lock8:jwt-login')
    response = drf_client.assert_success(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'organization_uuid': org.uuid,
    })
    assert 'token' in response.data
    assert 'refresh_token' in response.data
    assert response.data['refresh_token'] is not None

    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman',
        'organization_uuid': another_org.uuid,
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT

    user = User.objects.get(email='rms@fsf.org', organization=another_org)
    assert str(another_org.uuid) in user.username
    assert user.organizations.get(affiliation__role='renter') == another_org
    assert user.organization == another_org
    user.is_active = True
    user.save()

    url = reverse_query('lock8:jwt-login')
    response = drf_client.assert_success(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'organization_uuid': another_org.uuid,
    })
    assert 'token' in response.data
    assert 'refresh_token' in response.data
    assert response.data['refresh_token'] is not None


def test_email_register_with_invalid_org_uuid(drf_client, non_matching_uuid):
    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman',
        'organization_uuid': non_matching_uuid,
    })
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.parametrize('password,errors', [
    (
        'a1b2c3d',
        [
            (
                'password_too_short',
                'This password is too short. It must contain at least 8 characters.'  # noqa
            )
        ]
     ),
    (
        '123456789',
        [
            (
                'password_too_common',
                ErrorDetail(
                    string='This password is too common.',
                    code='password_too_common'
                )
            ),
            (
                'password_entirely_numeric',
                ErrorDetail(
                    string='This password is entirely numeric.',
                    code='password_entirely_numeric'
                )
            )
        ]
    ),
    (
        '111111111',
        [
            (
                'password_too_common',
                ErrorDetail(
                    string='This password is too common.',
                    code='password_too_common'
                )
            ),
            (
                'password_entirely_numeric',
                ErrorDetail(
                    string='This password is entirely numeric.',
                    code='password_entirely_numeric'
                )
            )
        ]
    ),
])
def test_email_register_with_invalid_password(drf_client, password, errors):
    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': password,
        'first_name': 'Richard',
        'last_name': 'Stallman',
    })
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert errors == [(d['code'], d['message'])
                      for d in response.data['detail']['password']]


def test_email_register_with_org_and_allowed_signup_domain_names(
        drf_client, org):
    from velodrome.lock8.models import User

    org.allowed_signup_domain_names = ['fsf.org']
    org.save()

    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman',
        'organization_uuid': org.uuid,
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT

    user = User.objects.get(email__iexact='rms@fsf.org')
    assert user.organizations.get() == org


def test_email_register_with_org_and_allowed_signup_domain_names_non_match(
        drf_client, org):
    org.allowed_signup_domain_names = ['example.ooooorrrrrggg']
    org.save()

    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman',
        'organization_uuid': org.uuid,
    })
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_email_register_with_org_not_open_fleet(drf_client, org):
    org.is_open_fleet = False
    org.save()

    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman',
        'organization_uuid': org.uuid,
    })
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_login_without_org_uuid_but_no_user(
        drf_client, org, mocked_redis_incr_with_cleared_cache):
    url = reverse_query('lock8:jwt-login')
    drf_client.assert_400(url, {
        'non_field_errors': [{
            'code': 'invalid_credentials',
            'message': 'Invalid credentials.'}]
    }, data={'email': 'rms@fsf.org', 'password': 'superSecretPassword'})
    assert mocked_redis_incr_with_cleared_cache.call_count == 1


def test_login_with_org_uuid_but_no_user(
        drf_client, org, mocked_redis_incr_with_cleared_cache):
    url = reverse_query('lock8:jwt-login')
    drf_client.assert_400(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'organization_uuid': org.uuid,
    })
    assert mocked_redis_incr_with_cleared_cache.call_count == 1


def test_login_with_invalid_org_uuid(drf_client, non_matching_uuid):
    url = reverse_query('lock8:jwt-login')
    drf_client.assert_400(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'organization_uuid': non_matching_uuid,
    })


def test_email_register_with_org_uuid_and_another_bicycle(drf_client, org,
                                                          another_org,
                                                          another_bicycle):
    org.is_open_fleet = True
    org.save()
    another_org.is_open_fleet = True
    another_org.save()

    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman',
        'organization_uuid': org.uuid,
        'bicycle_uuid': another_bicycle.uuid
    })
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (response.data['detail']['bicycle_uuid'][0]['code'] ==
            'bicycle_organization_mismatch')


def test_email_register_with_org_uuid_and_another_invitation(
        drf_client, org, another_org, owner, fleet_operator):
    from velodrome.lock8.models import Invitation
    another_invitation = Invitation.objects.create(
        owner=owner,
        organization=another_org,
        email='rms@fsf.org',
    )
    another_invitation.provision(by=fleet_operator)
    org.is_open_fleet = True
    org.is_whitelabel = True
    org.save()
    another_org.is_open_fleet = True
    another_org.is_whitelabel = True
    another_org.save()

    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman',
        'organization_uuid': org.uuid,
        'invitation_uuid': another_invitation.uuid
    })
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert (response.data['detail']['invitation_uuid'][0]['code'] ==
            'invitation_organization_mismatch')


def test_social_local_account_are_distinct(drf_client, client,
                                           login_alice_with_google):
    from velodrome.lock8.models import User

    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'foo@bar.com',  # same email as `google_user_data_body`
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman'
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT

    u1 = User.objects.get(email='foo@bar.com')
    u1.is_active = True
    u1.save()

    accounts, _ = login_alice_with_google(client=client)
    assert accounts.count() == 2
    with pytest.raises(Customer.DoesNotExist):
        u1.customers.get()

    url = reverse_query('lock8:jwt-login')
    response = drf_client.post(url, data={
        'email': 'foo@bar.com',
        'password': 'superSecretPassword',
    })
    assert response.status_code == status.HTTP_200_OK
    assert 'token' in response.data
    assert 'refresh_token' in response.data
    assert response.data['refresh_token'] is not None


def test_signup_with_social_auth_account(client, drf_client, root_org,
                                         login_alice_with_google):
    from velodrome.lock8.models import User

    google_user, _ = login_alice_with_google(client=client)

    url = reverse_query('lock8:register')
    drf_client.credentials(
        HTTP_AUTHORIZATION='JWT ' + jwt_encode_handler(
            jwt_payload_handler(google_user)))

    response = drf_client.post(url, data={
        'email': 'foo@bar.com',  # same email as `google_user_data_body`
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman'
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT

    assert (google_user.refresh_tokens
            .filter(app='lock8_google_oauth2').exists())

    # activate immediately
    local_account = User.objects.filter_local_users(email='foo@bar.com').get()
    assert local_account.refresh_tokens.filter(app='local').exists()

    local_account.is_active = True
    with pytest.raises(Customer.DoesNotExist):
        local_account.customers.get()
    local_account.save()

    url = reverse_query('lock8:jwt-login')
    response = drf_client.post(url, data={
        'email': 'foo@bar.com',
        'password': 'superSecretPassword',
    })
    assert response.status_code == status.HTTP_200_OK
    assert 'token' in response.data
    assert 'refresh_token' in response.data
    assert all(tk is not None for tk in (response.data['token'],
                                         response.data['refresh_token']))
    with pytest.raises(Customer.DoesNotExist):
        google_user.customers.get()
    with pytest.raises(Customer.DoesNotExist):
        local_account.customers.get()


@pytest.mark.parametrize('as_renter', [True, False])
def test_password_reset_confirm_login(drf_client, non_matching_uuid,
                                      mailoutbox, as_renter, org):
    from velodrome.lock8.models import Affiliation, User

    drf_client.commit_db_on_successful_response = True

    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman'
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT

    u1 = User.objects.get(email='rms@fsf.org')
    u1.is_active = True
    u1.save()
    if not as_renter:
        Affiliation.objects.create(
            user=u1,
            organization=org,
            role=Affiliation.FLEET_OPERATOR
        )
        frontend_url = settings.FRONTEND_URL + '/reset'
    else:
        frontend_url = settings.FRONTEND_RESET_URL

    forgot_url = reverse_query('lock8:password-forgot')
    response = drf_client.post(
        forgot_url, data={'email': 'rms@fsf.org'},
    )
    assert response.status_code == status.HTTP_204_NO_CONTENT

    assert len(mailoutbox) == 2
    reset_mail = mailoutbox[1]
    assert reset_mail.subject == f'Noa - {settings.RESET_EMAIL_SUBJECT}'

    token = default_token_generator.make_token(u1)
    user_uuid = str(u1.uuid)
    assert frontend_url in reset_mail.body, reset_mail.body
    reset_url = next(filter(
        lambda x: x.startswith(frontend_url),
        reset_mail.body.split('\n')
    ))

    parsed_url = urlparse(reset_url)
    filtered_path = list(filter(bool, parsed_url.path.split('/')))
    parsed_token, parsed_uuid = filtered_path[1], filtered_path[2]
    assert parsed_token == token
    assert parsed_uuid == user_uuid
    assert parsed_url.query == 'email=rms%40fsf.org'

    url = reverse_query('lock8:password-reset')
    response = drf_client.post(url, data={
        'token': 'INVALID', 'uuid': non_matching_uuid,
        'new_password': 'newPassword123'
    })
    assert response.status_code == status.HTTP_400_BAD_REQUEST

    url = reverse_query('lock8:password-reset')
    response = drf_client.post(url, data={
        'token': token, 'uuid': user_uuid,
        'new_password': 'newPassword123'
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT

    url = reverse_query('lock8:jwt-login')
    drf_client.assert_success(url, data={
        'email': 'rms@fsf.org',
        'password': 'newPassword123'
    })


@pytest.mark.parametrize('data,with_user,errors', (
    ({'uuid': '13799eff-2d25-4c07-ba80-14f59f905316',
      'token': '47p-41e2d2839b85b6ab46ab'},
     False,
     {'uuid': [{'code': 'invalid', 'message': 'User does not exist.'}]}),
    ({'uuid': '13799eff-2d25-4c07-ba80-14f59f905316',
      'token': '47p-41e2d2839b85b6ab46ab'},
     True,
     {'token': [{'code': 'invalid',
                 'message': 'Invalid token for given user.'}]}),
))
def test_activation_rejects_bad_or_missing_fields(drf_client, data, with_user,
                                                  errors):
    from django.conf import settings

    if with_user:
        from velodrome.lock8.models import User
        User.objects.create(uuid=data['uuid'],
                            email='example@example.com',
                            username='example',
                            is_active=False)
    resp = drf_client.get(reverse_query('lock8:activate', kwargs=data))
    assert resp.status_code == status.HTTP_302_FOUND
    url, got_errors = resp.get('Location').split('?errors=')
    assert url == settings.FRONTEND_ACTIVATE_URL
    assert json.loads(unquote_plus(got_errors)) == errors


@pytest.mark.parametrize('data', ([
    {'uuid': 'invalid', 'token': 'anything'},
]))
def test_activation_doesnt_match(drf_client, data):
    with pytest.raises(NoReverseMatch):
        drf_client.get(reverse_query('lock8:activate', kwargs=data))


@pytest.mark.parametrize('data', ([
    {'email': 'e1', 'password': 'p1'},
    {'password': 'p1'}, {'email': 'e1'}
]))
def test_registration_rejects_bad_or_missing_fields(drf_client, data):
    url = reverse_query('lock8:register')
    response = drf_client.post(url, data)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_login_rejects_bad_password_and_missing_fields(
        drf_client, root_org, mocked_redis_incr_with_cleared_cache):
    from velodrome.lock8.models import User

    url = reverse_query('lock8:register')
    drf_client.assert_status(url, status.HTTP_204_NO_CONTENT, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman'
    })

    u1 = User.objects.get(email='rms@fsf.org')
    u1.is_active = True
    u1.save()

    url = reverse_query('lock8:jwt-login')
    drf_client.assert_400(url, data={'email': 'rms@fsf.org',
                                     'password': 'incorrectPassword'})
    assert mocked_redis_incr_with_cleared_cache.call_count == 1
    drf_client.assert_400(url, data={'email': 'rms@fsf.org'})
    drf_client.assert_400(url, data={'password': 'superSecretPassword'})
    assert mocked_redis_incr_with_cleared_cache.call_count == 1


def test_password_reset_rejects_bad_or_missing_fields(drf_client, alice):
    url = reverse_query('lock8:password-forgot')
    drf_client.assert_400(url, data={'email': 'INVALID'})
    drf_client.assert_400(url, data={})

    url = reverse_query('lock8:password-reset')
    drf_client.assert_400(url, data={'new_password': 'newPassword123'})
    drf_client.assert_400(
        url,
        data={'new_password': '1233445678',
              'uuid': alice.uuid,
              'token': default_token_generator.make_token(alice)},
        expected_detail={'new_password': [
            {'code': 'password_entirely_numeric',
             'message': 'This password is entirely numeric.'}]})


def test_password_reset_with_whitelabel_user(drf_client, org, renter,
                                             non_matching_uuid, mailoutbox):
    url = reverse_query('lock8:password-forgot')

    response = drf_client.post(url, data={'email': renter.email,
                                          'organization_uuid': org.uuid})
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert not mailoutbox

    response = drf_client.post(url,
                               data={'email': renter.email,
                                     'organization_uuid': non_matching_uuid})
    assert response.status_code == status.HTTP_400_BAD_REQUEST, response.data
    assert response.data == {'detail': {
        'organization_uuid': [{'code': 'organization_not_found',
                               'message': 'Organization not found.'}]}}

    renter.organization = org
    renter.save()

    response = drf_client.post(url, data={'email': renter.email,
                                          'organization_uuid': org.uuid})
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert len(mailoutbox) == 1
    assert mailoutbox[0].subject == f'Noa - {settings.RESET_EMAIL_SUBJECT}'

    # Finds whitelabel user also without organization_uuid.
    # Workaround for FMS (and likely iOS).
    response = drf_client.post(url, data={'email': renter.email})
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert len(mailoutbox) == 2
    assert mailoutbox[1].subject == f'Noa - {settings.RESET_EMAIL_SUBJECT}'

    UserSocialAuth.objects.create(user=renter)

    response = drf_client.post(url, data={'email': renter.email,
                                          'organization_uuid': org.uuid})
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert len(mailoutbox) == 2

    response = drf_client.post(url, data={'email': renter.email})
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert len(mailoutbox) == 2


def test_activation_info_cant_be_used_for_password_reset(drf_client,
                                                         mailoutbox):
    from django.conf import settings
    from velodrome.lock8.models import User

    drf_client.commit_db_on_successful_response = True

    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman'
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert len(mailoutbox) == 1

    activation_mail = mailoutbox[0]
    assert activation_mail.subject == (
        f'Noa - {settings.ACTIVATION_EMAIL_SUBJECT}')
    u1 = User.objects.get(email='rms@fsf.org')
    token = default_token_generator.make_token(u1)

    url = reverse_query('lock8:password-reset')
    response = drf_client.post(url, data={
        'token': token, 'uuid': u1.uuid,
        'new_password': 'newPassword123'
    })
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_password_reset_stale_confirmation_link(drf_client, non_matching_uuid,
                                                mailoutbox, caplog, root_org):
    from velodrome.lock8.models import User

    drf_client.commit_db_on_successful_response = True

    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman'
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert len(mailoutbox) == 1

    u1 = User.objects.get(email='rms@fsf.org')
    u1.is_active = True
    u1.save()

    url = reverse_query('lock8:password-forgot')
    response = drf_client.post(url, data={'email': 'rms@fsf.org'})
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert len(mailoutbox) == 2

    # Check logging
    msgs = [rec.message for rec in caplog.records]
    for m in [
            "Sending email to ['rms@fsf.org'] (Noa - Reset password, ",
            "Sending email to ['rms@fsf.org'] (Noa - Account activation, ",
    ]:
        assert any(msg.startswith(m) for msg in msgs)

    token = default_token_generator.make_token(u1)

    url = reverse_query('lock8:password-reset')
    response = drf_client.post(url, data={
        'token': token, 'uuid': u1.uuid,
        'new_password': 'newPassword123'
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT

    url = reverse_query('lock8:password-reset')
    response = drf_client.post(url, data={
        'token': token, 'uuid': u1.uuid,
        'new_password': 'newPassword123'
    })
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {
        'detail': {'token': [{'code': 'invalid',
                              'message': 'Invalid token for given user.'}]}}

    response = drf_client.post(url, data={
        'token': token, 'uuid': non_matching_uuid,
        'new_password': 'newerPassword'
    })
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_password_does_not_reset_resends_activation_if_inactive(drf_client, mailoutbox,
                                                       root_org):
    drf_client.commit_db_on_successful_response = True

    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman'
    })

    url = reverse_query('lock8:password-forgot')
    response = drf_client.post(url, data={'email': 'rms@fsf.org'})
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert [x.subject for x in mailoutbox] == [
        f'Noa - {settings.ACTIVATION_EMAIL_SUBJECT}'
    ]


def test_password_reset_no_user_found(drf_client):
    url = reverse_query('lock8:password-forgot')
    response = drf_client.post(url, data={'email': 'foo@bar.com'})
    assert response.status_code == status.HTTP_204_NO_CONTENT


def test_password_reset_only_social_user_found(drf_client, social_alice):
    url = reverse_query('lock8:password-forgot')
    response = drf_client.post(url, data={'email': social_alice.email})
    assert response.status_code == status.HTTP_204_NO_CONTENT


def test_slug_username_raises_409(mocker, drf_client, alice):
    from velodrome.lock8.models import User
    from velodrome.lock8.serializers import EmailRegistrationSerializer

    request = drf_client.get(reverse_query('lock8:api-root'))
    request.user = None
    data = {'email': 'rms@fsf.org',
            'password': 'superSecretPassword',
            'first_name': 'Richard',
            'last_name': 'Stallman'}
    serializer = EmailRegistrationSerializer(data=data,
                                             context={'request': request})
    assert serializer.is_valid(raise_exception=True)

    mocker.patch('velodrome.lock8.models.random', return_value=4)
    alice.username = User.generate_username_from_email(data['email'])
    alice.save()
    with pytest.raises(DuplicateContentError):
        serializer.create(serializer.validated_data)


@pytest.mark.parametrize('activate', (True, False))
def test_local_accounts_email_must_be_unique(activate, drf_client, mailoutbox,
                                             root_org):
    from velodrome.lock8.models import User

    drf_client.commit_db_on_successful_response = True

    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman'
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT
    user1 = User.objects.get(email='rms@fsf.org')
    assert [x.subject for x in mailoutbox] == ['Noa - Account activation']
    mailoutbox[:] = []

    if activate:
        user1.is_active = True
        user1.save()

    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'RMS@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman'
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT

    if activate:
        assert [x.subject for x in mailoutbox] == [
            f'Noa - {settings.SUSPICIOUS_REGISTRATION_EMAIL_SUBJECT}']
    else:
        assert [x.subject for x in mailoutbox] == [
            f'Noa - {settings.ACTIVATION_EMAIL_SUBJECT}']


def test_invitation_requires_email(drf_fleet_operator, org):
    inv_url = reverse_query('lock8:invitation-list')
    org_url = reverse_query('lock8:organization-detail',
                            kwargs={'uuid': org.uuid})
    drf_fleet_operator.assert_400(
        inv_url, {'email': [{'code': 'required',
                             'message': 'This field is required.'}]},
        method='post', data={'organization': org_url})


def test_invitation_registration_flow_skips_activation(drf_fleet_operator,
                                                       org, drf_client, owner,
                                                       non_matching_uuid,
                                                       mailoutbox):
    from velodrome.lock8.models import User, InvitationStates, Invitation

    inv_url = reverse_query('lock8:invitation-list')
    org_url = reverse_query('lock8:organization-detail',
                            kwargs={'uuid': org.uuid})
    response = drf_fleet_operator.post(inv_url, data={
        'organization': org_url, 'email': 'rms@fsf.org'}
    )
    assert response.status_code == status.HTTP_201_CREATED

    reg_url = reverse_query('lock8:register')
    invitation_uuid = response.data['uuid']
    response = drf_client.post(reg_url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman',
        'invitation_uuid': invitation_uuid
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT

    user = User.objects.get(email='rms@fsf.org')
    assert user.is_active
    refresh_token = user.refresh_tokens.get()
    assert refresh_token.app == 'local'
    assert len(mailoutbox) == 1

    invitation = Invitation.objects.get(uuid=invitation_uuid)
    assert invitation.state == InvitationStates.CONFIRMED.value

    login_url = reverse_query('lock8:jwt-login')
    drf_client.assert_success(login_url, data={
        'email': 'rms@fsf.org', 'password': 'superSecretPassword'
    })

    reg_url = reverse_query('lock8:register')
    response = drf_client.post(reg_url, data={
        'email': 'wizard@oz.com',
        'password': 'tinman123;!',
        'first_name': 'Rich',
        'last_name': 'Guy',
        'invitation_uuid': non_matching_uuid
    })
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {'detail': {'invitation_uuid': [
        {'code': 'not_found',
         'message': 'No Invitation with given UUID exists.'}]}}


def test_registration_does_not_check_confirmed_invitations(
        drf_fleet_operator, org, drf_client, owner):
    from velodrome.lock8.models import Invitation

    invitation = Invitation.objects.create(
        organization=org, email='rms@fsf.org',
        owner=owner,
    )
    invitation.provision()
    invitation.confirm(by=owner)

    reg_url = reverse_query('lock8:register')
    response = drf_client.post(reg_url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman',
        'invitation_uuid': invitation.uuid
    })
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {'detail': {'invitation_uuid': [
        {'code': 'not_found',
         'message': 'No Invitation with given UUID exists.'}]}}


def test_registration_with_allowed_signup_domain_names_and_activation(
        org, drf_client, owner, another_org):
    from velodrome.lock8.models import Invitation

    another_org.allowed_signup_domain_names = ['fsf.org']
    another_org.save()

    invitation = Invitation.objects.create(
        organization=org, email='rms@fsf.org', owner=owner)
    invitation.provision()

    reg_url = reverse_query('lock8:register')
    response = drf_client.post(reg_url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman',
        'invitation_uuid': invitation.uuid
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT
    invitation.refresh_from_db()
    assert invitation.user.get_organizations(Q(pk=org.pk)).exists()
    assert invitation.user.get_organizations(Q(pk=another_org.pk)).exists()


def test_invitation_already_affiliated_local_account_400(drf_fleet_operator,
                                                         org, drf_client,
                                                         owner):
    from velodrome.lock8.models import Invitation, InvitationStates, User

    invitation = Invitation.objects.create(
        organization=org, email='rms@fsf.org',
        owner=owner,
    )
    invitation.provision()

    reg_url = reverse_query('lock8:register')
    response = drf_client.post(reg_url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman',
        'invitation_uuid': invitation.uuid
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT

    user = User.objects.get(email='rms@fsf.org')
    assert user.is_active

    invitation.refresh_from_db()
    assert invitation.state == InvitationStates.CONFIRMED.value

    url = reverse_query('lock8:invitation-list')
    organization_url = reverse_query(
        'lock8:organization-detail', kwargs={'uuid': org.uuid}
    )
    response = drf_fleet_operator.post(url, data={
        'organization': organization_url, 'email': 'rms@fsf.org'}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data['detail'] == {
        'non_field_errors': [
            {'message': 'This email address already has an existing'
             ' affiliation with this organization.',
             'code': 'already_member'}]}


def test_invitation_already_affiliated_whitelabel(
        drf_fleet_operator, org, alice, owner, drf_client):
    from velodrome.lock8.models import Affiliation, Invitation, User

    org.is_whitelabel = True
    org.save()
    alice.organization = org
    alice.save()

    Affiliation.objects.create(organization=org, user=alice)

    url = reverse_query('lock8:invitation-list')
    organization_url = reverse_query(
        'lock8:organization-detail', kwargs={'uuid': org.uuid}
    )
    response = drf_fleet_operator.post(url, data={
        'organization': organization_url,
        'email': alice.email,
        'role': Affiliation.FLEET_OPERATOR,
    }
    )
    assert response.status_code == status.HTTP_201_CREATED

    invitation = Invitation.objects.get(uuid=response.data['uuid'])

    reg_url = reverse_query('lock8:register')
    response = drf_client.post(reg_url, data={
        'email': alice.email,
        'password': 'superSecretPassword',
        'first_name': 'Alice',
        'last_name': 'In Chains',
        'invitation_uuid': invitation.uuid
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT

    fleet_op_account_alice = User.objects.get(
        email=alice.email,
        organization__isnull=True)
    assert (
        User.objects.filter_local_whitelabel_users(
            org, email=alice.email).get() == alice)
    assert (
        User.objects.filter_local_users(
            email=alice.email).get() == fleet_op_account_alice)
    assert (alice.organizations
            .filter(affiliation__role=Affiliation.RENTER)
            .exists())
    assert (fleet_op_account_alice.organizations
            .filter(affiliation__role=Affiliation.FLEET_OPERATOR)
            .exists())


def test_invitation_check_email_domain_validation_on_creation(
        drf_fleet_operator, org, drf_client, owner, organization_preference):
    organization_preference.email_domain_validation = 'example.org'
    organization_preference.save()

    url = reverse_query('lock8:invitation-list')
    organization_url = reverse_query(
        'lock8:organization-detail', kwargs={'uuid': org.uuid}
    )
    response = drf_fleet_operator.post(url, data={
        'organization': organization_url, 'email': 'rms@fsf.org'}
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data['detail'] == {
        'non_field_errors': [
            {'message': 'User email address domain is not allowed,'
             " it should belong to 'example.org'.",
             'code': 'unauthorized_email_domain'}]}

    response = drf_fleet_operator.post(url, data={
        'organization': organization_url, 'email': 'rms@example.org'}
    )
    assert response.status_code == status.HTTP_201_CREATED


def test_invitation_check_email_domain_validation_on_creation_wo_pref(
        drf_fleet_operator, org, drf_client, owner, organization_preference):
    organization_preference.delete()

    url = reverse_query('lock8:invitation-list')
    organization_url = reverse_query(
        'lock8:organization-detail', kwargs={'uuid': org.uuid}
    )
    response = drf_fleet_operator.post(url, data={
        'organization': organization_url, 'email': 'rms@fsf.org'}
    )
    assert response.status_code == status.HTTP_201_CREATED


def test_email_login_is_case_insensitive(drf_client, alice):
    url = reverse_query('lock8:jwt-login')
    response = drf_client.post(url, data={
        'email': 'ALICE@example.com',
        'password': 'pwd_alice',
    })
    assert response.status_code == status.HTTP_200_OK
    assert 'token' in response.data
    assert 'refresh_token' in response.data


def test_password_forgot_is_case_insensitive(drf_client, alice):
    url = reverse_query('lock8:password-forgot')
    response = drf_client.post(url, data={'email': 'ALICE@example.com'})
    assert response.status_code == status.HTTP_204_NO_CONTENT


def test_signup_domain_name_preference_is_set(drf_client, org):
    from velodrome.lock8.models import User

    org.allowed_signup_domain_names = ['google.com', 'hotmail.com']
    org.save()

    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'foo@bar.com', 'password': 'bark,189:',
        'first_name': 'Foo', 'last_name': 'Bar'})
    assert response.status_code == status.HTTP_204_NO_CONTENT

    foo_user = User.objects.get(email='foo@bar.com')
    assert foo_user.affiliations.count() == 0

    response = drf_client.post(url, data={
        'email': 'bar@google.com', 'password': 'foo,78:qw',
        'first_name': 'Bar', 'last_name': 'Foo'})
    assert response.status_code == status.HTTP_204_NO_CONTENT

    bar_user = User.objects.get(email='bar@google.com')
    assert not bar_user.affiliations.exists()

    token = default_token_generator.make_token(bar_user)

    kwargs = {'uuid': str(bar_user.uuid), 'token': token}
    activation_url = reverse_query('lock8:activate', kwargs=kwargs)
    response = drf_client.get(activation_url)
    assert response.status_code == status.HTTP_302_FOUND

    bar_user.refresh_from_db()
    assert bar_user.affiliations.count() == 1
    assert bar_user.organizations.get() == org


def test_signup_domain_name_org_3_nodes(drf_client, org, root_org, owner):
    from velodrome.lock8.models import Organization, User

    Organization.objects.create(name='org2', parent=root_org, owner=owner)
    org3 = Organization.objects.create(name='org3', parent=root_org,
                                       owner=owner)

    org.allowed_signup_domain_names = ['google.com']
    org.save()

    org3.allowed_signup_domain_names = ['google.com']
    org3.save()

    response = drf_client.post(
        reverse_query('lock8:register'),
        data={'email': 'foo@google.com', 'password': 'barbar123',
              'first_name': 'Foo', 'last_name': 'Bar'})
    assert response.status_code == status.HTTP_204_NO_CONTENT

    foo_user = User.objects.get(email='foo@google.com')
    assert not foo_user.affiliations.exists()

    token = default_token_generator.make_token(foo_user)

    kwargs = {'uuid': str(foo_user.uuid), 'token': token}
    activation_url = reverse_query('lock8:activate', kwargs=kwargs)
    response = drf_client.get(activation_url)
    assert response.status_code == status.HTTP_302_FOUND

    foo_user.refresh_from_db()
    assert foo_user.affiliations.count() == 2
    aff_org1, aff_org2 = foo_user.organizations.all()
    assert aff_org1 == org and aff_org2 == org3


def test_signup_domain_name_with_bicycle_uuid(drf_client, bicycle):
    from velodrome.lock8.models import Affiliation, User

    org = bicycle.organization
    assert not org.is_open_fleet

    url = reverse_query('lock8:register')

    data = {'email': 'foo@bar.com', 'bicycle_uuid': str(bicycle.uuid),
            'password': 'barakj19:', 'first_name': 'Foo', 'last_name': 'Bar'}
    response = drf_client.post(url, data=data)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {'detail': {
        'bicycle_uuid': [{
            'code': 'email_not_whitelisted',
            'message':
                'The email address is not allowed for this organization.'}]}}

    org.allowed_signup_domain_names = ['google.com', 'hotmail.com']
    org.save()

    response = drf_client.post(url, data=data)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {'detail': {
        'bicycle_uuid': [{
            'code': 'email_not_whitelisted',
            'message':
                'The email address is not allowed for this organization.'}]}}

    data['email'] = 'foo@hotmail.com'
    response = drf_client.post(url, data=data)
    assert response.status_code == status.HTTP_204_NO_CONTENT
    user = User.objects.get(email='foo@hotmail.com')
    assert user.affiliations.filter(organization=org,
                                    role=Affiliation.RENTER).exists()
    assert not user.is_active


def test_signup_domain_name_with_invalid_bicycle_uuid(drf_client,
                                                      non_matching_uuid):
    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'foo@bar.com', 'password': 'bar98;,du',
        'first_name': 'Foo', 'last_name': 'Bar',
        'bicycle_uuid': str(non_matching_uuid)})
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {'detail': {
        'bicycle_uuid': [{
            'code': 'invalid', 'message': 'Bicycle not found.'}]}}


def test_invitation_not_allowed_with_bicycle(drf_client, bicycle,
                                             org, owner):
    from velodrome.lock8.models import Invitation

    # To allow for bicycle_uuid validation.
    org.is_open_fleet = True
    org.save()

    invitation = Invitation.objects.create(
        email='rms@fsf.org', organization=org, owner=owner)
    invitation.provision()

    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman',
        'bicycle_uuid': bicycle.uuid,
        'invitation_uuid': invitation.uuid,
    })
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {'detail': {
        'non_field_errors': [{
            'code': 'invalid',
            'message': 'invitation_uuid and bicycle_uuid '
                       'must not be used together.'}]}}


def test_resend_invitation(drf_fleet_operator, mailoutbox, org, owner):
    from velodrome.lock8.models import Invitation

    invitation = Invitation.objects.create(
        email='rms@fsf.org', organization=org, owner=owner)
    invitation.provision()
    assert len(mailoutbox) == 1

    url = reverse_query('lock8:invitation-actions',
                        kwargs={'uuid': invitation.uuid})
    response = drf_fleet_operator.post(url, data={'type': 'resend'})
    assert response.status_code == status.HTTP_200_OK
    assert len(mailoutbox) == 2


def test_bicycle_not_allowed_with_closed_fleet(drf_client, bicycle,
                                               org, owner):
    assert not org.is_open_fleet
    assert not org.allowed_signup_domain_names

    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman',
        'bicycle_uuid': bicycle.uuid,
    })
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {'detail': {
        'bicycle_uuid': [{
            'code': 'email_not_whitelisted',
            'message':
                'The email address is not allowed for this organization.'}]}}


def test_self_signup_redirect_with_valid_code(drf_client, today, root_org):
    from django.core.cache import caches
    from velodrome.lock8.models import User

    url = reverse_query('lock8:register')
    response = drf_client.post(
        url, data={'email': 'rms@fsf.org',
                   'password': 'GNUword18.:',
                   'first_name': 'Richard',
                   'last_name': 'Stallman'})
    assert response.status_code == status.HTTP_204_NO_CONTENT

    user = User.objects.get(email='rms@fsf.org')
    token = default_token_generator.make_token(user)

    kwargs = {'uuid': str(user.uuid), 'token': token}
    activation_url = reverse_query('lock8:activate', kwargs=kwargs)
    response = drf_client.get(activation_url)
    assert response.status_code == status.HTTP_302_FOUND

    parsed_url = urlparse(response.url)
    parsed_query = dict(parse_qsl(parsed_url.query))
    code = unquote(parsed_query['code'])

    auth_code_cache = caches['auth_codes']
    assert code in auth_code_cache
    assert auth_code_cache.get(code) == str(user.uuid)


def test_auto_login_using_code_param(drf_client, alice, auto_login_code):
    url = reverse_query('lock8:jwt-login')
    response = drf_client.post(url, data={'code': auto_login_code})
    assert response.status_code == status.HTTP_200_OK
    assert all(k in response.data for k in ('token', 'refresh_token'))


def test_auto_login_one_time_only(drf_client, auto_login_code):
    url = reverse_query('lock8:jwt-login')
    response = drf_client.post(url, data={'code': auto_login_code})
    assert response.status_code == status.HTTP_200_OK

    url = reverse_query('lock8:jwt-login')
    response = drf_client.post(url, data={'code': auto_login_code})
    assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_auto_login_code_expired(drf_client, auto_login_code, today):
    with freeze_time(today + dt.timedelta(days=2)):
        url = reverse_query('lock8:jwt-login')
        response = drf_client.post(url, data={'code': auto_login_code})
        assert response.status_code == status.HTTP_400_BAD_REQUEST


def test_activation_rejects_invalid_verb(drf_client, alice):
    token = default_token_generator.make_token(alice)
    kwargs = {'uuid': str(alice.uuid), 'token': token}
    activation_url = reverse_query('lock8:activate', kwargs=kwargs)
    response = drf_client.put(activation_url)
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED


def test_user_list_ordering_first_name(drf_fleet_operator, alice, bob, org):
    from velodrome.lock8.models import Affiliation

    Affiliation.objects.create(organization=org,
                               user=alice)
    Affiliation.objects.create(organization=org,
                               user=bob)

    url = reverse_query('lock8:user-list',
                        query_kwargs={'ordering': 'first_name',
                                      'role': 'renter'})
    response = drf_fleet_operator.assert_success(url)
    assert response.data['results'][0]['uuid'] == str(alice.uuid)
    assert response.data['results'][1]['uuid'] == str(bob.uuid)

    url = reverse_query('lock8:user-list',
                        query_kwargs={'ordering': '-first_name',
                                      'role': 'renter'})
    response = drf_fleet_operator.assert_success(url)
    assert response.data['results'][0]['uuid'] == str(bob.uuid)
    assert response.data['results'][1]['uuid'] == str(alice.uuid)


def test_user_list_ordering_last_name(drf_fleet_operator, alice, bob, org):
    from velodrome.lock8.models import Affiliation

    Affiliation.objects.create(organization=org,
                               user=alice)
    Affiliation.objects.create(organization=org,
                               user=bob)

    url = reverse_query('lock8:user-list',
                        query_kwargs={'ordering': 'last_name',
                                      'role': 'renter'})
    response = drf_fleet_operator.assert_success(url)
    assert response.data['results'][0]['uuid'] == str(alice.uuid)
    assert response.data['results'][1]['uuid'] == str(bob.uuid)

    url = reverse_query('lock8:user-list',
                        query_kwargs={'ordering': '-last_name',
                                      'role': 'renter'})
    response = drf_fleet_operator.assert_success(url)
    assert response.data['results'][0]['uuid'] == str(bob.uuid)
    assert response.data['results'][1]['uuid'] == str(alice.uuid)


def test_user_list_ordering_username(drf_fleet_operator, alice, bob, org):
    from velodrome.lock8.models import Affiliation

    Affiliation.objects.create(organization=org,
                               user=alice)
    Affiliation.objects.create(organization=org,
                               user=bob)

    url = reverse_query('lock8:user-list',
                        query_kwargs={'ordering': 'username',
                                      'role': 'renter'})
    response = drf_fleet_operator.assert_success(url)
    assert response.data['results'][0]['uuid'] == str(alice.uuid)
    assert response.data['results'][1]['uuid'] == str(bob.uuid)

    url = reverse_query('lock8:user-list',
                        query_kwargs={'ordering': '-username',
                                      'role': 'renter'})
    response = drf_fleet_operator.assert_success(url)
    assert response.data['results'][0]['uuid'] == str(bob.uuid)
    assert response.data['results'][1]['uuid'] == str(alice.uuid)


def test_user_list_ordering_full_name(drf_fleet_operator, alice, bob, org):
    from velodrome.lock8.models import Affiliation

    Affiliation.objects.create(organization=org,
                               user=alice)
    Affiliation.objects.create(organization=org,
                               user=bob)

    url = reverse_query('lock8:user-list',
                        query_kwargs={'ordering': 'full_name',
                                      'role': 'renter'})
    response = drf_fleet_operator.assert_success(url)
    assert response.data['results'][0]['uuid'] == str(alice.uuid)
    assert response.data['results'][1]['uuid'] == str(bob.uuid)

    url = reverse_query('lock8:user-list',
                        query_kwargs={'ordering': '-full_name',
                                      'role': 'renter'})
    response = drf_fleet_operator.assert_success(url)
    assert response.data['results'][0]['uuid'] == str(bob.uuid)
    assert response.data['results'][1]['uuid'] == str(alice.uuid)


def test_user_list_filtering_full_name(drf_fleet_operator, alice, bob, org):
    from velodrome.lock8.models import Affiliation

    Affiliation.objects.create(organization=org,
                               user=alice)
    Affiliation.objects.create(organization=org,
                               user=bob)

    url = reverse_query('lock8:user-list',
                        query_kwargs={'full_name': 'alice C',
                                      'role': 'renter'})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:user-list',
                        query_kwargs={'full_name': 'AliceC',
                                      'role': 'renter'})
    drf_fleet_operator.assert_count(url, 0)


def test_crud_invitation(drf_fleet_operator, drf_alice, alice, org, admin_user,
                         another_org, settings, image, mailoutbox):
    from velodrome.lock8.models import Invitation

    org.image = image
    org.save()

    url = reverse_query('lock8:invitation-list')
    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})
    response = drf_fleet_operator.post(url,
                                       data={'organization': organization_url,
                                             'email': alice.email})
    assert response.status_code == status.HTTP_201_CREATED

    response_ = drf_fleet_operator.post(url,
                                        data={'organization': organization_url,
                                              'email': alice.email})
    assert response_.status_code == status.HTTP_409_CONFLICT
    assert response_.data['detail'] == {
        'non_field_errors': [
            {'code': 'duplicated_content',
             'message': 'A pending invitation to this organization already'
             ' exists for this email address.'}]}

    invitation = Invitation.objects.get()
    assert org.image.url in response.data['organization_icon']
    del response.data['organization_icon']
    assert response.data == {
        'organization': 'http://testserver' + organization_url,
        'user': None,
        'organization_name': 'org',
        'role': 'renter',
        'uuid': str(invitation.uuid),
        'email': 'alice@example.com',
        'is_registered': True,
        'url': 'http://testserver' + reverse_query(
            'lock8:invitation-detail',
            kwargs={'uuid': invitation.uuid}),
        'state': 'provisioned',
        'concurrency_version': invitation.concurrency_version,
        'modified': invitation.modified.isoformat()[:-13] + 'Z',
        'created': invitation.created.isoformat()[:-13] + 'Z',
    }

    # try a second time, shouldn't be possible
    response = drf_fleet_operator.post(url,
                                       data={'organization': organization_url,
                                             'email': alice.email})
    assert response.status_code == status.HTTP_409_CONFLICT
    assert Invitation.objects.count() == 1

    url = reverse_query('lock8:invitation-list',
                        {'organization': str(another_org.uuid)})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:invitation-actions',
                        kwargs={'uuid': invitation.uuid})
    response = drf_fleet_operator.post(url, data={'type': 'provision'})
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {
        'detail': {
            'actions': [
                {'message': "Action 'provision' not allowed from current"
                 " state 'provisioned'. Available actions:"
                 " ['cancel', 'confirm', 'decline', 'resend'].",
                 'code': 'action_not_allowed'}]}}

    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.subject == ('Noa - Invitation to join the'
                             ' organization {}.'.format(org.name))

    assert settings.FRONTEND_INVITATION_URL in email.body
    assert str(invitation.uuid) in email.body
    assert urlencode({'organization_name': org.name}) in email.body
    assert urlencode({'organization_icon': org.image.url}) in email.body
    assert urlencode({'email': alice.email}) in email.body
    assert urlencode({'signup': '0'}) in email.body

    assert email.recipients() == ['alice@example.com']
    assert not alice.get_organizations().exists()

    url = reverse_query('lock8:invitation-detail',
                        kwargs={'uuid': invitation.uuid})
    response = drf_fleet_operator.put(url)
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    drf_fleet_operator.assert_success(url)

    response = drf_fleet_operator.patch(url)
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    url = reverse_query('lock8:invitation-actions',
                        kwargs={'uuid': invitation.uuid})
    response = drf_alice.post(url, data={'type': 'confirm'})
    assert response.status_code == status.HTTP_200_OK

    invitation.refresh_from_db()
    assert invitation.state == 'confirmed'
    assert list(alice.get_organizations()) == [org]

    url = reverse_query('lock8:invitation-detail',
                        kwargs={'uuid': invitation.uuid})
    drf_alice.assert_success(url)


def test_invitation_can_be_confirmed_by_anyone(drf_client, fleet_operator,
                                               drf_alice, alice, org):
    from velodrome.lock8.models import Invitation

    invitation = Invitation.objects.create(
        organization=org,
        email=alice.email,
        owner=fleet_operator,
    )
    invitation.provision()

    assert not alice.get_organizations().exists()

    url = reverse_query('lock8:invitation-detail',
                        kwargs={'uuid': invitation.uuid})
    response = drf_client.put(url)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    response = drf_client.patch(url)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED

    drf_client.assert_success(url)

    url = reverse_query('lock8:invitation-actions',
                        kwargs={'uuid': invitation.uuid})
    response = drf_alice.post(url, data={'type': 'confirm'})
    assert response.status_code == status.HTTP_200_OK

    url = reverse_query('lock8:invitation-detail',
                        kwargs={'uuid': invitation.uuid})
    response = drf_client.get(url)
    assert response.status_code == status.HTTP_404_NOT_FOUND

    invitation.refresh_from_db()
    assert invitation.state == 'confirmed'
    assert list(alice.get_organizations()) == [org]


def test_filter_invitation(drf_alice, drf_fleet_operator, alice, org,
                           admin_user, owner):
    from velodrome.lock8.models import Invitation

    invitation = Invitation.objects.create(
        organization=org,
        email=alice.email,
        owner=owner)
    url = reverse_query('lock8:invitation-list')
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:invitation-list', {'state': 'provisioned'})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:invitation-list', {'user': str(alice.uuid)})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:invitation-list', {'email': alice.email})
    drf_fleet_operator.assert_count(url, 1)

    invitation.provision()
    url = reverse_query('lock8:invitation-list', {'user': str(alice.uuid)})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:invitation-list')
    drf_alice.assert_count(url, 0)

    url = reverse_query('lock8:invitation-detail',
                        kwargs={'uuid': str(invitation.uuid)})
    response = drf_alice.assert_success(url)
    assert response.data['uuid'] == str(invitation.uuid)


def test_invitation_not_blocked_by_existing_affiliations(drf_fleet_operator,
                                                         drf_admin,
                                                         org, drf_client,
                                                         owner, another_org):
    from velodrome.lock8.models import Invitation, InvitationStates, User

    invitation = Invitation.objects.create(
        organization=org, email='rms@fsf.org',
        owner=owner,
    )
    invitation.provision()

    reg_url = reverse_query('lock8:register')
    response = drf_client.post(reg_url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman',
        'invitation_uuid': invitation.uuid
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT

    user = User.objects.get(email='rms@fsf.org')
    assert user.is_active

    invitation.refresh_from_db()
    assert invitation.state == InvitationStates.CONFIRMED.value

    url = reverse_query('lock8:invitation-list')
    organization_url = reverse_query(
        'lock8:organization-detail', kwargs={'uuid': another_org.uuid}
    )
    response = drf_admin.post(url, data={
        'organization': organization_url, 'email': 'rms@fsf.org'}
    )
    assert response.status_code == status.HTTP_201_CREATED


def test_invitation_registration_flow_with_active_user(org, drf_client, alice,
                                                       owner):
    from velodrome.lock8.models import Invitation, User

    alice.is_active = True
    alice.save()

    reg_url = reverse_query('lock8:register')

    assert User.objects.filter(email__iexact=alice.email).count() == 1

    for i in range(2):
        invitation = Invitation.objects.create(
            organization=org, owner=owner, email=alice.email)
        invitation.provision()

        response = drf_client.post(reg_url, data={
            'email': alice.email,
            'password': 'superSecretPassword',
            'first_name': alice.first_name,
            'last_name': alice.last_name,
            'invitation_uuid': str(invitation.uuid)
        })
        assert response.status_code == status.HTTP_204_NO_CONTENT

        invitation.refresh_from_db()

        assert invitation.state == 'confirmed'

    assert User.objects.filter(email__iexact=alice.email).count() == 1


def test_authenticated_user_can_confirm_invitation(drf_alice, alice, org,
                                                   owner):

    from velodrome.lock8.models import Invitation

    invitation = Invitation.objects.create(
        organization=org, email='rms@fsf.org',
        owner=owner,
    )
    invitation.provision()

    url = reverse_query('lock8:invitation-actions',
                        kwargs={'uuid': invitation.uuid})
    response = drf_alice.post(url, data={'type': 'confirm'})
    assert response.status_code == status.HTTP_200_OK

    assert alice.organizations.get() == org


def test_authenticated_user_has_rejected_invitation(drf_alice, alice, org,
                                                    organization_preference,
                                                    owner):

    from velodrome.lock8.models import Invitation

    invitation = Invitation.objects.create(
        organization=org, email='rms@fsf.org',
        owner=owner,
    )
    invitation.provision()
    organization_preference.email_domain_validation = 'fsf.org'
    organization_preference.save()

    url = reverse_query('lock8:invitation-actions',
                        kwargs={'uuid': invitation.uuid})
    response = drf_alice.post(url, data={'type': 'confirm'})
    assert response.status_code == status.HTTP_400_BAD_REQUEST

    assert not alice.organizations.exists()


def test_user_can_always_see_her_own_account(drf_alice, alice):
    url = reverse_query('lock8:user-detail', kwargs={'uuid': alice.uuid})
    response = drf_alice.assert_success(url)
    assert response.data['uuid'] == str(alice.uuid)


def test_renter_can_see_herself_in_user_list_with_org(drf_renter, renter, org):
    url = reverse_query('lock8:user-list',
                        {'organization': str(org.uuid)})
    response = drf_renter.assert_count(url, 1)
    assert response.data['results'][0]['uuid'] == str(renter.uuid)


def test_current_user(drf_client, drf_renter, renter, org):
    url = reverse_query('lock8:me-detail')

    drf_client.assert_status(url, 401)

    response = drf_renter.assert_success(url)
    assert response.data['uuid'] == str(renter.uuid)
    assert 'accepted_terms_of_services' in response.data
    assert 'new_terms_of_services' in response.data

    url = reverse_query('lock8:me-detail',
                        {'organization': str(org.uuid)})
    response = drf_renter.assert_success(url)
    assert response.data['uuid'] == str(renter.uuid)
    assert response.data['roles'] == ['renter', ]


def test_current_user_accept_tos(drf_client, drf_renter, drf_bob,
                                 another_renter, terms_of_service,
                                 terms_of_service_version):
    accept_url = reverse_query('lock8:me-accept-terms-of-service')
    tos_url = reverse_query('lock8:terms_of_service-detail',
                            kwargs={'uuid': str(terms_of_service.uuid)})
    drf_renter.assert_404(
        accept_url, data={'terms_of_service': tos_url})
    drf_bob.assert_404(
        accept_url, data={'terms_of_service': tos_url})

    terms_of_service.version = terms_of_service_version
    terms_of_service.provision()
    terms_of_service_version.provision()

    list_url = reverse_query('lock8:me-detail')
    response = drf_renter.assert_success(list_url)
    assert len(response.data['accepted_terms_of_services']) == 0
    assert len(response.data['new_terms_of_services']) == 1

    response = drf_renter.post(
        accept_url, data={'terms_of_service': tos_url})
    assert response.status_code == status.HTTP_204_NO_CONTENT

    drf_bob.assert_404(
        accept_url, data={'terms_of_service': tos_url})

    response = drf_renter.assert_success(list_url)
    assert len(response.data['accepted_terms_of_services']) == 1
    assert len(response.data['new_terms_of_services']) == 0
    accepted_tos = response.data['accepted_terms_of_services'][0]
    assert accepted_tos['uuid'] == str(terms_of_service.uuid)


def test_current_user_new_tos(drf_client, drf_renter, terms_of_service,
                              terms_of_service_version):
    terms_of_service.version = terms_of_service_version
    terms_of_service.provision()
    terms_of_service_version.provision()

    url = reverse_query('lock8:me-detail')
    response = drf_renter.assert_success(url)
    assert len(response.data['accepted_terms_of_services']) == 0
    assert len(response.data['new_terms_of_services']) == 1
    new_tos = response.data['new_terms_of_services'][0]
    assert new_tos['uuid'] == str(terms_of_service.uuid)


def test_current_user_queries(drf_renter, renter, terms_of_service,
                              terms_of_service_version, owner, org,
                              another_org):
    from velodrome.lock8.models import (
        Affiliation, TermsOfService, TermsOfServiceVersion)
    Affiliation.objects.create(
        user=drf_renter.user,
        organization=another_org,
        role=Affiliation.RENTER,
    )
    url = reverse_query('lock8:me-detail')

    with CaptureQueriesContext(connection) as capture:
        drf_renter.assert_success(url)
    assert len(capture.captured_queries) == 13

    terms_of_service.version = terms_of_service_version
    terms_of_service.provision()
    terms_of_service_version.provision()
    renter.accept_terms_of_service(terms_of_service)

    with CaptureQueriesContext(connection) as capture:
        drf_renter.assert_success(url)
    assert len(capture.captured_queries) == 13

    terms_of_service_version = TermsOfServiceVersion.objects.create(
        organization=another_org, label='test 2 tos version')
    terms_of_service = TermsOfService.objects.create(
        owner=owner,
        organization=another_org,
        version=terms_of_service_version,
        tos_url='http://example.org',
        language='en',
        content='Test 2 TOS content',
    )
    terms_of_service.provision()
    terms_of_service_version.provision()

    with CaptureQueriesContext(connection) as capture:
        drf_renter.assert_success(url)
    assert len(capture.captured_queries) == 13

    renter.accept_terms_of_service(terms_of_service)

    with CaptureQueriesContext(connection) as capture:
        drf_renter.assert_success(url)
    assert len(capture.captured_queries) == 13


def test_current_user_multi_language_tos(drf_renter, terms_of_service,
                                         terms_of_service_version, renter):
    from velodrome.lock8.models import TermsOfService
    terms_of_service.version = terms_of_service_version
    terms_of_service.provision()
    terms_of_service_fr = TermsOfService.objects.create(
        owner=terms_of_service.owner,
        organization=terms_of_service.organization,
        version=terms_of_service_version,
        language='fr',
        content='',
    )
    terms_of_service_fr.provision()
    terms_of_service_version.provision()

    url = reverse_query('lock8:me-detail')
    response = drf_renter.assert_success(url)
    assert len(response.data['accepted_terms_of_services']) == 0
    assert len(response.data['new_terms_of_services']) == 2

    renter.accept_terms_of_service(terms_of_service)

    response = drf_renter.assert_success(url)
    assert len(response.data['accepted_terms_of_services']) == 1
    assert len(response.data['new_terms_of_services']) == 0


@pytest.mark.parametrize('with_logo', (True, False))
def test_whitelabel_activation_email(with_logo, request, drf_client,
                                     mailoutbox, org):
    drf_client.commit_db_on_successful_response = True

    org.is_open_fleet = True
    org.name = 'White'
    org.is_whitelabel = True
    if with_logo:
        org.user_email_logo = SimpleUploadedFile(
            name='test_image.jpg',
            content='',
            content_type='image/jpeg')
    org.save()
    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'pass;12word1',
        'first_name': 'Richard',
        'last_name': 'Stallman',
        'organization_uuid': org.uuid,
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT, response.data

    assert len(mailoutbox) == 1
    activation_mail = mailoutbox[0]
    assert activation_mail.subject == (
        f'White - {settings.ACTIVATION_EMAIL_SUBJECT}')
    assert 'welcome to your new Rider app, from White' in activation_mail.body
    html, content_type = activation_mail.alternatives[0]
    assert content_type == 'text/html'
    if with_logo:
        assert (
            '<img class="logo" src="http' in html or
            '<img class="logo" src="/' in html
        )
        assert f'src="{org.user_email_logo.url}"' in html
    else:
        assert '<img ' not in html


def test_whitelabel_reset_pass_email(drf_client, mailoutbox, org):
    from velodrome.lock8.models import User

    drf_client.commit_db_on_successful_response = True

    org.is_open_fleet = True
    org.name = 'White'
    org.is_whitelabel = True
    org.save()

    url = reverse_query('lock8:register')
    response = drf_client.post(url, data={
        'email': 'rms@fsf.org',
        'password': 'superSecretPassword',
        'first_name': 'Richard',
        'last_name': 'Stallman',
        'organization_uuid': org.uuid,
    })
    assert response.status_code == status.HTTP_204_NO_CONTENT

    u1 = User.objects.get(email='rms@fsf.org')
    u1.is_active = True
    u1.save()

    forgot_url = reverse_query('lock8:password-forgot')
    response = drf_client.post(
        forgot_url,
        data={'email': 'rms@fsf.org', 'organization_uuid': org.uuid}
    )
    assert response.status_code == status.HTTP_204_NO_CONTENT

    assert len(mailoutbox) == 2
    reset_mail = mailoutbox[1]
    assert reset_mail.subject == f'White - {settings.RESET_EMAIL_SUBJECT}'
    content = 'We received a request to reset your White account password.'
    assert content in reset_mail.body


@pytest.mark.parametrize('param_user', (None, 'alice', 'django_admin_user'))
def test_login_blocked_after_failures(param_user, request,
                                      mocked_redis_incr_with_cleared_cache,
                                      settings, drf_client):
    from velodrome.lock8.authentication import failed_logins_cache

    failed_logins_cache.clear()
    settings.FAILED_LOGINS_MAX_ATTEMPTS = 2

    if param_user:
        user = request.getfixturevalue(param_user)
        email = user.email
    else:
        user = None
        email = 'doesNOTexist@example.com'

    url = reverse_query('lock8:jwt-login')

    data = {'email': email, 'password': 'wrong'}
    drf_client.assert_400(url, data=dict(data, password='a'), expected_detail={
        'non_field_errors': [{
            'code': 'invalid_credentials',
            'message': 'Invalid credentials.'}]})
    # Trying the same password again does not increment the counter.
    drf_client.assert_400(url, data=dict(data, password='a'), expected_detail={
        'non_field_errors': [{
            'code': 'invalid_credentials',
            'message': 'Invalid credentials.'}]})
    drf_client.assert_400(url, data=dict(data, password='b'), expected_detail={
        'non_field_errors': [{
            'code': 'invalid_credentials',
            'message': 'Invalid credentials.'}]})

    failure_msg = ('You have attempted to login 2 times unsuccessfully. '
                   'The account is locked for 5 minutes.')
    failure_response = {
        'detail': {'non_field_errors': [{
            'code': 'authentication_failed',
            'message': failure_msg}]}}
    drf_client.assert_status(url, 403, failure_response, data=data)

    if param_user:
        # Login is now blocked also with correct password.
        if param_user == 'alice':
            data = {'email': email, 'password': 'pwd_alice'}
        else:
            data = {'email': email, 'password': 'password'}
        drf_client.assert_status(url, 403, failure_response, data=data)

        if param_user == 'django_admin_user':
            # Correct password works with admin (uses username, not email).
            admin_login_url = reverse_query('admin:login')
            drf_client.assert_status(admin_login_url, 302, data={
                'username': user.username,
                'password': 'password'})

            # admin login gets blocked after failures, too.
            err_msg = 'Please enter the correct username and password'
            wrong_data = {'username': user.username,
                          'password': 'wrong'}
            response = drf_client.post(admin_login_url, wrong_data)
            assert err_msg in str(response.content)
            response = drf_client.post(admin_login_url, wrong_data)
            assert err_msg in str(response.content)
            # Now blocked.
            response = drf_client.post(admin_login_url, wrong_data)
            assert failure_msg in str(response.content)
        else:
            # It works after stored counts are expired.
            failed_logins_cache.clear()

        drf_client.assert_success(url, data=data)

    assert mocked_redis_incr_with_cleared_cache.call_count
