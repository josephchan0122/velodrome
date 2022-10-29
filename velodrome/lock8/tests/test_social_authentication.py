import jwt
import pytest
from rest_framework import status
from rest_framework_jwt import utils
from rest_framework_jwt.settings import api_settings

from velodrome.lock8.jwt_extensions import jwt_payload_handler
from velodrome.lock8.utils import reverse_query


@pytest.fixture
def client(client_with_csrf):
    client_with_csrf.defaults['HTTP_ACCEPT'] = 'application/json; version=1.0'
    return client_with_csrf


def test_google_oauth2(client, login_alice_with_google, settings, mailoutbox,
                       root_org):
    client.commit_db_on_successful_response = True

    avatar_url = 'https://lh5.googleusercontent.com/-ui-GqpNh5Ms/AAAAAAAAAAI/AAAAAAAAAZw/a7puhHMO_fg/photo.jpg'  # noqa: E501

    user, response = login_alice_with_google(client=client)
    assert response.data['user'] == {
        'avatar': avatar_url,
        'concurrency_version': user.concurrency_version,
        'created': user.created.isoformat()[:-13] + 'Z',
        'display_name': 'Foo Bar',
        'email': 'foo@bar.com',
        'first_name': 'Foo',
        'is_local': False,
        'last_login': user.last_login.isoformat()[:-13] + 'Z',
        'last_name': 'Bar',
        'modified': user.modified.isoformat()[:-13] + 'Z',
        'phone_numbers': None,
        'state': 'new',
        'url': 'http://testserver' + reverse_query('lock8:user-detail',
                                                   kwargs={'uuid': user.uuid}),
        'username': 'foo',
        'uuid': str(user.uuid),
    }
    assert 'refresh_token' in response.data
    jwt_token = response.data['token']
    decoded = jwt.decode(
        jwt_token,
        settings.JWT_SECRET_KEY,
        algorithms=[api_settings.JWT_ALGORITHM])
    assert decoded['iss'] == 'lock8_google_oauth2'

    social_auth = user.social_auth.get()
    assert social_auth.uid == '101010101010101010101'
    assert social_auth.provider == 'lock8_google_oauth2'
    extra_data = social_auth.extra_data
    assert 'access_token' in extra_data
    assert extra_data['picture'] == avatar_url
    assert user.avatar == avatar_url

    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.subject == 'Welcome to Noa.'

    refresh_token = user.refresh_tokens.get()
    assert refresh_token.app == 'lock8_google_oauth2'
    jwt_token_content = jwt.decode(
        response.data['token'],
        settings.JWT_SECRET_KEY,
        algorithms=[api_settings.JWT_ALGORITHM])
    assert 'iss' in jwt_token_content
    assert jwt_token_content['iss'] == 'lock8_google_oauth2'
    assert response.data['refresh_token'] == refresh_token.key


def test_facebook_oauth2(client, login_alice_with_facebook, settings, root_org,
                         mailoutbox):
    from velodrome.lock8.models import User

    client.commit_db_on_successful_response = True

    user, response = login_alice_with_facebook(client=client)
    jwt_token = response.data['token']
    decoded = jwt.decode(
        jwt_token,
        settings.JWT_SECRET_KEY,
        algorithms=[api_settings.JWT_ALGORITHM])
    assert decoded['iss'] == 'lock8_facebook_oauth2'

    user = User.objects.get(username='foobar')
    assert response.data['user'] == {
        'uuid': str(user.uuid),
        'username': 'foobar',
        'email': 'foo@bar.com',
        'first_name': 'Foo',
        'last_name': 'Bar',
        'display_name': 'Foo Bar',
        'url': 'http://testserver' + reverse_query('lock8:user-detail',
                                                   kwargs={'uuid': user.uuid}),
        'avatar':
        'https://graph.facebook.com/v2.3/110011001100010/picture?type=large',
        'phone_numbers': None,
        'state': 'new',
        'concurrency_version': user.concurrency_version,
        'modified': user.modified.isoformat()[:-13] + 'Z',
        'created': user.created.isoformat()[:-13] + 'Z',
        'last_login': user.last_login.isoformat()[:-13] + 'Z',
        'is_local': False,
    }
    assert 'refresh_token' in response.data

    assert user.email == 'foo@bar.com'

    social_auth = user.social_auth.get()
    assert user.social_auth is not None
    assert social_auth.uid == '110011001100010'
    assert social_auth.provider == 'lock8_facebook_oauth2'
    assert 'access_token' in social_auth.extra_data

    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.subject == 'Welcome to Noa.'
    assert email.from_email == 'info@noa.one'

    refresh_token = user.refresh_tokens.get()
    assert refresh_token.app == 'lock8_facebook_oauth2'
    jwt_token_content = jwt.decode(
        response.data['token'],
        settings.JWT_SECRET_KEY,
        algorithms=[api_settings.JWT_ALGORITHM])
    assert 'iss' in jwt_token_content
    assert jwt_token_content['iss'] == 'lock8_facebook_oauth2'
    assert response.data['refresh_token'] == refresh_token.key


def test_verify_token(client, settings, fleet_operator):
    payload = jwt_payload_handler(fleet_operator)
    jwt_token = utils.jwt_encode_handler(payload)
    url = reverse_query('lock8:jwt-verify')
    response = client.post(url, data={'token': jwt_token}, format='json')
    assert response.status_code == status.HTTP_200_OK, response.data
    assert 'token' in response.data
    assert 'refresh_token' in response.data
    assert response.data['token'] == jwt_token


def test_long_refresh_token(drf_client, refresh_token, alice, settings):
    data = {
        'client_id': 'local',
        'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        'refresh_token': refresh_token.key,
        'api_type': 'app',
    }
    url = reverse_query('lock8:jwt-refreshtoken')
    response = drf_client.post(url, data=data, format='json')
    assert response.status_code == status.HTTP_200_OK, response.data
    assert 'token' in response.data
    assert 'refresh_token' in response.data
    jwt_token_content = jwt.decode(
        response.data['token'],
        settings.JWT_SECRET_KEY,
        algorithms=[api_settings.JWT_ALGORITHM])
    assert 'iss' in jwt_token_content
    assert jwt_token_content['iss'] == 'local'


def test_cannot_login_as_inactive(drf_fleet_operator, fleet_operator):
    drf_fleet_operator.use_jwt_auth()
    fleet_operator.is_active = False
    fleet_operator.save()

    url = reverse_query('lock8:user-list')
    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_401_UNAUTHORIZED


def test_user_consolidation_with_google_oauth2(drf_alice, client, alice,
                                               org, login_alice_with_google):
    from velodrome.lock8.models import Affiliation

    assert alice.refresh_tokens.count() == 0
    oauth2_user, response = login_alice_with_google(client=drf_alice)
    assert oauth2_user.representative == alice

    assert response.data['user']['uuid'] == str(alice.uuid)
    assert alice.shadowed_users.get() == oauth2_user

    assert oauth2_user.is_active is False

    # now log in anonymously, a local account should be returned.
    _, response = login_alice_with_google(client=client)
    assert response.data['user']['uuid'] == str(alice.uuid)

    # add some affiliations
    Affiliation.objects.create(user=oauth2_user, organization=org,
                               role=Affiliation.RENTER)
    login_alice_with_google(client=drf_alice)
    assert alice.affiliations.filter(organization=org,
                                     role=Affiliation.RENTER).exists()
    assert alice.refresh_tokens.filter(app='lock8_google_oauth2').exists()


def test_cannot_consolidate_already_shadowed_user(drf_alice, client, root_org,
                                                  alice, bob,
                                                  login_alice_with_google):
    oauth2_user, response = login_alice_with_google(client=client)
    assert oauth2_user.representative is None

    oauth2_user.representative = bob
    oauth2_user.save()

    _, response = login_alice_with_google(client=drf_alice)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {
        'non_field_errors': ['User account is compromised.'
                             ' There is a user assigned to the OAuth'
                             ' account already']
    }


def test_cannot_consolidate_inactive_user(drf_alice, client, root_org,
                                          alice, bob, login_alice_with_google):
    alice.is_active = False
    alice.save()

    oauth2_user, response = login_alice_with_google(client=client)

    oauth2_user.is_active = False
    oauth2_user.representative = alice
    oauth2_user.save()

    _, response = login_alice_with_google(client=client)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {'non_field_errors': ['User account is disabled.']}


def test_social_domain_name_preference_is_set(client, org,
                                              login_alice_with_facebook):
    org.allowed_signup_domain_names = ['bar.com']  # facebook_user_data_body
    org.save()

    oauth_user, _ = login_alice_with_facebook(client=client)
    assert oauth_user.affiliations.get().organization == org

    # should skip affiliation creation
    login_alice_with_facebook(client=client)
