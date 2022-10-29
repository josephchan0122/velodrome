import datetime as dt

from freezegun import freeze_time
import pytest
from rest_framework import exceptions, status

from velodrome.lock8.utils import reverse_query


def test_jwt_payload_handler(client, settings, fleet_operator, org,
                             another_org, sub_org):
    from velodrome.lock8.models import Affiliation
    from velodrome.lock8.jwt_extensions import jwt_payload_handler

    Affiliation.objects.create(user=fleet_operator, organization=org,
                               role=Affiliation.RENTER)
    Affiliation.objects.create(user=fleet_operator, organization=another_org,
                               role=Affiliation.RENTER)
    now = dt.datetime(2016, 1, 1)
    with freeze_time(now):
        payload = jwt_payload_handler(fleet_operator)
    assert payload == {
        'affs': {str(org.uuid): ['fleet_operator', 'renter'],
                 str(another_org.uuid): ['renter'],
                 str(sub_org.uuid): ['fleet_operator', 'renter']},
        'email': 'fleet_operator@example.com',
        'exp': dt.datetime(2016, 1, 1, 0, 30, 0),
        'iss': 'local',
        'orig_iat': now.timestamp(),
        'user_id': str(fleet_operator.uuid),
        'username': 'fleet_operator'
    }


def test_jwt_with_invalid_user_uuid():
    from velodrome.lock8.jwt_extensions import JSONWebTokenAuthentication

    auth = JSONWebTokenAuthentication()
    with pytest.raises(exceptions.AuthenticationFailed) as excinfo:
        auth.authenticate_credentials({
            'iss': 'local',
            'user_id': 'invaliduuid',
        })
    assert excinfo.value.args == ('Invalid user account.',)


def test_authentication_model_backend(django_admin_user, root_org):
    from velodrome.lock8.authentication import ModelBackend
    from velodrome.lock8.models import Affiliation

    Affiliation.objects.create(user=django_admin_user,
                               organization=root_org,
                               role=Affiliation.RENTER)

    backend = ModelBackend()
    user = backend.authenticate(request={},
                                username=django_admin_user.username,
                                password='password')

    assert user.is_admin_of_lock8

    user = backend.get_user(django_admin_user.pk)
    assert user.is_admin_of_lock8


def test_authentication_model_backend_wo_affiliations(django_admin_user):
    from velodrome.lock8.authentication import ModelBackend
    from velodrome.lock8.models import Affiliation

    Affiliation.objects.filter(user=django_admin_user).delete()

    backend = ModelBackend()
    user = backend.authenticate(request={},
                                username=django_admin_user.username,
                                password='password')

    assert not user.is_admin_of_lock8

    user = backend.get_user(django_admin_user.pk)
    assert not user.is_admin_of_lock8


def test_authentication_model_backend_get_user(db):
    from velodrome.lock8.authentication import ModelBackend

    backend = ModelBackend()
    assert backend.get_user(123) is None


def test_trips_with_token_user(trip, drf_token_admin, org):
    from velodrome.lock8.models import Affiliation

    url = reverse_query('lock8:trip-list')
    drf_token_admin.assert_count(url, 1)

    Affiliation.objects.create(user=drf_token_admin.user, organization=org,
                               role=Affiliation.RENTER)
    drf_token_admin.assert_count(url, 1)


def test_refresh_token_revocation(drf_alice, refresh_token, alice, drf_bob):
    url = reverse_query('lock8:refresh_token-revoke',
                        kwargs={'key': refresh_token.key})
    response = drf_bob.post(url)
    assert response.status_code == status.HTTP_404_NOT_FOUND
    response = drf_alice.post(url)
    assert response.status_code == status.HTTP_201_CREATED
    new_rt = alice.refresh_tokens.get()

    alice_url = reverse_query('lock8:user-detail', kwargs={'uuid': alice.uuid})
    assert response.data == {
        'key': new_rt.key,
        'created': new_rt.created.isoformat()[:-13] + 'Z',
        'app': refresh_token.app,
        'user': 'http://testserver' + alice_url,
    }


def test_blocked_login_without_redis(mocker, caplog):
    import redis.exceptions
    from velodrome.lock8.authentication import (
        is_login_blocked, clear_failed_logins, register_failed_login,
    )

    m_get = mocker.patch('django_redis.cache.RedisCache.get',
                         side_effect=redis.exceptions.ConnectionError)
    m_del = mocker.patch('django_redis.cache.RedisCache.delete',
                         side_effect=redis.exceptions.ConnectionError)

    assert is_login_blocked(email='foo@example.com') is False
    register_failed_login(email='foo@example.com')

    class FakeUser:
        email = 'foo'
        username = 'bar'
    clear_failed_logins(FakeUser)

    assert m_get.call_count == 2
    assert m_del.call_count == 1
    assert len(caplog.record_tuples) == 3
    assert all(r[2] == 'Failed to connect to Redis: ConnectionError()'
               for r in caplog.record_tuples)


def test_register_failed_login(mocker):
    from velodrome.lock8.authentication import (failed_logins_cache,
                                                register_failed_login)

    mocker.patch('velodrome.lock8.authentication.failed_logins_cache.incr',
                 side_effect=ValueError)
    cache_set = mocker.spy(failed_logins_cache, 'set')
    register_failed_login(email='foo@example.com')

    call = mocker.mock_module.call
    assert cache_set.call_args_list == [call('e:foo@example.com', 1),
                                        call('h:e:foo@example.com', None)]
