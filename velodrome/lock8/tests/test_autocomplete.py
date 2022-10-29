import json

import pytest
from rest_framework import status

from velodrome.lock8.utils import reverse_query


def test_autocomplete_endpoints_smoke(client, django_admin_user, alice):
    endpoint = 'dal:user'
    url = reverse_query(endpoint, query_kwargs={'q': 'q'})

    response = client.get(url)
    assert response.status_code == status.HTTP_302_FOUND

    assert client.login(username=django_admin_user.username,
                        password='password')
    response = client.get(url)
    assert response.status_code == status.HTTP_200_OK

    client.logout()
    assert client.login(username=alice.username, password='pwd_alice')
    response = client.get(url)
    # In the past versions of Velodrome DAL answers with 302 to non-admin users
    # this bug-like behaviour was changed after this bug in Django was fixed:
    # https://code.djangoproject.com/ticket/28379
    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.parametrize('org', (True, False))
@pytest.mark.parametrize('q', ('', 'search term'))
def test_autocomplete_endpoints_access(q, org, rf, django_admin_user):
    from velodrome.lock8.dal import PermissionCheckMixin, urlpatterns

    params = {'q': q}
    if org:
        params['forward'] = json.dumps({'organization': 1})
    fake_request = rf.get('/', params)
    fake_request.user = django_admin_user
    fake_request.user.is_admin_of_lock8 = True

    for p in urlpatterns:
        assert issubclass(p.callback.view_class, PermissionCheckMixin)

        response = p.callback(fake_request)
        assert response.status_code == 200, str(response.content)


def test_autocomplete_bicycle(django_admin_rf, admin_user, bicycle, bicycle2):
    from velodrome.lock8.dal import LockAutocomplete

    admin_user.is_admin_of_lock8 = True

    view = LockAutocomplete.as_view()

    url = reverse_query('dal:lock', query_kwargs={
        'forward': json.dumps({'bicycle': bicycle.pk})})
    response = view(django_admin_rf().get(url))
    assert response.status_code == 200, str(response.content)
    results = json.loads(response.content)['results']
    assert len(results) == 1
    assert results[0]['id'] == str(bicycle.lock.pk)

    url = reverse_query('dal:lock')
    response = view(django_admin_rf().get(url))
    results = json.loads(response.content)['results']
    assert len(results) == 2
