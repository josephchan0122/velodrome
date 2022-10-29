from django.core.exceptions import ValidationError
import pytest
from rest_framework import status

from velodrome.lock8.utils import reverse_query


def default_pref_data(preference, url):
    from velodrome.lock8.models import Alert

    return {
        'uuid': str(preference.uuid),
        'allowed_email_alert_types': [],
        'allowed_push_alert_types': [t for t, _ in Alert.TYPES],
        'allow_returning_bicycle_outside_drop_zone': True,
        'currency': '',
        'allow_renting_without_pricings': True,
        'url': 'http://testserver' + url,
        'name': '',
        'timezone': 'UTC',
        'unit_system': 'metric',
        'idle_bicycle_duration': None,
        'state': 'new',
        'concurrency_version': preference.concurrency_version,
        'modified': preference.modified.isoformat()[:-13] + 'Z',
        'created': preference.created.isoformat()[:-13] + 'Z',
        'is_free_floating_fleet': False,
        'is_access_controlled': True,
        'send_support_ticket_per_email': False,
        'support_email': None,
        'support_phone_number': None,
        'uses_payments': False,
        'tax_percent': None,
        }


def test_get_acquired_organization_preference(drf_fleet_operator, org,
                                              root_org, owner):
    from velodrome.lock8.models import OrganizationPreference

    root_org.active_preference.delete()
    url = reverse_query('lock8:organization-preference',
                        kwargs={'uuid': org.uuid})
    with pytest.raises(OrganizationPreference.DoesNotExist):
        assert org.preference
    OrganizationPreference.objects.create(organization=root_org, owner=owner)
    assert org.active_preference is not None
    preference = org.active_preference
    response = drf_fleet_operator.assert_success(url)
    assert response.data == default_pref_data(preference, url)


def test_get_non_acquired_organization_preference(drf_fleet_operator, org,
                                                  owner):
    from velodrome.lock8.models import OrganizationPreference

    url = reverse_query('lock8:organization-preference',
                        kwargs={'uuid': org.uuid})
    preference = OrganizationPreference.objects.create(organization=org,
                                                       owner=owner)
    response = drf_fleet_operator.assert_success(url)
    assert response.data == default_pref_data(preference, url)


def test_copy_on_write_acquired_organization_preference(drf_fleet_operator,
                                                        org, root_org, owner,
                                                        fleet_operator):
    from velodrome.lock8.models import Organization, OrganizationPreference

    root_org.active_preference.delete()
    url = reverse_query('lock8:organization-preference',
                        kwargs={'uuid': org.uuid})
    with pytest.raises(OrganizationPreference.DoesNotExist):
        assert org.preference
    OrganizationPreference.objects.create(organization=root_org, owner=owner)
    assert org.active_preference is not None
    response = drf_fleet_operator.patch(url, {'name': 'Local pref'})
    assert response.status_code == status.HTTP_200_OK

    org = Organization.objects.get(pk=org.pk)
    preference = org.preference
    assert response.data == dict(default_pref_data(preference, url), **{
        'name': 'Local pref',
    })
    assert preference.owner == fleet_operator
    root_org.preference.refresh_from_db()
    assert root_org.preference.name == ''


def test_update_on_non_acquired_organization_preference(drf_fleet_operator,
                                                        org, owner,
                                                        fleet_operator):
    from velodrome.lock8.models import OrganizationPreference

    url = reverse_query('lock8:organization-preference',
                        kwargs={'uuid': org.uuid})
    preference = OrganizationPreference.objects.create(organization=org,
                                                       owner=owner)
    response = drf_fleet_operator.patch(url, {'name': 'Local pref'})
    assert response.status_code == status.HTTP_200_OK

    preference.refresh_from_db()
    assert response.data == dict(default_pref_data(preference, url), **{
        'name': 'Local pref',
    })
    assert preference.owner == owner


@pytest.mark.parametrize('roles', [
    'fleet_operator',
    ['xxx']
])
def test_preference_roles_validation(roles, org, owner):
    from velodrome.lock8.models import OrganizationPreference

    org_pref = OrganizationPreference(
        alert_type_to_role_mapping={'lock.bat.low': roles},
        organization=org,
        owner=owner)
    with pytest.raises(ValidationError) as excinfo:
        org_pref.full_clean()
    assert 'alert_type_to_role_mapping' in excinfo.value.message_dict


def test_update_organization_preference_support_ticket_flag(drf_fleet_operator,
                                                            org, owner):
    from velodrome.lock8.models import OrganizationPreference
    url = reverse_query('lock8:organization-preference',
                        kwargs={'uuid': org.uuid})
    OrganizationPreference.objects.create(organization=org, owner=owner)
    expected = {
        'detail': {'__all__': [{
            'code': 'invalid',
            'message': 'Cannot send support ticket per email '
                       'without a support email'}]}}

    response = drf_fleet_operator.patch(url, format='json', data={
        'send_support_ticket_per_email': True,
    })
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == expected

    response = drf_fleet_operator.patch(url, format='json', data={
        'send_support_ticket_per_email': True,
        'support_email': 'test@example.com',
    })
    assert response.status_code == status.HTTP_200_OK

    response = drf_fleet_operator.patch(url, format='json', data={
        'send_support_ticket_per_email': True,
        'support_email': '',
    })
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == expected
