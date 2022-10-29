from rest_framework import status
from rest_framework_jwt.utils import jwt_encode_handler

from velodrome.lock8.jwt_extensions import jwt_payload_handler
from velodrome.lock8.utils import reverse_query


def test_crud_organization(drf_client, drf_fleet_operator, org, fleet_admin,
                           image, feature, organization_preference):
    from velodrome.lock8.conftest import cast_to_dict
    from velodrome.lock8.models import Alert

    preference = organization_preference
    org.image = image
    org.phone_numbers = {'Emergency': 911}
    org.save()

    url = reverse_query('lock8:organization-list')
    response = drf_fleet_operator.assert_count(url, 1)
    result = response.data['results'][0]

    pref_url = reverse_query('lock8:organization-preference',
                             kwargs={'uuid': org.uuid})
    assert cast_to_dict(result) == {
        'uuid': str(org.uuid),
        'name': 'org',
        'phone_numbers': {'Emergency': 911},
        'is_open_fleet': False,
        'icon': 'http://127.0.0.1:8000/{}'.format(org.image.name),
        'url': 'http://testserver' + reverse_query('lock8:organization-detail',
                                                   kwargs={'uuid': org.uuid}),
        'features': [{'name': 'feature'}],
        'uses_payments': False,
        'stripe_publishable_key': None,
        'state': 'new',
        'concurrency_version': org.concurrency_version,
        'modified': org.modified.isoformat()[:-13] + 'Z',
        'created': org.created.isoformat()[:-13] + 'Z',
        'preference': {
            'uuid': str(preference.uuid),
            'allowed_email_alert_types': [t for t, _ in Alert.TYPES],
            'allowed_push_alert_types': [t for t, _ in Alert.TYPES],
            'allow_returning_bicycle_outside_drop_zone': True,
            'currency': 'usd',
            'allow_renting_without_pricings': True,
            'url': 'http://testserver' + pref_url,
            'name': 'organization_preference',
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
        },
    }

    url = reverse_query('lock8:organization-list')
    response = drf_fleet_operator.post(url)
    assert response.status_code == status.HTTP_403_FORBIDDEN

    url = reverse_query('lock8:organization-detail', kwargs={'uuid': org.uuid})
    response = drf_fleet_operator.put(url)
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    response = drf_fleet_operator.patch(url)
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    response = drf_fleet_operator.delete(url)
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    drf_client.credentials(
        HTTP_AUTHORIZATION='JWT ' + jwt_encode_handler(
            jwt_payload_handler(fleet_admin)))

    url = reverse_query('lock8:organization-list')
    response = drf_fleet_operator.assert_count(url, 1)
    result = response.data['results'][0]

    assert result == {
        'uuid': str(org.uuid),
        'name': 'org',
        'icon': 'http://127.0.0.1:8000/{}'.format(org.image.name),
        'is_open_fleet': False,
        'phone_numbers': {'Emergency': 911},
        'url': 'http://testserver' + reverse_query('lock8:organization-detail',
                                                   kwargs={'uuid': org.uuid}),
        'features': [{'name': 'feature'}],
        'uses_payments': False,
        'stripe_publishable_key': None,
        'state': 'new',
        'concurrency_version': org.concurrency_version,
        'created': org.created.isoformat()[:-13] + 'Z',
        'modified': org.modified.isoformat()[:-13] + 'Z',
        'preference': {
            'uuid': str(preference.uuid),
            'allowed_email_alert_types': [t for t, _ in Alert.TYPES],
            'allowed_push_alert_types': [t for t, _ in Alert.TYPES],
            'allow_returning_bicycle_outside_drop_zone': True,
            'currency': 'usd',
            'allow_renting_without_pricings': True,
            'url': 'http://testserver' + pref_url,
            'name': 'organization_preference',
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
        },
    }

    url = reverse_query('lock8:organization-list')
    response = drf_fleet_operator.post(url)
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_anonymous_cannot_access_open_fleet(drf_client, org):
    url = reverse_query('lock8:organization-detail',
                        kwargs={'uuid': org.uuid})
    org.is_open_fleet = True
    org.save()
    drf_client.assert_404(url)
