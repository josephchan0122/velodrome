from pinax.stripe.models import Account
import pytest
from rest_framework import status

from velodrome.lock8.utils import reverse_query


def test_stripe_oauth_client_id(drf_fleet_operator, org, settings, drf_renter):
    settings.STRIPE_CLIENT_ID = 'ac_0123abcd'
    url = reverse_query('lock8:stripe-client_id')
    response = drf_fleet_operator.assert_success(url)
    assert response.data == {'client_id': 'ac_0123abcd'}
    drf_renter.assert_status(url, status.HTTP_403_FORBIDDEN)


@pytest.mark.parametrize('existing_account', (False, True))
def test_stripe_oauth_redirect(existing_account, request, drf_client, settings,
                               active_requests_mock):
    stripe_account_id = 'acct_01abc'
    business_name = 'Noa Technologies Inc.'
    display_name = 'Noa Technologies'
    if existing_account:
        Account.objects.create(
            stripe_id=stripe_account_id,
            business_name=business_name,
            display_name=display_name,
        )
        org = request.getfixturevalue('org_with_payments')
    else:
        org = request.getfixturevalue('org')
        org.stripe_account = None
        org.save()

        active_requests_mock.get(
            f'https://api.stripe.com/v1/accounts/{stripe_account_id}',
            json={
                'business_logo': None,
                'business_name': business_name,
                'business_url': 'https://www.noa.one',
                'charges_enabled': True,
                'country': 'US',
                'default_currency': 'usd',
                'details_submitted': True,
                'display_name': display_name,
                'email': 'accounting@noa.one',
                'id': stripe_account_id,
                'object': 'account',
                'payouts_enabled': True,
                'statement_descriptor': 'NOA TECHNOLOGIES, INC.',
                'support_address': {
                    'city': None,
                    'country': 'DE',
                    'line1': None,
                    'line2': None,
                    'postal_code': None,
                    'state': None
                },
                'support_email': 'support@noa.one',
                'support_phone': '6505040845',
                'support_url': '',
                'timezone': 'Europe/Berlin',
                'type': 'standard'})

    active_requests_mock.post(
        'https://connect.stripe.com/oauth/token',
        json={'stripe_user_id': stripe_account_id,
              'stripe_publishable_key': 'ac_0123abcd'})
    url = reverse_query('lock8:stripe-redirect',
                        query_kwargs={'state': org.uuid,
                                      'code': 'abc'})
    response = drf_client.get(url)
    assert response.status_code == status.HTTP_302_FOUND
    assert response.get('Location') == (
        'https://fms.noa.one/organisation-settings?'
        'message=Account+connected+successfully.')
    account = Account.objects.get(stripe_id=stripe_account_id,
                                  stripe_publishable_key='ac_0123abcd')
    org.refresh_from_db()
    assert org.stripe_account == account
    account.refresh_from_db()
    assert account.business_name == business_name
    assert account.display_name == display_name


def test_stripe_oauth_redirect_wrong_org(drf_client, non_matching_uuid,
                                         settings, active_requests_mock):

    active_requests_mock.post(
        'https://connect.stripe.com/oauth/token',
        json={'stripe_user_id': 'acc_01abc'})
    url = reverse_query('lock8:stripe-redirect',
                        query_kwargs={'state': non_matching_uuid,
                                      'code': 'abc'})
    response = drf_client.get(url)
    assert response.status_code == status.HTTP_403_FORBIDDEN


def test_stripe_oauth_redirect_stripe_error(drf_client, org, settings,
                                            active_requests_mock):

    url = reverse_query('lock8:stripe-redirect',
                        query_kwargs={'state': org.uuid,
                                      'error_description': 'a desc',
                                      'error': 'a'})
    response = drf_client.get(url)
    assert response.status_code == status.HTTP_302_FOUND
    assert response.get('Location') == (
        'https://fms.noa.one/organisation-settings?message=a+desc')
