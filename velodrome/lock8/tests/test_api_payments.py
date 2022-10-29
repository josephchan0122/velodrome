import copy
import datetime as dt
import json
from urllib.parse import urlencode

from django.conf import settings
from django.db import connection
from django.db.models.signals import post_save
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from freezegun import freeze_time
from pinax.stripe.models import Subscription
import pytest
import requests_mock
from rest_framework import status
import stripe

from velodrome.lock8.utils import reverse_query

pytestmark = pytest.mark.uses_payments


@pytest.fixture
def customer_wo_subscriptions(active_requests_mock, customer):
    active_requests_mock.get(
        'https://api.stripe.com/v1/customers/cus_7hT8uNWiStYnxq/subscriptions',
        json={'data': [],
              'has_more': False,
              'object': 'list',
              'url': '/v1/customers/cus_7hT8uNWiStYnxq/subscriptions'})


def test_api_crud_pricing_scheme(drf_fleet_operator, org):
    from velodrome.lock8.models import PricingScheme
    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})
    url = reverse_query('lock8:pricing_scheme-list')

    response = drf_fleet_operator.post(
        url,
        data={
            'organization': organization_url,
            'name': 'That is a good plan for the weekend',
            'time_ranges': [[0, None, 123, False, 0]],
            'description': {
                'en': {
                    'title': 'plan title',
                    'description': 'blabla',
                    'short_description': 'bla',
                    'fine_print': '...'
                }
            }
        },
        format='json')
    assert response.status_code == status.HTTP_201_CREATED

    pricing_scheme = PricingScheme.objects.get()
    url = reverse_query('lock8:pricing_scheme-detail',
                        kwargs={'uuid': pricing_scheme.uuid})
    assert response.data == {
        'url': 'http://testserver' + url,
        'uuid': str(pricing_scheme.uuid),
        'organization': 'http://testserver' + organization_url,
        'name': 'That is a good plan for the weekend',
        'time_ranges': [[0, None, 123, False, 0]],
        'max_daily_charged_cents': None,
        'bicycle_model': None,
        'description': {
            'en': {
                'title': 'plan title',
                'description': 'blabla',
                'amount': 123,
                'short_description': 'bla',
                'fine_print': '...'
            },
        },
        'state': 'new',
        'modified': pricing_scheme.modified.isoformat()[:-13] + 'Z',
        'created': pricing_scheme.created.isoformat()[:-13] + 'Z',
        'concurrency_version': pricing_scheme.concurrency_version,
    }

    url = reverse_query('lock8:pricing_scheme-detail',
                        kwargs={'uuid': pricing_scheme.uuid})
    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_200_OK

    url = reverse_query('lock8:pricing_scheme-detail',
                        kwargs={'uuid': pricing_scheme.uuid})
    response = drf_fleet_operator.patch(url, data={'name': 'oh oh!'})
    assert response.status_code == status.HTTP_200_OK

    pricing_scheme.refresh_from_db()

    assert pricing_scheme.name == 'oh oh!'

    description_data = {
        'en': {'title': 'plan title',
               'description': 'blabla',
               'amount': 0,
               'short_description': 'bla',
               'fine_print': '...'},
        'fr': {'title': 'plan titre',
               'description': 'blabla',
               'amount': 1,
               'short_description': 'bla',
               'fine_print': '...'},
    }
    response = drf_fleet_operator.patch(
        url, data={'description': description_data}, format='json')
    assert response.status_code == status.HTTP_200_OK

    pricing_scheme.refresh_from_db()
    assert pricing_scheme.description == description_data

    response = drf_fleet_operator.delete(url)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    with pytest.raises(PricingScheme.DoesNotExist):
        pricing_scheme.refresh_from_db()


def test_api_crud_subscription_plan(drf_fleet_operator, org,
                                    stripe_plan_detail, active_requests_mock):
    from velodrome.lock8.models import SubscriptionPlan

    organization_url = org.get_absolute_url()
    url = reverse_query('lock8:subscription_plan-list')
    lower = dt.datetime(2015, 1, 1, 12, 1, tzinfo=dt.timezone.utc)
    upper = dt.datetime(2015, 2, 2, 12, 1, tzinfo=dt.timezone.utc)

    active_requests_mock.register_uri('GET', stripe_plan_detail, json={
        'id': 'gold',
        'object': 'plan',
    })
    active_requests_mock.register_uri(
        'POST',
        'https://api.stripe.com/v1/plans/gold', json={
            'id': 'gold',
            'object': 'plan',
        })
    response = drf_fleet_operator.post(
        url,
        data={
            'organization': organization_url,
            'name': 'That is a good plan for the weekend',
            'interval': SubscriptionPlan.WEEK,
            'cents': 800,
            'trial_period_days': 0,
            'weekdays': {'lower': '6',
                         'upper': '7'},
            'available_dates': {
                'lower': lower,
                'upper': upper},
        },
        format='json')
    assert response.status_code == status.HTTP_201_CREATED

    subscription_plan = SubscriptionPlan.objects.get()
    url = reverse_query('lock8:subscription_plan-detail',
                        kwargs={'uuid': subscription_plan.uuid})
    assert response.data == {
        'url': 'http://testserver' + url,
        'uuid': str(subscription_plan.uuid),
        'organization': 'http://testserver' + organization_url,
        'bicycle_model': None,
        'pricing_scheme': None,
        'name': 'That is a good plan for the weekend',
        'interval': SubscriptionPlan.WEEK,
        'description': {},
        'cents': 800,
        'trial_period_days': 0,
        'weekdays': {
            'upper': 7,
            'bounds': '[)',
            'lower': 6},
        'available_dates': {
            'lower': lower.isoformat()[:-6] + 'Z',
            'upper': upper.isoformat()[:-6] + 'Z',
            'bounds': '[)',
        },
        'statement_descriptor': '',
        'is_restricted': False,
        'can_be_used_by_user': False,
        'state': 'new',
        'created': subscription_plan.created.isoformat()[:-13] + 'Z',
        'modified': subscription_plan.modified.isoformat()[:-13] + 'Z',
        'concurrency_version': subscription_plan.concurrency_version,
    }

    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_200_OK

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
    subscription_plan.provision()

    url = reverse_query('lock8:subscription_plan-detail',
                        kwargs={'uuid': subscription_plan.uuid})
    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_200_OK
    # because the subscription_plan is modified by post_save signal
    # the DRF serializer shows an outdated version of the object
    # so we remove concurrency_version and modified fields.
    del response.data['concurrency_version']
    del response.data['modified']
    assert response.data == {
        'url': 'http://testserver' + url,
        'uuid': str(subscription_plan.uuid),
        'organization': 'http://testserver' + organization_url,
        'bicycle_model': None,
        'pricing_scheme': None,
        'name': 'That is a good plan for the weekend',
        'interval': SubscriptionPlan.WEEK,
        'description': {},
        'cents': 800,
        'trial_period_days': 0,
        'weekdays': {
            'upper': 7,
            'bounds': '[)',
            'lower': 6},
        'available_dates': {
            'lower': lower.isoformat()[:-6] + 'Z',
            'upper': upper.isoformat()[:-6] + 'Z',
            'bounds': '[)',
        },
        'statement_descriptor': '',
        'is_restricted': False,
        'can_be_used_by_user': True,
        'state': 'provisioned',
        'created': subscription_plan.created.isoformat()[:-13] + 'Z',
    }

    with requests_mock.Mocker() as m:
        m.register_uri('GET', stripe_plan_detail, json={
            'id': 'gold',
            'object': 'plan',
        })
        m.register_uri('POST', 'https://api.stripe.com/v1/plans/gold', json={
            'id': 'gold',
            'object': 'plan',
        })
        response = drf_fleet_operator.patch(url,
                                            data={'name': 'oh oh!'},
                                            format='json')
        assert response.status_code == status.HTTP_200_OK
        response = drf_fleet_operator.assert_success(
            url, data={'statement_descriptor': 'ohoh'}, method='patch',
            format='json')
        response = drf_fleet_operator.assert_success(
            url, data={'trial_period_days': '14'}, method='patch',
            format='json')

        # TODO: validate
        response = drf_fleet_operator.assert_400(
            url, data={'cents': '100'}, method='patch', format='json')

    subscription_plan.refresh_from_db()

    assert subscription_plan.name == 'oh oh!'

    description_data = {
        'en': {'title': 'plan title',
               'description': 'blabla',
               'amount': '123',
               'short_description': 'bla',
               'fine_print': '...'},
        'fr': {'title': 'plan titre',
               'description': 'blabla',
               'amount': '123',
               'short_description': 'bla',
               'fine_print': '...'},
    }
    response = drf_fleet_operator.patch(
        url, data={'description': description_data}, format='json')
    assert response.status_code == status.HTTP_200_OK
    subscription_plan.refresh_from_db()
    assert subscription_plan.description == description_data

    drf_fleet_operator.assert_400(
        url, {'description': [{
            'code': 'invalid',
            'message': 'en-us is not a supported language'}]},
        data={'description': {'en-us': 'Plan description'}},
        method='patch', format='json')

    drf_fleet_operator.assert_400(
        url, {'description': [{
            'code': 'missing_fields',
            'message': 'The following entries are required: title, '
            'description, short_description, fine_print'}]},
        data={'description': {'en': {'amount': 1}}},
        method='patch', format='json')

    response = drf_fleet_operator.delete(url)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    with pytest.raises(SubscriptionPlan.DoesNotExist):
        subscription_plan.refresh_from_db()


def test_subscription_plan_filtering_organization(org, drf_fleet_operator,
                                                  non_matching_uuid,
                                                  subscription_plan):
    filter_url = reverse_query('lock8:subscription_plan-list',
                               {'organization': org.uuid})
    drf_fleet_operator.assert_count(filter_url, 1)
    filter_url = reverse_query('lock8:subscription_plan-list',
                               {'organization': non_matching_uuid})
    drf_fleet_operator.assert_count(filter_url, 0)


def test_subscription_plan_filtering_is_restricted(drf_fleet_operator,
                                                   subscription_plan):
    filter_url = reverse_query('lock8:subscription_plan-list',
                               {'is_restricted': False})
    drf_fleet_operator.assert_count(filter_url, 1)
    filter_url = reverse_query('lock8:subscription_plan-list',
                               {'is_restricted': True})
    drf_fleet_operator.assert_count(filter_url, 0)


def test_subscription_plan_filtering_by_state(drf_fleet_operator,
                                              subscription_plan):
    filter_url = reverse_query('lock8:subscription_plan-list',
                               {'state': 'provisioned'})
    drf_fleet_operator.assert_count(filter_url, 1)
    filter_url = reverse_query('lock8:subscription_plan-list',
                               {'state': 'new'})
    drf_fleet_operator.assert_count(filter_url, 0)


def test_get_bicycle_pricings_api(drf_renter, org, bicycle_available,
                                  bicycle_model, owner, customer,
                                  stripe_plan_detail, active_requests_mock):
    from velodrome.lock8.models import PricingScheme, SubscriptionPlan

    bicycle_available.model = bicycle_model
    bicycle_available.save()

    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})
    url = reverse_query('lock8:bicycle-pricings',
                        kwargs={'uuid': bicycle_available.uuid})
    response = drf_renter.get(url)
    assert response.data == {'pricing_schemes': [],
                             'subscription_plans': [],
                             'active_subscriptions': []}

    active_requests_mock.get(stripe_plan_detail, json={
        'id': 'gold',
        'object': 'plan'})
    active_requests_mock.post('https://api.stripe.com/v1/plans/gold', json={
        'id': 'gold',
        'object': 'plan'})
    subscription_plan = SubscriptionPlan.objects.create(
        owner=owner,
        organization=org,
        name='weekday plan',
        interval=SubscriptionPlan.WEEK,
        cents=500,
        trial_period_days=0,
        weekdays=(1, 7),
    )
    subscription_plan.provision()
    subscription_plan.refresh_from_db()

    Subscription.objects.create(
        stripe_id='fake',
        customer=customer,
        plan=subscription_plan.plan,
        quantity=1,
        start=timezone.now(),
        status='active',
    )
    subscription_plan_url = reverse_query(
        'lock8:subscription_plan-detail',
        kwargs={'uuid': subscription_plan.uuid})

    # 1st December 2015 is a Monday.
    with freeze_time(dt.datetime(2015, 12, 1, 12, 00, 00,
                                 tzinfo=timezone.utc)):
        response = drf_renter.get(url)
        assert len(response.data) == 3
        assert len(response.data['pricing_schemes']) == 0
        assert len(response.data['subscription_plans']) == 0
        assert len(response.data['active_subscriptions']) == 1
        assert dict(response.data['active_subscriptions'][0]) == {
            'url': 'http://testserver' + subscription_plan_url,
            'uuid': str(subscription_plan.uuid),
            'organization': 'http://testserver' + organization_url,
            'bicycle_model': None,
            'pricing_scheme': None,
            'name': 'weekday plan',
            'interval': SubscriptionPlan.WEEK,
            'cents': 500,
            'trial_period_days': 0,
            'weekdays': {'upper': 7, 'bounds': '[)', 'lower': 1},
            'description': {},
            'available_dates': None,
            'statement_descriptor': '',
            'is_restricted': False,
            'can_be_used_by_user': True,
            'state': 'provisioned',
            'modified': subscription_plan.modified.isoformat()[:-13] + 'Z',
            'created': subscription_plan.created.isoformat()[:-13] + 'Z',
            'concurrency_version': subscription_plan.concurrency_version,
        }
    pricing_scheme = PricingScheme.objects.create(
        organization=org,
        owner=owner,
        name='pricing',
        time_ranges=((0, None, 0, True, 60),),
        description={'en': {
            'title': 'title',
            'description': 'description',
            'fine_print': 'fine_print',
            'short_description': 'short_description',
        }}
    )
    pricing_scheme.provision()
    subscription_plan.pricing_scheme = pricing_scheme
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
    subscription_plan.save()

    pricing_scheme_url = reverse_query(
        'lock8:pricing_scheme-detail',
        kwargs={'uuid': pricing_scheme.uuid}
    )
    # 1st December 2015 is a Monday.
    with freeze_time(dt.datetime(2015, 12, 1, 12, 00, 00,
                                 tzinfo=timezone.utc)):
        response = drf_renter.get(url)
        assert response.data == {
            'active_subscriptions': [
                {'url': 'http://testserver' + subscription_plan_url,
                 'uuid': str(subscription_plan.uuid),
                 'organization': 'http://testserver' + organization_url,
                 'bicycle_model': None,
                 'pricing_scheme': 'http://testserver' + pricing_scheme_url,
                 'name': 'weekday plan',
                 'interval': SubscriptionPlan.WEEK,
                 'cents': 500,
                 'trial_period_days': 0,
                 'weekdays': {'upper': 7, 'bounds': '[)', 'lower': 1},
                 'available_dates': None,
                 'statement_descriptor': '',
                 'description': {},
                 'state': 'provisioned',
                 'is_restricted': False,
                 'can_be_used_by_user': True,
                 'modified': subscription_plan.modified.isoformat()[:-13] + 'Z',  # noqa
                 'created': subscription_plan.created.isoformat()[:-13] + 'Z',
                 'concurrency_version': subscription_plan.concurrency_version,
                 }
            ],
            'pricing_schemes': [],
            'subscription_plans': [],
        }

    pricing_scheme = PricingScheme.objects.create(
        organization=org,
        owner=owner,
        bicycle_model=bicycle_model,
        name='pricing',
        time_ranges=((0, None, 0, True, 60),),
        description={'en': {
            'title': 'title',
            'description': 'description',
            'fine_print': 'fine_print',
            'short_description': 'short_description',
        }}
    )
    pricing_scheme.provision()

    pricing_scheme_url = reverse_query(
        'lock8:pricing_scheme-detail',
        kwargs={'uuid': pricing_scheme.uuid}
    )

    bicycle_model_url = reverse_query('lock8:bicycle_model-detail',
                                      kwargs={'uuid': bicycle_model.uuid})
    response = drf_renter.get(url)
    assert response.status_code == status.HTTP_200_OK, response.data
    assert len(response.data) == 3
    assert len(response.data['active_subscriptions']) == 0
    assert len(response.data['subscription_plans']) == 0
    assert len(response.data['pricing_schemes']) == 1
    assert dict(response.data['pricing_schemes'][0]) == {
        'uuid': str(pricing_scheme.uuid),
        'name': 'pricing',
        'url': 'http://testserver' + pricing_scheme_url,
        'bicycle_model': 'http://testserver' + bicycle_model_url,
        'organization': 'http://testserver' + organization_url,
        'time_ranges': [[0, None, 0, True, 60]],
        'max_daily_charged_cents': None,
        'description': {'en': {
            'title': 'title',
            'description': 'description',
            'fine_print': 'fine_print',
            'short_description': 'short_description',
            'amount': 0,
        }},
        'modified': pricing_scheme.modified.isoformat()[:-13] + 'Z',
        'created': pricing_scheme.created.isoformat()[:-13] + 'Z',
        'concurrency_version': pricing_scheme.concurrency_version,
        'state': 'provisioned',
    }


def test_can_ask_estimate_amount(drf_renter, org, owner):
    from velodrome.lock8.models import PricingScheme

    time_ranges = ((0, 30, 100, True, 60), (30, None, 200, True, 60))
    duration = dt.timedelta(hours=2)

    pricing_scheme = PricingScheme.objects.create(
        organization=org,
        owner=owner,
        name='Pricing scheme',
        time_ranges=time_ranges,
        description={'en': {
            'title': 'title',
            'description': 'description',
            'fine_print': 'fine_print',
            'short_description': 'short_description',
        }}
    )
    pricing_scheme.provision()

    url = reverse_query('lock8:pricing_scheme-compute-amount',
                        kwargs={'uuid': pricing_scheme.uuid},
                        query_kwargs={'duration': duration.total_seconds()})
    response = drf_renter.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert org.currency == 'eur'
    assert response.data == {
        'cents': 350,
        'currency': 'eur',
        'tax_percent': None,
    }

    url = reverse_query('lock8:pricing_scheme-compute-amount',
                        kwargs={'uuid': pricing_scheme.uuid})
    response = drf_renter.get(url)
    assert response.status_code == status.HTTP_400_BAD_REQUEST


@pytest.mark.parametrize('has_sub', ('no', 'with_canceled_at_period_end'))
def test_subscribe_user_to_subscription_plan(
        has_sub, request, org, owner, alice, customer, drf_renter,
        subscription_plan, subscription_json, stripe_plan_detail,
        active_requests_mock, non_matching_uuid):

    active_requests_mock.get(
        'https://api.stripe.com/v1/subscriptions/sub_test1',
        json=subscription_json)
    unsub_json = subscription_json.copy()
    unsub_json['status'] = 'active'
    unsub_json['ended_at'] = None
    unsub_json['cancel_at_period_end'] = True
    active_requests_mock.delete(
        'https://api.stripe.com/v1/subscriptions/sub_test1?at_period_end=True',
        json=unsub_json)
    if has_sub == 'no':
        active_requests_mock.post('https://api.stripe.com/v1/subscriptions',
                                  json=subscription_json)
    else:
        active_requests_mock.post('https://api.stripe.com/v1/subscriptions/sub_test1',  # noqa: E501
                                  json=subscription_json)
        subscription = request.getfixturevalue('subscription')
        subscription.cancel_at_period_end = True
        subscription.save()

    url = reverse_query('lock8:subscription_plan-subscribe-user',
                        kwargs={'uuid': subscription_plan.uuid})
    drf_renter.assert_success(
        url, data={'stripe_source': 'payment-source',
                   'coupon': '25OFF'},
        expected_data={
            'cancel_at_period_end': True,
            'current_period_end':
            dt.datetime.utcfromtimestamp(1452854186).isoformat() + 'Z',
            'current_period_start':
            dt.datetime.utcfromtimestamp(1451990186).isoformat() + 'Z',
            'ended_at': None,
            'status': 'active',
            'stripe_id': 'sub_test1',
            'subscription_plan': {
                'available_dates': None,
                'bicycle_model': None,
                'cents': 500,
                'concurrency_version': subscription_plan.concurrency_version,
                'created': subscription_plan.created.isoformat()[:-13] + 'Z',
                'description': {},
                'interval': 'week',
                'modified': subscription_plan.modified.isoformat()[:-13] + 'Z',
                'name': 'subscription_plan',
                'organization':
                    f'http://testserver/api/organizations/{org.uuid}/',
                'pricing_scheme': None,
                'state': 'provisioned',
                'statement_descriptor': '',
                'is_restricted': False,
                'can_be_used_by_user': True,
                'trial_period_days': 0,
                'url': f'http://testserver/api/subscription_plans/{subscription_plan.uuid}/',  # noqa: E501
                'uuid': f'{subscription_plan.uuid}',
                'weekdays': None
            },
            'discount': {
                'coupon': {
                    'amount_off': None,
                    'currency': 'eur',
                    'duration': 'repeating',
                    'duration_in_months': 3,
                    'livemode': False,
                    'percent_off': 25,
                    'stripe_id': '25OFF',
                    'valid': True
                },
                'customer': None,
                'end':
                dt.datetime.utcfromtimestamp(1516868522).isoformat() + 'Z',
                'start':
                dt.datetime.utcfromtimestamp(1508919722).isoformat() + 'Z',
            },
        }
    )

    request_history = active_requests_mock.request_history
    assert request_history[-1]._request.method == 'DELETE'
    assert request_history[-1].qs == {'at_period_end': ['true']}

    assert request_history[-2]._request.method == 'POST'
    if has_sub == 'no':
        assert request_history[-2].path == '/v1/subscriptions'
        assert request_history[-2].text == urlencode({
            'source': 'payment-source',
            'customer': 'cus_7UkUzpBtATnab9',
            'plan': subscription_plan.plan.stripe_id,
            'quantity': 1,
            'coupon': '25OFF'})
        subscription = Subscription.objects.get()
    else:
        assert request_history[-2].path == '/v1/subscriptions/sub_test1'
        assert request_history[-2].text is None
        subscription.refresh_from_db()
    assert subscription.cancel_at_period_end is True

    url = reverse_query('lock8:user-subscriptions',
                        kwargs={'uuid': non_matching_uuid})
    drf_renter.assert_404(url)

    url = reverse_query('lock8:user-subscriptions',
                        query_kwargs={'organization': org.uuid},
                        kwargs={'uuid': alice.uuid})
    drf_renter.assert_count(url, 1)


def test_subscribe_user_to_restricted_subscription_plan(
        alice, customer, drf_renter, subscription_plan, subscription_json,
        active_requests_mock):
    from velodrome.lock8.models import PlanPass

    active_requests_mock.get(
        'https://api.stripe.com/v1/subscriptions/sub_test1',
        json=subscription_json)
    active_requests_mock.delete(
        'https://api.stripe.com/v1/subscriptions/sub_test1?at_period_end=True',
        json=subscription_json)
    subscription_plan.is_restricted = True
    subscription_plan.save()
    active_requests_mock.post('https://api.stripe.com/v1/subscriptions',
                              json=subscription_json)
    url = reverse_query('lock8:subscription_plan-subscribe-user',
                        kwargs={'uuid': subscription_plan.uuid})
    drf_renter.assert_403(
        url, data={'stripe_source': 'payment-source', 'quantity': 1})

    PlanPass.objects.create(user=alice, subscription_plan=subscription_plan)
    response = drf_renter.assert_success(
        url, data={'stripe_source': 'payment-source', 'quantity': 1})
    assert response.data['subscription_plan']['is_restricted'] is True
    assert response.data['subscription_plan']['can_be_used_by_user'] is True


@pytest.mark.parametrize('params, stripe_error, api_error', (
    ({'stripe_source': 'payment-source'},
     (400, {'message': 'No such token: payment-source',
            'param': 'source',
            'type': 'invalid_request_error'
            }),
     {'stripe_source': {
         'code': 'invalid_source',
         'message': 'No such token.',
     }}),
    ({'stripe_source': 'payment-source',
      'auto_renewal': False,
      },
     (402, {'code': 'card_declined',
            'decline_code': 'insufficient_funds',
            'doc_url': 'https://stripe.com/docs/error-codes/card-declined',
            'message': 'Your card has insufficient funds.',
            'param': '',
            'type': 'card_error',
            }),
     {'stripe_source': {
         'code': 'user_card_insufficient_funds',
         'message': 'The card has insufficient funds.',
     }}),
    ({'stripe_source': 'payment-source',
      'auto_renewal': False,
      },
     (402, {'code': 'unexpected_code',
            'message': 'Unexpected card error.',
            'param': '',
            'type': 'card_error',
            }),
     {'stripe_source': {
         'code': 'user_card_error',
         'message': 'There was a card-related error: Unexpected card error. '
                    '(code=unexpected_code)',
     }}),
    ({'coupon': 'some-coupon'},
     (400, {'message': 'No such coupon: some-coupon',
            'param': 'coupon',
            'type': 'invalid_request_error',
            }),
     # XXX: should not be a list?!
     {'coupon': [{
         'code': 'invalid_coupon',
         'message': 'No such coupon: some-coupon'
     }]}),
))
def test_subscribe_user_expected_exception(active_requests_mock,
                                           customer_wo_subscriptions,
                                           subscription_plan, drf_renter,
                                           params, stripe_error, api_error):
    stripe_rcode, stripe_error = stripe_error
    active_requests_mock.post(
        'https://api.stripe.com/v1/subscriptions', status_code=stripe_rcode,
        json={'error': stripe_error})

    url = reverse_query('lock8:subscription_plan-subscribe-user',
                        kwargs={'uuid': subscription_plan.uuid})
    drf_renter.assert_400(url, data=params,
                          expected_detail=api_error)


def test_subscribe_user_unexpected_exception(active_requests_mock,
                                             customer_wo_subscriptions,
                                             subscription_plan, drf_renter):
    active_requests_mock.post(
        'https://api.stripe.com/v1/subscriptions', status_code=400,
        json={'error': {'message': 'Unknown error'}})

    url = reverse_query('lock8:subscription_plan-subscribe-user',
                        kwargs={'uuid': subscription_plan.uuid})
    with pytest.raises(stripe.error.InvalidRequestError):
        drf_renter.post(url, data={'stripe_source': 'test'})


def test_subscribe_user_with_existing_subscription(
        active_requests_mock, subscription_plan, subscription, drf_renter):
    subscription.cancel_at_period_end = False

    url = reverse_query('lock8:subscription_plan-subscribe-user',
                        kwargs={'uuid': subscription_plan.uuid})
    drf_renter.assert_status(url, status.HTTP_409_CONFLICT,
                             data={'stripe_source': 'test'})
    subscription.refresh_from_db()
    assert subscription.cancel_at_period_end is False


@pytest.mark.parametrize('at_period_end', (True, False))
def test_unsubscribe_user_from_subscription_plan(
        at_period_end, org, owner, alice, customer, drf_renter,
        alice_subscription, stripe_plan_detail, active_requests_mock,
        non_matching_uuid):
    from velodrome.lock8.models import SubscriptionPlan

    now = timezone.now()

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
        organization=org,
        name='weekday plan',
        interval=SubscriptionPlan.WEEK,
        cents=500,
        trial_period_days=0)
    subscription_plan.provision()
    subscription_plan.refresh_from_db()

    subscription_json['plan']['id'] = subscription_plan.plan.stripe_id
    cancelled_subscription_json = copy.deepcopy(subscription_json)
    if at_period_end:
        cancelled_subscription_json['status'] = 'active'
        cancelled_subscription_json['ended_at'] = None
        cancelled_subscription_json['cancel_at_period_end'] = True
    else:
        cancelled_subscription_json['status'] = 'canceled'
        cancelled_subscription_json['ended_at'] = now.timestamp()
        cancelled_subscription_json['cancel_at_period_end'] = False
    cancelled_subscription_json['canceled_at'] = now.timestamp()
    cancelled_subscription_json['plan']['id'] = (
        subscription_plan.plan.stripe_id)
    active_requests_mock.get(
        'https://api.stripe.com/v1/subscriptions/sub_7fCa7LZ9yzao5d',
        text=json.dumps(subscription_json))
    active_requests_mock.delete(
        'https://api.stripe.com/v1/subscriptions/'
        'sub_7fCa7LZ9yzao5d?at_period_end=%s' % at_period_end,
        text=json.dumps(cancelled_subscription_json))
    url = reverse_query('lock8:subscription_plan-unsubscribe-user',
                        kwargs={'uuid': subscription_plan.uuid})
    alice_subscription.plan = subscription_plan.plan
    alice_subscription.save()

    drf_renter.assert_success(
        url, data={'at_period_end': at_period_end}, expected_data={
            'cancel_at_period_end': at_period_end,
            'current_period_end': '2016-01-15T10:36:26Z',
            'current_period_start': '2016-01-05T10:36:26Z',
            'discount': None,
            'ended_at': None if at_period_end else now.isoformat()[:-13] + 'Z',
            'status': cancelled_subscription_json['status'],
            'stripe_id': 'sub_7fCa7LZ9yzao5d',
            'subscription_plan': {
                'available_dates': None,
                'bicycle_model': None,
                'cents': 500,
                'concurrency_version': subscription_plan.concurrency_version,
                'created': subscription_plan.created.isoformat()[:-13] + 'Z',
                'description': {},
                'interval': 'week',
                'modified': subscription_plan.modified.isoformat()[:-13] + 'Z',
                'name': 'weekday plan',
                'organization':
                    f'http://testserver/api/organizations/{org.uuid}/',
                'pricing_scheme': None,
                'state': 'provisioned',
                'statement_descriptor': '',
                'is_restricted': False,
                'can_be_used_by_user': True,
                'trial_period_days': 0,
                'url': f'http://testserver/api/subscription_plans/{subscription_plan.uuid}/',  # noqa: E501
                'uuid': f'{subscription_plan.uuid}',
                'weekdays': None}})

    alice_subscription.refresh_from_db()
    assert alice_subscription.status == cancelled_subscription_json['status']

    if not at_period_end:
        drf_renter.assert_404(url, data={'at_period_end': True})

        # Test filtering (does not include canceled ones).
        url = reverse_query('lock8:user-subscriptions',
                            query_kwargs={'organization': org.uuid},
                            kwargs={'uuid': alice.uuid})
        drf_renter.assert_count(url, 0)


def test_unsubscribe_user_multiple_subscriptions(
        mocker, drf_renter, customer, subscription, subscription_plan,
        caplog):
    from pinax.stripe.models import Subscription

    duplicate_subscription = Subscription.objects.create(
        stripe_id='sub_duplicate',
        customer=subscription.customer,
        plan=subscription.plan,
        quantity=subscription.quantity,
        start=timezone.now(),
        status='active')

    mocker.patch('pinax.stripe.actions.subscriptions.cancel',
                 side_effect=[subscription, duplicate_subscription])

    url = reverse_query('lock8:subscription_plan-unsubscribe-user',
                        kwargs={'uuid': subscription_plan.uuid})
    response = drf_renter.assert_success(url, data={})
    assert response.data['stripe_id'] == 'sub_duplicate'

    log_messages = [(rec.levelname, rec.message) for rec in caplog.records]
    expected_msg = 'Found multiple subscriptions for user %r: %s, %s' % (
        drf_renter.user, subscription.pk, duplicate_subscription.pk)
    assert ('ERROR', expected_msg) in log_messages


def test_unsubscribe_user_unknown_subscription_plan(drf_renter,
                                                    subscription_plan,
                                                    alice_subscription,
                                                    active_requests_mock,
                                                    mocker):
    error_body = {'error': {
        'type': 'invalid_request_error',
        'code': None,
        'message': 'InvalidRequestError: Request req_X',
        'param': 'subscription'}
    }
    active_requests_mock.delete(
        'https://api.stripe.com/v1/subscriptions/'
        'sub_7fCa7LZ9yzao5d?at_period_end=True',
        status_code=400, text=json.dumps(error_body))
    url = reverse_query(
        'lock8:subscription_plan-unsubscribe-user',
        kwargs={'uuid': subscription_plan.uuid})
    log_mock = mocker.patch('velodrome.lock8.models.logger')
    drf_renter.assert_success(url, data={'at_period_end': True})
    log_mock.warning.assert_called_with(
        "InvalidRequestError: Request req_X: OrderedDict(["
        "('error', OrderedDict(["
        "('type', 'invalid_request_error'), "
        "('code', None), "
        "('message', 'InvalidRequestError: Request req_X'), "
        "('param', 'subscription')"
        "]))"
        "])")
    error_body['error']['param'] = 'other'
    active_requests_mock.delete(
        'https://api.stripe.com/v1/subscriptions/'
        'sub_7fCa7LZ9yzao5d?at_period_end=True',
        status_code=400, json=error_body)
    with pytest.raises(stripe.error.InvalidRequestError):
        drf_renter.post(url, data={'at_period_end': True})


@pytest.mark.parametrize('with_customer', (True, False))
def test_unsubscribe_user_without_subscription(
        request, with_customer, drf_renter, org, owner):
    from velodrome.lock8.models import SubscriptionPlan

    if with_customer:
        request.getfixturevalue('customer')

    subscription_plan = SubscriptionPlan.objects.create(
        owner=owner,
        organization=org,
        name='weekday plan',
        interval=SubscriptionPlan.WEEK,
        cents=500,
        trial_period_days=0)
    url = reverse_query('lock8:subscription_plan-unsubscribe-user',
                        kwargs={'uuid': subscription_plan.uuid})
    response = drf_renter.post(url, data={'at_period_end': True})
    assert response.status_code == status.HTTP_404_NOT_FOUND


def test_rent_base(request, renter, drf_renter, bicycle_available,
                   pricing_scheme, active_requests_mock):
    rent_data = {'type': 'rent',
                 'user': reverse_query('lock8:user-detail',
                                       kwargs={'uuid': str(renter.uuid)})}
    url = reverse_query('lock8:bicycle-actions',
                        kwargs={'uuid': bicycle_available.uuid})
    expected_data = {'non_field_errors': [
        {'code': 'user_has_no_customer',
         'message': 'The user has no customer.'}]}
    drf_renter.assert_400(url, expected_data, data=rent_data)

    customer = request.getfixturevalue('customer_chargable')
    response = drf_renter.assert_success(url, None, data=rent_data)
    assert response.data['rental_session']['subscription_plan'] is None
    assert response.data['rental_session']['pricing_scheme'] == (
        'http://testserver' + reverse_query(
            'lock8:pricing_scheme-detail',
            kwargs={'uuid': pricing_scheme.uuid}))

    rental_session = bicycle_available.active_rental_session
    rental_session.refresh_from_db()
    charge = rental_session.charge
    assert charge.customer == customer
    assert charge.captured is False
    assert rental_session.payment_state == 'pending'


def test_user_ephemeral_key(alice, drf_alice, active_requests_mock, request,
                            drf_fleet_operator, org, non_matching_uuid,
                            customer):
    from velodrome.lock8.models import Affiliation

    Affiliation.objects.create(user=alice, organization=org)

    url = reverse_query('lock8:user-ephemeralkey', kwargs={'uuid': alice.uuid})
    response = drf_alice.get(url)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {'detail': {
        'stripe_api_version': [{'message': 'This field is required.',
                                'code': 'required'}],
        'organization': [{'message': 'This field is required.',
                          'code': 'required'}]
    }}
    url = reverse_query('lock8:user-ephemeralkey',
                        query_kwargs={'stripe_api_version': 'a',
                                      'organization': non_matching_uuid},
                        kwargs={'uuid': alice.uuid})
    response = drf_alice.get(url)
    assert response.status_code == status.HTTP_404_NOT_FOUND

    active_requests_mock.post(
        'https://api.stripe.com/v1/ephemeral_keys', status_code=400, json={
            'error': {'type': 'invalid_request_error',
                      'message': 'Invalid Stripe API version: invalid_ver'}})
    invalid_url = reverse_query(
        'lock8:user-ephemeralkey',
        query_kwargs={'stripe_api_version': 'invalid_ver',
                      'organization': org.uuid},
        kwargs={'uuid': alice.uuid}
    )
    response = drf_alice.get(invalid_url)
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.data == {'detail': {
        'stripe_api_version': [{
            'message': 'Invalid Stripe API version: invalid_ver',
            'code': 'invalid'}]}}

    request.getfixturevalue('customer')

    key_secret = "ek_test_YWNjdF8xNno2bDhFV25JdU96b29mLHM4Zmd4STRYWjBnZFJKbEVveGFjRG9NZmxieUN5dXU"  # noqa
    key_response = {
        "associated_objects": [{
                "id": "cus_BJB3ZFfkXyGe95",
                "type": "customer"
            }],
        "created": 1504109163,
        "expires": 1504112763,
        "id": "ephkey_1AwYhbEWnIuOzoofdZzn3BS7",
        "livemode": False,
        "object": "ephemeral_key",
        "secret": key_secret,
    }
    active_requests_mock.post(
        'https://api.stripe.com/v1/ephemeral_keys', json=key_response)

    url = reverse_query(
        'lock8:user-ephemeralkey',
        query_kwargs={'stripe_api_version': settings.PINAX_STRIPE_API_VERSION,
                      'organization': org.uuid},
        kwargs={'uuid': alice.uuid}
    )
    drf_alice.assert_success(url, key_response)

    drf_fleet_operator.assert_status(url, status.HTTP_404_NOT_FOUND)


def test_user_ephemeralkey_race(active_requests_mock, drf_renter, renter, org,
                                live_server, event_loop, mock_stripe_customer,
                                mocker):
    """
    Test race with getting ephemeralkey for the same non-existing customer.

    This uses a live_server (in a new thread) and asyncio for this.

    This was/is rather common with Android Rider IIRC.
    """
    import asyncio
    import time

    import aiohttp
    import rest_framework_jwt
    import stripe

    from velodrome.lock8.jwt_extensions import jwt_payload_handler

    key_secret = "ek_test_YWNjdF8xNno2bDhFV25JdU96b29mLHM4Zmd4STRYWjBnZFJKbEVveGFjRG9NZmxieUN5dXU"  # noqa
    key_response = {
        "associated_objects": [{
                "id": "cus_BJB3ZFfkXyGe95",
                "type": "customer"
            }],
        "created": 1504109163,
        "expires": 1504112763,
        "id": "ephkey_1AwYhbEWnIuOzoofdZzn3BS7",
        "livemode": False,
        "object": "ephemeral_key",
        "secret": key_secret,
    }
    active_requests_mock.post(
        'https://api.stripe.com/v1/ephemeral_keys', json=key_response)

    url = '%s%s' % (live_server.url, reverse_query(
        'lock8:user-ephemeralkey',
        query_kwargs={'stripe_api_version': settings.PINAX_STRIPE_API_VERSION,
                      'organization': org.uuid},
        kwargs={'uuid': renter.uuid}
    ))

    event_loop.set_debug(True)

    # Patch stripe.Customer.create to trigger race reliably.
    c = 0

    orig_create = stripe.Customer.create

    def slow_create(*args, **kwargs):
        nonlocal c
        c += 1
        while c < 2:
            time.sleep(0.05)
        return orig_create(*args, **kwargs)

    mocker.patch('stripe.Customer.create', side_effect=slow_create)

    async def get_ephemeralkey():
        async with aiohttp.ClientSession(headers={
            'Accept': 'application/json; version=1.0',
            'Authorization': 'JWT %s' % (
                rest_framework_jwt.utils.jwt_encode_handler(
                    jwt_payload_handler(renter)
                )),
        }) as client:
            async with client.get(url) as resp:
                text = await resp.text()
                assert resp.status == 200, text
                assert json.loads(text) == key_response

    coros = asyncio.gather(
        get_ephemeralkey(),
        get_ephemeralkey(),
        loop=event_loop,
    )
    event_loop.run_until_complete(coros)
    assert c == 2


def test_list_user_subscriptions(request, drf_renter, drf_bob, bob, alice, org,
                                 subscription_plan, subscription, customer,
                                 non_matching_uuid, plan):
    from velodrome.lock8.models import Affiliation, create_stripe_customer
    from velodrome.lock8.utils import disable_signal

    url = reverse_query('lock8:user-subscriptions',
                        kwargs={'uuid': non_matching_uuid})
    drf_renter.assert_404(url)

    # Alice cannot see bob's subscriptions
    url = reverse_query('lock8:user-subscriptions',
                        kwargs={'uuid': bob.uuid})
    drf_renter.assert_404(url)

    # Alice can see her own subscriptions
    url = reverse_query('lock8:user-subscriptions',
                        query_kwargs={'organization': org.uuid},
                        kwargs={'uuid': alice.uuid})

    expected_response = {
        'count': 1,
        'next': None,
        'previous': None,
        'results': [{
            'stripe_id': 'sub_test1',
            'cancel_at_period_end': False,
            'current_period_end': None,
            'current_period_start': None,
            'ended_at': None,
            'discount': None,
            'status': 'active',
            'subscription_plan': {
                'available_dates': None,
                'bicycle_model': None,
                'cents': 500,
                'concurrency_version': subscription_plan.concurrency_version,
                'created': subscription_plan.created.isoformat()[:-13] + 'Z',
                'description': {},
                'interval': 'week',
                'modified': subscription_plan.modified.isoformat()[:-13] + 'Z',
                'name': 'subscription_plan',
                'organization': f'http://testserver/api/organizations/{subscription_plan.organization.uuid}/',  # noqa
                'pricing_scheme': None,
                'state': 'provisioned',
                'is_restricted': False,
                'can_be_used_by_user': True,
                'statement_descriptor': '',
                'trial_period_days': 0,
                'url': f'http://testserver/api/subscription_plans/{subscription_plan.uuid}/',  # noqa
                'uuid': str(subscription_plan.uuid),
                'weekdays': None
            }
        }],
    }
    with CaptureQueriesContext(connection) as capture:
        drf_renter.assert_success(url, expected_response)

    # Creating a second subscription should result in the same number of
    # queries.
    request.getfixturevalue('second_subscription')
    with CaptureQueriesContext(connection) as capture2:
        drf_renter.assert_count(url, 2)
    assert len(capture.captured_queries) == len(capture2.captured_queries)

    # Bob cannot see his own subscriptions if he's not member of org
    url = reverse_query('lock8:user-subscriptions',
                        query_kwargs={'organization': org.uuid},
                        kwargs={'uuid': bob.uuid})
    drf_bob.assert_404(url)

    with disable_signal(post_save, create_stripe_customer, Affiliation):
        Affiliation.objects.create(user=bob, organization=org)
    # Bob can see his own subscriptions
    url = reverse_query('lock8:user-subscriptions',
                        query_kwargs={'organization': org.uuid},
                        kwargs={'uuid': bob.uuid})
    drf_bob.assert_count(url, 0)


def test_crud_plan_passes(drf_fleet_operator, fleet_operator, org, alice,
                          subscription_plan, bob):
    from velodrome.lock8.models import (
        Affiliation, PlanPass, create_stripe_customer)
    from velodrome.lock8.utils import disable_signal

    with disable_signal(post_save, create_stripe_customer, Affiliation):
        Affiliation.objects.create(user=bob, organization=org)
    subscription_plan.is_restricted = True
    subscription_plan.save()

    url = reverse_query('lock8:plan_pass-list')
    drf_fleet_operator.assert_count(url, 0)
    PlanPass.objects.create(user=alice, subscription_plan=subscription_plan)

    response = drf_fleet_operator.assert_count(url, 1)
    result = response.data['results'][0]

    plan_pass = PlanPass.objects.get()
    expected = {
        'uuid': str(plan_pass.uuid),
        'url': 'http://testserver' + reverse_query(
            'lock8:plan_pass-detail',
            kwargs={'uuid': plan_pass.uuid}),
        'subscription_plan': 'http://testserver' + reverse_query(
            'lock8:subscription_plan-detail',
            kwargs={'uuid': subscription_plan.uuid}),
        'user': 'http://testserver' + reverse_query(
            'lock8:user-detail',
            kwargs={'uuid': alice.uuid}),
        'concurrency_version': plan_pass.concurrency_version,
        'modified': plan_pass.modified.isoformat()[:-13] + 'Z',
        'created': plan_pass.created.isoformat()[:-13] + 'Z',
    }

    assert result == expected
    data = {
        'subscription_plan': 'http://testserver' + reverse_query(
            'lock8:subscription_plan-detail',
            kwargs={'uuid': subscription_plan.uuid}),
        'user': 'http://testserver' + reverse_query(
            'lock8:user-detail',
            kwargs={'uuid': alice.uuid}),
    }
    drf_fleet_operator.assert_400(url, data=data, format='json')
    assert subscription_plan.can_be_used_by_user(alice)
    assert not subscription_plan.can_be_used_by_user(bob)

    data['user'] = 'http://testserver' + reverse_query(
            'lock8:user-detail', kwargs={'uuid': bob.uuid})
    drf_fleet_operator.assert_status(url, status.HTTP_201_CREATED, data=data,
                                     format='json')
    assert subscription_plan.can_be_used_by_user(bob)

    plan_pass = PlanPass.objects.filter(user=alice).get()
    url = reverse_query('lock8:plan_pass-detail',
                        kwargs={'uuid': plan_pass.uuid})
    drf_fleet_operator.assert_success(url, expected_data=expected)

    url = reverse_query('lock8:plan_pass-list')
    drf_fleet_operator.assert_count(url, 2)

    url = reverse_query('lock8:plan_pass-detail',
                        kwargs={'uuid': plan_pass.uuid})
    response = drf_fleet_operator.delete(url)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    url = reverse_query('lock8:plan_pass-list')
    drf_fleet_operator.assert_count(url, 1)

    PlanPass.objects.create(user=alice, subscription_plan=subscription_plan)

    url = reverse_query('lock8:plan_pass-list')
    drf_fleet_operator.assert_count(url, 2)

    url = reverse_query('lock8:plan_pass-list',
                        {'user': alice.uuid})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:plan_pass-list',
                        {'subscription_plan': subscription_plan.uuid})
    drf_fleet_operator.assert_count(url, 2)


def test_pricing_scheme_filtering_by_state(drf_fleet_operator,
                                           pricing_scheme):
    filter_url = reverse_query('lock8:pricing_scheme-list',
                               {'state': 'provisioned'})
    drf_fleet_operator.assert_count(filter_url, 1)
    filter_url = reverse_query('lock8:pricing_scheme-list',
                               {'state': 'new'})
    drf_fleet_operator.assert_count(filter_url, 0)
