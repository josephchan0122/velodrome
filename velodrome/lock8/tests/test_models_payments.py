from datetime import timedelta
from decimal import ROUND_CEILING, Decimal
import re
import urllib.parse

from django.core.exceptions import ValidationError
from django.utils import timezone
from freezegun import freeze_time
from pinax.stripe.models import Subscription
from pinax.stripe.signals import WEBHOOK_SIGNALS
from psycopg2.extras import DateTimeTZRange, NumericRange
import pytest
from rest_framework import status
import stripe.error

pytestmark = pytest.mark.uses_payments


def test_subscriptionplan_model(org, owner, stripe_plan_detail,
                                active_requests_mock, renter):
    from velodrome.lock8.models import SubscriptionPlan

    now = timezone.now()

    def create_plan_callback(request, context):
        context.status_code = 200
        posted_body = dict(urllib.parse.parse_qsl(request.text))
        assert posted_body['amount'] == '3900'
        assert posted_body['currency'] == 'eur'
        body = {
            'id': posted_body['id'],
            'object': 'plan',
            'amount': posted_body['amount'],
            'created': now.timestamp(),
            'currency': posted_body['currency'],
            'interval': posted_body['interval'],
            'interval_count': posted_body['interval_count'],
            'livemode': False,
            'metadata': {
            },
            'name': posted_body['name'],
            'statement_descriptor': posted_body['statement_descriptor'],
            'trial_period_days': posted_body['trial_period_days']
        }
        return body

    active_requests_mock.register_uri(
        'GET', stripe_plan_detail, json={'error': {}},
        status_code=status.HTTP_404_NOT_FOUND)
    active_requests_mock.register_uri(
        'POST', 'https://api.stripe.com/v1/plans',
        json=create_plan_callback)
    description = {'en': {
        'title': 'title',
        'description': 'description',
        'fine_print': 'fine_print',
        'short_description': 'short_description',
    }}
    subscriptionplan = SubscriptionPlan.objects.create(
        owner=owner,
        organization=org,
        name='monthly plan',
        interval=SubscriptionPlan.MONTH,
        interval_count=2,
        description=description,
        cents=3900,
        trial_period_days=10,
        available_dates=(now - timedelta(days=7), now + timedelta(days=1)),
        weekdays=(1, 3),
        statement_descriptor='Whoa so cheap!',
    )
    subscriptionplan.refresh_from_db()
    assert subscriptionplan.owner == owner
    assert subscriptionplan.organization == org
    assert subscriptionplan.name == 'monthly plan'
    assert subscriptionplan.interval == 'month'
    assert subscriptionplan.interval_count == 2
    assert subscriptionplan.description == description
    assert subscriptionplan.cents == 3900
    assert subscriptionplan.trial_period_days == 10
    assert subscriptionplan.available_dates == DateTimeTZRange(
        lower=now - timedelta(days=7),
        upper=now + timedelta(days=1),
        bounds='[)',
    )
    assert subscriptionplan.weekdays == NumericRange(lower=1, upper=3,
                                                     bounds='[)')

    # A Stripe plan gets created on provisioning.
    assert subscriptionplan.plan is None
    assert not subscriptionplan.can_be_used_by_user(renter)

    subscriptionplan.provision()
    subscriptionplan.refresh_from_db()
    assert subscriptionplan.can_be_used_by_user(renter)

    plan = subscriptionplan.plan
    assert plan is not None
    assert plan.interval == 'month'
    assert plan.interval_count == 2
    assert plan.amount == 39
    assert plan.trial_period_days == 10
    assert plan.name == 'monthly plan'

    subscriptionplan.is_restricted = True
    subscriptionplan.save()
    assert not subscriptionplan.can_be_used_by_user(renter)

    # Cannot change most of the fields after it has been provisioned.
    subscriptionplan.cents += 1
    subscriptionplan.interval_count += 1
    with pytest.raises(ValidationError) as excinfo:
        subscriptionplan.clean()
    assert excinfo.value.message_dict == {
        'cents': ['Value cannot be changed after provisioning.'],
        'interval_count': ['Value cannot be changed after provisioning.']}

    subscriptionplan.cents -= 1
    subscriptionplan.interval_count -= 1
    subscriptionplan.plan = None
    with pytest.raises(ValidationError) as excinfo:
        subscriptionplan.full_clean()
    assert excinfo.value.message_dict == {
        'plan': ['A Plan is required for provisioned state. '
                 'This should get handled automatically - '
                 'might just have been created.']}


def test_subscriptionplan_model_race_condition(org, owner, subscription_plan,
                                               stripe_plan_detail,
                                               active_requests_mock):

    active_requests_mock.register_uri(
        'GET', stripe_plan_detail,
        [{'json': {'error': {
            'message': 'Not Found',
            'type': 'invalid_request_error'}},
          'status_code': 404},
         {'json': {'id': 'gold',
                   'object': 'plan'},
          'status_code': 200},
         ])
    active_requests_mock.register_uri(
        'POST', 'https://api.stripe.com/v1/plans',
        status_code=400,
        json={
            'error': {'message': 'Plan already exists.',
                      'type': 'invalid_request_error'}
        })
    active_requests_mock.register_uri(
        'PATCH', stripe_plan_detail,
        json={'id': 'gold', 'object': 'plan'})
    subscription_plan.name = 'New Name'
    subscription_plan.save()
    subscription_plan.plan.refresh_from_db()
    assert subscription_plan.plan.name == 'New Name'


def test_subscriptionplan_model_race_condition_unhandled_failure(
        org, owner, subscription_plan, stripe_plan_detail,
        active_requests_mock):

    active_requests_mock.register_uri(
        'GET', stripe_plan_detail,
        json={'error': {'message': 'Not Found',
                        'type': 'invalid_request_error'}},
        status_code=404,
         )
    active_requests_mock.register_uri(
        'POST', 'https://api.stripe.com/v1/plans',
        status_code=400,
        json={
            'error': {'message': 'Some error',
                      'type': 'api_error'}
        })
    active_requests_mock.register_uri(
        'PATCH', stripe_plan_detail,
        json={'id': 'gold', 'object': 'plan'})
    subscription_plan.name = 'New Name'
    with pytest.raises(stripe.error.InvalidRequestError):
        subscription_plan.save()


def test_subscriptionplan_clean():
    from velodrome.lock8.models import SubscriptionPlan
    from pinax.stripe.models import Plan

    subscriptionplan = SubscriptionPlan()
    subscriptionplan.plan = Plan()
    with pytest.raises(ValidationError) as excinfo:
        subscriptionplan.clean()
    assert excinfo.value.message_dict == {
        'plan': ['Plan requires to have a currency.']}


def test_subscriptionplan_str(subscription_plan):
    assert str(subscription_plan) == (
        f'{subscription_plan.name} '
        f'Organization[{subscription_plan.organization_id}]')


def test_update_or_create_remote_plan(mocker, owner, org):
    from velodrome.celery import update_or_create_remote_plan
    from velodrome.lock8.models import SubscriptionPlan
    import stripe

    subscriptionplan = SubscriptionPlan.objects.create(
        owner=owner, organization=org, name='some subscription plan',
        interval=SubscriptionPlan.WEEK, cents=500, trial_period_days=0)

    retrieve_mock = mocker.patch(
        'stripe.Plan.retrieve',
        side_effect=stripe.error.InvalidRequestError(
            'Request req_guxYJLcK7msp3u: No such Plan: nadda', 'plan'))
    create_mock = mocker.patch('stripe.Plan.create')
    update_or_create_remote_plan(subscriptionplan.pk)
    assert retrieve_mock.call_args_list == [
        mocker.call(subscriptionplan.stripe_id, stripe_account='acc_org')]
    assert create_mock.call_args_list == [
        mocker.call(amount=500, currency='eur',
                    id=subscriptionplan.stripe_id,
                    interval='week', interval_count=1,
                    name='some subscription plan',
                    statement_descriptor=None,
                    trial_period_days=0,
                    stripe_account='acc_org',
                    )]


def test_update_or_create_remote_plan_race(mocker, owner, org):
    from velodrome.celery import update_or_create_remote_plan
    from velodrome.lock8.models import SubscriptionPlan
    from pinax.stripe.models import Plan
    import stripe

    subscriptionplan = SubscriptionPlan.objects.create(
        owner=owner, organization=org, name='some subscription plan',
        interval=SubscriptionPlan.WEEK, cents=500, trial_period_days=0)
    Plan.objects.create(amount=5, interval='week', interval_count=1,
                        name='existing_name',
                        stripe_id=subscriptionplan.stripe_id,
                        stripe_account=org.stripe_account)

    stripe_plan = mocker.Mock(autospec=stripe.Plan)
    stripe_plan.name = 'stripe_plan_name'
    retrieve_mock = mocker.patch('stripe.Plan.retrieve',
                                 return_value=stripe_plan)
    update_or_create_remote_plan(subscriptionplan.pk)
    assert retrieve_mock.call_args_list == [
        mocker.call(subscriptionplan.stripe_id, stripe_account='acc_org')]

    plan = Plan.objects.get()
    assert plan.name == 'existing_name'
    assert stripe_plan.name == 'existing_name'
    assert stripe_plan.save.call_args_list == [mocker.call()]


def test_pricing_scheme_model(org, owner):
    from velodrome.lock8.models import PricingScheme, SubscriptionPlan

    description = {'en-gb': {
        'title': 'title',
        'description': 'description',
        'fine_print': 'fine_print',
        'short_description': 'short_description',
    }}
    pricing_scheme = PricingScheme.objects.create(
        name='dat pricing scheme',
        organization=org,
        owner=owner,
        time_ranges=((0, None, 0, False, 0),),
        max_daily_charged_cents=2000,
        description=description,
    )

    assert pricing_scheme.owner == owner
    assert pricing_scheme.organization == org
    assert pricing_scheme.name == 'dat pricing scheme'
    assert pricing_scheme.max_daily_charged_cents == 2000
    assert pricing_scheme.time_ranges == ((0, None, 0, False, 0),)
    assert pricing_scheme.description == description

    pricing_scheme.provision()
    pricing_scheme.clean()

    pricing_scheme2 = PricingScheme(
        name='dat pricing scheme 2',
        organization=org,
        owner=owner,
        time_ranges=((0, None, 0, False, 0),),
        max_daily_charged_cents=2000,
        description=description,
    )
    pricing_scheme2.clean()
    with pytest.raises(ValidationError) as excinfo:
        pricing_scheme2.provision()
    assert excinfo.value.messages == [
        'A global PricingScheme is already provisioned in the scope'
        ' of this organization.']

    # But given two global pricing schemes, decommission is possible.
    pricing_scheme2.state = 'provisioned'
    pricing_scheme2.save()
    pricing_scheme2.clean()
    pricing_scheme.decommission()

    with pytest.raises(ValidationError) as excinfo:
        pricing_scheme.provision()
    assert excinfo.value.messages == [
        'A global PricingScheme is already provisioned in the scope'
        ' of this organization.']

    # Attach pricing_scheme to subscription_plan and provision it.
    subscription_plan = SubscriptionPlan.objects.create(
        owner=owner,
        organization=org,
        name='sub',
        interval=SubscriptionPlan.WEEK,
        cents=500,
        trial_period_days=0,
    )
    subscription_plan.pricing_scheme = pricing_scheme
    subscription_plan.save()
    subscription_plan.clean()
    pricing_scheme.provision()

    # Ignores self.pk.
    pricing_scheme2._provision()

    subscription_plan.pricing_scheme = None
    with pytest.raises(ValidationError) as excinfo:
        subscription_plan.clean()
    assert excinfo.value.messages == [
        'A global PricingScheme is already provisioned in the scope'
        ' of this organization.']


def test_pricing_scheme_model_clean_without_org(db):
    from velodrome.lock8.models import PricingScheme
    pricing_scheme = PricingScheme()
    pricing_scheme.clean()


@pytest.mark.parametrize('time_ranges,error_message', (
    (None, 'This field cannot be null.'),
    (1, 'time_ranges 1 is not a list.'),
    ((1, ()), 'Item #0 is not a list.'),
    ((), 'This field cannot be blank.'),
    (((0, 1, 0, False, 0), (0, 0), (0, 0, 0, False, 0)),
     'Item #1 is not a list with 5 entries.'),
    ((('', 0, 0,  False, 0), (0, 0, 0, False, 0)),
     'Item #0: lower_duration is not a decimal.'),
    (((0, '', 0, False, 0), (0, 0, 0, False, 0)),
     'Item #0: upper_duration is not a decimal.'),
    (((0, 1, 0, False, 0), (1, 2, '', False, 0), (0, 0, 0, False, 0)),
     'Item #1: cents is not a integer.'),
    (((0, 1, 0, False, 0), (1, 2, -1, False, 0), (0, 0, 0, False, 0)),
     'Item #1: cents is not positive.'),
    (((0, 0, 0, False, 0), (0, 0, 0, False, 0)),
     'Item #0: upper_duration must be greater than lower_duration.'),
    (((0, 1, 0, 1, 30), (1, None, 0, False, 0)),
     'Item #0: prorated must be a boolean.'),
    (((0, 1, 0, True, 'h'), (1, None, 0, False, 0)),
     'Item #0: prorated_duration must be null or an integer.'),
    (((0, 1, 0, True, 0), (1, None, 0, False, 0)),
     'Item #0: prorated_duration cannot be 0 if prorated is True.'),
    (((0, 30, 0, False, 0),
      (40, 60, 0, False, 0),
      (60, None, 0, False, 0)),
     'Item #1: duration is not contiguous: 30 != 40.'),
    (((0, 1, 0, False, 0), None), 'Last item is not a list.'),
    (((0, 1, 0, False, 0), (0, 0)),
     'Last item is not a list with 5 entries.'),
    (((0, 1, 0, False, 0), ('', 0, 0, False, 0)),
     'Last item: lower_duration is not a decimal.'),
    (((0, 1, 0, False, 0), (0, '', 0, False, 0)),
     'Last item: upper_duration must be null.'),
    (((0, 1, 0, False, 0), (0, None, '', False, 0)),
     'Last item: cents is not a integer.'),
    (((0, 1, 0, False, 0), (1, None, -1, False, 0)),
     'Last item: cents is not positive.'),
    (((0, 1, 0, False, 0), (1, None, 1, None, 0)),
     'Last item: prorated must be a boolean.'),
    (((0, 1, 0, False, 0), (1, None, 0, True, 'h')),
     'Last item: prorated_duration must be null or an integer.'),
    (((0, 1, 0, False, 0), (1, None, 0, True, 0)),
     'Last item: prorated_duration cannot be 0 if prorated is True.'),
    (((0, 30, 0, False, 0), (40, None, 0, False, 0)),
     'Last item: duration is not contiguous: 30 != 40.'),
))
def test_pricing_scheme_time_ranges_validation(time_ranges, error_message,
                                               owner, org):
    from velodrome.lock8.models import PricingScheme

    p = PricingScheme(time_ranges=time_ranges,
                      owner=owner,
                      organization=org,
                      )
    with pytest.raises(ValidationError) as e:
        p.full_clean(validate_unique=False)
    assert error_message in str(e.value)


@pytest.mark.parametrize('description,error_message', (
    (None, 'This field cannot be null.'),
    (1, "1 is not of type 'dict'"),
    ({1: 'test'}, '1 is not a supported language'),
    ({'xx': 'test'}, 'xx is not a supported language'),
    ({'en': 1}, "Value for key en is not of type 'dict'"),
    ({'en': {'not_a_description': 'foo'}},
     'Extra fields found: not_a_description'),
))
def test_payments_description_validation(description, error_message, owner,
                                         org):
    from velodrome.lock8.models import PricingScheme, SubscriptionPlan

    pricing = PricingScheme(
        description=description,
        owner=owner,
        organization=org,
        time_ranges=[[0, None, 0, False, 0]],
    )
    sub = SubscriptionPlan(
        description=description,
        owner=owner,
        organization=org,
    )
    for model in (pricing, sub):
        with pytest.raises(ValidationError) as e:
            model.clean_fields()
        assert error_message in str(e.value)


def test_get_pricings_from_bicycle_priorities(
        org, bicycle, bicycle_model, alice, owner, customer,
        stripe_plan_detail, active_requests_mock):

    from velodrome.lock8.models import (
        Affiliation,
        PricingScheme,
        SubscriptionPlan,
    )

    Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.RENTER,
    )
    bicycle.model = bicycle_model
    bicycle.save()

    description = {'en-gb': {
        'title': 'title',
        'description': 'description',
        'fine_print': 'fine_print',
        'short_description': 'short_description',
    }}
    # default behaviour
    assert bicycle.get_pricings_for_user(alice) == {'pricing_schemes': [],
                                                    'subscription_plans': [],
                                                    'active_subscriptions': []}

    # pricing scheme attached to org
    pricing_scheme_org = PricingScheme.objects.create(
        organization=org,
        owner=owner,
        name='1',
        time_ranges=((0, None, 0, True, 60),),
        description=description,
        )
    pricing_scheme_org.provision()
    assert bicycle.get_pricings_for_user(alice) == {
        'pricing_schemes': [pricing_scheme_org],
        'subscription_plans': [],
        'active_subscriptions': []}

    # pricing scheme + subscription plan attached to org
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
        name='monthly plan',
        interval=SubscriptionPlan.MONTH,
        cents=3900,
        trial_period_days=10,
        pricing_scheme=pricing_scheme_org,
    )
    subscription_plan.provision()
    subscription_plan.refresh_from_db()
    assert bicycle.get_pricings_for_user(alice) == {
        'pricing_schemes': [],
        'subscription_plans': [subscription_plan],
        'active_subscriptions': [],
    }

    Subscription.objects.create(
        customer=customer,
        plan=subscription_plan.plan,
        quantity=1,
        start=timezone.now(),
        status='active',
    )
    assert bicycle.get_pricings_for_user(alice) == {
        'active_subscriptions': [subscription_plan],
        'pricing_schemes': [],
        'subscription_plans': [],
    }
    subscription_plan.decommission()
    assert bicycle.get_pricings_for_user(alice) == {
        'active_subscriptions': [subscription_plan],
        'pricing_schemes': [],
        'subscription_plans': [],
    }

    # pricing scheme attached to bicycle model
    pricing_scheme_model = PricingScheme.objects.create(
        organization=org,
        bicycle_model=bicycle_model,
        owner=owner,
        name='1',
        time_ranges=((0, None, 0, True, 60),),
        description=description,
        )
    pricing_scheme_model.provision()
    assert bicycle.get_pricings_for_user(alice) == {
        'pricing_schemes': [pricing_scheme_model],
        'subscription_plans': [],
        'active_subscriptions': [],
    }

    # pricing scheme + subscription plan attached to bicycle model
    pricing_scheme = PricingScheme.objects.create(
        organization=org,
        owner=owner,
        name='1',
        time_ranges=((0, None, 0, True, 60),),
        description=description,
    )
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
    subscription_plan_model = SubscriptionPlan.objects.create(
        owner=owner,
        organization=org,
        bicycle_model=bicycle_model,
        name='monthly plan 2',
        interval=SubscriptionPlan.MONTH,
        cents=3900,
        trial_period_days=10,
        pricing_scheme=pricing_scheme,
        description=description,
    )
    subscription_plan_model.provision()
    subscription_plan_model.refresh_from_db()
    assert bicycle.get_pricings_for_user(alice) == {
        'pricing_schemes': [pricing_scheme_model],
        'subscription_plans': [subscription_plan_model],
        'active_subscriptions': [],
    }

    Subscription.objects.create(
        stripe_id='fake',
        customer=customer,
        plan=subscription_plan_model.plan,
        quantity=1,
        start=timezone.now(),
        status='active',
    )
    assert bicycle.get_pricings_for_user(alice) == {
        'active_subscriptions': [subscription_plan_model],
        'pricing_schemes': [],
        'subscription_plans': [],
    }
    subscription_plan_model.decommission()
    assert bicycle.get_pricings_for_user(alice) == {
        'active_subscriptions': [subscription_plan_model],
        'pricing_schemes': [],
        'subscription_plans': [],
    }


def test_get_pricings_from_bicycle_available(org, bicycle, bicycle_model,
                                             alice, owner, customer,
                                             stripe_plan_detail,
                                             active_requests_mock):

    from velodrome.lock8.models import (
        Affiliation,
        SubscriptionPlan,
    )

    Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.RENTER,
    )
    bicycle.model = bicycle_model
    bicycle.save()

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
    # subscription attached to org only available in the future
    subscription_plan = SubscriptionPlan.objects.create(
        owner=owner,
        organization=org,
        name='weekday plan',
        interval=SubscriptionPlan.WEEK,
        cents=500,
        trial_period_days=0,
        available_dates=(timezone.now() + timedelta(days=1),
                         timezone.now() + timedelta(days=2)),
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
    # subscription attached to org only available now
    subscription_plan = SubscriptionPlan.objects.create(
        owner=owner,
        organization=org,
        name='weekend plan',
        interval=SubscriptionPlan.WEEK,
        cents=2000,
        trial_period_days=0,
        available_dates=(timezone.now() - timedelta(days=1),
                         timezone.now() + timedelta(days=1)),
    )
    subscription_plan.provision()
    subscription_plan.refresh_from_db()
    Subscription.objects.create(
        stripe_id='fake2',
        customer=customer,
        plan=subscription_plan.plan,
        quantity=1,
        start=timezone.now(),
        status='active',
    )
    assert bicycle.get_pricings_for_user(alice) == {
        'active_subscriptions': [subscription_plan],
        'pricing_schemes': [],
        'subscription_plans': [],
    }


def test_get_pricings_from_bicycle_weekday(
        org, bicycle, bicycle_model, alice, owner, customer,
        stripe_plan_detail, active_requests_mock):
    from velodrome.lock8.models import Affiliation, SubscriptionPlan

    Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.RENTER,
    )
    bicycle.model = bicycle_model
    bicycle.save()

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
    # subscription attached to org only available during week days.
    subscription_plan = SubscriptionPlan.objects.create(
        owner=owner,
        organization=org,
        name='weekday plan',
        interval=SubscriptionPlan.WEEK,
        cents=500,
        trial_period_days=0,
        weekdays=(1, 5),
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
    with freeze_time('2015-11-08 12:01:01'):  # this is a Sunday
        assert bicycle.get_pricings_for_user(alice) == {
            'pricing_schemes': [],
            'subscription_plans': [],
            'active_subscriptions': [],
        }

    with freeze_time('2015-11-09 12:01:01'):  # this is a Monday
        assert bicycle.get_pricings_for_user(alice) == {
            'active_subscriptions': [subscription_plan],
            'pricing_schemes': [],
            'subscription_plans': [],
        }


def test__rent_handle_payments(
        mocker, renter, organization_preference, bicycle,
        subscription_plan, subscription,
        second_subscription_plan, second_subscription,
        pricing_scheme):
    from velodrome.lock8.models import RentalSession

    rental_session = RentalSession.objects.create(
        user=renter, owner=renter, bicycle=bicycle)
    assert organization_preference.allow_renting_without_pricings is True

    # User has no pricings.
    mocker.patch('velodrome.lock8.models.Bicycle.get_pricings_for_user',
                 return_value={})

    with pytest.raises(ValidationError) as excinfo:
        bicycle._rent_handle_payments(rental_session, subscription_plan, None)
    assert excinfo.value.message_dict == {
        'subscription_plan': ['This SubscriptionPlan is not valid.']}

    with pytest.raises(ValidationError) as excinfo:
        bicycle._rent_handle_payments(rental_session, None, pricing_scheme)
    assert excinfo.value.message_dict == {
        'pricing_scheme': ['This PricingScheme is not valid.']}

    organization_preference.allow_renting_without_pricings = False
    organization_preference.save()
    assert bicycle.organization.allow_renting_without_pricings is False
    with pytest.raises(ValidationError) as excinfo:
        bicycle._rent_handle_payments(rental_session, subscription_plan, None)
    assert excinfo.value.messages == [
        'This bicycle can not be rented due to pricing policy.']

    # User has a single subscription.
    mocker.patch('velodrome.lock8.models.Bicycle.get_pricings_for_user',
                 return_value={'active_subscriptions': [subscription_plan]})

    with pytest.raises(ValidationError) as excinfo:
        bicycle._rent_handle_payments(rental_session,
                                      second_subscription_plan, None)
    assert excinfo.value.message_dict == {
        'subscription_plan': ['This SubscriptionPlan is not valid.']}

    m = mocker.patch.object(rental_session, 'save')
    bicycle._rent_handle_payments(rental_session, subscription_plan, None)
    assert m.called
    assert rental_session.payment_state == 'pending'
    assert rental_session.charge is None

    # User has two subscriptions.
    mocker.patch('velodrome.lock8.models.Bicycle.get_pricings_for_user',
                 return_value={'active_subscriptions': [
                     subscription_plan, second_subscription_plan]})

    with pytest.raises(ValidationError) as excinfo:
        bicycle._rent_handle_payments(rental_session, None, None)
    assert excinfo.value.messages == [
        'A pricing needs to be chosen by the renter.']


@pytest.mark.parametrize('time_ranges,duration,expected_amount', (
    (((0, None, 0, True, 60),), timedelta(hours=2), 0),
    (((0, None, 1, True, 60),), timedelta(hours=2), 2),
    (((0, None, 1, False, 0),), timedelta(hours=2), 1),
    (((0, 30, 1, False, 0), (30, None, 2, False, 0)), timedelta(hours=2), 3),
    # 0.5h * 1              + 1.5h * 2                               = 4
    (((0, 30, 1, False, 0), (30, None, 2, True, 60)), timedelta(hours=2), 4),
    (((0, 30, 100, True, 60), (30, None, 200, False, 0)), timedelta(hours=2),
     250),
    # 0.5h * 1€               + 1.5h * 2€                            = 3.5
    (((0, 30, 100, True, 60), (30, None, 200, True, 60)),
     timedelta(hours=2), 350),
    # 0.25h * 1€              + break                  = 0.25€
    (((0, 30, 100, True, 60), (30, None, 100, False, 0)),
     timedelta(minutes=15), 25),
    # 1€                      + break                   = 1
    (((0, 30, 100, False, 0), (30, None, 100, True, 60)),
     timedelta(minutes=15), 100),
    (((0, 30, 100, False, 0), (30, 60, 200, False, 0),
      (60, None, 500, True, 60)), timedelta(hours=2, minutes=30), 1050),
    # 0                     + 4                    + break = 4
    (((0, 30, 0, False, 0), (30, 60, 4, False, 0), (60, None, 7, True, 30)),
     timedelta(minutes=31), 4),
    # 0€                   + 1€ for every started rested minutes (5 * 1 minute)
    (((0, 1, 0, False, 0), (1, None, 100, False, 1)),
     timedelta(minutes=5, seconds=3), 500),
    # 0€                   + 1€ for every started rested minutes (4 * 1 minute)
    (((0, 1, 0, False, 0), (1, None, 100, False, 1)),
     timedelta(minutes=5), 400),
    (((0,  1, 0, False, 0), (1,  10, 100, False, 1),
      (10, None, 200, False, 1)), timedelta(minutes=2, seconds=30), 200),

    (((0, 30, 0, False, 0), (30, None, 100, False, 60)),
     timedelta(hours=1), 100),
    (((0, 30, 0, False, 0), (30, None, 100, False, 60)),
     timedelta(hours=2), 200),
    (((0, 30, 0, False, 0), (30, None, 100, False, 60)),
     timedelta(hours=2, minutes=30), 200),
    (((0, 30, 0, False, 0), (30, None, 100, False, 60)),
     timedelta(hours=2, minutes=30, seconds=1), 300),
))
def test_compute_amount_for_duration(time_ranges, duration, expected_amount):
    from velodrome.lock8.models import PricingScheme

    pricing_scheme = PricingScheme(name='Pricing scheme',
                                   time_ranges=time_ranges)

    computed_amount = pricing_scheme.compute_amount_for_duration(duration)
    assert computed_amount == expected_amount
    assert type(computed_amount) == int


def test_compute_amount_for_duration_with_tax(pricing_scheme,
                                              organization_preference):
    duration = timedelta(hours=1)
    computed_amount = pricing_scheme.compute_amount_for_duration(duration)
    assert computed_amount == 100
    assert type(computed_amount) == int

    organization_preference.tax_percent = 12.34
    organization_preference.save()
    computed_amount = pricing_scheme.compute_amount_for_duration(duration)
    assert computed_amount == 113
    assert type(computed_amount) == int

    duration = timedelta(hours=2)
    computed_amount = pricing_scheme.compute_amount_for_duration(duration)
    organization_preference.tax_percent = 12.34
    organization_preference.save()
    assert computed_amount == 225
    assert type(computed_amount) == int


@pytest.mark.parametrize('hours', (1, 2, 3))
@pytest.mark.parametrize('tax_percent', (None, Decimal('12.34')))
def test_price_computation_when_returning_bicycle_with_pricing_scheme(
        hours, tax_percent, org, bicycle_available, renter,
        owner, customer, organization_preference, customer_chargable,
        active_requests_mock, stripe_charge_from_source_json, mocker,
        commit_success, refund_charge_json, now):
    from velodrome.celery import generate_payment
    from velodrome.lock8.models import PricingScheme
    import pinax.stripe.actions.charges

    duration = timedelta(hours=hours) - timedelta(seconds=1)

    if tax_percent:
        organization_preference.tax_percent = tax_percent
        organization_preference.save()

    description = {'en': {
        'title': 'title',
        'description': 'description',
        'fine_print': 'fine_print',
        'short_description': 'short_description',
    }}
    pricing_scheme = PricingScheme.objects.create(
        organization=org, owner=owner, name='Pricing scheme',
        time_ranges=((0, None, 100, True, 60),),
        description=description,
    )
    pricing_scheme.provision()

    bicycle = bicycle_available

    with freeze_time(now):
        bicycle.rent(by=renter, pricing_scheme=pricing_scheme)
    assert bicycle.active_rental_session.pricing_scheme == pricing_scheme
    assert bicycle.active_rental_session.subscription_plan is None
    rental_session = bicycle.rental_sessions.get()
    # non-captured charge for 2 hours.
    non_captured_amount = Decimal('2')
    if tax_percent:
        non_captured_amount += Decimal(
            non_captured_amount / 100 * tax_percent).quantize(
                Decimal('1.00'), rounding=ROUND_CEILING)
    assert rental_session.charge.amount == non_captured_amount

    expected_cents = 100 * hours
    if tax_percent:
        expected_cents += Decimal(
            Decimal(expected_cents) / 100 * tax_percent).quantize(
                Decimal('1'), rounding=ROUND_CEILING)
    expected_amount = Decimal(expected_cents) / 100

    def charge_json(request, context):
        posted_body = dict(urllib.parse.parse_qsl(request.text))
        assert posted_body == {
            'amount': str(expected_cents),
            'expand[0]': 'balance_transaction'}

        response = stripe_charge_from_source_json.copy()
        stripe_id = re.match('/v1/charges/([^/]+)/capture', request.path)[1]
        response['id'] = stripe_id
        response['amount'] = int(posted_body['amount'])
        response['captured'] = True
        return response

    refund_called = False

    def refund_json(request, context):
        nonlocal refund_called
        refund_called = True

        response = refund_charge_json.copy()
        stripe_id = re.match('/v1/charges/([^/]+)/refund', request.path)[1]
        response['id'] = stripe_id
        response['amount'] = 338 if tax_percent else 300
        response['charge'] = charge_stripe_id
        return refund_charge_json

    m_generate_payment_task = mocker.patch.object(generate_payment, 'delay')

    with freeze_time(now + duration):
        bicycle.return_(by=renter)
    commit_success()

    call = mocker.mock_module.call
    assert m_generate_payment_task.call_args_list == [call(rental_session.pk)]

    charge_stripe_id = rental_session.charge.stripe_id
    if hours <= 2:
        active_requests_mock.post(
            f'https://api.stripe.com/v1/charges/{charge_stripe_id}/capture',
            json=charge_json)
        charges_capture = mocker.spy(pinax.stripe.actions.charges, 'capture')
    else:
        charges_create = mocker.spy(pinax.stripe.actions.charges, 'create')
        active_requests_mock.get(
            f'https://api.stripe.com/v1/charges/{charge_stripe_id}'
            '?expand%5B0%5D=balance_transaction',
            json=stripe_charge_from_source_json)
        active_requests_mock.post(
            f'https://api.stripe.com/v1/charges/{charge_stripe_id}/refund',
            json=refund_json)

    # Call the Celery task now.
    generate_payment(rental_session.pk)

    if hours <= 2:
        assert charges_capture.call_args_list == [
            call(rental_session.charge, amount=expected_amount,
                 idempotency_key=f'capture-{rental_session.uuid}')]
    else:
        assert refund_called
        assert charges_create.call_args_list == [
            call(amount=Decimal('3.38') if tax_percent else Decimal('3'),
                 capture=True,
                 currency='usd',
                 customer=customer,
                 idempotency_key=f'replace-{rental_session.uuid}',
                 send_receipt=False)]

    rental_session.refresh_from_db()
    assert rental_session.payment_state == 'processed'
    assert (int(rental_session.duration.total_seconds()) ==
            int(duration.total_seconds()))
    assert rental_session.cents == expected_cents
    assert rental_session.currency == 'usd'
    rental_session.charge.refresh_from_db()
    assert rental_session.charge.amount == expected_amount


@pytest.mark.parametrize('hours', (1, 2, 3))
def test_price_computation_when_returning_bicycle_with_subscriptionplan(
        hours, subscription, subscription_plan, org, bicycle_available, renter,
        owner, customer, customer_chargable, mocker, commit_success, now):
    from velodrome.celery import generate_payment
    from velodrome.lock8.models import PricingScheme
    import pinax.stripe.actions.charges

    duration = timedelta(hours=hours)

    # Attach a pricing_scheme for overages.
    description = {'en': {
        'title': 'title',
        'description': 'description',
        'fine_print': 'fine_print',
        'short_description': 'short_description',
    }}
    pricing_scheme = PricingScheme.objects.create(
        organization=org, owner=owner, name='Pricing scheme',
        time_ranges=[
            [0, 60, 0, False, 0],
            [60, None, 300, False, 60],
        ],
        description=description,
    )
    pricing_scheme.provision()
    subscription_plan.pricing_scheme = pricing_scheme
    subscription_plan.save()

    expected_cents = 300 * (hours - 1)
    expected_amount = Decimal(expected_cents) / 100

    bicycle = bicycle_available

    with freeze_time(now):
        bicycle.rent(by=renter, subscription_plan=subscription_plan)

    rental_session = bicycle.active_rental_session
    assert rental_session.subscription_plan == subscription_plan
    assert rental_session.pricing_scheme is None
    assert rental_session.charge is None

    m_generate_payment_task = mocker.patch.object(generate_payment, 'delay')
    with freeze_time(now + duration):
        bicycle.return_(by=renter)
    commit_success()

    if hours > 1:
        call = mocker.mock_module.call
        assert m_generate_payment_task.call_args_list == [
            call(rental_session.pk)]

        charges_create = mocker.spy(pinax.stripe.actions.charges, 'create')
        # Call the Celery task now.
        generate_payment(rental_session.pk)

    rental_session.refresh_from_db()

    if hours > 1:
        assert charges_create.call_args_list == [
            call(amount=expected_amount,
                 capture=True,
                 currency='eur',
                 customer=customer,
                 idempotency_key=f'create-{rental_session.uuid}',
                 send_receipt=False)]
        assert rental_session.charge.amount == expected_amount
    else:
        assert rental_session.cents == 0
        assert rental_session.charge is None

    assert rental_session.payment_state == 'processed'
    assert (int(rental_session.duration.total_seconds()) ==
            int(duration.total_seconds()))
    assert rental_session.cents == expected_cents
    assert rental_session.currency == 'eur'


@pytest.mark.parametrize('error', ('charge_already_refunded', None))
def test_process_payments_with_exception_after_new_charge(
        error, caplog, bicycle_available, renter, pricing_scheme, customer,
        customer_chargable, active_requests_mock, mocker, commit_success, now):
    from velodrome.celery import generate_payment
    from pinax.stripe.models import Charge

    bicycle = bicycle_available

    with freeze_time(now):
        bicycle.rent(by=renter, pricing_scheme=pricing_scheme)
    rental_session = bicycle.rental_sessions.get()

    m_generate_payment_task = mocker.patch.object(generate_payment, 'delay')

    with freeze_time(now + timedelta(hours=3)):
        bicycle.return_(by=renter)
    commit_success()

    call = mocker.mock_module.call
    assert m_generate_payment_task.call_args_list == [call(rental_session.pk)]

    m_stripe_charge = mocker.patch('pinax.stripe.models.Charge.stripe_charge')
    if error == 'charge_already_refunded':
        m_stripe_charge.refund.side_effect = stripe.error.InvalidRequestError(
                    message='Charge ch_foo has already been refunded.',
                    param=None,
                    code='charge_already_refunded')
    else:
        m_stripe_charge.refund.side_effect = Exception('custom_exc')

    def new_charge(*args, **kwargs):
        return Charge.objects.create(amount=kwargs['amount'])
    charges_create = mocker.patch('pinax.stripe.actions.charges.create',
                                  side_effect=new_charge)
    charge_stripe_id = rental_session.charge.stripe_id
    active_requests_mock.post(
        f'https://api.stripe.com/v1/charges/{charge_stripe_id}/refund',
        exc=stripe.error.InvalidRequestError(
            message='Charge ch_foo has already been refunded.',
            param=None,
            code='charge_already_refunded'))

    # Call the Celery task now.
    generate_payment(rental_session.pk)

    assert charges_create.call_args_list == [
        call(amount=Decimal('3'),
             capture=True,
             currency='eur',
             customer=customer,
             idempotency_key=f'replace-{rental_session.uuid}',
             send_receipt=False)]

    rental_session.refresh_from_db()
    assert rental_session.payment_state == 'processed'
    assert rental_session.cents == 300
    assert rental_session.currency == 'eur'
    assert rental_session.charge.amount == Decimal('3')

    if error == 'charge_already_refunded':
        assert caplog.record_tuples[-1] == (
            'velodrome.lock8.models', 20,
            'process_payment: charge was already refunded')
    else:
        assert caplog.record_tuples[-1] == (
            'velodrome.lock8.models', 40,
            'process_payment: error when refunding charge: custom_exc')


@pytest.mark.parametrize('param', ('subscription_plan',
                                   'subscription_plan_with_pricing_scheme'))
def test_price_computation_when_returning_bicycle_with_subscription_plan(
        param, request, fleet_operator, org, bicycle_available, renter, owner,
        customer, subscription):
    subscription_plan = request.getfixturevalue(param)
    bicycle = bicycle_available

    bicycle.rent(by=renter, subscription_plan=subscription_plan)
    assert bicycle.active_rental_session.subscription_plan == subscription_plan
    assert bicycle.active_rental_session.pricing_scheme is None

    duration = timedelta(minutes=15)
    with freeze_time(timezone.now() + duration):
        bicycle.return_(by=renter)

    rental_session = bicycle.rental_sessions.get()
    assert (int(rental_session.duration.total_seconds()) ==
            int(duration.total_seconds()))
    assert rental_session.cents == 0


@pytest.mark.parametrize('param', ('pricing_scheme',
                                   'subscription_plan_with_pricing_scheme'))
def test_price_computation_rollback_with_non_captured_charge(
        param, request, settings, caplog, mocker, bicycle_available, renter,
        customer, commit_success):
    from velodrome.celery import generate_payment

    bicycle = bicycle_available

    if param == 'pricing_scheme':
        pricing_scheme = request.getfixturevalue('pricing_scheme')
        subscription_plan = None
        request.getfixturevalue('customer_chargable')
        charges_capture = mocker.patch('pinax.stripe.actions.charges.capture')

        bicycle.rent(by=renter, pricing_scheme=pricing_scheme)
    else:
        pricing_scheme = None
        subscription_plan = request.getfixturevalue(
            'subscription_plan_with_pricing_scheme')
        request.getfixturevalue('subscription')

        bicycle.rent(by=renter, pricing_scheme=pricing_scheme)

    rental_session = bicycle.active_rental_session
    assert rental_session.subscription_plan == subscription_plan
    assert rental_session.pricing_scheme == pricing_scheme

    m_generate_payment_task = mocker.patch.object(generate_payment, 'delay')

    hours = 5
    with freeze_time(timezone.now() + timedelta(hours=hours)):
        bicycle.return_(by=renter)

    commit_success()
    assert m_generate_payment_task.call_args_list == [
        mocker.mock_module.call(rental_session.pk)]

    rental_session = bicycle.rental_sessions.get()
    assert (int(rental_session.duration.total_seconds()) ==
            int(timedelta(hours=hours).total_seconds()))
    assert rental_session.cents == hours * 100
    assert rental_session.currency == 'eur'
    assert rental_session.payment_state == 'pending'
    # Call the Celery task now.
    mocker.patch('pinax.stripe.actions.charges.create',
                 side_effect=Exception('exc_side_effect'))
    with pytest.raises(Exception) as excinfo:
        generate_payment(rental_session.pk)
    assert excinfo.value.args[0] == 'exc_side_effect'

    assert rental_session.payment_state == 'pending'
    assert rental_session.state == 'closed'

    errors = [r.message for r in caplog.records if r.levelname == 'ERROR']
    if param == 'pricing_scheme':
        assert rental_session.charge.amount == 2  # for two hours
        assert rental_session.charge.captured is False

        assert errors == [
            'Failed to create new charge, capturing existing one.']

        call = mocker.mock_module.call
        assert charges_capture.call_args_list == [call(rental_session.charge)]
    else:
        assert errors == ['process_payment: failed to create charge.']


def test_can_not_rent_if_subscription_plan_and_prcing_scheme_are_given(
        org, owner, bicycle, alice, fleet_operator, customer,
        stripe_plan_detail, active_requests_mock):
    from velodrome.lock8.models import (
        Affiliation,
        PricingScheme,
        SubscriptionPlan,
    )
    Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.RENTER,
    )

    description = {'en': {
        'title': 'title',
        'description': 'description',
        'fine_print': 'fine_print',
        'short_description': 'short_description',
    }}
    pricing_scheme = PricingScheme.objects.create(
        organization=org,
        owner=owner,
        name='Pricing scheme',
        time_ranges=((0, None, 100, False, 0),),
        description=description,
    )
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
        pricing_scheme=pricing_scheme,
        name='weekday plan',
        interval=SubscriptionPlan.WEEK,
        cents=500,
        trial_period_days=0,
        description=description,
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

    bicycle.declare_available(by=fleet_operator)
    with pytest.raises(ValidationError) as e:
        bicycle.rent(by=alice,
                     subscription_plan=subscription_plan,
                     pricing_scheme=pricing_scheme,
                     )
    assert ('subscription_plan and pricing_scheme are mutually exclusive.'
            in str(e.value))


def test_can_not_rent_if_no_choice_is_made(org, owner, bicycle, alice,
                                           fleet_operator, customer,
                                           stripe_plan_detail,
                                           active_requests_mock):
    from velodrome.lock8.models import (
        Affiliation,
        SubscriptionPlan,
    )
    Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.RENTER,
    )

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
        trial_period_days=0,
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
    subscription_plan = SubscriptionPlan.objects.create(
        owner=owner,
        organization=org,
        name='weekday plan 2',
        interval=SubscriptionPlan.WEEK,
        cents=1000,
        trial_period_days=0,
    )
    subscription_plan.provision()
    subscription_plan.refresh_from_db()
    Subscription.objects.create(
        stripe_id='fake2',
        customer=customer,
        plan=subscription_plan.plan,
        quantity=1,
        start=timezone.now(),
        status='active',
    )
    bicycle.declare_available(by=fleet_operator)

    with pytest.raises(ValidationError) as e:
        bicycle.rent(by=alice)
    assert 'A pricing needs to be chosen by the renter' in str(e.value)


def test_rent_choose_pricing_scheme(
        bicycle_available, renter, pricing_scheme, customer_chargable):
    bicycle = bicycle_available
    bicycle.rent(by=renter)
    assert bicycle.active_rental_session.pricing_scheme == pricing_scheme


def test_rent_errors(request, bicycle_available, renter, pricing_scheme,
                     customer_json, active_requests_mock):
    bicycle = bicycle_available

    with pytest.raises(ValidationError) as e:
        bicycle.rent(by=renter)
    assert (e.value.code, e.value.message) == (
        'user_has_no_customer', 'The user has no customer.')

    request.getfixturevalue('customer')
    active_requests_mock.get(
        'https://api.stripe.com/v1/customers/cus_7UkUzpBtATnab9',
        json=customer_json)
    active_requests_mock.get(
        'https://api.stripe.com/v1/customers/cus_7UkUzpBtATnab9/sources',
        json={'object': 'list', 'data': [], 'has_more': False,
              'url': '/v1/customers/cus_7UkUzpBtATnab9/sources'})

    def charges_json(request, context):
        # A non-captured charge for 200 cents is created (2 hours).
        assert request.text == (
            'amount=200&currency=eur'
            '&customer=cus_7UkUzpBtATnab9&capture=False')

        return {'error': {
            'code': 'missing',
            'message': 'Cannot charge a customer that has no active card',
            'param': 'card',
            'type': 'card_error'}}
    active_requests_mock.post('https://api.stripe.com/v1/charges',
                              status_code=status.HTTP_402_PAYMENT_REQUIRED,
                              json=charges_json)

    with pytest.raises(ValidationError) as e:
        bicycle.rent(by=renter)
    assert (e.value.code, e.value.message) == (
        'user_has_no_cards', 'The user has no payment method configured.')

    # Test declined card.
    active_requests_mock.post(
        'https://api.stripe.com/v1/charges',
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        json={'error': {
            'charge': 'ch_1BLXDNEWnIuOzoofE1xzJazX',
            'code': 'card_declined',
            'decline_code': 'generic_decline',
            'message': 'Your card was declined.',
            'type': 'card_error'}})
    with pytest.raises(ValidationError) as e:
        bicycle.rent(by=renter)
    assert (e.value.code, e.value.message) == (
        'user_card_declined',
        'Your card was declined.')

    # Test declined card with insufficient funds.
    active_requests_mock.post(
        'https://api.stripe.com/v1/charges',
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        json={'error': {
            'charge': 'ch_1C4byFEsFcHZcT2DPhw2caso',
            'code': 'card_declined',
            'decline_code': 'insufficient_funds',
            'message': 'Your card has insufficient funds.',
            'type': 'card_error'}})
    with pytest.raises(ValidationError) as e:
        bicycle.rent(by=renter)
    assert (e.value.code, e.value.message) == (
        'user_card_insufficient_funds',
        'The card has insufficient funds.')

    # Test generic card error.
    active_requests_mock.post(
        'https://api.stripe.com/v1/charges',
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        json={'error': {
            'charge': 'ch_1C4byFEsFcHZcT2DPhw2caso',
            'code': 'customcode',
            'decline_code': 'something_generic',
            'message': 'Something generic.',
            'type': 'card_error'}})
    with pytest.raises(ValidationError) as e:
        bicycle.rent(by=renter)
    assert (e.value.code, e.value.message) == (
        'user_card_error',
        'There was a card-related error: Something generic. (code=customcode)')

    # Test generic StripeError.
    stripe_msg = 'Some generic non-card stripe error.'
    active_requests_mock.post(
        'https://api.stripe.com/v1/charges',
        status_code=status.HTTP_400_BAD_REQUEST,
        json={'error': {
            'message': stripe_msg,
            'code': 'generic_code'}})
    with pytest.raises(ValidationError) as e:
        bicycle.rent(by=renter)
    assert (e.value.code, e.value.message) == (
        'user_cannot_be_charged',
        f'Could not create non-captured charge for customer: {stripe_msg}.')


def test_rent_choose_subscription_plan(org, owner, bicycle, alice,
                                       fleet_operator, customer,
                                       alice_card, stripe_plan_detail,
                                       active_requests_mock):
    from velodrome.lock8.models import (
        Affiliation,
        SubscriptionPlan,
    )
    Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.RENTER,
    )

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
        cents=1000,
        trial_period_days=0,
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
    bicycle.declare_available(by=fleet_operator)

    bicycle.rent(by=alice)
    assert bicycle.active_rental_session.subscription_plan == subscription_plan


def test_account_deauthorized(org, subscription_plan, pricing_scheme, mocker):
    event = mocker.Mock()
    event.stripe_account = org.stripe_account
    WEBHOOK_SIGNALS['account.application.deauthorized'].send(sender=None,
                                                             event=event)

    subscription_plan.refresh_from_db()
    pricing_scheme.refresh_from_db()
    assert subscription_plan.state == 'decommissioned'
    assert pricing_scheme.state == 'decommissioned'


def test_get_stripe_ephemeralkey_base(
        mocker, active_requests_mock, alice, customer, org):
    from stripe.error import InvalidRequestError
    from django.core.exceptions import ValidationError

    exc = Exception('custom_exception')
    mocker.patch('stripe.EphemeralKey.create', side_effect=exc)
    with pytest.raises(Exception) as excinfo:
        alice.get_stripe_ephemeralkey(stripe_api_version='2017-08-15',
                                      organization=org)
    assert excinfo.value is exc

    exc = InvalidRequestError(message='Invalid Stripe API version: invalid',
                              param=None)
    mocker.patch('stripe.EphemeralKey.create', side_effect=exc)
    with pytest.raises(ValidationError) as excinfo:
        alice.get_stripe_ephemeralkey(stripe_api_version='mocked',
                                      organization=org)
    assert excinfo.value.message_dict == {
        'stripe_api_version': ['Invalid Stripe API version: invalid']}

    exc = InvalidRequestError(message='Something completely different',
                              param=None)
    mocker.patch('stripe.EphemeralKey.create', side_effect=exc)
    with pytest.raises(InvalidRequestError) as excinfo:
        alice.get_stripe_ephemeralkey(stripe_api_version='mocked',
                                      organization=org)
    assert excinfo.value is exc


def test_get_stripe_ephemeralkey_recreates_missing_customer(
        mocker, active_requests_mock, alice, customer, customer_json, org):
    def response_cb(request, context):
        assert request.headers['Stripe-Account'] == 'acc_org'
        assert request.headers['Stripe-Version'] == 'mocked'

        if request.text == 'customer=cus_anewone':
            context.status_code = 200
            return {
                'associated_objects': [{
                    'id': 'cus_anewone',
                    'type': 'customer'
                }],
                'created': 1504109163,
                'expires': 1504112763,
                'id': 'ephkey_1AwYhbEWnIuOzoofdZzn3BS7',
                'livemode': False,
                'object': 'ephemeral_key',
                'secret': 'ek_test_secret',
            }
        context.status_code = 400
        return {'error': {
            'message': 'No such customer: %s' % customer.stripe_id,
            'type': 'invalid_request_error',
            'param': 'customer'}}

    active_requests_mock.post('https://api.stripe.com/v1/ephemeral_keys',
                              json=response_cb)

    customer_json['id'] = 'cus_anewone'
    active_requests_mock.post('https://api.stripe.com/v1/customers',
                              json=customer_json)

    alice.get_stripe_ephemeralkey(stripe_api_version='mocked',
                                  organization=org)
    assert alice.user_accounts.get().customer.stripe_id == 'cus_anewone'


def test_plan_pass_repr(subscription_plan, alice):
    from velodrome.lock8.models import PlanPass

    plan_pass = PlanPass.objects.create(user=alice,
                                        subscription_plan=subscription_plan)

    user = repr(alice)
    subscription_plan = repr(subscription_plan)
    assert repr(plan_pass) == (f'PlanPass(pk={plan_pass.pk}, user={user}, '
                               f'subscription_plan={subscription_plan})')


def test_plan_pass_validation(renter, subscription_plan, another_renter):
    from velodrome.lock8.models import PlanPass

    plan_pass = PlanPass(user=renter)
    plan_pass.clean()

    plan_pass = PlanPass(subscription_plan=subscription_plan)
    plan_pass.clean()

    plan_pass = PlanPass(user=another_renter,
                         subscription_plan=subscription_plan)
    with pytest.raises(ValidationError):
        plan_pass.clean()

    subscription_plan.decommission()
    plan_pass = PlanPass(user=renter, subscription_plan=subscription_plan)
    with pytest.raises(ValidationError):
        plan_pass.clean()


def test_provision_org_wo_payments(org, owner):
    from velodrome.lock8.models import PricingScheme, SubscriptionPlan
    org.stripe_account = None
    org.save()

    subscription_plan = SubscriptionPlan.objects.create(
        owner=owner,
        organization=org,
        name='plan',
        interval=SubscriptionPlan.WEEK,
        cents=500,
        trial_period_days=0,
    )
    pricing_scheme = PricingScheme.objects.create(
        name='ps',
        organization=org,
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

    with pytest.raises(ValidationError):
        subscription_plan.provision()
    with pytest.raises(ValidationError):
        pricing_scheme.provision()


@pytest.mark.parametrize('tax_percent', (None, Decimal('12.34')))
def test_subscribe_user_with_tax(tax_percent, mocker, subscription_plan, org,
                                 organization_preference, renter, customer):
    from pinax.stripe.models import Subscription

    organization_preference.tax_percent = tax_percent
    organization_preference.save()

    p_get = mocker.patch('pinax.stripe.models.Subscription.objects.get',
                         side_effect=Subscription.DoesNotExist)
    p_sync = mocker.patch('pinax.stripe.actions.subscriptions.sync_subscription_from_stripe_data')  # noqa: E501
    p_unsub = mocker.patch.object(subscription_plan, 'unsubscribe_user')
    m = mocker.patch('stripe.Subscription.create')

    subscription_plan.subscribe_user(renter, 'stripe_source')

    assert len(m.call_args_list) == 1
    assert m.call_args_list[0][1]['tax_percent'] == tax_percent

    assert p_get.call_count == 1
    assert p_sync.call_count == 1
    assert p_unsub.call_count == 1
