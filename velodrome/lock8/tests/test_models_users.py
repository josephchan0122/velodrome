import datetime as dt
import itertools
import json
import urllib.parse

from django.contrib.auth.tokens import default_token_generator
from django.core.exceptions import ValidationError
from django.utils import timezone
from django_redis import get_redis_connection
from freezegun import freeze_time
from pinax.stripe.models import Customer
import pytest
from social_django.models import UserSocialAuth


def test_user_model(owner):
    from velodrome.lock8.models import User

    user = User.objects.create(
        first_name='Alice',
        last_name='Cooper',
        username='a' * 254,
        email='alice@example.com',
        avatar='https://example.com',
        password='b',
        owner=owner,
    )
    assert user.username == 'a' * 254
    assert user.email == 'alice@example.com'
    assert user.avatar == 'https://example.com'
    assert user.display_name == 'Alice Cooper'
    assert user.admin_list_name == 'Alice Cooper'

    user.disable()
    assert user.state == 'disabled'

    user.enable()
    assert user.state == 'new'
    assert user.transitions.all().count() == 2

    with pytest.raises(Customer.DoesNotExist):
        user.customers.get()


def test_user_queryset_local_user(alice, org):
    from velodrome.lock8.models import User
    assert User.objects.filter_local_users(pk=alice.pk).exists()
    assert not User.objects.filter_local_whitelabel_users(org, pk=alice.pk).exists()  # noqa: E501
    assert not User.objects.filter_social_users(pk=alice.pk).exists()
    assert not User.objects.filter_social_whitelabel_users(org, pk=alice.pk).exists()  # noqa: E501


def test_user_queryset_local_whitelabel_user(renter, org):
    from velodrome.lock8.models import User
    alice = renter
    alice.organization = org
    alice.save()
    assert not User.objects.filter_local_users(pk=alice.pk).exists()
    assert User.objects.filter_local_whitelabel_users(org, pk=alice.pk).exists()  # noqa: E501
    assert not User.objects.filter_social_users(pk=alice.pk).exists()
    assert not User.objects.filter_social_whitelabel_users(org, pk=alice.pk).exists()  # noqa: E501


def test_user_queryset_social_user(alice, org):
    from velodrome.lock8.models import User
    UserSocialAuth.objects.create(user=alice)

    assert not User.objects.filter_local_users(pk=alice.pk).exists()
    assert not User.objects.filter_local_whitelabel_users(org, pk=alice.pk).exists()  # noqa: E501
    assert User.objects.filter_social_users(pk=alice.pk).exists()
    assert not User.objects.filter_social_whitelabel_users(org, pk=alice.pk).exists()  # noqa: E501


def test_user_queryset_social_whitelabel_user(renter, org):
    from velodrome.lock8.models import User
    alice = renter
    alice.organization = org
    alice.save()
    UserSocialAuth.objects.create(user=alice)

    assert not User.objects.filter_local_users(pk=alice.pk).exists()
    assert not User.objects.filter_local_whitelabel_users(org, pk=alice.pk).exists()  # noqa: E501
    assert not User.objects.filter_social_users(pk=alice.pk).exists()
    assert User.objects.filter_social_whitelabel_users(org, pk=alice.pk).exists()  # noqa: E501


@pytest.mark.uses_payments
def test_user_customer(alice, customer_json, active_requests_mock, org,
                       organization_preference):
    from velodrome.lock8.models import Affiliation

    with pytest.raises(Customer.DoesNotExist):
        alice.customers.get()
    active_requests_mock.post('https://api.stripe.com/v1/customers',
                              json=customer_json)
    Affiliation.objects.create(user=alice,
                               organization=org,
                               role=Affiliation.RENTER)
    pk = alice.get_customer(org).pk
    Affiliation.objects.create(user=alice,
                               organization=org,
                               role=Affiliation.FLEET_OPERATOR)
    assert alice.get_customer(org).pk == pk


def test_user_display_name_from_username():
    from velodrome.lock8.models import User
    user = User(username='username-1',
                email='alice@example.com')
    assert user.display_name == 'username'
    user.username = '0'
    assert user.display_name == '0'
    assert user.admin_list_name == '0'

    user.first_name = '0'
    assert user.display_name == '0'
    user.first_name = 'Alice'
    assert user.display_name == 'Alice'

    user.last_name = 'Cooper'
    assert user.display_name == 'Alice Cooper'
    user.first_name = user.last_name = '0'
    assert user.display_name == '0 0'


def test_user_display_name_from_email(non_matching_uuid):
    from velodrome.lock8.models import User

    email = 'alice@example.com'
    user = User(email=email)
    assert user.display_name == email
    assert user.admin_list_name == email


def test_user_display_name_from_social(db, social_provider,
                                       non_matching_uuid):
    from velodrome.lock8.models import User

    user = User.objects.create(
        username='username-12',
        email='alice@example.com'
    )

    UserSocialAuth.create_social_auth(user, non_matching_uuid,
                                      social_provider)
    assert user.display_name == 'username-12'


def test_user_fallbacks(db):
    from velodrome.lock8.models import User

    user = User.objects.create()
    assert user.__str__() == f"{user.uuid} (member of '')"
    assert user.display_name == f'{user.uuid}'
    assert user.admin_list_name == f'#{user.pk}'


def test_user_profile_model(alice, owner):
    from velodrome.lock8.models import UserProfile

    user_profile = UserProfile.objects.create(
        owner=owner,
        phone_numbers={'mobile': 'whatever 10928102983'},
    )

    assert user_profile.owner == owner
    assert user_profile.phone_numbers == {'mobile': 'whatever 10928102983'}


def test_user_get_organizations_helpers(org, fleet_operator, alice, owner,
                                        admin_user, root_org):
    from velodrome.lock8.models import Affiliation, Organization

    affiliation = Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER,
    )

    sub_org = Organization.objects.create(
        owner=owner,
        name='sub',
        parent=org,
    )
    assert list(admin_user
                .get_organizations()
                .all()) == [root_org]
    assert (list(admin_user
                 .get_descendants_organizations()
                 .all()) == [root_org, org, sub_org])
    assert (list(admin_user
                 .get_descendants_managed_organizations()
                 .all()) == [root_org, org, sub_org])

    assert list(fleet_operator
                .get_organizations()
                .all()) == [org]
    assert (list(fleet_operator
                 .get_descendants_organizations()
                 .all()) == [org, sub_org])
    assert (list(fleet_operator
                 .get_descendants_managed_organizations()
                 .all()) == [org, sub_org])

    assert list(alice
                .get_organizations()
                .all()) == [org]
    assert list(alice.
                get_descendants_organizations()
                .all()) == [org, sub_org]
    assert not (alice
                .get_descendants_managed_organizations()
                .all().exists())

    affiliation.delete()

    Affiliation.objects.create(
        user=alice,
        organization=sub_org,
        role=Affiliation.RENTER,
    )
    assert list(alice
                .get_organizations()
                .all()) == [sub_org]
    assert list(alice
                .get_descendants_organizations()
                .all()) == [sub_org]
    assert not (alice
                .get_descendants_managed_organizations()
                .all().exists())

    Affiliation.objects.create(
        user=alice,
        organization=root_org,
        role=Affiliation.RENTER,
    )
    assert list(alice
                .get_organizations()
                .all()) == [root_org, sub_org]
    assert list(alice
                .get_descendants_organizations()
                .all()) == [root_org, org, sub_org]
    assert not (alice
                .get_descendants_managed_organizations()
                .all().exists())


def test_invitation_provisioned(org, owner, alice, settings, fleet_operator):
    from velodrome.lock8.models import Invitation

    invitation = Invitation.objects.create(
        organization=org,
        email=alice.email,
        owner=owner,
    )

    assert invitation.organization == org
    assert invitation.email == 'alice@example.com'
    assert invitation.owner == owner
    assert invitation.state == 'new'

    invitation.provision(by=fleet_operator)

    invitation.confirm(by=alice)

    assert invitation.state == 'confirmed'

    assert list(alice.get_organizations()) == [org]


def test_resend_invitation(org, owner, alice, settings, fleet_operator):
    from velodrome.lock8.models import Invitation

    invitation = Invitation.objects.create(
        organization=org,
        email=alice.email,
        owner=owner,
    )

    assert invitation.organization == org
    assert invitation.email == 'alice@example.com'
    assert invitation.owner == owner
    assert invitation.state == 'new'

    invitation.provision(by=fleet_operator)
    assert invitation.state == 'provisioned'

    invitation.resend(by=fleet_operator)
    assert invitation.state == 'provisioned'


def test_invitation_declined(org, owner, alice, settings, fleet_operator):
    from velodrome.lock8.models import Invitation

    invitation = Invitation.objects.create(
        organization=org,
        email=alice.email,
        owner=owner,
    )

    invitation.provision(by=fleet_operator)
    invitation.decline(by=alice)

    assert invitation.state == 'declined'
    assert not alice.get_organizations().exists()


def test_invitation_confirmed(org, owner, alice, settings, fleet_operator):
    from velodrome.lock8.models import Invitation

    invitation = Invitation.objects.create(
        organization=org,
        email=alice.email,
        owner=owner,
    )

    invitation.provision(by=fleet_operator)
    invitation.confirm(by=alice)

    assert invitation.state == 'confirmed'
    assert alice.get_organizations().exists()

    invitation = Invitation.objects.create(
        organization=org,
        email=alice.email,
        owner=owner,
    )

    invitation.provision(by=fleet_operator)
    invitation.confirm(by=alice)
    assert invitation.state == 'confirmed'


@pytest.mark.parametrize('role', ['renter', 'fleet_operator'])
def test_invitation_confirmed_with_whitelabel_org(
        org, owner, alice, fleet_operator, role):
    from velodrome.lock8.models import Affiliation, Invitation
    org.is_whitelabel = True
    org.save()

    invitation = Invitation.objects.create(
        organization=org,
        email=alice.email,
        owner=owner,
        role=role,
    )

    invitation.provision(by=fleet_operator)
    invitation.confirm(by=alice)

    assert invitation.state == 'confirmed'
    assert alice.get_organizations().exists()
    alice.refresh_from_db()
    if role == Affiliation.RENTER:
        assert alice.organization == org
    else:
        assert alice.organization is None


def test_invitation_confirmed_by_admin_with_whitelabel_org(
        org, owner, alice, fleet_operator):
    from velodrome.lock8.models import Affiliation, Invitation
    org.is_whitelabel = True
    org.save()

    Affiliation.objects.create(organization=org,
                               role=Affiliation.FLEET_OPERATOR,
                               user=alice)
    invitation = Invitation.objects.create(
        organization=org,
        email=alice.email,
        owner=owner,
        role=Affiliation.RENTER,
    )

    invitation.provision(by=fleet_operator)
    with pytest.raises(ValidationError) as error:
        invitation.confirm(by=alice)
    assert error.value.code == 'user_organization_mismatch'
    assert (str(error.value.message) == 'You cannot be invited as a renter to'
            ' this fleet with this account. You must accept this invitation'
            ' from another account.')


def test_affiliation_deletion_cancel_invitation(org, owner, alice):
    from velodrome.lock8.models import Affiliation, Invitation

    affiliation = Affiliation.objects.create(user=alice,
                                             organization=org)
    invitation = Invitation.objects.create(organization=org,
                                           email=alice.email,
                                           owner=owner)
    invitation.provision()

    affiliation.delete()

    invitation.refresh_from_db()
    assert invitation.state == 'cancelled'


@pytest.mark.parametrize('with_user, as_renter', [
    *itertools.product((True, False), (True, False))])
def test_invitation_signup_flag(with_user, request, owner, org, settings,
                                mailoutbox, as_renter):
    from velodrome.lock8.models import Affiliation, Invitation

    if with_user:
        request.getfixturevalue('alice')

    invitation = Invitation.objects.create(
        organization=org,
        email='alice@example.com',
        owner=owner,
        role=Affiliation.RENTER if as_renter else Affiliation.FLEET_OPERATOR
    )

    invitation.provision()

    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.subject == ('Noa - Invitation to join the'
                             ' organization {}.'.format(org.name))

    if as_renter:
        assert settings.FRONTEND_INVITATION_URL in email.body
    else:
        assert settings.FRONTEND_URL in email.body
    assert urllib.parse.urlencode(
        {'signup': 0 if with_user else 1}) in email.body


def test_is_admin_of_lock8_annotation(admin_user, fleet_operator, root_org,
                                      renter):
    from velodrome.lock8.models import Affiliation, User

    assert (User.objects.annotate_with_is_admin_of_lock8()
            .filter(is_admin_of_lock8=True,
                    pk=admin_user.pk).exists())

    assert (User.objects.annotate_with_is_admin_of_lock8()
            .filter(is_admin_of_lock8=False,
                    pk=fleet_operator.pk).exists())

    assert (User.objects.annotate_with_is_admin_of_lock8()
            .filter(is_admin_of_lock8=False,
                    pk=renter.pk).exists())

    Affiliation.objects.create(role=Affiliation.FLEET_OPERATOR,
                               user=admin_user,
                               organization=root_org)

    assert (User.objects.annotate_with_is_admin_of_lock8()
            .filter(is_admin_of_lock8=True,
                    pk=admin_user.pk).exists())
    renter.is_superuser = True
    renter.save()
    assert (User.objects.annotate_with_is_admin_of_lock8()
            .filter(is_admin_of_lock8=True,
                    pk=renter.pk).exists())


def test_with_trigram_annotation(alice):
    from velodrome.lock8.models import User

    assert (User.objects.annotate_with_trigram('first_name', term='')
            .filter(pk=alice.pk).exists())


@pytest.mark.django_db
def test_user_manager_get_by_natural_key():
    from velodrome.lock8.models import User

    with pytest.raises(User.DoesNotExist):
        User._default_manager.get_by_natural_key('doesnotexists')


def test_default_token_generator_hash_on_user_modified(alice):
    token = default_token_generator.make_token(alice)
    with freeze_time(timezone.now() + dt.timedelta(minutes=1)):
        alice.save()
    new_token = default_token_generator.make_token(alice)
    assert token != new_token


def test_default_token_generator_hash_on_user_login(alice):
    assert alice.last_login is None
    token = default_token_generator.make_token(alice)
    alice.last_login = timezone.now() - dt.timedelta(minutes=1)
    alice.update_modified = False
    alice.save()
    new_token = default_token_generator.make_token(alice)
    assert token != new_token


def test_invitation_confirmation_with_preferernce(
        organization_preference, org, owner, alice):
    from velodrome.lock8.models import Invitation
    organization_preference.email_domain_validation = 'example.org'
    organization_preference.save()
    alice.email = 'alice@example.org'
    alice.save()

    invitation = Invitation.objects.create(
        owner=owner,
        organization=org,
        email='alice@example.org',
    )
    invitation.provision()
    invitation.confirm(by=alice)


def test_accept_terms_of_service(renter, terms_of_service,
                                 terms_of_service_version):
    with pytest.raises(ValidationError):
        renter.accept_terms_of_service(terms_of_service)

    terms_of_service.version = terms_of_service_version
    terms_of_service.provision()
    terms_of_service_version.provision()

    renter.accept_terms_of_service(terms_of_service)

    accepted_tos = renter.terms_of_services.all()
    assert len(accepted_tos) == 1
    assert accepted_tos[0] == terms_of_service


def test_user_publish_activated_event(alice, commit_success):
    redis = get_redis_connection('publisher')

    pubsub = redis.pubsub()
    channel = f'/activation/{alice.email}'
    pubsub.subscribe(channel)
    message = pubsub.get_message()
    assert message == {'channel': channel.encode('utf-8'),
                       'data': 1,
                       'pattern': None,
                       'type': 'subscribe'}
    alice.publish_activated_event()
    commit_success()

    message = pubsub.get_message()
    assert sorted(list(message.keys())) == ['channel', 'data',
                                            'pattern', 'type']
    assert message['channel'] == channel.encode('utf-8')
    assert message['pattern'] is None
    assert message['type'] == 'message'

    assert json.loads(message['data'].decode('utf-8')) == {
        'topic': channel,
        'sender': 'user',
        'message': {'is_active': True}}


@pytest.mark.uses_payments
def test_user_transfer_failed_payments(caplog, renter, customer):
    assert renter.transfer_failed_payments(customer, 'card', debt={}) is True
    assert renter.transfer_failed_payments(customer, 'card', debt={
        'eur': [49, []]
    }) is True
    assert caplog.record_tuples == [(
        'velodrome.lock8.models', 20,
        'transfer_failed_payments: skipping for amount of less than 50 cents (49)')]  # noqa: E501


@pytest.mark.uses_payments
def test_user_retry_failed_payments(
        mocker, bicycle_available, unpaid_rentalsession, customer_chargable,
        org
):
    import stripe

    user = unpaid_rentalsession.user

    debt = user.get_debt_for_rentals()
    assert debt == (
        {'eur': [99, [unpaid_rentalsession]]},
        True
    )

    assert user.retry_failed_payments(org, {}) is True

    # Fails with no chargable sources.
    assert user.retry_failed_payments(org) is False

    # Mock sources for customer.
    sources = stripe.api_resources.list_object.ListObject()
    sources.update({
        'data': [
            stripe.Source.construct_from({
                'id': 'src_1D7q8PEsFcHZcT2D2VKn2Ag8',
                'status': 'chargeable',
                'type': 'card',
                'usage': 'reusable'
            }, 'stripe_api_key'),
        ]})
    customer_with_sources = user.customers.first()

    mocker.patch.object(customer_with_sources.stripe_customer, 'sources',
                        sources)
    mocker.patch.object(user, 'get_customer',
                        return_value=customer_with_sources)

    charges_capture = mocker.patch('pinax.stripe.actions.charges.capture')
    assert user.retry_failed_payments(org) is True
    assert charges_capture.call_count == 1
