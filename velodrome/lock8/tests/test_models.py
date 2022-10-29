import datetime as dt
import textwrap

from concurrency.exceptions import RecordModifiedError
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import ValidationError
from django.db import connection
from psycopg2.extras import NumericRange
import pytest
import reversion.revisions


def test_organization_model(owner, root_org):
    from velodrome.lock8.models import Organization

    org = Organization.objects.create(name='Org', parent=root_org, owner=owner)
    assert org.name == 'Org'
    assert org.owner == owner
    assert not org.is_open_fleet
    assert not org.is_whitelabel
    assert org.app_download_url is None
    assert not org.user_email_logo
    assert org.image is not None
    assert org.phone_numbers == {}

    org.phone_numbers = {'Emergency': '01-234-345-345'}
    org.allowed_signup_domain_names = ['google.com']
    org.save()

    assert org.phone_numbers == {'Emergency': '01-234-345-345'}
    assert org.allowed_signup_domain_names == ['google.com']
    assert org.stripe_publishable_key is None


def test_organization_get_root_org(owner, request):
    from velodrome.lock8.models import Organization

    try:
        del Organization._root_org
    except AttributeError:  # pragma: no cover
        pass

    Organization.objects.all().delete()

    with pytest.raises(Organization.DoesNotExist):
        Organization.get_root_org()

    another_root_org = Organization.objects.create(name='Another root',
                                                   owner=owner, parent=None)
    assert Organization.get_root_org() == another_root_org


def test_organization_get_preference(owner, org, root_org):
    from velodrome.lock8.models import OrganizationPreference
    default = object()
    root_org.active_preference.delete()

    assert org.get_preference('allow_returning_bicycle_outside_drop_zone',
                              default=default) is default
    assert org.get_preference('currency') == ''
    with pytest.raises(AttributeError):
        assert org.get_preference('name')
    with pytest.raises(AttributeError):
        assert org.get_preference('nonexistingpref')

    OrganizationPreference.objects.create(
        owner=owner,
        organization=org,
        allow_returning_bicycle_outside_drop_zone=True,
        currency='usd',
    )
    assert org.get_preference('allow_returning_bicycle_outside_drop_zone',
                              default=default) is True
    assert org.get_preference(
        'allow_returning_bicycle_outside_drop_zone') is True


def test_organization_get_active_preference(owner, org, root_org):
    from velodrome.lock8.models import OrganizationPreference

    preference = root_org.active_preference
    preference.allow_returning_bicycle_outside_drop_zone = True
    preference.currency = 'usd'
    preference.save()

    with pytest.raises(OrganizationPreference.DoesNotExist):
        org.preference
    assert org.active_preference == root_org.preference
    assert org.get_preference('currency') == 'usd'

    new_pref = OrganizationPreference.objects.create(
        owner=owner,
        organization=org,
        allow_returning_bicycle_outside_drop_zone=True,
        currency='eur',
    )
    assert org.preference == new_pref
    assert org.active_preference == new_pref
    assert org.get_preference('currency') == 'eur'


def test_affiliation_model(org, alice):
    from velodrome.lock8.models import Affiliation

    affiliation = Affiliation.objects.create(organization=org,
                                             user=alice,
                                             )
    assert affiliation.organization == org
    assert affiliation.user == alice
    assert affiliation.role == Affiliation.RENTER


def test_affiliation_model_validation(org, alice, another_org):
    from velodrome.lock8.models import Affiliation

    affiliation = Affiliation.objects.create(organization=org,
                                             user=alice,
                                             )
    alice.organization = another_org
    with pytest.raises(ValidationError):
        affiliation.full_clean()

    affiliation = Affiliation(organization=org)
    affiliation.clean()


def test_affiliation_mechanic_role_exists(mechanic1):
    from velodrome.lock8.models import Affiliation
    affiliation = Affiliation.objects.get(user=mechanic1)
    assert affiliation.role == Affiliation.MECHANIC


def test_affiliation_security_role_exists(security1):
    from velodrome.lock8.models import Affiliation
    affiliation = Affiliation.objects.get(user=security1)
    assert affiliation.role == Affiliation.SECURITY


def test_delete_affiliation_close_reservation(org, alice, bicycle,
                                              fleet_operator):
    from velodrome.lock8.models import Affiliation

    affiliation_renter = Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.RENTER,
    )
    affiliation_admin = Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.ADMIN,
    )
    bicycle.declare_available(by=fleet_operator)

    bicycle.reserve(by=alice)

    affiliation_admin.delete()

    assert alice.active_reservation is not None

    affiliation_renter.delete()

    assert alice.active_reservation is None


def test_delete_affiliation_close_rental_session(org, alice, bicycle,
                                                 fleet_operator):
    from velodrome.lock8.models import Affiliation

    affiliation_renter = Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.RENTER,
    )
    affiliation_admin = Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.ADMIN,
    )
    bicycle.declare_available(by=fleet_operator)

    bicycle.reserve(by=alice)
    bicycle.rent(by=alice)

    affiliation_admin.delete()

    assert alice.active_rental_session is not None

    affiliation_renter.delete()

    assert alice.active_rental_session is None


def test_bicycle_type_model(owner):
    from velodrome.lock8.models import BicycleType

    bt = BicycleType(reference='ref',
                     title='Title',
                     owner=owner)
    assert bt.reference == 'ref'
    assert bt.title == 'Title'
    assert bt.owner == owner


def test_address_model(owner, org):
    from velodrome.lock8.models import Address
    address = Address.objects.create(email='woldcompany@example.com',
                                     phone_number='123-456-7890',
                                     text_address=textwrap.dedent(
                                         """\
                                         32 Main street
                                         94101
                                         San Francisco
                                         CA"""),
                                     owner=owner,
                                     organization=org)
    assert address.email == 'woldcompany@example.com'
    assert address.phone_number == '123-456-7890'
    assert address.text_address == '32 Main street\n94101\nSan Francisco\nCA'


def test_delete_user_delete_also_affiliations(alice, org, fleet_operator):
    from velodrome.lock8.models import Affiliation
    affiliation = Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER,
    )

    alice.delete()

    with pytest.raises(Affiliation.DoesNotExist):
        affiliation.refresh_from_db()


def test_delete_organization_delete_also_affiliations(alice, org,
                                                      fleet_operator):
    from velodrome.lock8.models import Affiliation
    affiliation = Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER,
    )
    org.delete()

    with pytest.raises(Affiliation.DoesNotExist):
        affiliation.refresh_from_db()


def test_organization_feedback_category_tree_helpers(owner, org, root_org):
    from velodrome.lock8.models import FeedbackCategory, Organization

    sub_org = Organization.objects.create(
        owner=owner,
        name='sub',
        parent=org,
    )

    c1 = FeedbackCategory.objects.create(parent=None, name='c1')
    FeedbackCategory.objects.create(name='helmet', parent=c1)
    FeedbackCategory.objects.create(name='basket', parent=c1)

    assert org.feedback_category_tree is None
    org.feedback_category_tree = c1
    org.save()

    assert sub_org.feedback_category_tree is None
    assert root_org.feedback_category_tree is not None

    sub_org_ctree = sub_org.get_feedback_category_tree()
    assert sub_org_ctree != root_org.feedback_category_tree
    assert sub_org_ctree == org.feedback_category_tree
    assert sub_org_ctree.get_children().filter(name='helmet').exists()
    assert sub_org_ctree.get_children().filter(name='basket').exists()


def test_zone_model(org, owner, central_park, middle_of_central_park,
                    mechanic1):
    from velodrome.lock8.models import Zone

    zone = Zone.objects.create(
        organization=org,
        owner=owner,
        name='Drop me',
        polygon=central_park,
        preferred_mechanic=mechanic1,
        low_threshold=20,
        high_threshold=100
    )
    assert zone.state == 'new'
    assert zone.name == 'Drop me'
    assert zone.organization == org
    assert zone.owner == owner
    assert zone.polygon == central_park
    assert zone.preferred_mechanic == mechanic1
    assert zone.low_threshold == 20
    assert zone.high_threshold == 100
    assert (Zone
            .objects
            .filter(polygon__intersects=middle_of_central_park)
            .count()) == 1


def test_reservation_model(alice, bicycle, owner, settings):
    from velodrome.lock8.models import Reservation

    reservation = Reservation.objects.create(
        user=alice,
        owner=owner,
        bicycle=bicycle,
    )
    assert reservation.user == alice
    assert reservation.bicycle == bicycle
    assert reservation.owner == owner
    assert reservation.state == 'new'

    assert alice.reservations.all().get() == reservation
    assert bicycle.reservations.all().get() == reservation

    assert (reservation.default_duration ==
            settings.DEFAULT_MAX_RESERVATION_DURATION)


def test_eligible_renting_scheme(bicycle, org, owner):
    from velodrome.lock8.models import RentingScheme

    assert list(bicycle.eligible_renting_schemes) == []

    rs1 = RentingScheme.objects.create(
        organization=org,
        max_reservation_duration=dt.timedelta(seconds=1),
        owner=owner,
    )
    rs2 = RentingScheme.objects.create(
        organization=org,
        max_reservation_duration=dt.timedelta(seconds=2),
        owner=owner,
    )
    rs3 = RentingScheme.objects.create(
        organization=org,
        bicycle=bicycle,
        max_reservation_duration=dt.timedelta(seconds=2),
        owner=owner,
    )
    rs4 = RentingScheme.objects.create(
        organization=org,
        bicycle=bicycle,
        max_reservation_duration=dt.timedelta(seconds=1),
        owner=owner,
    )
    assert list(bicycle.eligible_renting_schemes) == [rs3, rs4, rs2, rs1]


def test_organization_preference_model(org, owner):
    from velodrome.lock8.models import Alert, OrganizationPreference

    preference = OrganizationPreference(
        owner=owner,
        organization=org,
        name='Main preference',
        allowed_email_alert_types=[Alert.LOW_BATTERY],
        allowed_push_alert_types=[Alert.LOW_BATTERY],
        currency='usd',
        timezone='UTC',
        operational_weekday_period=(8, 17),
        operational_weekend_period=(0, 0),
        unit_system='imperial',
    )
    preference.full_clean()

    assert preference.owner == owner
    assert preference.organization == org
    assert preference.name == 'Main preference'
    assert preference.allowed_email_alert_types == ['lock.bat.low']
    assert preference.allowed_push_alert_types == ['lock.bat.low']
    assert preference.currency == 'usd'
    assert preference.allow_renting_without_pricings is True
    assert preference.timezone == 'UTC'
    assert preference.state == 'new'
    assert preference.operational_weekday_period == NumericRange(upper=17,
                                                                 lower=8)
    assert preference.operational_weekend_period == NumericRange(upper=0,
                                                                 lower=0)
    assert preference.unit_system == 'imperial'


def test_organization_preference_all_default(org, owner):
    from velodrome.lock8.models import OrganizationPreference

    OrganizationPreference.objects.create(
        owner=owner,
        organization=org,
    )


def test_organization_preference_clean(db, stripe_account, org):
    from velodrome.lock8.models import OrganizationPreference

    org.stripe_account = stripe_account
    op = OrganizationPreference()
    op.clean()

    op.organization = org
    op.currency = ''
    with pytest.raises(ValidationError) as excinfo:
        op.clean()
    assert excinfo.value.message_dict == {
        'currency': ['This field is required with "uses_payments".']}


@pytest.mark.parametrize('pref_and_test_vals', (
    ('allowed_email_alert_types', (['foo'], {'bar'}, ['lock.bat.low', 'foo'])),
    ('alert_type_to_role_mapping', (
        {'foo'}, ['bar'], {'lock.bat.low': 'foo'}, {'bar': 'security'}
    ))
))
def test_organization_preference_validation(organization_preference,
                                            pref_and_test_vals):
    pref, test_vals = pref_and_test_vals
    for test_val in test_vals:
        setattr(organization_preference, pref, test_val)
        with pytest.raises(ValidationError):
            organization_preference.full_clean()


@pytest.mark.parametrize('send_flag, email, raises', (
    (True, None, True),
    (True, 'foo@example.com', False),
    (False, 'foo@example.com', False),
    (False, None, False),
))
def test_organization_preference_validation_clean(organization_preference,
                                                  send_flag, email, raises):
    organization_preference.send_support_ticket_per_email = send_flag
    organization_preference.support_email = email
    if raises:
        with pytest.raises(ValidationError):
            organization_preference.full_clean()
    else:
        organization_preference.full_clean()
        assert (
            organization_preference.send_support_ticket_per_email == send_flag)
        assert organization_preference.support_email == email


def test_firmware_model(owner, org, get_firmware_hex):
    from velodrome.lock8.models import Firmware

    firmware = Firmware.objects.create(
        owner=owner,
        organization=org,
        chip=Firmware.NORDIC,
        version='a' * 40,
        binary=get_firmware_hex('fw_model'),
        name='Da firmware',
    )
    assert firmware.owner == owner
    assert firmware.organization == org
    assert firmware.chip == '0'
    assert firmware.version == 'a' * 40
    assert firmware.binary.size == 4
    assert firmware.state == 'new'
    assert firmware.name == 'Da firmware'

    firmware.provision()

    assert firmware.state == 'provisioned'

    firmware3 = Firmware.objects.create(
        owner=owner,
        organization=org,
        chip=Firmware.NORDIC,
        version='a' * 40,
    )
    with pytest.raises(ValidationError) as excinfo:
        firmware3.provision()
    assert 'A file is required' in str(excinfo.value)

    firmware4 = Firmware.objects.create(
        owner=owner,
        organization=org,
        chip=Firmware.NORDIC,
        binary=get_firmware_hex('fw_model_2'),
    )
    with pytest.raises(ValidationError) as excinfo:
        firmware4.provision()
    assert 'A version is required' in str(excinfo.value)
    assert not firmware4.binary

    assert firmware.binary
    firmware.delete()
    assert firmware.binary
    firmware.binary.delete()
    assert not firmware.binary


def test_concurrent_edition_raise_an_error(alice):
    """
    User is an arbitrary model than supports .concurrency_version
    field.
    """
    from velodrome.lock8.models import User

    alice2 = User.objects.get(pk=alice.pk)
    alice.first_name = 'boo'
    alice.save()

    alice2.last_name = 'ba'
    with pytest.raises(RecordModifiedError):
        alice2.save()


def test_notification_message_generic_delete(alice, alert, feedback,
                                             organization_preference,
                                             fleet_operator):
    from velodrome.lock8.models import NotificationMessage

    assert NotificationMessage.objects.count() == 0
    feedback.send()
    assert NotificationMessage.objects.count() == 1
    feedback.delete()
    assert not NotificationMessage.objects.filter(
        object_id=feedback.id
    ).exists()
    assert NotificationMessage.objects.count() == 0


@pytest.mark.skip(reason='unstable results on fresh database, fix later')
def test_revisioned_models():
    from velodrome.lock8.models import (
        Address, Alert, Bicycle, BicycleModel, BicycleModelMaintenanceRule,
        BicycleType, ClientApp, Feature, Feedback, Firmware, Invitation, Lock,
        LockFirmwareUpdate,
        Organization, OrganizationPreference, Photo, PlanPass, PricingScheme,
        RentalSession, RentingScheme, Reservation, SubscriptionPlan,
        SupportTicket, Task, TermsOfService, User, UserProfile, Zone)

    assert sorted(reversion.revisions.get_registered_models(),
                  key=lambda c: c.__name__) == [
                      Address,
                      Alert,
                      Bicycle,
                      BicycleModel,
                      BicycleModelMaintenanceRule,
                      BicycleType,
                      ClientApp,
                      ContentType,
                      Feature,
                      Feedback,
                      Firmware,
                      Invitation,
                      Lock,
                      LockFirmwareUpdate,
                      Organization,
                      OrganizationPreference,
                      Photo,
                      PlanPass,
                      PricingScheme,
                      RentalSession,
                      RentingScheme,
                      Reservation,
                      SubscriptionPlan,
                      SupportTicket,
                      Task,
                      TermsOfService,
                      User,
                      UserProfile,
                      Zone,
                  ]


def test_get_causality(alert, task1, lock, feedback, bicycle,
                       bicycle_model, org, another_lock):
    from django.contrib.contenttypes.models import ContentType
    from velodrome.lock8.models import Affiliation, Alert, Task

    assert alert.get_final_causality() == lock
    assert task1.get_final_causality() == lock
    assert feedback.get_final_causality() == bicycle

    assert (Alert.objects
            .annotate_with_causative_bicycle_uuid().get(pk=alert.pk)
            .causative_bicycle_uuid == bicycle.uuid)
    assert (Task.objects
            .annotate_with_causative_bicycle_uuid().get(pk=task1.pk)
            .causative_bicycle_uuid == bicycle.uuid)

    with pytest.raises(AttributeError):
        bicycle_model.get_final_causality()

    alert_ctype = ContentType.objects.get(app_label="lock8", model="alert")
    with connection.cursor() as cursor:
        cursor.execute("SELECT currval('lock8_bicycle_id_seq')")
        latest_id = cursor.fetchone()[0]
    alert_wo_cause = Alert.objects.create(
        organization=org,
        content_type=alert_ctype,
        object_id=latest_id + 1,
        roles=[Affiliation.FLEET_OPERATOR],
        alert_type=Alert.LOW_BATTERY,
    )
    assert alert_wo_cause.get_final_causality() is None
    assert (Alert.objects
            .annotate_with_causative_bicycle_uuid().get(pk=alert_wo_cause.pk)
            .causative_bicycle_uuid is None)

    assert alert_wo_cause.get_final_causality(expect_bicycle=True) is None
    assert alert.get_final_causality(expect_bicycle=True) == bicycle
    assert feedback.get_final_causality(expect_bicycle=True) == bicycle
    assert (Alert.objects
            .annotate_with_causative_bicycle_uuid().get(pk=alert.pk)
            .causative_bicycle_uuid == bicycle.uuid)
    assert (Task.objects
            .annotate_with_causative_bicycle_uuid().get(pk=task1.pk)
            .causative_bicycle_uuid == bicycle.uuid)

    task = Task.objects.create(organization=org, causality=another_lock)
    assert task.get_final_causality(expect_bicycle=True) is None


def test_models_repr(owner):
    from velodrome.lock8.models import (
        Affiliation, Alert, AlertStates, Bicycle, Organization, PricingScheme,
        User, RentalSession, SubscriptionPlan, AcceptedTermsOfService,
        TermsOfService, TermsOfServiceVersion)

    org = Organization(owner=owner)
    user = User()
    assert repr(Affiliation()) == "Affiliation(pk=None, user=None, organization=None, role='renter')"  # noqa: E501
    assert repr(org) == "Organization(pk=None, name='', uses_payments=False)"
    assert repr(user) == "User(pk=None, email='', affiliations=[], organization=None)"  # noqa: E501

    assert repr(Affiliation(user=user, organization=org)) == (
        "Affiliation(pk=None, user=User(pk=None), organization=%r, role='renter')" % (  # noqa: E501
            org))
    subscription_plan = SubscriptionPlan()
    assert repr(subscription_plan) == "SubscriptionPlan(pk=None, name='', plan=None, state='new')"  # noqa: E501

    user.save()
    org.save()
    affiliation = Affiliation(user=user, organization=org)
    affiliation.save()
    assert repr(Affiliation(user=user, organization=org)) == (
        "Affiliation(pk=None, user=User(pk=%d), organization=%r, role='renter')" % (  # noqa: E501
            user.pk, org))

    rental_session = RentalSession()
    assert repr(rental_session) == "RentalSession(pk=None, user=None, bicycle=None, effective_pricing_scheme=None, subscription_plan=None, duration=None, cents=None, charge=None)"  # noqa: E501
    rental_session.subscription_plan = subscription_plan
    rental_session.duration = dt.timedelta(minutes=10, seconds=11)
    assert repr(rental_session) == "RentalSession(pk=None, user=None, bicycle=None, effective_pricing_scheme=None, subscription_plan=%r, duration='0:10:11', cents=None, charge=None)" % (  # noqa: E501
        subscription_plan)

    pricing_scheme = PricingScheme()
    assert repr(pricing_scheme) == "PricingScheme(pk=None, name='', time_ranges=[], max_daily_charged_cents=None)"  # noqa: E501

    # Terms of Services
    terms_of_service_version = TermsOfServiceVersion()
    assert repr(terms_of_service_version) == "TermsOfServiceVersion(pk=None, label='', organization=None)"  # noqa: E501
    terms_of_service = TermsOfService()
    assert repr(terms_of_service) == "TermsOfService(pk=None, language='', version=None, organization=None)"  # noqa: E501
    accepted_terms_of_service = AcceptedTermsOfService()
    assert repr(accepted_terms_of_service) == "AcceptedTermsOfService(pk=None, terms_of_service=None, user=None)"  # noqa: E501

    terms_of_service_version.organization = org
    terms_of_service_version.label = 'Label'
    assert repr(terms_of_service_version) == f"TermsOfServiceVersion(pk=None, label='Label', organization={org!r})"  # noqa: E501

    terms_of_service.language = 'en'
    terms_of_service.version = terms_of_service_version
    terms_of_service.organization = org
    assert repr(terms_of_service) == f"TermsOfService(pk=None, language='en', version={terms_of_service_version!r}, organization={org!r})"  # noqa: E501

    accepted_terms_of_service.terms_of_service = terms_of_service
    accepted_terms_of_service.user = user
    assert repr(accepted_terms_of_service) == f"AcceptedTermsOfService(pk=None, terms_of_service={terms_of_service!r}, user={user!r})"  # noqa: E501

    bicycle = Bicycle()
    assert repr(bicycle) == "Bicycle(pk=None, name='', organization=None, state='in_maintenance')"  # noqa: E501
    bicycle.name = '007'
    bicycle.organization = org
    bicycle.pk = 1
    assert repr(bicycle) == f"Bicycle(pk=1, name='007', organization={bicycle.organization!r}, state='in_maintenance')"  # noqa: E501

    alert = Alert()
    assert repr(alert) == "Alert(pk=None, alert_type='', state='new')"
    alert.pk = 1
    alert.alert_type = Alert.LOW_BATTERY
    alert.state = AlertStates.RESOLVED.value
    assert repr(alert) == "Alert(pk=1, alert_type='lock.bat.low', state='resolved')"  # noqa: E501


def test_models_str(alice, org, sub_org, another_org, owner):
    from velodrome.lock8.models import (
        Affiliation, Organization)

    sub_org_2 = Organization.objects.create(
        owner=owner, name='sub_org_2', parent=org
    )
    for org in (org, sub_org, another_org, sub_org_2):
        Affiliation.objects.create(user=alice, organization=org,
                                   role=Affiliation.RENTER)
    display = "Alice Cooper (member of 'org, sub_org, sub_org_2 (...)')"
    assert alice.__str__() == display

    assert alice.affiliations.get(organization=org).__str__() == (
        'Organization[%d] - User[%d] - Renter' % (org.pk, alice.pk))
