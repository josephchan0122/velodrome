import functools

from django.db.models import Q
import rules

from velodrome.custom_tagging.models import TagDeclaration
from velodrome.lock8.models import (
    Address, Affiliation, Alert, AlertMessage, AxaLock, Bicycle, BicycleModel,
    BicycleModelMaintenanceRule, BicycleStates, Feature, FeatureStates,
    Feedback, FeedbackCategory, Firmware, Invitation, InvitationStates, Lock,
    LockFirmwareUpdate, Organization, OrganizationPreference, Photo, PlanPass,
    PricingScheme, RentalSession, RentingScheme, Reservation, SharedSecret,
    SubscriptionPlan, SupportTicket, Task, TermsOfService, Tracking, Trip,
    User, UserProfile, Zone,
)


@rules.predicate
def is_superuser(user):
    return user.is_active and user.is_superuser


@rules.predicate
def is_at_least_supervisor(user):
    predicate = Q(affiliation__role__in=(
        Affiliation.ADMIN,
        Affiliation.SUPERVISOR,
    ))
    return (
        user.is_authenticated and
        user.get_organizations(predicate=predicate).exists()
    )


@rules.predicate
def is_at_least_fleet_operator(user):
    predicate = Q(affiliation__role__in=(
        Affiliation.ADMIN,
        Affiliation.SUPERVISOR,
        Affiliation.FLEET_OPERATOR,
    ))
    return (
        user.is_authenticated and
        user.get_organizations(predicate=predicate).exists()
    )


@rules.predicate
def is_at_least_mechanic(user):
    predicate = Q(affiliation__role__in=(
        Affiliation.ADMIN,
        Affiliation.SUPERVISOR,
        Affiliation.FLEET_OPERATOR,
        Affiliation.MECHANIC,
    ))
    return (
        user.is_authenticated and
        user.get_organizations(predicate=predicate).exists()
    )


@rules.predicate
def is_mechanic(user):
    predicate = Q(affiliation__role=Affiliation.MECHANIC)
    return (user.is_authenticated and
            user.get_organizations(predicate=predicate).exists())


@rules.predicate
def is_at_least_renter(user):
    """A Renter is not a bot."""
    return (user.is_authenticated and
            not user.organizations
            .filter(affiliation__role=Affiliation.SPECTATOR)
            .exists())


@rules.predicate
def is_admin_of_lock8(user):
    predicate = Q(affiliation__role=Affiliation.ADMIN, level=0)
    return (user.is_authenticated and
            user.get_organizations(predicate=predicate).exists())


@rules.predicate
def is_production_software(user):
    predicate = Q(affiliation__role=Affiliation.PRODUCTION_SOFTWARE, level=0)
    return (user.is_authenticated and
            user.get_organizations(predicate=predicate).exists())


@rules.predicate
def is_at_least_supervisor_or_admin_of_lock8(user):
    return is_at_least_supervisor(user) or is_admin_of_lock8(user)


@rules.predicate
def is_at_least_fleet_op_or_admin_of_lock8(user):
    return is_at_least_fleet_operator(user) or is_admin_of_lock8(user)


@rules.predicate
def is_at_least_mechanic_or_admin_of_lock8(user):
    return is_at_least_mechanic(user) or is_admin_of_lock8(user)


@rules.predicate(bind=True)
def is_open_fleet(self, user, obj):
    if self.context.args[1] is None:
        return True

    if isinstance(obj, (Bicycle,
                        BicycleModel,
                        OrganizationPreference,
                        Photo,
                        PricingScheme,
                        SubscriptionPlan,
                        TermsOfService,
                        Zone,
                        )):
        organization = obj.organization
    elif isinstance(obj, Organization):
        organization = obj
    else:
        raise NotImplementedError

    return organization.is_open_fleet


is_closed_fleet = ~is_open_fleet


@rules.predicate(bind=True)
def is_member_of_closed_fleet(self, user, obj):
    if self.context.args[1] is None:
        return None
    if user.is_anonymous:
        return False

    if isinstance(obj, (Bicycle,
                        BicycleModel,
                        OrganizationPreference,
                        Photo,
                        PricingScheme,
                        SubscriptionPlan,
                        TermsOfService,
                        Zone,
                        )):
        organization = obj.organization
    elif isinstance(obj, Organization):
        organization = obj
    elif isinstance(obj, SharedSecret):
        organization = obj.lock.organization
    else:
        raise NotImplementedError

    predicate = Q(pk=organization.pk)
    return (user
            .get_descendants_organizations().filter(predicate)
            .exists())


@rules.predicate
def is_allowed_by_email_domain(user, obj):
    if obj is None:
        return None
    try:
        domain = user.email.split('@', 1)[1]
    except IndexError:
        return False
    return domain in obj.allowed_signup_domain_names


def _is_x_of_descendants_organization(self, user, obj, roles_predicate):
    if self.context.args[1] is None:
        return None
    if user.is_anonymous:
        return False
    organization = None
    if isinstance(obj, (
            Address,
            Affiliation,
            AxaLock,
            Bicycle,
            BicycleModel,
            Invitation,
            Zone,
            Lock,
            Alert,
            Feedback,
            OrganizationPreference,
            Photo,
            PricingScheme,
            RentingScheme,
            SubscriptionPlan,
            SupportTicket,
            TagDeclaration,
            Task,
            TermsOfService,
            Firmware,
    )):
        organization = obj.organization
    elif isinstance(obj, Organization):
        organization = obj
    elif isinstance(obj, Tracking):
        organization = obj.lock.organization
    elif isinstance(obj, (RentalSession, Reservation)):
        organization = obj.bicycle.organization
    elif isinstance(obj, User):
        predicate = Q(pk__in=obj
                      .get_organizations()
                      .all()
                      .values_list('pk', flat=True))
    elif isinstance(obj, UserProfile):
        predicate = Q(pk__in=obj.user
                      .get_organizations()
                      .all()
                      .values_list('pk', flat=True))
    elif isinstance(obj, AlertMessage):
        organization = obj.alert.organization
    elif isinstance(obj, FeedbackCategory):
        organization = obj.get_root().organization
    elif isinstance(obj, BicycleModelMaintenanceRule):
        organization = obj.bicycle_model.organization
    elif isinstance(obj, (LockFirmwareUpdate, SharedSecret)):
        organization = obj.lock.organization
    elif isinstance(obj, Trip):
        try:
            organization = Organization.objects.get(uuid=obj.organization_uuid)
        except Organization.DoesNotExist:
            return False
    elif isinstance(obj, PlanPass):
        organization = obj.subscription_plan.organization
    else:
        raise NotImplementedError

    if organization is not None:
        predicate = Q(pk=organization.pk)

    return (user
            .get_descendants_organizations(predicate=roles_predicate)
            .filter(predicate)
            .exists())


@rules.predicate(bind=True)
def is_at_least_supervisor_of_descendant_organization(
    self, user, obj
):
    return _is_x_of_descendants_organization(
        self, user, obj,
        Q(affiliation__role__in=(
            Affiliation.ADMIN,
            Affiliation.SUPERVISOR,
            Affiliation.FLEET_OPERATOR,
        ))
    )


@rules.predicate(bind=True)
def is_at_least_fleet_op_of_descendant_organization(
    self, user, obj
):
    return _is_x_of_descendants_organization(
        self, user, obj,
        Q(affiliation__role__in=(
            Affiliation.ADMIN,
            Affiliation.SUPERVISOR,
            Affiliation.FLEET_OPERATOR,
        ))
    )


@rules.predicate(bind=True)
def is_at_least_mechanic_of_descendant_organization(
    self, user, obj
):
    return _is_x_of_descendants_organization(
        self, user, obj,
        Q(affiliation__role__in=(
            Affiliation.ADMIN,
            Affiliation.SUPERVISOR,
            Affiliation.FLEET_OPERATOR,
            Affiliation.MECHANIC,
        ))
    )


@rules.predicate()
def is_category_viewable(user, obj):
    if obj is None:
        return None
    assert isinstance(obj, FeedbackCategory)
    org = obj.get_root().organization

    if obj.is_leaf_node() and org.is_open_fleet:
        return True

    family_pks = org.get_family().values_list('pk', flat=True)
    if not (user
            .get_descendants_organizations()
            .exclude(affiliation__role=Affiliation.RENTER)
            .exists()):
        # Just a renter
        if org.level == 0 and obj.is_leaf_node():
            # Anybody can see leafs of FeedbackCategory that belongs to lock8.
            return True
        # can see if category belongs to same org family of open fleet.
        return (obj.is_leaf_node() and (
            org.is_open_fleet or
            (user
             .get_organizations(Q(is_open_fleet=True, pk__in=family_pks))
             .exists())))
    else:
        return (user
                .get_organizations()
                .filter(pk__in=family_pks)
                .exists())


@rules.predicate()
def is_self(user, obj):
    if obj is None:
        return None
    return user == (obj.user if isinstance(obj, UserProfile) else obj)


@rules.predicate(bind=True)
def is_local(self, user, obj):
    if self.context.args[1] is None:
        return True
    return obj.is_local


@rules.predicate(bind=True)
def is_at_least_fleet_op_of_descendant_organization_but_self(
    self, user, obj
):
    if self.context.args[1] is None:
        return True

    if isinstance(obj, (Bicycle,)):
        organization = obj.organization
    elif isinstance(obj, Organization):
        organization = obj
    else:
        raise NotImplementedError

    predicate = ~Q(pk=organization.pk)
    return (user
            .get_descendants_managed_organizations(predicate=predicate)
            .filter(pk=organization.pk)
            .exists())


@rules.predicate()
def is_used_by(user, obj):
    if obj is None:
        return None
    return obj.user == user


@rules.predicate()
def is_owned_by(user, obj):
    if obj is None:
        return None
    return obj.owner == user


@rules.predicate(bind=True)
def is_current_renter_or_reserver(self, user, obj):
    if self.context.args[1] is None:
        return None
    return obj.latest_transition_by == user


@rules.predicate()
def is_current_renter(user, obj):
    if obj is None:
        return None
    if isinstance(obj, SharedSecret):
        obj = obj.lock.bicycle

    return (obj.state == BicycleStates.RENTED.value and
            obj.latest_transition_by == user)


@rules.predicate(bind=True)
def is_by_bicycle_state(self, user, obj):
    if self.context.args[1] is None:
        return True
    organization = obj.organization
    if obj.state == BicycleStates.AVAILABLE.value:
        # is open fleet or member of closed fleet
        if user.is_anonymous:
            return organization.is_open_fleet

        return (organization.is_open_fleet or
                user
                .get_descendants_organizations()
                .filter(pk=organization.pk)
                .exists()
                )
    elif obj.state in (BicycleStates.RESERVED.value,
                       BicycleStates.RENTED.value,
                       ):
        if user.is_anonymous:
            return False
        # is current renter or fleet operator
        return (obj.latest_transition_by == user or
                user.get_descendants_managed_organizations()
                .filter(pk=organization.pk)
                .exists()
                )
    else:
        if user.is_anonymous:
            return False
        # is fleet_operator or admin
        return (user
                .get_descendants_managed_organizations()
                .filter(pk=organization.pk)
                .exists()
                )


@rules.predicate()
def is_renting_the_attached_bicycle(user, obj):
    if obj is None:
        return user.is_authenticated
    try:
        bicycle = obj.bicycle
    except Bicycle.DoesNotExist:
        return False

    qs = user.rental_sessions.filter(bicycle=bicycle,
                                     created__lt=obj.start_date)
    if obj.end_date is not None:
        qs = qs.exclude(created__gte=obj.end_date)
    return qs.exists()


@rules.predicate
def is_reservable(user, obj):
    return 'reserve' in (t.name for t in obj.get_available_state_transitions())


@rules.predicate(bind=True)
def is_rentable(self, user, obj):
    if obj is None:
        return None
    return 'rent' in (t.name for t in obj.get_available_state_transitions())


@rules.predicate
def is_assigned_to_group(user, obj):
    if obj is None:
        return None
    assert isinstance(obj, Task)
    return (
        user.affiliations
        .exclude(role=Affiliation.RENTER)
        .filter(
            role=obj.role,
            organization=obj.organization
        ).exists()
    )


@rules.predicate
def has_task_viewable_role(user):
    roles = (Affiliation.MECHANIC,
             Affiliation.FLEET_OPERATOR,
             Affiliation.SUPERVISOR,
             Affiliation.ADMIN)
    return (user.is_authenticated and
            user.organizations
            .filter(affiliation__role__in=roles)
            .exists())


@rules.predicate
def is_anon_and_invitation_provisioned(user, obj):
    if obj is None:
        return True
    return (not user.is_authenticated and
            obj.state == InvitationStates.PROVISIONED.value)


@rules.predicate()
def is_eligible_for_plan(user, plan):
    if not isinstance(plan, SubscriptionPlan):
        return None
    return plan.can_be_used_by_user(user)


def _can_access_feature(name, user):
    predicate = Q(affiliation__role__in=(Affiliation.ADMIN,
                                         Affiliation.SUPERVISOR,
                                         Affiliation.FLEET_OPERATOR,
                                         Affiliation.SPECTATOR))
    if not (Feature.objects
            .filter(name=name, state=FeatureStates.ACTIVE.value)
            .exists()):
        return (user
                .get_descendants_organizations(predicate=predicate)
                .exists())
    # temp workaround because the only feature implemented
    # at the moment is analytics
    # FIXME

    # return user.get_descendants_managed_organizations().filter(
    #     features__name=name).exists()
    return (user
            .get_descendants_organizations(predicate=predicate)
            .filter(features__name=name)
            .exists())


can_access_analytics_feature = rules.predicate(
    functools.partial(_can_access_feature, 'analytics'))
