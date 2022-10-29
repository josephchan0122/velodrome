import base64
from collections import namedtuple
import contextlib
import datetime as dt
from decimal import ROUND_CEILING, Decimal
from enum import Enum
import functools
import inspect
import itertools
import json
import logging
import math
import operator
import os
from random import random
import typing
from urllib.parse import urlencode, urljoin
import uuid

from concurrency.fields import IntegerVersionField
from django.conf import settings
from django.contrib.auth.models import (
    AbstractUser, UserManager as DjangoUserManager,
)
from django.contrib.auth.tokens import default_token_generator
from django.contrib.contenttypes.fields import (
    GenericForeignKey, GenericRelation,
)
from django.contrib.contenttypes.models import ContentType
from django.contrib.gis.db.models import (
    LineStringField, Model as GeoModel, MultiPolygonField, PointField,
)
from django.contrib.gis.db.models.functions import Distance as GeoDistance
from django.contrib.gis.geos import Point
from django.contrib.gis.measure import Distance
from django.contrib.postgres.fields import (
    ArrayField, DateTimeRangeField, IntegerRangeField, JSONField,
)
from django.contrib.postgres.search import TrigramSimilarity
from django.contrib.postgres.validators import (
    RangeMaxValueValidator, RangeMinValueValidator,
)
from django.core.exceptions import (
    NON_FIELD_ERRORS, FieldDoesNotExist, ObjectDoesNotExist, ValidationError,
)
from django.core.files.storage import get_storage_class
from django.core.validators import (
    MaxLengthValidator, MaxValueValidator, MinValueValidator,
)
from django.db import IntegrityError, connections, models, transaction
from django.db.models import FilteredRelation, base, signals
from django.db.models.aggregates import Count, Max, Sum
from django.db.models.base import ModelBase
from django.db.models.expressions import Case, F, RawSQL, Value, When
from django.db.models.fields import NOT_PROVIDED, AutoField, FloatField
from django.db.models.functions import Concat
from django.db.models.manager import Manager
from django.db.models.query import Prefetch, Q, QuerySet
from django.db.models.sql.compiler import SQLCompiler
from django.dispatch import receiver
from django.forms.fields import UUIDField
from django.http import Http404
from django.urls import NoReverseMatch, reverse
from django.utils import timezone
from django.utils.dateparse import parse_datetime
from django.utils.functional import cached_property
from django.utils.text import slugify
from django.utils.translation import ugettext_lazy as _
from django_extensions.db.models import TimeStampedModel
from django_fsm import GET_STATE, FSMField, transition
from django_fsm.signals import post_transition
from django_fsm_log.decorators import fsm_log_by
from django_fsm_log.models import StateLog
from django_redis import get_redis_connection
from humanize import naturaldelta
from mptt.managers import TreeManager
from mptt.models import MPTTModel, TreeForeignKey
import pinax.stripe.actions.charges
import pinax.stripe.actions.customers
from pinax.stripe.actions.subscriptions import (
    sync_subscription_from_stripe_data,
)
from pinax.stripe.models import Account, Charge, Customer, Plan, Subscription
from pinax.stripe.signals import WEBHOOK_SIGNALS
import pytz
import requests
from storages.backends.s3boto3 import S3Boto3Storage
import stripe

from .exceptions import DuplicateContentError, SubscriptionExistsError
from .fields import (
    IndexedDateTimeField, IndexedFloatJsonField, IndexedPointField,
    IndexedPositiveIntegerJsonField, LanguageField,
)
from .metrics import (
    Key, get_ddbtable, get_distance_for_bicycles_since, query_table,
)
from .utils import (
    DurationExtract, build_frontend_uri, camel_case_to_snake_case,
    charge_estimator, make_short_id, raise_for_response_status_with_context,
    send_email,
)
from .validators import (
    validate_alert_type_to_role_mapping, validate_alert_types,
    validate_alert_types_to_task, validate_iccid, validate_imei,
    validate_payment_description, validate_sid, validate_signup_domain_names,
    validate_time_ranges,
)

logger = logging.getLogger(__name__)

NOT_SET = object()

GPS_LOCATION_MESSAGE = 'GPS'
CELLULAR_LOCATION_MESSAGE = 'CEL'
DEVICE_SYSTEM_STATUS_MESSAGE = 'DSS'
BATTERY_MESSAGE = 'BAT'  # legacy
AMBIENT_WEATHER_MESSAGE = 'AWM'
AMBIENT_GAS_MESSAGE = 'AGM'

GPS_FIELDS = ('latitude', 'longitude', 'latest_gps_accuracy',
              'latest_gps_timestamp', 'latest_gps_pdop')
DSS_FIELDS = ('state_of_charge', 'estimated_state_of_charge')
TRACKING_FIELDS = GPS_FIELDS + DSS_FIELDS

keysafe_http_session = requests.Session()
keysafe_http_session.headers['X-Api-Key'] = settings.KEY_SAFE_API_KEY


def modelbase_og_shortcut(self, *args, **kwargs):
    """A shortcut for `objects.get` on models."""
    return self._base_manager.get(*args, **kwargs)


ModelBase.o = ModelBase._default_manager
ModelBase.g = modelbase_og_shortcut


class DeviceEvents(Enum):
    """
    Copy of statuses from https://github.com/lock8/LockAPI/blob/master/messages/DeviceSystemStatus.proto
    """  # noqa
    INIT = 1
    CYCLING_STARTED = 2
    CYCLING_STOPPED = 3
    PERIODIC_UPDATE = 4
    CYCLING_NO_GPS_AVAILABLE = 5
    ACCELEROMETER_ERROR = 6
    DEPRECATED_CYCLING_NOT_CHARGING = 7
    CYCLING_NO_CELLULAR = 8
    SYSTEM_SHUTDOWN_MODE = 9
    LOCKING = 10
    LOCKED_BUT_CABLE_NOT_PRESENT = 11
    DEVICE_REPORT_BATTERY = 12


class DeviceLockStatus(Enum):
    UNKNOWN = 1
    LOCKED = 2
    UNLOCKED = 3


storage_class = get_storage_class()
if storage_class is S3Boto3Storage:
    private_storage = storage_class(
        bucket=settings.PRIVATE_BUCKET_NAME, acl='private')
else:
    private_storage = storage_class()


def returner(getter, attribute_name, self):
    try:
        return getter(self).get(attribute_name)
    except AttributeError:
        pass


def noop(self, *args):
    """
    Readonly and not overidable
    Still do not prevent callers to call setattr or delattr
    """
    pass


def maybe_create_and_send_alert(causality, alert_type,
                                message=None, user=None, default_roles=None,
                                owner=None, context=None,
                                concurrency_version=None):
    if default_roles is None:
        default_roles = []
    organization = causality.organization
    mapping = organization.get_preference('alert_type_to_role_mapping', {})
    roles = mapping.get(alert_type, default_roles)
    already_exists_predicate = Q(
        alert_type=alert_type,
        state__in=(
            AlertStates.NEW.value,
            AlertStates.ESCALATED.value,
            AlertStates.SILENCED.value))

    if causality.alerts.filter(already_exists_predicate).exists():
        return

    if not alert_type.startswith(causality.__class__.__name__.lower()):
        raise ValidationError(
            'Alert of type {} must not have {} causality.'.format(
                alert_type, causality.__class__.__name__))

    if message is None:
        message = 'Causality: %s %s | Type: %s' % (
                causality._meta.model_name, causality.uuid, alert_type)

    if context is None:
        context = {}
    if 'location' not in context:
        try:
            context['location'] = {
                'type': 'Point',
                'coordinates': causality.public_tracking.point.coords}
        except AttributeError:
            pass
        try:
            context['location'] = {
                'type': 'Point',
                'coordinates': causality.polygon.centroid.coords}
        except AttributeError:
            pass
    if 'state_of_charge' not in context:
        if hasattr(causality, 'state_of_charge'):
            state_of_charge = causality.state_of_charge
            if state_of_charge is not None:
                context['state_of_charge'] = state_of_charge

    alert = Alert.objects.create(
        causality=causality,
        organization=organization,
        roles=roles,
        user=user,
        alert_type=alert_type,
        message=message,
        owner=owner,
        context=context,
    )
    escalate_or_send_alert(alert)
    return alert


def escalate_or_send_alert(alert):
    bicycle = None
    if isinstance(alert.causality, Lock):
        bicycle = alert.causality.bicycle
    elif isinstance(alert.causality, Bicycle):
        bicycle = alert.causality
    elif isinstance(alert.causality, Zone):
        pass
    else:
        raise NotImplementedError

    if (bicycle and bicycle.model):
        alert_types_to_task = bicycle.model.alert_types_to_task
    else:
        alert_types_to_task = {}

    if alert.alert_type in alert_types_to_task:
        severity = alert_types_to_task[alert.alert_type]
        alert.escalate(severity=severity, role=alert.roles[0])  # XXX roles[0]
    else:
        alert.send_async()


@functools.total_ordering
class Severity():
    def __init__(self, severity):
        if not isinstance(severity, str):
            raise TypeError
        self.severity = severity

    def __eq__(self, other):
        return self.severity == other.severity

    def __lt__(self, other):
        f = FeedbackCategory
        if self.severity == f.SEVERITY_LOW:
            return other.severity != f.SEVERITY_LOW
        elif self.severity == f.SEVERITY_MEDIUM:
            return other.severity == f.SEVERITY_HIGH
        elif self.severity == f.SEVERITY_HIGH:
            return False
        else:
            raise NotImplementedError


class NullsLastSQLCompiler(SQLCompiler):
    """Add "NULLS LAST" to order_by, skipping AutoFields."""
    def get_order_by(self):
        result = super().get_order_by()
        if result and self.connection.vendor == 'postgresql':
            return [(expr, (sql
                            if isinstance(expr.field, AutoField)
                            else sql + ' NULLS LAST', params, is_ref))
                    for (expr, (sql, params, is_ref)) in result]
        return result


class NullsLastQuery(models.sql.query.Query):
    """Use a custom compiler to inject 'NULLS LAST' (for PostgreSQL)."""

    def get_compiler(self, using=None, connection=None):
        if using is None and connection is None:
            raise ValueError("Need either using or connection")
        if using:
            connection = connections[using]
        return NullsLastSQLCompiler(self, connection, using)


class NullsLastQuerySet(models.QuerySet):
    def __init__(self, model=None, query=None, using=None, hints=None):
        super().__init__(model, query, using, hints)
        self.query = query or NullsLastQuery(self.model)


class ActiveManager(Manager):
    """
    For Backward compatibility with migrations.
    """


class MetaJsonAccessorBuilder(base.ModelBase):
    """
    Provides attribute access like of json field content
    from the instance.

    .. code-block:: python

        instance.my_key == instance.json_field.get('my_key')

    The list of fields to expose as an attribute is configurable
    from the ``exposed_attributes`` property.
    The Json field to extract data from is discovered
    automatically.

    .. note::
        meta_json_placeholder_name must be defined to indicate
        which JSONField will be used.
    """

    def __new__(cls, name, bases, kwargs):
        exposed_attributes = None
        placeholder_name = None
        try:
            exposed_attributes = kwargs['exposed_attributes']
            placeholder_name = kwargs['meta_json_placeholder_name']
        except KeyError:
            if not getattr(kwargs.get('Meta', object), 'abstract', False):
                for klass in bases:
                    try:
                        exposed_attributes, placeholder_name = (
                            getattr(klass, 'exposed_attributes'),
                            getattr(klass, 'meta_json_placeholder_name'))
                    except KeyError:
                        continue
                    break
        cls_ = super().__new__(cls, name, bases, kwargs)
        if not exposed_attributes:
            if not hasattr(cls_, 'exposed_attributes'):
                logger.warning('exposed_attributes missing on class %s', name)
            return cls_
        if not placeholder_name:
            if not hasattr(cls_, 'placeholder_name'):
                logger.warning('placeholder_name missing on class %s', name)
            return cls_
        base_returner = functools.partial(
            returner,
            operator.attrgetter(placeholder_name))
        disallowed_deferred_fields = set()
        for attribute in exposed_attributes:
            if callable(attribute):
                prop = property(attribute, noop, noop)
                attribute = attribute.name
            else:
                prop = property(functools.partial(base_returner, attribute),
                                noop, noop)
            if attribute in kwargs:
                disallowed_deferred_fields.add(attribute)
            setattr(cls_, attribute, prop)

        def get_deferred_fields(self):
            """return list  of fields that has been deferred by user
            with QuerySet.defer().
            On save() deferred fields are excluded because they are out of sync
            with value from db.
            But in our case we don't want this behaviour since our IndexedField
            are always in sync with db content.
            """
            deferred_fields = super(cls_, self).get_deferred_fields()
            return deferred_fields - disallowed_deferred_fields

        cls_.get_deferred_fields = get_deferred_fields
        return cls_


class GenericStates(Enum):
    NEW = 'new'
    PROVISIONED = 'provisioned'
    DECOMMISSIONED = 'decommissioned'


class BaseModelMixin(TimeStampedModel):
    uuid = models.UUIDField(unique=True, db_index=True,
                            default=uuid.uuid4, editable=False)
    concurrency_version = IntegerVersionField()

    class Meta(TimeStampedModel.Meta):
        abstract = True
        ordering = ('-created', )

    def get_absolute_uri(self, request):
        return request.build_absolute_uri(self.get_absolute_url())

    def get_absolute_url(self):
        view_base_name = camel_case_to_snake_case(self.__class__.__name__)
        try:
            return reverse('lock8:{}-detail'.format(view_base_name),
                           kwargs={'uuid': self.uuid})
        except NoReverseMatch:
            # contrib.contenttypes.views.shortcut expects a string.
            return ''


class OwnerableModelMixin(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL,
                              related_name='+',
                              on_delete=models.PROTECT)

    class Meta:
        abstract = True


class ActionableModelMixin(models.Model):

    transitions = GenericRelation(StateLog)

    @property
    def latest_transition(self):
        try:
            return self.transitions.filter(state=self.state).latest()
        except StateLog.DoesNotExist:
            pass

    @property
    def latest_transition_by(self):
        try:
            return self.latest_transition.by
        except AttributeError:
            pass

    class Meta:
        abstract = True


class GenericStateMixin(models.Model):
    """
    A mixin for generic ``state``.
    """
    state = FSMField(default=GenericStates.NEW.value, db_index=True)

    class Meta:
        abstract = True

    @fsm_log_by
    @transition(field=state,
                source=(GenericStates.NEW.value,
                        GenericStates.DECOMMISSIONED.value),
                target=GenericStates.PROVISIONED.value)
    def provision(self, **kwargs):
        if hasattr(self, '_provision'):
            return self._provision(**kwargs)

    @fsm_log_by
    @transition(field=state,
                source=(GenericStates.NEW.value,
                        GenericStates.PROVISIONED.value),
                target=GenericStates.DECOMMISSIONED.value)
    def decommission(self, **kwargs):
        pass


class NotificationMessageDeleteMixin:
    def delete(self, *args, **kwargs):
        """
        As the `on_delete` behaviour is not available for `GenericForeignKey`,
        a delete mixin does the job. This mixin should be used for any model
        that could be a `causality` for the `NotificationMessage` model.
        """
        NotificationMessage.objects.filter(object_id=self.id).delete()
        super().delete(*args, **kwargs)


class OrganizationOwnedModelMixin:

    @classmethod
    def get_queryset(cls, request=None, **kwargs):
        user = request.user
        if user.is_anonymous:
            return cls.objects.none()
        # XXX usage of distinct is very costly, let's not use it.
        return cls.objects.filter(
            organization__in=user.get_descendants_organizations(),
        )


class FinalCausalityModelMixin:
    @cached_property
    def bicycle_causality(self):
        return self.get_final_causality(expect_bicycle=True)

    def get_final_causality(self, expect_bicycle=False):
        causality = self.causality
        while hasattr(causality, 'causality'):
            causality = causality.causality
        if expect_bicycle:
            if isinstance(causality, Bicycle):
                return causality
            if isinstance(causality, Lock):
                try:
                    return causality.bicycle
                except Bicycle.DoesNotExist:
                    return None
        return causality


class Affiliation(BaseModelMixin, ActionableModelMixin):
    RENTER = 'renter'
    FLEET_OPERATOR = 'fleet_operator'
    ADMIN = 'admin'
    MECHANIC = 'mechanic'
    SECURITY = 'security'
    SPECTATOR = 'spectator'
    PRODUCTION_SOFTWARE = 'production_software'
    SUPERVISOR = 'supervisor'
    ROLES = (
        (RENTER, 'Renter'),
        (FLEET_OPERATOR, 'Fleet Operator'),
        (ADMIN, 'Admin'),
        (MECHANIC, 'Mechanic'),
        (SECURITY, 'Security'),
        (SPECTATOR, 'Spectator'),
        (PRODUCTION_SOFTWARE, 'Production Software'),
        (SUPERVISOR, 'Supervisor'),
    )

    user = models.ForeignKey('lock8.User',
                             related_name='affiliations',
                             related_query_name='affiliation',
                             on_delete=models.CASCADE)
    organization = models.ForeignKey('lock8.Organization',
                                     related_name='affiliations',
                                     related_query_name='affiliation',
                                     on_delete=models.CASCADE)
    role = models.CharField(max_length=25,
                            choices=list(ROLES),
                            default=RENTER)
    # deprecated
    state = FSMField(default=GenericStates.NEW.value, db_index=True, null=True)

    class Meta(BaseModelMixin.Meta):
        unique_together = ('user', 'organization', 'role')

    def __str__(self):
        return 'Organization[{}] - User[{}] - {}'.format(
            self.organization_id,
            self.user_id,
            self.get_role_display())

    def __repr__(self):
        return 'Affiliation(pk=%r, user=%s, organization=%r, role=%r)' % (
            self.pk,
            'User(pk=%s)' % self.user.pk if hasattr(self, 'user') else None,
            self.organization if hasattr(self, 'organization') else None,
            self.role)

    def clean(self):
        try:
            user = self.user
        except User.DoesNotExist:
            return
        if (user.organization is not None and
                user.organization != self.organization):
            raise ValidationError(
                f'The user {user} already belongs to the {user.organization}')

    def delete(self):
        """
        If it is the last Affiliation to this Organization,
        then close pending reservations and rental_sessions and invitations.
        """
        if not Affiliation.objects.filter(
                user=self.user,
                organization=self.organization).exclude(pk=self.pk).exists():
            # self is the last Affiliation of this user to this org.
            reservation = self.user.active_reservation
            if reservation is not None:
                reservation.close()
            rental_session = self.user.active_rental_session
            if rental_session is not None:
                rental_session.close()
            for invitation in (self.user.invitations.filter(
                    organization=self.organization,
                    state=InvitationStates.PROVISIONED.value) |
                               Invitation.objects.filter(
                                   email__iexact=self.user.email,
                                   organization=self.organization,
                                   state=InvitationStates.PROVISIONED.value)):
                invitation.cancel()
        return super().delete()


class UserProfile(BaseModelMixin, ActionableModelMixin, GenericStateMixin,
                  OwnerableModelMixin):
    phone_numbers = JSONField(default=dict, blank=True)

    def __str__(self):
        return 'UserProfile #{}'.format(self.id)

    @classmethod
    def get_queryset(cls, request=None, **kwargs):
        try:
            user_uuid = request.parser_context['kwargs']['parent_lookup_uuid']
        except KeyError:
            # From schema generator
            return cls.objects.none()
        user = User.objects.get(uuid=user_uuid)
        if not request.user.has_perm('lock8.view_user', user):
            raise Http404()
        return cls.objects.filter(user=user).distinct()


class UserStates(Enum):
    NEW = 'new'
    DISABLED = 'disabled'


class UserQuerySet(NullsLastQuerySet):
    def annotate_with_full_name(self):
        return self.annotate(full_name=Concat(
            'first_name', Value(' '), 'last_name'))

    def annotate_with_is_admin_of_lock8(self):
        return self.annotate(is_admin_of_lock8=Case(
            When(affiliation__role=Affiliation.ADMIN,
                 affiliation__organization__level=0,
                 then=True),
            default=F('is_superuser'),
            output_field=models.BooleanField())).order_by(
                '-is_admin_of_lock8')

    def annotate_with_trigram(self, *args, term):
        similarities = functools.reduce(lambda x, y: x+y, [
            TrigramSimilarity(expression, term) for expression in args])
        return self.annotate(similarity=similarities).order_by(
            F('similarity').desc())


class UserManager(DjangoUserManager.from_queryset(UserQuerySet)):
    def get_by_natural_key(self, username):
        return (self.annotate_with_is_admin_of_lock8()
                .distinct()
                .filter(**{self.model.USERNAME_FIELD: username})[:1]
                .get())

    def filter_local_users(self, *args, **kwargs):
        return self.filter(
            social_auth__user__isnull=True,
            organization__isnull=True,
            *args, **kwargs)

    def filter_local_whitelabel_users(self, organization, *args, **kwargs):
        return self.filter(
            social_auth__user__isnull=True,
            organizations=organization,
            organization=organization,
            *args, **kwargs)

    def filter_social_users(self, *args, **kwargs):
        return self.filter(
            social_auth__user__isnull=False,
            organization__isnull=True,
            *args, **kwargs)

    def filter_social_whitelabel_users(self, organization, *args, **kwargs):
        return self.filter(
            social_auth__user__isnull=False,
            organizations=organization,
            organization=organization,
            *args, **kwargs)


class ActiveUserManager(UserManager):
    def get_queryset(self):
        return super().get_queryset().filter(is_active=True)


class User(BaseModelMixin, AbstractUser, ActionableModelMixin,
           OwnerableModelMixin):
    organizations = models.ManyToManyField('lock8.Organization',
                                           through=Affiliation,
                                           related_name='members',
                                           related_query_name='member',
                                           blank=True)
    organization = models.ForeignKey(
        'lock8.Organization',
        related_name='whitelabel_members',
        related_query_name='whitelabel_member',
        blank=True,
        null=True,
        help_text='White Label users can belong to only one organization.',
        on_delete=models.PROTECT,
    )
    avatar = models.URLField(max_length=254, blank=True, null=True)
    profile = models.OneToOneField(UserProfile, blank=True, null=True,
                                   on_delete=models.SET_NULL)
    representative = models.ForeignKey(
        'lock8.User',
        related_name='shadowed_users',
        related_query_name='shadowed_user',
        null=True,
        blank=True,
        on_delete=models.SET_NULL,
        help_text='The target is returned during authentication',
    )
    subscription_plans = models.ManyToManyField(
        'lock8.SubscriptionPlan',
        through='PlanPass',
        related_name='users',
        related_query_name='user',
        blank=True)
    terms_of_services = models.ManyToManyField(
        'lock8.TermsOfService',
        through='AcceptedTermsOfService',
        related_name='users',
        related_query_name='user',
        blank=True)
    state = FSMField(default=UserStates.NEW.value, db_index=True)

    objects = UserManager()
    actives = ActiveUserManager()

    class Meta(AbstractUser.Meta, BaseModelMixin.Meta):
        pass

    def __str__(self):
        orgs = self.member_of
        names = orgs.split(',')
        memberships = ('{} (...)'.format(','.join(names[:3]))
                       if len(names) > 3
                       else orgs)
        name = self.get_full_name()
        if not name:
            name = self.username
            if not name:
                name = str(self.uuid)
        return '{} (member of {!r})'.format(name, memberships)

    def __repr__(self):
        affs = [(x.organization, x.role) for x in self.affiliations.all()]
        return 'User(pk=%r, email=%r, affiliations=%r, organization=%r)' % (
            self.pk, self.email, affs, self.organization)

    @classmethod
    def get_queryset(cls, request=None, **kwargs):
        """
        Either return Users that are affiliated to the Organization
        and descendants of the current user if they are an
        ``admin`` or a ``fleet_operator``.
        Returns only the current user's account.
        """
        user = request.user
        predicate = Q(
            affiliation__organization__in=user.
            get_descendants_managed_organizations())
        if user.is_admin_of_lock8:
            predicate |= Q(affiliation__isnull=True)
            qs = cls.objects
        else:
            qs = cls.actives

        org_uuid = request.query_params.get('organization', None)
        if org_uuid:
            try:
                org_uuid = UUIDField().to_python(org_uuid)
            except ValidationError:
                return cls.objects.none()
            predicate &= Q(affiliation__organization__uuid=org_uuid)

        if (not org_uuid or
                user.get_descendants_organizations(
                    Q(uuid=org_uuid)).exists()):
            predicate |= Q(pk=user.pk)

        return qs.filter(predicate).distinct()

    @property
    def display_name(self):
        full_name = self.get_full_name()
        if len(full_name):
            return full_name
        username = (self.get_username() if self.social_auth.exists()
                    else self.get_username().split('-', 1)[0])
        if len(username):
            return username
        if len(self.email):
            return self.email
        return str(self.uuid)

    @property
    def admin_list_name(self):
        """Property to be used in admin lists (no joins, PK is OK)."""
        full_name = self.get_full_name()
        if len(full_name):
            return full_name
        username = self.get_username()
        if len(username):
            return username
        if len(self.email):
            return self.email
        return f'#{self.pk}'

    @classmethod
    def generate_username_from_email(cls, email, organization_uuid=None):
        for __ in range(1, 10):
            slug = '-'.join((
                slugify(email),
                str(organization_uuid) if organization_uuid else '',
                slugify(random())))
            if not cls.objects.filter(username=slug).exists():
                return slug
        raise DuplicateContentError(detail='Unable to slug username.')

    @property
    def is_client_app(self):
        return self.clientapp_set.exists()

    def get_organizations(self, predicate=Q()):
        """
        Return Organizations where the user is currently affiliated to.
        """
        return Organization.objects.filter(
            predicate &
            Q(affiliation__user=self)
        ).select_related('parent')

    def get_descendants_organizations(self, predicate=Q()):
        """
        Return Organizations and sub Organizations
        where the user is currently affiliated to.

        It gives the availibility for lock8's staff to see everything.
        Or gives access for organization's members to access resources
        of subsidiaries.
        """
        return Organization.objects.get_queryset_descendants(
            self.get_organizations(predicate=predicate),
            include_self=True)

    def get_descendants_managed_organizations(self, predicate=Q()):
        """
        Return Organizations and sub Organizations
        where the user is currently affiliated to as
        an ``admin`` or a ``fleet_operator`` or the base Organization.

        It gives the availibility for lock8's staff to see everything.
        Or gives access for Fleet Operator to access resources
        of their subsidiaries.
        """
        predicate = predicate & Q(affiliation__role__in=(
            Affiliation.FLEET_OPERATOR,
            Affiliation.SUPERVISOR,
            Affiliation.ADMIN))
        return self.get_descendants_organizations(predicate=predicate)

    @property
    def member_of(self):
        return ', '.join(x.name for x in self.organizations.all())

    @property
    def active_reservations(self):
        return self.reservations.filter(state=ReservationStates.NEW.value)

    @property
    def active_reservation(self):
        try:
            return self.active_reservations.get()
        except Reservation.DoesNotExist:
            pass

    @property
    def active_rental_sessions(self):
        return self.rental_sessions.filter(state=RentalSessionStates.NEW.value)

    @property
    def active_rental_session(self):
        try:
            return self.active_rental_sessions.get()
        except RentalSession.DoesNotExist:
            pass

    @property
    def is_local(self):
        try:
            return not bool(self._social_auth)
        except AttributeError:
            return not self.social_auth.all().exists()

    def publish_activated_event(self):
        def post_commit_handler():
            redis = get_redis_connection('publisher')
            topic = f'/activation/{self.email}'
            payload = {'sender': 'user',
                       'topic': topic,
                       'message': {'is_active': True}}
            message = json.dumps(payload)
            redis.publish(topic, message)
        transaction.on_commit(post_commit_handler)

    def get_org_for_email(self):
        if self.organization and self.organization.is_whitelabel:
            return self.organization
        return Organization.get_root_org()

    def _get_email_org_context(self):
        org = self.get_org_for_email()
        return {
            'user': self,
            'organization_name': org.name,
            'app_download_url': org.app_download_url,
            'logo': org.user_email_logo,
            'support_email': org.get_preference('support_email'),
        }

    def send_welcome_email(self):
        context = self._get_email_org_context()
        title = f"Welcome to {context['organization_name']}."
        try:
            send_email(title, [self.email],
                       'email/renter_welcome.txt',
                       template_html='email/renter_welcome.html',
                       context=context)
        except Exception:
            logger.error('Failed to send welcome email for user %s', self)
            raise

    def send_activation_email(self):
        context = self._get_email_org_context()
        token = default_token_generator.make_token(self)
        activation_url = (f'{settings.FRONTEND_ACTIVATE_URL}'
                          f'?uuid={self.uuid}&token={token}')
        context['activation_url'] = activation_url
        title = (f"{context['organization_name']} "
                 f"- {settings.ACTIVATION_EMAIL_SUBJECT}")
        send_email(title, [self.email],
                   'email/user_activation.txt',
                   template_html='email/user_activation.html',
                   context=context)

    def send_password_reset_email(self):
        context = self._get_email_org_context()
        token = default_token_generator.make_token(self)
        if not self.organizations.exclude(
                affiliation__role=Affiliation.RENTER).exists():
            reset_url = '{}/{}/{}/?{}'.format(
                settings.FRONTEND_RESET_URL,
                token, str(self.uuid),
                urlencode({'email': self.email})
            )
        else:
            reset_url = '{}/reset/{}/{}/?{}'.format(
                settings.FRONTEND_URL,
                token, str(self.uuid),
                urlencode({'email': self.email})
            )
        context['username'] = '{user.first_name}'.format(user=self)
        context['reset_url'] = reset_url
        title = (f"{context['organization_name']} "
                 f"- {settings.RESET_EMAIL_SUBJECT}")
        send_email(title, [self.email],
                   'email/user_password_reset.txt',
                   template_html='email/user_password_reset.html',
                   context=context)

    @fsm_log_by
    @transition(field=state,
                source=UserStates.NEW.value,
                target=UserStates.DISABLED.value)
    def disable(self, **kwargs):
        """set inactive"""
        self.is_active = False

    @fsm_log_by
    @transition(field=state,
                source=UserStates.DISABLED.value,
                target=UserStates.NEW.value)
    def enable(self, **kwargs):
        """set active"""
        self.is_active = True

    def get_customer(self, organization):
        stripe_account = organization.stripe_account
        return self.customers.get(
            user_account__account=stripe_account)

    def get_or_create_customer(self, organization):
        stripe_account = organization.stripe_account
        if stripe_account is None:
            raise ValidationError({
                'organization': 'The organization does not use payments.'})
        try:
            return self.get_customer(organization), False
        except Customer.DoesNotExist:
            try:
                with transaction.atomic():
                    return pinax.stripe.actions.customers.create(
                        self, stripe_account=stripe_account), True
            except IntegrityError:
                return self.get_customer(organization), False

    def recreate_missing_stripe_customer(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            callargs = inspect.getcallargs(f, *args, **kwargs)
            user = callargs['self']
            organization = callargs['organization']

            try:
                return f(*args, **kwargs)
            except stripe.error.InvalidRequestError as exc:
                if (exc.param == 'customer' and
                        exc.args[0].startswith('No such customer:')):
                    customer, _ = user.get_or_create_customer(organization)
                    customer.delete()
                    return f(*args, **kwargs)
                raise exc
        return wrapper

    @recreate_missing_stripe_customer
    def get_stripe_ephemeralkey(self, stripe_api_version, organization):
        customer, _ = self.get_or_create_customer(organization)
        stripe_account_id = organization.stripe_account.stripe_id
        customer_stripe_id = customer.stripe_id
        try:
            return stripe.EphemeralKey.create(
                customer=customer_stripe_id,
                stripe_account=stripe_account_id,
                stripe_version=stripe_api_version)
        except stripe.error.InvalidRequestError as exc:
            if exc.args[0].startswith('Invalid Stripe API version: '):
                raise ValidationError({'stripe_api_version': exc.args[0]})
            raise exc

    def accept_terms_of_service(self, terms_of_service):
        if terms_of_service.state != GenericStates.PROVISIONED.value:
            raise ValidationError('Terms of service is not provisioned')

        AcceptedTermsOfService.objects.get_or_create(
            user=self, terms_of_service=terms_of_service)

    def get_unpaid_rentalsessions(self, organization=None):
        qs = self.rental_sessions.filter(
            state=RentalSessionStates.CLOSED.value,
            payment_state=RentalSessionPaymentStates.FAILED.value,
        )
        if organization:
            qs = qs.filter(bicycle__organization=organization)
        return qs

    def get_paid_rentalsessions(self, organization=None):
        qs = self.rental_sessions.filter(
            state=RentalSessionStates.CLOSED.value,
            cents__gt=0,
            payment_state__in=(
                RentalSessionPaymentStates.PROCESSED.value,
                RentalSessionPaymentStates.TRANSFERRED.value,
            ))
        if organization:
            qs = qs.filter(bicycle__organization=organization)
        return qs

    def retry_failed_payments(self, org, debt=None) -> bool:
        if debt is None:
            debt, _ = self.get_debt_for_rentals(org)
        if not debt:
            return True

        customer = self.get_customer(org)
        sources = customer.stripe_customer.sources
        chargable_sources = [x for x in sources
                             if 'status' not in x or x.status == 'chargeable']
        for source in chargable_sources:
            if self.transfer_failed_payments(customer, source.id, debt):
                return True
        return False

    def get_debt_for_rentals(self, org=None):
        unpaid_rentals = self.get_unpaid_rentalsessions(org)

        debt = {}
        for rental_session in unpaid_rentals:
            assert rental_session.cents
            currency = rental_session.currency
            if currency not in debt:
                debt[currency] = [0, []]

            cents = rental_session.cents
            charge = rental_session.charge
            if charge and charge.paid and charge.captured:
                # Take into account already captured amount (when falling back
                # to capturing the 2h charge).
                assert charge.currency == currency
                already_paid_cents = charge.amount * 100
                assert cents > already_paid_cents
                cents -= already_paid_cents
            debt[currency][0] += cents
            debt[currency][1].append(rental_session)

        must_be_retried = False
        for currency, info in debt.items():
            cents, _ = info
            if cents >= 50:
                must_be_retried = True
                break

        return debt, must_be_retried

    def transfer_failed_payments(self, customer, stripe_card_id,
                                 debt=None) -> bool:
        org = customer.stripe_account.organization_set.get()
        if debt is None:
            debt, _ = self.get_debt_for_rentals(org)

        ok = True
        for currency, info in debt.items():
            cents, rental_sessions = info
            if cents < 50:
                logger.info('transfer_failed_payments: skipping for amount of less than 50 cents (%d)', cents)  # noqa: E501
                continue

            idempotency_key = 'retry-failed-payment-%s-%s-%s' % (
                self.uuid, stripe_card_id, currency)
            logger.info('transfer_failed_payments for %r (%s)',
                        customer, idempotency_key)

            new_charge = None
            try:
                create_charge_kwargs = {
                    'source': stripe_card_id,
                    'capture': False,
                    'amount': Decimal(cents) / 100,
                    'customer': customer,
                    'currency': currency,
                    'send_receipt': False,
                    'idempotency_key': idempotency_key,
                }
                try:
                    create_charge_kwargs['idempotency_key'] += '-capture'
                    new_charge = pinax.stripe.actions.charges.create(
                        **create_charge_kwargs)
                    new_charge_captured = False
                except stripe.error.InvalidRequestError as err:
                    if err.args[0] == (
                            'You cannot pass capture=false for this payment type.'):  # noqa: E501
                        create_charge_kwargs['capture'] = True
                        new_charge = pinax.stripe.actions.charges.create(
                            **create_charge_kwargs)
                        new_charge_captured = True
                    else:
                        raise

                logger.info('transfer_failed_payments: created charge %s',
                            new_charge.stripe_id)
                with transaction.atomic():
                    for rental_session in rental_sessions:
                        rental_session.transfer_payment(new_charge)

                    if not create_charge_kwargs['capture']:
                        pinax.stripe.actions.charges.capture(new_charge)
            except Exception as exc:
                if not self.get_unpaid_rentalsessions(org):
                    # This might happen if process_pending_payments was called
                    # through an event already.
                    logger.info('transfer_failed_payments: all paid (%s)',
                                exc)
                    return True

                logger.exception('transfer_failed_payments: %r', exc)
                ok = False

                if new_charge:
                    if not new_charge_captured:
                        try:
                            new_charge.stripe_charge.refund()
                            logger.info('transfer_failed_payments: refund: %s',
                                        new_charge.stripe_id)
                        except Exception as exc:
                            logger.exception('transfer_failed_payments: failed to refund: %r',  # noqa: E501
                                             exc)
                    else:
                        logger.warning(
                            'transfer_failed_payments: cannot refund: %s', exc)
        return ok


# HACKISH django doesn't allow field override, even from Abstract Models
# Change max length of username field
username_field = User._meta.get_field('username')
username_field.max_length = 254
username_field.help_text = _('Required. 254 characters or fewer.'
                             ' Letters, digits and @/./+/-/_ only.')
for i, v in enumerate(username_field.validators):
    if isinstance(v, MaxLengthValidator):
        new_v = MaxLengthValidator(254)
        username_field.validators[i] = new_v

# make owner field optional (chicken egg problem)
owner_field = User._meta.get_field('owner')
owner_field.null = True

# compliant with RFCs 3696 and 5321
email_field = User._meta.get_field('email')
email_field.max_length = 254
for i, v in enumerate(email_field.validators):
    if isinstance(v, MaxLengthValidator):
        new_v = MaxLengthValidator(254)
        email_field.validators[i] = new_v


class ClientApp(BaseModelMixin, OwnerableModelMixin,
                OrganizationOwnedModelMixin):
    PERMISSION_SCOPE_MAPPING = {
        'bicycle:read': {'lock8.view_bicycle',
                         'lock8.view_bicycle_transitions',
                         'lock8.view_bicycle_pricings',
                         'lock8.view_bicycle_otp',
                         },
        'bicycle:write': {'lock8.add_bicycle',
                          'lock8.change_bicycle',
                          'lock8.put_in_maintenance_bicycle',
                          'lock8.declare_available_bicycle',
                          'lock8.declare_lost_bicycle',
                          'lock8.declare_unrecoverable_bicycle',
                          'lock8.reserve_bicycle',
                          'lock8.rent_bicycle',
                          'lock8.force_put_in_maintenance_bicycle',
                          'lock8.take_over_bicycle',
                          'lock8.cancel_reservation_bicycle',
                          'lock8.return_bicycle',
                          'lock8.retire_bicycle',
                          },
        'trip:read': {'lock8.view_trip'},
        'organization:read': {'lock8.view_organization'},
        # For production software, don't increase the list of permissions
        # as we just want to authorize creation.
        'lock:write': {'lock8.add_lock'},
        'zone:read': {'lock8.view_zone'},
        'zone:write': {'lock8.add_zone',
                       'lock8.change_zone',
                       'lock8.delete_zone',
                       },
        'support-ticket:read': {'lock8.view_supportticket'},
        'support-ticket:write': {'lock8.add_supportticket',
                                 'lock8.change_supportticket',
                                 'lock8.delete_supportticket'},
    }
    SCOPES = [(s, s) for s in sorted(PERMISSION_SCOPE_MAPPING)]
    name = models.CharField(max_length=128)
    label = models.CharField(max_length=128, blank=True)
    organization = models.ForeignKey('Organization', on_delete=models.CASCADE)
    scopes = ArrayField(models.CharField(max_length=64, choices=SCOPES),
                        default=list, blank=True)
    remote_uuid = models.UUIDField()
    user = models.ForeignKey(User, on_delete=models.PROTECT)

    @property
    def remote_url(self):
        return settings.STS_BASE_URL + '/client_apps/{}/'.format(
            self.remote_uuid)

    class Meta(BaseModelMixin.Meta):
        unique_together = (
            ('name', 'organization'),
        )


class Organization(MPTTModel, BaseModelMixin, ActionableModelMixin,
                   OwnerableModelMixin):
    name = models.CharField(max_length=255)
    parent = TreeForeignKey('self', blank=True, null=True,
                            related_name='children',
                            on_delete=models.CASCADE)
    is_open_fleet = models.BooleanField(default=False)
    image = models.ImageField(upload_to='icons', max_length=254, blank=True)
    phone_numbers = JSONField(default=dict, blank=True)
    state = FSMField(default=GenericStates.NEW.value, db_index=True)
    feedback_category_tree = models.OneToOneField(
        'FeedbackCategory',
        related_name='organization',
        related_query_name='organization',
        blank=True, null=True,
        on_delete=models.SET_NULL,
    )
    allowed_signup_domain_names = JSONField(
        default=list, blank=True,
        help_text=(
            'The accepted list of email domain names for self-sign up.'
        ),
        validators=[validate_signup_domain_names]
    )
    stripe_account = models.ForeignKey(Account, blank=True, null=True,
                                       on_delete=models.SET_NULL)
    is_whitelabel = models.BooleanField(default=False)
    app_download_url = models.URLField(max_length=254, blank=True, null=True)
    user_email_logo = models.ImageField(
        upload_to='user_email_logo', max_length=254, blank=True)

    objects = TreeManager()

    def __str__(self):
        if self.parent_id is not None:
            return 'Organization[{}]/{}'.format(self.parent_id, self.name)
        return self.name

    def __repr__(self):
        return 'Organization(pk=%r, name=%r, uses_payments=%r)' % (
            self.pk, self.name, self.uses_payments)

    @classmethod
    def get_queryset(cls, request=None, **kwargs):
        user = request.user
        if user.is_anonymous:
            return cls.objects.none()
        try:
            email_domain = user.email.split('@', 1)[1]
        except IndexError:
            return user.get_descendants_organizations()
        predicate = Q(allowed_signup_domain_names__contains=[email_domain])
        return (user.get_descendants_organizations() |
                cls.objects.filter(predicate))

    @classmethod
    def get_root_org(cls):
        try:
            return cls._root_org
        except AttributeError:
            cls._root_org = cls.objects.get(tree_id=1, parent=None)
        return cls._root_org

    @property
    def stripe_publishable_key(self):
        with contextlib.suppress(AttributeError):
            return self.stripe_account.stripe_publishable_key

    @property
    def active_preference(self):
        try:
            return OrganizationPreference.objects.filter(
                organization__in=self.get_ancestors(include_self=True),
            ).order_by('-organization__level')[:1].get()
        except OrganizationPreference.DoesNotExist:
            pass

    def get_preference(self, name, default=NOT_SET):
        preference = self.active_preference
        if preference is None:
            if default is not NOT_SET:
                return default
            try:
                f = OrganizationPreference._meta.get_field(name)
            except FieldDoesNotExist:
                raise AttributeError('No preference found for {!r}.'.format(
                    name))
            default = f.default
            if default is NOT_PROVIDED:
                raise AttributeError(
                    'No default preference found for {!r}.'.format(name))
            return default
        return getattr(preference, name)

    def get_feedback_category_tree(self):
        ancestors = self.get_ancestors(include_self=True, ascending=True)
        return next(
            filter(None, (a.feedback_category_tree for a in ancestors))
        )

    @property
    def max_allowed_bicycles_per_renter(self):
        return self.get_preference('max_allowed_bicycles_per_renter',
                                   default=1)

    @property
    def allow_renting_without_pricings(self):
        return self.get_preference('allow_renting_without_pricings',
                                   default=True)

    @property
    def idle_bicycle_duration(self):
        return self.get_preference(
            'idle_bicycle_duration',
            default=settings.DEFAULT_IDLE_BICYCLE_DURATION,
        )

    @property
    def currency(self):
        return self.get_preference('currency',
                                   default=settings.DEFAULT_CURRENCY)

    @property
    def uses_payments(self):
        try:
            return self.stripe_account.authorized
        except AttributeError:
            return False


class Address(BaseModelMixin, OwnerableModelMixin,
              OrganizationOwnedModelMixin):
    organization = models.ForeignKey(Organization,
                                     null=True,
                                     related_name='addresses',
                                     related_query_name='address',
                                     on_delete=models.CASCADE,
                                     )
    email = models.EmailField(blank=True)
    phone_number = models.CharField(blank=True, max_length=128)
    text_address = models.TextField(default='')

    class Meta(BaseModelMixin.Meta):
        verbose_name_plural = "addresses"

    def __str__(self):
        return 'Organization[{}] {} {} {}'.format(
            self.organization_id,
            self.text_address,
            self.phone_number,
            self.email,
            )


class FeatureStates(Enum):
    NEW = 'new'
    ACTIVE = 'active'
    DEACTIVATED = 'deactivated'


class Feature(BaseModelMixin, OwnerableModelMixin):
    organizations = models.ManyToManyField(Organization,
                                           related_name='features',
                                           related_query_name='features')
    name = models.CharField(max_length=128)
    state = FSMField(default=FeatureStates.NEW.value, db_index=True)

    def __str__(self):
        return 'Feature[#{}] {}'.format(self.pk, self.name)

    @fsm_log_by
    @transition(field=state,
                source=(FeatureStates.NEW.value,
                        FeatureStates.DEACTIVATED.value),
                target=FeatureStates.ACTIVE.value)
    def activate(self, **kwargs):
        """no side effect"""
        pass

    @fsm_log_by
    @transition(field=state,
                source=FeatureStates.ACTIVE.value,
                target=FeatureStates.DEACTIVATED.value)
    def deactivate(self, **kwargs):
        """no side effect"""
        pass


class Firmware(BaseModelMixin, GenericStateMixin, OwnerableModelMixin,
               OrganizationOwnedModelMixin):
    NORDIC = '0'  # legacy
    XMEGA = '1'  # legacy
    MERCURY = '2'
    CHIPS = (
        (MERCURY, 'Mercury'),
        (NORDIC, 'Nordic'),  # legacy
        (XMEGA, 'Xmega'),  # legacy
    )
    name = models.CharField(max_length=30, blank=True)
    organization = models.ForeignKey(Organization,
                                     null=True,
                                     related_name='firmwares',
                                     related_query_name='firmware',
                                     on_delete=models.CASCADE,
                                     )
    chip = models.CharField(choices=CHIPS, max_length=1, blank=False)
    version = models.CharField(blank=True, max_length=40, db_index=True)
    binary = models.FileField(upload_to='firmwares',
                              storage=private_storage,
                              max_length=254,
                              blank=True)

    def __str__(self):
        return 'Organization[{}] {} {} {}'.format(
            self.organization_id,
            self.get_chip_display(),
            self.name,
            self.version,
            )

    def _provision(self, **kwargs):
        if not self.binary:
            raise ValidationError('A file is required')
        if not self.version:
            self.binary.delete()
            raise ValidationError('A version is required')

        if Firmware.objects.filter(
                state=GenericStates.PROVISIONED.value,
                chip=self.chip,
                lock__in=self.lock_set.all()).exists():
            self.binary.delete()
            raise ValidationError({
                NON_FIELD_ERRORS: [
                    "There is already a provisioned firmware assigned "
                    "to this lock and chip!"
                ]
            })


class ZoneQuerySet(models.QuerySet):

    def annotate_with_bicycle_count(self, tracking_table):
        return self.annotate(
            bicycle_count=RawSQL(
                f'select count(*) as bicycle_count '
                f'from lock8_bicycle '
                f'join {tracking_table} '
                f'  on lock8_bicycle.public_tracking_id = {tracking_table}.id '
                f'where st_dwithin('
                f'   {tracking_table}.point::geography, '
                f'   lock8_zone.polygon, '
                f'   ('
                f'       COALESCE(("{tracking_table}"."attributes" ->> \'gps_accuracy\')::double precision, 0) * '  # noqa: E501
                f'       COALESCE(("{tracking_table}"."attributes" ->> \'gps_pdop\')::double precision, 1)'  # noqa: E501
                f'   )'
                f') and lock8_bicycle.organization_id = lock8_zone.organization_id '  # noqa: E501
                f'and lock8_bicycle.state != \'retired\'',
                [],
                output_field=models.IntegerField()
            )
        )


class Zone(BaseModelMixin, ActionableModelMixin, GenericStateMixin, GeoModel,
           OrganizationOwnedModelMixin):
    DROP = 'dropzone'
    SERVICE = 'cycling_area'
    MAINTENANCE = 'maintenance'
    CUSTOM = 'custom'
    TYPE_ZONES = (
        (DROP, 'Dropzone'),
        (SERVICE, 'Service Area'),
        (MAINTENANCE, 'Maintenance'),
        (CUSTOM, 'Custom'),
    )
    owner = models.ForeignKey(settings.AUTH_USER_MODEL,
                              related_name='+',
                              on_delete=models.PROTECT,
                              )
    organization = models.ForeignKey(Organization,
                                     related_name='zones',
                                     related_query_name='zone',
                                     on_delete=models.CASCADE,
                                     )
    name = models.CharField(max_length=255, blank=True)
    polygon = MultiPolygonField(geography=True)
    alerts = GenericRelation('Alert', related_query_name='zones')
    type = models.CharField(
        max_length=12,
        choices=TYPE_ZONES,
        default=DROP,
    )
    preferred_mechanic = models.ForeignKey(
        User,
        related_name='zones',
        related_query_name='zone',
        null=True, blank=True, default=None,
        on_delete=models.SET_NULL,
    )
    description = models.TextField(
        blank=True,
        null=True,
        default=None,
        help_text='Meaning of custom zone.'
    )

    low_threshold = models.PositiveIntegerField(
        blank=True,
        default=None,
        null=True,
        verbose_name='Low threshold'
    )

    high_threshold = models.PositiveIntegerField(
        blank=True,
        default=None,
        null=True,
        verbose_name='High threshold'
    )

    objects = ZoneQuerySet.as_manager()

    def __str__(self):
        return '{} {} Organization[{}]'.format(
            self.name,
            self.get_type_display(),
            self.organization_id)

    @property
    def display_name(self):
        return self.name

    @property
    def has_thresholds(self) -> bool:
        if (self.low_threshold is not None or
                self.high_threshold is not None):
            return True
        return False


class LockStates(Enum):
    NEW = 'new'
    PROVISIONED = 'provisioned'
    ACTIVE = 'active'
    IN_MAINTENANCE = 'in_maintenance'
    DECOMMISSIONED = 'decommissioned'


PUBLIC_LOCKSTATES = (
    LockStates.ACTIVE.value,
    LockStates.IN_MAINTENANCE.value,
)


class LockLockedStates(Enum):
    UNLOCKED = 'unlocked'
    LOCKED = 'locked'


class LockMountedStates(Enum):
    UNMOUNTED = 'unmounted'
    MOUNTED = 'mounted'


class LatestTrackingsMixin(models.Model):
    """Mixin for bikes and locks."""
    class Meta:
        abstract = True

    public_tracking = models.OneToOneField('PublicTracking',
                                           related_name='+',
                                           on_delete=models.SET_NULL,
                                           blank=True, null=True)
    private_tracking = models.OneToOneField('PrivateTracking',
                                            related_name='+',
                                            on_delete=models.SET_NULL,
                                            blank=True, null=True)

    @property
    def estimated_state_of_charge(self):
        if self.state_of_charge is None or self.private_tracking is None:
            return
        return charge_estimator(self.state_of_charge,
                                self.private_tracking.dt.timestamp())

    @property
    def latest_gps_accuracy(self):
        try:
            return self.private_tracking.gps_accuracy
        except AttributeError:
            pass

    @property
    def latest_gps_pdop(self):
        try:
            return self.private_tracking.gps_pdop
        except AttributeError:
            pass

    @property
    def latest_gps_timestamp(self):
        try:
            return self.private_tracking.gps_timestamp
        except AttributeError:
            pass

    @property
    def latitude(self):
        try:
            return self.private_tracking.gps_latitude
        except AttributeError:
            pass

    @property
    def longitude(self):
        try:
            return self.private_tracking.gps_longitude
        except AttributeError:
            pass

    @property
    def state_of_charge(self):
        try:
            return float(self.private_tracking.state_of_charge)
        except (AttributeError, TypeError):
            pass

    @property
    def time_stamp(self):
        try:
            return self.private_tracking.time_stamp
        except AttributeError:
            pass

    @property
    def voltage(self):
        try:
            return self.private_tracking.voltage
        except AttributeError:
            pass


def generate_random_bytes(nb_bytes):
    """
    replacement of python3.6's secrets module.
    """
    # TODO replace with secrets.token_bytes
    return os.urandom(nb_bytes)


class SharedSecret(BaseModelMixin):
    value = models.BinaryField(default=functools.partial(generate_random_bytes,
                                                         20))

    @property
    def b64_value(self):
        return base64.b64encode(self.value).decode('ascii')


class Lock(BaseModelMixin, ActionableModelMixin, OwnerableModelMixin,
           LatestTrackingsMixin):
    TRACKER = 'tracker'
    LOCK = 'lock'
    TYPES = (
        (TRACKER, 'Tracker'),
        (LOCK, 'Lock'),
    )
    organization = models.ForeignKey(Organization,
                                     null=True,
                                     related_name='locks',
                                     related_query_name='lock',
                                     on_delete=models.PROTECT,
                                     )
    counter = models.PositiveIntegerField()
    serial_number = models.CharField(max_length=64,
                                     unique=True)
    imei = models.CharField(max_length=15, unique=True,
                            validators=[validate_imei],
                            help_text=r'Format: \d{15}')
    iccid = models.CharField(max_length=20, unique=True,
                             validators=[validate_iccid],
                             help_text=r'Format: \d{20}')
    sid = models.CharField(max_length=32,
                           blank=True,
                           validators=[validate_sid],
                           help_text=r'Format: [a-fA-F\d]{32}')
    bleid = models.CharField(max_length=128, unique=True)
    randblock = models.TextField(blank=True, max_length=2048)
    feedbacks = GenericRelation('Feedback', related_query_name='locks')
    alerts = GenericRelation('Alert', related_query_name='locks')
    tasks = GenericRelation('Task', related_query_name='locks')
    type = models.CharField(max_length=7, choices=TYPES, default=LOCK)
    state = FSMField(default=LockStates.NEW.value, db_index=True)
    locked_state = FSMField(default=LockLockedStates.UNLOCKED.value,
                            db_index=True)
    mounted_state = FSMField(default=LockMountedStates.UNMOUNTED.value,
                             db_index=True)
    firmwares = models.ManyToManyField(
        Firmware,
        through='LockFirmwareUpdate',
        blank=True)
    firmware_versions = JSONField(
        default=dict, blank=True,
        help_text="Dictionary of current/reported version per chip.")

    shared_secret = models.OneToOneField(SharedSecret, related_name='lock',
                                         on_delete=models.SET_NULL,
                                         blank=True, null=True)

    objects = NullsLastQuerySet.as_manager()

    def __str__(self):
        return '#{} ({}, org#{})'.format(
            self.pk if self.pk else '-',
            self.serial_number,
            self.organization_id)

    @classmethod
    def get_queryset(cls, request=None, **kwargs):
        user = request.user
        organizations = user.get_descendants_managed_organizations()
        return cls.objects.filter(
            organization__in=organizations).distinct()

    @property
    def firmware_version(self):
        try:
            return self.firmware_versions['mercury']
        except KeyError:
            try:
                return ' | '.join((self.firmware_versions[fw]
                                   for fw in ('xmega', 'nordic')))
            except KeyError:
                pass

    @property
    def paired_at(self):
        if hasattr(self, '_paired_lock_list'):
            if not self._paired_lock_list:
                return None
            last_connection = self._paired_lock_list[0]
        else:
            last_connection = (
                self.lock_connections
                    .order_by('-paired')
                    .first()
            )

        try:
            return last_connection.paired \
                if not last_connection.detached \
                else None
        except AttributeError:
            return None

    def clean(self):
        if not self.imei:
            raise ValidationError(_('imei must be defined.'))
        if not self.iccid:
            raise ValidationError(_('iccid must be defined.'))
        if not self.bleid:
            raise ValidationError(_('bleid must be defined.'))

        try:
            if self.bicycle.organization != self.organization:
                raise ValidationError({
                    'organization':
                    "Lock's Bicycle does not belong to the same Organization."
                })
        except self._meta.model.bicycle.RelatedObjectDoesNotExist:
            pass

    @fsm_log_by
    @transition(field=state,
                source=LockStates.NEW.value,
                target=LockStates.PROVISIONED.value)
    def provision(self, **kwargs):
        """
        No side effect
        """
        pass

    @fsm_log_by
    @transition(field=state,
                source=(LockStates.PROVISIONED.value,
                        LockStates.DECOMMISSIONED.value),
                target=LockStates.ACTIVE.value)
    def activate(self, **kwargs):
        """
        No side effect
        """
        pass

    @fsm_log_by
    @transition(field=state,
                source=LockStates.ACTIVE.value,
                target=LockStates.IN_MAINTENANCE.value)
    def put_in_maintenance(self, **kwargs):
        """
        No side effect
        """
        pass

    @fsm_log_by
    @transition(field=state,
                source=LockStates.IN_MAINTENANCE.value,
                target=LockStates.ACTIVE.value)
    def restore(self, **kwargs):
        """
        No side effect
        """
        pass

    @fsm_log_by
    @transition(field=state,
                source=(LockStates.IN_MAINTENANCE.value,
                        LockStates.ACTIVE.value),
                target=LockStates.DECOMMISSIONED.value)
    def decommission(self, **kwargs):
        """
        No side effect
        """
        pass

    @transition(field=locked_state,
                source=LockLockedStates.UNLOCKED.value,
                target=LockLockedStates.LOCKED.value)
    def lock(self, **kwargs):
        """
        No side effect
        """
        pass

    @transition(field=locked_state,
                source=LockLockedStates.LOCKED.value,
                target=LockLockedStates.UNLOCKED.value)
    def unlock(self, **kwargs):
        """
        No side effect
        """
        pass


class LockFirmwareUpdate(BaseModelMixin, OwnerableModelMixin,
                         GenericStateMixin):
    "A Firmware meant to be updated on a Lock."
    lock = models.ForeignKey('Lock',
                             related_name='locks',
                             related_query_name='lock',
                             on_delete=models.CASCADE,
                             )
    firmware = models.ForeignKey(Firmware,
                                 related_name='firmwares',
                                 related_query_name='firmware',
                                 on_delete=models.CASCADE,
                                 )

    objects = Manager()

    def validate_unique(self, exclude=None):
        """
        Check that each lock has only one firmware of a chip and type.
        """
        super().validate_unique(exclude)

        try:
            chip = self.firmware.chip
        except Firmware.DoesNotExist:
            pass
        else:
            if self.__class__.objects.exclude(pk=self.pk).filter(
                    lock=self.lock,
                    firmware__state=GenericStates.PROVISIONED.value,
                    firmware__chip=chip).exists():
                raise ValidationError({
                    NON_FIELD_ERRORS: [
                        "There is already a provisioned firmware assigned "
                        "to this lock and chip!"
                    ]
                })

    def __str__(self):
        return 'LockFirmwareUpdate: Lock #{} / Firmware #{}'.format(
            self.lock_id if self.lock_id else '<No lock>',
            self.firmware_id if self.firmware_id else '<No firmware>')


class AxaLockStates(Enum):
    NEW = 'new'
    CLAIMED = 'claimed'
    TRANSFERABLE = 'transferable'
    STORED = 'stored'


class AxaLock(BaseModelMixin, ActionableModelMixin, OwnerableModelMixin,
              metaclass=MetaJsonAccessorBuilder):
    organization = models.ForeignKey(Organization,
                                     null=True,
                                     related_name='axa_locks',
                                     related_query_name='axa_lock',
                                     on_delete=models.PROTECT,
                                     )
    remote_id = models.BigIntegerField(blank=True, null=True, default=None)
    uid = models.CharField(max_length=20, unique=True, db_index=True,
                           verbose_name='Bleid of device and'
                           ' lock_uid from remote API.')
    claim_code_at_creation = models.UUIDField()
    attributes = JSONField(default=dict, blank=True)
    state = FSMField(default=AxaLockStates.NEW.value, db_index=True)

    objects = NullsLastQuerySet.as_manager()

    # MetaJson
    meta_json_placeholder_name = 'attributes'

    exposed_attributes = (
        'firmware_modified',
        'firmware_version'
        'hardware_model',
        'hardware_version',
        'key',
        'lock_model',
        'lock_status',
        'lock_version',
        'mac_address',
        'nr_of_slots',
        'reference',
        'software_modified',
        'software_version',
        'claim_code',
        'battery_assessment',
        'battery_assessment_remarks',
        'cycles_performed',
    )

    def __str__(self):
        return '#{} (org#{})'.format(
            self.pk if self.pk else '-',
            self.organization_id)

    @classmethod
    def get_queryset(cls, request=None, **kwargs):
        user = request.user
        organizations = user.get_descendants_managed_organizations()
        return cls.objects.filter(
            organization__in=organizations).distinct()

    @property
    def bleid(self):
        return 'AXA:' + self.uid

    @property
    def remote_url(self):
        return settings.KEY_SAFE_BASE_URI + '/locks/{}'.format(self.remote_id)

    @property
    def paired_at(self):
        if hasattr(self, '_paired_axa_lock_list'):
            if not self._paired_axa_lock_list:
                return None
            last_connection = self._paired_axa_lock_list[0]
        else:
            last_connection = (
                self.axa_lock_connections
                    .order_by('-paired')
                    .first()
            )

        try:
            return last_connection.paired \
                if not last_connection.detached \
                else None
        except AttributeError:
            return None

    @fsm_log_by
    @transition(field=state,
                source=(AxaLockStates.NEW.value,
                        AxaLockStates.TRANSFERABLE.value),
                target=AxaLockStates.CLAIMED.value)
    def claim(self, dry_run=False, **kwargs):
        if dry_run:
            return
        response = keysafe_http_session.post(
            settings.KEY_SAFE_BASE_URI + '/locks',
            json={'claim_code': self.claim_code_at_creation.hex,
                  'lock_uid': self.uid})
        raise_for_response_status_with_context(response)
        result = response.json()['result']
        self.remote_id = result['id']
        self.attributes = result

    def _declare_state(self, state, dry_run=False, **kwargs):
        if dry_run:
            return
        response = keysafe_http_session.put(
            self.remote_url + '/status',
            json={'lock_status': state})
        raise_for_response_status_with_context(response)
        result = response.json()['result']
        self.attributes.update(result)

    @fsm_log_by
    @transition(field=state,
                source=AxaLockStates.CLAIMED.value,
                target=AxaLockStates.TRANSFERABLE.value)
    def declare_transferable(self, dry_run=False, **kwargs):
        self._declare_state(
            AxaLockStates.TRANSFERABLE.value,
            dry_run=dry_run,
            **kwargs
        )

    @fsm_log_by
    @transition(field=state,
                source=AxaLockStates.CLAIMED.value,
                target=AxaLockStates.STORED.value)
    def declare_stored(self, dry_run=False, **kwargs):
        self._declare_state(
            AxaLockStates.STORED.value,
            dry_run=dry_run,
            **kwargs
        )

    @fsm_log_by
    @transition(field=state,
                source=AxaLockStates.STORED.value,
                target=AxaLockStates.CLAIMED.value)
    def declare_active(self, dry_run=False, **kwargs):
        self._declare_state(
            'active',  # because of the difference in our/their statuses
            dry_run=dry_run,
            **kwargs
        )

    def sync(self):
        response = keysafe_http_session.get(self.remote_url)
        raise_for_response_status_with_context(response)
        result = response.json()['result']
        self.attributes.update(result)
        self.save()

    def obtain_otps(self, slot, nr_of_passkeys, hours):
        """Side effect: if otps were requested for `stored` AXA lock,
        this lock become `active` automatically at the AXA side.
        TODO: Maybe we need to add FSM transition for this case.
        """
        url = '/'.join((self.remote_url, 'slots', str(slot)))
        response = keysafe_http_session.put(
            url,
            json={'passkey_type': 'otp',
                  'nr_of_passkeys': nr_of_passkeys,
                  'hours': hours})
        raise_for_response_status_with_context(response)
        json = response.json()
        result = json['result']
        otps = result['passkey'].split('-')
        expiration = parse_datetime(json['now']) + dt.timedelta(hours=hours)
        assert len(otps) == nr_of_passkeys
        if result['slot_position'] != slot:
            logger.warning(f"Unexpected slot_position in response "
                           f"({result['slot_position']} != {slot}).")
        return result['ekey'], otps, expiration

    def update_health_status(self, lock_health_msg):
        url = '/'.join((self.remote_url, 'health'))
        response = keysafe_http_session.put(
            url, json={'lock_health_msg': lock_health_msg,
                       'reported_at': dt.datetime.now().isoformat()}
        )
        raise_for_response_status_with_context(response)
        json = response.json()
        self.attributes.update(json['result'])
        self.save()


class SendableModelMixin:
    def get_sendable_recipients_predicate(self):
        raise NotImplementedError

    @transaction.atomic()
    def send(self):
        predicate = self.get_sendable_recipients_predicate()
        if predicate is None:
            return
        recipients = User.actives.filter(predicate)
        for user in recipients:
            message = NotificationMessage.objects.create(
                user=user,
                causality=self,
            )
            with transaction.atomic():
                try:
                    message.send()
                except Exception as e:
                    logger.exception('Message sending failed: %s (%s)',
                                     e, message)

    def send_async(self):
        from velodrome.celery import sendable_task
        transaction.on_commit(functools.partial(
            sendable_task.delay,
            self.pk, self._meta.app_label, self._meta.model_name
        ))


class AlertStates(Enum):
    NEW = 'new'
    RESOLVED = 'resolved'
    ESCALATED = 'escalated'
    STOPPED = 'stopped'
    SILENCED = 'silenced'


class AlertQuerySet(models.QuerySet):
    def count_by_type(self, predicate):
        return (self.filter(predicate,
                            state=AlertStates.NEW.value)
                .values('alert_type')
                .annotate(total=Count('alert_type'))
                .order_by('-total'))

    def annotate_with_causative_bicycle_uuid(self):
        return self.annotate(
            causative_bicycle_uuid=Case(
                When(bicycles__isnull=False,
                     then=F('bicycles__uuid')),
                When(locks__bicycle__isnull=False,
                     then=F('locks__bicycle__uuid')),
                When(feedbacks__bicycles__isnull=False,
                     then=F('feedbacks__bicycles__uuid')),
                When(tasks__bicycles__isnull=False,
                     then=F('tasks__bicycles__uuid')),
                default=None,
            ),
            # For Alert.extra.
            causative_bicycle_name=Case(
                When(bicycles__isnull=False,
                     then=F('bicycles__name')),
                When(locks__bicycle__isnull=False,
                     then=F('locks__bicycle__name')),
                When(feedbacks__bicycles__isnull=False,
                     then=F('feedbacks__bicycles__name')),
                When(tasks__bicycles__isnull=False,
                     then=F('tasks__bicycles__name')),
                default=None,
            ),
            causative_bicycle_state=Case(
                When(bicycles__isnull=False,
                     then=F('bicycles__state')),
                When(locks__bicycle__isnull=False,
                     then=F('locks__bicycle__state')),
                When(feedbacks__bicycles__isnull=False,
                     then=F('feedbacks__bicycles__state')),
                When(tasks__bicycles__isnull=False,
                     then=F('tasks__bicycles__state')),
                default=None,
            ),
            causative_bicycle_attributes=Case(
                When(bicycles__isnull=False,
                     then=F('bicycles__public_tracking__attributes')),
                When(locks__bicycle__isnull=False,
                     then=F('locks__bicycle__public_tracking__attributes')),
                When(feedbacks__bicycles__isnull=False,
                     then=F('feedbacks__bicycles__public_tracking__attributes')),  # noqa: E501
                When(tasks__bicycles__isnull=False,
                     then=F('tasks__bicycles__public_tracking__attributes')),
                default=None,
            ),
            # TODO: Try to prefetch whole bicycle model object (if possible)
        )


class Alert(BaseModelMixin, FinalCausalityModelMixin, ActionableModelMixin,
            NotificationMessageDeleteMixin, SendableModelMixin,
            OrganizationOwnedModelMixin):
    LOW_BATTERY = 'lock.bat.low'
    RIDE_OUTSIDE_SERVICE_AREA = 'bicycle.ride_outside'
    RETURN_OUTSIDE_DROP_ZONE = 'bicycle.return_outside'
    NO_TRACKING_RECEIVED_SINCE = 'lock.no_tracking'
    LOST_BICYCLE_REPORTED = 'bicycle.lost_reported'
    USAGE_OUTSIDE_OPERATIONAL_PERIOD = 'bicycle.outside_operational_period'
    BICYCLE_IDLE_FOR_TOO_LONG = 'bicycle.too_long_idle'
    BICYCLE_LEFT_UNLOCKED = 'bicycle.left_unlocked'
    DEVICE_SHUTDOWN = 'lock.shutdown'
    LOCKED_BUT_CABLE_NOT_PRESENT = 'lock.locked_wo_cable'
    BICYCLE_STOLEN = 'bicycle.bike_stolen'
    LOCK_ALARM_TRIGGERED = 'lock.alarm_triggered'
    ZONE_HIGH_THRESHOLD_TRIGGERED = 'zone.high_threshold'
    ZONE_LOW_THRESHOLD_TRIGGERED = 'zone.low_threshold'

    TYPES = (
        (LOW_BATTERY, 'Low Battery'),
        (RIDE_OUTSIDE_SERVICE_AREA, 'Outside Service Area'),
        (NO_TRACKING_RECEIVED_SINCE, 'Device Not Reporting'),
        (RETURN_OUTSIDE_DROP_ZONE, 'Outside Dropzone'),
        (LOST_BICYCLE_REPORTED, 'Lost Bicycle Reported'),
        (USAGE_OUTSIDE_OPERATIONAL_PERIOD, 'Bicycle is used outside'
         ' operational period'),
        (BICYCLE_IDLE_FOR_TOO_LONG, 'No Recent Rides'),
        (BICYCLE_LEFT_UNLOCKED, 'Bicycle left unlocked'),
        (DEVICE_SHUTDOWN, 'Device Shutdown'),
        (LOCKED_BUT_CABLE_NOT_PRESENT, 'Bicycle was locked without a cable'),
        (ZONE_HIGH_THRESHOLD_TRIGGERED, 'Zone has reached a high threshold'),
        (ZONE_LOW_THRESHOLD_TRIGGERED, 'Zone has reached a low threshold'),
        # To be removed.
        (BICYCLE_STOLEN, 'Bicycle being stolen'),
        (LOCK_ALARM_TRIGGERED, 'Alarm of lock triggered'),
    )
    organization = models.ForeignKey(Organization,
                                     related_name='alerts',
                                     related_query_name='alert',
                                     on_delete=models.CASCADE,
                                     )
    owner = models.ForeignKey(settings.AUTH_USER_MODEL,
                              related_name='+',
                              blank=True, null=True,
                              on_delete=models.CASCADE,
                              )
    user = models.ForeignKey(User,
                             related_name='alerts',
                             related_query_name='alert',
                             blank=True, null=True,
                             on_delete=models.SET_NULL,
                             )
    # deprecated
    role = models.CharField(max_length=25,
                            choices=list(Affiliation.ROLES),
                            blank=True)
    roles = ArrayField(models.CharField(max_length=25,
                                        choices=list(Affiliation.ROLES)),
                       blank=True)
    content_type = models.ForeignKey(ContentType, on_delete=models.PROTECT)
    object_id = models.PositiveIntegerField()
    causality = GenericForeignKey('content_type', 'object_id')

    alert_type = models.CharField(max_length=64,
                                  choices=TYPES)
    message = models.TextField(blank=True)
    tasks = GenericRelation('Task', related_query_name='alerts')
    notification_messages = GenericRelation('NotificationMessage',
                                            related_query_name='alerts')
    context = JSONField(default=dict, blank=True, null=True,
                        verbose_name='Context provided during creation')
    state = FSMField(default=AlertStates.NEW.value, db_index=True)

    objects = AlertQuerySet.as_manager()

    def __str__(self):
        return 'Organization[{}] / {} / {}'.format(
            self.organization_id,
            self.alert_type,
            self.get_role_display(),
        )

    def __repr__(self):
        return 'Alert(pk=%r, alert_type=%r, state=%r)' % (
            self.pk,
            self.alert_type,
            self.state,
        )

    @property
    def display_time(self):
        tz_name = self.organization.get_preference('timezone')
        loc_tz = pytz.timezone(tz_name)
        loc_dt = loc_tz.normalize(self.created.replace(microsecond=0))
        return '{} {}'.format(dt.datetime.strftime(loc_dt, '%a, %d %b %Y %T'),
                              tz_name)

    @property
    def description(self):
        return dict(Alert.TYPES)[self.alert_type]

    @property
    def frontend_uri(self):
        path = 'alerts/alert/{}'.format(self.uuid)
        return urljoin(settings.FRONTEND_URL, path)

    def get_sendable_recipients_predicate(self):
        users = Q(affiliation__organization=self.organization,
                  affiliation__role__in=self.roles)
        if self.user_id:
            users |= Q(id=self.user_id)
        predicate = users & ~Q(notification_message__alerts=self)
        return predicate

    @property
    def extra(self):
        result = self.context.copy()
        extra_keys = (
            'bicycle_gps_accuracy',
            'bicycle_model_name',
            'bicycle_model_photo',
            'bicycle_name',
            'bicycle_state',
            'bicycle_uuid',
        )
        for key in extra_keys:
            result[key] = None

        # bicycle
        try:
            # In case Alert was loaded by Queryset
            # with method `annotate_with_causative_bicycle_uuid`,
            # which means it has already preloaded all needed data
            if self.causative_bicycle_attributes:
                result['bicycle_gps_accuracy'] = (
                    self.causative_bicycle_attributes.get('gps_accuracy')
                )
                result['bicycle_gps_latitude'] = (
                    self.causative_bicycle_attributes.get('gps_latitude')
                )
                result['bicycle_gps_longitude'] = (
                    self.causative_bicycle_attributes.get('gps_longitude')
                )
                long = self.causative_bicycle_attributes.get('gps_longitude')
                lat = self.causative_bicycle_attributes.get('gps_latitude')
                result['bicycle_coordinates'] = (
                        long / 1e6,
                        lat / 1e6
                )
            result['bicycle_name'] = self.causative_bicycle_name
            result['bicycle_state'] = self.causative_bicycle_state
            if self.causative_bicycle_uuid:
                result['bicycle_uuid'] = str(self.causative_bicycle_uuid)
        except AttributeError:
            if isinstance(self.causality, Bicycle):
                result['bicycle_gps_accuracy'] = self.causality.latest_gps_accuracy  # noqa
                result['bicycle_name'] = self.causality.name
                result['bicycle_state'] = self.causality.state
                result['bicycle_uuid'] = str(self.causality.uuid)

        # lock and bicycle model
        bicycle_model = None
        if isinstance(self.causality, Bicycle):
            if self.causality.lock is not None:
                result['lock_uuid'] = str(self.causality.lock.uuid)
                result['lock_bleid'] = self.causality.lock.bleid
            bicycle_model = self.causality.model
        elif isinstance(self.causality, Lock):
            result['lock_uuid'] = str(self.causality.uuid)
            result['lock_bleid'] = self.causality.bleid
            try:
                bicycle_model = self.causality.bicycle.model
            except AttributeError:
                pass

        if bicycle_model is not None:
            result['bicycle_model_name'] = bicycle_model.name
            if bicycle_model.photo:
                result['bicycle_model_photo'] = (
                    bicycle_model.photo.image.url
                )

        return result

    @fsm_log_by
    @transition(field=state,
                source=AlertStates.NEW.value,
                target=AlertStates.RESOLVED.value)
    def resolve(self, **kwargs):
        """
        User decision.
        """
        pass

    @fsm_log_by
    @transition(field=state,
                source=AlertStates.NEW.value,
                target=GET_STATE(
                    lambda self, *args, **kwargs: (
                        AlertStates.STOPPED.value
                        if self.alert_type == Alert.LOST_BICYCLE_REPORTED
                        else AlertStates.SILENCED.value),
                    states=[AlertStates.SILENCED.value,
                            AlertStates.STOPPED.value]))
    def silence(self, **kwargs):
        """
        Will prevent creating further alerts until the alert is stopped
        Note that LOST_BICYCLE_REPORTED alerts are automatically stopped
        when user is silencing them.
        """
        pass

    @fsm_log_by
    @transition(field=state,
                source=(
                    AlertStates.NEW.value,
                    AlertStates.ESCALATED.value,
                    AlertStates.SILENCED.value),
                target=AlertStates.STOPPED.value)
    def stop(self, dry_run=False, **kwargs):
        """
        System decision.
        Also cancel active tasks if escalated automatically.
        """
        if dry_run:
            return
        if self.state == AlertStates.ESCALATED.value:
            for task in self.tasks.filter(
                    state__in=(TaskStates.UNASSIGNED.value,
                               TaskStates.ASSIGNED.value),
                    assignor__isnull=True):
                task.cancel(**kwargs)

    @fsm_log_by
    @transition(field=state,
                source=AlertStates.NEW.value,
                target=AlertStates.ESCALATED.value)
    def escalate(self, by=None, severity=None, description=None,
                 role=None, dry_run=False, **kwargs):
        """
        User decision to close the alert by creating a Task.
        """
        if dry_run:
            return
        admin = User.objects.get(username='root_admin')
        task = Task.objects.create(
            organization=self.organization,
            causality=self,
            assignor=by,
            role=role if role else self.roles[0],  # XXX roles[0]
            severity=severity,
            context={'description': description},
            owner=admin,
        )
        task.send()


class ReturnOutsideDropZone():
    type = Alert.RETURN_OUTSIDE_DROP_ZONE
    message_template = ('Bike {self.causality.name!r} with Lock'
                        ' {self.causality.lock.bleid!r} is returned outside'
                        ' drop zone.')
    causality_type = 'bicycle'
    role = Affiliation.FLEET_OPERATOR

    def __init__(self, causality):
        self.causality = causality

    def as_message(self):
        return self.message_template.format(self=self)

    def process(self):
        if self.must_create:
            maybe_create_and_send_alert(
                self.causality, self.type,
                self.as_message(),
                default_roles=[self.role])
        if self.must_stop:
            predicate = Q(state__in=(AlertStates.NEW.value,
                                     AlertStates.SILENCED.value,
                                     AlertStates.ESCALATED.value),
                          alert_type=self.type)
            for alert in self.causality.alerts.filter(predicate):
                alert.stop()

    @property
    def must_create(self):
        if self.causality is None:
            return False
        if self.causality.state in (BicycleStates.IN_MAINTENANCE.value,
                                    BicycleStates.RETIRED.value):
            return False
        return not self.causality.is_allowed_to_be_dropped

    @property
    def must_stop(self):
        if self.causality is None:
            return False
        if self.causality.state in (BicycleStates.IN_MAINTENANCE.value,
                                    BicycleStates.RETIRED.value):
            return False
        return self.causality.is_allowed_to_be_dropped


class AlertMessageStates(Enum):
    NEW = 'new'
    SENT = 'sent'
    ERROR = 'error'
    ACKNOWLEDGED = 'acknowledged'


class AlertMessage(BaseModelMixin, ActionableModelMixin):
    alert = models.ForeignKey(Alert,
                              related_name='alert_messages',
                              related_query_name='alert_message',
                              on_delete=models.CASCADE,
                              )
    user = models.ForeignKey(User,
                             related_name='alert_messages',
                             related_query_name='alert_message',
                             on_delete=models.CASCADE,
                             )

    state = FSMField(default=AlertMessageStates.NEW.value,
                     db_index=True)

    def __str__(self):
        return 'User[{}] / Alert[{}]'.format(
            self.user_id,
            self.alert_id,
        )

    @fsm_log_by
    @transition(field=state,
                source='*',
                target=AlertMessageStates.SENT.value,
                on_error=AlertMessageStates.ERROR.value)
    def send(self, **kwargs):
        raise NotImplementedError

    @fsm_log_by
    @transition(field=state,
                source=AlertMessageStates.ERROR.value,
                target=AlertMessageStates.SENT.value)
    def retry(self, **kwargs):
        raise NotImplementedError

    @fsm_log_by
    @transition(field=state,
                source=AlertMessageStates.SENT.value,
                target=AlertMessageStates.ACKNOWLEDGED.value)
    def acknowledge(self, **kwargs):
        raise NotImplementedError


class SupportTicketStates(Enum):
    NEW = 'new'
    PENDING = 'pending'
    RESOLVED = 'resolved'
    CLOSED = 'closed'


class SupportTicket(BaseModelMixin, OrganizationOwnedModelMixin,
                    OwnerableModelMixin):
    REQUEST_BICYCLE = 'location_needs_bicycles'
    LOST_BICYCLE = 'bicycle_missing'
    DAMAGED_BICYCLE = 'bicycle_damaged'
    CATEGORIES = (
        (REQUEST_BICYCLE, 'Bicycles requested by a rider'),
        (LOST_BICYCLE, "Rider couldn't find a bicycle"),
        (DAMAGED_BICYCLE, 'Rider reported a damaged bicycle'),
    )
    organization = models.ForeignKey(Organization,
                                     related_name='support_tickets',
                                     related_query_name='support_ticket',
                                     on_delete=models.CASCADE,
                                     )
    bicycle = models.ForeignKey('Bicycle',
                                blank=True,
                                null=True,
                                related_name='support_tickets',
                                related_query_name='support_ticket',
                                on_delete=models.SET_NULL,
                                )
    message = models.TextField(default='', blank=True)
    category = models.CharField(max_length=25,
                                choices=CATEGORIES,
                                null=True, blank=True)
    location = PointField(blank=True, null=True)
    state = FSMField(default=SupportTicketStates.NEW.value, db_index=True)

    def __str__(self):
        return f'SupportTicket[{self.id}] / User[{self.owner_id}]'

    def clean(self):
        if (self.category in (SupportTicket.REQUEST_BICYCLE,
                              SupportTicket.LOST_BICYCLE) and
                not self.location):
            raise ValidationError(
                f'Cannot set category `{self.category}` without a location.')
        if self.category == SupportTicket.DAMAGED_BICYCLE and not self.bicycle:
            raise ValidationError(
                'Cannot set category `bicycle_damaged` without a bicycle.')

    def send_support_email(self):
        support_email = self.organization.get_preference('support_email')
        send_per_email = self.organization.get_preference(
            'send_support_ticket_per_email')
        if not support_email or not send_per_email:
            return

        username = self.owner.display_name
        subject = next(i[1] for i in self.CATEGORIES if i[0] == self.category)
        try:
            lon = self.location.coords[0]
            lat = self.location.coords[1]
        except AttributeError:
            lon = lat = None

        try:
            last_rental = self.bicycle.transitions.filter(
                state=BicycleStates.RENTED.value).last()
        except AttributeError:
            last_rental = None

        loc_dt = None
        if last_rental:
            tz_name = self.organization.get_preference('timezone')
            loc_tz = pytz.timezone(tz_name)
            loc_dt = loc_tz.normalize(
                last_rental.timestamp.replace(microsecond=0))

        to = [support_email]
        context = {
            'info_list': {
                'username': username,
                'message': self.message,
                'bicycle': self.bicycle,
                'last_rental_timestamp': loc_dt,
                'category': self.category,
                'lon': lon,
                'lat': lat,
            },
            'self': self,
            'user_link': build_frontend_uri('users', self.owner.uuid),
        }
        send_email(subject, to, 'email/support.txt',
                   template_html='email/support.html',
                   context=context)


class FeedbackCategory(BaseModelMixin, MPTTModel):
    SEVERITY_LOW = 'low'
    SEVERITY_MEDIUM = 'medium'
    SEVERITY_HIGH = 'high'
    SEVERITIES = (
        (SEVERITY_LOW, 'Low severity'),
        (SEVERITY_MEDIUM, 'Medium severity'),
        (SEVERITY_HIGH, 'High severity')
    )
    name = models.CharField(max_length=50)
    severity = models.CharField(max_length=25,
                                choices=SEVERITIES,
                                null=True, blank=True)
    parent = TreeForeignKey(
        'self',
        null=True, blank=True,
        related_name='children',
        db_index=True,
        on_delete=models.CASCADE,
    )

    objects = TreeManager()

    def __str__(self):
        return str(self.organization.id) if self.is_root_node() else self.name

    @classmethod
    def get_queryset(cls, request=None, **kwargs):
        # XXX we assumed only the category tree
        # assigned to lock8 is available.
        user = request.user
        if not user.affiliations.exclude(role=Affiliation.RENTER).exists():
            # Just a renter, return leaf nodes.
            return cls.objects.filter(lft=F('rght')-1)
        return cls.objects.all()


class FeedbackStates(Enum):
    NEW = 'new'
    ESCALATED = 'escalated'
    DISCARDED = 'discarded'


class FeedbackQuerySet(models.QuerySet):
    def annotate_with_causative_bicycle_uuid(self):
        return self.annotate(
            causative_bicycle_uuid=Case(
                When(bicycles__isnull=False,
                     then=F('bicycles__uuid')),
                When(locks__bicycle__isnull=False,
                     then=F('locks__bicycle__uuid')),
                default=None,
            ),
        )


class Feedback(FinalCausalityModelMixin, NotificationMessageDeleteMixin,
               BaseModelMixin, ActionableModelMixin, OwnerableModelMixin,
               SendableModelMixin, OrganizationOwnedModelMixin):
    organization = models.ForeignKey(Organization,
                                     related_name='feedbacks',
                                     related_query_name='feedback',
                                     on_delete=models.CASCADE)
    user = models.ForeignKey(User, related_name='feedbacks',
                             related_query_name='feedback',
                             on_delete=models.CASCADE)
    image = models.ImageField(upload_to='feedbacks', max_length=254,
                              blank=True)
    message = models.TextField(default='', blank=True)
    state = FSMField(default=FeedbackStates.NEW.value, db_index=True)
    category = models.ForeignKey(FeedbackCategory,
                                 related_name='feedbacks',
                                 related_query_name='feedback',
                                 on_delete=models.SET_NULL,
                                 null=True, blank=True)
    severity = models.CharField(max_length=25,
                                choices=FeedbackCategory.SEVERITIES,
                                null=True, blank=True)

    content_type = models.ForeignKey(ContentType, on_delete=models.PROTECT)
    object_id = models.PositiveIntegerField()
    causality = GenericForeignKey('content_type', 'object_id')
    tasks = GenericRelation('Task', related_query_name='feedbacks')
    alerts = GenericRelation('Alert', related_query_name='feedbacks')

    objects = FeedbackQuerySet.as_manager()

    def __str__(self):
        return 'Feedback[{}] / User[{}]'.format(
            self.id, self.user_id
        )

    def get_sendable_recipients_predicate(self):
        # TODO: Should Supervisor be also 'sendable'?
        return Q(affiliation__organization=self.organization,
                 affiliation__role=Affiliation.FLEET_OPERATOR)

    @fsm_log_by
    @transition(field=state,
                source=FeedbackStates.NEW.value,
                target=FeedbackStates.ESCALATED.value)
    def escalate(self, role=None, severity=None, dry_run=False, **kwargs):
        if dry_run:
            return
        Task.objects.create(
            organization=self.organization,
            causality=self,
            role=role if role is not None else Affiliation.MECHANIC,
            severity=severity
        )

    @fsm_log_by
    @transition(field=state,
                source=FeedbackStates.NEW.value,
                target=FeedbackStates.DISCARDED.value)
    def discard(self, **kwargs):
        """Fleet operator decision."""
        pass


class TaskQuerySet(models.QuerySet):
    def annotate_with_causative_bicycle_uuid(self):
        return self.annotate(
            causative_bicycle_uuid=Case(
                When(bicycles__isnull=False,
                     then=F('bicycles__uuid')),
                When(alerts__bicycles__isnull=False,
                     then=F('alerts__bicycles__uuid')),
                When(alerts__locks__bicycle__isnull=False,
                     then=F('alerts__locks__bicycle__uuid')),
                When(feedbacks__bicycles__isnull=False,
                     then=F('feedbacks__bicycles__uuid')),
                When(feedbacks__locks__bicycle__isnull=False,
                     then=F('feedbacks__locks__bicycle__uuid')),
                default=None,
            ),
        )


class TaskStates(Enum):
    UNASSIGNED = 'unassigned'
    ASSIGNED = 'assigned'
    COMPLETED = 'completed'
    CANCELLED = 'cancelled'


class Task(BaseModelMixin, FinalCausalityModelMixin,
           ActionableModelMixin, OwnerableModelMixin,
           SendableModelMixin):
    organization = models.ForeignKey('lock8.Organization',
                                     related_name='tasks',
                                     related_query_name='task',
                                     on_delete=models.CASCADE)
    assignor = models.ForeignKey('lock8.User',
                                 related_name='created_tasks',
                                 related_query_name='created_task',
                                 blank=True, null=True,
                                 on_delete=models.PROTECT)
    assignee = models.ForeignKey('lock8.User',
                                 related_name='assigned_tasks',
                                 related_query_name='assigned_task',
                                 on_delete=models.PROTECT,
                                 blank=True, null=True)
    role = models.CharField(max_length=25,
                            choices=list(Affiliation.ROLES),
                            default=Affiliation.MECHANIC)
    context = JSONField(default=dict, blank=True, null=True)
    state = FSMField(default=TaskStates.UNASSIGNED.value, db_index=True)
    due = models.DateTimeField(blank=True, null=True)

    content_type = models.ForeignKey(ContentType, on_delete=models.PROTECT)
    object_id = models.PositiveIntegerField()
    causality = GenericForeignKey('content_type', 'object_id')

    maintenance_rule = models.ForeignKey('BicycleModelMaintenanceRule',
                                         related_name='tasks',
                                         related_query_name='task',
                                         on_delete=models.PROTECT,
                                         blank=True, null=True)

    notification_messages = GenericRelation(
        'NotificationMessage', related_query_name='tasks'
    )
    severity = models.CharField(max_length=25,
                                choices=FeedbackCategory.SEVERITIES,
                                null=True, blank=True)
    is_due = models.BooleanField(default=False)

    objects = TaskQuerySet.as_manager()

    def __str__(self):
        return 'Task[{}] / Organization[{}] / Causality[{}] | {}'.format(
            self.id,
            self.organization_id,
            self.object_id,
            self.state,
        )

    @property
    def completed_at(self):
        if hasattr(self, '_transitions'):
            try:
                return self._transitions[0].timestamp
            except IndexError:
                return None
        try:
            return self.transitions.filter(
                state=TaskStates.COMPLETED.value
            ).latest().timestamp
        except StateLog.DoesNotExist:
            pass

    def get_due_date(self):
        due_date = self.due

        bmmr = self.maintenance_rule
        if bmmr is not None:
            if not (bmmr.fixed_date or bmmr.recurring_time):
                return None
            if bmmr.fixed_date:
                return bmmr.fixed_date
            return self.created + bmmr.recurring_time
        return due_date

    def get_remaining_distance(self):
        if (self.maintenance_rule is None or
                self.maintenance_rule.distance is None):
            return None
        uuid = str(self.causality.uuid)
        dist_metrics = get_distance_for_bicycles_since([uuid], self.created)
        distance_in_km = dist_metrics.get(uuid)
        if distance_in_km:
            diff = self.maintenance_rule.distance - distance_in_km
            return diff if diff > 0 else 0

    def get_sendable_recipients_predicate(self):
        if self.state == TaskStates.UNASSIGNED.value:
            if self.assignee:
                predicate = Q(id=self.assignee.id)
            else:
                predicate = Q(
                    affiliation__role=self.role,
                    affiliation__organization=self.organization
                )
        elif self.state == TaskStates.ASSIGNED.value and self.assignee:
            predicate = Q(id=self.assignee.id)
        elif self.state == TaskStates.COMPLETED.value and self.assignor:
            predicate = Q(id=self.assignor.id)
        elif self.state == TaskStates.CANCELLED.value and self.assignee:
            predicate = Q(id=self.assignee.id)
            if self.assignor:
                predicate = Q(id__in=(self.assignee.id, self.assignor.id))
        else:
            return
        return predicate

    @fsm_log_by
    @transition(field=state,
                source=(TaskStates.UNASSIGNED.value,
                        TaskStates.ASSIGNED.value),
                target=TaskStates.ASSIGNED.value)
    def assign(self, assignee, dry_run=False, **kwargs):
        has_affiliation = assignee.affiliations.filter(
            organization_id=self.organization_id,
        ).exists()
        if not has_affiliation:
            raise ValidationError((
                'Cannot assign Task to {}.'
                ' No existing affiliation.'.format(assignee.display_name)
            ))
        if dry_run:
            return
        if self.assignee:
            messages_to_ack = NotificationMessage.objects.filter(
                user=self.assignee, tasks__pk=self.id,
                state=NotificationMessageStates.SENT.value
            )
        else:
            messages_to_ack = NotificationMessage.objects.filter(
                tasks__pk=self.id,
                state=NotificationMessageStates.SENT.value,
            )
        for message in messages_to_ack:
            message.acknowledge()

        self.assignee = assignee
        self.save()

    @fsm_log_by
    @transition(field=state,
                source=(TaskStates.ASSIGNED.value),
                target=(TaskStates.UNASSIGNED.value))
    def unassign(self, dry_run=False, **kwargs):
        if dry_run:
            return
        messages_to_ack = NotificationMessage.objects.filter(
            user=self.assignee, tasks__pk=self.id,
            state=NotificationMessageStates.SENT.value
        )
        for message in messages_to_ack:
            message.acknowledge()

        self.assignee = None
        self.save()

    @fsm_log_by
    @transition(field=state,
                source=(TaskStates.UNASSIGNED.value,
                        TaskStates.ASSIGNED.value),
                target=TaskStates.COMPLETED.value)
    def complete(self, dry_run=False, **kwargs):
        if dry_run:
            return
        messages_to_ack = NotificationMessage.objects.filter(
            user=self.assignee, tasks__pk=self.id,
            state=NotificationMessageStates.SENT.value
        )
        for message in messages_to_ack:
            message.acknowledge()

    @fsm_log_by
    @transition(field=state,
                source=(TaskStates.UNASSIGNED.value,
                        TaskStates.ASSIGNED.value),
                target=TaskStates.CANCELLED.value)
    def cancel(self, **kwargs):
        """Cancel a Task. Notify assigned user if set."""
        pass


# make owner field optional (chicken egg problem)
owner_field = Task._meta.get_field('owner')
owner_field.null = True
owner_field.blank = True


class NotificationMessageStates(Enum):
    NEW = 'new'
    SENT = 'sent'
    ERROR = 'error'
    ACKNOWLEDGED = 'acknowledged'


class NotificationMessage(ActionableModelMixin, BaseModelMixin):
    user = models.ForeignKey(User,
                             related_name='notification_messages',
                             related_query_name='notification_message',
                             on_delete=models.CASCADE)
    state = FSMField(default=NotificationMessageStates.NEW.value,
                     db_index=True)

    content_type = models.ForeignKey(ContentType, on_delete=models.PROTECT)
    object_id = models.PositiveIntegerField()
    causality = GenericForeignKey('content_type', 'object_id')

    class Meta(ActionableModelMixin.Meta, BaseModelMixin.Meta):
        # For the `~Q(notification_message__alerts=self)` lookup in
        # Alert.get_sendable_recipients_predicate.
        index_together = [('content_type', 'object_id')]

    def __str__(self):
        return 'Causality[{}], User[#{}]'.format(self.causality, self.user_id)

    def _send(self, dry_run=False, **kwargs):
        from velodrome.lock8.dispatchers import (
            send_notification_message_dispatcher)
        if dry_run:
            return
        send_notification_message_dispatcher(self.causality, self)

    @fsm_log_by
    @transition(field=state,
                source='*',
                target=NotificationMessageStates.SENT.value,
                on_error=NotificationMessageStates.ERROR.value)
    def send(self, **kwargs):
        return self._send(**kwargs)

    @fsm_log_by
    @transition(field=state,
                source=NotificationMessageStates.ERROR.value,
                target=NotificationMessageStates.SENT.value)
    def retry(self, **kwargs):
        return self._send(**kwargs)

    @fsm_log_by
    @transition(field=state,
                source=NotificationMessageStates.SENT.value,
                target=NotificationMessageStates.ACKNOWLEDGED.value)
    def acknowledge(self, **kwargs):
        pass


class Photo(BaseModelMixin, ActionableModelMixin, GenericStateMixin,
            OwnerableModelMixin, OrganizationOwnedModelMixin):
    organization = models.ForeignKey(Organization,
                                     related_name='photos',
                                     related_query_name='photo',
                                     on_delete=models.CASCADE,
                                     )
    image = models.ImageField(upload_to='photos', max_length=254, blank=True)

    def __str__(self):
        return str(self.image)


class BicycleType(BaseModelMixin, OwnerableModelMixin):
    reference = models.CharField(max_length=50, unique=True)
    title = models.CharField(max_length=50)

    def __str__(self):
        return self.reference


class BicycleModel(BaseModelMixin, GenericStateMixin, OwnerableModelMixin,
                   OrganizationOwnedModelMixin):
    organization = models.ForeignKey(Organization,
                                     related_name='bicycle_models',
                                     related_query_name='bicycle_model',
                                     on_delete=models.CASCADE,
                                     )
    name = models.CharField(max_length=128, blank=True)
    type = models.ForeignKey(BicycleType,
                             related_name='bicycle_models',
                             related_query_name='bicycle_model',
                             blank=True, null=True,
                             on_delete=models.SET_NULL)
    photo = models.ForeignKey(Photo, blank=True, null=True,
                              on_delete=models.SET_NULL)
    alert_types_to_task = JSONField(
        default=dict,
        blank=True,
        help_text="Mapping of alert types, severity level.\n"
                  "When present, a Task will be created.",
        validators=[validate_alert_types_to_task])
    feedback_auto_escalate_severity = models.CharField(
        max_length=25, choices=FeedbackCategory.SEVERITIES,
        null=True, blank=True
    )
    hidden = models.BooleanField(default=False,
                                 help_text=(
                                     'Visible only to fleet operators.'))

    def __str__(self):
        return '{} / Type[{}]'.format(
            self.name,
            self.type_id,
        )

    @property
    def bicycle_count(self):
        return self.bicycles.exclude(state=BicycleStates.RETIRED.value).count()

    def delete(self):
        """
        Can't delete if bound to Bicycles.
        """
        if self.bicycles.exists():
            raise ValidationError('Some Bicycles are still bound to this'
                                  ' Model')
        super().delete()


class BicycleModelMaintenanceRuleStates(Enum):
    ACTIVE = 'active'
    DEACTIVATED = 'deactivated'


class BicycleModelMaintenanceRule(BaseModelMixin):
    bicycle_model = models.ForeignKey(BicycleModel,
                                      related_name='maintenance_rules',
                                      related_query_name='maintenance_rule',
                                      on_delete=models.CASCADE)
    description = models.TextField(blank=True, null=True)
    note = models.TextField(blank=True, null=True)
    distance = models.IntegerField(blank=True, null=True)
    fixed_date = models.DateTimeField(blank=True, null=True)
    recurring_time = models.DurationField(blank=True, null=True)
    start_date = models.DateTimeField(null=True,
                                      default=timezone.now)
    role = models.CharField(max_length=25, choices=list(Affiliation.ROLES),
                            default=Affiliation.MECHANIC)
    severity = models.CharField(max_length=25,
                                choices=FeedbackCategory.SEVERITIES,
                                blank=True, null=True)
    state = FSMField(default=BicycleModelMaintenanceRuleStates.ACTIVE.value,
                     db_index=True)

    def __str__(self):
        f1, f2, f3 = "{}km", "{:%Y-%M-%d}", naturaldelta
        pred = (
            self.distance is not None and f1.format(self.distance) or
            self.fixed_date is not None and f2.format(self.fixed_date) or
            self.recurring_time is not None and f3(self.recurring_time)
        )
        return 'Rule #{} - {} - {}'.format(self.pk, pred, self.bicycle_model)

    @classmethod
    def get_queryset(cls, request=None, **kwargs):
        user = request.user
        orgs = user.get_descendants_organizations()
        pred = Q(bicycle_model__organization__in=orgs)
        return cls.objects.filter(pred).distinct()

    def clean(self):
        if not any((self.fixed_date, self.recurring_time, self.distance)):
            msg = 'Rule must set one of the following fields: {}'.format(
                'fixed_date, recurring_time, distance'
            )
            raise ValidationError(msg)
        if self.fixed_date and self.recurring_time:
            msg = 'Rule cannot set both fixed_date and recurring_time fields'
            raise ValidationError(msg)
        if self.fixed_date and self.distance:
            msg = 'Rule cannot set fixed_date and distance fields'
            raise ValidationError(msg)
        if self.recurring_time and self.distance:
            msg = 'Rule cannot set recurring_time and distance fields'
            raise ValidationError(msg)

    @property
    def has_occured(self):
        return self.start_date is None or self.start_date <= timezone.now()

    @fsm_log_by
    @transition(field=state,
                source=BicycleModelMaintenanceRuleStates.ACTIVE.value,
                target=BicycleModelMaintenanceRuleStates.DEACTIVATED.value)
    def deactivate(self, cancel_tasks=False, dry_run=False, **kwargs):
        """Deactivate BMMR. Cancel all tasks if `cancel_tasks` is True."""
        if dry_run:
            return
        if cancel_tasks:
            tasks_to_cancel = (
                Task.objects
                .filter(
                    state__in=[TaskStates.ASSIGNED.value,
                               TaskStates.UNASSIGNED.value],
                    maintenance_rule=self
                )
            )
            for task in tasks_to_cancel:
                task.cancel()

    @fsm_log_by
    @transition(field=state,
                source=BicycleModelMaintenanceRuleStates.DEACTIVATED.value,
                target=BicycleModelMaintenanceRuleStates.ACTIVE.value)
    def activate(self, dry_run=False, **kwargs):
        """Create tasks that are missing since we reactivate that rule"""
        from velodrome.celery import create_missing_tasks_async
        if dry_run:
            return
        if self.has_occured:
            create_missing_tasks_async.delay(self.pk)

    def create_missing_tasks(self):
        """Create Tasks for Bicycles that don't have one."""
        predicate = (
            Q(tasks__state__in=(TaskStates.ASSIGNED.value,
                                TaskStates.UNASSIGNED.value)) &
            Q(tasks__maintenance_rule=self)
        )
        bicycle_wo_new_recurring_task = (
            self.bicycle_model.bicycles
            .exclude(state__in=(
                BicycleStates.LOST.value,
                BicycleStates.RETIRED.value))
            .annotate(
                new_tasks_count=Sum(Case(
                    When(predicate, then=1),
                    default=0,
                    output_field=models.IntegerField()
                ))
            )
            .filter(new_tasks_count=0)
        )
        admin = User.objects.get(username='root_admin')
        for bicycle in bicycle_wo_new_recurring_task:
            Task.objects.create(
                organization=self.bicycle_model.organization,
                causality=bicycle,
                maintenance_rule=self,
                role=self.role,
                severity=self.severity,
                context={'description': self.description},
                owner=admin,
            )


class BicycleStates(Enum):
    IN_MAINTENANCE = 'in_maintenance'
    AVAILABLE = 'available'
    RESERVED = 'reserved'
    RENTED = 'rented'
    LOST = 'lost'
    RETIRED = 'retired'
    UNRECOVERABLE = 'unrecoverable'


class BicycleQuerySet(NullsLastQuerySet):
    def prefetch_active(self, fields):
        qs = self
        if 'reservation' in fields:
            active_reservations = Reservation.objects.filter(
                state=ReservationStates.NEW.value).order_by()
            qs = qs.prefetch_related(Prefetch(
                'reservations',
                queryset=active_reservations,
                to_attr='_active_reservations'
            ))
        if 'rental_session' in fields:
            active_rental_sessions = RentalSession.objects.filter(
                state=RentalSessionStates.NEW.value).order_by()
            qs = qs.prefetch_related(Prefetch(
                'rental_sessions',
                queryset=active_rental_sessions,
                to_attr='_active_rental_sessions'
            ))
        return qs

    def count_by_state(self, predicate):
        return (self.filter(predicate)
                .values('state')
                .annotate(total=Count('state'))
                .order_by('-total'))

    def annotate_with_distance(self, point, tracking_lookup):
        return self.annotate(raw_distance=GeoDistance(tracking_lookup, point))


class Bicycle(BaseModelMixin, ActionableModelMixin, OwnerableModelMixin,
              LatestTrackingsMixin):
    organization = models.ForeignKey(Organization,
                                     related_name='bicycles',
                                     related_query_name='bicycle',
                                     on_delete=models.PROTECT,
                                     )
    lock = models.OneToOneField(Lock, blank=True, null=True,
                                on_delete=models.SET_NULL)
    axa_lock = models.OneToOneField(AxaLock, blank=True, null=True,
                                    on_delete=models.SET_NULL)
    model = models.ForeignKey(BicycleModel,
                              related_name='bicycles',
                              related_query_name='bicycle',
                              blank=True, null=True,
                              on_delete=models.SET_NULL)
    name = models.CharField(max_length=128, blank=True, db_index=True)
    # deprecated
    reference = models.CharField(max_length=128, blank=True, null=True)
    # not used anywhere in production (was added with serial_number).
    # Removed from serializer, should be removed completely probably.
    service_identifier = models.CharField(max_length=128, blank=True,
                                          db_index=True)
    serial_number = models.CharField(max_length=128, blank=True,
                                     db_index=True)
    description = models.TextField(default='', blank=True)
    alerts = GenericRelation('Alert', related_query_name='bicycles')
    tasks = GenericRelation('Task', related_query_name='bicycles')
    feedbacks = GenericRelation('Feedback', related_query_name='bicycles')
    short_id = models.CharField(max_length=12,
                                default=make_short_id,
                                unique=True,
                                )
    state = FSMField(default=BicycleStates.IN_MAINTENANCE.value, db_index=True)
    note = models.TextField(blank=True, null=True)  # Switch to ServiceNote!
    tags = GenericRelation(
        'custom_tagging.TagInstance',
        related_query_name='tags'
    )

    locked = models.BooleanField(default=True)

    objects = BicycleQuerySet.as_manager()

    def clean(self):
        if self.lock is not None:
            if self.lock.organization != self.organization:
                raise ValidationError(
                    {'lock': _('Lock does not belong to the same'
                               ' Organization.')})

    @classmethod
    def get_queryset(cls, request=None, includes_spectator=False, **kwargs):
        user = request.user
        qs = cls.objects.all()
        visible_predicate = (Q(model__isnull=True) | (
            Q(model__isnull=False) & Q(model__hidden=False))
        )
        if user.is_anonymous:
            return qs.filter(visible_predicate &
                             Q(organization__is_open_fleet=True) &
                             Q(state=BicycleStates.AVAILABLE.value)).distinct()

        mgmt_team_predicate = Q(affiliation__role__in=(
            Affiliation.ADMIN,
            Affiliation.SUPERVISOR,
            Affiliation.FLEET_OPERATOR))
        if includes_spectator:
            mgmt_team_predicate |= Q(affiliation__role=Affiliation.SPECTATOR)
        managed_organizations = set(
            user
            .get_descendants_organizations(predicate=mgmt_team_predicate)
            .values_list('pk', flat=True)
        )
        organizations = set(user.get_organizations().values_list(
            'pk', flat=True))
        only_renter_organizations = organizations - managed_organizations
        if managed_organizations and not only_renter_organizations:
            return (qs
                    .filter(organization__pk__in=managed_organizations)
                    .distinct()
                    )
        qs = (qs
              .annotate(
                  reservation_user=FilteredRelation(
                      'reservation',
                      condition=Q(
                          reservation__state=ReservationStates.NEW.value,
                          reservation__user=user)))
              .annotate(
                  rental_session_user=FilteredRelation(
                      'rental_session',
                      condition=Q(
                          rental_session__state=RentalSessionStates.NEW.value,
                          rental_session__user=user)))
              )
        predicate = (
            Q(state=BicycleStates.AVAILABLE.value) &
             (Q(organization__is_open_fleet=True) | (
                 Q(organization__is_open_fleet=False) &
                 Q(organization__pk__in=only_renter_organizations))) |
            Q(reservation_user__isnull=False) |
            Q(rental_session_user__isnull=False))
        return (qs
                .filter((predicate & visible_predicate) |
                        Q(organization__pk__in=managed_organizations))
                .distinct()
                )

    @property
    def active_reservations(self):
        try:
            return self._active_reservations
        except AttributeError:
            return list(self.reservations.filter(
                state=ReservationStates.NEW.value))

    @property
    def active_reservation(self):
        try:
            return self.active_reservations[0]
        except IndexError:
            pass

    @property
    def active_rental_sessions(self):
        try:
            return self._active_rental_sessions
        except AttributeError:
            return list(self.rental_sessions.filter(
                state=RentalSessionStates.NEW.value))

    @property
    def active_rental_session(self):
        try:
            return self.active_rental_sessions[0]
        except IndexError:
            pass

    @property
    def display_name(self):
        return self.name

    @property
    def eligible_renting_schemes(self):
        linked_to_bicycle = Q(bicycle=self)
        only_organization = (
            Q(bicycle__isnull=True) &
            Q(organization__in=self.organization.get_ancestors(
                include_self=True)))
        return (
            RentingScheme
            .objects
            .annotate(
                bicycle_count=Count('bicycle'),
                max_max_reservation_duration=Max('max_reservation_duration'))
            .filter(linked_to_bicycle | only_organization)
            .order_by('-bicycle_count',
                      '-max_max_reservation_duration',
                      )
            )

    @cached_property
    def is_allowed_to_be_dropped(self):
        latest_tracking = self.public_tracking
        if (latest_tracking is None or
                getattr(latest_tracking, 'point', None) is None):
            return True
        return self._is_within_zone((Zone.DROP, Zone.MAINTENANCE))

    @cached_property
    def is_cycling_within_service_area(self):
        latest_tracking = self.public_tracking
        if (latest_tracking is None or
                getattr(latest_tracking, 'point', None) is None):
            return True
        return self._is_within_zone((Zone.SERVICE,))

    def _is_within_zone(self, types, default=True):
        latest_tracking = self.public_tracking
        if (latest_tracking is None or
                getattr(latest_tracking, 'point', None) is None):
            raise TypeError('Can not decide if within zone')
        zones = Zone.objects.filter(
            organization=self.organization,
            type__in=types)
        if zones.exists():
            if latest_tracking.gps_accuracy is None:
                predicate = Q(polygon__intersects=latest_tracking.point)
            else:
                mult = max(1, (latest_tracking.gps_pdop
                               if latest_tracking.gps_pdop is not None else 1))
                inaccuracy = latest_tracking.gps_accuracy * mult
                predicate = Q(
                    polygon__dwithin=(
                        latest_tracking.point,
                        Distance(m=inaccuracy)))
            return zones.filter(predicate).exists()
        return default

    @cached_property
    def get_drop_zones(self) -> typing.Optional[QuerySet]:
        return self._get_zones((Zone.DROP,))

    def _get_zones(self, types) -> typing.Optional[QuerySet]:
        latest_tracking = self.public_tracking
        if (latest_tracking is None
                or getattr(latest_tracking, 'point', None) is None):
            return None
        zones = Zone.objects.filter(
            organization=self.organization,
            type__in=types)
        if zones.exists():
            if latest_tracking.gps_accuracy is None:
                predicate = Q(polygon__intersects=latest_tracking.point)
            else:
                mult = max(1, (latest_tracking.gps_pdop
                               if latest_tracking.gps_pdop is not None else 1))
                inaccuracy = latest_tracking.gps_accuracy * mult
                predicate = Q(
                    polygon__dwithin=(
                        latest_tracking.point,
                        Distance(m=inaccuracy)))
            return zones.filter(predicate)
        return None

    @property
    def frontend_uri(self):
        frontend_uri = urljoin(settings.FRONTEND_URL, 'map')
        formatted_uuid = str(self.uuid).replace('-', '_')
        encoded_uuid = urlencode({'bike': formatted_uuid})
        return '?'.join((frontend_uri, encoded_uuid))

    @property
    def devices(self):
        devices = {}
        if self.lock is not None:
            if self.lock.type == Lock.TRACKER:
                devices['tracker'] = self.lock
            else:
                devices['lock'] = self.lock
        if self.axa_lock is not None:
            if 'lock' in devices:
                logger.info('Bicycle #%s is paired with'
                            ' a Vulkan #%s and an Axa lock #%s',
                            self.pk, self.lock.pk, self.axa_lock.pk)
                devices['tracker'] = devices['lock']
            devices['lock'] = self.axa_lock
        return devices

    @property
    def distance_m(self):
        try:
            return self.raw_distance.m
        except AttributeError:
            pass

    def get_total_ridden_distance(self):
        table = get_ddbtable('v2-bicycle-distance-meters-ridden-total')
        query = {'KeyConditionExpression': Key('bicycle').eq(str(self.uuid))}
        response = query_table(table, query, 'distance')
        if response['Count'] == 0:
            return 0
        return response['Items'][0]['distance']

    def get_pricings_for_user(self, user):
        now = timezone.now()

        available_dates_predicate = (
            Q(available_dates__contains=now) |
            Q(available_dates__isnull=True))

        weekdays_predicate = (
            Q(weekdays__contains=now.isoweekday()) |
            Q(weekdays__isnull=True))

        def get_default_pricings(include_org):
            # Get PricingScheme from Model.
            predicate = Q(organization=self.organization,
                          bicycle_model=self.model,
                          subscription_plan__isnull=True,
                          state=GenericStates.PROVISIONED.value)
            pricing_schemes = [*PricingScheme.objects.filter(predicate)]
            if include_org and not pricing_schemes:
                # Get PricingScheme from Organization.
                predicate = Q(organization=self.organization,
                              bicycle_model__isnull=True,
                              subscription_plan__isnull=True,
                              state=GenericStates.PROVISIONED.value)
                pricing_schemes = [*PricingScheme.objects.filter(predicate)]
            predicate = Q(organization=self.organization,
                          bicycle_model=self.model,
                          state=GenericStates.PROVISIONED.value)

            # Get SubscriptionPlans from Model.
            subscription_plans = [*SubscriptionPlan.objects.filter(
                predicate & available_dates_predicate & weekdays_predicate)]
            if include_org and not subscription_plans:
                # Get SubscriptionPlans from Organization.
                predicate = Q(organization=self.organization,
                              bicycle_model__isnull=True,
                              state=GenericStates.PROVISIONED.value)
                subscription_plans = [
                    *SubscriptionPlan.objects.filter(
                        predicate & available_dates_predicate &
                        weekdays_predicate)
                ]
            return {'pricing_schemes': pricing_schemes,
                    'subscription_plans': subscription_plans,
                    'active_subscriptions': []}

        try:
            customer = user.get_customer(self.organization)
        except Customer.DoesNotExist:
            return get_default_pricings(True)
        else:
            # Get active subscriptions from Model (SubscriptionPlan).
            active_subscription = Q(
                plan__subscription__customer=customer,
                plan__subscription__status__in=('trialing',
                                                'active',
                                                'past_due'),
            ) & (Q(plan__subscription__ended_at__isnull=True) |
                 Q(plan__subscription__ended_at__gt=timezone.now()))
            predicate = (
                Q(bicycle_model=self.model,
                  organization=self.organization,
                  state__in=(GenericStates.PROVISIONED.value,
                             GenericStates.DECOMMISSIONED.value),
                  ) & available_dates_predicate &
                weekdays_predicate &
                active_subscription
            )
            active_subscriptions = [*SubscriptionPlan.objects
                                    .filter(predicate)]
            if active_subscriptions:
                return {'active_subscriptions': active_subscriptions,
                        'pricing_schemes': [],
                        'subscription_plans': []}

            # Get default PricingSchemes and SubscriptionPlans from Model.
            defaults = get_default_pricings(False)
            if defaults['pricing_schemes'] or defaults['subscription_plans']:
                return defaults

            # Get active subscriptions from Organization.
            predicate = (
                Q(bicycle_model__isnull=True,
                  organization=self.organization,
                  state__in=(GenericStates.PROVISIONED.value,
                             GenericStates.DECOMMISSIONED.value),
                  ) & available_dates_predicate &
                weekdays_predicate &
                active_subscription
            )
            active_subscriptions = [
                *SubscriptionPlan.objects.filter(predicate)]
            if active_subscriptions:
                return {'active_subscriptions': active_subscriptions,
                        'pricing_schemes': [],
                        'subscription_plans': []}
            return get_default_pricings(True)

    def __str__(self):
        return 'Bicycle #{} {} / {} with lock {}'.format(
            self.pk or '-',
            self.name,
            self.short_id,
            self.lock_id,
        )

    def __repr__(self):
        return 'Bicycle(%s)' % ', '.join(
            '%s=%r' % (k, getattr(self, k, None)) for k in (
                'pk', 'name', 'organization', 'state'))

    def _stop_lost_bicycle_reported_alerts(self, **kwargs):
        for alert in self.alerts.filter(
                state__in=(AlertStates.NEW.value,
                           AlertStates.ESCALATED.value,
                           AlertStates.SILENCED.value),
                alert_type=Alert.LOST_BICYCLE_REPORTED):
            alert.stop(**kwargs)

    @fsm_log_by
    @transition(field=state,
                source=(BicycleStates.IN_MAINTENANCE.value,
                        BicycleStates.LOST.value,
                        BicycleStates.UNRECOVERABLE.value),
                target=BicycleStates.AVAILABLE.value)
    def declare_available(self, dry_run=False, **kwargs):
        """
        Assert there is a lock attached.
        """
        if not self.lock:
            raise ValidationError(
                "This bicycle does not have a device attached.")
        if dry_run:
            return
        self._stop_lost_bicycle_reported_alerts(**kwargs)

    @fsm_log_by
    @transition(field=state,
                source=(BicycleStates.AVAILABLE.value,
                        BicycleStates.LOST.value,
                        BicycleStates.UNRECOVERABLE.value),
                target=BicycleStates.IN_MAINTENANCE.value)
    def put_in_maintenance(self, dry_run=False, **kwargs):
        if dry_run:
            return
        self._handle_transition_to_in_maintenance(**kwargs)

    @fsm_log_by
    @transition(field=state,
                source=(BicycleStates.AVAILABLE.value,
                        BicycleStates.LOST.value,
                        BicycleStates.IN_MAINTENANCE.value,
                        BicycleStates.UNRECOVERABLE.value),
                target=BicycleStates.IN_MAINTENANCE.value)
    def take_over(self, dry_run=False, **kwargs):
        self._close_active_reservation_and_rental_session(**kwargs)
        if dry_run:
            return
        self._handle_transition_to_in_maintenance(**kwargs)

    def _handle_transition_to_in_maintenance(self, **kwargs):
        for alert in self.alerts.filter(
                alert_type=Alert.RIDE_OUTSIDE_SERVICE_AREA,
                state__in=(AlertStates.NEW.value,
                           AlertStates.ESCALATED.value,
                           AlertStates.SILENCED.value)):
            alert.stop(**kwargs)
        if self.state == BicycleStates.AVAILABLE.value:
            for alert in self.alerts.filter(
                    alert_type=Alert.BICYCLE_IDLE_FOR_TOO_LONG,
                    state__in=(AlertStates.NEW.value,
                               AlertStates.ESCALATED.value,
                               AlertStates.SILENCED.value)):
                alert.stop(**kwargs)
        publish_updates(self, for_state_leaving={'state': self.state})
        self._stop_lost_bicycle_reported_alerts(**kwargs)

    @fsm_log_by
    @transition(field=state,
                source=(BicycleStates.IN_MAINTENANCE.value,
                        BicycleStates.AVAILABLE.value,
                        BicycleStates.UNRECOVERABLE.value),
                target=BicycleStates.LOST.value)
    def declare_lost(self, dry_run=False, **kwargs):
        if dry_run:
            return
        self._stop_all_alerts(**kwargs)

    @fsm_log_by
    @transition(field=state,
                source=(BicycleStates.AVAILABLE.value,
                        BicycleStates.LOST.value),
                target=BicycleStates.UNRECOVERABLE.value)
    def declare_unrecoverable(self, dry_run=False, **kwargs):
        if dry_run:
            return
        self._stop_all_alerts(**kwargs)

    def _stop_all_alerts(self, **kwargs):
        for alert in self.alerts.filter(
                state__in=(AlertStates.NEW.value,
                           AlertStates.SILENCED.value,
                           AlertStates.ESCALATED.value)):
            alert.stop(**kwargs)

    @fsm_log_by
    @transition(field=state,
                source=BicycleStates.AVAILABLE.value,
                target=BicycleStates.RESERVED.value)
    def reserve(self, by=None, user=None, dry_run=False, **kwargs):
        """
        Notify subscribers that the bicycle won't remain available.
        Create the reservation.
        """
        if user is None:
            user = by
        max_allowed_bicycles_per_renter = self.organization.max_allowed_bicycles_per_renter  # noqa
        if self.active_reservation is not None:
            raise ValidationError('This bicycle is already reserved.')
        reservation_count = user.active_reservations.count()
        if reservation_count >= max_allowed_bicycles_per_renter:
            if reservation_count == 1:
                message = 'You already have an active reservation.'
            else:
                message = (f'You already have {reservation_count} active'
                           ' reservations.')
            raise ValidationError(message, code='too_many_reservations')
        if self.active_rental_session is not None:
            raise ValidationError('This bicycle is already rented.')
        rental_session_count = user.active_rental_sessions.count()
        if rental_session_count >= max_allowed_bicycles_per_renter:
            if rental_session_count == 1:
                message = 'You already have an active rental session.'
            else:
                message = (f'You already have {rental_session_count} active'
                           ' rental sessions.')
            raise ValidationError(message, code='too_many_rentalsessions')

        if dry_run:
            return

        publish_updates(self, for_state_leaving={'state': self.state})
        Reservation.objects.create(
            user=user,
            owner=by,
            bicycle=self,
        )

    def _rent_handle_pending_payments(self, user, dry_run):
        debt, must_be_retried = user.get_debt_for_rentals(self.organization)
        if not must_be_retried:
            if debt and not dry_run:
                logger.info('Not retrying failed payments: %r', debt)
            return

        ok = False
        if not dry_run:
            try:
                ok = user.retry_failed_payments(self.organization, debt)
            except Exception as exc:
                logger.exception(
                    'Error when retrying failed payments: %s', exc)
        if not ok:
            unpaid_rentals_count = len(debt.values())
            plural = unpaid_rentals_count > 1
            if plural:
                msg = f'There are {unpaid_rentals_count} outstanding payments.'
            else:
                msg = 'There is one outstanding payment.'
            raise ValidationError(msg, code='user_has_pending_payments')

    def _rent_handle_payments(self, rental_session, subscription_plan,
                              pricing_scheme: 'PricingScheme',
                              dry_run=False, by=None):
        # Validate PricingScheme/SubscriptionPlan.
        user = rental_session.user
        available_pricings = self.get_pricings_for_user(user)
        active_subscriptions = available_pricings.get(
            'active_subscriptions', [])
        pricing_schemes = available_pricings.get('pricing_schemes', [])
        if (not (active_subscriptions or pricing_schemes) and
                not self.organization.allow_renting_without_pricings):
            raise ValidationError(
                'This bicycle can not be rented due to pricing policy.')
        if subscription_plan is not None:
            if subscription_plan not in active_subscriptions:
                raise ValidationError({'subscription_plan':
                                       'This SubscriptionPlan is not valid.'})
        elif (pricing_scheme is not None and
              pricing_scheme not in pricing_schemes):
            raise ValidationError({'pricing_scheme':
                                   'This PricingScheme is not valid.'})
        elif len(active_subscriptions) > 1:
            raise ValidationError(
                'A pricing needs to be chosen by the renter.')
        elif active_subscriptions:
            subscription_plan = active_subscriptions[0]
        elif not pricing_scheme and pricing_schemes:
            pricing_scheme = pricing_schemes[0]
        elif pricing_scheme:
            pass
        else:
            assert subscription_plan is None
            assert pricing_scheme is None
            rental_session.skip_payment(dry_run=dry_run, by=by)
            return
        try:
            user.get_customer(organization=self.organization)
        except Customer.DoesNotExist:
            raise ValidationError('The user has no customer.',
                                  code='user_has_no_customer')
        currency = self.organization.currency
        rental_session.currency = currency
        rental_session.subscription_plan = subscription_plan
        rental_session.pricing_scheme = pricing_scheme

        rental_session.init_payment(dry_run=dry_run, by=by)

    @fsm_log_by
    @transition(field=state,
                source=(BicycleStates.AVAILABLE.value,
                        BicycleStates.RESERVED.value),
                target=BicycleStates.RENTED.value)
    def rent(self, by=None, user=None, subscription_plan=None,
             pricing_scheme=None, dry_run=False, **kwargs):
        """
        Notify subscribers that the bicycle won't remain available.
        Close the Reservation &
        Create the RentalSession
        """
        if user is None:
            user = by
        if subscription_plan and pricing_scheme:
            raise ValidationError('subscription_plan and pricing_scheme are'
                                  ' mutually exclusive.')
        max_allowed_bicycles_per_renter = self.organization.max_allowed_bicycles_per_renter  # noqa
        active_reservation = self.active_reservation
        if active_reservation is not None and active_reservation.user != user:
            raise ValidationError('This bicycle is already reserved.')
        if by is None:
            assert dry_run
        elif not by.is_client_app:
            reservation_count = user.active_reservations.exclude(
                bicycle=self).count()
            if reservation_count >= max_allowed_bicycles_per_renter:
                if reservation_count == 1:
                    message = 'You already have an active reservation.'
                else:
                    message = (f'You already have {reservation_count} active'
                               ' reservations.')
                raise ValidationError(message, code='too_many_reservations')
            if self.active_rental_session is not None:
                raise ValidationError('This bicycle is already rented.')
            rental_session_count = user.active_rental_sessions.count()
            if rental_session_count >= max_allowed_bicycles_per_renter:
                if rental_session_count == 1:
                    message = 'You already have an active rental session.'
                else:
                    message = (f'You already have {rental_session_count}'
                               ' active rental sessions.')
                raise ValidationError(message, code='too_many_rentalsessions')

        uses_payments = self.organization.uses_payments
        if not uses_payments:
            if pricing_scheme:
                raise ValidationError(
                    {'pricing_scheme':
                     'The organization does not use payments.'})
            elif subscription_plan:
                raise ValidationError(
                    {'subscription_plan':
                     'The organization does not use payments.'})

        if pricing_scheme or subscription_plan:
            self._rent_handle_pending_payments(user, dry_run)

        if dry_run:
            return

        reservation = self.active_reservation
        if reservation is not None:
            reservation.delete()

        with transaction.atomic():
            rental_session = RentalSession.objects.create(
                user=user,
                owner=by,
                bicycle=self,
                subscription_plan=subscription_plan,
                pricing_scheme=pricing_scheme,
            )

            if uses_payments:
                self._rent_handle_payments(
                    rental_session,
                    subscription_plan,
                    pricing_scheme,
                    by=by,
                    dry_run=dry_run)
            else:
                rental_session.skip_payment(dry_run=dry_run, by=by)

        publish_updates(self, for_state_leaving={'state': self.state})

        from velodrome.celery import stop_alerts_for_rental
        transaction.on_commit(functools.partial(
            stop_alerts_for_rental.delay,
            self.pk, user.pk))

    @fsm_log_by
    @transition(field=state,
                source=BicycleStates.RENTED.value,
                target=BicycleStates.AVAILABLE.value)
    def return_(self, by=None, dry_run=False, **kwargs):
        """
        Close the RentalSession
        """
        logger.info('Returning bicycle %s (dry_run=%d)', self.uuid, dry_run)
        allow_return_bicycle_outside_drop_zone = (
            self.organization.get_preference(
                'allow_returning_bicycle_outside_drop_zone', True))
        if not allow_return_bicycle_outside_drop_zone:
            if not self.is_allowed_to_be_dropped:
                logger.warning(
                    'Bicycle %s is not allowed to be dropped (dry_run=%d)',
                    self.uuid, dry_run)
                exc = ValidationError(
                    'This bicycle is not allowed to be returned here.',
                    code='outside_dropzone')
                latest_tracking = self.public_tracking
                exc.sentry_extra = {
                    'latest_tracking': latest_tracking.attributes,
                    'zones': [x.pk for x in Zone.objects.filter(
                        organization=self.organization,
                        type__in=(Zone.DROP, Zone.MAINTENANCE))],
                }
                raise exc
        if dry_run:
            return

        zones = self.get_drop_zones
        if zones is not None:
            from velodrome.celery import start_zone_alert_thresholds
            for zone in zones:
                if zone.has_thresholds:
                    start_zone_alert_thresholds.delay(zone.id)

        rental_session = self.active_rental_session
        if rental_session is not None:
            if self.latest_gps_timestamp is not None:
                ReturnOutsideDropZone(self).process()
            rental_session.close(**kwargs)

    @fsm_log_by
    @transition(field=state,
                source=(BicycleStates.RESERVED.value,
                        BicycleStates.RENTED.value,
                        BicycleStates.RETIRED.value),
                target=BicycleStates.IN_MAINTENANCE.value)
    def force_put_in_maintenance(self, dry_run=False, **kwargs):
        if dry_run:
            return
        self._close_active_reservation_and_rental_session(**kwargs)

    def _close_active_reservation_and_rental_session(self, **kwargs):
        """
        TODO: Send an alert to the renter, the bicycle
        is not available for her anymore.
        """
        reservation = self.active_reservation
        if reservation is not None:
            reservation.close(**kwargs)
        renting_session = self.active_rental_session
        if renting_session is not None:
            renting_session.close(**kwargs)

    @fsm_log_by
    @transition(field=state,
                source=BicycleStates.RESERVED.value,
                target=BicycleStates.AVAILABLE.value)
    def cancel_reservation(self, dry_run=False, **kwargs):
        """
        Cancel the Reservation
        """
        if dry_run:
            return
        self.active_reservation.cancel(**kwargs)

    @fsm_log_by
    @transition(field=state,
                source=BicycleStates.RESERVED.value,
                target=BicycleStates.AVAILABLE.value)
    def expire_reservation(self, dry_run=False, **kwargs):
        """
        Expire the Reservation
        """
        if dry_run:
            return
        self.active_reservation.expire(**kwargs)

    @fsm_log_by
    @transition(field=state,
                source=BicycleStates.RENTED.value,
                target=BicycleStates.AVAILABLE.value)
    def expire_rental_session(self, dry_run=False, **kwargs):
        """
        Expire the RentalSession
        """
        if dry_run:
            return
        self.active_rental_session.expire(**kwargs)

    @fsm_log_by
    @transition(field=state,
                source=BicycleStates.IN_MAINTENANCE.value,
                target=BicycleStates.RETIRED.value)
    def retire(self, dry_run=False, **kwargs):
        """Ends life time of Bicycle.
        Close also all causative resources.
        """
        if self.lock is not None:
            raise ValidationError('Lock must be unpaired before'
                                  ' retiring this Bicycle.')
        if self.axa_lock is not None:
            raise ValidationError('Axa Lock must be unpaired before'
                                  ' retiring this Bicycle.')
        if dry_run:
            return
        for alert in self.alerts.filter(state=AlertStates.NEW.value):
            alert.stop(**kwargs)
        for task in self.tasks.filter(state__in=(TaskStates.ASSIGNED.value,
                                                 TaskStates.UNASSIGNED.value)):
            task.cancel(**kwargs)
        for feedback in self.feedbacks.filter(state=FeedbackStates.NEW.value):
            feedback.discard(**kwargs)

    def delete(self):
        """
        TODO: Send an alert to the renter, the bicycle
        is not available for her anymore.
        """
        reservation = self.active_reservation
        if reservation is not None:
            reservation.close()
        rental_session = self.active_rental_session
        if rental_session is not None:
            rental_session.close()
        super().delete()

    class Meta(BaseModelMixin.Meta):
        unique_together = (
            ('organization', 'name'),
        )


class BicycleMetaData(BaseModelMixin):
    bicycle = models.OneToOneField(
        Bicycle,
        null=True,
        blank=True,
        default=True,
        related_name='metadata',
        related_query_name='metadata',
        on_delete=models.CASCADE,
    )
    recoverability_score = models.IntegerField(
        default=None,
        null=True, blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(100)])
    needs_attention_score = models.IntegerField(
        default=None,
        null=True, blank=True,
        validators=[MinValueValidator(0), MaxValueValidator(100)])


def get_default_push_alert_types() -> typing.List[str]:
    """Hack because of: (postgres.E003) JSONField default should be a callable
    instead of an instance so that it's not shared between all field instances.
    """
    return [t for t, _ in Alert.TYPES]


class OrganizationPreference(BaseModelMixin, OwnerableModelMixin,
                             GenericStateMixin, OrganizationOwnedModelMixin):
    METRIC = 'metric'
    IMPERIAL = 'imperial'
    UNIT_SYSTEMS = (
        (METRIC, 'Metric'),
        (IMPERIAL, 'Imperial'),
    )
    organization = models.OneToOneField(Organization,
                                        related_name='preference',
                                        related_query_name='preference',
                                        on_delete=models.CASCADE,
                                        )
    allowed_email_alert_types = JSONField(
        default=list,
        blank=True,
        help_text=(
            'List of enabled Alert types.\n'
            'Corresponds to enabled email notifications for each type.'
        ),
        validators=[validate_alert_types])
    allowed_push_alert_types = JSONField(
        default=get_default_push_alert_types,
        blank=True,
        help_text=(
            'List of enabled Alert types\n'
            'Corresponds to enabled push notification for each type.'
        ),
        validators=[validate_alert_types])
    alert_type_to_role_mapping = JSONField(
        default=dict,
        blank=True,
        help_text=(
            'A dictionary in which the keys correspond to Alert types\n'
            'and values to Roles. Specified Alert types notify the\n'
            'corresponding Role.'
        ),
        validators=[validate_alert_type_to_role_mapping]
    )
    name = models.CharField(max_length=128, blank=True)
    allow_returning_bicycle_outside_drop_zone = models.BooleanField(
        default=True
    )
    max_allowed_bicycles_per_renter = models.IntegerField(default=1)
    currency = models.CharField(
        choices=settings.CURRENCIES,
        max_length=10,
        blank=True,
        default='',
    )
    allow_renting_without_pricings = models.BooleanField(default=True)

    timezone = models.CharField(max_length=32,
                                default='UTC',
                                choices=[(tz, tz) for tz in
                                         pytz.common_timezones])
    operational_weekday_period = IntegerRangeField(
        default=None,
        null=True,
        blank=True,
        help_text=('Operational hours during weekdays.'),
        validators=[RangeMinValueValidator(0),
                    RangeMaxValueValidator(24)]
    )
    operational_weekend_period = IntegerRangeField(
        default=None,
        null=True,
        blank=True,
        help_text=('Operational hours during weekend.'),
        validators=[RangeMinValueValidator(0),
                    RangeMaxValueValidator(24)]
    )
    unit_system = models.CharField(max_length=9,
                                   choices=UNIT_SYSTEMS,
                                   default=METRIC)
    send_support_ticket_per_email = models.BooleanField(default=False)
    send_feedback_per_email = models.BooleanField(default=False)
    send_task_per_email = models.BooleanField(default=False)
    idle_bicycle_duration = models.DurationField(
        null=True,
        blank=True,
        default=None,
        help_text='Duration of inactivity after which \'Bicycle is idle for '
        'too long\' alert is triggered. Format: DAYS HOURS:MINS:SECS, e.g. '
        '1 05:20:00')
    email_domain_validation = models.CharField(
        max_length=128,
        blank=True,
        default='',
        help_text='If set, invitations must be accepted with an email that'
        ' belongs to that domain.',
    )

    duration_after_bicycle_is_lost = models.DurationField(
        null=True, blank=True, default=None,
        help_text='Duration of presence outside of service area after which '
        'bicycle is automatically transferred into \'Lost\' state. Format: '
        'DAYS HOURS:MINS:SECS, e.g. 1 05:20:00')
    max_inactive_rental_session_duration = models.DurationField(
        null=True, blank=True, default=None,
        help_text='Duration of inactivity after which current rental session '
        'is expired. Format: DAYS HOURS:MINS:SECS, e.g. 1 05:20:00')
    is_free_floating_fleet = models.BooleanField(default=False,
                                                 help_text='Deprecated.')
    is_access_controlled = models.BooleanField(
        default=True,
        help_text='Does the organization use access control (i.e. locks)?')
    support_email = models.EmailField(
        null=True, blank=True, default=None,
        help_text='Primary support email address.')
    support_phone_number = models.CharField(
        null=True, blank=True, max_length=128,
        help_text='Primary support phone number.')
    tax_percent = models.DecimalField(
        null=True, blank=True, max_digits=5, decimal_places=3,
        help_text='Tax percentage to apply to subscriptions and charges.'
    )

    @property
    def uses_payments(self):
        try:
            return self.organization.stripe_account is not None
        except Organization.DoesNotExist:
            return False

    def clean(self):
        if self.send_support_ticket_per_email and not self.support_email:
            raise ValidationError(
                'Cannot send support ticket per email without a support email')
        if self.uses_payments and not self.currency:
            raise ValidationError({
                'currency': 'This field is required with "uses_payments".'})


class RentingScheme(BaseModelMixin, OwnerableModelMixin, GenericStateMixin,
                    OrganizationOwnedModelMixin):
    organization = models.ForeignKey(Organization,
                                     related_name='renting_schemes',
                                     related_query_name='renting_scheme',
                                     on_delete=models.CASCADE,
                                     )
    bicycle = models.ForeignKey(Bicycle,
                                blank=True,
                                null=True,
                                related_name='renting_schemes',
                                related_query_name='renting_scheme',
                                on_delete=models.SET_NULL,
                                )
    max_reservation_duration = models.DurationField(blank=True, null=True)


class ReservationStates(Enum):
    NEW = 'new'
    CLOSED = 'closed'
    CANCELLED = 'cancelled'
    EXPIRED = 'expired'


class Reservation(BaseModelMixin, ActionableModelMixin, OwnerableModelMixin):
    user = models.ForeignKey(User,
                             related_name='reservations',
                             related_query_name='reservation',
                             on_delete=models.CASCADE,
                             )
    bicycle = models.ForeignKey(Bicycle,
                                related_name='reservations',
                                related_query_name='reservation',
                                on_delete=models.CASCADE,
                                )

    state = FSMField(default=ReservationStates.NEW.value, db_index=True)

    def __str__(self):
        return 'Bicycle[{}] User[{}] {}'.format(
            self.bicycle_id,
            self.user_id,
            self.state,
        )

    @property
    def default_duration(self):
        try:
            return (self.bicycle
                    .eligible_renting_schemes[:1]
                    .get().max_reservation_duration)
        except RentingScheme.DoesNotExist:
            return settings.DEFAULT_MAX_RESERVATION_DURATION

    @fsm_log_by
    @transition(field=state,
                source=ReservationStates.NEW.value,
                target=ReservationStates.CLOSED.value)
    def close(self, **kwargs):
        """No side effect."""
        pass

    @fsm_log_by
    @transition(field=state,
                source=ReservationStates.NEW.value,
                target=ReservationStates.CANCELLED.value)
    def cancel(self, **kwargs):
        """No side effect."""
        pass

    @fsm_log_by
    @transition(field=state,
                source=ReservationStates.NEW.value,
                target=ReservationStates.EXPIRED.value)
    def expire(self, **kwargs):
        """No side effect."""
        pass


class RentalSessionStates(Enum):
    NEW = 'new'
    CLOSED = 'closed'
    EXPIRED = 'expired'


class RentalSessionPaymentStates(Enum):
    UNKNOWN = 'unknown'
    PENDING = 'pending'
    FAILED = 'failed'
    PROCESSED = 'processed'
    SKIPPED = 'skipped'
    TRANSFERRED = 'transferred'
    IGNORE_UNPAID = 'ignore_unpaid'


class RentalSession(BaseModelMixin, ActionableModelMixin, OwnerableModelMixin):
    user = models.ForeignKey(User,
                             related_name='rental_sessions',
                             related_query_name='rental_session',
                             on_delete=models.CASCADE,
                             )
    bicycle = models.ForeignKey(Bicycle,
                                related_name='rental_sessions',
                                related_query_name='rental_session',
                                on_delete=models.CASCADE,
                                )
    subscription_plan = models.ForeignKey('lock8.SubscriptionPlan',
                                          related_name='rental_sessions',
                                          related_query_name='rental_session',
                                          blank=True, null=True, default=None,
                                          on_delete=models.SET_NULL)
    pricing_scheme = models.ForeignKey('lock8.PricingScheme',
                                       related_name='rental_sessions',
                                       related_query_name='rental_session',
                                       blank=True, null=True, default=None,
                                       on_delete=models.SET_NULL)
    duration = models.DurationField(blank=True, null=True, default=None,
                                    db_column='duration_of_rental_session')
    cents = models.IntegerField(blank=True, null=True,
                                verbose_name='Amount in cents')
    currency = models.CharField(choices=settings.CURRENCIES, max_length=10,
                                blank=True, null=True)
    charge = models.OneToOneField(Charge, blank=True, null=True, default=None,
                                  on_delete=models.SET_NULL)

    state = FSMField(default=RentalSessionStates.NEW.value, db_index=True)
    payment_state = FSMField(default=RentalSessionPaymentStates.UNKNOWN.value,
                             db_index=True)

    @property
    def duration_of_rental_session(self):
        """Deprecated."""
        return self.duration

    def __repr__(self):
        return (
            'RentalSession(pk=%r, user=%s, bicycle=%s, '
            'effective_pricing_scheme=%r, subscription_plan=%r, '
            'duration=%r, cents=%r, charge=%r)' % (
                self.pk,
                getattr(self, 'user', None),
                getattr(self, 'bicycle', None),
                self.effective_pricing_scheme,
                self.subscription_plan,
                str(self.duration) if self.duration else None,
                self.cents,
                self.charge))

    @property
    def effective_pricing_scheme(self):
        if (self.subscription_plan is not None and
                self.subscription_plan.pricing_scheme):
            return self.subscription_plan.pricing_scheme
        elif self.pricing_scheme is not None:
            return self.pricing_scheme

    @fsm_log_by
    @transition(field=state,
                source=RentalSessionStates.NEW.value,
                target=RentalSessionStates.CLOSED.value)
    def close(self, dry_run=False, **kwargs):
        """
        Close the rental session, computing the duration and price.

        Catches any exceptions to allow for the renter to return the Bicycle.
        """
        if dry_run:
            return
        try:
            with transaction.atomic():
                self.duration = timezone.now() - self.created
                pricing_scheme = self.effective_pricing_scheme
                if not pricing_scheme:
                    self.cents = 0
                    self.currency = ''
                    return

                self.cents = pricing_scheme.compute_amount_for_duration(
                    self.duration)

            if self.payment_state != 'pending':
                logger.warning(
                    'RentalSession.close was called with payment_state "%s"',
                    self.payment_state,
                    exc_info=True)
                return

            if self.charge or self.cents:
                from velodrome.celery import generate_payment
                transaction.on_commit(functools.partial(
                    generate_payment.delay,
                    self.pk))
            else:
                self.process_payment()

        except Exception as e:
            logger.exception('Exception in RentalSession.close: %s', e)

    @fsm_log_by
    @transition(field=state,
                source=RentalSessionStates.NEW.value,
                target=RentalSessionStates.EXPIRED.value)
    def expire(self, **kwargs):
        if self.effective_pricing_scheme:
            raise ValueError('Expiration forbidden.')

    @fsm_log_by
    @transition(field=payment_state,
                source=RentalSessionPaymentStates.UNKNOWN.value,
                target=RentalSessionPaymentStates.PENDING.value)
    def init_payment(self, **kawrgs):
        if self.subscription_plan:
            return

        organization = self.bicycle.organization
        if self.user.get_paid_rentalsessions(organization).exists():
            logger.info('init_payment: skipping uncaptured charge for recurring customer')  # noqa: E501
            return

        customer, _ = self.user.get_or_create_customer(organization)
        # Create charge with capture=False.
        cents_for_2h = self.pricing_scheme.compute_amount_for_duration(
            dt.timedelta(hours=2))
        try:
            self.charge = pinax.stripe.actions.charges.create(
                capture=False,
                amount=Decimal(cents_for_2h) / 100,
                customer=customer,
                currency=self.currency,
                send_receipt=False,
                idempotency_key=f'uncaptured-{self.uuid}')
            logger.info('init_payment: created uncaptured charge %s',
                        self.charge.stripe_id)
        except stripe.error.StripeError as exc:
            if isinstance(exc, stripe.error.CardError):
                if exc.code == 'missing':
                    raise ValidationError(
                        'The user has no payment method configured.',
                        code='user_has_no_cards')
                elif exc.code == 'card_declined':
                    json_error = exc.json_body['error']
                    decline_code = json_error['decline_code']
                    if decline_code == 'insufficient_funds':
                        raise ValidationError(
                            'The card has insufficient funds.',
                            code='user_card_insufficient_funds')
                    raise ValidationError(json_error['message'],
                                          code='user_card_declined')
                msg = '%s (code=%s)' % (exc.args[0], exc.code)
                raise ValidationError(
                    f'There was a card-related error: {msg}',
                    code='user_card_error')
            raise ValidationError(
                f'Could not create non-captured charge for customer: {exc}.',
                code='user_cannot_be_charged')

    @fsm_log_by
    @transition(field=payment_state,
                source=RentalSessionPaymentStates.PENDING.value,
                target=RentalSessionPaymentStates.PROCESSED.value,
                on_error=RentalSessionPaymentStates.FAILED.value)
    @transaction.atomic
    def process_payment(self):
        logger.info('process_payment for %r', self)
        to_charge = self.cents
        if not to_charge:
            if self.charge:
                logger.info('process_payment: refunding %s',
                            self.charge.stripe_id)
                self.charge.stripe_charge.refund()
            return

        amount = Decimal(to_charge) / 100

        if self.charge:
            # Capture amount on existing charge, if any.
            capturable_cents = self.charge.amount * 100
            if to_charge <= capturable_cents:
                logger.info('process_payment: capturing charge %s (%s)',
                            self.charge.stripe_id, amount)
                pinax.stripe.actions.charges.capture(
                    self.charge,
                    amount=amount,
                    idempotency_key=f'capture-{self.uuid}',
                )
                return

        # Create a single Charge, falling back to capturing any existing one.
        bicycle = self.bicycle
        user = self.user
        customer = user.get_customer(organization=bicycle.organization)
        currency = self.currency
        if self.charge:
            idempotency_key = f'replace-{self.uuid}'
        else:
            idempotency_key = f'create-{self.uuid}'
        try:
            charge = pinax.stripe.actions.charges.create(
                capture=True,
                amount=amount,
                customer=customer,
                currency=currency,
                send_receipt=False,
                idempotency_key=idempotency_key)
        except Exception:
            if self.charge:
                logger.exception(
                    'Failed to create new charge, capturing existing one.')
                pinax.stripe.actions.charges.capture(self.charge)
            else:
                logger.exception('process_payment: failed to create charge.')
            raise
        else:
            try:
                logger.info('process_payment: created charge %s (%s)',
                            charge.stripe_id, charge)
                if self.charge:
                    logger.info('process_payment: refunding uncaptured %s',
                                self.charge.stripe_id)
                    self.charge.stripe_charge.refund()
            except Exception as exc:
                # Handle any exceptions here, so that payment_state does not
                # become "failed".
                if (isinstance(exc, stripe.error.InvalidRequestError)
                        and exc.code == 'charge_already_refunded'):
                    logger.info('process_payment: charge was already refunded')
                else:
                    logger.exception(
                        'process_payment: error when refunding charge: %s',
                        exc
                    )
            self.charge = charge

    @fsm_log_by
    @transition(field=payment_state,
                source=RentalSessionPaymentStates.UNKNOWN.value,
                target=RentalSessionPaymentStates.SKIPPED.value)
    def skip_payment(self, **kawrgs):
        """No side effect."""

    @fsm_log_by
    @transition(field=payment_state,
                source=[
                    RentalSessionPaymentStates.FAILED.value,
                    RentalSessionPaymentStates.PENDING.value,
                    RentalSessionPaymentStates.UNKNOWN.value,
                ],
                target=RentalSessionPaymentStates.IGNORE_UNPAID.value)
    def ignore_unpaid(self, **kawrgs):
        """No side effect."""

    @fsm_log_by
    @transition(field=payment_state,
                source=RentalSessionPaymentStates.FAILED.value,
                target=RentalSessionPaymentStates.TRANSFERRED.value)
    def transfer_payment(self, charge):
        """Store the ID of the new Charge in the metadata."""
        if self.charge:
            existing_charge = self.charge.stripe_charge
            existing_charge.metadata.update(
                {'noa_transferred': charge.stripe_id})
            existing_charge.save()
        else:
            self.charge = charge
            self.save()

    @property
    def estimated_end_of_trip(self):
        """those 5mn are necessary because the tracker will wait one
        minute before sending the STOP trip event.
        And if the tracker is out of reach, will retry during 5mn
        to send this event."""
        try:
            ts = self.latest_transition.timestamp
        except AttributeError:
            ts = self.modified if self.modified else timezone.now()
        return ts + dt.timedelta(minutes=5)


def point_getter(instance):
    if instance.gps_longitude is None or instance.gps_latitude is None:
        return
    return Point(
        instance.gps_longitude,
        instance.gps_latitude)


point_getter.name = 'point'


def gps_latitude_getter(instance):
    try:
        return instance.attributes['gps_latitude'] / 1e6
    except (KeyError, TypeError):
        return


gps_latitude_getter.name = 'gps_latitude'


def gps_longitude_getter(instance):
    try:
        return instance.attributes['gps_longitude'] / 1e6
    except (KeyError, TypeError):
        return


gps_longitude_getter.name = 'gps_longitude'


def timestamp_getter(instance):
    if instance.time_stamp is None:
        return instance.created
    return dt.datetime.fromtimestamp(float(instance.time_stamp),
                                     tz=dt.timezone.utc)


timestamp_getter.name = 'timestamp'


class BaseTracking(BaseModelMixin,
                   GeoModel, metaclass=MetaJsonAccessorBuilder):
    class Meta:
        abstract = True
        get_latest_by = 'timestamp'

    AMBIENT_WEATHER_MESSAGE = AMBIENT_WEATHER_MESSAGE
    AMBIENT_GAS_MESSAGE = AMBIENT_GAS_MESSAGE
    GPS_LOCATION_MESSAGE = GPS_LOCATION_MESSAGE
    CELLULAR_LOCATION_MESSAGE = CELLULAR_LOCATION_MESSAGE
    DEVICE_SYSTEM_STATUS_MESSAGE = DEVICE_SYSTEM_STATUS_MESSAGE
    TRACKING_TYPES = (
        (GPS_LOCATION_MESSAGE, 'GPS Location'),
        (CELLULAR_LOCATION_MESSAGE, 'Cellular Location'),
        (DEVICE_SYSTEM_STATUS_MESSAGE, 'Device System Status'),
        (BATTERY_MESSAGE, 'Battery Message'),  # legacy
        (AMBIENT_WEATHER_MESSAGE, 'Ambient Weather'),
        (AMBIENT_GAS_MESSAGE, 'Ambient Gas'),
    )

    # Meta JSON fields
    meta_json_placeholder_name = 'attributes'
    timestamp = IndexedDateTimeField()
    point = IndexedPointField()
    state_of_charge = IndexedFloatJsonField()
    attributes = JSONField(blank=True)

    exposed_attributes = (
        'serial_number',
        'time_stamp',
        'gps_utm_zone',
        'gps_accuracy',
        gps_longitude_getter,
        gps_latitude_getter,
        'voltage',
        'state_of_charge',
        point_getter,
        timestamp_getter,
        'firmware_version_tag',
        'event',
        'lock_status',
        'gps_pdop',
        'temperature',
        'relative_humidity',
        'nitrogen_dioxide',
        'carbon_monoxide',
    )

    def __init__(self, *args, **kwargs):
        if 'bicycle' in kwargs or 'lock' in kwargs:
            raise ValidationError(
                'You are not allowed to pass in a bicycle/lock directly.')
        super().__init__(*args, **kwargs)

    def __str__(self):
        return '#{} ({}, @{})'.format(
            self.pk if self.pk else '-',
            self.serial_number if self.serial_number else '-',
            self.timestamp.isoformat() if self.timestamp else '-'
        )

    @property
    def dt(self):
        return self.timestamp


class LatestTracking(BaseTracking):
    gps_timestamp = IndexedDateTimeField()

    class Meta:
        abstract = True

    def _provision(self, **kwargs):
        """No side effect."""

    @property
    def estimated_state_of_charge(self):
        if self.state_of_charge:
            return charge_estimator(self.state_of_charge, self.dt.timestamp())


class PublicTracking(LatestTracking):
    pass


class PrivateTracking(LatestTracking):
    pass


class TrackingStates(Enum):
    NEW = 'new'
    PROVISIONED = 'provisioned'
    DISCARDED = 'discarded'


class Tracking(BaseTracking, ActionableModelMixin, GenericStateMixin):
    # Deprecated.
    time_stamp = IndexedPositiveIntegerJsonField()
    message_uuid = models.UUIDField(unique=True, blank=True, null=True,
                                    default=None)
    message_timestamp = models.DateTimeField(blank=True, null=True,
                                             default=None)
    bicycle = models.ForeignKey(Bicycle, blank=True, null=True,
                                related_name='trackings',
                                related_query_name='tracking',
                                on_delete=models.PROTECT)
    lock = models.ForeignKey(Lock, blank=True, null=True,
                             related_name='trackings',
                             related_query_name='tracking',
                             on_delete=models.PROTECT)
    tracking_type = models.CharField(max_length=3,
                                     choices=BaseTracking.TRACKING_TYPES,
                                     default=GPS_LOCATION_MESSAGE)
    state = FSMField(default=TrackingStates.NEW.value, db_index=True)
    organization = models.ForeignKey(Organization, blank=True, null=True,
                                     related_name='%(class)ss',
                                     related_query_name='%(class)s',
                                     on_delete=models.PROTECT)

    def __str__(self):
        return '#{} ({}, {}, @{})'.format(
            self.pk if self.pk else '-',
            self.get_tracking_type_display(),
            self.serial_number if self.serial_number else '-',
            self.timestamp.isoformat() if self.timestamp else '-'
        )

    @fsm_log_by
    @transition(field=state,
                source=TrackingStates.NEW.value,
                target=TrackingStates.PROVISIONED.value)
    def provision(self, **kwargs):
        raise RuntimeError  # pragma: no cover


class ReadonlyTracking(models.Model):
    class Meta:
        managed = settings.IS_TESTER
        db_table = 'tracking'

    uuid = models.UUIDField(unique=True)
    created = models.DateTimeField(auto_now_add=True)
    bicycle_uuid = models.UUIDField(blank=True, null=True)
    device_uuid = models.UUIDField(blank=True, null=True)
    organization_uuid = models.UUIDField(blank=True, null=True)
    tracking_type = models.CharField(max_length=3,
                                     choices=BaseTracking.TRACKING_TYPES,
                                     default=GPS_LOCATION_MESSAGE)
    state = FSMField(default=TrackingStates.NEW.value, db_index=True)
    attributes = JSONField()
    point = PointField(blank=True, null=True)
    timestamp = models.DateTimeField()

    def __str__(self):
        return '#{} ({}, @{})'.format(
            self.pk if self.pk else '-',
            self.tracking_type,
            self.timestamp.isoformat() if self.timestamp else '-'
        )

    def is_sibling_tracking(self, other: Tracking):
        return self.uuid and self.uuid == other.message_uuid

    def get_diff_to_tracking(self, other: Tracking):
        diff = {}

        def rgetattr(obj, attr):
            _getattr = getattr
            try:
                return functools.reduce(_getattr, [obj]+attr.split('.'))
            except AttributeError:
                return None

        for (field, other_field) in (
                ('uuid', 'message_uuid'),
                # ('created', 'created'),
                # ('bicycle_uuid', 'bicycle.uuid'),
                ('device_uuid', 'lock.uuid'),
                ('organization_uuid', 'organization.uuid'),
                ('tracking_type', 'tracking_type'),
                ('state', 'state'),
                ('attributes', 'attributes'),
                ('point.latitude', 'point.latitude'),
                ('point.longitude', 'point.longitude'),
                ('timestamp', 'timestamp'),
        ):
            this_value = rgetattr(self, field)
            other_value = rgetattr(other, other_field)

            if this_value != other_value:
                diff[field] = (this_value, other_value)
        return diff


class TripQuerySet(NullsLastQuerySet):
    def annotate_with_speed(self):
        return self.annotate(
            speed=Case(
                When(duration__gt=dt.timedelta(seconds=0), then=(
                    F('distance_m') * Value(3.6)
                    # https://code.djangoproject.com/ticket/27473#ticket
                    / DurationExtract(F('duration'), 'epoch'))),
                default=None,
                output_field=FloatField()))


class Trip(models.Model):
    ASSET_IN_SERVICE = 'in_service'
    ASSET_IN_MAINTENANCE = 'in_maintenance'
    ASSET_PRIVATE = 'private'
    ASSET_TYPES = (
        (ASSET_IN_SERVICE, 'In service'),
        (ASSET_IN_MAINTENANCE, 'In maintenace'),
        (ASSET_PRIVATE, 'Private'),
    )

    TYPE_REGULAR = 'regular'
    TYPE_SUSPICIOUS = 'suspicious'
    TYPES = (
        (TYPE_REGULAR, TYPE_REGULAR),
        (TYPE_SUSPICIOUS, TYPE_SUSPICIOUS),
    )

    uuid = models.UUIDField(unique=True)
    created = models.DateTimeField(auto_now_add=True)
    modified = models.DateTimeField(auto_now=True)
    bicycle_uuid = models.UUIDField(blank=True, null=True)
    organization_uuid = models.UUIDField(blank=True, null=True)
    start_date = models.DateTimeField(db_column='started')
    end_date = models.DateTimeField(blank=True, null=True, db_column='ended')
    route = LineStringField(blank=True, null=True)
    snapped_route = LineStringField(blank=True, null=True)
    duration = models.DurationField(blank=True, null=True)
    distance_m = models.IntegerField(blank=True, null=True,
                                     verbose_name='Distance (m)')
    serial_number = models.CharField(max_length=24)
    gps_average_accuracy = models.FloatField(blank=True, null=True)
    gps_time_first_fix = models.IntegerField(blank=True, null=True)
    gps_timeout_events = models.IntegerField(blank=True, null=True,
                                             verbose_name='GPS timeouts')
    cell_time_connect = models.IntegerField(blank=True, null=True)
    cell_timeout_events = models.IntegerField(blank=True, null=True,
                                              verbose_name='cell timeouts')
    state_charge_start = models.FloatField(blank=True, null=True)
    state_charge_end = models.FloatField(blank=True, null=True)
    is_valid = models.NullBooleanField(verbose_name='valid')
    asset_state = models.CharField(max_length=14, choices=ASSET_TYPES)
    type = models.CharField(max_length=10, choices=TYPES)
    last_gps_accuracy = models.FloatField(null=True)

    objects = TripQuerySet.as_manager()

    class Meta:
        managed = settings.IS_TESTER
        db_table = 'trip'
        ordering = ('-pk',)

    def __str__(self):
        return '#{} ({}, {}, @{})'.format(
            self.pk if self.pk else '-',
            self.type,
            '{}m'.format(self.distance_m) if self.distance_m else '-',
            self.created.isoformat() if self.created else '-'
        )

    @property
    def organization(self):
        return Organization.objects.get(uuid=self.organization_uuid)

    @property
    def bicycle(self):
        return Bicycle.objects.get(uuid=self.bicycle_uuid)

    @classmethod
    def get_queryset(cls, request=None, **kwargs):
        user = request.user
        qs = cls.objects.all()

        if 'rental_session' in request.query_params:
            uuids = tuple(user.get_descendants_organizations()
                          .values_list('uuid', flat=True))
            predicate = Q(organization_uuid__in=uuids)
        else:
            uuids = tuple(user.get_descendants_managed_organizations()
                          .values_list('uuid', flat=True))
            predicate = Q(organization_uuid__in=uuids)
            try:
                rental_session = user.rental_sessions.latest()
            except RentalSession.DoesNotExist:
                pass
            else:
                # enable access only to the latest rental_session
                # of current user.
                if rental_session.state == RentalSessionStates.CLOSED.value:
                    end_date = (
                        Q(end_date__lt=rental_session.estimated_end_of_trip) |
                        Q(end_date__isnull=True))
                    predicate |= Q(
                        start_date__gte=rental_session.created,
                        bicycle_uuid=rental_session.bicycle.uuid) & end_date
                else:
                    predicate |= Q(
                        start_date__gte=rental_session.created,
                        bicycle_uuid=rental_session.bicycle.uuid)
        return qs.filter(predicate)


class TermsOfService(BaseModelMixin, OrganizationOwnedModelMixin,
                     GenericStateMixin, OwnerableModelMixin):
    organization = models.ForeignKey(Organization,
                                     related_name='terms_of_services',
                                     related_query_name='terms_of_service',
                                     on_delete=models.CASCADE,)
    tos_url = models.URLField(max_length=254, blank=True,
                              help_text='Optional URL for TOS')
    language = LanguageField(help_text='Language code of TOS')
    content = models.TextField(blank=True, null=True)
    version = models.ForeignKey('TermsOfServiceVersion',
                                related_name='terms_of_services',
                                related_query_name='terms_of_service',
                                on_delete=models.CASCADE,)

    class Meta(BaseModelMixin.Meta):
        unique_together = (
            ('organization', 'language', 'version'),
        )

    @classmethod
    def get_queryset(cls, request=None, **kwargs):
        user = request.user
        qs = cls.objects.select_related('organization', 'version')
        managed_organizations = set(
            user.get_descendants_managed_organizations().values_list(
                'pk', flat=True))
        renter_predicate = Q(
            state=GenericStates.PROVISIONED.value,
            version__isnull=False,
            version__state=GenericStates.PROVISIONED.value,
            organization__in=user.get_descendants_organizations())
        if not managed_organizations:
            return qs.filter(renter_predicate)

        admin_predicate = renter_predicate | Q(
            organization__in=managed_organizations)

        return qs.filter(admin_predicate).distinct()

    def __str__(self):
        return f'TOS[{self.id}] / Organization[{self.organization_id}]'

    def __repr__(self):
        return (
            f'TermsOfService(pk={self.pk!r}, language={self.language!r}, '
            f'version={getattr(self, "version", None)!r}, '
            f'organization={getattr(self, "organization", None)!r})')


class TermsOfServiceVersion(BaseModelMixin, OrganizationOwnedModelMixin,
                            GenericStateMixin):
    organization = models.ForeignKey(
        Organization,
        related_name='terms_of_service_versions',
        related_query_name='terms_of_service_version',
        on_delete=models.CASCADE,)
    label = models.CharField(blank=True, max_length=40)

    def _provision(self, **kwargs):
        if not self.terms_of_services.filter(
                state=GenericStates.PROVISIONED.value).exists():
            raise ValidationError(
                'There are no provisioned terms of service assigned to this '
                'version')
        provisioned_version = TermsOfServiceVersion.objects.filter(
            organization=self.organization,
            state=GenericStates.PROVISIONED.value).first()
        if provisioned_version:
            raise ValidationError(
                'Cannot provision terms of service version.'
                f' Version {provisioned_version.uuid} is already provisioned.')

    def __str__(self):
        return (f'TOSVersion[{self.id} - {self.label}] / '
                f'Organization[{self.organization_id}]')

    def __repr__(self):
        return (
            f'TermsOfServiceVersion(pk={self.pk!r}, label={self.label!r}, '
            f'organization={getattr(self, "organization", None)!r})')


class AcceptedTermsOfService(BaseModelMixin):
    user = models.ForeignKey(User, related_name='accepted_terms_of_services',
                             related_query_name='accepted_terms_of_service',
                             on_delete=models.CASCADE)
    terms_of_service = models.ForeignKey(
        TermsOfService, related_name='accepted_terms_of_services',
        related_query_name='accepted_terms_of_service',
        on_delete=models.CASCADE)

    class Meta(BaseModelMixin.Meta):
        unique_together = (('user', 'terms_of_service'),)

    def __repr__(self):
        return (
            f'AcceptedTermsOfService(pk={self.pk!r}, '
            f'terms_of_service={getattr(self, "terms_of_service", None)!r}, '
            f'user={getattr(self, "user", None)!r})')


class InvitationStates(Enum):
    NEW = 'new'
    PROVISIONED = 'provisioned'
    CONFIRMED = 'confirmed'
    CANCELLED = 'cancelled'
    DECLINED = 'declined'


class Invitation(BaseModelMixin, ActionableModelMixin,
                 OwnerableModelMixin):
    organization = models.ForeignKey(Organization,
                                     related_name='invitations',
                                     related_query_name='invitation',
                                     on_delete=models.CASCADE,
                                     )
    user = models.ForeignKey(User,
                             related_name='invitations',
                             related_query_name='invitation',
                             blank=True,
                             null=True,
                             on_delete=models.SET_NULL,
                             )
    email = models.EmailField(max_length=254)
    role = models.CharField(max_length=25,
                            choices=list(Affiliation.ROLES),
                            default=Affiliation.RENTER)
    state = FSMField(default=InvitationStates.NEW.value, db_index=True)

    def __str__(self):
        return '{} of Organization[{}] {}'.format(
            self.email,
            self.organization_id,
            self.state)

    def _provision_or_resend(self, request, dry_run=False):
        if dry_run:
            return
        if request is not None:
            base_url = request.build_absolute_uri('/')[:-1]
        else:
            base_url = ''
        self.send_invitation_email(base_url)

    @fsm_log_by
    @transition(field=state,
                source=InvitationStates.NEW.value,
                target=InvitationStates.PROVISIONED.value)
    def provision(self, request=None, dry_run=False, **kwargs):
        """
        Send invitation email.
        """
        self._provision_or_resend(request, dry_run)

    @fsm_log_by
    @transition(field=state,
                source=[InvitationStates.NEW.value,
                        InvitationStates.PROVISIONED.value],
                target=InvitationStates.PROVISIONED.value)
    def resend(self, request=None, dry_run=False, **kwargs):
        """
        Resend invitation email.
        """
        self._provision_or_resend(request, dry_run)

    def send_invitation_email(self, base_url):
        """
        Send invitation email.
        """
        organization_name = self.organization.name
        organization_icon = (self.organization.image.url if
                             self.organization.image else None)
        already_exists = (self.user is not None or
                          User.objects.filter_local_users(
                              email__iexact=self.email)
                          .exists())
        username = self.user.display_name if self.user is not None else ''
        if self.role == Affiliation.RENTER:
            invitation_url = '{}/{}?{}'.format(
                    settings.FRONTEND_INVITATION_URL,
                    str(self.uuid),
                    urlencode({
                        'organization_name': organization_name,
                        'organization_icon': organization_icon,
                        'email': self.email,
                        'signup': 0 if already_exists else 1,
                    }))
        else:
            invitation_url = '{}/invitation/{}?{}'.format(
                    settings.FRONTEND_URL,
                    str(self.uuid),
                    urlencode({
                        'organization_name': organization_name,
                        'organization_icon': organization_icon,
                        'email': self.email,
                        'signup': 0 if already_exists else 1,
                    }))
        context = {
            'base_url': base_url,
            'uuid': str(self.uuid),
            'organization_name': organization_name,
            'organization_icon': organization_icon,
            'username': username,
            'invitation_url': invitation_url,
            'support_email': self.organization.get_preference('support_email')
        }
        send_email('Noa - Invitation to join the organization {}.'.format(
            organization_name), [self.email], 'email/user_invitation.txt',
                   template_html='email/user_invitation.html',
                   context=context)

    @fsm_log_by
    @transition(field=state,
                source=InvitationStates.PROVISIONED.value,
                target=InvitationStates.CANCELLED.value)
    def cancel(self, **kwargs):
        """
        Cancel the invitation, after email was sent.
        """
        pass

    @fsm_log_by
    @transition(field=state,
                source=InvitationStates.PROVISIONED.value,
                target=InvitationStates.CONFIRMED.value)
    def confirm(self, by=None, dry_run=False, **kwargs):
        """
        Assign user to Organization.
        """
        self.user = by
        email_domain_validation = self.organization.get_preference(
            'email_domain_validation')
        if email_domain_validation:
            user_domain = by.email.partition('@')[2]
            if user_domain != email_domain_validation:
                raise ValidationError(
                    'User email address domain is not allowed.')
        already_manager = by.get_descendants_managed_organizations(
            Q(pk=self.organization.pk, is_whitelabel=True)).exists()
        if already_manager and self.role == Affiliation.RENTER:
            raise ValidationError('You cannot be invited as a renter to this'
                                  ' fleet with this account. You must accept'
                                  ' this invitation from another account.',
                                  code='user_organization_mismatch')
        if dry_run:
            return
        if not Affiliation.objects.filter(
                user=by,
                role=self.role,
                organization=self.organization,
                ).exists():
            Affiliation.objects.create(
                user=by,
                role=self.role,
                organization=self.organization,
            )
        if self.role == Affiliation.RENTER and self.organization.is_whitelabel:
            by.organization = self.organization
            by.save()

    @fsm_log_by
    @transition(field=state,
                source=InvitationStates.PROVISIONED.value,
                target=InvitationStates.DECLINED.value)
    def decline(self, **kwargs):
        """
        User declined the invitation.
        """
        pass


PricingSchemeRange = namedtuple('PricingSchemeRange', ['lower_duration',
                                                       'upper_duration',
                                                       'cents',
                                                       'prorated',
                                                       'prorated_duration'])


class PricingScheme(BaseModelMixin, ActionableModelMixin,
                    GenericStateMixin, OwnerableModelMixin,
                    OrganizationOwnedModelMixin):
    """
    Store Business rules to compute an amount based on rental duration.
    """
    organization = models.ForeignKey(Organization,
                                     related_name='pricing_schemes',
                                     related_query_name='pricing_scheme',
                                     on_delete=models.CASCADE,
                                     )
    bicycle_model = models.ForeignKey(BicycleModel,
                                      null=True, blank=True,
                                      related_name='pricing_schemes',
                                      related_query_name='pricing_scheme',
                                      on_delete=models.SET_NULL)
    name = models.CharField(max_length=255, blank=True)
    max_daily_charged_cents = models.IntegerField(blank=True, null=True)
    time_ranges = JSONField(default=list, validators=[validate_time_ranges],
                            help_text='A list of time ranges (%s), e.g. %s' % (
                                ', '.join(PricingSchemeRange._fields),
                                '[[0, null, 500, false, null]]'))
    description = JSONField(
        default=dict,
        help_text=(
            'Dictionary of localized pricing scheme descriptions, e.g. %s' % (
                '{"en": {"title": "Title", "description": "Description", '
                '"short_description": "Short", "fine_print": "Fine print"}}')),
        validators=[validate_payment_description])

    def __repr__(self):
        return ('PricingScheme(pk=%r, name=%r, time_ranges=%r, '
                'max_daily_charged_cents=%r)' % (
                    self.pk,
                    self.name,
                    self.time_ranges,
                    self.max_daily_charged_cents))

    @classmethod
    def get_queryset(cls, request=None, **kwargs):
        user = request.user
        renter_predicate = Q(
            state=GenericStates.PROVISIONED.value,
            organization__in=user.get_descendants_organizations())
        admin_predicate = Q(
            organization__in=user.get_descendants_managed_organizations())
        predicate = renter_predicate | admin_predicate
        return cls.objects.filter(predicate).distinct()

    @classmethod
    def _validate_global_pricing_scheme(cls, org, pricing_scheme=None):
        """Check consistency.
        Make sure only one PricingScheme is provisioned at a time per
        Organization if not attached to a SubscriptionPlan nor a BicycleModel.
        """
        predicate = Q(
            organization=org,
            subscription_plan__isnull=True,
            bicycle_model__isnull=True,
            state=GenericStates.PROVISIONED.value)
        if pricing_scheme is not None:
            predicate &= ~Q(pk=pricing_scheme.pk)
        if PricingScheme.objects.filter(predicate).exists():
            raise ValidationError(
                'A global PricingScheme is already provisioned in the'
                ' scope of this organization.')

    def _provision(self, **kwargs):
        if not self.organization.uses_payments:
            raise ValidationError(
                "This organization doesn't have payments activated")

        if self.bicycle_model is None:
            try:
                self.subscription_plan
            except SubscriptionPlan.DoesNotExist:
                org = getattr(self, 'organization', None)
                self._validate_global_pricing_scheme(org, self)

    def clean(self):
        super().clean()
        validate_time_ranges(self.time_ranges)

    def __str__(self):
        return '{} Organization #{} BicycleModel #{}'.format(
            self.name,
            self.organization_id,
            self.bicycle_model_id,
        )

    def compute_amount_for_duration(self, duration: dt.timedelta) -> int:
        partial_duration = dt.timedelta(seconds=duration.total_seconds())
        cents = 0
        for item in self.time_ranges:
            pricing_scheme_range = PricingSchemeRange(*item)
            partial_seconds = int(partial_duration.total_seconds())
            if pricing_scheme_range.upper_duration is None:
                # this is the last price_range
                if pricing_scheme_range.prorated:
                    cents += math.ceil(
                        partial_seconds *
                        pricing_scheme_range.cents /
                        pricing_scheme_range.prorated_duration /
                        60  # prorated is in minutes
                    )
                elif pricing_scheme_range.prorated_duration:
                    ranges, rest = divmod(
                        partial_seconds,
                        pricing_scheme_range.prorated_duration * 60)
                    cents += ((ranges + int(bool(rest))) *
                              pricing_scheme_range.cents)
                elif partial_seconds:
                    cents += pricing_scheme_range.cents
            else:
                sliced_duration = dt.timedelta(
                    minutes=(pricing_scheme_range.upper_duration -
                             pricing_scheme_range.lower_duration))
                sliced_seconds = sliced_duration.total_seconds()
                if pricing_scheme_range.prorated:
                    cents += math.ceil(
                        min(sliced_seconds, partial_seconds) *
                        pricing_scheme_range.cents /
                        pricing_scheme_range.prorated_duration /
                        60  # prorated is in minutes
                    )
                elif pricing_scheme_range.prorated_duration:
                    ranges, rest = divmod(
                        partial_seconds,
                        pricing_scheme_range.prorated_duration * 60)
                    cents += ((ranges + int(bool(rest))) *
                              pricing_scheme_range.cents)
                elif partial_seconds:
                    cents += pricing_scheme_range.cents
                if partial_duration >= sliced_duration:
                    partial_duration -= sliced_duration
                else:
                    partial_duration = dt.timedelta(0)
        try:
            tax_percent = self.organization.get_preference('tax_percent')
        except self._meta.model.organization.RelatedObjectDoesNotExist:
            pass
        else:
            if tax_percent:
                cents += int(
                    Decimal(Decimal(cents) / 100 * tax_percent).quantize(
                        Decimal('1'), rounding=ROUND_CEILING))
        return cents


class SubscriptionPlan(ActionableModelMixin, BaseModelMixin,
                       GenericStateMixin, OwnerableModelMixin,
                       OrganizationOwnedModelMixin):
    """
    A model that will be useful to configure a stripe:Plan.
    The user will be charged the same amount periodically disregarding
    consumption of the service.
    """
    DAY, WEEK, MONTH, YEAR = 'day', 'week', 'month', 'year'
    INTERVALS = ((DAY, 'day'),
                 (WEEK, 'week'),
                 (MONTH, 'month'),
                 (YEAR, 'year'))
    STRIPE_FIELDS_UPDATABLE = ('name', 'statement_descriptor',
                               'trial_period_days')

    organization = models.ForeignKey(Organization,
                                     related_name='subscription_plans',
                                     related_query_name='subscription_plan',
                                     on_delete=models.CASCADE,
                                     )
    plan = models.OneToOneField(Plan, blank=True, null=True, default=None,
                                on_delete=models.CASCADE)
    pricing_scheme = models.OneToOneField(
        PricingScheme,
        related_name='subscription_plan',
        related_query_name='subscription_plan',
        blank=True,
        null=True,
        on_delete=models.CASCADE)
    bicycle_model = models.ForeignKey(BicycleModel,
                                      null=True, blank=True,
                                      related_name='subscription_plans',
                                      related_query_name='subscription_plan',
                                      on_delete=models.SET_NULL)
    name = models.CharField(max_length=100)
    interval = models.CharField(max_length=10, choices=INTERVALS)
    description = JSONField(
        default=dict, blank=True,
        help_text='Dictionary of localized subscription plan descriptions.',
        validators=[validate_payment_description])
    cents = models.IntegerField(verbose_name='Amount (per period) in cents')
    interval_count = models.IntegerField(default=1)
    trial_period_days = models.IntegerField(default=0)
    statement_descriptor = models.TextField(blank=True)
    available_dates = DateTimeRangeField(default=None, null=True, blank=True)
    weekdays = IntegerRangeField(default=None, null=True, blank=True,
                                 help_text=('Days of the week, from 1 to 7'
                                            ' where Monday is 1.'),
                                 validators=[RangeMinValueValidator(1),
                                             RangeMaxValueValidator(7)])
    is_restricted = models.BooleanField(
        default=False, help_text=('Restricted plans are availabe only to users'
                                  ' associated through plan_passes'))

    class Meta(BaseModelMixin.Meta):
        unique_together = (('organization', 'name'),)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._prev_pricing_scheme = self.pricing_scheme

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        self._prev_pricing_scheme = self.pricing_scheme

    @classmethod
    def get_queryset(cls, request=None, **kwargs):
        user = request.user
        renter_predicate = Q(
            state=GenericStates.PROVISIONED.value,
            organization__in=user.get_descendants_organizations())
        admin_predicate = Q(
            organization__in=user.get_descendants_managed_organizations())
        predicate = renter_predicate | admin_predicate
        return cls.objects.filter(predicate).distinct()

    @property
    def stripe_id(self):
        try:
            return self.plan.stripe_id
        except AttributeError:
            return ('{env}-{organization}#{org_pk}'
                    '-{name}-#{subscription_plan_pk}'.format(
                        env=settings.ENVIRONMENT,
                        organization=self.organization.name,
                        org_pk=self.organization.pk,
                        name=self.name,
                        subscription_plan_pk=self.pk))

    def get_kwargs_for_plan(self, update=False):
        kwargs = {
            'name': self.name,
            'statement_descriptor': self.statement_descriptor,
            'trial_period_days': self.trial_period_days}
        if not update:
            kwargs.update({
                'amount': Decimal(self.cents) / 100 if self.cents else 0,
                'currency': self.organization.get_preference(
                    'currency', default=settings.DEFAULT_CURRENCY),
                'interval': self.interval,
                'interval_count': self.interval_count,
                'name': self.name,
                'statement_descriptor': self.statement_descriptor,
                'trial_period_days': self.trial_period_days,
            })
        return kwargs

    def subscribe_user(self, user, stripe_source, quantity=1, coupon=None,
                       auto_renewal=False):
        customer = user.get_customer(self.organization)
        stripe_plan = self.plan
        try:
            subscription = Subscription.objects.get(
                customer=customer,
                plan=stripe_plan,
                status__in=Subscription.STATUS_CURRENT)
        except Subscription.DoesNotExist:
            subscription = pinax.stripe.actions.subscriptions.create(
                customer,
                self.plan.stripe_id,
                quantity=quantity,
                coupon=coupon,
                trial_days=self.trial_period_days,
                token=stripe_source,
                tax_percent=self.organization.get_preference('tax_percent'),
            )
        else:
            if not subscription.cancel_at_period_end:
                raise SubscriptionExistsError()
            # Updating the subscription will set cancel_at_period_end=False.
            updated_stripe_sub = stripe.Subscription.modify(
                subscription.stripe_id,
                stripe_account=subscription.stripe_account_stripe_id)
            updated_subscription = sync_subscription_from_stripe_data(
                customer, updated_stripe_sub)
            assert updated_subscription == subscription, \
                'Existing subscription was updated'
            subscription = updated_subscription

        if auto_renewal is False:
            subscription = self.unsubscribe_user(user, at_period_end=True)

        return subscription

    def unsubscribe_user(self, user, at_period_end):
        customer = user.get_customer(self.organization)
        plan = self.plan

        # Handle multiple subscriptions for now.
        # It should not happen (with new customers/data), but better to not
        # crash.
        subscriptions = Subscription.objects.filter(
            customer=customer,
            plan=plan,
            status__in=Subscription.STATUS_CURRENT).order_by('created_at')
        if not subscriptions:
            raise ObjectDoesNotExist()

        if subscriptions.count() > 1:
            logger.exception(
                'Found multiple subscriptions for user %r: %s',
                user, ', '.join([str(x.pk) for x in subscriptions]))
        for subscription in subscriptions:
            try:
                subscription = pinax.stripe.actions.subscriptions.cancel(
                    subscription, at_period_end=at_period_end)
            except stripe.error.InvalidRequestError as exc:
                if exc.param == 'subscription':
                    logger.warning(f'{exc}: {exc.json_body}')
                else:
                    raise exc
        return subscription

    def can_be_used_by_user(self, user):
        if not self.state == GenericStates.PROVISIONED.value:
            return False
        if not self.is_restricted:
            return True
        return self.users.filter(pk=user.pk).exists()

    def clean(self):
        super().clean()

        # Validate global pricing scheme if a pricing scheme was removed here.
        if (self.pricing_scheme is None
                and self._prev_pricing_scheme is not None):
            PricingScheme._validate_global_pricing_scheme(self.organization)

        if self.plan:
            plan = self.plan
            if not plan.currency:
                raise ValidationError({
                    'plan': 'Plan requires to have a currency.'})

        state = self.state
        if (self.state == GenericStates.PROVISIONED.value
                and not self.plan
                and self.latest_transition
                and self.latest_transition.state != GenericStates.NEW.value):
            raise ValidationError({'plan': (
                'A Plan is required for provisioned state. '
                'This should get handled automatically - '
                'might just have been created.')})

        # Already provisioned, or in the process of getting provisioned.
        state = self.state
        if state != GenericStates.NEW.value and self.plan:
            errors = {}
            for k, v in self.get_kwargs_for_plan(False).items():
                if k in self.STRIPE_FIELDS_UPDATABLE:
                    continue
                if k == 'currency':
                    continue
                if k == 'stripe_account':
                    continue
                if k == 'amount':
                    old = self.plan.amount * 100
                    k = 'cents'
                else:
                    old = getattr(self.plan, k)
                new = getattr(self, k)
                if old != new:
                    errors[k] = ValidationError(
                        'Value cannot be changed after provisioning.')
            if errors:
                raise ValidationError(errors)

    def _provision(self, **kwargs):
        """
        Provision also the pricing_scheme.
        """
        if not self.organization.uses_payments:
            raise ValidationError(
                "This organization doesn't have payments activated")
        if (self.pricing_scheme is not None and
                self.pricing_scheme.state == GenericStates.NEW.value):
            self.pricing_scheme.provision()

    def __repr__(self):
        return 'SubscriptionPlan(pk=%r, name=%r, plan=%r, state=%r)' % (
            self.pk, self.name, self.plan, self.state)

    def __str__(self):
        return f'{self.name} Organization[{self.organization_id}]'


class PlanPass(BaseModelMixin):
    user = models.ForeignKey(User, related_name='plan_passes',
                             related_query_name='plan_pass',
                             on_delete=models.CASCADE)
    subscription_plan = models.ForeignKey(
        SubscriptionPlan, related_name='plan_passes',
        related_query_name='plan_pass', on_delete=models.CASCADE)

    def __str__(self):
        return (f'SubscriptionPlan[{self.subscription_plan_id}] - '
                f'User[{self.user_id}]')

    def __repr__(self):
        return 'PlanPass(pk=%r, user=%r, subscription_plan=%r)' % (
            self.pk, self.user, self.subscription_plan)

    class Meta(BaseModelMixin.Meta):
        unique_together = ('user', 'subscription_plan')
        verbose_name_plural = 'plan passes'

    def clean(self):
        try:
            subscription_plan = self.subscription_plan
        except SubscriptionPlan.DoesNotExist:
            return
        try:
            user = self.user
        except User.DoesNotExist:
            return
        if subscription_plan.state != GenericStates.PROVISIONED.value:
            raise ValidationError(
                f'SubscriptionPlan must be {GenericStates.PROVISIONED.value}.')
        if not user.get_descendants_organizations(
                Q(pk=subscription_plan.organization.pk)).exists():
            raise ValidationError(
                f'User {user} does not belong to'
                ' {subscription_plan.organization}')


class LockConnection(models.Model):
    bicycle = models.ForeignKey('Bicycle',
                                related_name='lock_connections',
                                related_query_name='lock_connection',
                                on_delete=models.CASCADE)
    lock = models.ForeignKey('Lock',
                             related_name='lock_connections',
                             related_query_name='lock_connection',
                             on_delete=models.CASCADE)
    paired = models.DateTimeField(auto_now_add=True)
    detached = models.DateTimeField(blank=True, null=True)

    class Meta:
        indexes = [
            models.Index(fields=['-paired', ]),
            models.Index(fields=['-detached', ]),
        ]

    def __str__(self):
        return 'Bicycle #{} paired with Lock #{}: from {} to {}'.format(
            self.bicycle.pk,
            self.lock.pk,
            self.paired,
            self.detached or '-',
        )


class AxaLockConnection(models.Model):
    bicycle = models.ForeignKey('Bicycle',
                                related_name='axa_lock_connections',
                                related_query_name='axa_lock_connection',
                                on_delete=models.CASCADE)
    axa_lock = models.ForeignKey('AxaLock',
                                 related_name='axa_lock_connections',
                                 related_query_name='axa_lock_connection',
                                 on_delete=models.CASCADE)
    paired = models.DateTimeField(auto_now_add=True)
    detached = models.DateTimeField(blank=True, null=True)

    class Meta:
        indexes = [
            models.Index(fields=['-paired', ]),
            models.Index(fields=['-detached', ]),
        ]

    def __str__(self):
        return 'Bicycle #{} paired with AxaLock #{}: from {} to {}'.format(
            self.bicycle.pk,
            self.axa_lock.pk,
            self.paired,
            self.detached or '-',
        )


def save_instance_after_transition(instance=None, method_kwargs=None,
                                   source=None, *args, **kwargs):
    dry_run = (method_kwargs.get('dry_run', False) if
               method_kwargs is not None else False)
    if dry_run:
        transaction.set_rollback(True)
        instance.state = source
        return
    instance.full_clean()
    instance.save()


def save_current_state_lock(instance=None, *args, **kwargs):
    instance._original_lock_id = instance.lock_id


def save_current_state_axa_lock(instance=None, *args, **kwargs):
    instance._original_axa_lock_id = instance.axa_lock_id


def log_bicycle_devices_connections(instance=None,
                                    created=False,
                                    *args,
                                    **kwargs):
    for device_type, connection_cls in (('lock', LockConnection),
                                        ('axa_lock', AxaLockConnection)):
        current_device_id = getattr(instance, f'{device_type}_id', None)
        prev_device_id = getattr(instance, f'_original_{device_type}_id', None)
        if not created and current_device_id == prev_device_id:
            # Same devices (excluding case when Bicycle was initialized
            # ...with Lock already). Or no devices. Nothing to log.
            continue

        if not created and prev_device_id:
            # Bicycle was previously paired with some device,
            # find log record about it
            try:
                # If this pair was logged before, set the disconnection date
                devices_pairing_history = getattr(
                    instance,
                    f'{device_type}_connections'
                )
                prev_pair = (
                    devices_pairing_history
                    .filter(detached__isnull=True)
                    .last()
                )
                prev_pair.detached = instance.modified
                prev_pair.save()
            except AttributeError:
                pass

        current_device = getattr(instance, device_type, None)
        if current_device_id and current_device:
            # If it's not just disconnection of device, log data about new pair
            actual_pair = connection_cls(**{'bicycle': instance,
                                            device_type: current_device,
                                            'paired': instance.modified, })
            actual_pair.save()


def sync_plan(instance=None, *args, **kwargs):
    from velodrome.celery import update_or_create_remote_plan
    if instance.state == GenericStates.PROVISIONED.value:
        update_or_create_remote_plan.delay(instance.pk)


def send_async_support_ticket(instance=None, created=False, *args, **kwargs):
    from velodrome.celery import send_support_email_task
    if created:
        send_support_email_task(instance.pk)


def send_async_feedback(instance=None, created=False, *args, **kwargs):
    if created:
        if isinstance(instance.causality, Lock):
            bicycle = instance.causality.bicycle
        elif isinstance(instance.causality, Bicycle):
            bicycle = instance.causality
        else:
            raise NotImplementedError

        if (bicycle is not None and
                bicycle.model is not None and
                instance.severity and
                bicycle.model.feedback_auto_escalate_severity):
            model_pref = bicycle.model.feedback_auto_escalate_severity
            if Severity(instance.severity) >= Severity(model_pref):
                return instance.escalate(severity=instance.severity)
        instance.send_async()


def new_task_being_created(instance=None, *args, **kwargs):
    """General purpose, pre-create, Task assignor."""
    if instance.assignee_id is None and instance.pk is None:
        causality = instance.get_final_causality()
        if (causality is None or
                instance.maintenance_rule is not None or
                causality.public_tracking is None or
                causality.public_tracking.point is None):
            return
        try:
            attributes = causality.public_tracking.attributes
            distance = (attributes.get('gps_accuracy', 0) *
                        attributes.get('gps_pdop', 1))
            zone = Zone.objects.filter(
                polygon__dwithin=(causality.public_tracking.point, distance),
                preferred_mechanic__isnull=False)[:1].get()
        except Zone.DoesNotExist:
            pass
        else:
            instance.assignee = zone.preferred_mechanic


def new_task_created(instance=None, created=False, *args, **kwargs):
    """Behaviour for creation of Task not based on BMMR."""
    if created and instance.maintenance_rule is None:
        instance.is_due = True
        instance.save()
        instance.send_async()


def new_bmmr_created(instance=None, created=False, *args, **kwargs):
    """Behaviour for creation of BMMR."""
    if created and instance.has_occured:
        from velodrome.celery import create_missing_tasks_async
        create_missing_tasks_async.delay(instance.pk)


def handle_task_post_transition(instance, target=None, *args, **kwargs):
    """Task transition state handler."""
    if target in (TaskStates.ASSIGNED.value, TaskStates.COMPLETED.value,
                  TaskStates.CANCELLED.value):
        instance.send_async()

    bmmr = instance.maintenance_rule
    if (bmmr is not None and
            bmmr.state == BicycleModelMaintenanceRuleStates.ACTIVE.value):
        is_recurring = bmmr.recurring_time or bmmr.distance
        if is_recurring and target == TaskStates.COMPLETED.value:
            admin = User.objects.get(username='root_admin')
            Task.objects.create(
                organization=instance.organization,
                causality=instance.causality,
                maintenance_rule=bmmr,
                role=instance.role,
                severity=instance.severity,
                context={'description': bmmr.description},
                owner=admin,
            )


def publish_updates(instance, sender=None, for_state_leaving=None,
                    *args, **kwargs):
    """Send real time updates to redis publisher"""
    transaction.on_commit(functools.partial(
        publish_update_on_commit,
        instance,
        for_state_leaving=for_state_leaving))


def publish_update_on_commit(instance, for_state_leaving=None):
    from velodrome.celery import publish_pusher_update

    publish_pusher_update.delay(instance._meta.app_label,
                                instance._meta.model_name,
                                instance.pk, for_state_leaving)


def create_stripe_customer(instance=None, created=False, *args, **kwargs):
    if created:
        affiliation = instance
        user = affiliation.user
        organization = affiliation.organization
        if organization.uses_payments:
            customer, created = user.get_or_create_customer(organization)
            if created:
                logger.info('Created Stripe customer for %r (affiliation %r).',
                            user, affiliation)


@receiver(WEBHOOK_SIGNALS['account.application.deauthorized'])
def decommision_pricings(sender, event, *args, **kwargs):
    account = event.stripe_account
    predicate = Q(organization__stripe_account=account,
                  state=GenericStates.PROVISIONED.value)
    for pricing in itertools.chain(SubscriptionPlan.objects.filter(predicate),
                                   PricingScheme.objects.filter(predicate)):
        pricing.decommission()


@receiver(WEBHOOK_SIGNALS['customer.source.created'])
def process_pending_payments(sender, event, **kwargs):
    account = event.stripe_account
    customer = event.customer
    user = customer.users.filter(user_account__account=account).get()
    stripe_card_id = event.validated_message['data']['object']['id']
    user.transfer_failed_payments(customer, stripe_card_id)


post_transition.connect(save_instance_after_transition)
post_transition.connect(handle_task_post_transition, sender=Task)

signals.post_init.connect(save_current_state_lock, sender=Bicycle)
signals.post_init.connect(save_current_state_axa_lock, sender=Bicycle)
signals.post_save.connect(sync_plan, sender=SubscriptionPlan)
signals.post_save.connect(send_async_support_ticket, sender=SupportTicket)
signals.post_save.connect(send_async_feedback, sender=Feedback)
signals.pre_save.connect(new_task_being_created, sender=Task)
signals.post_save.connect(new_task_created, sender=Task)
signals.post_save.connect(new_bmmr_created, sender=BicycleModelMaintenanceRule)
signals.post_save.connect(log_bicycle_devices_connections, sender=Bicycle)

signals.post_save.connect(publish_updates, sender=Bicycle)
