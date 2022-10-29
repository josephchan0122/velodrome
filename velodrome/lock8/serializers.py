from calendar import timegm
from collections import OrderedDict
from datetime import datetime
import hashlib
import json
import logging
import re
import typing

from django.conf import settings
from django.contrib.auth import password_validation
from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.contrib.auth.tokens import default_token_generator
from django.contrib.gis.geos import MultiPolygon
from django.core.cache import caches
from django.core.validators import validate_email as django_email_validator
from django.db.models import Prefetch, Q, QuerySet
from django.utils.translation import ugettext as _
from django_fsm_log.models import StateLog
from djoser.serializers import (
    PasswordResetSerializer as DjoserPasswordResetSerializer,
)
from drf_extra_fields.fields import Base64ImageField
from generic_relations.relations import GenericRelatedField
from humanize import naturaldelta
from pinax.stripe.models import Coupon, Discount, Subscription
from refreshtoken.serializers import RefreshTokenSerializer
import requests
from requests.exceptions import HTTPError
from rest_framework import exceptions, serializers
from rest_framework_jwt.compat import Serializer
from rest_framework_jwt.serializers import (
    jwt_encode_handler, jwt_payload_handler,
)
from rest_framework_jwt.settings import api_settings
from rest_framework_nested.relations import NestedHyperlinkedRelatedField
from social_django.models import UserSocialAuth

from velodrome.celery import send_suspicious_registration_email_task
from velodrome.lock8.authentication import is_login_blocked

from .exceptions import (
    DuplicateContentError, InternalServerError, SkipValidationError,
)
from .fields import (
    Base64FileField, DateTimeFieldWithSecondPrecision, DurationInSecondField,
    GenericHyperLinkedRelatedField, NestedDetailViewHyperlinkedRelatedField,
    ParentHyperLinkedRelatedField, UUIDHyperlinkedRelatedField,
)
from .models import (
    TRACKING_FIELDS, AcceptedTermsOfService, Address, Affiliation, Alert,
    AlertMessage, AxaLock, AxaLockConnection, Bicycle, BicycleModel,
    BicycleModelMaintenanceRule, BicycleStates, BicycleType, ClientApp,
    Feature, Feedback, FeedbackCategory, Firmware, Invitation,
    InvitationStates, Lock, LockConnection, LockFirmwareUpdate,
    NotificationMessage, Organization, OrganizationPreference, Photo, PlanPass,
    PricingScheme, RentalSession, RentingScheme, Reservation, SharedSecret,
    SubscriptionPlan, SupportTicket, Task, TaskStates, TermsOfService,
    TermsOfServiceVersion, Trip, User, UserProfile, Zone, ZoneQuerySet,
    maybe_create_and_send_alert,
)
from .utils import create_affiliations_if_whitelisted, reverse_query

logger = logging.getLogger(__name__)


class DefaultUserMixin:

    def create(self, validated_data):
        """Override ``create`` to provide a user via request.user by default.

        This is required since the read_only ``user`` field is not included by
        default anymore since
        https://github.com/encode/django-rest-framework/pull/5886.
        """
        if 'user' not in validated_data:
            validated_data['user'] = self.context['request'].user
        return super(DefaultUserMixin, self).create(validated_data)


UserFieldQuerySet = User.actives.prefetch_related('affiliations',
                                                  'organizations')


class _MetaMarker(serializers.HyperlinkedModelSerializer):
    pass


class MetaclassForMeta(serializers.SerializerMetaclass):
    def __new__(cls, name, bases, kwargs):
        """
        Extend _MetaMarker.Meta.* into
        subclasses's Meta.* .
        """
        is_abstract_serializer = kwargs.get(
            '_{}__is_abstract_serializer'.format(name), False)
        if not is_abstract_serializer:
            metametas = [meta_base.Meta for base in bases
                         for meta_base in base.mro()
                         if getattr(meta_base,
                                    '_{}__is_abstract_serializer'.format(
                                        meta_base.__name__), False)]
            seen = set()
            metametas = [x for x in metametas
                         if not (x in seen or seen.add(x))]
            try:
                Meta = kwargs['Meta']
            except KeyError:
                base_Meta = next(base.Meta for base in bases
                                 if issubclass(base, _MetaMarker))
                try:
                    metametas.remove(base_Meta)
                except ValueError:
                    pass
                assert base_Meta not in metametas
                Meta = kwargs['Meta'] = type('{}_Meta'.format(name),
                                             (base_Meta,), {})

            for MetaMeta in metametas:
                for attr in filter(lambda n: not n.startswith('_'),
                                   dir(MetaMeta)):
                    new = getattr(MetaMeta, attr)
                    try:
                        old = getattr(Meta, attr)
                    except AttributeError:
                        setattr(Meta, attr, new)
                    else:
                        if isinstance(old, dict):
                            value = {**old, **new}
                        else:
                            value = old + new
                        setattr(Meta, attr, value)
        cls_ = super().__new__(cls, name, bases, kwargs)
        return cls_


class BaseHyperlinkedModelSerializer(_MetaMarker, metaclass=MetaclassForMeta):
    __is_abstract_serializer = True

    concurrency_version = serializers.IntegerField(required=False)

    class Meta:
        fields = (
            'uuid',
            'url',
            'created',
            'modified',
            'concurrency_version',
        )
        read_only_fields = (
            'uuid',
            'url',
            'created',
            'modified',
        )

    def __init__(self, *args, fields=(), **kwargs):
        """Discard some fields when filter is present"""
        super().__init__(*args, **kwargs)
        if fields:
            selected = set(fields)
            existing = set(self.fields)
            for f in existing - selected:
                self.fields.pop(f)
            # Add fields from _declared_fields that are not enabled by default.
            unknown_fields = []
            for f in selected:
                if f not in self.fields:
                    try:
                        declared_field = self._declared_fields[f]
                    except KeyError:
                        unknown_fields.append(f)
                    else:
                        self.fields[f] = declared_field
            if unknown_fields:
                raise serializers.ValidationError(
                    f'Unknown fields: {", ".join(unknown_fields)}',
                    'unknown_fields')

    def update(self, instance, validated_data):
        instance = super().update(instance, validated_data)
        instance.full_clean()
        return instance

    def create(self, validated_data):
        instance = super().create(validated_data)
        instance.full_clean()
        return instance

    def optimize_queryset(self, qs):
        return qs

    def get_extra_kwargs(self):
        """Inject optimized queryset for fields."""
        extra_kwargs = super().get_extra_kwargs()
        if 'user' in self.Meta.fields:
            view = self.context.get('view', {})
            action = getattr(view, 'action', None)
            read_only = extra_kwargs.get('user', {}).get('read_only')
            if action == 'create' and not read_only:
                extra_kwargs.setdefault('user', {}).setdefault(
                    'queryset', UserFieldQuerySet)
        return extra_kwargs


class FSMHyperlinkedModelSerializer(_MetaMarker, metaclass=MetaclassForMeta):
    __is_abstract_serializer = True

    class Meta:
        fields = (
            'state',
        )
        read_only_fields = (
            'state',
        )


class OwnerableHyperlinkedModelSerializer(_MetaMarker,
                                          metaclass=MetaclassForMeta):
    __is_abstract_serializer = True

    owner = serializers.HiddenField(default=serializers.CurrentUserDefault())

    class Meta:
        fields = (
            'owner',
        )


class DefaultBaseHyperlinkedModelSerializer(
    BaseHyperlinkedModelSerializer,
    FSMHyperlinkedModelSerializer,
    OwnerableHyperlinkedModelSerializer):
    __is_abstract_serializer = True


class DeprecatedCausalityResourceNameSerializer(Serializer):
    """Explicity name the hyperlinked `causality` by type."""
    __is_abstract_serializer = True

    causality_resource_type = serializers.SerializerMethodField(
        help_text='Deprecated.  Use causality_info instead.')

    class Meta:
        fields = ('causality_resource_type',)
        read_only_fields = ('causality_resource_type',)

    def get_causality_resource_type(self, obj):
        if obj.causality:
            return obj.causality._meta.model_name


class CausalityInfoSerializer(Serializer):
    """Add `causality_info` for hyperlinked `causality`."""
    __is_abstract_serializer = True

    causality_info = serializers.SerializerMethodField()

    class Meta:
        fields = ('causality_info',)

    def get_causality_info(self, obj):
        if not obj.causality:
            return {}
        info = {
            'resource_type': obj.causality._meta.model_name,
        }
        if isinstance(obj.causality, Alert):
            info['alert_type'] = obj.causality.alert_type
        elif isinstance(obj.causality, Feedback):
            info['severity'] = obj.causality.severity
        return info


class GenericBicycleRelationSerializer(Serializer):
    """Generically related `Bicycle` model hyperlink serializer

    If a model only has a `GenericRelation` to the `Bicycle` model
    and needs to present a hyperlinked relation, we use this mixin.

    Note. The related model must inherit from `FinalCausalityModelMixin`.
    """
    __is_abstract_serializer = True

    bicycle = serializers.SerializerMethodField()

    class Meta:
        fields = ('bicycle',)
        read_only_fields = ('bicycle',)

    def get_bicycle(self, obj):
        request = self.context['request']
        try:
            bicycle_uuid = obj.causative_bicycle_uuid
        except AttributeError:
            return
        if bicycle_uuid:
            kwargs = {'uuid': bicycle_uuid}
            uri = reverse_query('lock8:bicycle-detail', kwargs=kwargs)
            return request.build_absolute_uri(uri)


class GenericTagRelationSerializer(serializers.Serializer):
    """Mixin for adding related tags information for any taggable object
    """
    __is_abstract_serializer = True

    tags = serializers.SerializerMethodField()

    class Meta:
        fields = read_only_fields = (
            'tags',
        )

    def get_tags(self, instance):
        # TODO: Find how to optimize tags prefetching in parent model
        from velodrome.custom_tagging.serializers import (
            EmbeddedTagInfoSerializer,
        )
        return EmbeddedTagInfoSerializer(
            instance.tags,
            context=self.context,
            many=True,
            read_only=True
        ).data


class OrganizationOwnedHyperlinkedModelSerializer(_MetaMarker,
                                                  metaclass=MetaclassForMeta):
    __is_abstract_serializer = True

    class Meta:
        fields = (
            'organization',
        )
        extra_kwargs = {
            'organization': {'view_name': 'lock8:organization-detail',
                             'lookup_field': 'uuid'},
        }

    def create(self, validated_data):
        if not self.context['request'].user.has_perm(
                'set_related_organization', validated_data['organization']):
            raise exceptions.PermissionDenied(
                detail='You are not allowed to link to this organization.')
        return super().create(validated_data)

    def update(self, instance, validated_data):
        try:
            organization = validated_data['organization']
        except KeyError:
            return super().update(instance, validated_data)
        if not self.context['request'].user.has_perm(
                'set_related_organization', organization):
            raise exceptions.PermissionDenied(
                detail='You are not allowed to link to this organization.')
        return super().update(instance, validated_data)


class ActionableSerializer(Serializer):
    type = serializers.CharField()
    dry_run = serializers.BooleanField(required=False, default=False)


class SubscribeUserToSubscriptionPlanInputSerializer(Serializer):
    stripe_source = serializers.CharField(required=False)
    coupon = serializers.CharField(required=False)
    auto_renewal = serializers.BooleanField(required=False)


class UnsubscribeUserFromSubscriptionPlanInputSerializer(Serializer):
    at_period_end = serializers.BooleanField(required=False)


class BicycleActionableSerializer(ActionableSerializer):
    """
    Accept duration field
    """
    user = serializers.HyperlinkedRelatedField(
        required=False,
        write_only=True,
        view_name='lock8:user-detail',
        lookup_field='uuid',
        queryset=User.objects.all(),
    )
    duration = DurationInSecondField(
        required=False,
        write_only=True,
        allow_null=True
    )
    subscription_plan = serializers.HyperlinkedRelatedField(
        required=False,
        write_only=True,
        view_name='lock8:subscription_plan-detail',
        lookup_field='uuid',
        queryset=SubscriptionPlan.objects.all(),
    )
    pricing_scheme = serializers.HyperlinkedRelatedField(
        required=False,
        write_only=True,
        view_name='lock8:pricing_scheme-detail',
        lookup_field='uuid',
        queryset=PricingScheme.objects.all(),
    )


class JSONWebTokenSerializer(Serializer):
    access_token = serializers.CharField(required=True, write_only=True)

    def validate(self, attrs):
        # inspired from
        # rest_framework_jwt/serializers.py:JSONWebTokenSerializer.validate
        request = self.context['request']
        user = oauth2_user = request.backend.do_auth(attrs['access_token'])
        if not request.user.is_anonymous and request.user.is_local:
            user = request.user
            # we are consolidating users.
            if oauth2_user.is_active:
                oauth2_user.is_active = False
            if not oauth2_user.representative:
                oauth2_user.representative = user
            elif not oauth2_user.representative == user:
                msg = _('User account is compromised. There is a user assigned'
                        ' to the OAuth account already')
                raise serializers.ValidationError(msg, 'account_compromised')
            oauth2_user.save()
            # transfer Affiliations
            for affiliation in oauth2_user.affiliations.all():
                if not user.affiliations.filter(
                        organization=affiliation.organization,
                        role=affiliation.role).exists():
                    Affiliation.objects.create(
                        user=user,
                        organization=affiliation.organization,
                        role=affiliation.role)
            # transfer refresh_tokens
            if not user.refresh_tokens.filter(
                    app=request.backend.name).exists():
                user.refresh_tokens.create(app=request.backend.name)

        if user:
            if not user.is_active:
                try:
                    user = user.representative
                    assert user.is_active
                except (AttributeError, AssertionError):
                    msg = _('User account is disabled.')
                    raise serializers.ValidationError(msg, 'account_disabled')
            payload = jwt_payload_handler(user)

            if api_settings.JWT_ALLOW_REFRESH:
                payload['orig_iat'] = timegm(
                    datetime.utcnow().utctimetuple()
                )

            user_logged_in.send(sender=user.__class__, request=request,
                                user=user)
            return api_settings.JWT_RESPONSE_PAYLOAD_HANDLER(
                jwt_encode_handler(payload),
                user=user,
                request=request,
            )
        else:
            msg = _('Unable to login with access_token')
            raise serializers.ValidationError(msg)


class JSONWebTokenLocalSerializer(Serializer):
    email = serializers.CharField()
    password = serializers.CharField(
        style={'input_type': 'password'},
    )
    organization_uuid = serializers.UUIDField(required=False)

    def validate_organization_uuid(self, uuid):
        try:
            org = Organization.objects.get(uuid=uuid)
        except Organization.DoesNotExist:
            raise serializers.ValidationError('Organization not found.',
                                              code='organization_not_found')
        self.context['organization'] = org
        return uuid

    def validate(self, attrs):
        request = self.context['request']
        email = request.data['email'].lower()
        if is_login_blocked(email=email):
            max_attempts = settings.FAILED_LOGINS_MAX_ATTEMPTS
            duration = naturaldelta(settings.FAILED_LOGINS_COOLOFF)
            msg = (f'You have attempted to login {max_attempts} times '
                   f'unsuccessfully. The account is locked for {duration}.')
            raise exceptions.AuthenticationFailed(msg)

        def _raise_invalid_credentials(reason):
            password_hash = hashlib.new('md5')
            password_hash.update(request.data['password'].encode())
            user_login_failed.send(
                sender=User,
                request=request,
                credentials={
                    'email': email,
                    'password': '***',
                    'password_hash': password_hash.hexdigest(),
                })
            exc = serializers.ValidationError(
                'Invalid credentials.', code='invalid_credentials')
            exc.sentry_extra = {
                'invalid_credentials_reason': reason,
            }
            raise exc

        try:
            organization = self.context['organization']
        except KeyError:
            # rider user
            try:
                user = User.objects.filter_local_users(
                    email__iexact=request.data['email']).get()
            except User.DoesNotExist:
                _raise_invalid_credentials('Rider user does not exist')
        else:
            # white label user
            try:
                user = User.objects.filter_local_whitelabel_users(
                    organization,
                    email__iexact=request.data['email']).get()
            except User.DoesNotExist:
                _raise_invalid_credentials('Whitelabel user does not exist')

        if not user.check_password(request.data['password']):
            _raise_invalid_credentials('Invalid password')

        if not user.is_active:
            _raise_invalid_credentials('User is not active')

        user_logged_in.send(sender=user.__class__, request=request, user=user)
        return api_settings.JWT_RESPONSE_PAYLOAD_HANDLER(
            jwt_encode_handler(jwt_payload_handler(user)),
            user=user,
            request=request)


class JSONWebTokenAutoLoginSerializer(Serializer):
    code = serializers.CharField()

    def validate_code(self, value):
        auth_code_cache = caches['auth_codes']
        self.user_uuid = auth_code_cache.get(value)
        if self.user_uuid is None:
            msg = _("Invalid authorization code.")
            raise serializers.ValidationError(msg)
        # FIXME: investigate django-redis atomic operations
        auth_code_cache.delete(value)


class AddressSerializer(BaseHyperlinkedModelSerializer,
                        OwnerableHyperlinkedModelSerializer):
    class Meta:
        model = Address
        fields = (
            'organization',
            'email',
            'phone_number',
            'text_address',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:address-detail',
                    'lookup_field': 'uuid'},
            'organization': {'view_name': 'lock8:organization-detail',
                             'lookup_field': 'uuid'},
        }

    def optimize_queryset(self, qs):
        if 'organization' in self.fields:
            return qs.select_related('organization')
        return qs

    def create(self, validated_data):
        if validated_data['organization'].addresses.exists():
            raise DuplicateContentError(
                detail={'non_field_errors':
                            ['Only one address per organization is allowed.']})
        return super().create(validated_data)


class AffiliationSerializer(BaseHyperlinkedModelSerializer,
                            FSMHyperlinkedModelSerializer):
    organization_name = serializers.CharField(
        source='organization.name',
        read_only=True,
    )
    organization_icon = Base64ImageField(
        source='organization.image',
        read_only=True,
        required=False)

    class Meta:
        model = Affiliation
        fields = (
            'user',
            'organization',
            'organization_name',
            'organization_icon',
            'role',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:affiliation-detail',
                    'lookup_field': 'uuid'},
            'organization': {'view_name': 'lock8:organization-detail',
                             'lookup_field': 'uuid'},
            'user': {'view_name': 'lock8:user-detail',
                     'lookup_field': 'uuid'},
        }

    def optimize_queryset(self, qs):
        if 'organization' in self.fields:
            qs = qs.select_related('organization')
        if 'user' in self.fields:
            qs = qs.select_related('user')
        return qs

    def get_unique_together_validators(self):
        """
        We bypass unique together constraint, to
        allow resurrection of deleted objects.
        """
        return []


class AxaLockCreateSerializer(DefaultBaseHyperlinkedModelSerializer):
    class Meta:
        model = AxaLock
        fields = (
            'organization',
            'uid',
            'claim_code_at_creation',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:axa_lock-detail',
                    'lookup_field': 'uuid'},
            'organization': {'view_name': 'lock8:organization-detail',
                             'lookup_field': 'uuid'},
        }


class AxaLockSerializer(DefaultBaseHyperlinkedModelSerializer):
    class Meta:
        model = AxaLock
        read_only_fields = fields = (
            'organization',
            'remote_id',
            'uid',
            'attributes',
            'bleid',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:axa_lock-detail',
                    'lookup_field': 'uuid'},
            'organization': {'view_name': 'lock8:organization-detail',
                             'lookup_field': 'uuid'},
        }


class ClientAppSerializer(BaseHyperlinkedModelSerializer,
                          OwnerableHyperlinkedModelSerializer,
                          OrganizationOwnedHyperlinkedModelSerializer):
    class Meta:
        model = ClientApp
        fields = (
            'name',
            'label',
            'organization',
            'scopes',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:client_app-detail',
                    'lookup_field': 'uuid'},
            'organization': {'view_name': 'lock8:organization-detail',
                             'lookup_field': 'uuid'},

        }

    def create(self, validated_data):
        sts_data = {
            'name': validated_data['name'],
            'organization_uuid': str(validated_data['organization'].uuid),
        }
        try:
            sts_data['scopes'] = validated_data['scopes']
        except KeyError:
            pass
        try:
            sts_data['label'] = validated_data['label']
        except KeyError:
            pass
        sts_response = requests.post(
            settings.STS_BASE_URL + '/client_apps/',
            headers={
                'Authorization': f'Token {settings.STS_AUTH_TOKEN.strip()}'},
            data=json.dumps(sts_data))
        try:
            sts_response.raise_for_status()
        except HTTPError as exc:
            logger.exception('Station Error')
            raise InternalServerError(
                code=sts_response.json()['error']) from exc
        remote_client_app = sts_response.json()
        validated_data['remote_uuid'] = remote_client_app['uuid']
        inactive_user = User.objects.create(
            username='{}:{}'.format(validated_data['organization'].uuid,
                                    validated_data['name']),
            is_active=False,
        )
        Affiliation.objects.create(organization=validated_data['organization'],
                                   user=inactive_user,
                                   role=Affiliation.ADMIN)
        validated_data['user'] = inactive_user
        client_app = super().create(validated_data)
        client_app.private_key = remote_client_app['private_key']
        return client_app


class ClientAppUpdateSerializer(ClientAppSerializer):
    class Meta(ClientAppSerializer.Meta):
        read_only_fields = ('name', 'organization')

    def update(self, instance, validated_data):
        new_validated_data = {}
        for attr in ('scopes', 'label'):
            try:
                new_validated_data[attr] = validated_data[attr]
            except KeyError:
                pass
        if not new_validated_data:
            return instance
        super().update(instance, new_validated_data)

        sts_response = requests.patch(
            instance.remote_url,
            headers={
                'Authorization': f'Token {settings.STS_AUTH_TOKEN.strip()}'},
            data=json.dumps(validated_data))
        try:
            sts_response.raise_for_status()
        except HTTPError as exc:
            logger.exception('Station Error')
            raise InternalServerError(
                code=sts_response.json()['error']) from exc
        return instance


class LockFirmwareUpdateSerializer(BaseHyperlinkedModelSerializer,
                                   OwnerableHyperlinkedModelSerializer):
    class Meta:
        model = LockFirmwareUpdate
        fields = (
            'lock',
            'firmware',
        )
        extra_kwargs = {
            'url': {
                'view_name': 'lock8:lock_firmware_update-detail',
                'lookup_field': 'uuid'
            },
            'lock': {
                'view_name': 'lock8:lock-detail',
                'lookup_field': 'uuid'
            },
            'firmware': {
                'view_name': 'lock8:firmware-detail',
                'lookup_field': 'uuid'
            },
        }


class ReservationSerializer(DefaultBaseHyperlinkedModelSerializer):
    duration = DurationInSecondField(
        source='default_duration',
        read_only=True,
    )

    class Meta:
        model = Reservation
        fields = (
            'user',
            'bicycle',
            'duration',
        )
        read_only_fields = (
            'user',
            'bicycle',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:reservation-detail',
                    'lookup_field': 'uuid'},
            'user': {'view_name': 'lock8:user-detail',
                     'lookup_field': 'uuid'},
            'bicycle': {'view_name': 'lock8:bicycle-detail',
                        'lookup_field': 'uuid'},
        }

    def optimize_queryset(self, qs):
        """
        Callback for queryset optimization.
        """
        if 'bicycle' in self.fields:
            qs = qs.select_related('bicycle')
        if 'user' in self.fields:
            qs = qs.select_related('user')
        return qs


class RentalSessionSerializer(DefaultBaseHyperlinkedModelSerializer):
    duration_of_rental_session = DurationInSecondField(
        required=False, allow_null=True, source='duration')

    class Meta:
        model = RentalSession
        fields = (
            'bicycle',
            'user',
            'duration_of_rental_session',
            'cents',
            'currency',
            'subscription_plan',
            'pricing_scheme',
        )
        read_only_fields = (
            'bicycle',
            'user',
            'duration_of_rental_session',
            'cents',
            'currency',
            'subscription_plan',
            'pricing_scheme',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:rental_session-detail',
                    'lookup_field': 'uuid'},
            'user': {'view_name': 'lock8:user-detail',
                     'lookup_field': 'uuid'},
            'bicycle': {'view_name': 'lock8:bicycle-detail',
                        'lookup_field': 'uuid'},
            'subscription_plan': {
                'view_name': 'lock8:subscription_plan-detail',
                'lookup_field': 'uuid'},
            'pricing_scheme': {'view_name': 'lock8:pricing_scheme-detail',
                               'lookup_field': 'uuid'},
        }

    def optimize_queryset(self, qs):
        """
        Callback for queryset optimization.
        """
        if 'bicycle' in self.fields:
            qs = qs.select_related('bicycle')
        if 'user' in self.fields:
            qs = qs.select_related('user')
        return qs


class BaseLatestTrackingsSerializer(DefaultBaseHyperlinkedModelSerializer):
    __is_abstract_serializer = True

    estimated_state_of_charge = serializers.SerializerMethodField()
    last_cellular_update = serializers.SerializerMethodField()

    def get_estimated_state_of_charge(self, obj):
        tracking = getattr(obj, self.TRACKING_SOURCE)
        if tracking:
            return getattr(tracking, 'estimated_state_of_charge')

    def get_last_cellular_update(self, obj):
        tracking = getattr(obj, self.TRACKING_SOURCE)
        if tracking:
            return DateTimeFieldWithSecondPrecision().to_representation(
                getattr(tracking, 'modified'))

    def optimize_queryset(self, qs):
        return qs.select_related(self.TRACKING_SOURCE)

    @classmethod
    def make_tracking_lookup(cls, template, request):
        """Take a formatted string eg. ``{tracking_source}__point__contained``
        and a request.
        Return appropriate lookup based on user permissions.
        """
        return template.format(
            tracking_source=cls.get_serializer_class_for_user(
                request.user).TRACKING_SOURCE)


class DeviceSerializer(serializers.Serializer):
    __is_abstract_serializer = True
    bleid = serializers.CharField()
    manufacturer = serializers.SerializerMethodField()
    url = serializers.SerializerMethodField()
    paired_at = DateTimeFieldWithSecondPrecision()

    def __init__(self, *args, **kwargs):
        """
        Mark url as request dependent field, to use an offline serializer.
        """
        super().__init__(*args, **kwargs)
        setattr(self.fields['url'], '_is_relation', True)

    class Meta:
        read_only_fields = fields = (
            'bleid',
            'manufacturer',
            'paired_at',
            'url',
        )

    def get_manufacturer(self, obj):
        if isinstance(obj, Lock):
            return 'noa'
        if isinstance(obj, AxaLock):
            return 'axa'
        raise NotImplementedError

    def get_url(self, obj):
        request = self.context['request']
        if isinstance(obj, Lock):
            view_name = 'lock8:lock-detail'
        elif isinstance(obj, AxaLock):
            view_name = 'lock8:axa_lock-detail'
        else:
            raise NotImplementedError
        uri = reverse_query(view_name, kwargs={'uuid': obj.uuid})
        return request.build_absolute_uri(uri)


class EmbeddedLockSerializer(DeviceSerializer):
    pass


class EmbeddedTrackerSerializer(DeviceSerializer):
    pass


class DevicesSerializer(serializers.Serializer):
    tracker = EmbeddedTrackerSerializer(required=False, read_only=True)
    lock = EmbeddedLockSerializer(required=False, read_only=True)

    class Meta:
        fields = (
            'tracker',
            'lock',
        )


class BicycleBaseSerializer(BaseLatestTrackingsSerializer,
                            OrganizationOwnedHyperlinkedModelSerializer,
                            GenericTagRelationSerializer,
                            _MetaMarker, metaclass=MetaclassForMeta):
    __is_abstract_serializer = True

    bleid = serializers.CharField(source='lock.bleid', read_only=True,
                                  allow_null=True)
    device_type = serializers.CharField(source='lock.type', read_only=True,
                                        allow_null=True)
    image_url = Base64ImageField(source='model.photo.image', read_only=True,
                                 allow_null=True)
    reservation = ReservationSerializer(
        source='active_reservation',
        read_only=True,
    )
    rental_session = RentalSessionSerializer(
        source='active_rental_session',
        read_only=True,
    )
    latest_gps_timestamp = DateTimeFieldWithSecondPrecision(
        required=False,
        read_only=True,
    )
    bicycle_model_name = serializers.CharField(
        source='model.name',
        read_only=True,
        allow_null=True,
    )

    devices = DevicesSerializer(read_only=True)

    distance = serializers.IntegerField(source='distance_m', read_only=True)
    app_download_url = serializers.URLField(
        source='organization.app_download_url',
        read_only=True,
    )

    class Meta:
        model = Bicycle
        fields = (
            'name',
            'description',
            'model',
            'bleid',
            'device_type',
            'lock',
            'image_url',
            'reservation',
            'rental_session',
            'short_id',
            'bicycle_model_name',
            'serial_number',
            'devices',
            'distance',
            'last_cellular_update',
            'axa_lock',
            'note',
        )
        read_only_fields = (
            'short_id',
            'locked'
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:bicycle-detail',
                    'lookup_field': 'uuid'},
            'type': {'view_name': 'lock8:bicycle_type-detail',
                     'lookup_field': 'uuid',
                     'source': 'model.type',
                     'read_only': True},
            'model': {'view_name': 'lock8:bicycle_model-detail',
                      'lookup_field': 'uuid'},
            'lock': {'view_name': 'lock8:lock-detail',
                     'lookup_field': 'uuid',
                     'required': False,
                     'allow_null': True,
                     },
            'photo': {'view_name': 'lock8:photo-detail',
                      'lookup_field': 'uuid',
                      'source': 'model.photo',
                      'read_only': True,
                      },
            'name': {'required': True},
            'axa_lock': {'write_only': True,
                         'view_name': 'lock8:axa_lock-detail',
                         'lookup_field': 'uuid',
                         'allow_null': True,
                         }
        }

    def optimize_queryset(self, qs):
        qs = super().optimize_queryset(qs)
        if 'lock' in self.fields or 'bleid' in self.fields:
            qs = qs.select_related('lock')
        if 'devices' in self.fields:
            qs = (
                qs.select_related(
                    'lock',
                    'axa_lock'
                )
                    # TODO: Maybe we need to prefetch it not only when need Devices
                    .prefetch_related(
                    Prefetch(
                        'lock__lock_connections',
                        queryset=LockConnection.objects.order_by('-paired'),
                        to_attr='_paired_lock_list'
                    ),
                    Prefetch(
                        'axa_lock__axa_lock_connections',
                        queryset=AxaLockConnection.objects.order_by('-paired'),
                        to_attr='_paired_axa_lock_list'
                    )
                )
            )
        if 'organization' in self.fields:
            qs = qs.select_related('organization')
        if 'model' in self.fields:
            qs = qs.select_related('model')
        if 'photo' in self.fields or 'image_url' in self.fields:
            qs = qs.select_related('model__photo')
        if 'type' in self.fields:
            qs = qs.select_related('model__type')

        if self.context['request'].method in ('GET', 'HEAD', 'OPTIONS'):
            qs = qs.prefetch_active([
                x for x in ['reservation', 'rental_session']
                if x in self.fields])
        return qs

    def validate_lock(self, value):
        instance = self.instance
        if (instance is not None and
                instance.lock != value and
                instance.state not in (BicycleStates.IN_MAINTENANCE.value,
                                       BicycleStates.RETIRED.value)):
            raise exceptions.ValidationError(
                'Can not modify lock assignment if Bicycle is not in'
                ' maintenance state or retired state.',
                code='inconsistent')
        return value

    def validate_axa_lock(self, value):
        instance = self.instance
        if (instance is not None and
                instance.axa_lock != value and
                instance.state not in (BicycleStates.IN_MAINTENANCE.value,
                                       BicycleStates.RETIRED.value)):
            raise exceptions.ValidationError(
                'Can not modify lock assignment if Bicycle is not in'
                ' maintenance state or retired state.',
                code='inconsistent')
        return value

    @staticmethod
    def get_serializer_class_for_user(user):
        try:
            if user.is_admin_of_lock8:
                return PrivateBicycleSerializer
        except AttributeError:
            pass
        return PublicBicycleSerializer


class BicycleStatsSerializer(serializers.Serializer):
    total_distance = serializers.IntegerField(
        source='stats.total_distance',
        required=False,
    )
    last_cellular_update = DateTimeFieldWithSecondPrecision(
        required=False, allow_null=True)


class BicycleModelSerializer(DefaultBaseHyperlinkedModelSerializer,
                             OrganizationOwnedHyperlinkedModelSerializer):
    photo_url = Base64ImageField(source='photo.image', read_only=True,
                                 allow_null=True)
    bicycle_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = BicycleModel
        fields = (
            'name',
            'type',
            'photo',
            'photo_url',
            'bicycle_count',
            'alert_types_to_task',
            'feedback_auto_escalate_severity',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:bicycle_model-detail',
                    'lookup_field': 'uuid'},
            'type': {'view_name': 'lock8:bicycle_type-detail',
                     'lookup_field': 'uuid'},
            'photo': {'view_name': 'lock8:photo-detail',
                      'lookup_field': 'uuid'},
        }

    def optimize_queryset(self, qs):
        return qs.select_related(
            'organization',
            'type',
            'photo',
        )


class BicycleLockStatusSerializer(serializers.ModelSerializer):
    class Meta:
        model = Bicycle
        fields = ['locked']


class BicycleTypeSerializer(BaseHyperlinkedModelSerializer,
                            OwnerableHyperlinkedModelSerializer):
    class Meta:
        model = BicycleType
        fields = (
            'reference',
            'title',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:bicycle_type-detail',
                    'lookup_field': 'uuid'},
        }


class TermsOfServiceSerializer(DefaultBaseHyperlinkedModelSerializer,
                               OrganizationOwnedHyperlinkedModelSerializer):
    class Meta:
        model = TermsOfService
        fields = (
            'tos_url',
            'language',
            'content',
            'version',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:terms_of_service-detail',
                    'lookup_field': 'uuid'},
            'version': {'view_name': 'lock8:terms_of_service_version-detail',
                        'lookup_field': 'uuid'},
        }


class TermsOfServiceVersionSerializer(
    BaseHyperlinkedModelSerializer,
    OrganizationOwnedHyperlinkedModelSerializer):
    class Meta:
        model = TermsOfServiceVersion
        fields = ('label',)

        extra_kwargs = {
            'url': {'view_name': 'lock8:terms_of_service_version-detail',
                    'lookup_field': 'uuid'},
        }


class AcceptTermsOfServiceInputSerializer(serializers.Serializer):
    terms_of_service = serializers.HyperlinkedRelatedField(
        view_name='lock8:terms_of_service-detail',
        lookup_field='uuid',
        queryset=TermsOfService.objects.all(),
    )


class InvitationSerializer(DefaultBaseHyperlinkedModelSerializer,
                           OrganizationOwnedHyperlinkedModelSerializer):
    organization_name = serializers.CharField(
        source='organization.name', read_only=True
    )
    organization_icon = Base64ImageField(
        source='organization.image',
        read_only=True, required=False
    )
    is_registered = serializers.SerializerMethodField()

    def validate(self, data):
        qs = self.context['view'].get_queryset()
        organization = data['organization']
        email = data['email']
        pred = Q(email=email, organization=organization)

        is_pending = (pred & Q(state=InvitationStates.PROVISIONED.value))
        if qs.filter(is_pending).exists():
            raise DuplicateContentError(
                detail={'non_field_errors': [
                    'A pending invitation to this organization already exists'
                    ' for this email address.']})

        is_member = (
                Q(organization=organization) &
                Q(organization__member__email__iexact=email) &
                Q(user__social_auth__user__isnull=True)
        )
        if qs.filter(is_member).exists():
            raise serializers.ValidationError(
                ('This email address already has an existing affiliation'
                 ' with this organization.'),
                code='already_member'
            )

        email_domain_validation = organization.get_preference(
            'email_domain_validation')
        if email_domain_validation:
            user_domain = email.partition('@')[2]
            if user_domain != email_domain_validation:
                raise serializers.ValidationError(
                    'User email address domain is not allowed,'
                    f' it should belong to {email_domain_validation!r}.',
                    code='unauthorized_email_domain')
        return data

    class Meta:
        model = Invitation
        fields = (
            'user',
            'email',
            'role',
            'is_registered',
            'organization_name',
            'organization_icon',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:invitation-detail',
                    'lookup_field': 'uuid'},
            'user': {'view_name': 'lock8:user-detail',
                     'lookup_field': 'uuid'},
        }

    def optimize_queryset(self, qs):
        return qs.select_related('organization', 'user')

    def get_is_registered(self, instance):
        return (instance.user is not None or
                User.objects.filter_local_users(
                    email__iexact=instance.email)
                .exists())


class LockBaseSerializer(BaseLatestTrackingsSerializer,
                         _MetaMarker, metaclass=MetaclassForMeta):
    __is_abstract_serializer = True

    shared_secret = serializers.CharField(
        source='shared_secret.b64_value',
        read_only=True, allow_null=True)

    class Meta:
        model = Lock
        fields = (
            'counter',
            'serial_number',
            'imei',
            'iccid',
            'bleid',
            'voltage',
            'organization',
            'bicycle',
            'type',
            'firmware_version',
            'locked_state',
            'shared_secret',
        )
        read_only_fields = (
            'voltage',
            'bicycle',
            'organization',
            'firmware_version',
            'locked_state',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:lock-detail',
                    'lookup_field': 'uuid'},
            'organization': {'view_name': 'lock8:organization-detail',
                             'lookup_field': 'uuid',
                             },
            'bicycle': {'view_name': 'lock8:bicycle-detail',
                        'lookup_field': 'uuid'},
        }

    def optimize_queryset(self, qs):
        qs = super().optimize_queryset(qs)
        if 'bicycle' in self.fields:
            qs = qs.select_related('bicycle')
        if 'organization' in self.fields:
            qs = qs.select_related('organization')
        return qs

    def create(self, validated_data):
        """
        Always assign the lock to the root org.
        """
        validated_data['organization'] = Organization.objects.get(level=0)
        validated_data['shared_secret'] = SharedSecret.objects.create()
        return super().create(validated_data)

    @staticmethod
    def get_serializer_class_for_user(user):
        try:
            if user.is_admin_of_lock8:
                return PrivateLockSerializer
        except AttributeError:
            pass
        return PublicLockSerializer


class FirmwareSerializer(DefaultBaseHyperlinkedModelSerializer,
                         OrganizationOwnedHyperlinkedModelSerializer,
                         FSMHyperlinkedModelSerializer):
    binary = Base64FileField(required=False)

    class Meta:
        model = Firmware
        fields = (
            'name',
            'chip',
            'version',
            'binary',
        )
        extra_kwargs = {
            'url': {
                'view_name': 'lock8:firmware-detail',
                'lookup_field': 'uuid'
            },
        }


class SupportTicketSerializer(DefaultBaseHyperlinkedModelSerializer,
                              OrganizationOwnedHyperlinkedModelSerializer):
    owner = serializers.HyperlinkedRelatedField(
        default=serializers.CurrentUserDefault(),
        view_name='lock8:user-detail',
        lookup_field='uuid',
        queryset=User.actives.all(),
    )

    class Meta:
        model = SupportTicket
        fields = (
            'owner',
            'message',
            'location',
            'bicycle',
            'category',
        )
        read_only_fields = ('owner',)
        extra_kwargs = {
            'url': {'view_name': 'lock8:support_ticket-detail',
                    'lookup_field': 'uuid'},
            'bicycle': {'view_name': 'lock8:bicycle-detail',
                        'lookup_field': 'uuid'},
        }

    def optimize_queryset(self, qs):
        qs = qs.select_related('owner')
        if 'organization' in self.fields:
            qs = qs.select_related('organization')
        if 'bicycle' in self.fields:
            qs = qs.select_related('bicycle')
        return qs


class FeedbackCategorySerializer(BaseHyperlinkedModelSerializer):
    class Meta:
        model = FeedbackCategory
        fields = (
            'name',
            'parent',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:feedback_category-detail',
                    'lookup_field': 'uuid'},
            'parent': {'view_name': 'lock8:feedback_category-detail',
                       'lookup_field': 'uuid'},
        }

    def optimize_queryset(self, qs):
        return qs.select_related(
            'parent',
        )


class FeedbackActionableSerializer(Serializer):
    type = serializers.CharField()
    severity = serializers.ChoiceField(
        choices=FeedbackCategory.SEVERITIES, required=False
    )
    role = serializers.ChoiceField(choices=[r for r in Affiliation.ROLES if
                                            r != Affiliation.RENTER],
                                   required=False)


class FeedbackSerializer(GenericBicycleRelationSerializer,
                         DefaultBaseHyperlinkedModelSerializer,
                         DeprecatedCausalityResourceNameSerializer,
                         CausalityInfoSerializer):
    user = serializers.HyperlinkedRelatedField(
        default=serializers.CurrentUserDefault(),
        view_name='lock8:user-detail',
        lookup_field='uuid',
        queryset=User.actives.all(),
    )
    causality = GenericRelatedField({
        Bicycle: serializers.HyperlinkedRelatedField(
            lookup_field='uuid',
            view_name='lock8:bicycle-detail',
            queryset=Bicycle.objects.all(),
        ),
        Lock: serializers.HyperlinkedRelatedField(
            lookup_field='uuid',
            view_name='lock8:lock-detail',
            queryset=Lock.objects.all(),
        ),
    })

    class Meta:
        model = Feedback
        fields = (
            'organization',
            'user',
            'image',
            'message',
            'causality',
            'category',
            'severity',
        )
        read_only_fields = ('organization',)
        extra_kwargs = {
            'url': {
                'view_name':
                    'lock8:feedback-detail',
                'lookup_field': 'uuid'
            },
            'organization': {
                'view_name':
                    'lock8:organization-detail',
                'lookup_field': 'uuid'
            },
            'category': {'view_name': 'lock8:feedback_category-detail',
                         'lookup_field': 'uuid'},
        }

    def optimize_queryset(self, qs):
        return qs.select_related(
            'organization',
            'user',
            'category',
        ).prefetch_related('causality')

    def create(self, validated_data):
        validated_data['organization'] = validated_data['causality'].organization  # noqa
        return super().create(validated_data)


class AlertActionableSerializer(Serializer):
    type = serializers.CharField()
    severity = serializers.ChoiceField(choices=FeedbackCategory.SEVERITIES,
                                       required=False)
    description = serializers.CharField(allow_blank=True, required=False)


class AlertSerializer(GenericBicycleRelationSerializer,
                      OrganizationOwnedHyperlinkedModelSerializer,
                      DefaultBaseHyperlinkedModelSerializer,
                      DeprecatedCausalityResourceNameSerializer,
                      CausalityInfoSerializer):
    causality = GenericRelatedField({
        Bicycle: serializers.HyperlinkedRelatedField(
            lookup_field='uuid',
            view_name='lock8:bicycle-detail',
            queryset=Bicycle.objects.all(),
        ),
        Lock: serializers.HyperlinkedRelatedField(
            lookup_field='uuid',
            view_name='lock8:lock-detail',
            queryset=Lock.objects.all(),
        ),
        Zone: serializers.HyperlinkedRelatedField(
            lookup_field='uuid',
            view_name='lock8:zone-detail',
            queryset=Zone.objects.all(),
        ),
    })
    extra = serializers.DictField(read_only=True)

    class Meta:
        model = Alert
        fields = (
            'role',
            'roles',
            'user',
            'causality',
            'alert_type',
            'message',
            'extra',
        )
        read_only_fields = (
            'message',
            'role',
            'roles',
            'tracking',
            'organization',
            'extra',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:alert-detail',
                    'lookup_field': 'uuid'},
            'user': {'view_name': 'lock8:user-detail',
                     'lookup_field': 'uuid'},
        }

    def optimize_queryset(self, qs):
        return qs.select_related(
            'organization',
            'user',
        ).prefetch_related('causality')

    def create(self, validated_data):
        alert = maybe_create_and_send_alert(
            default_roles=[Affiliation.FLEET_OPERATOR], **validated_data)
        if alert is None:
            raise DuplicateContentError(
                detail={'non_field_errors': ['Alert already exists']})
        return alert


class AlertCreateSerializer(AlertSerializer):
    """Alert serializer used on creation, with access to `context`."""
    context = serializers.DictField(required=False)

    class Meta(AlertSerializer.Meta):
        fields = AlertSerializer.Meta.fields + ('context',)


class NotificationMessageSerializer(DefaultBaseHyperlinkedModelSerializer,
                                    DeprecatedCausalityResourceNameSerializer,
                                    CausalityInfoSerializer):
    causality = GenericHyperLinkedRelatedField(
        lookup_field='uuid',
        view_name='XXX',
        read_only=True,
    )

    class Meta:
        model = NotificationMessage
        fields = (
            'causality',
            'user',
        )
        read_only_fields = (
            'causality',
            'user',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:notification_message-detail',
                    'lookup_field': 'uuid'},
            'user': {'view_name': 'lock8:user-detail', 'lookup_field': 'uuid'}
        }

    def optimize_queryset(self, qs):
        return qs.select_related('user').prefetch_related('causality')


class AlertMessageSerializer(DefaultBaseHyperlinkedModelSerializer):
    class Meta:
        model = AlertMessage
        fields = (
            'alert',
            'user',
        )
        read_only_fields = (
            'alert',
            'user',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:alert_message-detail',
                    'lookup_field': 'uuid'},
            'alert': {'view_name': 'lock8:alert-detail',
                      'lookup_field': 'uuid'},
            'user': {'view_name': 'lock8:user-detail',
                     'lookup_field': 'uuid'},
        }

    def optimize_queryset(self, qs):
        return qs.select_related(
            'alert',
            'user',
        )


class FeatureSerializer(serializers.ModelSerializer):
    class Meta:
        model = Feature
        read_only_fields = fields = (
            'name',
        )


class UpdateHealthStatusAxaLock(serializers.Serializer):
    lock_health_msg = serializers.CharField(required=True)


class OtpInputSerializer(serializers.Serializer):
    number = serializers.IntegerField(
        required=True,
        help_text='Number of OTP passkeys to generate.')
    hours = serializers.IntegerField(
        required=False, default=2, min_value=1, max_value=24 * 30,
        help_text='Number of hours that the requested eKey should be valid.')
    slot = serializers.IntegerField(
        required=False, default=None, min_value=3, max_value=7,
        help_text=('Slot position within the lock.  '
                   'If not provided it will rotate over slots 0-2.'))


class OtpSerializer(serializers.Serializer):
    ekey = serializers.CharField()
    otps = serializers.ListField()
    expiration = DateTimeFieldWithSecondPrecision(
        label='Expiration datetime',
        help_text='Parsed from remote API, converted to UTC.')


class NestedOrganizationPreferenceSerializer(
    DefaultBaseHyperlinkedModelSerializer):
    serializer_url_field = NestedDetailViewHyperlinkedRelatedField
    owner = serializers.HiddenField(default=serializers.CurrentUserDefault())
    allowed_email_alert_types = serializers.ListField(required=False)
    allowed_push_alert_types = serializers.ListField(required=False)
    # deprecated
    uses_payments = serializers.BooleanField(
        read_only=True,
        source='organization.uses_payments')

    class Meta:
        model = OrganizationPreference
        fields = (
            'name',
            'allowed_email_alert_types',
            'allowed_push_alert_types',
            'allow_returning_bicycle_outside_drop_zone',
            'allow_renting_without_pricings',
            'currency',
            'is_free_floating_fleet',
            'is_access_controlled',
            'timezone',
            'unit_system',
            'idle_bicycle_duration',
            'url',
            'send_support_ticket_per_email',
            'support_email',
            'support_phone_number',
            'uses_payments',
            'tax_percent',
        )
        extra_kwargs = {
            'url': {
                'view_name': 'lock8:organization-preference',
                'parent_lookup_field': 'organization.uuid',
                'read_only': True,
                'source': '*',
            },
        }


class OrganizationSerializer(DefaultBaseHyperlinkedModelSerializer):
    owner = serializers.HiddenField(default=serializers.CurrentUserDefault())
    icon = Base64ImageField(source='image', required=False)
    phone_numbers = serializers.DictField()
    features = FeatureSerializer(read_only=True, many=True)
    uses_payments = serializers.BooleanField(read_only=True)
    preference = NestedOrganizationPreferenceSerializer(
        source='active_preference', read_only=True)
    stripe_publishable_key = serializers.CharField(read_only=True)

    class Meta:
        model = Organization
        fields = (
            'name',
            'is_open_fleet',
            'icon',
            'phone_numbers',
            'features',
            'uuid',
            'uses_payments',
            'preference',
            'stripe_publishable_key',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:organization-detail',
                    'lookup_field': 'uuid'},
        }


class PasswordChangeSerializer(serializers.Serializer):
    old_password = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'},
    )
    new_password = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'},
    )

    def validate_old_password(self, value):
        if not self.context['request'].user.check_password(value):
            raise serializers.ValidationError(
                'Invalid credentials.', code='invalid_credentials')
        return value

    def validate_new_password(self, value):
        user = self.context['request'].user
        password_validation.validate_password(value, user)
        return value

    def save(self):
        user = self.context['request'].user
        user.set_password(self.validated_data['new_password'])
        user.save()


class PhotoSerializer(DefaultBaseHyperlinkedModelSerializer,
                      OrganizationOwnedHyperlinkedModelSerializer):
    owner = serializers.HiddenField(default=serializers.CurrentUserDefault())
    image = Base64ImageField(required=False)

    class Meta:
        model = Photo
        fields = (
            'image',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:photo-detail',
                    'lookup_field': 'uuid'},
        }

    def optimize_queryset(self, qs):
        return qs.select_related('organization')


class PricingSchemeSerializer(DefaultBaseHyperlinkedModelSerializer,
                              OrganizationOwnedHyperlinkedModelSerializer):
    description = serializers.JSONField(required=False)

    class Meta:
        model = PricingScheme
        fields = (
            'name',
            'bicycle_model',
            'time_ranges',
            'description',
            'max_daily_charged_cents',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:pricing_scheme-detail',
                    'lookup_field': 'uuid'},
            'bicycle_model': {'view_name': 'lock8:bicycle_model-detail',
                              'lookup_field': 'uuid'},
        }

    def optimize_queryset(self, qs):
        return qs.select_related(
            'organization',
            'bicycle_model',
        )

    def to_representation(self, obj):
        data = super().to_representation(obj)
        for language, orig_desc in obj.description.items():
            desc = orig_desc.copy()
            desc['amount'] = obj.time_ranges[0][2]
            data['description'][language] = desc
        return data


class PhotoSerializerForPost(PhotoSerializer):
    """
    for POST requests we want the image field mandatory
    """
    image = Base64ImageField(required=True)


class RentingSchemeSerializer(DefaultBaseHyperlinkedModelSerializer,
                              OrganizationOwnedHyperlinkedModelSerializer):
    class Meta:
        model = RentingScheme
        fields = (
            'bicycle',
            'max_reservation_duration',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:renting_scheme-detail',
                    'lookup_field': 'uuid'},
            'bicycle': {'view_name': 'lock8:bicycle-detail',
                        'lookup_field': 'uuid'},
        }

    def optimize_queryset(self, qs):
        return qs.select_related(
            'organization',
            'bicycle',
        )


class SubscriptionPlanSerializer(DefaultBaseHyperlinkedModelSerializer,
                                 OrganizationOwnedHyperlinkedModelSerializer):
    description = serializers.JSONField(required=False)
    can_be_used_by_user = serializers.SerializerMethodField()

    class Meta:
        model = SubscriptionPlan
        fields = (
            'bicycle_model',
            'pricing_scheme',
            'name',
            'interval',
            'description',
            'cents',
            'trial_period_days',
            'available_dates',
            'weekdays',
            'statement_descriptor',
            'is_restricted',
            'can_be_used_by_user',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:subscription_plan-detail',
                    'lookup_field': 'uuid'},
            'pricing_scheme': {'view_name': 'lock8:pricing_scheme-detail',
                               'lookup_field': 'uuid'},
            'bicycle_model': {'view_name': 'lock8:bicycle_model-detail',
                              'lookup_field': 'uuid'},
        }

    def get_can_be_used_by_user(self, obj):
        request = self.context['request']
        return obj.can_be_used_by_user(user=request.user)

    def optimize_queryset(self, qs):
        return qs.select_related(
            'organization',
            'bicycle_model',
            'pricing_scheme',
        )

    def to_representation(self, obj):
        data = super().to_representation(obj)
        for language, orig_desc in obj.description.items():
            desc = orig_desc.copy()
            desc['amount'] = obj.cents
            data['description'][language] = desc
        return data


class PlanPassSerializer(BaseHyperlinkedModelSerializer):
    class Meta:
        model = PlanPass
        fields = (
            'user',
            'subscription_plan',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:plan_pass-detail',
                    'lookup_field': 'uuid'},
            'subscription_plan': {
                'view_name': 'lock8:subscription_plan-detail',
                'lookup_field': 'uuid'},
            'user': {'view_name': 'lock8:user-detail',
                     'lookup_field': 'uuid'},
        }


class BicyclePricingSerializer(serializers.Serializer):
    active_subscriptions = SubscriptionPlanSerializer(many=True)
    pricing_schemes = PricingSchemeSerializer(many=True)
    subscription_plans = SubscriptionPlanSerializer(many=True)


class TaskActionableSerializer(Serializer):
    type = serializers.CharField()
    assignee = serializers.HyperlinkedRelatedField(
        view_name='lock8:user-detail',
        lookup_field='uuid',
        queryset=User.objects.all(),
        required=False
    )

    def validate(self, data):
        if data['type'] == 'assign' and 'assignee' not in data:
            raise exceptions.ValidationError(
                'assignee is required for this action', code='required')
        return data


class TaskSerializer(GenericBicycleRelationSerializer,
                     OrganizationOwnedHyperlinkedModelSerializer,
                     DefaultBaseHyperlinkedModelSerializer,
                     DeprecatedCausalityResourceNameSerializer,
                     CausalityInfoSerializer):
    # deprecated
    bicycle_uuid = serializers.UUIDField(
        source='bicycle_causality.uuid',
        read_only=True,
        allow_null=True,
    )
    due = DateTimeFieldWithSecondPrecision(
        read_only=True,
        source='get_due_date'
    )
    remaining_distance = serializers.ReadOnlyField(
        source='get_remaining_distance'
    )
    assignor = serializers.HyperlinkedRelatedField(
        default=serializers.CurrentUserDefault(),
        view_name='lock8:user-detail',
        lookup_field='uuid',
        queryset=User.objects.all(),
    )
    maintenance_rule = ParentHyperLinkedRelatedField(
        lookup_field='uuid',
        nested_lookup_field='bicycle_model__uuid',
        view_name='lock8:maintenance_rule-detail',
        read_only=True
    )
    causality = GenericRelatedField({
        Bicycle: serializers.HyperlinkedRelatedField(
            lookup_field='uuid',
            view_name='lock8:bicycle-detail',
            queryset=Bicycle.objects.all(),
        ),
        Alert: serializers.HyperlinkedRelatedField(
            lookup_field='uuid',
            view_name='lock8:alert-detail',
            queryset=Alert.objects.all(),
        ),
        Feedback: serializers.HyperlinkedRelatedField(
            lookup_field='uuid',
            view_name='lock8:feedback-detail',
            queryset=Feedback.objects.all(),
        )
    })
    is_due = serializers.ReadOnlyField()
    completed_at = DateTimeFieldWithSecondPrecision(read_only=True)

    class Meta:
        model = Task
        fields = (
            'assignor',
            'assignee',
            'role',
            'context',
            'causality',
            'severity',
            'bicycle_uuid',  # deprecated
            'due',
            'remaining_distance',
            'maintenance_rule',
            'is_due',
            'completed_at',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:task-detail',
                    'lookup_field': 'uuid'},
            'assignee': {'view_name': 'lock8:user-detail',
                         'lookup_field': 'uuid'},
        }

    def optimize_queryset(self, qs):
        state_logs = (StateLog.objects
                      .filter(state=TaskStates.COMPLETED.value)
                      .order_by('-timestamp'))
        prefetch_transitions = Prefetch(
            'transitions',
            queryset=state_logs,
            to_attr='_transitions'
        )

        return qs.select_related(
            'organization',
            'assignor',
            'assignee',
        ).prefetch_related(
            'causality',
            'maintenance_rule',
            prefetch_transitions,
        )


class BicycleModelMaintenanceRuleActionableSerializer(Serializer):
    type = serializers.CharField()
    cancel_tasks = serializers.BooleanField(required=False, default=False)


class BicycleModelMaintenanceRuleSerializer(BaseHyperlinkedModelSerializer):
    serializer_url_field = NestedHyperlinkedRelatedField

    recurring_time = DurationInSecondField(required=False, allow_null=True)

    class Meta:
        model = BicycleModelMaintenanceRule
        fields = (
            'description',
            'note',
            'distance',
            'fixed_date',
            'recurring_time',
            'start_date',
            'role',
            'severity',
        )
        extra_kwargs = {
            'url': {
                'view_name': 'lock8:maintenance_rule-detail',
                'parent_lookup_kwargs': {
                    'parent_lookup_uuid': 'bicycle_model__uuid'},
                'lookup_field': 'uuid',
                'read_only': True,
                'source': '*',
            },
        }


class SharedSecretSerializer(BaseHyperlinkedModelSerializer):
    serializer_url_field = NestedDetailViewHyperlinkedRelatedField
    value = serializers.CharField(read_only=True, source='b64_value')

    class Meta:
        model = SharedSecret
        fields = (
            'value',
        )
        extra_kwargs = {
            'url': {
                'view_name': 'lock8:bicycle-shared-secret',
                'parent_lookup_field': 'lock.bicycle.uuid',
                'read_only': True,
                'source': '*',
            }}


class BaseTripSerializer(BaseHyperlinkedModelSerializer):
    bicycle = UUIDHyperlinkedRelatedField(
        view_name='lock8:bicycle-detail',
        source='bicycle_uuid',
        required=False,
        lookup_field='uuid',
        read_only=True,
    )
    organization = UUIDHyperlinkedRelatedField(
        view_name='lock8:organization-detail',
        source='organization_uuid',
        required=False,
        lookup_field='uuid',
        read_only=True,
    )

    class Meta:
        model = Trip
        fields = read_only_fields = (
            'uuid',
            'created',
            'modified',
            'bicycle',
            'organization',
            'start_date',
            'end_date',
            'route',
            'snapped_route',
            'duration',
            'distance_m',
            'serial_number',

            'asset_state',
            'type',
        )
        extra_kwargs = {
            'bicycle': {'view_name': 'lock8:bicycle-detail',
                        'lookup_field': 'uuid'},
            'organization': {'view_name': 'lock8:organization-detail'},
            'url': {'view_name': 'lock8:trip-detail',
                    'lookup_field': 'uuid'},
        }

    @staticmethod
    def get_serializer_class_for_user(user):
        try:
            if user.is_admin_of_lock8:
                return PrivateTripSerializer
        except AttributeError:
            pass
        return PublicTripSerializer


class PrivateTripSerializer(BaseTripSerializer):
    class Meta(BaseTripSerializer.Meta):
        fields = read_only_fields = BaseTripSerializer.Meta.fields + (
            'is_valid',)


class PublicTripSerializer(BaseTripSerializer):
    pass


class UserSerializer(DefaultBaseHyperlinkedModelSerializer):
    phone_numbers = serializers.CharField(
        source='profile.phone_numbers',
        read_only=True,
        allow_null=True,
    )

    class Meta:
        model = User
        fields = (
            'username',
            'email',
            'first_name',
            'last_name',
            'display_name',
            'uuid',
            'avatar',
            'phone_numbers',
            'last_login',
            'is_local',
        )
        read_only_fields = (
            'uuid',
            'display_name',
            'last_login',
            'is_local',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:user-detail',
                    'lookup_field': 'uuid'},
            'email': {'required': True},
        }

    def optimize_queryset(self, qs):
        qs = qs.select_related('profile')
        if 'is_local' in self.fields:
            qs = qs.prefetch_related(
                Prefetch('social_auth',
                         queryset=UserSocialAuth.objects.all(),
                         to_attr='_social_auth'))
        return qs


class UserOfOrganizationSerializer(UserSerializer):
    roles = serializers.SerializerMethodField(
        help_text='User roles shown when filtering by organization')

    class Meta(UserSerializer.Meta):
        fields = UserSerializer.Meta.fields + ('roles',)

    def get_roles(self, obj):
        return [affiliation.role for affiliation in obj._affiliations]

    def optimize_queryset(self, qs):
        qs = super().optimize_queryset(qs)
        try:
            query_params = self.context['request'].query_params
        except (KeyError, AttributeError):
            return qs

        if query_params.get('organization'):
            org_predicate = Q(
                organization__uuid=query_params.get('organization')
            )
        elif query_params.get('organizations'):
            org_list = [x.strip()
                        for x
                        in query_params.get('organizations').split(',')]
            org_predicate = Q(
                organization__uuid__in=org_list
            )
        else:
            return qs

        return qs.prefetch_related(
            Prefetch(
                'affiliations',
                queryset=(
                    Affiliation
                        .objects
                        .select_related('organization')
                        .filter(org_predicate)
                ),
                to_attr='_affiliations'
            ),
        )


class CurrentUserSerializer(UserSerializer):
    accepted_terms_of_services = serializers.SerializerMethodField()
    new_terms_of_services = serializers.SerializerMethodField()
    roles = serializers.SerializerMethodField()

    class Meta(UserSerializer.Meta):
        fields = UserSerializer.Meta.fields + (
            'accepted_terms_of_services',
            'new_terms_of_services',
            'roles'
        )

    def get_accepted_terms_of_services(self, obj):
        # Only show provisioned accepted terms of services
        qs = TermsOfService.get_queryset(self.context['request']).filter(
            accepted_terms_of_service__user=obj)
        serializer = TermsOfServiceSerializer(
            qs, context=self.context, many=True)
        return serializer.data

    def get_new_terms_of_services(self, obj):
        # Exclude all TOS of versions that have been accepted
        versions = [i.terms_of_service.version
                    for i in getattr(obj, '_accepted_tos', [])]
        qs = TermsOfService.get_queryset(self.context['request'])
        if versions:
            qs = qs.exclude(version__in=versions)
        serializer = TermsOfServiceSerializer(
            qs, context=self.context, many=True)
        return serializer.data

    def get_roles(self, obj):
        return [affiliation.role for affiliation in obj._affiliations]

    def optimize_queryset(self, qs):
        qs = super().optimize_queryset(qs)
        qs = qs.prefetch_related(
            Prefetch(
                'terms_of_services',
                queryset=AcceptedTermsOfService.objects.select_related(
                    'terms_of_service',
                    'terms_of_service__version'
                ).filter(
                    user=self.context['request'].user
                ),
                to_attr='_accepted_tos'
            ),
        )
        qs = qs.prefetch_related(
            Prefetch(
                'affiliations',
                to_attr='_affiliations'
            ),
        )
        return qs


class EmailRegistrationSerializer(DefaultBaseHyperlinkedModelSerializer):
    invitation_uuid = serializers.UUIDField(required=False)
    bicycle_uuid = serializers.UUIDField(
        required=False,
        help_text='Create renter affiliation with organization of this '
                  'bicycle for whitelisted email domains.')
    organization_uuid = serializers.UUIDField(
        required=False,
        help_text='Create a renter affiliation with this organization for'
                  ' whitelisted email domains or open fleets.'
    )

    class Meta:
        model = User
        fields = (
            'email',
            'password',
            'first_name',
            'last_name',
            'avatar',
            'invitation_uuid',
            'bicycle_uuid',
            'organization_uuid',
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:user-detail', 'lookup_field': 'uuid'},
            'password': {'write_only': True},
            'email': {'required': True},
            'username': {'required': False, 'help_text': None},
            'first_name': {'required': True},
            'last_name': {'required': True},
        }

    def validate_email(self, email):
        django_email_validator(email)
        return email

    def validate_password(self, password):
        password_validation.validate_password(password)
        return password

    def validate_invitation_uuid(self, uuid):
        email = self.context['request'].data['email']
        try:
            self.context['invitation'] = Invitation.objects.get(
                uuid=uuid,
                email=email,
                state=InvitationStates.PROVISIONED.value)
        except Invitation.DoesNotExist as exc:
            raise serializers.ValidationError(
                _('No Invitation with given UUID exists.'),
                code='not_found') from exc
        return uuid

    def validate_bicycle_uuid(self, uuid):
        try:
            bicycle = Bicycle.objects.get(uuid=uuid)
        except Bicycle.DoesNotExist:
            raise serializers.ValidationError('Bicycle not found.')

        email = self.context['request'].data['email']
        domain = email.partition('@')[2]

        org = bicycle.organization
        allowed_domains = org.allowed_signup_domain_names
        if allowed_domains:
            if domain not in allowed_domains:
                raise serializers.ValidationError(
                    'The email address is not allowed for this organization.',
                    code='email_not_whitelisted')
        elif not org.is_open_fleet:
            raise serializers.ValidationError(
                'The email address is not allowed for this organization.',
                code='email_not_whitelisted')
        self.context['bicycle'] = bicycle
        return uuid

    def validate_organization_uuid(self, uuid):
        try:
            org = Organization.objects.get(uuid=uuid)
        except Organization.DoesNotExist:
            raise serializers.ValidationError('Organization not found.',
                                              code='organization_not_found')

        email = self.context['request'].data['email']
        domain = email.partition('@')[2]

        allowed_domains = org.allowed_signup_domain_names
        if allowed_domains:
            if domain not in allowed_domains:
                raise serializers.ValidationError(
                    'The email address is not allowed for this organization.',
                    code='email_not_whitelisted')
        elif not org.is_open_fleet:
            raise serializers.ValidationError(
                'The email address is not allowed for this organization.',
                code='email_not_whitelisted')
        self.context['organization'] = org
        return uuid

    def validate(self, data):
        if 'invitation_uuid' in data and 'bicycle_uuid' in data:
            raise serializers.ValidationError(
                'invitation_uuid and bicycle_uuid must not be used together.')
        if 'invitation_uuid' not in data:
            def check_local_user():
                try:
                    existing_user = User.objects.filter_local_users(
                        email__iexact=data['email'],
                    ).get()
                except User.DoesNotExist:
                    pass
                else:
                    if existing_user.is_active:
                        send_suspicious_registration_email_task.delay(
                            data['email'], Organization.get_root_org().pk)
                    else:
                        existing_user.send_activation_email()
                    raise SkipValidationError

            if 'organization_uuid' in data:
                organization = self.context['organization']
                if organization.is_whitelabel:
                    try:
                        existing_user = User.objects.filter_local_whitelabel_users(  # noqa: E501
                            organization,
                            email__iexact=data['email'],
                        ).get()
                    except User.DoesNotExist:
                        pass
                    else:
                        if existing_user.is_active:
                            send_suspicious_registration_email_task.delay(
                                data['email'], organization.pk)
                        else:
                            existing_user.send_activation_email()
                        raise SkipValidationError
                else:
                    check_local_user()
            else:
                check_local_user()
        if ('bicycle_uuid' in data and 'organization_uuid' in data and
                self.context['organization'] !=
                self.context['bicycle'].organization):
            msg = _('This Bicycle can not be rented through this app.')
            raise serializers.ValidationError(
                {'bicycle_uuid': [msg]}, code='bicycle_organization_mismatch'
            )
        if ('invitation_uuid' in data and 'organization_uuid' in data and
                self.context['organization'] !=
                self.context['invitation'].organization):
            msg = _('This Invitation can not be accepted through this app.')
            raise serializers.ValidationError(
                {'invitation_uuid': [msg]},
                code='invitation_organization_mismatch'
            )
        return data

    def create(self, validated_data):
        try:
            del validated_data['invitation_uuid']
        except KeyError:
            pass
        bicycle_uuid = validated_data.pop('bicycle_uuid', None)
        organization_uuid = validated_data.pop('organization_uuid', None)
        email = validated_data['email']
        invitation = self.context.get('invitation')
        organization = self.context.get(
            'organization',
            getattr(invitation, 'organization', None))

        is_whitelabel = (organization.is_whitelabel if organization is not None
                         else False)
        is_fleet_op_invitation = (
            invitation.role in (Affiliation.FLEET_OPERATOR, Affiliation.ADMIN)
            if invitation is not None else False)
        bind_to_organization = is_whitelabel and not is_fleet_op_invitation
        is_active = invitation is not None
        try:
            if bind_to_organization:
                user = User.objects.filter_local_whitelabel_users(
                    organization,
                    email__iexact=email).get()
            else:
                user = User.objects.filter_local_users(
                    email__iexact=email).get()
        except User.DoesNotExist:
            new_uname = User.generate_username_from_email(
                validated_data['email'],
                organization_uuid=(
                    organization_uuid if bind_to_organization else None),
            )
            validated_data['owner'] = None
            validated_data['username'] = new_uname
            validated_data['is_active'] = is_active
            validated_data['organization'] = (
                organization if bind_to_organization else None)
            user = User.objects.create_user(**validated_data)
            user.refresh_tokens.create(app='local')
            if is_active:
                user.publish_activated_event()
        if is_active:
            invitation.confirm(by=user)
            create_affiliations_if_whitelisted(user)
        elif organization is not None:
            Affiliation.objects.create(user=user,
                                       organization=organization,
                                       role=Affiliation.RENTER)
        elif bicycle_uuid:
            bicycle = self.context['bicycle']
            Affiliation.objects.create(user=user,
                                       organization=bicycle.organization,
                                       role=Affiliation.RENTER)

        return user


class UserProfileSerializer(DefaultBaseHyperlinkedModelSerializer):
    serializer_url_field = NestedHyperlinkedRelatedField
    phone_numbers = serializers.DictField()

    class Meta:
        model = UserProfile
        fields = (
            'phone_numbers',
        )
        extra_kwargs = {
            'url': {
                'view_name': 'lock8:user_profile-detail',
                'parent_lookup_kwargs': {'parent_lookup_uuid': 'user__uuid'},
                'lookup_field': 'uuid',
                'read_only': True,
                'source': '*',
            },
        }


class ZoneSerializer(DefaultBaseHyperlinkedModelSerializer,
                     OrganizationOwnedHyperlinkedModelSerializer):
    class Meta:
        model = Zone
        fields = (
            'name',
            'type',
            'polygon',
            'preferred_mechanic',
            'low_threshold',
            'high_threshold'
        )
        extra_kwargs = {
            'url': {'view_name': 'lock8:zone-detail',
                    'lookup_field': 'uuid'},
            'preferred_mechanic': {'view_name': 'lock8:user-detail',
                                   'lookup_field': 'uuid'},
        }

    def __init__(self, *args, **kwargs):
        super(ZoneSerializer, self).__init__(*args, **kwargs)
        request = kwargs['context']['request']
        if request.GET.get('include_bicycle_count', False):
            self.fields['bicycle_count'] = \
                serializers.IntegerField(read_only=True)

    def optimize_queryset(self, qs: ZoneQuerySet) -> QuerySet:
        return qs.select_related('organization')

    def validate_polygon(self, polygon: MultiPolygon) -> MultiPolygon:
        if polygon.geom_type != 'MultiPolygon':
            raise serializers.ValidationError(
                f'Invalid polygon type `{polygon.geom_type}`,'
                'expected `MultiPolygon`', code='invalid')
        return polygon

    def validate_high_threshold(self, high_threshold: typing.Optional[int]
                                ) -> typing.Optional[int]:
        if high_threshold and high_threshold < 0:
            raise serializers.ValidationError(
                f'Invalid high threshold `{high_threshold}`,'
                'expected a positive integer', code='invalid')
        return high_threshold

    def validate_low_threshold(self, low_threshold: typing.Optional[int]
                               ) -> typing.Optional[int]:
        if low_threshold and low_threshold < 0:
            raise serializers.ValidationError(
                f'Invalid low threshold `{low_threshold}`,'
                'expected a positive integer', code='invalid')
        return low_threshold

    def validate(self, data: OrderedDict) -> OrderedDict:
        low_threshold: int = data.get('low_threshold', None)
        high_threshold: int = data.get('high_threshold', None)
        if low_threshold and high_threshold:
            if low_threshold >= high_threshold:
                raise serializers.ValidationError(
                    f'Invalid high threshold `{high_threshold}`,'
                    'expected a value higher than low threshold',
                    code='invalid')
        return data


class PasswordForgotSerializer(DjoserPasswordResetSerializer):
    organization_uuid = serializers.UUIDField(required=False)

    def validate_organization_uuid(self, uuid):
        try:
            org = Organization.objects.get(uuid=uuid)
        except Organization.DoesNotExist:
            raise serializers.ValidationError('Organization not found.',
                                              code='organization_not_found')
        self.context['organization'] = org
        return uuid

    def validate(self, data):
        super().validate(data)

        email = data['email']

        if 'organization' in self.context:
            self.user = User.objects.filter_local_whitelabel_users(
                self.context['organization'],
                email__iexact=email,
            ).first()
        else:
            self.user = User.objects.filter_local_users(
                email__iexact=email).first()
            if self.user is None:
                self.user = User.objects.filter(
                    social_auth__user__isnull=True,
                    email__iexact=email).first()

        return data


class UUIDAndTokenSerializer(serializers.Serializer):
    uuid = serializers.UUIDField(required=True)
    token = serializers.CharField(required=True)

    def validate_uuid(self, uuid):
        try:
            self.user = User.objects.get(uuid=uuid)
        except User.DoesNotExist:
            msg = _('User does not exist.')
            raise serializers.ValidationError(msg)


class PasswordResetSerializer(UUIDAndTokenSerializer):
    new_password = serializers.CharField(style={'input_type': 'password'})

    def validate_new_password(self, value):
        user = self.context['request'].user or self.user
        assert user is not None
        password_validation.validate_password(value, user)
        return value

    def validate(self, attrs):
        if not default_token_generator.check_token(self.user, attrs['token']):
            msg = _('Invalid token for given user.')
            raise serializers.ValidationError({'token': [msg]})
        if not self.user.is_active:
            msg = _('User account is disabled.')
            raise serializers.ValidationError(msg)
        return attrs


class AccountActivationSerializer(UUIDAndTokenSerializer):
    def validate(self, attrs):
        if self.user.is_active:
            msg = _('Stale token for given user.')
            raise serializers.ValidationError({'token': [msg]},
                                              code='already_activated')
        if not default_token_generator.check_token(self.user, attrs['token']):
            msg = _('Invalid token for given user.')
            raise serializers.ValidationError({'token': [msg]})
        return attrs


class TransitionSerializer(serializers.HyperlinkedModelSerializer):
    class Meta:
        model = StateLog
        fields = (
            'timestamp',
            'state',
            'transition',
            'by',
        )
        extra_kwargs = {
            'by': {'view_name': 'lock8:user-detail',
                   'lookup_field': 'uuid'},
        }


bbox_regex = re.compile('^{}$'.format(','.join((r'-?[0-9\.]+',) * 4)))


class ClusterInputSerializer(Serializer):
    bbox = serializers.RegexField(
        bbox_regex, required=True,
        help_text='South-West then North-East corners of the box (csv).'
    )
    include_state = serializers.BooleanField(
        required=False, default=False,
        help_text='Include state field in response?'
    )
    include_model = serializers.BooleanField(
        required=False, default=False,
        help_text='Include model field in response?'
                  ' exclusive from include_state.'
    )
    organizations = serializers.CharField(
        required=False,
        allow_blank=True,
        default='',
        help_text='List of organizations filter for bicycles'
    )


class MetaclassForLatestTrackings(MetaclassForMeta):
    """Add fields to class, based on TRACKING_SOURCE."""

    def __new__(cls, name, bases, kwargs):
        try:
            _Meta = kwargs['Meta']
        except KeyError:
            _Meta = type('{}_MetaForFields'.format(name), (), {})

        class Meta(_Meta):
            fields = TRACKING_FIELDS
            read_only_fields = fields

        # XXX: this prepends the fields instead of appending them.
        # See test_crud_on_lock_serialized.
        tracking_source = kwargs['TRACKING_SOURCE']
        kwargs.update({
            'Meta': Meta,
            'latest_gps_timestamp': DateTimeFieldWithSecondPrecision(
                source=f'{tracking_source}.gps_timestamp',
                allow_null=True,
                read_only=True),
            'latitude': serializers.FloatField(
                source=f'{tracking_source}.gps_latitude',
                allow_null=True,
                read_only=True),
            'longitude': serializers.FloatField(
                source=f'{tracking_source}.gps_longitude',
                allow_null=True,
                read_only=True),
            'latest_gps_accuracy': serializers.FloatField(
                source=f'{tracking_source}.gps_accuracy',
                allow_null=True,
                read_only=True),
            'latest_gps_pdop': serializers.FloatField(
                source=f'{tracking_source}.gps_pdop',
                allow_null=True,
                read_only=True),
            'state_of_charge': serializers.FloatField(
                source=f'{tracking_source}.state_of_charge',
                allow_null=True,
                read_only=True),
        })
        return super().__new__(cls, name, bases, kwargs)


class PrivateBicycleSerializer(BicycleBaseSerializer,
                               metaclass=MetaclassForLatestTrackings):
    TRACKING_SOURCE = 'private_tracking'


class PublicBicycleSerializer(BicycleBaseSerializer,
                              metaclass=MetaclassForLatestTrackings):
    TRACKING_SOURCE = 'public_tracking'


class PrivateLockSerializer(LockBaseSerializer,
                            metaclass=MetaclassForLatestTrackings):
    TRACKING_SOURCE = 'private_tracking'


class PublicLockSerializer(LockBaseSerializer,
                           metaclass=MetaclassForLatestTrackings):
    TRACKING_SOURCE = 'public_tracking'


class CouponSerializer(serializers.ModelSerializer):
    class Meta:
        model = Coupon
        read_only_fields = fields = (
            'stripe_id',
            'amount_off',
            'currency',
            'duration',
            'duration_in_months',
            'livemode',
            'percent_off',
            'valid'
        )


class DiscountSerializer(serializers.ModelSerializer):
    coupon = CouponSerializer()

    class Meta:
        model = Discount
        read_only_fields = fields = (
            'coupon',
            'customer',
            'end',
            'start',
        )


class UserEphemeralkeyInputSerializer(serializers.Serializer):
    stripe_api_version = serializers.CharField(required=True)
    organization = serializers.UUIDField(required=True)


class UserSubscriptionsInputSerializer(serializers.Serializer):
    organization = serializers.UUIDField(required=True)


class UserSubscriptionSerializer(serializers.ModelSerializer):
    subscription_plan = SubscriptionPlanSerializer(
        source='plan.subscriptionplan')
    discount = DiscountSerializer()

    class Meta:
        model = Subscription
        read_only_fields = fields = (
            'stripe_id',
            'status',
            'current_period_start',
            'current_period_end',
            'cancel_at_period_end',
            'discount',
            'ended_at',
            'subscription_plan',
        )
        depth = 1


class MetricValueSerializer(serializers.Serializer):
    pass


class MetricsSerializer(serializers.Serializer):
    values = MetricValueSerializer(many=True)


class PredictionSerializer(serializers.Serializer):
    q25 = serializers.IntegerField()
    q75 = serializers.IntegerField()
    median = serializers.IntegerField()
    date = serializers.DateTimeField()


class PredictionValueSerializer(serializers.Serializer):
    zone = serializers.HyperlinkedRelatedField(
        view_name='lock8:zone-detail',
        lookup_field='uuid',
        read_only=True,
    )
    predictions = PredictionSerializer(many=True)


class PredictionsSerializer(serializers.Serializer):
    values = PredictionValueSerializer(many=True)


class RefreshTokenSerializer(RefreshTokenSerializer):
    user = serializers.HyperlinkedRelatedField(
        required=False,
        read_only=True,
        lookup_field='uuid',
        view_name='lock8:user-detail',
        default=serializers.CurrentUserDefault())
