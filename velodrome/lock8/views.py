import contextlib
import datetime as dt
import functools
import json
import logging
import time
from urllib.parse import urlencode
import uuid

from django.conf import settings
from django.contrib.auth.signals import user_logged_in
from django.contrib.gis.db.models.functions import BoundingCircle, Distance
from django.contrib.gis.geos import Point, Polygon
from django.core.cache import caches
from django.core.exceptions import ObjectDoesNotExist
from django.db import transaction
from django.db.models.query import F, Q
from django.http import Http404
from django.shortcuts import get_object_or_404, redirect
from django.utils.translation import ugettext as _
from django.views.decorators.cache import never_cache
from djoser.views import (
    PasswordResetConfirmView as DjoserPasswordResetConfirmView,
    PasswordResetView as DjoserPasswordResetView,
    UserCreateView as DjoserRegistrationView,
)
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from drf_yasg.views import get_schema_view
from pinax.stripe.models import Subscription
from refreshtoken.views import RefreshTokenViewSet
import requests
from rest_framework import exceptions, serializers, status, viewsets
from rest_framework.decorators import (
    action, api_view, permission_classes, schema,
)
from rest_framework.generics import GenericAPIView, RetrieveAPIView
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.settings import api_settings
from rest_framework_csv.renderers import CSVRenderer, CSVStreamingRenderer
from rest_framework_jwt.serializers import (
    jwt_encode_handler, jwt_payload_handler,
)
from rest_framework_jwt.settings import api_settings as jwt_settings
from rest_framework_jwt.views import (
    JSONWebTokenAPIView, RefreshJSONWebToken, VerifyJSONWebToken,
)
from social_django.utils import psa
import stripe

from velodrome.celery import (
    debug_celery_log, send_activation_email_task,
    send_password_reset_email_task,
)

from . import filters as lock8_filters, serializers as lock8_serializers
from .exceptions import SkipValidationError, SubscriptionExistsError
from .filters import (
    AddressFilter, AffiliationFilter, AlertFilter, AlertMessageFilter,
    AxaLockFilter, BaseFilterSet, BicycleFilter, BicycleModelFilter,
    BicycleModelMaintenanceRuleFilter, FeedbackCategoryFilter, FeedbackFilter,
    FirmwareFilter, InvitationFilter, LockFilter, LockFirmwareUpdateFilter,
    NotificationMessageFilter, OrganizationFilterMixin, PhotoFilter,
    PlanPassFilter, PricingSchemeFilter, RentalSessionFilter,
    ReservationFilter, SubscriptionPlanFilter, SupportTicketFilter, TaskFilter,
    TermsOfServiceFilter, UserFilter, ZoneFilter,
)
from .metrics import MetricsFilterBackend, MetricsQuerysetLike
from .models import (
    Address, Affiliation, Alert, AlertMessage, AxaLock, Bicycle, BicycleModel,
    BicycleModelMaintenanceRule, BicycleType, ClientApp, Feedback,
    FeedbackCategory, Firmware, Invitation, InvitationStates, Lock,
    LockFirmwareUpdate, NotificationMessage, Organization,
    OrganizationPreference, Photo, PlanPass, PricingScheme, PrivateTracking,
    PublicTracking, RentalSession, RentingScheme, Reservation,
    SubscriptionPlan, SupportTicket, Task, TermsOfService,
    TermsOfServiceVersion, Trip, User, UserProfile, Zone,
)
from .permissions import (
    AnonCustomPermissions, AnonDjangoObjectPermissions, CustomPermissions,
    IsAllowedToSeeTransitions, check_scopes_are_allowed,
)
from .predictions import PredictionsFilterBackend, PredictionsQuerysetLike
from .renderers import TSVStreamingRenderer
from .serializers import (
    AcceptTermsOfServiceInputSerializer, AccountActivationSerializer,
    ActionableSerializer, AddressSerializer, AffiliationSerializer,
    AlertActionableSerializer, AlertCreateSerializer, AlertMessageSerializer,
    AlertSerializer, AxaLockCreateSerializer, AxaLockSerializer,
    BicycleActionableSerializer, BicycleBaseSerializer, BicycleLockStatusSerializer,
    BicycleModelMaintenanceRuleActionableSerializer,
    BicycleModelMaintenanceRuleSerializer, BicycleModelSerializer,
    BicyclePricingSerializer, BicycleStatsSerializer, BicycleTypeSerializer,
    ClientAppSerializer, ClientAppUpdateSerializer, ClusterInputSerializer,
    CurrentUserSerializer, EmailRegistrationSerializer,
    FeedbackActionableSerializer, FeedbackCategorySerializer,
    FeedbackSerializer, FirmwareSerializer, InvitationSerializer,
    JSONWebTokenAutoLoginSerializer, JSONWebTokenLocalSerializer,
    JSONWebTokenSerializer, LockBaseSerializer, LockFirmwareUpdateSerializer,
    MetricsSerializer, NestedOrganizationPreferenceSerializer,
    NotificationMessageSerializer, OrganizationSerializer, OtpInputSerializer,
    OtpSerializer, PasswordChangeSerializer, PasswordForgotSerializer,
    PasswordResetSerializer, PhotoSerializer, PhotoSerializerForPost,
    PlanPassSerializer, PredictionsSerializer, PricingSchemeSerializer,
    RefreshTokenSerializer, RentalSessionSerializer, RentingSchemeSerializer,
    ReservationSerializer, SharedSecretSerializer,
    SubscribeUserToSubscriptionPlanInputSerializer, SubscriptionPlanSerializer,
    SupportTicketSerializer, TaskActionableSerializer, TaskSerializer,
    TermsOfServiceSerializer, TermsOfServiceVersionSerializer,
    TransitionSerializer, UnsubscribeUserFromSubscriptionPlanInputSerializer,
    UpdateHealthStatusAxaLock, UserEphemeralkeyInputSerializer,
    UserOfOrganizationSerializer, UserProfileSerializer, UserSerializer,
    UserSubscriptionSerializer, UserSubscriptionsInputSerializer,
    ZoneSerializer,
)
from .throttling import SharedSecretUserRateThrottle
from .utils import (
    ClusterWithin, ClusterWithinAggregate, create_affiliations_if_whitelisted,
    debug_log_error, extend_clusters, generate_auto_login_code,
    get_cluster_distance_from_bbox, get_next_ekey_slot,
    group_to_model_clusters, group_to_state_clusters,
)

logger = logging.getLogger(__name__)


class BaseViewMixin:
    pass


class ObtainJSONWebToken(BaseViewMixin, JSONWebTokenAPIView):
    """
    API View that receives a `POST` request with an `access_token`
    provided by a third party OAuth2 provider.

    Returns a JSON Web Token that can be used to perform authenticated requests
    to lock8's API.

    Supported authentication backends are:

      1. `lock8_facebook_oauth2`
      1. `lock8_google_oauth2`

    For example you should perform a `POST` request to:

        /api/jwt_social_auth/lock8_google_oauth2/

    If you have a token delivered by `google`.

    Once you received a jwt token, you need to send it back in further requests
    in `Authorization` header with value `"JWT " + token` (note the space).
    """
    serializer_class = JSONWebTokenSerializer
    permission_classes = (AllowAny,)
    authentication_classes = api_settings.DEFAULT_AUTHENTICATION_CLASSES

    def post(self, request, backend, *args, **kwargs):
        return super().post(request, *args, **kwargs)


tokeninfo = psa()(ObtainJSONWebToken.as_view())


class ObtainLocalJSONWebToken(JSONWebTokenAPIView):
    permission_classes = (AllowAny,)

    def get_serializer_class(self):
        if 'code' in getattr(self.request, 'data', {}):
            return JSONWebTokenAutoLoginSerializer
        return JSONWebTokenLocalSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        if 'code' in serializer.validated_data:
            user = User.objects.get(uuid=serializer.user_uuid)
            user_logged_in.send(sender=user.__class__,
                                request=request, user=user)
            handler = jwt_settings.JWT_RESPONSE_PAYLOAD_HANDLER
            encoded = jwt_encode_handler(jwt_payload_handler(user))
            return Response(handler(encoded, user=user, request=request))
        return super().post(request, *args, **kwargs)


localtokeninfo = ObtainLocalJSONWebToken.as_view()
refresh_jwt_token = RefreshJSONWebToken.as_view()
verify_jwt_token = VerifyJSONWebToken.as_view()


RefreshTokenViewSet.serializer_class = RefreshTokenSerializer


class DeviceViewSetMixin:

    def get_queryset(self):
        user = self.request.user
        return self.model.objects.filter(user=user).order_by('pk')


@contextlib.contextmanager
def enforce_model_serializer(view):
    """
    When you know you want the model serializer in the context of a custom
    action like interacting with the state machine or to obtain the queryset.
    """
    previous_action = view.action
    try:
        view.action = 'list'
        yield
    finally:
        view.action = previous_action


class BaseModelViewSetMixin(BaseViewMixin):
    lookup_field = 'uuid'

    def __init__(self, *args, **kwargs):
        """Use BaseFilter with self.model and mixins if there is
        no filterset_class defined."""
        super().__init__(*args, **kwargs)
        try:
            self.filterset_class
        except AttributeError:
            klassname = self.__class__.__name__
            parents = ()
            if any(f for f in self.model._meta.get_fields()
                   if f.name == 'organization'):
                parents += (OrganizationFilterMixin,)

            parents += (BaseFilterSet,)
            meta_parents = tuple(p.Meta for p in parents
                                 if hasattr(p, 'Meta'))
            self.filterset_class = type(
                'FilterFor{}'.format(klassname), parents, {
                    'Meta': type('FilterMetaFor{}'.format(klassname),
                                 meta_parents,
                                 {'model': self.model})})

    def _has_action_perm(self, action_type, obj, request):
        # TODO: Check how these generated perms work.
        perm_to_check = '.'.join(
            (obj._meta.app_label,
             '_'.join((action_type, obj._meta.model_name))))
        return (check_scopes_are_allowed(request, [perm_to_check])
                and request.user.has_perm(perm_to_check, obj))

    def _actions(self, request, uuid=None, log=False):
        obj = self.get_object()
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        action_type = serializer.validated_data.pop('type')
        dry_run = serializer.validated_data.pop('dry_run', False)
        by = request.user
        action = getattr(obj, action_type,
                         getattr(obj, action_type + '_', None))
        if action is None:
            raise Http404
        if not self._has_action_perm(action_type, obj, request):
            raise exceptions.PermissionDenied

        available_actions = [t.name.rstrip('_')
                             for t in obj.get_available_state_transitions()]
        if action_type not in available_actions:
            allowed_available_action = [
                x for x in available_actions
                if self._has_action_perm(x, obj, request)
            ]
            error_code = 'action_not_allowed'
            message = ('Action {!r} not allowed from current state {!r}. '
                       'Available actions: {!r}.'.format(
                           action_type, obj.state, allowed_available_action))
            raise exceptions.ParseError(detail={'actions': [message]},
                                        code=error_code)

        action_name_for_sentry = 'action ' + action_type
        if dry_run:
            action_name_for_sentry += ' (dry_run)'
        request._request._action_name_for_sentry = action_name_for_sentry

        if log:
            logger.info('Calling action %s for %s %s: dry_run=%d, by=%s',
                        action_type, obj.__class__.__name__,
                        getattr(obj, 'uuid', obj), dry_run, by.uuid)
        action(by=by, request=request, dry_run=dry_run,
               **serializer.validated_data)
        if dry_run:
            return Response(status=status.HTTP_204_NO_CONTENT)

        with enforce_model_serializer(self):
            serializer = self.get_serializer(obj)

        assert getattr(obj, '_prefetched_objects_cache', {}) == {}, \
            '_prefetched_objects_cache must not be used in _actions'

        return Response(serializer.data, status=status.HTTP_200_OK)

    def get_serializer(self, *args, **kwargs):
        try:
            kwargs['fields'] = self.request.query_params['fields'].split(',')
        except KeyError:
            pass
        return super().get_serializer(*args, **kwargs)

    def get_queryset(self):
        try:
            return self._qs.all()
        except AttributeError:
            serializer = self.get_serializer()
            self._qs = self.get_internal_queryset()
            if hasattr(serializer, 'optimize_queryset'):
                self._qs = serializer.optimize_queryset(self._qs)
            return self._qs

    def get_internal_queryset(self):
        return self.model.get_queryset(request=self.request)


class ActionableModelViewSetMixin:

    def get_serializer_class(self):
        if self.action == 'transitions':
            return TransitionSerializer
        elif self.action == 'actions':
            return ActionableSerializer
        return super().get_serializer_class()

    @action(detail=True, methods=['get'], suffix='Transitions',
            permission_classes=(IsAllowedToSeeTransitions,))
    def transitions(self, request, uuid=None):
        """
        Show history of transitions related to current resource.
        """
        instance = self.get_object()
        transitions = self.paginate_queryset(instance.transitions
                                             .all()
                                             .order_by('-timestamp'))
        serializer = self.get_serializer_class()(
            transitions, many=True, context={'request': request,
                                             'view': self})
        return self.paginator.get_paginated_response(serializer.data)


class SoftDeletedModelViewSetMixin:

    def perform_destroy(self, instance):
        instance.delete()


class AddressViewSet(BaseModelViewSetMixin, viewsets.ModelViewSet):
    """
    An Address linked to an Organization.
    """
    serializer_class = AddressSerializer
    model = Address
    filterset_class = AddressFilter


class AffiliationViewSet(BaseModelViewSetMixin,
                         SoftDeletedModelViewSetMixin,
                         viewsets.ModelViewSet):
    """
    Identify the relationship between a User and an Organization.
    This resource carries also the `role` of the user within the Organization.
    """
    serializer_class = AffiliationSerializer
    model = Affiliation
    filterset_class = AffiliationFilter

    def get_internal_queryset(self):
        user = self.request.user
        predicate = (
            Q(organization__in=user
              .get_descendants_managed_organizations()) |
            Q(user__pk=user.pk))
        return self.model.objects.filter(predicate).distinct()

    def destroy(self, *args, **kwargs):
        """
        Delete the Affiliation.
        It can be use to remove a Role of the user or to remove completely
        the User from the Organization.
        """
        return super().destroy(*args, **kwargs)


class LockFirmwareUpdateViewSet(BaseModelViewSetMixin,
                                SoftDeletedModelViewSetMixin,
                                viewsets.ModelViewSet):
    serializer_class = LockFirmwareUpdateSerializer
    filterset_class = LockFirmwareUpdateFilter
    model = LockFirmwareUpdate

    def get_internal_queryset(self):
        return self.model.objects.all()


class BicycleViewSet(BaseModelViewSetMixin,
                     SoftDeletedModelViewSetMixin,
                     ActionableModelViewSetMixin,
                     viewsets.ModelViewSet):
    model = Bicycle
    filterset_class = BicycleFilter
    renderer_classes = api_settings.DEFAULT_RENDERER_CLASSES + [CSVRenderer]
    permission_classes = (AnonDjangoObjectPermissions,)
    includes_spectator = False

    def get_serializer_class(self):
        if self.action == 'actions':
            return BicycleActionableSerializer
        elif self.action == 'stats':
            return BicycleStatsSerializer
        elif self.action == 'pricings':
            return BicyclePricingSerializer
        elif self.action == 'transitions':
            return TransitionSerializer
        elif self.action == 'shared_secret':
            return SharedSecretSerializer
        elif self.action == 'otp':
            return OtpSerializer
        return BicycleBaseSerializer.get_serializer_class_for_user(
            self.request.user
        )

    def get_internal_queryset(self):
        return self.model.get_queryset(
            request=self.request,
            includes_spectator=self.includes_spectator)

    def _is_csv_renderer(self):
        request = self.request
        if not isinstance(request, Request):
            self.request = Request(request)
        renderer, __ = self.content_negotiation_class().select_renderer(
            self.request, self.renderer_classes)
        return issubclass(renderer, CSVRenderer)

    def paginate_queryset(self, queryset):
        """
        Disable Pagination for csv views
        """
        if self._is_csv_renderer():
            return None
        if isinstance(self.request, Request):
            disable_pagination = self.request.query_params.get('no_page', None)
            if disable_pagination:
                return None
        return super().paginate_queryset(queryset)

    @action(detail=True, methods=['post'], suffix='Actions',
            permission_classes=(IsAuthenticated,))
    def actions(self, *args, **kwargs):
        """
        Available actions are:

        - `declare_available`
            Make the Bicycle accessible for renting.

        - `put_in_maintenance`
            Remove the Bicycle from rentable fleet.

        - `declare_lost`
            Declare the Bicycle lost. The Bicycle will not be
            available for renting.

        - `reserve`
            Reserve the Bicycle for yourself or on behalf of a user.

            A reservation can end automatically if the user didn't start
            the rental session on time.

            Accepted arguments:

             - **`user`** (User's resource url), optional.

        - `rent`
            Rent a Bicycle for yourself.

            Accepted arguments:

             - **`subscription_plan`** (Subscription Plan's resource url),
               optional.
             - **`pricing_scheme`** (Pricing Scheme's resource url), optional.
             - **`user`** (User's resource url), optional.

        - `force_put_in_maintenance`
           A Fleet operator will interrupt reservation or renting session and
           put directly the Bicycle in maintenance mode.
           The renter will receive a notification.
           The `rental_session` won't be charged.

        - `take_over`
           Crew members (fleet operators) can put a Bicycle in maintenance mode
           from Available, lost or in maintenance states.
           This is similar to `put_in_maintenance`, but will record this
           specific transition for later analysis / filtering.
           This can't be used to stop a rental session (or a reservation),
           `force_put_in_maintenance` should be called first.

        - `cancel_reservation`
            Ends the reservation session. The bicycle will become available for
            other renters.

        - `return`
            Ends the renting and the reservation sessions.
            The bicycle will be available for other renters.

            If fees are applicable for that `rental_session`,
            the renter will be charged for that amount.

            By passing `dry_run=True` you will be able to test the feasability
            of the transition without doing it.
            It is useful to check if the renter is allowed to return the
            Bicycle at the current location before locking it.

        - `retire`
            Ends life time of Bicycle.
        """
        return self._actions(*args, log=True, **kwargs)

    @action(detail=True, methods=['get'], suffix='Stats')
    def stats(self, request, uuid=None):
        """
        Expose statistics data related to the Bicycle and
        the associated Lock.
        - `total_distance` (in meters)
        - `last_cellular_update`
        """
        bicycle = self.get_object()
        total_distance = bicycle.get_total_ridden_distance()
        bicycle_serializer = (BicycleBaseSerializer
                              .get_serializer_class_for_user(request.user))
        try:
            latest_tracking_timestamp = getattr(
                bicycle, bicycle_serializer.TRACKING_SOURCE).modified
        except AttributeError:
            latest_tracking_timestamp = None
        serializer = self.get_serializer(
            data={'total_distance': int(total_distance),
                  'last_cellular_update': latest_tracking_timestamp,
                  })
        serializer.is_valid(raise_exception=True)

        return Response(
            serializer.to_representation(serializer.validated_data),
            status=status.HTTP_200_OK)

    @action(detail=True, methods=['get'], suffix='Pricings')
    def pricings(self, request, uuid=None):
        """
        Get active subscriptions, or available pricing schemes and subscription
        plans.

        This endpoint returns an object containing the following optional
        lists:

        - `active_subscriptions`: SubscriptionPlanSerializer(many=True)
        - `pricing_schemes`: PricingSchemeSerializer(many=True)
        - `subscription_plans`: SubscriptionPlanSerializer(many=True)

        `active_subscriptions` are subscriptions the renter is subscribed
        to currently.

        1. If there are several `active_subscriptions`

            We expect the renter to choose a `SubscriptionPlan` to cover the
            costs of the rental session.
            The `url` should be passed to the `rent()` api call:

                http POST /bicycles/{uuid}/actions/ type=rent subscription_plan=https://api.lock8.me/api/subscription_plans/{uuid}/

        2. If there is only one `active_subscription`

            This will be used to cover the costs of the rental session.

        3. If it contains one `pricing_schemes` and no `subscription_plans`

            This `PricingScheme` will be used to compute the price of the
            rental session.

        4. Default

            `subscription_plans` contains the list of plans, and
            `pricing_schemes` the list of pricing schemes the renter can choose
            from to rent the current Bicycle.

        5. If all entries are empty

            According to the preference `allow_renting_without_pricings`
            defined on the `OrganizationPreference`:

            1. `true`: the renter can start a rental session and ride free of
               charge.
            2. `false`: the renter is expected to be subscribed to a
               subscription that will support the cost of the rental session.
        """  # noqa: E501
        bicycle = self.get_object()
        data = bicycle.get_pricings_for_user(request.user)
        serializer = self.get_serializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True,
            methods=['get'],
            suffix='Shared Secrets',
            throttle_classes=(SharedSecretUserRateThrottle,))
    def shared_secret(self, request, uuid=None):
        """
        Shared Secret used to encrypt communication with Device.
        """
        lock = self.get_object().lock
        if lock is None or lock.shared_secret is None:
            raise Http404()

        serializer = self.get_serializer(lock.shared_secret)
        return Response(serializer.data, status=status.HTTP_200_OK)

    @swagger_auto_schema(query_serializer=OtpInputSerializer)
    @action(detail=True, methods=['get'],
            suffix='OTP',
            throttle_classes=(SharedSecretUserRateThrottle,))
    def otp(self, request, uuid=None):
        """Return a list of OTPs for the Device carried by the Bicycle."""
        axa_lock = self.get_object().axa_lock
        if axa_lock is None:
            raise Http404()
        serializer = OtpInputSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)

        slot = serializer.validated_data['slot']
        if slot is None:
            slot = get_next_ekey_slot(axa_lock)

        ekey, otps, expiration = axa_lock.obtain_otps(
            slot,
            serializer.validated_data['number'],
            hours=serializer.validated_data['hours'])
        serializer = self.get_serializer({
            'ekey': ekey, 'otps': otps, 'expiration': expiration})
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'],
            suffix='Report AXA lock status')
    def report_axa_lock_status(self, request, uuid=None):
        """Update status of axa lock."""
        axa_lock = self.get_object().axa_lock
        if axa_lock is None:
            raise Http404()
        serializer = UpdateHealthStatusAxaLock(data=request.data)
        serializer.is_valid(raise_exception=True)
        axa_lock.update_health_status(
            serializer.validated_data['lock_health_msg'])
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=['post'], suffix="Set bicycle status to locked or unlocked", permission_classes=[AllowAny,])
    def bicycle_lock_status(self, request, uuid=None):
        """Lock or Unlock Bicycle"""
        bicycle = self.get_object()
        if bicycle is None:
            raise Http404()
        serializer = BicycleLockStatusSerializer(data=request.data, instance=bicycle)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_206_PARTIAL_CONTENT, data=serializer.data)

class BicycleModelViewSet(BaseModelViewSetMixin,
                          SoftDeletedModelViewSetMixin,
                          viewsets.ModelViewSet):
    """
    Model of Bicycles.
    """
    serializer_class = BicycleModelSerializer
    model = BicycleModel
    filterset_class = BicycleModelFilter


class BicycleModelMaintenanceRuleViewSet(BaseModelViewSetMixin,
                                         SoftDeletedModelViewSetMixin,
                                         ActionableModelViewSetMixin,
                                         viewsets.ModelViewSet):
    """
    Maintenance rules related to a given bicycle model.
    """
    serializer_class = BicycleModelMaintenanceRuleSerializer
    model = BicycleModelMaintenanceRule
    filterset_class = BicycleModelMaintenanceRuleFilter

    def get_serializer_class(self):
        if self.action == 'actions':
            return BicycleModelMaintenanceRuleActionableSerializer
        return super().get_serializer_class()

    def destroy(self, request, *args, **kwargs):
        msg = _('Rules make historical data. Use `deactivate` intead.')
        raise serializers.ValidationError(msg)

    def get_internal_queryset(self):
        try:
            uuid = self.request.parser_context['kwargs']['parent_lookup_uuid']
        except KeyError:
            # From schema generator
            return self.model.get_queryset(request=self.request).none()
        return self.model.get_queryset(request=self.request).filter(
            bicycle_model__uuid=uuid)

    def perform_create(self, serializer):
        uuid = self.request.parser_context['kwargs']['parent_lookup_uuid']
        serializer.is_valid(raise_exception=True)
        bmodel = BicycleModel.objects.get(uuid=uuid)
        serializer.validated_data.update({'bicycle_model': bmodel})
        serializer.save()

    @action(detail=True, methods=['post'], suffix='Actions',
            permission_classes=(IsAuthenticated,))
    def actions(self, *args, parent_lookup_uuid=None, **kwargs):
        """
        Available actions are:

        - `deactivate`
            Prevent the BicycleModelMaintenanceRule to create further tasks,
            once they are completed.
            - **cancel_tasks**  cancel tasks for rule.
        - `activate`
            Resume the creation of Tasks once it is active again.
        """
        return self._actions(*args, **kwargs)


class BicycleTypeViewSet(BaseModelViewSetMixin,
                         viewsets.ReadOnlyModelViewSet):
    """
    Category of Bicycles.
    """
    serializer_class = BicycleTypeSerializer
    model = BicycleType
    queryset = BicycleType.objects.all()

    def get_internal_queryset(self):
        return self.queryset.all()


class ClientAppViewSet(BaseModelViewSetMixin, viewsets.ModelViewSet):
    serializer_class = ClientAppSerializer
    model = ClientApp

    def get_serializer_class(self):
        if self.action in ('partial_update', 'update'):
            return ClientAppUpdateSerializer
        return super().get_serializer_class()

    def get_queryset(self):
        user = self.request.user
        return self.model.objects.filter(
            organization__in=user.get_descendants_managed_organizations())

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        instance = serializer.instance
        with enforce_model_serializer(self):
            serializer = self.get_serializer(instance)
        headers = self.get_success_headers(serializer.data)
        data = serializer.data.copy()
        data['private_key'] = instance.private_key
        return Response(data,
                        status=status.HTTP_201_CREATED,
                        headers=headers)

    def destroy(self, request, pk=None, uuid=None):
        obj = self.get_object()
        sts_response = requests.delete(
            obj.remote_url,
            headers={'Authorization': 'Token {}'.format(
                settings.STS_AUTH_TOKEN.strip())},
        )
        assert sts_response.status_code == 204
        return super().destroy(request, pk=pk, uuid=uuid)


class TermsOfServiceViewSet(BaseModelViewSetMixin,
                            SoftDeletedModelViewSetMixin,
                            viewsets.ModelViewSet):
    serializer_class = TermsOfServiceSerializer
    model = TermsOfService
    filterset_class = TermsOfServiceFilter


class TermsOfServiceVersionViewSet(BaseModelViewSetMixin,
                                   viewsets.ModelViewSet):
    serializer_class = TermsOfServiceVersionSerializer
    model = TermsOfServiceVersion


class InvitationViewSet(BaseModelViewSetMixin,
                        SoftDeletedModelViewSetMixin,
                        ActionableModelViewSetMixin,
                        viewsets.ModelViewSet):
    serializer_class = InvitationSerializer
    model = Invitation
    filterset_class = InvitationFilter
    permission_classes = (AnonDjangoObjectPermissions,)

    def get_internal_queryset(self):
        user = self.request.user
        if user.is_authenticated:
            per_user = Q(user=user)
            per_admin = Q(organization__in=user
                          .get_descendants_managed_organizations())
            predicate = (per_user | per_admin)
            if self.action in ('retrieve', 'actions'):
                anyone_predicate = Q(state=InvitationStates.PROVISIONED.value)
                predicate |= anyone_predicate
            return self.model.objects.filter(predicate).distinct()
        elif self.action in ('retrieve', 'actions'):
            predicate = Q(state=InvitationStates.PROVISIONED.value)
            return self.model.objects.filter(predicate).distinct()
        else:
            return self.model.objects.none()

    @action(detail=True, methods=['post'], suffix='Actions',
            permission_classes=(IsAuthenticated,))
    def actions(self, *args, **kwargs):
        """
        Available actions are:

        - `cancel`
            Fleet Operator can cancel the Invitation, after the email was sent.
        - `confirm`
            User confirmed the Invitation, the Affiliation between the User
            and Organization will be created.
        - `resend`
            Resend the invitation email.
        - `decline`
            User declines the Invitation.
            No Affiliation between the User and Organisation is created.
        """
        return self._actions(*args, **kwargs)

    def update(self, request, *args, **kwargs):
        """
        No update possible
        """
        raise exceptions.MethodNotAllowed(request.method)

    def retrieve(self, *args, **kwargs):
        """
        If a user own any invitation uuid,
        she can access any Invitation she likes.
        """
        return super().retrieve(*args, **kwargs)

    def perform_create(self, serializer):
        """
        Create a new Invitation and send the email.
        """
        serializer.save()
        request = self.request
        serializer.instance.provision(by=request.user, request=request)


class LockViewSet(BaseModelViewSetMixin,
                  SoftDeletedModelViewSetMixin,
                  ActionableModelViewSetMixin,
                  viewsets.ModelViewSet):
    filterset_class = LockFilter
    model = Lock

    def get_serializer_class(self):
        if self.action == 'actions':
            return ActionableSerializer
        elif self.action == 'transitions':
            return TransitionSerializer
        return LockBaseSerializer.get_serializer_class_for_user(
            self.request.user
        )

    @action(detail=True, methods=['post'], suffix='Actions',
            permission_classes=(IsAuthenticated,))
    def actions(self, *args, **kwargs):
        """
        Available actions are:

        - `provision`
            Declare the lock ready and configured after manufacturing.
            The Lock is operational and can be associated to a Bicycle.
            Only admins of lock8 can call this action.
        - `activate`
            The lock is claimed by an organisation.
            Only admins of lock8 can call this action.
        - `put_in_maintenance`
            Bicycle associated to this Lock will be removed
            from rentable fleet.
        - `decommission`
            The lock is deemed not fit for service.
            Only admins of lock8 can call this action.
        - `restore`
            Declare the Bicycle associated to this Lock available
            for renting again.
        """
        return self._actions(*args, **kwargs)


class AxaLockViewSet(BaseModelViewSetMixin,
                     SoftDeletedModelViewSetMixin,
                     ActionableModelViewSetMixin,
                     viewsets.ModelViewSet):
    serializer_class = AxaLockSerializer
    filterset_class = AxaLockFilter
    model = AxaLock

    def get_serializer_class(self):
        if self.action == 'create':
            return AxaLockCreateSerializer
        elif self.action == 'otp':
            return OtpSerializer
        return super().get_serializer_class()

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        headers = self.get_success_headers(serializer.data)
        with enforce_model_serializer(self):
            output_serializer = self.get_serializer(serializer.instance)
        return Response(output_serializer.data,
                        status=status.HTTP_201_CREATED,
                        headers=headers)

    @action(detail=True, methods=['post'], suffix='Actions',
            permission_classes=(IsAuthenticated,))
    def actions(self, *args, **kwargs):
        """
        Available actions are:

        - `claim`
            Claim the lock to be in inventory of current KeySafe tenant.
        - `declare_transferable`
            Create a claim_token to be consumed by another KeySafe tenant.
            Once claimed, we lose access to this Lock.
        - `declare_stored`
            Lock will not be utilized for a while. Due to end of the season
            or maybe even pandemic! Pay attention that lock will be set
            to `active` state on AXA side, in case we requested OTPs for it.
        """
        return self._actions(*args, **kwargs)

    @swagger_auto_schema(query_serializer=OtpInputSerializer)
    @action(detail=True, methods=['get'], suffix='OTP')
    def otp(self, request, uuid=None):
        """Return a list of OTPs for the lock."""
        axa_lock = self.get_object()
        serializer = OtpInputSerializer(data=request.query_params)
        serializer.is_valid(raise_exception=True)

        slot = serializer.validated_data['slot']
        if slot is None:
            slot = get_next_ekey_slot(axa_lock)

        ekey, otps, expiration = axa_lock.obtain_otps(
            slot,
            serializer.validated_data['number'],
            hours=serializer.validated_data['hours'])
        serializer = self.get_serializer({
            'ekey': ekey, 'otps': otps, 'expiration': expiration})
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['post'], suffix='Report AXA lock status')
    def report_axa_lock_status(self, request, uuid=None):
        """Update status of axa lock."""
        axa_lock = self.get_object()
        serializer = UpdateHealthStatusAxaLock(data=request.data)
        serializer.is_valid(raise_exception=True)
        axa_lock.update_health_status(
            serializer.validated_data['lock_health_msg'])
        return Response(status=status.HTTP_204_NO_CONTENT)


class FirmwareViewSet(BaseModelViewSetMixin,
                      SoftDeletedModelViewSetMixin,
                      ActionableModelViewSetMixin,
                      viewsets.ModelViewSet):
    """
        Firmware view set.

        Binarys must be sent as base64 encoded values with sentinel values:
        ```
            'filename:<filename>;base64,<b64-encoded-contents>'
        ```

        **Required to be an `admin` on Noa.**
    """
    serializer_class = FirmwareSerializer
    filterset_class = FirmwareFilter
    model = Firmware

    @action(detail=True, methods=['post'], suffix='Actions',
            permission_classes=(IsAuthenticated,))
    def actions(self, *args, **kwargs):
        """
        Available actions are:

        - `provision`
          Provision the firmware with lock and chip.
          Only admins of lock8 can call this action.
        """
        return self._actions(*args, **kwargs)


class SupportTicketViewSet(BaseModelViewSetMixin,
                           SoftDeletedModelViewSetMixin,
                           ActionableModelViewSetMixin,
                           viewsets.ModelViewSet):
    """
    A `SupportTicket` is a user request for support.

    `SupportTicket` has a category field that can be one of the following:

    - ``location_needs_bicycles``
    - ``bicycle_missing``
    - ``bicycle_damaged``
    """
    serializer_class = SupportTicketSerializer
    filterset_class = SupportTicketFilter
    model = SupportTicket

    def get_internal_queryset(self):
        user = self.request.user
        return self.model.objects.filter(
            Q(owner=user) |
            Q(organization__in=user.get_descendants_managed_organizations())
        )


class FeedbackCategoryViewSet(BaseModelViewSetMixin,
                              SoftDeletedModelViewSetMixin,
                              viewsets.ReadOnlyModelViewSet):
    serializer_class = FeedbackCategorySerializer
    filterset_class = FeedbackCategoryFilter
    model = FeedbackCategory


class FeedbackViewSet(BaseModelViewSetMixin,
                      SoftDeletedModelViewSetMixin,
                      ActionableModelViewSetMixin,
                      viewsets.ModelViewSet):
    """
    A `Feedback` represent a possible actionable reported to the system by a
    user.

    A `Feedback` has a causality field. It can be one of the following:

      - `Bicycle`
      - `Lock`
    """  # noqa
    serializer_class = FeedbackSerializer
    filterset_class = FeedbackFilter
    model = Feedback

    def get_serializer_class(self):
        if self.action == 'actions':
            return FeedbackActionableSerializer
        return super().get_serializer_class()

    def get_internal_queryset(self):
        user = self.request.user
        return self.model.objects.filter(
            Q(user=user) |
            Q(organization__in=user.get_descendants_managed_organizations())
        ).annotate_with_causative_bicycle_uuid()

    @action(detail=True, methods=['post'], suffix='Actions',
            permission_classes=(IsAuthenticated,))
    def actions(self, *args, **kwargs):
        """
        Available actions are:

        - `escalate`
            Escalate a Feedback - Task has been created based on it.
            - **severity**
            - **role**
        - `discard`
            Discard a Feedback - Feedback requires no further action.
        """
        return self._actions(*args, **kwargs)


class AlertViewSet(BaseModelViewSetMixin,
                   SoftDeletedModelViewSetMixin,
                   ActionableModelViewSetMixin,
                   viewsets.ModelViewSet):
    serializer_class = AlertSerializer
    filterset_class = AlertFilter
    model = Alert

    def get_internal_queryset(self):
        return (self.model.get_queryset(request=self.request)
                .annotate_with_causative_bicycle_uuid())

    def get_serializer_class(self):
        if self.action == 'actions':
            return AlertActionableSerializer
        if self.action == 'create':
            return AlertCreateSerializer
        return super().get_serializer_class()

    @action(detail=True, methods=['post'], suffix='Actions',
            permission_classes=(IsAuthenticated,))
    def actions(self, *args, **kwargs):
        """
        Available actions are:

        - `resolve`
            Resolve a Alert, means it won't be considered as an active
            Alert.
        - `escalate`
            Escalate a Alert, resolve the alert and create a follow up task.
            - **severity**
            - **decription**
        - `silence`
            Silencing an Alert will not create a new one
            (even if its conditions are met), until the alert is stopped
            automatically by the system.
        """
        return self._actions(*args, **kwargs)


class NotificationMessageViewSet(BaseModelViewSetMixin,
                                 SoftDeletedModelViewSetMixin,
                                 ActionableModelViewSetMixin,
                                 viewsets.ModelViewSet):
    serializer_class = NotificationMessageSerializer
    model = NotificationMessage
    filterset_class = NotificationMessageFilter

    def get_internal_queryset(self):
        return self.request.user.notification_messages.all()

    @action(detail=True, methods=['post'], suffix='Actions',
            permission_classes=(IsAuthenticated,))
    def actions(self, *args, **kwargs):
        """
        Available actions are:

        - `send`
            Send the notification, or resend it as a reminder.
        - `acknowledge`
            Acknowledge the NotificationMessage.
        """
        return self._actions(*args, **kwargs)


class AlertMessageViewSet(BaseModelViewSetMixin,
                          SoftDeletedModelViewSetMixin,
                          ActionableModelViewSetMixin,
                          viewsets.ModelViewSet):
    serializer_class = AlertMessageSerializer
    model = AlertMessage
    filterset_class = AlertMessageFilter

    def get_internal_queryset(self):
        return self.request.user.alert_messages.all()

    @action(detail=True, methods=['post'], suffix='Actions',
            permission_classes=(IsAuthenticated,))
    def actions(self, *args, **kwargs):
        """
        Available actions are:

        - `send`
            Send the alert, or resend it as a reminder.
        - `acknowledge`
            Acknowledge the AlertMessage.
        """
        return self._actions(*args, **kwargs)


class OrganizationViewSet(BaseModelViewSetMixin,
                          SoftDeletedModelViewSetMixin,
                          ActionableModelViewSetMixin,
                          viewsets.ReadOnlyModelViewSet):
    serializer_class = OrganizationSerializer
    model = Organization
    permission_classes = (AnonDjangoObjectPermissions,)

    def get_serializer_class(self):
        if self.action == 'preference':
            return NestedOrganizationPreferenceSerializer
        return OrganizationSerializer

    @action(detail=True, methods=['get', 'put', 'patch'], suffix='Preferences')
    def preference(self, request, *args, **kwargs):
        """
        The active Organization Preference.
        """
        organization = self.get_object()
        preference = organization.active_preference
        serializer_class = self.get_serializer_class()
        if request.method in ('PUT', 'PATCH'):
            try:
                organization.preference
            except OrganizationPreference.DoesNotExist:
                # Copy on Write
                preference.pk = None
                preference.uuid = uuid.uuid4()
                preference.organization = organization
                preference.owner = request.user
            partial = kwargs.pop('partial',
                                 True if request.method == 'PATCH' else False)
            serializer = serializer_class(
                preference, data=request.data, partial=partial,
                context={'request': request})
            serializer.is_valid(raise_exception=True)
            serializer.save()
            if getattr(preference, '_prefetched_objects_cache', None):
                # If 'prefetch_related' has been applied to a queryset, we need
                # to forcibly invalidate the prefetch cache on the instance.
                preference._prefetched_objects_cache = {}
            return Response(serializer.data)
        else:
            # pretend the preference is not acquired
            preference.organization = organization
            serializer = serializer_class(
                preference, context={'request': request})
            return Response(serializer.data)


class PhotoViewSet(BaseModelViewSetMixin,
                   SoftDeletedModelViewSetMixin,
                   ActionableModelViewSetMixin,
                   viewsets.ModelViewSet):
    serializer_class = PhotoSerializer
    model = Photo
    filterset_class = PhotoFilter

    def get_serializer_class(self):
        if self.request.method == 'POST':
            return PhotoSerializerForPost
        return self.serializer_class

    def list(self, *args, **kwargs):
        """
        Returns a list of Photos that has been uploaded to the Organization.

        **Required to be a member of this Organization
        if Organization is a closed fleet rental system.
        Otherwise access is public**
        """
        return super().list(*args, **kwargs)

    def create(self, *args, **kwargs):
        """
        Upload a given Photo to the Organization.

        Images must be sent as base64 encoded values.

        **Required to be `fleet operator` or `admin` of the same Organization
        or parent's Organization.**
        """
        return super().create(*args, **kwargs)

    def update(self, *args, **kwargs):
        """
        Replaces a given Photo that has been previously uploaded
        to the Organization.

        Images must be sent as base64 encoded values.

        **Required to be `fleet operator` or `admin` of the same Organization
        or parent's Organization.**
        """
        return super().update(*args, **kwargs)

    def destroy(self, *args, **kwargs):
        """
        Deletes a given Photo that has been previously uploaded
        to the Organization.

        **Required to be `fleet operator` or `admin` of the same Organization
        or parent's Organization.**
        """
        return super().destroy(*args, **kwargs)

    def retrieve(self, *args, **kwargs):
        """
        Returns a Photo that has been uploaded to the Organization.

        **Required to be a member of this Organization
        if Organization is a closed fleet rental system.
        Otherwise access is public**
        """
        return super().retrieve(*args, **kwargs)


class PricingSchemeViewSet(BaseModelViewSetMixin,
                           SoftDeletedModelViewSetMixin,
                           ActionableModelViewSetMixin,
                           viewsets.ModelViewSet):
    serializer_class = PricingSchemeSerializer
    model = PricingScheme
    filterset_class = PricingSchemeFilter

    @action(detail=True, methods=['get'], suffix='Compute amount')
    def compute_amount(self, request, uuid=None):
        """
        Get the amount that will be charged for a given duration in cents.

        ---

        parameters:
            - name: duration
              description: duration of the rental_session in seconds.
              required: true
              type: integer
              paramType: query
        """
        pricing_scheme = self.get_object()
        try:
            duration = request.query_params['duration']
        except KeyError:
            raise exceptions.ValidationError(
                detail='The `duration` query parameter is required.')
        cents = pricing_scheme.compute_amount_for_duration(
            dt.timedelta(seconds=float(duration)))
        currency = pricing_scheme.organization.currency
        tax_percent = pricing_scheme.organization.get_preference('tax_percent')
        return Response({'cents': cents,
                         'currency': currency,
                         'tax_percent': tax_percent})


class FilterByUserModelViewSetMixin():
    def get_internal_queryset(self):
        user = self.request.user
        assert user.is_authenticated

        per_user = Q(user=user)
        per_admin = Q(bicycle__organization__in=user
                      .get_descendants_managed_organizations())
        predicate = (per_user | per_admin)
        return self.model.objects.filter(predicate).distinct()


class RentalSessionViewSet(FilterByUserModelViewSetMixin,
                           BaseModelViewSetMixin,
                           SoftDeletedModelViewSetMixin,
                           viewsets.ReadOnlyModelViewSet):
    """RentalSessions track history of all rentals for a given bicycle."""
    serializer_class = RentalSessionSerializer
    model = RentalSession
    filterset_class = RentalSessionFilter


class RentingSchemeViewSet(BaseModelViewSetMixin,
                           SoftDeletedModelViewSetMixin,
                           viewsets.ModelViewSet):
    """
    RentingSchemes are resources that contain information
    to drive business decisions related to reservation and renting.
    RentingSchemes are attached to an organization, but can also be attached to
    one or several Bicycles. The ones that are attached to Bicycles take
    precedence.

    **Note:** RentingSchemes attached to a Bicycle are not considered anymore
    as being available in the scope of the entire Organization.

    - `max_reservation_duration`: Specify the maximum amount of time a user can
    reserve a Bicycle. If the duration specified by the user exceeds this
    limit, the `reserve` action will fail.
    """
    serializer_class = RentingSchemeSerializer
    model = RentingScheme


class ReservationViewSet(FilterByUserModelViewSetMixin,
                         BaseModelViewSetMixin,
                         SoftDeletedModelViewSetMixin,
                         viewsets.ReadOnlyModelViewSet):
    """Reservations track history of all rentals for a given bicycle."""
    serializer_class = ReservationSerializer
    model = Reservation
    filterset_class = ReservationFilter

    def get_internal_queryset(self):
        user = self.request.user
        return self.model.objects.filter(
            bicycle__organization__in=user
            .get_descendants_organizations(),
        ).distinct()


class TaskViewSet(BaseModelViewSetMixin,
                  ActionableModelViewSetMixin,
                  viewsets.ModelViewSet):
    """
    A `Task` represents actions to be taken and are delegated to users
    of the system either automatically, or manually.

    A `Task` has a causality field. It can be one of the following:

      - `Bicycle`
      - `Alert`
      - `Feedback`

    Tasks may also be the result of a `BicycleModelMaintenanceRule`. In this
    case, the `Task` will expose a `maintenance_rule` field and causality will
    be of type `Bicycle`.
    """  # noqa
    serializer_class = TaskSerializer
    model = Task
    filterset_class = TaskFilter

    def destroy(self, request, *args, **kwargs):
        msg = _('Tasks make historical data. Use `cancel` intead.')
        raise serializers.ValidationError(msg)

    def get_internal_queryset(self):
        user = self.request.user
        predicate = Q(organization__in=user.get_descendants_organizations())
        return (self.model.objects
                .filter(predicate)
                .annotate_with_causative_bicycle_uuid())

    def get_serializer_class(self):
        if self.action == 'actions':
            return TaskActionableSerializer
        return super().get_serializer_class()

    @action(detail=True, methods=['post'], suffix='Actions',
            permission_classes=(IsAuthenticated,))
    def actions(self, *args, **kwargs):
        """
        Available actions are:

        - `assign`
            Assign the task to someone else.
            - **assignee** new recipient for that task.
        - `unassign`
           Unassign the task.
        - `complete`
            Complete the task.
        """
        return self._actions(*args, **kwargs)


class SubscriptionPlanViewSet(BaseModelViewSetMixin,
                              SoftDeletedModelViewSetMixin,
                              ActionableModelViewSetMixin,
                              viewsets.ModelViewSet):
    serializer_class = SubscriptionPlanSerializer
    model = SubscriptionPlan
    filterset_class = SubscriptionPlanFilter

    def get_serializer_class(self):
        if self.action == 'subscribe_user':
            return SubscribeUserToSubscriptionPlanInputSerializer
        elif self.action == 'unsubscribe_user':
            return UnsubscribeUserFromSubscriptionPlanInputSerializer
        return super().get_serializer_class()

    @action(detail=True, methods=['POST'], suffix='Subscribe User')
    def subscribe_user(self, request, uuid=None):
        """
        Check authenticity of `stripe_source` (if given, defaults to customers
        default source), and then create the subscription.

        [Stripe Documentation](https://stripe.com/docs/tutorials/subscriptions#subscribing-a-customer-to-a-plan)
        """  # noqa

        serializer = SubscribeUserToSubscriptionPlanInputSerializer(
            data=request.data)
        serializer.is_valid(raise_exception=True)
        subscription_plan = self.get_object()
        stripe_source = serializer.validated_data.get('stripe_source')
        coupon = serializer.validated_data.get('coupon')
        auto_renewal = serializer.validated_data.get('auto_renewal')

        try:
            subscription = subscription_plan.subscribe_user(
                request.user, stripe_source, None, coupon, auto_renewal)
        except stripe.error.InvalidRequestError as exc:
            if exc.args[0].startswith('No such token: '):
                raise exceptions.ValidationError({
                    'stripe_source': 'No such token.'},
                    code='invalid_source') from exc
            if exc.param == 'coupon':
                raise exceptions.ValidationError({
                    'coupon': [exc.json_body['error']['message']]},
                    code='invalid_coupon') from exc
            raise exc
        except stripe.error.CardError as exc:
            if exc.code == 'card_declined':
                json_error = exc.json_body['error']
                decline_code = json_error['decline_code']
                if decline_code == 'insufficient_funds':
                    raise exceptions.ValidationError({
                        'stripe_source': 'The card has insufficient funds.'},
                        code='user_card_insufficient_funds') from exc
                raise exceptions.ValidationError({
                    'stripe_source': json_error['message']},
                     code='user_card_declined') from exc
            msg = '%s (code=%s)' % (exc.args[0], exc.code)
            raise exceptions.ValidationError({
                'stripe_source': f'There was a card-related error: {msg}'},
                 code='user_card_error') from exc
        except SubscriptionExistsError as exc:
            conflict_exc = exceptions.APIException(
                detail='There is a subscription already.',
                code='subscription_exists')
            conflict_exc.status_code = status.HTTP_409_CONFLICT
            raise conflict_exc from exc

        serializer = UserSubscriptionSerializer(
            subscription, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)

    @action(detail=True, methods=['POST'], suffix='Unsubscribe User')
    def unsubscribe_user(self, request, uuid=None):
        """
        Cancel Subscription of user.
        """
        subscription_plan = self.get_object()
        user = request.user
        serializer = UnsubscribeUserFromSubscriptionPlanInputSerializer(
            data=request.data)
        serializer.is_valid(raise_exception=True)
        at_period_end = serializer.validated_data.get('at_period_end', False)

        try:
            subscription = subscription_plan.unsubscribe_user(
                user, at_period_end)
        except ObjectDoesNotExist:
            raise Http404

        serializer = UserSubscriptionSerializer(
            subscription, context={'request': request})
        return Response(serializer.data, status=status.HTTP_200_OK)


class PlanPassViewSet(BaseModelViewSetMixin,
                      SoftDeletedModelViewSetMixin,
                      viewsets.ModelViewSet):
    """
    Allow a User to access restricted SubscriptionPlans.
    """
    serializer_class = PlanPassSerializer
    model = PlanPass
    filterset_class = PlanPassFilter

    def get_internal_queryset(self):
        user = self.request.user
        return self.model.objects.filter(
            subscription_plan__organization__in=user.
            get_descendants_managed_organizations())

    def destroy(self, *args, **kwargs):
        """
        Delete the Plan Pass.
        It can be use to remove access of the user from the SubscriptionPlan.
        """
        return super().destroy(*args, **kwargs)


class TripViewSet(BaseModelViewSetMixin, viewsets.ReadOnlyModelViewSet):
    """
    Trips.
    """
    model = Trip
    filterset_class = lock8_filters.TripFilter

    def get_serializer_class(self):
        return (lock8_serializers.BaseTripSerializer
                .get_serializer_class_for_user(self.request.user))

    def filter_queryset(self, qs):
        qs = super().filter_queryset(qs)
        if (not self.request.user.is_admin_of_lock8 or
                'include_invalid' not in self.request.query_params):
            qs = qs.filter(Q(is_valid=True) | Q(is_valid__isnull=True))
        if not self.request.user.is_admin_of_lock8:
            qs = qs.filter(asset_state__in=[Trip.ASSET_IN_MAINTENANCE,
                                            Trip.ASSET_IN_SERVICE])
        return qs


class UserViewSet(BaseModelViewSetMixin,
                  ActionableModelViewSetMixin,
                  viewsets.ModelViewSet):
    serializer_class = UserSerializer
    model = User
    filterset_class = UserFilter

    def get_serializer_class(self):
        if (
            self.request.method == 'GET' and (
                self.request.query_params.get('organization')
                or self.request.query_params.get('organizations')
            )
        ):
            return UserOfOrganizationSerializer

        return super().get_serializer_class()

    @action(detail=True, methods=['post'], suffix='Actions',
            permission_classes=(IsAuthenticated,))
    def actions(self, *args, **kwargs):
        """
        Available actions are:

        - `disable`
            Prevent User from being able to rent Bicycles.
        - `enable`
            Restore permissions of User.
        """
        return self._actions(*args, **kwargs)

    def list(self, *args, **kwargs):
        """
        Returns the requesting user's details and all users that the user
        can manage as an operator or administrator of an Organization.
        If the requesting user has no operator or administrator
        Affiliation roles, only their details are returned in the response.

        Filtering options are:

        - `organization`: `uuid` of Organization
        - `email`: email address of User (case insensitive)
        - `role`: any roles defined on the Affiliation
        """
        return super().list(*args, **kwargs)

    @action(detail=True, methods=['post'], suffix='Change password')
    def change_password(self, request, uuid=None):
        """
        Allow user to change their password.
        ---
        serializer: velodrome.lock8.serializers.PasswordChangeSerializer
        """
        serializer = PasswordChangeSerializer(data=request.data,
                                              context={'request': request,
                                                       'view': self})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(status=status.HTTP_204_NO_CONTENT)

    @action(detail=True, methods=['post'], suffix='Reset refresh tokens')
    def reset_refresh_tokens(self, request, uuid=None):
        """
        Allow any user to reset all its refresh_tokens.

        By doing so, a user will have to re-authenticate on every
        client application that is storing their refresh_tokens.

        This is useful when mobile devices get lost.
        ---
        serializer: rest_framework.serializers.Serializer
        """
        for rt in request.user.refresh_tokens.all():
            rt.revoke()
        return Response(status=status.HTTP_204_NO_CONTENT)

    def perform_destroy(self, obj):
        obj.is_active = False
        obj.save()

    @action(detail=True, methods=['get'], suffix='EphemeralKey')
    def ephemeralkey(self, request, uuid=None):
        """Get a Stripe EphemeralKey for the user.

        Query arguments:

         - ``stripe_api_version``:
           the Stripe API version to use, e.g. "2017-08-15" (**required**).
         - ``organization``:
           UUID of the organization of the bicycle the user trying to rent.
        """
        user = self.get_object()
        if not(request.user == user or request.user.is_superuser):
            raise exceptions.PermissionDenied()

        input = UserEphemeralkeyInputSerializer(data=request.query_params)
        input.is_valid(raise_exception=True)
        organization_uuid = input.validated_data['organization']
        organization = Organization.get_queryset(request).get(
                uuid=organization_uuid)

        key = user.get_stripe_ephemeralkey(
            stripe_api_version=input.validated_data['stripe_api_version'],
            organization=organization)
        return Response(key)

    @action(detail=True, methods=['get'], suffix='Subscriptions')
    def subscriptions(self, request, uuid=None):
        """List Stripe Subscriptions for the user."""
        user = self.get_object()
        if not(request.user == user or request.user.is_superuser):
            raise exceptions.PermissionDenied()

        input = UserSubscriptionsInputSerializer(data=request.query_params)
        input.is_valid(raise_exception=True)
        organization_uuid = input.validated_data['organization']
        organization = Organization.get_queryset(request).get(
                uuid=organization_uuid)

        queryset = (
            Subscription.objects.filter(
                customer__user_account__user=user,
                customer__user_account__account=organization.stripe_account,
                status__in=Subscription.STATUS_CURRENT)
            .select_related(
                'plan__subscriptionplan',
                'plan__subscriptionplan__pricing_scheme',
                'plan__subscriptionplan__organization',
                'discount')
            .order_by(F('current_period_end').desc()))
        page = self.paginate_queryset(queryset)
        serializer = UserSubscriptionSerializer(page, many=True,
                                                context={'request': request})
        return self.paginator.get_paginated_response(serializer.data)


class UserProfileViewSet(BaseModelViewSetMixin,
                         SoftDeletedModelViewSetMixin,
                         ActionableModelViewSetMixin,
                         viewsets.ModelViewSet):
    serializer_class = UserProfileSerializer
    model = UserProfile

    def perform_create(self, serializer):
        serializer.save()
        user_uuid = self.request.parser_context['kwargs']['parent_lookup_uuid']
        user = User.objects.get(uuid=user_uuid)
        user.profile = serializer.instance
        user.save()


class CurrentUserView(BaseViewMixin, RetrieveAPIView):
    serializer_class = CurrentUserSerializer
    permission_classes = (IsAuthenticated,)

    def get_queryset(self):
        serializer = self.get_serializer()
        qs = User.get_queryset(request=self.request)
        if hasattr(serializer, 'optimize_queryset'):
            qs = serializer.optimize_queryset(qs)
        return qs

    def get_object(self):
        qs = self.get_queryset()
        user = get_object_or_404(qs, pk=self.request.user.pk)
        self.check_object_permissions(self.request, user)
        return user


@api_view(http_method_names=['POST'])
@permission_classes((IsAuthenticated,))
def accept_terms_of_service(request):
    serializer = AcceptTermsOfServiceInputSerializer(
        data=request.data, context={'request': request})
    serializer.is_valid(raise_exception=True)
    try:
        terms_of_service = TermsOfService.get_queryset(request).get(
            uuid=serializer.validated_data['terms_of_service'].uuid)
    except ObjectDoesNotExist:
        raise Http404
    request.user.accept_terms_of_service(terms_of_service)
    return Response(status=status.HTTP_204_NO_CONTENT)


class ZoneViewSet(BaseModelViewSetMixin,
                  ActionableModelViewSetMixin,
                  viewsets.ModelViewSet):
    """
    A Zone linked to an Organization.

    The polygon field is a json value
    that follows this structure:

        {"coordinates": [... Array of polygons
                         [... Array of ring points
                          [... Array of location coordinates
                           [... Coordinates]]]],
         "type": "MultiPolygon"}

    **Note:** The first and last coordinates must be the same
    to close the Polygon.
    """
    serializer_class = ZoneSerializer
    model = Zone
    filterset_class = ZoneFilter

    def get_internal_queryset(self):
        qs = super().get_internal_queryset()
        try:
            _ = self.request.query_params['include_bicycle_count']
            tracking_source = (
                BicycleBaseSerializer.get_serializer_class_for_user(
                    self.request.user
                ).TRACKING_SOURCE
            )
            if tracking_source == 'public_tracking':
                table_name = PublicTracking._meta.db_table
            else:
                table_name = PrivateTracking._meta.db_table
            qs = qs.annotate_with_bicycle_count(table_name)
        except KeyError:
            pass
        return qs


class ParentMetricsViewSet(viewsets.ViewSet):
    lookup_field = 'name'


class MetricsViewSet(viewsets.GenericViewSet):
    filter_backends = (MetricsFilterBackend,)
    pagination_class = None
    permission_classes = (functools.partial(
        CustomPermissions,
        ('lock8.view_metrics',)),)
    renderer_classes = (api_settings.DEFAULT_RENDERER_CLASSES + [
        CSVStreamingRenderer, TSVStreamingRenderer])
    serializer_class = MetricsSerializer
    queryset = MetricsQuerysetLike()

    def list(self, request, metric_name=None):
        """
        Retrieves results for given metric
        """
        data = self.filter_queryset(self.get_queryset()).values(request)
        if issubclass(request.accepted_renderer.__class__, CSVRenderer):
            data = data['values']

        return Response(data)


class ParentPredictionsViewSet(viewsets.ViewSet):
    lookup_field = 'name'


class PredictionsViewSet(viewsets.GenericViewSet):
    filter_backends = (PredictionsFilterBackend,)
    pagination_class = None
    permission_classes = (functools.partial(
        CustomPermissions,
        ('lock8.view_predictions',)),)
    renderer_classes = (api_settings.DEFAULT_RENDERER_CLASSES + [
        CSVStreamingRenderer, TSVStreamingRenderer])
    serializer_class = PredictionsSerializer
    queryset = PredictionsQuerysetLike()

    def list(self, request, prediction_name=None):
        """
        Retrieves results for given prediction
        """
        data = self.filter_queryset(self.get_queryset()).values(request)
        if issubclass(request.accepted_renderer.__class__, CSVRenderer):
            data = [{**prediction,
                     'zone': item['zone'],
                     'zone_name': item['zone_name']}
                    for item in data['values']
                    for prediction in item['predictions']]

        return Response(data)


@api_view(http_method_names=['GET'])
@permission_classes(
    (functools.partial(CustomPermissions, ('lock8.view_dashboard',)),),
)
@schema(None)
def dashboard(request):
    """
    Return raw data to display the dashboard on fms.

    Example of response:

        {
        "count_bicycles_by_state": [
            {
                "state": "available",
                "total": 2
            }
            {
                "state": "reserved",
                "total": 1
            },
        ],
        TODO: WIP…
        }

    ### Parameters ###

    XXX

    **Requires `admin` or `fleet_operator` role privileges**.

    type:
        count_bicycles_by_state:
            required: true
            type: list
    parameters:
        - name: organization
          required: false
          type: uuid
          label: uuid of Organization, defaults to current user's.
    """
    user = request.user
    organizations = user.get_descendants_managed_organizations()
    try:
        org_uuid = request.query_params['organization']
    except KeyError:
        pass
    else:
        organizations = organizations.filter(uuid=org_uuid)

    if not organizations.exists():
        raise exceptions.PermissionDenied

    predicate = Q(organization__in=organizations)

    data = {
        'count_alerts_by_type': list(Alert.objects.count_by_type(predicate)),
        'count_bicycles_by_state': list(
            Bicycle.objects.count_by_state(predicate)),
    }
    return Response(data)


class EmailRegistrationView(DjoserRegistrationView):
    serializer_class = EmailRegistrationSerializer

    def create(self, request, *args, **kwargs):
        try:
            super().create(request, *args, **kwargs)
        except SkipValidationError:
            pass
        return Response(status=status.HTTP_204_NO_CONTENT)

    def perform_create(self, serializer):
        user = serializer.save()
        logger.debug('Created user %r (active=%r)', user, user.is_active)
        if not user.is_active:
            transaction.on_commit(functools.partial(
                send_activation_email_task.delay,
                user.pk))
        return Response(status=status.HTTP_204_NO_CONTENT)


class PasswordForgotView(DjoserPasswordResetView):
    serializer_class = PasswordForgotSerializer

    def _action(self, serializer):
        serializer.is_valid(raise_exception=True)

        user = serializer.user
        if user:
            if user.is_active:
                send_password_reset_email_task.delay(user.pk)
        return Response(status=status.HTTP_204_NO_CONTENT)


class PasswordResetView(DjoserPasswordResetConfirmView):
    def get_serializer_class(self):
        return PasswordResetSerializer

    def _action(self, serializer):
        user = serializer.user
        user.set_password(serializer.data['new_password'])
        user.save()
        for rt in user.refresh_tokens.all():
            rt.revoke()
        return Response(status=status.HTTP_204_NO_CONTENT)


class ActivateView(BaseViewMixin, GenericAPIView):
    permission_classes = (AllowAny,)

    def get_serializer_class(self):
        return AccountActivationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.user
        user.is_active = True
        user.save()
        user.publish_activated_event()
        create_affiliations_if_whitelisted(user)

        token = generate_auto_login_code()

        auth_code_cache = caches['auth_codes']
        ttl = settings.AUTO_LOGIN_CODE_EXPIRY.total_seconds()
        auth_code_cache.set(token, str(serializer.user.uuid), ttl)

        return Response({'code': token}, status=status.HTTP_200_OK)


class ActivateGETwithPOSTView(ActivateView):
    schema = None

    def post(self, request, *args, **kwargs):
        request.data.update({'token': kwargs.pop('token'),
                             'uuid': kwargs.pop('uuid')})
        return super().post(request, *args, **kwargs)

    @never_cache
    def get(self, request, *args, **kwargs):
        try:
            response = self.post(request, *args, **kwargs)
        except exceptions.ValidationError as exc:
            params = urlencode({'errors': json.dumps(exc.get_full_details())})
            return redirect('{}?{}'.format(settings.FRONTEND_ACTIVATE_URL,
                                           params))
        else:
            params = urlencode({'code': response.data['code']})
            return redirect('{}?{}'.format(settings.FRONTEND_ACTIVATE_URL,
                                           params))


email_registration = EmailRegistrationView.as_view()
email_activation = ActivateView.as_view()
email_GET_with_POST_activation = ActivateGETwithPOSTView.as_view()
password_forgot = PasswordForgotView.as_view()
password_reset = PasswordResetView.as_view()


@swagger_auto_schema(method='get', query_serializer=ClusterInputSerializer)
@api_view(http_method_names=['GET'])
@permission_classes((functools.partial(
    AnonCustomPermissions, ('lock8.view_bicycle',)),)
)
def get_clusters(request):
    """
    Return list of clusters.
    """
    input = ClusterInputSerializer(data=request.GET)
    input.is_valid(raise_exception=True)
    bbox = input.validated_data['bbox']
    include_state = input.validated_data['include_state']
    include_model = input.validated_data['include_model']
    if include_state and include_model:
        raise exceptions.ValidationError(
            detail={'include_state': ['is exclusive from include_model'],
                    'include_model': ['is exclusive from include_state']})

    envelope = Polygon.from_bbox((float(n) for n in bbox.split(','))).envelope
    distance = get_cluster_distance_from_bbox(envelope)

    if not distance > 0:
        raise exceptions.ValidationError(
            detail={'bbox': ['Bounding box too small']})

    serializer_class = BicycleBaseSerializer.get_serializer_class_for_user(
        request.user)

    bicycle_view = BicycleViewSet(request=request)
    bicycle_qs = bicycle_view.filter_queryset(
        Bicycle.get_queryset(request=request))

    qs = Bicycle.objects.filter(pk__in=bicycle_qs)

    if include_state:
        get_clusters_fn = group_to_state_clusters
        cluster_within_class = ClusterWithinAggregate

        # Determines the GROUP BY
        qs = qs.values('state')
    elif include_model:
        get_clusters_fn = group_to_model_clusters
        cluster_within_class = ClusterWithinAggregate

        # Determines the GROUP BY
        qs = qs.values('model__name')
    else:
        get_clusters_fn = extend_clusters
        cluster_within_class = ClusterWithin

    tracking_lookup = '{}__point'.format(serializer_class.TRACKING_SOURCE)
    clusters = (qs
                .annotate(cluster=cluster_within_class(tracking_lookup,
                                                       distance=distance))
                .annotate(bounding_circle=BoundingCircle('cluster')))

    select_values = ['cluster', 'bounding_circle']
    if include_state:
        select_values.append('state')
        bbox_edge = Point(envelope.coords[0][0], srid=4326)
        clusters = clusters.annotate(distance=Distance('cluster', bbox_edge))
        order_by = ['distance']
    elif include_model:
        select_values.append('model__name')
        bbox_edge = Point(envelope.coords[0][0], srid=4326)
        clusters = clusters.annotate(distance=Distance('cluster', bbox_edge))
        order_by = ['distance']
    else:
        order_by = []

    ordered_clusters = clusters.values(*select_values).order_by(*order_by)
    clusters = get_clusters_fn(ordered_clusters, distance)

    if include_state or include_model:
        total = sum(sum(x['density'].values()) for x in clusters)
    else:
        total = sum(x['density'] for x in clusters)

    return Response({'density_total': total,
                     'clusters': clusters})


@api_view(http_method_names=['GET'])
@schema(None)
@permission_classes(
    (functools.partial(CustomPermissions, ('lock8.view_debug',)),),
)
def debug_sleep(request):
    seconds = float(request.query_params.get('seconds', 0.0))
    time.sleep(seconds)
    return Response('Slept for {} seconds.'.format(seconds))


@api_view(http_method_names=['GET'])
@schema(None)
@permission_classes(
    (functools.partial(CustomPermissions, ('lock8.view_debug',)),),
)
def debug_logplz(request):
    logger.error('debug_logplz: test logging error')
    debug_log_error('via debug_logplz')
    debug_celery_log.delay()
    return Response('Logged testing errors.')


@api_view(http_method_names=['GET'])
@schema(None)
@permission_classes(
    (functools.partial(CustomPermissions, ('lock8.view_debug',)),),
)
def debug_500plz(request):
    1 / 0


schema_view = get_schema_view(
    openapi.Info(
        title='Velodrome API',
        default_version='1.0',
        description='Velodrome API',
        terms_of_service='https://www.noa.one',
        contact=openapi.Contact(email='support@noa.one'),
    ),
    validators=['ssv'],
    public=True,
    permission_classes=(AllowAny,),
)
