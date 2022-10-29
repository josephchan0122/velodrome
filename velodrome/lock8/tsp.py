import json
import logging
from pathlib import Path

from django.contrib.gis.geos.collections import Point
from django.db.models.expressions import F
from django.shortcuts import get_object_or_404
from django.urls import include, path
import jsonschema
from rest_framework import (
    exceptions, mixins, parsers, permissions, serializers, status, viewsets,
)
from rest_framework.response import Response
from rest_framework.routers import DefaultRouter

from velodrome.lock8.models import Bicycle, RentalSession
from velodrome.lock8.permissions import (
    IsAuthenticated, check_scopes_are_allowed,
)
from velodrome.lock8.serializers import OtpSerializer
from velodrome.lock8.utils import get_next_ekey_slot

logger = logging.getLogger(__name__)

AGENCY_ID = 'noa'


class TSPMixin():
    @classmethod
    def format_leg_dict(cls, data, bicycle):
        return {
            'agencyId': AGENCY_ID,
            'mode': data['mode'],
            'startTime': data['startTime'],
            'endTime': data.get('endTime', data['startTime']),
            'from': {
                'lat': bicycle.latitude,
                'lon': bicycle.longitude,
            },
            'to': {
                'lat': bicycle.latitude,
                'lon': bicycle.longitude,
            },
        }

    @classmethod
    def format_meta_dict(cls, bicycle, **kwargs):
        data = {
            'MODE_BICYCLE': {},
            AGENCY_ID: {
                'bicycle_uuid': str(bicycle.uuid),
            }
        }

        try:
            data[AGENCY_ID]['bicycle_distance'] = {
                'length': bicycle.raw_distance.m,
                'unit': 'm',
            }
        except AttributeError:
            pass

        for key in kwargs:
            data[AGENCY_ID][key] = kwargs[key]

        return data

    @classmethod
    def format_terms_dict(cls):
        # TODO: Figure out what to return here
        return {'price': {'amount': 0, 'currency': 'EUR'}}


class Option(TSPMixin):
    """Wrapper class for booking options business logic."""
    @classmethod
    def find(cls, query_data, request):
        """Return a list of Options available filtered by the query_data."""
        if query_data.get('mode') != 'BICYCLE':
            return {'options': []}

        point = Point([query_data['from']['lon'], query_data['from']['lat']],
                      srid=4326)
        # FIXME: Limit this query with a radius
        qs = Bicycle.get_queryset(request).annotate_with_distance(
            point, 'private_tracking__point')
        bicycles = qs.filter(raw_distance__isnull=False).order_by(
            F('raw_distance').asc())[:100]
        return {'options': [cls._to_dict(query_data, bicycle)
                            for bicycle in bicycles]}

    @classmethod
    def _to_dict(cls, query_data, bicycle):
        return {
            'leg': cls.format_leg_dict(query_data, bicycle),
            'meta': cls.format_meta_dict(bicycle),
            'terms': cls.format_terms_dict(),
        }


class Booking(TSPMixin):
    """Wrapper class for booking business logic."""
    @classmethod
    def create(cls, request):
        data = request.data
        meta_serializer = BookingMetaSerializer(data=data.get('meta'))
        meta_serializer.is_valid(raise_exception=True)

        point = Point([data['leg']['from']['lon'], data['leg']['from']['lat']],
                      srid=4326)
        qs = Bicycle.get_queryset(request).annotate_with_distance(
            point, 'private_tracking__point')
        bicycle = get_object_or_404(
            qs, uuid=data['meta'][AGENCY_ID]['bicycle_uuid'])

        if hasattr(bicycle, 'axa_lock') and bicycle.axa_lock is not None:
            ekey, otps, expiration = bicycle.axa_lock.obtain_otps(
                slot=get_next_ekey_slot(bicycle.axa_lock), nr_of_passkeys=10,
                hours=1)
            serializer = OtpSerializer({
                'ekey': ekey, 'otps': otps, 'expiration': expiration})
            otps = serializer.data

        bicycle.rent(by=request.user)
        rental_session = get_object_or_404(
            RentalSession, user=request.user, bicycle=bicycle)

        return {
            'leg': cls.format_leg_dict(data['leg'], bicycle),
            'meta': cls.format_meta_dict(bicycle, axa_lock=otps),
            'terms': cls.format_terms_dict(),
            'token': {},  # TODO
            'customer': data['customer'],
            'tspId': str(rental_session.uuid),
        }

    @classmethod
    def get(cls, uuid):
        rental_session = get_object_or_404(
            RentalSession, uuid=uuid)
        return {
            'state': 'ACTIVATED',  # TODO
            'terms': cls.format_terms_dict(),
            'token': {},  # TODO
            'tspId': str(rental_session.uuid),
            'meta': cls.format_meta_dict(rental_session.bicycle),
        }

    @classmethod
    def cancel(cls, uuid, request):
        rental_session = get_object_or_404(
           RentalSession, uuid=uuid)
        rental_session.bicycle.return_(by=request.user)
        return {'state': 'CANCELLED'}


class TSPResolver(jsonschema.RefResolver):
    tsp_root_url = 'https://api.maas.global/v1/tsp/'
    schemas_root = Path(__file__).parent / Path('maas-tsp-reference/schemas')
    required_schemas = (
        'core/plan.json', 'core/units.json', 'core/customer.json',
        'core/booking.json', 'tsp/booking-option.json', 'tsp/booking.json',
        'tsp/request-customer.json',
    )

    def __init__(self):
        """
        Populate the resolver with mappings from each API call's
        schema references to their equivalent schemas.
        """
        schemas_mapping = {
            key: json.loads(Path(self.schemas_root, key).read_text())
            for key in self.required_schemas}
        self.schemas_store = {
            f'{self.tsp_root_url}core/plan.json':
                schemas_mapping['core/plan.json'],
            f'{self.tsp_root_url}core/units.json':
                schemas_mapping['core/units.json'],
            f'{self.tsp_root_url}booking-options-list/core/plan.json':
                schemas_mapping['core/plan.json'],
            f'{self.tsp_root_url}booking-options-list/core/units.json':
                schemas_mapping['core/units.json'],
            f'{self.tsp_root_url}booking-options-list/tsp/booking-option.json':
                schemas_mapping['tsp/booking-option.json'],
            f'{self.tsp_root_url}booking-option':
                schemas_mapping['tsp/booking-option.json'],
            f'{self.tsp_root_url}booking-create/core/plan.json':
                schemas_mapping['core/plan.json'],
            f'{self.tsp_root_url}booking-create/core/core/units.json':
                schemas_mapping['core/units.json'],
            f'{self.tsp_root_url}booking-create/core/customer.json':
                schemas_mapping['core/customer.json'],
            f'{self.tsp_root_url}booking-create/core/booking.json':
                schemas_mapping['core/booking.json'],
            f'{self.tsp_root_url}booking-read-by-id/tsp/booking.json':
                schemas_mapping['tsp/booking.json'],
            f'{self.tsp_root_url}booking-read-by-id/tsp/core/booking.json':
                schemas_mapping['core/booking.json'],
            f'{self.tsp_root_url}booking-read-by-id/tsp/core/core/units.json':
                schemas_mapping['core/units.json'],
        }
        super().__init__('', None, store=self.schemas_store)


class TSPParser(parsers.JSONParser):
    """Validate the request body using the TSP schemas."""
    resolver = TSPResolver()

    def parse(self, stream, media_type=None, parser_context=None):
        data = super().parse(stream, media_type, parser_context)
        view = parser_context['view']
        view.validate_schema(view.schemas[view.action]['request'], data)
        return data


class TSPSerializer(serializers.Serializer):
    """Validate velodrome's responses using the TSP response schemas."""
    def __init__(self, *args, **kwargs):
        self.view = kwargs['context']['view']
        self.request = self.view.request
        self.response_schema = self.view.schemas[self.view.action]['response']
        self.request_schema = self.view.schemas[self.view.action]['request']
        super().__init__(*args, **kwargs)

    def to_internal_value(self, data):
        """Override default validation."""
        return data

    def validate(self, data):
        self.view.validate_schema(self.request_schema, data)
        return data

    def validate_response(self, data):
        try:
            self.view.validate_schema(self.response_schema, data)
        except exceptions.ParseError as e:
            msg = {'data': data, 'error': e.get_full_details()}
            logger.warning('TSP response validation error: %s', msg)

        return data

    def to_representation(self, data):
        if self.view.action in ('create', 'destroy', 'list'):
            self.validate_response(data)
        elif self.view.action == 'retrieve':
            data = Booking.get(data.uuid)
            self.validate_response(data)
        else:
            raise exceptions.MethodNotAllowed(self.request.method)

        return data

    def create(self, validated_data):
        return Booking.create(self.request)


class AgencyMetaSerializer(serializers.Serializer):
    bicycle_uuid = serializers.UUIDField()
    bicycle_distance = serializers.DictField(required=False)


class BookingMetaSerializer(serializers.Serializer):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields[AGENCY_ID] = self.fields.pop('AGENCY_ID')

    MODE_BICYCLE = serializers.DictField()
    AGENCY_ID = AgencyMetaSerializer()


class ClientAppPermissions(IsAuthenticated):
    def has_permission(self, request, view):
        return (getattr(request.user, 'is_client_app', False) and
                super().has_permission(request, view))


class TSPPermissions(permissions.BasePermission):
    model = Bicycle
    list_perms = {
        'list': f'{model._meta.app_label}.view_{model._meta.model_name}',
        'create': f'{model._meta.app_label}.rent_{model._meta.model_name}',
    }
    detail_perms = {
        'retrieve': f'{model._meta.app_label}.view_{model._meta.model_name}',
        'destroy': f'{model._meta.app_label}.return_{model._meta.model_name}',
    }

    def has_permission(self, request, view):
        if view.action in self.list_perms:
            perm_to_check = self.list_perms[view.action]
            if (check_scopes_are_allowed(request, [perm_to_check]) and
                    request.user.has_perm(perm_to_check)):
                return True

            return False
        elif view.action in self.detail_perms:
            rental_session = view.get_object()
            obj = rental_session.bicycle
            perm_to_check = self.detail_perms[view.action]
            if (check_scopes_are_allowed(request, [perm_to_check]) and
                    request.user.has_perm(perm_to_check, obj)):
                return True

            return False
        else:
            raise exceptions.NotFound


class BaseBookingView(viewsets.GenericViewSet):
    schema = None
    pagination_class = None
    parser_classes = (TSPParser,)
    permission_classes = (ClientAppPermissions, TSPPermissions)
    serializer_class = TSPSerializer
    schemas = {}

    def _get_schema(self, path):
        schema_path = Path(TSPParser.resolver.schemas_root, 'tsp', path)
        return json.loads(schema_path.read_text())

    def validate_schema(self, schema_path, data):
        schema = self._get_schema(schema_path)
        try:
            jsonschema.Draft4Validator(
                schema, resolver=TSPParser.resolver).validate(data)
        except jsonschema.ValidationError as e:
            raise exceptions.ParseError(detail=e.message)

    def get_serializer(self, instance=None, data=None, many=False):
        if data is not None:
            return TSPSerializer(
                instance, data=data, context={'view': self})
        return TSPSerializer(instance, context={'view': self})


class BookingOptionsListViewSet(mixins.ListModelMixin, BaseBookingView):
    schemas = {
        'list': {
            'request': 'booking-options-list/request.json',
            'response': 'booking-options-list/response.json',
        }
    }

    def validate_query_params(self, query_params):
        for field in ('from', 'to'):
            try:
                try:
                    query_params[field] = json.loads(query_params[field])
                except json.decoder.JSONDecodeError as e:
                    raise exceptions.ParseError(detail=e.msg)
            except KeyError:
                continue

        for field in ('startTime', 'endTime'):
            if isinstance(query_params.get(field), str):
                query_params[field] = int(query_params[field])

        self.validate_schema(
            self.schemas[self.action]['request'], query_params)
        return query_params

    def get_queryset(self):
        params = self.validate_query_params(self.request.query_params.dict())
        options = Option.find(params, self.request)
        return options


class BookingViewSet(mixins.CreateModelMixin,
                     mixins.RetrieveModelMixin,
                     mixins.DestroyModelMixin,
                     BaseBookingView):
    schemas = {
        'create': {
            'request': 'booking-create/request.json',
            'response': 'booking-create/response.json',
        },
        'retrieve': {
            'request': 'booking-read-by-id/request.json',
            'response': 'booking-read-by-id/response.json',
        },
        'destroy': {
            'request': 'booking-cancel/request.json',
            'response': 'booking-cancel/response.json',
        }
    }
    lookup_field = 'tspId'

    def get_object(self):
        tspId = self.kwargs.get('tspId')
        self.validate_schema(
            self.schemas[self.action]['request'], {'tspId': tspId})
        return get_object_or_404(RentalSession, uuid=tspId)

    def destroy(self, request, *args, **kwargs):
        # Destroy needed because MixinDestroy returns 204 wihtout any data
        instance = self.get_object()
        data = Booking.cancel(instance.uuid, self.request)
        serializer = self.get_serializer(data)
        return Response(serializer.data, status=status.HTTP_200_OK)


router = DefaultRouter()
router.register(r'bookings/options', BookingOptionsListViewSet,
                basename='booking-options')
router.register(r'bookings',
                BookingViewSet, basename='booking')

urlpatterns = [
    path('', include(router.urls))
]
