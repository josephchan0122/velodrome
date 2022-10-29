import re
from textwrap import dedent
import types
from uuid import UUID

from django import forms
from django.contrib.gis.geos import Point, Polygon
from django.db import models
from django.db.models import F, FilteredRelation, Q
from django.db.models.expressions import RawSQL
import django_filters
from django_filters import rest_framework as filters
from django_filters.rest_framework import DjangoFilterBackend
from rest_framework import exceptions
from rest_framework_gis.filters import GeometryFilter
from rest_framework_gis.filterset import GeoFilterSet

from .forms import BicycleFilterSetForm
from .models import (
    Address, Affiliation, Alert, AlertMessage, AlertMessageStates, AlertStates,
    AxaLock, Bicycle, BicycleModel, BicycleModelMaintenanceRule,
    BicycleModelMaintenanceRuleStates, BicycleStates, Feedback,
    FeedbackCategory, FeedbackStates, Firmware, GenericStates, Invitation,
    InvitationStates, Lock, LockFirmwareUpdate, LockStates,
    NotificationMessage, NotificationMessageStates, Photo, PlanPass,
    PricingScheme, PrivateTracking, PublicTracking, RentalSession,
    RentalSessionStates, Reservation, ReservationStates, SubscriptionPlan,
    SupportTicket, SupportTicketStates, Task, TaskStates, TermsOfService,
    Tracking, Trip, User, Zone,
)
from .serializers import BicycleBaseSerializer, bbox_regex
from .utils import ToTimestamp
from .widgets import StrictBooleanWidget


class CustomDjangoFilterBackend(DjangoFilterBackend):
    def filter_queryset(self, request, queryset, view):
        try:
            return super().filter_queryset(request, queryset, view)
        except ReturnNoResults:
            return queryset.none()


class ReturnNoResults(Exception):
    pass


class UUIDListField(forms.CharField):
    def prepare_value(self, value):
        if value:
            try:
                return ', '.join(
                    map(str, map(UUID, map(str.strip, value.split(','))))
                )
            except ValueError:
                return ''
        else:
            return ''

    def to_python(self, value: str):
        result = []
        if value:
            for item in value.split(','):
                try:
                    result.append(UUID(item.strip()))
                except ValueError:
                    pass

        return result


class UUIDListFilter(filters.UUIDFilter):
    field_class = UUIDListField


class StrictBooleanFilter(filters.BooleanFilter):
    def __init__(self, *args, **kwargs):
        # XXX: not on the class, since we use django_filters.rest_framework.filters?!  # noqa
        kwargs.setdefault('widget', StrictBooleanWidget)
        super().__init__(*args, **kwargs)


class BaseFilterSet(filters.FilterSet):
    created_after = filters.NumberFilter(
        method='filter_by_created_after',
        label='Timestamp greater to `created`.',
    )
    modified_since = filters.NumberFilter(
        field_name='modified',
        lookup_expr='get',
        method='filter_by_modified',
        label='Timestamp greater or equal to `modified`.',
    )
    uuid = django_filters.filters.BaseInFilter(field_name='uuid')

    def __new__(cls, *args, **kwargs):
        """Use a default ordering filter (on all filters).

        This gets updated from override_ordering, if defined.
        """
        cls_ = super().__new__(cls)

        ordering = filters.OrderingFilter(fields=cls_.base_filters.keys())
        try:
            override_ordering = cls_.base_filters['override_ordering']
        except KeyError:
            pass
        else:
            ordering.param_map.update(override_ordering.param_map)
            ordering.extra['choices'].extend(
                override_ordering.extra['choices'])
        cls_.base_filters['ordering'] = ordering
        cls_.declared_filters['ordering'] = ordering
        return cls_

    class Meta:
        fields = ('created_after', 'modified_since', 'created', 'modified',
                  'uuid')

    def filter_by_modified(self, qs, name, value):
        return qs.filter(modified__gte=ToTimestamp(value))

    def filter_by_created_after(self, qs, name, value):
        return qs.filter(created__gt=ToTimestamp(value))


class OrganizationFilterMixin(filters.FilterSet):
    organization = django_filters.UUIDFilter(
        field_name='organization__uuid',
        label='`uuid` of Organization',
    )


class DateTimeFilter(filters.IsoDateTimeFilter):
    label = 'Datetime (ISO 8601), e.g. `2016-02-29T13:37`'


class AddressFilter(BaseFilterSet):
    organization = filters.UUIDFilter(
        field_name='organization__uuid',
        label='`uuid` of Organization',
    )

    class Meta(BaseFilterSet.Meta):
        model = Address
        fields = BaseFilterSet.Meta.fields + ('organization',)


class AffiliationFilter(BaseFilterSet):
    role = filters.MultipleChoiceFilter(
        choices=Affiliation.ROLES,
    )
    organization = filters.UUIDFilter(
        field_name='organization__uuid',
        label='`uuid` of Organization',
    )
    user = filters.UUIDFilter(
        field_name='user__uuid',
        label='`uuid` of User',
    )

    class Meta(BaseFilterSet.Meta):
        model = Affiliation
        fields = BaseFilterSet.Meta.fields + ('role', 'organization', 'user')


class AxaLockFilter(OrganizationFilterMixin, BaseFilterSet):

    class Meta(BaseFilterSet.Meta):
        model = AxaLock

    bleid = filters.CharFilter(
        method='filter_by_bleid',
        label='`bleid` of the Lock',
    )

    def filter_by_bleid(self, qs, name, value):
        if not value.startswith('AXA:'):
            raise exceptions.ValidationError(
                detail={'bleid': ['AxaLock bleids start with "AXA:"']})
        value = value[4:]
        return qs.filter(uid=value)


class AllValidModelMultipleChoiceField(forms.ModelMultipleChoiceField):
    """A ModelMultipleChoiceField that accepts non-existing input.

    The input gets validated by calling ``to_python`` on a ``my_field_class``
    instance.
    """

    my_validation_field = forms.UUIDField()

    def _check_values(self, value):
        """Override Django's internal _check_values.

        It removes the evaluation of the queryset, but calls the `to_python`
        method of a UUIDField instance instead.

        Ref: https://code.djangoproject.com/ticket/27148
        """
        from django.core.exceptions import ValidationError

        key = self.to_field_name or 'pk'
        # deduplicate given values to avoid creating many querysets or
        # requiring the database backend deduplicate efficiently.
        try:
            value = frozenset(value)
        except TypeError:
            # list of lists isn't hashable, for example
            raise ValidationError(
                self.error_messages['list'],
                code='list',
            )
        for pk in value:
            try:
                self.queryset.filter(**{key: pk})
            except (ValueError, TypeError):
                raise ValidationError(
                    self.error_messages['invalid_pk_value'],
                    code='invalid_pk_value',
                    params={'pk': pk},
                )

        # dh> Here comes the missing and custom code.
        if value:
            for o in value:
                self.my_validation_field.to_python(o)
            qs = self.queryset.filter(**{'%s__in' % key: value})
            if not qs:
                raise ReturnNoResults
        return qs


class AllValidModelMultipleChoiceFilter(filters.ModelMultipleChoiceFilter):
    field_class = AllValidModelMultipleChoiceField


class RelatedZonesUUIDFilter(AllValidModelMultipleChoiceFilter):
    def __init__(self, *args, **kwargs):
        # kwargs.setdefault('field_name', 'zones__uuid')
        kwargs.setdefault('to_field_name', 'uuid')
        kwargs.setdefault('queryset', Zone.get_queryset)
        return super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        if value:
            values = set(value)
            qs = self.get_method(qs)(
                **{'{}__in'.format(self.field_name): [v.uuid for v in values]}
            ).distinct()
        return qs


class CausativeBicyleFilter(AllValidModelMultipleChoiceFilter):
    label = '`uuid` of bicycle (multiple allowed)'

    def filter(self, qs, value):
        if value:
            values = set(value)
            qs = qs.annotate_with_causative_bicycle_uuid()
            qs = self.get_method(qs)(
                **{'causative_bicycle_uuid__in': [
                    v.causative_bicycle_uuid for v in values]}
            ).distinct()
        return qs


class RelatedBicyclesUUIDFilter(AllValidModelMultipleChoiceFilter):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('field_name', 'bicycle__uuid')
        kwargs.setdefault('to_field_name', 'uuid')
        kwargs.setdefault('queryset', Bicycle.get_queryset)
        kwargs.setdefault('label', '`uuid` of bicycle (multiple allowed)')
        return super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        if value:
            values = set(value)
            qs = self.get_method(qs)(
                **{'{}__in'.format(self.field_name): [v.uuid for v in values]}
            ).distinct()
        return qs


class RelatedBicycleModelsUUIDFilter(AllValidModelMultipleChoiceFilter):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('field_name', 'model__uuid')
        kwargs.setdefault('to_field_name', 'uuid')
        kwargs.setdefault('queryset', BicycleModel.get_queryset)
        kwargs['label'] = '`uuid` of bicycle model (multiple allowed)'
        return super().__init__(*args, **kwargs)

    def filter(self, qs, value):
        if value:
            values = set(value)
            qs = self.get_method(qs)(
                **{'{}__in'.format(self.field_name): [v.uuid for v in values]}
            ).distinct()
        return qs


class LockFirmwareUpdateFilter(BaseFilterSet):
    lock = filters.UUIDFilter(
        field_name='lock__uuid',
        label='`uuid` of Lock',
    )
    firmware = filters.UUIDFilter(
        field_name='firmware__uuid',
        label='`uuid` of Firmware',
    )
    organization = filters.UUIDFilter(
        field_name='lock__organization__uuid',
        label='Filter resource by organization'
    )

    class Meta(BaseFilterSet.Meta):
        model = LockFirmwareUpdate
        fields = BaseFilterSet.Meta.fields + (
            'lock',
            'firmware',
            'organization',
        )


class AnnotatedFilter(django_filters.filters.Filter):
    def __new__(cls, *args, **kwargs):
        filterset_class = kwargs.pop('filterset_class')
        instance = filterset_class(*args, **kwargs)

        def _filter(self, qs, value):
            if self.field_name not in qs.query.annotations:
                annotate = getattr(qs, 'annotate_with_{}'.format(
                    self.field_name))
                qs = annotate()
            return super(filterset_class, self).filter(qs, value)

        instance.filter = types.MethodType(_filter, instance)
        # This is required when not returning an instance of cls.
        instance.__init__(*args, **kwargs)
        return instance


class LatestTrackingsFilterMixin(filters.FilterSet):
    bbox = filters.CharFilter(
        method='filter_bicycle_or_lock_by_bounding_box',
        label=('Filter Bicycle within the bounding box defined by those'
               ' four coordinates: `point1x,point1y,point2x,point2y`'),
    )
    name = filters.CharFilter(
        lookup_expr='icontains',
    )

    zone = filters.UUIDFilter(
        method='filter_bicycle_or_lock_by_zone',
        label='Filter Bicycle contained within Zone given its uuid',
    )

    max_state_of_charge = filters.filters.NumberFilter(
        method='filter_by_max_state_of_charge',
        label='State of battery charge.',
    )
    min_state_of_charge = filters.filters.NumberFilter(
        method='filter_by_min_state_of_charge',
        label='State of battery charge.',
    )

    class Meta:
        fields = (
            'bbox',
        )

    def filter_bicycle_or_lock_by_bounding_box(self, qs, name, value):
        if not re.match(bbox_regex, value):
            raise exceptions.ValidationError(
                detail={'bbox': ['value must be a comma separated list of '
                                 'floats']}
            )
        p1x, p1y, p2x, p2y = (float(n) for n in value.split(','))
        envelope = Polygon.from_bbox((p1x, p1y, p2x, p2y)).envelope
        tracking_lookup = BicycleBaseSerializer.make_tracking_lookup(
            '{tracking_source}__point__intersects', self.request)
        return qs.filter(**{tracking_lookup: envelope})

    def filter_bicycle_or_lock_by_zone(self, qs, name, value):
        try:
            zone = Zone.objects.get(uuid=value)
        except Zone.DoesNotExist:
            return qs.none()
        tracking_lookup = BicycleBaseSerializer.make_tracking_lookup(
            '{tracking_source}__point__dwithin_expr', self.request)
        attrs_lookup = BicycleBaseSerializer.make_tracking_lookup(
            '{tracking_source}__attributes', self.request)

        if attrs_lookup == 'public_tracking__attributes':
            table_name = PublicTracking._meta.db_table
        else:
            table_name = PrivateTracking._meta.db_table
        return (qs
                .annotate(attrs=F(attrs_lookup))  # makes the join
                .filter(**{tracking_lookup: (
                    zone.polygon,
                    # Get the distance from another column
                    RawSQL(
                        f'COALESCE(("{table_name}"."attributes" ->>'
                        ' \'gps_accuracy\')::double precision, 0) * '
                        f'COALESCE(("{table_name}"."attributes" ->>'
                        ' \'gps_pdop\')::double precision, 1)',
                        [],
                        output_field=models.FloatField()
                    )
                )}))

    def filter_by_max_state_of_charge(self, qs, name, value):
        tracking_lookup = BicycleBaseSerializer.make_tracking_lookup(
            '{tracking_source}__state_of_charge__lt', self.request)
        return qs.filter(**{tracking_lookup: value})

    def filter_by_min_state_of_charge(self, qs, name, value):
        tracking_lookup = BicycleBaseSerializer.make_tracking_lookup(
            '{tracking_source}__state_of_charge__gte', self.request)
        return qs.filter(**{tracking_lookup: value})


class GenericBicycleBboxFilterMixin(filters.FilterSet):
    bbox = filters.CharFilter(
        method='filter_bicycle_causality_by_bounding_box',
        label=('Filter resource (with regard to bicycle) within the bounding'
               ' box defined by those four coordinates:'
               ' `point1x,point1y,point2x,point2y`.'
               'Where each point represents South-West then'
               'North-East corners.'),
    )

    class Meta:
        fields = (
            'bbox'
        )

    def filter_bicycle_causality_by_bounding_box(self, qs, name, value):
        try:
            p1x, p1y, p2x, p2y = (float(n) for n in value.split(','))
        except ValueError:
            raise exceptions.ValidationError(
                detail={'bbox': ['value must be a comma separated list of '
                                 'floats']})
        envelope = Polygon.from_bbox((p1x, p1y, p2x, p2y)).envelope
        tracking_lookup = BicycleBaseSerializer.make_tracking_lookup(
            'bicycles__{tracking_source}__point__intersects', self.request)
        return qs.filter(**{tracking_lookup: envelope})


class GenericTagMixin(filters.FilterSet):
    tag = filters.CharFilter(
        method='filter_by_tag_uuid_or_name',
        label='Filter by tag represented as uuid or name',
    )

    class Meta:
        fields = (
            'tag',
        )

    def filter_by_tag_uuid_or_name(self, qs, name, value):
        try:
            _ = UUID(value)
            return qs.filter(Q(tags__declaration__uuid=value))
        except ValueError:
            return qs.filter(Q(tags__declaration__name=value))


class BicycleFilter(LatestTrackingsFilterMixin,
                    GenericTagMixin,
                    BaseFilterSet):
    state = filters.MultipleChoiceFilter(
        choices=[(v.value, v.value) for v in BicycleStates])
    state__exclude = filters.MultipleChoiceFilter(
        field_name='state',
        choices=[(v.value, v.value) for v in BicycleStates],
        exclude=True,
    )
    organization = filters.UUIDFilter(
        field_name='organization__uuid',
        label='`uuid` of Organization',
    )
    organizations = UUIDListFilter(
        field_name='organization__uuid',
        lookup_expr='in',
        label='Comma-separated Organization `uuid` list',
    )
    assigned_to = filters.UUIDFilter(
        method='filter_by_renter',
        field_name='is_reserved_or_assigned_to',
        label='`uuid` of User. Display Bicycles that are `reserved` or'
        ' `rented` by given user. Deprecated by `assignee`.')
    assignee = filters.UUIDFilter(
        method='filter_by_renter',
        label='`uuid` of User. Display Bicycles that are `reserved` or'
        ' `rented` by given user.')
    name = filters.CharFilter(
        lookup_expr='icontains',
    )
    modified_since = filters.NumberFilter(
        method='filter_by_modified_since',
        label=('Timestamp. Keep only Bicycles that have been updated since '
               'the given DateTime or when the related GPS Trackings have '
               'been updated.')
    )
    with_alerts = filters.BooleanFilter(
        method='filter_by_alerts',
        label=('Filter Bicycle with Alerts for it.'),
    )
    alert_type = filters.MultipleChoiceFilter(
        method='filter_by_alert_type',
        choices=Alert.TYPES,
        label='type of alert. Return only bicycle with an active alert of'
        ' given type.')
    model = RelatedBicycleModelsUUIDFilter()
    has_lock = filters.BooleanFilter(
        field_name='lock',
        lookup_expr='isnull',
        exclude=True,
        label="`True` or `False`",
    )
    serial_number = filters.CharFilter()
    query = filters.CharFilter(
        method='filter_by_full_text',
        label=("Full text search. Based on Bicycle's name, description."
               " lock bleid or serial number."),
    )
    device_type = filters.MultipleChoiceFilter(
        field_name='lock__type',
        choices=Lock.TYPES
    )
    bleid = filters.CharFilter(
        method='filter_by_bleid',
        label='`bleid` of attached Device',
    )
    needs_attention = filters.NumberFilter(
        method='filter_by_attention_needed',
        label='Filter Bicycles that need attention by crew members.',
    )
    recoverable = filters.NumberFilter(
        method='filter_by_recoverability',
        label='Filter bicycles by chance of recoverability higher or equal'
        ' than the given percentage.'
    )

    override_ordering = filters.OrderingFilter(
        fields=(
            ('lock__private_tracking__state_of_charge', 'state_of_charge'),
            ('private_tracking__gps_timestamp', 'latest_gps_timestamp'),
            ('raw_distance', 'distance'),
            ('metadata__needs_attention_score', 'needs_attention'),
            ('metadata__recoverability_score', 'recoverable'),
            ('lock__public_tracking__modified', 'last_cellular_update'),
        ),
        field_labels={'distance': 'Distance from bbox centroid in meters'},
    )

    class Meta(LatestTrackingsFilterMixin.Meta,
               GenericTagMixin.Meta,
               BaseFilterSet.Meta):
        model = Bicycle
        fields = (BaseFilterSet.Meta.fields +
                  GenericTagMixin.Meta.fields +
                  LatestTrackingsFilterMixin.Meta.fields) + (
                      'state',
                      'organization',
                      'assignee',
                      'name',
                      'bbox',
                      'short_id',
                      'with_alerts',
                      'model',
                      'has_lock',
                      'query',
                      'device_type',
                  )
        form = BicycleFilterSetForm

    def filter_bicycle_or_lock_by_bounding_box(self, qs, name, value):
        qs = super().filter_bicycle_or_lock_by_bounding_box(qs, name, value)
        p1x, p1y, p2x, p2y = (float(n) for n in value.split(','))
        envelope = Polygon.from_bbox((p1x, p1y, p2x, p2y)).envelope
        return qs.annotate_with_distance(
                    Point(*envelope.centroid, srid=4236),
                    BicycleBaseSerializer.make_tracking_lookup(
                        '{tracking_source}__point', self.request))

    def filter_by_renter(self, qs, name, value):
        try:
            user = User.objects.get(uuid=value)
        except User.DoesNotExist:
            return qs.none()
        return (
            qs
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
            .filter(Q(reservation_user__isnull=False) |
                    Q(rental_session_user__isnull=False))
        )

    def filter_by_modified_since(self, qs, name, value):
        predicate = Q(
            modified__gte=ToTimestamp(value),
        ) | Q(
            tracking__timestamp__gte=ToTimestamp(value),
            tracking__tracking_type=Tracking.GPS_LOCATION_MESSAGE,

        )
        return qs.filter(predicate)

    def filter_by_alerts(self, qs, name, value):
        predicate = Q(alerts__state=AlertStates.NEW.value) | Q(
            lock__alerts__state=AlertStates.NEW.value)
        return qs.filter(predicate) if value else qs.exclude(predicate)

    def filter_by_alert_type(self, qs, name, value):
        # Looks at alert types to avoid LEFT OUTER join, which does not play
        # well with get_clusters.
        bicycle_alerts = []
        lock_alerts = []
        for v in value:
            if v.startswith('bicycle.'):
                bicycle_alerts.append(v)
            elif v.startswith('lock.'):
                lock_alerts.append(v)
            else:
                raise ValueError('Invalid value for {} filter: {}'.format(
                    name, value))
        if bicycle_alerts:
            qs = qs.filter(Q(alerts__state=AlertStates.NEW.value,
                             alerts__alert_type__in=bicycle_alerts))
        if lock_alerts:
            qs = qs.filter(Q(lock__alerts__state=AlertStates.NEW.value,
                             lock__alerts__alert_type__in=lock_alerts))
        return qs

    def filter_by_full_text(self, qs, name, value):
        return qs.filter(
            Q(name__unaccent__icontains=value) |
            Q(description__unaccent__icontains=value) |
            Q(lock__bleid__icontains=value) |
            Q(serial_number__icontains=value)
        )

    def filter_by_bleid(self, qs, name, value):
        if value.startswith('AXA:'):
            value = value[4:]
            return qs.filter(axa_lock__uid=value)
        return qs.filter(lock__bleid=value)

    def filter_by_attention_needed(self, qs, name, value):
        return qs.filter(metadata__needs_attention_score__gte=value).order_by(
            '-metadata__needs_attention_score')

    def filter_by_recoverability(self, qs, name, value):
        return qs.filter(metadata__recoverability_score__gte=value).order_by(
            '-metadata__recoverability_score')


class ZoneFilter(GeoFilterSet, BaseFilterSet):
    state = filters.MultipleChoiceFilter(
        choices=[(v.value, v.value) for v in GenericStates])
    organization = filters.UUIDFilter(
        field_name='organization__uuid',
        label='`uuid` of Organization',
    )
    organizations = UUIDListFilter(
        field_name='organization__uuid',
        lookup_expr='in',
        label='Comma-separated Organization `uuid` list',
    )
    geo = GeometryFilter(
        field_name='polygon',
        lookup_expr='intersects',
        label=dedent("""
            a geographical coordinate
            {"type": "Point",
             "coordinates": [40.7874455, -73.961900369117]}
            """)
    )
    bbox = filters.CharFilter(
        method='filter_zone_by_bounding_box',
        label=('Filter Zones within the bounding box defined by those'
               ' four coordinates: `point1x,point1y,point2x,point2y`'),
    )
    type = filters.MultipleChoiceFilter(
        choices=Zone.TYPE_ZONES)

    class Meta(BaseFilterSet.Meta):
        model = Zone
        fields = BaseFilterSet.Meta.fields + (
            'state',
            'organization',
            'geo',
            'type',
            'bbox',
        )

    def filter_zone_by_bounding_box(self, qs, name, value):
        try:
            p1x, p1y, p2x, p2y = (float(n) for n in value.split(','))
        except ValueError:
            raise exceptions.ValidationError(
                detail={'bbox': ['value must be a comma separated list of '
                                 'floats']})
        envelope = Polygon.from_bbox((p1x, p1y, p2x, p2y)).envelope
        return qs.filter(polygon__intersects=envelope)


class TermsOfServiceFilter(BaseFilterSet, OrganizationFilterMixin):
    language = filters.CharFilter(
        field_name='language',
        label='Language code of TOS',
    )
    state = filters.MultipleChoiceFilter(
        choices=[(v.value, v.value) for v in GenericStates])
    version = filters.UUIDFilter(
        field_name='version__uuid',
        label='`uuid` of TOS version',
    )

    class Meta(BaseFilterSet.Meta):
        model = TermsOfService
        fields = BaseFilterSet.Meta.fields + (
            'organization', 'language', 'state', 'version')


class InvitationFilter(BaseFilterSet):
    organization = filters.UUIDFilter(
        field_name='organization__uuid',
        label='`uuid` of Organization',
    )
    organizations = UUIDListFilter(
        field_name='organization__uuid',
        lookup_expr='in',
        label='Comma-separated Organization `uuid` list',
    )
    email = filters.CharFilter(
        field_name='email',
        label='email address of User (case insensitive)',
    )
    user = filters.UUIDFilter(
        field_name='user__uuid',
        label='`uuid` of invited User',
    )
    state = filters.MultipleChoiceFilter(
        choices=[(v.value, v.value) for v in InvitationStates])

    class Meta(BaseFilterSet.Meta):
        model = Invitation
        fields = BaseFilterSet.Meta.fields + ('organization', 'user', 'email')


class BicycleModelFilter(BaseFilterSet):
    organization = filters.UUIDFilter(
        field_name='organization__uuid',
        label='`uuid` of Organization',
    )

    class Meta(BaseFilterSet.Meta):
        model = BicycleModel
        fields = BaseFilterSet.Meta.fields + (
            'organization',
        )


class BicycleModelMaintenanceRuleFilter(BaseFilterSet):
    state = filters.MultipleChoiceFilter(
        choices=[(v.value, v.value) for v in
                 BicycleModelMaintenanceRuleStates])

    class Meta(BaseFilterSet.Meta):
        model = BicycleModelMaintenanceRule
        fields = BaseFilterSet.Meta.fields + (
            'severity',
            'role',
            'state',
        )


class LockFilter(LatestTrackingsFilterMixin, BaseFilterSet):
    available = filters.BooleanFilter(
        field_name='bicycle',
        lookup_expr='isnull',
        label=('True` or `False`. '
               'A Lock is available if not assigned to a Bicycle.')
    )
    state = filters.MultipleChoiceFilter(
        choices=[(v.value, v.value) for v in LockStates])
    organization = filters.UUIDFilter(
        field_name='organization__uuid',
        label='`uuid` of Organization'
    )
    organizations = UUIDListFilter(
        field_name='organization__uuid',
        lookup_expr='in',
        label='Comma-separated Organization `uuid` list',
    )
    bleid = filters.CharFilter(
        lookup_expr='icontains',
        label='`bleid` of the Lock',
    )
    type = filters.MultipleChoiceFilter(
        choices=Lock.TYPES
    )
    imei = filters.CharFilter(
        label='`imei` of the Lock',
    )
    query = filters.CharFilter(
        method='filter_by_full_text',
        label=("Full text search. Based on Lock's bleid, imei, counter,"
               " iccid and serial number."),
    )
    override_ordering = filters.OrderingFilter(
        fields=(
            ('private_tracking__state_of_charge', 'state_of_charge'),
            ('private_tracking__gps_timestamp', 'latest_gps_timestamp'),
            ('public_tracking__modified', 'last_cellular_update'),
        ),
    )
    serial_number = django_filters.filters.BaseInFilter(
        field_name='serial_number')

    class Meta(BaseFilterSet.Meta):
        model = Lock
        fields = BaseFilterSet.Meta.fields + (
            'available',
            'state',
            'organization',
            'bleid',
            'type',
            'imei',
            'counter',
            'serial_number',
        )

    def filter_by_full_text(self, qs, name, value):
        return qs.filter(
            Q(bleid__icontains=value) |
            Q(imei__icontains=value) |
            Q(counter__icontains=value) |
            Q(iccid__icontains=value) |
            Q(serial_number__icontains=value)
        )


class FirmwareFilter(BaseFilterSet):
    name = filters.filters.CharFilter()
    organization = filters.UUIDFilter(
        field_name='organization__uuid',
        label='`uuid` of Organization',
    )

    class Meta(BaseFilterSet.Meta):
        model = Firmware
        fields = BaseFilterSet.Meta.fields + (
            'name',
            'organization',
            'chip',
            'state',
            'version',
        )


class SupportTicketFilter(OrganizationFilterMixin, BaseFilterSet):
    owner = filters.UUIDFilter(
        field_name='owner__uuid',
        label='`uuid` of Onwer',
    )
    bicycle = RelatedBicyclesUUIDFilter()
    state = filters.MultipleChoiceFilter(
        choices=[(v.value, v.value) for v in SupportTicketStates])

    class Meta(BaseFilterSet.Meta):
        model = SupportTicket
        fields = BaseFilterSet.Meta.fields + (
            'owner',
            'organization',
            'category',
            'bicycle',
        )


class FeedbackCategoryFilter(BaseFilterSet):
    name = filters.filters.CharFilter()

    class Meta(BaseFilterSet.Meta):
        model = FeedbackCategory
        fields = BaseFilterSet.Meta.fields + (
            'name',
        )


class FeedbackFilter(GenericBicycleBboxFilterMixin, BaseFilterSet):
    organization = filters.UUIDFilter(
        field_name='organization__uuid',
        label='`uuid` of Organization',
    )
    role = filters.MultipleChoiceFilter(
        choices=Affiliation.ROLES
    )
    state = filters.MultipleChoiceFilter(
        choices=[(v.value, v.value) for v in FeedbackStates]
    )

    category = filters.UUIDFilter(
        method='filter_feedback_by_category',
        label='`uuid` of Feedback Category',
    )
    bicycle = CausativeBicyleFilter(
        to_field_name='causative_bicycle_uuid',
        queryset=Feedback.objects.annotate_with_causative_bicycle_uuid(),
    )

    class Meta(BaseFilterSet.Meta):
        model = Feedback
        fields = BaseFilterSet.Meta.fields + (
            'organization',
            'role',
            'state',
            'category',
            'bicycle',
        )

    def filter_feedback_by_category(self, qs, name, value):
        categories = FeedbackCategory.objects.get_queryset_descendants(
            FeedbackCategory.objects.filter(uuid=value),
            include_self=True)
        return qs.filter(category__in=categories)


class AlertFilter(GenericBicycleBboxFilterMixin, BaseFilterSet):
    organization = django_filters.UUIDFilter(
        field_name='organization__uuid',
        label='`uuid` of Organization',
    )
    organizations = UUIDListFilter(
        field_name='organization__uuid',
        lookup_expr='in',
        label='Comma-separated Organization `uuid` list',
    )
    # deprecated
    role = filters.MultipleChoiceFilter(
        field_name='roles',
        choices=Affiliation.ROLES,
        method='filter_by_roles',
        help_text='Deprecated, use roles instead.'
    )
    roles = filters.MultipleChoiceFilter(
        choices=Affiliation.ROLES,
        method='filter_by_roles',
    )
    state = filters.MultipleChoiceFilter(
        choices=[(v.value, v.value) for v in AlertStates])
    alert_type = filters.MultipleChoiceFilter(
        choices=Alert.TYPES,
    )
    causality = django_filters.UUIDFilter(
        method='filter_by_causality',
        label='`uuid` of causality'
    )
    bicycle = CausativeBicyleFilter(
        to_field_name='causative_bicycle_uuid',
        queryset=Alert.objects.annotate_with_causative_bicycle_uuid(),
    )
    bicycle_state = filters.MultipleChoiceFilter(
        choices=[(v.value, v.value) for v in BicycleStates],
        method='filter_by_bicycle_state',
    )
    zone = RelatedZonesUUIDFilter(
        field_name='zones__uuid',
        label='`uuid list` of Zones',
    )

    class Meta(BaseFilterSet.Meta):
        model = Alert
        fields = BaseFilterSet.Meta.fields + (
            'organization',
            'role',
            'state',
            'alert_type',
            'bicycle',
            'causality',
            'bicycle_state',
            'zone',
        )

    def filter_by_causality(self, qs, name, value):
        return qs.filter(Q(bicycles__uuid=value)
                         | Q(locks__uuid=value)
                         | Q(zones__uuid=value))

    def filter_by_bicycle_state(self, qs, name, value):
        return qs.filter(Q(bicycles__state__in=value) |
                         Q(locks__bicycle__state__in=value))

    def filter_by_roles(self, qs, name, value):
        return qs.filter(roles__contains=value)


class AlertMessageFilter(BaseFilterSet):
    state = filters.MultipleChoiceFilter(
        choices=[(v.value, v.value) for v in AlertMessageStates])

    class Meta(BaseFilterSet.Meta):
        model = AlertMessage
        fields = BaseFilterSet.Meta.fields + ('state',)


class NotificationMessageFilter(BaseFilterSet):
    state = filters.MultipleChoiceFilter(
        choices=[(v.value, v.value) for v in NotificationMessageStates])

    class Meta(BaseFilterSet.Meta):
        model = NotificationMessage
        fields = BaseFilterSet.Meta.fields + ('state',)


class PhotoFilter(BaseFilterSet):
    organization = filters.UUIDFilter(
        field_name='organization__uuid',
        label='`uuid` of Organization',
    )

    class Meta(BaseFilterSet.Meta):
        model = Photo
        fields = BaseFilterSet.Meta.fields + ('organization',)


class PlanPassFilter(BaseFilterSet):
    user = filters.UUIDFilter(
        field_name='user__uuid',
        label='`uuid` of User',
    )
    subcription_plan = filters.UUIDFilter(
        field_name='subscription_plan__uuid',
        label='`uuid` of SubscriptionPlan',
    )

    class Meta(BaseFilterSet.Meta):
        model = PlanPass
        fields = BaseFilterSet.Meta.fields + ('user', 'subcription_plan')


class PricingSchemeFilter(OrganizationFilterMixin, BaseFilterSet):
    state = filters.MultipleChoiceFilter(
        choices=[(v.value, v.value) for v in GenericStates])

    class Meta(BaseFilterSet.Meta):
        model = PricingScheme


class RentalSessionFilter(BaseFilterSet):
    user = filters.UUIDFilter(
        field_name='user__uuid',
        label='`uuid` of User',
    )
    bicycle = RelatedBicyclesUUIDFilter()
    organization = filters.UUIDFilter(
        field_name='bicycle__organization__uuid',
        label='`uuid` of Organization',
    )
    state = filters.MultipleChoiceFilter(
        choices=[(v.value, v.value) for v in RentalSessionStates])

    class Meta(BaseFilterSet.Meta):
        model = RentalSession
        fields = BaseFilterSet.Meta.fields + (
            'user',
            'bicycle',
            'organization',
            'state',
        )


class ReservationFilter(BaseFilterSet):
    user = filters.UUIDFilter(
        field_name='user__uuid',
        label='`uuid` of User',
    )
    bicycle = RelatedBicyclesUUIDFilter()
    organization = filters.UUIDFilter(
        field_name='bicycle__organization__uuid',
        label='`uuid` of Organization',
    )
    state = filters.MultipleChoiceFilter(
        choices=[(v.value, v.value) for v in ReservationStates])

    class Meta(BaseFilterSet.Meta):
        model = Reservation
        fields = BaseFilterSet.Meta.fields + (
            'user',
            'bicycle',
            'organization',
            'state',
        )


class SubscriptionPlanFilter(OrganizationFilterMixin, BaseFilterSet):
    is_restricted = filters.BooleanFilter()
    state = filters.MultipleChoiceFilter(
        choices=[(v.value, v.value) for v in GenericStates])

    class Meta(BaseFilterSet.Meta):
        model = SubscriptionPlan


class TaskFilter(GenericBicycleBboxFilterMixin, BaseFilterSet):
    organization = django_filters.UUIDFilter(
        field_name='organization__uuid',
        label='`uuid` of Organization',
    )
    assignor = django_filters.UUIDFilter(
        field_name='assignor__uuid',
        label='`uuid` of Assignee',
    )
    assignee = django_filters.UUIDFilter(
        field_name='assignee__uuid',
        label='`uuid` of Assignee',
    )
    bicycle_model = django_filters.UUIDFilter(
        field_name='maintenance_rule__bicycle_model__uuid',
        label='`uuid` of bicycle model'
    )
    maintenance_rule = django_filters.UUIDFilter(
        field_name='maintenance_rule__uuid',
        label='`uuid` of maintenance rule'
    )
    role = filters.ChoiceFilter(
        choices=Affiliation.ROLES,
    )
    severity = filters.ChoiceFilter(
        choices=FeedbackCategory.SEVERITIES,
    )
    state = filters.MultipleChoiceFilter(
        choices=[(v.value, v.value) for v in TaskStates])
    causality = django_filters.UUIDFilter(
        method='filter_task_by_causality',
        label='`uuid` of causality'
    )
    is_due = filters.filters.BooleanFilter()
    bicycle = CausativeBicyleFilter(
        to_field_name='causative_bicycle_uuid',
        queryset=Task.objects.annotate_with_causative_bicycle_uuid(),
    )

    class Meta(BaseFilterSet.Meta):
        model = Task
        fields = BaseFilterSet.Meta.fields + (
            'organization',
            'assignor',
            'assignee',
            'role',
            'severity',
            'state',
            'is_due',
            'maintenance_rule',
            'bicycle'
        )

    def filter_task_by_causality(self, qs, name, value):
        return qs.filter(Q(alerts__uuid=value) |
                         Q(feedbacks__uuid=value) |
                         Q(bicycles__uuid=value) |
                         Q(alerts__bicycles__uuid=value) |
                         Q(alerts__locks__uuid=value) |
                         Q(alerts__locks__bicycle__uuid=value) |
                         Q(feedbacks__bicycles__uuid=value) |
                         Q(feedbacks__locks__uuid=value) |
                         Q(feedbacks__locks__bicycle__uuid=value))


class TripFilter(BaseFilterSet):
    organization = filters.UUIDFilter(
        field_name='organization_uuid',
        label='`uuid` of Organization'
    )
    organizations = UUIDListFilter(
        field_name='organization__uuid',
        lookup_expr='in',
        label='Comma-separated Organization `uuid` list',
    )
    bicycle = filters.UUIDFilter(
        field_name='bicycle_uuid',
        label='`uuid` of Bicycle'
    )
    rental_session = filters.UUIDFilter(
        method='filter_by_rental_session_uuid',
        label='`uuid` of Rental Session')
    started_after = filters.NumberFilter(
        method='filter_by_started_after',
        label='Timestamp greater or equal to `start_date`.',
    )
    ended_before = filters.NumberFilter(
        method='filter_by_ended_before',
        label='Timestamp less than `end_date`.',
    )
    type = filters.TypedMultipleChoiceFilter(
        choices=[(v, v) for k, v in Trip.TYPES])
    asset_state = filters.MultipleChoiceFilter(
        choices=Trip.ASSET_TYPES)

    class Meta(BaseFilterSet.Meta):
        model = Trip

    def __init__(self, data=None, queryset=None, prefix=None, request=None):
        try:
            is_admin_of_lock8 = request.user.is_admin_of_lock8
        except AttributeError:
            is_admin_of_lock8 = False
        if is_admin_of_lock8:
            self.base_filters['include_invalid'] = StrictBooleanFilter(
                method='filter_include_invalid',
                label=('Include invalid trips (default: False).'))
        else:
            self.base_filters.pop('include_invalid', None)

        super().__init__(data=data, queryset=queryset, prefix=prefix,
                         request=request)

    def filter_by_started_after(self, qs, name, value):
        return qs.filter(start_date__gte=ToTimestamp(value))

    def filter_by_ended_before(self, qs, name, value):
        return qs.filter(end_date__lt=ToTimestamp(value))

    def filter_include_invalid(self, qs, name, value):
        if not value:
            qs = qs.filter(is_valid=True)
        return qs

    def filter_by_rental_session_uuid(self, qs, name, value):
        try:
            rental_session = RentalSession.objects.get(uuid=value)
        except RentalSession.DoesNotExist:
            return qs.none()
        if not self.request.user.has_perm('lock8.view_rentalsession',
                                          rental_session):
            return qs.none()
        end_predicate = Q(end_date__isnull=True) | Q(
            end_date__lt=rental_session.estimated_end_of_trip)
        return qs.filter(
            end_predicate,
            start_date__gte=rental_session.created,
            bicycle_uuid=rental_session.bicycle.uuid)


class UserFilter(BaseFilterSet):
    organization = filters.UUIDFilter(
        field_name='affiliation__organization__uuid',
        label='`uuid` of Organization',
    )
    organizations = UUIDListFilter(
        field_name='affiliation__organization__uuid',
        lookup_expr='in',
        label='Comma-separated Organization `uuid` list',
    )
    email = filters.CharFilter()
    role = filters.CharFilter(method='filter_user_by_role')
    query = filters.CharFilter(method='filter_user_by_name_username_or_email')
    full_name = AnnotatedFilter(
        filterset_class=filters.CharFilter,
        lookup_expr='icontains',
    )

    class Meta(BaseFilterSet.Meta):
        model = User
        fields = BaseFilterSet.Meta.fields + (
            'organization',
            'email',
            'role',
            'last_login',
            'first_name',
            'last_name',
            'username',
        )

    def filter_user_by_role(self, qs, name, value):
        if value:
            predicate = Q(affiliation__role=value)
            query_params = self.request.query_params
            if 'organization' in query_params:
                org_uuid = query_params['organization']
                predicate &= Q(affiliation__organization__uuid=org_uuid)
            return qs.filter(predicate)
        return qs

    def filter_user_by_name_username_or_email(self, qs, name, value):
        if '@' in value:
            return qs.filter(email__icontains=value)

        if len(value) < 3:
            return qs.filter(
                Q(email__icontains=value) | Q(first_name__icontains=value) | Q(
                    last_name__icontains=value) | Q(username__icontains=value)
            )

        return qs.annotate_with_trigram(
            'first_name', 'last_name', 'username', term=value).filter(
                similarity__gt=0.3)
