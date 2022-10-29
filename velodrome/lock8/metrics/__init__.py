from copy import deepcopy
import datetime as dt
from enum import Enum
import logging

from boto3.dynamodb.conditions import Key
from django.db.models.query import Q
from django.utils import timezone
from rest_framework import exceptions, filters, serializers
from rest_framework.compat import coreapi
from rest_framework_jwt.compat import Serializer

from velodrome.lock8.dynamodb import dynamodb, get_ddbtable, query_table
from velodrome.lock8.fields import DateTimeFieldWithSecondPrecision
from velodrome.lock8.utils import is_valid_uuid

logger = logging.getLogger(__name__)


class Resolution(Enum):
    MINUTE = 'minute'
    HOUR = 'hour'
    DAY = 'day'
    MONTH = 'month'
    YEAR = 'year'

    def strftime(self, date):
        resolution_to_strftime = {
            Resolution.MINUTE: '%Y%m%d%H%M',
            Resolution.HOUR: '%Y%m%d%H',
            Resolution.DAY: '%Y%m%d',
            Resolution.MONTH: '%Y%m',
            Resolution.YEAR: '%Y',
        }
        fmt = resolution_to_strftime[self]
        return date.strftime(fmt)

    @classmethod
    def all(cls):
        return list(cls)

    @classmethod
    def above_minute(cls):
        return [Resolution.HOUR, Resolution.DAY,
                Resolution.MONTH, Resolution.YEAR]

    @classmethod
    def above_hour(cls):
        return [Resolution.DAY, Resolution.MONTH, Resolution.YEAR]

    @classmethod
    def below_year(cls):
        return [Resolution.MINUTE, Resolution.HOUR,
                Resolution.DAY, Resolution.MONTH]


class BaseMetric:
    """
    Base class for metrics. Assumes that default index is organization-based,
    i.e. has 'organization' field as hash and 'date' field as range key.
    """
    resolutions = Resolution.above_minute()

    def __init__(self, name: str, table_basename: str, value_name: str):
        self.name = name
        self.table_basename = table_basename
        self.value_name = value_name
        self.projection = set(
            ['date'] + ([value_name] if value_name is not None else []))

    def get_values(self, organization, resolution: Resolution,
                   start: dt.datetime, end: dt.datetime, **kwargs) -> dict:
        """
        Retrieves values for the metric for selected organization, resolution,
        start/end dates and other implementation-dependent arguments
        """
        query_kwargs = self._get_query_kwargs(
            organization, resolution, start, end, **kwargs)
        table = self._get_table(resolution)
        response = query_table(table, query_kwargs, 'values')
        return {
            'values': [
                {
                    self._rename_value_key(k): self._parse_metric_value(k, v)
                    for k, v in item.items()
                }
                for item in response['Items']
            ]
        }

    def _get_full_table_name(self, resolution: Resolution) -> str:
        return '{}-{}'.format(self.table_basename, resolution.value)

    def _get_table(self, resolution: Resolution) -> dynamodb.Table:
        return get_ddbtable(self._get_full_table_name(resolution))

    def _get_query_kwargs(self, organization, resolution=None,
                          start=None, end=None, **kwargs):
        (escaped_projection, expression_attributes) = self._escape_projection()
        key_condition_expression = self._get_key_condition_expression(
            organization, resolution, start, end, **kwargs)

        return {
            'ProjectionExpression': escaped_projection,
            'ExpressionAttributeNames': expression_attributes,
            'KeyConditionExpression': key_condition_expression,
        }

    def _get_partition_key(self, organization, **kwargs):
        return Key('organization').eq(str(organization.uuid))

    def _get_key_condition_expression(self, organization, resolution, start,
                                      end, **kwargs):
        key = self._get_partition_key(organization, **kwargs)
        if start is not None and end is not None:
            key &= Key('date').between(
                int(resolution.strftime(start)),
                int(resolution.strftime(end)))

        return key

    def _escape_projection(self):
        escaped_projection = []
        attributes = {}
        for field in self.projection:
            if field in ['date', 'user', 'zone']:
                escaped_field = '#{}'.format(field)
                escaped_projection.append(escaped_field)
                attributes[escaped_field] = field
            else:
                escaped_projection.append(field)
        return ','.join(escaped_projection), attributes

    def _rename_value_key(self, key):
        return 'value' if key == self.value_name else key

    def _parse_metric_value(self, key, value):
        return default_parse_metric_value(key, value)


class TotalValuesMixin:
    def get_values(self, organization, resolution: Resolution,
                   start: dt.datetime, end: dt.datetime, **kwargs):
        """
        Retrieves requested values for the metrics, as well as total number
        of values and current value.
        """
        values = super().get_values(
            organization, resolution, start, end, **kwargs)
        values['total'] = self._get_total(organization)
        return values

    def _get_total(self, organization):
        table = self._get_table(Resolution.YEAR)
        query_kwargs = self._get_query_kwargs(organization)

        response = query_table(table, query_kwargs, 'total')
        total = 0
        if response['Count']:
            total_value = sum(
                item[self.value_name] for item in response['Items'])

            total = self._parse_metric_value(self.value_name, total_value)

        return float(round(total, 2))


class CurrentValuesMixin:
    def get_values(self, organization, resolution: Resolution,
                   start: dt.datetime, end: dt.datetime, **kwargs):
        """
        Retrieves requested values for the metrics, as well as total number
        of values and current value.
        """
        values = super().get_values(
            organization, resolution, start, end, **kwargs)
        values['current'] = self._get_current(organization)
        return values

    def _get_current(self, organization):
        table = self._get_table(Resolution.HOUR)
        now = timezone.now()
        current_start = now - dt.timedelta(hours=24)
        current_end = now + dt.timedelta(hours=1)
        query_kwargs = self._get_query_kwargs(
            organization, Resolution.HOUR, current_start, current_end)

        response = query_table(table, query_kwargs, 'current')
        current_value = self._parse_metric_value(
            self.value_name,
            sum(item[self.value_name] for item in response['Items']))

        return float(round(current_value, 2))


class OrganizationMetric(TotalValuesMixin, CurrentValuesMixin, BaseMetric):
    pass


class BaseMetricWithSeparateOrganizationIndex(BaseMetric):
    """
    Base class for metrics whose tables do not have organization-based
    primary index. In the case of retrieving values for organization,
    a given secondary index is used.
    """
    organization_index_name = 'organization-date-index'

    def _get_query_kwargs(self, organization, resolution, start=None, end=None,
                          **kwargs):
        query_kwargs = super()._get_query_kwargs(
            organization, resolution, start, end, **kwargs)
        query_kwargs['IndexName'] = self.organization_index_name
        return query_kwargs


class BicycleMetric(BaseMetricWithSeparateOrganizationIndex):
    resolutions = Resolution.above_hour()

    def __init__(self, name: str, table_basename: str, value_name: str):
        super().__init__(name, table_basename, value_name)
        self.projection.add('bicycle')

    def _get_query_kwargs(self, organization, resolution, start=None, end=None,
                          **kwargs):
        query_kwargs = super()._get_query_kwargs(
            organization, resolution, start, end, **kwargs)

        if kwargs.get('bicycle_uuid') is not None:
            del query_kwargs['IndexName']

        return query_kwargs

    def _get_partition_key(self, organization, **kwargs):
        if kwargs.get('bicycle_uuid') is not None:
            return Key('bicycle').eq(str(kwargs['bicycle_uuid']))

        return super()._get_partition_key(organization, **kwargs)


class ZoneMetric(BaseMetricWithSeparateOrganizationIndex):
    def __init__(self, name: str, table_basename: str, value_name: str):
        super().__init__(name, table_basename, value_name)
        self.projection.add('zone')
        self.projection.add('zone_type')

    def _get_query_kwargs(self, organization, resolution, start=None, end=None,
                          **kwargs):
        query_kwargs = super()._get_query_kwargs(
            organization, resolution, start, end, **kwargs)

        if kwargs.get('zone_uuid') is not None:
            del query_kwargs['IndexName']

        return query_kwargs

    def _get_partition_key(self, organization, **kwargs):
        if kwargs.get('zone_uuid') is not None:
            return Key('zone').eq(str(kwargs['zone_uuid']))

        return super()._get_partition_key(organization, **kwargs)

    def _rename_value_key(self, key):
        return key


class UserMetric(BaseMetricWithSeparateOrganizationIndex):
    resolutions = Resolution.above_hour()

    def __init__(self, name: str, table_basename: str, value_name: str):
        super().__init__(name, table_basename, value_name)
        self.projection.add('user')

    def _get_query_kwargs(self, organization, resolution, start=None, end=None,
                          **kwargs):
        query_kwargs = super()._get_query_kwargs(
            organization, resolution, start, end, **kwargs)

        if kwargs.get('user_uuid') is not None:
            del query_kwargs['IndexName']

        return query_kwargs

    def _get_partition_key(self, organization, **kwargs):
        user_uuid = kwargs.get('user_uuid')
        if user_uuid is not None:
            user_organization = f'{user_uuid}_{organization.uuid}'
            return Key('user_organization').eq(user_organization)

        return super()._get_partition_key(organization, **kwargs)


class DropzoneMetric(BaseMetricWithSeparateOrganizationIndex):
    resolutions = Resolution.below_year()

    def __init__(self, name: str, table_basename: str, value_name: str):
        super().__init__(name, table_basename, value_name)
        self.projection.update({'zone', 'max_bicycles', 'min_bicycles'})

    def _get_query_kwargs(self, organization, resolution, start=None, end=None,
                          **kwargs):
        query_kwargs = super()._get_query_kwargs(
            organization, resolution, start, end, **kwargs)

        if kwargs.get('zone_uuid') is not None:
            del query_kwargs['IndexName']

        return query_kwargs

    def _get_partition_key(self, organization, **kwargs):
        if kwargs.get('zone_uuid') is not None:
            return Key('zone').eq(str(kwargs['zone_uuid']))

        return super()._get_partition_key(organization, **kwargs)

    def _get_key_condition_expression(self, organization, resolution, start,
                                      end, **kwargs):
        key = self._get_partition_key(organization, **kwargs)
        if start is not None and end is not None:
            key &= Key('date').between(
                int(resolution.strftime(start)),
                int(resolution.strftime(end)))

        return key

    def _rename_value_key(self, key):
        return key

    def _parse_metric_value(self, key, value):
        if key in ('max_bicycles', 'min_bicycles', 'total_bicycles'):
            return int(value)

        return super()._parse_metric_value(key, value)


METRICS = {
    metric.name: metric
    for metric in [
        BicycleMetric(
            name='bicycles-distance',
            table_basename='bicycle-distance-meters-ridden',
            value_name='distance'),
        BicycleMetric(
            name='bicycles-time',
            table_basename='bicycle-usage-time',
            value_name='seconds'),
        BicycleMetric(
            name='bicycles-trips',
            table_basename='bicycle-trips',
            value_name='trips'),
        OrganizationMetric(
            name='distance',
            table_basename='distance-meters-ridden',
            value_name='distance'),
        OrganizationMetric(
            name='trips',
            table_basename='trips',
            value_name='trips'),
        OrganizationMetric(
            name='time',
            table_basename='usage-time',
            value_name='seconds'),
        UserMetric(
            name='users-distance',
            table_basename='user-distance-meters-ridden',
            value_name='distance'),
        UserMetric(
            name='users-unique',
            table_basename='user-distance-meters-ridden',
            value_name=None),
        ZoneMetric(
            name='zones-bicycles',
            table_basename='zones-bicycles',
            value_name='bicycles'),

        BicycleMetric(
            name='bicycles-distance-v2',
            table_basename='v2-bicycle-distance-meters-ridden',
            value_name='distance'),
        BicycleMetric(
            name='bicycles-time-v2',
            table_basename='v2-bicycle-usage-time',
            value_name='seconds'),
        BicycleMetric(
            name='bicycles-trips-v2',
            table_basename='v2-bicycle-trips',
            value_name='trips'),
        OrganizationMetric(
            name='distance-v2',
            table_basename='v2-organization-distance-meters-ridden',
            value_name='distance'),
        OrganizationMetric(
            name='trips-v2',
            table_basename='v2-organization-trips',
            value_name='trips'),
        OrganizationMetric(
            name='time-v2',
            table_basename='v2-organization-usage-time',
            value_name='seconds'),
        UserMetric(
            name='users-distance-v2',
            table_basename='v2-user-distance-meters-ridden',
            value_name='distance'),
        UserMetric(
            name='users-unique-v2',
            table_basename='v2-user-distance-meters-ridden',
            value_name=None),
        DropzoneMetric(
            name='dropzone-metrics-v2',
            table_basename='v2-dropzone-metrics',
            value_name='avg_bicycles')
    ]
}

START_DELTA_FOR_RESOLUTION = {
    Resolution.MINUTE: 1,
    Resolution.HOUR: 1,
    Resolution.DAY: 30,
    Resolution.MONTH: 365,
    Resolution.YEAR: 3650
}


class MetricsQuerysetLike:
    def filter(self, metric_name: str = None, start: dt.datetime = None,
               end: dt.datetime = None, resolution: Resolution = None,
               organization=None, bicycle_uuid=None, zone_uuid=None,
               user_uuid=None):
        qs = deepcopy(self)
        try:
            metric = METRICS[metric_name]
        except KeyError:
            raise exceptions.ValidationError({
                'metric_name': ['Metric {!r} not found.'.format(metric_name)]})
        qs._metric = metric

        if resolution not in metric.resolutions:
            raise exceptions.ValidationError({
                'resolution': ['Invalid value "{}" for metric "{}".'.format(
                    resolution.value, metric.name)]})
        qs._resolution = resolution

        if not end:
            end = timezone.now()
        if not start:
            start = end - dt.timedelta(START_DELTA_FOR_RESOLUTION[resolution])
        if start > end:
            raise exceptions.ValidationError({
                'start': ["'start' needs to be earlier than 'end'"]})
        start = max(dt.datetime(2016, 1, 1, tzinfo=dt.timezone.utc), start)
        qs._start = start
        qs._end = end

        qs._organization = organization
        qs._kwargs = {
            'bicycle_uuid': bicycle_uuid,
            'zone_uuid': zone_uuid,
            'user_uuid': user_uuid
        }

        return qs

    def values(self, request):
        data = self._metric.get_values(
            self._organization,
            self._resolution,
            self._start,
            self._end,
            **self._kwargs)
        data['values'] = annotate_all_values(data['values'], request)
        return data


class MetricsInputSerializer(Serializer):
    organization = serializers.UUIDField(required=True)
    resolution = serializers.ChoiceField({
            r.value: 'Get metrics by the %s' % r.value
            for r in list(Resolution)
        },
        required=True,
        help_text='Available resolutions: %s' % ', '.join([
            resolution.value for resolution in list(Resolution)
        ]))
    start = DateTimeFieldWithSecondPrecision(required=False)
    end = DateTimeFieldWithSecondPrecision(required=False)
    bicycle = serializers.UUIDField(required=False)
    zone = serializers.UUIDField(required=False)
    user = serializers.UUIDField(required=False)


class MetricsFilterBackend(filters.BaseFilterBackend):
    def filter_queryset(self, request, qs, view):
        assert type(qs) == MetricsQuerysetLike, \
            'MetricsFilterBackend can be used with MetricsQuerysetLike only'

        metric_name = view.kwargs.get('metric_name')

        input = MetricsInputSerializer(data=request.GET)
        input.is_valid(raise_exception=True)

        org_uuid = input.validated_data.get('organization')
        bicycle_uuid = input.validated_data.get('bicycle')
        zone_uuid = input.validated_data.get('zone')
        user_uuid = input.validated_data.get('user')
        resolution = Resolution(input.validated_data.get('resolution'))

        from velodrome.lock8.models import Affiliation, Organization
        try:
            mgmt_team_predicate = Q(affiliation__role__in=(
                Affiliation.ADMIN,
                Affiliation.FLEET_OPERATOR,
                Affiliation.SPECTATOR))
            org = (request.user
                   .get_descendants_organizations(
                       predicate=mgmt_team_predicate)
                   .get(uuid=org_uuid))
        except Organization.DoesNotExist:
            raise exceptions.PermissionDenied

        return qs.filter(
                metric_name=metric_name,
                start=input.validated_data.get('start'),
                end=input.validated_data.get('end'),
                resolution=resolution,
                organization=org,
                bicycle_uuid=bicycle_uuid,
                zone_uuid=zone_uuid,
                user_uuid=user_uuid)

    def get_schema_fields(self, view):
        from rest_framework.schemas.inspectors import field_to_schema

        serializer = MetricsInputSerializer()
        fields = []
        for field in serializer.fields.values():
            fields.append(coreapi.Field(
                name=field.field_name,
                location='query',
                required=field.required,
                schema=field_to_schema(field)))
        return fields


def get_distance_for_bicycles_since(bicycles, start, end=None):
    """Get distances for a list of bicycle UUIDs since `start`."""
    metric = METRICS['bicycles-distance-v2']
    results = {}
    if end is None:
        end = timezone.now()
    for bicycle in bicycles:
        for data in metric.get_values(
                None, Resolution.DAY, start, end,
                bicycle_uuid=bicycle)['values']:
            current = results.get(bicycle, 0)
            results[bicycle] = current + float(data['value'])
    return results


def default_parse_metric_value(key, value):
    if key == 'date':
        return convert_metric_timestamp_to_RFC(value)
    if key == 'distance':
        return float(round(value / 1000, 2))
    if key == 'zone' and value == 'None':
        return None
    return value


def convert_metric_timestamp_to_RFC(s):  # noqa
    """Converts 'YYYYMMDDHH' to 'YYYY[-MM[-DD[THH:mm]]]'."""
    s = str(s)
    length = len(s)
    if length == 12:  # minute
        return '{:0>4}-{:0>2}-{:0>2}T{:0>2}:{:0>2}'.format(s[0:4], s[4:6],
                                                           s[6:8], s[8:10],
                                                           s[10:12])
    if length == 10:  # hour
        return '{:0>4}-{:0>2}-{:0>2}T{:0>2}:{}'.format(s[0:4], s[4:6],
                                                       s[6:8], s[8:10], '00')
    if length == 8:  # day
        return '{:0>4}-{:0>2}-{:0>2}'.format(s[0:4], s[4:6], s[6:8])
    if length == 6:  # month
        return '{:0>4}-{:0>2}'.format(s[0:4], s[4:6])
    if length == 4:  # year
        return '{:0>4}'.format(s[0:4])
    raise ValueError('Unexpected resolution of len {}.'.format(length))


def annotate_all_values(values, request):
    """Transforms bicycle, user and zone UUIDs into valid URLs to our API"""
    from velodrome.lock8.models import Bicycle, User, Zone

    if values:
        for key, cls in [('bicycle', Bicycle), ('user', User), ('zone', Zone)]:
            if key in values[0]:
                values = annotate_values(values, key, cls.objects, request)
    return values


def annotate_values(values, key, qs, request):
    """
    Transforms UUIDs into URLs to our API by looking them up in given
    queryset
    """
    valid_uuids = [x for x in (d[key] for d in values) if
                   is_valid_uuid(x)]

    map_by_uuid = {
        str(obj.uuid): {
            '{}_name'.format(key): obj.display_name,
            key: request.build_absolute_uri(obj.get_absolute_url())
            if obj else None,
        } for obj in qs.filter(uuid__in=valid_uuids)
    }
    return [dict(d, **map_by_uuid.get(str(d[key]), {
        key: None,
        '{}_name'.format(key): None,
    })) for d in values]
