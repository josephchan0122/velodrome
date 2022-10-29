from copy import deepcopy
from datetime import datetime, timedelta
import itertools
import logging

from boto3.dynamodb.conditions import Key
from django.db.models.query import Q
from rest_framework import exceptions, filters, serializers
from rest_framework.compat import coreapi
from rest_framework.schemas.inspectors import field_to_schema
from rest_framework_jwt.compat import Serializer

from velodrome.lock8.dynamodb import get_ddbtable, query_table
from velodrome.lock8.fields import DateTimeFieldWithSecondPrecision
from velodrome.lock8.metrics import annotate_all_values
from velodrome.lock8.models import Affiliation, Organization, Zone

logger = logging.getLogger(__name__)


class DropzonePrediction:
    def __init__(self, name):
        self.name = name

    def get_values(self, org, zone=None, made_at=None, period=None):
        query_kwargs = self._get_query_kwargs(org, zone, made_at)
        table = get_ddbtable('dropzone-predictions-absolute')
        response = query_table(table, query_kwargs, 'values')
        items = self._process_items(response['Items'], period)
        return {'values': items}

    def _get_query_kwargs(self, org, zone, made_at):
        query_kwargs = {
            'ProjectionExpression':
                'median,q25,q75,dropzone_uuid,pred_made_at,pred_frequency',
        }
        if zone:
            key_expr = Key('dropzone_uuid').eq(str(zone.uuid))
        else:
            key_expr = Key('organization_uuid').eq(str(org.uuid))
            query_kwargs['IndexName'] = 'organization_uuid-pred_made_at-index'

        if not made_at:
            now = datetime.now()
            made_at = now.replace(minute=(now.minute // 10) * 10, second=0)

        key_expr &= Key('pred_made_at').eq(self._format_datetime(made_at))
        query_kwargs['KeyConditionExpression'] = key_expr

        return query_kwargs

    def _process_items(self, items, period):
        return [self._process_item(item, period) for item in items]

    def _process_item(self, item, period):
        zone = item['dropzone_uuid']
        start_time = self._parse_datetime(item['pred_made_at'])

        q25 = item['q25']
        q75 = item['q75']
        median = item['median']
        assert len(q25) == len(q75) == len(median), \
            "Lengths of predictions should be equal"

        pred_frequency_seconds = int(item['pred_frequency'])
        pred_delta = timedelta(seconds=pred_frequency_seconds)

        if not period:
            period = 72

        predictions = itertools.islice(zip(q25, q75, median), period * 6)

        return {'zone': zone,
                'predictions': [{'q25': float(q25),
                                 'q75': float(q75),
                                 'median': float(median),
                                 'date': start_time + (pred_delta * (i + 1)), }
                                for (i, (q25, q75, median))
                                in enumerate(predictions)]}

    _DATE_FORMAT = '%Y-%m-%d %H:%M:%S'

    def _format_datetime(self, date):
        return date.strftime(DropzonePrediction._DATE_FORMAT)

    def _parse_datetime(self, s):
        return datetime.strptime(s, DropzonePrediction._DATE_FORMAT)


PREDICTIONS = {
    prediction.name: prediction
    for prediction in [
        DropzonePrediction('bicycles-in-dropzones')
    ]
}


class PredictionsInputSerializer(Serializer):
    organization = serializers.UUIDField(
        required=True, help_text='Organization UUID for which you are '
                                 'requesting predictions.')
    zone = serializers.UUIDField(
        required=False, help_text='Zone UUID for which you are requesting '
                                  'predictions. Zone needs to be of type '
                                  'dropzone.')
    made_at = DateTimeFieldWithSecondPrecision(
        required=False, help_text='When the prediction was generated. Leave '
                                  'at default unless you are evaluating '
                                  'predictions.')
    period = serializers.IntegerField(
        required=False, min_value=0, max_value=72,
        help_text='Integer value specifying how many hours into the future '
                  'you get predictions for. Default and current maximum is '
                  '72.')


class PredictionsQuerysetLike:
    def filter(self, prediction_name, organization, zone, made_at, period):
        qs = deepcopy(self)

        try:
            prediction = PREDICTIONS[prediction_name]
        except KeyError:
            raise exceptions.ValidationError({
                'prediction_name': [
                    'Prediction {!r} not found'.format(prediction_name)]})

        qs._prediction = prediction
        qs._organization = organization
        qs._zone = zone
        qs._made_at = made_at
        qs._period = period

        return qs

    def values(self, request):
        data = self._prediction.get_values(
            self._organization,
            self._zone,
            self._made_at,
            self._period)
        data['values'] = annotate_all_values(data['values'], request)
        return data


class PredictionsFilterBackend(filters.BaseFilterBackend):
    def filter_queryset(self, request, qs, view):
        assert type(qs) == PredictionsQuerysetLike, \
            'PredictionsFilterBackend can be used with \
             PredictionsQuerysetLike only'

        prediction_name = view.kwargs.get('prediction_name')
        input = PredictionsInputSerializer(data=request.GET)
        input.is_valid(raise_exception=True)

        org_uuid = input.validated_data.get('organization')
        zone_uuid = input.validated_data.get('zone')
        made_at = input.validated_data.get('made_at')
        period = input.validated_data.get('period')

        org = self._get_organization(request, org_uuid)
        zone = self._get_zone(org, zone_uuid)

        return qs.filter(
            prediction_name=prediction_name,
            organization=org,
            zone=zone,
            made_at=made_at,
            period=period)

    def _get_organization(self, request, org_uuid):
        try:
            mgmt_team_predicate = Q(affiliation__role__in=(
                Affiliation.ADMIN,
                Affiliation.FLEET_OPERATOR,
                Affiliation.SPECTATOR))
            return (request.user
                    .get_descendants_organizations(
                        predicate=mgmt_team_predicate)
                    .get(uuid=org_uuid))
        except Organization.DoesNotExist:
            raise exceptions.PermissionDenied

    def _get_zone(self, org, zone_uuid):
        if zone_uuid is None:
            return None
        else:
            try:
                return Zone.objects.get(
                    uuid=zone_uuid,
                    organization=org,
                    type=Zone.DROP)
            except Zone.DoesNotExist:
                raise exceptions.PermissionDenied

    def get_schema_fields(self, view):
        serializer = PredictionsInputSerializer()
        fields = []
        for field in serializer.fields.values():
            fields.append(coreapi.Field(
                name=field.field_name,
                location='query',
                required=field.required,
                schema=field_to_schema(field)))
        return fields
