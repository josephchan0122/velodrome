import binascii
import contextlib
import datetime as dt
import functools
from io import BytesIO
import json
import logging
import math
import os
import random
import re
import sys
from urllib.parse import urljoin
import uuid

from aiozmq import rpc
import base58
from concurrency.api import disable_concurrency
from concurrency.exceptions import RecordModifiedError
from django.apps import apps as django_apps
from django.conf import settings
from django.contrib.gis.db.backends.postgis.operations import PostGISOperations
from django.contrib.gis.db.models.fields import GeometryCollectionField
from django.contrib.gis.db.models.lookups import DWithinLookup
from django.contrib.gis.geos import GeometryCollection, MultiPoint, Point
from django.core.cache import caches
from django.core.exceptions import (
    PermissionDenied, ValidationError as DjangoValidationError,
)
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.db import connection, transaction
from django.db.models import Aggregate, DurationField
from django.db.models.expressions import Func
from django.db.models.functions.datetime import Extract
from django.db.utils import InterfaceError
from django.http import Http404
from django.template.loader import get_template
from django.urls import reverse
from django.utils import six, timezone
from django.utils.http import urlencode
from django.utils.translation import ugettext_lazy as _
from django_redis import get_redis_connection
from openpyxl import Workbook
import pinax.stripe.actions.events
import pinax.stripe.actions.exceptions
from premailer import Premailer
from raven.contrib.django.models import get_client as get_sentry_client
import requests
from rest_framework import exceptions, status
from rest_framework.response import Response
from rest_framework.settings import api_settings
from reversion import revisions

from .fields import IndexedPointField

SENTINEL = object()
logger = logging.getLogger(__name__)


def exception_logger(method):
    """Log exceptions before raising them."""
    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        try:
            result = method(*args, **kwargs)
        except Exception as exc:
            try:
                cls_name = args[0].__class__.__name__
                name = '{}.{}'.format(cls_name, method.__name__)
            except Exception:
                name = method.__name__
            logger.exception('Exception in %s: %s', name, exc)
            raise exc
        else:
            return result
    return wrapper


def call_logger(method):
    """Log call to function."""
    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        import inspect
        b = inspect.signature(method).bind(*args, **kwargs)

        logger.info('Calling %s with %s.', method.__name__,
                    {k: v for k, v in b.arguments.items() if k != 'self'})
        result = method(*args, **kwargs)
        logger.info('Returning: %s.',
                    '{} byte{}'.format(len(result),
                                       's' if len(result) > 1 else '')
                    if isinstance(result, bytes) else result)
        return result
    return wrapper


def detect_staled_connection(method):
    """Close Django database connection explicitly, if found to be
    already closed. Then retry the decorated function.
    """
    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        try:
            with transaction.atomic():
                result = method(*args, **kwargs)
        except InterfaceError as e:
            if 'connection already closed' in str(e):
                connection.close()
                with transaction.atomic():
                    result = method(*args, **kwargs)
            else:
                raise e
        return result
    return wrapper


class RPCMessageHandler(rpc.AttrHandler):
    """RPC server for locksocket firmware updating pipeline."""

    @rpc.method
    @exception_logger
    @call_logger
    @detect_staled_connection
    def is_there_is_update(self, serial_number: str, mercury_version: str):
        """RPC handler for locksocket server by SQS."""
        return handle_firmware_available_request(
            serial_number, mercury_version
        )

    @rpc.method
    @exception_logger
    @call_logger
    @detect_staled_connection
    def get_binary_for_mercury(self, serial_number: str):
        """RPC handler for locksocket server by SQS."""
        return handle_mercury_download(serial_number)

    @rpc.method
    @exception_logger
    @call_logger
    @detect_staled_connection
    def get_new_firmware_advanced_device(
        self,
        serial_number: str,
        version: str,
        firmware_type: int,
        check_only: bool
    ):
        """Check version of firmware for new devices or get the binary data."""
        dev_app = django_apps.get_app_config("advanced_devices")
        if check_only:
            result = dev_app.api.actual_device_firmware_version(
                logger, serial_number, version, firmware_type
            )
        else:
            result = dev_app.api.get_device_firmware(
                logger, serial_number, version
            )

        return result

    @rpc.method
    @exception_logger
    @call_logger
    @detect_staled_connection
    def device_sync_config(self, serial_number: str, checksum: str):
        """Search new configuration content for device."""
        dev_app = django_apps.get_app_config("advanced_devices")
        return dev_app.api.get_new_device_config_content(
            logger, serial_number, checksum
        )


def handle_firmware_available_request(serial_number, mercury_version):
    """Handle request for available firmwares.
    Codes are defined in locksocket/protodefs/FirmwareAvailableRequest_pb2.py.
    """
    from velodrome.lock8.models import (Firmware, Lock, LockFirmwareUpdate,
                                        GenericStates)

    try:
        lock = Lock.objects.get(serial_number=serial_number)
    except Lock.DoesNotExist:
        return 1

    reported_version = str(mercury_version)
    current_version = str(lock.firmware_versions.get('mercury'))
    if reported_version != current_version:
        lock.firmware_versions['mercury'] = reported_version
        with transaction.atomic():
            with disable_concurrency(lock):
                with revisions.create_revision():
                    revisions.set_comment('handle_firmware_available_request')
                    lock.save(update_fields=('firmware_versions', 'modified'))

    mercury = LockFirmwareUpdate.objects.filter(
        lock=lock,
        firmware__state=GenericStates.PROVISIONED.value,
        firmware__chip=Firmware.MERCURY
    ).exclude(firmware__version=mercury_version).exists()
    if mercury:
        return 2
    return 1


NO_FIRMWARE = b'\0'


@transaction.atomic
def handle_mercury_download(serial_number):
    from velodrome.lock8.models import Firmware, GenericStates

    try:
        mercury = Firmware.objects.get(
            lock__serial_number=serial_number,
            state=GenericStates.PROVISIONED.value,
            chip=Firmware.MERCURY)
    except Firmware.DoesNotExist:
        return NO_FIRMWARE
    else:
        return mercury.binary.read()


class Ago(Func):
    function = None
    template = "NOW() - %(expressions)s"

    def convert_value(self, value, expression, connection, context):
        return value


class Later(Func):
    function = None
    template = "NOW() + %(expressions)s"

    def convert_value(self, value, expression, connection, context):
        return value


class ToTimestamp(Func):
    function = None
    template = "to_timestamp(%(expressions)s)"

    def convert_value(self, value, expression, connection, context):
        return value


class ARRAY(Func):
    function = "ARRAY"
    template = "%(function)s(SELECT %(expressions)s)"

    def convert_value(self, value, expression, connection, context):
        return value


class NullIf(Func):
    function = 'NULLIF'


def make_short_id():
    return ''.join(random.choices(base58.alphabet.decode(), k=12))


def reverse_query(viewname, query_kwargs=None, kwargs=None, urlconf=None,
                  current_app=None, args=None):
    """Custom reverse to add a query string after the url."""
    url = reverse(viewname, urlconf=urlconf, args=args, kwargs=kwargs,
                  current_app=current_app)
    if query_kwargs:
        url = '%s?%s' % (url, urlencode(query_kwargs))
    return url


def get_exc_fingerprint_for_sentry(exc):
    codes = exc.get_codes()
    if codes == {'coupon': ['invalid_coupon']}:
        return ['validationerror_invalid_coupon']
    elif codes == 'throttled':
        # Do not use repr(), since it includes the seconds.
        return ['{{ default }}']
    return ['{{ default }}', repr(exc)]


def api_exception_handler(exc, context):
    """
    Returns the response that should be used for any given exception.

    By default we handle the REST framework `APIException`, and also
    Django's built-in `Http404` and `PermissionDenied` exceptions.

    Any unhandled exceptions may return `None`, which will cause a 500 error
    to be raised.
    """
    from rest_framework.views import set_rollback
    if isinstance(exc, exceptions.APIException):
        headers = {}
        if getattr(exc, 'auth_header', None):
            headers['WWW-Authenticate'] = exc.auth_header
        if getattr(exc, 'wait', None):
            headers['Retry-After'] = '%d' % exc.wait

        details = exc.get_full_details()
        if 'message' in details:
            data = {'detail': {'non_field_errors': [details]}}
        else:
            data = {'detail': details}

        msg = 'APIException (%d): %r' % (exc.status_code, exc)
        logger.info(msg)

        if settings.ENVIRONMENT != 'dev':
            if not isinstance(exc, (
                    exceptions.AuthenticationFailed,
                    exceptions.NotAuthenticated,
            )):
                # Add exc_info during exception handling, but not when calling
                # this handler directly (e.g. in tests).
                capture_kwargs = {
                    'message': msg,
                    'level': 'info',
                    'fingerprint': get_exc_fingerprint_for_sentry(exc),
                }
                exc_info = sys.exc_info()
                if exc_info[0] is None:
                    event = 'raven.events.Message'
                else:
                    capture_kwargs['exc_info'] = exc_info
                    event = 'raven.events.Exception'
                get_sentry_client().capture(event, **capture_kwargs)

        set_rollback()
        return Response(data, status=exc.status_code, headers=headers)

    elif isinstance(exc, Http404):
        msg = exc.args[0] if exc.args else _('Not found.')
        data = {'detail': {api_settings.NON_FIELD_ERRORS_KEY: [{
            'message': six.text_type(msg),
            'code': 'not_found'}]}}

        set_rollback()
        return Response(data, status=status.HTTP_404_NOT_FOUND)

    elif isinstance(exc, PermissionDenied):
        msg = exc.args[0] if exc.args else _('Permission denied.')
        data = {'detail': {api_settings.NON_FIELD_ERRORS_KEY: [{
            'message': six.text_type(msg),
            'code': 'permission_denied'}]}}

        set_rollback()
        return Response(data, status=status.HTTP_403_FORBIDDEN)

    elif isinstance(exc, RecordModifiedError):
        msg = _('Conflict due to concurrent edition.')
        data = {'detail': {'message': six.text_type(msg),
                           'code': 'conflict'}}

        set_rollback()
        return Response(data, status=status.HTTP_409_CONFLICT)

    elif isinstance(exc, DjangoValidationError):
        default_code = getattr(exc, 'code', None) or 'invalid'
        try:
            error_dict = exc.error_dict
        except AttributeError:
            error_dict = {api_settings.NON_FIELD_ERRORS_KEY: exc.error_list}
        error_dict = {
            k: [exceptions.ErrorDetail(e.message % (e.params or ()),
                                       e.code if e.code else default_code)
                for e in error_list]
            for k, error_list in error_dict.items()
        }
        drf_validation_error = exceptions.ValidationError(error_dict,
                                                          default_code)
        drf_validation_error.sentry_extra = getattr(exc, 'sentry_extra', None)
        return api_exception_handler(drf_validation_error, context)

    # Note: Unhandled exceptions will raise a 500 error.
    return None


def export_telit_trackings(recipient):
    cache = caches['telit_trackings']
    wb = Workbook()
    ws = wb.active
    for index, key in enumerate(cache.client.keys('*')):
        counter, timestamp = key.split(':')
        tracking = cache.get(key)
        if index == 0:
            titles = sorted(tracking.keys())
            ws.append(['bleid', 'timestamp'] + titles)
        row = [counter, timestamp] + [tracking[column] for column in titles]
        ws.append(row)
    buffer = BytesIO()
    wb.save(buffer)
    email = EmailMessage('Telit Trackings',
                         'Please find the report attached.',
                         settings.DEFAULT_FROM_EMAIL,
                         [recipient])
    buffer.seek(0)
    email.attach('telit_trackings.xlsx', buffer.read(),
                 ('application/vnd.openxmlformats-officedocument'
                  '.spreadsheetml.sheet'))
    email.send()


@contextlib.contextmanager
def disable_signal(signal_type, handler, instance_or_class):
    klass = (
        instance_or_class if isinstance(instance_or_class, type) else
        instance_or_class.__class__)
    try:
        signal_type.disconnect(handler, klass)
        yield
    finally:
        signal_type.connect(handler, klass)


@transaction.atomic
@revisions.create_revision()
def ingest_stripe_event(data):
    kind = 'unknown event'
    try:
        livemode = data['livemode']
        if livemode != settings.STRIPE_LIVEMODE:
            raise RuntimeError(
                'Received unexpected Stripe event: livemode=%s/settings=%s' % (
                    livemode, settings.STRIPE_LIVEMODE))
        if pinax.stripe.actions.events.dupe_event_exists(data['id']):
            pinax.stripe.actions.exceptions.log_exception(
                json.dumps(data), 'Duplicate event record.')
        else:
            stripe_id = data['id']
            kind = data['type']
            revisions.set_comment('ingest_stripe_event: %s' % (kind,))
            livemode = data['livemode']
            with transaction.atomic():
                pinax.stripe.actions.events.add_event(
                    stripe_id=stripe_id,
                    kind=kind,
                    livemode=livemode,
                    message=data)
    except Exception as exc:
        logger.exception('ingest_stripe_event: %s: %r' % (kind, exc))
        pinax.stripe.actions.exceptions.log_exception(
            json.dumps(data), repr(exc))


def charge_estimator(current_soc, latest_timestamp):
    """
    The estimated charge of a lock based on time elapsed
    from the latest tracking.

    - HOURLY_GRADIENT:
        - the battery will drain 1% every 20 hours, hence, -0.05% per hour.
    - MIN_ESTIMATION_DIFF:
        - trust the hardware estimation if the difference is negligible.
    """
    hourly_gradient = -0.05
    min_estimation_diff = 1.

    latest = dt.datetime.fromtimestamp(
        float(latest_timestamp), tz=dt.timezone.utc
    )
    hours_diff = ((timezone.now() - latest).total_seconds() / 3600)
    estimated_soc = (hourly_gradient * hours_diff) + current_soc
    negligible_diff = (current_soc - estimated_soc) < min_estimation_diff

    if hours_diff <= 0. or negligible_diff:
        return current_soc
    if estimated_soc < 0.:
        return 0.
    return round(estimated_soc, 1)


def get_cluster_distance_from_bbox(envelope):
    """
    Compute the distance of a cluster for given bbox.
    Cluster Distance Ratio is completely arbitrary. This value has been
    taken from empiristic testing with iOS app and mr-hyde fleet in Berlin.
    """
    CLUSTER_DISTANCE_RATIO = 75
    if len(envelope.coords) == 2:
        # points are the same
        return 0
    coords = envelope.coords[0]
    length_side = min(Point(coords[0]).distance(Point(coords[1])),
                      Point(coords[1]).distance(Point(coords[2])))
    return math.pi * math.sqrt(2) * length_side / CLUSTER_DISTANCE_RATIO


def is_valid_uuid(s):
    try:
        uuid.UUID(str(s))
    except ValueError:
        return False
    return True


def send_email(subject, recipients, template_text, template_html=None,
               context=None):
    if context is None:
        context = {}
    msg_text = get_template(template_text).render(context)
    email = EmailMultiAlternatives(
        subject=subject,
        body=msg_text,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=recipients)
    if template_html:
        msg_html = get_template(template_html).render(context)
        inlined_email = Premailer(msg_html,
                                  disable_validation=True,
                                  cssutils_logging_level=logging.ERROR,
                                  ).transform()
        email.attach_alternative(inlined_email, 'text/html')
    logger.info('Sending email to %s (%s, %s).', recipients, subject, context)
    email.send(fail_silently=False)


class ClusterWithin(Func):
    """
    ST_ClusterWithin returns several results. Needs to be treated as a pure
    function so Django can returns all results.
    """
    name = 'ClusterWithin'
    function = 'ST_ClusterWithin'
    template = 'ST_AsBinary(unnest(%(function)s(%(expressions)s,%(distance)f)))'  # noqa: E501
    output_field = GeometryCollectionField()


class ClusterWithinAggregate(ClusterWithin, Aggregate):
    """
    Grouping by a specific property requires of an aggregate, so that Django
    understands that a grouping can be in place.
    """
    pass


def get_json_from_extent(extent):
    x1, y1, x2, y2 = extent
    if x1 == x2 and y1 == y2:
        return {'type': 'Point', 'coordinates': [x1, y1]}
    return {'type': 'Polygon', 'coordinates': [list(t) for t in
                                               zip(*[iter(extent)] * 2)]}


def group_to_state_clusters(bicycle_clusters, max_cluster_distance):
    """ Group clusters merging different states per cluster.

    Currently, the request to clusters does not accept break down
    according to aggregations on specific properties inside of the
    clusters. This method re-groups clusters hierarchically based
    on their proximity, and applying the same distance used in the
    query to clusters. The clustering process resembles other
    density based algorithms in that it connects points that are
    within certain distance thresholds to others, but recalculating
    the new centroid on every new iteration.

    The clustering process is the following:
        1. Take a point from the subset.
        2. Calculate distance with the rest of points.
            a. If one point is within the distance threshold,
            merge them, calculating centroid, bbox and densities,
            and add back into the subset. Start on 1 again.
            b. If There is no point nearby, add cluster to final result.

    Args:
        bicycle_clusters: list, clusters returned from request to database.
        max_cluster_distance: float, maximum separation for two points
                              to be considered within the same cluster.
    """
    clusters = [{
        'centroid': bc['cluster'].centroid,
        'density': {bc['state']: bc['cluster'].num_geom},
        'bbox': bc['bounding_circle'].envelope
    } for bc in bicycle_clusters]

    grouped_clusters = []
    while clusters:

        # Pick one cluster at a time
        tested_cluster = clusters.pop(0)

        # Compare each cluster to the rest
        for i, cluster in enumerate(clusters):
            distance = tested_cluster['centroid'].distance(
                cluster['centroid'])

            # If clusters are near, regroup and loop again
            if distance <= max_cluster_distance:
                cluster_to_combine = clusters.pop(i)
                clusters.insert(0, _combine_clusters(
                    tested_cluster, cluster_to_combine))
                break
        else:
            # Found no cluster nearby, add to final result
            grouped_clusters.append(tested_cluster)

    return [_get_extended_cluster(**gc) for gc in grouped_clusters]


def extend_clusters(bicycle_clusters, max_cluster_distance):
    return [_get_extended_cluster(
        bc['cluster'].centroid,
        bc['bounding_circle'],
        bc['cluster'].num_geom) for bc in bicycle_clusters]


def _get_extended_cluster(centroid, bbox, density):
    return {
        'centroid': {
            'type': centroid.__class__.__name__,
            'coordinates': list(centroid.coords)
        },
        'density': density,
        'bbox': get_json_from_extent(bbox.extent)
    }


def _combine_clusters(c1, c2):
    """Combine two clusters into a new one.

    Merge two clusters by combining their properties such that they can fully
    define the new resulting cluster.
    """

    # Merge and sum dictionary of densities
    c1_d = c1['density']
    c2_d = c2['density']
    density = {
        d: c1_d.get(d, 0) + c2_d.get(d, 0) for d in set(c1_d) | set(c2_d)
    }

    return {
        'density': density,
        'centroid': MultiPoint(c1['centroid'], c2['centroid']).centroid,
        'bbox': GeometryCollection(c1['bbox'], c2['bbox']).envelope
    }


def group_to_model_clusters(bicycle_clusters, max_cluster_distance):
    """ Group clusters merging different models per cluster.

    Currently, the request to clusters does not accept break down
    according to aggregations on specific properties inside of the
    clusters. This method re-groups clusters hierarchically based
    on their proximity, and applying the same distance used in the
    query to clusters. The clustering process resembles other
    density based algorithms in that it connects points that are
    within certain distance thresholds to others, but recalculating
    the new centroid on every new iteration.

    The clustering process is the following:
        1. Take a point from the subset.
        2. Calculate distance with the rest of points.
            a. If one point is within the distance threshold,
            merge them, calculating centroid, bbox and densities,
            and add back into the subset. Start on 1 again.
            b. If There is no point nearby, add cluster to final result.

    Args:
        bicycle_clusters: list, clusters returned from request to database.
        max_cluster_distance: float, maximum separation for two points
                              to be considered within the same cluster.
    """
    clusters = [{
        'centroid': bc['cluster'].centroid,
        'density': {bc['model__name']: bc['cluster'].num_geom},
        'bbox': bc['bounding_circle'].envelope
    } for bc in bicycle_clusters]

    grouped_clusters = []
    while clusters:

        # Pick one cluster at a time
        tested_cluster = clusters.pop(0)

        # Compare each cluster to the rest
        for i, cluster in enumerate(clusters):
            distance = tested_cluster['centroid'].distance(
                cluster['centroid'])

            # If clusters are near, regroup and loop again
            if distance <= max_cluster_distance:
                cluster_to_combine = clusters.pop(i)
                clusters.insert(0, _combine_clusters(
                    tested_cluster, cluster_to_combine))
                break
        else:
            # Found no cluster nearby, add to final result
            grouped_clusters.append(tested_cluster)

    return [_get_extended_cluster(**gc) for gc in grouped_clusters]


def generate_auto_login_code(length=20):
    # taken from generate_key in rest_framework/authtoken/models.py
    return binascii.hexlify(os.urandom(length)).decode()


def create_affiliations_if_whitelisted(user):
    from velodrome.lock8.models import Affiliation, Organization

    if user.organization is not None:
        # White labeled users doesn't need to belong to other orgs.
        return

    domain = user.email.partition('@')[2]
    uuids = user.affiliations.values_list('organization__uuid', flat=True)
    orgs = (
        Organization.objects
        .exclude(uuid__in=uuids)
        .filter(allowed_signup_domain_names__contains=[domain])
    )
    for org in orgs:
        Affiliation.objects.create(
            user=user, organization=org, role=Affiliation.RENTER
        )


def raise_for_response_status_with_context(response):
    try:
        response_content = response.content
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        e.sentry_extra = {'response_content': response_content}
        raise e from e


class DurationExtract(Extract):
    """Extract transformation that supports DurationField.

    It removes the instance checks that Django does.
    Ref: https://github.com/django/django/pull/7600.
    Included in Django 2.0.
    """
    def as_sql(self, compiler, connection):
        assert isinstance(self.lhs.output_field, DurationField)
        sql, params = compiler.compile(self.lhs)
        sql = connection.ops.time_extract_sql(self.lookup_name, sql)
        return sql, params

    def resolve_expression(self, query=None, allow_joins=True, reuse=None,
                           summarize=False, for_save=False):
        copy = super(Extract, self).resolve_expression(
            query, allow_joins, reuse, summarize, for_save)
        assert isinstance(copy.lhs.output_field, DurationField)
        return copy


def get_next_ekey_slot(axa_lock):
    """This rotates over slot 0-2.

    3, 4 are reserved for Noa.
    5, 6, 7 are reserved for customers (e.g. Apple).."""
    redis = get_redis_connection('default')
    slot_key = 'ekey-slot-{}'.format(axa_lock.uuid)
    value = redis.incr(slot_key)
    if value > 3:
        redis.set(slot_key, 0)
        return 0
    return value - 1


def update_bicycle_metadata(message):
    from velodrome.lock8.models import Bicycle, BicycleMetaData

    assert message['version'] == 'v1'
    bicycle = Bicycle.objects.get(uuid=message['uuid'])
    try:
        bicycle.metadata
    except BicycleMetaData.DoesNotExist:
        BicycleMetaData.objects.create(
            bicycle=bicycle, **message['properties'])
    else:
        for key, value in message['properties'].items():
            setattr(bicycle.metadata, key, value)
        bicycle.metadata.save()


def camel_case_to_snake_case(s):
    return s[0].lower() + re.sub(
        r'[A-Z]', lambda matched: '_' + matched.group(0).lower(), s[1:])


def build_frontend_uri(path, uuid):
    path = path.rstrip('/') + '/'  # add trailing slash to path for urljoin
    return functools.reduce(
        urljoin, [settings.FRONTEND_URL, path, str(uuid)]
    )


@IndexedPointField.register_lookup
class DWithinLookupWithExpression(DWithinLookup):
    """
    Like DWithin but allows to pass an expression for distance value
    """
    lookup_name = 'dwithin_expr'
    sql_template = '%(func)s(%(lhs)s::geography, %(rhs)s, %(value)s)'


def debug_log_error(msg):
    """Create an error and warning logging entry for testing."""
    logger.error('debug_log_error: %s', msg)
    logger.warning('debug_log_error: warning: %s', msg)


PostGISOperations.gis_operators['dwithin_expr'] = PostGISOperations.gis_operators['dwithin']  # noqa: E501
