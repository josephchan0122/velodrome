import functools
import logging

from django.conf import settings
from django.core.mail import EmailMessage
from generic_relations.relations import GenericRelatedField
from rest_framework import serializers
from rest_framework.relations import HyperlinkedRelatedField

from .models import (
    Affiliation, Alert, Bicycle, BicycleStates, Feedback, Lock,
    NotificationMessage, NotificationMessageStates, Task, TaskStates, Zone,
)
from .serializers import (
    AlertSerializer, FeedbackSerializer, GenericBicycleRelationSerializer,
    PrivateBicycleSerializer, PublicBicycleSerializer, TaskSerializer,
)
from .utils import build_frontend_uri, send_email

logger = logging.getLogger(__name__)

alert_type_email_handlers_registry = {}


def register_email(predicate):
    def decorate(fn):
        if isinstance(predicate, (list, tuple, set)):
            for pred in predicate:
                alert_type_email_handlers_registry[pred] = fn
        else:
            alert_type_email_handlers_registry[predicate] = fn
        return fn
    return decorate


def _send_the_email(subject, to, template_name, context):
    msg = EmailMessage(
        subject=subject,
        from_email=settings.DEFAULT_FROM_EMAIL,
        to=to,
    )
    msg.template_name = template_name
    msg.global_merge_vars = context
    msg.send(fail_silently=False)


def _send_alert_email(alert, message, context=None):
    if context is None:
        context = {}
    if isinstance(alert.causality, Lock):
        causality = alert.causality.bicycle
    else:
        causality = alert.causality
    subject = '[Noa Alert] {}: {} [{}]'.format(
        alert.description, causality.name, alert.organization.name
    )
    info_list = context.setdefault('info_list', {})
    info_list.update({
        'Time': alert.display_time,
    })
    context.update({
        'alert': alert,
        'username': message.user.display_name,
    })
    send_email(subject, [message.user.email],
               'email/alert_generic.txt',
               template_html='email/alert_generic.html',
               context=context)


@functools.singledispatch
def send_notification_message_dispatcher(causality, message):
    raise NotImplementedError('Unknown causality - {}'.format(causality))


@send_notification_message_dispatcher.register(Feedback)
def send_feedback_notification(feedback, message):
    username = feedback.user.display_name
    subject = '[FEEDBACK] reported by {}'.format(username)

    # EMAIL
    if feedback.organization.get_preference('send_feedback_per_email', False):
        to = [message.user.email]
        template_name = 'user_feedback'
        context = {
            'user_name': username,
            'user_link': build_frontend_uri('users', feedback.user.uuid),
            'image': feedback.image.url if feedback.image else None,
            'message': feedback.message,
        }
        _send_the_email(subject, to, template_name, context)


@send_notification_message_dispatcher.register(Task)
def send_task_notification(task, message):
    context = {}
    if task.state == TaskStates.UNASSIGNED.value:
        template_name = 'task_created'
        if task.assignor:
            subject = '[TASK] created by {}'.format(task.assignor.display_name)
            context.update({'assignor_name': task.assignor.display_name})
        elif isinstance(task.causality, Feedback):
            subject = '[TASK] created based on Feedback of {}'.format(
                task.causality.user.display_name
            )
            context.update({'user': task.causality.user.display_name})
        elif isinstance(task.causality, Alert):
            subject = '[TASK] created based on {} alert'.format(
                task.causality.get_alert_type_display().lower()
            )
        elif isinstance(task.causality, Lock):
            subject = '[TASK] created based on device #{} '.format(
                task.causality.serial_number
            )
        elif task.maintenance_rule is not None:
            subject = '[TASK] created based on rule - {}'.format(
                task.maintenance_rule.description
            )
        else:
            raise NotImplementedError
    elif task.state == TaskStates.ASSIGNED.value:
        template_name = 'task_assigned'
        subject = '[TASK] assigned'
        context.update({'assignee_name': task.assignee.display_name})
    elif task.state == TaskStates.CANCELLED.value:
        template_name = 'task_cancelled'
        subject = '[TASK] cancelled'
    else:
        template_name = 'task_completed'
        if task.assignee:
            subject = '[TASK] completed by {}'.format(
                task.assignee.display_name
            )
            context.update({'assignee_name': task.assignee.display_name})
        else:
            subject = '[TASK] completed'

    # EMAIL
    if task.organization.get_preference('send_task_per_email', False):
        to = [message.user.email]
        template_name = template_name
        _send_the_email(subject, to, template_name, context)


@register_email(Alert.ZONE_HIGH_THRESHOLD_TRIGGERED)
def send_zone_high_threshold_email(alert, message):
    _send_alert_email(alert, message, {})


@register_email(Alert.ZONE_LOW_THRESHOLD_TRIGGERED)
def send_zone_low_threshold_email(alert, message):
    _send_alert_email(alert, message, {})


@register_email(Alert.LOW_BATTERY)
def send_low_battery_email(alert, message):
    context = {'info_list': {'Battery level': alert.causality.state_of_charge}}
    _send_alert_email(alert, message, context)


@register_email(Alert.RIDE_OUTSIDE_SERVICE_AREA)
def send_alert_ride_outside_service_area(alert, message):
    causality = alert.causality
    zone_uuid = alert.context.get('zone_uuid')
    try:
        zone = Zone.objects.get(uuid=zone_uuid)
    except Zone.DoesNotExist:
        zone = None
    if zone:
        desc = 'Bicycle {} is riding outside service area {}.'.format(
            causality.name, zone.name)
    else:
        desc = 'Bicycle {} is riding outside service area.'.format(
            causality.name)
    context = {
        'description': desc,
    }
    _send_alert_email(alert, message, context)


@register_email(Alert.NO_TRACKING_RECEIVED_SINCE)
def send_alert_tracking_not_received_since(alert, message):
    context = {'info_list': {'Last seen': '24 hours ago'}}
    _send_alert_email(alert, message, context)


@register_email([Alert.DEVICE_SHUTDOWN,
                 Alert.RETURN_OUTSIDE_DROP_ZONE,
                 Alert.LOST_BICYCLE_REPORTED,
                 Alert.USAGE_OUTSIDE_OPERATIONAL_PERIOD,
                 Alert.BICYCLE_IDLE_FOR_TOO_LONG,
                 Alert.LOCKED_BUT_CABLE_NOT_PRESENT,
                 Alert.BICYCLE_LEFT_UNLOCKED,
                 Alert.BICYCLE_STOLEN,
                 ])
def send_alert_generic(alert, message):
    _send_alert_email(alert, message)


@send_notification_message_dispatcher.register(Alert)
def send_alert(alert, message):
    email_types = alert.organization.get_preference(
        'allowed_email_alert_types', ()
    )
    if message.user != alert.user and alert.alert_type in email_types:
        try:
            dispatcher = alert_type_email_handlers_registry[alert.alert_type]  # noqa
        except KeyError as exc:
            raise NotImplementedError(
                'Got unexpected alert {}'.format(alert.alert_type)
            ) from exc
        dispatcher(alert, message)


def make_offline_serializer(serializer):
    """Delete all fields relying on request object,
    that we don't have.
    """
    for field_name, field in list(serializer.fields.items()):
        if (isinstance(field, (HyperlinkedRelatedField,
                               GenericRelatedField)) or
                getattr(field, '_is_relation', False)):
            del serializer.fields[field_name]
        if isinstance(field, serializers.Serializer):
            make_offline_serializer(field)
        if isinstance(field, serializers.ListSerializer):
            make_offline_serializer(field.child)
    if isinstance(serializer, GenericBicycleRelationSerializer):
        del serializer.fields['bicycle']


@functools.singledispatch
def build_publisher_topics(instance, for_state_leaving=None):
    raise NotImplementedError


@build_publisher_topics.register(Bicycle)
def build_publisher_topics_bicycle(instance, for_state_leaving=None):
    parent_organizations_topic = '/'.join(
        str(org.uuid)
        for org in instance.organization.get_ancestors(ascending=True)
    )
    prefixes = ['']
    if parent_organizations_topic:
        prefixes += ['/{}'.format(parent_organizations_topic)]

    for prefix in prefixes:
        for role in (
            Affiliation.ADMIN,
            Affiliation.FLEET_OPERATOR,
            Affiliation.MECHANIC,
        ):
            if instance.organization.level == 0 and role == Affiliation.ADMIN:
                continue
            yield '{prefix}/{organization}/{role}/bicycles/{bicycle}/'.format(
                prefix=prefix,
                organization=instance.organization.uuid,
                role=role,
                bicycle=instance.uuid,
            ), False

        if instance.state == BicycleStates.RESERVED.value:
            yield (
                '{prefix}/{organization}/{renter}/bicycles/{bicycle}/'.format(
                    prefix=prefix,
                    organization=instance.organization.uuid,
                    renter=instance.active_reservation.user.uuid,
                    bicycle=instance.uuid,
                )
            ), False
        elif instance.state == BicycleStates.RENTED.value:
            yield (
                '{prefix}/{organization}/{renter}/bicycles/{bicycle}/'.format(
                    prefix=prefix,
                    organization=instance.organization.uuid,
                    renter=instance.active_rental_session.user.uuid,
                    bicycle=instance.uuid,
                )
            ), False
        elif instance.state == BicycleStates.AVAILABLE.value:
            if instance.organization.is_open_fleet:
                yield (
                    '{prefix}/{organization}/public/bicycles/'
                    '{bicycle}/'.format(
                        prefix=prefix,
                        organization=instance.organization.uuid,
                        bicycle=instance.uuid,
                    ),
                    False,
                )
            yield '{prefix}/{organization}/renter/bicycles/{bicycle}/'.format(
                prefix=prefix,
                organization=instance.organization.uuid,
                bicycle=instance.uuid,
            ), False
        if (
            for_state_leaving
            and for_state_leaving.get('state') == BicycleStates.AVAILABLE.value
        ):
            yield '{prefix}/{organization}/renter/bicycles/{bicycle}/'.format(
                prefix=prefix,
                organization=instance.organization.uuid,
                bicycle=instance.uuid,
            ), False

    if instance.organization.level == 0:
        yield '/{organization}/{role}/bicycles/{bicycle}/'.format(
            organization=instance.organization.uuid,
            role=Affiliation.ADMIN,
            bicycle=instance.uuid,
        ), True


@build_publisher_topics.register(NotificationMessage)
def build_publisher_topics_notification_message(instance,
                                                for_state_leaving=None):
    yield '/{organization}/{user}/notifications/'.format(
        organization=instance.causality.organization.uuid,
        user=instance.user.uuid,
    ), False


@functools.singledispatch
def build_publisher_serialization(instance, private):
    raise NotImplementedError


@build_publisher_serialization.register(Bicycle)
def build_publisher_serialization_bicycle(instance, private,
                                          for_state_leaving=None):
    if for_state_leaving:
        return ('bicycle_leaving_{0}'.format(*for_state_leaving.keys()),
                for_state_leaving)

    serializer_class = (PrivateBicycleSerializer
                        if private else PublicBicycleSerializer)
    serializer = serializer_class(instance)
    make_offline_serializer(serializer)
    return 'bicycle', serializer.to_representation(instance)


@build_publisher_serialization.register(NotificationMessage)
def build_publisher_serialization_notification_message(instance, _,
                                                       for_state_leaving=None):

    if not instance.state == NotificationMessageStates.SENT.value:
        raise NotImplementedError
    if isinstance(instance.causality, Alert):
        serializer = AlertSerializer(instance.causality)
        topic = 'alert'
    elif isinstance(instance.causality, Feedback):
        serializer = FeedbackSerializer(instance.causality)
        topic = 'feedback'
    elif isinstance(instance.causality, Task):
        serializer = TaskSerializer(instance.causality)
        topic = 'task'
    else:
        raise NotImplementedError
    make_offline_serializer(serializer)
    return topic, serializer.to_representation(instance.causality)
