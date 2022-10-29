import json
import logging

from boto3.session import Session
from django.core.management.base import BaseCommand

from velodrome.lock8.utils import ingest_stripe_event

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    can_import_settings = True

    def handle(self, *args, **kwargs):
        from django.conf import settings

        session = Session(region_name=settings.AWS_REGION_NAME)
        sqs = session.resource('sqs')
        queue = sqs.get_queue_by_name(QueueName='-'.join((
            settings.STRIPE_EVENT_SQS_QUEUE_NAME,
            settings.ENVIRONMENT,
        )))
        while True:
            try:
                for message in queue.receive_messages(
                        WaitTimeSeconds=settings.STRIPE_EVENT_SQS_WAIT_TIME_SECONDS):  # noqa
                    ingest_stripe_event(json.loads(message.body))
                    message.delete()
            except Exception as e:
                logger.exception('Unexpected exception when draining stripe '
                                 'events: %s', e)
