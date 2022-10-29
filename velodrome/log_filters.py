import logging

from django.conf import settings


class EC2InstanceIdFilter(logging.Filter):

    def filter(self, record):
        record.ec2_instance_id = getattr(settings, 'EC2_INSTANCE_ID', '')
        return True
