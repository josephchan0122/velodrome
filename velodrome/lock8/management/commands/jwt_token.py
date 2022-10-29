import uuid

from django.core.management.base import LabelCommand
from rest_framework_jwt import utils

from velodrome.lock8.jwt_extensions import jwt_payload_handler
from velodrome.lock8.models import Q, User


class Command(LabelCommand):
    label = 'username_pk_or_uuid'

    def handle_label(self, user, **options):
        predicate = Q(username=user)
        try:
            user_pk = int(user)
        except ValueError:
            pass
        else:
            predicate |= Q(pk=user_pk)
        try:
            user_uuid = uuid.UUID(str(user))
        except ValueError:
            pass
        else:
            predicate |= Q(uuid=user_uuid)
        try:
            user = User.objects.get(predicate)
        except User.DoesNotExist:
            self.stderr.write("{}: user not found, skipping.".format(user))
            return
        jwt_token = utils.jwt_encode_handler(jwt_payload_handler(user))
        self.stdout.write("{}: JWT {}".format(user, jwt_token))
