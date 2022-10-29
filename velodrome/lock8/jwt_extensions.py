from calendar import timegm
from collections import defaultdict
from datetime import datetime
from uuid import UUID

from django.conf import settings
import jwt
from refreshtoken.models import RefreshToken
from rest_framework import exceptions
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from rest_framework_jwt.settings import api_settings
from social_django.models import UserSocialAuth

from velodrome.lock8.models import ClientApp, Organization, User

jwt_get_username_from_payload = api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER


def jwt_decode_handler(token):
    key = api_settings.JWT_SECRET_KEY

    options = {
        'verify_exp': api_settings.JWT_VERIFY_EXPIRATION,
    }
    return jwt.decode(
        token,
        key,
        api_settings.JWT_VERIFY,
        options=options,
        leeway=api_settings.JWT_LEEWAY,
        audience=api_settings.JWT_AUDIENCE,
        issuer=api_settings.JWT_ISSUER,
        algorithms=[api_settings.JWT_ALGORITHM]
    )


class JSONWebTokenAuthentication(JSONWebTokenAuthentication):
    def authenticate(self, request):
        """
        Returns a two-tuple of `User` and token if a valid signature has been
        supplied using JWT-based authentication.  Otherwise returns `None`.

        This is a copy of the original implementation, but returning the
        decoded payload.
        Ref: https://github.com/GetBlimp/django-rest-framework-jwt/pull/370.
        """
        jwt_value = self.get_jwt_value(request)
        if jwt_value is None:
            return None

        try:
            payload = jwt_decode_handler(jwt_value)
        except jwt.ExpiredSignature:
            msg = 'Signature has expired.'
            raise exceptions.AuthenticationFailed(msg)
        except jwt.DecodeError:
            msg = 'Error decoding signature.'
            raise exceptions.AuthenticationFailed(msg)
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed()

        user = self.authenticate_credentials(payload)

        return (user, payload)

    def authenticate_credentials(self, payload):
        """
        Returns an active user that matches the payload's user id and email.
        Uses `user_id` to fetch the user by UUID, or client app name for STS.
        """
        iss = payload['iss']
        user_uuid = payload['user_id']
        if iss == settings.STS_JWT_ISSUER:
            try:
                client_app = ClientApp.objects.get(
                    name=user_uuid,
                    organization__uuid=payload['organization'])
            except ClientApp.DoesNotExist:
                raise exceptions.AuthenticationFailed(
                    'Invalid client application account.')

            user = client_app.user = (User.objects
                                      .annotate_with_is_admin_of_lock8()
                                      .get(pk=client_app.user_id))
        elif iss.startswith('sts'):
            # Help with unexpected sts iss, mostly for test/dev/prod mixup.
            raise exceptions.AuthenticationFailed(
                'Unexpected JWT iss for STS (expected %s)' % (
                    settings.STS_JWT_ISSUER))
        else:
            # Validate user_id here to not mask DoesNotExist with DB lookup.
            try:
                user_uuid = UUID(user_uuid)
            except ValueError:
                raise exceptions.AuthenticationFailed('Invalid user account.')
            try:
                user = User.objects.get(uuid=user_uuid, is_active=True)
            except User.DoesNotExist:
                raise exceptions.AuthenticationFailed('Invalid user account.')

            # Decorate with "is_admin_of_lock8".
            affs = payload['affs']
            root_org_uuid = str(Organization.get_root_org().uuid)
            user.is_admin_of_lock8 = (
                root_org_uuid in affs and 'admin' in affs[root_org_uuid])

        return user


def jwt_payload_handler(user):
    affiliations = defaultdict(set)
    org_cache = {}
    for affiliation in user.affiliations.all().select_related('organization'):
        org_uuid = str(affiliation.organization.uuid)
        affiliations[org_uuid].add(affiliation.role)
        try:
            sub_org_uuids = org_cache[org_uuid]
        except KeyError:
            sub_org_uuids = (affiliation.organization
                             .get_descendants()
                             .values_list('uuid', flat=True))
            org_cache[org_uuid] = sub_org_uuids
        # all suborganization inherit roles from their parents
        for sub_org_uuid in sub_org_uuids:
            affiliations[str(sub_org_uuid)].add(affiliation.role)

    payload = {'user_id': str(user.uuid),
               'email': user.email,
               'username': user.get_username(),
               'exp': datetime.utcnow() + api_settings.JWT_EXPIRATION_DELTA,
               'affs': {k: sorted(v) for k, v in affiliations.items()},
               }
    try:
        payload['iss'] = user.social_auth.get().provider
    except (AttributeError, UserSocialAuth.DoesNotExist):
        payload['iss'] = 'local'
    if api_settings.JWT_ALLOW_REFRESH:  # pragma: no branch
        payload['orig_iat'] = timegm(
            datetime.utcnow().utctimetuple()
        )
    return payload


def jwt_response_payload_handler(token, user=None, request=None):
    from .serializers import UserSerializer

    payload = {}
    try:
        backend = request.backend.name
    except AttributeError:
        try:
            backend = user.social_auth.get().provider
        except (AttributeError, UserSocialAuth.DoesNotExist):
            backend = 'local'

    if isinstance(user, User):
        try:
            refresh_token = user.refresh_tokens.get(app=backend).key
        except RefreshToken.DoesNotExist:
            refresh_token = None
        user = UserSerializer(user, context={'request': request}).data
    else:
        try:
            refresh_token = RefreshToken.objects.get(
                app=backend,
                user__uuid=user['uuid']).key
        except RefreshToken.DoesNotExist:
            refresh_token = None
    payload['token'] = token
    payload['user'] = user
    payload['refresh_token'] = refresh_token
    return payload
