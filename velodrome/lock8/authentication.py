import logging

from django import forms
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend as DjangoModelBackend
from django.core.cache import caches
from humanize import naturaldelta
import redis.exceptions
from rest_framework.authentication import TokenAuthentication

failed_logins_cache = caches['failed_logins']

logger = logging.getLogger(__name__)


class ModelBackend(DjangoModelBackend):
    """
    Like django.contrib.auth.backends.ModelBackend,
    But calls annotate_with_is_admin_of_lock8 when fetching user.
    """
    def authenticate(self, request, username=None, password=None, **kwargs):
        if is_login_blocked(username=username):
            max_attempts = settings.FAILED_LOGINS_MAX_ATTEMPTS
            duration = naturaldelta(settings.FAILED_LOGINS_COOLOFF)
            msg = (f'You have attempted to login {max_attempts} times '
                   f'unsuccessfully. The account is locked for {duration}.')
            raise forms.ValidationError(msg, code='invalid_login')
        return super().authenticate(request, username, password, **kwargs)

    def get_user(self, user_id):
        UserModel = get_user_model()
        try:
            user = (UserModel._default_manager
                    .annotate_with_is_admin_of_lock8()
                    .distinct()
                    .filter(pk=user_id)[:1]
                    .get())
        except UserModel.DoesNotExist:
            return None
        return user if self.user_can_authenticate(user) else None


class TokenAuthentication(TokenAuthentication):
    def authenticate_credentials(self, key):
        from velodrome.lock8.models import User

        (user, token) = super().authenticate_credentials(key)
        user = User.actives.filter(
            pk=user.pk).annotate_with_is_admin_of_lock8().first()
        return (user, token)


def _get_failed_login_keys(email=None, username=None):
    if email is not None:
        yield f'e:{email.lower()}'
    if username is not None:
        yield f'u:{username}'


def is_login_blocked(email=None, username=None):
    try:
        for key in _get_failed_login_keys(email, username):
            if (failed_logins_cache.get(key, 0) >=
                    settings.FAILED_LOGINS_MAX_ATTEMPTS):
                return True
        return False
    except redis.exceptions.ConnectionError as exc:
        logger.warning('Failed to connect to Redis: %r', exc, exc_info=True)
        return False


def register_failed_login(email=None, username=None, password_hash=None):
    try:
        for key in _get_failed_login_keys(email, username):
            lasthash_key = f'h:{key}'
            lasthash = failed_logins_cache.get(lasthash_key, None)
            if lasthash is None or lasthash != password_hash:
                try:
                    failed_logins_cache.incr(key)
                except ValueError:
                    failed_logins_cache.set(key, 1)
                # Update TTL.
                failed_logins_cache.expire(key, settings.FAILED_LOGINS_COOLOFF)
            failed_logins_cache.set(lasthash_key, password_hash)
    except redis.exceptions.ConnectionError as exc:
        logger.warning('Failed to connect to Redis: %r', exc, exc_info=True)


def clear_failed_logins(user):
    try:
        for key in _get_failed_login_keys(user.email, user.username):
            failed_logins_cache.delete(key)
    except redis.exceptions.ConnectionError as exc:
        logger.warning('Failed to connect to Redis: %r', exc, exc_info=True)
