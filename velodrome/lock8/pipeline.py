import functools
import logging
import urllib.parse

from django.db import transaction

from velodrome.celery import send_welcome_email_task
from velodrome.lock8.utils import create_affiliations_if_whitelisted

from .social_backends import Lock8FacebookOAuth2, Lock8GoogleOAuth2

logger = logging.getLogger(__name__)


def send_welcome_email(strategy, details, user=None, is_new=False, **kwargs):
    if not is_new:
        return {'is_new': is_new}
    if user.email:
        transaction.on_commit(functools.partial(
            send_welcome_email_task.delay,
            user.pk))
    else:
        logger.info('User created without email. strategy: %s user: %s',
                    strategy, user)


def user_avatar(strategy, details, user=None, social=None, backend=None,
                uid=None, *args, **kwargs):
    """Include avatar url"""
    if user:
        user_changed = False
        if social is not None:
            extra_data = social.extra_data
            current_avatar = user.avatar
            if isinstance(backend, Lock8GoogleOAuth2):
                avatar = extra_data.get('picture', '')
            elif isinstance(backend, Lock8FacebookOAuth2):
                if uid is not None:
                    params = {'type': 'large'}
                    avatar = '?'.join(
                        (backend.IMAGE_DATA_URL.format(uid),
                         urllib.parse.urlencode(params)))
                else:
                    avatar = ''
            else:
                raise NotImplementedError
            user_changed |= current_avatar != avatar
            user.avatar = avatar
        if user_changed:
            strategy.storage.user.changed(user)


def user_create_refreshtoken(strategy, details, user=None, backend=None,
                             is_new=False, *args, **kwargs):
    from refreshtoken.models import RefreshToken

    if user and is_new:
        RefreshToken.objects.create(user=user, app=backend.name)


def create_affiliations(strategy, details, user=None, is_new=False,
                        *args, **kwargs):
    if user and is_new:
        create_affiliations_if_whitelisted(user)
