import functools
import logging
import os

from django.apps import AppConfig
from django.contrib.auth.signals import user_logged_in, user_login_failed
from django.contrib.auth.tokens import default_token_generator
from django.db.backends.signals import connection_created

logger = logging.getLogger(__name__)


class Lock8Config(AppConfig):
    name = 'velodrome.lock8'
    verbose_name = 'Lock8'

    def ready(self):
        from django.conf import settings
        from django.contrib.contenttypes.models import ContentType
        from reversion import revisions
        from .admin import adjust_pinax_stripe_admin

        from velodrome.lock8.authentication import (
            clear_failed_logins, register_failed_login,
        )

        revisions.register(ContentType)

        # Disconnect signal that would cause an UPDATE statement.
        if settings.CONFIGURATION == 'velodrome.settings.DevProdReadonly':
            from django.contrib.auth.models import update_last_login
            disconnected = user_logged_in.disconnect(
                update_last_login, dispatch_uid='update_last_login')
            assert disconnected is True

        # NOTE: this is run before the connection is setup/changed for tests.
        # https://code.djangoproject.com/ticket/22002
        if not settings.IS_TESTER and 'trackings' in settings.DATABASES:
            self.verify_trackings_connection()

        def _make_hash_value(original_make_hash_value, user, timestamp):
            value = original_make_hash_value(user, timestamp)
            return value + str(user.modified.replace(microsecond=0,
                                                     tzinfo=None))

        original_make_hash_value = default_token_generator._make_hash_value
        default_token_generator._make_hash_value = functools.partial(
            _make_hash_value, original_make_hash_value)

        adjust_pinax_stripe_admin()

        def handle_user_logged_in(sender, user, **kwargs):
            clear_failed_logins(user)

        def handle_user_login_failed(sender, credentials, **kwargs):
            register_failed_login(
                email=credentials.get('email', None),
                username=credentials.get('username', None),
                password_hash=credentials.get('password_hash', None))

        user_logged_in.connect(handle_user_logged_in, weak=False)
        user_login_failed.connect(handle_user_login_failed, weak=False)

        if settings.CONFIGURATION == 'velodrome.settings.DevProdReadonly':
            def connection_created_handler(connection, **kwargs):
                with connection.cursor() as cursor:
                    cursor.execute('SET default_transaction_read_only = true;')
            connection_created.connect(connection_created_handler, weak=False)

        if settings.ENVIRONMENT != 'dev':
            self._notify_sentry_for_new_release()

    def _notify_sentry_for_new_release(self):
        from raven.contrib.django.models import get_client
        raven_client = get_client()
        raven_client.captureMessage('new release.', level='info')

    def verify_trackings_connection(self):
        """Ensure the trackings DB connection exists during startup."""
        from django.conf import settings
        from django.db import connections

        if os.environ.get('VELODROME_SKIP_TRACKINGS_DB'):
            logger.info('verify_trackings_connection: skipped from env.')
            return

        t = connections['trackings']
        try:
            t.ensure_connection()
        except Exception as exc:
            logger.exception('Could not connect to trackings DB, '
                             'removing it from known databases: %r.', exc)
            del settings.DATABASES['trackings']
            assert 'trackings' not in connections.databases

            # Indicate this for the autoreloading runserver (subprocess).
            os.environ['VELODROME_SKIP_TRACKINGS_DB'] = 'true'
        else:
            t.close()
