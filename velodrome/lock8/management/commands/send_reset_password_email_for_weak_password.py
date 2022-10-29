import secrets
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.core.cache import caches
from django.core.management.base import BaseCommand
from django.db import transaction
from django.db.models import Q

SENTINEL = object()


class Command(BaseCommand):
    def add_arguments(self, parser):
        parser.add_argument('--dry-run', action='store_true')
        parser.add_argument('--noa-only', action='store_true')

    @transaction.atomic
    def handle(self, *args, **options):
        from velodrome.lock8.models import Affiliation, Organization, User
        from velodrome.lock8.utils import send_email

        dry_run = options.get('dry_run')
        if dry_run:
            settings.EMAIL_BACKEND = 'django.core.mail.backends.console.EmailBackend'  # noqa
        cache = caches['crm']
        if options.get('noa_only'):
            root_org = Organization.get_root_org()
            predicate = Q(
                affiliation__role__in=[
                    Affiliation.FLEET_OPERATOR,
                    Affiliation.ADMIN],
                affiliation__organization_id=root_org.pk)
        else:
            predicate = Q(
                affiliation__role__in=[
                    Affiliation.FLEET_OPERATOR,
                    Affiliation.ADMIN])
        predicate &= Q(social_auth__user__isnull=True)
        users = User.actives.filter(predicate).distinct()
        total = users.count()
        for i, user in enumerate(users, start=1):
            cache_key = f'{__name__}-{user.pk}'
            value = cache.get(cache_key, SENTINEL)
            user_str = f'{user} (pk={user.pk})'
            if value is not SENTINEL:
                self.stdout.write(f'[{i}/{total}] Skipping user: {user_str}')
                continue
            if not user.has_usable_password():
                self.stdout.write(f'[{i}/{total}] Skipping user: {user_str} for unusable password')  # noqa: E501
                continue
            self.stdout.write(f'[{i}/{total}] Processing user: {user_str})')
            if not dry_run:
                cache.set(cache_key, None)
            user.set_password(secrets.token_hex(16))
            if not user.is_active:
                # don't send email to those users.
                # but still change their password.
                if not dry_run:
                    user.save()
                continue
            if not dry_run:
                user.save()
            token = default_token_generator.make_token(user)
            encoded_email = urlencode({'email': user.email})
            reset_url = f'{settings.FRONTEND_URL}/reset/{token}/{user.uuid}/?{encoded_email}'  # noqa
            context = {'reset_url': reset_url,
                       'username': user.display_name}

            org = user.get_org_for_email()
            subject = (f"{org.name} "
                       f"- {settings.RESET_EMAIL_SUBJECT}")
            send_email(
                subject, [user.email],
                'email/fleet_op_password_vulnerability.txt',
                template_html='email/fleet_op_password_vulnerability.html',
                context=context)
