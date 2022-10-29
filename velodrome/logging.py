from raven.contrib.django.handlers import SentryHandler


class SentryHandler(SentryHandler):

    def filter(self, record):
        if record.name == 'django.request':
            if getattr(record, 'status_code', None) in (403, 404):
                return False
            if getattr(record, 'funcName') == 'handle_uncaught_exception':
                # status_code 500: handled by Sentry already
                return False
        elif record.name == 'django.security.DisallowedHost':
            return False

        return super().filter(record)
