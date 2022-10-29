from django.conf import settings
from django.core.exceptions import PermissionDenied


class LoadBalancerRouter:
    def db_for_read(self, model, **hints):
        if model._meta.app_label == 'lock8':
            if model._meta.model_name in ('readonlytracking', 'trip'):
                return settings.TRACKINGS_DB
        return None

    def db_for_write(self, model, **hints):
        if model._meta.model_name in ('readonlytracking', 'trip'):
            raise PermissionDenied('db_for_write with {}'.format(
                model._meta.model_name))
        return 'default'

    def allow_migrate(self, db, app_label, model_name=None, **hints):
        if db == settings.TRACKINGS_DB:
            return (app_label == 'lock8' and
                    model_name in ('readonlytracking', 'trip'))
        return None
