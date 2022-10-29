from django.apps import AppConfig

from .const import DJANGO_APP_NAME


class BaseConfig(AppConfig):
    name = f'velodrome.{DJANGO_APP_NAME}'
    verbose_name = 'Tagging system'
