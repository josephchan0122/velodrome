import types
import typing

from django.apps import AppConfig

from .const import DJANGO_APP_NAME


class BaseConfig(AppConfig):
    """Configuration.
    """

    name = f"velodrome.{DJANGO_APP_NAME}"
    verbose_name = "Advanced devices management"
    api_module: typing.Optional[types.ModuleType] = None

    @property
    def api(self) -> types.ModuleType:
        """Main api module for external apps.
        """
        if self.api_module is None:
            from . import api
            self.api_module = api

        return self.api_module
