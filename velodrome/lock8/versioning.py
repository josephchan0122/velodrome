from django.conf import settings
import drf_yasg
from rest_framework.versioning import AcceptHeaderVersioning


class AcceptHeaderVersioning(AcceptHeaderVersioning):
    invalid_version_message = (
        'Invalid API version. '
        'Please provide it in the "Accept" header, '
        'e.g. "Accept: application/json; version={}".'.format(
            settings.REST_FRAMEWORK['ALLOWED_VERSIONS'][-1]))

    def determine_version(self, request, *args, **kwargs):
        self.request = request
        return super().determine_version(request, *args, **kwargs)

    def is_allowed_version(self, version):
        """Accept only allowed version (skipping default_version == None).

        Ref: https://github.com/tomchristie/django-rest-framework/pull/4370"""

        if version is None:
            # Accept missing version with DRF's browsable API.
            if self.request.accepted_media_type.partition(';')[0] in (
                    'text/html', 'application/openapi+json'):
                return True

            if isinstance(self.request.accepted_renderer,
                          drf_yasg.renderers._SpecRenderer):
                return True

        return version in self.allowed_versions
