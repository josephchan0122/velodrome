from rest_framework.throttling import SimpleRateThrottle


class SharedSecretUserRateThrottle(SimpleRateThrottle):
    rate = '6/minute'

    def get_cache_key(self, request, view):
        if request.user.is_authenticated:
            ident = request.user.pk
        else:
            ident = self.get_ident(request)

        obj = view.get_object()
        if obj:
            ident = '{}_{}-{}'.format(ident, obj._meta.model_name, obj.pk)

        return self.cache_format % {
            'scope': self.scope,
            'ident': ident
        }
