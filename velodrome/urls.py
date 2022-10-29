from django.conf import settings
from django.conf.urls.static import static
from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path, re_path
import social_django.urls

import velodrome.advanced_devices.urls
import velodrome.custom_tagging.urls
import velodrome.features_flags.urls
import velodrome.lock8.dal
import velodrome.lock8.handlers
import velodrome.lock8.tsp
import velodrome.lock8.urls
from velodrome.lock8.views import debug_500plz, schema_view
import velodrome.lock8.views_auth

handler500 = velodrome.lock8.handlers.handler500


urlpatterns = [
    path('admin/', admin.site.urls),
    path('admin/500plz/', debug_500plz, name='admin_500plz'),
    path('admin/password_reset/',
         auth_views.PasswordResetView.as_view(),
         name='admin_password_reset'),
    path('admin/password_reset/done/',
         auth_views.PasswordResetDoneView.as_view(),
         name='password_reset_done'),
    path('reset/<str:uidb64>/<str:token>/',
         auth_views.PasswordResetConfirmView.as_view(),
         name='password_reset_confirm'),
    path('reset/done/',
         auth_views.PasswordResetCompleteView.as_view(),
         name='password_reset_complete'),
    path('', include(social_django.urls, namespace='social')),
    path(
         'saml-user/',
         velodrome.lock8.views_auth.saml_complete,
         name='saml-user-login',
         kwargs={'backend': 'saml'}
     ),
    path('api/', include((velodrome.lock8.urls, 'lock8'),
                         namespace='lock8')),
    path('autocomplete/', include((velodrome.lock8.dal, 'dal'),
                                  namespace='dal')),
    path('docs/',
         schema_view.with_ui('redoc', cache_timeout=60 * 15),
         name='api-docs'),
    re_path(r'swagger(?P<format>\.json|\.yaml)$',
            schema_view.without_ui(cache_timeout=None), name='schema-json'),
    path('swagger/',
         schema_view.with_ui('swagger', cache_timeout=None),
         name='schema-swagger-ui'),
    path('tsp/', include((velodrome.lock8.tsp, 'tsp'), namespace='tsp')),
    path(
         'devices-api/',
         include((velodrome.advanced_devices.urls, 'devices-api'), namespace='devices-api')  # noqa
    ),
    path(
         'api/features-flags/',
         include((velodrome.features_flags.urls, 'features-flags'), namespace='features-flags')  # noqa
    ),
    path(
        'api/custom-tagging/',
        include(
            (velodrome.custom_tagging.urls, 'custom-tagging'),
            namespace='custom-tagging'
        )
    ),
]

if "silk" in settings.INSTALLED_APPS:
    urlpatterns += [
        path('admin/silk/', include('silk.urls', namespace='silk')),
    ]

if "debug_toolbar" in settings.INSTALLED_APPS:
    import debug_toolbar
    urlpatterns += [
        path('__debug__/', include(debug_toolbar.urls)),
    ]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL,
                          document_root=settings.MEDIA_ROOT)
