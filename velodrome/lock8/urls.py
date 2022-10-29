from django.urls import include, path
from refreshtoken.views import delegate_jwt_token

from . import stripe
from .key_server_access import KeyServerAccessTokenView
from .router import router
from .views import (
    CurrentUserView, accept_terms_of_service, dashboard, debug_500plz,
    debug_logplz, debug_sleep, email_activation,
    email_GET_with_POST_activation, email_registration, get_clusters,
    localtokeninfo, password_forgot, password_reset, tokeninfo,
    verify_jwt_token,
)

urlpatterns = [
    path('jwt/social_auth/<str:backend>/', tokeninfo, name='tokeninfo'),
    path('jwt/verify/', verify_jwt_token, name='jwt-verify'),
    path('jwt/refresh_token/', delegate_jwt_token, name='jwt-refreshtoken'),
    path('jwt/login/', localtokeninfo, name='jwt-login'),
    path('dashboard/', dashboard, name='dashboard'),
    path('', include(router.urls)),
    path('registration/', email_registration, name='register'),
    # taken from django.contrib.auth.urls
    path('activate/<uuid:uuid>/<str:token>/',
         email_GET_with_POST_activation,
         name='activate'),
    path('activate/', email_activation, name='activate'),
    path('password/forgot/', password_forgot, name='password-forgot'),
    path('password/reset/', password_reset, name='password-reset'),
    path('clusters/', get_clusters, name='cluster-list'),
    path('stripe/', include(stripe)),
    path('me/', CurrentUserView.as_view(), name='me-detail'),
    path(
        'key-server-api-token/',
        KeyServerAccessTokenView.as_view(),
        name="get-key-server-api-token"
    ),
    path('me/accept_terms_of_service/', accept_terms_of_service,
         name='me-accept-terms-of-service'),

    # Debug views.
    # Allow to trigger ZeroDivisionError manually (e.g. to test Sentry).
    path('500plz', debug_500plz, name='500plz'),
    path('logplz', debug_logplz, name='logplz'),
    path('sleepplz', debug_sleep, name='sleepplz'),
]
