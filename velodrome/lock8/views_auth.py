import logging

from django.contrib.auth import login
from django.http import (
    HttpResponseBadRequest, HttpResponseForbidden, HttpResponseNotFound,
    HttpResponseRedirect,
)
from django.urls import reverse
from django.views.decorators.cache import never_cache
from django.views.decorators.csrf import csrf_exempt
from social_django.utils import psa

from .saml_api import SAMLAuth, extract_user_data

logger = logging.getLogger(__name__)


@never_cache
@csrf_exempt
@psa("/")
def saml_complete(request, backend, *args, **kwargs):
    """SAML authentication complete view
    """
    auth: SAMLAuth = request.backend
    data = auth.strategy.request_data()
    idp_name = data.get("RelayState")
    saml = auth._create_saml_auth(auth.get_idp(idp_name))
    saml.process_response()
    attributes = saml.get_attributes()
    if not attributes:
        msg = f"Attributes does not available from ipd {idp_name}"
        result = HttpResponseForbidden(msg)
        logger.warning(msg)
    else:
        org, user = extract_user_data(idp_name, attributes)
        if not org:
            msg = "Unknown organization"
            result = HttpResponseNotFound(msg)
            logger.warning(msg)
        elif user:
            request.backend = None
            request.user = user
            login(
                request,
                user,
                backend="velodrome.lock8.authentication.ModelBackend"
            )
            result = HttpResponseRedirect(reverse("admin:index"))
        else:
            msg = "Impossible to create user by attributes from IdP"
            logger.warning(msg)
            result = HttpResponseBadRequest(msg)

    return result
