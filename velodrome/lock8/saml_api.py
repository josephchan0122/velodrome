import typing
import uuid

from django.conf import settings
from django.db import transaction
from django.urls import reverse
from social_core.backends.saml import (
    OneLogin_Saml2_Auth, SAMLAuth as BaseSAMLAuth,
)
from social_django.strategy import DjangoStrategy

from .models import Organization, User


class SAMLAuth(BaseSAMLAuth):
    """System SAML auth adapter
    """
    use_port = False

    def __init__(
        self,
        strategy: typing.Optional[DjangoStrategy] = None,
        redirect_uri=None
    ):
        if redirect_uri:
            default_complete_url = reverse("social:complete", args=("saml", ))
            complete_url = reverse("saml-user-login")
            redirect_uri = redirect_uri.replace(
                default_complete_url, complete_url
            )

        return super().__init__(strategy, redirect_uri)

    def _create_saml_auth(self, idp):
        """Get an instance of OneLogin_Saml2_Auth"""
        config = self.generate_saml_config(idp)
        request_info = {
            "https": "on" if self.strategy.request_is_secure() else "off",
            "http_host": self.strategy.request_host(),
            "script_name": self.strategy.request_path(),
            "get_data": self.strategy.request_get(),
            "post_data": self.strategy.request_post(),
        }
        if self.use_port:
            request_info["server_port"] = self.strategy.request_port()

        return OneLogin_Saml2_Auth(request_info, config)


@transaction.atomic
def extract_user_data(idp: str, attrs: dict) -> typing.Tuple[
    typing.Optional[Organization], typing.Optional[User]
]:
    """Extract data of user from an IdP (identity provider).
    """
    conf = settings.SOCIAL_AUTH_SAML_ENABLED_IDPS.get(idp)
    if conf:
        mapping = conf["mapping"]
        default_org = ""
        organization = email = first_name = last_name = None
        org_field = "organization"
        email_field = mapping["email"]
        first_name_field = mapping["first_name"]
        last_name_field = mapping["last_name"]
        organization_conf = mapping["organization"]
        if organization_conf:
            org_field, default_org = organization_conf

        organization_name = attrs.get(org_field) or default_org
        if organization_name:
            if isinstance(organization_name, list):
                organization_name, *_ = organization_name

            organization = Organization.objects.filter(
                name=organization_name
            ).order_by("-parent").first()

        if not organization:
            return organization, None

        if email_field:
            email = attrs.get(email_field)
            if email and isinstance(email, list):
                email, *_ = email

            if first_name_field:
                first_name = attrs.get(first_name_field)
                if first_name and isinstance(first_name, list):
                    first_name, *_ = first_name
            if last_name_field:
                last_name = attrs.get(last_name_field)
                if last_name and isinstance(last_name, list):
                    last_name, *_ = last_name

        if email:
            user = User.objects.filter(email=email).first()
            if not user:
                # create
                user: User = User.objects.create_user(
                    username=first_name,
                    email=email,
                    password=uuid.uuid4().hex
                )
                if first_name:
                    user.first_name = first_name
                if last_name:
                    user.last_name = last_name

                user.organization = organization
                user.is_staff = True
                user.is_active = True
                user.save()

            return organization, user

    return (None, None)
