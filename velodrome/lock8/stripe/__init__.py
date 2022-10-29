import functools
from urllib.parse import urlencode

from django.conf import settings
from django.shortcuts import redirect
from django.urls import path
import pinax.stripe.actions.accounts
from pinax.stripe.models import Account
import requests
from rest_framework import exceptions, serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from ..models import Organization
from ..permissions import CustomPermissions


class StripeOauthInputSerializer(serializers.Serializer):
    code = serializers.CharField(required=False)
    state = serializers.UUIDField(required=True)
    error_description = serializers.CharField(required=False)


@api_view(['GET'])
@permission_classes(
    permission_classes=(
        functools.partial(CustomPermissions, ('lock8.stripe_oauth',)),))
def get_client_id(request):
    return Response({'client_id': settings.STRIPE_CLIENT_ID})


@api_view(['GET'])
@permission_classes((AllowAny,))
def redirect_handler(request):
    serializer = StripeOauthInputSerializer(data=request.query_params)
    serializer.is_valid(raise_exception=True)
    organization_uuid = serializer.validated_data['state']
    try:
        organization = Organization.objects.get(uuid=organization_uuid)
    except Organization.DoesNotExist:
        raise exceptions.PermissionDenied()
    try:
        code = serializer.validated_data['code']
    except KeyError:
        error_description = serializer.validated_data['error_description']
        params = urlencode({'message': error_description})
        return redirect(
            f'{settings.FRONTEND_URL}/organisation-settings?{params}')

    response = requests.post(
        'https://connect.stripe.com/oauth/token',
        json={'grant_type': 'authorization_code',
              'code': code},
        headers={'Authorization': f'Bearer {settings.PINAX_STRIPE_SECRET_KEY}'}
    )
    try:
        response.raise_for_status()
    except requests.RequestException as exc:
        error = response.json()
        raise exceptions.ValidationError(
            f'Error during account creation: {error["error_description"]}',
            code=error['error']) from exc
    data = response.json()
    stripe_account_id = data['stripe_user_id']
    stripe_publishable_key = data['stripe_publishable_key']
    account, created = Account.objects.get_or_create(
        stripe_id=stripe_account_id,
        defaults={
            'stripe_publishable_key': stripe_publishable_key,
        })
    organization.stripe_account = account
    organization.save()

    if created:
        pinax.stripe.actions.accounts.sync_account_from_stripe_data(
            account.stripe_account)
    else:
        account.stripe_publishable_key = stripe_publishable_key
        account.save()

    params = urlencode({'message': 'Account connected successfully.'})
    return redirect(f'{settings.FRONTEND_URL}/organisation-settings?{params}')


urlpatterns = [
    path('client_id/', get_client_id, name='stripe-client_id'),
    path('redirect/', redirect_handler, name='stripe-redirect'),
]
