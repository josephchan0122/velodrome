from dal import autocomplete
from dal_select2_queryset_sequence.views import Select2QuerySetSequenceView
from django.contrib.auth.mixins import AccessMixin
from django.db.models import Q
from django.urls import path
from pinax.stripe.models import Account, Charge, Plan
from queryset_sequence import QuerySetSequence
from rest_framework.request import Request

from .models import (
    Alert, AxaLock, Bicycle, BicycleModel, BicycleModelMaintenanceRule,
    Feedback, FeedbackCategory, Firmware, Lock, LockFirmwareUpdate,
    Organization, Photo, PricingScheme, SubscriptionPlan,
    TermsOfServiceVersion, User,
)


class PermissionCheckMixin(AccessMixin):
    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated and request.user.is_admin_of_lock8:
            return super().dispatch(request, *args, **kwargs)
        return self.handle_no_permission()


class BaseAutocomplete(PermissionCheckMixin, autocomplete.Select2QuerySetView):
    skip_version_check = True

    def _get_user_and_qs(self, parser_context=None):
        user = self.request.user
        request = Request(self.request, parser_context=parser_context)
        request.user = user
        qs = self.model.get_queryset(request=request).order_by('-modified')
        return user, qs


class CausalityAutocomplete(PermissionCheckMixin, Select2QuerySetSequenceView):
    skip_version_check = True

    def get_queryset(self):
        user = self.request.user
        organizations = user.get_descendants_managed_organizations()
        bicycles = Bicycle.objects.filter(organization__in=organizations)
        locks = Lock.objects.filter(organization__in=organizations)
        feedbacks = Feedback.objects.filter(organization__in=organizations)
        alerts = Alert.objects.filter(organization__in=organizations)
        bmmrs = BicycleModelMaintenanceRule.objects.filter(
            bicycle_model__organization__in=organizations)
        if self.q:
            bicycles = bicycles.filter(name__istartswith=self.q)
            locks = locks.filter(serial_number__istartswith=self.q)
            feedbacks = feedbacks.filter(user__email__istartswith=self.q)
            alerts = alerts.filter(
                Q(bicycles__name__istartswith=self.q) |
                Q(locks__serial_number__istartswith=self.q)
            )
            bmmrs = bmmrs.filter(bicycle_model__name__istartswith=self.q)

        qs = QuerySetSequence(bicycles, locks, feedbacks, alerts, bmmrs)

        qs = self.mixup_querysets(qs)
        return qs


class StripeAccountAutocomplete(BaseAutocomplete):
    model = Account

    def get_queryset(self):
        qs = self.model.objects.all().order_by('-created_at')
        if self.q:
            qs = qs.filter(business_name__istartswith=self.q)
        return qs


class AlertAutocomplete(BaseAutocomplete):
    model = Alert

    def get_queryset(self):
        _, qs = self._get_user_and_qs()
        if self.q:
            qs = qs.filter(Q(locks__serial_number__istartswith=self.q) |
                           Q(bicycles__name__istartswith=self.q))
        return qs


class AxaLockAutocomplete(BaseAutocomplete):
    model = AxaLock

    def get_queryset(self):
        user, qs = self._get_user_and_qs()
        organization = self.forwarded.get('organization')
        if organization:
            qs = qs.filter(organization__pk=organization)
        if self.q:
            qs = qs.filter(uid__istartswith=self.q)
        bicycle = self.forwarded.get('bicycle')
        if bicycle:
            qs = qs.filter(Q(bicycle__isnull=True) | Q(bicycle=bicycle))
        return qs


class BicycleAutocomplete(BaseAutocomplete):
    model = Bicycle

    def get_queryset(self):
        user, qs = self._get_user_and_qs()
        organization = self.forwarded.get('organization')
        if organization:
            qs = qs.filter(organization__pk=organization)
        if self.q:
            qs = qs.filter(name__istartswith=self.q)
        return qs


class BicycleModelAutocomplete(BaseAutocomplete):
    model = BicycleModel

    def get_queryset(self):
        user, qs = self._get_user_and_qs()
        organization = self.forwarded.get('organization')
        if organization:
            qs = qs.filter(organization__pk=organization)
        if self.q:
            qs = qs.filter(name__istartswith=self.q)
        return qs


class ChargeAutocomplete(BaseAutocomplete):
    model = Charge

    def get_queryset(self):
        qs = self.model.objects.all().order_by('-created_at')
        if self.q:
            qs = qs.filter(customer__user__email__istartswith=self.q)
        return qs


class BicycleModelMaintenanceRuleAutocomplete(BaseAutocomplete):
    model = BicycleModelMaintenanceRule

    def get_queryset(self):
        _, qs = self._get_user_and_qs()
        if self.q:
            qs = qs.filter(description__istartswith=self.q)
        return qs


class FeedbackCategoryAutocomplete(BaseAutocomplete):
    model = FeedbackCategory

    def get_queryset(self):
        user, qs = self._get_user_and_qs()
        if 'name' in self.forwarded:
            # Autocomplete from OrganizationForm
            # return only root nodes
            qs = qs.filter(level=0)
        if self.q:
            qs = qs.filter(name__istartswith=self.q)
        return qs


class FirmwareAutocomplete(BaseAutocomplete):
    model = Firmware

    def get_queryset(self):
        _, qs = self._get_user_and_qs()

        predicate = Q()
        if self.q:
            predicate &= (Q(version__istartswith=self.q) |
                          Q(name__istartswith=self.q))
        if 'organization' in self.forwarded:
            predicate &= Q(organization_id=self.forwarded['organization'])
        return qs.filter(predicate)


class LockAutocomplete(BaseAutocomplete):
    model = Lock

    def get_queryset(self):
        user, qs = self._get_user_and_qs()
        organization = self.forwarded.get('organization')
        if organization:
            qs = qs.filter(organization__pk=organization)
        if self.q:
            qs = qs.filter(serial_number__istartswith=self.q)
        bicycle = self.forwarded.get('bicycle')
        if bicycle:
            qs = qs.filter(Q(bicycle__isnull=True) | Q(bicycle=bicycle))
        return qs


class LockFirmwareUpdateAutocomplete(BaseAutocomplete):
    model = LockFirmwareUpdate

    def get_queryset(self):
        user = self.request.user
        qs = self.model.objects.filter(
            lock__organization__in=user.get_descendants_managed_organizations()
        )
        if self.q:
            qs = qs.filter(firmware__version__istartswith=self.q)
        return qs


class OrganizationAutocomplete(BaseAutocomplete):
    model = Organization

    def get_queryset(self):
        _, qs = self._get_user_and_qs()
        if self.q:
            qs = qs.filter(name__istartswith=self.q)
        return qs


class PlanAutocomplete(BaseAutocomplete):
    model = Plan

    def get_queryset(self):
        qs = self.model.objects.all().order_by('-created_at')
        if self.q:
            qs = qs.filter(name__istartswith=self.q)
        return qs


class PhotoAutocomplete(BaseAutocomplete):
    model = Photo

    def get_queryset(self):
        user, qs = self._get_user_and_qs()
        organization = self.forwarded.get('organization')
        if organization:
            qs = qs.filter(organization__pk=organization)
        if self.q:
            qs = qs.filter(image__istartswith=self.q)
        return qs


class PricingSchemeAutocomplete(BaseAutocomplete):
    model = PricingScheme

    def get_queryset(self):
        _, qs = self._get_user_and_qs()
        organization = self.forwarded.get('organization')
        if organization:
            qs = qs.filter(organization__pk=organization)
        if self.q:
            qs = qs.filter(name__istartswith=self.q)
        return qs


class SubscriptionPlanAutocomplete(BaseAutocomplete):
    model = SubscriptionPlan

    def get_queryset(self):
        _, qs = self._get_user_and_qs()
        if self.q:
            qs = qs.filter(name__istartswith=self.q)
        return qs


class TermsOfServiceVersionAutocomplete(BaseAutocomplete):
    model = TermsOfServiceVersion

    def get_queryset(self):
        _, qs = self._get_user_and_qs()
        organization = self.forwarded.get('organization')
        if organization:
            qs = qs.filter(organization__pk=organization)
        if self.q:
            qs = qs.filter(label__istartswith=self.q)
        return qs


class UserAutocomplete(BaseAutocomplete):
    model = User

    def get_queryset(self):
        user, qs = self._get_user_and_qs()
        organization = self.forwarded.get('organization')
        if organization:
            qs = qs.filter(affiliation__organization__pk=organization)
        if self.q:
            qs = qs.filter(Q(first_name__istartswith=self.q) |
                           Q(last_name__istartswith=self.q) |
                           Q(email__istartswith=self.q) |
                           Q(username__istartswith=self.q))
        return qs


urlpatterns = [
    path('stripe_account/', StripeAccountAutocomplete.as_view(),
         name='stripe_account'),
    path('axalock/', AxaLockAutocomplete.as_view(), name='axalock'),
    path('causality/', CausalityAutocomplete.as_view(), name='causality'),
    path('alert/', AlertAutocomplete.as_view(), name='alert'),
    path('bicycle/', BicycleAutocomplete.as_view(), name='bicycle'),
    path('bicyclemodel/', BicycleModelAutocomplete.as_view(),
         name='bicyclemodel'),
    path('maintenancerule/',
         BicycleModelMaintenanceRuleAutocomplete.as_view(),
         name='maintenancerule'),
    path('charge/', ChargeAutocomplete.as_view(), name='charge'),
    path('feedbackcategory/', FeedbackCategoryAutocomplete.as_view(),
         name='feedbackcategory'),
    path('firmware/', FirmwareAutocomplete.as_view(), name='firmware'),
    path('lock/', LockAutocomplete.as_view(), name='lock'),
    path('lockfirmwareupdate/',
         LockFirmwareUpdateAutocomplete.as_view(),
         name='lockfirmwareupdate'),
    path('organization/', OrganizationAutocomplete.as_view(),
         name='organization'),
    path('plan/', PlanAutocomplete.as_view(), name='plan'),
    path('photo/', PhotoAutocomplete.as_view(), name='photo'),
    path('pricingscheme/', PricingSchemeAutocomplete.as_view(),
         name='pricingscheme'),
    path('subscriptionplan/', SubscriptionPlanAutocomplete.as_view(),
         name='subscriptionplan'),
    path('termsofserviceversion/',
         TermsOfServiceVersionAutocomplete.as_view(),
         name='termsofserviceversion'),
    path('user/', UserAutocomplete.as_view(), name='user'),
]
