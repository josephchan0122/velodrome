from dal import autocomplete, forward
from dal_queryset_sequence.fields import QuerySetSequenceModelField
from dal_select2_queryset_sequence.widgets import QuerySetSequenceSelect2
from django import forms
from django.contrib.auth.forms import UserChangeForm
from django.core import validators
from django.utils.translation import ugettext_lazy as _
from mptt.forms import TreeNodeChoiceField
from queryset_sequence import QuerySetSequence
from refreshtoken.models import RefreshToken
from rest_framework.authtoken.models import Token

from .models import (
    Address, Affiliation, Alert, AlertMessage, AxaLock, Bicycle, BicycleModel,
    BicycleModelMaintenanceRule, ClientApp, Feature, Feedback,
    FeedbackCategory, Firmware, Invitation, Lock, LockFirmwareUpdate,
    NotificationMessage, Organization, OrganizationPreference, Photo, PlanPass,
    PricingScheme, ReadonlyTracking, RentalSession, RentingScheme, Reservation,
    SubscriptionPlan, SupportTicket, Task, TermsOfService,
    TermsOfServiceVersion, Trip, User, UserProfile, Zone,
)


class BaseModelForm(forms.ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Handle disabled fields.
        for formfield in self.fields.values():
            if formfield.disabled:
                # For django.contrib.gis.admin.widgets.OpenLayersWidget.
                formfield.widget.params['modifiable'] = False
                # "modifiable" seems to be enough, but let's be safe.
                formfield.widget.params['editable'] = False

            # Replace 'pk' in any widget's `forward` with instance PK.
            # This replaces the widget inline, and therefore has to handle the
            # replacement for when the form is used with another instance.
            widget = formfield.widget
            try:
                forwarded = widget.widget.forward
            except AttributeError:
                continue

            model_name = self.instance._meta.model_name
            for idx, f in enumerate(forwarded):
                if (f == 'pk' or (
                        isinstance(f, forward.Const) and f.dst == model_name)):
                    widget.widget.forward[idx] = forward.Const(
                        self.instance.pk, model_name)
                    break


class FacebookBicycleImportForm(forms.Form):
    organization = TreeNodeChoiceField(queryset=Organization.objects,
                                       required=True)
    import_file = forms.FileField(label=_('File to import'))


class GenericBicycleImportForm(forms.ModelForm):
    import_file = forms.FileField(label=_('File to import'))

    class Meta:
        model = Bicycle
        fields = ('organization', 'model',)
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
            'model': autocomplete.ModelSelect2(url='dal:bicyclemodel',
                                               forward=['organization']),
        }


class BulkLockOrgUpdateForm(forms.Form):
    organization = TreeNodeChoiceField(
        queryset=Organization.objects, required=True
    )
    import_file = forms.FileField(label=_('File to import'))


class MoveBicyclesToOrgForm(forms.ModelForm):
    ids = forms.CharField(label='', widget=forms.HiddenInput())
    organization = forms.ModelChoiceField(
        Organization.objects.all(),
        required=True,
        widget=autocomplete.ModelSelect2(url='dal:organization'),
    )
    model = forms.ModelChoiceField(
        BicycleModel.objects.all(),
        required=True,
        widget=autocomplete.ModelSelect2(url='dal:bicyclemodel',
                                         forward=['organization']),
    )

    class Meta:
        model = Bicycle
        fields = ('organization', 'model', 'ids')


class BulkLockCreationForm(forms.Form):
    lower_range = forms.IntegerField(
        label=_('First "counter" value for this batch'),
        validators=[
            validators.MinValueValidator(0),
            validators.MaxValueValidator(1e9)
        ]
    )
    upper_range = forms.IntegerField(
        label=_('Last "counter" value for this batch (exclusive)'),
        validators=[
            validators.MinValueValidator(0),
            validators.MaxValueValidator(1e9)
        ]
    )
    production_settings = forms.CharField(
        max_length=24,
        label=_('production_settings for this batch'),
        help_text=_('String that identifies uniquely the production batch'),
    )
    organization = TreeNodeChoiceField(queryset=Organization.objects,
                                       required=False)
    with_bikes = forms.BooleanField(
        label=_('Also create a bike for each lock automatically?'),
    )


class BulkAxaLockBulkClaiming(forms.Form):
    organization = TreeNodeChoiceField(queryset=Organization.objects,
                                       required=False)
    import_file = forms.FileField(label=_('File to import'))


class AssignDevicesToBicyclesForm(forms.Form):
    organization = TreeNodeChoiceField(
        queryset=Organization.objects, required=True
    )
    import_file = forms.FileField(label=_('File to import'))


class AddressForm(forms.ModelForm):
    class Meta:
        model = Address
        fields = ('__all__')
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
        }


class AffiliationForm(forms.ModelForm):
    class Meta:
        model = Affiliation
        fields = ('__all__')
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
            'user': autocomplete.ModelSelect2(url='dal:user'),
        }


class AxaLockForm(forms.ModelForm):
    class Meta:
        model = AxaLock
        fields = ('__all__')
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
        }


class _CausalityForm(autocomplete.FutureModelForm):
    causality = QuerySetSequenceModelField(
        queryset=QuerySetSequence(
            Bicycle.objects.all(),
            Lock.objects.all(),
            Feedback.objects.all(),
            Alert.objects.all(),
            BicycleModelMaintenanceRule.objects.all(),
            Zone.objects.all(),
        ),
        widget=QuerySetSequenceSelect2('dal:causality')
    )


class AlertForm(_CausalityForm):
    class Meta:
        model = Alert
        exclude = (
            'content_type',
            'object_id',
        )
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
            'user': autocomplete.ModelSelect2(url='dal:user'),
            'causality': autocomplete.ModelSelect2(url='dal:causality'),
            'owner': autocomplete.ModelSelect2(url='dal:user'),
        }


class AlertMessageForm(forms.ModelForm):
    class Meta:
        model = AlertMessage
        fields = ('__all__')
        widgets = {
            'user': autocomplete.ModelSelect2(url='dal:user'),
            'alert': autocomplete.ModelSelect2(url='dal:alert'),
            'causality': autocomplete.ModelSelect2(url='dal:causality'),
        }


class BicycleForm(BaseModelForm):
    class Meta:
        model = Bicycle
        fields = ('__all__')
        widgets = {
            'lock': autocomplete.ModelSelect2(
                url='dal:lock', forward=['organization', 'pk']),
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
            'photo': autocomplete.ModelSelect2(url='dal:photo'),
            'model': autocomplete.ModelSelect2(url='dal:bicyclemodel',
                                               forward=['organization']),
            'axa_lock': autocomplete.ModelSelect2(
                url='dal:axalock', forward=['organization', 'pk']),
        }


class BicycleModelForm(forms.ModelForm):
    class Meta:
        model = BicycleModel
        fields = ('__all__')
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
            'photo': autocomplete.ModelSelect2(url='dal:photo',
                                               forward=['organization']),
        }


class BicycleModelMaintenanceRuleForm(forms.ModelForm):
    class Meta:
        model = BicycleModelMaintenanceRule
        fields = ('__all__')
        widgets = {
            'bicycle_model': autocomplete.ModelSelect2(
                url='dal:bicyclemodel'
            ),
        }


class BulkFirmwareUpdateForm(forms.Form):
    firmwares = forms.ModelMultipleChoiceField(
        queryset=Firmware.objects.all(),
        widget=autocomplete.ModelSelect2Multiple(url='dal:firmware',
                                                 forward=['firmwares',
                                                          'organization'])
    )
    organization = forms.ModelChoiceField(
        queryset=Organization.objects.all(),
        widget=forms.HiddenInput())


class ClientAppForm(BaseModelForm):
    class Meta:
        model = ClientApp
        fields = '__all__'
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
            'user': autocomplete.ModelSelect2(url='dal:user'),
        }


class FeatureForm(forms.ModelForm):
    class Meta:
        model = Feature
        fields = '__all__'
        widgets = {
            'organizations': autocomplete.ModelSelect2Multiple(
                url='dal:organization')
        }


class SupportTicketForm(forms.ModelForm):
    class Meta:
        model = SupportTicket
        exclude = (
            'content_type',
            'object_id',
        )
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
            'owner': autocomplete.ModelSelect2(url='dal:user'),
            'bicycle': autocomplete.ModelSelect2(url='dal:bicycle'),
        }


class FeedbackForm(_CausalityForm):
    class Meta:
        model = Feedback
        exclude = (
            'content_type',
            'object_id',
        )
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
            'user': autocomplete.ModelSelect2(url='dal:user'),
            'category': autocomplete.ModelSelect2(url='dal:feedbackcategory'),
            'causality': autocomplete.ModelSelect2(url='dal:causality'),
        }


class FeedbackCategoryForm(forms.ModelForm):
    class Meta:
        model = FeedbackCategory
        fields = ('__all__')
        widgets = {
            'parent': autocomplete.ModelSelect2(url='dal:feedbackcategory'),
        }


class FirmwareForm(forms.ModelForm):
    class Meta:
        model = Firmware
        fields = ('__all__')
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
        }


class InvitationForm(forms.ModelForm):
    class Meta:
        model = Invitation
        fields = ('__all__')
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
            'user': autocomplete.ModelSelect2(url='dal:user',
                                              forward=['organization']),
        }


class LockForm(forms.ModelForm):
    class Meta:
        model = Lock
        fields = ('__all__')
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
        }


class LockFirmwareUpdateForm(forms.ModelForm):
    class Meta:
        model = LockFirmwareUpdate
        fields = ('__all__')
        widgets = {
            'lock': autocomplete.ModelSelect2(url='dal:lock'),
            'firmware': autocomplete.ModelSelect2(url='dal:firmware'),
        }


class LockFirmwareUpdateInlineForm(forms.ModelForm):
    class Meta:
        model = LockFirmwareUpdate
        fields = ('firmware',)
        widgets = {
            'firmware': autocomplete.ModelSelect2(url='dal:firmware',
                                                  forward=['firmware',
                                                           'organization'])
        }


class NotificationMessageForm(_CausalityForm):
    class Meta:
        model = NotificationMessage
        fields = ('__all__')
        exclude = (
            'content_type',
            'object_id',
        )
        widgets = {
            'user': autocomplete.ModelSelect2(url='dal:user'),
        }


class OrganizationForm(forms.ModelForm):
    class Meta:
        model = Organization
        fields = ('__all__')
        widgets = {
            'parent': autocomplete.ModelSelect2(url='dal:organization'),
            'feedback_category_tree': autocomplete.ModelSelect2(
                url='dal:feedbackcategory',
                forward=['name'],
            ),
            'stripe_account': autocomplete.ModelSelect2(
                url='dal:stripe_account'),
        }


class OrganizationPreferenceForm(forms.ModelForm):
    class Meta:
        model = OrganizationPreference
        fields = ('__all__')
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
        }


class PhotoForm(forms.ModelForm):
    class Meta:
        model = Photo
        fields = ('__all__')
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
        }


class PricingSchemeForm(forms.ModelForm):
    class Meta:
        model = PricingScheme
        fields = ('__all__')
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
            'bicycle_model': autocomplete.ModelSelect2(
                url='dal:bicyclemodel',
                forward=['organization']),
        }


class RefreshTokenForm(forms.ModelForm):
    class Meta:
        model = RefreshToken
        fields = ('__all__')
        widgets = {
            'user': autocomplete.ModelSelect2(url='dal:user'),
        }


class RentalSessionForm(forms.ModelForm):
    class Meta:
        model = RentalSession
        fields = ('__all__')
        widgets = {
            'user': autocomplete.ModelSelect2(url='dal:user'),
            'bicycle': autocomplete.ModelSelect2(url='dal:bicycle'),
            'subscription_plan': autocomplete.ModelSelect2(
                url='dal:subscriptionplan'),
            'pricing_scheme': autocomplete.ModelSelect2(
                url='dal:pricingscheme'),
            'charge': autocomplete.ModelSelect2(url='dal:charge'),
        }


class RentingSchemeForm(forms.ModelForm):
    class Meta:
        model = RentingScheme
        fields = ('__all__')
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
            'bicycle': autocomplete.ModelSelect2(url='dal:bicycle',
                                                 forward=['organization']),
        }


class ReservationForm(forms.ModelForm):
    class Meta:
        model = Reservation
        fields = ('__all__')
        widgets = {
            'bicycle': autocomplete.ModelSelect2(url='dal:bicycle'),
            'user': autocomplete.ModelSelect2(url='dal:user'),
        }


class SubscriptionPlanForm(forms.ModelForm):
    class Meta:
        model = SubscriptionPlan
        fields = ('__all__')
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
            'plan': autocomplete.ModelSelect2(url='dal:plan'),
            'pricing_scheme': autocomplete.ModelSelect2(
                url='dal:pricingscheme',
                forward=['organization'],
            ),
            'bicycle_model': autocomplete.ModelSelect2(
                url='dal:bicyclemodel',
                forward=['organization'],
            ),
        }


class PlanPassForm(forms.ModelForm):
    class Meta:
        model = PlanPass
        fields = ('__all__')
        widgets = {
            'subscription_plan': autocomplete.ModelSelect2(
                url='dal:subscriptionplan'),
            'user': autocomplete.ModelSelect2(url='dal:user'),
        }


class TaskForm(_CausalityForm):
    class Meta:
        model = Task
        exclude = (
            'content_type',
            'object_id',
        )
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
            'assignor': autocomplete.ModelSelect2(url='dal:user',
                                                  forward=['organization']),
            'assignee': autocomplete.ModelSelect2(url='dal:user',
                                                  forward=['organization']),
        }


class TermsOfServiceForm(forms.ModelForm):
    class Meta:
        model = TermsOfService
        fields = ('__all__')
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
            'version': autocomplete.ModelSelect2(
                url='dal:termsofserviceversion',
                forward=['organization'],
            ),
        }


class TermsOfServiceVersionForm(forms.ModelForm):
    class Meta:
        model = TermsOfServiceVersion
        fields = ('__all__')
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
        }


class TokenForm(forms.ModelForm):
    class Meta:
        model = Token
        fields = ('__all__')
        widgets = {
            'user': autocomplete.ModelSelect2(url='dal:user')
        }


class ReadonlyTrackingForm(BaseModelForm):
    class Meta:
        model = ReadonlyTracking
        fields = ('__all__')


class TripForm(BaseModelForm):
    class Meta:
        model = Trip
        fields = ('__all__')


class UserForm(UserChangeForm):
    class Meta:
        model = User
        fields = ('__all__')
        widgets = {
            'organizations': autocomplete.ModelSelect2(url='dal:organization'),
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
        }


class UserProfileForm(forms.ModelForm):
    class Meta:
        model = UserProfile
        fields = ('__all__')
        widgets = {
            'user': autocomplete.ModelSelect2(url='dal:user')
        }


class ZoneForm(forms.ModelForm):
    class Meta:
        model = Zone
        fields = ('__all__')
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
            'preferred_mechanic': autocomplete.ModelSelect2(
                url='dal:user',
                forward=['organization'],
            )
        }


class MoveOrCopyZoneToOrgForm(forms.ModelForm):
    ids = forms.CharField(label='', widget=forms.HiddenInput())
    move = forms.BooleanField(label='Move or Copy ? if false, a copy will be'
                              ' created.', initial=False, required=False)

    class Meta:
        model = Zone
        fields = ('organization', 'ids', 'move')
        widgets = {
            'organization': autocomplete.ModelSelect2(url='dal:organization'),
        }


class BicycleFilterSetForm(forms.Form):
    def clean(self):
        ordering = self.cleaned_data.get('ordering')
        bbox = self.cleaned_data.get('bbox')
        if (ordering and
                any(o in ('distance', '-distance') for o in ordering) and
                not bbox):
            raise forms.ValidationError(
                'bbox filter is required to sort on distance')
