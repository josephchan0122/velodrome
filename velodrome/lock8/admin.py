import datetime as dt
from functools import reduce
import logging
import operator
import uuid

from concurrency.api import disable_concurrency
from django.contrib import admin, messages
from django.contrib.admin import helpers
from django.contrib.admin.options import csrf_protect_m
from django.contrib.admin.utils import lookup_needs_distinct
import django.contrib.admin.views.main
from django.contrib.auth import admin as auth_admin, get_permission_codename
from django.contrib.gis.admin import OSMGeoAdmin
from django.core.exceptions import (
    MultipleObjectsReturned, PermissionDenied, ValidationError,
)
from django.core.paginator import Paginator
from django.db import connections, router, transaction
from django.db.models.aggregates import Count
from django.db.models.query import Q
from django.forms import Media
from django.forms.models import BaseInlineFormSet
from django.http import HttpResponseRedirect
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.utils.functional import cached_property
from django.utils.safestring import mark_safe
from django.utils.translation import ugettext_lazy as _
from fsm_admin.mixins import FSMTransitionMixin
from mptt.admin import MPTTModelAdmin
from refreshtoken.models import RefreshToken
from rest_framework.authtoken.admin import TokenAdmin
from rest_framework_jwt import utils
from reversion.admin import VersionAdmin

from .forms import (
    AddressForm, AffiliationForm, AlertForm, AlertMessageForm,
    AssignDevicesToBicyclesForm, AxaLockForm, BicycleForm, BicycleModelForm,
    BicycleModelMaintenanceRuleForm, BulkFirmwareUpdateForm,
    BulkLockCreationForm, BulkLockOrgUpdateForm, ClientAppForm,
    FacebookBicycleImportForm, FeatureForm, FeedbackCategoryForm, FeedbackForm,
    FirmwareForm, GenericBicycleImportForm, InvitationForm,
    LockFirmwareUpdateForm, LockFirmwareUpdateInlineForm, LockForm,
    MoveBicyclesToOrgForm, MoveOrCopyZoneToOrgForm, NotificationMessageForm,
    OrganizationForm, OrganizationPreferenceForm, PhotoForm, PlanPassForm,
    PricingSchemeForm, ReadonlyTrackingForm, RefreshTokenForm,
    RentalSessionForm, RentingSchemeForm, ReservationForm,
    SubscriptionPlanForm, SupportTicketForm, TaskForm, TermsOfServiceForm,
    TermsOfServiceVersionForm, TokenForm, TripForm, UserForm, UserProfileForm,
    ZoneForm,
)
from .jwt_extensions import jwt_payload_handler
from .models import (
    TRACKING_FIELDS, Address, Affiliation, Alert, AlertMessage, AxaLock,
    AxaLockStates, Bicycle, BicycleModel, BicycleModelMaintenanceRule,
    BicycleStates, BicycleType, ClientApp, Feature, Feedback, FeedbackCategory,
    Firmware, Invitation, Lock, LockFirmwareUpdate, NotificationMessage,
    Organization, OrganizationPreference, Photo, PlanPass, PricingScheme,
    ReadonlyTracking, RentalSession, RentingScheme, Reservation,
    SubscriptionPlan, SupportTicket, Task, TermsOfService,
    TermsOfServiceVersion, Trip, User, UserProfile, Zone, private_storage,
)
from .utils import reverse_query

logger = logging.getLogger(__name__)

ADMIN_TRACKING_FIELDS = TRACKING_FIELDS + ('private_tracking',
                                           'public_tracking')

TokenAdmin.form = TokenForm

original_revision_view = VersionAdmin.revision_view


def revision_view(self, request, object_id, version_id, extra_context=None):
    with disable_concurrency():
        return original_revision_view(self, request, object_id, version_id,
                                      extra_context=extra_context)


VersionAdmin.revision_view = revision_view


def get_field(model, lookup):
    """Lookup a field on a model via string representation ('foo__bar')."""
    field = None
    m = model
    for f in lookup.split('__'):
        meta = m._meta
        field = meta.get_field(f)
        if field.remote_field:
            m = field.remote_field.model
    return field


def _display_image(image, style=None):
    if image:
        alt = str(image)
        try:
            url = image.url
        except AttributeError:
            url = str(image)
        return mark_safe(
            "<img src='%s' alt='%s' title='%s' %s/>" % (
                url, alt, alt, "style='%s'" % style if style else '',
            ))
    return '-'


def _display_image_list(image):
    return _display_image(image, 'height:3ex; margin:-1ex 0')


def _display_image_changeview(image):
    return _display_image(image)


class ApproximatePaginator(Paginator):
    estimated_count = True

    @cached_property
    def count(self):
        """
        Returns the total number of objects, across all pages.
        """
        from django.db import connections

        qs = self.object_list
        if qs.query.where:
            self.estimated_count = False
            return super().count
        model = qs.model
        cursor = connections[self.object_list.db].cursor()

        cursor.execute('SELECT n_live_tup FROM pg_stat_all_tables '
                       ' WHERE relname = %s', (model._meta.db_table,))
        c = cursor.fetchone()[0]
        if c == 0:
            # Might be 0 on (read-only?!) replicas.
            cursor.execute('SELECT reltuples FROM pg_class '
                           ' WHERE relname = %s', (model._meta.db_table,))
            c = int(cursor.fetchone()[0])
        return c


class ChangeList(django.contrib.admin.views.main.ChangeList):
    """A custom changelist to prefetch related fields for 'user'."""
    def get_queryset(self, request):
        qs = super().get_queryset(request)

        list_display = self.list_display
        assert 'owner' not in list_display
        assert ('owner_list_name' not in list_display or
                'owner' in self.list_select_related)
        if 'user' in list_display:
            qs = qs.prefetch_related('user__affiliations',
                                     'user__organizations')
        if 'owner_list_name' in list_display:
            qs = qs.prefetch_related('owner__social_auth')
        return qs


# Monkey-patch the base class used by other apps, e.g. pinax_stripe.
django.contrib.admin.views.main.ChangeList = ChangeList


class BaseAdmin(admin.ModelAdmin):
    list_display = ('created',)
    disabled_fields = ()

    def view_on_site(self, obj):
        """Use get_absolute_url directly to check for NoReverseMatch there."""
        try:
            url = obj.get_absolute_url()
        except AttributeError:
            return None
        return None if url == '' else url

    def get_form(self, *args, **kwargs):
        """Handle custom disabled_fields list."""
        form = super().get_form(*args, **kwargs)
        for field_name in self.disabled_fields:
            try:
                form.base_fields[field_name].disabled = True
            except KeyError:
                # Happens with DSS, where the field is in readonly_fields.
                pass
        return form

    def get_search_results(self, request, queryset, search_term):
        """
        Overwrite to handle '=foo' as exact search.

        Ref: https://code.djangoproject.com/ticket/26184
        """
        # Apply keyword searches.
        def construct_search(field_name):
            if field_name.startswith('^'):
                return "%s__istartswith" % field_name[1:]
            elif field_name.startswith('='):
                return "%s__exact" % field_name[1:]
            elif field_name.startswith('@'):
                return "%s__search" % field_name[1:]
            else:
                return "%s__icontains" % field_name

        use_distinct = False
        search_fields = self.get_search_fields(request)
        if search_fields and search_term:
            orm_lookups = [construct_search(str(search_field))
                           for search_field in search_fields]
            or_queries = []
            for bit in search_term.split():
                for orm_lookup in orm_lookups:
                    field = get_field(self.model,
                                      orm_lookup.rpartition('__')[0])
                    try:
                        field.get_db_prep_value(bit, connections[queryset.db])
                    except ValidationError as e:  # e.g. ValueError: badly formed hexadecimal UUID string  # noqa
                        # Never-matching Q object.
                        or_queries.append(Q(pk__in=[]))
                    else:
                        or_queries.append(Q(**{orm_lookup: bit}))
            if or_queries:
                queryset = queryset.filter(reduce(operator.or_, or_queries))
            if not use_distinct:
                for search_spec in orm_lookups:
                    if lookup_needs_distinct(self.opts, search_spec):
                        use_distinct = True
                        break

        return queryset, use_distinct


class StamenGeoModelAdmin(OSMGeoAdmin):
    map_template = 'gis/admin/stamen.html'

    @property
    def media(self):
        stamen_js = 'https://stamen-maps.a.ssl.fastly.net/js/tile.stamen.js'
        return super().media + Media(js=[stamen_js])


class FSMModelMixin(FSMTransitionMixin):
    fsm_field = ['state']

    def revisionform_view(self, request, version, *args, **kwargs):
        """
        https://django-concurrency.readthedocs.org/en/latest/cookbook.html#recover-deleted-record-with-django-reversion
        Disable concurrency when reverting objects.
        """
        queryset = self.get_queryset(request)
        # XXX disable at Model level for the current thread.
        with disable_concurrency(queryset.model):
            return super().revisionform_view(request, version, *args, **kwargs)

    def get_form(self, request, obj, *args, **kwargs):
        """
        Hook into the form to allow for validation.

        This calls the transition with parameter `dry_run=True` to trigger
        the transition's validation without persisting the outcome.
        This will make it show up with the call to the forms `is_valid` in the
        admin's `changelist_view`.
        """
        form = super().get_form(request, obj, *args, **kwargs)
        fsm_field, transition = self._get_requested_transition(request)
        if transition:
            form._fsm_transition = transition

            def _full_clean(self):
                super(type(self), self).full_clean()
                transition = self._fsm_transition
                try:
                    transition_func = getattr(self.instance, transition)
                except AttributeError:
                    pass
                else:
                    try:
                        with transaction.atomic():
                            transition_func(dry_run=True)
                    except ValidationError as e:
                        self._update_errors(e)

            form.full_clean = _full_clean
        return form


class OwnerableModelAdminMixin(object):
    def owner_list_name(self, obj):
        return obj.owner.display_name
    owner_list_name.short_description = 'Owner'

    def save_model(self, request, obj, form, change):
        if not change or obj.owner is None:
            obj.owner = request.user
            obj.save()
        return super().save_model(request, obj, form, change)


class OwnerableInlineFormset(BaseInlineFormSet):
    def save_new(self, form, commit=True):
        obj = super().save_new(form, commit=False)
        obj.owner = self.request.user
        if commit:
            obj.save()
        return obj

    def save_existing(self, form, instance, commit=True):
        obj = super().save_existing(form, instance, commit=False)
        obj.owner = self.request.user
        if commit:
            obj.save()
            return obj


class OwnerableInlineModelAdminMixin(object):
    "This mixin will use OwnerableInlineFormset and set request on it."
    formset = OwnerableInlineFormset

    def get_formset(self, request, obj=None, **kwargs):
        formset = super().get_formset(request, obj, **kwargs)
        formset.request = request
        return formset


class OrganizationNameFilter(admin.SimpleListFilter):
    title = _('Organization')
    parameter_name = 'organization'

    def lookups(self, request, model_admin):
        return [(org.pk, org.name) for org in
                Organization.objects.all().order_by('name')]

    def queryset(self, request, queryset):
        value = self.value()
        if value is not None:
            return queryset.filter(**{self.parameter_name: value})


class OrganizationUUIDFilter(OrganizationNameFilter):
    parameter_name = 'organization_uuid'

    def lookups(self, request, model_admin):
        return [(org.uuid, org.name) for org in
                Organization.objects.all().order_by('name')]


class FirmwareUpdateFilter(admin.SimpleListFilter):
    title = _('Firmware updates')
    parameter_name = 'firmwares'

    def lookups(self, request, model_admin):
        return [('{}_{}'.format(fw.version, fw.chip),
                 '{} ({})'.format(fw.version, fw.get_chip_display()))
                for fw in Firmware.objects.all()] + [
                        ('None', '(None)'),
                ] + [('None_' + chip, '(No {})'.format(chip_name))
                     for chip, chip_name in Firmware.CHIPS]

    def queryset(self, request, queryset):
        value = self.value()
        if value is not None:
            if value == 'None':
                return queryset.filter(**{
                    self.parameter_name + '__isnull': True})
            if value.startswith('None_'):
                _, chip = value.split('_', 1)
                return queryset.exclude(**{
                    self.parameter_name + '__chip': chip})
            version, chip = value.split('_', 1)
            predicate = {}
            if len(version):
                predicate['firmwares__version'] = version
            if len(chip):
                predicate['firmwares__chip'] = chip
            return queryset.filter(**predicate)


class AbstractFirmwareVersionsFilter(admin.SimpleListFilter):
    def lookups(self, request, model_admin):
        fieldname, key = self.parameter_name.split('__')
        return sorted(set((d[key], d[key])
                          for d in Lock.objects
                          .filter(**{'firmware_versions__has_key': key})
                          .order_by('firmware_versions')
                          .values_list('firmware_versions', flat=True)))

    def queryset(self, request, queryset):
        value = self.value()
        if value:
            queryset = queryset.filter(**{self.parameter_name: value})
        return queryset


class FirmwareVersionsNordicFilter(AbstractFirmwareVersionsFilter):
    title = _('Firmware versions (nordic)')
    parameter_name = 'firmware_versions__nordic'


class FirmwareVersionsXmegaFilter(AbstractFirmwareVersionsFilter):
    title = _('Firmware versions (xmega)')
    parameter_name = 'firmware_versions__xmega'


class FirmwareVersionsMercuryFilter(AbstractFirmwareVersionsFilter):
    title = _('Firmware versions (mercury)')
    parameter_name = 'firmware_versions__mercury'


@admin.register(Address)
class AddressAdmin(OwnerableModelAdminMixin,
                   VersionAdmin,
                   admin.ModelAdmin):
    form = AddressForm
    list_filter = (OrganizationNameFilter,)
    readonly_fields = ('uuid', 'created', 'modified', 'owner')
    search_fields = ('uuid',)
    list_select_related = ('organization',)


class AffiliationRoleFilter(admin.SimpleListFilter):
    title = _('Role')
    parameter_name = 'affiliation__role'

    def lookups(self, request, model_admin):
        return Affiliation.ROLES

    def queryset(self, request, queryset):
        value = self.value()
        if value is not None:
            return queryset.filter(**{self.parameter_name: value}).distinct()


@admin.register(Affiliation)
class AffiliationAdmin(BaseAdmin):
    form = AffiliationForm
    list_display = (
        'id', 'user', 'organization', 'role') + BaseAdmin.list_display
    search_fields = ('=uuid', 'user__email', 'organization__name')
    list_filter = ('role', OrganizationNameFilter,)
    readonly_fields = ('uuid', 'created', 'modified')
    list_select_related = ('organization', 'user')


@admin.register(AxaLock)
class AxaLockAdmin(OwnerableModelAdminMixin, FSMModelMixin, admin.ModelAdmin):
    form = AxaLockForm
    list_display = ('id', 'remote_id', 'uid', 'lock_model', 'software_version',
                    'lock_status')
    search_fields = ('=uid', '=remote_id', '=uuid')
    list_filter = (OrganizationNameFilter,)
    readonly_fields = ('id', 'remote_id', 'attributes', 'state', 'uuid',
                       'created', 'modified', 'owner')
    list_select_related = ('organization',)

    change_list_template = 'lock8/admin/change_list_export_axa_lock.html'

    def get_urls(self):
        return [path('claim_axa_locks/',
                     self.admin_site.admin_view(
                         self.claim_axa_locks_from_spreadsheet),
                     name='claim_axa_locks'),
                ] + super().get_urls()

    def claim_axa_locks_from_spreadsheet(self, request, *args):
        from velodrome.celery import claim_axa_locks_from_spreadsheet_task

        context = {}
        form = BulkLockOrgUpdateForm(request.POST or None,
                                     request.FILES or None,)
        if request.POST and form.is_valid():
            import_file = form.cleaned_data['import_file']
            file_id = 'claim_axa_locks/{}'.format(uuid.uuid4())
            private_storage.save(file_id, import_file)

            organization = form.cleaned_data['organization']
            org_pk = organization.pk if organization else None

            claim_axa_locks_from_spreadsheet_task.delay(file_id, org_pk,
                                                        request.user.pk)
            context['result'] = file_id

        context['form'] = form
        context['opts'] = self.model._meta

        adminForm = helpers.AdminForm(form, [], {}, {}, model_admin=self)
        media = self.media + adminForm.media
        context['media'] = media

        return TemplateResponse(
            request, ['lock8/admin/import.html'], context
        )

    claim_axa_locks_from_spreadsheet.short_description = (
        'Claim Axa Locks from Spreadsheet')

    def declare_axa_locks_from_list_stored(self, request, queryset):
        from velodrome.celery import declare_axa_lock_state_task

        i = 0
        for i, axa_lock in enumerate(
            queryset.exclude(state=AxaLockStates.STORED.value),
            start=1
        ):
            declare_axa_lock_state_task.delay(
                axa_lock.pk,
                AxaLockStates.STORED.value
            )
        self.message_user(
            request, f'Declaring {i} lock{"s" if i != 1 else ""} as STORED.'
        )
    declare_axa_locks_from_list_stored.short_description = (
        'Declare selected locks as STORED'
    )

    actions = [declare_axa_locks_from_list_stored, ]


@admin.register(ClientApp)
class ClientAppAdmin(OwnerableModelAdminMixin, VersionAdmin, admin.ModelAdmin):
    form = ClientAppForm
    list_display = ('id', 'uuid', 'name', 'organization', 'scopes',
                    'remote_uuid')
    search_fields = ('=uuid', 'name', '=remote_uuid')
    readonly_fields = ('uuid', 'created', 'modified', 'owner')


@admin.register(Feature)
class FeatureAdmin(OwnerableModelAdminMixin,
                   VersionAdmin,
                   admin.ModelAdmin):
    form = FeatureForm
    list_display = ('id', 'name', 'created', 'modified')
    search_fields = ('=uuid', 'name')
    readonly_fields = ('uuid', 'created', 'modified', 'owner')


@admin.register(Firmware)
class FirmwareAdmin(FSMModelMixin,
                    OwnerableModelAdminMixin,
                    VersionAdmin,
                    admin.ModelAdmin):
    form = FirmwareForm
    list_display = ('id', 'organization', 'chip', 'name', 'version', 'state')
    search_fields = ('=uuid', 'name', 'version')
    list_filter = ('state', 'chip', OrganizationNameFilter,)
    readonly_fields = ('uuid', 'state', 'created', 'modified', 'owner')


@admin.register(LockFirmwareUpdate)
class LockFirmwareUpdateAdmin(OwnerableModelAdminMixin, BaseAdmin):
    form = LockFirmwareUpdateForm
    list_display = ('id', 'lock', 'firmware', 'created', 'modified')
    readonly_fields = ('uuid', 'state', 'created', 'modified', 'owner')
    search_fields = ('=uuid', '=lock__serial_number')
    list_filter = ('firmware__chip', 'firmware__version',)


class LockFirmwareUpdateInline(OwnerableInlineModelAdminMixin,
                               admin.TabularInline):
    form = LockFirmwareUpdateInlineForm
    model = LockFirmwareUpdate
    max_num = len(Firmware.CHIPS)
    extra = 1
    formset = OwnerableInlineFormset


class AdminBooleanFilter(admin.SimpleListFilter):
    qs_lookup = None

    def lookups(self, request, model_admin):
        return [('True', 'Yes'), ('False', 'No')]

    def queryset(self, request, queryset):
        value = self.value()
        if value is not None:
            if value == 'True':
                value = True
            elif value == 'False':
                value = False
            else:
                raise ValueError('%s must be "True" or "False"' % (
                    self.parameter_name))

            lookup = ('%s__isnull' % self.parameter_name
                      if self.qs_lookup is None else self.qs_lookup)
            return queryset.filter(**{
                lookup: value
            })


class LockIsUnpairedFilter(AdminBooleanFilter):
    title = 'unpaired'
    parameter_name = 'unpaired'
    qs_lookup = 'bicycle__isnull'


@admin.register(Lock)
class LockAdmin(FSMModelMixin, OwnerableModelAdminMixin, VersionAdmin,
                admin.ModelAdmin):

    def get_firmware_updates(self, obj):
        firmwares = obj.firmwares.all()
        return (', '.join([str(fw.version) for fw in firmwares])
                if firmwares else '-')
    get_firmware_updates.short_description = 'Assigned firmware'

    form = LockForm
    list_display = ('id', 'serial_number', 'bleid', 'organization', 'state',
                    'firmware_versions', 'get_firmware_updates', 'bicycle',
                    'modified', 'created')
    list_filter = ('state', 'locked_state', 'mounted_state',
                   LockIsUnpairedFilter,
                   OrganizationNameFilter,
                   FirmwareVersionsNordicFilter,
                   FirmwareVersionsXmegaFilter,
                   FirmwareVersionsMercuryFilter,
                   FirmwareUpdateFilter)
    fsm_field = ('state', 'locked_state', 'mounted_state')
    readonly_fields = ('uuid', 'state', 'created', 'modified', 'owner',
                       'locked_state', 'mounted_state', 'firmware_versions',
                       ) + ADMIN_TRACKING_FIELDS + ('display_linked_bicycle',)
    search_fields = ('=uuid', 'serial_number', 'firmware_versions', '=iccid',
                     '=bleid', 'bicycle__name')
    list_select_related = ('bicycle', 'organization')
    exclude = ('latest_gps_pdop', 'randblock')

    inlines = [LockFirmwareUpdateInline]

    change_list_template = 'lock8/admin/change_list_export.html'

    def display_linked_bicycle(self, obj):
        bicycle = obj.bicycle
        if bicycle is None:
            return bicycle
        url = reverse('admin:lock8_bicycle_change', args=(bicycle.pk,))
        return mark_safe(f'<a href="{url}">{bicycle}</a>')
    display_linked_bicycle.short_description = 'Bicycle'

    def get_queryset(self, request):
        return super().get_queryset(request).prefetch_related('firmwares')

    def get_urls(self):
        return [path('bulk_creation/',
                     self.admin_site.admin_view(
                         self.process_bulk_creation),
                     name='bulk_lock_creation'),
                path('bulk_lock_org_update/',
                     self.admin_site.admin_view(
                         self.process_bulk_lock_org_update),
                     name='bulk_lock_org_update'),
                path('bulk_firmware_update/',
                     self.admin_site.admin_view(
                         self.process_bulk_firmware_update),
                     name='bulk_firmware_update'),
                ] + super().get_urls()

    def process_bulk_creation(self, request, *args):
        context = {}
        form = BulkLockCreationForm(request.POST or None,
                                    request.FILES or None,
                                    initial={'backward': True})
        if request.POST and form.is_valid():
            from velodrome.celery import bulk_lock_creation
            lower_range = form.cleaned_data['lower_range']
            upper_range = form.cleaned_data['upper_range']
            organization = form.cleaned_data['organization']
            production_settings = form.cleaned_data['production_settings']
            bulk_lock_creation.delay(
                request.user.pk,
                lower_range,
                upper_range,
                organization.pk if organization is not None else None,
                production_settings,
            )
            context['result'] = {
                'message': 'You will receive an email report shortly'}

        context['form'] = form
        context['opts'] = self.model._meta
        return TemplateResponse(request, ['lock8/admin/bulk_creation.html'],
                                context)

    process_bulk_creation.short_description = 'Create Locks in Bulk'

    def process_bulk_lock_org_update(self, request, *args):
        from velodrome.celery import bulk_lock_org_update

        context = {}
        form = BulkLockOrgUpdateForm(request.POST or None,
                                     request.FILES or None,)
        if request.POST and form.is_valid():
            import_file = form.cleaned_data['import_file']
            file_id = 'bulk_lock_org_update/{}'.format(uuid.uuid4())
            private_storage.save(file_id, import_file)

            organization = form.cleaned_data['organization']
            org_pk = organization.pk if organization else None

            bulk_lock_org_update.delay(file_id, org_pk, request.user.pk)
            context['result'] = file_id

        context['form'] = form
        context['opts'] = self.model._meta

        adminForm = helpers.AdminForm(form, [], {}, {}, model_admin=self)
        media = self.media + adminForm.media
        context['media'] = media

        return TemplateResponse(
            request, ['lock8/admin/import.html'], context
        )

    process_bulk_lock_org_update.short_description = (
        'Update Organization of new locks in bulk'
    )

    def bulk_activation(self, request, queryset):
        i = 0
        for i, lock in enumerate(queryset.all(), start=1):
            lock.activate()

        self.message_user(request, 'Activated {} lock{}.'.format(
            i, 's' if i != 1 else ''))
    bulk_activation.short_description = 'Activate selected Locks'

    def bulk_decommission(self, request, queryset):
        i = 0
        for i, lock in enumerate(queryset.all(), start=1):
            lock.decommission()

        self.message_user(request, 'Decommissioned {} lock{}.'.format(
            i, 's' if i != 1 else ''))
    bulk_decommission.short_description = 'Decommission selected Locks'

    def process_bulk_firmware_update(self, request):
        context = {}
        form = BulkFirmwareUpdateForm(
            request.POST or None,
            request.FILES or None,
            initial={'organization': request.GET['organization']})
        if request.POST and form.is_valid():
            queryset = Lock.objects.filter(
                pk__in=request.GET['pks'].split(','))
            firmwares = form.cleaned_data['firmwares']
            for lock in queryset:
                for firmware in firmwares:
                    if lock.firmwares.filter(chip=firmware.chip).exists():
                        LockFirmwareUpdate.objects.filter(
                            lock=lock, firmware__chip=firmware.chip).delete()
                    LockFirmwareUpdate.objects.create(
                        lock=lock, firmware=firmware,
                        owner=request.user)
            self.message_user(request,
                              '{} Lock updated to new firmwares'.format(
                                  queryset.count()))
            return HttpResponseRedirect(reverse('admin:lock8_lock_changelist'))

        context['form'] = form
        context['opts'] = self.model._meta
        adminForm = helpers.AdminForm(form, [], {}, {}, model_admin=self)
        media = self.media + adminForm.media
        context['media'] = media
        return TemplateResponse(request, ['lock8/admin/import.html'], context)

    def bulk_firmware_update(self, request, queryset):
        assert not (queryset
                    .annotate(count_org=Count('organization'))
                    .filter(count_org__gt=1)
                    .exists())
        return HttpResponseRedirect(
            'bulk_firmware_update/?organization={}&pks={}'.format(
                queryset[0].organization_id,
                ','.join(map(str, queryset.values_list('pk', flat=True)))))

    actions = [bulk_activation, bulk_firmware_update, bulk_decommission]


@admin.register(SupportTicket)
class SupportTicketAdmin(FSMModelMixin, OwnerableModelAdminMixin, VersionAdmin,
                         StamenGeoModelAdmin, admin.ModelAdmin):
    form = SupportTicketForm
    list_display = ('id', 'organization', 'message', 'location', 'category',
                    'state', 'created')
    list_filter = ('state', 'category')
    readonly_fields = ('uuid', 'state', 'created', 'modified')
    search_fields = ('=uuid', 'message')
    list_select_related = ('organization', 'owner', 'bicycle')


@admin.register(Feedback)
class FeedbackAdmin(FSMModelMixin, OwnerableModelAdminMixin, VersionAdmin,
                    admin.ModelAdmin):
    form = FeedbackForm
    list_display = ('id', 'organization', 'message', 'category', 'state',
                    'created', 'image',)
    list_filter = ('state', 'category')
    readonly_fields = ('uuid', 'state', 'created', 'modified', 'owner')
    search_fields = ('=uuid',)
    raw_id_fields = ('content_type',)
    list_select_related = ('organization', 'user', 'category')


@admin.register(FeedbackCategory)
class FeedbackCategoryAdmin(MPTTModelAdmin):
    form = FeedbackCategoryForm
    list_display = ('id', 'name', 'parent', 'modified', 'created')
    readonly_fields = ('uuid', 'created', 'modified',)
    search_fields = ('=uuid', 'name')
    list_select_related = ('parent',)


@admin.register(Alert)
class AlertAdmin(FSMModelMixin, VersionAdmin, admin.ModelAdmin):
    form = AlertForm
    list_display = ('id', 'alert_type', 'organization', 'message', 'state',
                    'created')
    list_filter = ('state', 'alert_type', OrganizationNameFilter)
    readonly_fields = ('uuid', 'state', 'created', 'modified')
    search_fields = ('=uuid',)
    raw_id_fields = ('content_type',)
    list_select_related = ('organization', 'user')


@admin.register(AlertMessage)
class AlertMessageAdmin(FSMModelMixin, admin.ModelAdmin):
    form = AlertMessageForm
    list_display = ('id', 'alert', 'user', 'state', 'created')
    list_filter = ('state',)
    readonly_fields = ('uuid', 'state', 'created', 'modified',)
    search_fields = ('=uuid',)
    list_select_related = ('alert', 'user')


@admin.register(NotificationMessage)
class NotificationMessageAdmin(FSMModelMixin, admin.ModelAdmin):
    form = NotificationMessageForm
    list_display = ('id', 'causality', 'user', 'state', 'created')
    list_filter = ('state',)
    readonly_fields = ('uuid', 'state', 'created', 'modified',)
    search_fields = ('=uuid',)
    list_select_related = ('user',)


class OrganizationUsesPaymentsFilter(admin.SimpleListFilter):
    title = 'Uses payments'
    parameter_name = 'uses_payments'

    def lookups(self, request, model_admin):
        return [(1, 'Yes'), (0, 'No')]

    def queryset(self, request, queryset):
        value = self.value()
        if value is not None:
            if value == '1':
                return queryset.filter(stripe_account__authorized=True)
            return queryset.exclude(stripe_account__authorized=True)


@admin.register(Organization)
class OrganizationAdmin(FSMModelMixin, VersionAdmin, OwnerableModelAdminMixin,
                        MPTTModelAdmin):
    form = OrganizationForm
    list_display = ('id', 'name', 'display_image_list', 'parent',
                    'is_open_fleet', 'state')
    list_filter = ('state', OrganizationUsesPaymentsFilter, 'is_whitelabel')
    exclude = ('icon',)
    readonly_fields = ('uuid', 'state', 'created', 'modified', 'owner')
    search_fields = ('=uuid', 'name',)
    list_select_related = ('parent',)

    def display_image_list(self, obj):
        return _display_image_list(obj.image)
    display_image_list.__name__ = 'Image'


@admin.register(OrganizationPreference)
class OrganizationPreferenceAdmin(VersionAdmin, FSMModelMixin,
                                  OwnerableModelAdminMixin, admin.ModelAdmin):
    form = OrganizationPreferenceForm
    list_display = ('id', 'name', 'organization', 'state', 'modified',
                    'created')
    readonly_fields = ('uuid', 'created', 'modified', 'owner', 'state')
    search_fields = ('=uuid', 'name', 'organization__name')
    list_select_related = ('organization',)


@admin.register(Photo)
class PhotoAdmin(OwnerableModelAdminMixin, FSMModelMixin, VersionAdmin,
                 admin.ModelAdmin):
    def display_image_list(self, obj):
        return _display_image_list(obj.image)
    display_image_list.short_description = 'Image'

    def display_image(self, obj):
        return _display_image_changeview(obj.image)
    display_image.short_description = 'Image'

    form = PhotoForm

    list_display = ('id', 'organization', 'display_image_list', 'state')
    list_filter = ('state', OrganizationNameFilter)
    list_select_related = ('organization',)
    readonly_fields = ('display_image', 'uuid', 'state', 'created', 'modified',
                       'owner')
    search_fields = ('=uuid',)


@admin.register(PricingScheme)
class PricingSchemeAdmin(OwnerableModelAdminMixin, FSMModelMixin, VersionAdmin,
                         admin.ModelAdmin):
    def testable_computations(self, obj=None):
        return mark_safe('<br/>'.join(
            f'A rental duration of <b>{d}</b> will cost'
            f' <b>{self.compute_amount_for_duration(d)}</b> cents' for d in (
                dt.timedelta(minutes=5),
                dt.timedelta(minutes=15),
                dt.timedelta(minutes=29),
                dt.timedelta(minutes=31),
                dt.timedelta(minutes=45),
                dt.timedelta(minutes=61),
                dt.timedelta(minutes=90),
                dt.timedelta(minutes=91),
                dt.timedelta(hours=2),
                dt.timedelta(hours=3),
                dt.timedelta(hours=5),
                dt.timedelta(hours=6),
                dt.timedelta(hours=7),
                dt.timedelta(hours=8),
                dt.timedelta(hours=9),
                dt.timedelta(hours=10),
            )))

    def display_linked_subscriptionplan(self, obj):
        subscription_plan = obj.subscription_plan
        if subscription_plan:
            url = reverse('admin:lock8_subscriptionplan_change', args=(
                subscription_plan.pk,))
            return mark_safe(f'<a href="{url}">{subscription_plan}</a>')
    display_linked_subscriptionplan.short_description = 'SubscriptionPlan'

    def display_tax_percent(self, obj):
        if not obj:
            return None
        return obj.organization.get_preference('tax_percent')
    display_tax_percent.short_description = 'Organization tax_percent'

    def display_has_subscriptionplan(self, obj):
        return obj.subscription_plan is not None
    display_has_subscriptionplan.short_description = 'Has SP?'
    display_has_subscriptionplan.boolean = True
    display_has_subscriptionplan.admin_order_field = 'subscription_plan'

    form = PricingSchemeForm
    list_display = ('id', 'name', 'organization', 'bicycle_model',
                    'owner_list_name', 'state',
                    'display_has_subscriptionplan',
                    'modified', 'created')
    list_filter = ('state', OrganizationNameFilter,)
    readonly_fields = ('uuid', 'state', 'created', 'modified', 'owner',
                       'display_linked_subscriptionplan',
                       'display_tax_percent',
                       testable_computations)
    search_fields = ('=uuid', 'name')
    list_select_related = ('organization', 'bicycle_model', 'owner',
                           'subscription_plan')


class WhiteLabelOrganizationNameFilter(admin.SimpleListFilter):
    title = _('Whitelabel Organization Membership')
    parameter_name = 'organization'

    def lookups(self, request, model_admin):
        return [(org.pk, org.name) for org in
                Organization.objects
                .filter(is_whitelabel=True).order_by('name')]

    def queryset(self, request, queryset):
        value = self.value()
        if value is not None:
            return queryset.filter(**{self.parameter_name: value})


class AffiliationOrganizationFilter(WhiteLabelOrganizationNameFilter):
    title = _('Organization Membership')
    parameter_name = 'affiliation__organization'

    def lookups(self, request, model_admin):
        return [(org.pk, org.name) for org in
                Organization.objects.all().order_by('name')]


class UserHasSocialAuthFilter(AdminBooleanFilter):
    title = 'connected to social account'
    parameter_name = 'social_auth'


@admin.register(User)
class UserAdmin(OwnerableModelAdminMixin, FSMModelMixin, VersionAdmin,
                auth_admin.UserAdmin):
    form = UserForm

    def has_add_permission(self, request):
        return False

    def get_queryset(self, request):
        """Prefetch organizations for member_of/display_affiliations."""
        return super().get_queryset(request).prefetch_related(
            'organizations',
            'social_auth',
        )

    def display_avatar_list(self, obj):
        return _display_image_list(obj.avatar)
    display_avatar_list.short_description = 'Avatar'

    def display_avatar(self, obj):
        return _display_image_changeview(obj.avatar)
    display_avatar.short_description = 'Avatar'

    def display_affiliations(self, obj):
        affs = obj.affiliations.all()
        return ', '.join(f'{x.organization} ({x.role})'
                         for x in affs) if affs else None
    display_affiliations.short_description = 'Affiliations'

    def display_has_social_auth(self, obj):
        return obj.social_auth.exists()
    display_has_social_auth.boolean = True
    display_has_social_auth.short_description = 'Social auth?'

    def display_social_auth_providers(self, obj):
        providers = [x.provider for x in obj.social_auth.all()]
        return ', '.join(providers) if providers else self.empty_value_display
    display_social_auth_providers.short_description = 'Social auth providers'

    list_display = auth_admin.UserAdmin.list_display + (
        'display_avatar_list', 'member_of', 'is_active',
        'display_has_social_auth', 'state', 'last_login',
        'created', 'modified')

    list_filter = auth_admin.UserAdmin.list_filter + (
        'state',
        AffiliationRoleFilter,
        WhiteLabelOrganizationNameFilter,
        UserHasSocialAuthFilter,
        AffiliationOrganizationFilter,
    )
    WRITABLE_FIELDS_FOR_SUPERUSER = (
        'is_superuser', 'groups', 'user_permissions',
    )
    readonly_fields = auth_admin.UserAdmin.readonly_fields + (
        'uuid', 'state', 'created', 'modified', 'owner', 'last_login',
        'display_avatar', 'representative', 'display_affiliations',
        'display_social_auth_providers',
    ) + WRITABLE_FIELDS_FOR_SUPERUSER
    fieldsets = auth_admin.UserAdmin.fieldsets + (
        ('Whitelabel/organization properties', {'fields': (
            'organization',
            'display_affiliations',
        )}),
        (_('Administrative properties'), {'fields': (
            'uuid', 'state', 'created', 'modified', 'owner',
            'display_avatar', 'representative',
            'display_social_auth_providers',
        )}),
    )
    search_fields = auth_admin.UserAdmin.search_fields + ('=uuid', 'email',)

    def get_readonly_fields(self, request, obj=None):
        # Only allow superuser to change is_superuser etc.
        if request.user.is_superuser:
            return {
                x for x in self.readonly_fields
                if x not in self.WRITABLE_FIELDS_FOR_SUPERUSER
            }
        return self.readonly_fields

    def generate_jwt(self, request, queryset):
        if not request.user.is_superuser:
            raise PermissionDenied
        try:
            user = queryset.get()
        except User.DoesNotExist:
            self.message_user(request, 'Please select one user.',
                              level=messages.ERROR)
        except MultipleObjectsReturned:
            self.message_user(request, 'Please select only one user.',
                              level=messages.ERROR)
        else:
            jwt_token = utils.jwt_encode_handler(jwt_payload_handler(user))

            self.message_user(request,
                              'The JWT token for user {} is {!r}'.format(
                                  user, jwt_token))
    generate_jwt.short_description = 'Display JWT token for user'

    def resend_email_action(self, request, queryset):
        if not request.user.is_superuser:
            raise PermissionDenied
        try:
            user = queryset.get()
        except User.DoesNotExist:
            self.message_user(request, 'Please select one user.',
                              level=messages.ERROR)
        except MultipleObjectsReturned:
            self.message_user(request, 'Please select only one user.',
                              level=messages.ERROR)
        else:
            if user.is_active:
                user.send_password_reset_email()
                msg = f'Sent password-reset email for {user}.'
            else:
                user.send_activation_email()
                msg = f'Sent activation email for {user}.'
            self.message_user(request, msg, messages.SUCCESS)
    resend_email_action.short_description = \
        'Send activation or reset-password email'

    actions = [generate_jwt, resend_email_action]


@admin.register(Bicycle)
class BicycleAdmin(OwnerableModelAdminMixin, FSMModelMixin, VersionAdmin,
                   admin.ModelAdmin):
    form = BicycleForm
    list_filter = ('state', OrganizationNameFilter, 'model')
    list_display = ('id', 'name', 'model', 'serial_number', 'organization',
                    'lock', 'axa_lock', 'state',
                    'get_gps_timestamp',
                    'get_last_cellular_update')
    readonly_fields = (
        'short_id',
        'latest_gps_timestamp',
        'uuid',
        'state',
        'created',
        'modified',
        'owner') + ADMIN_TRACKING_FIELDS
    search_fields = ('=uuid', 'name', '=serial_number', '=lock__serial_number')
    list_select_related = ('lock', 'organization', 'model', 'model__photo',
                           'model__type', 'axa_lock',
                           'private_tracking')
    exclude = ('latest_gps_pdop',)

    change_list_template = 'lock8/admin/bicycle_change_list.html'

    def get_last_cellular_update(self, obj):
        return obj.private_tracking.modified if obj.private_tracking else None
    get_last_cellular_update.short_description = 'Last cellular update'
    get_last_cellular_update.admin_order_field = 'private_tracking__modified'

    def get_gps_timestamp(self, obj):
        return (obj.private_tracking.gps_timestamp
                if obj.private_tracking else None)
    get_gps_timestamp.short_description = 'Last GPS update'
    get_gps_timestamp.admin_order_field = 'private_tracking__gps_timestamp'

    def get_urls(self):
        return [path('fb_bulk_import/',
                     self.admin_site.admin_view(
                         self.process_fb_bulk_import),
                     name='fb_bulk_import'),
                path('generic_bulk_import/',
                     self.admin_site.admin_view(
                         self.process_generic_bulk_import),
                     name='generic_bulk_import'),
                path('move_to_org/',
                     self.admin_site.admin_view(
                         self.move_selected_bicycles),
                     name='move_to_org'),
                path('assign_devices_to_bicycles/',
                     self.admin_site.admin_view(
                         self.assign_devices_to_bicycles),
                     name='assign_devices_to_bicycles'),
                ] + super().get_urls()

    def process_fb_bulk_import(self, request, *args):
        from velodrome.celery import fb_bulk_bicycle_import
        context = {}

        form = FacebookBicycleImportForm(request.POST or None,
                                         request.FILES or None)
        if request.POST and form.is_valid():
            import_file = form.cleaned_data['import_file']
            file_id = 'fb_bulk_bicycle_import/{}'.format(uuid.uuid4())
            private_storage.save(file_id, import_file)
            organization = form.cleaned_data['organization']
            org_pk = organization.pk if organization else None
            fb_bulk_bicycle_import.delay(file_id, request.user.pk, org_pk)
            context['result'] = file_id

        context['form'] = form
        context['opts'] = self.model._meta
        adminForm = helpers.AdminForm(form, [], {}, {}, model_admin=self)
        media = self.media + adminForm.media
        context['media'] = media
        return TemplateResponse(request, ['lock8/admin/import.html'],
                                context)

    process_fb_bulk_import.short_description = ('Facebook Import of Bicycles'
                                                ' from spreadsheet')

    def process_generic_bulk_import(self, request, *args):
        from velodrome.celery import generic_bulk_bicycle_import
        context = {}

        form = GenericBicycleImportForm(request.POST or None,
                                        request.FILES or None)
        if request.POST and form.is_valid():
            import_file = form.cleaned_data['import_file']
            file_id = 'generic_bulk_bicycle_import/{}'.format(uuid.uuid4())
            private_storage.save(file_id, import_file)
            organization = form.cleaned_data['organization']
            bicycle_model = form.cleaned_data['model']
            org_pk = organization.pk if organization else None
            bicycle_model_pk = bicycle_model.pk if bicycle_model else None
            generic_bulk_bicycle_import.delay(file_id, request.user.pk,
                                              org_pk, bicycle_model_pk)
            context['result'] = file_id

        context['form'] = form
        context['opts'] = self.model._meta
        adminForm = helpers.AdminForm(form, [], {}, {}, model_admin=self)
        media = self.media + adminForm.media
        context['media'] = media
        return TemplateResponse(request, ['lock8/admin/import.html'],
                                context)

    process_generic_bulk_import.short_description = ('Generic Import of'
                                                     ' Bicycles from'
                                                     ' Spreadsheet')

    def move_selected_bicycles(self, request, *args):
        context = {}
        root_org = Organization.objects.get(parent=None)
        form_data = request.POST or {'ids': request.GET['ids'],
                                     'organization': root_org.pk,
                                     'model': None}
        form = MoveBicyclesToOrgForm(form_data, request.FILES or None)
        if request.POST and form.is_valid():
            organization = form.cleaned_data['organization']
            bicycle_model = form.cleaned_data['model']
            assert organization == bicycle_model.organization
            ids = form.cleaned_data['ids'].split(',')
            bike_updates = Bicycle.objects.filter(id__in=ids).update(
                organization=organization,
                model=bicycle_model)
            lock_updates = Lock.objects.filter(bicycle__id__in=ids).update(
                organization=organization)
            axalock_updates = AxaLock.objects.filter(
                bicycle__id__in=ids).update(organization=organization)
            msg = 'Updated {} bicycle{}, {} lock{}, and {} AXA lock{}.'.format(
                bike_updates, 's' if bike_updates > 1 else '',
                lock_updates, 's' if lock_updates > 1 else '',
                axalock_updates, 's' if axalock_updates > 1 else '')
            self.message_user(request, msg)
            return HttpResponseRedirect(
                reverse_query('admin:lock8_bicycle_changelist'))

        context['form'] = form
        context['opts'] = self.model._meta
        adminForm = helpers.AdminForm(form, [], {}, {}, model_admin=self)
        media = self.media + adminForm.media
        context['media'] = media
        return TemplateResponse(request,
                                ['lock8/admin/move_bicycle_to_org.html'],
                                context)

    def move_bicycle_to_org_redirect(self, request, queryset):
        selected = request.POST.getlist(admin.ACTION_CHECKBOX_NAME)
        return HttpResponseRedirect(reverse_query('admin:move_to_org',
                                                  {'ids': ",".join(selected)}))

    move_bicycle_to_org_redirect.short_description = ('Move selected Bicycles'
                                                      ' to new organization')

    def assign_devices_to_bicycles(self, request, *args):
        from velodrome.celery import assign_devices_to_bicycles
        context = {}
        form_data = request.POST
        form = AssignDevicesToBicyclesForm(form_data, request.FILES or None)
        if request.method == 'POST' and form.is_valid():
            organization = form.cleaned_data['organization']
            import_file = form.cleaned_data['import_file']
            file_id = 'assign_devices_to_bicycles/{}'.format(uuid.uuid4())
            private_storage.save(file_id, import_file)
            assign_devices_to_bicycles.delay(file_id, organization.pk,
                                             request.user.pk)
            context['result'] = file_id

        context['form'] = form
        context['opts'] = self.model._meta
        adminForm = helpers.AdminForm(form, [], {}, {}, model_admin=self)
        media = self.media + adminForm.media
        context['media'] = media
        return TemplateResponse(
            request, ['lock8/admin/assign_devices_to_bicycles.html'], context)

    assign_devices_to_bicycles.short_description = ('Assign Devices to '
                                                    'Bicycles with '
                                                    'spreadsheet.')

    def retire_bicycles(self, request, queryset):
        retired = 0
        for bicycle in queryset.exclude(state=BicycleStates.RETIRED.value):
            bicycle.lock = None
            bicycle.axa_lock = None
            if bicycle.state in (
                    BicycleStates.AVAILABLE.value,
                    BicycleStates.LOST.value,
                    BicycleStates.UNRECOVERABLE.value):
                bicycle.put_in_maintenance(by=request.user)
            bicycle.retire(by=request.user)
            retired += 1
        msg = f'Retired {retired} out of {queryset.count()} selected bicycles.'
        self.message_user(request, msg, messages.SUCCESS)

    retire_bicycles.short_description = 'Retire bicycles'

    actions = [move_bicycle_to_org_redirect, retire_bicycles]


@admin.register(BicycleType)
class BicycleTypeAdmin(OwnerableModelAdminMixin, VersionAdmin,
                       admin.ModelAdmin):
    list_display = ('id', 'reference', 'title')
    readonly_fields = ('uuid', 'created', 'modified', 'owner')
    search_fields = ('=uuid',)


@admin.register(BicycleModel)
class BicycleModelAdmin(OwnerableModelAdminMixin, VersionAdmin,
                        admin.ModelAdmin):
    form = BicycleModelForm
    list_display = ('id', 'name', 'type', 'organization', 'hidden', 'state')
    readonly_fields = ('uuid', 'created', 'modified', 'owner', 'state')
    search_fields = ('=uuid', 'name', 'type__title')
    list_filter = ('state', 'type', 'hidden',)
    list_select_related = ('organization', 'type', 'photo')


@admin.register(BicycleModelMaintenanceRule)
class BicycleModelMaintenanceRuleAdmin(FSMModelMixin, VersionAdmin,
                                       admin.ModelAdmin):
    form = BicycleModelMaintenanceRuleForm
    list_display = ('id', 'bicycle_model', 'description', 'note', 'distance',
                    'fixed_date', 'recurring_time', 'role', 'severity',
                    'state')
    readonly_fields = ('uuid', 'created', 'modified', 'state')
    search_fields = ('=uuid',)
    list_filter = ('state', 'role', 'severity',)


@admin.register(Invitation)
class InvitationAdmin(OwnerableModelAdminMixin, FSMModelMixin, VersionAdmin,
                      admin.ModelAdmin):
    form = InvitationForm
    list_display = ('id', 'organization', 'email', 'state',
                    'owner_list_name', 'created')
    readonly_fields = ('uuid', 'state', 'created', 'modified', 'owner')
    search_fields = ('=uuid', '=organization__uuid', 'email')
    list_select_related = ('organization', 'user', 'owner')
    list_filter = ('state', 'role', OrganizationNameFilter)


@admin.register(RefreshToken)
class RefreshTokenAdmin(admin.ModelAdmin):
    form = RefreshTokenForm
    list_display = ('key', 'user', 'app', 'created')
    readonly_fields = ('created', 'key')
    list_filter = ('app',)
    search_fields = ('user__email',
                     'user__username',
                     'user__last_name',
                     )
    list_select_related = ('user',)


class OrganizationRentalSessionFilter(OrganizationNameFilter):
    title = _('Organization')
    parameter_name = 'bicycle__organization'

    def lookups(self, request, model_admin):
        return [(org.pk, f'{org.name} ({org.count})') for org in (
            Organization.objects
            .annotate(count=Count('bicycle__rental_session'))
            .filter(count__gt=0)
            .only('pk', 'name')
            .order_by('name'))]


@admin.register(RentalSession)
class RentalSessionAdmin(OwnerableModelAdminMixin, FSMModelMixin, VersionAdmin,
                         admin.ModelAdmin):
    form = RentalSessionForm
    list_display = ('id', 'bicycle', 'user', 'created', 'modified',
                    'owner_list_name', 'cents', 'state', 'payment_state')
    readonly_fields = ('uuid', 'state', 'created', 'modified', 'owner',
                       'payment_state')
    search_fields = ('=uuid', '=user__uuid', '=user__email', '=bicycle__uuid',
                     '=charge__stripe_id', '=bicycle__name')
    list_filter = ('state', OrganizationRentalSessionFilter, 'payment_state')
    list_select_related = ('bicycle', 'user', 'owner')


@admin.register(RentingScheme)
class RentingSchemeAdmin(OwnerableModelAdminMixin, VersionAdmin,
                         admin.ModelAdmin):
    form = RentingSchemeForm
    list_display = ('id', 'bicycle', 'organization',
                    'max_reservation_duration',  'created', 'modified',
                    'owner_list_name')
    readonly_fields = ('uuid', 'state', 'created', 'modified', 'owner')
    search_fields = ('=uuid',)
    list_filter = ('state', OrganizationNameFilter,)
    list_select_related = ('organization', 'bicycle', 'owner')


@admin.register(Reservation)
class ReservationAdmin(OwnerableModelAdminMixin, VersionAdmin,
                       admin.ModelAdmin):
    form = ReservationForm
    list_display = ('id', 'bicycle', 'user', 'created', 'modified',
                    'owner_list_name')
    readonly_fields = ('uuid', 'state', 'created', 'modified', 'owner',
                       'state')
    search_fields = ('=uuid', '=user__uuid')
    exclude = ('duration',)
    list_filter = ('state',)
    list_select_related = ('bicycle', 'user', 'owner')


@admin.register(SubscriptionPlan)
class SubscriptionPlanAdmin(OwnerableModelAdminMixin, FSMModelMixin,
                            VersionAdmin, admin.ModelAdmin):
    form = SubscriptionPlanForm
    list_display = ('id', 'name', 'organization', 'bicycle_model',
                    'owner_list_name', 'state', 'modified', 'created')
    readonly_fields = ('uuid', 'state', 'created', 'modified', 'owner', 'plan')
    search_fields = ('=uuid', 'name')
    list_filter = ('state', OrganizationNameFilter,)
    list_select_related = ('organization', 'bicycle_model', 'pricing_scheme',
                           'owner')


@admin.register(PlanPass)
class PlanPassAdmin(VersionAdmin, admin.ModelAdmin):
    form = PlanPassForm
    list_display = ('id', 'user', 'subscription_plan', 'created', 'modified')
    readonly_fields = ('uuid', 'created', 'modified')
    search_fields = ('=uuid', '=user__email__iexact')
    list_filter = ('user', 'subscription_plan',)
    list_select_related = ('user', 'subscription_plan')


@admin.register(Task)
class TaskAdmin(FSMModelMixin, OwnerableModelAdminMixin, VersionAdmin,
                admin.ModelAdmin):
    form = TaskForm
    list_display = ('id', 'organization', 'causality', 'assignor',
                    'assignee', 'role', 'severity', 'due', 'modified',
                    'created', 'state')
    readonly_fields = ('uuid', 'state', 'created', 'modified', 'owner')
    search_fields = ('=uuid',)
    list_filter = ('role', 'severity', 'state', OrganizationNameFilter,)
    list_select_related = ('organization', 'assignor', 'assignee')


@admin.register(TermsOfService)
class TermsOfServiceAdmin(FSMModelMixin, OwnerableModelAdminMixin,
                          VersionAdmin, admin.ModelAdmin):
    form = TermsOfServiceForm
    list_display = ('id', 'organization', 'language', 'created', 'modified',
                    'state')
    readonly_fields = ('created', 'modified', 'owner', 'state')
    search_fields = ('=uuid', '=organization_uuid', '=version__label')
    list_filter = ('state', 'language', OrganizationNameFilter,)
    list_select_related = ('organization',)


@admin.register(TermsOfServiceVersion)
class TermsOfServiceVersionAdmin(FSMModelMixin, admin.ModelAdmin):
    form = TermsOfServiceVersionForm
    list_display = ('id', 'organization', 'label', 'created', 'modified',
                    'state')
    readonly_fields = ('created', 'modified', 'state')
    search_fields = ('=uuid', '=organization_uuid', '=label')
    list_filter = ('state', OrganizationNameFilter,)
    list_select_related = ('organization',)


class ReadonlyAdminMixin:
    actions = None

    @csrf_protect_m
    def changeform_view(self, request, object_id=None, form_url='',
                        extra_context=None):
        """Like Django's original, but using db_for_read."""
        with transaction.atomic(using=router.db_for_read(self.model)):
            return self._changeform_view(request, object_id, form_url,
                                         extra_context)

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        """Use custom 'view' permission instead of 'change'."""
        opts = self.opts
        assert not opts.auto_created  # not handled here.

        codename = get_permission_codename('view', opts)
        return request.user.has_perm("%s.%s" % (opts.app_label, codename))


@admin.register(ReadonlyTracking)
class ReadonlyTrackingAdmin(ReadonlyAdminMixin, StamenGeoModelAdmin,
                            BaseAdmin):
    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    form = ReadonlyTrackingForm
    paginator = ApproximatePaginator

    readonly_fields = (
        'uuid', 'created', 'bicycle_uuid', 'device_uuid', 'organization_uuid',
        'tracking_type', 'state', 'attributes', 'timestamp',
    )
    disabled_fields = ('point',)
    fields = disabled_fields + readonly_fields
    list_display = ('id', 'tracking_type', 'state', 'timestamp', 'attributes',
                    ) + BaseAdmin.list_display
    search_fields = ('=uuid', '=bicycle_uuid', '=device_uuid',
                     '=organization_uuid')
    show_full_result_count = False

    def get_readonly_fields(self, request, obj=None):
        readonly_fields = super().get_readonly_fields(request, obj)
        if not obj or obj.tracking_type != 'GPS':
            readonly_fields += ('point',)
        return readonly_fields


class TripGpsFirstFixFilter(admin.SimpleListFilter):
    title = _('First GPS fix')
    parameter_name = 'gps_time_first_fix__lt'

    def lookups(self, request, model_admin):
        return [('10', 'less than 10 seconds'),
                ('30', 'less than 30 seconds'),
                ('60', 'less than 1 minute'),
                ('120', 'less than 2 minutes')]

    def queryset(self, request, queryset):
        value = self.value()
        if value is not None:
            return queryset.filter(**{self.parameter_name: value})


class TripDistanceFilter(admin.SimpleListFilter):
    title = _('Distance')
    parameter_name = 'distance_m'

    def lookups(self, request, model_admin):
        return [('lt__500', 'less than 500 meters'),
                ('lt__1000', 'less than 1km'),
                ('lt__2000', 'less than 2km'),
                ('lt__10000', 'less than 10km'),
                ('lt__20000', 'less than 20km'),
                ('gte__20000', '20km and more')]

    def queryset(self, request, queryset):
        value = self.value()
        if value is not None:
            # NOTE: no validation of `op` - allows to specify it manually, and
            #       we have trusted users.
            op, _, value = value.partition('__')
            assert op
            if not value:
                value = op
                op = 'lte'
            f = '{}__{}'.format(self.parameter_name, op)
            return queryset.filter(**{f: value})


class TripSpeedFilter(admin.SimpleListFilter):
    title = _('speed')
    parameter_name = 'speed'

    def lookups(self, request, model_admin):
        return [('lt__5', 'less than 5 km/h'),
                ('lt__10', 'less than 10 km/h'),
                ('lt__20', 'less than 20 km/h'),
                ('lt__30', 'less than 30 km/h'),
                ('gte__40', '40 km/h and more')]

    def queryset(self, request, queryset):
        value = self.value()
        if value is not None:
            # NOTE: no validation of `op` - allows to specify it manually, and
            #       we have trusted users.
            op, _, value = value.partition('__')
            assert op
            if not value:
                value = op
                op = 'lte'
            f = '{}__{}'.format(self.parameter_name, op)
            return queryset.annotate_with_speed().filter(**{f: value})


@admin.register(Trip)
class TripAdmin(ReadonlyAdminMixin, StamenGeoModelAdmin, BaseAdmin):
    form = TripForm
    paginator = ApproximatePaginator
    show_full_result_count = False

    def get_speed(self, inst):
        return round(inst.speed, 1) if inst.speed else None
    get_speed.short_description = 'km/h'
    get_speed.admin_order_field = 'speed'

    def get_changelist_instance(self, request):
        """Annotate (only) result_list with "speed"."""
        cl = super().get_changelist_instance(request)
        cl.result_list = cl.result_list.annotate_with_speed()
        return cl

    readonly_fields = (
        'distance_m', 'get_speed',
        'bicycle_uuid', 'asset_state', 'serial_number', 'organization_uuid',
        'gps_average_accuracy', 'gps_time_first_fix', 'gps_timeout_events',
        'cell_time_connect', 'cell_timeout_events',
        'duration', 'start_date', 'end_date',
        'state_charge_start', 'state_charge_end',
        'is_valid', 'type', 'created', 'modified', 'uuid',
    )

    disabled_fields = ('route',)
    list_display = ('id', 'is_valid', 'type', 'distance_m', 'get_speed',
                    'duration', 'cell_timeout_events', 'gps_timeout_events',
                    ) + BaseAdmin.list_display
    fieldsets = (
        (None, {
            'fields': ('route', 'distance_m', 'get_speed')}),
        ('Bicycle', {
            'fields': ('bicycle_uuid', 'asset_state', 'serial_number',
                       'organization_uuid')}),
        ('GPS', {
            'fields': ('gps_average_accuracy', 'gps_time_first_fix',
                       'gps_timeout_events')}),
        ('cell', {
            'fields': ('cell_time_connect', 'cell_timeout_events')}),
        ('Time', {
            'fields': ('duration', ('start_date', 'end_date'),
                       'state_charge_start', 'state_charge_end')
        }),
        ('Advanced', {
            'fields': ('is_valid', 'type', 'created', 'modified', 'uuid')
        }),
    )
    list_filter = ('type', TripSpeedFilter, TripDistanceFilter,
                   TripGpsFirstFixFilter, OrganizationUUIDFilter)
    search_fields = ('=uuid', '=bicycle_uuid', '=organization_uuid')


@admin.register(UserProfile)
class UserProfileAdmin(OwnerableModelAdminMixin, VersionAdmin,
                       admin.ModelAdmin):
    form = UserProfileForm
    list_display = ('id', 'user', 'phone_numbers', 'created', 'modified',
                    'owner_list_name')
    list_select_related = ('user', 'owner')
    readonly_fields = ('uuid', 'state', 'created', 'modified', 'owner')
    search_fields = ('=uuid',)
    list_filter = ('state',)


@admin.register(Zone)
class ZoneAdmin(FSMModelMixin, OwnerableModelAdminMixin, VersionAdmin,
                StamenGeoModelAdmin):
    form = ZoneForm
    list_display = ('id', 'name', 'organization', 'type', 'state',
                    'low_threshold', 'high_threshold')
    list_filter = ('state', OrganizationNameFilter, 'type')
    readonly_fields = ('uuid', 'state', 'created', 'modified', 'owner')
    search_fields = ('=uuid', 'name')
    list_select_related = ('organization',)

    def get_urls(self):
        return [path('copy_or_move_to_org/',
                     self.admin_site.admin_view(self.copy_or_move_to_org),
                     name='copy_or_move_to_org'),
                ] + super().get_urls()

    def copy_or_move_to_org(self, request, *args):
        context = {}
        root_org = Organization.objects.get(parent=None)
        form_data = request.POST or {'ids': request.GET['ids'],
                                     'organization': root_org.pk,
                                     'move': False}
        form = MoveOrCopyZoneToOrgForm(form_data, request.FILES or None)
        if request.POST and form.is_valid():
            organization = form.cleaned_data['organization']
            ids = form.cleaned_data['ids'].split(',')
            move = form.cleaned_data['move']
            if move:
                zone_moved = Zone.objects.filter(id__in=ids).update(
                    organization=organization)
                msg = f'{zone_moved} moved zones.'
            else:
                index = 0
                for index, zone in enumerate(Zone.objects.filter(id__in=ids)):
                    zone.id = None
                    zone.uuid = uuid.uuid4()
                    zone.organization = organization
                    zone.save()
                msg = f'{index} Zones copied.'
            self.message_user(request, msg)
            return HttpResponseRedirect(
                reverse_query('admin:lock8_zone_changelist'))

        context['form'] = form
        context['opts'] = self.model._meta
        adminForm = helpers.AdminForm(form, [], {}, {}, model_admin=self)
        media = self.media + adminForm.media
        context['media'] = media
        return TemplateResponse(request,
                                ['lock8/admin/copy_or_move_zones.html'],
                                context)

    def copy_or_move_to_org_redirect(self, request, queryset):
        selected = request.POST.getlist(admin.ACTION_CHECKBOX_NAME)
        return HttpResponseRedirect(reverse_query('admin:copy_or_move_to_org',
                                                  {'ids': ",".join(selected)}))

    copy_or_move_to_org_redirect.short_description = ('Copy or Move selected'
                                                      ' zones to a new'
                                                      ' organization')

    actions = [copy_or_move_to_org_redirect]


def adjust_pinax_stripe_admin():
    from django.contrib import admin
    import pinax.stripe.admin

    admin.site.unregister(pinax.stripe.models.Account)
    admin.site.unregister(pinax.stripe.models.Charge)
    admin.site.unregister(pinax.stripe.models.Customer)

    class AccountAdmin(pinax.stripe.admin.AccountAdmin):
        list_display = pinax.stripe.admin.AccountAdmin.list_display
        list_display.insert(list_display.index('display_name') + 1,
                            'display_organizations')

        def display_organizations(self, obj):
            return ', '.join([str(o) for o in obj.organization_set.all()])
        display_organizations.short_description = 'Organizations'

        def get_queryset(self, request):
            qs = super().get_queryset(request)
            return qs.prefetch_related('organization_set')

    class ChargeAdmin(pinax.stripe.admin.ChargeAdmin):
        def get_queryset(self, request):
            qs = super().get_queryset(request)
            return qs.prefetch_related('customer__users__affiliations',
                                       'customer__users__organizations')

    class CustomerAdmin(pinax.stripe.admin.CustomerAdmin):
        def get_queryset(self, request):
            qs = super().get_queryset(request)
            return qs.prefetch_related('users__affiliations',
                                       'users__organizations')

    admin.site.register(pinax.stripe.models.Account, AccountAdmin)
    admin.site.register(pinax.stripe.models.Charge, ChargeAdmin)
    admin.site.register(pinax.stripe.models.Customer, CustomerAdmin)
