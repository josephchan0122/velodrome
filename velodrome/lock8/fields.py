from base64 import b64decode
import binascii
import datetime
from functools import reduce

from django.conf import settings
from django.contrib.gis.db.models import PointField
from django.core.files.base import ContentFile
from django.db.models.fields import (
    CharField, DateTimeField, FloatField, PositiveIntegerField,
)
from django.utils.translation import ugettext_lazy as _
from rest_framework.fields import (
    DateTimeField as DRFDateTimeField, DurationField, FileField,
)
from rest_framework.relations import HyperlinkedRelatedField
from rest_framework.serializers import ModelSerializer


class IndexedDateTimeField(DateTimeField):
    """
    Read only field used to index content of attributes field (JSON)
    to ease search or ordering through those values.
    """

    def __init__(self, *args, **kw):
        kw['db_index'] = True
        kw['blank'] = True
        kw['null'] = True
        kw['editable'] = False
        super().__init__(*args, **kw)


class IndexedFloatJsonField(FloatField):
    """
    Read only field used to index content of attributes field (JSON)
    to ease search or ordering through those values.
    """

    def __init__(self, *args, **kw):
        kw['db_index'] = True
        kw['blank'] = True
        kw['null'] = True
        kw['editable'] = False
        super().__init__(*args, **kw)


class IndexedPositiveIntegerJsonField(PositiveIntegerField):
    """
    Read only field used to index content of attributes field (JSON)
    to ease search or ordering through those values.
    """

    def __init__(self, *args, **kw):
        kw['db_index'] = True
        kw['blank'] = True
        kw['null'] = True
        kw['editable'] = False
        super().__init__(*args, **kw)


class IndexedPointField(PointField):
    """
    Read only field used to index content of attributes field (JSON)
    to ease search or orderiing though those values.
    """

    def __init__(self, *args, **kw):
        kw['db_index'] = True
        kw['blank'] = True
        kw['null'] = True
        kw['editable'] = False
        super().__init__(*args, **kw)


class DurationInSecondField(DurationField):
    default_error_messages = {
        'invalid': _('Duration has wrong format. Send duration as seconds'),
    }

    def to_internal_value(self, value):
        if isinstance(value, datetime.timedelta):
            return value
        try:
            return datetime.timedelta(seconds=int(value))
        except Exception:
            self.fail('invalid')

    def to_representation(self, value):
        if value is None:
            return None
        return value.total_seconds()


class GenericHyperLinkedRelatedField(HyperlinkedRelatedField):
    def get_url(self, obj, view_name, request, format):
        """
        Given an object, return the URL that hyperlinks to the object.
        May raise a `NoReverseMatch` if the `view_name` and `lookup_field`
        attributes are not configured to correctly match the URL conf.
        """
        # Unsaved objects will not yet have a valid URL.
        if hasattr(obj, 'pk') and obj.pk is None:
            return None

        lookup_value = getattr(obj, self.lookup_field)
        kwargs = {self.lookup_url_kwarg: lookup_value}
        view_name = 'lock8:{}-detail'.format(obj.__class__._meta.model_name)
        return self.reverse(view_name, kwargs=kwargs, request=request,
                            format=format)


class ParentHyperLinkedRelatedField(HyperlinkedRelatedField):
    def __init__(self, *args, **kwargs):
        self.nested_lookup_field = kwargs.pop('nested_lookup_field')
        super().__init__(*args, **kwargs)

    def get_url(self, obj, view_name, request, format):
        """
        Resolves a URL for an object which is a nested resource
        under another serializer.
        """
        lookup_value = getattr(obj, self.lookup_field)
        parent_lookups = self.nested_lookup_field.split('__')
        parent_lookup_value = reduce(getattr, [obj]+parent_lookups)
        kwargs = {
            self.lookup_url_kwarg: lookup_value,
            'parent_lookup_uuid': parent_lookup_value
        }
        return self.reverse(
            view_name, kwargs=kwargs, request=request, format=format
        )


class NestedDetailViewHyperlinkedRelatedField(HyperlinkedRelatedField):
    """
    Useful for @detail_view on top of CBV.

    e.g: /api/resources/{uuid}/unique_resource/
    """
    def __init__(self, *args, **kwargs):
        self.parent_lookup_field = kwargs.pop('parent_lookup_field')
        super().__init__(*args, **kwargs)

    def get_url(self, obj, view_name, request, format):
        *parent_paths, lookup_field = self.parent_lookup_field.split('.')
        while parent_paths:
            obj = getattr(obj, parent_paths.pop(0))
        lookup_value = getattr(obj, lookup_field)
        return self.reverse(
            view_name, kwargs={lookup_field: lookup_value},
            request=request, format=format
        )


class UUIDHyperlinkedRelatedField(HyperlinkedRelatedField):
    def get_url(self, obj, view_name, request, format):
        """Override get_url to use `str(obj)`."""

        lookup_value = str(obj)
        kwargs = {self.lookup_url_kwarg: lookup_value}
        return self.reverse(view_name, kwargs=kwargs, request=request,
                            format=format)


class DateTimeFieldWithSecondPrecision(DRFDateTimeField):
    def to_representation(self, value):
        if not value:
            return value
        value = value.replace(microsecond=0)
        return super().to_representation(value)

ModelSerializer.serializer_field_mapping[DateTimeField] = DateTimeFieldWithSecondPrecision  # noqa


class Base64FileField(FileField):
    SENTINEL = ';base64,'
    FNAME_SENTINEL = 'filename:'

    default_error_messages = {
        'invalid_encoding': 'Failed to decode payload',
        'no_filename': 'Failed to retrieve filename',
        'no_sentinel': 'Payload does not contain sentinel',
    }

    def to_internal_value(self, data):
        if (self.SENTINEL not in data or
                self.FNAME_SENTINEL not in data):
            self.fail('no_sentinel')

        try:
            header, base64_data = data.split(self.SENTINEL, 1)
            decoded = b64decode(base64_data)
        except (TypeError, ValueError, binascii.Error):
            self.fail('invalid_encoding')

        try:
            filename = header.split(self.FNAME_SENTINEL, 1)[-1]
        except (ValueError, IndexError):
            self.fail('no_filename')

        cfile = ContentFile(content=decoded, name=filename)
        return super().to_internal_value(cfile)


class LanguageField(CharField):
    """
    A language field for Django models.
    """
    def __init__(self, *args, **kwargs):
        kwargs.setdefault('max_length', 7)
        kwargs.setdefault('choices', settings.LANGUAGES)
        super().__init__(*args, **kwargs)
