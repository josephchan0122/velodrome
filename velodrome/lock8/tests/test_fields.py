from datetime import timedelta

from django.core.files.base import ContentFile
import pytest
from rest_framework import exceptions


def test_duration_field_as_second():
    from velodrome.lock8.fields import DurationInSecondField

    field = DurationInSecondField()
    assert field.to_representation(timedelta(seconds=2)) == 2
    assert field.to_representation(None) is None

    assert field.to_internal_value(2) == timedelta(seconds=2)
    assert (field.to_internal_value(timedelta(seconds=2)) ==
            timedelta(seconds=2))

    with pytest.raises(exceptions.ValidationError):
        field.to_internal_value(None)


def test_b64_file_field(b64_firmware_hex):
    from velodrome.lock8.fields import Base64FileField

    field = Base64FileField()

    f1 = field.to_internal_value(b64_firmware_hex)
    assert isinstance(f1, ContentFile)

    with pytest.raises(exceptions.ValidationError) as err:
        field.to_internal_value('filename:foo.hex')
    assert err.value.detail == ['Payload does not contain sentinel']

    with pytest.raises(exceptions.ValidationError) as err:
        field.to_internal_value('foo.hex;base64,')
    assert err.value.detail == ['Payload does not contain sentinel']

    with pytest.raises(exceptions.ValidationError) as err:
        field.to_internal_value('filename:foo.hex;base64,INVALID')
    assert err.value.detail == ['Failed to decode payload']


def test_language_field():
    from django.conf import settings
    from velodrome.lock8.fields import LanguageField

    field = LanguageField()
    assert field.max_length == 7
    assert field.choices == settings.LANGUAGES
