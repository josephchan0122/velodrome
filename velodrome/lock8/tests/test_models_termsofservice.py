from django.core.exceptions import ValidationError
from django.db import IntegrityError
import pytest


def test_terms_of_service_model(alice, org, terms_of_service_version):
    from velodrome.lock8.models import TermsOfService

    tos = TermsOfService.objects.create(
        owner=alice,
        organization=org,
        language='en',
        version=terms_of_service_version,
    )
    assert tos.owner == alice
    assert tos.organization == org
    assert tos.version == terms_of_service_version
    assert tos.language == 'en'
    assert tos.tos_url == ''
    assert tos.content is None

    assert str(tos) == f'TOS[{tos.id}] / Organization[{org.id}]'

    tos = TermsOfService.objects.create(
        owner=alice,
        organization=org,
        language='fr',
        version=terms_of_service_version,
    )
    assert tos.language == 'fr'

    with pytest.raises(IntegrityError):
        TermsOfService.objects.create(
            owner=alice,
            organization=org,
            language='fr',
            version=terms_of_service_version,
        )


def test_terms_of_service_model_language(alice, org, terms_of_service_version):
    from velodrome.lock8.models import TermsOfService
    tos = TermsOfService.objects.create(
        owner=alice,
        organization=org,
        version=terms_of_service_version,
        language='unknown',
    )

    with pytest.raises(ValidationError) as e:
        tos.clean_fields()

    assert 'Value \'unknown\' is not a valid choice' in str(e.value)


def test_terms_of_service_version_model(alice, org):
    from velodrome.lock8.models import TermsOfService, TermsOfServiceVersion

    tos_version = TermsOfServiceVersion.objects.create(
        organization=org,
        label='model test tos version'
    )
    assert tos_version.organization == org
    assert tos_version.label == 'model test tos version'

    assert str(tos_version) == (
        f'TOSVersion[{tos_version.id} - {tos_version.label}] '
        f'/ Organization[{org.id}]')

    with pytest.raises(ValidationError) as e:
        tos_version.provision()

    assert ('There are no provisioned terms of service assigned to this '
            'version' in str(e.value))

    tos = TermsOfService.objects.create(
        owner=alice,
        organization=org,
        version=tos_version,
        language='en',
    )
    tos.provision()
    tos_version.provision()

    tos_version2 = TermsOfServiceVersion.objects.create(
        organization=org,
        label='model test tos version 2'
    )
    tos2 = TermsOfService.objects.create(
        owner=alice,
        organization=org,
        version=tos_version2,
        language='en',
    )
    tos2.provision()
    with pytest.raises(ValidationError) as e:
        tos_version2.provision()

    assert ('Cannot provision terms of service version.'
            f' Version {tos_version.uuid} is already provisioned.'
            in str(e.value))
