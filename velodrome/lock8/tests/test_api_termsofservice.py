import pytest
from rest_framework import status

from velodrome.lock8.models import GenericStates
from velodrome.lock8.utils import reverse_query


def test_crud_on_tos(drf_fleet_operator, drf_renter, owner, org,
                     terms_of_service_version):
    from velodrome.lock8.models import TermsOfService

    url = reverse_query('lock8:terms_of_service-list')
    tos_version_url = reverse_query(
        'lock8:terms_of_service_version-detail',
        kwargs={'uuid': terms_of_service_version.uuid})
    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})
    payload = {
        'organization': organization_url,
        'tos_url': 'https://s3.com/tos.xml',
        'language': 'de',
        'content': 'Terms here.',
        'version': tos_version_url,
    }

    response = drf_renter.post(url, data=payload)
    assert response.status_code == status.HTTP_403_FORBIDDEN, response.data

    response = drf_fleet_operator.post(url, data=payload)
    assert response.status_code == status.HTTP_201_CREATED, response.data

    drf_fleet_operator.assert_count(url, 1)
    drf_renter.assert_count(url, 0)  # not provisioned yet

    tos = TermsOfService.objects.get()
    tos.provision()
    drf_renter.assert_count(url, 0)  # still not provisioned

    terms_of_service_version.provision()
    drf_renter.assert_count(url, 1)

    tos.refresh_from_db()

    url = reverse_query('lock8:terms_of_service-detail',
                        kwargs={'uuid': tos.uuid})
    payload.pop('organization')
    payload.pop('version')
    del response.data['concurrency_version']
    del response.data['modified']
    assert response.data == dict(
        **payload,
        uuid=str(tos.uuid),
        url='http://testserver' + url,
        organization='http://testserver' + organization_url,
        version='http://testserver' + tos_version_url,
        state=GenericStates.NEW.value,
        created=tos.created.isoformat()[:-13] + 'Z',
    )

    response = drf_fleet_operator.get(url)
    assert response.status_code == status.HTTP_200_OK

    response = drf_fleet_operator.patch(url, data={'language': 'en'})
    assert response.status_code == status.HTTP_200_OK

    tos.refresh_from_db()
    assert tos.language == 'en'

    response = drf_fleet_operator.delete(url)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    with pytest.raises(TermsOfService.DoesNotExist):
        tos.refresh_from_db()


def test_tos_filtering_organization(drf_fleet_operator, terms_of_service, org,
                                    non_matching_uuid):
    filter_url = reverse_query('lock8:terms_of_service-list',
                               {'organization': org.uuid})
    drf_fleet_operator.assert_count(filter_url, 1)

    filter_url = reverse_query('lock8:terms_of_service-list',
                               {'organization': non_matching_uuid})
    drf_fleet_operator.assert_count(filter_url, 0)


def test_tos_filtering_language(drf_fleet_operator, terms_of_service):
    filter_url = reverse_query('lock8:terms_of_service-list',
                               {'language': terms_of_service.language})
    drf_fleet_operator.assert_count(filter_url, 1)

    filter_url = reverse_query('lock8:terms_of_service-list',
                               {'language': 'el'})
    drf_fleet_operator.assert_count(filter_url, 0)


def test_tos_filtering_state(drf_fleet_operator, terms_of_service):
    filter_url = reverse_query('lock8:terms_of_service-list',
                               {'state': GenericStates.NEW.value})
    drf_fleet_operator.assert_count(filter_url, 1)

    filter_url = reverse_query('lock8:terms_of_service-list',
                               {'state': GenericStates.PROVISIONED.value})
    drf_fleet_operator.assert_count(filter_url, 0)


def test_tos_filtering_version(drf_fleet_operator, terms_of_service,
                               non_matching_uuid):
    filter_url = reverse_query('lock8:terms_of_service-list',
                               {'version': terms_of_service.version.uuid})
    drf_fleet_operator.assert_count(filter_url, 1)

    filter_url = reverse_query('lock8:terms_of_service-list',
                               {'version': non_matching_uuid})
    drf_fleet_operator.assert_count(filter_url, 0)
