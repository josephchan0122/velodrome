from os.path import basename, join

from rest_framework import status

from velodrome.lock8.utils import reverse_query


def test_crud_firmware(drf_fleet_operator, firmware_mercury,
                       firmware_mercury_update, owner,
                       b64_firmware_hex, org, drf_admin,
                       settings):
    from velodrome.lock8.models import Firmware

    firmware_list_url = reverse_query('lock8:firmware-list')
    drf_admin.assert_count(firmware_list_url, 2)

    firmware_detail_url = reverse_query(
        'lock8:firmware-detail', kwargs={'uuid': str(firmware_mercury.uuid)}
    )
    org_detail_url = reverse_query(
        'lock8:organization-detail',
        kwargs={'uuid': str(firmware_mercury.organization.uuid)}
    )
    drf_admin.assert_success(firmware_detail_url, {
        'version': '1.1.1',
        'url': 'http://testserver{}'.format(firmware_detail_url),
        'name': '',
        'organization': 'http://testserver{}'.format(org_detail_url),
        'concurrency_version': firmware_mercury.concurrency_version,
        'chip': firmware_mercury.chip,
        'modified': firmware_mercury.modified.isoformat()[:-13] + 'Z',
        'state': firmware_mercury.state,
        'created': firmware_mercury.created.isoformat()[:-13] + 'Z',
        'uuid': str(firmware_mercury.uuid),
        'binary': 'http://127.0.0.1:8000/{}'.format(
            firmware_mercury.binary.name
        ),
    })

    response = drf_fleet_operator.patch(firmware_list_url)
    assert response.status_code == status.HTTP_403_FORBIDDEN

    response = drf_admin.post(firmware_list_url, data={
        'organization': org_detail_url, 'chip': Firmware.MERCURY,
        'version': '1.1.2', 'binary': b64_firmware_hex
    })
    assert response.status_code == status.HTTP_201_CREATED, response.data

    binary = Firmware.objects.latest().binary
    path = join(settings.MEDIA_ROOT, binary.name)
    with open(path, mode='r+b') as open_file:
        assert binary.read() == open_file.read()
        assert basename(open_file.name) in basename(binary.name)

    response = drf_admin.put(
        firmware_detail_url,
        data={'version': '1.1.3', 'chip': Firmware.MERCURY,
              'binary': b64_firmware_hex}
    )
    assert response.status_code == status.HTTP_200_OK
    new = Firmware.objects.latest().binary

    # The old binary is being kept.
    assert binary
    binary.delete()

    response = drf_admin.patch(firmware_detail_url)
    assert response.status_code == status.HTTP_200_OK

    firmware_action_url = reverse_query(
        'lock8:firmware-actions',
        kwargs={'uuid': firmware_mercury.uuid}
    )
    response = drf_admin.post(firmware_action_url, data={'type': 'provision'})
    assert response.status_code == status.HTTP_200_OK

    response = drf_admin.delete(firmware_detail_url)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    # Cleanup.
    new.delete()


def test_firmware_state_filtering(drf_admin, firmware_mercury,
                                  firmware_mercury_update):
    url = reverse_query('lock8:firmware-list',
                        {'state': 'provisioned'})
    drf_admin.assert_count(url, 0)

    firmware_mercury.provision()
    url = reverse_query('lock8:firmware-list',
                        {'state': 'provisioned'})
    drf_admin.assert_count(url, 1)


def test_firmware_name_filtering(drf_admin, firmware_mercury,
                                 firmware_mercury_update):
    url = reverse_query('lock8:firmware-list', {'name': 'badger'})
    drf_admin.assert_count(url, 0)

    firmware_mercury.name = 'foo'
    firmware_mercury.save()

    url = reverse_query('lock8:firmware-list', {'name': 'foo'})
    drf_admin.assert_count(url, 1)


def test_firmware_organization_filtering(drf_admin, firmware_mercury,
                                         firmware_mercury_update, another_org):
    url = reverse_query('lock8:firmware-list',
                        {'organization': str(another_org.uuid)})
    drf_admin.assert_count(url, 0)

    url = reverse_query(
        'lock8:firmware-list',
        {'organization': str(firmware_mercury.organization.uuid)}
    )
    drf_admin.assert_count(url, 2)


def test_firmware_chip_filtering(drf_admin, firmware_mercury,
                                 firmware_mercury_update):
    firmware_mercury_update.chip = '0'
    firmware_mercury_update.save()

    url = reverse_query('lock8:firmware-list',
                        {'chip': firmware_mercury_update.chip})
    drf_admin.assert_count(url, 1)

    url = reverse_query('lock8:firmware-list',
                        {'chip': firmware_mercury.chip})
    drf_admin.assert_count(url, 1)


def test_firmware_version_filtering(drf_admin, firmware_mercury,
                                    firmware_mercury_update):
    url = reverse_query('lock8:firmware-list',
                        {'version': '6.6.6'})
    drf_admin.assert_count(url, 0)

    url = reverse_query('lock8:firmware-list',
                        {'version': firmware_mercury.version})
    drf_admin.assert_count(url, 1)
