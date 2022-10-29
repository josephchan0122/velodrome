from rest_framework import status

from velodrome.lock8.utils import reverse_query


def test_crud_lock_firmware_update(drf_fleet_operator, lock_firmware_update,
                                   another_lock_firmware_update, drf_admin,
                                   another_org, org, lock, firmware_mercury,
                                   owner):
    lfu_list_url = reverse_query('lock8:lock_firmware_update-list')
    drf_admin.assert_count(lfu_list_url, 2)

    lfu_detail_url = reverse_query(
        'lock8:lock_firmware_update-detail',
        kwargs={'uuid': str(lock_firmware_update.uuid)}
    )
    firmware_detail_url = reverse_query(
        'lock8:firmware-detail',
        kwargs={'uuid': str(lock_firmware_update.firmware.uuid)}
    )
    lock_detail_url = reverse_query(
        'lock8:lock-detail',
        kwargs={'uuid': str(lock_firmware_update.lock.uuid)}
    )
    drf_admin.assert_success(lfu_detail_url, {
        'created': lock_firmware_update.created.isoformat()[:-13] + 'Z',
        'modified': lock_firmware_update.modified.isoformat()[:-13] + 'Z',
        'url': 'http://testserver{}'.format(lfu_detail_url),
        'firmware': 'http://testserver{}'.format(firmware_detail_url),
        'lock': 'http://testserver{}'.format(lock_detail_url),
        'concurrency_version': lock_firmware_update.concurrency_version,
        'uuid': str(lock_firmware_update.uuid)
    })

    response = drf_fleet_operator.get(lfu_list_url)
    assert response.status_code == status.HTTP_403_FORBIDDEN

    response = drf_admin.post(lfu_list_url, data={
        'lock': lock_detail_url,
        'firmware': firmware_detail_url,
    })
    assert response.status_code == status.HTTP_201_CREATED

    response = drf_admin.put(lfu_detail_url, data={
        'lock': lock_detail_url,
        'firmware': firmware_detail_url,
    })
    assert response.status_code == status.HTTP_200_OK

    response = drf_admin.patch(lfu_detail_url)
    assert response.status_code == status.HTTP_200_OK

    response = drf_admin.delete(lfu_detail_url)
    assert response.status_code == status.HTTP_204_NO_CONTENT


def test_filtering_lock_firmware_update_lock(drf_admin,
                                             lock_firmware_update, lock,
                                             another_lock):
    url = reverse_query('lock8:lock_firmware_update-list',
                        {'lock': str(another_lock.uuid)})
    drf_admin.assert_count(url, 0)

    url = reverse_query('lock8:lock_firmware_update-list',
                        {'lock': str(lock.uuid)})
    drf_admin.assert_count(url, 1)


def test_filtering_lock_firmware_update_firmware(drf_admin,
                                                 lock_firmware_update,
                                                 firmware_mercury,
                                                 non_matching_uuid):
    url = reverse_query('lock8:lock_firmware_update-list',
                        {'firmware': non_matching_uuid})
    drf_admin.assert_count(url, 0)

    url = reverse_query('lock8:lock_firmware_update-list',
                        {'firmware': str(firmware_mercury.uuid)})
    drf_admin.assert_count(url, 1)


def test_filtering_lock_firmware_update_org(drf_admin,
                                            lock_firmware_update,
                                            firmware_mercury, org,
                                            non_matching_uuid):
    url = reverse_query('lock8:lock_firmware_update-list',
                        {'organization': non_matching_uuid})
    drf_admin.assert_count(url, 0)

    url = reverse_query('lock8:lock_firmware_update-list',
                        {'organization': str(org.uuid)})
    drf_admin.assert_count(url, 1)
