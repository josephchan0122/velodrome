import datetime as dt
import json

import pytest
from rest_framework import status

from velodrome.lock8.utils import reverse_query


def test_add_bicycle_count_field(org, drf_fleet_operator,
                                 bicycle, bicycle2, another_bicycle,
                                 create_gps_tracking,
                                 zone, maintenance_zone,
                                 middle_of_central_park,
                                 middle_of_theodore_roosevelt_park):

    create_gps_tracking(bicycle, *middle_of_central_park.tuple)
    create_gps_tracking(bicycle2, *middle_of_theodore_roosevelt_park.tuple)
    create_gps_tracking(another_bicycle, *middle_of_central_park.tuple)

    url = reverse_query('lock8:zone-list', {})
    response = drf_fleet_operator.assert_count(url, 2)
    for zone_item in response.data['results']:
        assert 'bicycle_count' not in zone_item

    url = reverse_query('lock8:zone-list', {'include_bicycle_count': 1})
    response = drf_fleet_operator.assert_count(url, 2)
    assert response.data['results'][0]['name'] == 'Somewhere [maintenance]'
    assert response.data['results'][0]['bicycle_count'] == 0
    assert response.data['results'][1]['name'] == 'Central Park'
    assert response.data['results'][1]['bicycle_count'] == 1


def test_crud_zone(org, drf_fleet_operator, drf_another_fleet_operator,
                   central_park):
    from velodrome.lock8.models import Zone

    url = reverse_query('lock8:zone-list')

    org_url = reverse_query('lock8:organization-detail',
                            kwargs={'uuid': org.uuid})
    # create
    response = drf_fleet_operator.post(url, data={
        'organization': org_url,
        'name': 'Central Park',
        'polygon': json.loads(central_park.json),
    }, format='json')
    assert response.status_code == status.HTTP_201_CREATED, response.data

    zone = Zone.objects.get()

    url = reverse_query('lock8:zone-detail', kwargs={'uuid': zone.uuid})
    drf_fleet_operator.assert_success(url, {
        'uuid': str(zone.uuid),
        'organization': 'http://testserver' + org_url,
        'url': 'http://testserver' + url,
        'name': 'Central Park',
        'polygon': json.loads(central_park.json),
        'type': 'dropzone',
        'preferred_mechanic': None,
        'state': 'new',
        'concurrency_version': zone.concurrency_version,
        'modified': zone.modified.isoformat()[:-13] + 'Z',
        'created': zone.created.isoformat()[:-13] + 'Z',
        'low_threshold': None,
        'high_threshold': None
    })

    url = reverse_query('lock8:zone-detail',
                        {'organization': str(org.uuid)},
                        kwargs={'uuid': zone.uuid})
    response = drf_fleet_operator.patch(url, data={'name': 'New York'})
    assert response.status_code == status.HTTP_200_OK

    drf_another_fleet_operator.assert_status(url, status.HTTP_404_NOT_FOUND)

    response = drf_fleet_operator.delete(url)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    with pytest.raises(Zone.DoesNotExist):
        zone.refresh_from_db()


def test_crud_on_zones_threshold(org, drf_fleet_operator, central_park):
    from velodrome.lock8.models import Zone
    list_url = reverse_query('lock8:zone-list')
    org_url = reverse_query('lock8:organization-detail',
                            kwargs={'uuid': org.uuid})
    data = {
        'organization': org_url,
        'name': 'Central Park',
        'polygon': json.loads(central_park.json),
    }
    response = drf_fleet_operator.post(list_url, data=data, format='json')
    assert response.status_code == status.HTTP_201_CREATED, response.data

    zone = Zone.objects.get()
    url = reverse_query('lock8:zone-detail', kwargs={'uuid': zone.uuid})
    drf_fleet_operator.assert_success(url, {
        'uuid': str(zone.uuid),
        'organization': 'http://testserver' + org_url,
        'url': 'http://testserver' + url,
        'name': 'Central Park',
        'polygon': json.loads(central_park.json),
        'type': 'dropzone',
        'preferred_mechanic': None,
        'state': 'new',
        'concurrency_version': zone.concurrency_version,
        'modified': zone.modified.isoformat()[:-13] + 'Z',
        'created': zone.created.isoformat()[:-13] + 'Z',
        'low_threshold': None,
        'high_threshold': None,
    })

    zone = Zone.objects.get()
    url = reverse_query('lock8:zone-detail', kwargs={'uuid': zone.uuid})
    data['low_threshold'] = low_threshold = 2
    data['high_threshold'] = high_threshold = 5
    drf_fleet_operator.assert_success(
        url, method='put', data=data, format='json')
    drf_fleet_operator.assert_values_has_data(url, {
        'low_threshold': low_threshold,
        'high_threshold': high_threshold
    })
    data['high_threshold'] = high_threshold = 20
    drf_fleet_operator.assert_success(
        url, method='patch', data=data, format='json')
    drf_fleet_operator.assert_values_has_data(url, {
        'low_threshold': low_threshold,
        'high_threshold': high_threshold
    })

    del data['low_threshold']
    data['high_threshold'] = high_threshold = 20
    drf_fleet_operator.assert_created(list_url, data=data)
    zone = Zone.objects.filter(uuid=response.data['uuid']).first()
    url = reverse_query('lock8:zone-detail', kwargs={'uuid': zone.uuid})
    drf_fleet_operator.assert_values_has_data(url, {
        'low_threshold': None,
        'high_threshold': high_threshold
    })

    data['low_threshold'] = None
    data['high_threshold'] = high_threshold = 50
    drf_fleet_operator.assert_created(list_url, data=data)
    zone = Zone.objects.filter(uuid=response.data['uuid']).first()
    url = reverse_query('lock8:zone-detail', kwargs={'uuid': zone.uuid})
    drf_fleet_operator.assert_values_has_data(url, {
        'low_threshold': None,
        'high_threshold': high_threshold
    })


def test_zone_threshold_validations(org, drf_fleet_operator, central_park):
    url = reverse_query('lock8:zone-list')

    org_url = reverse_query('lock8:organization-detail',
                            kwargs={'uuid': org.uuid})

    response = drf_fleet_operator.post(url, data={
        'organization': org_url,
        'name': 'Central Park',
        'polygon': json.loads(central_park.json),
        'low_threshold': 100,
        'high_threshold': 20,
    }, format='json')
    assert response.status_code == status.HTTP_400_BAD_REQUEST, response.data

    response = drf_fleet_operator.post(url, data={
        'organization': org_url,
        'name': 'Central Park',
        'polygon': json.loads(central_park.json),
        'low_threshold': -100,
        'high_threshold': -100,
    }, format='json')
    assert response.status_code == status.HTTP_400_BAD_REQUEST, response.data

    response = drf_fleet_operator.post(url, data={
        'organization': org_url,
        'name': 'Central Park',
        'polygon': json.loads(central_park.json),
        'low_threshold': 300,
        'high_threshold': 300,
    }, format='json')
    assert response.status_code == status.HTTP_400_BAD_REQUEST, response.data

    response = drf_fleet_operator.post(url, data={
        'organization': org_url,
        'name': 'Central Park',
        'polygon': json.loads(central_park.json),
        'high_threshold': 20,
    }, format='json')
    assert response.status_code == status.HTTP_201_CREATED, response.data

    response = drf_fleet_operator.post(url, data={
        'organization': org_url,
        'name': 'Central Park',
        'polygon': json.loads(central_park.json),
        'low_threshold': 50,
    }, format='json')
    assert response.status_code == status.HTTP_201_CREATED, response.data


def test_filtering_zone(org, drf_fleet_operator, central_park,
                        another_org, middle_of_central_park, zone):
    url = reverse_query('lock8:zone-list',
                        {'organization': str(another_org.uuid)})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:zone-list',
                        {'geo': middle_of_central_park.json})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:zone-list',
                        {'geo': json.dumps({'type': 'Point',
                                            'coordinates': [0, 1]})})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:zone-list', {'state': 'new'})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:zone-list', {'state': 'provisioned'})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:zone-list',
                        {'modified_since': zone.modified.timestamp()})  # noqa
    drf_fleet_operator.assert_count(url, 1)

    tstamp = (zone.modified + dt.timedelta(seconds=1)).timestamp()
    url = reverse_query('lock8:zone-list',
                        {'modified_since': tstamp})
    drf_fleet_operator.assert_count(url, 0)


def test_filtering_zone_type(zone, drf_fleet_operator):
    url = reverse_query('lock8:zone-list', {'type': 'dropzone'})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:zone-list', {'type': 'cycling_area'})
    drf_fleet_operator.assert_count(url, 0)

    zone.type = 'cycling_area'
    zone.save()

    url = reverse_query('lock8:zone-list', {'type': 'cycling_area'})
    drf_fleet_operator.assert_count(url, 1)


def test_list_zone_renter(org, drf_alice, zone, alice):
    from velodrome.lock8.models import Affiliation

    url = reverse_query('lock8:zone-list')

    response = drf_alice.get(url)
    assert response.status_code == status.HTTP_200_OK, response.data
    assert response.data['count'] == 0

    Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.RENTER,
    )
    response = drf_alice.assert_count(url, 1)


def test_filtering_zone_by_bbox(org, drf_fleet_operator, zone):
    url = reverse_query('lock8:zone-list',
                        {'bbox': '-74.01352,40.75981,-73.91730,40.80530'})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:zone-list',
                        {'bbox': '13.3683645,52.5062991,13.4240352,52.5390943'}
                        )
    drf_fleet_operator.assert_count(url, 0)


def test_filtering_zone_by_bbox_error(org, drf_fleet_operator, zone):
    url = reverse_query('lock8:zone-list',
                        {'bbox': ',,,'})
    drf_fleet_operator.assert_400(url)


def test_create_zone_errors(org, drf_fleet_operator):
    url = reverse_query('lock8:zone-list')
    org_url = reverse_query('lock8:organization-detail',
                            kwargs={'uuid': org.uuid})
    poly = {'coordinates': [[
        [37.410387, -122.025346], [37.41022491455078, -122.0252227783203],
        [37.41043090820313, -122.0249633789062],
        [37.4107437134, -122.0250015259],
        [37.4107666015625, -122.0252685546875],
        [37.410387, -122.025346]]], 'type': 'Polygon'}
    drf_fleet_operator.assert_400(url, data={
        'organization': org_url,
        'name': 'risk_zone_test',
        'polygon': poly,
    }, format='json')
