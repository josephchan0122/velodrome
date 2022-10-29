import itertools

from django.contrib.gis.geos import Polygon
import pytest

from velodrome.lock8.tests.utils import sorted_dicts
from velodrome.lock8.utils import reverse_query


def sorter(value):
    bbox = value['bbox']
    if bbox['type'] == 'Point':
        return bbox['coordinates']
    return [*itertools.chain.from_iterable(bbox['coordinates'])]


def test_api_get_clusters_simple(drf_fleet_operator, bicycle,
                                 middle_of_central_park, middle_of_somewhere,
                                 middle_of_theodore_roosevelt_park, bicycle2,
                                 bicycle3, create_gps_tracking):

    for b, coords in ((bicycle, middle_of_central_park),
                      (bicycle2, middle_of_theodore_roosevelt_park),
                      (bicycle3, middle_of_somewhere)):
        b.lock.activate()
        create_gps_tracking(b, *coords)

    # somewhere
    url = reverse_query('lock8:cluster-list', {'bbox': '0,0,2,2'})
    response = drf_fleet_operator.assert_success(url)
    assert response.data == {
        'density_total': 1,
        'clusters': [
            {'centroid': {'coordinates': [1.0, 1.5], 'type': 'Point'},
             'density': 1,
             'bbox': {'type': 'Point', 'coordinates': [1.0, 1.5]}}]}

    # central park + theodore roosevelt park
    url = reverse_query('lock8:cluster-list',
                        {'bbox': '-74.01352,40.75981,-73.91730,40.80530'})
    response = drf_fleet_operator.assert_success(url)

    assert len(response.data) == 2
    assert response.data['density_total'] == 2
    assert sorted(response.data['clusters'], key=sorter) == [
        {'centroid': {'coordinates': [-73.97479, 40.78159],
                      'type': 'Point'},
         'bbox': {'coordinates': [-73.97479, 40.78159], 'type': 'Point'},
         'density': 1},
        {'centroid': {'coordinates': [-73.961900369117, 40.7874455],
                      'type': 'Point'},
         'bbox': {'type': 'Point',
                  'coordinates': [-73.961900369117, 40.7874455]},
         'density': 1},
    ]


def test_api_get_state_clusters(drf_fleet_operator, create_gps_tracking,
                                bicycle, middle_of_central_park,
                                bicycle2, middle_of_theodore_roosevelt_park,
                                bicycle3, side_of_thedore_roosevelt_park,
                                bicycle4, bicycle5):
    bicycle2.declare_available()
    bicycle3.declare_available()
    bicycle4.declare_available()

    for b, coords in ((bicycle, middle_of_central_park),
                      (bicycle2, middle_of_theodore_roosevelt_park),
                      (bicycle3, middle_of_theodore_roosevelt_park),
                      (bicycle4, side_of_thedore_roosevelt_park),
                      (bicycle5, middle_of_theodore_roosevelt_park)):
        create_gps_tracking(b, *coords, declare_available=False)

    url = reverse_query('lock8:cluster-list', {
        'bbox': '-73.97932,40.77906,-73.95526,40.79044',
        'include_state': True})
    response = drf_fleet_operator.assert_success(url)

    response_with_state = response.data
    assert response_with_state == {
        'density_total': 5,
        'clusters': [
            {'centroid': {'type': 'Point',
                          'coordinates': [-73.97479, 40.78159]},
             'density': {'in_maintenance': 1, 'available': 2},
             'bbox': {'type': 'Point',
                      'coordinates': [-73.97479, 40.78159]}},
            {'centroid': {'type': 'Point',
                          'coordinates': [-73.9753611, 40.782553]},
             'density': {'available': 1},
             'bbox': {'type': 'Point',
                      'coordinates': [-73.9753611, 40.782553]}},
            {'centroid': {'type': 'Point',
                          'coordinates': [-73.961900369117, 40.7874455]},
             'density': {'in_maintenance': 1},
             'bbox': {'type': 'Point',
                      'coordinates': [-73.961900369117, 40.7874455]}}
        ]}

    # Compare to result without state grouping.
    clusters_with_state = response.data['clusters']
    url_without_state = reverse_query('lock8:cluster-list', {
        'bbox': '-73.97932,40.77906,-73.95526,40.79044',
        'include_state': False})
    response = drf_fleet_operator.assert_success(url_without_state)
    clusters_without_state = response.data['clusters']
    for c in clusters_with_state:
        c['density'] = sum(c['density'].values())
    assert sorted_dicts(clusters_without_state, ['bbox']) == \
        sorted_dicts(clusters_with_state, ['bbox'])


@pytest.mark.parametrize('include_state', ('with_state', 'without_state'))
def test_filter_clusters_with_alert_type(include_state, drf_fleet_operator,
                                         bicycle, create_gps_tracking,
                                         middle_of_central_park):
    from velodrome.lock8.models import Affiliation, Alert

    include_state = include_state == 'with_state'
    org = bicycle.organization
    create_gps_tracking(bicycle, *middle_of_central_park)

    url = reverse_query('lock8:cluster-list', {
        'bbox': '-73.97932,40.77906,-73.95526,40.79044',
        'alert_type': Alert.LOST_BICYCLE_REPORTED,
        'include_state': include_state})
    drf_fleet_operator.assert_success(url, {'density_total': 0,
                                            'clusters': []})

    # Create one alert on bicycle.
    Alert.objects.create(organization=org,
                         alert_type=Alert.LOST_BICYCLE_REPORTED,
                         causality=bicycle,
                         roles=[Affiliation.FLEET_OPERATOR])
    expected = {
        'density_total': 1,
        'clusters': [
            {'centroid': {'type': 'Point',
                          'coordinates': [-73.961900369117, 40.7874455]},
             'density': {'available': 1} if include_state else 1,
             'bbox': {'type': 'Point',
                      'coordinates': [-73.961900369117, 40.7874455]}}]}
    drf_fleet_operator.assert_success(url, expected)

    # Create two alerts on lock (one being stopped).
    # This tests filter_by_alert_type to not use an OUTER JOIN.
    alert = Alert.objects.create(organization=org,
                                 alert_type=Alert.LOW_BATTERY,
                                 causality=bicycle.lock,
                                 roles=[Affiliation.FLEET_OPERATOR])
    alert.stop()
    Alert.objects.create(organization=org,
                         alert_type=Alert.LOW_BATTERY,
                         causality=bicycle.lock,
                         roles=[Affiliation.FLEET_OPERATOR])
    drf_fleet_operator.assert_success(url, expected)

    url = reverse_query('lock8:cluster-list', (
        ('bbox', '-73.97932,40.77906,-73.95526,40.79044'),
        ('alert_type', Alert.LOST_BICYCLE_REPORTED),
        ('alert_type', Alert.LOW_BATTERY),
        ('include_state', include_state)))
    drf_fleet_operator.assert_success(url, expected)


def test_api_state_clusters_with_alerts(drf_fleet_operator, org,
                                        bicycle, bicycle2,
                                        create_gps_tracking,
                                        middle_of_central_park):
    """Ensure that bicycles with multiple alerts don't count more than once"""

    from velodrome.lock8.models import Affiliation, Alert

    for b in (bicycle, bicycle2):
        Alert.objects.create(
            organization=org,
            alert_type=Alert.RIDE_OUTSIDE_SERVICE_AREA,
            roles=[Affiliation.FLEET_OPERATOR],
            causality=b
        )

        create_gps_tracking(b, *middle_of_central_park)

    # Add one extra alert to bicycle
    Alert.objects.create(
        organization=org,
        alert_type=Alert.LOST_BICYCLE_REPORTED,
        roles=[Affiliation.FLEET_OPERATOR],
        causality=bicycle,
    )

    expected = {
        'density_total': 2,
        'clusters': [
            {'centroid': {'type': 'Point',
                          'coordinates': [-73.961900369117, 40.7874455]},
             'density': {'available': 2},
             'bbox': {'type': 'Point',
                      'coordinates': [-73.961900369117, 40.7874455]}}]}

    url = reverse_query('lock8:cluster-list', (
        ('bbox', '-73.97932,40.77906,-73.95526,40.79044'),
        ('include_state', True),
        ('alert_type', Alert.RIDE_OUTSIDE_SERVICE_AREA),
        ('alert_type', Alert.LOST_BICYCLE_REPORTED),)
    )
    drf_fleet_operator.assert_success(url, expected)


def test_api_get_clusters_zooming(drf_fleet_operator, bicycle,
                                  middle_of_central_park,
                                  middle_of_theodore_roosevelt_park,
                                  bicycle2, bicycle3, create_gps_tracking):
    from velodrome.lock8.models import Bicycle

    near_middle_of_central_park = (-73.961900369116, 40.7874456)

    for b, coords in (
            (bicycle, middle_of_central_park),
            (bicycle2, middle_of_theodore_roosevelt_park),
            (bicycle3, near_middle_of_central_park)):
        create_gps_tracking(b, *coords)

    # Big Zoom
    url = reverse_query('lock8:cluster-list',
                        {'bbox': '-74.01352,40.75981,-73.91730,40.80530'})
    response = drf_fleet_operator.assert_success(url)

    BBOX_COORDS = [[pytest.approx(-73.9619004191165),
                    pytest.approx(40.787445)],
                   [pytest.approx(-73.96190031911651),
                    pytest.approx(40.787445600000005)]]
    assert len(response.data) == 2
    assert response.data['density_total'] == 3
    assert sorted(response.data['clusters'], key=sorter) == [
        {'density': 1,
         'centroid': {'type': 'Point',
                      'coordinates': [-73.97479, 40.78159]},
         'bbox': {'type': 'Point',
                  'coordinates': [-73.97479, 40.78159]}},
        {'density': 2,
         'centroid': {'type': 'Point',
                      'coordinates': [-73.9619003691165, 40.78744555]},
         'bbox': {'type': 'Polygon',
                  'coordinates': BBOX_COORDS}
         },
    ]

    clusters = response.data['clusters']
    bbox_for_zoom_search = Polygon.from_bbox(
        [coord for coords in clusters[0]['bbox']['coordinates']
         for coord in coords])

    assert (Bicycle.objects.filter(
        public_tracking__point__contained=bbox_for_zoom_search).count() ==
            2)

    # Smaller Zoom
    url = reverse_query('lock8:cluster-list',
                        {'bbox': '-73.97932,40.77906,-73.95526,40.79044'})
    response = drf_fleet_operator.assert_success(url)
    assert len(response.data) == 2
    assert response.data['density_total'] == 3
    assert sorted(response.data['clusters'], key=sorter) == [
        {'centroid': {'coordinates': [-73.97479, 40.78159],
                      'type': 'Point'},
         'density': 1,
         'bbox': {'coordinates': [-73.97479, 40.78159], 'type': 'Point'}},
        {'centroid': {'type': 'Point',
                      'coordinates': [-73.9619003691165, 40.78744555]},
         'density': 2,
         'bbox': {'type': 'Polygon',
                  'coordinates': BBOX_COORDS}},
    ]


def test_api_get_clusters_anonymous(drf_client, bicycle,
                                    middle_of_somewhere, org,
                                    create_gps_tracking):
    org.is_open_fleet = True
    org.save()

    create_gps_tracking(bicycle, *middle_of_somewhere)

    # somewhere
    url = reverse_query('lock8:cluster-list', {'bbox': '0,0,2,2'})
    response = drf_client.assert_success(url)
    assert response.data == {
        'density_total': 1,
        'clusters': [
            {'centroid': {'coordinates': [1.0, 1.5], 'type': 'Point'},
             'bbox': {'type': 'Point', 'coordinates': [1.0, 1.5]},
             'density': 1}]}


@pytest.mark.parametrize('value,message', (
    ('0,0',
     {'bbox': [{'message': 'This value does not match the required pattern.',
                'code': 'invalid'}]}),
    (',,0,0,0,0',
     {'bbox': [{'message': 'This value does not match the required pattern.',
                'code': 'invalid'}]}),
    ('0,0,0,0',
     {'bbox': [{'message': 'Bounding box too small',
                'code': 'invalid'}]}),
))
def test_api_get_clusters_invalid(drf_fleet_operator, value, message):
    url = reverse_query('lock8:cluster-list', {'bbox': value})
    drf_fleet_operator.assert_400(url, message)


def test_api_get_clusters_filtering(drf_fleet_operator, org, another_org,
                                    active_lock, gps_tracking_on_bicycle):
    # somewhere
    url = reverse_query('lock8:cluster-list', {'bbox': '0,0,2,2',
                                               'organization': org.uuid})
    response = drf_fleet_operator.assert_success(url)
    assert len(response.data['clusters']) == 1

    url = reverse_query('lock8:cluster-list',
                        {'bbox': '0,0,2,2', 'organization': another_org.uuid})
    response = drf_fleet_operator.assert_success(url)
    assert len(response.data['clusters']) == 0


def test_api_get_clusters_renter(drf_renter, bicycle, bicycle2, bicycle3,
                                 middle_of_central_park,
                                 middle_of_theodore_roosevelt_park,
                                 alice, create_gps_tracking):
    """
    When a renter uses cluster endpoint and several rental sessions
    exists for the bicycles, bicycles gets duplicated.
    """

    for b, coords in (
            (bicycle, middle_of_central_park),
            (bicycle2, middle_of_theodore_roosevelt_park),
            (bicycle3, middle_of_central_park)):
        b.declare_available()
        iterator = reversed(range(3))
        while next(iterator):
            # generate at least 2 reservation and 2 rental sessions
            b.reserve(by=alice)
            b.rent(by=alice)
            b.return_()
        create_gps_tracking(b, *coords)

    # central park + theodore roosevelt park
    url = reverse_query('lock8:cluster-list',
                        {'bbox': '-74.01352,40.75981,-73.91730,40.80530'})
    response = drf_renter.assert_success(url)
    assert response.data == {
        'density_total': 3,
        'clusters': [
            {'centroid': {'coordinates': [-73.961900369117, 40.7874455],
                          'type': 'Point'},
             'bbox': {'type': 'Point',
                      'coordinates': [-73.961900369117, 40.7874455]},
             'density': 2},
            {'centroid': {'coordinates': [-73.97479, 40.78159],
                          'type': 'Point'},
             'bbox': {'coordinates': [-73.97479, 40.78159], 'type': 'Point'},
             'density': 1}]}


def test_bbox_encompasses_international_date_line(drf_fleet_operator):
    url = reverse_query('lock8:cluster-list',
                        {'bbox': '145.674771,-7.723224,-82.489291,69.918087'})
    drf_fleet_operator.assert_success(url)


def test_api_get_model_clusters(drf_fleet_operator, create_gps_tracking,
                                bicycle, middle_of_central_park,
                                bicycle2, middle_of_theodore_roosevelt_park,
                                bicycle3, side_of_thedore_roosevelt_park,
                                bicycle4, bicycle5, bicycle_model):
    for bicy in (bicycle2, bicycle3, bicycle4):
        bicy.model = bicycle_model
        bicy.declare_available()

    for b, coords in ((bicycle, middle_of_central_park),
                      (bicycle2, middle_of_theodore_roosevelt_park),
                      (bicycle3, middle_of_theodore_roosevelt_park),
                      (bicycle4, side_of_thedore_roosevelt_park),
                      (bicycle5, middle_of_theodore_roosevelt_park)):
        create_gps_tracking(b, *coords, declare_available=False)

    url = reverse_query('lock8:cluster-list', {
        'bbox': '-73.97932,40.77906,-73.95526,40.79044',
        'include_model': True})
    response = drf_fleet_operator.assert_success(url)

    response_with_model = response.data
    assert response_with_model == {
        'density_total': 5,
        'clusters': [
            {'centroid': {'type': 'Point',
                          'coordinates': [-73.97479, 40.78159]},
             'density': {None: 1, 'bicycle_model': 2},
             'bbox': {'type': 'Point',
                      'coordinates': [-73.97479, 40.78159]}},
            {'centroid': {'type': 'Point',
                          'coordinates': [-73.9753611, 40.782553]},
             'density': {'bicycle_model': 1},
             'bbox': {'type': 'Point',
                      'coordinates': [-73.9753611, 40.782553]}},
            {'centroid': {'type': 'Point',
                          'coordinates': [-73.961900369117, 40.7874455]},
             'density': {None: 1},
             'bbox': {'type': 'Point',
                      'coordinates': [-73.961900369117, 40.7874455]}}
        ]}

    # Compare to result without state grouping.
    clusters_with_state = response.data['clusters']
    url_without_state = reverse_query('lock8:cluster-list', {
        'bbox': '-73.97932,40.77906,-73.95526,40.79044',
        'include_state': False})
    response = drf_fleet_operator.assert_success(url_without_state)
    clusters_without_state = response.data['clusters']
    for c in clusters_with_state:
        c['density'] = sum(c['density'].values())
    assert sorted_dicts(clusters_without_state, ['bbox']) == \
        sorted_dicts(clusters_with_state, ['bbox'])


def test_api_get_clusters_grouping_are_exclusive(drf_fleet_operator):
    url = reverse_query('lock8:cluster-list', {
        'bbox': '-73.97932,40.77906,-73.95526,40.79044',
        'include_state': True, 'include_model': True})
    drf_fleet_operator.assert_400(url)
