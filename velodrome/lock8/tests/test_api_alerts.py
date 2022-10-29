import datetime as dt

from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework import status

from velodrome.lock8.models import Alert
from velodrome.lock8.utils import reverse_query

ALERT_TYPES = [t[0] for t in Alert.TYPES]


def test_post_outside_operational_period(request, bicycle, drf_admin,
                                         bicycle_model, photo):
    bicycle = request.getfixturevalue('bicycle')
    bicycle_model.photo = photo
    bicycle_model.save()
    bicycle.model = bicycle_model
    bicycle.save()

    url = reverse_query('lock8:alert-list')
    response = drf_admin.post(
        url,
        {
            "alert_type": "bicycle.outside_operational_period",
            "causality": f"https://api.lock8.me/api/bicycles/{bicycle.uuid}/"
        }
    )
    assert response.status_code == status.HTTP_201_CREATED, response.data


def test_bicycle_location_alerts(alert_stolen_bicycle, org, drf_fleet_operator,
                                 bicycle):
    from velodrome.lock8.models import PublicTracking
    longitude = 33
    latitude = -57
    attributes = {
        'gps_utm_zone': -7.530941473730957e-14,
        'gps_accuracy': 30807.1328125,
        'time_stamp': 1428509326,
        'gps_longitude': longitude * 1e6,
        'gps_latitude': latitude * 1e6
    }
    alert = alert_stolen_bicycle
    bicycle.public_tracking = PublicTracking.objects.create(
        attributes=attributes
    )
    alert.causality = bicycle
    alert.context = {'location': {'coordinates': [longitude, latitude],
                                  'type': 'Point'}}
    bicycle.save()
    alert.save()

    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})
    bicycle_url = reverse_query('lock8:bicycle-detail',
                                kwargs={'uuid': bicycle.uuid})
    url = reverse_query('lock8:alert-detail',
                        kwargs={'uuid': alert.uuid})
    drf_fleet_operator.assert_success(url, {
        'uuid': str(alert.uuid),
        'organization': 'http://testserver' + organization_url,
        'user': None,
        'causality': 'http://testserver' + bicycle_url,
        'bicycle': 'http://testserver' + bicycle_url,
        'causality_info': {'resource_type': 'bicycle'},
        'causality_resource_type': 'bicycle',
        'alert_type': 'bicycle.bike_stolen',
        'message': 'alert_stolen_bicycle',
        'role': '',
        'roles': ['fleet_operator'],
        'extra': {'lock_bleid': alert.causality.lock.bleid,
                  'lock_uuid': str(alert.causality.lock.uuid),
                  'bicycle_coordinates': (longitude, latitude),
                  'bicycle_gps_accuracy': attributes['gps_accuracy'],
                  'bicycle_gps_latitude': attributes['gps_latitude'],
                  'bicycle_gps_longitude': attributes['gps_longitude'],
                  'bicycle_model_name': None,
                  'bicycle_model_photo': None,
                  'location': {'coordinates': [longitude, latitude],
                               'type': 'Point'},
                  'bicycle_name': 'bicycle',
                  'bicycle_state': 'in_maintenance',
                  'bicycle_uuid': str(bicycle.uuid)},
        'state': 'new',
        'concurrency_version': alert.concurrency_version,
        'modified': alert.modified.isoformat()[:-13] + 'Z',
        'created': alert.created.isoformat()[:-13] + 'Z',
        'url': 'http://testserver' + url,
    })


def test_crud_alerts(request, drf_fleet_operator, fleet_operator, org, owner,
                     alert_wo_bicycle, bicycle_model, photo):
    from velodrome.lock8.models import Affiliation, Alert

    alert = alert_wo_bicycle
    lock = alert_wo_bicycle.causality

    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})
    lock_url = reverse_query('lock8:lock-detail',
                             kwargs={'uuid': lock.uuid})
    url = reverse_query('lock8:alert-detail',
                        kwargs={'uuid': alert.uuid})
    drf_fleet_operator.assert_success(url, {
        'uuid': str(alert.uuid),
        'organization': 'http://testserver' + organization_url,
        'user': None,
        'causality': 'http://testserver' + lock_url,
        'bicycle': None,
        'causality_info': {'resource_type': 'lock'},
        'causality_resource_type': 'lock',
        'alert_type': 'lock.bat.low',
        'message': 'alert_wo_bicycle',
        'role': '',
        'roles': ['fleet_operator'],
        'extra': {'lock_bleid': lock.bleid,
                  'lock_uuid': str(lock.uuid),
                  'bicycle_gps_accuracy': None,
                  'bicycle_model_name': None,
                  'bicycle_model_photo': None,
                  'bicycle_name': None,
                  'bicycle_state': None,
                  'bicycle_uuid': None},
        'state': 'new',
        'concurrency_version': alert.concurrency_version,
        'modified': alert.modified.isoformat()[:-13] + 'Z',
        'created': alert.created.isoformat()[:-13] + 'Z',
        'url': 'http://testserver' + url,
    })

    # Add bicycle to the lock.
    bicycle = request.getfixturevalue('bicycle')
    bicycle_model.photo = photo
    bicycle_model.save()
    bicycle.model = bicycle_model
    bicycle.save()

    bicycle_url = reverse_query('lock8:bicycle-detail',
                                kwargs={'uuid': bicycle.uuid})
    url = reverse_query('lock8:alert-detail',
                        kwargs={'uuid': alert.uuid})
    drf_fleet_operator.assert_success(url, {
        'uuid': str(alert.uuid),
        'organization': 'http://testserver' + organization_url,
        'user': None,
        'causality': 'http://testserver' + lock_url,
        'bicycle': 'http://testserver' + bicycle_url,
        'causality_info': {'resource_type': 'lock'},
        'causality_resource_type': 'lock',
        'alert_type': 'lock.bat.low',
        'message': 'alert_wo_bicycle',
        'role': '',
        'roles': ['fleet_operator'],
        'extra': {'lock_bleid': lock.bleid,
                  'lock_uuid': str(lock.uuid),
                  'bicycle_gps_accuracy': None,
                  'bicycle_model_name': bicycle.model.name,
                  'bicycle_model_photo': bicycle.model.photo.image.url,
                  'bicycle_name': bicycle.name,
                  'bicycle_state': bicycle.state,
                  'bicycle_uuid': str(bicycle.uuid)},
        'state': 'new',
        'concurrency_version': alert.concurrency_version,
        'modified': alert.modified.isoformat()[:-13] + 'Z',
        'created': alert.created.isoformat()[:-13] + 'Z',
        'url': 'http://testserver' + url,
    })

    alert = Alert.objects.create(
        organization=org,
        alert_type=Alert.RIDE_OUTSIDE_SERVICE_AREA,
        causality=bicycle,
        roles=[Affiliation.FLEET_OPERATOR],
        message='Alert!',
    )
    bicycle_url = reverse_query('lock8:bicycle-detail',
                                kwargs={'uuid': bicycle.uuid})
    url = reverse_query('lock8:alert-detail',
                        kwargs={'uuid': alert.uuid})
    drf_fleet_operator.assert_success(url, {
        'uuid': str(alert.uuid),
        'organization': 'http://testserver' + organization_url,
        'causality': 'http://testserver' + bicycle_url,
        'causality_info': {'resource_type': 'bicycle'},
        'causality_resource_type': 'bicycle',
        'bicycle': 'http://testserver' + bicycle_url,
        'user': None,
        'alert_type': 'bicycle.ride_outside',
        'message': 'Alert!',
        'role': '',
        'roles': ['fleet_operator'],
        'extra': {'lock_bleid': lock.bleid,
                  'lock_uuid': str(lock.uuid),
                  'bicycle_gps_accuracy': None,
                  'bicycle_model_name': bicycle.model.name,
                  'bicycle_model_photo': bicycle.model.photo.image.url,
                  'bicycle_name': bicycle.name,
                  'bicycle_state': bicycle.state,
                  'bicycle_uuid': str(bicycle.uuid)},
        'state': 'new',
        'concurrency_version': alert.concurrency_version,
        'modified': alert.modified.isoformat()[:-13] + 'Z',
        'created': alert.created.isoformat()[:-13] + 'Z',
        'url': 'http://testserver' + url,
    })

    # TODO: Find out what author meant before with passing {'zone'} (like set)
    response = drf_fleet_operator.put(
        url,
        data={'context': {'zone': None}},
        format='json'
    )
    assert response.status_code == status.HTTP_403_FORBIDDEN, response.data

    url = reverse_query('lock8:alert-list')
    response = drf_fleet_operator.post(url, data={})
    assert response.status_code == status.HTTP_403_FORBIDDEN

    url = reverse_query('lock8:alert-actions',
                        kwargs={'uuid': alert.uuid})
    response = drf_fleet_operator.post(url, data={'type': 'resolve'})
    assert response.status_code == status.HTTP_200_OK, response.data

    alert.refresh_from_db()
    assert alert.state == 'resolved'

    response = drf_fleet_operator.patch(url)
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    response = drf_fleet_operator.delete(url)
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED


def test_crud_zone_alerts(drf_fleet_operator, org, alert_zone_threshold, zone):
    alert = alert_zone_threshold
    organization_url = reverse_query(
        "lock8:organization-detail", kwargs={"uuid": org.uuid}
    )
    zone_url = reverse_query("lock8:zone-detail", kwargs={"uuid": zone.uuid})
    url = reverse_query("lock8:alert-detail", kwargs={"uuid": alert.uuid})

    drf_fleet_operator.assert_success(
        url,
        {
            "uuid": str(alert.uuid),
            "organization": "http://testserver" + organization_url,
            "user": None,
            "causality": "http://testserver" + zone_url,
            "bicycle": None,
            "causality_info": {"resource_type": "zone"},
            "causality_resource_type": "zone",
            "alert_type": alert.alert_type,
            "message": alert.message,
            "role": "",
            "roles": ["fleet_operator"],
            "extra": {
                "bicycle_gps_accuracy": None,
                "bicycle_model_name": None,
                "bicycle_model_photo": None,
                "bicycle_name": None,
                "bicycle_state": None,
                "bicycle_uuid": None,
            },
            "state": "new",
            "concurrency_version": alert.concurrency_version,
            "modified": alert.modified.isoformat()[:-13] + "Z",
            "created": alert.created.isoformat()[:-13] + "Z",
            "url": "http://testserver" + url,
        },
    )

    response = drf_fleet_operator.put(url, data={"context": {"zone"}},
                                      format="json")
    assert response.status_code == status.HTTP_403_FORBIDDEN, response.data

    url = reverse_query("lock8:alert-list")
    response = drf_fleet_operator.post(url, data={})
    assert response.status_code == status.HTTP_403_FORBIDDEN

    url = reverse_query("lock8:alert-actions", kwargs={"uuid": alert.uuid})
    response = drf_fleet_operator.post(url, data={"type": "resolve"})
    assert response.status_code == status.HTTP_200_OK, response.data

    alert.refresh_from_db()
    assert alert.state == "resolved"

    response = drf_fleet_operator.patch(url)
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    response = drf_fleet_operator.delete(url)
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED


def test_crud_alerts_admin(request, alert_type, drf_admin, org,
                           lock, bicycle, mocker, zone):
    from velodrome.lock8.models import Affiliation, Alert, AlertStates

    mocker.spy(Alert, 'send_async')
    url = reverse_query('lock8:alert-list')

    context = {'anything': {'is': 'allowed'},
               'lock_bleid': 'will_not_be_in_extra'}
    alert_type, _, additional_fixture = alert_type.partition('+')
    fixture = (request.getfixturevalue(additional_fixture)
               if additional_fixture else None)
    is_lock = True
    if alert_type.startswith('bicycle.'):
        causality = bicycle
    elif alert_type.startswith('zone.'):
        causality = zone
        is_lock = False
    else:
        assert alert_type.startswith('lock.')
        causality = lock
    alert_data = {'causality': causality.get_absolute_url(),
                  'context': context}
    if additional_fixture == 'zone':
        context['zone_uuid'] = fixture.uuid
        with_zone = True
    else:
        with_zone = False
    if additional_fixture == 'alice':
        user_url = reverse_query('lock8:user-detail',
                                 kwargs={'uuid': fixture.uuid})
        alert_data['user'] = user_url
        with_user = True
    else:
        with_user = False

    alert_data['alert_type'] = alert_type

    response = drf_admin.post(url, data=alert_data, format='json')
    assert response.status_code == status.HTTP_201_CREATED, response.data

    alert = Alert.objects.get(uuid=response.data['uuid'])
    assert alert.send_async.call_count == 1
    default_message = 'Causality: %s %s | Type: %s' % (
                causality._meta.model_name, causality.uuid, alert_type)

    assert alert.causality == causality
    assert alert.alert_type == alert_type
    assert alert.roles == [Affiliation.FLEET_OPERATOR]
    assert alert.message == default_message
    assert alert.state == AlertStates.NEW.value
    assert alert.user == (fixture if with_user else None)
    assert alert.extra['anything'] == {'is': 'allowed'}
    if is_lock:
        assert alert.extra['lock_bleid'] == lock.bleid
    if with_zone:
        assert alert.extra['zone_uuid'] == str(fixture.uuid)

    response = drf_admin.post(url, data=alert_data, format='json')
    assert response.status_code == status.HTTP_409_CONFLICT

    url = reverse_query('lock8:alert-actions', kwargs={'uuid': alert.uuid})
    response = drf_admin.post(url, data={'type': 'stop'})
    assert response.status_code == status.HTTP_200_OK, response.data

    alert.refresh_from_db()
    assert alert.state == AlertStates.STOPPED.value


def test_crud_alerts_admin_without_context(request, drf_admin, lock, bicycle):
    from velodrome.lock8.models import Alert

    url = reverse_query('lock8:alert-list')
    lock_url = reverse_query('lock8:lock-detail', kwargs={'uuid': lock.uuid})

    alert_data = {'causality': lock_url,
                  'alert_type': Alert.DEVICE_SHUTDOWN}
    response = drf_admin.post(url, data=alert_data, format='json')
    assert response.status_code == status.HTTP_201_CREATED, response.data


def test_alert_creation_handles_concurrency_version_in_kwargs(request, bicycle,
                                                              drf_admin):
    from velodrome.lock8.models import Alert

    lock = bicycle.lock
    concurrency_version = 42
    url = reverse_query('lock8:alert-list')
    lock_url = reverse_query('lock8:lock-detail', kwargs={'uuid': lock.uuid})
    alert_data = {'causality': lock_url,
                  'alert_type': Alert.DEVICE_SHUTDOWN,
                  'concurrency_version': concurrency_version,
                  'context': {'anything': {'is': 'allowed'},
                              'lock_bleid': 'will_not_be_in_extra'}}

    response = drf_admin.post(url, data=alert_data, format='json')
    assert response.status_code == status.HTTP_201_CREATED, response.data

    alert = Alert.objects.get(uuid=response.data['uuid'])
    assert alert.causality == lock
    assert alert.concurrency_version != concurrency_version


def test_alert_missing_causality_resource_type(drf_fleet_operator, org):
    from velodrome.lock8.models import Affiliation, Alert

    alert_ctype = ContentType.objects.get(app_label="lock8", model="alert")
    alert = Alert.objects.create(
        organization=org,
        content_type=alert_ctype,
        object_id=42,
        roles=[Affiliation.FLEET_OPERATOR],
        alert_type=Alert.LOW_BATTERY,
    )
    url = reverse_query('lock8:alert-detail', kwargs={'uuid': alert.uuid})
    response = drf_fleet_operator.get(url)
    assert response.data['causality_resource_type'] is None
    assert response.data['causality_info'] == {}


def test_alert_filtering(drf_fleet_operator, alert, org, lock, zone,
                         non_matching_uuid, bicycle, alert_zone_threshold):
    url = reverse_query('lock8:alert-list', {'role': 'XX'})
    drf_fleet_operator.assert_invalid_choice(url, 'role', 'XX')

    url = reverse_query('lock8:alert-list', {'role': 'fleet_operator'})
    drf_fleet_operator.assert_count(url, 2)

    url = reverse_query('lock8:alert-list', {'roles': 'fleet_operator'})
    drf_fleet_operator.assert_count(url, 2)

    url = reverse_query('lock8:alert-list', {'organization': org.uuid})
    drf_fleet_operator.assert_count(url, 2)

    url = reverse_query('lock8:alert-list', {'organization':
                                             non_matching_uuid})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:alert-list', {'state': 'sent'})
    drf_fleet_operator.assert_invalid_choice(url, 'state', 'sent')

    url = reverse_query('lock8:alert-list', {'state': 'resolved'})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:alert-list', {'state': 'new'})
    drf_fleet_operator.assert_count(url, 2)

    url = reverse_query('lock8:alert-list', {'alert_type': 'lock.bat.low'})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:alert-list', {'alert_type': 'doesnotexists'})
    drf_fleet_operator.assert_invalid_choice(url, 'alert_type',
                                             'doesnotexists')

    url = reverse_query('lock8:alert-list', {'causality': str(lock.uuid)})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:alert-list', {'causality': non_matching_uuid})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:alert-list', {'bicycle': non_matching_uuid})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:alert-list', {
        'alert_type': alert_zone_threshold.alert_type
    })
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:alert-list', {'causality': str(zone.uuid)})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:alert-list', {'zone': non_matching_uuid})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:alert-list', {'zone': str(zone.uuid)})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:alert-list', (
        ('zone', str(zone.uuid)), ('zone', non_matching_uuid),))
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:alert-list', {'bicycle': 'invalid_uuid'})
    drf_fleet_operator.assert_400(url,
                                  {'bicycle': [
                                      {'message': 'Enter a valid UUID.',
                                       'code': 'invalid'}]})

    url = reverse_query('lock8:alert-list', {'bicycle': str(bicycle.uuid)})
    drf_fleet_operator.assert_count(url, 1)


def test_alert_filtering_bbox(drf_fleet_operator, bicycle, active_lock, org,
                              owner, create_gps_tracking):
    from velodrome.lock8.models import Affiliation, Alert

    Alert.objects.create(organization=org,
                         causality=bicycle,
                         roles=[Affiliation.FLEET_OPERATOR],
                         alert_type=Alert.LOW_BATTERY)

    timestamp = timezone.now() + dt.timedelta(seconds=2)
    create_gps_tracking(active_lock, 13.403145, 52.527433,
                        attributes={'time_stamp': timestamp.timestamp()})
    bbox_points1 = {'bbox': '13.3683645,52.5062991,13.4240352,52.5390943'}
    url = reverse_query('lock8:alert-list', bbox_points1)
    drf_fleet_operator.assert_count(url, 1)

    bbox_points2 = {'bbox': '-0.0903313,51.5106892,-0.09256,51.50701'}
    url = reverse_query('lock8:alert-list', bbox_points2)
    drf_fleet_operator.assert_count(url, 0)


def test_alert_filtering_multiple_bikes(drf_fleet_operator, alert, alert2,
                                        org, lock, bicycle, bicycle2):
    url = reverse_query('lock8:alert-list', (('bicycle', bicycle.uuid),
                                             ('bicycle', bicycle2.uuid)))
    drf_fleet_operator.assert_count(url, 2)


def test_alert_filtering_bicycle_state(drf_fleet_operator, alert, bicycle):

    url = reverse_query('lock8:alert-list', {'bicycle_state': bicycle.state})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:alert-list',
                        {'bicycle_state': 'invalid_state'})
    drf_fleet_operator.assert_400(
        url,
        {'bicycle_state': [
            {'message': 'Select a valid choice. invalid_state is not one '
             'of the available choices.', 'code': 'invalid_choice'}]})


def test_alert_db_queries_basic(drf_fleet_operator, alert, alert2):
    # Clear ContentType cache, to make this test predictable (when run alone).
    ContentType.objects.clear_cache()

    url = reverse_query('lock8:alert-list')
    with CaptureQueriesContext(connection) as capture:
        drf_fleet_operator.assert_count(url, 2)
    content_type_queries = [x for x in capture.captured_queries if
                            x['sql'].startswith(
                                'SELECT "django_content_type"')]
    assert len(content_type_queries) == 4, '\n\n'.join(
        q['sql'] for q in content_type_queries)
    assert len(capture.captured_queries) == 14, '\n\n'.join(
        q['sql'] for q in capture.captured_queries)


def test_alert_db_queries_with_bicycle_filter(drf_fleet_operator, alert,
                                              alert2, bicycle):
    # Clear ContentType cache, to make this test predictable (when run alone).
    ContentType.objects.clear_cache()

    url = reverse_query('lock8:alert-list', {'bicycle': bicycle.uuid})
    with CaptureQueriesContext(connection) as capture:
        drf_fleet_operator.assert_count(url, 1)
    # The extra query is because of the validation of the filter input.
    # (ModelMultipleChoiceField.clean/_check_values).
    assert len(capture.captured_queries) == 14, '\n\n'.join(
        q['sql'] for q in capture.captured_queries)


def test_alert_sorting_default(drf_fleet_operator, request):
    # access fixture here to have expected order on creation date
    alert1 = request.getfixturevalue('alert')
    alert2 = request.getfixturevalue('alert2')
    alert3 = request.getfixturevalue('alert_stolen_bicycle')
    assert alert1.created < alert2.created < alert3.created

    url = reverse_query('lock8:alert-list')
    response = drf_fleet_operator.assert_success(url)
    assert [a['uuid'] for a in response.data['results']] == [
        str(alert3.uuid), str(alert2.uuid), str(alert1.uuid)]


def test_alert_escalation_api(drf_fleet_operator, fleet_operator, org, alert):
    from velodrome.lock8.models import Affiliation, Task

    url = reverse_query('lock8:alert-actions',
                        kwargs={'uuid': alert.uuid})
    response = drf_fleet_operator.post(url, data={
        'type': 'escalate',
        'severity': 'low',
        'description': 'bla'
    })
    assert response.status_code == status.HTTP_200_OK, response.data

    alert.refresh_from_db()
    assert alert.state == 'escalated'

    task = Task.objects.get()
    assert task.assignor == fleet_operator
    assert task.context == {'description': 'bla'}
    assert task.role == Affiliation.FLEET_OPERATOR
    assert task.causality == alert
    assert task.organization == org


def test_silence_lost_bicycle_reported(alert_lost_bicycle_reported,
                                       drf_fleet_operator):
    url = reverse_query('lock8:alert-actions',
                        kwargs={'uuid': alert_lost_bicycle_reported.uuid})

    response = drf_fleet_operator.post(url, data={'type': 'silence'})
    assert response.status_code == status.HTTP_200_OK

    alert_lost_bicycle_reported.refresh_from_db()
    assert alert_lost_bicycle_reported.state == 'stopped'
