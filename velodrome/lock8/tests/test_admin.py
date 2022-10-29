import re

from _pytest import fixtures
from django.contrib import messages
from django.db import connection
from django.test.utils import CaptureQueriesContext
import pytest
from rest_framework import status

from velodrome.lock8.utils import reverse_query

pytestmark = pytest.mark.slow

ADMIN_VIEWS_ALL = (
    'admin:lock8_address',
    'admin:lock8_affiliation',
    'admin:lock8_alert',
    'admin:lock8_axalock',
    'admin:lock8_bicycle',
    'admin:lock8_bicyclemodel',
    'admin:lock8_bicycletype',
    'admin:lock8_feedback',
    'admin:lock8_feedbackcategory',
    'admin:lock8_firmware',
    'admin:lock8_invitation',
    'admin:lock8_lock',
    'admin:lock8_lockfirmwareupdate',
    'admin:lock8_notificationmessage',
    'admin:lock8_organization',
    'admin:lock8_organizationpreference',
    'admin:lock8_photo',
    'admin:lock8_planpass',
    'admin:lock8_pricingscheme',
    'admin:lock8_readonlytracking',
    'admin:lock8_rentingscheme',
    'admin:lock8_subscriptionplan',
    'admin:lock8_supportticket',
    'admin:lock8_task',
    'admin:lock8_termsofservice',
    'admin:lock8_termsofserviceversion',
    'admin:lock8_trip',
    'admin:lock8_user',
    'admin:lock8_userprofile',
    'admin:lock8_zone',
    'admin:refreshtoken_refreshtoken',
)

ADMIN_VIEWS_ADD_403 = (
    'admin:lock8_notificationmessage',
    'admin:lock8_readonlytracking',
    'admin:lock8_rentalsession',
    'admin:lock8_reservation',
    'admin:lock8_trip',
    'admin:lock8_user',
)

ADMIN_VIEWS_CHANGE_403 = (
)


@pytest.fixture
def get_model_admin():
    def inner(model_class):
        from django.contrib.admin.sites import AdminSite
        from django.utils.module_loading import import_string

        admin_class = import_string('velodrome.lock8.admin.{}Admin'.format(
            model_class.__name__))

        return admin_class(model_class, AdminSite())
    return inner


@pytest.fixture
def get_changelist_view(get_model_admin, django_admin_rf):
    def inner(model_class):
        rf = django_admin_rf()
        ma = get_model_admin(model_class)

        info = ma.model._meta.app_label, ma.model._meta.model_name
        url = reverse_query('admin:%s_%s_changelist' % info)
        request = rf.get(url)
        return ma.changelist_view(request)
    return inner


@pytest.fixture
def get_change_view(get_model_admin, django_admin_rf):
    def inner(model_class, object_id=None):
        ma = get_model_admin(model_class)
        rf = django_admin_rf()
        info = ma.model._meta.app_label, ma.model._meta.model_name
        url = reverse_query('admin:%s_%s_change' % info,
                            kwargs={'object_id': object_id})
        request = rf.get(url)
        if object_id is not None:
            object_id = str(object_id)  # to prevent error in Django's unquote.
        return ma.change_view(request, object_id)
    return inner


@pytest.fixture
def get_changelist(get_changelist_view):
    def inner(model_class):
        clv = get_changelist_view(model_class)
        return clv.context_data['cl']
    return inner


def test_admin_index(django_admin_client):
    url = reverse_query('admin:index')
    response = django_admin_client.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert b'Noa administration' in response.content


@pytest.mark.parametrize('view_name', sorted(set(ADMIN_VIEWS_ALL) -
                                             set(ADMIN_VIEWS_ADD_403)))
def test_admin_views_add_ok(view_name, django_admin_client):
    url = reverse_query('{}_add'.format(view_name))
    response = django_admin_client.get(url)
    assert response.status_code == status.HTTP_200_OK


@pytest.mark.parametrize('view_name', ADMIN_VIEWS_ADD_403)
def test_admin_views_add_403(view_name, django_admin_client):
    url = reverse_query('{}_add'.format(view_name))
    response = django_admin_client.get(url)
    assert response.status_code == status.HTTP_403_FORBIDDEN


@pytest.mark.parametrize('view_name', ADMIN_VIEWS_ALL)
def test_admin_views_changelist_ok(view_name, request, django_admin_client,
                                   admin_user):
    if view_name == 'admin:lock8_tracking':
        admin_user.is_superuser = True
        admin_user.save()

    fixturename = view_name.partition('_')[2]
    try:
        request.getfixturevalue(fixturename)
    except fixtures.FixtureLookupError:
        pass

    url = reverse_query('{}_changelist'.format(view_name))
    response = django_admin_client.get(url)
    assert response.status_code == status.HTTP_200_OK


@pytest.fixture
def readonlytracking_modeladmin(django_admin_rf):
    from django.contrib.admin.sites import AdminSite
    from velodrome.lock8.admin import ReadonlyTrackingAdmin
    from velodrome.lock8.models import ReadonlyTracking

    ma = ReadonlyTrackingAdmin(ReadonlyTracking, AdminSite())

    def get_changelist_view_cl(url):
        clv = ma.changelist_view(django_admin_rf().get(url))
        return clv.context_data['cl']
    ma.get_changelist_view_cl = get_changelist_view_cl
    return ma


def test_admin_readonlytracking_changelist_search(
        readonlytracking_modeladmin, readonlytracking, non_matching_uuid,
        admin_user):

    ma = readonlytracking_modeladmin

    url = reverse_query('admin:lock8_readonlytracking_changelist', {
        'q': str(readonlytracking.uuid)})
    assert ma.get_changelist_view_cl(url).queryset.count() == 1

    url = reverse_query('admin:lock8_readonlytracking_changelist', {
        'q': str(non_matching_uuid)})
    assert not ma.get_changelist_view_cl(url).queryset.count()

    url = reverse_query('admin:lock8_readonlytracking_changelist', {
        'q': 'NOUUID'})
    assert not ma.get_changelist_view_cl(url).queryset.count()

    url = reverse_query('admin:lock8_readonlytracking_changelist', {
        'q': '{} {}'.format('NOUUID', str(readonlytracking.uuid))})
    assert ma.get_changelist_view_cl(url).queryset.count() == 1


def try_get_fixture(name, request):
    """Get a pytest fixture, handling FixtureLookupError."""
    try:
        return request.getfixturevalue(name)
    except fixtures.FixtureLookupError as exc:
        if not exc.argname == name:  # pragma: no cover
            raise exc


@pytest.mark.db
@pytest.mark.parametrize('status_code,view_name', (
    [(status.HTTP_200_OK, v)
     for v in ADMIN_VIEWS_ALL if v not in ADMIN_VIEWS_CHANGE_403] +
    [(status.HTTP_403_FORBIDDEN, v) for v in ADMIN_VIEWS_CHANGE_403]))
def test_admin_change_views(request, view_name, status_code, image_ext):
    fixturename = view_name.partition('_')[2]
    obj = try_get_fixture(fixturename, request)
    if obj is None:
        fm = request.session._fixturemanager
        for name in fm._arg2fixturedefs:
            if name.replace('_', '') == fixturename:
                obj = try_get_fixture(name, request)
                break
        else:
            pytest.skip('Missing fixture: {}'.format(fixturename))

    django_admin_client = request.getfixturevalue('django_admin_client')

    url = reverse_query(f'{view_name}_change', args=(obj.pk,))
    response = django_admin_client.get(url)
    assert response.status_code == status_code

    if status_code == status.HTTP_403_FORBIDDEN:
        admin_user = request.getfixturevalue('admin_user')
        admin_user.is_superuser = True
        admin_user.save()
        response = django_admin_client.get(url)
        assert response.status_code == status.HTTP_200_OK


@pytest.mark.test_in_docker
def test_admin_change_view_readonlytracking(
        request, admin_user, readonlytracking, readonlytracking_dss,
        django_admin_client):
    admin_user.is_superuser = True
    admin_user.save()

    # DSS
    url = reverse_query('admin:lock8_readonlytracking_change', args=(
        readonlytracking_dss.id,))
    response = django_admin_client.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert b'<label>Point:</label>' in response.content

    # GPS
    url = reverse_query('admin:lock8_readonlytracking_change', args=(
        readonlytracking.id,))
    response = django_admin_client.get(url)
    assert response.status_code == status.HTTP_200_OK
    content = str(response.content)
    assert '<label for="id_point">Point:</label>' in content
    assert 'geodjango_point.modifiable = false' in content
    assert 'addStamenLayer' in content
    assert '"https://a.tile.openstreetmap.org' in content

    # Check that the point could be converted.
    assert re.search(r'<textarea id="id_point" class="vWKTField required"[^>]+'
                     r'name="point"[^>]*>POINT \(', str(content))


def test_admin_user_change_view_for_superuser(
        get_change_view, django_admin_user):
    from velodrome.lock8.models import User

    checkbox_is_superuser = '<input type="checkbox" name="is_superuser"'
    select_user_permissions = '<select name="user_permissions"'
    select_groups = '<select name="groups"'

    cv = get_change_view(User, django_admin_user.pk)
    assert checkbox_is_superuser not in cv.rendered_content
    assert select_user_permissions not in cv.rendered_content
    assert select_groups not in cv.rendered_content

    django_admin_user.is_superuser = True
    cv = get_change_view(User, django_admin_user.pk)
    assert checkbox_is_superuser in cv.rendered_content
    assert select_user_permissions in cv.rendered_content
    assert select_groups in cv.rendered_content


def test_reset_password_email(django_admin_client, admin_user, site,
                              mailoutbox):
    url = reverse_query('admin_password_reset')
    response = django_admin_client.post(url, {'email': admin_user.email})
    assert response.status_code == status.HTTP_302_FOUND

    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.subject == 'Password reset on api-dev'
    assert 'http://api-dev.lock8.me/reset/' in email.body


def test_move_bicycle(django_admin_client, owner, bicycle, another_org,
                      another_bicycle_model, bicycle_model, lock, axalock):
    client = django_admin_client
    bicycle.axa_lock = axalock
    bicycle.save()
    response = client.get(reverse_query('admin:move_to_org',
                                        {'ids': str(bicycle.pk)}))
    assert response.status_code == status.HTTP_200_OK
    response = client.post(reverse_query('admin:move_to_org'),
                           data={'ids': str(bicycle.pk),
                                 'organization': another_org.id,
                                 'model': another_bicycle_model.pk})

    assert response.status_code == status.HTTP_302_FOUND

    bicycle.refresh_from_db()
    assert bicycle.organization == another_org
    assert bicycle.model == another_bicycle_model

    lock.refresh_from_db()
    assert lock.organization == another_org
    axalock.refresh_from_db()
    assert axalock.organization == another_org

    assert [x.message
            for x in messages.get_messages(response.wsgi_request)] == [
                    'Updated 1 bicycle, 1 lock, and 1 AXA lock.']


def test_lock_bulk_update_org(django_admin_client, admin_user, mailoutbox,
                              lock_bleid_list_file, lock, lock2, lock3, org,
                              another_org):
    assert all(item.organization == org for item in (lock, lock2))

    lock3.organization = another_org
    lock3.save()

    url = reverse_query('admin:bulk_lock_org_update')
    response = django_admin_client.post(url, data={
        'import_file': lock_bleid_list_file,
        'organization': another_org.id,
    })

    assert response.status_code == status.HTTP_200_OK
    assert b'You will receive an email shortly' in response.content

    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.subject.startswith('Bulk lock organization report')
    assert email.recipients() == [admin_user.email]
    assert 'updated was 2' in email.body, email.body
    assert 'skipped was 1' in email.body, email.body

    [item.refresh_from_db() for item in (lock, lock2)]
    assert all(item.organization == another_org for item in (lock, lock2))


def test_lock_bulk_update_org_provision_fail(django_admin_client, admin_user,
                                             lock_bleid_list_file, lock,
                                             lock2, lock3, org, another_org,
                                             bicycle, mailoutbox):
    # we only want to move fresh locks in the `new` state
    lock2.provision()
    lock2.activate()
    lock3.provision()
    lock3.activate()

    url = reverse_query('admin:bulk_lock_org_update')
    response = django_admin_client.post(url, data={
        'import_file': lock_bleid_list_file,
        'organization': another_org.id,
    })

    assert response.status_code == status.HTTP_200_OK
    assert b'You will receive an email shortly' in response.content

    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.subject.startswith('Bulk lock organization report')
    assert email.recipients() == [admin_user.email]
    assert 'updated was 0' in email.body
    assert 'Device 01020112 is assigned to bicycle bicycle' in email.body
    assert 'Invalid Lock _14 with state: active' in email.body
    assert 'Invalid Lock _15 with state: active' in email.body

    [item.refresh_from_db() for item in (lock, lock2, lock3)]
    assert all(item.organization == org for item in (lock, lock2, lock3))


def test_lock_bulk_update_org_failure(django_admin_client, admin_user,
                                      lock_bleid_list_error_file, lock,
                                      lock2, lock3, org, another_org,
                                      mailoutbox):
    url = reverse_query('admin:bulk_lock_org_update')
    response = django_admin_client.post(url, data={
        'import_file': lock_bleid_list_error_file,
        'organization': another_org.id,
    })

    assert response.status_code == status.HTTP_200_OK
    assert b'You will receive an email shortly' in response.content

    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.subject.startswith('Bulk lock organization report')
    assert email.recipients() == [admin_user.email]
    assert 'updated was 0' in email.body
    assert 'No Lock: doesnotexist' in email.body

    [item.refresh_from_db() for item in [lock, lock2, lock3]]
    assert all(item.organization == org for item in [lock, lock3])


def test_assign_device_to_bicycle_success(django_admin_client, admin_user,
                                          assign_devices_to_bicycles_file,
                                          bicycle, bicycle2, bicycle3, lock,
                                          lock2, lock3, org, mailoutbox):
    bicycle.lock = None
    bicycle.save()
    bicycle2.lock = None
    bicycle2.save()

    url = reverse_query('admin:assign_devices_to_bicycles')
    response = django_admin_client.post(
        url,
        data={'import_file': assign_devices_to_bicycles_file,
              'organization': org.pk})
    assert response.status_code == status.HTTP_200_OK
    assert b'You will receive an email shortly' in response.content

    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.subject == 'Assign Devices to Bicycles report.'
    assert email.recipients() == [admin_user.email]
    assert 'updated was 2' in email.body
    assert 'skipped was 1' in email.body

    bicycle.refresh_from_db()
    bicycle2.refresh_from_db()
    assert bicycle.lock == lock


def test_assign_device_to_bicycle_error(django_admin_client, admin_user,
                                        assign_devices_to_bicycles_error_file,
                                        bicycle, bicycle2, lock, lock2, org,
                                        mailoutbox):
    url = reverse_query('admin:assign_devices_to_bicycles')
    response = django_admin_client.post(
        url,
        data={'import_file': assign_devices_to_bicycles_error_file,
              'organization': org.pk})
    assert response.status_code == status.HTTP_200_OK
    assert b'You will receive an email shortly' in response.content

    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.subject == 'Assign Devices to Bicycles report.'
    assert email.recipients() == [admin_user.email]
    assert 'updated was 0' in email.body
    assert 'No Bicycle: no_bicycle' in email.body
    assert 'No Lock: no_lock' in email.body


def test_assign_device_to_bicycle_fail_on_save(django_admin_client, admin_user,
                                               assign_devices_to_bicycles_file,
                                               bicycle, lock, org, mailoutbox,
                                               another_org):
    bicycle.lock = None
    bicycle.save()
    lock.organization = another_org
    lock.save()

    url = reverse_query('admin:assign_devices_to_bicycles')
    response = django_admin_client.post(
        url,
        data={'import_file': assign_devices_to_bicycles_file,
              'organization': org.pk})
    assert response.status_code == status.HTTP_200_OK
    assert b'You will receive an email shortly' in response.content

    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.subject == 'Assign Devices to Bicycles report.'
    assert email.recipients() == [admin_user.email]
    assert 'Number of failures 3.' in email.body
    assert 'Lock does not belong to the same Organization' in email.body


def test_claim_axa_locks_success(django_admin_client, admin_user,
                                 claim_axa_locks_file, bicycle, org,
                                 active_requests_mock, settings, mailoutbox):
    from velodrome.lock8.models import AxaLock

    url = reverse_query('admin:claim_axa_locks')
    active_requests_mock.register_uri(
        'POST',
        settings.KEY_SAFE_BASE_URI + '/locks',
        [{'json': {
            "now": "2016-01-12T22:27:27.675145+00:00",
            "result": {
                "created": "2016-01-11T20:29:02.866292",
                "firmware_modified": "2016-01-11T20:29:02.893996",
                "firmware_version": "1.00",
                "hardware_model": "PCB/eRL2",
                "hardware_version": "1.1",
                "id": 5785905063264256,
                "key": "ahFkZXZ-a2V5c2FmZS1jbG91ZHIRCxIETG9jaxiAgICAgMijCgw",
                "lock_model": "eRL",
                "lock_status": "active",
                "lock_uid": "c32a9cdf35194ddeb6f6",
                "lock_version": "1.0",
                "mac_address": "32453311fdaa",
                "modified": "2016-01-11T23:07:48.215889",
                "nr_of_slots": 3,
                "reference": None,
                "software_modified": "2016-01-11T20:29:03.699398",
                "software_version": "1.00"
            },
            "status": "success"}},
         {'json': {
             "now": "2016-01-12T22:27:27.675145+00:00",
             "result": {
                 "created": "2016-01-11T20:29:02.866292",
                 "firmware_modified": "2016-01-11T20:29:02.893996",
                 "firmware_version": "1.00",
                 "hardware_model": "PCB/eRL2",
                 "hardware_version": "1.1",
                 "id": 5785905063264257,
                 "key": "ahFkZXZ-a2V5c2FmZS1jbG91ZHIRCxIETG9jaxiAgICAgMijCgw",
                 "lock_model": "eRL",
                 "lock_status": "active",
                 "lock_uid": "c32a9cdf35194ddeb6f7",
                 "lock_version": "1.0",
                 "mac_address": "32453311fdab",
                 "modified": "2016-01-11T23:07:48.215889",
                 "nr_of_slots": 3,
                 "reference": None,
                 "software_modified": "2016-01-11T20:29:03.699398",
                 "software_version": "1.00"
             },
             "status": "success"
          }}]
    )
    response = django_admin_client.post(
        url,
        data={'import_file': claim_axa_locks_file,
              'organization': org.pk})
    assert response.status_code == status.HTTP_200_OK
    assert b'You will receive an email shortly' in response.content

    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.subject == \
        'Report about claimed Axa Locks from your spreadsheet'
    assert email.recipients() == [admin_user.email]
    assert 'Number of Axa Locks paired with a bicycle: 1' in email.body
    assert 'Number of Axa Locks created: 2' in email.body

    bicycle.refresh_from_db()
    assert bicycle.axa_lock is not None
    assert AxaLock.objects.count() == 2


def test_claim_axa_locks_error(django_admin_client, admin_user,
                               claim_axa_locks_error_file, bicycle, org,
                               active_requests_mock, settings, mailoutbox,
                               caplog):
    from velodrome.lock8.models import AxaLock

    url = reverse_query('admin:claim_axa_locks')
    active_requests_mock.register_uri(
        'POST',
        settings.KEY_SAFE_BASE_URI + '/locks',
        [{'json': {
            "now": "2016-01-12T22:27:27.675145+00:00",
            "result": {
                "created": "2016-01-11T20:29:02.866292",
                "firmware_modified": "2016-01-11T20:29:02.893996",
                "firmware_version": "1.00",
                "hardware_model": "PCB/eRL2",
                "hardware_version": "1.1",
                "id": 5785905063264256,
                "key": "ahFkZXZ-a2V5c2FmZS1jbG91ZHIRCxIETG9jaxiAgICAgMijCgw",
                "lock_model": "eRL",
                "lock_status": "active",
                "lock_uid": "c32a9cdf35194ddeb6f6",
                "lock_version": "1.0",
                "mac_address": "32453311fdaa",
                "modified": "2016-01-11T23:07:48.215889",
                "nr_of_slots": 3,
                "reference": None,
                "software_modified": "2016-01-11T20:29:03.699398",
                "software_version": "1.00"
            },
            "status": "success"}},
         {'json': {"now": "2016-01-12T22:27:27.675145+00:00",
                   "status": "failed"},
          'status_code': status.HTTP_400_BAD_REQUEST}]
    )
    response = django_admin_client.post(
        url,
        data={'import_file': claim_axa_locks_error_file,
              'organization': org.pk})
    assert response.status_code == status.HTTP_200_OK
    assert b'You will receive an email shortly' in response.content

    assert len(mailoutbox) == 1
    email = mailoutbox[0]
    assert email.subject == \
        'Report about claimed Axa Locks from your spreadsheet'
    assert email.recipients() == [admin_user.email]
    assert 'paired with a bicycle: 0' in email.body
    assert 'created: 1' in email.body
    assert 'failures: 2' in email.body

    bicycle.refresh_from_db()
    assert bicycle.axa_lock is None
    assert AxaLock.objects.count() == 1

    recs = caplog.records
    assert [(r.levelname, r.message) for r in recs][0:2] == [
        ('ERROR', 'Exception while pairing axa locks'),
        ('ERROR', 'Exception while claiming axa locks')]
    assert len(recs) == 3
    assert str(recs[0].exc_info[1]) == 'Bicycle matching query does not exist.'
    err_txt = repr(recs[1].exc_info[1])
    assert '400 Client Error: None for url: ' in err_txt
    assert 'HTTPError' in err_txt
    assert recs[2].message.startswith(
         'Task velodrome.celery.claim_axa_locks_from_spreadsheet_task[')


@pytest.fixture
def trip_modeladmin():
    from django.contrib.admin.sites import AdminSite
    from velodrome.lock8.admin import TripAdmin
    from velodrome.lock8.models import Trip
    return TripAdmin(Trip, AdminSite())


def test_admin_trip_changelist(get_changelist, trip, trip_without_duration,
                               django_admin_client):
    from velodrome.lock8.models import Trip

    cl = get_changelist(Trip)
    result_list = cl.result_list
    assert result_list.count() == 2
    assert result_list[0].speed is None
    assert result_list[1].speed == 20.0


def test_admin_trip_changelist_filters(trip_modeladmin, trip,
                                       trip_without_duration, django_admin_rf):
    from django.contrib.admin.sites import AdminSite
    from velodrome.lock8.admin import TripAdmin
    from velodrome.lock8.models import Trip

    rf = django_admin_rf()
    ma = TripAdmin(Trip, AdminSite())

    def changelist_view(url):
        request = rf.get(url)
        return ma.changelist_view(request)

    def changelist(url):
        return changelist_view(url).context_data['cl']

    url = reverse_query('admin:lock8_trip_changelist', {
        'gps_time_first_fix__lt': 10})
    assert not changelist(url).queryset.count()

    url = reverse_query('admin:lock8_trip_changelist', {
        'distance_m': 'lt__500'})
    assert changelist(url).queryset.count() == 1

    url = reverse_query('admin:lock8_trip_changelist', {
        'speed': 'lt__5'})
    assert changelist(url).queryset.count() == 0

    url = reverse_query('admin:lock8_trip_changelist', {
        'speed': '50'})
    clv = changelist_view(url)
    cl = clv.context_data['cl']
    assert cl.queryset.count() == 1

    assert clv.context_data['action_form'] is None


@pytest.fixture
def lockfirmwareupdate_modeladmin():
    from django.contrib.admin.sites import AdminSite
    from velodrome.lock8.admin import LockFirmwareUpdateAdmin
    from velodrome.lock8.models import LockFirmwareUpdate
    return LockFirmwareUpdateAdmin(LockFirmwareUpdate, AdminSite())


def test_admin_search_exact(lockfirmwareupdate_modeladmin, django_admin_rf,
                            lock_firmware_update):
    ma = lockfirmwareupdate_modeladmin
    lock = lock_firmware_update.lock
    lock.serial_number = 'lowercase'
    lock.save()

    def changelist_view(url):
        return ma.changelist_view(django_admin_rf().get(url))

    def changelist(url):
        return changelist_view(url).context_data['cl']

    url = reverse_query('admin:lock8_lockfirmwareupdate_changelist', {
        'q': str(lock_firmware_update.uuid)})
    assert changelist(url).queryset.count() == 1

    # Works with upper case, since it gets converted to a UUID object.
    url = reverse_query('admin:lock8_lockfirmwareupdate_changelist', {
        'q': str(lock_firmware_update.uuid).upper()})
    assert changelist(url).queryset.count() == 1

    # Search for lock serial number.
    url = reverse_query('admin:lock8_lockfirmwareupdate_changelist', {
        'q': str(lock.serial_number)})
    assert changelist(url).queryset.count() == 1

    # Works with upper case, since it gets converted to a UUID object.
    url = reverse_query('admin:lock8_lockfirmwareupdate_changelist', {
        'q': str(lock.serial_number).upper()})
    assert changelist(url).queryset.count() == 0


def test_admin_trip_changelist_filter_org(trip_modeladmin, trip, another_trip,
                                          django_admin_rf):
    from django.contrib.admin.sites import AdminSite
    from velodrome.lock8.admin import TripAdmin
    from velodrome.lock8.models import Trip

    rf = django_admin_rf()
    ma = TripAdmin(Trip, AdminSite())

    def changelist(url):
        request = rf.get(url)
        return ma.changelist_view(request).context_data['cl']

    url = reverse_query('admin:lock8_trip_changelist')
    assert changelist(url).queryset.count() == 2

    url = reverse_query('admin:lock8_trip_changelist', {
        'organization_uuid': trip.organization_uuid})
    assert changelist(url).queryset.count() == 1

    url = reverse_query('admin:lock8_trip_changelist', {
        'organization_uuid': another_trip.organization_uuid})
    assert changelist(url).queryset.count() == 1


@pytest.mark.skip(reason='Query count was significantly increased after '
                         'upgrade to Django 2.1, research needed')
def test_admin_user_changelist_queries_users(get_changelist):
    from velodrome.lock8.models import User

    with CaptureQueriesContext(connection) as capture:
        cl = get_changelist(User)
    assert [x.username for x in cl.queryset] == ['admin_user', 'root_admin']

    assert len(capture.captured_queries) == 12, '\n\n'.join(
        q['sql'] for q in capture.captured_queries)


@pytest.mark.skip(reason='Query count was significantly increased after '
                         'upgrade to Django 2.1, research needed')
def test_admin_user_changelist_queries_affiliations(get_changelist, renter):
    """Test that a custom ChangeList is used with prefetch_related."""
    from velodrome.lock8.admin import Affiliation

    with CaptureQueriesContext(connection) as capture:
        cl = get_changelist(Affiliation)
    assert len(capture.captured_queries) == 8, '\n\n'.join(
        q['sql'] for q in capture.captured_queries)
    assert [str(x.user) for x in cl.result_list] == [
        "Alice Cooper (member of 'org')", "admin_user (member of 'Noa')"]


@pytest.mark.skip(reason='Query count was significantly increased after '
                         'upgrade to Django 2.1, research needed')
@pytest.mark.parametrize('multiple', (False, True))
def test_admin_user_changelist_queries_rentalsession(
        multiple, bicycle, get_changelist_view):
    from velodrome.lock8.models import RentalSession, User

    user_with_display_name_via_social_auth = User.objects.create(
        username='testuser1')
    RentalSession.objects.create(
        owner=user_with_display_name_via_social_auth,
        user=user_with_display_name_via_social_auth,
        bicycle=bicycle,
    )
    if multiple:
        user_with_display_name_via_social_auth = User.objects.create(
            username='testuser2')
        RentalSession.objects.create(
            owner=user_with_display_name_via_social_auth,
            user=user_with_display_name_via_social_auth,
            bicycle=bicycle,
        )

    with CaptureQueriesContext(connection) as capture:
        changelist_view = get_changelist_view(RentalSession)
        content = changelist_view.rendered_content

    assert len(capture.captured_queries) == 15, '\n\n'.join(
        q['sql'] for q in capture.captured_queries)

    assert 'testuser1' in content
    if multiple:
        assert 'testuser2' in content


def test_admin_lockfirmwareupdate_view_on_site(django_admin_client,
                                               lock_firmware_update):
    url = reverse_query('admin:lock8_lockfirmwareupdate_change',
                        args=(lock_firmware_update.pk,))
    response = django_admin_client.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert b'history' in response.content
    assert b'viewsitelink' in response.content
    assert b'View on site' in response.content


def test_other_apps_use_custom_changelist():
    from velodrome.lock8.admin import ChangeList
    from django.apps import apps
    from django.contrib import admin

    app_config = apps.get_app_config('pinax_stripe')
    customer_model = app_config.get_model('customer')
    adm = admin.site._registry[customer_model]
    changelist = adm.get_changelist({})
    assert issubclass(changelist, ChangeList)


def test_bicycle_dal(get_change_view, bicycle):
    from velodrome.lock8.models import Bicycle

    cv = get_change_view(Bicycle)
    assert ('{"type": "const", "val": null, "dst": "bicycle"}' in
            cv.rendered_content)

    cv = get_change_view(Bicycle, bicycle.pk)
    assert ('<script type="text/dal-forward-conf">'
            '[{"type": "field", "src": "organization"}, '
            '{"type": "const", "val": %d, "dst": "bicycle"}]'
            '</script>' % (bicycle.pk,) in cv.rendered_content)


def test_disable_user_without_owner(get_model_admin, django_admin_rf):
    from velodrome.lock8.models import User

    obj = User.objects.create()
    assert obj.owner is None

    ma = get_model_admin(User)
    info = ma.model._meta.app_label, ma.model._meta.model_name
    url = reverse_query('admin:%s_%s_change' % info,
                        kwargs={'object_id': obj.pk})
    request = django_admin_rf().get(url)
    form = ma.get_form(request, obj)(request.POST, request.FILES, instance=obj)

    ma.save_model(request, obj, form, change=True)
    assert obj.owner is request.user


def test_zone_thresholds_views(get_changelist, get_change_view):
    from velodrome.lock8.models import Zone

    list_view = get_changelist(Zone)
    change_view = get_change_view(Zone)
    admin_form_fields = change_view.context_data['adminform'].form.fields

    assert list_view.list_display[6] == 'low_threshold'
    assert list_view.list_display[7] == 'high_threshold'
    assert 'low_threshold' in admin_form_fields
    assert 'high_threshold' in admin_form_fields


def test_alert_causality_form(alert_type, django_admin_client, org, owner,
                              lock, bicycle, zone):
    from velodrome.lock8.models import Affiliation, Alert
    alert_type, _, additional_fixture = alert_type.partition('+')

    is_bicycle = alert_type.startswith('bicycle.')
    is_zone = alert_type.startswith('zone.')

    alert = Alert.objects.create(
        organization=org,
        causality=bicycle if is_bicycle else zone if is_zone else lock,
        message=str(alert_type),
        owner=owner,
        roles=[Affiliation.FLEET_OPERATOR],
        alert_type=alert_type,
    )
    url = reverse_query('admin:lock8_alert_change', args=(alert.pk,))
    data = {
        'organization': alert.organization.pk,
        'alert_type': alert.alert_type,
        'causality': f'{alert.content_type.pk}-{alert.causality.pk}',
        '_fsmtransition-state-stop': 'Stop Alert'
    }
    response = django_admin_client.post(url, data=data)
    assert response.status_code == status.HTTP_302_FOUND
    alert.refresh_from_db()
    assert alert.state == 'stopped'
