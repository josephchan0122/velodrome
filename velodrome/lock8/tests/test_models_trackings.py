import datetime as dt
import uuid

from django.contrib.gis.geos import Point
from django.core.exceptions import ValidationError
import pytest
from reversion.revisions import is_registered


def test_latlon_getter_without_attributes(tracking):
    from velodrome.lock8.models import PrivateTracking

    t = PrivateTracking()
    assert t.gps_latitude is None
    assert t.gps_longitude is None


def test_latest_trackings_for_inactive_lock(lock, create_gps_tracking):
    assert lock.private_tracking is None

    create_gps_tracking(lock, 1, 0, activate=False)
    assert lock.public_tracking is None


def test_tracking_models_are_not_registered_with_reversion():
    from velodrome.lock8.models import (PublicTracking, PrivateTracking,
                                        Tracking)
    assert not is_registered(Tracking)
    assert not is_registered(PublicTracking)
    assert not is_registered(PrivateTracking)


def test_provision_tracking_device_system_status_message(lock,
                                                         create_dss_tracking):
    create_dss_tracking(lock, 50.,
                        attributes={'firmware_version_tag': 'v1.0-12-8f8f90c*'}
                        )
    assert lock.firmware_versions == {'mercury': 'v1.0-12-8f8f90c*'}


def test_dss_locked_lock_the_lock(lock, create_dss_tracking):
    assert lock.locked_state == 'unlocked'

    create_dss_tracking(lock, 32, event=10,
                        attributes={'lock_status': 2})

    assert lock.locked_state == 'locked'
    assert lock.transitions.count() == 1


def test_dss_unlocked_unlock_the_lock(create_dss_tracking, lock):
    assert lock.locked_state == 'unlocked'
    lock.lock()

    create_dss_tracking(lock, 50, event=10,
                        attributes={'lock_status': 3})

    assert lock.locked_state == 'unlocked'
    assert lock.transitions.count() == 2


def test_tracking_invalid_create_kwargs(bicycle, lock):
    from velodrome.lock8.models import Tracking

    with pytest.raises(ValidationError) as e:
        Tracking.objects.create(bicycle=bicycle)
    assert (e.value.message ==
            'You are not allowed to pass in a bicycle/lock directly.')

    with pytest.raises(ValidationError) as e:
        Tracking.objects.create(lock=lock)
    assert (e.value.message ==
            'You are not allowed to pass in a bicycle/lock directly.')


def test_tracking_str(lock):
    from velodrome.lock8.models import Tracking

    t = Tracking()
    assert str(t) == '#- (GPS Location, -, @-)'
    assert '{!r}'.format(t) == '<Tracking: #- (GPS Location, -, @-)>'

    dts = dt.datetime.fromtimestamp(1428509326, tz=dt.timezone.utc).isoformat()
    t = Tracking(attributes={
        'time_stamp': 1428509326
    })
    assert str(t) == '#- (GPS Location, -, @{})'.format(dts)

    t = Tracking(attributes={
        'serial_number': 12345,
        'time_stamp': 1428509326,
    })
    assert str(t) == '#- (GPS Location, 12345, @{})'.format(dts)

    t = Tracking(attributes={
        'serial_number': 12345,
        'time_stamp': 1428509326,
    })
    assert str(t) == '#- (GPS Location, 12345, @{})'.format(dts)
    t.save()
    assert str(t) == '#{} (GPS Location, 12345, @{})'.format(t.pk, dts)


def test_publictracking_str(lock):
    from velodrome.lock8.models import PublicTracking

    dts = dt.datetime.fromtimestamp(1428509326, tz=dt.timezone.utc).isoformat()
    t = PublicTracking(attributes={
        'serial_number': 12345,
        'time_stamp': 1428509326,
    })
    assert str(t) == '#- (12345, @{})'.format(dts)


def test_latest_tracking_from_new_tracking(today, lock, gps_tracking,
                                           create_gps_tracking):

    t1 = gps_tracking
    assert lock.private_tracking.time_stamp == t1.timestamp.timestamp()

    attributes = dict(t1.attributes,
                      time_stamp=t1.attributes['time_stamp'] + 1)
    t2 = create_gps_tracking(lock, 1, 2, attributes=attributes)
    assert t2.timestamp > t1.timestamp

    lock.private_tracking.refresh_from_db()
    assert lock.private_tracking.time_stamp == t2.timestamp.timestamp()


def test_tracking_types(today, gps_tracking):
    tracking = gps_tracking
    assert isinstance(tracking.timestamp, dt.datetime)
    # Replacing microseconds might be required because of
    # https://bugs.python.org/23517 (fixed in 3.5.1)
    assert (tracking.timestamp.replace(microsecond=0) ==
            today.replace(microsecond=0))

    del(tracking.attributes['time_stamp'])
    assert tracking.timestamp == tracking.created


def test_tracking_model_cell_message(bicycle, lock):
    from velodrome.lock8.models import Tracking

    body = {'serial_number': lock.serial_number,
            'gps_longitude': 13403145,
            'gps_latitude': 52527433,
            'gps_accuracy': 30807.1328125,
            }
    tracking = Tracking.objects.create(
        attributes=body,
        tracking_type=Tracking.CELLULAR_LOCATION_MESSAGE,
    )
    assert tracking.serial_number == lock.serial_number
    assert tracking.time_stamp is None
    assert tracking.gps_accuracy == 30807.1328125
    assert tracking.gps_longitude == 13.403145
    assert tracking.gps_latitude == 52.527433
    assert tracking.point == Point(13.403145, 52.527433)
    assert tracking.tracking_type == 'CEL'
    assert tracking.state == 'new'


def test_tracking_model_max_counter(db):
    from velodrome.lock8.models import Tracking

    body = {
        'serial_number': '9' * 9,
        'time_stamp': 1428509327,
    }
    tracking = Tracking.objects.create(attributes=body)
    assert tracking.serial_number == '9' * 9

    assert Tracking.objects.filter(
        attributes__serial_number='9' * 9).exists()


def test_tracking_init_provision_lock(lock, create_dss_tracking):

    assert lock.state == 'new'
    create_dss_tracking(lock, 50, event=1, activate=False)
    lock.refresh_from_db()
    assert lock.state == 'provisioned'
    assert lock.private_tracking is not None


def test_tracking_if_no_init_doesnt_provision(lock, create_dss_tracking):
    from velodrome.lock8.models import LockStates

    assert lock.state == LockStates.NEW.value
    create_dss_tracking(lock, 50, event=2)
    assert lock.state == LockStates.NEW.value


def test_tracking_init_doesnt_provision_twice(lock, create_dss_tracking):
    from velodrome.lock8.models import LockStates

    assert lock.state == LockStates.NEW.value
    create_dss_tracking(lock, 50, event=1, activate=False)

    assert lock.state == LockStates.PROVISIONED.value

    create_dss_tracking(lock, 0., event=1, activate=False)

    assert lock.state == LockStates.PROVISIONED.value


@pytest.mark.django_db
def test_tracking_attributes_point_can_be_changed(middle_of_somewhere, today,
                                                  middle_of_central_park):
    from velodrome.lock8.models import Tracking

    lon, lat = middle_of_somewhere
    tracking = Tracking.objects.create(
        attributes={'gps_latitude': lat * 1e6,
                    'gps_longitude': lon * 1e6,
                    'gps_timestamp': today.timestamp()})
    assert tuple(tracking.point) == (lon, lat)
    assert Tracking.objects.filter(point=Point(lon, lat)).exists()

    lon, lat = middle_of_central_park
    tracking.attributes['gps_longitude'] = lon * 1e6
    tracking.attributes['gps_latitude'] = lat * 1e6
    tracking.save()

    tracking.refresh_from_db()

    assert tuple(tracking.point) == (lon, lat)

    assert Tracking.objects.filter(point=Point(lon, lat)).exists()


def test_is_sibling_tracking(tracking):
    from velodrome.lock8.models import ReadonlyTracking

    assert not tracking.message_uuid
    ro_tracking = ReadonlyTracking()
    assert not ro_tracking.is_sibling_tracking(tracking)

    tracking.message_uuid = uuid.uuid4()
    assert not ro_tracking.is_sibling_tracking(tracking)

    ro_tracking.uuid = tracking.message_uuid
    assert ro_tracking.is_sibling_tracking(tracking)


def test_get_diff_to_tracking(tracking, bicycle):
    from velodrome.lock8.models import ReadonlyTracking

    ro_tracking = ReadonlyTracking()
    diff = ro_tracking.get_diff_to_tracking(tracking)
    assert diff.keys() == {'attributes', 'timestamp'}
    assert diff['attributes'][0] is None

    ro_tracking.attributes = tracking.attributes
    ro_tracking.timestamp = tracking.timestamp

    tracking.message_uuid = uuid.uuid4()
    assert ro_tracking.get_diff_to_tracking(tracking) == {
        'uuid': (None, tracking.message_uuid)
    }

    # bicycle/bicycle_uuid is ignored.
    tracking.bicycle = bicycle
    assert ro_tracking.get_diff_to_tracking(tracking) == {
        'uuid': (None, tracking.message_uuid),
    }


def test_provision_and_assign_gps_tracking_after_dss(bicycle, dss_tracking,
                                                     create_gps_tracking):
    assert bicycle.latest_gps_timestamp is None

    create_gps_tracking(bicycle, 13.403145, 52.527433,
                        time_stamp=bicycle.private_tracking.time_stamp - 1)
    bicycle.private_tracking.refresh_from_db()
    assert (bicycle.latest_gps_timestamp.timestamp() ==
            bicycle.private_tracking.gps_timestamp.timestamp())
