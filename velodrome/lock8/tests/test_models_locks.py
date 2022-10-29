import datetime as dt

from django.core.exceptions import ValidationError
from django.utils import timezone as django_timezone
from freezegun import freeze_time
import pytest


def test_lock_model(org, owner, create_gps_tracking, create_dss_tracking):
    from velodrome.lock8.models import Lock

    lock = Lock.objects.create(organization=org, owner=owner,
                               counter=12,
                               serial_number='a.b.c12',
                               type='tracker',
                               imei='359785028015876',
                               iccid='89462046044000108670',
                               sid='f6cefb7474f291997c6a303031303835',
                               bleid='4c4f434b385f30303030303031303835',
                               randblock='a' * 2048)

    assert lock.organization == org
    assert lock.owner == owner
    assert lock.locked_state == 'unlocked'
    assert lock.mounted_state == 'unmounted'
    assert lock.counter == 12
    assert lock.serial_number == 'a.b.c12'
    assert lock.imei == '359785028015876'
    assert lock.iccid == '89462046044000108670'
    assert lock.sid == 'f6cefb7474f291997c6a303031303835'
    assert lock.bleid == '4c4f434b385f30303030303031303835'
    assert lock.randblock == 'a' * 2048
    assert lock.type == 'tracker'
    assert lock.state == 'new'

    lock.provision()
    assert lock.state == 'provisioned'

    lock.activate()
    assert lock.state == 'active'

    lock.put_in_maintenance()
    assert lock.state == 'in_maintenance'

    lock.restore()
    assert lock.state == 'active'

    create_gps_tracking(lock, 13.403145, 52.527433, time_stamp=1428509326)

    assert lock.latitude == 52.527433
    assert lock.longitude == 13.403145
    assert lock.time_stamp == 1428509326

    create_dss_tracking(lock, 33.)

    lock.private_tracking.refresh_from_db()

    assert lock.state_of_charge == 33.


def test_lock_model_validation(org, owner):
    from velodrome.lock8.models import Lock

    lock = Lock(organization=org, owner=owner,
                counter=12,
                serial_number='a.b.c12',
                type='tracker',
                imei='359785028015876',
                sid='f6cefb7474f291997c6a303031303835',
                bleid='4c4f434b385f30303030303031303835',
                randblock='a' * 2048)
    with pytest.raises(ValidationError):
        lock.clean()

    lock = Lock(organization=org, owner=owner,
                counter=12,
                serial_number='a.b.c12',
                type='tracker',
                imei='359785028015876',
                iccid='89462046044000108670',
                sid='f6cefb7474f291997c6a303031303835',
                randblock='a' * 2048)
    with pytest.raises(ValidationError):
        lock.clean()


def test_lock_model_validation_bicycle_another_org(bicycle, another_org):
    bicycle.lock.organization = another_org
    with pytest.raises(ValidationError) as excinfo:
        bicycle.lock.clean()
    assert excinfo.value.message_dict == {'organization': [
        "Lock's Bicycle does not belong to the same Organization."]}


def test_lockfirmware(owner, lock, firmware_mercury, firmware_mercury_update):
    ":type lock: velodrome.lock8.models.Lock"

    from velodrome.lock8.models import Firmware, LockFirmwareUpdate
    assert not lock.firmwares.all()

    # Assign current firmware.
    upd = LockFirmwareUpdate.objects.create(lock=lock,
                                            firmware=firmware_mercury,
                                            owner=owner)

    # Creating an instance with/to another version should raise an error.
    LockFirmwareUpdate.objects.create(lock=lock,
                                      firmware=firmware_mercury_update,
                                      owner=owner)
    firmware_mercury_update.provision()
    with pytest.raises(ValidationError) as e:
        LockFirmwareUpdate(lock=lock,
                           firmware=firmware_mercury_update,
                           owner=owner).full_clean()
    assert e.value.messages == ['There is already a provisioned firmware '
                                'assigned to this lock and chip!']
    upd.firmware = firmware_mercury_update
    with pytest.raises(ValidationError) as e:
        upd.full_clean()
    assert e.value.messages == ['There is already a provisioned firmware '
                                'assigned to this lock and chip!']
    assert LockFirmwareUpdate.objects.count() == 2
    assert Firmware.objects.filter(state="provisioned").count() == 1


def test_lockfirmware_multiple(owner, lock, another_lock,
                               firmware_mercury):
    from velodrome.lock8.models import LockFirmwareUpdate

    LockFirmwareUpdate.objects.create(lock=lock,
                                      firmware=firmware_mercury,
                                      owner=owner)
    LockFirmwareUpdate.objects.create(lock=another_lock,
                                      firmware=firmware_mercury,
                                      owner=owner)


def test_lockfirmwareupdate_without_firmware(db):
    from velodrome.lock8.models import LockFirmwareUpdate

    upd = LockFirmwareUpdate()
    upd.validate_unique()


def test_lockfirmware_delete(owner, lock, firmware_mercury):
    from velodrome.lock8.models import LockFirmwareUpdate

    obj = LockFirmwareUpdate.objects.create(lock=lock,
                                            firmware=firmware_mercury,
                                            owner=owner)
    assert LockFirmwareUpdate.objects.count() == 1
    obj.delete()
    assert LockFirmwareUpdate.objects.count() == 0


def test_lockfirmware_provisioning(owner, lock, firmware_mercury,
                                   firmware_mercury_update):
    ":type lock: velodrome.lock8.models.Lock"

    from velodrome.lock8.models import LockFirmwareUpdate
    assert not lock.firmwares.all()

    LockFirmwareUpdate.objects.create(lock=lock,
                                      firmware=firmware_mercury,
                                      owner=owner)

    LockFirmwareUpdate.objects.create(lock=lock,
                                      firmware=firmware_mercury_update,
                                      owner=owner)

    firmware_mercury_update.provision()

    with pytest.raises(ValidationError) as e:
        firmware_mercury.provision()

    assert e.value.messages == ['There is already a provisioned firmware '
                                'assigned to this lock and chip!']


@pytest.mark.parametrize('reported,expected', (
    ({'mercury': 'bar'}, 'bar'),
    ({'xmega': 'xbar', 'nordic': 'nbar'}, 'xbar | nbar'),
    ({'xmega': 'xbar'}, None),
    ({'nordic': 'nbar'}, None),
    ({}, None)
))
def test_lock_firmware_version(lock, reported, expected):
    lock.firmware_versions = reported
    lock.save()
    assert lock.firmware_version == expected


def test_lock_model_blank_sid(lock, another_lock):
    lock.sid = ''
    lock.save()
    another_lock.sid = ''
    another_lock.save()


def test_lock_estimated_state_of_charge(lock, create_dss_tracking):
    now = django_timezone.now()
    with freeze_time(now):
        create_dss_tracking(lock, 21)

        with freeze_time(now + dt.timedelta(hours=20)):
            assert lock.estimated_state_of_charge == 20.

        with freeze_time(now + dt.timedelta(hours=35)):
            assert lock.estimated_state_of_charge == 19.2


def test_lock_estimated_state_of_charge_wo_time_stamp(lock,
                                                      create_dss_tracking):

    now = django_timezone.now()
    with freeze_time(now):
        create_dss_tracking(lock, 21)
        lock.refresh_from_db()

        with freeze_time(now + dt.timedelta(hours=20)):
            assert lock.estimated_state_of_charge == 20.

        with freeze_time(now + dt.timedelta(hours=35)):
            assert lock.estimated_state_of_charge == 19.2
