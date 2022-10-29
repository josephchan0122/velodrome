from datetime import timedelta

from django.utils import timezone
from freezegun import freeze_time
import pytest


def test_closed_fleet_organization(org, fleet_operator, alice, admin_user,
                                   owner, another_org, fleet_admin,
                                   bob, supervisor):
    from velodrome.lock8.models import Affiliation, Organization

    sub_org = Organization.objects.create(
        name='sub',
        parent=org,
        owner=owner,
    )

    assert admin_user.has_perm('lock8.add_organization')
    assert admin_user.has_perm('lock8.change_organization', org)
    assert admin_user.has_perm('lock8.view_organization', org)
    assert admin_user.has_perm('lock8.delete_organization', org)
    assert admin_user.has_perm('lock8.change_organization', sub_org)
    assert admin_user.has_perm('lock8.view_organization', sub_org)
    assert admin_user.has_perm('lock8.delete_organization', sub_org)
    assert admin_user.has_perm('lock8.view_organization_transitions', sub_org)
    assert admin_user.has_perm('lock8.change_organization', another_org)
    assert admin_user.has_perm('lock8.view_organization', another_org)
    assert admin_user.has_perm('lock8.delete_organization', another_org)
    assert admin_user.has_perm('lock8.view_organization_transitions',
                               another_org)

    for user in (fleet_operator, supervisor):
        assert not user.has_perm('lock8.add_organization')
        assert user.has_perm('lock8.change_organization', org)
        assert user.has_perm('lock8.view_organization', org)
        assert not user.has_perm('lock8.delete_organization', org)
        assert user.has_perm('lock8.change_organization', sub_org)
        assert user.has_perm('lock8.view_organization', sub_org)
        assert user.has_perm('lock8.delete_organization', sub_org)
        assert user.has_perm('lock8.view_organization_transitions', sub_org)
        assert not user.has_perm('lock8.change_organization', another_org)
        assert not user.has_perm('lock8.view_organization', another_org)
        assert not user.has_perm('lock8.delete_organization', another_org)
        assert not user.has_perm('lock8.view_organization_transitions',
                                 another_org)

    assert not fleet_admin.has_perm('lock8.add_organization')
    assert fleet_admin.has_perm('lock8.change_organization', org)
    assert fleet_admin.has_perm('lock8.view_organization', org)
    assert not fleet_admin.has_perm('lock8.delete_organization', org)
    assert fleet_admin.has_perm('lock8.change_organization', sub_org)
    assert fleet_admin.has_perm('lock8.view_organization', sub_org)
    assert fleet_admin.has_perm('lock8.delete_organization', sub_org)
    assert not fleet_admin.has_perm('lock8.change_organization',
                                    another_org)
    assert not fleet_admin.has_perm('lock8.view_organization',
                                    another_org)
    assert not fleet_admin.has_perm('lock8.delete_organization',
                                    another_org)

    assert not alice.has_perm('lock8.add_organization')
    assert not alice.has_perm('lock8.change_organization', org)
    assert not alice.has_perm('lock8.view_organization', org)
    assert not alice.has_perm('lock8.delete_organization', org)
    assert not alice.has_perm('lock8.change_organization', sub_org)
    assert not alice.has_perm('lock8.view_organization', sub_org)
    assert not alice.has_perm('lock8.delete_organization', sub_org)

    Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER,
    )
    assert not alice.has_perm('lock8.change_organization', org)
    assert alice.has_perm('lock8.view_organization', org)
    assert not alice.has_perm('lock8.delete_organization', org)
    assert not alice.has_perm('lock8.change_organization', sub_org)
    assert alice.has_perm('lock8.view_organization', sub_org)
    assert not alice.has_perm('lock8.delete_organization', sub_org)
    assert not alice.has_perm('lock8.change_organization', another_org)
    assert not alice.has_perm('lock8.view_organization', another_org)
    assert not alice.has_perm('lock8.delete_organization', another_org)
    assert not bob.has_perm('lock8.view_organization', org)
    org.allowed_signup_domain_names = ['example.com']
    org.save()
    assert bob.has_perm('lock8.view_organization', org)
    bob.email = ''
    bob.save()
    assert not bob.has_perm('lock8.view_organization', org)


def test_open_fleet_organization(org, fleet_operator, alice, admin_user,
                                 owner, another_org, fleet_admin, supervisor):
    from velodrome.lock8.models import Organization

    org.is_open_fleet = True
    org.save()

    sub_org = Organization.objects.create(
        name='sub',
        parent=org,
        owner=owner,
        is_open_fleet=True,
    )

    assert admin_user.has_perm('lock8.add_organization')
    assert admin_user.has_perm('lock8.change_organization', org)
    assert admin_user.has_perm('lock8.view_organization', org)
    assert admin_user.has_perm('lock8.delete_organization', org)
    assert admin_user.has_perm('lock8.change_organization', sub_org)
    assert admin_user.has_perm('lock8.view_organization', sub_org)
    assert admin_user.has_perm('lock8.delete_organization', sub_org)
    assert admin_user.has_perm('lock8.change_organization', another_org)
    assert admin_user.has_perm('lock8.view_organization', another_org)
    assert admin_user.has_perm('lock8.delete_organization', another_org)

    for user in (fleet_operator, supervisor):
        assert not user.has_perm('lock8.add_organization')
        assert user.has_perm('lock8.change_organization', org)
        assert user.has_perm('lock8.view_organization', org)
        assert not user.has_perm('lock8.delete_organization', org)
        assert user.has_perm('lock8.change_organization', sub_org)
        assert user.has_perm('lock8.view_organization', sub_org)
        assert user.has_perm('lock8.delete_organization', sub_org)
        assert not user.has_perm('lock8.change_organization', another_org)
        assert not user.has_perm('lock8.view_organization', another_org)
        assert not user.has_perm('lock8.delete_organization', another_org)

    assert not fleet_admin.has_perm('lock8.add_organization')
    assert fleet_admin.has_perm('lock8.change_organization', org)
    assert fleet_admin.has_perm('lock8.view_organization', org)
    assert not fleet_admin.has_perm('lock8.delete_organization', org)
    assert fleet_admin.has_perm('lock8.change_organization', sub_org)
    assert fleet_admin.has_perm('lock8.view_organization', sub_org)
    assert fleet_admin.has_perm('lock8.delete_organization', sub_org)
    assert not fleet_admin.has_perm('lock8.change_organization',
                                    another_org)
    assert not fleet_admin.has_perm('lock8.view_organization',
                                    another_org)
    assert not fleet_admin.has_perm('lock8.delete_organization',
                                    another_org)

    assert not alice.has_perm('lock8.change_organization', org)
    assert alice.has_perm('lock8.view_organization', org)
    assert not alice.has_perm('lock8.delete_organization', org)
    assert not alice.has_perm('lock8.change_organization', sub_org)
    assert alice.has_perm('lock8.view_organization', sub_org)
    assert not alice.has_perm('lock8.delete_organization', sub_org)
    assert not alice.has_perm('lock8.change_organization', another_org)
    assert not alice.has_perm('lock8.view_organization', another_org)
    assert not alice.has_perm('lock8.delete_organization', another_org)


def test_bicycle_closed_fleet(org, bicycle, fleet_operator, alice,
                              admin_user, another_bicycle, fleet_admin, bob,
                              anon, spectator, supervisor):
    from velodrome.lock8.models import Affiliation

    assert admin_user.has_perm('lock8.add_bicycle')
    assert admin_user.has_perm('lock8.change_bicycle', bicycle)
    assert admin_user.has_perm('lock8.view_bicycle', bicycle)
    assert admin_user.has_perm('lock8.delete_bicycle', bicycle)
    assert admin_user.has_perm('lock8.put_in_maintenance_bicycle', bicycle)
    assert admin_user.has_perm('lock8.declare_available_bicycle', bicycle)
    assert admin_user.has_perm('lock8.declare_lost_bicycle', bicycle)
    assert admin_user.has_perm('lock8.declare_lost_bicycle', bicycle)
    assert admin_user.has_perm('lock8.reserve_bicycle', bicycle)
    assert admin_user.has_perm('lock8.rent_bicycle', bicycle)
    assert admin_user.has_perm('lock8.force_put_in_maintenance_bicycle',
                               bicycle)
    assert admin_user.has_perm('lock8.take_over_bicycle', bicycle)
    assert not admin_user.has_perm('lock8.cancel_reservation_bicycle', bicycle)
    assert not admin_user.has_perm('lock8.return_bicycle', bicycle)
    assert admin_user.has_perm('lock8.change_bicycle', another_bicycle)
    assert admin_user.has_perm('lock8.view_bicycle', another_bicycle)
    assert admin_user.has_perm('lock8.delete_bicycle', another_bicycle)
    assert admin_user.has_perm('lock8.put_in_maintenance_bicycle',
                               another_bicycle)
    assert admin_user.has_perm('lock8.declare_available_bicycle',
                               another_bicycle)
    assert admin_user.has_perm('lock8.declare_lost_bicycle', another_bicycle)
    assert admin_user.has_perm('lock8.reserve_bicycle', another_bicycle)
    assert admin_user.has_perm('lock8.rent_bicycle', another_bicycle)
    assert admin_user.has_perm('lock8.force_put_in_maintenance_bicycle',
                               another_bicycle)
    assert admin_user.has_perm('lock8.take_over_bicycle',
                               another_bicycle)
    assert not admin_user.has_perm('lock8.cancel_reservation_bicycle',
                                   another_bicycle)
    assert not admin_user.has_perm('lock8.return_bicycle',
                                   another_bicycle)

    for user in (fleet_operator, supervisor):
        assert user.has_perm('lock8.add_bicycle')
        assert user.has_perm('lock8.change_bicycle', bicycle)
        assert user.has_perm('lock8.view_bicycle', bicycle)
        assert user.has_perm('lock8.delete_bicycle', bicycle)
        assert user.has_perm('lock8.put_in_maintenance_bicycle', bicycle)
        assert user.has_perm('lock8.declare_available_bicycle', bicycle)
        assert user.has_perm('lock8.declare_lost_bicycle', bicycle)
        assert user.has_perm('lock8.reserve_bicycle', bicycle)
        assert user.has_perm('lock8.rent_bicycle', bicycle)
        assert user.has_perm('lock8.force_put_in_maintenance_bicycle', bicycle)
        assert user.has_perm('lock8.take_over_bicycle', bicycle)
        assert user.has_perm('lock8.view_bicycle_transitions', bicycle)
        assert not user.has_perm('lock8.cancel_reservation_bicycle', bicycle)
        assert not user.has_perm('lock8.return_bicycle', bicycle)
        assert not user.has_perm('lock8.change_bicycle', another_bicycle)
        assert not user.has_perm('lock8.view_bicycle', another_bicycle)
        assert not user.has_perm('lock8.delete_bicycle', another_bicycle)
        assert not user.has_perm('lock8.put_in_maintenance_bicycle',
                                 another_bicycle)
        assert not user.has_perm('lock8.declare_available_bicycle',
                                 another_bicycle)
        assert not user.has_perm('lock8.declare_lost_bicycle', another_bicycle)
        assert not user.has_perm('lock8.reserve_bicycle', another_bicycle)
        assert not user.has_perm('lock8.rent_bicycle', another_bicycle)
        assert not user.has_perm('lock8.force_put_in_maintenance_bicycle',
                                 another_bicycle)
        assert not user.has_perm('lock8.take_over_bicycle', another_bicycle)
        assert not user.has_perm('lock8.cancel_reservation_bicycle',
                                 another_bicycle)
        assert not user.has_perm('lock8.return_bicycle', another_bicycle)
        assert not user.has_perm('lock8.view_bicycle_transitions',
                                 another_bicycle)

    assert not spectator.has_perm('lock8.add_bicycle')
    assert not spectator.has_perm('lock8.change_bicycle', bicycle)
    assert not spectator.has_perm('lock8.view_bicycle', bicycle)
    assert not spectator.has_perm('lock8.delete_bicycle', bicycle)
    assert not spectator.has_perm('lock8.put_in_maintenance_bicycle',
                                  bicycle)
    assert not spectator.has_perm('lock8.declare_available_bicycle',
                                  bicycle)
    assert not spectator.has_perm('lock8.declare_lost_bicycle', bicycle)
    assert not spectator.has_perm('lock8.reserve_bicycle', bicycle)
    assert not spectator.has_perm('lock8.rent_bicycle', bicycle)
    assert not spectator.has_perm(
        'lock8.force_put_in_maintenance_bicycle', bicycle)
    assert not spectator.has_perm('lock8.take_over_bicycle', bicycle)
    assert not spectator.has_perm('lock8.view_bicycle_transitions',
                                  bicycle)
    assert not spectator.has_perm('lock8.cancel_reservation_bicycle',
                                  bicycle)
    assert not spectator.has_perm('lock8.return_bicycle', bicycle)

    assert fleet_admin.has_perm('lock8.add_bicycle')
    assert fleet_admin.has_perm('lock8.change_bicycle', bicycle)
    assert fleet_admin.has_perm('lock8.view_bicycle', bicycle)
    assert fleet_admin.has_perm('lock8.delete_bicycle', bicycle)
    assert fleet_admin.has_perm('lock8.put_in_maintenance_bicycle', bicycle)
    assert fleet_admin.has_perm('lock8.declare_available_bicycle', bicycle)
    assert fleet_admin.has_perm('lock8.declare_lost_bicycle', bicycle)
    assert fleet_admin.has_perm('lock8.reserve_bicycle', bicycle)
    assert fleet_admin.has_perm('lock8.rent_bicycle', bicycle)
    assert fleet_admin.has_perm('lock8.force_put_in_maintenance_bicycle',
                                bicycle)
    assert fleet_admin.has_perm('lock8.take_over_bicycle', bicycle)
    assert not fleet_admin.has_perm('lock8.cancel_reservation_bicycle',
                                    bicycle)
    assert not fleet_admin.has_perm('lock8.return_bicycle', bicycle)
    assert not fleet_admin.has_perm('lock8.change_bicycle',
                                    another_bicycle)
    assert not fleet_admin.has_perm('lock8.view_bicycle',
                                    another_bicycle)
    assert not fleet_admin.has_perm('lock8.delete_bicycle',
                                    another_bicycle)
    assert not fleet_admin.has_perm('lock8.put_in_maintenance_bicycle',
                                    another_bicycle)
    assert not fleet_admin.has_perm('lock8.declare_available_bicycle',
                                    another_bicycle)
    assert not fleet_admin.has_perm('lock8.declare_lost_bicycle',
                                    another_bicycle)
    assert not fleet_admin.has_perm('lock8.reserve_another_bicycle',
                                    another_bicycle)
    assert not fleet_admin.has_perm('lock8.rent_another_bicycle',
                                    another_bicycle)
    assert not fleet_admin.has_perm('lock8.end_trip_another_bicycle',
                                    another_bicycle)
    assert not fleet_admin.has_perm('lock8.cancel_reservation_bicycle',
                                    another_bicycle)
    assert not fleet_admin.has_perm('lock8.return_bicycle',
                                    another_bicycle)

    assert not alice.has_perm('lock8.add_bicycle')
    assert not alice.has_perm('lock8.change_bicycle', bicycle)
    assert not alice.has_perm('lock8.view_bicycle', bicycle)
    assert not alice.has_perm('lock8.delete_bicycle', bicycle)
    assert not alice.has_perm('lock8.put_in_maintenance_bicycle', bicycle)
    assert not alice.has_perm('lock8.declare_available_bicycle', bicycle)
    assert not alice.has_perm('lock8.declare_lost_bicycle', bicycle)
    assert not alice.has_perm('lock8.reserve_bicycle', bicycle)
    assert not alice.has_perm('lock8.rent_bicycle', bicycle)
    assert not alice.has_perm('lock8.end_trip_bicycle', bicycle)
    assert not alice.has_perm('lock8.return_bicycle', bicycle)
    assert not alice.has_perm('lock8.view_bicycle_transitions', bicycle)

    Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER,
    )
    Affiliation.objects.create(
        user=bob,
        organization=org,
        role=Affiliation.RENTER,
    )

    assert not alice.has_perm('lock8.add_bicycle')
    assert not alice.has_perm('lock8.change_bicycle', bicycle)
    assert not alice.has_perm('lock8.view_bicycle', bicycle)
    assert not alice.has_perm('lock8.delete_bicycle', bicycle)
    assert not alice.has_perm('lock8.add_bicycle')
    assert not alice.has_perm('lock8.change_bicycle', another_bicycle)
    assert not alice.has_perm('lock8.view_bicycle', another_bicycle)
    assert not alice.has_perm('lock8.delete_bicycle', another_bicycle)

    bicycle.declare_available()
    assert alice.has_perm('lock8.view_bicycle', bicycle)
    assert bob.has_perm('lock8.view_bicycle', bicycle)

    assert alice.has_perm('lock8.reserve_bicycle', bicycle)
    bicycle.reserve(by=alice, user=alice)

    assert alice.has_perm('lock8.view_bicycle', bicycle)
    assert not bob.has_perm('lock8.view_bicycle', bicycle)

    assert alice.has_perm('lock8.rent_bicycle', bicycle)
    bicycle.rent(by=alice, user=alice)

    assert not alice.has_perm('lock8.view_bicycle_transitions', bicycle)

    assert alice.has_perm('lock8.return_bicycle', bicycle)
    bicycle.return_(by=alice, user=alice)

    assert not anon.has_perm('lock8.view_bicycle', bicycle)


def test_bicycle_open_fleet(org, bicycle, fleet_operator, alice, admin_user,
                            fleet_admin, bob, anon, spectator):
    org.is_open_fleet = True
    org.save()

    assert not alice.has_perm('lock8.add_bicycle')
    assert not alice.has_perm('lock8.change_bicycle', bicycle)
    assert not alice.has_perm('lock8.view_bicycle', bicycle)
    assert not alice.has_perm('lock8.delete_bicycle', bicycle)
    assert not alice.has_perm('lock8.put_in_maintenance_bicycle', bicycle)
    assert not alice.has_perm('lock8.declare_available_bicycle', bicycle)
    assert not alice.has_perm('lock8.declare_lost_bicycle', bicycle)
    assert not alice.has_perm('lock8.reserve_bicycle', bicycle)
    assert not alice.has_perm('lock8.rent_bicycle', bicycle)
    assert not alice.has_perm('lock8.end_trip_bicycle', bicycle)
    assert not alice.has_perm('lock8.cancel_bicycle', bicycle)
    assert not anon.has_perm('lock8.view_bicycle', bicycle)

    assert not spectator.has_perm('lock8.add_bicycle')
    assert not spectator.has_perm('lock8.change_bicycle', bicycle)
    assert not spectator.has_perm('lock8.view_bicycle', bicycle)
    assert not spectator.has_perm('lock8.delete_bicycle', bicycle)
    assert not spectator.has_perm('lock8.put_in_maintenance_bicycle',
                                  bicycle)
    assert not spectator.has_perm('lock8.declare_available_bicycle',
                                  bicycle)
    assert not spectator.has_perm('lock8.declare_lost_bicycle', bicycle)
    assert not spectator.has_perm('lock8.reserve_bicycle', bicycle)
    assert not spectator.has_perm('lock8.rent_bicycle', bicycle)
    assert not spectator.has_perm('lock8.end_trip_bicycle', bicycle)
    assert not spectator.has_perm('lock8.cancel_bicycle', bicycle)

    bicycle.declare_available()
    assert alice.has_perm('lock8.view_bicycle', bicycle)
    assert bob.has_perm('lock8.view_bicycle', bicycle)
    assert anon.has_perm('lock8.view_bicycle', bicycle)
    assert not anon.has_perm('lock8.add_bicycle')
    assert not anon.has_perm('lock8.change_bicycle', bicycle)
    assert not anon.has_perm('lock8.delete_bicycle', bicycle)
    assert not anon.has_perm('lock8.put_in_maintenance_bicycle', bicycle)
    assert not anon.has_perm('lock8.declare_available_bicycle', bicycle)
    assert not anon.has_perm('lock8.declare_lost_bicycle', bicycle)
    assert not anon.has_perm('lock8.reserve_bicycle', bicycle)
    assert not anon.has_perm('lock8.rent_bicycle', bicycle)
    assert not anon.has_perm('lock8.end_trip_bicycle', bicycle)
    assert not anon.has_perm('lock8.cancel_bicycle', bicycle)

    bicycle.reserve(by=alice, user=alice)
    assert alice.has_perm('lock8.view_bicycle', bicycle)
    assert not bob.has_perm('lock8.view_bicycle', bicycle)
    assert not anon.has_perm('lock8.view_bicycle', bicycle)


def test_bicycle_model_closed_fleet(org, bicycle_model, fleet_operator, alice,
                                    admin_user, fleet_admin, spectator,
                                    supervisor):
    from velodrome.lock8.models import Affiliation

    assert admin_user.has_perm('lock8.add_bicyclemodel')
    assert admin_user.has_perm('lock8.change_bicyclemodel', bicycle_model)
    assert admin_user.has_perm('lock8.view_bicyclemodel', bicycle_model)
    assert admin_user.has_perm('lock8.delete_bicyclemodel', bicycle_model)

    for user in (fleet_operator, supervisor):
        assert user.has_perm('lock8.add_bicyclemodel')
        assert user.has_perm('lock8.change_bicyclemodel', bicycle_model)
        assert user.has_perm('lock8.view_bicyclemodel', bicycle_model)
        assert user.has_perm('lock8.delete_bicyclemodel', bicycle_model)

    assert fleet_admin.has_perm('lock8.add_bicyclemodel')
    assert fleet_admin.has_perm('lock8.change_bicyclemodel', bicycle_model)
    assert fleet_admin.has_perm('lock8.view_bicyclemodel', bicycle_model)
    assert fleet_admin.has_perm('lock8.delete_bicycle', bicycle_model)

    assert not alice.has_perm('lock8.add_bicyclemodel')
    assert not alice.has_perm('lock8.change_bicyclemodel', bicycle_model)
    assert not alice.has_perm('lock8.view_bicyclemodel', bicycle_model)
    assert not alice.has_perm('lock8.delete_bicyclemodel', bicycle_model)

    assert not spectator.has_perm('lock8.add_bicyclemodel')
    assert not spectator.has_perm('lock8.change_bicyclemodel',
                                  bicycle_model)
    assert spectator.has_perm('lock8.view_bicyclemodel', bicycle_model)
    assert not spectator.has_perm('lock8.delete_bicyclemodel',
                                  bicycle_model)

    Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER,
    )

    assert not alice.has_perm('lock8.add_bicyclemodel')
    assert not alice.has_perm('lock8.change_bicyclemodel', bicycle_model)
    assert alice.has_perm('lock8.view_bicyclemodel', bicycle_model)
    assert not alice.has_perm('lock8.delete_bicyclemodel', bicycle_model)
    assert not alice.has_perm('lock8.add_bicyclemodel')

    assert not spectator.has_perm('lock8.add_bicyclemodel')
    assert not spectator.has_perm('lock8.change_bicyclemodel',
                                  bicycle_model)
    assert spectator.has_perm('lock8.view_bicyclemodel', bicycle_model)
    assert not spectator.has_perm('lock8.delete_bicyclemodel',
                                  bicycle_model)


def test_bicycle_model_open_fleet(org, bicycle_model, fleet_operator, alice,
                                  admin_user, fleet_admin, bob,
                                  spectator, supervisor):
    org.is_open_fleet = True
    org.save()

    assert not alice.has_perm('lock8.add_bicyclemodel')
    assert not alice.has_perm('lock8.change_bicyclemodel', bicycle_model)
    assert alice.has_perm('lock8.view_bicyclemodel', bicycle_model)
    assert not alice.has_perm('lock8.delete_bicyclemodel', bicycle_model)
    assert not alice.has_perm('lock8.view_bicyclemodel_transitions',
                              bicycle_model)

    assert fleet_operator.has_perm('lock8.view_bicyclemodel_transitions',
                                   bicycle_model)
    assert supervisor.has_perm('lock8.view_bicyclemodel_transitions',
                               bicycle_model)

    assert not spectator.has_perm('lock8.add_bicyclemodel')
    assert not spectator.has_perm('lock8.change_bicyclemodel',
                                  bicycle_model)
    assert spectator.has_perm('lock8.view_bicyclemodel', bicycle_model)
    assert not spectator.has_perm('lock8.delete_bicyclemodel',
                                  bicycle_model)


def test_bicycle_type(city_bike, fleet_operator, alice, admin_user,
                      fleet_admin, spectator, supervisor):
    assert admin_user.has_perm('lock8.add_bicycletype')
    assert admin_user.has_perm('lock8.change_bicycletype', city_bike)
    assert admin_user.has_perm('lock8.view_bicycletype', city_bike)
    assert admin_user.has_perm('lock8.delete_bicycletype', city_bike)

    for user in (fleet_operator, supervisor):
        assert not user.has_perm('lock8.add_bicycletype')
        assert not user.has_perm('lock8.change_bicycletype', city_bike)
        assert user.has_perm('lock8.view_bicycletype', city_bike)
        assert not user.has_perm('lock8.delete_bicycletype', city_bike)

    assert not fleet_admin.has_perm('lock8.add_bicycletype')
    assert not fleet_admin.has_perm('lock8.change_bicycletype', city_bike)
    assert fleet_admin.has_perm('lock8.view_bicycletype', city_bike)
    assert not fleet_admin.has_perm('lock8.delete_bicycletype', city_bike)

    assert not alice.has_perm('lock8.add_bicycletype')
    assert not alice.has_perm('lock8.change_bicycletype', city_bike)
    assert alice.has_perm('lock8.view_bicycletype', city_bike)
    assert not alice.has_perm('lock8.delete_bicycletype', city_bike)

    assert not spectator.has_perm('lock8.add_bicycletype')
    assert not spectator.has_perm('lock8.change_bicycletype', city_bike)
    assert spectator.has_perm('lock8.view_bicycletype', city_bike)
    assert not spectator.has_perm('lock8.delete_bicycletype', city_bike)


def test_lock(lock, fleet_operator, alice, admin_user, another_lock,
              fleet_admin, spectator, production_software, supervisor):

    assert admin_user.has_perm('lock8.import_lock_csv_file')
    assert admin_user.has_perm('lock8.add_lock')
    assert admin_user.has_perm('lock8.change_lock', lock)
    assert admin_user.has_perm('lock8.view_lock', lock)
    assert admin_user.has_perm('lock8.view_lock_transitions', lock)
    assert admin_user.has_perm('lock8.delete_lock', lock)
    assert admin_user.has_perm('lock8.provision_lock', lock)
    assert admin_user.has_perm('lock8.put_in_maintenance_lock', lock)
    assert admin_user.has_perm('lock8.restore_lock', lock)
    assert admin_user.has_perm('lock8.change_lock', another_lock)
    assert admin_user.has_perm('lock8.view_lock', another_lock)
    assert admin_user.has_perm('lock8.delete_lock', another_lock)
    assert admin_user.has_perm('lock8.provision_lock', another_lock)
    assert admin_user.has_perm('lock8.put_in_maintenance_lock', another_lock)
    assert admin_user.has_perm('lock8.restore_lock', another_lock)

    for user in (fleet_operator, supervisor):
        assert not user.has_perm('lock8.import_lock_csv_file')
        assert not user.has_perm('lock8.add_lock')
        assert not user.has_perm('lock8.change_lock', lock)
        assert user.has_perm('lock8.view_lock', lock)
        assert not user.has_perm('lock8.view_lock_transitions', lock)
        assert not user.has_perm('lock8.delete_lock', lock)
        assert user.has_perm('lock8.put_in_maintenance_lock', lock)
        assert user.has_perm('lock8.restore_lock', lock)
        assert not user.has_perm('lock8.change_lock', another_lock)
        assert not user.has_perm('lock8.view_lock', another_lock)
        assert not user.has_perm('lock8.delete_lock', another_lock)
        assert not user.has_perm('lock8.put_in_maintenance_lock', another_lock)
        assert not user.has_perm('lock8.restore_lock', another_lock)

    # Supervisor now can activate and provision locks
    assert supervisor.has_perm('lock8.activate_lock', lock)
    assert not supervisor.has_perm('lock8.activate_lock', another_lock)
    assert supervisor.has_perm('lock8.provision_lock', lock)
    assert not supervisor.has_perm('lock8.provision_lock', another_lock)

    # ...and fleet operator still can not
    assert not fleet_operator.has_perm('lock8.activate_lock', lock)
    assert not fleet_operator.has_perm('lock8.activate_lock', another_lock)
    assert not fleet_operator.has_perm('lock8.provision_lock', lock)
    assert not fleet_operator.has_perm('lock8.provision_lock', another_lock)

    assert not fleet_admin.has_perm('lock8.import_lock_csv_file')
    assert not fleet_admin.has_perm('lock8.add_lock')
    assert not fleet_admin.has_perm('lock8.change_lock', lock)
    assert fleet_admin.has_perm('lock8.view_lock', lock)
    assert not fleet_admin.has_perm('lock8.delete_lock', lock)
    assert fleet_admin.has_perm('lock8.provision_lock', lock)
    assert fleet_admin.has_perm('lock8.put_in_maintenance_lock', lock)
    assert fleet_admin.has_perm('lock8.restore_lock', lock)
    assert not fleet_admin.has_perm('lock8.change_lock', another_lock)
    assert not fleet_admin.has_perm('lock8.view_lock', another_lock)
    assert not fleet_admin.has_perm('lock8.delete_lock', another_lock)
    assert not fleet_admin.has_perm('lock8.provision_lock', another_lock)
    assert not fleet_admin.has_perm('lock8.put_in_maintenance_lock',
                                    another_lock)
    assert not fleet_admin.has_perm('lock8.restore_lock', another_lock)

    assert not alice.has_perm('lock8.import_lock_csv_file')
    assert not alice.has_perm('lock8.add_lock')
    assert not alice.has_perm('lock8.change_lock', lock)
    assert not alice.has_perm('lock8.view_lock', lock)
    assert not alice.has_perm('lock8.delete_lock', lock)
    assert not alice.has_perm('lock8.provision', lock)
    assert not alice.has_perm('lock8.put_in_maintenance_lock', lock)
    assert not alice.has_perm('lock8.restore_lock', lock)

    assert not spectator.has_perm('lock8.import_lock_csv_file')
    assert not spectator.has_perm('lock8.add_lock')
    assert not spectator.has_perm('lock8.change_lock', lock)
    assert not spectator.has_perm('lock8.view_lock', lock)
    assert not spectator.has_perm('lock8.delete_lock', lock)
    assert not spectator.has_perm('lock8.provision', lock)
    assert not spectator.has_perm('lock8.put_in_maintenance_lock', lock)
    assert not spectator.has_perm('lock8.restore_lock', lock)

    assert not production_software.has_perm('lock8.import_lock_csv_file')
    assert production_software.has_perm('lock8.add_lock')
    assert not production_software.has_perm('lock8.change_lock', lock)
    assert not production_software.has_perm('lock8.view_lock', lock)
    assert not production_software.has_perm('lock8.view_lock_transitions',
                                            lock)
    assert not production_software.has_perm('lock8.delete_lock', lock)
    assert not production_software.has_perm('lock8.provision_lock', lock)
    assert not production_software.has_perm('lock8.put_in_maintenance_lock',
                                            lock)
    assert not production_software.has_perm('lock8.restore_lock', lock)


def test_photo_closed_fleet(photo, fleet_operator, alice, admin_user, org,
                            another_photo, fleet_admin, spectator, supervisor):
    from velodrome.lock8.models import Affiliation

    assert admin_user.has_perm('lock8.add_photo')
    assert admin_user.has_perm('lock8.change_photo', photo)
    assert admin_user.has_perm('lock8.view_photo', photo)
    assert admin_user.has_perm('lock8.delete_photo', another_photo)
    assert admin_user.has_perm('lock8.change_photo', another_photo)
    assert admin_user.has_perm('lock8.view_photo', another_photo)
    assert admin_user.has_perm('lock8.delete_photo', another_photo)

    assert fleet_operator.has_perm('lock8.add_photo')
    assert fleet_operator.has_perm('lock8.change_photo', photo)
    assert fleet_operator.has_perm('lock8.view_photo', photo)
    assert fleet_operator.has_perm('lock8.delete_photo', photo)
    assert fleet_operator.has_perm('lock8.view_photo_transitions', photo)
    assert not fleet_operator.has_perm('lock8.change_photo', another_photo)
    assert not fleet_operator.has_perm('lock8.view_photo', another_photo)
    assert not fleet_operator.has_perm('lock8.delete_photo', another_photo)
    assert not fleet_operator.has_perm('lock8.view_photo_transitions',
                                       another_photo)

    for user in (fleet_operator, supervisor):
        assert user.has_perm('lock8.add_photo')
        assert user.has_perm('lock8.change_photo', photo)
        assert user.has_perm('lock8.view_photo', photo)
        assert user.has_perm('lock8.delete_photo', photo)
        assert user.has_perm('lock8.view_photo_transitions', photo)
        assert not user.has_perm('lock8.change_photo', another_photo)
        assert not user.has_perm('lock8.view_photo', another_photo)
        assert not user.has_perm('lock8.delete_photo', another_photo)
        assert not user.has_perm('lock8.view_photo_transitions', another_photo)

    assert fleet_admin.has_perm('lock8.add_photo')
    assert fleet_admin.has_perm('lock8.change_photo', photo)
    assert fleet_admin.has_perm('lock8.view_photo', photo)
    assert fleet_admin.has_perm('lock8.delete_photo', photo)
    assert not fleet_admin.has_perm('lock8.change_photo', another_photo)
    assert not fleet_admin.has_perm('lock8.view_photo', another_photo)
    assert not fleet_admin.has_perm('lock8.delete_photo', another_photo)

    assert not alice.has_perm('lock8.add_photo')
    assert not alice.has_perm('lock8.change_photo', photo)
    assert not alice.has_perm('lock8.view_photo', photo)
    assert not alice.has_perm('lock8.delete_photo', photo)

    Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER,
    )

    assert not alice.has_perm('lock8.change_photo', photo)
    assert alice.has_perm('lock8.view_photo', photo)
    assert not alice.has_perm('lock8.delete_photo', photo)
    assert not alice.has_perm('lock8.change_photo', another_photo)
    assert not alice.has_perm('lock8.view_photo', another_photo)
    assert not alice.has_perm('lock8.delete_photo', another_photo)

    assert not spectator.has_perm('lock8.change_photo', photo)
    assert spectator.has_perm('lock8.view_photo', photo)
    assert not spectator.has_perm('lock8.delete_photo', photo)
    assert not spectator.has_perm('lock8.change_photo', another_photo)
    assert not spectator.has_perm('lock8.view_photo', another_photo)
    assert not spectator.has_perm('lock8.delete_photo', another_photo)


def test_photo_open_fleet(org, photo, fleet_operator, alice, admin_user,
                          fleet_admin, supervisor):
    org.is_open_fleet = True
    org.save()

    assert admin_user.has_perm('lock8.add_photo')
    assert admin_user.has_perm('lock8.change_photo', photo)
    assert admin_user.has_perm('lock8.view_photo', photo)
    assert admin_user.has_perm('lock8.delete_photo', photo)

    assert fleet_operator.has_perm('lock8.add_photo')
    assert fleet_operator.has_perm('lock8.change_photo', photo)
    assert fleet_operator.has_perm('lock8.view_photo', photo)
    assert fleet_operator.has_perm('lock8.delete_photo', photo)

    for user in (fleet_operator, supervisor):
        assert user.has_perm('lock8.add_photo')
        assert user.has_perm('lock8.change_photo', photo)
        assert user.has_perm('lock8.view_photo', photo)
        assert user.has_perm('lock8.delete_photo', photo)

    assert fleet_admin.has_perm('lock8.add_photo')
    assert fleet_admin.has_perm('lock8.change_photo', photo)
    assert fleet_admin.has_perm('lock8.view_photo', photo)
    assert fleet_admin.has_perm('lock8.delete_photo', photo)

    assert not alice.has_perm('lock8.add_photo')
    assert not alice.has_perm('lock8.change_photo', photo)
    assert alice.has_perm('lock8.view_photo', photo)
    assert not alice.has_perm('lock8.delete_photo', photo)


def test_user(org, fleet_operator, alice, admin_user, fleet_admin,
              spectator, supervisor):
    from velodrome.lock8.models import Affiliation

    assert admin_user.has_perm('lock8.add_user')
    assert admin_user.has_perm('lock8.change_user', alice)
    assert admin_user.has_perm('lock8.view_user', alice)
    assert admin_user.has_perm('lock8.delete_user', alice)
    assert admin_user.has_perm('lock8.disable_user', alice)
    assert admin_user.has_perm('lock8.enable_user', alice)

    for user in (fleet_operator, supervisor):
        assert not user.has_perm('lock8.add_user')
        assert not user.has_perm('lock8.change_user', alice)
        assert not user.has_perm('lock8.view_user', alice)
        assert not user.has_perm('lock8.view_user_transitions', alice)
        assert not user.has_perm('lock8.delete_user', alice)
        assert not user.has_perm('lock8.enable_user', alice)
        assert not user.has_perm('lock8.disable_user', alice)

    assert not fleet_admin.has_perm('lock8.add_user')
    assert not fleet_admin.has_perm('lock8.change_user', alice)
    assert not fleet_admin.has_perm('lock8.view_user', alice)
    assert not fleet_admin.has_perm('lock8.delete_user', alice)
    assert not fleet_admin.has_perm('lock8.disable_user', alice)
    assert not fleet_admin.has_perm('lock8.enable_user', alice)

    assert not alice.has_perm('lock8.add_user')
    assert alice.has_perm('lock8.change_user', alice)
    assert alice.has_perm('lock8.view_user', alice)
    assert not alice.has_perm('lock8.view_user_transitions', alice)
    assert alice.has_perm('lock8.delete_user', alice)
    assert not alice.has_perm('lock8.enable_user', alice)
    assert not alice.has_perm('lock8.disable_user', alice)

    Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER,
    )

    for user in (fleet_operator, supervisor):
        assert not user.has_perm('lock8.add_user')
        assert not user.has_perm('lock8.change_user', alice)
        assert user.has_perm('lock8.view_user', alice)
        assert not user.has_perm('lock8.view_user_transitions', alice)
        assert not user.has_perm('lock8.delete_user', alice)
        assert user.has_perm('lock8.disable_user', alice)
        assert user.has_perm('lock8.enable_user', alice)

    assert not fleet_admin.has_perm('lock8.add_user')
    assert not fleet_admin.has_perm('lock8.change_user', alice)
    assert fleet_admin.has_perm('lock8.view_user', alice)
    assert not fleet_admin.has_perm('lock8.delete_user', alice)
    assert fleet_admin.has_perm('lock8.disable_user', alice)
    assert fleet_admin.has_perm('lock8.enable_user', alice)

    assert not spectator.has_perm('lock8.add_user')
    assert not spectator.has_perm('lock8.change_user', spectator)
    assert spectator.has_perm('lock8.view_user', spectator)
    assert not spectator.has_perm('lock8.view_user_transitions',
                                  spectator)
    assert not spectator.has_perm('lock8.delete_user', spectator)
    assert not spectator.has_perm('lock8.enable_user', spectator)
    assert not spectator.has_perm('lock8.disable_user',
                                  spectator)


def test_alice_can_view_herself_when_not_same_object(alice):
    from velodrome.lock8.models import User

    obj = User.objects.get(pk=alice.pk)
    assert obj is not alice
    assert alice.has_perm('lock8.view_user', obj)


def test_alice_can_change_her_password(alice, bob):
    assert alice.has_perm('lock8.change_password_user', alice)
    assert not alice.has_perm('lock8.change_password_user', bob)


def test_trip_security(trip, another_trip, trip_with_invalid_bicycle,
                       fleet_operator, alice, admin_user, fleet_admin, org,
                       bicycle, spectator, supervisor):

    assert not admin_user.has_perm('lock8.add_trip')
    assert not admin_user.has_perm('lock8.change_trip')
    assert not admin_user.has_perm('lock8.change_trip', trip)
    assert admin_user.has_perm('lock8.view_trip', trip)
    assert not admin_user.has_perm('lock8.delete_trip', trip)
    assert not admin_user.has_perm('lock8.change_trip', another_trip)

    assert admin_user.has_perm('lock8.view_trip', another_trip)
    assert not admin_user.has_perm('lock8.delete_trip', another_trip)

    for user in (fleet_operator, supervisor):
        assert not user.has_perm('lock8.add_trip')
        assert not user.has_perm('lock8.change_trip')
        assert not user.has_perm('lock8.change_trip', trip)
        assert user.has_perm('lock8.view_trip')
        assert user.has_perm('lock8.view_trip', trip)
        assert not user.has_perm('lock8.delete_trip', trip)
        assert not user.has_perm('lock8.change_trip', another_trip)
        assert not user.has_perm('lock8.view_trip', another_trip)
        assert not user.has_perm('lock8.delete_trip', another_trip)

    assert not fleet_admin.has_perm('lock8.add_trip')
    assert not fleet_admin.has_perm('lock8.change_trip', trip)
    assert fleet_admin.has_perm('lock8.view_trip')
    assert fleet_admin.has_perm('lock8.view_trip', trip)
    assert not fleet_admin.has_perm('lock8.delete_trip', trip)
    assert not fleet_admin.has_perm('lock8.change_trip', another_trip)
    assert not fleet_admin.has_perm('lock8.view_trip', another_trip)
    assert not fleet_admin.has_perm('lock8.delete_trip', another_trip)

    assert not alice.has_perm('lock8.add_trip')
    assert not alice.has_perm('lock8.change_trip', trip)
    assert not alice.has_perm('lock8.view_trip', trip)
    assert not alice.has_perm('lock8.delete_trip', trip)


def test_trip_security_for_renter(renter, request, bicycle):
    bicycle.declare_available()
    bicycle.reserve(by=renter)

    assert renter.has_perm('lock8.view_trip')

    with freeze_time(timezone.now() - timedelta(minutes=15, seconds=2)):
        bicycle.rent(by=renter)
    trip = request.getfixturevalue('trip')
    unfinished_trip = request.getfixturevalue('unfinished_trip')

    assert renter.has_perm('lock8.view_trip')
    assert renter.has_perm('lock8.view_trip', trip)
    assert renter.has_perm('lock8.view_trip', unfinished_trip)

    bicycle.return_(by=renter)

    assert renter.has_perm('lock8.view_trip', trip)
    assert renter.has_perm('lock8.view_trip', unfinished_trip)


def test_invitation(org, invitation, fleet_operator, alice, admin_user,
                    fleet_admin, spectator, supervisor):

    assert admin_user.has_perm('lock8.add_invitation')
    assert admin_user.has_perm('lock8.change_invitation', invitation)
    assert admin_user.has_perm('lock8.view_invitation', invitation)
    assert admin_user.has_perm('lock8.delete_invitation', invitation)
    assert admin_user.has_perm('lock8.provision_invitation', invitation)
    assert admin_user.has_perm('lock8.cancel_invitation', invitation)
    assert admin_user.has_perm('lock8.confirm_invitation', invitation)
    assert admin_user.has_perm('lock8.decline_invitation', invitation)

    for user in (fleet_operator, supervisor):
        assert user.has_perm('lock8.add_invitation')
        assert user.has_perm('lock8.change_invitation', invitation)
        assert user.has_perm('lock8.view_invitation', invitation)
        assert user.has_perm('lock8.view_invitation_transitions', invitation)
        assert user.has_perm('lock8.delete_invitation', invitation)
        assert user.has_perm('lock8.provision_invitation', invitation)
        assert user.has_perm('lock8.cancel_invitation', invitation)
        assert user.has_perm('lock8.confirm_invitation', invitation)
        assert user.has_perm('lock8.decline_invitation', invitation)

    assert fleet_admin.has_perm('lock8.add_invitation')
    assert fleet_admin.has_perm('lock8.change_invitation', invitation)
    assert fleet_admin.has_perm('lock8.view_invitation', invitation)
    assert fleet_admin.has_perm('lock8.delete_invitation', invitation)
    assert fleet_admin.has_perm('lock8.provision_invitation', invitation)
    assert fleet_admin.has_perm('lock8.cancel_invitation', invitation)
    assert fleet_admin.has_perm('lock8.confirm_invitation', invitation)
    assert fleet_admin.has_perm('lock8.decline_invitation', invitation)

    assert not alice.has_perm('lock8.add_invitation')
    assert not alice.has_perm('lock8.change_invitation', invitation)
    assert alice.has_perm('lock8.view_invitation', invitation)
    assert not alice.has_perm('lock8.view_invitation_transitions', invitation)
    assert not alice.has_perm('lock8.delete_invitation', invitation)
    assert not alice.has_perm('lock8.provision_invitation', invitation)
    assert not alice.has_perm('lock8.cancel_invitation', invitation)
    assert alice.has_perm('lock8.confirm_invitation', invitation)
    assert alice.has_perm('lock8.decline_invitation', invitation)

    assert not spectator.has_perm('lock8.add_invitation')
    assert not spectator.has_perm('lock8.change_invitation', invitation)
    assert not spectator.has_perm('lock8.view_invitation', invitation)
    assert not spectator.has_perm('lock8.view_invitation_transitions',
                                  invitation)
    assert not spectator.has_perm('lock8.delete_invitation', invitation)
    assert not spectator.has_perm('lock8.provision_invitation', invitation)
    assert not spectator.has_perm('lock8.cancel_invitation', invitation)
    assert not spectator.has_perm('lock8.confirm_invitation', invitation)
    assert not spectator.has_perm('lock8.decline_invitation', invitation)

    invitation.provision()
    invitation.confirm(by=alice)

    assert alice.has_perm('lock8.view_invitation', invitation)
    assert not spectator.has_perm('lock8.view_invitation', invitation)


def test_affiliation(org, fleet_operator, alice, admin_user, fleet_admin,
                     spectator, supervisor):
    from velodrome.lock8.models import Affiliation

    affiliation = Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.RENTER,
    )

    assert admin_user.has_perm('lock8.add_affiliation')
    assert admin_user.has_perm('lock8.change_affiliation', affiliation)
    assert admin_user.has_perm('lock8.view_affiliation', affiliation)
    assert admin_user.has_perm('lock8.delete_affiliation', affiliation)

    for user in (fleet_operator, supervisor):
        assert user.has_perm('lock8.add_affiliation')
        assert user.has_perm('lock8.change_affiliation', affiliation)
        assert user.has_perm('lock8.view_affiliation', affiliation)
        assert user.has_perm('lock8.delete_affiliation', affiliation)

    assert fleet_admin.has_perm('lock8.add_affiliation')
    assert fleet_admin.has_perm('lock8.change_affiliation', affiliation)
    assert fleet_admin.has_perm('lock8.view_affiliation', affiliation)
    assert fleet_admin.has_perm('lock8.delete_affiliation', affiliation)

    assert not alice.has_perm('lock8.add_affiliation')
    assert not alice.has_perm('lock8.change_affiliation', affiliation)
    assert alice.has_perm('lock8.view_affiliation', affiliation)
    assert not alice.has_perm('lock8.delete_affiliation', affiliation)

    assert not spectator.has_perm('lock8.add_affiliation')
    assert not spectator.has_perm('lock8.change_affiliation',
                                  affiliation)
    assert not spectator.has_perm('lock8.view_affiliation', affiliation)
    assert not spectator.has_perm('lock8.delete_affiliation',
                                  affiliation)


def test_address(address, fleet_operator, alice, admin_user,
                 fleet_admin, org, supervisor):
    from velodrome.lock8.models import Affiliation

    Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.RENTER,
    )

    assert admin_user.has_perm('lock8.add_address')
    assert admin_user.has_perm('lock8.change_address', address)
    assert admin_user.has_perm('lock8.view_address', address)
    assert admin_user.has_perm('lock8.delete_address', address)

    assert fleet_operator.has_perm('lock8.add_address')
    assert fleet_operator.has_perm('lock8.change_address', address)
    assert fleet_operator.has_perm('lock8.view_address', address)
    assert fleet_operator.has_perm('lock8.view_address_transitions', address)
    assert fleet_operator.has_perm('lock8.delete_address', address)

    for user in (fleet_operator, supervisor):
        assert user.has_perm('lock8.add_address')
        assert user.has_perm('lock8.change_address', address)
        assert user.has_perm('lock8.view_address', address)
        assert user.has_perm('lock8.view_address_transitions', address)
        assert user.has_perm('lock8.delete_address', address)

    assert fleet_admin.has_perm('lock8.add_address')
    assert fleet_admin.has_perm('lock8.change_address', address)
    assert fleet_admin.has_perm('lock8.view_address', address)
    assert fleet_admin.has_perm('lock8.delete_address', address)

    assert not alice.has_perm('lock8.add_address')
    assert not alice.has_perm('lock8.change_address', address)
    assert not alice.has_perm('lock8.view_address', address)
    assert not alice.has_perm('lock8.view_address_transitions', address)
    assert not alice.has_perm('lock8.delete_address', address)


def test_zone(zone, fleet_operator, alice, admin_user,
              fleet_admin, org, spectator, supervisor):
    from velodrome.lock8.models import Affiliation

    assert not alice.has_perm('lock8.view_zone', zone)

    Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.RENTER,
    )

    assert admin_user.has_perm('lock8.add_zone')
    assert admin_user.has_perm('lock8.change_zone', zone)
    assert admin_user.has_perm('lock8.view_zone', zone)
    assert admin_user.has_perm('lock8.delete_zone', zone)

    for user in (fleet_operator, supervisor):
        assert user.has_perm('lock8.add_zone')
        assert user.has_perm('lock8.change_zone', zone)
        assert user.has_perm('lock8.view_zone', zone)
        assert user.has_perm('lock8.view_zone_transitions', zone)
        assert user.has_perm('lock8.delete_zone', zone)

    assert fleet_admin.has_perm('lock8.add_zone')
    assert fleet_admin.has_perm('lock8.change_zone', zone)
    assert fleet_admin.has_perm('lock8.view_zone', zone)
    assert fleet_admin.has_perm('lock8.delete_zone', zone)

    assert not alice.has_perm('lock8.add_zone')
    assert not alice.has_perm('lock8.change_zone', zone)
    assert alice.has_perm('lock8.view_zone', zone)
    assert not alice.has_perm('lock8.view_zone_transitions', zone)
    assert not alice.has_perm('lock8.delete_zone', zone)

    assert not spectator.has_perm('lock8.add_zone')
    assert not spectator.has_perm('lock8.change_zone', zone)
    assert not spectator.has_perm('lock8.view_zone', zone)
    assert not spectator.has_perm('lock8.view_zone_transitions', zone)
    assert not spectator.has_perm('lock8.delete_zone', zone)


def test_reservation_security(fleet_operator, alice, admin_user, bicycle,
                              fleet_admin, another_bicycle, bob, supervisor):
    bicycle.declare_available()
    bicycle.reserve(by=alice)

    reservation = bicycle.active_reservation

    another_bicycle.declare_available()
    another_bicycle.reserve(by=bob)

    another_reservation = another_bicycle.active_reservation
    assert not admin_user.has_perm('lock8.add_reservation')
    assert admin_user.has_perm('lock8.change_reservation', reservation)
    assert admin_user.has_perm('lock8.view_reservation', reservation)
    assert admin_user.has_perm('lock8.view_reservation_transitions',
                               reservation)
    assert admin_user.has_perm('lock8.delete_reservation', reservation)
    assert admin_user.has_perm('lock8.change_reservation',
                               another_reservation)
    assert admin_user.has_perm('lock8.view_reservation',
                               another_reservation)
    assert admin_user.has_perm('lock8.delete_reservation',
                               another_reservation)

    for user in (fleet_operator, supervisor):
        assert not user.has_perm('lock8.add_reservation')
        assert user.has_perm('lock8.change_reservation', reservation)
        assert user.has_perm('lock8.view_reservation', reservation)
        assert user.has_perm('lock8.delete_reservation', reservation)
        assert not user.has_perm('lock8.change_reservation',
                                 another_reservation)
        assert not user.has_perm('lock8.view_reservation', another_reservation)
        assert not user.has_perm('lock8.view_reservation_transitions',
                                 another_reservation)
        assert not user.has_perm('lock8.delete_reservation',
                                 another_reservation)

    assert not fleet_admin.has_perm('lock8.add_reservation')
    assert fleet_admin.has_perm('lock8.change_reservation', reservation)
    assert fleet_admin.has_perm('lock8.view_reservation', reservation)
    assert fleet_admin.has_perm('lock8.delete_reservation', reservation)
    assert not fleet_admin.has_perm('lock8.change_reservation',
                                    another_reservation)
    assert not fleet_admin.has_perm('lock8.view_reservation',
                                    another_reservation)
    assert not fleet_admin.has_perm('lock8.delete_reservation',
                                    another_reservation)

    assert not alice.has_perm('lock8.add_reservation')
    assert not alice.has_perm('lock8.change_reservation', reservation)
    assert alice.has_perm('lock8.view_reservation', reservation)
    assert alice.has_perm('lock8.view_reservation_transitions', reservation)
    assert not alice.has_perm('lock8.delete_reservation', reservation)


def test_rental_session_security(fleet_operator, alice, admin_user, bicycle,
                                 fleet_admin, another_bicycle, bob,
                                 supervisor):
    bicycle.declare_available()
    bicycle.rent(by=alice)
    rental_session = bicycle.active_rental_session

    another_bicycle.declare_available()
    another_bicycle.rent(by=bob)
    another_rental_session = another_bicycle.active_rental_session

    assert not admin_user.has_perm('lock8.add_rentalsession')
    assert admin_user.has_perm('lock8.change_rentalsession', rental_session)
    assert admin_user.has_perm('lock8.view_rentalsession', rental_session)
    assert admin_user.has_perm('lock8.delete_rentalsession', rental_session)
    assert admin_user.has_perm('lock8.change_rentalsession',
                               another_rental_session)
    assert admin_user.has_perm('lock8.view_rentalsession',
                               another_rental_session)
    assert admin_user.has_perm('lock8.delete_rentalsession',
                               another_rental_session)

    for user in (fleet_operator, supervisor):
        assert not user.has_perm('lock8.add_rentalsession')
        assert user.has_perm('lock8.change_rentalsession', rental_session)
        assert user.has_perm('lock8.view_rentalsession', rental_session)
        assert user.has_perm('lock8.view_rentalsession_transitions',
                             rental_session)
        assert user.has_perm('lock8.delete_rentalsession', rental_session)
        assert not user.has_perm('lock8.change_rentalsession',
                                 another_rental_session)
        assert not user.has_perm('lock8.view_rentalsession',
                                 another_rental_session)
        assert not user.has_perm('lock8.delete_rentalsession',
                                 another_rental_session)

    assert not fleet_admin.has_perm('lock8.add_rentalsession')
    assert fleet_admin.has_perm('lock8.change_rentalsession', rental_session)
    assert fleet_admin.has_perm('lock8.view_rentalsession', rental_session)
    assert fleet_admin.has_perm('lock8.delete_rentalsession', rental_session)
    assert not fleet_admin.has_perm('lock8.change_rentalsession',
                                    another_rental_session)
    assert not fleet_admin.has_perm('lock8.view_rentalsession',
                                    another_rental_session)
    assert not fleet_admin.has_perm('lock8.delete_rentalsession',
                                    another_rental_session)

    assert not alice.has_perm('lock8.add_rentalsession')
    assert not alice.has_perm('lock8.change_rentalsession', rental_session)
    assert alice.has_perm('lock8.view_rentalsession', rental_session)
    assert alice.has_perm('lock8.view_rentalsession_transitions',
                          rental_session)
    assert not alice.has_perm('lock8.delete_rentalsession', rental_session)


def test_renting_scheme(renting_scheme, fleet_operator, alice, admin_user,
                        another_renting_scheme, fleet_admin, supervisor):
    assert admin_user.has_perm('lock8.add_rentingscheme')
    assert admin_user.has_perm('lock8.change_rentingscheme', renting_scheme)
    assert admin_user.has_perm('lock8.view_rentingscheme', renting_scheme)
    assert admin_user.has_perm('lock8.delete_rentingscheme', renting_scheme)
    assert admin_user.has_perm('lock8.change_rentingscheme',
                               another_renting_scheme)
    assert admin_user.has_perm('lock8.view_rentingscheme',
                               another_renting_scheme)
    assert admin_user.has_perm('lock8.delete_rentingscheme',
                               another_renting_scheme)

    for user in (fleet_operator, supervisor):
        assert user.has_perm('lock8.add_rentingscheme')
        assert user.has_perm('lock8.change_rentingscheme', renting_scheme)
        assert user.has_perm('lock8.view_rentingscheme', renting_scheme)
        assert user.has_perm('lock8.view_rentingscheme_transitions',
                             renting_scheme)
        assert user.has_perm('lock8.delete_rentingscheme', renting_scheme)
        assert not user.has_perm('lock8.change_rentingscheme',
                                 another_renting_scheme)
        assert not user.has_perm('lock8.view_rentingscheme',
                                 another_renting_scheme)
        assert not user.has_perm('lock8.delete_rentingscheme',
                                 another_renting_scheme)

    assert fleet_admin.has_perm('lock8.add_rentingscheme')
    assert fleet_admin.has_perm('lock8.change_rentingscheme', renting_scheme)
    assert fleet_admin.has_perm('lock8.view_rentingscheme', renting_scheme)
    assert fleet_admin.has_perm('lock8.delete_rentingscheme', renting_scheme)
    assert not fleet_admin.has_perm('lock8.change_rentingscheme',
                                    another_renting_scheme)
    assert not fleet_admin.has_perm('lock8.view_rentingscheme',
                                    another_renting_scheme)
    assert not fleet_admin.has_perm('lock8.delete_rentingscheme',
                                    another_renting_scheme)

    assert not alice.has_perm('lock8.add_rentingscheme')
    assert not alice.has_perm('lock8.change_rentingscheme', renting_scheme)
    assert not alice.has_perm('lock8.view_rentingscheme', renting_scheme)
    assert not alice.has_perm('lock8.view_rentingscheme_transitions',
                              renting_scheme)
    assert not alice.has_perm('lock8.delete_rentingscheme', renting_scheme)


@pytest.mark.uses_payments
def test_plan_pass_security(org, another_org, renter, admin_user,
                            fleet_operator, subscription_plan,
                            another_fleet_operator, supervisor):
    from velodrome.lock8.models import PlanPass
    assert renter.has_perm('lock8.subscribe_user_subscriptionplan',
                           subscription_plan)
    subscription_plan.is_restricted = True
    subscription_plan.save()

    assert not renter.has_perm('lock8.subscribe_user_subscriptionplan',
                               subscription_plan)

    plan_pass = PlanPass.objects.create(user=renter,
                                        subscription_plan=subscription_plan)
    assert renter.has_perm('lock8.subscribe_user_subscriptionplan',
                           subscription_plan)

    assert not renter.has_perm('lock8.add_planpass')
    assert not renter.has_perm('lock8.view_planpass', plan_pass)
    assert not renter.has_perm('lock8.change_planpass', plan_pass)
    assert not renter.has_perm('lock8.delete_planpass', plan_pass)
    assert admin_user.has_perm('lock8.add_planpass')
    assert admin_user.has_perm('lock8.view_planpass', plan_pass)
    assert admin_user.has_perm('lock8.change_planpass', plan_pass)
    assert admin_user.has_perm('lock8.delete_planpass', plan_pass)

    for user in (fleet_operator, supervisor):
        assert user.has_perm('lock8.add_planpass')
        assert user.has_perm('lock8.view_planpass', plan_pass)
        assert user.has_perm('lock8.change_planpass', plan_pass)
        assert user.has_perm('lock8.delete_planpass', plan_pass)

    assert another_fleet_operator.has_perm('lock8.add_planpass')
    assert not another_fleet_operator.has_perm('lock8.view_planpass',
                                               plan_pass)
    assert not another_fleet_operator.has_perm('lock8.change_planpass',
                                               plan_pass)
    assert not another_fleet_operator.has_perm('lock8.delete_planpass',
                                               plan_pass)


def test_organization_preference_security(organization_preference,
                                          fleet_operator, alice, admin_user,
                                          fleet_admin, org, spectator,
                                          supervisor):
    from velodrome.lock8.models import Affiliation

    Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.RENTER,
    )

    assert admin_user.has_perm('lock8.add_organizationpreference')
    assert admin_user.has_perm('lock8.change_organizationpreference',
                               organization_preference)
    assert admin_user.has_perm('lock8.view_organizationpreference',
                               organization_preference)
    assert admin_user.has_perm('lock8.delete_organizationpreference',
                               organization_preference)

    for user in (fleet_operator, supervisor):
        assert user.has_perm('lock8.add_organizationpreference')
        assert user.has_perm('lock8.change_organizationpreference',
                             organization_preference)
        assert user.has_perm('lock8.view_organizationpreference',
                             organization_preference)
        assert user.has_perm('lock8.view_organizationpreference_transitions',
                             organization_preference)
        assert user.has_perm('lock8.delete_organizationpreference',
                             organization_preference)

    assert fleet_admin.has_perm('lock8.add_organizationpreference')
    assert fleet_admin.has_perm('lock8.change_organizationpreference',
                                organization_preference)
    assert fleet_admin.has_perm('lock8.view_organizationpreference',
                                organization_preference)
    assert fleet_admin.has_perm('lock8.delete_organizationpreference',
                                organization_preference)

    assert not alice.has_perm('lock8.add_organizationpreference')
    assert not alice.has_perm('lock8.change_organizationpreference',
                              organization_preference)
    assert not alice.has_perm('lock8.view_organizationpreference',
                              organization_preference)
    assert not alice.has_perm('lock8.delete_organizationpreference',
                              organization_preference)
    assert not alice.has_perm('lock8.view_organizationpreference_transitions',
                              organization_preference)

    assert not spectator.has_perm('lock8.add_organizationpreference')
    assert not spectator.has_perm('lock8.change_organizationpreference',
                                  organization_preference)
    assert not spectator.has_perm('lock8.view_organizationpreference',
                                  organization_preference)
    assert not spectator.has_perm('lock8.delete_organizationpreference',
                                  organization_preference)
    assert not spectator.has_perm(
        'lock8.view_organizationpreference_transitions',
        organization_preference)
    assert not alice.has_perm('lock8.add_organizationpreference')
    assert not alice.has_perm('lock8.change_organizationpreference',
                              organization_preference)
    assert not alice.has_perm('lock8.view_organizationpreference',
                              organization_preference)
    assert not alice.has_perm('lock8.delete_organizationpreference',
                              organization_preference)
    assert not alice.has_perm('lock8.view_organizationpreference_transitions',
                              organization_preference)


def test_support_ticket_security(fleet_operator, alice, admin_user,
                                 fleet_admin, support_ticket,
                                 another_support_ticket, spectator,
                                 supervisor):
    assert admin_user.has_perm('lock8.add_supportticket')
    assert admin_user.has_perm('lock8.view_supportticket', support_ticket)
    assert admin_user.has_perm(
        'lock8.view_supportticket', another_support_ticket
    )
    assert admin_user.has_perm('lock8.change_supportticket', support_ticket)
    assert admin_user.has_perm(
        'lock8.change_supportticket', another_support_ticket
    )
    assert admin_user.has_perm('lock8.delete_supportticket', support_ticket)
    assert admin_user.has_perm(
        'lock8.delete_supportticket', another_support_ticket
    )

    for user in (fleet_operator, supervisor):
        assert user.has_perm('lock8.add_supportticket')
        assert user.has_perm('lock8.view_supportticket', support_ticket)
        assert not user.has_perm('lock8.view_supportticket',
                                 another_support_ticket)
        assert user.has_perm('lock8.change_supportticket', support_ticket)
        assert not user.has_perm('lock8.change_supportticket',
                                 another_support_ticket)
        assert user.has_perm('lock8.delete_supportticket', support_ticket)
        assert not user.has_perm('lock8.delete_supportticket',
                                 another_support_ticket)

    assert fleet_admin.has_perm('lock8.add_supportticket')
    assert fleet_admin.has_perm('lock8.view_supportticket', support_ticket)
    assert not fleet_admin.has_perm(
        'lock8.view_supportticket', another_support_ticket
    )
    assert fleet_admin.has_perm('lock8.change_supportticket', support_ticket)
    assert not fleet_admin.has_perm(
        'lock8.change_supportticket', another_support_ticket
    )
    assert fleet_admin.has_perm('lock8.delete_supportticket', support_ticket)
    assert not fleet_admin.has_perm(
        'lock8.delete_supportticket', another_support_ticket
    )

    assert alice.has_perm('lock8.add_supportticket')
    assert alice.has_perm('lock8.view_supportticket', support_ticket)
    assert not alice.has_perm(
        'lock8.view_supportticket', another_support_ticket
    )
    assert alice.has_perm('lock8.change_supportticket', support_ticket)
    assert not alice.has_perm(
        'lock8.change_supportticket', another_support_ticket
    )
    assert not alice.has_perm('lock8.delete_supportticket', support_ticket)
    assert not alice.has_perm(
        'lock8.delete_supportticket', another_support_ticket
    )

    assert not spectator.has_perm('lock8.add_supportticket')
    assert not spectator.has_perm('lock8.view_supportticket', support_ticket)
    assert not spectator.has_perm('lock8.view_supportticket',
                                  another_support_ticket)
    assert not spectator.has_perm('lock8.change_supportticket', support_ticket)
    assert not spectator.has_perm('lock8.change_supportticket',
                                  another_support_ticket)
    assert not spectator.has_perm('lock8.delete_supportticket', support_ticket)
    assert not spectator.has_perm('lock8.delete_supportticket',
                                  another_support_ticket)


def test_feedback_security(fleet_operator, alice, admin_user,
                           fleet_admin, feedback, another_feedback,
                           spectator, supervisor):
    assert admin_user.has_perm('lock8.add_feedback')
    assert admin_user.has_perm('lock8.view_feedback', feedback)
    assert admin_user.has_perm('lock8.view_feedback', another_feedback)
    assert admin_user.has_perm('lock8.change_feedback', feedback)
    assert admin_user.has_perm('lock8.change_feedback', another_feedback)
    assert admin_user.has_perm('lock8.delete_feedback', feedback)
    assert admin_user.has_perm('lock8.delete_feedback', another_feedback)
    assert admin_user.has_perm('lock8.escalate_feedback', feedback)
    assert admin_user.has_perm('lock8.escalate_feedback', another_feedback)
    assert admin_user.has_perm('lock8.discard_feedback', feedback)
    assert admin_user.has_perm('lock8.discard_feedback', another_feedback)

    for user in (fleet_operator, supervisor):
        assert user.has_perm('lock8.add_feedback')
        assert user.has_perm('lock8.view_feedback', feedback)
        assert not user.has_perm('lock8.view_feedback', another_feedback)
        assert user.has_perm('lock8.change_feedback', feedback)
        assert not user.has_perm('lock8.change_feedback', another_feedback)
        assert user.has_perm('lock8.delete_feedback', feedback)
        assert not user.has_perm('lock8.delete_feedback', another_feedback)
        assert user.has_perm('lock8.escalate_feedback', feedback)
        assert not user.has_perm('lock8.escalate_feedback', another_feedback)
        assert user.has_perm('lock8.discard_feedback', feedback)
        assert not user.has_perm('lock8.discard_feedback', another_feedback)

    assert fleet_admin.has_perm('lock8.add_feedback')
    assert fleet_admin.has_perm('lock8.view_feedback', feedback)
    assert not fleet_admin.has_perm('lock8.view_feedback', another_feedback)
    assert fleet_admin.has_perm('lock8.change_feedback', feedback)
    assert not fleet_admin.has_perm('lock8.change_feedback', another_feedback)
    assert fleet_admin.has_perm('lock8.delete_feedback', feedback)
    assert not fleet_admin.has_perm('lock8.delete_feedback', another_feedback)
    assert fleet_admin.has_perm('lock8.escalate_feedback', feedback)
    assert not fleet_admin.has_perm(
        'lock8.escalate_feedback', another_feedback
    )
    assert fleet_admin.has_perm('lock8.discard_feedback', feedback)
    assert not fleet_admin.has_perm(
        'lock8.discard_feedback', another_feedback)

    assert alice.has_perm('lock8.add_feedback')
    assert alice.has_perm('lock8.view_feedback', feedback)
    assert not alice.has_perm('lock8.view_feedback', another_feedback)
    assert alice.has_perm('lock8.change_feedback', feedback)
    assert not alice.has_perm('lock8.change_feedback', another_feedback)
    assert not alice.has_perm('lock8.delete_feedback', feedback)
    assert not alice.has_perm('lock8.delete_feedback', another_feedback)
    assert not alice.has_perm('lock8.escalate_feedback', feedback)
    assert not alice.has_perm('lock8.escalate_feedback', another_feedback)
    assert not alice.has_perm('lock8.discard_feedback', feedback)
    assert not alice.has_perm('lock8.discard_feedback', another_feedback)

    assert not spectator.has_perm('lock8.add_feedback')
    assert not spectator.has_perm('lock8.view_feedback', feedback)
    assert not spectator.has_perm('lock8.view_feedback',
                                  another_feedback)
    assert not spectator.has_perm('lock8.change_feedback', feedback)
    assert not spectator.has_perm('lock8.change_feedback',
                                  another_feedback)
    assert not spectator.has_perm('lock8.delete_feedback', feedback)
    assert not spectator.has_perm('lock8.delete_feedback',
                                  another_feedback)
    assert not spectator.has_perm('lock8.escalate_feedback', feedback)
    assert not spectator.has_perm('lock8.escalate_feedback',
                                  another_feedback)
    assert not spectator.has_perm('lock8.discard_feedback', feedback)
    assert not spectator.has_perm('lock8.discard_feedback',
                                  another_feedback)


def test_alert_security(fleet_operator, alice, admin_user, fleet_admin,
                        alert, another_alert, spectator, supervisor):
    assert admin_user.has_perm('lock8.add_alert')
    assert admin_user.has_perm('lock8.change_alert', alert)
    assert admin_user.has_perm('lock8.view_alert', alert)
    assert admin_user.has_perm('lock8.delete_alert', alert)
    assert admin_user.has_perm('lock8.change_alert',
                               another_alert)
    assert admin_user.has_perm('lock8.view_alert',
                               another_alert)
    assert admin_user.has_perm('lock8.delete_alert',
                               another_alert)

    for user in (fleet_operator, supervisor):
        assert not user.has_perm('lock8.add_alert')
        assert not user.has_perm('lock8.change_alert', alert)
        assert user.has_perm('lock8.view_alert', alert)
        assert user.has_perm('lock8.view_alert_transitions', alert)
        assert not user.has_perm('lock8.delete_alert', alert)
        assert not user.has_perm('lock8.change_alert', another_alert)
        assert not user.has_perm('lock8.view_alert', another_alert)
        assert not user.has_perm('lock8.delete_alert', another_alert)

    assert not fleet_admin.has_perm('lock8.add_alert')
    assert not fleet_admin.has_perm('lock8.change_alert', alert)
    assert fleet_admin.has_perm('lock8.view_alert', alert)
    assert not fleet_admin.has_perm('lock8.delete_alert', alert)
    assert not fleet_admin.has_perm('lock8.change_alert',
                                    another_alert)
    assert not fleet_admin.has_perm('lock8.view_alert',
                                    another_alert)
    assert not fleet_admin.has_perm('lock8.delete_alert',
                                    another_alert)

    assert not alice.has_perm('lock8.add_alert')
    assert not alice.has_perm('lock8.change_alert', alert)
    assert not alice.has_perm('lock8.view_alert', alert)
    assert not alice.has_perm('lock8.view_alert_transitions', alert)

    assert not spectator.has_perm('lock8.add_alert')
    assert not spectator.has_perm('lock8.change_alert', alert)
    assert not spectator.has_perm('lock8.view_alert', alert)
    assert not spectator.has_perm('lock8.view_alert_transitions', alert)


def test_notification_message_security(fleet_operator, alice, admin_user,
                                       fleet_admin, notification_message):
    assert not admin_user.has_perm('lock8.add_notificationmessage')
    assert not admin_user.has_perm('lock8.view_notificationmessage',
                                   notification_message)
    assert not admin_user.has_perm('lock8.change_notificationmessage',
                                   notification_message)
    assert not admin_user.has_perm('lock8.delete_notificationmessage',
                                   notification_message)
    assert not admin_user.has_perm('lock8.acknowledge_notificationmessage',
                                   notification_message)
    assert not admin_user.has_perm('lock8.send_notificationmessage',
                                   notification_message)

    assert not fleet_operator.has_perm('lock8.add_notificationmessage')
    assert fleet_operator.has_perm('lock8.view_notificationmessage',
                                   notification_message)
    assert fleet_operator.has_perm('lock8.change_notificationmessage',
                                   notification_message)
    assert fleet_operator.has_perm('lock8.delete_notificationmessage',
                                   notification_message)
    assert fleet_operator.has_perm('lock8.acknowledge_notificationmessage',
                                   notification_message)
    assert fleet_operator.has_perm('lock8.send_notificationmessage',
                                   notification_message)

    assert not fleet_admin.has_perm('lock8.add_notificationmessage')
    assert not fleet_admin.has_perm('lock8.view_notificationmessage',
                                    notification_message)
    assert not fleet_admin.has_perm('lock8.change_notificationmessage',
                                    notification_message)
    assert not fleet_admin.has_perm('lock8.delete_notificationmessage',
                                    notification_message)
    assert not fleet_admin.has_perm('lock8.acknowledge_notificationmessage',
                                    notification_message)
    assert not fleet_admin.has_perm('lock8.send_notificationmessage',
                                    notification_message)

    assert not alice.has_perm('lock8.add_notificationmessage')
    assert not alice.has_perm('lock8.view_notificationmessage',
                              notification_message)
    assert not alice.has_perm('lock8.change_notificationmessage',
                              notification_message)
    assert not alice.has_perm('lock8.delete_notificationmessage',
                              notification_message)
    assert not alice.has_perm('lock8.acknowledge_notificationmessage',
                              notification_message)
    assert not alice.has_perm('lock8.send_notificationmessage',
                              notification_message)


def test_user_profile(fleet_operator, alice, bob, admin_user, supervisor,
                      fleet_admin, owner, org, another_org, spectator):
    from velodrome.lock8.models import Affiliation, UserProfile

    Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.RENTER,
    )

    alice_profile = UserProfile.objects.create(
        owner=owner,
    )
    alice.profile = alice_profile
    alice.save()

    another_user_profile = UserProfile.objects.create(
        owner=owner,
    )
    bob.profile = another_user_profile
    bob.save()

    spectator_profile = UserProfile.objects.create(
        owner=spectator,
    )
    spectator.profile = spectator_profile
    spectator.save()

    assert admin_user.has_perm('lock8.add_userprofile')
    assert admin_user.has_perm('lock8.change_userprofile', alice_profile)
    assert admin_user.has_perm('lock8.view_userprofile', alice_profile)
    assert admin_user.has_perm('lock8.delete_userprofile', alice_profile)
    assert admin_user.has_perm('lock8.change_userprofile',
                               another_user_profile)
    assert admin_user.has_perm('lock8.view_userprofile',
                               another_user_profile)
    assert admin_user.has_perm('lock8.delete_userprofile',
                               another_user_profile)

    for user in (fleet_operator, supervisor):
        assert user.has_perm('lock8.add_userprofile')
        assert user.has_perm('lock8.change_userprofile', alice_profile)
        assert user.has_perm('lock8.view_userprofile', alice_profile)
        assert user.has_perm('lock8.delete_userprofile', alice_profile)
        assert user.has_perm('lock8.view_userprofile_transitions',
                             alice_profile)
        assert not user.has_perm('lock8.change_userprofile',
                                 another_user_profile)
        assert not user.has_perm('lock8.view_userprofile',
                                 another_user_profile)
        assert not user.has_perm('lock8.delete_userprofile',
                                 another_user_profile)

    assert fleet_admin.has_perm('lock8.add_userprofile')
    assert fleet_admin.has_perm('lock8.change_userprofile', alice_profile)
    assert fleet_admin.has_perm('lock8.view_userprofile', alice_profile)
    assert fleet_admin.has_perm('lock8.delete_userprofile', alice_profile)
    assert not fleet_admin.has_perm('lock8.change_userprofile',
                                    another_user_profile)
    assert not fleet_admin.has_perm('lock8.view_userprofile',
                                    another_user_profile)
    assert not fleet_admin.has_perm('lock8.delete_userprofile',
                                    another_user_profile)

    assert alice.has_perm('lock8.add_userprofile')
    assert alice.has_perm('lock8.change_userprofile', alice_profile)
    assert alice.has_perm('lock8.view_userprofile', alice_profile)
    assert alice.has_perm('lock8.delete_userprofile', alice_profile)
    assert alice.has_perm('lock8.view_userprofile_transitions', alice_profile)

    assert not spectator.has_perm('lock8.add_userprofile')
    assert not spectator.has_perm('lock8.change_userprofile',
                                  spectator_profile)
    assert not spectator.has_perm('lock8.view_userprofile',
                                  spectator_profile)
    assert not spectator.has_perm('lock8.delete_userprofile',
                                  spectator_profile)
    assert not spectator.has_perm('lock8.view_userprofile_transitions',
                                  spectator_profile)


def test_feedback_category_security(admin_user, alice, fleet_admin,
                                    fleet_operator, root_org, mechanic1,
                                    org, owner, another_org, another_mechanic,
                                    supervisor):
    from velodrome.lock8.models import FeedbackCategory

    lock8_root = root_org.feedback_category_tree
    lock8_descendant = lock8_root.get_descendants().get(name='bicycle')
    lock8_leaf = lock8_root.get_descendants().get(name='front-wheel')

    org_root = FeedbackCategory.objects.create(parent=None, name='root')
    org_descendant = FeedbackCategory.objects.create(
        name='org-descendant',
        parent=org_root
    )
    org_leaf = FeedbackCategory.objects.create(
        name='org-leaf',
        parent=org_descendant
    )
    org.feedback_category_tree = org_root
    org.is_open_fleet = False
    org.save()

    another_root = FeedbackCategory.objects.create(parent=None, name='root')
    another_descendant = FeedbackCategory.objects.create(
        name='another-org-descendant',
        parent=another_root
    )
    another_leaf = FeedbackCategory.objects.create(
        name='another-leaf', parent=another_descendant
    )
    another_org.feedback_category_tree = another_root
    another_org.is_open_fleet = True
    another_org.save()

    all_roots = (lock8_root, org_root, another_root)
    all_leaves = (lock8_leaf, org_leaf, another_leaf)
    all_descendants = (org_descendant, another_descendant, lock8_descendant)

    assert not alice.has_perm('lock8.add_feedbackcategory')
    for node in (all_roots + all_descendants + (org_leaf,)):
        assert not alice.has_perm('lock8.view_feedbackcategory', node)

    for node in (all_roots + all_descendants + (org_leaf, lock8_leaf)):
        assert not alice.has_perm('lock8.change_feedbackcategory', node)
        assert not alice.has_perm('lock8.delete_feedbackcategory', node)

    assert alice.has_perm('lock8.view_feedbackcategory', lock8_leaf)
    assert alice.has_perm('lock8.view_feedbackcategory', another_leaf)
    assert not alice.has_perm('lock8.change_feedbackcategory', another_leaf)
    assert not alice.has_perm('lock8.delete_feedbackcategory', another_leaf)

    assert not mechanic1.has_perm('lock8.add_feedbackcategory')
    for node in (lock8_root, org_root, lock8_descendant, org_descendant,):
        assert mechanic1.has_perm('lock8.view_feedbackcategory', node)
        assert not mechanic1.has_perm('lock8.change_feedbackcategory', node)
        assert not mechanic1.has_perm('lock8.delete_feedbackcategory', node)

    assert not mechanic1.has_perm('lock8.view_feedbackcategory', another_root)
    assert not mechanic1.has_perm('lock8.view_feedbackcategory',
                                  another_descendant)
    for node in all_leaves:
        assert mechanic1.has_perm('lock8.view_feedbackcategory', node)
        assert not mechanic1.has_perm('lock8.change_feedbackcategory', node)
        assert not mechanic1.has_perm('lock8.delete_feedbackcategory', node)

    assert not another_mechanic.has_perm('lock8.view_feedbackcategory',
                                         org_leaf)

    assert admin_user.has_perm('lock8.add_feedbackcategory')
    for node in (all_roots + all_descendants + all_leaves):
        assert admin_user.has_perm('lock8.view_feedbackcategory', node)
        assert admin_user.has_perm('lock8.change_feedbackcategory', node)
        assert admin_user.has_perm('lock8.delete_feedbackcategory', node)

    for user in (fleet_operator, supervisor, fleet_admin):
        assert user.has_perm('lock8.add_feedbackcategory')
        for node in (org_root, org_descendant, org_leaf):
            assert user.has_perm('lock8.view_feedbackcategory', node)
            assert user.has_perm('lock8.change_feedbackcategory', node)
            assert user.has_perm('lock8.delete_feedbackcategory', node)

        for node in (another_root, another_descendant):
            assert not user.has_perm('lock8.view_feedbackcategory', node)
            assert not user.has_perm('lock8.change_feedbackcategory', node)
            assert not user.has_perm('lock8.delete_feedbackcategory', node)

        for node in (lock8_root, lock8_descendant, lock8_leaf,
                     another_leaf):
            assert user.has_perm('lock8.view_feedbackcategory', node)
            assert not user.has_perm('lock8.change_feedbackcategory', node)
            assert not user.has_perm('lock8.delete_feedbackcategory', node)


def test_task_security(admin_user, alice, another_mechanic,
                       another_task, mechanic1, task1, fleet_admin,
                       fleet_operator, spectator, supervisor):
    assert not alice.has_perm('lock8.add_task')
    assert not alice.has_perm('lock8.view_task', task1)
    assert not alice.has_perm('lock8.view_task')
    assert not alice.has_perm('lock8.change_task', task1)
    assert not alice.has_perm('lock8.delete_task', task1)
    assert not alice.has_perm('lock8.assign_task', task1)
    assert not alice.has_perm('lock8.unassign_task', task1)
    assert not alice.has_perm('lock8.complete_task', task1)

    assert not spectator.has_perm('lock8.add_task')
    assert not spectator.has_perm('lock8.view_task', task1)
    assert not spectator.has_perm('lock8.view_task')
    assert not spectator.has_perm('lock8.change_task', task1)
    assert not spectator.has_perm('lock8.delete_task', task1)
    assert not spectator.has_perm('lock8.assign_task', task1)
    assert not spectator.has_perm('lock8.unassign_task', task1)
    assert not spectator.has_perm('lock8.complete_task', task1)

    assert mechanic1.has_perm('lock8.add_task')
    assert mechanic1.has_perm('lock8.view_task', task1)
    assert mechanic1.has_perm('lock8.view_task')
    assert mechanic1.has_perm('lock8.change_task', task1)
    assert mechanic1.has_perm('lock8.delete_task', task1)
    assert mechanic1.has_perm('lock8.assign_task', task1)
    assert mechanic1.has_perm('lock8.unassign_task', task1)
    assert mechanic1.has_perm('lock8.complete_task', task1)

    assert not another_mechanic.has_perm('lock8.view_task', task1)
    assert another_mechanic.has_perm('lock8.view_task')
    assert another_mechanic.has_perm('lock8.view_task', another_task)

    for user in (admin_user, fleet_admin, supervisor, fleet_operator):
        assert user.has_perm('lock8.add_task')
        assert user.has_perm('lock8.view_task', task1)
        assert user.has_perm('lock8.change_task', task1)
        assert user.has_perm('lock8.delete_task', task1)
        assert user.has_perm('lock8.assign_task', task1)
        assert user.has_perm('lock8.unassign_task', task1)
        assert user.has_perm('lock8.complete_task', task1)

    assert admin_user.has_perm('lock8.view_task', another_task)
    assert not fleet_operator.has_perm('lock8.view_task', another_task)
    assert not fleet_admin.has_perm('lock8.view_task', another_task)


def test_bmmr_security(admin_user, alice, mechanic1, fleet_admin,
                       fleet_operator, bmmr_recurring, bmmr_fixed,
                       another_bicycle_model, spectator, supervisor):
    bmmr_fixed.bicycle_model = another_bicycle_model
    bmmr_fixed.save()
    bmmr_fixed.refresh_from_db()

    bmmr = bmmr_recurring
    another_bmmr = bmmr_fixed

    for user in (admin_user, fleet_operator, supervisor, fleet_admin):
        assert user.has_perm('lock8.add_bicyclemodelmaintenancerule')
        assert user.has_perm('lock8.view_bicyclemodelmaintenancerule', bmmr)
        assert user.has_perm('lock8.change_bicyclemodelmaintenancerule', bmmr)
        assert user.has_perm('lock8.delete_bicyclemodelmaintenancerule', bmmr)
    assert admin_user.has_perm(
        'lock8.view_bicyclemodelmaintenancerule', another_bmmr
    )
    assert not fleet_operator.has_perm(
        'lock8.view_bicyclemodelmaintenancerule', another_bmmr
    )
    assert not fleet_admin.has_perm(
        'lock8.view_bicyclemodelmaintenancerule', another_bmmr
    )

    for user in (alice, mechanic1, spectator):
        assert not user.has_perm('lock8.add_bicyclemodelmaintenancerule')
        assert not user.has_perm(
            'lock8.view_bicyclemodelmaintenancerule', bmmr
        )
        assert not user.has_perm(
            'lock8.change_bicyclemodelmaintenancerule', bmmr
        )
        assert not user.has_perm(
            'lock8.delete_bicyclemodelmaintenancerule', bmmr
        )


def test_feature_security(admin_user, fleet_operator, alice, feature,
                          spectator, supervisor):
    assert admin_user.has_perm('lock8.add_feature')
    assert admin_user.has_perm('lock8.view_feature', feature)
    assert admin_user.has_perm('lock8.change_feature', feature)
    assert admin_user.has_perm('lock8.delete_feature', feature)

    for user in (fleet_operator, supervisor):
        assert not user.has_perm('lock8.add_feature')
        assert not user.has_perm('lock8.view_feature', feature)
        assert not user.has_perm('lock8.change_feature', feature)
        assert not user.has_perm('lock8.delete_feature', feature)

    assert not alice.has_perm('lock8.add_feature')
    assert not alice.has_perm('lock8.view_feature', feature)
    assert not alice.has_perm('lock8.change_feature', feature)
    assert not alice.has_perm('lock8.delete_feature', feature)

    assert not spectator.has_perm('lock8.add_feature')
    assert not spectator.has_perm('lock8.view_feature', feature)
    assert not spectator.has_perm('lock8.change_feature', feature)
    assert not spectator.has_perm('lock8.delete_feature', feature)


def test_metrics_security(admin_user, fleet_operator, alice,
                          analytics_feature, spectator, org, supervisor):

    assert admin_user.has_perm('lock8.view_metrics')
    assert fleet_operator.has_perm('lock8.view_metrics')
    assert supervisor.has_perm('lock8.view_metrics')
    assert spectator.has_perm('lock8.view_metrics')
    assert not alice.has_perm('lock8.view_metrics')

    analytics_feature.activate()

    assert admin_user.has_perm('lock8.view_metrics')
    assert fleet_operator.has_perm('lock8.view_metrics')
    assert supervisor.has_perm('lock8.view_metrics')
    assert spectator.has_perm('lock8.view_metrics')
    assert not alice.has_perm('lock8.view_metrics')

    analytics_feature.organizations.remove(org)

    assert admin_user.has_perm('lock8.view_metrics')
    assert not fleet_operator.has_perm('lock8.view_metrics')
    assert not supervisor.has_perm('lock8.view_metrics')
    assert not spectator.has_perm('lock8.view_metrics')
    assert not alice.has_perm('lock8.view_metrics')

    analytics_feature.deactivate()

    assert admin_user.has_perm('lock8.view_metrics')
    assert fleet_operator.has_perm('lock8.view_metrics')
    assert supervisor.has_perm('lock8.view_metrics')
    assert spectator.has_perm('lock8.view_metrics')
    assert not alice.has_perm('lock8.view_metrics')


def test_shared_secret_security(shared_secret, admin_user, fleet_operator,
                                mechanic1, alice, bob, org, bicycle,
                                supervisor):
    from velodrome.lock8.models import Affiliation

    Affiliation.objects.create(
        user=alice,
        organization=org,
    )

    assert admin_user.has_perm('lock8.add_sharedsecret')
    assert not fleet_operator.has_perm('lock8.add_sharedsecret')
    assert not supervisor.has_perm('lock8.add_sharedsecret')
    assert not mechanic1.has_perm('lock8.add_sharedsecret')
    assert not alice.has_perm('lock8.add_sharedsecret')

    assert admin_user.has_perm('lock8.view_sharedsecret', shared_secret)
    assert fleet_operator.has_perm('lock8.view_sharedsecret', shared_secret)
    assert supervisor.has_perm('lock8.view_sharedsecret', shared_secret)
    assert mechanic1.has_perm('lock8.view_sharedsecret', shared_secret)
    assert not alice.has_perm('lock8.view_sharedsecret', shared_secret)

    assert not admin_user.has_perm('lock8.change_sharedsecret', shared_secret)
    assert not fleet_operator.has_perm('lock8.change_sharedsecret',
                                       shared_secret)
    assert not supervisor.has_perm('lock8.change_sharedsecret', shared_secret)
    assert not mechanic1.has_perm('lock8.change_sharedsecret', shared_secret)
    assert not alice.has_perm('lock8.change_sharedsecret', shared_secret)

    assert not admin_user.has_perm('lock8.delete_sharedsecret', shared_secret)
    assert not fleet_operator.has_perm('lock8.delete_sharedsecret',
                                       shared_secret)
    assert not supervisor.has_perm('lock8.delete_sharedsecret', shared_secret)
    assert not mechanic1.has_perm('lock8.delete_sharedsecret', shared_secret)
    assert not alice.has_perm('lock8.delete_sharedsecret', shared_secret)

    bicycle.declare_available()
    bicycle.reserve(by=alice)

    assert admin_user.has_perm('lock8.view_sharedsecret', shared_secret)
    assert fleet_operator.has_perm('lock8.view_sharedsecret', shared_secret)
    assert supervisor.has_perm('lock8.view_sharedsecret', shared_secret)
    assert mechanic1.has_perm('lock8.view_sharedsecret', shared_secret)
    assert not alice.has_perm('lock8.view_sharedsecret', shared_secret)
    assert not bob.has_perm('lock8.view_sharedsecret', shared_secret)

    bicycle.rent(by=alice)

    assert admin_user.has_perm('lock8.view_sharedsecret', shared_secret)
    assert fleet_operator.has_perm('lock8.view_sharedsecret', shared_secret)
    assert supervisor.has_perm('lock8.view_sharedsecret', shared_secret)
    assert mechanic1.has_perm('lock8.view_sharedsecret', shared_secret)
    assert alice.has_perm('lock8.view_sharedsecret', shared_secret)
    assert not bob.has_perm('lock8.view_sharedsecret', shared_secret)

    bicycle.return_()

    assert admin_user.has_perm('lock8.view_sharedsecret', shared_secret)
    assert fleet_operator.has_perm('lock8.view_sharedsecret', shared_secret)
    assert supervisor.has_perm('lock8.view_sharedsecret', shared_secret)
    assert mechanic1.has_perm('lock8.view_sharedsecret', shared_secret)
    assert not alice.has_perm('lock8.view_sharedsecret', shared_secret)
    assert not bob.has_perm('lock8.view_sharedsecret', shared_secret)


def test_axa_lock_security(axalock, bicycle, alice, admin_user,
                           fleet_operator, bob, org, supervisor):
    from velodrome.lock8.models import Affiliation

    assert admin_user.has_perm('lock8.add_axalock')
    assert not fleet_operator.has_perm('lock8.add_axalock')
    assert not supervisor.has_perm('lock8.add_axalock')
    assert not alice.has_perm('lock8.add_axalock')

    assert admin_user.has_perm('lock8.view_axalock', axalock)
    assert fleet_operator.has_perm('lock8.view_axalock', axalock)
    assert supervisor.has_perm('lock8.view_axalock', axalock)
    assert not alice.has_perm('lock8.view_axalock', axalock)

    assert admin_user.has_perm('lock8.change_axalock', axalock)
    assert not fleet_operator.has_perm('lock8.change_axalock', axalock)
    assert not supervisor.has_perm('lock8.change_axalock', axalock)
    assert not alice.has_perm('lock8.change_axalock', axalock)

    assert admin_user.has_perm('lock8.delete_axalock', axalock)
    assert not fleet_operator.has_perm('lock8.delete_axalock', axalock)
    assert not supervisor.has_perm('lock8.delete_axalock', axalock)
    assert not alice.has_perm('lock8.delete_axalock', axalock)

    assert admin_user.has_perm('lock8.claim_axalock', axalock)
    assert not fleet_operator.has_perm('lock8.claim_axalock', axalock)
    assert not supervisor.has_perm('lock8.claim_axalock', axalock)
    assert not alice.has_perm('lock8.claim_axalock', axalock)

    assert admin_user.has_perm('lock8.declare_transferable_axalock', axalock)
    assert not fleet_operator.has_perm('lock8.declare_transferable_axalock',
                                       axalock)
    assert not supervisor.has_perm('lock8.declare_transferable_axalock',
                                   axalock)
    assert not alice.has_perm('lock8.declare_transferable_axalock', axalock)

    assert admin_user.has_perm('lock8.declare_stored_axalock', axalock)
    assert not fleet_operator.has_perm('lock8.declare_stored_axalock', axalock)
    assert not supervisor.has_perm('lock8.declare_stored_axalock', axalock)
    assert not alice.has_perm('lock8.declare_stored_axalock', axalock)

    Affiliation.objects.create(organization=org, user=alice)
    bicycle.axa_lock = axalock
    bicycle.declare_available()
    bicycle.rent(by=alice)

    assert not alice.has_perm('lock8.view_axalock', axalock)
    assert not bob.has_perm('lock8.view_axalock', axalock)


def test_axalock_can_be_claimed_by_owner(axalock, alice, org):
    from velodrome.lock8.models import Affiliation, AxaLock

    orig_owner = axalock.owner
    assert orig_owner.pk != alice.pk

    assert not alice.has_perm('lock8.add_axalock')
    assert not alice.has_perm('lock8.claim_axalock')

    def add_user_perm(user, codename, model):
        from django.contrib.auth.models import Permission
        from django.contrib.contenttypes.models import ContentType
        from django.contrib.auth import get_user_model

        content_type = ContentType.objects.get_for_model(model)
        permission = Permission.objects.get(
            codename=codename,
            content_type=content_type,
        )
        alice.user_permissions.add(permission)

        # Return new object to work around cached permissions.
        return get_user_model().objects.get(pk=alice.pk)

    alice = add_user_perm(alice, 'add_axalock', AxaLock)
    assert alice.has_perm('lock8.add_axalock')
    assert not alice.has_perm('lock8.claim_axalock')
    assert not alice.has_perm('lock8.claim_axalock', axalock)

    axalock.owner = alice
    assert not alice.has_perm('lock8.claim_axalock')
    assert not alice.has_perm('lock8.claim_axalock', axalock)

    Affiliation.objects.create(organization=org, user=alice,
                               role=Affiliation.FLEET_OPERATOR)
    assert alice.has_perm('lock8.claim_axalock')
    assert alice.has_perm('lock8.claim_axalock', axalock)
    assert alice.has_perm('lock8.declare_transferable_axalock', axalock)

    axalock.owner = orig_owner
    assert alice.has_perm('lock8.claim_axalock')
    assert not alice.has_perm('lock8.claim_axalock', axalock)


def test_client_app_security(client_app, alice, fleet_operator, supervisor):
    for user in (fleet_operator, supervisor):
        assert user.has_perm('lock8.add_clientapp')
        assert user.has_perm('lock8.view_clientapp')
        assert user.has_perm('lock8.view_clientapp', client_app)
        assert user.has_perm('lock8.change_clientapp', client_app)
        assert user.has_perm('lock8.delete_clientapp', client_app)

    assert not alice.has_perm('lock8.add_clientapp')
    assert not alice.has_perm('lock8.view_clientapp')
    assert not alice.has_perm('lock8.view_clientapp', client_app)
    assert not alice.has_perm('lock8.change_clientapp', client_app)
    assert not alice.has_perm('lock8.delete_clientapp', client_app)
