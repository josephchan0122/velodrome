import datetime as dt

from concurrency.exceptions import RecordModifiedError
from django.db import connection
from django.test.utils import CaptureQueriesContext
import pytest
from rest_framework import status
from rest_framework.test import APIClient
from rest_framework_jwt.utils import jwt_encode_handler

from velodrome.lock8.jwt_extensions import jwt_payload_handler
from velodrome.lock8.utils import reverse_query

# Run theses as smoke tests in the Docker image.
pytestmark = pytest.mark.test_in_docker


def test_selectable_fields(drf_fleet_operator, bicycle):
    url = reverse_query('lock8:bicycle-list', {'fields': 'name,state'})
    response = drf_fleet_operator.assert_count(url, 1)
    assert response.data['results'][0] == {'name': 'bicycle',
                                           'state': 'in_maintenance'}


def test_selectable_fields_unknown(drf_client):
    url = reverse_query('lock8:bicycle-list', {
        'fields': 'nonexisting,name,another-unknown'})
    response = drf_client.assert_400(url)
    assert len(response.data['detail']) == 1, response.data
    detail = response.data['detail'][0]
    assert detail['code'] == 'unknown_fields'
    assert detail['message'].startswith('Unknown fields: ')
    assert 'nonexisting' in detail['message']
    assert 'another-unknown' in detail['message']


def test_blank_metadata(drf_fleet_operator):
    url = reverse_query('lock8:bicycle-list')
    response = drf_fleet_operator.options(url)
    assert response.status_code == status.HTTP_200_OK
    assert response.data == {}


def test_post_owner_ignored(drf_fleet_operator, alice, org, bicycle_model,
                            fleet_operator):
    from velodrome.lock8.models import Bicycle

    url = reverse_query('lock8:bicycle-list')
    bicycle_model_url = reverse_query('lock8:bicycle_model-detail',
                                      kwargs={'uuid': bicycle_model.uuid})
    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})
    alice_url = reverse_query('lock8:user-detail',
                              kwargs={'uuid': alice.uuid})
    response = drf_fleet_operator.post(url, data={
        'owner': alice_url,
        'organization': organization_url,
        'model': bicycle_model_url,
        'name': 'ride me',
    })
    assert response.status_code == status.HTTP_201_CREATED
    bicycle = Bicycle.objects.get()
    assert bicycle.owner == fleet_operator


def test_api_versioning_ok(db):
    url = reverse_query('lock8:api-root')
    drf_client = APIClient(HTTP_ACCEPT='*/*; version=1.0')
    response = drf_client.get(url)
    assert response.status_code == status.HTTP_200_OK
    assert response.accepted_media_type == 'application/json;version=1.0'


@pytest.mark.parametrize('view', ['lock8:bicycle-list', 'lock8:dashboard',
                                  'lock8:jwt-verify'])
def test_api_versioning_missing(view, fleet_operator):
    from django.conf import settings

    drf_client = APIClient()  # versioning is missing
    drf_client.credentials(
        HTTP_AUTHORIZATION='JWT ' + jwt_encode_handler(
            jwt_payload_handler(fleet_operator)))
    url = reverse_query(view)
    response = drf_client.get(url)
    assert response.status_code == status.HTTP_406_NOT_ACCEPTABLE
    assert response.data['detail'] == {
        'non_field_errors': [{
            'message': 'Invalid API version. Please provide it in the "Accept"'
            ' header, e.g. "Accept: application/json; version={}".'.format(
                settings.REST_FRAMEWORK['ALLOWED_VERSIONS'][-1]
            ), 'code': 'not_acceptable'}]}


@pytest.mark.parametrize('view', ['dal:bicycle'])
def test_api_versioning_skip_autocomplete(view, django_admin_client):
    url = reverse_query(view)
    response = django_admin_client.get(url)
    assert response.status_code == status.HTTP_200_OK


def test_drf_docs_without_version_header(db, client_with_html_accept):
    url = reverse_query('lock8:bicycle-list')
    response = client_with_html_accept.get(url)
    assert response.status_code == status.HTTP_200_OK, response.data


def test_transitions_view(drf_fleet_operator, bicycle, alice, fleet_operator):
    bicycle.declare_available(by=fleet_operator)
    bicycle.reserve(by=alice)
    bicycle.rent(by=alice)
    bicycle.return_(by=alice)

    fleet_operator_url = reverse_query('lock8:user-detail',
                                       kwargs={'uuid': fleet_operator.uuid})
    alice_url = reverse_query('lock8:user-detail',
                              kwargs={'uuid': alice.uuid})

    t1, t2, t3, t4 = bicycle.transitions.all().order_by('-timestamp')
    url = reverse_query('lock8:bicycle-transitions',
                        kwargs={'uuid': bicycle.uuid})
    drf_fleet_operator.assert_success(url, {
        'count': 4,
        'next': None,
        'previous': None,
        'results': [
            {'timestamp': t1.timestamp.isoformat()[:-13] + 'Z',
             'by': 'http://testserver' + alice_url,
             'state': 'available',
             'transition': 'return_'},
            {'timestamp': t2.timestamp.isoformat()[:-13] + 'Z',
             'by': 'http://testserver' + alice_url,
             'state': 'rented',
             'transition': 'rent'},
            {'timestamp': t3.timestamp.isoformat()[:-13] + 'Z',
             'by': 'http://testserver' + alice_url,
             'state': 'reserved',
             'transition': 'reserve'},
            {'timestamp': t4.timestamp.isoformat()[:-13] + 'Z',
             'by': 'http://testserver' + fleet_operator_url,
             'state': 'available',
             'transition': 'declare_available'},
        ]})


@pytest.mark.parametrize('view_name,expected_count', (
    ('organization', 1),
    ('address', 0),
    ('bicycle', 0),
    ('lock', 0),
    ('photo', 0),
    ('user', 1)))
def test_security_on_any(drf_client, fleet_operator, another_fleet_operator,
                         view_name, expected_count,
                         bicycle, lock, photo, address):
    drf_client.credentials(
        HTTP_AUTHORIZATION='JWT ' + jwt_encode_handler(
            jwt_payload_handler(fleet_operator)))

    url = reverse_query('lock8:{}-list'.format(view_name))
    drf_client.assert_count(url, 1)

    # now authenticate with another_fleet_operator
    drf_client.credentials(
        HTTP_AUTHORIZATION='JWT ' + jwt_encode_handler(
            jwt_payload_handler(another_fleet_operator)))
    drf_client.assert_count(url, expected_count)


def test_crud_affiliation(drf_fleet_operator, fleet_operator, org, alice,
                          image):
    from velodrome.lock8.models import Affiliation

    org.image = image
    org.save()
    url = reverse_query('lock8:affiliation-list')
    response = drf_fleet_operator.assert_count(url, 1)
    result = response.data['results'][0]

    affiliation = Affiliation.objects.get()
    assert result == {
        'uuid': str(affiliation.uuid),
        'url': 'http://testserver' + reverse_query(
            'lock8:affiliation-detail',
            kwargs={'uuid': affiliation.uuid}),
        'organization': 'http://testserver' + reverse_query(
            'lock8:organization-detail',
            kwargs={'uuid': org.uuid}),
        'organization_name': org.name,
        'organization_icon': 'http://127.0.0.1:8000/{}'.format(org.image.name),
        'user': 'http://testserver' + reverse_query(
            'lock8:user-detail',
            kwargs={'uuid': fleet_operator.uuid}),
        'role': 'fleet_operator',
        'state': 'new',
        'concurrency_version': affiliation.concurrency_version,
        'modified': affiliation.modified.isoformat()[:-13] + 'Z',
        'created': affiliation.created.isoformat()[:-13] + 'Z',
    }

    url = reverse_query('lock8:affiliation-list')
    data = {
        'organization': 'http://testserver' + reverse_query(
            'lock8:organization-detail',
            kwargs={'uuid': org.uuid}),
        'user': 'http://testserver' + reverse_query(
            'lock8:user-detail',
            kwargs={'uuid': alice.uuid}),
        'role': Affiliation.RENTER,
    }
    response = drf_fleet_operator.post(url, data=data, format='json')
    assert response.status_code == status.HTTP_201_CREATED

    affiliation = Affiliation.objects.filter(user=alice).get()

    alice.refresh_from_db()
    assert org in alice.get_organizations()

    url = reverse_query('lock8:affiliation-detail',
                        kwargs={'uuid': affiliation.uuid})

    response = drf_fleet_operator.patch(url, data={'role': Affiliation.ADMIN})
    assert response.status_code == status.HTTP_200_OK
    affiliation.refresh_from_db()
    assert affiliation.role == 'admin'

    url = reverse_query('lock8:affiliation-list')
    drf_fleet_operator.assert_count(url, 2)

    url = reverse_query('lock8:affiliation-detail',
                        kwargs={'uuid': affiliation.uuid})
    response = drf_fleet_operator.delete(url)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    url = reverse_query('lock8:affiliation-list')
    drf_fleet_operator.assert_count(url, 1)

    affiliation = Affiliation.objects.create(
        user=alice,
        organization=org,
        role=Affiliation.ADMIN,
    )

    url = reverse_query('lock8:affiliation-list')
    drf_fleet_operator.assert_count(url, 2)

    url = reverse_query('lock8:affiliation-list',
                        {'user': alice.uuid})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:affiliation-list',
                        (('role', 'admin'), ('role', 'fleet_operator')))
    drf_fleet_operator.assert_count(url, 2)


def test_list_affiliation(drf_alice, org, alice, owner):
    from velodrome.lock8.models import Affiliation
    Affiliation.objects.create(
        organization=org,
        user=owner,
    )
    Affiliation.objects.create(
        organization=org,
        user=alice,
    )

    url = reverse_query('lock8:affiliation-list')
    drf_alice.assert_count(url, 1)


def test_affiliation_deletion_with_multiple_affiliations(drf_fleet_operator,
                                                         org, alice, drf_alice,
                                                         fleet_operator):
    from velodrome.lock8.models import Affiliation
    affiliation_renter = Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.RENTER,
    )
    affiliation_admin = Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.ADMIN,
    )
    affiliation_fleet_operator = Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.FLEET_OPERATOR,
    )
    url = reverse_query('lock8:affiliation-detail',
                        kwargs={'uuid': affiliation_renter.uuid})
    response = drf_fleet_operator.delete(url)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    with pytest.raises(Affiliation.DoesNotExist):
        affiliation_renter.refresh_from_db()

    affiliation_admin.refresh_from_db()
    assert affiliation_admin.state == 'new'

    affiliation_fleet_operator.refresh_from_db()
    assert affiliation_fleet_operator.state == 'new'

    url = reverse_query('lock8:user-list', {'organization': org.uuid})
    response = drf_fleet_operator.assert_count(url, 2)
    uuids = [result['uuid'] for result in response.data['results']]
    assert str(alice.uuid) in uuids
    assert str(fleet_operator.uuid) in uuids

    # Delete the remaining affiliations.
    affiliation_admin.delete()
    affiliation_fleet_operator.delete()
    assert not Affiliation.objects.filter(user=alice).count()

    url = reverse_query('lock8:user-list', {'organization': org.uuid})
    drf_alice.assert_count(url, 0)


def test_fleet_operator_cannot_see_users_from_parent_org(root_org, org, alice,
                                                         fleet_operator,
                                                         drf_fleet_operator):
    from velodrome.lock8.models import Affiliation

    Affiliation.objects.create(
        organization=org,
        user=alice,
        role=Affiliation.RENTER,
    )
    Affiliation.objects.create(
        organization=root_org,
        user=alice,
        role=Affiliation.RENTER,
    )

    url = reverse_query('lock8:user-list', {'organization': root_org.uuid})
    drf_fleet_operator.assert_count(url, 0)


def test_crud_address(owner, drf_fleet_operator, fleet_operator, org,
                      another_org):
    from velodrome.lock8.models import Address

    url = reverse_query('lock8:address-list')

    org_url = reverse_query('lock8:organization-detail',
                            kwargs={'uuid': org.uuid})
    # create
    response = drf_fleet_operator.post(url, data={
        'organization': org_url,
        'email': 'org@example.com',
        'phone_number': '0123',
        'text_address': '10 downstreet',
    }, format='json')
    assert response.status_code == status.HTTP_201_CREATED, response.data

    address = Address.objects.get()
    assert address.owner == fleet_operator

    url = reverse_query('lock8:address-list',
                        {'organization': str(another_org.uuid)})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:address-detail', kwargs={'uuid': address.uuid})
    drf_fleet_operator.assert_success(url, {
        'uuid': str(address.uuid),
        'organization': 'http://testserver' + org_url,
        'url': 'http://testserver' + url,
        'email': 'org@example.com',
        'phone_number': '0123',
        'text_address': '10 downstreet',
        'modified': address.modified.isoformat()[:-13] + 'Z',
        'created': address.created.isoformat()[:-13] + 'Z',
        'concurrency_version': address.concurrency_version,
    })

    # create a second time should fail
    url = reverse_query('lock8:address-list')
    response = drf_fleet_operator.post(url, data={
        'organization': org_url,
        'email': 'org@example.com',
        'phone_number': '0123',
        'text_address': '10 downstreet',
    }, format='json')
    assert response.status_code == status.HTTP_409_CONFLICT

    url = reverse_query('lock8:address-detail', kwargs={'uuid': address.uuid})
    response = drf_fleet_operator.patch(url, data={'phone_number': '1234'})
    assert response.status_code == status.HTTP_200_OK

    response = drf_fleet_operator.delete(url)
    assert response.status_code == status.HTTP_204_NO_CONTENT
    assert Address.objects.count() == 0


def test_crud_on_renting_schemes(drf_fleet_operator, owner, org, bicycle):
    from velodrome.lock8.models import RentingScheme

    url = reverse_query('lock8:renting_scheme-list')
    bicycle_url = reverse_query('lock8:bicycle-detail',
                                kwargs={'uuid': bicycle.uuid})
    organization_url = reverse_query('lock8:organization-detail',
                                     kwargs={'uuid': org.uuid})
    response = drf_fleet_operator.post(url, data={
        'max_reservation_duration': '10:00',
        'bicycle': bicycle_url,
        'organization': organization_url,
    })
    assert response.status_code == status.HTTP_201_CREATED
    renting_scheme = RentingScheme.objects.all().get()
    rs_uuid = response.data['uuid']
    assert response.data == {
        'uuid': rs_uuid,
        'max_reservation_duration': '00:10:00',
        'bicycle': 'http://testserver' + bicycle_url,
        'organization': 'http://testserver' + organization_url,
        'url': 'http://testserver' + reverse_query(
            'lock8:renting_scheme-detail', kwargs={'uuid': rs_uuid}),
        'state': 'new',
        'concurrency_version': renting_scheme.concurrency_version,
        'modified': renting_scheme.modified.isoformat()[:-13] + 'Z',
        'created': renting_scheme.created.isoformat()[:-13] + 'Z',
    }

    url = reverse_query('lock8:renting_scheme-list')
    drf_fleet_operator.assert_count(url, 1)

    # modify the renting scheme
    url = reverse_query('lock8:renting_scheme-detail',
                        kwargs={'uuid': renting_scheme.uuid})
    response = drf_fleet_operator.patch(url,
                                        data={'max_reservation_duration': '2'})
    assert response.status_code == status.HTTP_200_OK
    assert response.data['max_reservation_duration'] == '00:00:02'

    # delete the renting scheme
    response = drf_fleet_operator.delete(url)
    assert response.status_code == status.HTTP_204_NO_CONTENT

    with pytest.raises(RentingScheme.DoesNotExist):
        renting_scheme.refresh_from_db()

    # check renting scheme not in list
    url = reverse_query('lock8:renting_scheme-list')
    drf_fleet_operator.assert_count(url, 0)


def test_dashboard_view(drf_fleet_operator, org, fleet_operator,
                        gps_tracking_seven_days,
                        lock, bicycle, another_org):
    from velodrome.lock8.models import Affiliation, Alert, Bicycle, Lock

    for i in range(2):
        lock_ = Lock.objects.create(
            organization=org,
            owner=fleet_operator,
            counter=i,
            serial_number='010101{}'.format(i),
            imei='35978502801587{:d}'.format(i),
            iccid='8946204604400010866{:d}'.format(i),
            bleid='{}'.format(i),
            randblock='asd',
        )
        lock_.provision()
        bicycle_ = Bicycle.objects.create(
            name='{:d}'.format(i),
            organization=org,
            owner=fleet_operator,
            lock=lock_,
        )
        bicycle_.declare_available()
    url = reverse_query('lock8:dashboard')
    drf_fleet_operator.assert_success(url, {
        'count_bicycles_by_state': [{'state': 'available', 'total': 2},
                                    {'state': 'in_maintenance', 'total': 1}],
        'count_alerts_by_type': [],
    })

    alert = Alert.objects.create(
        organization=org,
        alert_type=Alert.RIDE_OUTSIDE_SERVICE_AREA,
        roles=[Affiliation.FLEET_OPERATOR],
        causality=bicycle,
    )

    url = reverse_query('lock8:dashboard')
    drf_fleet_operator.assert_success(url, {
        'count_bicycles_by_state': [{'state': 'available', 'total': 2},
                                    {'state': 'in_maintenance', 'total': 1}],
        'count_alerts_by_type': [
            {'alert_type': 'bicycle.ride_outside', 'total': 1}],
    })

    alert.resolve()
    response = drf_fleet_operator.assert_success(url)
    assert response.data['count_alerts_by_type'] == []


def test_dashboard_disallow_no_orgs(drf_fleet_operator, another_org):
    url = reverse_query('lock8:dashboard', {'organization': another_org.uuid})
    drf_fleet_operator.assert_status(url, status.HTTP_403_FORBIDDEN)


def test_dashboard_anonymous(drf_client):
    url = reverse_query('lock8:dashboard')
    drf_client.assert_status(url, status.HTTP_401_UNAUTHORIZED)


def test_crud_rental_session(drf_fleet_operator, drf_alice, bicycle, alice,
                             bob, bicycle2, non_matching_uuid):
    bicycle.declare_available()
    bicycle.rent(by=alice)
    url = reverse_query('lock8:rental_session-list')
    drf_fleet_operator.assert_count(url, 1)

    rental_session = bicycle.active_rental_session
    rental_session.duration = dt.timedelta(minutes=15)
    rental_session.save()

    alice_url = reverse_query('lock8:user-detail',
                              kwargs={'uuid': str(alice.uuid)})
    bicycle_url = reverse_query('lock8:bicycle-detail',
                                kwargs={'uuid': bicycle.uuid})

    url = reverse_query('lock8:rental_session-detail',
                        kwargs={'uuid': rental_session.uuid})
    drf_fleet_operator.assert_success(url, {
        'url': 'http://testserver' + url,
        'uuid': str(rental_session.uuid),
        'user': 'http://testserver' + alice_url,
        'bicycle': 'http://testserver' + bicycle_url,
        'duration_of_rental_session': 900,
        'cents': None,
        'currency': None,
        'subscription_plan': None,
        'pricing_scheme': None,
        'created': rental_session.created.isoformat()[:-13] + 'Z',
        'state': 'new',
        'concurrency_version': rental_session.concurrency_version,
        'modified': rental_session.modified.isoformat()[:-13] + 'Z',
    })

    response = drf_fleet_operator.patch(url)
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    response = drf_fleet_operator.delete(url)
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    url = reverse_query('lock8:rental_session-list')
    response = drf_alice.assert_count(url, 1)

    url = reverse_query('lock8:rental_session-detail',
                        kwargs={'uuid': rental_session.uuid})
    response = drf_alice.assert_success(url)
    assert response.data['state'] == 'new'

    # Filtering on bicycles.
    url = reverse_query('lock8:rental_session-list', {'bicycle': bicycle.uuid})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:rental_session-list', (
        ('bicycle', bicycle.uuid),
        ('bicycle', non_matching_uuid)))
    drf_fleet_operator.assert_count(url, 1)

    bicycle2.declare_available()
    bicycle2.rent(by=bob)
    url = reverse_query('lock8:rental_session-list', (
        ('bicycle', bicycle.uuid),
        ('bicycle', bicycle2.uuid)))
    drf_fleet_operator.assert_count(url, 2)


def test_rentalsession_only_user(drf_renter, bob, org, bicycle_rented):
    from velodrome.lock8.models import Affiliation

    Affiliation.objects.create(organization=org,
                               user=bob,
                               role=Affiliation.RENTER)
    bicycle_rented.return_(by=drf_renter.user)
    bicycle_rented.rent(by=bob)
    bicycle_rented.return_(by=bob)
    url = reverse_query('lock8:rental_session-list')
    drf_renter.assert_count(url, 1)


def test_crud_reservation(drf_fleet_operator, drf_alice, bicycle, bicycle2,
                          alice, bob, renting_scheme, non_matching_uuid):
    bicycle.declare_available()
    bicycle.reserve(by=alice)
    url = reverse_query('lock8:reservation-list')
    drf_fleet_operator.assert_count(url, 1)

    reservation = bicycle.active_reservation
    alice_url = reverse_query('lock8:user-detail',
                              kwargs={'uuid': str(alice.uuid)})
    bicycle_url = reverse_query('lock8:bicycle-detail',
                                kwargs={'uuid': bicycle.uuid})

    url = reverse_query('lock8:reservation-detail',
                        kwargs={'uuid': reservation.uuid})
    drf_fleet_operator.assert_success(url, {
        'url': 'http://testserver' + url,
        'uuid': str(reservation.uuid),
        'user': 'http://testserver' + alice_url,
        'bicycle': 'http://testserver' + bicycle_url,
        'created': reservation.created.isoformat()[:-13] + 'Z',
        'duration': 900,
        'state': 'new',
        'concurrency_version': reservation.concurrency_version,
        'modified': reservation.modified.isoformat()[:-13] + 'Z',
    })

    response = drf_fleet_operator.patch(url)
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    response = drf_fleet_operator.delete(url)
    assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    url = reverse_query('lock8:rental_session-list')
    drf_alice.assert_count(url, 0)

    url = reverse_query('lock8:reservation-detail',
                        kwargs={'uuid': reservation.uuid})
    response = drf_alice.get(url)
    assert response.status_code == status.HTTP_404_NOT_FOUND

    # Filtering on bicycles.
    url = reverse_query('lock8:reservation-list', {'bicycle': bicycle.uuid})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:reservation-list', (
        ('bicycle', bicycle.uuid),
        ('bicycle', non_matching_uuid)))
    drf_fleet_operator.assert_count(url, 1)

    bicycle2.declare_available()
    bicycle2.rent(by=bob)
    url = reverse_query('lock8:reservation-list', (
        ('bicycle', bicycle.uuid),
        ('bicycle', bicycle2.uuid)))
    drf_fleet_operator.assert_success(url)


def test_crud_notification_message(drf_fleet_operator, notification_message,
                                   fleet_operator, alert,
                                   drf_another_fleet_operator):
    url = reverse_query('lock8:notification_message-list')
    drf_fleet_operator.assert_count(url, 1)
    drf_another_fleet_operator.assert_count(url, 0)

    causality_url = reverse_query(
        'lock8:alert-detail',
        kwargs={'uuid': alert.uuid}
    )
    user_url = reverse_query(
        'lock8:user-detail',
        kwargs={'uuid': fleet_operator.uuid}
    )
    nmessage_url = reverse_query(
        'lock8:notification_message-detail',
        kwargs={'uuid': notification_message.uuid}
    )
    drf_fleet_operator.assert_status(nmessage_url, 200, expected_data={
        'causality': 'http://testserver{}'.format(causality_url),
        'causality_info': {'alert_type': 'lock.bat.low',
                           'resource_type': 'alert'},
        'causality_resource_type': 'alert',
        'concurrency_version': notification_message.concurrency_version,
        'created': notification_message.created.isoformat()[:-13] + 'Z',
        'modified': notification_message.modified.isoformat()[:-13] + 'Z',
        'state': notification_message.state,
        'url': 'http://testserver{}'.format(nmessage_url),
        'user': 'http://testserver{}'.format(user_url),
        'uuid': str(notification_message.uuid)
    })

    notification_message.send()
    notification_message.refresh_from_db()
    assert notification_message.state == 'sent'

    url = reverse_query(
        'lock8:notification_message-actions',
        kwargs={'uuid': notification_message.uuid}
    )
    response = drf_fleet_operator.post(url, data={'type': 'acknowledge'})
    assert response.status_code == status.HTTP_200_OK

    notification_message.refresh_from_db()
    assert notification_message.state == 'acknowledged'


def test_filtering_notification_message(notification_message,
                                        drf_fleet_operator):
    url = reverse_query('lock8:notification_message-list', {'state': 'XXX'})
    drf_fleet_operator.assert_invalid_choice(url, 'state', 'XXX')

    url = reverse_query('lock8:notification_message-list', {'state': 'new'})
    drf_fleet_operator.assert_count(url, 1)

    notification_message.send()

    url = reverse_query('lock8:notification_message-list', {'state': 'sent'})
    drf_fleet_operator.assert_count(url, 1)

    notification_message.acknowledge()

    url = reverse_query('lock8:notification_message-list',
                        {'state': 'acknowledged'})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:notification_message-list', {'state': 'new'})
    drf_fleet_operator.assert_count(url, 0)


def test_notification_message_num_queries(notification_message,
                                          drf_fleet_operator):
    drf_fleet_operator.use_jwt_auth()
    url = reverse_query('lock8:notification_message-list')
    with CaptureQueriesContext(connection) as capture:
        drf_fleet_operator.assert_count(url, 1)
    assert len(capture.captured_queries) == 6, '\n\n'.join(
        q['sql'] for q in capture.captured_queries)


def test_concurrent_edition(drf_fleet_operator, bicycle, monkeypatch):
    from velodrome.lock8.models import Bicycle

    def save(self, *args, **kwargs):
        raise RecordModifiedError(target=self)

    monkeypatch.setattr(Bicycle, 'save', save)

    url = reverse_query('lock8:bicycle-detail',
                        kwargs={'uuid': bicycle.uuid})
    data = {'name': 'New Name'}
    response = drf_fleet_operator.patch(url, data=data, format='json')
    assert response.status_code == status.HTTP_409_CONFLICT


def test_concurrent_edition_with_version(drf_fleet_operator, bicycle):
    url = reverse_query('lock8:bicycle-detail',
                        kwargs={'uuid': bicycle.uuid})
    data = {'name': 'New Name', 'concurrency_version': 1}
    response = drf_fleet_operator.patch(url, data=data, format='json')
    assert response.status_code == status.HTTP_409_CONFLICT


def test_filtering_on_invalid_uuid(drf_fleet_operator, bicycle, org):
    url = reverse_query('lock8:bicycle-list', {'organization': org.uuid})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:bicycle-list', {'organization': 'notanuid'})
    drf_fleet_operator.assert_400(url, {
        'organization': [{'message': 'Enter a valid UUID.',
                          'code': 'invalid'}]
    })

    # Test custom 'organization' filter in UserViewSet.get_internal_queryset.
    url = reverse_query('lock8:user-list', {'organization': 'notanuid'})
    drf_fleet_operator.assert_400(url, {
        'organization': [{'message': 'Enter a valid UUID.',
                          'code': 'invalid'}]
    })


def test_debug_views(drf_client, drf_alice, drf_admin, caplog):
    url = reverse_query('lock8:sleepplz')
    drf_client.assert_status(url, status.HTTP_401_UNAUTHORIZED)
    drf_alice.assert_403(url)
    drf_admin.assert_success(url, 'Slept for 0.0 seconds.')

    response = drf_admin.get(reverse_query('lock8:logplz'))
    assert response.content == b'"Logged testing errors."'

    assert ('velodrome.lock8.views', 40,
            'debug_logplz: test logging error') in caplog.record_tuples
    assert ('velodrome.lock8.utils', 40,
            'debug_log_error: via debug_logplz') in caplog.record_tuples
    assert ('velodrome.celery', 40,
            'debug_celery_log: test logging error') in caplog.record_tuples
    assert ('velodrome.lock8.utils', 40,
            'debug_log_error: via debug_celery_log') in caplog.record_tuples


@pytest.mark.django_db
def test_api_sorted_endpoints():
    url = reverse_query('lock8:api-root')
    drf_client = APIClient(HTTP_ACCEPT='application/json; version=1.0')
    response = drf_client.get(url)
    assert response.status_code == status.HTTP_200_OK
    names = [*response.data]
    assert names == sorted(names)
