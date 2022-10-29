import pytest
from rest_framework import status
from rest_framework_gis.fields import GeoJsonDict

from velodrome.lock8.utils import reverse_query


def test_crud_support_ticket(drf_fleet_operator, org, support_ticket,
                             drf_another_fleet_operator, drf_bob, drf_alice,
                             drf_admin, alice, another_support_ticket):
    from velodrome.lock8.models import Affiliation, SupportTicket
    ticket_list_url = reverse_query('lock8:support_ticket-list')

    drf_admin.assert_count(ticket_list_url, 2)

    for user in (drf_fleet_operator, drf_alice):
        response = user.assert_count(ticket_list_url, 1)
        assert response.data['results'][0]['message'] == support_ticket.message

    for user in (drf_another_fleet_operator, drf_bob):
        response = user.assert_count(ticket_list_url, 1)
        assert response.data['results'][0]['message'] == another_support_ticket.message  # noqa

    org_url = reverse_query('lock8:organization-detail',
                            kwargs={'uuid': org.uuid})
    bicycle_url = reverse_query(
        'lock8:bicycle-detail',
        kwargs={'uuid': support_ticket.bicycle.uuid}
    )

    Affiliation.objects.create(organization=org,
                               user=alice,
                               role=Affiliation.RENTER)
    user_url = reverse_query('lock8:user-detail', kwargs={'uuid': alice.uuid})
    payload = {
        'organization': org_url,
        'message': 'I think he\'s shuffling off sadly in the distance.',
        'bicycle': bicycle_url,
        'location': GeoJsonDict([('type', 'Point'),
                                ('coordinates', [-123.0, 44.0])]),
        'category': 'bicycle_damaged',
    }
    response = drf_alice.assert_status(
        ticket_list_url, status.HTTP_201_CREATED, data=payload, format='json')

    expected_data = {
        **payload, **{
            'organization': 'http://testserver{}'.format(org_url),
            'owner': 'http://testserver{}'.format(user_url),
            'bicycle': 'http://testserver{}'.format(bicycle_url),
            'state': 'new',
        }
    }
    for key in expected_data:
        assert response.data[key] == expected_data[key]

    payload['location']['coordinates'] = ['12.3', '23.4']
    drf_alice.assert_status(
        ticket_list_url, status.HTTP_400_BAD_REQUEST, data=payload,
        format='json')

    user_url = reverse_query('lock8:user-detail', kwargs={'uuid': alice.uuid})
    ticket_detail_url = reverse_query(
        'lock8:support_ticket-detail', kwargs={'uuid': support_ticket.uuid}
    )

    drf_fleet_operator.assert_success(ticket_detail_url, {
        'organization': 'http://testserver{}'.format(org_url),
        'owner': 'http://testserver{}'.format(user_url),
        'message': support_ticket.message,
        'bicycle': 'http://testserver{}'.format(bicycle_url),
        'category': support_ticket.category,
        'location': GeoJsonDict([('type', 'Point'),
                                 ('coordinates', [5.0, 23.0])]),
        'state': 'new',
        'uuid': str(support_ticket.uuid),
        'url': 'http://testserver{}'.format(ticket_detail_url),
        'created': support_ticket.created.isoformat()[:-13] + 'Z',
        'modified': support_ticket.modified.isoformat()[:-13] + 'Z',
        'concurrency_version': support_ticket.concurrency_version,
    })

    ticket_detail_url = reverse_query(
        'lock8:support_ticket-detail', kwargs={'uuid': support_ticket.uuid},
        query_kwargs={'fields': 'bicycle'}
    )
    drf_fleet_operator.assert_success(ticket_detail_url, {
        'bicycle': 'http://testserver{}'.format(bicycle_url),
    })
    ticket_detail_url = reverse_query(
        'lock8:support_ticket-detail', kwargs={'uuid': support_ticket.uuid},
        query_kwargs={'fields': 'organization'}
    )
    drf_fleet_operator.assert_success(ticket_detail_url, {
        'organization': 'http://testserver{}'.format(org_url),
    })

    response = drf_fleet_operator.delete(ticket_detail_url)
    assert response.status_code == status.HTTP_204_NO_CONTENT
    with pytest.raises(SupportTicket.DoesNotExist):
        support_ticket.refresh_from_db()


def test_support_ticket_filtering(drf_fleet_operator, support_ticket, org,
                                  alice, bob, another_org, bicycle,
                                  another_bicycle):
    from velodrome.lock8.models import SupportTicketStates
    url = reverse_query('lock8:support_ticket-list',
                        {'organization': org.uuid})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:support_ticket-list',
                        {'organization': another_org.uuid})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:support_ticket-list',
                        {'owner': alice.uuid})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:support_ticket-list',
                        {'owner': bob.uuid})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:support_ticket-list',
                        {'bicycle': bicycle.uuid})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:support_ticket-list',
                        {'bicycle': another_bicycle.uuid})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:support_ticket-list',
                        {'category': support_ticket.category})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:support_ticket-list',
                        {'category': support_ticket.DAMAGED_BICYCLE})
    drf_fleet_operator.assert_count(url, 0)

    url = reverse_query('lock8:support_ticket-list',
                        {'state': SupportTicketStates.NEW.value})
    drf_fleet_operator.assert_count(url, 1)

    url = reverse_query('lock8:support_ticket-list',
                        {'state': SupportTicketStates.CLOSED.value})
    drf_fleet_operator.assert_count(url, 0)


def test_support_ticket_validation(alice, drf_alice, org):
    from velodrome.lock8.models import Affiliation
    Affiliation.objects.create(organization=org,
                               user=alice,
                               role=Affiliation.RENTER)
    org_url = reverse_query('lock8:organization-detail',
                            kwargs={'uuid': org.uuid})

    ticket_list_url = reverse_query('lock8:support_ticket-list')
    payload = {
        'organization': org_url,
        'message': '',
        'category': 'bicycle_damaged',
    }
    drf_alice.assert_status(
        ticket_list_url, status.HTTP_400_BAD_REQUEST, data=payload,
        format='json', expected_data={'detail': {
            '__all__': [{
                'code': 'invalid',
                'message': 'Cannot set category `bicycle_damaged` '
                           'without a bicycle.'}]}})

    payload = {
        'organization': org_url,
        'message': '',
        'category': 'location_needs_bicycles',
    }
    drf_alice.assert_status(
        ticket_list_url, status.HTTP_400_BAD_REQUEST, data=payload,
        format='json', expected_data={'detail': {
            '__all__': [{
                'code': 'invalid',
                'message': 'Cannot set category `location_needs_bicycles` '
                           'without a location.'}]}})
