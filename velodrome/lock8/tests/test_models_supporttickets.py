from django.core.exceptions import ValidationError
from django.db.models import ProtectedError
import pytest


def test_support_ticket_model(org, alice, bicycle, with_email, fleet_operator):
    from velodrome.lock8.models import SupportTicket, SupportTicketStates

    support_ticket = SupportTicket.objects.create(
        owner=alice,
        organization=org,
        message='All glory to the hypnotoad',
        bicycle=bicycle,
        category=SupportTicket.REQUEST_BICYCLE,
        location='POINT(5 23)',
    )

    assert support_ticket.owner == alice
    assert support_ticket.message == 'All glory to the hypnotoad'
    assert support_ticket.bicycle == bicycle
    assert support_ticket.location.coords == (5, 23)
    assert support_ticket.category == SupportTicket.REQUEST_BICYCLE
    assert support_ticket.state == SupportTicketStates.NEW.value

    with_email, mailoutbox = with_email
    if with_email:
        assert len(mailoutbox) == 1
        email = mailoutbox[0]
        assert email.subject == 'Bicycles requested by a rider'
        assert email.recipients() == ['support@example.com']
        html = email.alternatives[0][0]
        for item in (support_ticket.owner.display_name, support_ticket.message,
                     '23.0,5.0'):
            assert item in html

        # Verify that no email is sent on ticket update
        support_ticket.state = SupportTicketStates.PENDING
        support_ticket.save()
        assert len(mailoutbox) == 1

    with pytest.raises(ProtectedError):
        alice.delete()

    support_ticket = SupportTicket.objects.create(
        owner=alice,
        organization=org,
        bicycle=bicycle,
        category=SupportTicket.DAMAGED_BICYCLE,
    )
    assert support_ticket.category == SupportTicket.DAMAGED_BICYCLE
    if with_email:
        assert len(mailoutbox) == 2
        email = mailoutbox[1]
        assert email.subject == 'Rider reported a damaged bicycle'
        html = email.alternatives[0][0]
        for item in (support_ticket.owner.display_name, support_ticket.message,
                     support_ticket.bicycle.frontend_uri):
            assert item in html
        assert 'This bicycle was last rented on' not in html

    bicycle.declare_available()
    bicycle.rent(by=alice)
    support_ticket = SupportTicket.objects.create(
        owner=alice,
        organization=org,
        bicycle=bicycle,
        category=SupportTicket.DAMAGED_BICYCLE,
    )
    assert support_ticket.category == SupportTicket.DAMAGED_BICYCLE
    if with_email:
        assert len(mailoutbox) == 3
        email = mailoutbox[2]
        assert email.subject == 'Rider reported a damaged bicycle'
        html = email.alternatives[0][0]
        for item in (support_ticket.owner.display_name, support_ticket.message,
                     support_ticket.bicycle.frontend_uri):
            assert item in html
        assert 'This bicycle was last rented on' in html
        ts = bicycle.transitions.filter(state='rented').first().timestamp
        assert ts.strftime('%Y-%m-%d %X') in html


def test_support_ticket_model_stripped(org, alice, with_email, fleet_operator):
    from velodrome.lock8.models import SupportTicket, SupportTicketStates

    support_ticket = SupportTicket.objects.create(
        owner=alice,
        organization=org,
        category=SupportTicket.LOST_BICYCLE,
        location='POINT(5 23)',
    )

    assert support_ticket.owner == alice
    assert support_ticket.message == ''
    assert support_ticket.bicycle is None
    assert support_ticket.location.coords == (5, 23)
    assert support_ticket.category == SupportTicket.LOST_BICYCLE
    assert support_ticket.state == SupportTicketStates.NEW.value

    with_email, mailoutbox = with_email
    if with_email:
        assert len(mailoutbox) == 1
        email = mailoutbox[0]
        assert email.subject == 'Rider couldn\'t find a bicycle'
        assert email.recipients() == ['support@example.com']
        html = email.alternatives[0][0]
        for item in (support_ticket.owner.display_name, support_ticket.message,
                     '23.0,5.0'):
            assert item in html


def test_support_ticket_validation(org, alice):
    from velodrome.lock8.models import SupportTicket

    support_ticket = SupportTicket(owner=alice,
                                   organization=org,
                                   category=SupportTicket.REQUEST_BICYCLE)
    with pytest.raises(ValidationError) as e:
        support_ticket.clean()
    assert ('Cannot set category `location_needs_bicycles` without a location.'
            in str(e.value))

    support_ticket = SupportTicket(owner=alice,
                                   organization=org,
                                   category=SupportTicket.LOST_BICYCLE)
    with pytest.raises(ValidationError) as e:
        support_ticket.clean()
    assert ('Cannot set category `bicycle_missing` without a location.'
            in str(e.value))

    support_ticket = SupportTicket(owner=alice,
                                   organization=org,
                                   category=SupportTicket.DAMAGED_BICYCLE)
    with pytest.raises(ValidationError) as e:
        support_ticket.clean()
    assert ('Cannot set category `bicycle_damaged` without a bicycle.'
            in str(e.value))


def test_support_ticket_missing_bicycle_with_bicycle(org, alice, bicycle,
                                                     with_email,
                                                     fleet_operator):
    from velodrome.lock8.models import SupportTicket

    support_ticket = SupportTicket.objects.create(
        owner=alice,
        organization=org,
        bicycle=bicycle,
        category=SupportTicket.LOST_BICYCLE,
        location='POINT(5 23)',
    )

    with_email, mailoutbox = with_email
    if with_email:
        assert len(mailoutbox) == 1
        email = mailoutbox[0]
        assert email.subject == "Rider couldn't find a bicycle"
        assert email.recipients() == ['support@example.com']
        html = email.alternatives[0][0]
        for item in (support_ticket.owner.display_name, support_ticket.message,
                     support_ticket.bicycle.name, '23.0,5.0',
                     support_ticket.bicycle.frontend_uri):
            assert item in html
