import datetime as dt

from django.db import connection
from django.db.utils import IntegrityError
import pytest


def test_rental_session_estimated_end_of_trip(db, today, alice, bicycle):
    from velodrome.lock8.models import RentalSession

    delta = dt.timedelta(minutes=5)

    rental_session = RentalSession()
    assert rental_session.modified is None
    assert rental_session.latest_transition is None
    assert rental_session.estimated_end_of_trip == today + delta
    rental_session.modified = today + delta
    assert rental_session.estimated_end_of_trip == today + (2 * delta)

    rental_session = RentalSession.objects.create(owner=alice, user=alice,
                                                  bicycle=bicycle)
    rental_session.created = today
    assert rental_session.estimated_end_of_trip == today + delta


@pytest.mark.uses_payments
def test_rentalsession_close_rollback(
        drf_renter, bicycle_available, renter, customer, pricing_scheme,
        mocker, caplog):
    from pinax.stripe.models import Charge

    mocker.patch('pinax.stripe.actions.charges.create',
                 return_value=Charge.objects.create())
    bicycle = bicycle_available
    bicycle.rent(by=renter,
                 pricing_scheme=pricing_scheme)
    rental_session = bicycle.active_rental_session

    mocker.patch(
        'velodrome.lock8.models.PricingScheme.compute_amount_for_duration',
        side_effect=IntegrityError('test_exc'))
    m_rollback = mocker.spy(connection, 'savepoint_rollback')
    bicycle.return_(by=renter)
    msgs = [(rec.levelname, rec.message) for rec in caplog.records]
    assert msgs == [
        ('INFO', 'init_payment: created uncaptured charge '),
        ('INFO', 'Returning bicycle %s (dry_run=0)' % (bicycle.uuid)),
        ('ERROR', 'Exception in RentalSession.close: test_exc')]

    rental_session.refresh_from_db()
    assert rental_session.state == 'closed'
    assert rental_session.cents is None
    assert rental_session.payment_state == 'pending'

    assert m_rollback.called


@pytest.mark.uses_payments
def test_rentalsession_init_payment_creates_customer(
        mock_stripe_customer, mock_stripe_customer_chargable,
        bicycle_available, renter, pricing_scheme):
    from velodrome.lock8.models import RentalSession

    assert getattr(renter, 'customer', None) is None

    rental_session = RentalSession(bicycle=bicycle_available,
                                   user=renter, cents=500, owner=renter,
                                   pricing_scheme=pricing_scheme)
    rental_session.init_payment(by=renter)
    assert renter.get_customer(organization=bicycle_available.organization)


@pytest.mark.uses_payments
def test_rentalsession_init_payment_skips_uncaptured_for_recurring(
        mocker, bicycle_available, renter, pricing_scheme):
    from velodrome.lock8.models import RentalSession

    assert not renter.get_paid_rentalsessions()

    m = mocker.patch.object(renter, 'get_paid_rentalsessions')
    rental_session = RentalSession(bicycle=bicycle_available,
                                   user=renter, cents=500, owner=renter,
                                   pricing_scheme=pricing_scheme)
    rental_session.init_payment(by=renter)
    assert m.return_value.exists.call_count == 1


@pytest.mark.uses_payments
def test_rentalsession_process_payments_with_nothing_to_charge(
        mocker, caplog, mock_stripe_customer_chargable, bicycle_available,
        mock_stripe_customer, pricing_scheme, renter):
    from velodrome.lock8.models import RentalSession

    rental_session = RentalSession(bicycle=bicycle_available,
                                   user=renter, cents=0, owner=renter,
                                   pricing_scheme=pricing_scheme)
    rental_session.init_payment(by=renter)

    m_retrieve = mocker.patch('stripe.Charge.retrieve')
    rental_session.process_payment()
    m_retrieve.assert_called_once_with(
        rental_session.charge.stripe_id,
        expand=['balance_transaction'],
        stripe_account='acc_org')
    m_retrieve().refund.assert_called_once_with()
    assert rental_session.payment_state == 'processed'


def test_rental_session_without_payments_gets_skipped(bicycle_rented):
    rental_session = bicycle_rented.active_rental_session
    assert rental_session.payment_state == 'skipped'
