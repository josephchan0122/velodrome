from django.core.mail import EmailMessage
from django.db import transaction
import pytest

pytestmark = pytest.mark.slow


@pytest.fixture
def email_messages():
    return [EmailMessage(subject='1'), EmailMessage(subject='2')]


def test_email_backend_send_on_commit(transactional_db, email_messages,
                                      mocker):
    from django_ses import SESBackend as RealSESBackend
    from velodrome.lock8.email import SESBackend, messages_store

    mock = mocker.patch.object(RealSESBackend, 'send_messages', return_value=2)

    with transaction.atomic():
        num_sent = SESBackend().send_messages(email_messages[:])
        assert not mock.called
    mock.assert_called_with(email_messages)
    assert not messages_store
    assert num_sent == 0


def test_email_backend_send_on_rollback(transactional_db, email_messages,
                                        mocker):
    from django_ses import SESBackend as RealSESBackend
    from velodrome.lock8.email import SESBackend, messages_store

    mock = mocker.patch.object(RealSESBackend, 'send_messages')

    with transaction.atomic():
        backend = SESBackend()
        num_sent = backend.send_messages(email_messages[:])
        transaction.set_rollback(True)
        assert not mock.called
        del backend
    assert not mock.called
    assert not messages_store
    assert num_sent == 0


def test_email_backend_non_atomic(transactional_db, email_messages, mocker):
    from django_ses import SESBackend as RealSESBackend
    from velodrome.lock8.email import SESBackend, messages_store

    mock = mocker.patch.object(RealSESBackend, 'send_messages', return_value=2)

    backend = SESBackend()
    num_sent = backend.send_messages(email_messages[:])
    mock.assert_called_with(email_messages)
    assert not messages_store
    assert num_sent == 2


def test_email_backend_non_atomic_diff(transactional_db, email_messages,
                                       mocker, caplog):
    from django_ses import SESBackend as RealSESBackend
    from velodrome.lock8.email import SESBackend, messages_store

    mock = mocker.patch.object(RealSESBackend, 'send_messages', return_value=1)

    backend = SESBackend()
    num_sent = backend.send_messages(email_messages[:])
    mock.assert_called_with(email_messages)
    assert not messages_store
    assert num_sent == 1
    assert 'SESBackend: 1 email were not sent' in caplog.text
