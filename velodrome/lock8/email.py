import functools
import logging
import queue
import weakref

from django.db import transaction
from django_ses import SESBackend

logger = logging.getLogger(__name__)

messages_store = {}


class SESBackend(SESBackend):
    def __send(self, email_messages):
        num_sent = super().send_messages(email_messages)
        diff = len(email_messages) - num_sent
        if diff:
            logger.error('SESBackend: %s email%s were not sent.\n%r',
                         diff, 's' if diff > 1 else '', email_messages)
        return num_sent

    def transactional_send_messages(self, key):
        messages = messages_store.pop(key)
        email_messages = []
        while not messages.empty():
            email_messages.append(messages.get())
            messages.task_done()
        return self.__send(email_messages)

    def send_messages(self, email_messages):
        """Transaction aware SESBackend.
        If within atomic block, messages will be accumulated into
        queue and dispatched only at the end of transaction.
        Registers only one signal transaction.on_commit per transaction.
        If not within an atomic block, then send messages immediately.
        """
        connection = transaction.get_connection()
        if connection.in_atomic_block:
            key = tuple(set(connection.savepoint_ids))
            try:
                messages = messages_store[key]
            except KeyError:
                messages_store[key] = messages = queue.Queue()
                transaction.on_commit(functools.partial(
                    self.transactional_send_messages, key))

                # If the transaction is rollbacked
                # don't accumulate messages and leak
                # memory
                def cleanup_messages_store(key):
                    try:
                        del messages_store[key]
                    except KeyError:
                        pass

                weakref.finalize(self, cleanup_messages_store, key)
            while email_messages:
                messages.put(email_messages.pop(0))
            return 0
        return self.__send(email_messages)
