import asyncio
import logging

from aiozmq import rpc
from django.core.management.base import BaseCommand

from velodrome.lock8.utils import RPCMessageHandler

logger = logging.getLogger(__name__)


class Command(BaseCommand):
    can_import_settings = True

    def handle(self, *args, **kwargs):
        from django.conf import settings

        async def spawn_server():
            server = await rpc.serve_rpc(
                RPCMessageHandler(),
                bind=settings.ZMQ_TRACKING_RPC_ENDPOINT)
            return server

        loop = asyncio.get_event_loop()
        logger.info('Will bind on %s', settings.ZMQ_TRACKING_RPC_ENDPOINT)
        loop.run_until_complete(spawn_server())
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            loop.stop()
            loop.close()
