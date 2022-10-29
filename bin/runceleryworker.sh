#!/bin/sh
set -e

exec dumb-init celery -A velodrome worker \
  --queues="${CELERY_QUEUES:-celery}" \
  --concurrency="${CELERY_WORKERS:-2}" \
  --loglevel INFO \
  "$@"
