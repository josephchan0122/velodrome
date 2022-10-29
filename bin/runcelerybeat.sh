#!/bin/sh
set -e

exec dumb-init celery -A velodrome beat --loglevel INFO
