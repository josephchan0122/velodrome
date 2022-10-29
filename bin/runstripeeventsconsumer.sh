#!/bin/sh
set -e

exec python /srv/velodrome/src/manage.py stripe_events_consumer
