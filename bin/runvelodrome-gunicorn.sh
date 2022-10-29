#!/bin/sh
set -e

exec dumb-init gunicorn -c /srv/velodrome/src/etc/gunicorn-conf.py velodrome.wsgi "$@"
