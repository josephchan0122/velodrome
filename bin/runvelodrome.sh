#!/bin/sh
set -e

exec dumb-init uwsgi /srv/velodrome/src/etc/uwsgi.ini "$@"
