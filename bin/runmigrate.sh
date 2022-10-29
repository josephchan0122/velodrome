#!/bin/sh
set -e

dumb-init python /srv/velodrome/src/manage.py migrate --noinput -v 3
