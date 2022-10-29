#!/bin/sh
set -e

exec dumb-init python /srv/velodrome/src/manage.py locksocket_rpc_server
