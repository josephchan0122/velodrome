#!/bin/sh
timeout --signal=TERM 5 celery -A velodrome worker
exit_code=$?
if [ "$exit_code" = 137 ]; then
  exit 0
fi
exit $exit_code
