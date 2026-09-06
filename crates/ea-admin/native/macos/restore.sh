#!/bin/sh
set -eu
# Run after profile/backup restoration and before reopening the native runtime.
exec /usr/bin/python3 "$(dirname "$0")/release.py" restore "$@"
