#!/bin/sh
# After the files are gone, for both packages. The ditto-relay user and
# /var/lib/ditto-relay stay: the database is the one thing a reinstall can't
# get back.
set -e

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
