#!/bin/sh
# Before the files go, for both packages. dpkg says `remove` when the package
# is going away and `upgrade` when a new version replaces it; rpm says how
# many copies will be left, 0 when it is going away.
set -e

case "$1" in
    remove | 0) ;;
    *) exit 0 ;;
esac

if [ -d /run/systemd/system ]; then
    systemctl disable --now ditto-relay.service || true
fi
