#!/bin/sh
# After the files are in place, for both packages. dpkg calls this with
# `configure <old version>`, the old version empty on a first install; rpm with
# the number of copies installed, 1 on a first install.
set -e

case "$1" in
    configure) upgrade="${2:+yes}" ;;
    1) upgrade= ;;
    [0-9]*) upgrade=yes ;;
    *) exit 0 ;;
esac

systemd-sysusers ditto-relay.conf
systemd-tmpfiles --create ditto-relay.conf

# Without systemd running (a container, a chroot) there is nothing to tell.
[ -d /run/systemd/system ] || exit 0
systemctl daemon-reload

if [ -n "$upgrade" ]; then
    # Only if it was running: one stopped on purpose stays stopped.
    systemctl try-restart ditto-relay.service
    exit 0
fi

# Not started, nor enabled: until url is set it would only fail and restart,
# every five seconds.
cat <<'MSG'
Ditto Relay is installed. Set url in /etc/ditto-relay/ditto-relay.toml, then:

    sudo systemctl enable --now ditto-relay

It listens on 127.0.0.1:13131; put a reverse proxy with TLS in front of it, or
turn on [tls] for it to serve HTTPS itself, with a certificate from Let's Encrypt.
MSG
