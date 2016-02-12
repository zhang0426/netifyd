#!/bin/bash
# Build netifyd command-line with all configured LAN interfaces (ClearOS)

NETIFYD_OPTS=

for ifn in $(/usr/sbin/network --get-lan-interfaces 2>/dev/null); do
    [ -z "$ifn" ] && break
    NETIFYD_OPTS="$NETIFYD_OPTS -I $ifn"
done

if [ -z "$NETIFYD_OPTS" ]; then
    echo "No LAN interfaces configured."
    exit 1
fi

systemctl set-environment NETIFYD_OPTS="$NETIFYD_OPTS"

exit 0

# vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4 syntax=sh
