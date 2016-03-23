#!/bin/bash
# Build netifyd command-line with all configured LAN/WAN interfaces (ClearOS)

source /etc/clearos/network.conf

NETIFYD_OPTS=

for ifn in $LANIF; do
    [ -z "$ifn" ] && break
    NETIFYD_OPTS="$NETIFYD_OPTS -I $ifn"
done

for ifn in $EXTIF; do
    [ -z "$ifn" ] && break
    NETIFYD_OPTS="$NETIFYD_OPTS -E $ifn"
done

if [ -z "$NETIFYD_OPTS" ]; then
    echo "No LAN/WAN interfaces configured."
    exit 1
fi

systemctl set-environment NETIFYD_OPTS="$NETIFYD_OPTS"

exit 0

# vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4 syntax=sh
