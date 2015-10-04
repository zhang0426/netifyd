#!/bin/bash
# Build cdpid command-line with all configured LAN interfaces

CDPID_OPTS=

for ifn in "$(/usr/sbin/network --get-lan-interfaces 2>/dev/null)"; do
    [ -z "$ifn" ] && break
    CDPID_OPTS="$CDPID_OPTS -I $ifn"
done

if [ -z "$CDPID_OPTS" ]; then
    echo "No LAN interfaces configured."
    exit 1
fi

systemctl set-environment CDPID_OPTS="$CDPID_OPTS"

exit 0

# vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4 syntax=sh
