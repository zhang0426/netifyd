#!/bin/bash
# Set Netify Daemon command-line options

# See man netifyd(8) for all options.
NETIFYD_OPTS=

# Dynamically add all configured LAN/WAN interfaces.
source /etc/clearos/network.conf

for ifn in $LANIF; do
    [ -z "$ifn" ] && break
    NETIFYD_OPTS="$NETIFYD_OPTS -I $ifn"
done

for ifn in $HOTIF; do
    [ -z "$ifn" ] && break
    NETIFYD_OPTS="$NETIFYD_OPTS -I $ifn"
done

for ifn in $EXTIF; do
    [ -z "$ifn" ] && break
    [ -f "/etc/sysconfig/network-scripts/ifcfg-${ifn}" ] &&
        source "/etc/sysconfig/network-scripts/ifcfg-${ifn}"
    if [ ! -z "$ETH" ]; then
        NETIFYD_OPTS="$NETIFYD_OPTS -E $ETH -N $ifn"
        unset ETH
    else
        NETIFYD_OPTS="$NETIFYD_OPTS -E $ifn"
    fi
done

if [ -z "$NETIFYD_OPTS" ]; then
    echo "No LAN/WAN interfaces configured."
    exit 1
fi

systemctl set-environment NETIFYD_OPTS="$NETIFYD_OPTS"

/sbin/modprobe -q nfnetlink
/sbin/modprobe -q nf_conntrack_netlink

exit 0

# vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4 syntax=sh
