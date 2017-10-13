#!/bin/bash
# Set Netify Daemon command-line options:
# At least one -I, --internal and/or -E, --external parameters are required.
# See man netifyd(8) for all options.

# NETIFYD_OPTS="--external eth0 --internal eth1"
NETIFYD_OPTS=

systemctl set-environment NETIFYD_OPTS="$NETIFYD_OPTS"

/sbin/modprobe -q nfnetlink
/sbin/modprobe -q nf_conntrack_netlink

exit 0

# vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4 syntax=sh
