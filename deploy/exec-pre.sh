#!/bin/bash
# Set Netify Daemon configuration options for systemd

NETIFYD_OPTS=
# NETIFYD_OPTS="--external eth0 --internal eth1"

systemctl set-environment NETIFYD_OPTS="$NETIFYD_OPTS"

/sbin/modprobe -q nfnetlink
/sbin/modprobe -q nf_conntrack_netlink

exit 0

# vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4 syntax=sh
