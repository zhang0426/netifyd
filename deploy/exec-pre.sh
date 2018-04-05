#!/bin/bash
# Set Netify Agent command-line options:
# At least one -I, --internal and/or -E, --external parameters are required.
# See man netifyd(8) for all options.

[ -f /etc/default/netifyd ] && source /etc/default/netifyd
[ -f /etc/sysconfig/netifyd ] && source /etc/sysconfig/netifyd

NETIFYD_OPTS=$NETIFYD_EXTRA_OPTS

for entry in $NETIFYD_INTNET; do
    if [ "$entry" == "${entry/,/}" ]; then
        NETIFYD_OPTS="$NETIFYD_OPTS -I $entry"
        continue
    fi
    for net in ${entry//,/ }; do
        if [ "$net" == "${entry/,*/}" ]; then
            NETIFYD_OPTS="$NETIFYD_OPTS -I $net"
        else
            NETIFYD_OPTS="$NETIFYD_OPTS -A $net"
        fi
    done
done

for entry in $NETIFYD_EXTNET; do
    if [ "$entry" == "${entry/,/}" ]; then
        NETIFYD_OPTS="$NETIFYD_OPTS -E $entry"
        continue
    fi
    for ifn in ${entry//,/ }; do
        if [ "$ifn" == "${entry/,*/}" ]; then
            NETIFYD_OPTS="$NETIFYD_OPTS -E $ifn"
        else
            NETIFYD_OPTS="$NETIFYD_OPTS -N $ifn"
        fi
    done
done

NETIFYD_OPTS=$(echo "$NETIFYD_OPTS" | sed -e 's/^[[:space:]]*//g' -e 's/[[:space:]]*$$//g')

systemctl set-environment NETIFYD_OPTS="$NETIFYD_OPTS"

/sbin/modprobe -q nfnetlink
/sbin/modprobe -q nf_conntrack_netlink

exit 0

# vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4 syntax=sh
