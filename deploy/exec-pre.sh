#!/bin/bash
# Set Netify Agent command-line options:
# At least one -I, --internal and/or -E, --external parameters are required.
# See man netifyd(8) for all options.

source /var/libexec/netifyd/functions.sh

load_modules

NETIFYD_OPTS=$(auto_detect_options)

systemctl set-environment NETIFYD_OPTS="$NETIFYD_OPTS"

exit 0

# vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4 syntax=sh
