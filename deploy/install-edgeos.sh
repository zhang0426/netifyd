#!/bin/sh
# Manual install script for Ubiquiti EdgeOS (USG-3P)

sudo cp -r etc/netify.d/* /etc/netify.d/
if [ ! -f /etc/netifyd.conf ]; then
    sudo cp etc/netifyd.conf /etc/
fi
if [ ! -f /etc/default/netifyd ]; then
    sudo cp etc/default/netifyd /etc/default/
fi
sudo cp -r usr/* /usr/
sudo mkdir -p /var/run/netifyd
sudo rm -rf /var/lib/netifyd

sudo cp etc/cron.d/* /etc/cron.d/
sudo /etc/init.d/cron restart

sudo cp etc/init.d/* /etc/init.d/

sudo /usr/sbin/netifyd --provision
