#!/bin/sh

sudo cp -r etc/netify.d/* /etc/netify.d/
if [ ! -f /etc/netifyd.conf ]; then
    sudo cp etc/netifyd.conf /etc/
fi
if [ ! -f /etc/default/netifyd ]; then
    sudo cp etc/default/netifyd /etc/default/
fi
sudo cp -r usr/* /usr/
sudo cp -r var/* /var/

sudo cp etc/cron.d/* /etc/cron.d/
sudo /etc/init.d/cron restart

sudo /usr/sbin/netifyd --provision

