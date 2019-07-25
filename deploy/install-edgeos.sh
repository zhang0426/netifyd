#!/bin/sh
# Manual install script for Ubiquiti EdgeOS (USG-3P)

sudo mkdir -p /etc/netify.d/ || exit 1
sudo cp -r etc/netify.d/* /etc/netify.d/ || exit 1

if [ ! -f /etc/netifyd.conf ]; then
    sudo cp etc/netifyd.conf /etc/ || exit 1
fi

if [ ! -f /etc/default/netifyd ]; then
    sudo cp etc/default/netifyd /etc/default/ || exit 1
fi

sudo cp -r usr/* /usr/ || exit 1
sudo chmod a+x /usr/share/netifyd/*.sh || exit 1

sudo mkdir -p /var/run/netifyd || exit 1
sudo rm -rf /var/lib/netifyd || exit 1

sudo cp etc/cron.d/* /etc/cron.d/ || exit 1
sudo /etc/init.d/cron restart

sudo cp etc/init.d/* /etc/init.d/ || exit 1

sudo /usr/sbin/netifyd --provision || exit 1
echo
sudo /usr/sbin/netifyd --status

echo -e "\nNow edit the defaults configuration file to define interfaces:"
echo "# sudo vi /etc/default/netifyd"

exit 0
