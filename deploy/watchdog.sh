#!/bin/sh

UPLOAD_WD="/var/lib/netifyd/upload.wd"

[ ! -f "$UPLOAD_WD" ] && exit 0
 
if [ $[ $(date '+%s') - 30 ] -gt $(stat -c '%Y' "$UPLOAD_WD") ]; then
	/etc/init.d/netifyd restart
	#service netifyd restart
	#systemctl restart netifyd
fi

exit 0
