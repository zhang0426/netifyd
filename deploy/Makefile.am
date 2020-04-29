# Netify Agent Deploy Automake File
# Copyright (C) 2016-2020 eGloo, Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

SUBDIRS = debian edgeos systemd ubios

TEMPLATEFILES = functions.sh netifyd.conf netifyd.init watchdog.cron watchdog.sh
TEMPLATEFILES_IN = functions.sh.in netifyd.conf.in netifyd.init.in watchdog.cron.in watchdog.sh.in

sharedatadir = $(datadir)/netifyd
sharedata_DATA = functions.sh watchdog.sh
sysconf_DATA = netifyd.conf

persistentstate_DATA = netify-sink.conf

BUILT_SOURCES = $(TEMPLATEFILES)
CLEANFILES = $(TEMPLATEFILES)
EXTRA_DIST = $(TEMPLATEFILES_IN) freebsd netifyd.default netify-sink.conf pfsense

%: %.in
	$(SED) \
		-e 's|[@]bindir@|$(bindir)|g' \
		-e 's|[@]datadir@|$(datadir)/$(PACKAGE_TARNAME)|g' \
		-e 's|[@]PACKAGE_NAME@|$(PACKAGE_NAME)|g' \
		-e 's|[@]PACKAGE_TARNAME@|$(PACKAGE_TARNAME)|g' \
		-e 's|[@]sysconfdir@|$(sysconfdir)|g' \
		-e 's|[@]volatilestatedir@|$(volatilestatedir)|g' \
		< "$<" > "$@"
