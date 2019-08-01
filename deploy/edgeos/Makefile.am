# Netify Agent Deploy Automake File for EdgeOS
# Copyright (C) 2016-2019 eGloo, Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

TEMPLATEFILES = netifyd.conf watchdog.cron watchdog-conf.sh
TEMPLATEFILES_IN = netifyd.conf.in watchdog.cron.in watchdog-conf.sh.in

BUILT_SOURCES = $(TEMPLATEFILES)
CLEANFILES = $(TEMPLATEFILES)
EXTRA_DIST = $(TEMPLATEFILES_IN) netify_edgeos

%: %.in
	$(SED) \
		-e 's|[@]datadir@|$(datadir)/$(PACKAGE_TARNAME)|g' \
		-e 's|[@]PACKAGE_NAME@|$(PACKAGE_NAME)|g' \
		-e 's|[@]PACKAGE_TARNAME@|$(PACKAGE_TARNAME)|g' \
		-e 's|[@]sysconfdir@|$(sysconfdir)|g' \
		-e 's|[@]volatilestatedir@|$(volatilestatedir)|g' \
		< "$<" > "$@"
