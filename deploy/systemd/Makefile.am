# Netify Agent "systemd" Automake File
# Copyright (C) 2016-2018 eGloo, Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

SYSTEMDFILES = exec-pre.sh netifyd.conf netifyd.service
SYSTEMDFILES_IN = exec-pre.sh.in netifyd.conf.in netifyd.service.in

sharedatadir = $(datadir)/netifyd
sharedata_DATA = exec-pre.sh

if HAVE_SYSTEMD
systemdsystemunit_DATA = netifyd.service
tmpfiles_DATA = netifyd.conf
sharedata_DATA += env.sh
endif

BUILT_SOURCES = $(SYSTEMDFILES)
CLEANFILES = $(SYSTEMDFILES)
EXTRA_DIST = $(SYSTEMDFILES_IN) env.sh

%: %.in
	$(SED) \
		-e 's|[@]datadir@|$(datadir)|g' \
		-e 's|[@]PACKAGE_NAME@|$(PACKAGE_NAME)|g' \
		-e 's|[@]PACKAGE_TARNAME@|$(PACKAGE_TARNAME)|g' \
		-e 's|[@]piddir@|$(piddir)|g' \
		-e 's|[@]sbindir@|$(sbindir)|g' \
		< "$<" > "$@"
