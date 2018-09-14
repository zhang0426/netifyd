# Netify Agent Debian Package Automake File
# Copyright (C) 2016-2018 eGloo, Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

DEBFILES = debian.changelog debian.control debian.init debian.postinst debian.rules netifyd.dsc
DEBFILES_IN = debian.changelog.in debian.control.in debian.init debian.postinst.in debian.rules.in netifyd.dsc.in

BUILT_SOURCES = $(DEBFILES)
CLEANFILES = $(DEBFILES)
EXTRA_DIST = $(DEBFILES_IN)

%: %.in
	$(SED) \
		-e 's|[@]bindir@|$(bindir)|g' \
		-e 's|[@]datadir@|$(datadir)/$(PACKAGE_TARNAME)|g' \
		-e 's|[@]includedir@|$(includedir)|g' \
		-e 's|[@]libdir@|$(libdir)|g' \
		-e 's|[@]PACKAGE_BUGREPORT@|$(PACKAGE_BUGREPORT)|g' \
		-e 's|[@]PACKAGE_NAME@|$(PACKAGE_NAME)|g' \
		-e 's|[@]PACKAGE_TARNAME@|$(PACKAGE_TARNAME)|g' \
		-e 's|[@]PACKAGE_VERSION@|$(PACKAGE_VERSION)|g' \
		-e 's|[@]sbindir@|$(sbindir)|g' \
		-e 's|[@]sysconfdir@|$(sysconfdir)|g' \
		-e 's|[@]volatilestatedir@|$(volatilestatedir)|g' \
		< "$<" > "$@"
