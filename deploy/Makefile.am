EXTRA_DIST = app-custom-match.conf env.sh exec-pre.sh functions.sh.in \
	netifyd.conf netifyd.default netifyd-debian.init netifyd-sysv.init \
	netifyd.service netifyd.tmpf

BUILT_SOURCES = functions.sh
CLEANFILES = functions.sh

functions.sh: functions.sh.in
	$(SED) \
		-e 's|[@]PACKAGE_TARNAME@|$(PACKAGE_TARNAME)|g' \
		-e 's|[@]sysconfdir@|$(sysconfdir)|g' \
		< "$<" > "$@"

if HAVE_SYSTEMD
systemdsystemunit_DATA = \
	netifyd.service
endif
