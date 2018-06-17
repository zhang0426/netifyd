EXTRA_DIST = app-custom-match.conf exec-pre.sh functions.sh netifyd.conf \
	netifyd.default netifyd-debian.init netifyd-sysv.init netifyd.service \
	netifyd.tmpf

#openwrt/Makefile: openwrt/Makefile.in
#	$(SED) \
#		-e 's|[@]GIT_LAST_COMMIT_DATE@|$(GIT_LAST_COMMIT_DATE)|g' \
#		-e 's|[@]GIT_LAST_COMMIT_HASH@|$(GIT_LAST_COMMIT_HASH)|g' \
#		-e 's|[@]GIT_SOURCE_URL@|$(GIT_SOURCE_URL)|g' \
#		-e 's|[@]PACKAGE_TARNAME@|$(PACKAGE_TARNAME)|g' \
#		-e 's|[@]PACKAGE_VERSION@|$(PACKAGE_VERSION)|g' \
#		-e 's|[@]sbindir@|$(sbindir)|g' \
#		-e 's|[@]sysconfdir@|$(sysconfdir)|g' \
#		< "$<" > "$@"

if HAVE_SYSTEMD
systemdsystemunit_DATA = \
	netifyd.service
endif
