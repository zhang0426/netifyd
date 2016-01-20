AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = $(CPPFLAGS) -D_GNU_SOURCE -I ../include -I ../ndpi/src/include -I ../inih/cpp \
	$(JSONC_CFLAGS) $(LIBCURL_CFLAGS) $(ZLIB_CFLAGS)

#EXTRA_DIST = 

sbin_PROGRAMS = netifyd
netifyd_SOURCES = netifyd.cpp nd-inotify.cpp nd-json.cpp nd-netlink.cpp nd-sha1.c nd-thread.cpp nd-util.cpp
netifyd_LDFLAGS = $(JSONC_LIBS) $(LIBCURL_LIBS) $(ZLIB_LIBS)
#netifyd_LDFLAGS = $(JSONC_LIBS) $(LIBCURL_LIBS) $(ZLIB_LIBS) /home/dsokoloski/openwrt-15.05/staging_dir/target-mips_34kc_uClibc-0.9.33.2/usr/lib/libmbedtls.so.9
netifyd_LDADD = ../inih/libini.la ../ndpi/src/lib/libndpi.la
nodist_netifyd_SOURCES = nd-json-object-type.h nd-json-result-code.h
BUILT_SOURCES = nd-json-object-type.h nd-json-result-code.h
CLEANFILES = nd-json-object-type.h nd-json-result-code.h

nd-json-object-type.h: Makefile
	../util/generate-json-include.sh c-object-type >$@

nd-json-result-code.h: Makefile
	../util/generate-json-include.sh c-result-code >$@

