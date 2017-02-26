AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = $(CPPFLAGS) -D_GNU_SOURCE -I ../include \
	-I ../ndpi/src/include -I ../inih/cpp \
	$(JSONC_CFLAGS) $(LIBCURL_CFLAGS) $(ZLIB_CFLAGS)

#EXTRA_DIST = 

sbin_PROGRAMS = netifyd
netifyd_SOURCES = netifyd.cpp nd-detection.cpp nd-flow.cpp \
	nd-json.cpp nd-ndpi.cpp nd-sha1.c nd-socket.cpp nd-thread.cpp \
	nd-upload.cpp nd-util.cpp
netifyd_LDFLAGS = $(JSONC_LIBS) $(LIBCURL_LIBS) $(ZLIB_LIBS)
netifyd_LDADD = ../inih/libini.la ../ndpi/src/lib/libndpi.la

if USE_CONNTRACK
netifyd_SOURCES += nd-conntrack.cpp
netifyd_LDADD += $(LIBNETFILTER_CONNTRACK_LIBS) $(LIBMNL_LIBS)
endif

if USE_INOTIFY
netifyd_SOURCES += nd-inotify.cpp
endif

if USE_NETLINK
netifyd_SOURCES += nd-netlink.cpp
endif

nodist_netifyd_SOURCES = nd-json-object-type.h nd-json-result-code.h nd-json-config-type.h
BUILT_SOURCES = nd-json-object-type.h nd-json-result-code.h nd-json-config-type.h
CLEANFILES = nd-json-object-type.h nd-json-result-code.h nd-json-config-type.h

nd-json-object-type.h: ../include/nd-json-object-type.txt.in Makefile
	../util/generate-json-include.sh c-object-type >$@

nd-json-result-code.h: ../include/nd-json-result-code.txt.in Makefile
	../util/generate-json-include.sh c-result-code >$@

nd-json-config-type.h: ../include/nd-json-config-type.txt.in Makefile
	../util/generate-json-include.sh c-config-type >$@

