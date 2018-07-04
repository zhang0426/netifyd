AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = $(CPPFLAGS) -D_GNU_SOURCE -I ../include \
	-I ../libs/ndpi/src/include -I ../libs/inih/cpp \
	$(JSONC_CFLAGS) $(LIBCURL_CFLAGS) $(ZLIB_CFLAGS) $(LIBTCMALLOC_CFLAGS) \
	-DNDPI_LIB_COMPILATION=1 \
	-D'ND_VOLATILE_STATEDIR="$(sharedstatedir)/$(PACKAGE_TARNAME)"' \
	-D'ND_PERSISTENT_STATEDIR="$(sysconfdir)/netify.d"'
	-D'ND_PID_FILE_NAME="$(localstatedir)/run/$(PACKAGE_TARNAME)/$(PACKAGE_TARNAME).pid"' \
	-D'ND_CONF_FILE_NAME="$(sysconfdir)/$(PACKAGE_TARNAME).conf"'

#EXTRA_DIST =

sbin_PROGRAMS = netifyd
netifyd_SOURCES = netifyd.cpp nd-detection.cpp nd-flow.cpp \
	nd-json.cpp nd-ndpi.cpp nd-sha1.c nd-socket.cpp nd-thread.cpp \
	nd-upload.cpp nd-util.cpp
netifyd_LDFLAGS = $(JSONC_LIBS) $(LIBCURL_LIBS) $(ZLIB_LIBS)
netifyd_LDADD = ../libs/inih/libini.la ../libs/ndpi/src/lib/libndpi.la

if USE_CONNTRACK
AM_CPPFLAGS += $(LIBNETFILTER_CONNTRACK_CFLAGS) $(LIBMNL_CFLAGS)
netifyd_SOURCES += nd-conntrack.cpp
netifyd_LDADD += $(LIBNETFILTER_CONNTRACK_LIBS) $(LIBMNL_LIBS)
endif

if USE_INOTIFY
netifyd_SOURCES += nd-inotify.cpp
endif

if USE_NCURSES
netifyd_LDADD += $(LIBNCURSES_LIBS)
endif

if USE_NETLINK
netifyd_SOURCES += nd-netlink.cpp
endif

if USE_LIBTCMALLOC
# XXX: Recommended compiler flags
AM_CFLAGS = -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free
AM_CXXFLAGS = -fno-builtin-malloc -fno-builtin-calloc -fno-builtin-realloc -fno-builtin-free
# XXX: It's important that this library be linked after all others.
LIBS += $(LIBTCMALLOC_LIBS)
endif

# For debugging ns_initparse
#netifyd_SOURCES += ns-parse.c

nodist_netifyd_SOURCES = nd-json-object-type.h nd-json-result-code.h nd-json-config-type.h
BUILT_SOURCES = nd-json-object-type.h nd-json-result-code.h nd-json-config-type.h
CLEANFILES = nd-json-object-type.h nd-json-result-code.h nd-json-config-type.h

nd-json-object-type.h: ../include/nd-json-object-type.txt.in Makefile
	../util/generate-json-include.sh c-object-type >$@

nd-json-result-code.h: ../include/nd-json-result-code.txt.in Makefile
	../util/generate-json-include.sh c-result-code >$@

nd-json-config-type.h: ../include/nd-json-config-type.txt.in Makefile
	../util/generate-json-include.sh c-config-type >$@

