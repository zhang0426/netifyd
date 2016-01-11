AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = $(CPPFLAGS) -I ../include
AM_CXXFLAGS = $(CXXFLAGS) -std=gnu++11 -I ../include -I ../ndpi/src/include -I ../inih/cpp \
	$(JSONC_CFLAGS) $(LIBCURL_CFLAGS) $(ZLIB_CFLAGS)

#EXTRA_DIST = 

sbin_PROGRAMS = netifyd
netifyd_SOURCES = netifyd.cpp nd-inotify.cpp nd-json.cpp nd-sha1.c nd-thread.cpp nd-util.cpp
netifyd_LDFLAGS = $(JSONC_LIBS) $(LIBCURL_LIBS) $(ZLIB_LIBS)
#netifyd_LDFLAGS = $(JSONC_LIBS) $(LIBCURL_LIBS) $(ZLIB_LIBS) /home/dsokoloski/openwrt/staging_dir/target-mips_34kc_musl-1.1.11/usr/lib/libmbedtls.so.9
netifyd_LDADD = ../inih/libini.la ../ndpi/src/lib/libndpi.la

