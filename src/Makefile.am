AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = $(CPPFLAGS) -I ../include
AM_CXXFLAGS = $(CXXFLAGS) -std=gnu++11 -I ../include -I ../ndpi/src/include -I ../inih/cpp \
	$(JSONC_CFLAGS) $(LIBCURL_CFLAGS) $(ZLIB_CFLAGS)

#EXTRA_DIST = 

sbin_PROGRAMS = cdpid
cdpid_SOURCES = cdpid.cpp cdpi-inotify.cpp cdpi-json.cpp cdpi-sha1.c cdpi-thread.cpp cdpi-util.cpp
cdpid_LDFLAGS = $(JSONC_LIBS) $(LIBCURL_LIBS) $(ZLIB_LIBS)
#cdpid_LDFLAGS = $(JSONC_LIBS) $(LIBCURL_LIBS) $(ZLIB_LIBS) /home/dsokoloski/openwrt/staging_dir/target-mips_34kc_musl-1.1.11/usr/lib/libmbedtls.so.9
cdpid_LDADD = ../inih/libini.la ../ndpi/src/lib/libndpi.la

