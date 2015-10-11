AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

AM_CXXFLAGS = $(CXXFLAGS) -std=gnu++11 -I ../include -I ../ndpi/src/include -I ../inih/cpp \
	$(JSONC_CFLAGS) $(LIBCRYPTO_CFLAGS) $(LIBCURL_CFLAGS) $(LIBMNL_CFLAGS) $(ZLIB_CFLAGS)

#EXTRA_DIST = 

sbin_PROGRAMS = cdpid
cdpid_SOURCES = cdpid.cpp cdpi-inotify.cpp cdpi-thread.cpp cdpi-util.cpp
cdpid_LDFLAGS = $(JSONC_LIBS) $(LIBCRYPTO_LIBS) $(LIBCURL_LIBS) $(LIBMNL_LIBS) $(ZLIB_LIBS)
cdpid_LDADD = ../inih/libini.la ../ndpi/src/lib/libndpi.la

