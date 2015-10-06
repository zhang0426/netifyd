AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

AM_CXXFLAGS = $(CXXFLAGS) $(JSONC_CFLAGS) $(LIBCRYPTO_CFLAGS) $(LIBCURL_CFLAGS) -std=gnu++11 -I ../include -I ../ndpi/src/include -I ../inih/cpp

#EXTRA_DIST = 

sbin_PROGRAMS = cdpid
cdpid_SOURCES = cdpid.cpp cdpi-thread.cpp cdpi-util.cpp
cdpid_LDFLAGS = $(JSONC_LIBS) $(LIBCRYPTO_LIBS) $(LIBCURL_LIBS)
cdpid_LDADD = ../inih/libini.la ../ndpi/src/lib/libndpi.la

