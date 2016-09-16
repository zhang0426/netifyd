AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = $(CPPFLAGS) -D_GNU_SOURCE -I ../include \
	-I ../ndpi/src/include -I ../ndpi/src/lib

#EXTRA_DIST = 

noinst_PROGRAMS = nd-content-match-export
nd_content_match_export_SOURCES = nd-content-match-export.cpp
nd_content_match_export_CXXFLAGS = $(AM_CPPFLAGS) -Wno-write-strings -D _ND_INCLUDE_CONTENT_MATCH=1

