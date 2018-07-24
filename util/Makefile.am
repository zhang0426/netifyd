AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

AM_CPPFLAGS = $(CPPFLAGS) -D_GNU_SOURCE -I ../include \
              -I ../libs/ndpi/src/include -I ../libs/ndpi/src/lib

#EXTRA_DIST = 

noinst_PROGRAMS = nd-match-export
nd_match_export_SOURCES = nd-match-export.cpp
nd_match_export_CXXFLAGS = $(AM_CPPFLAGS) -Wno-write-strings -Wno-unused-variable

