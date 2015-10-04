#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([cDPId], [1.0],
	[http://www.clearfoundation.com/docs/developer/bug_tracker/],
	[cdpid], [http://www.clearfoundation.com/])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/cdpid.cpp])
AC_CONFIG_SUBDIRS([ndpi])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CXX
AC_PROG_INSTALL
AM_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB([rt], [timer_create], [], [
	AC_MSG_ERROR([librt not found.])])
AC_CHECK_LIB([pthread], [pthread_create], [], [
	AC_MSG_ERROR([libpthread not found.])])
AC_CHECK_LIB([pcap], [pcap_open_live], [], [
	AC_MSG_ERROR([libpcap not found.])])
AC_CHECK_LIB([z], [zlibVersion], [], [
	AC_MSG_ERROR([libz not found.])])

PKG_CHECK_MODULES([JSONC], [json-c])
PKG_CHECK_MODULES([LIBCRYPTO], [libcrypto])
PKG_CHECK_MODULES([LIBCURL], [libcurl])

# Checks for header files.
#AC_CHECK_HEADERS([proc/readproc.h], [], [AC_MSG_ERROR([procps header files not found.])])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T

# Checks for library functions.

# Compiler optimizations
#CFLAGS+=" -fomit-frame-pointer -O3 -falign-functions=16 -falign-jumps=16 -falign-loops=16 -falign-labels=16"
#CXXFLAGS+=" -fomit-frame-pointer -O3 -falign-functions=16 -falign-jumps=16 -falign-loops=16 -falign-labels=16"

# Output files
AC_CONFIG_FILES([Makefile src/Makefile cdpid.spec])
AC_OUTPUT
