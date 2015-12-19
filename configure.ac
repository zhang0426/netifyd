#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([cDPId], [1.0],
	[http://www.clearfoundation.com/docs/developer/bug_tracker/],
	[cdpid], [http://www.clearfoundation.com/])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/cdpid.cpp])
AC_CONFIG_SUBDIRS([inih ndpi])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CXX
AC_PROG_INSTALL
AM_PROG_LIBTOOL

# Check for optional parameters
AC_ARG_ENABLE(cloud-sync,
	AS_HELP_STRING([--enable-cloud-sync], [enable eGloo cloud synchronization])
)
AS_IF([test "x$enable_cloud_sync" = "xyes"], [
    AC_DEFINE([USE_CLOUD_SYNC], [1], [Define to enable eGloo cloud synchronization.])
])

# Checks for libraries.
AC_CHECK_LIB([rt], [timer_create], [], [
	AC_MSG_ERROR([librt not found.])])
AC_CHECK_LIB([pthread], [pthread_create], [], [
	AC_MSG_ERROR([libpthread not found.])])
AC_CHECK_LIB([pcap], [pcap_open_live], [], [
	AC_MSG_ERROR([libpcap not found.])])
#AC_CHECK_LIB([libmbedtls.so.9], [ssl_init])

PKG_CHECK_MODULES([ZLIB], [zlib])
PKG_CHECK_MODULES([JSONC], [json-c])
#PKG_CHECK_MODULES([LIBCRYPTO], [libcrypto])
PKG_CHECK_MODULES([LIBCURL], [libcurl])
#PKG_CHECK_MODULES([LIBMNL], [libmnl])

# Checks for header files.
#AC_CHECK_HEADERS([proc/readproc.h], [], [AC_MSG_ERROR([procps header files not found.])])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_SIZE_T

# Checks for library functions.
AC_CHECK_FUNC([pthread_setname_np], [
	AC_DEFINE([HAVE_PTHREAD_SETNAME_NP], [1], [Define if pthread_setname_np is available.])
])
AC_CHECK_FUNC([pthread_attr_setaffinity_np], [
	AC_DEFINE([HAVE_PTHREAD_ATTR_SETAFFINITY_NP], [1], [Define if pthread_attr_setaffinity_np is available.])
])

# Compiler optimizations
#CFLAGS+=" -fomit-frame-pointer -O3 -falign-functions=16 -falign-jumps=16 -falign-loops=16 -falign-labels=16"
#CXXFLAGS+=" -fomit-frame-pointer -O3 -falign-functions=16 -falign-jumps=16 -falign-loops=16 -falign-labels=16"

# Output files
AC_CONFIG_FILES([Makefile src/Makefile cdpid.spec])
AC_OUTPUT
