# Netify DPI Daemon
# GNU Autoconf configuration

AC_PREREQ([2.63])
AC_INIT([Netify DPI Daemon], [1.2],
	[https://github.com/eglooca/netify-daemon/issues],
	[netifyd], [http://www.egloo.ca/])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/netifyd.cpp])
AC_CONFIG_SUBDIRS([inih ndpi])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AM_PROG_LIBTOOL

# Get git revision
if test -d ".git"; then :
    GIT_TAG=`git log -1 --format=%h`
    GIT_DATE=`git log -1 --format=%cd`

    # On CentOS 6 `git rev-list HEAD --count` does not work
    GIT_NUM=`git log --pretty=oneline | wc -l | tr -d '[[:space:]]'`
    GIT_BRANCH=`git rev-parse --abbrev-ref HEAD`
    GIT_RELEASE="${PACKAGE_VERSION}-${GIT_BRANCH}-${GIT_NUM}-${GIT_TAG}"
else
    GIT_RELEASE="${PACKAGE_VERSION}"
    GIT_DATE=`date`
fi

AC_DEFINE_UNQUOTED(GIT_RELEASE, "${GIT_RELEASE}", [GIT Release])
AC_DEFINE_UNQUOTED(GIT_DATE, "${GIT_DATE}", [Last GIT change])

# Check compiler flags (gnu++11)
m4_include([m4/ax_cxx_compile_stdcxx_0x.m4])
m4_include([m4/ax_cxx_compile_stdcxx_11.m4])
AX_CXX_COMPILE_STDCXX_11([ext], [optional])
AS_IF([test "$HAVE_CXX11" = "0"], [AX_CXX_COMPILE_STDCXX_0X])

#CXXFLAGS="$CXXFLAGS -std=gnu++0x"

# Check for optional parameters

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
PKG_CHECK_MODULES([LIBCURL], [libcurl])

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
AC_CONFIG_FILES([Makefile src/Makefile util/Makefile netifyd.spec])
AC_OUTPUT
