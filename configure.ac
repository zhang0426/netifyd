# Netify DPI Daemon
# GNU Autoconf configuration

AC_PREREQ([2.63])
AC_INIT([Netify DPI Daemon], [1.5],
	[https://github.com/eglooca/netify-daemon/issues],
	[netifyd], [http://www.egloo.ca/])
AM_INIT_AUTOMAKE
AC_CONFIG_SRCDIR([src/netifyd.cpp])
AC_CONFIG_SUBDIRS([inih ndpi])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_USE_SYSTEM_EXTENSIONS

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_INSTALL
AM_PROG_LIBTOOL

# Checks for libraries.
AC_CHECK_LIB([pcap],
    [pcap_open_live], [], [AC_MSG_ERROR([libpcap not found.])])
AC_CHECK_LIB([pthread],
    [pthread_create], [], [AC_MSG_ERROR([libpthread not found.])])
AC_CHECK_LIB([rt],
    [timer_create], [], [AC_MSG_ERROR([librt not found.])])

#AC_CHECK_LIB([libmbedtls.so.9], [ssl_init])

# Check for optional parameters
AC_ARG_ENABLE([conntrack],
    [AS_HELP_STRING([--enable-conntrack], [Enable connection tracking support [default=no]])],
    [],
    [enable_conntrack=no])

PKG_CHECK_MODULES([JSONC], [json-c])
PKG_CHECK_MODULES([LIBCURL], [libcurl])
PKG_CHECK_MODULES([ZLIB], [zlib])
AS_IF([test "x$enable_conntrack" = "xyes"], [
    AC_DEFINE([_ND_USE_CONNTRACK], [1],
        [Define to enable connection tracking support.])
    AM_CONDITIONAL(USE_CONNTRACK, true)
    PKG_CHECK_MODULES([LIBMNL], [libmnl >= 1.0.3])
    PKG_CHECK_MODULES([LIBNETFILTER_CONNTRACK], [libnetfilter_conntrack >= 1.0.4])
], [
    AM_CONDITIONAL(USE_CONNTRACK, false)
])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/file.h sys/ioctl.h sys/socket.h sys/time.h syslog.h unistd.h])

# Check compiler flags (gnu++11)
m4_include([m4/ax_cxx_compile_stdcxx_0x.m4])
m4_include([m4/ax_cxx_compile_stdcxx_11.m4])
AX_CXX_COMPILE_STDCXX_11([ext], [optional])
AS_IF([test "$HAVE_CXX11" = "0"], [AX_CXX_COMPILE_STDCXX_0X])

#CXXFLAGS="$CXXFLAGS -std=gnu++0x"

# Check for optional parameters

# Checks for typedefs, structures, and compiler characteristics.
#AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT32_T
AC_TYPE_INT64_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRNLEN

AC_CHECK_FUNCS([ftruncate memchr memset pathconf select socket strcasecmp strdup strerror])

AC_CHECK_FUNC([pthread_setname_np], [
	AC_DEFINE([HAVE_PTHREAD_SETNAME_NP], [1], [Define if pthread_setname_np is available.])
])
AC_CHECK_FUNC([pthread_attr_setaffinity_np], [
	AC_DEFINE([HAVE_PTHREAD_ATTR_SETAFFINITY_NP], [1], [Define if pthread_attr_setaffinity_np is available.])
])

# Compiler optimizations
#CFLAGS+=" -fomit-frame-pointer -O3 -falign-functions=16 -falign-jumps=16 -falign-loops=16 -falign-labels=16"
#CXXFLAGS+=" -fomit-frame-pointer -O3 -falign-functions=16 -falign-jumps=16 -falign-loops=16 -falign-labels=16"

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

# Output files
AC_CONFIG_FILES([Makefile deploy/Makefile src/Makefile util/Makefile netifyd.spec])
AC_OUTPUT
