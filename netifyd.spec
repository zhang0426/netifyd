# Netify Agent RPM Spec File
# Copyright (C) 2016-2020 eGloo, Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

# Configure conditionals
# Default values: --with conntrack --with inotify --with netlink
%{!?_with_conntrack: %{!?_without_conntrack: %define _with_conntrack --enable-conntrack}}
%{!?_with_inotify: %{!?_without_inotify: %define _with_inotify --enable-inotify}}
%{!?_with_netlink: %{!?_without_netlink: %define _with_netlink --enable-netlink}}

%if 0%{?centos_version} == 600
%define _with_bundled_libs 1
%endif

%{?_unitdir:%define _with_systemd 1}

# RH-specific configuration files/paths
%define netifyd_default deploy/%{name}.default
%define netifyd_init deploy/%{name}.init

# Persistent and volatile state paths
%define statedir_pdata %{_sysconfdir}/netify.d
%define statedir_vdata %{_localstatedir}/run/%{name}
%define statedir_vdata_old %{_sharedstatedir}/%{name}

# RPM package details
Name: netifyd
Summary: Netify Agent
Version: 3.02
Release: 1%{dist}
Vendor: eGloo Incorporated
URL: http://www.netify.ai/
License: GPLv3
Group: System/Daemons
Packager: eGloo Incorporated
Source: %{name}-%{version}.tar.gz
BuildRoot: /var/tmp/%{name}-%{version}
BuildRequires: autoconf >= 2.63
BuildRequires: automake
BuildRequires: bc
BuildRequires: libcurl-devel
BuildRequires: gperftools-devel
BuildRequires: libmnl-devel
BuildRequires: libnetfilter_conntrack-devel
BuildRequires: libpcap-devel
BuildRequires: libtool
BuildRequires: pkgconfig
BuildRequires: zlib-devel
%{?systemd_requires}

%description
The Netify Agent (https://www.netify.ai/) is a deep-packet inspection server.
The Agent is built on top of nDPI (formerly OpenDPI):
http://www.ntop.org/products/deep-packet-inspection/ndpi/

Protocol and application detections can be saved locally, served over a UNIX or
TCP socket, and/or "pushed" (via HTTP POSTs) to a remote third-party server.
Flow metadata, network statistics, and detection classifications are stored
using JSON encoding.

Optionally, the Netify Agent can be coupled with a Netify Cloud
(https://www.netify.ai/) subscription for further cloud processing, historical
storage, machine-learning analysis, event notifications, device
detection/identification, along with the option (on supported platforms) to
take an active role in policing/bandwidth-shaping specific network protocols
and applications.

Report bugs to: https://gitlab.com/netify.ai/public/netify-agent/issues

%package devel
Summary: Netify Agent Plugin API Files
Group: Development/Libraries

%description devel
Development files (headers) for developing Netify Agent Plugins.

Report bugs to: https://gitlab.com/netify.ai/public/netify-agent/issues

# Prepare
%prep
%setup -q

%if 0%{?_with_bundled_libs:1}

(cd libs/libmnl && ./autogen.sh && \
    CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix="$(pwd)" --disable-shared --enable-static --with-pic && \
    make %{?_smp_mflags} && ln -s src lib)

(cd libs/libnfnetlink && ./autogen.sh && \
    CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix="$(pwd)" --disable-shared --enable-static --with-pic && \
    make %{?_smp_mflags} && ln -s src lib)

export PKG_CONFIG_PATH=$(pwd)/libs/libmnl:$(pwd)/libs/libnfnetlink

(cd libs/libnetfilter-conntrack && ./autogen.sh && \
    CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix="$(pwd)" --disable-shared --enable-static --with-pic && \
    make %{?_smp_mflags} && ln -s src lib)

export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$(pwd)/libs/libnetfilter-conntrack

(cd libs/gperftools && ./autogen.sh && \
    CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix="$(pwd)" --disable-shared --enable-static --with-pic && \
    make %{?_smp_mflags} && ln -s .libs lib)

export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$(pwd)/libs/gperftools

%endif

./autogen.sh
%{configure} %{?_with_conntrack} %{?_with_inotify} %{?_with_netlink}

# Build
%build
make %{?_smp_mflags}

# Install
%install

EXTRA_DIST=%{buildroot}/EXTRA_DIST.txt
touch %{EXTRA_DIST}

make install DESTDIR=%{buildroot}

rm -rf %{buildroot}/%{_bindir}
rm -rf %{buildroot}/%{_includedir}/libndpi*
rm -rf %{buildroot}/%{_libdir}/libndpi*
rm -rf %{buildroot}/%{_libdir}/pkgconfig/libndpi*

rm -rf %{buildroot}/%{_includedir}/google
rm -rf %{buildroot}/%{_includedir}/gperftools
rm -rf %{buildroot}/usr/lib/debug
rm -rf %{buildroot}/%{_libdir}/libprofiler*
rm -rf %{buildroot}/%{_libdir}/libtcmalloc*
rm -rf %{buildroot}/%{_libdir}/pkgconfig/libprofiler*
rm -rf %{buildroot}/%{_libdir}/pkgconfig/libtcmalloc*
rm -rf %{buildroot}/%{_docdir}/gperftools
rm -rf %{buildroot}/%{_mandir}/man1/pprof*

install -d -m 0750 %{buildroot}/%{statedir_vdata}

install -D -m 0660 %{netifyd_default} %{buildroot}/%{_sysconfdir}/sysconfig/%{name}
install -D -m 0755 %{netifyd_init} %{buildroot}/%{_sysconfdir}/init.d/%{name}

%if %{?_with_systemd:1}%{!?_with_systemd:0}
echo "%{_unitdir}/%{name}.service" >> %{EXTRA_DIST}
echo "%{_tmpfilesdir}/%{name}.conf" >> %{EXTRA_DIST}
echo "%config(noreplace) %attr(640,root,root) %{_datadir}/%{name}/env.sh" >> %{EXTRA_DIST}
%endif

# Clean-up
%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

# Post-install
%post
%if %{?_with_systemd:1}%{!?_with_systemd:0}
%systemd_post %{name}.service
%endif

# Preserve configuration files from old volatile directory
if [ -d %{statedir_vdata_old} ]; then

    [ -f %{statedir_vdata_old}/agent.uuid ] && \
        mv -f %{statedir_vdata_old}/agent.uuid %{statedir_pdata}
    [ -f %{statedir_vdata_old}/site.uuid ] && \
        mv -f %{statedir_vdata_old}/site.uuid %{statedir_pdata}

    rm -rf %{statedir_vdata_old}
fi

exit 0

# Pre-uninstall
%preun
%if %{?_with_systemd:1}%{!?_with_systemd:0}
%systemd_preun %{name}.service
%endif

# Post-uninstall
%postun
%if %{?_with_systemd:1}%{!?_with_systemd:0}
%systemd_postun_with_restart %{name}.service
%endif

# Files
%files -f %{EXTRA_DIST}
%defattr(-,root,root)
%dir %{_localstatedir}/run/%{name}
%dir %attr(750,root,root) %{statedir_pdata}
%dir %attr(750,root,root) %{statedir_vdata}
%attr(755,root,root) %{_datadir}/%{name}/
%attr(755,root,root) %{_sysconfdir}/init.d/%{name}
%config(noreplace) %attr(644,root,root) %{_sysconfdir}/sysconfig/%{name}
%config(noreplace) %attr(640,root,root) %{statedir_pdata}/netify-sink.conf
%config(noreplace) %attr(660,root,root) %{_sysconfdir}/%{name}.conf
%{_sbindir}/%{name}
%{_libdir}/lib%{name}.so*
%{_mandir}/man5/*
%{_mandir}/man8/*

# Developer files
%files devel
%defattr(-,root,root)
%{_includedir}/%{name}
%{_libdir}/pkgconfig/lib%{name}.pc
%{_libdir}/lib%{name}.a
%{_libdir}/lib%{name}.la

# vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
