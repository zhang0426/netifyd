# Netify Agent

# Configure conditionals
# Default values: --with conntrack --with inotify --with netlink --without bundled_libs
%{!?_with_conntrack: %{!?_without_conntrack: %define _with_conntrack --enable-conntrack}}
%{!?_with_inotify: %{!?_without_inotify: %define _with_inotify --enable-inotify}}
%{!?_with_netlink: %{!?_without_netlink: %define _with_netlink --enable-netlink}}
%{!?_with_bundled_libs: %{!?_without_bundled_libs: %define _without_bundled_libs 1}}

%if 0%{?centos_version} == 600
%define _with_bundled_libs 1
%endif

%{?_unitdir:%define _with_systemd 1}

# Configuration files
%define netifyd_conf deploy/%{name}.conf
%define netifyd_default deploy/%{name}.default
%define netifyd_env deploy/env.sh
%define netifyd_exec_pre deploy/exec-pre.sh
%define netifyd_functions deploy/functions.sh
%define netifyd_init deploy/%{name}-sysv.init
%define netifyd_sink_conf deploy/app-custom-match.conf
%define netifyd_systemd_unit deploy/%{name}.service
%define netifyd_tmpf deploy/%{name}.tmpf

%define statedir_pdata %{_sysconfdir}/netify.d
%define statedir_vdata %{_sharedstatedir}/netifyd

# RPM package details
Name: netifyd
Summary: Netify Agent
Version: 2.74
Release: 1%{dist}
Vendor: eGloo Incorporated
License: GPLv3
Group: System/Daemons
Packager: eGloo Incorporated
Source: %{name}-%{version}.tar.gz
BuildRoot: /var/tmp/%{name}-%{version}
BuildRequires: autoconf >= 2.63
BuildRequires: automake
BuildRequires: bc
BuildRequires: json-c-devel
BuildRequires: libcurl-devel
%if %{?_without_bundled_libs:1}%{!?_without_bundled_libs:0}
BuildRequires: gperftools-devel
%if %{?_with_conntrack:1}%{!?_with_conntrack:0}
BuildRequires: libmnl-devel
BuildRequires: libnetfilter_conntrack-devel
%endif
%endif
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

# Prepare
%prep
%setup -q

%if 0%{?_with_bundled_libs:1}

(cd libs/libmnl && ./autogen.sh &&\
    CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix="$(pwd)" --disable-shared --enable-static &&\
    make %{?_smp_mflags} && ln -s src lib)

(cd libs/libnfnetlink && ./autogen.sh &&\
    CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix="$(pwd)" --disable-shared --enable-static &&\
    make %{?_smp_mflags} && ln -s src lib)

export PKG_CONFIG_PATH=$(pwd)/libs/libmnl:$(pwd)/libs/libnfnetlink

(cd libs/libnetfilter-conntrack && ./autogen.sh &&\
    CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix="$(pwd)" --disable-shared --enable-static &&\
    make %{?_smp_mflags} && ln -s src lib)

export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$(pwd)/libs/libnetfilter-conntrack

(cd libs/gperftools && ./autogen.sh &&\
    CFLAGS="$RPM_OPT_FLAGS" ./configure --prefix="$(pwd)" --disable-shared --enable-static &&\
    make %{?_smp_mflags} && ln -s .libs lib)

export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$(pwd)/libs/gperftools

%endif

./autogen.sh
%{configure} \
    %{?_with_conntrack} \
    %{?_with_inotify} \
    %{?_with_netlink}

# Build
%build
make %{?_smp_mflags}

# Install
%install

EXTRA_DIST=%{buildroot}/EXTRA_DIST.txt
touch %{EXTRA_DIST}

make install DESTDIR=%{buildroot}

rm -rf %{buildroot}/%{_bindir}
rm -rf %{buildroot}/%{_includedir}
rm -rf %{buildroot}/%{_libdir}

install -d -m 0750 %{buildroot}/%{statedir_pdata}
install -d -m 0750 %{buildroot}/%{statedir_vdata}
install -d -m 0755 %{buildroot}/%{_localstatedir}/run/%{name}

install -D -m 0644 %{netifyd_sink_conf} %{buildroot}/%{statedir_pdata}/netify-sink.conf
install -D -m 0660 %{netifyd_conf} %{buildroot}/%{_sysconfdir}/%{name}.conf
install -D -m 0660 %{netifyd_default} %{buildroot}/%{_sysconfdir}/sysconfig/%{name}
install -D -m 0755 %{netifyd_exec_pre} %{buildroot}/%{_libexecdir}/%{name}/exec-pre.sh
install -D -m 0755 %{netifyd_functions} %{buildroot}/%{_libexecdir}/%{name}/functions.sh
install -D -m 0755 %{netifyd_init} %{buildroot}/%{_sysconfdir}/init.d/%{name}

%if %{?_with_systemd:1}%{!?_with_systemd:0}
install -D -m 0644 %{netifyd_systemd_unit} %{buildroot}/%{_unitdir}/%{name}.service
echo "%{_unitdir}/%{name}.service" >> %{EXTRA_DIST}

install -D -m 0644 %{netifyd_tmpf} %{buildroot}/%{_tmpfilesdir}/%{name}.conf
echo "%{_tmpfilesdir}/%{name}.conf" >> %{EXTRA_DIST}

install -D -m 0640 %{netifyd_env} %{buildroot}/%{_libexecdir}/%{name}/env.sh
echo "%config(noreplace) %attr(640,root,root) %{_libexecdir}/%{name}/env.sh" >> %{EXTRA_DIST}
%endif

# Clean-up
%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

# Post-install
%post
%if %{?_with_systemd:1}%{!?_with_systemd:0}
%systemd_post %{name}.service
%endif

# Remove old CSV configuration files
rm -f %{statedir_vdata}/*.csv
[ -f %{statedir_vdata}/agent.uuid ] && \
    mv -f %{statedir_vdata}/agent.uuid %{statedir_pdata}
[ -f %{statedir_vdata}/site.uuid ] && \
    mv -f %{statedir_vdata}/site.uuid %{statedir_pdata}
[ -f %{statedir_vdata}/app-custom-match.conf ] && \
    mv -f %{statedir_vdata}/app-custom-match.conf %{statedir_pdata}/netify-sink.conf

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
%dir %{_localstatedir}/lib/%{name}
%dir %attr(750,root,root) %{statedir_pdata}
%dir %attr(750,root,root) %{statedir_vdata}
%attr(644,root,root) %{_sysconfdir}/sysconfig/%{name}
%attr(755,root,root) %{_libexecdir}/%{name}/
%attr(755,root,root) %{_sysconfdir}/init.d/%{name}
%config(noreplace) %attr(640,root,root) %{statedir_pdata}/netify-sink.conf
%config(noreplace) %attr(660,root,root) %{_sysconfdir}/%{name}.conf
%{_sbindir}/%{name}
%{_mandir}/man5/*
%{_mandir}/man8/*

# vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
