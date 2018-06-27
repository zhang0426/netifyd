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
%define netifyd_exec_pre deploy/exec-pre.sh
%define netifyd_functions deploy/functions.sh
%define netifyd_init deploy/%{name}-sysv.init
%define netifyd_sink_conf deploy/app-custom-match.conf
%define netifyd_systemd_unit deploy/%{name}.service
%define netifyd_tmpf deploy/%{name}.tmpf

# RPM package details
Name: netifyd
Summary: Netify Agent
Version: 2.67
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
%if 0%{?_with_bundled_libs:1}
BuildRequires: git
%endif
BuildRequires: libpcap-devel
BuildRequires: libtool
BuildRequires: pkgconfig
BuildRequires: zlib-devel
%{?systemd_requires}

%description
Netify provides visibility into the traffic on your network along with the option to take an active role (on supported devices) in stopping/shaping undesirable traffic from recurring on your network.
Report bugs to: https://bitbucket.org/eglooca/netify-daemon/issues

# Prepare
%prep
%setup -q

%if 0%{?_with_bundled_libs:1}

(cd libmnl && ./autogen.sh &&\
    ./configure --prefix=$(pwd) --disable-shared --enable-static &&\
    make %{?_smp_mflags} && ln -s src lib)

(cd libnfnetlink && ./autogen.sh &&\
    ./configure --prefix=$(pwd) --disable-shared --enable-static &&\
    make %{?_smp_mflags} && ln -s src lib)

export PKG_CONFIG_PATH=$(pwd)/libmnl:$(pwd)/libnfnetlink

(cd libnetfilter_conntrack && ./autogen.sh &&\
    ./configure --prefix=$(pwd) --disable-shared --enable-static &&\
    make %{?_smp_mflags} && ln -s src lib)

export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$(pwd)/libnetfilter_conntrack

(cd gperftools && ./autogen.sh &&\
    ./configure --prefix=$(pwd) --disable-shared --enable-static &&\
    make %{?_smp_mflags} && ln -s .libs lib)

export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$(pwd)/gperftools

%endif

./autogen.sh
%{configure} \
    %{?_with_conntrack} \
    %{?_with_inotify} \
    %{?_with_netlink} \
    --disable-ncurses

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

install -d -m 0750 %{buildroot}/%{_sysconfdir}/netify.d
install -d -m 0755 %{buildroot}/%{_localstatedir}/run/%{name}
install -d -m 0755 %{buildroot}/%{_localstatedir}/lib/%{name}

install -D -m 0644 %{netifyd_sink_conf} %{buildroot}/%{_sysconfdir}/netify.d/netify-sink.conf
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
%endif

# Clean-up
%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

# Post-install
%post
%systemd_post %{name}.service

# Remove old CSV configuration files
rm -f %{_sharedstatedir}/%{name}/*.csv
[ -f %{_sharedstatedir}/%{name}/agent.uuid ] && \
    mv -f %{_sharedstatedir}/%{name}/agent.uuid /etc/netify.d/
[ -f %{_sharedstatedir}/%{name}/site.uuid ] && \
    mv -f %{_sharedstatedir}/%{name}/site.uuid /etc/netify.d/
[ -f %{_sharedstatedir}/%{name}/app-custom-match.conf ] && \
    mv -f %{_sharedstatedir}/%{name}/app-custom-match.conf /etc/netify.d/netify-sink.conf

# Pre-uninstall
%preun
%systemd_preun %{name}.service

# Post-uninstall
%postun
%systemd_postun_with_restart %{name}.service

# Files
%files -f %{EXTRA_DIST}
%defattr(-,root,root)
%dir %{_localstatedir}/run/%{name}
%dir %{_localstatedir}/lib/%{name}
%dir %attr(750,root,root) %{_sharedstatedir}/%{name}/
%dir %attr(750,root,root) %{_sysconfdir}/netify.d/
%attr(644,root,root) %{_sysconfdir}/sysconfig/%{name}
%attr(755,root,root) %{_libexecdir}/%{name}/
%attr(755,root,root) %{_sysconfdir}/init.d/%{name}
%config(noreplace) %attr(640,root,root) %{_sysconfdir}/netify.d/netify-sink.conf
%config(noreplace) %attr(660,root,root) %{_sysconfdir}/%{name}.conf
%{_sbindir}/%{name}
%{_mandir}/man5/*
%{_mandir}/man8/*

# vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
