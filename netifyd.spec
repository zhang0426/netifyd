# Netify Agent

# Configure conditionals
# Default values: --with conntrack --with inotify --with netlink --without local_netlink
%{!?_with_conntrack: %{!?_without_conntrack: %define _with_conntrack --enable-conntrack}}
%{!?_with_inotify: %{!?_without_inotify: %define _with_inotify --enable-inotify}}
%{!?_with_netlink: %{!?_without_netlink: %define _with_netlink --enable-netlink}}
%{!?_with_local_netlink: %{!?_without_local_netlink: %define _without_local_netlink 1}}

%{?_unitdir:%define _with_systemd 1}

# Configuration files
%define netifyd_conf deploy/%{name}.conf
%define netifyd_init deploy/%{name}-sysv.init
%define netifyd_tmpf deploy/%{name}.tmpf
%define netifyd_systemd_exec deploy/exec-pre.sh
%define netifyd_systemd_func deploy/functions.sh
%define netifyd_systemd_unit deploy/%{name}.service

# RPM package details
Name: netifyd
Summary: Netify Agent
Version: 2.62
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
%if %{?_without_local_netlink:1}%{!?_without_local_netlink:0}
%if %{?_with_conntrack:1}%{!?_with_conntrack:0}
BuildRequires: libmnl-devel
BuildRequires: libnetfilter_conntrack-devel
%endif
%endif
%if 0%{?_with_local_netlink:1}
BuildRequires: git
%endif
BuildRequires: libpcap-devel
BuildRequires: libtool
BuildRequires: pkgconfig
BuildRequires: zlib-devel
%{?systemd_requires}

%description
Netify provides visibility into the traffic on your network along with the option to take an active role (on supported devices) in stopping/shaping undesirable traffic from recurring on your network.
Report bugs to: https://github.com/eglooca/netify-daemon/issues

# Prepare
%prep
%setup -q

%if 0%{?_with_local_netlink:1}

git clone git://git.netfilter.org/libmnl
(cd libmnl && ./autogen.sh &&\
    ./configure --prefix=$(pwd) --disable-shared --enable-static &&\
    make %{?_smp_mflags} && ln -s src lib)

git clone git://git.netfilter.org/libnfnetlink
(cd libnfnetlink && ./autogen.sh &&\
    ./configure --prefix=$(pwd) --disable-shared --enable-static &&\
    make %{?_smp_mflags} && ln -s src lib)

export PKG_CONFIG_PATH=$(pwd)/libmnl:$(pwd)/libnfnetlink

git clone git://git.netfilter.org/libnetfilter_conntrack
(cd libnetfilter_conntrack && ./autogen.sh &&\
    ./configure --prefix=$(pwd) --disable-shared --enable-static &&\
    make %{?_smp_mflags} && ln -s src lib)

export PKG_CONFIG_PATH=$PKG_CONFIG_PATH:$(pwd)/libnetfilter_conntrack

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

install -d -m 0755 %{buildroot}/var/run/%{name}

install -D -m 0644 deploy/app-custom-match.conf %{buildroot}/%{_sharedstatedir}/%{name}/app-custom-match.conf
%if %{?_with_systemd:1}%{!?_with_systemd:0}
install -D -m 0644 %{netifyd_systemd_unit} %{buildroot}/%{_unitdir}/%{name}.service
echo "%{_unitdir}/%{name}.service" >> %{EXTRA_DIST}
install -D -m 0644 %{netifyd_tmpf} %{buildroot}/%{_tmpfilesdir}/%{name}.conf
echo "%{_tmpfilesdir}/%{name}.conf" >> %{EXTRA_DIST}
%endif
install -D -m 0660 %{netifyd_conf} %{buildroot}/%{_sysconfdir}/%{name}.conf
install -D -m 0755 %{netifyd_init} %{buildroot}/%{_sysconfdir}/init.d/%{name}
install -D -m 0755 %{netifyd_systemd_exec} %{buildroot}/%{_libexecdir}/%{name}/exec-pre.sh
install -D -m 0755 %{netifyd_systemd_func} %{buildroot}/%{_libexecdir}/%{name}/functions.sh

# Clean-up
%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

# Post-install
%post
%systemd_post %{name}.service

# Remove old CSV configuration files
rm -f %{_sharedstatedir}/%{name}/*.csv

# Pre-uninstall
%preun
%systemd_preun %{name}.service

# Post-uninstall
%postun
%systemd_postun_with_restart %{name}.service

# Files
%files -f %{EXTRA_DIST}
%defattr(-,root,root)
%dir /var/run/%{name}
%dir %attr(750,root,root) %{_sharedstatedir}/%{name}/
%attr(755,root,root) %{_sysconfdir}/init.d/%{name}
%attr(755,root,root) %{_libexecdir}/%{name}/
%config(noreplace) %attr(640,root,root) %{_sharedstatedir}/%{name}/app-custom-match.conf
%config(noreplace) %attr(660,root,root) %{_sysconfdir}/%{name}.conf
%{_sbindir}/%{name}
%{_mandir}/man5/*
%{_mandir}/man8/*

# vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
