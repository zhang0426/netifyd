# Netify DPI Daemon

# Build conditionals:
# Default values: --with clearos --with systemd
%{!?_with_clearos: %{!?_without_clearos: %define _with_clearos 1}}
%{!?_with_systemd: %{!?_without_systemd: %define _with_systemd 1}}

# Configure conditionals
# Default values: --with conntrack --with inotify --with ncurses --with netlink
%{!?_with_conntrack: %{!?_without_conntrack: %define _with_conntrack --enable-conntrack}}
%{!?_with_inotify: %{!?_without_inotify: %define _with_inotify --enable-inotify}}
%{!?_with_ncurses: %{!?_without_ncurses: %define _with_ncurses --enable-ncurses}}
%{!?_with_netlink: %{!?_without_netlink: %define _with_netlink --enable-netlink}}

# Generic configuration files
%define netify_conf deploy/%{name}.conf
%define netify_init deploy/%{name}.init
%define netify_tmpf deploy/%{name}.tmpf
%define netify_systemd_exec deploy/exec-pre.sh
%define netify_systemd_unit deploy/%{name}.service

# ClearOS configuration file overrides
%if %{?_with_clearos:1}%{!?_with_clearos:0}
%define netify_conf deploy/clearos/%{name}.conf
%define netify_init deploy/clearos/%{name}.init
%define netify_tmpf deploy/clearos/%{name}.tmpf
%define netify_systemd_exec deploy/clearos/exec-pre.sh
%endif

# RPM package details
Name: netifyd
Summary: Netify DPI Daemon
Version: 1.22
Release: 1%{dist}
Vendor: eGloo Incorporated
License: GPL
Group: System/Daemons
Packager: eGloo Incorporated
Source: %{name}-%{version}.tar.gz
BuildRoot: /var/tmp/%{name}-%{version}
BuildRequires: autoconf >= 2.63
BuildRequires: automake
BuildRequires: bc
BuildRequires: json-c-devel
BuildRequires: libcurl-devel
%if %{?_with_conntrack:1}%{!?_with_conntrack:0}
BuildRequires: libmnl-devel
BuildRequires: libnetfilter_conntrack-devel
%endif
BuildRequires: libpcap-devel
BuildRequires: libtool
%{?_with_ncurses:BuildRequires: ncurses-devel}
BuildRequires: pkgconfig
BuildRequires: zlib-devel
%if %{?_with_clearos:1}%{!?_with_clearos:0}
Requires: app-network-core
Requires: ncurses
Requires: webconfig-httpd
%endif
%if %{?_with_systemd:1}%{!?_with_systemd:0}
%{?systemd_requires}
BuildRequires: systemd
%endif

%description
Netify provides visibility into the traffic on your network along with the option to take an active role (on supported devices) in stopping/shaping undesirable traffic from recurring on your network.
Report bugs to: https://github.com/eglooca/netify-daemon/issues

# Prepare
%prep
%setup -q
./autogen.sh
%{configure} \
    %{?_with_conntrack} \
    %{?_with_inotify} \
    %{?_with_ncurses} \
    %{?_with_netilink}

# Build
%build
make %{?_smp_mflags}

# Install
%install
make install DESTDIR=%{buildroot}
rm -rf %{buildroot}/%{_bindir}
rm -rf %{buildroot}/%{_includedir}
rm -rf %{buildroot}/%{_libdir}
mkdir -p %{buildroot}/%{_sharedstatedir}/%{name}
mkdir -p %{buildroot}/%{_sysconfdir}
mkdir -p %{buildroot}/var/run
install -D -m 0644 deploy/app-custom-match.conf %{buildroot}/%{_sharedstatedir}/%{name}/app-custom-match.conf
install -D -m 0660 %{netify_conf} %{buildroot}/%{_sysconfdir}/%{name}.conf
install -d -m 0755 %{buildroot}/var/run/%{name}

%if %{?_without_systemd:1}%{!?_without_systemd:0}
install -D -m 0755 %{netify_init} %{buildroot}/%{_sysconfdir}/init.d/%{name}
%else
install -D -m 0644 %{netify_tmpf} %{buildroot}/%{_tmpfilesdir}/%{name}.conf
install -D -m 0644 %{netify_systemd_unit} %{buildroot}/%{_unitdir}/%{name}.service
install -D -m 0755 %{netify_systemd_exec} %{buildroot}/%{_libexecdir}/%{name}/exec-pre.sh
%endif

# Clean-up
%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

# Post install
%post
%if %{?_with_systemd:1}%{!?_with_systemd:0}
%systemd_post %{name}.service
%endif

# Generate a new UUID if this is our first install
uuid=$(egrep '^uuid' %{_sysconfdir}/%{name}.conf | sed -e "s/^uuid[[:space:]]*=[[:space:]]*\([A-NP-Z0-9-]*\)$/\1/")
if [ -z "$uuid" -o "$uuid" == "00-00-00-00" ]; then
    uuid=$(%{_sbindir}/%{name} -U 2>/dev/null)
    if [ -z "$uuid" ]; then
        echo "Error generating UUID."
    else
        sed -e "s/^uuid[[:space:]]*=[[:space:]]*00-00-00-00/uuid = $uuid/" -i %{_sysconfdir}/%{name}.conf
    fi
fi

# Display new or existing UUID
if [ ! -z "$uuid" ]; then
    echo "Your Netify Site UUID is: $(tput smso)$uuid$(tput rmso)"
    echo "Follow this link to provision your site: https://www.egloo.ca/login"
fi

# Remove old CSV configuration files
rm -f %{_sharedstatedir}/%{name}/*.csv

# Pre uninstall
%preun
%if %{?_with_systemd:1}%{!?_with_systemd:0}
%systemd_preun %{name}.service
%endif

# Post uninstall
%postun
%if %{?_with_systemd:1}%{!?_with_systemd:0}
%systemd_postun_with_restart %{name}.service
%endif

# Files
%files
%defattr(-,root,root)
%if %{?_without_systemd:1}%{!?_without_systemd:0}
%dir /var/run/%{name}
%attr(755,root,root) %{_sysconfdir}/init.d/%{name}
%else
%attr(644,root,root) %{_tmpfilesdir}/%{name}.conf
%attr(644,root,root) %{_unitdir}/%{name}.service
%attr(755,root,root) %{_libexecdir}/%{name}/
%endif
%if %{?_with_clearos:1}%{!?_with_clearos:0}
%dir %attr(750,root,webconfig) %{_sharedstatedir}/%{name}/
%attr(640,root,webconfig) %{_sharedstatedir}/%{name}/app-custom-match.conf
%config(noreplace) %attr(660,root,webconfig) %{_sysconfdir}/%{name}.conf
%else
%dir %attr(750,root,root) %{_sharedstatedir}/%{name}/
%attr(640,root,root) %{_sharedstatedir}/%{name}/app-custom-match.conf
%config(noreplace) %attr(660,root,root) %{_sysconfdir}/%{name}.conf
%endif
%{_sbindir}/%{name}
%{_mandir}/man5/*
%{_mandir}/man8/*

# vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
