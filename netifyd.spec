# Netify DPI Daemon

%bcond_without clearos
%bcond_without systemd

%define netify_conf deploy/%{name}.conf
%define netify_init deploy/%{name}.init
%define netify_tmpf deploy/%{name}.tmpf
%define netify_systemd_exec deploy/exec-pre.sh
%define netify_systemd_unit deploy/%{name}.service

%if %{with clearos}
%define netify_conf deploy/clearos/%{name}.conf
%define netify_init deploy/clearos/%{name}.init
%define netify_tmpf deploy/clearos/%{name}.tmpf
%define netify_systemd_exec deploy/clearos/exec-pre.sh
%endif

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
BuildRequires: libmnl-devel
BuildRequires: libnetfilter_conntrack-devel
BuildRequires: libpcap-devel
BuildRequires: libtool
BuildRequires: ncurses-devel
BuildRequires: pkgconfig
BuildRequires: zlib-devel
%if %{with clearos}
Requires: app-network-core
Requires: ncurses
Requires: webconfig-httpd
%endif
%if %{with systemd}
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
%{configure}

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

%if %{without systemd}
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
%if %{with systemd}
%systemd_post %{name}.service
%endif

uuid=$(egrep '^uuid' %{_sysconfdir}/%{name}.conf | sed -e "s/^uuid[[:space:]]*=[[:space:]]*\([A-NP-Z0-9-]*\)$/\1/")
if [ -z "$uuid" -o "$uuid" == "00-00-00-00" ]; then
    uuid=$(%{_sbindir}/%{name} -U 2>/dev/null)
    if [ -z "$uuid" ]; then
        echo "Error generating UUID."
    else
        sed -e "s/^uuid[[:space:]]*=[[:space:]]*00-00-00-00/uuid = $uuid/" -i %{_sysconfdir}/%{name}.conf
    fi
fi

if [ ! -z "$uuid" ]; then
    echo "Your Netify Site UUID is: $(tput smso)$uuid$(tput rmso)"
    echo "Follow this link to provision your site: https://www.egloo.ca/login"
fi

rm -f %{_sharedstatedir}/%{name}/*.csv

# Pre uninstall
%preun
%if %{with systemd}
%systemd_preun %{name}.service
%endif

# Post uninstall
%postun
%if %{with systemd}
%systemd_postun_with_restart %{name}.service
%endif

# Files
%files
%defattr(-,root,root)
%if %{without systemd}
%dir /var/run/%{name}
%attr(755,root,root) %{_sysconfdir}/init.d/%{name}
%else
%attr(644,root,root) %{_tmpfilesdir}/%{name}.conf
%attr(644,root,root) %{_unitdir}/%{name}.service
%attr(755,root,root) %{_libexecdir}/%{name}/
%endif
%dir %attr(750,root,webconfig) %{_sharedstatedir}/%{name}/
%attr(640,root,webconfig) %{_sharedstatedir}/%{name}/app-custom-match.conf
%config(noreplace) %attr(660,root,webconfig) %{_sysconfdir}/%{name}.conf
%{_sbindir}/%{name}
%{_mandir}/man5/*
%{_mandir}/man8/*

# vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
