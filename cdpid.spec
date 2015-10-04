# ClearSync Process Watch Plugin RPM spec
Name: cdpid
Version: 1.0
Release: 10%{dist}
Vendor: ClearFoundation
License: GPL
Group: System/Daemons
Packager: ClearFoundation
Source: %{name}-%{version}.tar.gz
BuildRoot: /var/tmp/%{name}-%{version}
Requires: /usr/bin/systemctl
Requires: webconfig-httpd
Requires: app-network-core
BuildRequires: autoconf >= 2.63
BuildRequires: automake
BuildRequires: pkgconfig
BuildRequires: libtool
BuildRequires: libpcap-devel
BuildRequires: json-c-devel
BuildRequires: libcurl
BuildRequires: zlib-devel
Summary: ClearOS Deep Packet Inspection Daemon
Requires(pre): /sbin/ldconfig

%description
Deep Packet Inspection Daemon (DPI) based off of nDPI (http://www.ntop.org/products/deep-packet-inspection/ndpi/).
Report bugs to: http://www.clearfoundation.com/docs/developer/bug_tracker/

# Build
%prep
%setup -q
./autogen.sh
%{configure}

%build
make %{?_smp_mflags}

# Install
%install
make install DESTDIR=$RPM_BUILD_ROOT
rm -rf $RPM_BUILD_ROOT/%{_libdir}
rm -rf $RPM_BUILD_ROOT/%{_includedir}
rm -rf $RPM_BUILD_ROOT/%{_bindir}
mkdir -vp ${RPM_BUILD_ROOT}/%{_sharedstatedir}/cdpid
install -D -m 755 deploy/exec-pre.sh %{buildroot}/%{_libexecdir}/cdpid/exec-pre.sh
install -D -m 644 deploy/cdpid.service %{buildroot}/lib/systemd/system/cdpid.service
install -D -m 644 deploy/cdpid.tmpf %{buildroot}/%{_tmpfilesdir}/cdpid.conf

# Clean-up
%clean
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT

# Post install
%post
/sbin/ldconfig
/usr/bin/systemctl enable cdpid.service -q
/usr/bin/systemctl restart cdpid -q

# Post uninstall
%postun
/sbin/ldconfig
/usr/bin/systemctl stop cdpid -q
/usr/bin/systemctl disable cdpid.service -q

# Files
%files
%defattr(-,root,root)
%{_sbindir}/cdpid
%attr(750,root,webconfig) %{_sharedstatedir}/cdpid/
%attr(755,root,root) %{_libexecdir}/cdpid/
%attr(755,root,root) /lib/systemd/system
%attr(755,root,root) %{_tmpfilesdir}

# vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
