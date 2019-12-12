# Netify Agent Top-Level Automake File
# Copyright (C) 2016-2019 eGloo, Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

SUBDIRS_EXTRA =
if USE_LIBTCMALLOC_BUNDLED
SUBDIRS_EXTRA += libs/gperftools
endif

SUBDIRS = libs/inih libs/ndpi $(SUBDIRS_EXTRA) include src deploy doc tests
DIST_SUBDIRS = $(SUBDIRS)

EXTRA_DIST = LICENSE autogen.sh debian/compat \
	util/generate-json-include.sh util/generate-protocol-csv.sh \
	libs/gperftools libs/json

DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir) \
	--with-tmpfilesdir=$$dc_install_base/$(tmpfilesdir)

pkgconfig_DATA = lib@PACKAGE_TARNAME@.pc

dist-git:
	rm -f $(PACKAGE)-$(VERSION).tar*
	git archive --prefix=$(PACKAGE)-$(VERSION)/ --output=$(PACKAGE)-$(VERSION).tar HEAD
	p=`pwd`; (echo .; git submodule foreach) | while read entering path; do \
		temp="$${path%\'}"; \
		temp="$${temp#\'}"; \
		path=$$temp; \
		[ "$$path" = "" ] && continue; \
		(cd $$path && \
			git archive --prefix=$(PACKAGE)-$(VERSION)/$$path/ --output=/tmp/$(PACKAGE)-submodule.tar HEAD && \
			$(AMTAR) --concatenate --file="$$p/$(PACKAGE)-$(VERSION).tar" /tmp/$(PACKAGE)-submodule.tar && \
			rm -f /tmp/$(PACKAGE)-submodule.tar \
		); \
	done
	gzip $(PACKAGE)-$(VERSION).tar

netifyd-CentOS_8.spec: netifyd.spec
	grep -v 'gperftools-devel' netifyd.spec > netifyd-CentOS_8.spec

if HAVE_OSC
deploy-osc-update: netifyd-CentOS_8.spec dist-git
	./autogen.sh && \
		./configure --prefix=/usr --includedir=\${prefix}/include \
		--mandir=\${prefix}/share/man --sysconfdir=/etc --localstatedir=/var

	$(MAKE) clean
	$(MAKE) -C deploy/debian

	(cd $(HOME)/netify-osc/home\:egloo/netifyd && $(osc) update)
	cp deploy/debian/debian.changelog $(HOME)/netify-osc/home\:egloo/netifyd
	cp deploy/debian/debian.conffiles $(HOME)/netify-osc/home\:egloo/netifyd
	cp deploy/debian/debian.control $(HOME)/netify-osc/home\:egloo/netifyd
	cp deploy/debian/debian.postinst $(HOME)/netify-osc/home\:egloo/netifyd
	chmod a+x $(HOME)/netify-osc/home\:egloo/netifyd/debian.postinst
	cp deploy/debian/debian.rules $(HOME)/netify-osc/home\:egloo/netifyd
	cp deploy/debian/netifyd.dsc $(HOME)/netify-osc/home\:egloo/netifyd
	cp netifyd*.spec $(HOME)/netify-osc/home\:egloo/netifyd
	(cd $(HOME)/netify-osc/home\:egloo/netifyd && $(osc) rm --force $(PACKAGE)-*.tar.gz || true)
	cp $(PACKAGE)-$(VERSION).tar.gz $(HOME)/netify-osc/home\:egloo/netifyd
	(cd $(HOME)/netify-osc/home\:egloo/netifyd && $(osc) add $(PACKAGE)-*.tar.gz)
	(cd $(HOME)/netify-osc/home\:egloo/netifyd && $(osc) status)

deploy-osc-commit: deploy-osc-update
	(cd $(HOME)/netify-osc/home\:egloo/netifyd && $(osc) commit -m 'Updated to latest sources.')
endif

deploy-edgeos:
	rm -rf $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)
	./autogen.sh && \
		PKG_CONFIG=$(abs_top_builddir)/../../build/buildroot/target-usg-3p/output/host/bin/pkg-config \
		./configure \
		--build=x86_64-pc-linux-gnu --host=mips-linux \
		--prefix=/usr --sysconfdir=/etc --localstatedir=/var --sharedstatedir=/var/lib \
		--disable-shared --enable-static --enable-watchdogs --enable-lean-and-mean \
		--disable-libtcmalloc --disable-plugins --without-systemdsystemunitdir

	$(MAKE) clean
	$(MAKE) -j 17
	$(MAKE) DESTDIR=$(abs_top_builddir)/$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu) install

	$(STRIP) $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/usr/sbin/netifyd

	$(INSTALL) -d -m 0755 \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/usr/share/netifyd/netify_edgeos

	$(INSTALL) -D -m 0755 deploy/edgeos/netify_edgeos/install.py \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/usr/share/netifyd/netify_edgeos/install.py
	$(INSTALL) -D -m 0644 deploy/edgeos/netify_edgeos/netify_edgeos.py \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/usr/share/netifyd/netify_edgeos/netify_edgeos.py
	$(INSTALL) -D -m 0755 deploy/edgeos/netify_edgeos/options.py \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/usr/share/netifyd/netify_edgeos/options.py
	$(INSTALL) -D -m 0755 deploy/edgeos/netify_edgeos/watchdog.py \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/usr/share/netifyd/netify_edgeos/watchdog.py
	ln -s ./usr/share/netifyd/netify_edgeos \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/netify_edgeos

	$(INSTALL) -D -m 0755 deploy/edgeos/install.sh \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/install.sh

	$(INSTALL) -D -m 0640 deploy/edgeos/netifyd.conf \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/etc/netifyd.conf
	$(INSTALL) -D -m 0640 deploy/edgeos/watchdog.cron \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/etc/cron.d/netifyd
	$(INSTALL) -D -m 0755 deploy/debian/debian.init \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/etc/init.d/netifyd
	$(INSTALL) -D -m 0640 deploy/netifyd.default \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/etc/default/netifyd

	rm -rf $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/usr/lib
	rm -rf $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/usr/include
	rm -rf $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/usr/share/man

	rm -f $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu).tar.gz
	$(AMTAR) -czf $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu).tar.gz \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)
	rm -rf $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)

deploy-rpm:
	$(MAKE) dist-gzip
	cp -v $(PACKAGE)-$(VERSION).tar.gz ~/rpmbuild/SOURCES/
	rpmbuild -ba $(PACKAGE)_ClearOS8.spec

deploy-freebsd:
	./autogen.sh \
		CC=clang CXX=clang++ CPPFLAGS=-I/usr/local/include \
		./configure \
			--disable-conntrack \
			--disable-inotify
	$(MAKE) -C deploy
	rm -rf deploy/freebsd/work
	$(MAKE) dist-gzip
	sudo cp -v $(PACKAGE)-$(VERSION).tar.gz /usr/ports/distfiles/
	make -C deploy/freebsd clean
	make -C deploy/freebsd makesum
	make -C deploy/freebsd package DISABLE_VULNERABILITIES=yes
	ls -lh deploy/freebsd/work/pkg/*.txz

deploy-pfsense:
	make -C deploy/pfsense clean
	make -C deploy/pfsense package DISABLE_VULNERABILITIES=yes
	ls -lh deploy/pfsense/work/pkg/*.txz

deploy-debug: all
	scp src/.libs/netifyd gw:/usr/sbin/
	scp src/.libs/libnetifyd.so.0.0.0 gw:/usr/lib64/

deploy-debug-archive: all
	mkdir -p /tmp/netifyd-debug/usr/{sbin,lib64}
	cp src/.libs/netifyd /tmp/netifyd-debug/usr/sbin/
	cp src/.libs/libnetifyd.so.0.0.0 /tmp/netifyd-debug/usr/lib64/
	cd /tmp/netifyd-debug && tar -cvzf ../netifyd-debug.tar.gz *
