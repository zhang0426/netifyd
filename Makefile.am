# Netify Agent Top-Level Automake File
# Copyright (C) 2016-2018 eGloo, Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

SUBDIRS = libs/inih libs/ndpi include src deploy doc tests

EXTRA_DIST = autogen.sh debian/compat \
	util/generate-json-include.sh util/generate-protocol-csv.sh \
	libs/gperftools libs/libmnl libs/libnetfilter-conntrack libs/libnfnetlink

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

if HAVE_OSC
deploy-osc-update: dist-git
	./autogen.sh && \
		./configure --prefix=/usr --includedir=\${prefix}/include \
		--mandir=\${prefix}/share/man --sysconfdir=/etc --localstatedir=/var

	$(MAKE) clean
	$(MAKE) -C deploy/debian

	(cd $(HOME)/netify-osc/home\:egloo/netifyd && $(osc) update)
	cp deploy/debian/debian.changelog $(HOME)/netify-osc/home\:egloo/netifyd
	cp deploy/debian/debian.control $(HOME)/netify-osc/home\:egloo/netifyd
	cp deploy/debian/debian.postinst $(HOME)/netify-osc/home\:egloo/netifyd
	chmod a+x $(HOME)/netify-osc/home\:egloo/netifyd/debian.postinst
	cp deploy/debian/debian.rules $(HOME)/netify-osc/home\:egloo/netifyd
	cp deploy/debian/netifyd.dsc $(HOME)/netify-osc/home\:egloo/netifyd
	cp netifyd.spec $(HOME)/netify-osc/home\:egloo/netifyd
	grep -v 'gperftools-devel' netifyd.spec > $(HOME)/netify-osc/home\:egloo/netifyd/netifyd-CentOS_6.spec
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
		PKG_CONFIG=${BUILDROOT}/target-usg-3p/output/host/bin/pkg-config \
		./configure \
		--build=x86_64-pc-linux-gnu --host=mips-linux \
		--prefix=/usr --sysconfdir=/etc --localstatedir=/var --sharedstatedir=/var/lib \
		--disable-shared --enable-static --enable-watchdogs --enable-lean-and-mean \
		--disable-json-c --disable-libtcmalloc --disable-plugins --without-systemdsystemunitdir

	$(MAKE) clean
	$(MAKE) -j 17
	$(MAKE) DESTDIR=$(abs_top_builddir)/$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu) install

	$(STRIP) $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/usr/sbin/netifyd

	$(INSTALL) -d -m 0755 \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/var/run/netifyd
	$(INSTALL) -D -m 0640 deploy/watchdog.cron \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/etc/cron.d/netifyd
	$(INSTALL) -D -m 0755 deploy/debian/debian.init \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/etc/init.d/netifyd
	$(INSTALL) -D -m 0640 deploy/netifyd.default \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/etc/default/netifyd
	$(INSTALL) -D -m 0755 deploy/install-edgeos.sh \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/install.sh

	rm -rf $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/usr/lib
	rm -rf $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/usr/include
	rm -rf $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/usr/share/man

	rm -f $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu).tar.gz
	$(AMTAR) -czf $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu).tar.gz \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)
	rm -rf $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)

deploy-debug: all
	scp src/.libs/netifyd gw:/usr/sbin/
	scp src/.libs/libnetifyd.so.0.0.0 gw:/usr/lib64/
