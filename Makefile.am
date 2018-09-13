AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

SUBDIRS = libs/inih libs/ndpi include src deploy doc

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
deploy-osc-update: netifyd.spec deploy/debian/debian.changelog deploy/debian/debian.control deploy/debian/debian.rules deploy/debian/netifyd.dsc dist-git
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

deploy-edgeos: all
	rm -rf $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)
	$(INSTALL) -d -m 0755 $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)
	$(INSTALL) -d -m 0750 $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/var/lib/netifyd
	$(INSTALL) -d -m 0755 $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/run/netifyd

	$(INSTALL) -D -m 0755 src/netifyd \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/usr/sbin/netifyd
	$(STRIP) $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/usr/sbin/netifyd
	$(INSTALL) -D -m 0640 deploy/app-custom-match.conf \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/etc/netify.d/netify-sink.conf
	$(INSTALL) -D -m 0640 deploy/netifyd.conf \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/etc/netifyd.conf
	$(INSTALL) -D -m 0640 deploy/watchdog.cron \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/etc/cron.d/netifyd
	$(INSTALL) -D -m 0755 deploy/netifyd-debian.init \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/etc/init.d/netifyd
	$(INSTALL) -D -m 0755 deploy/functions.sh \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/usr/libexec/netifyd/functions.sh
	$(INSTALL) -D -m 0755 deploy/watchdog.sh \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/usr/libexec/netifyd/watchdog.sh
	$(INSTALL) -D -m 0640 deploy/netifyd.default \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/etc/default/netifyd
	$(INSTALL) -D -m 0755 deploy/install-edgeos.sh \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/install.sh

	rm -f $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu).tar.gz
	$(AMTAR) -czf $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu).tar.gz \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)
	rm -rf $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)

deploy-debug: all
	scp src/.libs/netifyd gw:/usr/sbin/
	scp src/.libs/libnetifyd.so.0.0.0 gw:/usr/lib64/
