AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

SUBDIRS = inih ndpi src util deploy doc

EXTRA_DIST = autogen.sh include debian/compat \
	util/generate-json-include.sh util/generate-protocol-csv.sh \
	gperftools libmnl libnetfilter_conntrack libnfnetlink

DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

if HAVE_OSC
deploy-osc: netifyd.spec deploy/debian/debian.changelog deploy/debian/debian.control deploy/debian/debian.rules deploy/debian/netifyd.dsc dist-gzip
	cp deploy/debian/debian.changelog ./osc/home\:egloo/netifyd
	cp deploy/debian/debian.control ./osc/home\:egloo/netifyd
	cp deploy/debian/debian.rules ./osc/home\:egloo/netifyd
	cp deploy/debian/netifyd.dsc ./osc/home\:egloo/netifyd
	cp netifyd.spec ./osc/home\:egloo/netifyd
	cp $(PACKAGE)-$(VERSION).tar.gz ./osc/home\:egloo/netifyd
	(cd ./osc/home\:egloo/netifyd && $(osc) status)
	(cd ./osc/home\:egloo/netifyd && $(osc) commit -m 'Updated to latest sources.')
endif

deploy-edgeos: src/netifyd
	rm -rf $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)
	$(INSTALL) -d -m 0755 $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)
	$(INSTALL) -d -m 0750 $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/var/lib/netifyd
	$(INSTALL) -d -m 0755 $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/run/netifyd

	$(INSTALL) -D -m 0755 src/netifyd \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/usr/sbin/netifyd
	$(INSTALL) -D -m 0640 deploy/app-custom-match.conf \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/etc/netify.d/netify-sink.conf
	$(INSTALL) -D -m 0640 deploy/netifyd.conf \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/etc/netifyd.conf
	$(INSTALL) -D -m 0755 deploy/netifyd-debian.init \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/etc/init.d/netifyd
	$(INSTALL) -D -m 0755 deploy/functions.sh \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/usr/libexec/netifyd/functions.sh
	$(INSTALL) -D -m 0640 deploy/netifyd.default \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/etc/default/netifyd
	$(INSTALL) -D -m 0755 deploy/install-edgeos.sh \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)/install.sh

	rm -f $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu).tar.gz
	$(AMTAR) -chozf $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu).tar.gz \
		$(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)
	rm -rf $(PACKAGE)-$(VERSION)-edgeos-$(host_cpu)
