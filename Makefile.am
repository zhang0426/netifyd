AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = ${ACLOCAL_FLAGS} -I m4

SUBDIRS = inih ndpi src util deploy doc

EXTRA_DIST = autogen.sh include debian/compat \
	util/generate-json-include.sh util/generate-protocol-csv.sh

DISTCHECK_CONFIGURE_FLAGS = \
	--with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

install-osc: netifyd.spec deploy/debian/debian.changelog deploy/debian/debian.control deploy/debian/debian.rules deploy/debian/netifyd.dsc dist-gzip
if !HAVE_OSC
    $(error osc not found, please install)
endif
	cp deploy/debian/debian.changelog ./osc/home\:egloo/netifyd
	cp deploy/debian/debian.control ./osc/home\:egloo/netifyd
	cp deploy/debian/debian.rules ./osc/home\:egloo/netifyd
	cp deploy/debian/netifyd.dsc ./osc/home\:egloo/netifyd
	cp netifyd.spec ./osc/home\:egloo/netifyd
	cp $(PACKAGE)-$(VERSION).tar.gz ./osc/home\:egloo/netifyd
	(cd ./osc/home\:egloo/netifyd && $(osc) status)
	(cd ./osc/home\:egloo/netifyd && $(osc) commit -m 'Updated to latest sources.')

