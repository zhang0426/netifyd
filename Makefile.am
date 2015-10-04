AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

SUBDIRS = ndpi src

EXTRA_DIST = autogen.sh ndpi include deploy/cdpid.service deploy/cdpid.tmpf deploy/exec-pre.sh

dist-hook:
	make -C $(distdir)/ndpi clean
