AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

EXTRA_DIST = nd-json-config-type.txt.in \
	nd-json-object-type.txt.in nd-json-result-code.txt.in

netifyincludedir = $(includedir)/netifyd
netifyinclude_HEADERS = nd-conntrack.h nd-detection.h nd-flow.h nd-inotify.h \
	nd-json-config-type.h nd-json.h nd-json-object-type.h nd-json-result-code.h \
	nd-ndpi.h nd-netlink.h nd-plugin.h nd-sha1.h nd-socket.h nd-thread.h nd-upload.h \
	nd-util.h netifyd.h

BUILT_SOURCES = nd-json-object-type.h nd-json-result-code.h nd-json-config-type.h
CLEANFILES = nd-json-object-type.h nd-json-result-code.h nd-json-config-type.h

nd-json-object-type.h: nd-json-object-type.txt.in
	../util/generate-json-include.sh c-object-type >$@

nd-json-result-code.h: nd-json-result-code.txt.in
	../util/generate-json-include.sh c-result-code >$@

nd-json-config-type.h: nd-json-config-type.txt.in
	../util/generate-json-include.sh c-config-type >$@

