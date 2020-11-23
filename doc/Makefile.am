# Netify Agent Documentation Automake File
# Copyright (C) 2016-2020 eGloo, Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = BUGS.md BUILD-openwrt.md OVERVIEW.md netifyd.conf-sample README-JSON-socket-example.md json-socket-example.sh json-socket-filter.jq

sharedatadir = $(datadir)/netifyd
sharedata_DATA = netifyd.conf-sample README-JSON-socket-example.md json-socket-example.sh json-socket-filter.jq

dist_man_MANS = netifyd.8 netifyd.conf.5

.5.pdf:
	man -t "./$<" | ps2pdf - "$@"
.8.pdf:
	man -t "./$<" | ps2pdf - "$@"
