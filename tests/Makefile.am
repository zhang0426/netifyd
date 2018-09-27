# Netify Agent Tests Automake File
# Copyright (C) 2016-2018 eGloo, Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

AUTOMAKE_OPTIONS = foreign

EXTRA_DIST = ndpi-pcap-files.txt netifyd-test-pcap.conf \
	test-pcap-logs test-pcap-regression.sh pcap/ssdp.cap.gz

test:
	TESTDIR="$(abs_srcdir)" ./test-pcap-regression.sh

clean-local: clean-local-check
clean-local-check:
	-rm -rf pcap-test/*.cap

.PHONY: test clean-local-check
