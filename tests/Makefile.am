# Netify Agent Tests Automake File
# Copyright (C) 2016-2018 eGloo, Incorporated
#
# This is free software, licensed under the GNU General Public License v3.

AUTOMAKE_OPTIONS = foreign

test:
	TESTDIR="$(abs_srcdir)" ./test-pcap-samples.sh

clean-local: clean-local-check
clean-local-check:
	-rm -rf pcap-test/*.cap

.PHONY: test clean-local-check
