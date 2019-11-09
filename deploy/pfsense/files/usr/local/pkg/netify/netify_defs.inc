<?php
/*
 * netify_defs.inc
 *
 * Netify for pfSense
 * Copyright (C) 2015-2019 eGloo Incorporated
 *
 * This program comes with ABSOLUTELY NO WARRANTY.
 *
 * This is free software, and you are welcome to redistribute it
 * under certain conditions according to the GNU General Public
 * License version 3, or (at your option) any later version.
 */

global $g, $config;

if (! defined("NETIFY_BASEDIR"))
	define("NETIFY_BASEDIR", "/usr/local/");

if (! defined("NETIFY_SBINDIR"))
	define("NETIFY_SBINDIR", NETIFY_BASEDIR . "sbin/");

if (! defined("NETIFY_CONFDIR"))
	define("NETIFY_CONFDIR", NETIFY_BASEDIR . "etc/netify.d");

if (! defined("NETIFYD_VERSION")) {
	$netifysbindir = NETIFY_SBINDIR;
	$netifyver = exec_command("{$netifysbindir}/netifyd --version 2>&1 | head -n 1 | cut -d' ' -f2 | cut -d '/' -f2");
	define("NETIFY_VERSION", $netifyver);
}

?>
