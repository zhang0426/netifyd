<?php
/*
 * netify.inc
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

require_once("config.inc");
require_once("pfsense-utils.inc");
require_once("util.inc");
require_once('services.inc');
require_once("service-utils.inc");

require_once("/usr/local/pkg/netify/netify_defs.inc");

function netify_create_rc() {
	$rcfile['file'] = 'netifyd.sh';
	$rcfile['start'] = 'mkdir -p ' .
		NETIFYD_VOLATILE_STATEDIR . "\n\t" .
		NETIFY_PREFIX . "etc/rc.d/netifyd onestart\n\t";
	$rcfile['stop'] = NETIFY_PREFIX . "etc/rc.d/netifyd onestop\n\t";
	write_rcfile($rcfile);
}

function netify_make_directories() {
	safe_mkdir(NETIFYD_VOLATILE_STATEDIR);
}

function netifyd_is_running() {
       return isvalidpid(NETIFYD_VOLATILE_STATEDIR . 'netifyd.pid');
}

function netifyd_get_uuid() {
	$uuid = '00-00-00-00';
	if (file_exists(NETIFYD_UUID_AGENT))
		$uuid = trim(file_get_contents(NETIFYD_UUID_AGENT));
	return $uuid;
}

function netifyd_get_agent_status_url() {
	$uuid = netifyd_get_uuid();
	return sprintf('%s%s', NETIFY_URL_AGENT_STATUS, $uuid);
}

function netify_package_sync() {
	netify_make_directories();
	netify_create_rc();
}

function netify_package_install() {
	netify_create_rc();
}

function netify_package_deinstall() {
}
?>
