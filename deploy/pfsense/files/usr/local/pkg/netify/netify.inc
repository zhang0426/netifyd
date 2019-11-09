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
require_once("filter.inc");
require_once("functions.inc");
require_once("pfsense-utils.inc");
require_once("pkg-utils.inc");
require_once("service-utils.inc");
require_once("xmlrpc_client.inc");

require_once("/usr/local/pkg/netify/netify_defs.inc");

// Explicitly declare this as global so it works through function call includes 
global $g, $config, $rebuild_rules;

if (! is_array($config['installedpackages'])) {
	$config['installedpackages'] = array();
}
if (! is_array($config['installedpackages']['netifyglobal'])) {
	$config['installedpackages']['netifyglobal'] = array();
}

function netify_is_running() {
	global $config, $g;

	return isvalidpid("{$g['varrun_path']}/netifyd.pid");
}

function netify_stop() {
	global $config, $g;

	if (isvalidpid("{$g['varrun_path']}/netifyd.pid")) {
		syslog(LOG_NOTICE, "[Netify] Netify STOP...");
		killbypid("{$g['varrun_path']}/netifyd.pid");

		// Wait up to 10 seconds for Netify to terminate
		$count = 0;
		do {
			if (! isvalidpid("{$g['varrun_path']}/netifyd.pid"))
				break;
			sleep(1);
			$count++;
		} while ($count < 10);
	}

	unlink_if_exists("{$g['varrun_path']}/netifyd.pid");
}

function netify_start($background = FALSE) {
	global $config, $g;

	$netifysbindir = NETIFY_SBINDIR;

	if (! isvalidpid("{$g['varrun_path']}/netifyd.pid")) {

		syslog(LOG_NOTICE, "[Netify] Netify Agent START...");

		if ($background)
			mwexec_bg("{$netifysbindir}netifyd -I lo");
		else
			mwexec("{$netifysbindir}netifyd -I lo");
	}
}

function netify_restart() {
	global $g, $config;

	netify_stop();
	sleep(2);
	netify_start(TRUE);
}

function netify_reload($signal = 'SIGHUP') {
	global $config, $g;

	if (isvalidpid("{$g['varrun_path']}/netifyd.pid")) {
		syslog(LOG_NOTICE, "[Netify] Netify Agent RELOAD CONFIG...");
		mwexec_bg("/bin/pkill -{$signal} -F {$g['varrun_path']}/netifyd.pid");
	}
}

function sync_netify_package_config() {
	netify_create_rc();
}

function netify_create_rc() {
	global $config, $g;

	$netifydir = NETIFY_CONFDIR;
	$netifysbindir = NETIFY_SBINDIR;
	$rcdir = RCFILEPREFIX;	

	/* If no interfaces are configured (LAN/WAN)...
	if (! ... ) {
		unlink_if_exists("{$rcdir}netifyd.sh");
		return;
	}
	*/

	$rc_start = "{$rcdir}/netifyd start"
	$rc_stop = "{$rcdir}/netifyd stop"

	$netify_sh_text = <<<EOD
#!/bin/sh
########
# This file was automatically generated
# by the pfSense service handler.
######## Start of main netify.sh

rc_start() {

	### Lock out other start signals until we are done
	/usr/bin/touch {$g['varrun_path']}/netify_pkg_starting.lck
	{$rc_start}

	### Remove the lock since we have started all interfaces
	if [ -f {$g['varrun_path']}/netify_pkg_starting.lck ]; then
		sleep 2
		/bin/rm {$g['varrun_path']}/netify_pkg_starting.lck
	fi
}

rc_stop() {
	{$rc_stop}
}

case $1 in
	start)
		if [ ! -f {$g['varrun_path']}/netify_pkg_starting.lck ]; then
			rc_start
		else
			/usr/bin/logger -p daemon.info -i -t NetifyStartup "Ignoring additional START command since Netify is already starting..."
		fi
		;;
	stop)
		rc_stop
		;;
	restart)
		if [ ! -f {$g['varrun_path']}/netify_pkg_starting.lck ]; then
			rc_stop
			rc_start
		else
			/usr/bin/logger -p daemon.info -i -t NetifyRestart "Ignoring RESTART command since Netify is already starting..."
		fi
		;;
esac

EOD;

	@file_put_contents("{$rcdir}netify.sh", $netify_sh_text);
	@chmod("{$rcdir}netify.sh", 0755);
}

?>
