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

if (! defined('NETIFY_PREFIX'))
    define('NETIFY_PREFIX', '/usr/local/');

if (! defined('NETIFY_SBINDIR'))
    define('NETIFY_SBINDIR', NETIFY_PREFIX . 'sbin/');

if (! defined('NETIFY_CONFDIR'))
    define('NETIFY_CONFDIR', NETIFY_PREFIX . 'etc/netify.d/');

if (! defined('NETIFYD_UUID_AGENT'))
    define('NETIFYD_UUID_AGENT', NETIFY_CONFDIR . 'agent.uuid');

if (! defined('NETIFY_URL_MANAGER_API'))
    define('NETIFY_URL_MANAGER_API', 'https://manager.netify.ai/');

if (! defined('NETIFY_URL_AGENT_STATUS')) {
    define('NETIFY_URL_AGENT_STATUS',
        NETIFY_URL_MANAGER_API . 'api/v1/deployment/agents/status/');
}

if (! defined('NETIFYD_VOLATILE_STATEDIR'))
    define('NETIFYD_VOLATILE_STATEDIR', '/var/run/netifyd/');

if (! defined('NETIFYD_VERSION')) {
    $netifyver = exec_command(NETIFY_SBINDIR .
        'netifyd --version 2>&1 | head -n 1 | cut -d\' \' -f2 | cut -d \'/\' -f2');
    define('NETIFYD_VERSION', $netifyver);
}

if (! defined('NETIFYD_CONFFILE'))
    define('NETIFYD_CONFFILE', NETIFY_PREFIX . 'etc/netifyd.conf');

if (! define('NETIFYD_JSON_STATUS'))
    define('NETIFYD_JSON_STATUS', '/var/run/netifyd/status.json');
?>
