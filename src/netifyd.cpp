// Netify Agent
// Copyright (C) 2015-2020 eGloo Incorporated <http://www.egloo.ca>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iomanip>
#include <iostream>
#include <map>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <list>
#include <vector>
#include <locale>
#ifdef HAVE_ATOMIC
#include <atomic>
#endif
#include <regex>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <locale.h>
#include <syslog.h>
#include <fcntl.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <netdb.h>
#include <netinet/in.h>

#include <curl/curl.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <resolv.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#ifdef _ND_USE_CONNTRACK
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#endif

#if defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H)
#include <gperftools/malloc_extension.h>
#endif

#include "INIReader.h"

using namespace std;

#include "netifyd.h"

#include "nd-ndpi.h"
#ifdef _ND_USE_INOTIFY
#include "nd-inotify.h"
#endif
#ifdef _ND_USE_NETLINK
#include "nd-netlink.h"
#endif
#include "nd-json.h"
#include "nd-flow.h"
#include "nd-thread.h"
#ifdef _ND_USE_CONNTRACK
#include "nd-conntrack.h"
#endif
#include "nd-dhc.h"
#include "nd-detection.h"
#include "nd-socket.h"
#include "nd-sink.h"
#include "nd-base64.h"
#ifdef _ND_USE_PLUGINS
#include "nd-plugin.h"
#endif
#include "nd-util.h"
#include "nd-signal.h"

#define ND_STR_ETHALEN     (ETH_ALEN * 2 + ETH_ALEN - 1)

static nd_ifaces ifaces;
static nd_devices devices;
static nd_flows flows;
static nd_stats stats;
static nd_threads threads;
static nd_agent_stats nda_stats;
static nd_packet_stats pkt_totals;
static ostringstream *nd_stats_os = NULL;
static ndSinkThread *thread_sink = NULL;
static ndSocketThread *thread_socket = NULL;
#ifdef _ND_USE_PLUGINS
static nd_plugins plugin_services;
static nd_plugins plugin_tasks;
#endif
static char *nd_conf_filename = NULL;
#ifdef _ND_USE_CONNTRACK
static ndConntrackThread *thread_conntrack = NULL;
#endif
#ifdef _ND_USE_INOTIFY
static ndInotify *inotify = NULL;
static nd_inotify_watch inotify_watches;
#endif
#ifdef _ND_USE_NETLINK
static ndNetlink *netlink = NULL;
nd_device_netlink device_netlink;
#endif
static nd_device_filter device_filters;
static bool nd_detection_stopped_by_signal = false;
static ndDNSHintCache *dns_hint_cache = NULL;
static time_t nd_ethers_mtime = 0;
static nd_interface_addr_map nd_interface_addrs;

nd_device_ethers device_ethers;

nd_global_config nd_config;
pthread_mutex_t *nd_printf_mutex = NULL;

static void nd_usage(int rc = 0, bool version = false)
{
    fprintf(stderr, "%s\n", nd_get_version_and_features().c_str());
    fprintf(stderr, "Copyright (C) 2015-2020 eGloo Incorporated\n"
            "[%s %s]\n", GIT_RELEASE, GIT_DATE);
    if (version) {
        fprintf(stderr, "\nThis application uses nDPI v%s\n"
            "http://www.ntop.org/products/deep-packet-inspection/ndpi/\n", ndpi_revision());
        fprintf(stderr, "\n  This program comes with ABSOLUTELY NO WARRANTY.\n"
            "  This is free software, and you are welcome to redistribute it\n"
            "  under certain conditions according to the GNU General Public\n"
            "  License version 3, or (at your option) any later version.\n");
#ifdef PACKAGE_BUGREPORT
        fprintf(stderr, "\nReport bugs to: %s\n", PACKAGE_BUGREPORT);
#endif
    }
    else {
        fprintf(stderr, "Basic options:\n"
            "\t--status\tdisplay agent status\n"
            "\t--provision\tprovision agent\n"
            "\t--enable-sink\tenable/disable sink uploads\n"
            "\t--disable-sink\n\n"
            "See netifyd(8) and netifyd.conf(5) for further help.\n");
    }

    exit(rc);
}

static void nd_config_init(void)
{
    nd_conf_filename = strdup(ND_CONF_FILE_NAME);

    nd_config.h_flow = stderr;

    nd_config.path_config = NULL;
    nd_config.path_json = NULL;
    nd_config.path_sink_config = strdup(ND_CONF_SINK_PATH);
    nd_config.path_uuid = NULL;
    nd_config.path_uuid_serial = NULL;
    nd_config.path_uuid_site = NULL;
    nd_config.url_sink = NULL;
    nd_config.uuid = NULL;
    nd_config.uuid_serial = NULL;
    nd_config.uuid_site = NULL;

    nd_config.max_backlog = ND_MAX_BACKLOG_KB * 1024;
    nd_config.max_packet_queue = ND_MAX_PKT_QUEUE_KB * 1024;

    nd_config.flags |= ndGF_SSL_VERIFY;
#ifdef _ND_USE_CONNTRACK
    nd_config.flags |= ndGF_USE_CONNTRACK;
#endif
#ifdef _ND_USE_NETLINK
    nd_config.flags |= ndGF_USE_NETLINK;
#endif

    nd_config.max_fhc = ND_MAX_FHC_ENTRIES;
    nd_config.max_tcp_pkts = ND_MAX_TCP_PKTS;
    nd_config.max_udp_pkts = ND_MAX_UDP_PKTS;
    nd_config.sink_max_post_errors = ND_SINK_MAX_POST_ERRORS;
    nd_config.sink_connect_timeout = ND_SINK_CONNECT_TIMEOUT;
    nd_config.sink_xfer_timeout = ND_SINK_XFER_TIMEOUT;
    nd_config.ttl_dns_entry = ND_TTL_IDLE_DHC_ENTRY;
    nd_config.ttl_idle_flow = ND_TTL_IDLE_FLOW * 1000;
    nd_config.ttl_idle_tcp_flow = ND_TTL_IDLE_TCP_FLOW * 1000;
    nd_config.update_interval = ND_STATS_INTERVAL;
    nd_config.update_imf = 1;

    memset(nd_config.digest_sink_config, 0, SHA1_DIGEST_LENGTH);

    nd_config.fhc_save = ndFHC_PERSISTENT;
    nd_config.fhc_purge_divisor = ND_FHC_PURGE_DIVISOR;
}

static int nd_config_load(void)
{
    typedef map<string, string> nd_config_section;

    if (nd_conf_filename == NULL) {
        fprintf(stderr, "Configuration file not defined.\n");
        return -1;
    }

    struct stat extern_config_stat;
    if (stat(nd_conf_filename, &extern_config_stat) < 0) {
        fprintf(stderr, "Can not stat configuration file: %s: %s\n",
            nd_conf_filename, strerror(errno));
        return -1;
    }

    INIReader reader(nd_conf_filename);

    if (reader.ParseError() != 0) {
        fprintf(stderr, "Error while parsing configuration file: %s\n",
            nd_conf_filename);
        return -1;
    }

    // Netify section
    nd_config_section netifyd_section;
    reader.GetSection("netifyd", netifyd_section);

    if (nd_config.uuid == NULL) {
        string uuid = reader.Get("netifyd", "uuid", ND_AGENT_UUID_NULL);
        if (uuid.size() > 0)
            nd_config.uuid = strdup(uuid.c_str());
    }

    if (nd_config.uuid_serial == NULL) {
        string serial = reader.Get("netifyd", "uuid_serial", ND_AGENT_SERIAL_NULL);
        if (serial.size() > 0)
            nd_config.uuid_serial = strdup(serial.c_str());
    }

    if (nd_config.uuid_site == NULL) {
        string uuid_site = reader.Get("netifyd", "uuid_site", ND_SITE_UUID_NULL);
        if (uuid_site.size() > 0)
            nd_config.uuid_site = strdup(uuid_site.c_str());
    }

    string path_uuid = reader.Get(
        "netifyd", "path_uuid", ND_AGENT_UUID_PATH);
    nd_config.path_uuid = strdup(path_uuid.c_str());

    string path_uuid_serial = reader.Get(
        "netifyd", "path_uuid_serial", ND_AGENT_SERIAL_PATH);
    nd_config.path_uuid_serial = strdup(path_uuid_serial.c_str());

    string path_uuid_site = reader.Get(
        "netifyd", "path_uuid_site", ND_SITE_UUID_PATH);
    nd_config.path_uuid_site = strdup(path_uuid_site.c_str());

    string url_sink = reader.Get(
        "netifyd", "url_sink", ND_URL_SINK);
    nd_config.url_sink = strdup(url_sink.c_str());

    nd_config.update_interval = (unsigned)reader.GetInteger(
        "netifyd", "update_interval", ND_STATS_INTERVAL);

    nd_config.sink_connect_timeout = (unsigned)reader.GetInteger(
        "netifyd", "upload_connect_timeout", ND_SINK_CONNECT_TIMEOUT);
    nd_config.sink_xfer_timeout = (unsigned)reader.GetInteger(
        "netifyd", "upload_timeout", ND_SINK_XFER_TIMEOUT);
    ND_GF_SET_FLAG(ndGF_UPLOAD_NAT_FLOWS, reader.GetBoolean(
        "netifyd", "upload_nat_flows", false));

    ND_GF_SET_FLAG(ndGF_JSON_SAVE,
        reader.GetBoolean("netifyd", "json_save", false));

    nd_config.max_backlog = reader.GetInteger(
        "netifyd", "max_backlog_kb", ND_MAX_BACKLOG_KB) * 1024;

    nd_config.max_packet_queue = reader.GetInteger(
        "netifyd", "max_packet_queue_kb", ND_MAX_PKT_QUEUE_KB) * 1024;

    ND_GF_SET_FLAG(ndGF_USE_SINK,
        reader.GetBoolean("netifyd", "enable_sink", false));

    if (netifyd_section.find("ssl_verify") != netifyd_section.end()) {
        ND_GF_SET_FLAG(ndGF_SSL_VERIFY,
            reader.GetBoolean("netifyd", "ssl_verify", true));
    } else if (netifyd_section.find("ssl_verify_peer") != netifyd_section.end()) {
        ND_GF_SET_FLAG(ndGF_SSL_VERIFY,
            reader.GetBoolean("netifyd", "ssl_verify_peer", true));
    }

    ND_GF_SET_FLAG(ndGF_SSL_USE_TLSv1,
        reader.GetBoolean("netifyd", "ssl_use_tlsv1", false));

    nd_config.max_tcp_pkts = (unsigned)reader.GetInteger(
        "netifyd", "max_tcp_pkts", ND_MAX_TCP_PKTS);

    nd_config.max_udp_pkts = (unsigned)reader.GetInteger(
        "netifyd", "max_udp_pkts", ND_MAX_UDP_PKTS);

    nd_config.sink_max_post_errors = (unsigned)reader.GetInteger(
        "netifyd", "sink_max_post_errors", ND_SINK_MAX_POST_ERRORS);

    nd_config.ttl_idle_flow = 1000 * (unsigned)reader.GetInteger(
        "netifyd", "ttl_idle_flow", ND_TTL_IDLE_FLOW);
    nd_config.ttl_idle_tcp_flow = 1000 * (unsigned)reader.GetInteger(
        "netifyd", "ttl_idle_tcp_flow", ND_TTL_IDLE_TCP_FLOW);

    ND_GF_SET_FLAG(ndGF_CAPTURE_UNKNOWN_FLOWS,
        reader.GetBoolean("netifyd", "capture_unknown_flows", false));

    // Flow Hash Cache section
    ND_GF_SET_FLAG(ndGF_USE_FHC,
        reader.GetBoolean("flow_hash_cache", "enable", true));

    string fhc_save_mode = reader.Get(
        "flow_hash_cache", "save", "persistent"
    );

    if (fhc_save_mode == "persistent")
        nd_config.fhc_save = ndFHC_PERSISTENT;
    else if (fhc_save_mode == "volatile")
        nd_config.fhc_save = ndFHC_VOLATILE;
    else
        nd_config.fhc_save = ndFHC_DISABLED;

    nd_config.max_fhc = (size_t)reader.GetInteger(
        "flow_hash_cache", "cache_size", ND_MAX_FHC_ENTRIES);
    nd_config.fhc_purge_divisor = (size_t)reader.GetInteger(
        "flow_hash_cache", "purge_divisor", ND_FHC_PURGE_DIVISOR);

    // DNS Cache section
    ND_GF_SET_FLAG(ndGF_USE_DHC,
        reader.GetBoolean("dns_hint_cache", "enable", true));

    string dhc_save_mode = reader.Get(
        "dns_hint_cache", "save", "persistent"
    );

    if (dhc_save_mode == "persistent" ||
        dhc_save_mode == "1" ||
        dhc_save_mode == "yes" ||
        dhc_save_mode == "true")
        nd_config.dhc_save = ndDHC_PERSISTENT;
    else if (dhc_save_mode == "volatile")
        nd_config.dhc_save = ndDHC_VOLATILE;
    else
        nd_config.dhc_save = ndDHC_DISABLED;

    nd_config.ttl_dns_entry = (unsigned)reader.GetInteger(
        "dns_hint_cache", "ttl", ND_TTL_IDLE_DHC_ENTRY);

    // Socket section
    ND_GF_SET_FLAG(ndGF_FLOW_DUMP_ESTABLISHED,
        reader.GetBoolean("socket", "dump_established_flows", false));
    ND_GF_SET_FLAG(ndGF_FLOW_DUMP_UNKNOWN,
        reader.GetBoolean("socket", "dump_unknown_flows", false));

    for (int i = 0; ; i++) {
        ostringstream os;
        os << "listen_address[" << i << "]";
        string socket_node = reader.Get("socket", os.str(), "");
        if (socket_node.size() > 0) {
            os.str("");
            os << "listen_port[" << i << "]";
            string socket_port = reader.Get(
                "socket", os.str(), ND_SOCKET_PORT);
            nd_config.socket_host.push_back(
                make_pair(socket_node, socket_port));
            continue;
        }
        else {
            os.str("");
            os << "listen_path[" << i << "]";
            socket_node = reader.Get("socket", os.str(), "");
            if (socket_node.size() > 0) {
                nd_config.socket_path.push_back(socket_node);
                continue;
            }
        }

        break;
    }

    // Privacy filter section
    for (int i = 0; ; i++) {
        ostringstream os;
        os << "mac[" << i << "]";
        string mac_addr = reader.Get("privacy_filter", os.str(), "");

        if (mac_addr.size() == 0) break;
        if (mac_addr.size() != ND_STR_ETHALEN) continue;

        uint8_t mac[ETH_ALEN], *p = mac;
        const char *a = mac_addr.c_str();
        for (int j = 0; j < ND_STR_ETHALEN; j += 3, p++)
            sscanf(a + j, "%2hhx", p);
        p = new uint8_t[ETH_ALEN];
        memcpy(p, mac, ETH_ALEN);
        nd_config.privacy_filter_mac.push_back(p);
    }

    for (int i = 0; ; i++) {
        ostringstream os;
        os << "host[" << i << "]";
        string host_addr = reader.Get("privacy_filter", os.str(), "");

        if (host_addr.size() == 0) break;

        struct addrinfo hints;
        struct addrinfo *result, *rp;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_UNSPEC;

        int rc = getaddrinfo(host_addr.c_str(), NULL, &hints, &result);
        if (rc != 0) {
            fprintf(stderr, "host[%d]: %s: %s\n",
                i, host_addr.c_str(), gai_strerror(rc));
            continue;
        }

        for (rp = result; rp != NULL; rp = rp->ai_next) {
            struct sockaddr *saddr = reinterpret_cast<struct sockaddr *>(
                new uint8_t[rp->ai_addrlen]
            );
            if (! saddr)
                throw ndSystemException(__PRETTY_FUNCTION__, "new", ENOMEM);
            memcpy(saddr, rp->ai_addr, rp->ai_addrlen);
            nd_config.privacy_filter_host.push_back(saddr);
        }

        freeaddrinfo(result);
    }
#ifdef HAVE_WORKING_REGEX
    for (int i = 0; ; i++) {
        ostringstream os;
        os << "regex_search[" << i << "]";
        string search = reader.Get("privacy_filter", os.str(), "");

        os.str("");
        os << "regex_replace[" << i << "]";
        string replace = reader.Get("privacy_filter", os.str(), "");

        if (search.size() == 0 || replace.size() == 0) break;

        try {
            regex *rx_search = new regex(
                search,
                regex_constants::icase |
                regex_constants::optimize |
                regex_constants::extended
            );
            nd_config.privacy_regex.push_back(make_pair(rx_search, replace));
        } catch (regex_error &e) {
            fprintf(stderr, "WARNING: %s: Error compiling privacy regex: %s: %d\n",
                nd_conf_filename, search.c_str(), e.code());
        } catch (bad_alloc &e) {
            throw ndSystemException(__PRETTY_FUNCTION__, "new", ENOMEM);
        }
    }
#endif
    ND_GF_SET_FLAG(ndGF_PRIVATE_EXTADDR,
        reader.GetBoolean("privacy_filter", "private_external_addresses", false));

#ifdef _ND_USE_INOTIFY
    // Watches section
    reader.GetSection("watches", inotify_watches);
#endif
#ifdef _ND_USE_PLUGINS
    // Plugins section
    reader.GetSection("services", nd_config.services);
    reader.GetSection("tasks", nd_config.tasks);
#endif
    reader.GetSection("sink_headers", nd_config.custom_headers);
    return 0;
}

#define _ND_LO_ENABLE_SINK      1
#define _ND_LO_DISABLE_SINK     2
#define _ND_LO_FORCE_RESET      3

static int nd_config_set_option(int option)
{
    string func, output;

    switch (option) {
    case _ND_LO_ENABLE_SINK:
        func = "config_enable_sink";
        printf("Enabling Netify Cloud Sink.\n");
        break;
    case _ND_LO_DISABLE_SINK:
        func = "config_disable_sink";
        printf("Disabling Netify Cloud Sink.\n");
        break;
    default:
        fprintf(stderr, "Unrecognized configuration option: %d\n", option);
        return 1;
    }

    int rc = nd_functions_exec(func, output);
    if (rc != 0) {
        fprintf(stderr, "Error while modifying configuration file.\n"
            "Manually edit configuration file: %s\n", nd_conf_filename);

        if (ND_DEBUG) fprintf(stderr, "%s", output.c_str());

        return rc;
    }
    else
        printf("Configuration modified: %s\n", nd_conf_filename);

    return 0;
}

static void nd_force_reset(void)
{
    if (nd_conf_filename == NULL)
        nd_conf_filename = strdup(ND_CONF_FILE_NAME);

    if (nd_config_load() < 0)
        return;

    vector<string> files = {
        nd_config.path_uuid, nd_config.path_uuid_site, ND_URL_SINK_PATH
    };

    int seconds = 3;
    fprintf(stdout,
        "%sWARNING%s: Resetting Agent state files in %s%d%s seconds...\n",
        ND_C_RED, ND_C_RESET, ND_C_RED, seconds, ND_C_RESET);
    for ( ; seconds >= 0; seconds--) {
        fprintf(stdout, "%sWARNING%s: Press CTRL-C to abort: %s%d%s\r",
            ND_C_RED, ND_C_RESET, ND_C_RED, seconds, ND_C_RESET);
        fflush(stdout);
        sleep(1);
    }
    fputc('\n', stdout);
    sleep(2);

    for (vector<string>::const_iterator i = files.begin();
        i != files.end(); i++) {
        fprintf(stdout, "Deleting file: %s\n", (*i).c_str());
        if (unlink((*i).c_str()) != 0 && errno != ENOENT) {
            fprintf(stderr, "Error while removing file: %s: %s\n",
                (*i).c_str(), strerror(errno));
        }
    }

    string output;
    int rc = nd_functions_exec("restart_netifyd", output);

    if (rc != 0) {
        fprintf(stderr, "Error while restarting service.\n"
            "Manual restart is required for the reset to be completed.\n");
    }

    if (output.size())
        fprintf(stdout, "%s", output.c_str());

    if (rc == 0)
        fprintf(stdout, "Reset successful.\n");
}

static int nd_start_detection_threads(void)
{
    if (threads.size() > 0) return 1;

    ndpi_global_init();

    for (nd_ifaces::iterator i = ifaces.begin();
        i != ifaces.end(); i++) {

        flows[(*i).second] = new nd_flow_map;
#ifdef HAVE_CXX11
        flows[(*i).second]->reserve(ND_HASH_BUCKETS_FLOWS);
        nd_debug_printf("%s: flows_map, buckets: %lu, max_load: %f\n",
            (*i).second.c_str(),
            flows[(*i).second]->bucket_count(),
            flows[(*i).second]->max_load_factor());
#endif
        stats[(*i).second] = new nd_packet_stats;

        // XXX: Only collect device MAC/addresses on LAN interfaces.
        devices[(*i).second] = ((*i).first) ? new nd_device_addrs : NULL;
    }

    try {
        long cpu = 0;
        nda_stats.cpus = sysconf(_SC_NPROCESSORS_ONLN);
        string netlink_dev;
        uint8_t private_addr = 0;
        uint8_t mac[ETH_ALEN];

        nd_ifaddrs_update(nd_interface_addrs);

        for (nd_ifaces::iterator i = ifaces.begin();
            i != ifaces.end(); i++) {

            if (! nd_ifaddrs_get_mac(nd_interface_addrs, (*i).second, mac))
                memset(mac, 0, ETH_ALEN);

            threads[(*i).second] = new ndDetectionThread(
                (*i).second,
                mac,
                (*i).first,
#ifdef _ND_USE_NETLINK
                netlink,
#endif
                thread_socket,
#ifdef _ND_USE_CONNTRACK
                (i->first || ! ND_USE_CONNTRACK) ?
                    NULL : thread_conntrack,
#endif
                flows[(*i).second],
                stats[(*i).second],
                devices[(*i).second],
                dns_hint_cache,
                (i->first) ? 0 : ++private_addr,
                (ifaces.size() > 1) ? cpu++ : -1
            );

            threads[(*i).second]->Create();

            if (cpu == nda_stats.cpus) cpu = 0;
        }
    }
    catch (exception &e) {
        nd_printf("Runtime error: %s\n", e.what());
        throw;
    }

    return 0;
}

static void nd_stop_detection_threads(void)
{
    if (threads.size() == 0) return;

    for (nd_ifaces::iterator i = ifaces.begin(); i != ifaces.end(); i++) {
        threads[(*i).second]->Terminate();
        delete threads[(*i).second];

        for (nd_flow_map::iterator j = flows[(*i).second]->begin();
            j != flows[(*i).second]->end(); j++) {
            j->second->release();
            delete j->second;
        }

        delete flows[(*i).second];
        delete stats[(*i).second];
        if (devices.find((*i).second) != devices.end())
            delete devices[(*i).second];
    }

    threads.clear();
    flows.clear();
    stats.clear();
    devices.clear();

    ndpi_global_destroy();
}

static void nd_reap_detection_threads(void)
{
    if (threads.size() == 0) return;

    nd_threads::iterator thread_iter;
    nd_flows::iterator flow_iter;
    nd_stats::iterator stat_iter;
    nd_devices::iterator device_iter;
    nd_ifaces::iterator iface_iter = ifaces.begin();

    while (iface_iter != ifaces.end()) {

        thread_iter = threads.find(iface_iter->second);
        if (thread_iter == threads.end() ||
            ! thread_iter->second->HasTerminated()) {
            iface_iter++;
            continue;
        }

        flow_iter = flows.find(iface_iter->second);
        if (flow_iter != flows.end()) {
            for (nd_flow_map::iterator f = flow_iter->second->begin();
                f != flow_iter->second->end(); f++) {
                f->second->release();
                delete f->second;
            }

            delete flow_iter->second;
            flows.erase(flow_iter);
        }

        stat_iter = stats.find(iface_iter->second);
        if (stat_iter != stats.end()) {
            delete stat_iter->second;
            stats.erase(stat_iter);
        }

        device_iter = devices.find(iface_iter->second);
        if (device_iter != devices.end()) {
            delete device_iter->second;
            devices.erase(device_iter);
        }

        delete thread_iter->second;
        threads.erase(thread_iter);
        iface_iter = ifaces.erase(iface_iter);
    }

    if (threads.size() == 0) ndpi_global_destroy();
}

#ifdef _ND_USE_PLUGINS

static int nd_start_services(void)
{
    for (map<string, string>::const_iterator i = nd_config.services.begin();
        i != nd_config.services.end(); i++) {
        try {
            plugin_services[i->first] = new ndPluginLoader(i->second, i->first);
            plugin_services[i->first]->GetPlugin()->Create();
        }
        catch (ndPluginException &e) {
            nd_printf("Error loading service plugin: %s\n", e.what());
            return 1;
        }
        catch (ndThreadException &e) {
            nd_printf("Error starting service plugin: %s %s: %s\n",
                i->first.c_str(), i->second.c_str(), e.what());
            return 1;
        }
    }

    return 0;
}

static void nd_stop_services(void)
{
    for (nd_plugins::iterator i = plugin_services.begin();
        i != plugin_services.end(); i++) {

        ndPluginService *service = reinterpret_cast<ndPluginService *>(
            i->second->GetPlugin()
        );
        service->Terminate();
        delete service;

        delete i->second;
    }

    plugin_services.clear();
}

static int nd_dispatch_service_param(
    const string &name, const string &uuid_dispatch, const ndJsonPluginParams &params)
{
    int rc = 0;
#if 0
    if (name == "netifyd.service.capture.start") {
        nd_printf("Unclassified flow capture started by service parameter request.\n");
        ND_GF_SET_FLAG(ndGF_CAPTURE_UNKNOWN_FLOWS, true);
        return 0;
    }
    else if (name == "netifyd.service.capture.stop") {
        nd_printf("Unclassified flow capture stopped by service parameter request.\n");
        ND_GF_SET_FLAG(ndGF_CAPTURE_UNKNOWN_FLOWS, false);
        return 0;
    }
#endif
    nd_plugins::iterator plugin_iter = plugin_services.find(name);

    if (plugin_iter == plugin_services.end()) {
        nd_printf("Unable to dispatch parameters; service not found: %s\n",
            name.c_str());
        rc = -1;
    }
    else {
        ndPluginService *service = reinterpret_cast<ndPluginService *>(
            plugin_iter->second->GetPlugin()
        );

        service->SetParams(uuid_dispatch, params);
    }

    return rc;
}

static int nd_start_task(
    const string &name, const string &uuid_dispatch, const ndJsonPluginParams &params)
{
    map<string, string>::const_iterator task_iter = nd_config.tasks.find(name);

    if (task_iter == nd_config.tasks.end()) {
        nd_printf("Unable to initialize plugin; task not found: %s\n",
            name.c_str());
        return -1;
    }

    nd_plugins::iterator plugin_iter = plugin_tasks.find(uuid_dispatch);

    if (plugin_iter != plugin_tasks.end()) {
        nd_printf("Unable to initialize plugin; task exists: %s: %s\n",
            name.c_str(), uuid_dispatch.c_str());
        return -1;
    }

    try {
        ndPluginLoader *plugin = new ndPluginLoader(
            task_iter->second, task_iter->first
        );

        ndPluginTask *task = reinterpret_cast<ndPluginTask *>(
            plugin->GetPlugin()
        );

        task->SetParams(uuid_dispatch, params);
        task->Create();

        plugin_tasks[uuid_dispatch] = plugin;
    }
    catch (ndPluginException &e) {
        nd_printf("Error loading task plugin: %s\n", e.what());
        return -1;
    }
    catch (ndThreadException &e) {
        nd_printf("Error starting task plugin: %s %s: %s\n",
            task_iter->first.c_str(), task_iter->second.c_str(), e.what());
        return -1;
    }

    return 0;
}

static void nd_stop_tasks(void)
{
    for (nd_plugins::iterator i = plugin_tasks.begin();
        i != plugin_tasks.end(); i++) {

        ndPluginTask *task = reinterpret_cast<ndPluginTask *>(
            i->second->GetPlugin()
        );
        task->Terminate();
        delete task;
    }
}

static void nd_reap_tasks(void)
{
    for (nd_plugins::iterator i = plugin_tasks.begin();
        i != plugin_tasks.end(); i++) {
        if (! i->second->GetPlugin()->HasTerminated()) continue;

        nd_debug_printf("Reaping task plugin: %s: %s\n",
            i->second->GetPlugin()->GetTag().c_str(),
            i->first.c_str());

        delete i->second->GetPlugin();
        delete i->second;

        plugin_tasks.erase(i);
    }
}

#endif // _USE_ND_PLUGINS

static int nd_sink_process_responses(void)
{
    int count = 0;
    bool reloaded = false;

    while (true) {
        ndJsonResponse *response = thread_sink->PopResponse();

        if (response == NULL) break;

        count++;

        if (response->resp_code == ndJSON_RESP_OK) {

            for (ndJsonData::const_iterator i = response->data.begin();
                i != response->data.end(); i++) {

                if (! reloaded && i->first == ND_CONF_SINK_BASE) {

                    if (! nd_detection_stopped_by_signal) {
                        nd_stop_detection_threads();
                        if (nd_start_detection_threads() < 0) return -1;
                    }

                    if (thread_socket) {
                        string json;
                        nd_json_protocols(json);
                        thread_socket->QueueWrite(json);
                    }

                    reloaded = true;
                }
            }
#ifdef _ND_USE_PLUGINS
            for (ndJsonPluginRequest::const_iterator
                i = response->plugin_request_service_param.begin();
                i != response->plugin_request_service_param.end(); i++) {

                ndJsonPluginDispatch::const_iterator iter_params;
                iter_params = response->plugin_params.find(i->first);

                if (iter_params != response->plugin_params.end()) {
                    const ndJsonPluginParams &params(iter_params->second);
                    nd_dispatch_service_param(i->second, i->first, params);
                }
                else {
                    const ndJsonPluginParams params;
                    nd_dispatch_service_param(i->second, i->first, params);
                }
            }

            for (ndJsonPluginRequest::const_iterator
                i = response->plugin_request_task_exec.begin();
                i != response->plugin_request_task_exec.end(); i++) {

                ndJsonPluginDispatch::const_iterator iter_params;
                iter_params = response->plugin_params.find(i->first);

                if (iter_params != response->plugin_params.end()) {
                    const ndJsonPluginParams &params(iter_params->second);
                    nd_start_task(i->second, i->first, params);
                }
                else {
                    const ndJsonPluginParams params;
                    nd_start_task(i->second, i->first, params);
                }
            }
#endif
        }

        nda_stats.sink_resp_code = response->resp_code;

        delete response;
    }

    return count;
}

void nd_json_agent_hello(string &json_string)
{
    json j;

    j["type"] = "agent_hello";
    j["build_version"] = nd_get_version_and_features();
    j["agent_version"] = strtod(PACKAGE_VERSION, NULL);
    j["json_version"] = (double)ND_JSON_VERSION;

    nd_json_to_string(j, json_string);
    json_string.append("\n");
}

void nd_json_agent_status(string &json_string)
{
    json j;

    j["type"] = "agent_status";
    j["timestamp"] = time(NULL);
    j["update_interval"] = nd_config.update_interval;
    j["update_imf"] = nd_config.update_imf;
    j["uptime"] =
        unsigned(nda_stats.ts_now.tv_sec - nda_stats.ts_epoch.tv_sec);
    j["cpu_cores"] = (unsigned)nda_stats.cpus;
    j["cpu_user"] = nda_stats.cpu_user;
    j["cpu_user_prev"] = nda_stats.cpu_user_prev;
    j["cpu_system"] = nda_stats.cpu_system;
    j["cpu_system_prev"] = nda_stats.cpu_system_prev;
    j["flows"] = nda_stats.flows;
    j["flows_prev"] = nda_stats.flows_prev;
    j["maxrss_kb"] = nda_stats.maxrss_kb;
    j["maxrss_kb_prev"] = nda_stats.maxrss_kb_prev;
#if defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H)
    j["tcm_kb"] = (unsigned)nda_stats.tcm_alloc_kb;
    j["tcm_kb_prev"] = (unsigned)nda_stats.tcm_alloc_kb_prev;
#endif // _ND_USE_LIBTCMALLOC
    j["dhc_status"] = nda_stats.dhc_status;
    if (nda_stats.dhc_status)
        j["dhc_size"] = nda_stats.dhc_size;

    j["sink_status"] = nda_stats.sink_status;
    j["sink_uploads"] = (ND_UPLOAD_ENABLED) ? true : false;
    if (nda_stats.sink_status) {
        j["sink_queue_size_kb"] = nda_stats.sink_queue_size / 1024;
        j["sink_queue_max_size_kb"] = nd_config.max_backlog / 1024;
        j["sink_resp_code"] = nda_stats.sink_resp_code;
    }

    try {
        nd_json_to_string(j, json_string);
        json_string.append("\n");
        nd_json_save_to_file(json_string, ND_JSON_FILE_STATUS);
    }
    catch (runtime_error &e) {
        nd_printf("Error saving Agent status to file: %s\n",
            e.what());
    }
}

void nd_json_protocols(string &json_string)
{
    json j, ja;
    j["type"] = "protocols";

    struct ndpi_detection_module_struct *ndpi = ndpi_get_parent();

    for (unsigned i = 0; i < (unsigned)ndpi->ndpi_num_supported_protocols; i++) {
        json jo;

        jo["id"] = i;
        jo["tag"] = ndpi->proto_defaults[i].proto_name;

        ja.push_back(jo);
    }

    j["protocols"] = ja;

    nd_json_to_string(j, json_string);
    json_string.append("\n");
}

static void nd_json_add_interfaces(json &parent)
{
    uint8_t mac[ETH_ALEN];
    char mac_addr[ND_STR_ETHALEN + 1];

    for (nd_ifaces::const_iterator i = ifaces.begin(); i != ifaces.end(); i++) {
        string iface_name;
        nd_iface_name(i->second, iface_name);

        json jo;

        jo["role"] = (i->first) ? "LAN" : "WAN";

        if (! nd_ifaddrs_get_mac(nd_interface_addrs, i->second, mac))
            memset(mac, 0, ETH_ALEN);

        snprintf(mac_addr, sizeof(mac_addr),
            "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
        );

        jo["mac"] = mac_addr;

        parent[iface_name] = jo;
    }
}

static void nd_json_add_devices(json &parent)
{
    nd_device_addrs device_addrs;

    for (nd_devices::const_iterator i = devices.begin(); i != devices.end(); i++) {
        if (i->second == NULL) continue;

        for (nd_device_addrs::const_iterator j = i->second->begin();
            j != i->second->end(); j++) {

            for (vector<string>::const_iterator k = j->second.begin();
                k != j->second.end(); k++) {

                bool duplicate = false;

                if (device_addrs.find(j->first) != device_addrs.end()) {

                    vector<string>::const_iterator l;
                    for (l = device_addrs[j->first].begin();
                        l != device_addrs[j->first].end(); l++) {
                        if ((*k) != (*l)) continue;
                        duplicate = true;
                        break;
                    }
                }

                if (! duplicate)
                    device_addrs[j->first].push_back((*k));
            }
        }

        i->second->clear();
    }

    for (nd_device_addrs::const_iterator i = device_addrs.begin();
        i != device_addrs.end(); i++) {

        uint8_t mac_src[ETH_ALEN];
        memcpy(mac_src, i->first.c_str(), ETH_ALEN);
        char mac_dst[ND_STR_ETHALEN + 1];

        sprintf(mac_dst, "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
            mac_src[0], mac_src[1], mac_src[2],
            mac_src[3], mac_src[4], mac_src[5]);

        json ja;

        for (vector<string>::const_iterator j = i->second.begin();
            j != i->second.end(); j++) {
            ja.push_back((*j));
        }

        parent[mac_dst] = ja;
    }
}

static void nd_json_add_stats(json &parent,
    nd_packet_stats *stats, struct pcap_stat *pcap)
{
    parent["raw"] = stats->pkt.raw;
    parent["ethernet"] = stats->pkt.eth;
    parent["mpls"] = stats->pkt.mpls;
    parent["pppoe"] = stats->pkt.pppoe;
    parent["vlan"] = stats->pkt.vlan;
    parent["fragmented"] = stats->pkt.frags;
    parent["discarded"] = stats->pkt.discard;
    parent["discarded_bytes"] = stats->pkt.discard_bytes;
    parent["largest_bytes"] = stats->pkt.maxlen;
    parent["ip"] = stats->pkt.ip;
    parent["tcp"] = stats->pkt.tcp;
    parent["udp"] = stats->pkt.udp;
    parent["icmp"] = stats->pkt.icmp;
    parent["igmp"] = stats->pkt.igmp;
    parent["ip_bytes"] = stats->pkt.ip_bytes;
    parent["wire_bytes"] = stats->pkt.wire_bytes;

    parent["pcap_recv"] = pcap->ps_recv - stats->pcap_last.ps_recv;
    parent["pcap_drop"] = pcap->ps_drop - stats->pcap_last.ps_drop;
    parent["pcap_ifdrop"] = pcap->ps_ifdrop - stats->pcap_last.ps_ifdrop;

    parent["queue_dropped"] = stats->pkt.queue_dropped;

    stats->pcap_last.ps_recv = pcap->ps_recv;
    stats->pcap_last.ps_drop = pcap->ps_drop;
    stats->pcap_last.ps_ifdrop = pcap->ps_ifdrop;
}

static void nd_json_add_flows(json &parent,
    struct ndpi_detection_module_struct *ndpi,
    const nd_flow_map *flows)
{
    for (nd_flow_map::const_iterator i = flows->begin();
        i != flows->end(); i++) {

        if (i->second->flags.detection_complete == false || ! i->second->ts_first_update
            || (! ND_UPLOAD_NAT_FLOWS && i->second->flags.ip_nat)) continue;

        json jf;
        i->second->json_encode(jf, ndpi);

        parent.push_back(jf);

        i->second->reset();
    }
}

static void nd_json_add_file(
    json &parent, const string &tag, const string &filename)
{
    string digest;
    uint8_t _digest[SHA1_DIGEST_LENGTH];

    if (nd_sha1_file(filename.c_str(), _digest) < 0) return;

    nd_sha1_to_string(_digest, digest);

    uint8_t buffer[ND_JSON_DATA_CHUNKSIZ];
    int fd = open(filename.c_str(), O_RDONLY);

    if (fd < 0) {
        nd_printf("Error opening file for upload: %s: %s\n",
            filename.c_str(), strerror(errno));
        return;
    }

    struct stat file_stat;
    if (fstat(fd, &file_stat) != 0) {
        nd_printf("Error reading stats for upload file: %s: %s\n",
            filename.c_str(), strerror(errno));
        close(fd);
        return;
    }

    json jd, jc;

    jd["digest"] = digest;
    jd["size"] = file_stat.st_size;

    size_t bytes;

    do {
        if ((bytes = read(fd, buffer, ND_JSON_DATA_CHUNKSIZ)) > 0)
            jc.push_back(base64_encode(buffer, bytes));
    }
    while (bytes > 0);

    close(fd);

    jd["chunks"] = jc;
    parent[tag] = jd;
}

static void nd_json_add_data(
    json &parent, const string &tag, const string &data)
{
    sha1 ctx;
    string digest;
    uint8_t _digest[SHA1_DIGEST_LENGTH];

    sha1_init(&ctx);

    json jd, jc;

    jd["size"] = data.size();

    size_t offset = 0;

    do {
        const string chunk = data.substr(offset, ND_JSON_DATA_CHUNKSIZ);

        if (! chunk.size()) break;

        sha1_write(&ctx, chunk.c_str(), chunk.size());

        jc.push_back(
            base64_encode((const unsigned char *)chunk.c_str(),
            chunk.size())
        );

        if (chunk.size() != ND_JSON_DATA_CHUNKSIZ) break;

        offset += ND_JSON_DATA_CHUNKSIZ;
    }
    while (offset < data.size());

    digest.assign((const char *)sha1_result(&ctx, _digest), SHA1_DIGEST_LENGTH);
    nd_sha1_to_string(_digest, digest);

    jd["digest"] = digest;
    jd["chunks"] = jc;

    parent[tag] = jd;
}

#ifdef _ND_USE_PLUGINS

static void nd_json_add_plugin_replies(
    json &json_plugin_service_replies,
    json &json_plugin_task_replies, json &json_data)
{
    vector<ndPlugin *> plugins;

    for (nd_plugins::const_iterator i = plugin_services.begin();
        i != plugin_services.end(); i++)
        plugins.push_back(i->second->GetPlugin());
    for (nd_plugins::const_iterator i = plugin_tasks.begin();
        i != plugin_tasks.end(); i++)
        plugins.push_back(i->second->GetPlugin());

    for (vector<ndPlugin *>::const_iterator i = plugins.begin();
        i != plugins.end(); i++) {

        json *parent = NULL;

        switch ((*i)->GetType()) {

        case ndPlugin::TYPE_SERVICE:
            parent = &json_plugin_service_replies;
            break;
        case ndPlugin::TYPE_TASK:
            parent = &json_plugin_task_replies;
            break;

        default:
            nd_debug_printf("%s: Unsupported plugin type: %d\n",
                __PRETTY_FUNCTION__, (*i)->GetType());
        }

        if (parent == NULL) continue;

        ndPluginFiles files, data;
        ndPluginReplies replies;
        (*i)->GetReplies(files, data, replies);

        nd_debug_printf("%s: files: %ld, data: %ld, replies: %ld\n",
            __PRETTY_FUNCTION__, files.size(), data.size(), replies.size());

        if (! replies.size()) continue;

        for (ndPluginReplies::const_iterator iter_reply = replies.begin();
            iter_reply != replies.end(); iter_reply++) {

            json ja;

            for (ndJsonPluginReplies::const_iterator iter_params = iter_reply->second.begin();
                iter_params != iter_reply->second.end(); iter_params++) {

                json jr;

                jr[iter_params->first] = base64_encode(
                    (const unsigned char *)iter_params->second.c_str(),
                    iter_params->second.size()
                );

                ja.push_back(jr);
            }

            (*parent)[iter_reply->first.c_str()] = ja;
        }

        for (ndPluginFiles::const_iterator iter_file = files.begin();
            iter_file != files.end(); iter_file++) {
            nd_json_add_file(json_data, iter_file->first, iter_file->second);
        }

        for (ndPluginFiles::const_iterator iter_file = data.begin();
            iter_file != data.end(); iter_file++) {
            nd_json_add_data(json_data, iter_file->first, iter_file->second);
        }
    }
}
#endif // _ND_USE_PLUGINS

static void nd_print_stats(void)
{
#ifndef _ND_LEAN_AND_MEAN
    string uptime;
    nd_uptime(nda_stats.ts_now.tv_sec - nda_stats.ts_epoch.tv_sec, uptime);

    nd_debug_printf("\n");
    nd_debug_printf("Cumulative Packet Totals [Uptime: %s]:\n",
        uptime.c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.raw, false);
    nd_debug_printf("%12s: %s ", "Wire", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.eth, false);
    nd_debug_printf("%12s: %s ", "ETH", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.vlan, false);
    nd_debug_printf("%12s: %s\n", "VLAN", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.ip, false);
    nd_debug_printf("%12s: %s ", "IP", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.ip4, false);
    nd_debug_printf("%12s: %s ", "IPv4", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.ip6, false);
    nd_debug_printf("%12s: %s\n", "IPv6", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.icmp + pkt_totals.pkt.igmp, false);
    nd_debug_printf("%12s: %s ", "ICMP/IGMP", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.udp, false);
    nd_debug_printf("%12s: %s ", "UDP", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.tcp, false);
    nd_debug_printf("%12s: %s\n", "TCP", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.mpls, false);
    nd_debug_printf("%12s: %s ", "MPLS", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.pppoe, false);
    nd_debug_printf("%12s: %s\n", "PPPoE", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.frags, false);
    nd_debug_printf("%12s: %s ", "Frags", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.discard, false);
    nd_debug_printf("%12s: %s ", "Discarded", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.maxlen);
    nd_debug_printf("%12s: %s\n", "Largest", (*nd_stats_os).str().c_str());

    nd_debug_printf("\nCumulative Byte Totals:\n");

    nd_print_number(*nd_stats_os, pkt_totals.pkt.wire_bytes);
    nd_debug_printf("%12s: %s\n", "Wire", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.ip_bytes);
    nd_debug_printf("%12s: %s ", "IP", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.ip4_bytes);
    nd_debug_printf("%12s: %s ", "IPv4", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.ip6_bytes);
    nd_debug_printf("%12s: %s\n", "IPv6", (*nd_stats_os).str().c_str());

    nd_print_number(*nd_stats_os, pkt_totals.pkt.discard_bytes);
    nd_debug_printf("%39s: %s ", "Discarded", (*nd_stats_os).str().c_str());

    (*nd_stats_os).str("");
    (*nd_stats_os) << setw(8) << nda_stats.flows;

    nd_debug_printf("%12s: %s (%s%d)", "Flows", (*nd_stats_os).str().c_str(),
        (nda_stats.flows > nda_stats.flows_prev) ? "+" : "",
        int(nda_stats.flows - nda_stats.flows_prev));

    nd_debug_printf("\n\n");
#endif // _ND_LEAN_AND_MEAN
}

#ifndef _ND_LEAN_AND_MEAN
static void nd_load_ethers(void)
{
    char buffer[1024 + ND_STR_ETHALEN + 17];

    struct stat ethers_stat;
    if (stat(ND_ETHERS_FILE_NAME, &ethers_stat) < 0) {
        fprintf(stderr, "Could not stat ethers file: %s: %s\n",
            ND_ETHERS_FILE_NAME, strerror(errno));
        return;
    }

    if (nd_ethers_mtime == ethers_stat.st_mtime) return;
    nd_ethers_mtime = ethers_stat.st_mtime;

    FILE *fh = fopen(ND_ETHERS_FILE_NAME, "r");

    if (fh == NULL) return;

    device_ethers.clear();

    size_t line = 0;
    while (! feof(fh)) {
        if (fgets(buffer, sizeof(buffer), fh)) {
            line++;
            char *p = buffer;
            while (isspace(*p) && *p != '\0') p++;

            char *ether = p;
            if (! isxdigit(*p)) continue;
            while (*p != '\0' && (isxdigit(*p) || *p == ':')) p++;
            *p = '\0';
            if (strlen(ether) != ND_STR_ETHALEN) continue;

            while (isspace(*(++p)) && *p != '\0');

            char *name = p;
            while (*p != '\n' && *p != '\0') p++;
            *p = '\0';
            if (! strlen(name)) continue;

            const char *a = ether;
            uint8_t mac[ETH_ALEN], *m = mac;
            for (int j = 0; j < ND_STR_ETHALEN; j += 3, m++)
                sscanf(a + j, "%2hhx", m);
            string key;
            key.assign((const char *)mac, ETH_ALEN);
            device_ethers[key] = name;
            //nd_debug_printf("%2lu: %02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (%s): %s\n", line,
            //    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ether, name);
        }
    }

    fclose(fh);

    nd_debug_printf("Loaded %lu entries from: %s\n",
        device_ethers.size(), ND_ETHERS_FILE_NAME);
}
#endif

static void nd_dump_stats(void)
{
#if defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H)
    size_t tcm_alloc_bytes = 0;

    // Force tcmalloc to free unused memory
    MallocExtension::instance()->ReleaseFreeMemory();
    MallocExtension::instance()->
        GetNumericProperty("generic.current_allocated_bytes", &tcm_alloc_bytes);
    nda_stats.tcm_alloc_kb_prev = nda_stats.tcm_alloc_kb;
    nda_stats.tcm_alloc_kb = tcm_alloc_bytes / 1024;
#endif
    struct rusage rusage_data;
    getrusage(RUSAGE_SELF, &rusage_data);

    nda_stats.cpu_user_prev = nda_stats.cpu_user;
    nda_stats.cpu_user = (double)rusage_data.ru_utime.tv_sec +
        ((double)rusage_data.ru_utime.tv_usec / 1000000.0);
    nda_stats.cpu_system_prev = nda_stats.cpu_system;
    nda_stats.cpu_system = (double)rusage_data.ru_stime.tv_sec +
        ((double)rusage_data.ru_stime.tv_usec / 1000000.0);

    nda_stats.maxrss_kb_prev = nda_stats.maxrss_kb;
    nda_stats.maxrss_kb = rusage_data.ru_maxrss;

    nda_stats.flows_prev = nda_stats.flows;
    nda_stats.flows = 0;

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &nda_stats.ts_now) != 0)
        memcpy(&nda_stats.ts_now, &nda_stats.ts_epoch, sizeof(struct timespec));

    if (ND_USE_DHC) {
        nda_stats.dhc_status = true;
        nda_stats.dhc_size = dns_hint_cache->size();
    }
    else
        nda_stats.dhc_status = false;

    if (thread_sink == NULL)
        nda_stats.sink_status = false;
    else {
        nda_stats.sink_status = true;
        nda_stats.sink_queue_size = thread_sink->QueuePendingSize();
    }

    json j;

    if (ND_USE_SINK || ND_JSON_SAVE) {
        j["version"] = (double)ND_JSON_VERSION;
        j["timestamp"] = time(NULL);
        j["uptime"] = nda_stats.ts_now.tv_sec - nda_stats.ts_epoch.tv_sec;
        j["cpu_cores"] = (unsigned)nda_stats.cpus;
        j["cpu_user"] = nda_stats.cpu_user;
        j["cpu_user_prev"] = nda_stats.cpu_user_prev;
        j["cpu_system"] = nda_stats.cpu_system;
        j["cpu_system_prev"] = nda_stats.cpu_system_prev;
        j["maxrss_kb"] = nda_stats.maxrss_kb;
#if defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H)
        j["tcm_kb"] = nda_stats.tcm_alloc_kb;
#endif // _ND_USE_LIBTCMALLOC

        json ji, jd;

        nd_json_add_interfaces(ji);
        j["interfaces"] = ji;

        nd_json_add_devices(jd);
        j["devices"] = jd;
    }

    for (nd_threads::iterator i = threads.begin();
        i != threads.end(); i++) {

        i->second->Lock();

        pkt_totals += *stats[i->first];
        nda_stats.flows += flows[i->first]->size();

        if (ND_USE_SINK || ND_JSON_SAVE) {
            struct pcap_stat lpc_stat;
            i->second->GetCaptureStats(lpc_stat);

            json js, jf;

            string iface_name;
            nd_iface_name(i->first, iface_name);

            nd_json_add_stats(js, stats[i->first], &lpc_stat);
            j["stats"][iface_name] = js;

            nd_json_add_flows(jf, i->second->GetDetectionModule(), flows[i->first]);
            j["flows"][iface_name] = jf;
        }

        stats[i->first]->reset();

        i->second->Unlock();
    }

#ifdef _ND_USE_PLUGINS
    json jsr, jtr, jpd;

    if (ND_USE_SINK) {
        nd_json_add_plugin_replies(jsr, jtr, jpd);

        j["service_replies"] = jsr;
        j["task_replies"] = jtr;
        j["data"] = jpd;
    }
#endif

    string json_string;
    if (ND_USE_SINK || ND_JSON_SAVE)
        nd_json_to_string(j, json_string, ND_DEBUG);

    if (ND_USE_SINK) {
        try {
#ifdef _ND_USE_INOTIFY
            for (nd_inotify_watch::const_iterator i = inotify_watches.begin();
                i != inotify_watches.end(); i++) {
                if (! inotify->EventOccured(i->first)) continue;

                json jd;

                nd_json_add_file(jd, i->first, i->second);
                j["data"].push_back(jd);
            }
#endif
#ifdef _ND_USE_WATCHDOGS
            nd_touch(ND_WD_UPLOAD);
#endif
            if (ND_UPLOAD_ENABLED)
                thread_sink->QueuePush(json_string);
            else {
                j["version"] = (double)ND_JSON_VERSION;
                j["timestamp"] = time(NULL);
                j["uptime"] = nda_stats.ts_now.tv_sec - nda_stats.ts_epoch.tv_sec;
                j["ping"] = true;

                nd_json_to_string(j, json_string);
                thread_sink->QueuePush(json_string);
            }
        }
        catch (runtime_error &e) {
            nd_printf("Error pushing JSON payload to upload queue: %s\n", e.what());
        }
    }

    try {
        if (ND_JSON_SAVE)
            nd_json_save_to_file(json_string, nd_config.path_json);
    }
    catch (runtime_error &e) {
        nd_printf("Error writing JSON playload to file: %s: %s\n",
            nd_config.path_json, e.what());
    }

    if (ND_DEBUG) {
#ifndef _ND_LEAN_AND_MEAN
        if (ND_DEBUG_WITH_ETHERS) nd_load_ethers();
#endif
        nd_print_stats();
    }
}

#ifndef _ND_LEAN_AND_MEAN
static void nd_dump_protocols(void)
{
    uint32_t custom_proto_base;
    struct ndpi_detection_module_struct *ndpi;

    ndpi_global_init();

    ndpi = nd_ndpi_init("netifyd", custom_proto_base);

    for (unsigned i = 0; i < (unsigned)ndpi->ndpi_num_supported_protocols; i++)
        printf("%4d: %s\n", i, ndpi->proto_defaults[i].proto_name);

    ndpi_free(ndpi);
    ndpi_global_destroy();
}
#endif

static void nd_status(void)
{
    const char *color = ND_C_GREEN;

    fprintf(stderr, "%s\n", nd_get_version_and_features().c_str());

    pid_t nd_pid = -1;
    FILE *hpid = fopen(ND_PID_FILE_NAME, "r");
    if (hpid != NULL) {
        char pid[32];
        if (fgets(pid, sizeof(pid), hpid)) {
            nd_pid = nd_is_running(
                (pid_t)strtol(pid, NULL, 0),
                "netifyd"
            );
        }
        fclose(hpid);
    }
    else if (errno == ENOENT)
        nd_pid = 0;

    if (nd_conf_filename == NULL)
        nd_conf_filename = strdup(ND_CONF_FILE_NAME);

    if (nd_config_load() < 0)
        return;

    if (nd_file_exists(ND_URL_SINK_PATH) > 0) {
        string url_sink;
        if (nd_load_sink_url(url_sink)) {
            free(nd_config.url_sink);
            nd_config.url_sink = strdup(url_sink.c_str());
        }
    }

    fprintf(stderr, "%s-%s agent %s.\n",
        (nd_pid < 0) ? ND_C_YELLOW :
            (nd_pid == 0) ? ND_C_RED : ND_C_GREEN,
        ND_C_RESET,
        (nd_pid < 0) ? "status could not be determined" :
            (nd_pid == 0) ? "is not running" : "is running");

    fprintf(stderr, "- persistent state path: %s\n", ND_PERSISTENT_STATEDIR);
    fprintf(stderr, "- volatile state path: %s\n", ND_VOLATILE_STATEDIR);

    ndJsonStatus json_status;
    bool json_status_valid = false;

    try {
        string status;
        if (nd_file_load(ND_JSON_FILE_STATUS, status) < 0) {
            fprintf(stderr,
                "%s-%s agent run-time status could not be determined.\n",
                ND_C_YELLOW, ND_C_RESET
            );
        }
        else {
            json_status.Parse(status);
            json_status_valid = true;
        }
    }
    catch (runtime_error &e) {
        fprintf(stderr, "%s-%s agent run-time status exception: %s%s%s\n",
            ND_C_RED, ND_C_RESET, ND_C_RED, e.what(), ND_C_RESET);
    }

    if (json_status_valid) {
        char timestamp[64];
        struct tm *tm_local = localtime(&json_status.timestamp);

        if (nd_pid <= 0) {
            fprintf(stderr, "%sThe following information may be out-dated:%s\n",
                ND_C_YELLOW, ND_C_RESET);
        }

        if (strftime(timestamp, sizeof(timestamp), "%c", tm_local) > 0) {
            fprintf(stderr, "%s-%s agent timestamp: %s\n",
                ND_C_GREEN, ND_C_RESET, timestamp);
        }
        string uptime;
        nd_uptime(json_status.uptime, uptime);
        fprintf(stderr, "%s-%s agent uptime: %s\n",
            ND_C_GREEN, ND_C_RESET, uptime.c_str());
        fprintf(stderr, "%s-%s active flows: %u\n",
            ND_C_GREEN, ND_C_RESET, json_status.stats. flows);

        double cpu_user_delta =
            json_status.stats.cpu_user - json_status.stats.cpu_user_prev;
        double cpu_system_delta =
            json_status.stats.cpu_system - json_status.stats.cpu_system_prev;

        double cpu_max_time =
            (double)json_status.update_interval * (double)json_status.stats.cpus;

        double cpu_user_percent = cpu_user_delta * 100.0 / cpu_max_time;
        double cpu_system_percent = cpu_system_delta * 100.0 / cpu_max_time;
        double cpu_total = cpu_user_percent + cpu_system_percent;

        if (cpu_total < 33.34)
            color = ND_C_GREEN;
        else if (cpu_total < 66.67)
            color = ND_C_YELLOW;
        else
            color = ND_C_RED;

        fprintf(stderr, "%s-%s CPU utilization (user + system): %s%.1f%%%s\n",
            color, ND_C_RESET, color, cpu_total, ND_C_RESET);
        fprintf(stderr, "%s-%s CPU time (user / system): %.1fs / %.1fs\n",
            color, ND_C_RESET, cpu_user_delta, cpu_system_delta);

#if defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H)
#if (SIZEOF_LONG == 4)
        fprintf(stderr, "%s-%s current memory usage: %u kB\n",
            ND_C_GREEN, ND_C_RESET, json_status.stats.tcm_alloc_kb);
#elif (SIZEOF_LONG == 8)
        fprintf(stderr, "%s-%s current memory usage: %lu kB\n",
            ND_C_GREEN, ND_C_RESET, json_status.stats.tcm_alloc_kb);
#endif
#endif // _ND_USE_LIBTCMALLOC
#if (SIZEOF_LONG == 4)
        fprintf(stderr, "%s-%s maximum memory usage: %u kB\n",
            ND_C_GREEN, ND_C_RESET, json_status.stats.maxrss_kb);
#elif (SIZEOF_LONG == 8)
        fprintf(stderr, "%s-%s maximum memory usage: %lu kB\n",
            ND_C_GREEN, ND_C_RESET, json_status.stats.maxrss_kb);
#endif
        fprintf(stderr, "%s-%s DNS hint cache: %s%s%s\n",
            (json_status.stats.dhc_status) ? ND_C_GREEN : ND_C_YELLOW,
            ND_C_RESET,
            (json_status.stats.dhc_status) ? ND_C_GREEN : ND_C_YELLOW,
            (json_status.stats.dhc_status) ? "enabled" : "disabled",
            ND_C_RESET
        );

        if (json_status.stats.dhc_status) {
#if (SIZEOF_LONG == 4)
            fprintf(stderr, "%s-%s DNS hint cache entries: %u\n",
                ND_C_GREEN, ND_C_RESET, json_status.stats.dhc_size);
#elif (SIZEOF_LONG == 8)
            fprintf(stderr, "%s-%s DNS hint cache entries: %lu\n",
                ND_C_GREEN, ND_C_RESET, json_status.stats.dhc_size);
#endif
        }
    }

    fprintf(stderr, "%s-%s sink URL: %s\n",
        ND_C_GREEN, ND_C_RESET, nd_config.url_sink);
    fprintf(stderr, "%s-%s sink services are %s.\n",
        (ND_USE_SINK) ? ND_C_GREEN : ND_C_RED, ND_C_RESET,
        (ND_USE_SINK) ? "enabled" : "disabled"
    );
    if (! ND_USE_SINK) {
        fprintf(stderr, "  To enable sink services, run the following command:\n");
        fprintf(stderr, "  # netifyd --enable-sink\n");
    }
    fprintf(stderr, "%s-%s sink uploads are %s.\n",
        (json_status.stats.sink_uploads) ? ND_C_GREEN : ND_C_RED, ND_C_RESET,
        (json_status.stats.sink_uploads) ? "enabled" : "disabled"
    );
    if (! json_status.stats.sink_uploads)
        fprintf(stderr, "  To enable sink uploads, ensure your Agent has been provisioned.\n");

    string uuid;

    uuid = (nd_config.uuid != NULL) ? nd_config.uuid : "00-00-00-00";
    if (nd_file_exists(nd_config.path_uuid) > 0)
        nd_load_uuid(uuid, nd_config.path_uuid, ND_AGENT_UUID_LEN);

    if (uuid.size() != ND_AGENT_UUID_LEN || uuid == "00-00-00-00") {
        fprintf(stderr, "%s-%s sink agent UUID is not set.\n",
            ND_C_RED, ND_C_RESET);
        fprintf(stderr, "  To generate a new one, run the following command:\n");
        fprintf(stderr, "  # netifyd --provision\n");
    }
    else {
        fprintf(stderr, "%s-%s sink agent UUID: %s\n",
            ND_C_GREEN, ND_C_RESET, uuid.c_str());
    }

    uuid = (nd_config.uuid_serial != NULL) ? nd_config.uuid_serial : "-";
    if (nd_file_exists(nd_config.path_uuid_serial) > 0)
        nd_load_uuid(uuid, nd_config.path_uuid_serial, ND_AGENT_SERIAL_LEN);

    if (uuid.size() && uuid != "-") {
        fprintf(stderr, "%s-%s sink serial UUID: %s\n",
            ND_C_GREEN, ND_C_RESET, uuid.c_str());
    }

    uuid = (nd_config.uuid_site != NULL) ? nd_config.uuid_site : "-";
    if (nd_file_exists(nd_config.path_uuid_site) > 0)
        nd_load_uuid(uuid, nd_config.path_uuid_site, ND_SITE_UUID_LEN);

    if (! uuid.size() || uuid == "-") {
        fprintf(stderr, "%s-%s sink site UUID is not set.\n",
            ND_C_YELLOW, ND_C_RESET);
        fprintf(stderr, "  A new site UUID will be automatically set "
            "after this agent has been provisioned by the sink server.\n");
    }
    else {
        fprintf(stderr, "%s-%s sink site UUID: %s\n",
            ND_C_GREEN, ND_C_RESET, uuid.c_str());
    }

    if (json_status_valid && json_status.stats.sink_status) {
        string status, help;
        color = ND_C_GREEN;

        switch (json_status.stats.sink_resp_code) {
        case ndJSON_RESP_NULL:
            status = "not available";
            color = ND_C_YELLOW;
            help = "Sink status not yet available, try again.";
            break;
        case ndJSON_RESP_OK:
            status = "ok";
            break;
        case ndJSON_RESP_AUTH_FAIL:
            status = "authorization failed";
            color = ND_C_YELLOW;
            help = "If no site UUID is set, please provision this agent.";
            break;
        case ndJSON_RESP_MALFORMED_DATA:
            status = "malformed data";
            color = ND_C_RED;
            help = "This should never happen, please contact support.";
            break;
        case ndJSON_RESP_SERVER_ERROR:
            status = "server error";
            color = ND_C_RED;
            help = "Contact support if this error persists.";
            break;
        case ndJSON_RESP_POST_ERROR:
            status = "upload error";
            color = ND_C_YELLOW;
            help = "This error should resolve automatically.";
            break;
        case ndJSON_RESP_PARSE_ERROR:
            status = "parse error";
            color = ND_C_RED;
            help = "This should never happen, please contact support.";
            break;
        case ndJSON_RESP_INVALID_RESPONSE:
            status = "invalid response";
            color = ND_C_RED;
            help = "This should never happen, please contact support.";
            break;
        case ndJSON_RESP_INVALID_CONTENT_TYPE:
            status = "invalid response content type";
            color = ND_C_RED;
            help = "This should never happen, please contact support.";
            break;
        default:
            status = "unknown error";
            color = ND_C_RED;
            help = "This should never happen, please contact support.";
            break;
        }

        fprintf(stderr, "%s-%s sink server status: %s%s (%d)%s\n",
            color, ND_C_RESET, color,
            status.c_str(), json_status.stats.sink_resp_code,
            ND_C_RESET
        );

        if (help.size() > 0)
            fprintf(stderr, "  %s\n", help.c_str());

        float sink_util =
            (float)((json_status.stats.sink_queue_size / 1024) * 100.0f) /
            (float)json_status.sink_queue_max_size_kb;
        if (sink_util < 33.34f)
            color = ND_C_GREEN;
        else if (sink_util < 66.67f)
            color = ND_C_YELLOW;
        else
            color = ND_C_RED;

        fprintf(stderr, "%s-%s sink queue utilization: %s%.1f%%%s\n",
            color, ND_C_RESET, color, sink_util, ND_C_RESET);
    }
}

#ifdef _ND_USE_NETLINK
static void nd_add_device_addresses(nd_device_addr &device_addresses)
{
    char *token = NULL;
    struct sockaddr_in network_ip4;
    struct sockaddr_in bcast_ip4;
    struct sockaddr_in6 network_ip6;
    int bit, word, words;
    uint32_t b, word_net[4] = { 0, 0, 0, 0 }, word_bcast[1] = { 0 };
    char netaddr[INET6_ADDRSTRLEN], bcastaddr[INET6_ADDRSTRLEN];

    for (nd_device_addr::const_iterator i = device_addresses.begin();
        i != device_addresses.end(); i++) {

        sa_family_t family = AF_UNSPEC;

        token = (char *)realloc(token, (*i).second.size() + 1);
        strncpy(token, (*i).second.c_str(), (*i).second.size() + 1);

        const char *address = strtok(token, "/");
        if (address == NULL) {
            fprintf(stderr, "WARNING: Invalid address, use CIDR notation: %s\n",
                (*i).second.c_str());
            continue;
        }

        if (inet_pton(AF_INET, address, &network_ip4.sin_addr) == 1) {
            words = 1;
            word_net[0] = ntohl(network_ip4.sin_addr.s_addr);
            word_bcast[0] = ntohl(network_ip4.sin_addr.s_addr);
            family = AF_INET;
        }
        else if (inet_pton(AF_INET6, address, &network_ip6.sin6_addr) == 1) {
            words = 4;
            word_net[0] = ntohl(network_ip6.sin6_addr.s6_addr32[0]);
            word_net[1] = ntohl(network_ip6.sin6_addr.s6_addr32[1]);
            word_net[2] = ntohl(network_ip6.sin6_addr.s6_addr32[2]);
            word_net[3] = ntohl(network_ip6.sin6_addr.s6_addr32[3]);
            family = AF_INET6;
        }
        else {
            fprintf(stderr, "WARNING: Not an IPv4 or IPv6 address: %s\n", address);
            continue;
        }

        const char *length = strtok(NULL, "/");
        if (length == NULL) {
            fprintf(stderr, "WARNING: Invalid address, use CIDR notation: %s\n",
                (*i).second.c_str());
            continue;
        }

        uint8_t _length = (uint8_t)atoi(length);
        if (_length == 0 || (
            (family == AF_INET && _length > 32) ||
            (family == AF_INET6 && _length > 128))) {
            fprintf(stderr, "WARNING: Invalid network length: %hhu\n", _length);
            continue;
        }

        nd_debug_printf("%s: %s: address: %s, length: %hu\n",
            __PRETTY_FUNCTION__, (*i).first.c_str(), address, _length);

        bit = (int)_length;

        for (word = 0; word < words; word++) {
            for (b = 0x80000000; b > 0; b >>= 1, bit--) {
                if (bit < 1) word_net[word] &= ~b;
            }
        }

        switch (family) {
        case AF_INET:
            network_ip4.sin_addr.s_addr = htonl(word_net[0]);
            inet_ntop(AF_INET,
                &network_ip4.sin_addr, netaddr, INET_ADDRSTRLEN);

            bit = (int)_length;

            for (word = 0; word < words; word++) {
                for (b = 0x80000000; b > 0; b >>= 1, bit--) {
                    if (bit < 1) word_bcast[word] |= b;
                }
            }

            bcast_ip4.sin_addr.s_addr = htonl(word_bcast[0]);
            inet_ntop(AF_INET,
                &bcast_ip4.sin_addr, bcastaddr, INET_ADDRSTRLEN);

            if (! netlink->AddAddress(family, _ND_NETLINK_BROADCAST, bcastaddr))
                fprintf(stderr, "WARNING: Error adding device address: %s\n", bcastaddr);

            break;

        case AF_INET6:
            network_ip6.sin6_addr.s6_addr32[0] = htonl(word_net[0]);
            network_ip6.sin6_addr.s6_addr32[1] = htonl(word_net[1]);
            network_ip6.sin6_addr.s6_addr32[2] = htonl(word_net[2]);
            network_ip6.sin6_addr.s6_addr32[3] = htonl(word_net[3]);
            inet_ntop(AF_INET6,
                &network_ip6.sin6_addr, netaddr, INET6_ADDRSTRLEN);
            break;
        }

        if (! netlink->AddNetwork(family, (*i).first, netaddr, _length)) {
            fprintf(stderr, "WARNING: Error adding device network: %s\n",
                (*i).second.c_str());
        }

        if (! netlink->AddAddress(family, (*i).first, address)) {
            fprintf(stderr, "WARNING: Error adding device address: %s\n", address);
        }
    }

    if (token != NULL) free(token);
}
#endif // _ND_USE_NETLINK

static int nd_check_agent_uuid(void)
{
    if (nd_config.uuid == NULL ||
        ! strncmp(nd_config.uuid, ND_AGENT_UUID_NULL, ND_AGENT_UUID_LEN)) {
        string uuid;
        if (! nd_load_uuid(uuid, ND_AGENT_UUID_PATH, ND_AGENT_UUID_LEN) ||
            ! uuid.size() ||
            ! strncmp(uuid.c_str(), ND_AGENT_UUID_NULL, ND_AGENT_UUID_LEN)) {
            nd_generate_uuid(uuid);
            printf("Generated a new Agent UUID: %s\n", uuid.c_str());
            if (! nd_save_uuid(uuid, ND_AGENT_UUID_PATH, ND_AGENT_UUID_LEN))
                return 1;
        }
        if (nd_config.uuid != NULL)
            free(nd_config.uuid);
        nd_config.uuid = strdup(uuid.c_str());
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int rc = 0;
    bool terminate = false;
    sigset_t sigset;
    struct sigevent sigev;
    timer_t timer_id;
    struct timespec tspec_sigwait;
    struct itimerspec itspec_update;
    string last_device;
    nd_device_addr device_addresses;

    setlocale(LC_ALL, "");

    ostringstream os;
    nd_stats_os = &os;
#ifdef HAVE_CXX11
    struct nd_numpunct : numpunct<char> {
        string do_grouping() const { return "\03"; }
    };

    locale lc(cout.getloc(), new nd_numpunct);
    os.imbue(lc);
#endif

    nd_config_init();

    openlog(PACKAGE_TARNAME, LOG_NDELAY | LOG_PID | LOG_PERROR, LOG_DAEMON);

    nd_printf_mutex = new pthread_mutex_t;
    pthread_mutex_init(nd_printf_mutex, NULL);

    static struct option options[] =
    {
        { "config", 1, 0, 'c' },
        { "debug", 0, 0, 'd' },
        { "debug-ether-names", 0, 0, 'e' },
        { "debug-uploads", 0, 0, 'D' },
        { "device-address", 1, 0, 'A' },
        { "device-filter", 1, 0, 'F' },
        { "device-netlink", 1, 0, 'N' },
        { "disable-conntrack", 0, 0, 't' },
        { "disable-netlink", 0, 0, 'l' },
        { "external", 1, 0, 'E' },
        { "hash-file", 1, 0, 'S' },
        { "help", 0, 0, 'h' },
        { "internal", 1, 0, 'I' },
        { "interval", 1, 0, 'i' },
        { "json", 1, 0, 'j' },
        { "protocols", 0, 0, 'P' },
        { "provision", 0, 0, 'p' },
        { "remain-in-foreground", 0, 0, 'R' },
        { "replay-delay", 0, 0, 'r' },
        { "sink-config", 1, 0, 'f' },
        { "status", 0, 0, 's' },
        { "test-output", 1, 0, 'T' },
        { "uuid", 1, 0, 'u' },
        { "uuidgen", 0, 0, 'U' },
        { "verbose", 0, 0, 'v' },
        { "version", 0, 0, 'V' },

        { "enable-sink", 0, NULL, _ND_LO_ENABLE_SINK },
        { "disable-sink", 0, NULL, _ND_LO_DISABLE_SINK },

        { "force-reset", 0, NULL, _ND_LO_FORCE_RESET },

        { NULL, 0, 0, 0 }
    };

    for (optind = 1;; ) {
        int o = 0;
        if ((rc = getopt_long(argc, argv,
            "?A:c:DdE:eF:f:hI:i:j:lN:PpRrS:stT:Uu:vV",
            options, &o)) == -1) break;
        switch (rc) {
        case 0:
            break;
        case _ND_LO_ENABLE_SINK:
        case _ND_LO_DISABLE_SINK:
            exit(nd_config_set_option(rc));
        case _ND_LO_FORCE_RESET:
            nd_force_reset();
            exit(0);
        case '?':
            fprintf(stderr, "Try `--help' for more information.\n");
            return 1;
        case 'A':
            if (last_device.size() == 0) {
                fprintf(stderr, "You must specify an interface first (-I/E).\n");
                exit(1);
            }
            device_addresses.push_back(make_pair(last_device, optarg));
            break;
        case 'c':
            if (nd_conf_filename != NULL) free(nd_conf_filename);
            nd_conf_filename = strdup(optarg);
            break;
        case 'd':
            nd_config.flags |= ndGF_DEBUG;
            break;
        case 'D':
            nd_config.flags |= ndGF_DEBUG_UPLOAD;
            break;
        case 'E':
            for (nd_ifaces::iterator i = ifaces.begin();
                i != ifaces.end(); i++) {
                if (strcasecmp((*i).second.c_str(), optarg) == 0) {
                    fprintf(stderr, "Duplicate interface specified: %s\n", optarg);
                    exit(1);
                }
            }
            last_device = optarg;
            ifaces.push_back(make_pair(false, optarg));
            break;
        case 'e':
            nd_config.flags |= ndGF_DEBUG_WITH_ETHERS;
            break;
        case 'F':
            if (last_device.size() == 0) {
                fprintf(stderr, "You must specify an interface first (-I/E).\n");
                exit(1);
            }
            if (nd_config.device_filters
                .find(last_device) != nd_config.device_filters.end()) {
                fprintf(stderr, "Only one filter can be applied to a device.\n");
                exit(1);
            }
            nd_config.device_filters[last_device] = optarg;
            break;
        case 'f':
            free(nd_config.path_sink_config);
            nd_config.path_sink_config = strdup(optarg);
            nd_config.flags |= ndGF_OVERRIDE_SINK_CONFIG;
            break;
        case 'h':
            nd_usage();
        case 'I':
            for (nd_ifaces::iterator i = ifaces.begin();
                i != ifaces.end(); i++) {
                if (strcasecmp((*i).second.c_str(), optarg) == 0) {
                    fprintf(stderr, "Duplicate interface specified: %s\n", optarg);
                    exit(1);
                }
            }
            last_device = optarg;
            ifaces.push_back(make_pair(true, optarg));
            break;
        case 'i':
            nd_config.update_interval = atoi(optarg);
            break;
        case 'j':
            nd_config.path_json = strdup(optarg);
            break;
        case 'l':
            nd_config.flags &= ~ndGF_USE_NETLINK;
            break;
        case 'N':
#if _ND_USE_NETLINK
            if (last_device.size() == 0) {
                fprintf(stderr, "You must specify an interface first (-I/E).\n");
                exit(1);
            }
            device_netlink[last_device] = optarg;
#else
            fprintf(stderr, "Sorry, this feature was not enabled for this build.\n");
            return 1;
#endif
            break;
        case 'P':
#ifndef _ND_LEAN_AND_MEAN
            nd_dump_protocols();
            exit(0);
#else
            fprintf(stderr, "Sorry, this feature was not enabled for this build.\n");
            exit(1);
#endif
        case 'p':
            if (nd_conf_filename == NULL)
                nd_conf_filename = strdup(ND_CONF_FILE_NAME);
            if (nd_config_load() < 0)
                return 1;
            if (nd_check_agent_uuid() || nd_config.uuid == NULL) return 1;
            printf("Agent UUID: %s\n", nd_config.uuid);
            return 0;
        case 'R':
            nd_config.flags |= ndGF_REMAIN_IN_FOREGROUND;
            break;
        case 'r':
            nd_config.flags |= ndGF_REPLAY_DELAY;
            break;
        case 'S':
#ifndef _ND_LEAN_AND_MEAN
            {
                uint8_t digest[SHA1_DIGEST_LENGTH];

                if (nd_sha1_file(optarg, digest) < 0) return 1;
                else {
                    string sha1;
                    nd_sha1_to_string(digest, sha1);
                    printf("%s\n", sha1.c_str());
                    return 0;
                }
            }
#else
            fprintf(stderr, "Sorry, this feature was not enabled for this build.\n");
            exit(1);
#endif
        case 's':
            nd_status();
            exit(0);
        case 't':
            nd_config.flags &= ~ndGF_USE_CONNTRACK;
            break;
        case 'T':
            if ((nd_config.h_flow = fopen(optarg, "w")) == NULL) {
                fprintf(stderr, "Error while opening test output log: %s: %s\n",
                    optarg, strerror(errno));
                exit(1);
            }
            break;
        case 'U':
            {
                string uuid;
                nd_generate_uuid(uuid);
                printf("%s\n", uuid.c_str());
            }
            exit(0);
        case 'u':
            nd_config.uuid = strdup(optarg);
            break;
        case 'V':
            nd_usage(0, true);
            break;
        case 'v':
            nd_config.flags |= ndGF_VERBOSE;
            break;
        default:
            nd_usage(1);
        }
    }

    if (nd_config.path_json == NULL)
        nd_config.path_json = strdup(ND_JSON_FILE_REQUEST);

    if (nd_conf_filename == NULL)
        nd_conf_filename = strdup(ND_CONF_FILE_NAME);

    if (nd_config_load() < 0)
        return 1;

    {
        string url_sink;
        if (nd_load_sink_url(url_sink)) {
            free(nd_config.url_sink);
            nd_config.url_sink = strdup(url_sink.c_str());
        }
    }

    if (nd_config.h_flow != stderr) {
        // Test mode enabled, disable/set certain config parameters
        ND_GF_SET_FLAG(ndGF_USE_DHC, true);
        ND_GF_SET_FLAG(ndGF_USE_FHC, true);
        ND_GF_SET_FLAG(ndGF_USE_SINK, false);
        ND_GF_SET_FLAG(ndGF_JSON_SAVE, false);
        ND_GF_SET_FLAG(ndGF_REMAIN_IN_FOREGROUND, true);

        nd_config.update_interval = 1;
#ifdef _ND_USE_PLUGINS
        nd_config.services.clear();
        nd_config.tasks.clear();
#endif
        nd_config.dhc_save = ndDHC_DISABLED;
        nd_config.fhc_save = ndFHC_DISABLED;
    }

    if (ND_USE_DHC)
        dns_hint_cache = new ndDNSHintCache();

    if (ifaces.size() == 0) {
        fprintf(stderr,
            "Required argument, (-I, --internal, or -E, --external) missing.\n");
        return 1;
    }

    CURLcode cc;
    if ((cc = curl_global_init(CURL_GLOBAL_ALL)) != 0) {
        fprintf(stderr, "Unable to initialize libCURL: %d\n", cc);
        return 1;
    }

    if (! ND_DEBUG && ! ND_REMAIN_IN_FOREGROUND) {
        if (daemon(1, 0) != 0) {
            nd_printf("daemon: %s\n", strerror(errno));
            return 1;
        }
    }

    nd_printf("%s\n", nd_get_version_and_features().c_str());

    nd_check_agent_uuid();
#ifndef _ND_LEAN_AND_MEAN
    nd_debug_printf("Flow entry size: %lu\n", sizeof(struct ndFlow) +
        sizeof(struct ndpi_flow_struct) + sizeof(struct ndpi_id_struct) * 2);
#endif
    if (! ND_DEBUG) {
        FILE *hpid = fopen(ND_PID_FILE_NAME, "w+");

        do {
            if (hpid == NULL) {
                nd_printf("Error opening PID file: %s: %s\n",
                    ND_PID_FILE_NAME, strerror(errno));

                if (mkdir(ND_VOLATILE_STATEDIR, 0755) == 0)
                    hpid = fopen(ND_PID_FILE_NAME, "w+");
                else {
                    nd_printf("Unable to create volatile state directory: %s: %s\n",
                        ND_VOLATILE_STATEDIR, strerror(errno));
                    return 1;
                }
            }
        } while(hpid == NULL);

        fprintf(hpid, "%d\n", getpid());
        fclose(hpid);
    }

    memset(&nda_stats, 0, sizeof(nd_agent_stats));
    memset(&pkt_totals, 0, sizeof(nd_packet_stats));

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &nda_stats.ts_epoch) != 0) {
        nd_printf("Error getting epoch time: %s\n", strerror(errno));
        return 1;
    }

    if (dns_hint_cache) dns_hint_cache->load();

    nd_sha1_file(
        nd_config.path_sink_config, nd_config.digest_sink_config
    );

    sigfillset(&sigset);
    //sigdelset(&sigset, SIGPROF);
    //sigdelset(&sigset, SIGINT);
    sigdelset(&sigset, SIGQUIT);
    sigprocmask(SIG_BLOCK, &sigset, NULL);

    sigemptyset(&sigset);
    sigaddset(&sigset, ND_SIG_SINK_REPLY);
    sigaddset(&sigset, ND_SIG_UPDATE);
    sigaddset(&sigset, ND_SIG_CONNECT);
    sigaddset(&sigset, SIGHUP);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGIO);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGUSR1);
    sigaddset(&sigset, SIGUSR2);

#ifndef _ND_LEAN_AND_MEAN
    if (ND_DEBUG_WITH_ETHERS) nd_load_ethers();
#endif

    try {
#ifdef _ND_USE_CONNTRACK
        if (ND_USE_CONNTRACK) {
            thread_conntrack = new ndConntrackThread();
            thread_conntrack->Create();
        }
#endif
        if (nd_config.socket_host.size() || nd_config.socket_path.size())
            thread_socket = new ndSocketThread();

        if (ND_USE_SINK) {
            thread_sink = new ndSinkThread();
            thread_sink->Create();
        }
    }
    catch (ndSinkThreadException &e) {
        nd_printf("Error starting upload thread: %s\n", e.what());
        return 1;
    }
    catch (ndSocketException &e) {
        nd_printf("Error starting socket thread: %s\n", e.what());
        return 1;
    }
    catch (ndSocketSystemException &e) {
        nd_printf("Error starting socket thread: %s\n", e.what());
        return 1;
    }
    catch (ndSocketThreadException &e) {
        nd_printf("Error starting socket thread: %s\n", e.what());
        return 1;
    }
#ifdef _ND_USE_CONNTRACK
    catch (ndConntrackThreadException &e) {
        nd_printf("Error starting conntrack thread: %s\n", e.what());
        return 1;
    }
#endif
    catch (ndThreadException &e) {
        nd_printf("Error starting thread: %s\n", e.what());
        return 1;
    }
    catch (exception &e) {
        nd_printf("Error starting thread: %s\n", e.what());
        return 1;
    }
#ifdef _ND_USE_INOTIFY
    try {
        inotify = new ndInotify();
        for (nd_inotify_watch::const_iterator i = inotify_watches.begin();
            i != inotify_watches.end(); i++)
            inotify->AddWatch(i->first, i->second);
        if (inotify_watches.size()) inotify->RefreshWatches();
    }
    catch (exception &e) {
        nd_printf("Error creating file watches: %s\n", e.what());
        return 1;
    }
#endif
#ifdef _ND_USE_NETLINK
    if (ND_USE_NETLINK) {
        try {
            netlink = new ndNetlink(ifaces);

            nd_device_netlink::const_iterator i;
            for (i = device_netlink.begin(); i != device_netlink.end(); i++)
                netlink->AddInterface(i->second);
        }
        catch (exception &e) {
            nd_printf("Error creating netlink watch: %s\n", e.what());
            return 1;
        }

        nd_add_device_addresses(device_addresses);
    }
#endif

    if (nd_start_detection_threads() < 0)
        return 1;

    try {
        if (thread_socket != NULL)
            thread_socket->Create();
    }
    catch (ndThreadException &e) {
        nd_printf("Error starting socket thread: %s\n", e.what());
        return 1;
    }

#ifdef _ND_USE_PLUGINS
    if (nd_start_services() < 0)
        return 1;
#endif

    memset(&sigev, 0, sizeof(struct sigevent));
    sigev.sigev_notify = SIGEV_SIGNAL;
    sigev.sigev_signo = ND_SIG_UPDATE;

    // XXX: Always send an update on start-up...
    nd_dump_stats();

    if (timer_create(CLOCK_REALTIME, &sigev, &timer_id) < 0) {
        nd_printf("timer_create: %s\n", strerror(errno));
        return 1;
    }

#ifdef _ND_USE_NETLINK
    if (ND_USE_NETLINK) netlink->Refresh();
#endif

    itspec_update.it_value.tv_sec = nd_config.update_interval;
    itspec_update.it_value.tv_nsec = 0;
    itspec_update.it_interval.tv_sec = nd_config.update_interval;
    itspec_update.it_interval.tv_nsec = 0;

    timer_settime(timer_id, 0, &itspec_update, NULL);

    tspec_sigwait.tv_sec = 1;
    tspec_sigwait.tv_nsec = 0;

    while (! terminate) {
        int sig;
        siginfo_t si;

        if ((sig = sigtimedwait(&sigset, &si, &tspec_sigwait)) < 0) {
            if (errno == EAGAIN || errno == EINTR) continue;
            rc = -1;
            terminate = true;
            nd_printf("sigwaitinfo: %s\n", strerror(errno));
            continue;
        }

        if (sig == ND_SIG_UPDATE) {
            nd_debug_printf("Caught signal: [%d] %s: Update\n", sig, strsignal(sig));
        }
        else if (sig == ND_SIG_SINK_REPLY) {
            nd_debug_printf("Caught signal: [%d] %s: Process sink reply\n", sig, strsignal(sig));
        }
        else if (sig == ND_SIG_CONNECT) {
            nd_debug_printf("Caught signal: [%d] %s: Client connected\n", sig, strsignal(sig));
        }
        else {
            nd_debug_printf("Caught signal: [%d] %s\n", sig, strsignal(sig));
        }

        if (sig == SIGINT || sig == SIGTERM) {
            rc = 0;
            terminate = true;
            nd_printf("Exiting...\n");
            continue;
        }

        if (sig == ND_SIG_UPDATE) {
#ifdef _ND_USE_INOTIFY
            inotify->RefreshWatches();
#endif
            nd_dump_stats();
#ifdef _ND_USE_PLUGINS
            nd_reap_tasks();
#endif
            if (thread_socket) {
                string json;
                nd_json_agent_status(json);
                thread_socket->QueueWrite(json);
            }

            if (dns_hint_cache)
                dns_hint_cache->purge();

            nd_reap_detection_threads();

            if (threads.size() == 0) {
                if (thread_sink == NULL ||
                    thread_sink->QueuePendingSize() == 0) {
                    nd_printf("Exiting, no remaining detection threads.\n");
                    terminate = true;
                    continue;
                }
            }

            continue;
        }

        if (sig == SIGIO) {
#ifdef _ND_USE_INOTIFY
            if (inotify->GetDescriptor() == si.si_fd)
                inotify->ProcessEvent();
#endif

#if defined(_ND_USE_NETLINK) && defined(HAVE_LINUX_NETLINK_H)
            if (ND_USE_NETLINK &&
                netlink->GetDescriptor() == si.si_fd) {
#ifndef _ND_LEAN_AND_MEAN
                if (netlink->ProcessEvent())
                    if (ND_DEBUG) netlink->Dump();
#else
                netlink->ProcessEvent();
#endif
            }
#endif
            continue;
        }

        if (sig == ND_SIG_SINK_REPLY) {
            if (ND_USE_SINK && nd_sink_process_responses() < 0) {
                nd_debug_printf("nd_sink_process_responses failed!\n");
                break;
            }

            continue;
        }

        if (sig == ND_SIG_CONNECT) {
            for (nd_threads::const_iterator t = threads.begin();
                t != threads.end(); t++) (*t).second->SendIPC(ND_SIG_CONNECT);
            continue;
        }

        if (sig == SIGHUP) {
            continue;
        }

        if (sig == SIGUSR1) {
            nd_start_detection_threads();
            nd_detection_stopped_by_signal = false;
            continue;
        }

        if (sig == SIGUSR2) {
            nd_stop_detection_threads();
            nd_detection_stopped_by_signal = true;
            continue;
        }

        nd_printf("Unhandled signal: %s\n", strsignal(sig));
    }

    timer_delete(timer_id);

    nd_stop_detection_threads();

#ifdef _ND_USE_PLUGINS
    nd_stop_services();

    nd_stop_tasks();
    nd_reap_tasks();
#endif

    if (thread_sink) {
        thread_sink->Terminate();
        delete thread_sink;
    }

    if (thread_socket) {
        thread_socket->Terminate();
        delete thread_socket;
    }

#ifdef _ND_USE_CONNTRACK
    if (ND_USE_CONNTRACK && thread_conntrack) {
        thread_conntrack->Terminate();
        delete thread_conntrack;
    }
#endif

    if (dns_hint_cache) {
        dns_hint_cache->save();
        delete dns_hint_cache;
    }

    nd_ifaddrs_free(nd_interface_addrs);

    nd_debug_printf("Normal exit.\n");
    pthread_mutex_destroy(nd_printf_mutex);
    delete nd_printf_mutex;

    curl_global_cleanup();

    closelog();

    if (! ND_DEBUG) unlink(ND_PID_FILE_NAME);

    return 0;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
