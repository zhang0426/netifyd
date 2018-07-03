// Netify Agent
// Copyright (C) 2015-2018 eGloo Incorporated <http://www.egloo.ca>
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
#include <vector>
#include <locale>
#ifdef HAVE_ATOMIC
#include <atomic>
#else
typedef bool atomic_bool;
#endif

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/resource.h>

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <locale.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <netdb.h>
#include <netinet/in.h>

#include <curl/curl.h>
#include <json.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <resolv.h>

#ifdef _ND_USE_CONNTRACK
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#endif

#ifdef _ND_USE_NCURSES
#include <ncurses.h>
#endif

#include "INIReader.h"

using namespace std;

#include "netifyd.h"
#include "nd-ndpi.h"
#include "nd-util.h"
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
#include "nd-detection.h"
#include "nd-socket.h"
#include "nd-upload.h"

#define ND_SIG_UPDATE       SIGRTMIN
#define ND_STR_ETHALEN     (ETH_ALEN * 2 + ETH_ALEN - 1)

nd_global_config nd_config;
pthread_mutex_t *nd_printf_mutex = NULL;

static struct timespec nd_ts_epoch;
static nd_ifaces ifaces;
static nd_devices devices;
nd_device_ethers device_ethers;
static nd_flows flows;
static nd_stats stats;
static nd_threads threads;
static nd_packet_stats totals;
static ostringstream *nd_stats_os = NULL;
static ndUploadThread *thread_upload = NULL;
static ndSocketThread *thread_socket = NULL;
static char *nd_conf_filename = NULL;
#ifdef _ND_USE_CONNTRACK
static ndConntrackThread *thread_conntrack = NULL;
#endif
#ifdef _ND_USE_INOTIFY
static ndInotify *inotify = NULL;
static nd_inotify_watch inotify_watches;
#endif
#ifdef _ND_USE_NCURSES
static WINDOW *win_stats = NULL;
WINDOW *win_output = NULL;
#endif
#ifdef _ND_USE_NETLINK
static ndNetlink *netlink = NULL;
nd_device_netlink device_netlink;
#endif
static nd_device_filter device_filters;

static time_t nd_ethers_mtime = 0;

void nd_dns_cache::insert(sa_family_t af, const uint8_t *addr, const string &hostname)
{
    sha1 ctx;
    string digest;
    uint8_t _digest[SHA1_DIGEST_LENGTH];

    sha1_init(&ctx);
    sha1_write(&ctx, (const char *)addr, (af == AF_INET) ?
        sizeof(struct in_addr) : sizeof(struct in6_addr));
    digest.assign((const char *)sha1_result(&ctx, _digest), SHA1_DIGEST_LENGTH);

    pthread_mutex_lock(&lock);

    nd_dns_tuple ar(time_t(time(NULL) + nd_config.dns_cache_ttl), hostname);
    nd_dns_cache_insert i = map_ar.insert(nd_dns_cache_insert_pair(digest, ar));

    if (! i.second)
        i.first->second.first = time(NULL) + nd_config.dns_cache_ttl;

    pthread_mutex_unlock(&lock);
}

void nd_dns_cache::insert(const string &digest, const string &hostname)
{
    int i = 0;
    uint8_t v;
    const char *p = digest.c_str();
    string _digest;

    // TODO: Verify length of digest (must be SHA1_DIGEST_LENGTH).

    do {
        if (sscanf(p, "%2hhx", &v) != 1) break;
        _digest.append(1, v);
        p += 2;
    }
    while (++i < SHA1_DIGEST_LENGTH);

    if (_digest.size() != SHA1_DIGEST_LENGTH) return;

    nd_dns_tuple ar(time_t(time(NULL) + nd_config.dns_cache_ttl), hostname);
    map_ar.insert(nd_dns_cache_insert_pair(_digest, ar));
}

bool nd_dns_cache::lookup(const struct in_addr &addr, string &hostname)
{
    sha1 ctx;
    string digest;
    uint8_t _digest[SHA1_DIGEST_LENGTH];

    sha1_init(&ctx);
    sha1_write(&ctx, (const char *)&addr, sizeof(struct in_addr));
    digest.assign((const char *)sha1_result(&ctx, _digest), SHA1_DIGEST_LENGTH);

    return lookup(digest, hostname);
}

bool nd_dns_cache::lookup(const struct in6_addr &addr, string &hostname)
{
    sha1 ctx;
    string digest;
    uint8_t _digest[SHA1_DIGEST_LENGTH];

    sha1_init(&ctx);
    sha1_write(&ctx, (const char *)&addr, sizeof(struct in6_addr));
    digest.assign((const char *)sha1_result(&ctx, _digest), SHA1_DIGEST_LENGTH);

    return lookup(digest, hostname);
}

bool nd_dns_cache::lookup(const string &digest, string &hostname)
{
    bool found = false;

    pthread_mutex_lock(&lock);

    nd_dns_ar::iterator i = map_ar.find(digest);
    if (i != map_ar.end()) {
        found = true;
        hostname = i->second.second;
        i->second.first = time(NULL) + nd_config.dns_cache_ttl;
    }

    pthread_mutex_unlock(&lock);

    return found;
}

size_t nd_dns_cache::purge(void)
{
    size_t purged = 0, remaining = 0;

    pthread_mutex_lock(&lock);

    nd_dns_ar::iterator i = map_ar.begin();
    while (i != map_ar.end()) {
        if (i->second.first < time(NULL)) {
            i = map_ar.erase(i);
            purged++;
        }
        else
            i++;
    }

    remaining = map_ar.size();

    pthread_mutex_unlock(&lock);

    if (purged > 0 && remaining > 0)
        nd_debug_printf("Purged %u DNS cache entries, %u active.\n", purged, remaining);

    return purged;
}

void nd_dns_cache::load(void)
{
    int rc;
    time_t ttl;
    char header[1024], *host, *digest;
    size_t loaded = 0, line = 1;

    FILE *h_f = fopen(ND_DNS_CACHE_FILE_NAME, "r");
    if (! h_f) return;

    if (fgets(header, sizeof(header), h_f) == NULL) { fclose(h_f); return; }

    pthread_mutex_lock(&lock);

    while (! feof(h_f)) {
        line++;
        if ((rc = fscanf(h_f,
            " \"%m[0-9A-z.-]\" , %m[0-9A-Fa-f] , %ld\n",
            &host, &digest, &ttl)) != 3) {
            nd_printf("%s: parse error at line #%u [%d]\n",
                ND_DNS_CACHE_FILE_NAME, line, rc);
            if (rc >= 1) free(host);
            if (rc >= 2) free(digest);
            break;
        }

        insert(digest, host);

        free(host);
        free(digest);

        loaded++;
    }

    nd_debug_printf("Loaded %u of %u DNS cache entries.\n", map_ar.size(), loaded);

    pthread_mutex_unlock(&lock);

    fclose(h_f);
}

void nd_dns_cache::save(void)
{
    string digest;

    FILE *h_f = fopen(ND_DNS_CACHE_FILE_NAME, "w");
    if (! h_f) return;

    pthread_mutex_lock(&lock);

    fprintf(h_f, "\"host\",\"addr_digest\",\"ttl\"\n");

    for (nd_dns_ar::iterator i = map_ar.begin();
        i != map_ar.end(); i++) {
        nd_sha1_to_string((const uint8_t *)i->first.c_str(), digest);
        fprintf(h_f, "\"%s\",%s,%u\n", i->second.second.c_str(),
            digest.c_str(), (unsigned)(i->second.first - time(NULL)));
    }

    pthread_mutex_unlock(&lock);

    fclose(h_f);
}

static nd_dns_cache dns_cache;

static void nd_usage(int rc = 0, bool version = false)
{
    cerr << nd_get_version_and_features() << endl;
    cerr << "Copyright (C) 2015-2018 eGloo Incorporated"
         <<  endl << "[" << GIT_RELEASE << " " << GIT_DATE << "]" << endl;
    if (version) {
        cerr << endl <<
            "This application uses nDPI v" <<  ndpi_revision() << endl <<
            "http://www.ntop.org/products/deep-packet-inspection/ndpi/" << endl;
        cerr << endl;
        cerr <<
            "  This program comes with ABSOLUTELY NO WARRANTY." << endl;
        cerr <<
            "  This is free software, and you are welcome to redistribute it" << endl;
        cerr <<
            "  under certain conditions according to the GNU General Public" << endl;
        cerr <<
            "  License version 3, or (at your option) any later version." << endl;
#ifdef PACKAGE_BUGREPORT
        cerr << endl;
        cerr << "Report bugs to: " << PACKAGE_BUGREPORT << endl;
#endif
    }
    else {
        cerr <<
            "  -V, --version" << endl;
        cerr <<
            "    Display program version and license information." << endl;
        cerr <<
            "  -d, --debug" << endl;
        cerr <<
            "    Output debug messages and remain in the foreground." << endl;
        cerr <<
            "  -I, --internal <device>" << endl;
        cerr <<
            "    Internal LAN interface.  Repeat for multiple interfaces.";
        cerr << endl;
        cerr <<
            "  -E, --external <device>" << endl;
        cerr <<
            "    External WAN interface.  Repeat for multiple interfaces.";
        cerr << endl;
        cerr <<
            "  -c, --config <filename>" << endl;
        cerr <<
            "    Configuration file.  Default: " << ND_CONF_FILE_NAME << endl;;
        cerr <<
            "  -j, --json <filename>" << endl;
        cerr <<
            "    JSON output file.  Default: " << ND_JSON_FILE_NAME << endl;;
        cerr <<
            "  -i, --interval <seconds>" << endl;
        cerr <<
            "    JSON update interval (seconds).  ";
        cerr <<
            "Default: " << ND_STATS_INTERVAL << endl;
    }

    exit(rc);
}

static void nd_config_init(void)
{
    nd_config.path_config = NULL;
    nd_config.path_content_match = NULL;
    nd_config.path_custom_match = NULL;
    nd_config.path_host_match = NULL;
    nd_config.path_json = NULL;
    nd_config.path_uuid = NULL;
    nd_config.path_uuid_serial = NULL;
    nd_config.path_uuid_site = NULL;
    nd_config.url_upload = NULL;
    nd_config.uuid = NULL;
    nd_config.uuid_serial = NULL;
    nd_config.uuid_site = NULL;

    nd_config.max_backlog = ND_MAX_BACKLOG_KB * 1024;
#if defined(_ND_USE_CONNTRACK) && defined(_ND_USE_NETLINK)
    nd_config.flags = ndGF_USE_CONNTRACK | ndGF_USE_NETLINK;
#elif defined(_ND_USE_CONNTRACK)
    nd_config.flags = ndGF_USE_CONNTRACK;
#elif defined(_ND_USE_NETLINK)
    nd_config.flags = ndGF_USE_NETLINK;
#endif
    nd_config.path_custom_match = strdup(ND_CONF_CUSTOM_MATCH);
    memset(nd_config.digest_custom_match, 0, SHA1_DIGEST_LENGTH);
#ifndef _ND_LEAN_AND_MEAN
    nd_config.path_content_match = strdup(ND_CONF_CONTENT_MATCH);
    nd_config.path_host_match = strdup(ND_CONF_HOST_MATCH);
    memset(nd_config.digest_content_match, 0, SHA1_DIGEST_LENGTH);
    memset(nd_config.digest_host_match, 0, SHA1_DIGEST_LENGTH);
#endif
    nd_config.max_tcp_pkts = ND_MAX_TCP_PKTS;
    nd_config.max_udp_pkts = ND_MAX_UDP_PKTS;
    nd_config.update_interval = ND_STATS_INTERVAL;
    nd_config.upload_timeout = ND_UPLOAD_TIMEOUT;
    nd_config.dns_cache_ttl = ND_IDLE_DNS_CACHE_TTL;
}

static int nd_config_load(void)
{
    if (nd_conf_filename == NULL) {
        cerr << "Configuration file not set." << endl;
        return -1;
    }

    struct stat extern_config_stat;
    if (stat(nd_conf_filename, &extern_config_stat) < 0) {
        cerr << "Can not stat configuration file: " << nd_conf_filename <<
            ": " << strerror(errno) << endl;
        return -1;
    }

    INIReader reader(nd_conf_filename);

    if (reader.ParseError() != 0) {
        cerr << "Can not parse configuration file: " << nd_conf_filename << endl;
        return -1;
    }

    if (nd_config.uuid == NULL) {
        string uuid = reader.Get("netifyd", "uuid", ND_AGENT_UUID_NULL);
        if (uuid.size() > 0)
            nd_config.uuid = strdup(uuid.c_str());
    }

    string path_uuid = reader.Get(
        "netifyd", "path_uuid", ND_AGENT_UUID_PATH);
    nd_config.path_uuid = strdup(path_uuid.c_str());

    string path_uuid_site = reader.Get(
        "netifyd", "path_uuid_site", ND_SITE_UUID_PATH);
    nd_config.path_uuid_site = strdup(path_uuid_site.c_str());

    if (nd_config.uuid_site == NULL) {
        string uuid_site = reader.Get("netifyd", "uuid_site", ND_SITE_UUID_NULL);
        if (uuid_site.size() > 0)
            nd_config.uuid_site = strdup(uuid_site.c_str());
    }

    if (nd_config.uuid_serial == NULL) {
        string serial = reader.Get("netifyd", "uuid_serial", ND_AGENT_SERIAL_NULL);
        if (serial.size() > 0)
            nd_config.uuid_serial = strdup(serial.c_str());
    }

    string url_upload = reader.Get(
        "netifyd", "url_upload", ND_URL_UPLOAD);
    nd_config.url_upload = strdup(url_upload.c_str());

    nd_config.update_interval = (unsigned)reader.GetInteger(
        "netifyd", "update_interval", ND_STATS_INTERVAL);

    nd_config.upload_timeout = (unsigned)reader.GetInteger(
        "netifyd", "upload_timeout", ND_UPLOAD_TIMEOUT);

    nd_config.flags |= (reader.GetBoolean(
        "netifyd", "json_save", false)) ? ndGF_JSON_SAVE : 0;

    nd_config.flags |= (reader.GetBoolean(
        "dns_cache", "enable", true)) ? ndGF_USE_DNS_CACHE : 0;

    nd_config.flags |= (reader.GetBoolean(
        "dns_cache", "save", true)) ? ndGF_DNS_CACHE_SAVE : 0;

    nd_config.dns_cache_ttl = (unsigned)reader.GetInteger(
        "dns_cache", "cache_ttl", ND_IDLE_DNS_CACHE_TTL);

    nd_config.max_backlog = reader.GetInteger(
        "netifyd", "max_backlog_kb", ND_MAX_BACKLOG_KB) * 1024;

    nd_config.flags |= (reader.GetBoolean(
        "netifyd", "enable_sink", false)) ? ndGF_USE_SINK : 0;

    nd_config.flags |= (reader.GetBoolean(
        "netifyd", "enable_netify_sink", false)) ? ndGF_USE_SINK : 0;

    nd_config.flags |= (reader.GetBoolean(
        "netifyd", "ssl_verify_peer", true)) ? ndGF_SSL_VERIFY_PEER : 0;

    nd_config.flags |= (reader.GetBoolean(
        "netifyd", "ssl_use_tlsv1", false)) ? ndGF_SSL_USE_TLSv1 : 0;

    nd_config.max_tcp_pkts = (unsigned)reader.GetInteger(
        "netifyd", "max_tcp_pkts", ND_MAX_TCP_PKTS);

    nd_config.max_udp_pkts = (unsigned)reader.GetInteger(
        "netifyd", "max_udp_pkts", ND_MAX_UDP_PKTS);

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
            nd_printf("host[%d]: %s: %s\n",
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
#ifdef _ND_USE_INOTIFY
    reader.GetSection("watches", inotify_watches);
#endif
    return 0;
}

static int nd_start_detection_threads(void)
{
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
        long cpus = sysconf(_SC_NPROCESSORS_ONLN);
        string netlink_dev;

        for (nd_ifaces::iterator i = ifaces.begin();
            i != ifaces.end(); i++) {
#ifdef _ND_USE_NETLINK
            if (ND_USE_NETLINK) {
                nd_device_netlink::const_iterator j;
                netlink_dev = (*i).second;
                if ((j = device_netlink.find(netlink_dev)) != device_netlink.end())
                    netlink_dev = j->second.c_str();
            }
#endif
            threads[(*i).second] = new ndDetectionThread(
                (*i).second,
                (*i).first,
#ifdef _ND_USE_NETLINK
                netlink_dev,
                netlink,
#endif
                (i->first) ? thread_socket : NULL,
#ifdef _ND_USE_CONNTRACK
                (i->first || ! ND_USE_CONNTRACK) ?
                    NULL : thread_conntrack,
#endif
                flows[(*i).second],
                stats[(*i).second],
                devices[(*i).second],
                (ND_USE_DNS_CACHE) ? &dns_cache : NULL,
                (ifaces.size() > 1) ? cpu++ : -1
            );

            threads[(*i).second]->Create();

            if (cpu == cpus) cpu = 0;
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
    for (nd_ifaces::iterator i = ifaces.begin();
        i != ifaces.end(); i++) {
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
}

void nd_json_protocols(string &json_string)
{
    ndJson json;
    json.AddObject(NULL, "type", "protocols");
    json_object *jarray = json.CreateArray(NULL, "protocols");

    uint32_t custom_proto_base;
    struct ndpi_detection_module_struct *ndpi;
    ndpi = nd_ndpi_init("netifyd", custom_proto_base);

    for (unsigned i = 0; i < (unsigned)ndpi->ndpi_num_supported_protocols; i++) {
        json_object *json_proto = json.CreateObject();
        json.AddObject(json_proto, "id", i);
        json.AddObject(json_proto, "tag", ndpi->proto_defaults[i].protoName);
        json.PushObject(jarray, json_proto);
    }

    ndpi_free(ndpi);

    json.ToString(json_string, false);
    json_string.append("\n");

    json.Destroy();
}

static void nd_json_add_interfaces(json_object *parent)
{
    json_object *jobj;
    ndJson json(parent);
/*
    char addr[INET6_ADDRSTRLEN];
    struct ifaddrs *ifap = NULL, *p = NULL;

    if (getifaddrs(&ifap) < 0) {
        nd_printf("Error collecting interface addresses: %s\n",
            strerror(errno));
    }
*/
    for (nd_ifaces::const_iterator i = ifaces.begin(); i != ifaces.end(); i++) {
/*
        for (p = ifap; p != NULL; p = p->ifa_next) {
            if (strncmp(p->ifa_name, i->second.c_str(), IFNAMSIZ)) continue;
            break;
        }
*/
        string iface_name;
        nd_iface_name(i->second, iface_name);

        jobj = json.CreateObject(NULL, iface_name);
        json.AddObject(jobj, "role", (i->first) ? "LAN" : "WAN");
/*
        if (p == NULL) continue;

        inet_ntop(p->ifa_addr, &new_flow->lower_addr.s_addr,
            new_flow->lower_ip, INET_ADDRSTRLEN);

        inet_ntop(AF_INET6, &new_flow->lower_addr6.s6_addr,
            new_flow->lower_ip, INET6_ADDRSTRLEN);
*/
    }

//    if (ifap) freeifaddrs(ifap);
}

static void nd_json_add_devices(json_object *parent)
{
    ndJson json(parent);
    json_object *jarray;
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

        sprintf(mac_dst, "%02x:%02x:%02x:%02x:%02x:%02x",
            mac_src[0], mac_src[1], mac_src[2],
            mac_src[3], mac_src[4], mac_src[5]);

        jarray = json.CreateArray(NULL, mac_dst);

        for (vector<string>::const_iterator j = i->second.begin();
            j != i->second.end(); j++) {
            json.PushObject(jarray, (*j));
        }
    }
}

static void nd_json_add_stats(json_object *parent,
    const nd_packet_stats *stats, struct pcap_stat *pcap)
{
    ndJson json(parent);

    json.AddObject(NULL, "raw", stats->pkt_raw);
    json.AddObject(NULL, "ethernet", stats->pkt_eth);
    json.AddObject(NULL, "mpls", stats->pkt_mpls);
    json.AddObject(NULL, "pppoe", stats->pkt_pppoe);
    json.AddObject(NULL, "vlan", stats->pkt_vlan);
    json.AddObject(NULL, "fragmented", stats->pkt_frags);
    json.AddObject(NULL, "discarded", stats->pkt_discard);
    json.AddObject(NULL, "discarded_bytes", stats->pkt_discard_bytes);
    json.AddObject(NULL, "largest_bytes", stats->pkt_maxlen);
    json.AddObject(NULL, "ip", stats->pkt_ip);
    json.AddObject(NULL, "tcp", stats->pkt_tcp);
    json.AddObject(NULL, "udp", stats->pkt_udp);
    json.AddObject(NULL, "icmp", stats->pkt_icmp);
    json.AddObject(NULL, "igmp", stats->pkt_igmp);
    json.AddObject(NULL, "ip_bytes", stats->pkt_ip_bytes);
    json.AddObject(NULL, "wire_bytes", stats->pkt_wire_bytes);
    json.AddObject(NULL, "pcap_recv", pcap->ps_recv);
    json.AddObject(NULL, "pcap_drop", pcap->ps_drop);
    json.AddObject(NULL, "pcap_ifdrop", pcap->ps_ifdrop);
}

static void nd_json_add_flows(
    const string &device, json_object *parent,
    struct ndpi_detection_module_struct *ndpi,
    const nd_flow_map *flows, bool unknown = true)
{
    ndJson json(parent);

    for (nd_flow_map::const_iterator i = flows->begin();
        i != flows->end(); i++) {

        if (i->second->detection_complete == false)
            continue;
        if (unknown == false &&
            i->second->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN)
            continue;
        if (i->second->lower_packets == 0 && i->second->upper_packets == 0)
            continue;

        json_object *json_flow = i->second->json_encode(device, json, ndpi);
        json.PushObject(NULL, json_flow);

        i->second->lower_bytes = i->second->upper_bytes = 0;
        i->second->lower_packets = i->second->upper_packets = 0;
    }
}

static void nd_json_add_file(
    json_object *parent, const string &type, const string &filename)
{
    char *c, *p, buffer[ND_FILE_BUFSIZ];
    FILE *fh = fopen(filename.c_str(), "r");

    if (fh == NULL) {
        nd_printf("Error opening file for upload: %s: %s\n",
            filename.c_str(), strerror(errno));
        return;
    }

    ndJson json(parent);
    json_object *json_lines = json.CreateArray(NULL, type.c_str());

    p = buffer;
    while (fgets(buffer, ND_FILE_BUFSIZ, fh) != NULL) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\r') continue;
        c = (char *)memchr((void *)p, '\n', ND_FILE_BUFSIZ - (p - buffer));
        if (c != NULL) *c = '\0';

        json.PushObject(json_lines, p);
    }

    fclose(fh);
}

static void nd_print_stats(uint32_t flow_count, nd_packet_stats &stats)
{
    struct timespec ts_now;
    static uint32_t flow_count_previous = 0;

    if (! ND_USE_NCURSES) {
        nd_printf("\n");
        nd_printf("Cumulative Packet Totals ");
        if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts_now) != 0)
            nd_printf("(clock_gettime: %s):\n", strerror(errno));
        else {
            nd_printf("(+%lus):\n",
                ts_now.tv_sec - nd_ts_epoch.tv_sec);
        }

        nd_print_number(*nd_stats_os, stats.pkt_raw, false);
        nd_printf("%12s: %s ", "Wire", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_eth, false);
        nd_printf("%12s: %s ", "ETH", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_vlan, false);
        nd_printf("%12s: %s\n", "VLAN", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_ip, false);
        nd_printf("%12s: %s ", "IP", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_ip4, false);
        nd_printf("%12s: %s ", "IPv4", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_ip6, false);
        nd_printf("%12s: %s\n", "IPv6", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_icmp + stats.pkt_igmp, false);
        nd_printf("%12s: %s ", "ICMP/IGMP", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_udp, false);
        nd_printf("%12s: %s ", "UDP", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_tcp, false);
        nd_printf("%12s: %s\n", "TCP", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_mpls, false);
        nd_printf("%12s: %s ", "MPLS", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_pppoe, false);
        nd_printf("%12s: %s\n", "PPPoE", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_frags, false);
        nd_printf("%12s: %s ", "Frags", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_discard, false);
        nd_printf("%12s: %s ", "Discarded", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_maxlen);
        nd_printf("%12s: %s\n", "Largest", (*nd_stats_os).str().c_str());

        nd_printf("\nCumulative Byte Totals:\n");

        nd_print_number(*nd_stats_os, stats.pkt_wire_bytes);
        nd_printf("%12s: %s\n", "Wire", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_ip_bytes);
        nd_printf("%12s: %s ", "IP", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_ip4_bytes);
        nd_printf("%12s: %s ", "IPv4", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_ip6_bytes);
        nd_printf("%12s: %s\n", "IPv6", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_discard_bytes);
        nd_printf("%39s: %s ", "Discarded", (*nd_stats_os).str().c_str());

        (*nd_stats_os).str("");
        (*nd_stats_os) << setw(8) << flow_count;

        nd_printf("%12s: %s (%s%d)", "Flows", (*nd_stats_os).str().c_str(),
            (flow_count > flow_count_previous) ? "+" : "",
            int(flow_count - flow_count_previous));
        nd_printf("\n\n");
    }
#ifdef _ND_USE_NCURSES
    else {
        //wclear(win_stats);
        nd_printf_lock();
        wmove(win_stats, 0, 0);
        wattrset(win_stats, A_BOLD | A_REVERSE);
        for (int i = 0; i < COLS; i++) waddch(win_stats, ' ');
        wmove(win_stats, 0, 0);
        nd_printf_unlock();
        nd_printw(win_stats, "%s v%s", PACKAGE_NAME, PACKAGE_VERSION);
        wattrset(win_stats, A_NORMAL);
        wmove(win_stats, 1, 0);

        nd_printw(win_stats, " Cumulative Packet Totals ");
        if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts_now) != 0)
            nd_printw(win_stats, "(clock_gettime: %s):\n", strerror(errno));
        else {
            nd_printw(win_stats, "(+%lus):\n",
                ts_now.tv_sec - nd_ts_epoch.tv_sec);
        }

        nd_print_number(*nd_stats_os, stats.pkt_raw, false);
        nd_printw(win_stats, "%10s: %s ", "Wire", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_eth, false);
        nd_printw(win_stats, "%12s: %s ", "ETH", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_vlan, false);
        nd_printw(win_stats, "%12s: %s", "VLAN", (*nd_stats_os).str().c_str());
        wclrtoeol(win_stats);
        nd_printw(win_stats, "\n");

        nd_print_number(*nd_stats_os, stats.pkt_ip, false);
        nd_printw(win_stats, "%10s: %s ", "IP", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_ip4, false);
        nd_printw(win_stats, "%12s: %s ", "IPv4", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_ip6, false);
        nd_printw(win_stats, "%12s: %s", "IPv6", (*nd_stats_os).str().c_str());
        wclrtoeol(win_stats);
        nd_printw(win_stats, "\n");

        nd_print_number(*nd_stats_os, stats.pkt_icmp + stats.pkt_igmp, false);
        nd_printw(win_stats, "%10s: %s ", "ICMP/IGMP", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_udp, false);
        nd_printw(win_stats, "%12s: %s ", "UDP", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_tcp, false);
        nd_printw(win_stats, "%12s: %s", "TCP", (*nd_stats_os).str().c_str());
        wclrtoeol(win_stats);
        nd_printw(win_stats, "\n");

        nd_print_number(*nd_stats_os, stats.pkt_mpls, false);
        nd_printw(win_stats, "%10s: %s ", "MPLS", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_pppoe, false);
        nd_printw(win_stats, "%12s: %s", "PPPoE", (*nd_stats_os).str().c_str());
        wclrtoeol(win_stats);
        nd_printw(win_stats, "\n");

        nd_print_number(*nd_stats_os, stats.pkt_frags, false);
        nd_printw(win_stats, "%10s: %s ", "Frags", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_discard, false);
        nd_printw(win_stats, "%12s: %s ", "Discarded", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_maxlen);
        nd_printw(win_stats, "%12s: %s", "Largest", (*nd_stats_os).str().c_str());
        wclrtoeol(win_stats);
        nd_printw(win_stats, "\n");

        nd_printw(win_stats, " Cumulative Byte Totals:\n");

        nd_print_number(*nd_stats_os, stats.pkt_wire_bytes);
        nd_printw(win_stats, "%10s: %s", "Wire", (*nd_stats_os).str().c_str());
        wclrtoeol(win_stats);
        nd_printw(win_stats, "\n");

        nd_print_number(*nd_stats_os, stats.pkt_ip_bytes);
        nd_printw(win_stats, "%10s: %s ", "IP", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_ip4_bytes);
        nd_printw(win_stats, "%12s: %s ", "IPv4", (*nd_stats_os).str().c_str());

        nd_print_number(*nd_stats_os, stats.pkt_ip6_bytes);
        nd_printw(win_stats, "%12s: %s", "IPv6", (*nd_stats_os).str().c_str());
        wclrtoeol(win_stats);
        nd_printw(win_stats, "\n");

        nd_print_number(*nd_stats_os, stats.pkt_discard_bytes);
        nd_printw(win_stats, "%37s: %s ", "Discarded", (*nd_stats_os).str().c_str());

        (*nd_stats_os).str("");
        (*nd_stats_os) << setw(8) << flow_count;

        nd_printw(win_stats, "%12s: %s (%s%d)", "Flows", (*nd_stats_os).str().c_str(),
            (flow_count > flow_count_previous) ? "+" : "",
            int(flow_count - flow_count_previous));
        wclrtoeol(win_stats);
        wrefresh(win_stats);
    }
#endif
    flow_count_previous = flow_count;
}

static void nd_load_ethers(void)
{
    char buffer[1024 + ND_STR_ETHALEN + 17];

    struct stat ethers_stat;
    if (stat(ND_ETHERS_FILE_NAME, &ethers_stat) < 0) {
        cerr << "Can not stat ethers file: " << ND_ETHERS_FILE_NAME <<
            ": " << strerror(errno) << endl;
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
            //nd_printf("%2lu: %02x:%02x:%02x:%02x:%02x:%02x (%s): %s\n", line,
            //    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ether, name);
        }
    }

    fclose(fh);

    nd_debug_printf("Loaded %lu entries from: %s\n",
        device_ethers.size(), ND_ETHERS_FILE_NAME);
}

static void nd_dump_stats(void)
{
    string digest;
    uint32_t flow_count = 0;

    ndJson json;
    json_object *json_obj = NULL;
    json_object *json_ifaces = NULL;
    json_object *json_devices = NULL;
    json_object *json_stats = NULL;
    json_object *json_flows = NULL;

    if (ND_USE_SINK || ND_JSON_SAVE) {
        json.AddObject(NULL, "version", (double)ND_JSON_VERSION);
        json.AddObject(NULL, "timestamp", (int64_t)time(NULL));
        nd_sha1_to_string(nd_config.digest_content_match, digest);
        json.AddObject(NULL, "content_match_digest", digest);
        nd_sha1_to_string(nd_config.digest_custom_match, digest);
        json.AddObject(NULL, "custom_match_digest", digest);
        nd_sha1_to_string(nd_config.digest_host_match, digest);
        json.AddObject(NULL, "host_match_digest", digest);

        struct rusage rusage_data;
        getrusage(RUSAGE_SELF, &rusage_data);
#if (SIZEOF_LONG == 4)
        json.AddObject(NULL, "maxrss_kb", (uint32_t)rusage_data.ru_maxrss);
#elif (SIZEOF_LONG == 8)
        json.AddObject(NULL, "maxrss_kb", (uint64_t)rusage_data.ru_maxrss);
#endif
        json_ifaces = json.CreateObject(NULL, "interfaces");
        json_devices = json.CreateObject(NULL, "devices");
        json_stats = json.CreateObject(NULL, "stats");
        json_flows = json.CreateObject(NULL, "flows");

        nd_json_add_interfaces(json_ifaces);
        nd_json_add_devices(json_devices);
    }

    for (nd_threads::iterator i = threads.begin();
        i != threads.end(); i++) {

        i->second->Lock();

        totals += *stats[i->first];
        flow_count += flows[i->first]->size();

        if (ND_USE_SINK || ND_JSON_SAVE) {
            struct pcap_stat pcap;
            i->second->GetCaptureStats(pcap);

            json_obj = json.CreateObject();
            nd_json_add_stats(json_obj, stats[i->first], &pcap);

            string iface_name;
            nd_iface_name(i->first, iface_name);
            json_object_object_add(json_stats, iface_name.c_str(), json_obj);

            json_obj = json.CreateArray(json_flows, iface_name);
            nd_json_add_flows(iface_name, json_obj,
                i->second->GetDetectionModule(), flows[i->first]);
        }

        memset(stats[i->first], 0, sizeof(nd_packet_stats));

        i->second->Unlock();
    }

    if (ND_USE_SINK) {
        try {
#ifdef _ND_USE_INOTIFY
            for (nd_inotify_watch::const_iterator i = inotify_watches.begin();
                i != inotify_watches.end(); i++) {
                if (! inotify->EventOccured(i->first)) continue;
                nd_json_add_file(json.GetRoot(), i->first, i->second);
            }
#endif
            string json_string;
            json.ToString(json_string);
#ifdef _ND_USE_WATCHDOGS
            nd_touch(ND_WD_UPLOAD);
#endif
            thread_upload->QueuePush(json_string);
        }
        catch (runtime_error &e) {
            nd_printf("Error pushing JSON payload to upload queue: %s\n", e.what());
        }
    }

    try {
        if (ND_JSON_SAVE)
            json.SaveToFile(nd_config.path_json);
    }
    catch (runtime_error &e) {
        nd_printf("Error writing JSON playload to file: %s: %s\n",
            nd_config.path_json, e.what());
    }

    json.Destroy();

    if (ND_DEBUG) {
        if (ND_DEBUG_WITH_ETHERS) nd_load_ethers();
        nd_print_stats(flow_count, totals);
    }
}

static void nd_dump_protocols(void)
{
    uint32_t custom_proto_base;
    struct ndpi_detection_module_struct *ndpi;

    ndpi_global_init();

    ndpi = nd_ndpi_init("netifyd", custom_proto_base);

    for (unsigned i = 0; i < (unsigned)ndpi->ndpi_num_supported_protocols; i++)
        printf("%4d: %s\n", i, ndpi->proto_defaults[i].protoName);

    ndpi_free(ndpi);
    ndpi_global_init();
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
            nd_printf("WARNING: Invalid address, use CIDR notation: %s\n",
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
            nd_printf("WARNING: Not an IPv4 or IPv6 address: %s\n", address);
            continue;
        }

        const char *length = strtok(NULL, "/");
        if (length == NULL) {
            nd_printf("WARNING: Invalid address, use CIDR notation: %s\n",
                (*i).second.c_str());
            continue;
        }

        uint8_t _length = (uint8_t)atoi(length);
        if (_length == 0 || (
            (family == AF_INET && _length > 32) ||
            (family == AF_INET6 && _length > 128))) {
            nd_printf("WARNING: Invalid network length: %hu\n", _length);
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
                nd_printf("WARNING: Error adding device address: %s\n", bcastaddr);

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
            nd_printf("WARNING: Error adding device network: %s\n",
                (*i).second.c_str());
        }

        if (! netlink->AddAddress(family, (*i).first, address)) {
            nd_printf("WARNING: Error adding device address: %s\n", address);
        }
    }

    if (token != NULL) free(token);
}
#endif // _ND_USE_NETLINK
static void nd_check_agent_uuid(void)
{
    if (nd_config.uuid == NULL ||
        ! strncmp(nd_config.uuid, ND_AGENT_UUID_NULL, ND_AGENT_UUID_LEN)) {
        string uuid;
        if (! nd_load_uuid(uuid, ND_AGENT_UUID_PATH, ND_AGENT_UUID_LEN) ||
            ! uuid.size() ||
            ! strncmp(uuid.c_str(), ND_AGENT_UUID_NULL, ND_AGENT_UUID_LEN)) {
            nd_generate_uuid(uuid);
            nd_printf("Generated a new UUID: %s\n", uuid.c_str());
            nd_save_uuid(uuid, ND_AGENT_UUID_PATH, ND_AGENT_UUID_LEN);
        }
        if (nd_config.uuid != NULL)
            free(nd_config.uuid);
        nd_config.uuid = strdup(uuid.c_str());
    }
}
#ifdef _ND_USE_NCURSES
static void nd_create_windows(void)
{
    win_stats = newwin(11, COLS, 0, 0);
    win_output = newwin(LINES - 11, COLS, 11 + 1, 0);
    scrollok(win_output, true);
    curs_set(0);
}
#endif
int main(int argc, char *argv[])
{
    int rc = 0;
    bool terminate = false;
    sigset_t sigset;
    struct sigevent sigev;
    timer_t timer_id;
    struct itimerspec it_spec;
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

    nd_printf_mutex = new pthread_mutex_t;
    pthread_mutex_init(nd_printf_mutex, NULL);

    pthread_mutex_init(&dns_cache.lock, NULL);
#ifdef HAVE_CXX11
    dns_cache.map_ar.reserve(ND_HASH_BUCKETS_DNSARS);
#endif
    static struct option options[] =
    {
        { "help", 0, 0, 'h' },
        { "version", 0, 0, 'V' },
        { "debug", 0, 0, 'd' },
        { "debug-ether-names", 0, 0, 'e' },
        { "debug-uploads", 0, 0, 'D' },
        { "debug-dns-cache", 0, 0, 's' },
        { "replay-delay", 0, 0, 'r' },
        { "uuid", 1, 0, 'u' },
        { "serial", 1, 0, 's' },
        { "internal", 1, 0, 'I' },
        { "external", 1, 0, 'E' },
        { "json", 1, 0, 'j' },
        { "interval", 1, 0, 'i' },
        { "config", 1, 0, 'c' },
        { "uuidgen", 0, 0, 'U' },
        { "protocols", 0, 0, 'P' },
        { "device-address", 1, 0, 'A' },
        { "device-filter", 1, 0, 'F' },
#ifdef _ND_USE_NETLINK
        { "device-netlink", 1, 0, 'N' },
#endif
        { "custom-match", 1, 0, 'f' },
        { "content-match", 1, 0, 'C' },
        { "host-match", 1, 0, 'H' },
        { "hash-file", 1, 0, 'S' },
        { "disable-conntrack", 0, 0, 't' },
        { "disable-netlink", 0, 0, 'l' },
        { "enable-ncurses", 0, 0, 'n' },
        { "provision", 0, 0, 'p' },

        { NULL, 0, 0, 0 }
    };

    for (optind = 1;; ) {
        int o = 0;
        if ((rc = getopt_long(argc, argv,
            "?hVdDaenrtlpu:s:I:E:j:i:c:UPA:N:f:H:C:S:F:",
            options, &o)) == -1) break;
        switch (rc) {
        case '?':
            cerr <<
                "Try " << argv[0] << " --help for more information." << endl;
            return 1;
        case 'h':
            nd_usage();
        case 'V':
            nd_usage(0, true);
        case 'd':
            nd_config.flags |= ndGF_DEBUG;
            break;
        case 'D':
            nd_config.flags |= ndGF_DEBUG_UPLOAD;
            break;
        case 'e':
            nd_config.flags |= ndGF_DEBUG_WITH_ETHERS;
            break;
        case 'a':
            nd_config.flags |= ndGF_DEBUG_DNS_CACHE;
            break;
        case 'r':
            nd_config.flags |= ndGF_REPLAY_DELAY;
            break;
        case 'u':
            nd_config.uuid = strdup(optarg);
            break;
        case 's':
            nd_config.uuid_serial = strdup(optarg);
            break;
        case 'I':
            for (nd_ifaces::iterator i = ifaces.begin();
                i != ifaces.end(); i++) {
                if (strcasecmp((*i).second.c_str(), optarg) == 0) {
                    cerr << "Duplicate interface specified: " << optarg << endl;
                    exit(1);
                }
            }
            last_device = optarg;
            ifaces.push_back(make_pair(true, optarg));
            break;
        case 'E':
            for (nd_ifaces::iterator i = ifaces.begin();
                i != ifaces.end(); i++) {
                if (strcasecmp((*i).second.c_str(), optarg) == 0) {
                    cerr << "Duplicate interface specified: " << optarg << endl;
                    exit(1);
                }
            }
            last_device = optarg;
            ifaces.push_back(make_pair(false, optarg));
            break;
        case 'j':
            nd_config.path_json = strdup(optarg);
            break;
        case 'i':
            nd_config.update_interval = atoi(optarg);
            break;
        case 'c':
            nd_conf_filename = strdup(optarg);
            break;
        case 'U':
            {
                string uuid;
                nd_generate_uuid(uuid);
                nd_config.flags |= ndGF_DEBUG;
                nd_printf("%s\n", uuid.c_str());
            }
            exit(0);
        case 'P':
            nd_dump_protocols();
            exit(0);
        case 'A':
            if (last_device.size() == 0) {
                cerr << "You must specify an interface first." << endl;
                exit(1);
            }
            device_addresses.push_back(make_pair(last_device, optarg));
            break;
        case 'F':
            if (last_device.size() == 0) {
                cerr << "You must specify an interface first." << endl;
                exit(1);
            }
            if (nd_config.device_filters
                .find(last_device) != nd_config.device_filters.end()) {
                cerr << "Only one filter can be applied to a device." << endl;
                exit(1);
            }
            nd_config.device_filters[last_device] = optarg;
            break;
#ifdef _ND_USE_NETLINK
        case 'N':
            if (last_device.size() == 0) {
                cerr << "You must specify an interface first." << endl;
                exit(1);
            }
            device_netlink[last_device] = optarg;
            break;
#endif
        case 'C':
            free(nd_config.path_content_match);
            nd_config.path_content_match = strdup(optarg);
            nd_config.flags |= ndGF_OVERRIDE_CONTENT_MATCH;
            break;
        case 'f':
            free(nd_config.path_custom_match);
            nd_config.path_custom_match = strdup(optarg);
            nd_config.flags |= ndGF_OVERRIDE_CUSTOM_MATCH;
            break;
        case 'H':
            free(nd_config.path_host_match);
            nd_config.path_host_match = strdup(optarg);
            nd_config.flags |= ndGF_OVERRIDE_HOST_MATCH;
            break;
        case 'S':
            {
                uint8_t digest[SHA1_DIGEST_LENGTH];

                nd_config.flags |= ndGF_DEBUG;

                if (nd_sha1_file(optarg, digest) < 0) return 1;
                else {
                    string sha1;
                    nd_sha1_to_string(digest, sha1);
                    nd_printf("%s\n", sha1.c_str());
                    return 0;
                }
            }
            break;
        case 't':
            nd_config.flags &= ~ndGF_USE_CONNTRACK;
            break;
        case 'l':
            nd_config.flags &= ~ndGF_USE_NETLINK;
            break;
        case 'n':
#if _ND_USE_NCURSES
            nd_config.flags |= ndGF_DEBUG;
#else
            nd_printf("Sorry, ncurses was not enabled for this build.\n");
            return 1;
#endif
            break;
        case 'p':
            nd_config.flags |= ndGF_DEBUG;
            if (nd_conf_filename == NULL)
                nd_conf_filename = strdup(ND_CONF_FILE_NAME);
            if (nd_config_load() < 0)
                return 1;
            nd_check_agent_uuid();
            if (nd_config.uuid == NULL) return 1;
            nd_printf("Netify Agent Provisioning UUID: %s\n", nd_config.uuid);
            nd_printf("%s%s\n", ND_URL_PROVISION, nd_config.uuid);
            return 0;
        default:
            nd_usage(1);
        }
    }

    if (nd_config.path_json == NULL)
        nd_config.path_json = strdup(ND_JSON_FILE_NAME);

    if (nd_conf_filename == NULL)
        nd_conf_filename = strdup(ND_CONF_FILE_NAME);

    if (nd_config_load() < 0)
        return 1;

    if (ifaces.size() == 0) {
        cerr <<
            "Required argument, (-I, --internal, or -E, --external) missing." <<
            endl;
        return 1;
    }

    CURLcode cc;
    if ((cc = curl_global_init(CURL_GLOBAL_ALL)) != 0) {
        cerr << "Unable to initialize libCURL: " << cc << endl;
        return 1;
    }

    if (! ND_DEBUG) {
        if (daemon(1, 0) != 0) {
            nd_printf("daemon: %s\n", strerror(errno));
            return 1;
        }

        FILE *hpid = fopen(ND_PID_FILE_NAME, "w+");
        if (hpid == NULL) {
            nd_printf("Error opening PID file: %s: %s\n",
                ND_PID_FILE_NAME, strerror(errno));
            return 1;
        }
        fprintf(hpid, "%d\n", getpid());
        fclose(hpid);
    }

    if (clock_gettime(CLOCK_MONOTONIC_RAW, &nd_ts_epoch) != 0) {
        nd_printf("Error getting epoch time: %s\n", strerror(errno));
        return 1;
    }

#ifdef _ND_USE_NCURSES
    if (ND_USE_NCURSES) {
        initscr();
        nd_create_windows();
    }
#endif
    nd_printf("%s\n", nd_get_version_and_features().c_str());
    nd_check_agent_uuid();
    nd_debug_printf("Flow entry size: %lu\n", sizeof(struct ndFlow) +
        sizeof(struct ndpi_flow_struct) + sizeof(struct ndpi_id_struct) * 2);

    memset(&totals, 0, sizeof(nd_packet_stats));

    if (ND_USE_DNS_CACHE) dns_cache.load();

    nd_sha1_file(
        nd_config.path_content_match, nd_config.digest_content_match);
    nd_sha1_file(
        nd_config.path_custom_match, nd_config.digest_custom_match);
    nd_sha1_file(
        nd_config.path_host_match, nd_config.digest_host_match);

    sigfillset(&sigset);
    //sigdelset(&sigset, SIGPROF);
    //sigdelset(&sigset, SIGINT);
    sigdelset(&sigset, SIGQUIT);
    sigprocmask(SIG_BLOCK, &sigset, NULL);

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, ND_SIG_UPDATE);
    sigaddset(&sigset, SIGIO);
    sigaddset(&sigset, SIGHUP);
#ifdef _ND_USE_NCURSES
    if (ND_USE_NCURSES)
        sigaddset(&sigset, SIGWINCH);
#endif
    nd_load_ethers();

    try {
#ifdef _ND_USE_CONNTRACK
        if (ND_USE_CONNTRACK) {
            thread_conntrack = new ndConntrackThread();
            thread_conntrack->Create();
        }
#endif
        if (nd_config.socket_host.size() || nd_config.socket_path.size()) {
            thread_socket = new ndSocketThread();
            thread_socket->Create();
        }

        if (ND_USE_SINK) {
            thread_upload = new ndUploadThread();
            thread_upload->Create();
        }
    }
    catch (ndUploadThreadException &e) {
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

    memset(&sigev, 0, sizeof(struct sigevent));
    sigev.sigev_notify = SIGEV_SIGNAL;
    sigev.sigev_signo = ND_SIG_UPDATE;

    if (timer_create(CLOCK_REALTIME, &sigev, &timer_id) < 0) {
        nd_printf("timer_create: %s\n", strerror(errno));
        return 1;
    }

    it_spec.it_value.tv_sec = nd_config.update_interval;
    it_spec.it_value.tv_nsec = 0;
    it_spec.it_interval.tv_sec = nd_config.update_interval;
    it_spec.it_interval.tv_nsec = 0;

    timer_settime(timer_id, 0, &it_spec, NULL);
#ifdef _ND_USE_NCURSES
    if (ND_USE_NCURSES) nd_print_stats(0, totals);
#endif
#ifdef _ND_USE_NETLINK
    if (ND_USE_NETLINK)
        netlink->Refresh();
#endif
    while (! terminate) {
        int sig;
        siginfo_t si;

        if ((sig = sigwaitinfo(&sigset, &si)) < 0) {
            if (errno == EINTR) {
                usleep(50000);
                continue;
            }

            nd_printf("sigwaitinfo: %s\n", strerror(errno));
            rc = -1;
            terminate = true;
            continue;
        }

        nd_debug_printf("Caught signal: [%d] %s\n", sig, strsignal(sig));

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

            if (ND_USE_DNS_CACHE) {
                dns_cache.purge();
                if (ND_DNS_CACHE_SAVE)
                    dns_cache.save();
            }

            nd_reap_detection_threads();

            if (threads.size() == 0) {
                if (thread_upload == NULL ||
                    thread_upload->QueuePendingSize() == 0) {
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

#ifdef _ND_USE_NETLINK
            if (ND_USE_NETLINK &&
                netlink->GetDescriptor() == si.si_fd) {
                if (netlink->ProcessEvent())
                    if (ND_DEBUG) netlink->Dump();
            }
#endif
            continue;
        }

        if (sig == SIGHUP) {
            nd_stop_detection_threads();
            if (nd_start_detection_threads() < 0) break;

            if (thread_socket) {
                string json;
                nd_json_protocols(json);
                thread_socket->QueueWrite(json);
            }

            continue;
        }
#ifdef _ND_USE_NCURSES
        if (sig == SIGWINCH) {
            nd_printf_lock();
            delwin(win_stats);
            delwin(win_output);
            endwin();
            refresh();
            nd_create_windows();
            nd_printf_unlock();
            nd_print_stats(0, totals);
            continue;
        }
#endif
        nd_printf("Unhandled signal: %s\n", strsignal(sig));
    }

    timer_delete(timer_id);

    nd_stop_detection_threads();

    if (thread_upload) {
        thread_upload->Terminate();
        delete thread_upload;
    }

    if (thread_socket) {
        thread_socket->Terminate();
        delete thread_socket;
    }
#ifdef _ND_USE_CONNTRACK
    if (ND_USE_CONNTRACK) {
        thread_conntrack->Terminate();
        delete thread_conntrack;
    }
#endif
    if (ND_USE_DNS_CACHE && ND_DNS_CACHE_SAVE)
        dns_cache.save();
    pthread_mutex_destroy(&dns_cache.lock);

    pthread_mutex_destroy(nd_printf_mutex);
    delete nd_printf_mutex;

    curl_global_cleanup();
#ifdef _ND_USE_NCURSES
    delwin(win_stats);
    delwin(win_output);
    refresh();
    endwin();
#endif
    return 0;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
