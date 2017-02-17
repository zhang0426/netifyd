// Netify Daemon
// Copyright (C) 2015-2016 eGloo Incorporated <http://www.egloo.ca>
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

#include <deque>
#include <iomanip>
#include <iostream>
#include <map>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>

#ifdef _ND_USE_CONNTRACK
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#endif

#include <curl/curl.h>
#include <json.h>
#include <pcap/pcap.h>
#include <pthread.h>

#include "INIReader.h"

#include "ndpi_main.h"

using namespace std;

#include "netifyd.h"
#include "nd-util.h"
#include "nd-inotify.h"
#include "nd-netlink.h"
#include "nd-json.h"
#include "nd-flow.h"
#include "nd-thread.h"
#ifdef _ND_USE_CONNTRACK
#include "nd-conntrack.h"
#endif
#include "nd-detection.h"
#include "nd-socket.h"
#include "nd-upload.h"
#include "nd-ndpi.h"

#define _ND_STR_ALEN    (ETH_ALEN * 2 + ETH_ALEN - 1)

bool nd_debug = false;
pthread_mutex_t *nd_output_mutex = NULL;

static nd_ifaces ifaces;
static nd_devices devices;
static nd_flows flows;
static nd_stats stats;
static nd_threads threads;
static nd_packet_stats totals;
static ndUploadThread *thread_upload = NULL;
static ndSocketThread *thread_socket = NULL;
#ifdef _ND_USE_CONNTRACK
static ndConntrackThread *thread_conntrack = NULL;
#endif
static ndInotify *inotify = NULL;
static ndNetlink *netlink = NULL;

static char *nd_conf_filename = NULL;

ndGlobalConfig nd_config;

static void nd_usage(int rc = 0, bool version = false)
{
    cerr << "Netify Daemon v" << PACKAGE_VERSION << "/";
    cerr << fixed << showpoint << setprecision(1) << ND_JSON_VERSION << endl;
    cerr << "Copyright (C) 2015-2016 eGloo Incorporated"
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

static int nd_config_load(void)
{
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

    string uuid = reader.Get("netifyd", "uuid", "");
    if (uuid.size() > 0)
        nd_config.uuid = strdup(uuid.c_str());
    else {
        cerr << "UUID not set in: " << nd_conf_filename << endl;
        return -1;
    }

    string serial = reader.Get("netifyd", "uuid_serial", "");
    if (serial.size() > 0) {
        if (nd_config.uuid_serial != NULL) free(nd_config.uuid_serial);
        nd_config.uuid_serial = strdup(serial.c_str());
    }

    string url_upload = reader.Get("netifyd", "url_upload", ND_URL_UPLOAD);
    nd_config.url_upload = strdup(url_upload.c_str());

    nd_config.update_interval = (unsigned)reader.GetInteger(
        "netifyd", "update_interval", ND_STATS_INTERVAL);

    nd_config.max_backlog = reader.GetInteger(
        "netifyd", "max_backlog_kb", ND_MAX_BACKLOG_KB) * 1024;

    nd_config.enable_netify_sink = reader.GetBoolean(
        "netifyd", "enable_netify_sink", false);

    nd_config.ssl_verify_peer = reader.GetBoolean(
        "netifyd", "ssl_verify_peer", true);

    nd_config.ssl_use_tlsv1 = reader.GetBoolean(
        "netifyd", "ssl_use_tlsv1", false);

    string uuid_realm = reader.Get("netifyd", "uuid_realm", ND_REALM_UUID_NULL);
    nd_config.uuid_realm = strdup(uuid_realm.c_str());

    for (int i = 0; ; i++) {
        ostringstream os;
        os << "listen_address[" << i << "]";
        string socket_node = reader.Get("socket", os.str(), "");
        if (socket_node.size() > 0) {
            os.str("");
            os << "listen_port[" << i << "]";
            string socket_port = reader.Get("socket", os.str(), ND_SOCKET_PORT);
            nd_config.socket_host.push_back(make_pair(socket_node, socket_port));
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
        string mac_addr = reader.Get("filter", os.str(), "");
        if (mac_addr.size() == _ND_STR_ALEN) {
            uint8_t mac[ETH_ALEN], *p = mac;
            const char *a = mac_addr.c_str();
            for (int j = 0; j < _ND_STR_ALEN; j += 3, p++)
                sscanf(a + j, "%2hhx", p);
            p = new uint8_t[ETH_ALEN];
            memcpy(p, mac, ETH_ALEN);
            nd_config.mac_filter_list.push_back(p);
            continue;
        }

        break;
    }

#if 0
    nd_account_id = reader.GetInteger("account", "id", 0);
    if (nd_account_id == 0) {
        cerr << "Account ID not set in: " << nd_conf_filename << endl;
        return 0;
    }
    string account_key = reader.Get("account", "key", "");
    if (account_key.size() > 0)
        nd_account_key = strdup(account_key.c_str());
    else {
        cerr << "Account Key not set in: " << nd_conf_filename << endl;
        return -1;
    }

    nd_system_id = reader.GetInteger("system", "id", 0);
    if (nd_system_id == 0) {
        cerr << "System ID not set in: " << nd_conf_filename << endl;
        return -1;
    }
#endif
    return 0;
}

int nd_start_detection_threads(void)
{
    for (nd_ifaces::iterator i = ifaces.begin();
        i != ifaces.end(); i++) {
        flows[(*i).second] = new nd_flow_map;
        stats[(*i).second] = new nd_packet_stats;
        devices[(*i).second] = ((*i).first) ? new nd_device_addrs : NULL;
    }

    try {
        long cpu = 0;
        long cpus = sysconf(_SC_NPROCESSORS_ONLN);

        for (nd_ifaces::iterator i = ifaces.begin();
            i != ifaces.end(); i++) {
            threads[(*i).second] = new ndDetectionThread(
                (*i).second,
                netlink,
                (i->first) ? thread_socket : NULL,
#ifdef _ND_USE_CONNTRACK
                (i->first || nd_config.disable_conntrack) ?
                    NULL : thread_conntrack,
#endif
                flows[(*i).second],
                stats[(*i).second],
                devices[(*i).second],
                (ifaces.size() > 1) ? cpu++ : -1
            );
            threads[(*i).second]->Create();
            if (cpu == cpus) cpu = 0;
        }
    }
    catch (exception &e) {
        nd_printf("Runtime error: %s\n", e.what());
        return -1;
    }

    return 0;
}

void nd_stop_detection_threads(void)
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
    }

    threads.clear();
    flows.clear();
    stats.clear();
}

void nd_packet_stats::print(const char *tag)
{
    nd_printf("          RAW: %llu\n", pkt_raw);
    nd_printf("          ETH: %llu\n", pkt_eth);
    nd_printf("           IP: %llu\n", pkt_ip);
    nd_printf("          TCP: %llu\n", pkt_tcp);
    nd_printf("          UDP: %llu\n", pkt_udp);
    nd_printf("         MPLS: %llu\n", pkt_mpls);
    nd_printf("        PPPoE: %llu\n", pkt_pppoe);
    nd_printf("         VLAN: %llu\n", pkt_vlan);
    nd_printf("        Frags: %llu\n", pkt_frags);
    nd_printf("      Largest: %lu\n", pkt_maxlen);
    nd_printf("     IP bytes: %llu\n", pkt_ip_bytes);
    nd_printf("   Wire bytes: %llu\n", pkt_wire_bytes);
    nd_printf("    Discarded: %llu\n", pkt_discard);
    nd_printf("Discard bytes: %llu\n", pkt_discard_bytes);
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
        jobj = json.CreateObject(NULL, i->second);
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

                if (!duplicate)
                    device_addrs[j->first].push_back((*k));
            }
        }

        i->second->clear();
    }

    for (nd_device_addrs::const_iterator i = device_addrs.begin();
        i != device_addrs.end(); i++) {

        uint8_t mac_src[ETH_ALEN];
        memcpy(mac_src, i->first.c_str(), ETH_ALEN);
        char mac_dst[_ND_STR_ALEN + 1];

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

static void nd_json_add_stats(json_object *parent, const nd_packet_stats *stats)
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
    json.AddObject(NULL, "ip_bytes", stats->pkt_ip_bytes);
    json.AddObject(NULL, "wire_bytes", stats->pkt_wire_bytes);
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
            i->second->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN)
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
    FILE *hf = fopen(filename.c_str(), "r");

    if (hf == NULL) {
        nd_printf("Error opening file for upload: %s: %s\n",
            filename.c_str(), strerror(errno));
        return;
    }

    ndJson json(parent);
    json_object *json_lines = json.CreateArray(NULL, type.c_str());

    p = buffer;
    while (fgets(buffer, ND_FILE_BUFSIZ, hf) != NULL) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\r') continue;
        c = (char *)memchr((void *)p, '\n', ND_FILE_BUFSIZ - (p - buffer));
        if (c != NULL) *c = '\0';

        json.PushObject(json_lines, p);
    }

    fclose(hf);
}

static void nd_json_upload(ndJson *json)
{
    if (inotify->EventOccured(ND_WATCH_HOSTS))
        nd_json_add_file(json->GetRoot(), "hosts", ND_WATCH_HOSTS);
    if (inotify->EventOccured(ND_WATCH_ETHERS))
        nd_json_add_file(json->GetRoot(), "ethers", ND_WATCH_ETHERS);

    string json_string;
    json->ToString(json_string);

    thread_upload->QueuePush(json_string);
}

static void nd_dump_stats(void)
{
    string digest;
    uint32_t flow_count = 0;

    ndJson json;
    json_object *json_obj;

    json.AddObject(NULL, "version", (double)ND_JSON_VERSION);
    json.AddObject(NULL, "timestamp", (int64_t)time(NULL));
    nd_sha1_to_string(nd_config.digest_content_match, digest);
    json.AddObject(NULL, "content_match_digest", digest);
    nd_sha1_to_string(nd_config.digest_custom_match, digest);
    json.AddObject(NULL, "custom_match_digest", digest);
    nd_sha1_to_string(nd_config.digest_host_match, digest);
    json.AddObject(NULL, "host_match_digest", digest);

    json_object *json_ifaces = json.CreateObject(NULL, "interfaces");
    json_object *json_devices = json.CreateObject(NULL, "devices");
    json_object *json_stats = json.CreateObject(NULL, "stats");
    json_object *json_flows = json.CreateObject(NULL, "flows");

    nd_json_add_interfaces(json_ifaces);
    nd_json_add_devices(json_devices);

    for (nd_threads::iterator i = threads.begin();
        i != threads.end(); i++) {

        i->second->Lock();

        totals += *stats[i->first];
        flow_count += flows[i->first]->size();

        json_obj = json.CreateObject();
        nd_json_add_stats(json_obj, stats[i->first]);
        json_object_object_add(json_stats, i->first.c_str(), json_obj);

        memset(stats[i->first], 0, sizeof(nd_packet_stats));

        json_obj = json.CreateArray(json_flows, i->first);
        nd_json_add_flows(i->first, json_obj,
            i->second->GetDetectionModule(), flows[i->first]);

        i->second->Unlock();
    }

    try {
        json.SaveToFile(nd_config.json_filename);
    }
    catch (runtime_error &e) {
        nd_printf("Error writing JSON file: %s: %s\n",
            nd_config.json_filename, e.what());
    }

    if (nd_config.enable_netify_sink) {
        try {
            nd_json_upload(&json);
        }
        catch (runtime_error &e) {
            nd_printf("Error uploading JSON: %s\n", e.what());
        }
    }

    json.Destroy();

    if (nd_debug) {
        nd_debug_printf("\nCumulative Totals:\n");
        totals.print();
        nd_debug_printf(" Active flows: %lu\n\n", flow_count);
    }
}

void nd_generate_uuid(void)
{
    int digit = 0;
    deque<char> result;
    uint64_t input = 623714775;
    unsigned int seed = (unsigned int)time(NULL);
	const char *clist = { "0123456789abcdefghijklmnpqrstuvwxyz" };
    FILE *fh = fopen("/dev/urandom", "r");

    if (fh == NULL)
        cerr << "Error opening random device: " << strerror(errno) << endl;
    else {
        if (fread((void *)&seed, sizeof(unsigned int), 1, fh) != 1)
            cerr << "Error reading from random device: " << strerror(errno) << endl;
        fclose(fh);
    }

    srand(seed);
    input = (uint64_t)rand();
    input += (uint64_t)rand() << 32;

	while (input != 0) {
		result.push_front(toupper(clist[input % strlen(clist)]));
		input /= strlen(clist);
	}

    for (size_t i = result.size(); i < 8; i++)
        result.push_back('0');

    while (result.size() && digit < 8) {
        fprintf(stdout, "%c", result.front());
        result.pop_front();
        if (digit == 1) fprintf(stdout, "-");
        if (digit == 3) fprintf(stdout, "-");
        if (digit == 5) fprintf(stdout, "-");
        digit++;
    }

    fprintf(stdout, "\n");
}

static void nd_dump_protocols(void)
{
    struct ndpi_detection_module_struct *ndpi;
    ndpi = nd_ndpi_init("netifyd");

    printf("%s\n", nd_config.csv_host_match);

    for (int i = 0; i < (int)ndpi->ndpi_num_supported_protocols; i++)
        printf("%4d: %s\n", i, ndpi->proto_defaults[i].protoName);
}

static void nd_add_device_addresses(vector<pair<string, string> > &device_addresses)
{
    char *token = NULL;
    struct sockaddr_in network_ip4;
    struct sockaddr_in bcast_ip4;
    struct sockaddr_in6 network_ip6;
    int bit, word, words;
    uint32_t b, word_net[4] = { 0, 0, 0, 0 }, word_bcast[1] = { 0 };
    char netaddr[INET6_ADDRSTRLEN], bcastaddr[INET6_ADDRSTRLEN];

    for (vector<pair<string, string> >::const_iterator i = device_addresses.begin();
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

int main(int argc, char *argv[])
{
    int rc = 0;
    bool terminate = false;
    sigset_t sigset;
    struct sigevent sigev;
    timer_t timer_id;
    struct itimerspec it_spec;
    string last_device;
    vector<pair<string, string> > device_addresses;

    memset(&nd_config, 0, sizeof(ndGlobalConfig));
    nd_config.max_backlog = ND_MAX_BACKLOG_KB * 1024;
    nd_config.proto_file = strdup(ND_CONF_CUSTOM_MATCH);
    nd_config.csv_host_match = strdup(ND_CSV_HOST_MATCH);
    nd_config.csv_content_match = strdup(ND_CSV_CONTENT_MATCH);

    nd_output_mutex = new pthread_mutex_t;
    pthread_mutex_init(nd_output_mutex, NULL);

    static struct option options[] =
    {
        { "help", 0, 0, 'h' },
        { "version", 0, 0, 'V' },
        { "debug", 0, 0, 'd' },
        { "serial", 1, 0, 's' },
        { "internal", 1, 0, 'I' },
        { "external", 1, 0, 'E' },
        { "json", 1, 0, 'j' },
        { "interval", 1, 0, 'i' },
        { "config", 1, 0, 'c' },
        { "uuidgen", 0, 0, 'U' },
        { "protocols", 0, 0, 'P' },
        { "device-address", 0, 0, 'A' },
        { "custom-match", 1, 0, 'f' },
        { "content-match", 1, 0, 'C' },
        { "host-match", 1, 0, 'H' },
        { "hash-file", 1, 0, 'S' },
        { "disable-conntrack", 1, 0, 't' },

        { NULL, 0, 0, 0 }
    };

    for (optind = 1;; ) {
        int o = 0;
        if ((rc = getopt_long(argc, argv,
            "?hVds:I:E:j:i:c:UPA:f:H:C:S:t",
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
            nd_debug = true;
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
            nd_config.json_filename = strdup(optarg);
            break;
        case 'i':
            nd_config.update_interval = atoi(optarg);
            break;
        case 'c':
            nd_conf_filename = strdup(optarg);
            break;
        case 'U':
            nd_generate_uuid();
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
        case 'f':
            free(nd_config.proto_file);
            nd_config.proto_file = strdup(optarg);
            break;
        case 'C':
            free(nd_config.csv_content_match);
            nd_config.csv_content_match = strdup(optarg);
            break;
        case 'H':
            free(nd_config.csv_host_match);
            nd_config.csv_host_match = strdup(optarg);
            break;
        case 'S':
            {
                uint8_t digest[SHA1_DIGEST_LENGTH];

                nd_debug = true;

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
            nd_config.disable_conntrack = true;
            break;
        default:
            nd_usage(1);
        }
    }

    if (nd_config.json_filename == NULL)
        nd_config.json_filename = strdup(ND_JSON_FILE_NAME);
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

    if (nd_debug == false) {
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

    nd_printf("Netify Daemon v%s\n", PACKAGE_VERSION);

    memset(&totals, 0, sizeof(nd_packet_stats));

    nd_sha1_file(
        nd_config.csv_content_match, nd_config.digest_content_match);
    nd_sha1_file(
        nd_config.proto_file, nd_config.digest_custom_match);
    nd_sha1_file(
        nd_config.csv_host_match, nd_config.digest_host_match);

    sigfillset(&sigset);
    //sigdelset(&sigset, SIGPROF);

    sigprocmask(SIG_BLOCK, &sigset, NULL);

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGRTMIN);
    sigaddset(&sigset, SIGIO);
    sigaddset(&sigset, SIGHUP);

    try {
#ifdef _ND_USE_CONNTRACK
        if (nd_config.disable_conntrack == false) {
            thread_conntrack = new ndConntrackThread();
            thread_conntrack->Create();
        }
#endif
        thread_socket = new ndSocketThread();
        thread_socket->Create();

        thread_upload = new ndUploadThread();
        thread_upload->Create();
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

    try {
        inotify = new ndInotify();
        inotify->AddWatch(ND_WATCH_HOSTS);
        inotify->AddWatch(ND_WATCH_ETHERS);
        inotify->RefreshWatches();
    }
    catch (exception &e) {
        nd_printf("Error creating file watches: %s\n", e.what());
        return 1;
    }

    try {
        netlink = new ndNetlink(ifaces);
    }
    catch (exception &e) {
        nd_printf("Error creating netlink watch: %s\n", e.what());
        return 1;
    }

    nd_add_device_addresses(device_addresses);

    if (nd_start_detection_threads() < 0)
        return 1;

    memset(&sigev, 0, sizeof(struct sigevent));
    sigev.sigev_notify = SIGEV_SIGNAL;
    sigev.sigev_signo = SIGRTMIN;

    if (timer_create(CLOCK_REALTIME, &sigev, &timer_id) < 0) {
        nd_printf("timer_create: %s\n", strerror(errno));
        return 1;
    }

    it_spec.it_value.tv_sec = nd_config.update_interval;
    it_spec.it_value.tv_nsec = 0;
    it_spec.it_interval.tv_sec = nd_config.update_interval;
    it_spec.it_interval.tv_nsec = 0;

    timer_settime(timer_id, 0, &it_spec, NULL);

    netlink->Refresh();

    while (!terminate) {
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

        if (sig == SIGINT || sig == SIGTERM) {
            rc = 0;
            terminate = true;
            nd_printf("Exiting...\n");
            continue;
        }

        if (sig == sigev.sigev_signo) {
            inotify->RefreshWatches();
            nd_dump_stats();
            continue;
        }

        if (sig == SIGIO) {
            if (inotify->GetDescriptor() == si.si_fd) {
                inotify->ProcessEvent();
                continue;
            }
            else if (netlink->GetDescriptor() == si.si_fd) {
                if (netlink->ProcessEvent())
                    if (nd_debug) netlink->Dump();
                continue;
            }
        }

        if (sig == SIGHUP) {
            nd_stop_detection_threads();
            if (nd_start_detection_threads() < 0) break;

            continue;
        }

        nd_printf("Unhandled signal: %s\n", strsignal(sig));
    }

    timer_delete(timer_id);

    nd_stop_detection_threads();

    thread_upload->Terminate();
    delete thread_upload;

    thread_socket->Terminate();
    delete thread_socket;
#ifdef _ND_USE_CONNTRACK
    if (nd_config.disable_conntrack == false) {
        thread_conntrack->Terminate();
        delete thread_conntrack;
    }
#endif
    pthread_mutex_destroy(nd_output_mutex);
    delete nd_output_mutex;

    curl_global_cleanup();

    return 0;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
