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

#ifndef _ND_H
#define _ND_H

#include "nd-json-response-code.h"

#ifndef ETH_ALEN
#include <net/ethernet.h>
#if !defined(ETH_ALEN) && defined(ETHER_ADDR_LEN)
#define ETH_ALEN ETHER_ADDR_LEN
#endif
#endif
#ifndef ETH_ALEN
#error Unable to define ETH_ALEN.
#endif

#if defined(_ND_USE_NETLINK) && defined(HAVE_LINUX_NETLINK_H)
#include <linux/netlink.h>
#endif

#include <sys/param.h>
#include <sys/socket.h>

#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif

#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

#if __cplusplus >= 201103L &&                             \
    (!defined(__GLIBCXX__) || (__cplusplus >= 201402L) || \
        (defined(_GLIBCXX_REGEX_DFS_QUANTIFIERS_LIMIT) || \
         defined(_GLIBCXX_REGEX_STATE_LIMIT)           || \
             (defined(_GLIBCXX_RELEASE)                && \
             _GLIBCXX_RELEASE > 4)))
#define HAVE_WORKING_REGEX 1
#else
#undef HAVE_WORKING_REGEX
#endif

#define ND_MAX_HOSTNAME         256

#define ND_STATS_INTERVAL       15      // Collect stats every N seconds
#define ND_MAX_BACKLOG_KB       2048    // Maximum upload queue size in kB
#define ND_DETECTION_TICKS      1000    // Ticks-per-second (1000 = milliseconds)
#define ND_TTL_IDLE_SCAN        1000    // Idle flow scan in milliseconds
#define ND_TTL_IDLE_FLOW        30      // Purge idle flows older than this (30s)
#define ND_TTL_IDLE_TCP_FLOW    300     // Purge idle TCP flows older than this (5m)
#define ND_TTL_IDLE_DHC_ENTRY  (60 * 30)// Purge TTL for idle DNS cache entries.
#define ND_TTL_PCAP_SELECT_USEC 500     // Minimum pcap select timeout in micros.
#define ND_HASH_BUCKETS_FLOWS   1613    // Initial flows map bucket count.
#define ND_HASH_BUCKETS_DNSARS  1613    // DNS cache address record hash buckets.

#define ND_MAX_FHC_ENTRIES      10000   // Maximum number of flow hash cache entries.
#define ND_FHC_PURGE_DIVISOR    10      // Divisor of FHC_ENTRIES to delete on purge.

#define ND_MAX_PKT_QUEUE_KB     8192    // Maximum packet queue size in kB
#define ND_PKTQ_FLUSH_DIVISOR   10      // Divisor of PKT_QUEUE_KB packets to flush.

#define ND_MAX_TCP_PKTS         10      // Maximum number of TCP packets to process.
#define ND_MAX_UDP_PKTS         8       // Maximum number of UDP packets to process.

#ifndef ND_VOLATILE_STATEDIR
#define ND_VOLATILE_STATEDIR    "/var/run/netifyd"
#endif

#ifndef ND_PERSISTENT_STATEDIR
#define ND_PERSISTENT_STATEDIR  "/etc/netify.d"
#endif

#ifndef ND_DATADIR
#define ND_DATADIR              "/usr/share/netifyd"
#endif

#ifndef ND_CONF_FILE_NAME
#define ND_CONF_FILE_NAME       "/etc/netifyd.conf"
#endif

#ifndef ND_PID_FILE_NAME
#define ND_PID_FILE_NAME        ND_VOLATILE_STATEDIR "/netifyd.pid"
#endif

#define ND_JSON_VERSION         1.9     // JSON format version
#define ND_JSON_FILE_USER       "root"
#ifndef BSD4_4
#define ND_JSON_FILE_GROUP      "root"
#else
#define ND_JSON_FILE_GROUP      "wheel"
#endif
#define ND_JSON_FILE_MODE       0600
#define ND_JSON_FILE_REQUEST    ND_VOLATILE_STATEDIR "/sink-request.json"
#define ND_JSON_FILE_RESPONSE   ND_VOLATILE_STATEDIR "/sink-response.json"
#define ND_JSON_FILE_BAD_SEND   ND_VOLATILE_STATEDIR "/sink-bad-request.json"
#define ND_JSON_FILE_BAD_RECV   ND_VOLATILE_STATEDIR "/sink-bad-response.json"
#define ND_JSON_FILE_STATUS     ND_VOLATILE_STATEDIR "/status.json"
#define ND_JSON_DATA_CHUNKSIZ   4096
#define ND_JSON_INDENT          4

#define ND_PCAP_SNAPLEN         1536    // Capture snap length
#define ND_PCAP_READ_TIMEOUT    500     // Milliseconds

#ifndef ND_URL_SINK
#define ND_URL_SINK             "https://sink.netify.ai/provision/"
#endif
#define ND_URL_SINK_PATH        ND_PERSISTENT_STATEDIR "/sink.url"
#define ND_URL_SINK_LEN         256

#define ND_SINK_MAX_POST_ERRORS 3       // Maximum number of sink POST errors.

#define ND_COOKIE_JAR           ND_VOLATILE_STATEDIR "/cookie.jar"

#define ND_SINK_CONNECT_TIMEOUT 30      // Default 30-second connection timeout
#define ND_SINK_XFER_TIMEOUT    300     // Default 5-minute upload timeout

#define ND_AGENT_UUID_PATH      ND_PERSISTENT_STATEDIR "/agent.uuid"
#define ND_AGENT_UUID_NULL      "00-00-00-00"
#define ND_AGENT_UUID_LEN       11

#define ND_AGENT_SERIAL_PATH    ND_PERSISTENT_STATEDIR "/serial.uuid"
#define ND_AGENT_SERIAL_NULL    "-"
#define ND_AGENT_SERIAL_LEN     32

#define ND_SITE_UUID_PATH       ND_PERSISTENT_STATEDIR "/site.uuid"
#define ND_SITE_UUID_NULL       "-"
#define ND_SITE_UUID_LEN        36

#define ND_ETHERS_FILE_NAME     "/etc/ethers"

#ifdef _ND_USE_WATCHDOGS
#define ND_WD_UPLOAD            ND_VOLATILE_STATEDIR "/upload.wd"
#endif

// Compress data if it's over this size (bytes)
#define ND_COMPRESS_SIZE       (1024 * 10)
#define ND_ZLIB_CHUNK_SIZE      16384   // Compress this many bytes at a time

#define ND_SOCKET_PORT          "7150"
#define ND_SOCKET_PATH_MODE     0640
#define ND_SOCKET_PATH_USER     "root"
#define ND_SOCKET_PATH_GROUP    "root"

#ifndef PACKAGE_URL
#define PACKAGE_URL             "http://www.egloo.ca/"
#endif

#define ND_CONF_SINK_BASE       "netify-sink.conf"
#define ND_CONF_SINK_PATH       ND_PERSISTENT_STATEDIR "/" ND_CONF_SINK_BASE

#define ND_STR_ETHALEN          (ETH_ALEN * 2 + ETH_ALEN - 1)

#define ND_PRIVATE_IPV4         "127.255.0."
#define ND_PRIVATE_IPV6         "fe:80::ffff:7fff:"

#include "nd-sha1.h"

typedef unordered_map<string, vector<string> > nd_device_addrs;
typedef map<string, pair<pthread_mutex_t *, nd_device_addrs *> > nd_devices;
typedef unordered_map<string, string> nd_device_ethers;
typedef vector<pair<bool, string> > nd_ifaces;
typedef vector<pair<string, string> > nd_device_addr;
typedef map<string, string> nd_device_filter;
typedef map<string, string> nd_device_netlink;
typedef map<string, string> nd_inotify_watch;
#ifdef _ND_USE_PLUGINS
class ndPluginLoader;
typedef map<string, ndPluginLoader *> nd_plugins;
#endif
typedef pair<struct sockaddr_storage, struct sockaddr_storage> nd_private_addr;

enum nd_dhc_save {
    ndDHC_DISABLED = 0,
    ndDHC_PERSISTENT = 1,
    ndDHC_VOLATILE = 2
};

enum nd_fhc_save {
    ndFHC_DISABLED = 0,
    ndFHC_PERSISTENT = 1,
    ndFHC_VOLATILE = 2
};

enum nd_global_flags {
    ndGF_DEBUG = 0x1,
    ndGF_DEBUG_UPLOAD = 0x2,
    ndGF_DEBUG_WITH_ETHERS = 0x4,
    ndGF_FREE_0x8 = 0x8,
    ndGF_OVERRIDE_SINK_CONFIG = 0x10,
    ndGF_CAPTURE_UNKNOWN_FLOWS = 0x20,
    ndGF_PRIVATE_EXTADDR = 0x40,
    ndGF_SSL_USE_TLSv1 = 0x80,
    ndGF_SSL_VERIFY = 0x100,
    ndGF_USE_CONNTRACK = 0x200,
    ndGF_USE_NETLINK = 0x400,
    ndGF_FREE_0x800 = 0x800,
    ndGF_USE_SINK = 0x1000,
    ndGF_USE_DHC = 0x2000,
    ndGF_USE_FHC = 0x4000,
    ndGF_JSON_SAVE = 0x8000,
    ndGF_VERBOSE = 0x10000,
    ndGF_REPLAY_DELAY = 0x20000,
    ndGF_REMAIN_IN_FOREGROUND = 0x40000,
    ndGF_FLOW_DUMP_ESTABLISHED = 0x80000,
    ndGF_FLOW_DUMP_UNKNOWN = 0x100000,
    ndGF_UPLOAD_ENABLED = 0x200000,
    ndGF_UPLOAD_NAT_FLOWS = 0x400000
};

#define ND_DEBUG (nd_config.flags & ndGF_DEBUG)
#define ND_DEBUG_UPLOAD (nd_config.flags & ndGF_DEBUG_UPLOAD)
#define ND_DEBUG_WITH_ETHERS (nd_config.flags & ndGF_DEBUG_WITH_ETHERS)
#define ND_OVERRIDE_SINK_CONFIG (nd_config.flags & ndGF_OVERRIDE_SINK_CONFIG)
#define ND_CAPTURE_UNKNOWN_FLOWS (nd_config.flags & ndGF_CAPTURE_UNKNOWN_FLOWS)
#define ND_PRIVATE_EXTADDR (nd_config.flags & ndGF_PRIVATE_EXTADDR)
#define ND_SSL_USE_TLSv1 (nd_config.flags & ndGF_SSL_USE_TLSv1)
#define ND_SSL_VERIFY (nd_config.flags & ndGF_SSL_VERIFY)
#define ND_USE_CONNTRACK (nd_config.flags & ndGF_USE_CONNTRACK)
#define ND_USE_NETLINK (nd_config.flags & ndGF_USE_NETLINK)
#define ND_USE_SINK (nd_config.flags & ndGF_USE_SINK)
#define ND_USE_DHC (nd_config.flags & ndGF_USE_DHC)
#define ND_USE_FHC (nd_config.flags & ndGF_USE_FHC)
#define ND_JSON_SAVE (nd_config.flags & ndGF_JSON_SAVE)
#define ND_VERBOSE (nd_config.flags & ndGF_VERBOSE)
#define ND_REPLAY_DELAY (nd_config.flags & ndGF_REPLAY_DELAY)
#define ND_REMAIN_IN_FOREGROUND (nd_config.flags & ndGF_REMAIN_IN_FOREGROUND)
#define ND_FLOW_DUMP_ESTABLISHED (nd_config.flags & ndGF_FLOW_DUMP_ESTABLISHED)
#define ND_FLOW_DUMP_UNKNOWN (nd_config.flags & ndGF_FLOW_DUMP_UNKNOWN)
#define ND_UPLOAD_ENABLED (nd_config.flags & ndGF_UPLOAD_ENABLED)
#define ND_UPLOAD_NAT_FLOWS (nd_config.flags & ndGF_UPLOAD_NAT_FLOWS)

#define ND_GF_SET_FLAG(flag, value) \
{ \
    if (value) nd_config.flags |= flag; \
    else nd_config.flags &= ~flag; \
}

typedef struct nd_global_config_t {
    char *path_config;
    char *path_sink_config;
    char *path_json;
    char *path_uuid;
    char *path_uuid_serial;
    char *path_uuid_site;
    char *url_sink;
    char *uuid;
    char *uuid_serial;
    char *uuid_site;
    size_t max_backlog;
    size_t max_packet_queue;
    uint32_t flags;
    uint8_t digest_sink_config[SHA1_DIGEST_LENGTH];
    unsigned max_fhc;
    unsigned max_tcp_pkts;
    unsigned max_udp_pkts;
    unsigned sink_max_post_errors;
    unsigned sink_connect_timeout;
    unsigned sink_xfer_timeout;
    unsigned ttl_dns_entry;
    unsigned ttl_idle_flow;
    unsigned ttl_idle_tcp_flow;
    unsigned update_interval;
    unsigned update_imf;
    int16_t ca_capture_base;
    int16_t ca_conntrack;
    int16_t ca_detection_base;
    int16_t ca_detection_cores;
    int16_t ca_sink;
    int16_t ca_socket;
    FILE *h_flow;
    enum nd_dhc_save dhc_save;
    enum nd_fhc_save fhc_save;
    unsigned fhc_purge_divisor;

    vector<pair<string, string> > socket_host;
    vector<string> socket_path;
    vector<struct sockaddr *> privacy_filter_host;
    vector<uint8_t *> privacy_filter_mac;
    vector<pair<regex *, string> > privacy_regex;
    nd_device_filter device_filters;
#ifdef _ND_USE_PLUGINS
    map<string, string> services;
    map<string, string> tasks;
#endif
    map<string, string> custom_headers;
} nd_global_config;

typedef struct nd_agent_stats_t
{
    long cpus;
    struct timespec ts_epoch;
    struct timespec ts_now;
    uint32_t flows;
    uint32_t flows_prev;
    double cpu_user;
    double cpu_user_prev;
    double cpu_system;
    double cpu_system_prev;
#if (SIZEOF_LONG == 4)
    uint32_t maxrss_kb;
    uint32_t maxrss_kb_prev;
#elif (SIZEOF_LONG == 8)
    uint64_t maxrss_kb;
    uint64_t maxrss_kb_prev;
#endif
#if defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H)
    size_t tcm_alloc_kb;
    size_t tcm_alloc_kb_prev;
#endif
    bool dhc_status;
    size_t dhc_size;
    bool sink_uploads;
    bool sink_status;
    size_t sink_queue_size;
    ndJsonResponseCode sink_resp_code;
} nd_agent_stats;

typedef struct nd_packet_stats_t
{
    struct pkt_t {
        uint64_t raw;
        uint64_t eth;
        uint64_t mpls;
        uint64_t pppoe;
        uint64_t vlan;
        uint64_t frags;
        uint64_t discard;
        uint32_t maxlen;
        uint64_t ip;
        uint64_t ip4;
        uint64_t ip6;
        uint64_t icmp;
        uint64_t igmp;
        uint64_t tcp;
        uint64_t udp;
        uint64_t ip_bytes;
        uint64_t ip4_bytes;
        uint64_t ip6_bytes;
        uint64_t wire_bytes;
        uint64_t discard_bytes;
        uint64_t queue_dropped;
    } pkt;

    struct pcap_stat pcap_last;

    inline nd_packet_stats_t& operator+=(const nd_packet_stats_t &rhs) {
        pkt.raw += rhs.pkt.raw;
        pkt.eth += rhs.pkt.eth;
        pkt.mpls += rhs.pkt.mpls;
        pkt.pppoe += rhs.pkt.pppoe;
        pkt.vlan += rhs.pkt.vlan;
        pkt.frags += rhs.pkt.frags;
        pkt.discard += rhs.pkt.discard;
        if (rhs.pkt.maxlen > pkt.maxlen)
            pkt.maxlen = rhs.pkt.maxlen;
        pkt.ip += rhs.pkt.ip;
        pkt.ip4 += rhs.pkt.ip4;
        pkt.ip6 += rhs.pkt.ip6;
        pkt.icmp += rhs.pkt.icmp;
        pkt.igmp += rhs.pkt.igmp;
        pkt.tcp += rhs.pkt.tcp;
        pkt.udp += rhs.pkt.udp;
        pkt.ip_bytes += rhs.pkt.ip_bytes;
        pkt.ip4_bytes += rhs.pkt.ip4_bytes;
        pkt.ip6_bytes += rhs.pkt.ip6_bytes;
        pkt.wire_bytes += rhs.pkt.wire_bytes;
        pkt.discard_bytes += rhs.pkt.discard_bytes;
        pkt.queue_dropped += rhs.pkt.queue_dropped;
        pcap_last.ps_recv += rhs.pcap_last.ps_recv;
        pcap_last.ps_drop += rhs.pcap_last.ps_drop;
        pcap_last.ps_ifdrop += rhs.pcap_last.ps_ifdrop;
        return *this;
    }

    inline void reset(void) {
        memset(&pkt, 0, sizeof(struct pkt_t));
    }
} nd_packet_stats;

typedef map<string, nd_packet_stats *> nd_stats;

void nd_json_agent_hello(string &json_string);
void nd_json_agent_status(string &json_string);
void nd_json_protocols(string &json_string);

struct ndInterfaceAddress
{
    sa_family_t family;
    union {
        uint8_t mac[ETH_ALEN];
        struct sockaddr_storage ip;
    };
};

typedef vector<struct ndInterfaceAddress *> nd_interface_addr_array;
typedef map<string, nd_interface_addr_array *> nd_interface_addr_map;
typedef pair<string, nd_interface_addr_array *> nd_interface_addr_pair;
typedef pair<nd_interface_addr_map::iterator, bool> nd_interface_addr_insert;

class ndException : public runtime_error
{
public:
    explicit ndException(
        const string &where_arg, const string &what_arg) throw();
    virtual ~ndException() throw();

    virtual const char *what() const throw();

    string where_arg;
    string what_arg;
    const char *message;
};

class ndSystemException : public runtime_error
{
public:
    explicit ndSystemException(
        const string &where_arg, const string &what_arg, int why_arg) throw();
    virtual ~ndSystemException() throw();

    virtual const char *what() const throw();

    string where_arg;
    string what_arg;
    int why_arg;
    const char *message;
};

#endif // _ND_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
