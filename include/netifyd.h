// Netify Daemon
// Copyright (C) 2015-2017 eGloo Incorporated <http://www.egloo.ca>
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

#ifndef ETH_ALEN
#include <net/ethernet.h>
#if !defined(ETH_ALEN) && defined(ETHER_ADDR_LEN)
#define ETH_ALEN ETHER_ADDR_LEN
#endif
#endif
#ifndef ETH_ALEN
#error Unable to define ETH_ALEN.
#endif

//#include <linux/if_ether.h>

#ifdef _ND_USE_NETLINK
#include <linux/netlink.h>
#endif

#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW CLOCK_MONOTONIC
#endif

#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

#ifndef HOST_NAME_MAX
#include <limits.h>
#define HOST_NAME_MAX _POSIX_HOST_NAME_MAX
#endif

#define ND_STATS_INTERVAL       15      // Collect stats every N seconds
                                        // Maximum upload queue size in kB
#define ND_MAX_BACKLOG_KB       1024
#define ND_DETECTION_TICKS      1000    // Ticks-per-second (1000 = milliseconds)
#define ND_IDLE_SCAN_TIME       10      // Idle flow scan in milliseconds
#define ND_IDLE_FLOW_TIME       30000   // Purge idle flows older than this (30s)

#define ND_MAX_TCP_PKTS         10      // Maximum number of TCP packets to process.
#define ND_MAX_UDP_PKTS         8       // Maximum number of UDP packets to process.

#define ND_PID_FILE_NAME        "/var/run/netifyd/netifyd.pid"

#define ND_CONF_FILE_NAME       "/etc/netifyd.conf"

#define ND_JSON_VERSION         1.4     // JSON format version
#define ND_JSON_FILE_NAME       "/var/lib/netifyd/netifyd.json"
#define ND_JSON_FILE_USER       "root"
#define ND_JSON_FILE_GROUP      "webconfig"
#define ND_JSON_FILE_MODE       0640

#define ND_PCAP_SNAPLEN         1536    // Capture snap length
#define ND_PCAP_READ_TIMEOUT    500     // Milliseconds

#define ND_URL_UPLOAD           "https://v1-netify-sink.egloo.ca/"
#define ND_COOKIE_JAR           "/var/lib/netifyd/netifyd.cookies"

#define ND_REALM_UUID_PATH      "/var/lib/netifyd/netify-realm.uuid"
#define ND_REALM_UUID_NULL      "-"
#define ND_REALM_UUID_LEN       36

#define ND_WATCH_HOSTS          "/etc/hosts"
#define ND_WATCH_ETHERS         "/etc/ethers"

// Compress data if it's over this size (bytes)
#define ND_COMPRESS_SIZE       (1024 * 10)
#define ND_ZLIB_CHUNK_SIZE      16384   // Compress this many bytes at a time

#define ND_FILE_BUFSIZ          4096

#define ND_SOCKET_PORT          "7150"
#define ND_SOCKET_PATH_MODE     0640
#define ND_SOCKET_PATH_USER     "root"
#define ND_SOCKET_PATH_GROUP    "root"

#ifndef PACKAGE_URL
#define PACKAGE_URL             "http://www.egloo.ca/"
#endif

#define ND_CONF_CONTENT_MATCH   "/var/lib/netifyd/app-content-match.csv"
#define ND_CONF_CUSTOM_MATCH    "/var/lib/netifyd/custom-match.conf"
#define ND_CONF_HOST_MATCH      "/var/lib/netifyd/app-host-match.csv"

#include "nd-sha1.h"

typedef struct {
    char *uuid;
    char *uuid_serial;
    char *uuid_realm;
    char *url_upload;
    size_t max_backlog;
    bool disable_conntrack;
    bool enable_netify_sink;
    bool ssl_use_tlsv1;
    bool ssl_verify_peer;
    char *json_filename;
    unsigned update_interval;
    unsigned max_tcp_pkts;
    unsigned max_udp_pkts;
    vector<pair<string, string> > socket_host;
    vector<string> socket_path;
    char *conf_content_match;
    bool conf_content_match_override;
    char *conf_custom_match;
    bool conf_custom_match_override;
    char *conf_host_match;
    bool conf_host_match_override;
    uint8_t digest_content_match[SHA1_DIGEST_LENGTH];
    uint8_t digest_custom_match[SHA1_DIGEST_LENGTH];
    uint8_t digest_host_match[SHA1_DIGEST_LENGTH];
    vector<uint8_t *> privacy_filter_mac;
    vector<struct sockaddr *> privacy_filter_host;
} ndGlobalConfig;

typedef struct nd_packet_stats_t
{
    uint64_t pkt_raw;
    uint64_t pkt_eth;
    uint64_t pkt_mpls;
    uint64_t pkt_pppoe;
    uint64_t pkt_vlan;
    uint64_t pkt_frags;
    uint64_t pkt_discard;
    uint32_t pkt_maxlen;
    uint64_t pkt_ip;
    uint64_t pkt_ip4;
    uint64_t pkt_ip6;
    uint64_t pkt_tcp;
    uint64_t pkt_udp;
    uint64_t pkt_ip_bytes;
    uint64_t pkt_ip4_bytes;
    uint64_t pkt_ip6_bytes;
    uint64_t pkt_wire_bytes;
    uint64_t pkt_discard_bytes;

    inline nd_packet_stats_t& operator+=(const nd_packet_stats_t &rhs) {
        pkt_raw += rhs.pkt_raw;
        pkt_eth += rhs.pkt_eth;
        pkt_mpls += rhs.pkt_mpls;
        pkt_pppoe += rhs.pkt_pppoe;
        pkt_vlan += rhs.pkt_vlan;
        pkt_frags += rhs.pkt_frags;
        pkt_discard += rhs.pkt_discard;
        if (rhs.pkt_maxlen > pkt_maxlen)
            pkt_maxlen = rhs.pkt_maxlen;
        pkt_ip += rhs.pkt_ip;
        pkt_ip4 += rhs.pkt_ip4;
        pkt_ip6 += rhs.pkt_ip6;
        pkt_tcp += rhs.pkt_tcp;
        pkt_udp += rhs.pkt_udp;
        pkt_ip_bytes += rhs.pkt_ip_bytes;
        pkt_ip4_bytes += rhs.pkt_ip4_bytes;
        pkt_ip6_bytes += rhs.pkt_ip6_bytes;
        pkt_wire_bytes += rhs.pkt_wire_bytes;
        pkt_discard_bytes += rhs.pkt_discard_bytes;
        return *this;
    }
} nd_packet_stats;

typedef unordered_map<string, vector<string> > nd_device_addrs;
typedef map<string, nd_device_addrs *> nd_devices;
typedef unordered_map<string, string> nd_device_ethers;
typedef vector<pair<bool, string> > nd_ifaces;
typedef map<string, nd_packet_stats *> nd_stats;

#endif // _ND_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
