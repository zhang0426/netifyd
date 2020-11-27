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

#include <cerrno>
#include <cstring>
#include <iostream>
#include <map>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <list>
#include <vector>
#ifdef HAVE_ATOMIC
#include <atomic>
#endif
#include <regex>
#include <algorithm>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <net/if.h>
#include <net/if_arp.h>
#include <net/ethernet.h>
#if HAVE_NET_PPP_DEFS_H
#include <net/ppp_defs.h>
#elif HAVE_LINUX_PPP_DEFS_H
#include <linux/ppp_defs.h>
#else
#error Unable to find a usable ppp_defs include
#endif

#define __FAVOR_BSD 1
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#undef __FAVOR_BSD

#if !defined(ETHERTYPE_MPLS_UC)
 #if defined(ETHERTYPE_MPLS)
  #define ETHERTYPE_MPLS_UC ETHERTYPE_MPLS
 #elif defined(ETH_P_MPLS_UC)
  #define ETHERTYPE_MPLS_UC ETH_P_MPLS_UC
 #else
  #error Unable to find suitable define for ETHERTYPE_MPLS_UC
 #endif
#endif

#if !defined(ETHERTYPE_MPLS_MC)
 #if defined(ETHERTYPE_MPLS_MCAST)
  #define ETHERTYPE_MPLS_MC ETHERTYPE_MPLS_MCAST
 #elif defined(ETH_P_MPLS_MC)
  #define ETHERTYPE_MPLS_MC ETH_P_MPLS_MC
 #else
  #error Unable to find suitable define for ETHERTYPE_MPLS_MC
 #endif
#endif

#if !defined(ETHERTYPE_PPPOE)
 #if defined(ETH_P_PPP_SES)
  #define ETHERTYPE_PPPOE ETH_P_PPP_SES
 #else
  #error Unable to find suitable define for ETHERTYPE_PPPOE
 #endif
#endif

#if !defined(ETHERTYPE_PPPOEDISC)
 #if defined(ETH_P_PPP_DISC)
  #define ETHERTYPE_PPPOEDISC ETH_P_PPP_DISC
 #else
  #error Unable to find suitable define for ETHERTYPE_PPPOEDISC
 #endif
#endif

#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <netdb.h>
#include <resolv.h>
#include <ctype.h>

#include <pcap/pcap.h>
#ifdef HAVE_PCAP_SLL_H
#include <pcap/sll.h>
#else
#include "pcap-compat/sll.h"
#endif
#ifdef HAVE_PCAP_VLAN_H
#include <pcap/vlan.h>
#else
#include "pcap-compat/vlan.h"
#endif

#include <nlohmann/json.hpp>
using json = nlohmann::json;

#ifdef _ND_USE_CONNTRACK
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#endif

#define _ND_PPP_PROTOCOL(p)	((((uint8_t *)(p))[0] << 8) + ((uint8_t *)(p))[1])

#define _ND_GTP_U_PORT    2152
#define _ND_GTP_G_PDU     0xff

using namespace std;

#include "netifyd.h"

#include "nd-ndpi.h"
#ifdef _ND_USE_NETLINK
#include "nd-netlink.h"
#endif
#include "nd-json.h"
#include "nd-flow.h"
#include "nd-thread.h"
#ifdef _ND_USE_CONNTRACK
#include "nd-conntrack.h"
#endif
#include "nd-socket.h"
#include "nd-util.h"
#include "nd-fhc.h"
#include "nd-dhc.h"
#include "nd-signal.h"
#include "nd-detection.h"

// Enable to log discarded packets
//#define _ND_LOG_PKT_DISCARD     1

// Enable DNS response debug logging
//#define _ND_LOG_DNS_RESPONSE    1

// Enable DNS hint cache debug logging
//#define _ND_LOG_DHC             1

// Enable flow hash cache debug logging
//#define _ND_LOG_FHC             1

// Enable packet queue debug logging
//#define _ND_LOG_PACKET_QUEUE    1

// Enable GTP tunnel dissection
#define _ND_DISSECT_GTP       1

extern nd_global_config nd_config;

struct __attribute__((packed)) nd_mpls_header_t
{
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    uint32_t ttl:8, s:1, exp:3, label:20;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    uint32_t label:20, exp:3, s:1, ttl:8;
#else
#error Endianess not defined (__BYTE_ORDER__).
#endif
};
#ifdef _ND_DISSECT_GTP
struct __attribute__((packed)) nd_gtpv1_header_t
{
    struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        uint8_t npdu_num:1;
        uint8_t seq_num:1;
        uint8_t ext_hdr:1;
        uint8_t reserved:1;
        uint8_t proto_type:1;
        uint8_t version:3;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        uint8_t version:3;
        uint8_t proto_type:1;
        uint8_t reserved:1;
        uint8_t ext_hdr:1;
        uint8_t seq_num:1;
        uint8_t npdu_num:1;
#error Endianess not defined (__BYTE_ORDER__).
#endif
    } flags;

    uint8_t type;
    uint16_t length;
    uint32_t teid;
};

struct __attribute__((packed)) nd_gtpv2_header_t
{
    struct {
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
        uint8_t reserved:3;
        uint8_t teid:1;
        uint8_t piggyback:1;
        uint8_t version:3;
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
        uint8_t version:3;
        uint8_t piggyback:1;
        uint8_t teid:1;
        uint8_t reserved:3;
#error Endianess not defined (__BYTE_ORDER__).
#endif
    } flags;

    uint8_t type;
    uint16_t length;
    uint32_t teid;
};
#endif // _ND_DISSECT_GTP

ndDetectionQueueEntry::ndDetectionQueueEntry(
    ndFlow *flow, uint8_t *pkt_data, uint16_t pkt_length, int addr_cmp
) : flow(flow), pkt_data(NULL), pkt_length(pkt_length), addr_cmp(addr_cmp)
{
    this->pkt_data = new uint8_t[pkt_length];
    if (this->pkt_data == NULL) throw ndDetectionThreadException(strerror(ENOMEM));
    memcpy(this->pkt_data, pkt_data, pkt_length);
}

ndDetectionQueueEntry::~ndDetectionQueueEntry()
{
    delete [] pkt_data;
}

ndDetectionThread::ndDetectionThread(
    int16_t cpu,
    const string &tag,
#ifdef _ND_USE_NETLINK
    ndNetlink *netlink,
#endif
    ndSocketThread *thread_socket,
#ifdef _ND_USE_CONNTRACK
    ndConntrackThread *thread_conntrack,
#endif
    nd_devices &devices,
    ndDNSHintCache *dhc,
    uint8_t private_addr)
    : ndThread(tag, (long)cpu, true),
    netlink(netlink),
    thread_socket(thread_socket),
#ifdef _ND_USE_CONNTRACK
    thread_conntrack(thread_conntrack),
#endif
    ndpi(NULL), custom_proto_base(0),
    devices(devices),
    dhc(dhc), fhc(NULL),
    flows(0)
{
    ndpi = nd_ndpi_init(tag, custom_proto_base);

    if (ND_USE_FHC) {
        fhc = new ndFlowHashCache(nd_config.max_fhc);
        fhc->load();
    }

    private_addrs.first.ss_family = AF_INET;
    nd_private_ipaddr(private_addr, private_addrs.first);

    private_addrs.second.ss_family = AF_INET6;
    nd_private_ipaddr(private_addr, private_addrs.second);
#if 0
    memcpy(this->dev_mac, dev_mac, ETH_ALEN);
    nd_debug_printf(
        "%s: hwaddr: %02hhx:%02hhx:%02hhx:%02hhx:%02hx:%02hhx\n",
        dev.c_str(),
        dev_mac[0], dev_mac[1], dev_mac[2],
        dev_mac[3], dev_mac[4], dev_mac[5]
    );
#endif
    int rc;

    pthread_condattr_t cond_attr;

    pthread_condattr_init(&cond_attr);
    pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
    if ((rc = pthread_cond_init(&pkt_queue_cond, &cond_attr)) != 0)
        throw ndDetectionThreadException(strerror(rc));
    pthread_condattr_destroy(&cond_attr);

    if ((rc = pthread_mutex_init(&pkt_queue_cond_mutex, NULL)) != 0)
        throw ndDetectionThreadException(strerror(rc));

    nd_debug_printf("%s: detection thread created on CPU: %hu, custom_proto_base: %u.\n",
        tag.c_str(), cpu, custom_proto_base);
}

ndDetectionThread::~ndDetectionThread()
{
    pthread_cond_broadcast(&pkt_queue_cond);

    Join();

    pthread_cond_destroy(&pkt_queue_cond);
    pthread_mutex_destroy(&pkt_queue_cond_mutex);

    // TODO: Free pkt_queue

    if (ndpi != NULL) nd_ndpi_free(ndpi);
    if (fhc != NULL) {
        fhc->save();
        delete fhc;
    }

    nd_debug_printf("%s: detection thread destroyed, %u flows processed.\n",
        tag.c_str(), flows);
}

void ndDetectionThread::QueuePacket(ndFlow *flow, uint8_t *pkt_data, uint16_t pkt_length, int addr_cmp)
{
    int rc;

    Lock();

    ndDetectionQueueEntry *entry = new ndDetectionQueueEntry(
        flow, pkt_data, pkt_length, addr_cmp
    );

    if (entry == NULL) throw ndDetectionThreadException(strerror(ENOMEM));

    pkt_queue.push(entry);

    if ((rc = pthread_cond_broadcast(&pkt_queue_cond)) != 0)
        throw ndDetectionThreadException(strerror(rc));

    Unlock();
}

void *ndDetectionThread::Entry(void)
{
    int rc;
    ndDetectionQueueEntry *entry;

    do {
        if ((rc = pthread_mutex_lock(&pkt_queue_cond_mutex)) != 0)
            throw ndDetectionThreadException(strerror(rc));
        if ((rc = pthread_cond_wait(&pkt_queue_cond, &pkt_queue_cond_mutex)) != 0)
            throw ndDetectionThreadException(strerror(rc));
        if ((rc = pthread_mutex_unlock(&pkt_queue_cond_mutex)) != 0)
            throw ndDetectionThreadException(strerror(rc));

        do {

            Lock();
            if (pkt_queue.size()) {
                entry = pkt_queue.front();
                pkt_queue.pop();
            }
            else
                entry = NULL;

            Unlock();

            if (entry != NULL) {
                ProcessPacket(entry);
                delete entry;
            }
        } while (entry != NULL);
    }
    while (terminate == false);

    nd_debug_printf("%s: detection thread ended on CPU: %hu\n", tag.c_str(), cpu);
#if 0
    nd_flow_map::iterator i = flows->begin();
    while (i != flows->end()) {

        if (thread_socket && (ND_FLOW_DUMP_UNKNOWN ||
            i->second->detected_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN)) {

            json j;

            j["type"] = "flow_purge";
            j["reason"] = "terminate";
            j["interface"] = tag;
            j["internal"] = internal;
            j["established"] = false;

            json jf;
            i->second->json_encode(jf, ndpi, ndFlow::ENCODE_STATS | ndFlow::ENCODE_TUNNELS);
            j["flow"] = jf;

            string json_string;
            nd_json_to_string(j, json_string, false);
            json_string.append("\n");
#if 0
            nd_debug_printf("%s: Purge %3u: %s\n", tag.c_str(), ++purged,
                jf["digest"].get<string>().c_str());
#endif
            thread_socket->QueueWrite(json_string);
        }

        i++;
    }
#endif
    return NULL;
}

#if 0
// XXX: Not thread-safe!
// XXX: Ensure the object is locked before calling.
void ndDetectionThread::DumpFlows(void)
{
    unsigned flow_count = 0;

    if (! thread_socket) return;

    for (nd_flow_map::const_iterator i = flows->begin(); i != flows->end(); i++) {

        if (i->second->flags.detection_complete == false) continue;
        if (! ND_FLOW_DUMP_UNKNOWN &&
            i->second->detected_protocol.master_protocol == NDPI_PROTOCOL_UNKNOWN) continue;

        json j;

        j["type"] = "flow";
        j["interface"] = tag;
        j["internal"] = internal;
        j["established"] = true;

        json jf;
        i->second->json_encode(jf, ndpi, ndFlow::ENCODE_METADATA);

        j["flow"] = jf;

        string json_string;
        nd_json_to_string(j, json_string, false);
        json_string.append("\n");

        thread_socket->QueueWrite(json_string);

        flow_count++;
    }

    nd_debug_printf("%s: dumped %lu flow(s).\n", tag.c_str(), flow_count);
}
#endif

void ndDetectionThread::ProcessPacket(ndDetectionQueueEntry *entry)
{
    struct ndpi_id_struct *id_src, *id_dst;
    uint16_t ndpi_proto = NDPI_PROTOCOL_UNKNOWN;
    ndpi_protocol_match_result npmr;

    if (entry->flow->ndpi_flow != NULL) {
        if (entry->addr_cmp == entry->flow->direction)
            id_src = entry->flow->id_src, id_dst = entry->flow->id_dst;
        else
            id_src = entry->flow->id_dst, id_dst = entry->flow->id_src;
    }
    else {
        flows++;
        entry->flow->ndpi_flow = (ndpi_flow_struct *)ndpi_malloc(sizeof(ndpi_flow_struct));
        if (entry->flow->ndpi_flow == NULL)
            throw ndDetectionThreadException(strerror(ENOMEM));

        memset(entry->flow->ndpi_flow, 0, sizeof(ndpi_flow_struct));

        entry->flow->id_src = new ndpi_id_struct;
        if (entry->flow->id_src == NULL)
            throw ndDetectionThreadException(strerror(ENOMEM));
        entry->flow->id_dst = new ndpi_id_struct;
        if (entry->flow->id_dst == NULL)
            throw ndDetectionThreadException(strerror(ENOMEM));

        memset(entry->flow->id_src, 0, sizeof(ndpi_id_struct));
        memset(entry->flow->id_dst, 0, sizeof(ndpi_id_struct));

        id_src = entry->flow->id_src;
        id_dst = entry->flow->id_dst;
    }

    entry->flow->detected_protocol = ndpi_detection_process_packet(
        ndpi,
        entry->flow->ndpi_flow,
        (const uint8_t *)entry->pkt_data,
        entry->pkt_length,
        entry->flow->ts_last_seen,
        id_src,
        id_dst
    );

//    nd_debug_printf("%s: %hhu.%hhu\n", tag.c_str(),
//        entry->flow->detected_protocol.master_protocol,
//        entry->flow->detected_protocol.app_protocol);

    if (entry->flow->detected_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN
        || (entry->flow->ip_protocol != IPPROTO_TCP &&
            entry->flow->ip_protocol != IPPROTO_UDP)
        || (entry->flow->ip_protocol == IPPROTO_UDP &&
            entry->flow->total_packets > nd_config.max_udp_pkts)
        || (entry->flow->ip_protocol == IPPROTO_TCP &&
            entry->flow->total_packets > nd_config.max_tcp_pkts)) {

#ifdef _ND_USE_NETLINK
        if (ND_USE_NETLINK) {
            entry->flow->lower_type = netlink->ClassifyAddress(&entry->flow->lower_addr);
            entry->flow->upper_type = netlink->ClassifyAddress(&entry->flow->upper_addr);
        }
#endif
        if (entry->flow->detected_protocol.master_protocol == NDPI_PROTOCOL_UNKNOWN) {

            entry->flow->detection_guessed |= ND_FLOW_GUESS_PROTO;

            entry->flow->detected_protocol.master_protocol =
                ndpi_guess_undetected_protocol(
                    ndpi,
                    NULL,
                    entry->flow->ip_protocol,
                    ntohs(entry->flow->lower_port),
                    ntohs(entry->flow->upper_port)
            );
        }
        else if (entry->flow->detected_protocol.master_protocol == NDPI_PROTOCOL_SSDP) {
            if (entry->flow->ndpi_flow->packet.packet_lines_parsed_complete) {
                string buffer;
                for (unsigned i = 0;
                    i < entry->flow->ndpi_flow->packet.parsed_lines; i++) {

                    buffer.assign(
                        (const char *)entry->flow->ndpi_flow->packet.line[i].ptr,
                        entry->flow->ndpi_flow->packet.line[i].len
                    );

                    size_t n = buffer.find_first_of(":");
                    if (n != string::npos && n > 0) {
                        string key = buffer.substr(0, n);
                        for_each(key.begin(), key.end(), [](char & c) {
                            c = ::tolower(c);
                        });

                        if (key != "user-agent" && key != "server" &&
                            ! (key.size() > 2 && key[0] == 'x' && key[1] == '-'))
                            continue;

                        string value = buffer.substr(n);
                        value.erase(value.begin(),
                            find_if(value.begin(), value.end(), [](int c) {
                                return !isspace(c) && c != ':';
                            })
                        );

                        entry->flow->ssdp.headers[key] = value;
                    }
                }
            }
        }

        if (dhc != NULL) {
            string hostname;
#ifdef _ND_USE_NETLINK
            if (entry->flow->lower_type == ndNETLINK_ATYPE_UNKNOWN)
                entry->flow->flags.dhc_hit = dhc->lookup(&entry->flow->lower_addr, hostname);
            else if (entry->flow->upper_type == ndNETLINK_ATYPE_UNKNOWN) {
                entry->flow->flags.dhc_hit = dhc->lookup(&entry->flow->upper_addr, hostname);
            }
#endif
            if (! entry->flow->flags.dhc_hit) {
                if (entry->flow->origin == ndFlow::ORIGIN_LOWER)
                    entry->flow->flags.dhc_hit = dhc->lookup(&entry->flow->upper_addr, hostname);
                else if (entry->flow->origin == ndFlow::ORIGIN_UPPER)
                    entry->flow->flags.dhc_hit = dhc->lookup(&entry->flow->lower_addr, hostname);
            }

            if (entry->flow->flags.dhc_hit &&
                (entry->flow->ndpi_flow->host_server_name[0] == '\0' ||
                nd_is_ipaddr((const char *)entry->flow->ndpi_flow->host_server_name))) {
                snprintf(
                    (char *)entry->flow->ndpi_flow->host_server_name,
                    sizeof(entry->flow->ndpi_flow->host_server_name) - 1,
                    "%s", hostname.c_str()
                );
            }
        }

        // Sanitize host server name; RFC 952 plus underscore for SSDP.
        for(int i = 0;
            i < ND_MAX_HOSTNAME &&
            i < sizeof(entry->flow->ndpi_flow->host_server_name); i++) {

            if (isalnum(entry->flow->ndpi_flow->host_server_name[i]) ||
                entry->flow->ndpi_flow->host_server_name[i] == '-' ||
                entry->flow->ndpi_flow->host_server_name[i] == '_' ||
                entry->flow->ndpi_flow->host_server_name[i] == '.') {
                entry->flow->host_server_name[i] = tolower(entry->flow->ndpi_flow->host_server_name[i]);
            }
            else {
                entry->flow->host_server_name[i] = '\0';
                break;
            }
        }

        // Determine application protocol
        if (entry->flow->host_server_name[0] != '\0') {
            entry->flow->detected_protocol.app_protocol = ndpi_match_host_app_proto(
                ndpi,
                entry->flow->ndpi_flow,
                (char *)entry->flow->host_server_name,
                strlen((const char *)entry->flow->host_server_name),
                &npmr
            );
        }

        // Determine application protocol based on master protocol
        switch (entry->flow->detected_protocol.master_protocol) {
        case NDPI_PROTOCOL_HTTPS:
        case NDPI_PROTOCOL_SSL:
        case NDPI_PROTOCOL_MAIL_IMAPS:
        case NDPI_PROTOCOL_MAIL_SMTPS:
        case NDPI_PROTOCOL_MAIL_POPS:
        case NDPI_PROTOCOL_SSL_NO_CERT:
        case NDPI_PROTOCOL_OSCAR:
            if (entry->flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
                entry->flow->ndpi_flow->protos.stun_ssl.ssl.client_certificate[0] != '\0') {
                entry->flow->detected_protocol.app_protocol = (uint16_t)ndpi_match_host_app_proto(
                    ndpi,
                    entry->flow->ndpi_flow,
                    (char *)entry->flow->ndpi_flow->protos.stun_ssl.ssl.client_certificate,
                    strlen((const char*)entry->flow->ndpi_flow->protos.stun_ssl.ssl.client_certificate),
                    &npmr);
            }
            if (entry->flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
                entry->flow->ndpi_flow->protos.stun_ssl.ssl.server_certificate[0] != '\0') {
                entry->flow->detected_protocol.app_protocol = (uint16_t)ndpi_match_host_app_proto(
                    ndpi,
                    entry->flow->ndpi_flow,
                    (char *)entry->flow->ndpi_flow->protos.stun_ssl.ssl.server_certificate,
                    strlen((const char*)entry->flow->ndpi_flow->protos.stun_ssl.ssl.server_certificate),
                    &npmr);
            }
            break;

        case NDPI_PROTOCOL_SPOTIFY:
            entry->flow->detected_protocol.app_protocol = ndpi_get_protocol_id(ndpi, "netify.spotify");
            break;

        case NDPI_PROTOCOL_MDNS:
            if (entry->flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
                    entry->flow->ndpi_flow->protos.mdns.answer[0] != '\0') {
                entry->flow->detected_protocol.app_protocol = (uint16_t)ndpi_match_host_app_proto(
                    ndpi, entry->flow->ndpi_flow,
                    (char *)entry->flow->ndpi_flow->protos.mdns.answer,
                    strlen((const char*)entry->flow->ndpi_flow->protos.mdns.answer),
                    &npmr
                );
            }
            break;
        }

        if (entry->flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) {
            entry->flow->detected_protocol.app_protocol = ndpi_match_host_proto_id(ndpi, entry->flow->ndpi_flow);
        }

        if (entry->flow->detected_protocol.master_protocol == NDPI_PROTOCOL_STUN) {
            if (entry->flow->detected_protocol.app_protocol == NDPI_PROTOCOL_FACEBOOK)
                entry->flow->detected_protocol.app_protocol = NDPI_PROTOCOL_MESSENGER;
            else if (entry->flow->detected_protocol.app_protocol == NDPI_PROTOCOL_GOOGLE)
                entry->flow->detected_protocol.app_protocol = NDPI_PROTOCOL_HANGOUT;
        }

        // Additional protocol-specific processing...
        ndpi_proto = entry->flow->master_protocol();

        switch (ndpi_proto) {

        case NDPI_PROTOCOL_MDNS:
            snprintf(
                entry->flow->mdns.answer, ND_FLOW_MDNS_ANSLEN,
                "%s", entry->flow->ndpi_flow->protos.mdns.answer
            );
            break;

        case NDPI_PROTOCOL_SSL:
            entry->flow->ssl.version =
                (entry->flow->ndpi_flow->protos.stun_ssl.ssl.version) ?
                entry->flow->ndpi_flow->protos.stun_ssl.ssl.version :
                entry->flow->ndpi_flow->protos.stun_ssl.ssl.ssl_version;
            entry->flow->ssl.cipher_suite =
                entry->flow->ndpi_flow->protos.stun_ssl.ssl.server_cipher;

            snprintf(entry->flow->ssl.client_sni, ND_FLOW_SSL_CNLEN,
                "%s", entry->flow->ndpi_flow->protos.stun_ssl.ssl.client_certificate);
            snprintf(entry->flow->ssl.server_cn, ND_FLOW_SSL_CNLEN,
                "%s", entry->flow->ndpi_flow->protos.stun_ssl.ssl.server_certificate);
            snprintf(entry->flow->ssl.server_organization, ND_FLOW_SSL_ORGLEN,
                "%s", entry->flow->ndpi_flow->protos.stun_ssl.ssl.server_organization);
            snprintf(entry->flow->ssl.client_ja3, ND_FLOW_SSL_JA3LEN,
                "%s", entry->flow->ndpi_flow->protos.stun_ssl.ssl.ja3_client);
            snprintf(entry->flow->ssl.server_ja3, ND_FLOW_SSL_JA3LEN,
                "%s", entry->flow->ndpi_flow->protos.stun_ssl.ssl.ja3_server);

            if (entry->flow->ndpi_flow->l4.tcp.tls_fingerprint_len) {
                memcpy(entry->flow->ssl.cert_fingerprint,
                    entry->flow->ndpi_flow->l4.tcp.tls_sha1_certificate_fingerprint,
                    ND_FLOW_SSL_HASH_LEN);
                entry->flow->ssl.cert_fingerprint_found = true;
            }

            break;
        case NDPI_PROTOCOL_HTTP:
            for (size_t i = 0;
                i < strlen((const char *)entry->flow->ndpi_flow->protos.http.user_agent); i++) {
                if (! isprint(entry->flow->ndpi_flow->protos.http.user_agent[i])) {
                    // XXX: Sanitize user_agent of non-printable characters.
                    entry->flow->ndpi_flow->protos.http.user_agent[i] = '\0';
                    break;
                }
            }
            snprintf(
                entry->flow->http.user_agent, ND_FLOW_UA_LEN,
                "%s", entry->flow->ndpi_flow->protos.http.user_agent
            );
            break;
        case NDPI_PROTOCOL_DHCP:
            snprintf(
                entry->flow->dhcp.fingerprint, ND_FLOW_DHCPFP_LEN,
                "%s", entry->flow->ndpi_flow->protos.dhcp.fingerprint
            );
            snprintf(
                entry->flow->dhcp.class_ident, ND_FLOW_DHCPCI_LEN,
                "%s", entry->flow->ndpi_flow->protos.dhcp.class_ident
            );
            break;
        case NDPI_PROTOCOL_SSH:
            snprintf(entry->flow->ssh.client_agent, ND_FLOW_SSH_UALEN,
                "%s", entry->flow->ndpi_flow->protos.ssh.client_signature);
            snprintf(entry->flow->ssh.server_agent, ND_FLOW_SSH_UALEN,
                "%s", entry->flow->ndpi_flow->protos.ssh.server_signature);
            break;
        case NDPI_PROTOCOL_BITTORRENT:
            if (entry->flow->ndpi_flow->protos.bittorrent.hash_valid) {
                entry->flow->bt.info_hash_valid = true;
                memcpy(
                    entry->flow->bt.info_hash,
                    entry->flow->ndpi_flow->protos.bittorrent.hash,
                    ND_FLOW_BTIHASH_LEN
                );
            }
            break;
        }

        if (entry->flow->ndpi_flow->http.url != NULL) {
            snprintf(
                entry->flow->http.url, ND_FLOW_URL_LEN,
                "%s", entry->flow->ndpi_flow->http.url
            );
        }

        if ((ndpi_proto == NDPI_PROTOCOL_DNS &&
            dhc != NULL && entry->pkt_length > 12 &&
            ProcessDNSResponse(entry->flow->host_server_name, entry->pkt_data, entry->pkt_length)) ||
            ndpi_proto == NDPI_PROTOCOL_MDNS) {

            // Rehash M/DNS flows:
            // This is done to uniquely track queries that originate from
            // the same local port.  Some devices re-use their local port
            // which would cause additional queries to not be processed.
            // Rehashing using the host_server_name as an additional key
            // guarantees that we see all DNS queries/responses.
#if 0
            if (ndpi_proto == NDPI_PROTOCOL_DNS) {
                entry->flow->hash(tag, false,
                    (const uint8_t *)entry->flow->host_server_name,
                    strnlen(entry->flow->host_server_name, ND_MAX_HOSTNAME));
            }
            else {
                entry->flow->hash(tag, false,
                    (const uint8_t *)entry->flow->mdns.answer,
                    strnlen(entry->flow->mdns.answer, ND_FLOW_MDNS_ANSLEN));
            }

            flows->erase(fi.first);

            memcpy(entry->flow->digest_mdata, entry->flow->digest_lower,
                SHA1_DIGEST_LENGTH);
            flow_digest.assign((const char *)entry->flow->digest_lower,
                SHA1_DIGEST_LENGTH);

            fi = flows->insert(nd_flow_pair(flow_digest, nf));

            if (! fi.second) {
                // Flow exists...  update stats and return.
                *fi.first->second += *nf;

                delete nf;

                return;
            }
#endif
        }

        if (ND_USE_FHC && entry->flow->lower_port != 0 && entry->flow->upper_port != 0) {
            if (! fhc->pop(flow_digest, flow_digest_mdata)) {

                entry->flow->hash(tag, true);

                flow_digest_mdata.assign(
                    (const char *)entry->flow->digest_mdata, SHA1_DIGEST_LENGTH
                );

                if (memcmp(entry->flow->digest_lower, entry->flow->digest_mdata,
                    SHA1_DIGEST_LENGTH))
                    fhc->push(flow_digest, flow_digest_mdata);
            }
            else {
                if (memcmp(entry->flow->digest_mdata, flow_digest_mdata.c_str(),
                    SHA1_DIGEST_LENGTH)) {
#ifdef _ND_LOG_FHC
                    nd_debug_printf("%s: Resurrected flow metadata hash from cache.\n",
                        tag.c_str());
#endif
                    memcpy(entry->flow->digest_mdata, flow_digest_mdata.c_str(),
                        SHA1_DIGEST_LENGTH);
                }
            }
        }
        else {
            entry->flow->hash(tag, true);
            flow_digest_mdata.assign(
                (const char *)entry->flow->digest_mdata, SHA1_DIGEST_LENGTH
            );
        }
        struct sockaddr_in *laddr4 = entry->flow->lower_addr4;
        struct sockaddr_in6 *laddr6 = entry->flow->lower_addr6;
        struct sockaddr_in *uaddr4 = entry->flow->upper_addr4;
        struct sockaddr_in6 *uaddr6 = entry->flow->upper_addr6;
#if 0
        if (ND_PRIVATE_EXTADDR &&
            internal == false && pcap_datalink_type == DLT_EN10MB) {

            if (! memcmp(dev_mac, entry->flow->lower_mac, ETH_ALEN)) {
                if (entry->flow->ip_version == 4)
                    laddr4 = (struct sockaddr_in *)&private_addrs.first;
                else
                    laddr6 = (struct sockaddr_in6 *)&private_addrs.second;
            }
            else if (! memcmp(dev_mac, entry->flow->upper_mac, ETH_ALEN)) {
                if (entry->flow->ip_version == 4)
                    uaddr4 = (struct sockaddr_in *)&private_addrs.first;
                else
                    uaddr6 = (struct sockaddr_in6 *)&private_addrs.second;
            }
        }
#endif
        switch (entry->flow->ip_version) {
        case 4:
            inet_ntop(AF_INET, &laddr4->sin_addr.s_addr,
                entry->flow->lower_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &uaddr4->sin_addr.s_addr,
                entry->flow->upper_ip, INET_ADDRSTRLEN);
            break;

        case 6:
            inet_ntop(AF_INET6, &laddr6->sin6_addr.s6_addr,
                entry->flow->lower_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &uaddr6->sin6_addr.s6_addr,
                entry->flow->upper_ip, INET6_ADDRSTRLEN);
            break;

        default:
            nd_printf("%s: ERROR: Unknown IP version: %d\n",
                tag.c_str(), entry->flow->ip_version);
            throw ndDetectionThreadException(strerror(EINVAL));
        }
#if 0
#ifdef _ND_USE_NETLINK
        nd_debug_printf("device: %s\n", entry->flow->iface->second.c_str());
        nd_device_addrs *device_addrs = devices[entry->flow->iface->second];
        if (device_addrs != NULL) {
            for (int t = ndFlow::TYPE_LOWER; t < ndFlow::TYPE_MAX; t++) {
                string ip;
                const uint8_t *umac = NULL;

                if (t == ndFlow::TYPE_LOWER &&
                    (entry->flow->lower_type == ndNETLINK_ATYPE_LOCALIP ||
                     entry->flow->lower_type == ndNETLINK_ATYPE_LOCALNET ||
                     entry->flow->lower_type == ndNETLINK_ATYPE_PRIVATE)) {

                    umac = entry->flow->lower_mac;
                    ip = entry->flow->lower_ip;
                }
                else if (t == ndFlow::TYPE_UPPER &&
                    (entry->flow->upper_type == ndNETLINK_ATYPE_LOCALIP ||
                     entry->flow->upper_type == ndNETLINK_ATYPE_LOCALNET ||
                     entry->flow->upper_type == ndNETLINK_ATYPE_PRIVATE)) {

                    umac = entry->flow->upper_mac;
                    ip = entry->flow->upper_ip;
                }
                else continue;

                // Filter out reserved MAC prefixes...
                // ...IANA RFC7042, IPv4 uni/multicast:
                if (! ((umac[0] == 0x00 || umac[0] == 0x01) &&
                    umac[1] == 0x00 && umac[2] == 0x5e) &&
                    // IPv6 multicast:
                    ! (umac[0] == 0x33 && umac[1] == 0x33)) {

                    string mac;
                    mac.assign((const char *)umac, ETH_ALEN);

                    nd_device_addrs::iterator i;
                    if ((i = device_addrs->find(mac)) == device_addrs->end())
                        (*device_addrs)[mac].push_back(ip);
                    else {
                        bool duplicate = false;
                        vector<string>::iterator j;
                        for (j = (*device_addrs)[mac].begin();
                            j != (*device_addrs)[mac].end(); j++) {
                            if (ip != (*j)) continue;
                            duplicate = true;
                            break;
                        }

                        if (! duplicate)
                            (*device_addrs)[mac].push_back(ip);
                    }
                }
            }
        }
#endif
#endif
#if defined(_ND_USE_CONNTRACK) && defined(_ND_USE_NETLINK)
        if (! entry->flow->iface->first && thread_conntrack != NULL) {
            if ((entry->flow->lower_type == ndNETLINK_ATYPE_LOCALIP &&
                entry->flow->upper_type == ndNETLINK_ATYPE_UNKNOWN) ||
                (entry->flow->lower_type == ndNETLINK_ATYPE_UNKNOWN &&
                entry->flow->upper_type == ndNETLINK_ATYPE_LOCALIP)) {

                thread_conntrack->ClassifyFlow(entry->flow);
            }
        }
#endif
        for (vector<uint8_t *>::const_iterator i =
            nd_config.privacy_filter_mac.begin();
            i != nd_config.privacy_filter_mac.end() &&
                entry->flow->privacy_mask !=
                (ndFlow::PRIVATE_LOWER | ndFlow::PRIVATE_UPPER); i++) {
            if (! memcmp((*i), entry->flow->lower_mac, ETH_ALEN))
                entry->flow->privacy_mask |= ndFlow::PRIVATE_LOWER;
            if (! memcmp((*i), entry->flow->upper_mac, ETH_ALEN))
                entry->flow->privacy_mask |= ndFlow::PRIVATE_UPPER;
        }

        for (vector<struct sockaddr *>::const_iterator i =
            nd_config.privacy_filter_host.begin();
            i != nd_config.privacy_filter_host.end() &&
                entry->flow->privacy_mask !=
                (ndFlow::PRIVATE_LOWER | ndFlow::PRIVATE_UPPER); i++) {

            struct sockaddr_in *sa_in;
            struct sockaddr_in6 *sa_in6;

            switch ((*i)->sa_family) {
            case AF_INET:
                sa_in = reinterpret_cast<struct sockaddr_in *>((*i));
                if (! memcmp(&entry->flow->lower_addr4, &sa_in->sin_addr,
                    sizeof(struct in_addr)))
                    entry->flow->privacy_mask |= ndFlow::PRIVATE_LOWER;
                if (! memcmp(&entry->flow->upper_addr4, &sa_in->sin_addr,
                    sizeof(struct in_addr)))
                    entry->flow->privacy_mask |= ndFlow::PRIVATE_UPPER;
                break;
            case AF_INET6:
                sa_in6 = reinterpret_cast<struct sockaddr_in6 *>((*i));
                if (! memcmp(&entry->flow->lower_addr6, &sa_in6->sin6_addr,
                    sizeof(struct in6_addr)))
                    entry->flow->privacy_mask |= ndFlow::PRIVATE_LOWER;
                if (! memcmp(&entry->flow->upper_addr6, &sa_in6->sin6_addr,
                    sizeof(struct in6_addr)))
                    entry->flow->privacy_mask |= ndFlow::PRIVATE_UPPER;
                break;
            }
        }
#if 0
        if (thread_socket && (ND_FLOW_DUMP_UNKNOWN ||
            entry->flow->detected_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN)) {

            json j;

            j["type"] = "flow";
            j["interface"] = tag;
            j["internal"] = internal;
            j["established"] = false;

            json jf;
            entry->flow->json_encode(jf, ndpi, ndFlow::ENCODE_METADATA);
            j["flow"] = jf;

            string json_string;
            nd_json_to_string(j, json_string, false);
            json_string.append("\n");

            thread_socket->QueueWrite(json_string);
        }

#endif
        if ((ND_DEBUG && ND_VERBOSE) || nd_config.h_flow != stderr)
            entry->flow->print(ndpi);

        entry->flow->flags.detection_complete = true;
        entry->flow->release();
    }
}

bool ndDetectionThread::ProcessDNSResponse(
    const char *host, const uint8_t *pkt, uint16_t length)
{
    ns_rr rr;
    int rc = ns_initparse(pkt, length, &ns_h);

    if (rc < 0) {
#ifdef _ND_LOG_DHC
        nd_debug_printf(
            "%s: dns initparse error: %s\n", tag.c_str(), strerror(errno));
#endif
        return false;
    }

    if (ns_msg_getflag(ns_h, ns_f_rcode) != ns_r_noerror) {
#ifdef _ND_LOG_DHC
        nd_debug_printf(
            "%s: dns response code: %hu\n", tag.c_str(),
            ns_msg_getflag(ns_h, ns_f_rcode));
#endif
        return false;
    }
#ifdef _ND_LOG_DNS_RESPONSE
    nd_debug_printf(
        "%s: dns queries: %hu, answers: %hu\n",
        tag.c_str(),
        ns_msg_count(ns_h, ns_s_qd), ns_msg_count(ns_h, ns_s_an));
#endif
    for (uint16_t i = 0; i < ns_msg_count(ns_h, ns_s_an); i++) {
        if (ns_parserr(&ns_h, ns_s_an, i, &rr)) {
#ifdef _ND_LOG_DHC
            nd_debug_printf(
                "%s: dns error parsing RR %hu of %hu.\n", tag.c_str(),
                i + 1, ns_msg_count(ns_h, ns_s_an));
#endif
            continue;
        }

        if (ns_rr_type(rr) != ns_t_a && ns_rr_type(rr) != ns_t_aaaa)
            continue;

        dhc->insert(
            (ns_rr_type(rr) == ns_t_a) ? AF_INET : AF_INET6,
            ns_rr_rdata(rr), host
        );
#ifdef _ND_LOG_DNS_RESPONSE
        char addr[INET6_ADDRSTRLEN];
        struct in_addr addr4;
        struct in6_addr addr6;

        if (ns_rr_type(rr) == ns_t_a) {
            memcpy(&addr4, ns_rr_rdata(rr), sizeof(struct in_addr));
            inet_ntop(AF_INET, &addr4, addr, INET_ADDRSTRLEN);
        }
        else {
            memcpy(&addr6, ns_rr_rdata(rr), sizeof(struct in6_addr));
            inet_ntop(AF_INET6, &addr6, addr, INET6_ADDRSTRLEN);
        }

#ifdef _ND_LOG_DHC
        nd_debug_printf(
            "%s: dns RR %s address: %s, ttl: %u, rlen: %hu: %s\n",
            tag.c_str(), host,
            (ns_rr_type(rr) == ns_t_a) ? "A" : "AAAA",
            ns_rr_ttl(rr), ns_rr_rdlen(rr), addr);
#endif // _ND_LOG_DHC

#endif
    }

    return true;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
