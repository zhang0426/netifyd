// Netify Agent
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <cerrno>
#include <cstring>
#include <deque>
#include <iostream>
#include <map>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <netdb.h>
#include <resolv.h>

#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <arpa/inet.h>
#include <arpa/nameser.h>

#include <net/if.h>
#include <net/ppp_defs.h>
#include <net/ethernet.h>

#define __FAVOR_BSD 1
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#undef __FAVOR_BSD

#ifndef ETHERTYPE_MPLS
#ifdef ETH_P_MPLS_UC
#define ETHERTYPE_MPLS ETH_P_MPLS_UC
#else
#error Unable to find suitable define for ETHERTYPE_MPLS
#endif
#endif
#ifndef ETHERTYPE_PPPOE
#ifdef ETH_P_PPP_SES
#define ETHERTYPE_PPPOE ETH_P_PPP_SES
#else
#error Unable to find suitable define for ETHERTYPE_PPPOE
#endif
#endif
#ifndef ETHERTYPE_PPPOEDISC
#ifdef ETH_P_PPP_DISC
#define ETHERTYPE_PPPOEDISC ETH_P_PPP_DISC
#else
#error Unable to find suitable define for ETHERTYPE_PPPOEDISC
#endif
#endif

#include <json.h>
#include <pcap/pcap.h>

#ifdef _ND_USE_NETLINK
#include <linux/netlink.h>
#endif

#ifdef _ND_USE_CONNTRACK
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#endif

extern "C" {
#include "ndpi_api.h"
}

#define _ND_PPP_PROTOCOL(p)	((((uint8_t *)(p))[0] << 8) + ((uint8_t *)(p))[1])

using namespace std;

#include "netifyd.h"
#include "nd-util.h"
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
#include "nd-ndpi.h"

// Enable to log discarded packets
//#define _ND_LOG_PKT_DISCARD     1

// Enable log log DNS Response processing
#define _ND_LOG_DNS_RESPONSE    1

extern bool nd_debug;

extern nd_global_config nd_config;

ndDetectionThread::ndDetectionThread(const string &dev,
#ifdef _ND_USE_NETLINK
    const string &netlink_dev,
    ndNetlink *netlink,
#endif
    ndSocketThread *thread_socket,
#ifdef _ND_USE_CONNTRACK
    ndConntrackThread *thread_conntrack,
#endif
    nd_flow_map *flow_map, nd_packet_stats *stats,
    nd_device_addrs *device_addrs,
    nd_dns_cache *dns_cache,
    long cpu)
    : ndThread(dev, cpu),
#ifdef _ND_USE_NETLINK
    netlink_dev(netlink_dev), netlink(netlink),
#endif
    thread_socket(thread_socket),
#ifdef _ND_USE_CONNTRACK
    thread_conntrack(thread_conntrack),
#endif
    pcap(NULL), pcap_snaplen(ND_PCAP_SNAPLEN),
    pcap_datalink_type(0), pkt_header(NULL), pkt_data(NULL), ts_pkt_last(0),
    ts_last_idle_scan(0), ndpi(NULL), custom_proto_base(0), flows(flow_map),
    stats(stats), device_addrs(device_addrs), dns_cache(dns_cache)
{
    memset(stats, 0, sizeof(nd_packet_stats));

    size_t p = string::npos;
    if ((p = tag.find_first_of(",")) != string::npos) {
        pcap_file = tag.substr(p + 1);
        tag = tag.substr(0, p);
        nd_debug_printf("%s: capture file: %s\n", tag.c_str(), pcap_file.c_str());
    }

    ndpi = nd_ndpi_init(tag, custom_proto_base);

    nd_debug_printf("%s: detection thread created, custom_proto_base: %u.\n",
        tag.c_str(), custom_proto_base);
}

ndDetectionThread::~ndDetectionThread()
{
    Join();
    if (pcap != NULL) pcap_close(pcap);
    if (ndpi != NULL) ndpi_exit_detection_module(ndpi);

    nd_debug_printf("%s: detection thread destroyed.\n", tag.c_str());
}

void *ndDetectionThread::Entry(void)
{
    int ifr_fd = -1;
    struct ifreq ifr;

    do {
        if (ifr_fd < 0 && (ifr_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
            nd_printf("%s: error creating ifr socket: %s\n",
                tag.c_str(), strerror(errno));
            sleep(1);
            continue;
        }

        if (pcap == NULL) {
            memset(&ifr, '\0', sizeof(struct ifreq));
            strncpy(ifr.ifr_name, tag.c_str(), IFNAMSIZ - 1);

            if (ioctl(ifr_fd, SIOCGIFFLAGS, (char *)&ifr) == -1) {
                nd_printf("%s: error getting interface flags: %s\n",
                    tag.c_str(), strerror(errno));
                close(ifr_fd);
                ifr_fd = -1;
                sleep(1);
                continue;
            }

            if (! (ifr.ifr_flags & IFF_UP)) {
                nd_debug_printf("%s: WARNING: interface is down.\n",
                    tag.c_str());
                sleep(1);
                continue;
            }

            memset(pcap_errbuf, 0, PCAP_ERRBUF_SIZE);

            pcap = OpenCapture();

            if (pcap == NULL) {
                nd_printf("%s.\n", pcap_errbuf);
                sleep(1);
                continue;
            }

            if (pcap_file.size()) {
            nd_printf("%s: using capture file: %s: v%d.%d\n",
                tag.c_str(), pcap_file.c_str(),
                pcap_major_version(pcap), pcap_minor_version(pcap));
            }

            if (strlen(pcap_errbuf))
                nd_printf("%s.\n", pcap_errbuf);

            pcap_datalink_type = pcap_datalink(pcap);

            nd_printf("%s: capture started on CPU: %lu\n",
                tag.c_str(), cpu >= 0 ? cpu : 0);
        }

        switch (pcap_next_ex(pcap, &pkt_header, &pkt_data)) {
        case 0:
            break;
        case 1:
            try {
                pthread_mutex_lock(&lock);
                ProcessPacket();
                pthread_mutex_unlock(&lock);
            }
            catch (exception &e) {
                pthread_mutex_unlock(&lock);
                throw;
            }
            break;
        case -1:
            nd_printf("%s: %s.\n", tag.c_str(), pcap_geterr(pcap));
            pcap_close(pcap);
            pcap = NULL;
            break;
        case -2:
            nd_printf("%s: end of capture file: %s\n",
                tag.c_str(), pcap_file.c_str());
            pcap_close(pcap);
            pcap = NULL;
            terminate = true;
            break;
        }
    }
    while (terminate == false);

    close(ifr_fd);

    nd_printf("%s: capture ended on CPU: %lu\n",
        tag.c_str(), cpu >= 0 ? cpu : 0);

    terminated = true;

    return NULL;
}

pcap_t *ndDetectionThread::OpenCapture(void)
{
    if (pcap_file.size()) {
        return pcap_open_offline(
            pcap_file.c_str(),
            pcap_errbuf
        );
    }

    return pcap_open_live(
        tag.c_str(),
        pcap_snaplen,
        1, // Promisc?
        ND_PCAP_READ_TIMEOUT,
        pcap_errbuf
    );
}

void ndDetectionThread::ProcessPacket(void)
{
    const struct ether_header *hdr_eth = NULL;
    const struct ip *hdr_ip = NULL;
    const struct ip6_hdr *hdr_ip6 = NULL;

    const uint8_t *l3 = NULL, *l4 = NULL, *pkt = NULL;
    uint16_t l2_len, l3_len, l4_len = 0, pkt_len = 0;

    uint16_t type;
    uint16_t ppp_proto;
    uint16_t frag_off = 0;
    uint8_t vlan_packet = 0;
    int addr_cmp = 0;

    struct ndFlow flow;
    memset(&flow, 0, sizeof(struct ndFlow));
    flow.internal = (thread_socket != NULL) ? true : false;

    string digest;

    struct ndpi_id_struct *id_src, *id_dst;

    uint64_t ts_pkt = ((uint64_t)pkt_header->ts.tv_sec) *
            ND_DETECTION_TICKS +
            pkt_header->ts.tv_usec /
            (1000000 / ND_DETECTION_TICKS);

    if (ts_pkt_last > ts_pkt) ts_pkt = ts_pkt_last;

    if (ND_REPLAY_DELAY && ts_pkt_last && pcap_file.size()) {
        useconds_t delay = useconds_t(ts_pkt - ts_pkt_last) * 1000;
        //nd_debug_printf("%s: pkt delay: %lu\n", tag.c_str(), delay);
        if (delay) {
            pthread_mutex_unlock(&lock);
            usleep(delay);
            pthread_mutex_lock(&lock);
        }
    }

    ts_pkt_last = ts_pkt;

    stats->pkt_raw++;
    if (pkt_header->len > stats->pkt_maxlen)
        stats->pkt_maxlen = pkt_header->len;
#if 0
    if (pkt_header->caplen < pkt_header->len) {
        // XXX: Warning: capture size less than packet size.
        // XXX: Increase capture size (detection may not work)...
    }
#endif

    switch (pcap_datalink_type) {
    case DLT_NULL:
        if (ntohl(*((uint32_t *)pkt_data)) == 2)
            type = ETHERTYPE_IP;
        else
            type = ETHERTYPE_IPV6;

        l2_len = 4;
        break;

    case DLT_EN10MB:
        hdr_eth = reinterpret_cast<const struct ether_header *>(pkt_data);
        type = ntohs(hdr_eth->ether_type);
        l2_len = sizeof(struct ether_header);
        stats->pkt_eth++;

        // STP?
        if ((hdr_eth->ether_shost[0] == 0x01 && hdr_eth->ether_shost[1] == 0x80 &&
            hdr_eth->ether_shost[2] == 0xC2) ||
            (hdr_eth->ether_dhost[0] == 0x01 && hdr_eth->ether_dhost[1] == 0x80 &&
            hdr_eth->ether_dhost[2] == 0xC2)) {
            stats->pkt_discard++;
            stats->pkt_discard_bytes += ntohs(hdr_eth->ether_type);
#ifdef _ND_LOG_PKT_DISCARD
            nd_debug_printf("%s: discard: STP protocol.\n", tag.c_str());
#endif
            return;
        }

        break;

    case DLT_LINUX_SLL:
        type = (pkt_data[14] << 8) + pkt_data[15];
        l2_len = 16;
        break;

    default:
        return;
    }

    while (true) {
        if (type == ETHERTYPE_VLAN) {
            vlan_packet = 1;
            flow.vlan_id = ((pkt_data[l2_len] << 8) + pkt_data[l2_len + 1]) & 0xFFF;
            type = (pkt_data[l2_len + 2] << 8) + pkt_data[l2_len + 3];
            l2_len += 4;
        }
        else if (type == ETHERTYPE_MPLS) {
            stats->pkt_mpls++;
            uint32_t label = ntohl(*((uint32_t *)&pkt_data[l2_len]));
            type = ETHERTYPE_IP;
            l2_len += 4;

            while ((label & 0x100) != 0x100) {
                l2_len += 4;
                label = ntohl(*((uint32_t *)&pkt_data[l2_len]));
            }
        }
        else if (type == ETHERTYPE_PPPOE) {
            stats->pkt_pppoe++;
            type = ETHERTYPE_IP;
            ppp_proto = (uint16_t)(
                _ND_PPP_PROTOCOL(pkt_data + l2_len + 6)
            );
            if (ppp_proto != PPP_IP && ppp_proto != PPP_IPV6) {
                stats->pkt_discard++;
                stats->pkt_discard_bytes += pkt_header->len;
#ifdef _ND_LOG_PKT_DISCARD
                nd_debug_printf("%s: discard: unsupported PPP protocol: 0x%04hx\n",
                    tag.c_str(), ppp_proto);
#endif
                return;
            }

            l2_len += 8;
        }
        else if (type == ETHERTYPE_PPPOEDISC) {
            stats->pkt_pppoe++;
            stats->pkt_discard++;
            stats->pkt_discard_bytes += pkt_header->len;
#ifdef _ND_LOG_PKT_DISCARD
            nd_debug_printf("%s: discard: PPPoE discovery protocol.\n", tag.c_str());
#endif
            return;
        }
        else
            break;
    }

    stats->pkt_vlan += vlan_packet;

    hdr_ip = reinterpret_cast<const struct ip *>(&pkt_data[l2_len]);
    flow.ip_version = hdr_ip->ip_v;

    if (flow.ip_version == 4) {
        l3_len = ((uint16_t)hdr_ip->ip_hl * 4);
        l4_len = ntohs(hdr_ip->ip_len) - l3_len;
        flow.ip_protocol = hdr_ip->ip_p;
        l3 = reinterpret_cast<const uint8_t *>(hdr_ip);

        if (pkt_header->caplen >= l2_len)
            frag_off = ntohs(hdr_ip->ip_off);

        if (pkt_header->len - l2_len < sizeof(struct ip)) {
            // XXX: header too small
            stats->pkt_discard++;
            stats->pkt_discard_bytes += pkt_header->len;
#ifdef _ND_LOG_PKT_DISCARD
            nd_debug_printf("%s: discard: header too small\n", tag.c_str());
#endif
            return;
        }

        if ((frag_off & 0x3FFF) != 0) {
            // XXX: fragmented packets are not supported
            stats->pkt_frags++;
            stats->pkt_discard++;
            stats->pkt_discard_bytes += pkt_header->len;
#ifdef _ND_LOG_PKT_DISCARD
            nd_debug_printf("%s: discard: fragmented 0x3FFF\n", tag.c_str());
#endif
            return;
        }

        if ((frag_off & 0x1FFF) != 0) {
            // XXX: fragmented packets are not supported
            stats->pkt_frags++;
            stats->pkt_discard++;
            stats->pkt_discard_bytes += pkt_header->len;
#ifdef _ND_LOG_PKT_DISCARD
            nd_debug_printf("%s: discard: fragmented 0x1FFF\n", tag.c_str());
#endif
            return;
        }

        if (l3_len > (pkt_header->len - l2_len)) {
            stats->pkt_discard++;
            stats->pkt_discard_bytes += pkt_header->len;
#ifdef _ND_LOG_PKT_DISCARD
            nd_debug_printf("%s: discard: l3_len[%hu] > (pkt_header->len[%hu] - l2_len[%hu])(%hu)\n",
                tag.c_str(), l3_len, pkt_header->len, l2_len, pkt_header->len - l2_len);
#endif
            return;
        }

        if ((pkt_header->len - l2_len) < ntohs(hdr_ip->ip_len)) {
            stats->pkt_discard++;
            stats->pkt_discard_bytes += pkt_header->len;
#ifdef _ND_LOG_PKT_DISCARD
            nd_debug_printf("%s: discard: (pkt_header->len[%hu] - l2_len[%hu](%hu)) < hdr_ip->ip_len[%hu]\n",
                tag.c_str(), pkt_header->len, l2_len, pkt_header->len - l2_len, ntohs(hdr_ip->ip_len));
#endif
            return;
        }

        addr_cmp = memcmp(&hdr_ip->ip_src, &hdr_ip->ip_dst, 4);

        if (addr_cmp < 0) {
            flow.lower_addr.s_addr = hdr_ip->ip_src.s_addr;
            flow.upper_addr.s_addr = hdr_ip->ip_dst.s_addr;
            if (pcap_datalink_type == DLT_EN10MB) {
                memcpy(flow.lower_mac, hdr_eth->ether_shost, ETH_ALEN);
                memcpy(flow.upper_mac, hdr_eth->ether_dhost, ETH_ALEN);
            }
        }
        else {
            flow.lower_addr.s_addr = hdr_ip->ip_dst.s_addr;
            flow.upper_addr.s_addr = hdr_ip->ip_src.s_addr;
            if (pcap_datalink_type == DLT_EN10MB) {
                memcpy(flow.lower_mac, hdr_eth->ether_dhost, ETH_ALEN);
                memcpy(flow.upper_mac, hdr_eth->ether_shost, ETH_ALEN);
            }
        }
    }
    else if (flow.ip_version == 6) {
        hdr_ip6 = reinterpret_cast<const struct ip6_hdr *>(&pkt_data[l2_len]);
        l3_len = sizeof(struct ip6_hdr);
        l4_len = ntohs(hdr_ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
        flow.ip_protocol = hdr_ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        l3 = reinterpret_cast<const uint8_t *>(hdr_ip6);

        if (flow.ip_protocol == IPPROTO_DSTOPTS) {
            const uint8_t *options = reinterpret_cast<const uint8_t *>(
                hdr_ip6 + sizeof(const struct ip6_hdr)
            );
            flow.ip_protocol = options[0];
            l3_len += 8 * (options[1] + 1);
        }

        int i = 0;
        if (memcmp(&hdr_ip6->ip6_src, &hdr_ip6->ip6_dst, sizeof(struct in6_addr))) {
            do {
                addr_cmp = memcmp(
                    &hdr_ip6->ip6_src.s6_addr32[i],
                    &hdr_ip6->ip6_dst.s6_addr32[i], 4);
                i++;
            }
            while (addr_cmp == 0);
        }

        if (addr_cmp < 0) {
            memcpy(&flow.lower_addr6, &hdr_ip6->ip6_src, sizeof(struct in6_addr));
            memcpy(&flow.upper_addr6, &hdr_ip6->ip6_dst, sizeof(struct in6_addr));
            if (pcap_datalink_type == DLT_EN10MB) {
                memcpy(flow.lower_mac, hdr_eth->ether_shost, ETH_ALEN);
                memcpy(flow.upper_mac, hdr_eth->ether_dhost, ETH_ALEN);
            }
        }
        else {
            memcpy(&flow.lower_addr6, &hdr_ip6->ip6_dst, sizeof(struct in6_addr));
            memcpy(&flow.upper_addr6, &hdr_ip6->ip6_src, sizeof(struct in6_addr));
            if (pcap_datalink_type == DLT_EN10MB) {
                memcpy(flow.lower_mac, hdr_eth->ether_dhost, ETH_ALEN);
                memcpy(flow.upper_mac, hdr_eth->ether_shost, ETH_ALEN);
            }
        }
    }
    else {
        // XXX: Warning: unsupported protocol version (IPv4/6 only)
        stats->pkt_discard++;
        stats->pkt_discard_bytes += pkt_header->len;
#ifdef _ND_LOG_PKT_DISCARD
        nd_debug_printf("%s: discard: invalid IP protocol version: %hhx\n",
            tag.c_str(), pkt_data[l2_len]);
#endif
        return;
    }

    l4 = reinterpret_cast<const uint8_t *>(l3 + l3_len);

    switch (flow.ip_protocol) {
    case IPPROTO_TCP:
        if (l4_len >= 20) {
            const struct tcphdr *hdr_tcp;
            hdr_tcp = reinterpret_cast<const struct tcphdr *>(l4);
            stats->pkt_tcp++;

            if (addr_cmp < 0) {
                flow.lower_port = hdr_tcp->th_sport;
                flow.upper_port = hdr_tcp->th_dport;
            }
            else {
                flow.lower_port = hdr_tcp->th_dport;
                flow.upper_port = hdr_tcp->th_sport;

                if (addr_cmp == 0) {
                    if (flow.lower_port > flow.upper_port) {
                        flow.lower_port = flow.upper_port;
                        flow.upper_port = hdr_tcp->th_dport;
                    }
                }
            }

            pkt = reinterpret_cast<const uint8_t *>(l4 + (hdr_tcp->th_off * 4));
            pkt_len = l4_len - (hdr_tcp->th_off * 4);
        }
        break;

    case IPPROTO_UDP:
        if (l4_len >= 8) {
            const struct udphdr *hdr_udp;
            hdr_udp = reinterpret_cast<const struct udphdr *>(l4);
            stats->pkt_udp++;

            if (addr_cmp < 0) {
                flow.lower_port = hdr_udp->uh_sport;
                flow.upper_port = hdr_udp->uh_dport;
            }
            else {
                flow.lower_port = hdr_udp->uh_dport;
                flow.upper_port = hdr_udp->uh_sport;
            }

            pkt = reinterpret_cast<const uint8_t *>(l4 + sizeof(struct udphdr));
            pkt_len = ntohs(hdr_udp->uh_ulen) - sizeof(struct udphdr);
        }
        break;

    default:
        // Non-TCP/UDP protocols, ex: ICMP...
        //nd_debug_printf("%s: non TCP/UDP protocol: %d\n", tag.c_str(), flow.ip_protocol);
        break;
    }

    flow.hash(tag, digest);

    ndFlow *new_flow = new ndFlow(flow);
    if (new_flow == NULL) throw ndDetectionThreadException(strerror(ENOMEM));

    nd_flow_insert flow_iter = flows->insert(nd_flow_pair(digest, new_flow));

    if (flow_iter.second) {
        new_flow->ts_first_seen = ts_pkt;

        new_flow->ndpi_flow = (ndpi_flow_struct *)ndpi_malloc(sizeof(ndpi_flow_struct));
        if (new_flow->ndpi_flow == NULL)
            throw ndDetectionThreadException(strerror(ENOMEM));
        memset(new_flow->ndpi_flow, 0, sizeof(ndpi_flow_struct));

        new_flow->id_src = new ndpi_id_struct;
        if (new_flow->id_src == NULL)
            throw ndDetectionThreadException(strerror(ENOMEM));
        new_flow->id_dst = new ndpi_id_struct;
        if (new_flow->id_dst == NULL)
            throw ndDetectionThreadException(strerror(ENOMEM));
        memset(new_flow->id_src, 0, sizeof(ndpi_id_struct));
        memset(new_flow->id_dst, 0, sizeof(ndpi_id_struct));
        id_src = new_flow->id_src;
        id_dst = new_flow->id_dst;
    }
    else {
        delete new_flow;
        new_flow = flow_iter.first->second;

        if (flow == *new_flow)
            id_src = new_flow->id_src, id_dst = new_flow->id_dst;
        else
            id_src = new_flow->id_dst, id_dst = new_flow->id_src;
    }

    stats->pkt_wire_bytes += pkt_header->len + 24;

    stats->pkt_ip++;
    stats->pkt_ip_bytes += pkt_header->len;

    if (new_flow->ip_version == 4) {
        stats->pkt_ip4++;
        stats->pkt_ip4_bytes += pkt_header->len;
    }
    else {
        stats->pkt_ip6++;
        stats->pkt_ip6_bytes += pkt_header->len;
    }

    new_flow->total_packets++;
    new_flow->total_bytes += pkt_header->len;
    new_flow->ts_last_seen = ts_pkt;

    if (addr_cmp < 0) {
        new_flow->lower_packets++;
        new_flow->lower_bytes += pkt_header->len;
    }
    else {
        new_flow->upper_packets++;
        new_flow->upper_bytes += pkt_header->len;
    }

    if (new_flow->detection_complete) return;

    new_flow->detected_protocol = ndpi_detection_process_packet(
        ndpi,
        new_flow->ndpi_flow,
        (new_flow->ip_version == 4) ?
            (const uint8_t *)hdr_ip : (const uint8_t *)hdr_ip6,
        pkt_header->len - l2_len,
        pkt_header->len,
        id_src,
        id_dst
    );

    if (new_flow->detected_protocol.app_protocol != NDPI_PROTOCOL_UNKNOWN
        || (new_flow->ip_protocol != IPPROTO_TCP &&
            new_flow->ip_protocol != IPPROTO_UDP)
        || (new_flow->ip_protocol == IPPROTO_UDP &&
            new_flow->total_packets > nd_config.max_udp_pkts)
        || (new_flow->ip_protocol == IPPROTO_TCP &&
            new_flow->total_packets > nd_config.max_tcp_pkts)) {

        new_flow->detection_complete = true;

        struct sockaddr_in lower, upper;
        struct sockaddr_in6 lower6, upper6;
        struct sockaddr_storage *lower_addr, *upper_addr;

        if (new_flow->ip_version == 4) {
            lower.sin_family = AF_INET;
            memcpy(&lower.sin_addr, &new_flow->lower_addr, sizeof(struct in_addr));
            upper.sin_family = AF_INET;
            memcpy(&upper.sin_addr, &new_flow->upper_addr, sizeof(struct in_addr));
            lower_addr = reinterpret_cast<struct sockaddr_storage *>(&lower);
            upper_addr = reinterpret_cast<struct sockaddr_storage *>(&upper);
        }
        else {
            lower6.sin6_family = AF_INET6;
            memcpy(
                &lower6.sin6_addr, &new_flow->lower_addr6, sizeof(struct in6_addr));
            upper6.sin6_family = AF_INET6;
            memcpy(
                &upper6.sin6_addr, &new_flow->upper_addr6, sizeof(struct in6_addr));
            lower_addr = reinterpret_cast<struct sockaddr_storage *>(&lower6);
            upper_addr = reinterpret_cast<struct sockaddr_storage *>(&upper6);
        }
#ifdef _ND_USE_NETLINK
        new_flow->lower_type = netlink->ClassifyAddress(lower_addr);
        new_flow->upper_type = netlink->ClassifyAddress(upper_addr);
#endif
        if (new_flow->detected_protocol.master_protocol == NDPI_PROTOCOL_UNKNOWN) {

            new_flow->detection_guessed |= ND_FLOW_GUESS_PROTO;

            if (new_flow->ndpi_flow->num_stun_udp_pkts > 0) {

                ndpi_set_detected_protocol(
                    ndpi,
                    new_flow->ndpi_flow,
                    NDPI_PROTOCOL_STUN,
                    new_flow->detected_protocol.app_protocol
                );
            }
            else {
                new_flow->detected_protocol = ndpi_guess_undetected_protocol(
                    ndpi,
                    new_flow->ip_protocol,
                    ntohl(
                        (new_flow->ip_version == 4) ?
                            new_flow->lower_addr.s_addr :
                                new_flow->lower_addr6.s6_addr32[2] +
                                new_flow->lower_addr6.s6_addr32[3]
                    ),
                    ntohs(new_flow->lower_port),
                    ntohl(
                        (new_flow->ip_version == 4) ?
                            new_flow->upper_addr.s_addr :
                                new_flow->upper_addr6.s6_addr32[2] +
                                new_flow->upper_addr6.s6_addr32[3]
                    ),
                    ntohs(new_flow->upper_port)
                );
            }
        }

        if (new_flow->detected_protocol.app_protocol < custom_proto_base) {
            new_flow->detected_protocol.master_protocol =
                new_flow->detected_protocol.app_protocol;
            new_flow->detected_protocol.app_protocol = NDPI_PROTOCOL_UNKNOWN;
        }

        if (new_flow->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) {

            if (new_flow->ndpi_flow->host_server_name[0] == '\0' ||
                nd_is_ipaddr((const char *)new_flow->ndpi_flow->host_server_name)) {

                string hostname;

                if (new_flow->lower_type == ndNETLINK_ATYPE_UNKNOWN) {
                    if (new_flow->ip_version == 4)
                        dns_cache->lookup(new_flow->lower_addr, hostname);
                    else
                        dns_cache->lookup(new_flow->lower_addr6, hostname);
                }
                else if (new_flow->upper_type == ndNETLINK_ATYPE_UNKNOWN) {
                    if (new_flow->ip_version == 4)
                        dns_cache->lookup(new_flow->upper_addr, hostname);
                    else
                        dns_cache->lookup(new_flow->upper_addr6, hostname);
                }

                if (hostname.size()) {

                    new_flow->detection_guessed |= ND_FLOW_GUESS_DNS;

                    snprintf(
                        (char *)new_flow->ndpi_flow->host_server_name,
                        sizeof(new_flow->ndpi_flow->host_server_name) - 1,
                        "%s", hostname.c_str()
                    );

                    new_flow->detected_protocol.app_protocol = ndpi_match_host_subprotocol(
                        ndpi,
                        new_flow->ndpi_flow,
                        (char *)new_flow->ndpi_flow->host_server_name,
                        strlen((const char *)new_flow->ndpi_flow->host_server_name),
                        new_flow->detected_protocol.master_protocol);

                    nd_debug_printf("%s: Found hostname for undetected app proto: %s [%hu]\n",
                        tag.c_str(), hostname.c_str(), new_flow->detected_protocol.app_protocol);
                }
            }
        }

        // Sanitize host server name; RFC 952 plus underscore for SSDP.
        snprintf(
            new_flow->host_server_name, HOST_NAME_MAX,
            "%s", new_flow->ndpi_flow->host_server_name
        );

        for (int i = 0; i < HOST_NAME_MAX; i++) {
            if (! isalnum(new_flow->host_server_name[i]) &&
                new_flow->host_server_name[i] != '-' &&
                new_flow->host_server_name[i] != '_' &&
                new_flow->host_server_name[i] != '.') {
                new_flow->host_server_name[i] = '\0';
                break;
            }
        }

        // Additional protocol-specific processing...
        switch (new_flow->master_protocol()) {

        case NDPI_PROTOCOL_DNS:
            if (pkt != NULL && pkt_len > 12 && ProcessDNSResponse(
                new_flow->host_server_name, pkt, pkt_len)) {

                new_flow->hash(tag, digest, false,
                    (const uint8_t *)new_flow->host_server_name,
                    strnlen(new_flow->host_server_name, HOST_NAME_MAX));

                // XXX: To be optimized.
                flows->erase(flow_iter.first);
                flow_iter = flows->insert(nd_flow_pair(digest, new_flow));

                if (! flow_iter.second) {
                    nd_debug_printf("%s: dns old flow re-inserted.\n",
                        tag.c_str());

                    delete new_flow;
                    new_flow = flow_iter.first->second;
                }
                else {
                    nd_debug_printf("%s: dns new flow re-inserted.\n",
                        tag.c_str());
                }
            }
            break;
        case NDPI_PROTOCOL_HTTP:
            snprintf(
                new_flow->http.user_agent, ND_FLOW_UA_LEN,
                "%s", new_flow->ndpi_flow->protos.http.detected_os
            );
            break;
        case NDPI_PROTOCOL_SSL:
            snprintf(new_flow->ssl.client_certcn, ND_FLOW_SSL_CNLEN,
                "%s", new_flow->ndpi_flow->protos.ssl.client_certificate);
            snprintf(new_flow->ssl.server_certcn, ND_FLOW_SSL_CNLEN,
                "%s", new_flow->ndpi_flow->protos.ssl.server_certificate);
            break;
        case NDPI_PROTOCOL_SSH:
            snprintf(new_flow->ssh.client_agent, ND_FLOW_SSH_UALEN,
                "%s", new_flow->ndpi_flow->protos.ssh.client_signature);
            snprintf(new_flow->ssh.server_agent, ND_FLOW_SSH_UALEN,
                "%s", new_flow->ndpi_flow->protos.ssh.server_signature);
            break;
        case NDPI_PROTOCOL_DHCP:
            snprintf(
                new_flow->dhcp.fingerprint, ND_FLOW_DHCPFP_LEN,
                "%s", new_flow->ndpi_flow->protos.dhcp.fingerprint
            );
            snprintf(
                new_flow->dhcp.class_ident, ND_FLOW_DHCPCI_LEN,
                "%s", new_flow->ndpi_flow->protos.dhcp.class_ident
            );
            break;
        case NDPI_PROTOCOL_BITTORRENT:
            if (new_flow->ndpi_flow->protos.bittorrent.hash_valid) {
                new_flow->bt.info_hash_valid = true;
                memcpy(
                    new_flow->bt.info_hash,
                    new_flow->ndpi_flow->protos.bittorrent.hash,
                    ND_FLOW_BTIHASH_LEN
                );
            }
        }

        switch (new_flow->ip_version) {
        case 4:
            inet_ntop(AF_INET, &new_flow->lower_addr.s_addr,
                new_flow->lower_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &new_flow->upper_addr.s_addr,
                new_flow->upper_ip, INET_ADDRSTRLEN);
            break;

        case 6:
            inet_ntop(AF_INET6, &new_flow->lower_addr6.s6_addr,
                new_flow->lower_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &new_flow->upper_addr6.s6_addr,
                new_flow->upper_ip, INET6_ADDRSTRLEN);
            break;
        }
#ifdef _ND_USE_NETLINK
        if (device_addrs != NULL) {
            string mac, ip;
            uint8_t *umac = NULL;
            nd_device_addrs::iterator i;

            umac = (new_flow->lower_type != ndNETLINK_ATYPE_UNKNOWN) ?
                new_flow->lower_mac : new_flow->upper_mac;

            // Filter out reserved MAC prefixes...
            // ...IANA RFC7042, IPv4 uni/multicast:
            if (! ((umac[0] == 0x00 || umac[0] == 0x01) &&
                umac[1] == 0x00 && umac[2] == 0x5e) &&
                // IPv6 multicast:
                ! (umac[0] == 0x33 && umac[1] == 0x33)) {

                mac.assign((const char *)umac, ETH_ALEN);

                ip = (new_flow->lower_type != ndNETLINK_ATYPE_UNKNOWN) ?
                    new_flow->lower_ip : new_flow->upper_ip;

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
#endif
        new_flow->release();
#if defined(_ND_USE_CONNTRACK) && defined(_ND_USE_NETLINK)
        if (thread_conntrack != NULL) {
            if ((new_flow->lower_type == ndNETLINK_ATYPE_LOCALIP &&
                new_flow->upper_type == ndNETLINK_ATYPE_UNKNOWN) ||
                (new_flow->lower_type == ndNETLINK_ATYPE_UNKNOWN &&
                new_flow->upper_type == ndNETLINK_ATYPE_LOCALIP)) {

                thread_conntrack->ClassifyFlow(new_flow);
            }
        }
#endif
        for (vector<uint8_t *>::const_iterator i =
            nd_config.privacy_filter_mac.begin();
            i != nd_config.privacy_filter_mac.end() &&
                new_flow->privacy_mask !=
                (ndFlow::PRIVATE_LOWER | ndFlow::PRIVATE_UPPER); i++) {
            if (! memcmp((*i), new_flow->lower_mac, ETH_ALEN))
                new_flow->privacy_mask |= ndFlow::PRIVATE_LOWER;
            if (! memcmp((*i), new_flow->upper_mac, ETH_ALEN))
                new_flow->privacy_mask |= ndFlow::PRIVATE_UPPER;
        }

        for (vector<struct sockaddr *>::const_iterator i =
            nd_config.privacy_filter_host.begin();
            i != nd_config.privacy_filter_host.end() &&
                new_flow->privacy_mask !=
                (ndFlow::PRIVATE_LOWER | ndFlow::PRIVATE_UPPER); i++) {

            struct sockaddr_in *sa_in;
            struct sockaddr_in6 *sa_in6;

            switch ((*i)->sa_family) {
            case AF_INET:
                sa_in = reinterpret_cast<struct sockaddr_in *>((*i));
                if (! memcmp(&new_flow->lower_addr, &sa_in->sin_addr,
                    sizeof(struct in_addr)))
                    new_flow->privacy_mask |= ndFlow::PRIVATE_LOWER;
                if (! memcmp(&new_flow->upper_addr, &sa_in->sin_addr,
                    sizeof(struct in_addr)))
                    new_flow->privacy_mask |= ndFlow::PRIVATE_UPPER;
                break;
            case AF_INET6:
                sa_in6 = reinterpret_cast<struct sockaddr_in6 *>((*i));
                if (! memcmp(&new_flow->lower_addr6, &sa_in6->sin6_addr,
                    sizeof(struct in6_addr)))
                    new_flow->privacy_mask |= ndFlow::PRIVATE_LOWER;
                if (! memcmp(&new_flow->upper_addr6, &sa_in6->sin6_addr,
                    sizeof(struct in6_addr)))
                    new_flow->privacy_mask |= ndFlow::PRIVATE_UPPER;
                break;
            }
        }

        if (ND_DEBUG)
            new_flow->print(tag.c_str(), ndpi);

        if (thread_socket) {
            ndJson json;

            json.AddObject(NULL, "type", "flow");
            json.AddObject(NULL, "version", (double)ND_JSON_VERSION);
            json.AddObject(NULL, "interface", tag);
            json_object *json_flow = new_flow->json_encode(
                tag.c_str(), json, ndpi, false);
            json.AddObject(NULL, "flow", json_flow);

            string json_string;
            json.ToString(json_string, false);
            json_string.append("\n");

            thread_socket->QueueWrite(json_string);

            json.Destroy();
        }
    }

    if (ts_last_idle_scan + ND_IDLE_SCAN_TIME < ts_pkt_last) {
        uint64_t purged = 0;
        nd_flow_map::iterator i = flows->begin();
        while (i != flows->end()) {
            if (i->second->ts_last_seen + ND_IDLE_FLOW_TIME < ts_pkt_last) {
                i->second->release();
                delete i->second;
                i = flows->erase(i);
                purged++;
            }
            else
                i++;
        }

        ts_last_idle_scan = ts_pkt_last;
#if 0
        if (purged > 0) {
            nd_debug_printf("%s: Purged %lu idle flows (%lu active)\n",
                tag.c_str(), purged, flows->size());
        }
#endif
    }
}

bool ndDetectionThread::ProcessDNSResponse(
    const char *host, const uint8_t *pkt, uint16_t length)
{
    ns_rr rr;
    int rc = ns_initparse(pkt, length, &ns_h);

    if (rc < 0) {
        nd_debug_printf(
            "%s: dns initparse error: %s\n", tag.c_str(), strerror(errno));
        return false;
    }

    if (ns_msg_getflag(ns_h, ns_f_rcode) != ns_r_noerror) {
        nd_debug_printf(
            "%s: dns response code: %hu\n", tag.c_str(),
            ns_msg_getflag(ns_h, ns_f_rcode));
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
            nd_debug_printf(
                "%s: dns error parsing RR %hu of %hu.\n", tag.c_str(),
                i + 1, ns_msg_count(ns_h, ns_s_an));
            continue;
        }

        if (ns_rr_type(rr) != ns_t_a && ns_rr_type(rr) != ns_t_aaaa)
            continue;

        dns_cache->insert(
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

        nd_debug_printf(
            "%s: dns RR %s address: %s, ttl: %u, rlen: %hu: %s\n",
            tag.c_str(), host,
            (ns_rr_type(rr) == ns_t_a) ? "A" : "AAAA",
            ns_rr_ttl(rr), ns_rr_rdlen(rr), addr);
#endif
    }

    return true;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
