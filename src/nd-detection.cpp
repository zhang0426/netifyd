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

#include <arpa/inet.h>
#include <json.h>
#include <linux/if_ether.h>
#include <linux/netlink.h>
#include <net/if.h>
#include <netinet/ip6.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap/pcap.h>
#include <pthread.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

extern "C" {
#include "ndpi_api.h"
}

using namespace std;

#include "netifyd.h"
#include "nd-netlink.h"
#include "nd-sha1.h"
#include "nd-json.h"
#include "nd-flow.h"
#include "nd-thread.h"
#include "nd-detection.h"
#include "nd-socket.h"
#include "nd-util.h"

extern bool nd_debug;

extern ndGlobalConfig nd_config;

ndDetectionThread::ndDetectionThread(const string &dev,
    ndNetlink *netlink, ndSocketThread *thread_socket,
    nd_flow_map *flow_map, ndDetectionStats *stats, long cpu)
    : ndThread(dev, cpu), netlink(netlink), thread_socket(thread_socket),
    pcap(NULL), pcap_snaplen(ND_PCAP_SNAPLEN), pcap_datalink_type(0),
    pkt_header(NULL), pkt_data(NULL),
    ts_pkt_last(0), ts_last_idle_scan(0),
    ndpi(NULL), flows(flow_map), stats(stats)
{
    memset(stats, 0, sizeof(struct ndDetectionStats));

    // XXX: ND_DETECTION_TICKS
    // Is now hard-coded in ndpi/src/lib/ndpi_main.c, which is 1000
    ndpi = ndpi_init_detection_module();

    if (ndpi == NULL)
        throw ndThreadException("Detection module initialization failure");

    set_ndpi_malloc(nd_mem_alloc);
    set_ndpi_free(nd_mem_free);
    set_ndpi_debug_function(nd_debug_printf);

    NDPI_PROTOCOL_BITMASK proto_all;
    NDPI_BITMASK_SET_ALL(proto_all);

    ndpi_set_protocol_detection_bitmask2(ndpi, &proto_all);

    if (nd_config.proto_file != NULL) {
        nd_printf("%s: loading custom protocols from: %s\n",
            tag.c_str(), nd_config.proto_file);
        ndpi_load_protocols_file(ndpi, nd_config.proto_file);
        nd_printf("%s: done.\n", tag.c_str());
    }

    if (nd_debug)
        nd_printf("%s: detection thread created.\n", tag.c_str());
}

ndDetectionThread::~ndDetectionThread()
{
    Join();
    if (pcap != NULL) pcap_close(pcap);
    if (ndpi != NULL) ndpi_exit_detection_module(ndpi);

    if (nd_debug)
        nd_printf("%s: detection thread destroyed.\n", tag.c_str());
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

            if (!(ifr.ifr_flags & IFF_UP)) {
                if (nd_debug) nd_printf("%s: WARNING: interface is down.\n",
                    tag.c_str());
                sleep(1);
                continue;
            }

            memset(pcap_errbuf, 0, PCAP_ERRBUF_SIZE);
            pcap = pcap_open_live(
                tag.c_str(),
                pcap_snaplen,
                1, // Promisc?
                ND_PCAP_READ_TIMEOUT,
                pcap_errbuf
            );

            if (pcap == NULL) {
                nd_printf("%s.\n", pcap_errbuf);
                sleep(1);
                continue;
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
        }
    }
    while (terminate == false);

    close(ifr_fd);

    return NULL;
}

void ndDetectionThread::ProcessPacket(void)
{
    const struct ethhdr *hdr_eth = NULL;
    const struct iphdr *hdr_ip = NULL;
    const struct ip6_hdr *hdr_ip6 = NULL;

    const uint8_t *layer3 = NULL;

    uint64_t ts_pkt;
    uint16_t type, ip_offset, ip_len, l4_len = 0;
    uint16_t frag_off = 0;
    uint8_t vlan_packet = 0;
    int addr_cmp = 0;

    struct ndFlow flow;
    memset(&flow, 0, sizeof(struct ndFlow));

    string digest;

    struct ndpi_id_struct *id_src, *id_dst;

    stats->pkt_raw++;
    if (pkt_header->len > stats->pkt_maxlen)
        stats->pkt_maxlen = pkt_header->len;
#if 0
    if (pkt_header->caplen < pkt_header->len) {
        // XXX: Warning: capture size less than packet size.
        // XXX: Increase capture size (detection may not work)...
    }
#endif
    ts_pkt = ((uint64_t)pkt_header->ts.tv_sec) * ND_DETECTION_TICKS +
        pkt_header->ts.tv_usec / (1000000 / ND_DETECTION_TICKS);

    if (ts_pkt_last > ts_pkt) ts_pkt = ts_pkt_last;
    ts_pkt_last = ts_pkt;

    switch (pcap_datalink_type) {
    case DLT_NULL:
        if (ntohl(*((uint32_t *)pkt_data)) == 2)
            type = ETH_P_IP;
        else
            type = ETH_P_IPV6;

        ip_offset = 4;
        break;

    case DLT_EN10MB:
        hdr_eth = reinterpret_cast<const struct ethhdr *>(pkt_data);
        type = ntohs(hdr_eth->h_proto);
        ip_offset = sizeof(struct ethhdr);
        stats->pkt_eth++;
        break;

    case DLT_LINUX_SLL:
        type = (pkt_data[14] << 8) + pkt_data[15];
        ip_offset = 16;
        break;

    default:
        return;
    }

    while (true) {
        if (type == ETH_P_8021Q) {
            vlan_packet = 1;
            flow.vlan_id = ((pkt_data[ip_offset] << 8) + pkt_data[ip_offset + 1]) & 0xFFF;
            type = (pkt_data[ip_offset + 2] << 8) + pkt_data[ip_offset + 3];
            ip_offset += 4;
        }
        else if (type == ETH_P_MPLS_UC) {
            stats->pkt_mpls++;
            uint32_t label = ntohl(*((uint32_t *)&pkt_data[ip_offset]));
            type = ETH_P_IP;
            ip_offset += 4;

            while ((label & 0x100) != 0x100) {
                ip_offset += 4;
                label = ntohl(*((uint32_t *)&pkt_data[ip_offset]));
            }
        }
        else if (type == ETH_P_PPP_SES) {
            stats->pkt_pppoe++;
            type = ETH_P_IP;
            ip_offset += 8;
        }
        else
            break;
    }

    stats->pkt_vlan += vlan_packet;

    hdr_ip = reinterpret_cast<const struct iphdr *>(&pkt_data[ip_offset]);
    flow.ip_version = hdr_ip->version;

    if (flow.ip_version == 4) {
        ip_len = ((uint16_t)hdr_ip->ihl * 4);
        l4_len = ntohs(hdr_ip->tot_len) - ip_len;
        flow.ip_protocol = hdr_ip->protocol;
        layer3 = reinterpret_cast<const uint8_t *>(hdr_ip);

        if (pkt_header->caplen >= ip_offset)
            frag_off = ntohs(hdr_ip->frag_off);

        if (pkt_header->len - ip_offset < sizeof(iphdr)) {
            // XXX: Warning: header too small
            stats->pkt_discard++;
            stats->pkt_discard_bytes += pkt_header->len;
            return;
        }

        if ((frag_off & 0x3FFF) != 0) {
            // XXX: Warning: packet fragmentation not supported
            stats->pkt_frags++;
            stats->pkt_discard++;
            stats->pkt_discard_bytes += pkt_header->len;
            return;
        }

        if ((frag_off & 0x1FFF) != 0) {
            stats->pkt_frags++;
            stats->pkt_discard++;
            stats->pkt_discard_bytes += pkt_header->len;
            return;
        }

        if (ip_len > pkt_header->len - ip_offset) {
            stats->pkt_discard++;
            stats->pkt_discard_bytes += pkt_header->len;
            return;
        }

        if (pkt_header->len - ip_offset < ntohs(hdr_ip->tot_len)) {
            stats->pkt_discard++;
            stats->pkt_discard_bytes += pkt_header->len;
            return;
        }

        addr_cmp = memcmp(&hdr_ip->saddr, &hdr_ip->daddr, 4);

        if (addr_cmp < 0) {
            flow.lower_addr.s_addr = hdr_ip->saddr;
            flow.upper_addr.s_addr = hdr_ip->daddr;
            if (pcap_datalink_type == DLT_EN10MB) {
                memcpy(flow.lower_mac, hdr_eth->h_source, ETH_ALEN);
                memcpy(flow.upper_mac, hdr_eth->h_dest, ETH_ALEN);
            }
        }
        else {
            flow.lower_addr.s_addr = hdr_ip->daddr;
            flow.upper_addr.s_addr = hdr_ip->saddr;
            if (pcap_datalink_type == DLT_EN10MB) {
                memcpy(flow.lower_mac, hdr_eth->h_dest, ETH_ALEN);
                memcpy(flow.upper_mac, hdr_eth->h_source, ETH_ALEN);
            }
        }
    }
    else if (flow.ip_version == 6) {
        hdr_ip6 = reinterpret_cast<const struct ip6_hdr *>(&pkt_data[ip_offset]);
        ip_len = sizeof(struct ip6_hdr);
        l4_len = ntohs(hdr_ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
        flow.ip_protocol = hdr_ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        layer3 = reinterpret_cast<const uint8_t *>(hdr_ip6);

        if (flow.ip_protocol == IPPROTO_DSTOPTS) {
            const uint8_t *options = reinterpret_cast<const uint8_t *>(
                hdr_ip6 + sizeof(const struct ip6_hdr)
            );
            flow.ip_protocol = options[0];
            ip_len += 8 * (options[1] + 1);
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
                memcpy(flow.lower_mac, hdr_eth->h_source, ETH_ALEN);
                memcpy(flow.upper_mac, hdr_eth->h_dest, ETH_ALEN);
            }
        }
        else {
            memcpy(&flow.lower_addr6, &hdr_ip6->ip6_dst, sizeof(struct in6_addr));
            memcpy(&flow.upper_addr6, &hdr_ip6->ip6_src, sizeof(struct in6_addr));
            if (pcap_datalink_type == DLT_EN10MB) {
                memcpy(flow.lower_mac, hdr_eth->h_dest, ETH_ALEN);
                memcpy(flow.upper_mac, hdr_eth->h_source, ETH_ALEN);
            }
        }
    }
    else {
        // XXX: Warning: unsupported protocol version (IPv4/6 only)
        stats->pkt_discard++;
        stats->pkt_discard_bytes += pkt_header->len;
        return;
    }

    switch (flow.ip_protocol) {
    case IPPROTO_TCP:
        if (l4_len >= 20) {
            const struct tcphdr *hdr_tcp;
            hdr_tcp = reinterpret_cast<const struct tcphdr *>(layer3 + ip_len);
            stats->pkt_tcp++;

            if (addr_cmp < 0) {
                flow.lower_port = hdr_tcp->source;
                flow.upper_port = hdr_tcp->dest;
            }
            else {
                flow.lower_port = hdr_tcp->dest;
                flow.upper_port = hdr_tcp->source;

                if (addr_cmp == 0) {
                    if (flow.lower_port > flow.upper_port) {
                        flow.lower_port = flow.upper_port;
                        flow.upper_port = hdr_tcp->dest;
                    }
                }
            }
        }
        break;

    case IPPROTO_UDP:
        if (l4_len >= 8) {
            const struct udphdr *hdr_udp;
            hdr_udp = reinterpret_cast<const struct udphdr *>(layer3 + ip_len);
            stats->pkt_udp++;

            if (addr_cmp < 0) {
                flow.lower_port = hdr_udp->source;
                flow.upper_port = hdr_udp->dest;
            }
            else {
                flow.lower_port = hdr_udp->dest;
                flow.upper_port = hdr_udp->source;
            }
        }
        break;

    default:
        // Non-TCP/UDP protocols...
        break;
    }

    flow.hash(tag, digest);

    ndFlow *new_flow = new ndFlow(flow);
    if (new_flow == NULL) throw ndThreadException(strerror(ENOMEM));

    nd_flow_insert rc = flows->insert(nd_flow_pair(digest, new_flow));

    if (rc.second) {
        new_flow->ndpi_flow = (ndpi_flow_struct *)ndpi_malloc(sizeof(ndpi_flow_struct));
        if (new_flow->ndpi_flow == NULL) throw ndThreadException(strerror(ENOMEM));
        memset(new_flow->ndpi_flow, 0, sizeof(ndpi_flow_struct));

        new_flow->id_src = new ndpi_id_struct;
        if (new_flow->id_src == NULL) throw ndThreadException(strerror(ENOMEM));
        new_flow->id_dst = new ndpi_id_struct;
        if (new_flow->id_dst == NULL) throw ndThreadException(strerror(ENOMEM));
        memset(new_flow->id_src, 0, sizeof(ndpi_id_struct));
        memset(new_flow->id_dst, 0, sizeof(ndpi_id_struct));
        id_src = new_flow->id_src;
        id_dst = new_flow->id_dst;
    }
    else {
        delete new_flow;
        new_flow = rc.first->second;

        if (flow == *new_flow)
            id_src = new_flow->id_src, id_dst = new_flow->id_dst;
        else
            id_src = new_flow->id_dst, id_dst = new_flow->id_src;
    }

    stats->pkt_ip++;
    stats->pkt_ip_bytes += pkt_header->len;
    stats->pkt_wire_bytes += pkt_header->len + 24;
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
        pkt_header->len - ip_offset,
        pkt_header->len,
        id_src,
        id_dst
    );

    if (new_flow->detected_protocol.protocol != NDPI_PROTOCOL_UNKNOWN
        || (new_flow->ip_protocol == IPPROTO_UDP && new_flow->total_packets > 8)
        || (new_flow->ip_protocol == IPPROTO_TCP && new_flow->total_packets > 10)) {

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

        new_flow->lower_type = netlink->ClassifyAddress(tag, lower_addr);
        new_flow->upper_type = netlink->ClassifyAddress(tag, upper_addr);

        if (new_flow->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN) {
            if (new_flow->ndpi_flow->num_stun_udp_pkts > 0) {
                ndpi_set_detected_protocol(
                    ndpi,
                    new_flow->ndpi_flow,
                    NDPI_PROTOCOL_STUN,
                    NDPI_PROTOCOL_UNKNOWN
                );
            }
            else {
                new_flow->detection_guessed = true;
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
                new_flow->detected_protocol.master_protocol = NDPI_PROTOCOL_UNKNOWN;
            }
        }

        snprintf(
            new_flow->detected_os, ND_FLOW_OS_LEN,
            "%s", new_flow->ndpi_flow->detected_os
        );

        snprintf(
            new_flow->host_server_name, HOST_NAME_MAX,
            "%s", new_flow->ndpi_flow->host_server_name
        );

        if (new_flow->ip_protocol == IPPROTO_TCP
            && new_flow->detected_protocol.protocol != NDPI_PROTOCOL_DNS) {
            snprintf(new_flow->ssl.client_cert, ND_FLOW_SSL_CERTLEN,
                "%s", new_flow->ndpi_flow->protos.ssl.client_certificate);
            snprintf(new_flow->ssl.server_cert, ND_FLOW_SSL_CERTLEN,
                "%s", new_flow->ndpi_flow->protos.ssl.server_certificate);
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

        new_flow->release();

        if (nd_debug)
            new_flow->print(tag.c_str(), ndpi);

        if (thread_socket) {
            ndJson json;
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
/*
        if (purged > 0) {
            nd_printf("%s: Purged %lu idle flows (%lu active)\n",
                tag.c_str(), purged, flows->size());
        }
*/
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
