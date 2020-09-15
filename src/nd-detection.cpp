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

size_t ndPacketQueue::push(struct pcap_pkthdr *pkt_header, const uint8_t *pkt_data)
{
    size_t dropped = 0;

    struct pcap_pkthdr *ph = new struct pcap_pkthdr;
    if (ph == NULL) throw ndDetectionThreadException(strerror(ENOMEM));
    memcpy(ph, pkt_header, sizeof(struct pcap_pkthdr));

    uint8_t *pd = new uint8_t[pkt_header->caplen];
    if (pd == NULL) throw ndDetectionThreadException(strerror(ENOMEM));
    memcpy(pd, pkt_data, pkt_header->caplen);

    pkt_queue.push(make_pair(ph, pd));
    pkt_queue_size += (sizeof(struct pcap_pkthdr) + pkt_header->caplen);

#ifdef _ND_LOG_PACKET_QUEUE
    nd_debug_printf("%s: packet queue push, new size: %lu\n",
        tag.c_str(), pkt_queue_size);
#endif
    if (pkt_queue_size >= nd_config.max_packet_queue) {

        nd_debug_printf("%s: packet queue full: %lu\n",
            tag.c_str(), pkt_queue_size);

        size_t target = nd_config.max_packet_queue / ND_PKTQ_FLUSH_DIVISOR;

        do {
            pop("flush");
            dropped++;
        } while (pkt_queue_size > target);
    }

    return dropped;
}

bool ndPacketQueue::front(
    struct pcap_pkthdr **pkt_header, const uint8_t **pkt_data)
{
    if (pkt_queue.empty()) return false;

    *pkt_header = pkt_queue.front().first;
    *pkt_data = pkt_queue.front().second;
#ifdef _ND_LOG_PACKET_QUEUE
    nd_debug_printf("%s: packet queue front.\n", tag.c_str());
#endif
    return true;
}

void ndPacketQueue::pop(const string &oper)
{
    if (pkt_queue.empty()) return;

    struct pcap_pkthdr *ph = pkt_queue.front().first;
    const uint8_t *pd = pkt_queue.front().second;

    pkt_queue_size -= (sizeof(struct pcap_pkthdr) + ph->caplen);

    delete ph;
    delete [] pd;

    pkt_queue.pop();

#ifdef _ND_LOG_PACKET_QUEUE
    nd_debug_printf("%s: packet queue %s: %lu\n",
        tag.c_str(), oper.c_str(), pkt_queue_size);
#endif
}

ndDetectionThread::ndDetectionThread(
    const string &dev,
    const uint8_t *dev_mac,
    bool internal,
#ifdef _ND_USE_NETLINK
    ndNetlink *netlink,
#endif
    ndSocketThread *thread_socket,
#ifdef _ND_USE_CONNTRACK
    ndConntrackThread *thread_conntrack,
#endif
    nd_flow_map *flow_map, nd_packet_stats *stats,
    nd_device_addrs *device_addrs,
    ndDNSHintCache *dhc,
    uint8_t private_addr,
    long cpu)
    : ndThread(dev, cpu, true),
    dev(dev),
    internal(internal),
    capture_unknown_flows(ND_CAPTURE_UNKNOWN_FLOWS),
#ifdef _ND_USE_NETLINK
    netlink(netlink),
#endif
    thread_socket(thread_socket),
#ifdef _ND_USE_CONNTRACK
    thread_conntrack(thread_conntrack),
#endif
    pcap(NULL), pcap_fd(-1), pcap_snaplen(ND_PCAP_SNAPLEN),
    pcap_datalink_type(0), pkt_header(NULL), pkt_data(NULL), ts_pkt_last(0),
    ts_last_idle_scan(0), ndpi(NULL), custom_proto_base(0), flows(flow_map),
    stats(stats), device_addrs(device_addrs), dhc(dhc), fhc(NULL),
    pkt_queue(tag)
{
    memset(stats, 0, sizeof(nd_packet_stats));

    size_t p = string::npos;
    if ((p = tag.find_first_of(",")) != string::npos) {
        pcap_file = tag.substr(p + 1);
        tag = tag.substr(0, p);
        nd_debug_printf("%s: capture file: %s\n", tag.c_str(), pcap_file.c_str());
    }

    ndpi = nd_ndpi_init(tag, custom_proto_base);

    if (ND_USE_FHC) {
        fhc = new ndFlowHashCache(tag, nd_config.max_fhc);
        fhc->load();
    }

    private_addrs.first.ss_family = AF_INET;
    nd_private_ipaddr(private_addr, private_addrs.first);

    private_addrs.second.ss_family = AF_INET6;
    nd_private_ipaddr(private_addr, private_addrs.second);

    memcpy(this->dev_mac, dev_mac, ETH_ALEN);
    nd_debug_printf(
        "%s: hwaddr: %02hhx:%02hhx:%02hhx:%02hhx:%02hx:%02hhx\n",
        dev.c_str(),
        dev_mac[0], dev_mac[1], dev_mac[2],
        dev_mac[3], dev_mac[4], dev_mac[5]
    );

    nd_debug_printf("%s: detection thread created, custom_proto_base: %u.\n",
        tag.c_str(), custom_proto_base);
}

ndDetectionThread::~ndDetectionThread()
{
    Join();

    if (pcap != NULL) pcap_close(pcap);
    if (ndpi != NULL) nd_ndpi_free(ndpi);
    if (fhc != NULL) {
        fhc->save();
        delete fhc;
    }

    nd_debug_printf("%s: detection thread destroyed.\n", tag.c_str());
}

void *ndDetectionThread::Entry(void)
{
    bool dump_flows = false;

    struct ifreq ifr;

    do {
        if (pcap == NULL) {
            if (nd_ifreq(tag, SIOCGIFFLAGS, &ifr) == -1) {
                sleep(1);
                continue;
            }

            if (! (ifr.ifr_flags & IFF_UP)) {
                nd_debug_printf("%s: WARNING: interface is down.\n",
                    tag.c_str());
                sleep(1);
                continue;
            }

            if ((pcap = OpenCapture()) == NULL) {
                sleep(1);
                continue;
            }

            pcap_datalink_type = pcap_datalink(pcap);

            nd_debug_printf("%s: capture started on CPU: %lu\n",
                tag.c_str(), cpu >= 0 ? cpu : 0);
        }

        if (pcap_fd != -1) {
            int rc, max_fd = 0;
            struct timeval tv;
            fd_set fds_read;

            FD_ZERO(&fds_read);
            FD_SET(fd_ipc[0], &fds_read);
            FD_SET(pcap_fd, &fds_read);

            memset(&tv, 0, sizeof(struct timeval));

            if (pkt_queue.empty()) tv.tv_sec = 1;
            tv.tv_usec = ND_TTL_PCAP_SELECT_USEC;

            max_fd = max(fd_ipc[0], pcap_fd);
            rc = select(max_fd + 1, &fds_read, NULL, NULL, &tv);

            if (rc == -1)
                throw ndDetectionThreadException(strerror(errno));

            if (! pkt_queue.empty() && pthread_mutex_trylock(&lock) == 0) {

                pkt_queue.front(&pkt_header, &pkt_data);

                try {
                    ProcessPacket();
                }
                catch (exception &e) {
                    pthread_mutex_unlock(&lock);
                    throw;
                }

                pthread_mutex_unlock(&lock);

                pkt_queue.pop();
            }

            if (dump_flows && pthread_mutex_trylock(&lock) == 0) {

                if (ND_FLOW_DUMP_ESTABLISHED)
                    DumpFlows();

                dump_flows = false;
                pthread_mutex_unlock(&lock);
            }

            if (rc == 0) continue;

            if (FD_ISSET(fd_ipc[0], &fds_read)) {
                uint32_t id = RecvIPC();

                if (id == (uint32_t)ND_SIG_CONNECT)
                    dump_flows = true;
                else {
                    nd_debug_printf("%s: Unknown IPC ID: %u (ND_SIG_CONNECT: %u).\n",
                        tag.c_str(), id, ND_SIG_CONNECT);
                }
            }

            if (! FD_ISSET(pcap_fd, &fds_read)) continue;
        }

        switch (pcap_next_ex(pcap, &pkt_header, &pkt_data)) {
        case 0:
            break;
        case 1:
            if (pthread_mutex_trylock(&lock) != 0) {

                stats->pkt.queue_dropped += pkt_queue.push(pkt_header, pkt_data);
            }
            else {
                bool from_queue = false;

                if (! pkt_queue.empty()) {
                    stats->pkt.queue_dropped += pkt_queue.push(pkt_header, pkt_data);
                    from_queue = pkt_queue.front(&pkt_header, &pkt_data);
                }

                try {
                    ProcessPacket();
                }
                catch (exception &e) {
                    pthread_mutex_unlock(&lock);
                    throw;
                }
                pthread_mutex_unlock(&lock);

                if (from_queue)
                    pkt_queue.pop();
            }
            break;
        case -1:
            nd_printf("%s: %s.\n", tag.c_str(), pcap_geterr(pcap));
            pcap_close(pcap);
            pcap = NULL;
            break;
        case -2:
            nd_debug_printf("%s: end of capture file: %s\n",
                tag.c_str(), pcap_file.c_str());
            pcap_close(pcap);
            pcap = NULL;
            terminate = true;
            break;
        }
    }
    while (terminate == false);

    nd_debug_printf("%s: capture ended on CPU: %lu\n",
        tag.c_str(), cpu >= 0 ? cpu : 0);

    return NULL;
}

pcap_t *ndDetectionThread::OpenCapture(void)
{
    pcap_t *pcap_new = NULL;

    memset(pcap_errbuf, 0, PCAP_ERRBUF_SIZE);

    if (pcap_file.size()) {
        if ((pcap_new = pcap_open_offline(pcap_file.c_str(), pcap_errbuf)) != NULL) {
            nd_debug_printf("%s: reading from capture file: %s: v%d.%d\n",
                tag.c_str(), pcap_file.c_str(),
                pcap_major_version(pcap_new), pcap_minor_version(pcap_new));
        }
    }
    else {
        pcap_new = pcap_open_live(tag.c_str(),
            pcap_snaplen, 1, ND_PCAP_READ_TIMEOUT, pcap_errbuf
        );
#if 0
        if (pcap_new != NULL) {
            bool adapter = false;
            int *pcap_tstamp_types, count;
            if ((count = pcap_list_tstamp_types(pcap_new, &pcap_tstamp_types)) > 0) {
                for (int i = 0; i < count; i++) {
                    nd_debug_printf("%s: tstamp_type: %s\n", tag.c_str(),
                        pcap_tstamp_type_val_to_name(pcap_tstamp_types[i]));
                    if (pcap_tstamp_types[i] == PCAP_TSTAMP_ADAPTER)
                        adapter = true;
                }

                pcap_free_tstamp_types(pcap_tstamp_types);

                //if (adapter) {
                //    if (pcap_set_tstamp_type(pcap_new, PCAP_TSTAMP_ADAPTER) != 0) {
                //        nd_printf("%s: Failed to set timestamp type: %s\n", tag.c_str(),
                //            pcap_geterr(pcap_new));
                //    }
                //}
            }
        }
#endif
    }

    if (pcap_new == NULL)
        nd_printf("%s: pcap_open: %s\n", tag.c_str(), pcap_errbuf);
    else {
        if ((pcap_fd = pcap_get_selectable_fd(pcap_new)) < 0)
            nd_debug_printf("%s: pcap_get_selectable_fd: -1\n", tag.c_str());

        nd_device_filter::const_iterator i = nd_config.device_filters.find(dev);

        if (i != nd_config.device_filters.end()) {

            if (pcap_compile(pcap_new, &pcap_filter,
                i->second.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0) {
                nd_printf("%s: pcap_compile: %s\n",
                    tag.c_str(), pcap_geterr(pcap_new));
                pcap_close(pcap_new);
                return NULL;
            }

            if (pcap_setfilter(pcap_new, &pcap_filter) < 0) {
                nd_printf("%s: pcap_setfilter: %s\n",
                    tag.c_str(), pcap_geterr(pcap_new));
                pcap_close(pcap_new);
                return NULL;
            }
        }
    }

    return pcap_new;
}

// XXX: Not thread-safe!
// XXX: Ensure the object is locked before calling.
void ndDetectionThread::DumpFlows(void)
{
    unsigned flow_count = 0;

    if (! thread_socket) return;

    for (nd_flow_map::const_iterator i = flows->begin(); i != flows->end(); i++) {

        if (i->second->detection_complete == false) continue;
        if (! ND_FLOW_DUMP_UNKNOWN &&
            i->second->detected_protocol.master_protocol == NDPI_PROTOCOL_UNKNOWN) continue;

        json j;

        j["type"] = "flow";
        j["interface"] = tag;
        j["internal"] = internal;
        j["established"] = true;

        json jf;
        i->second->json_encode(jf, ndpi, false);

        j["flow"] = jf;

        string json_string;
        nd_json_to_string(j, json_string, false);
        json_string.append("\n");

        thread_socket->QueueWrite(json_string);

        flow_count++;
    }

    nd_debug_printf("%s: dumped %lu flow(s).\n", tag.c_str(), flow_count);
}

// XXX: Not thread-safe!
// XXX: Ensure the object is locked before calling.
int ndDetectionThread::GetCaptureStats(struct pcap_stat &stats)
{
    memset(&stats, 0, sizeof(struct pcap_stat));

    if (pcap_file.size() || pcap == NULL) return 1;

    return pcap_stats(pcap, &stats);
}

void ndDetectionThread::ProcessPacket(void)
{
    ndFlow *nf;
    nd_flow_insert fi;

    const struct ether_header *hdr_eth = NULL;
    const struct sll_header *hdr_sll = NULL;
    const struct ip *hdr_ip = NULL;
    const struct ip6_hdr *hdr_ip6 = NULL;
    const struct tcphdr *hdr_tcp = NULL;
    const struct udphdr *hdr_udp = NULL;

    const uint8_t *l3 = NULL, *l4 = NULL, *pkt = NULL;
    uint16_t l2_len, l3_len, l4_len = 0, pkt_len = 0;

    uint16_t type = 0;
    uint16_t ppp_proto;
    uint16_t frag_off = 0;
    uint8_t vlan_packet = 0;
    int addr_cmp = 0;

    struct ndFlow flow(internal);

    struct ndpi_id_struct *id_src, *id_dst;
    uint16_t ndpi_proto = NDPI_PROTOCOL_UNKNOWN;
    ndpi_protocol_match_result npmr;

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

    stats->pkt.raw++;
    if (pkt_header->len > stats->pkt.maxlen)
        stats->pkt.maxlen = pkt_header->len;

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
        stats->pkt.eth++;

        // STP?
        if ((hdr_eth->ether_shost[0] == 0x01 && hdr_eth->ether_shost[1] == 0x80 &&
            hdr_eth->ether_shost[2] == 0xC2) ||
            (hdr_eth->ether_dhost[0] == 0x01 && hdr_eth->ether_dhost[1] == 0x80 &&
            hdr_eth->ether_dhost[2] == 0xC2)) {
            stats->pkt.discard++;
            stats->pkt.discard_bytes += pkt_header->caplen;
#ifdef _ND_LOG_PKT_DISCARD
            nd_debug_printf("%s: discard: STP protocol.\n", tag.c_str());
#endif
            return;
        }

        break;

    case DLT_LINUX_SLL:
        hdr_sll = reinterpret_cast<const struct sll_header *>(pkt_data);
        type = hdr_sll->sll_protocol;
        l2_len = SLL_HDR_LEN;
        break;

    case DLT_RAW:
        l2_len = 0;
        // type will be set to ETHERTYPE_IP/V6 below...
        break;

    default:
        stats->pkt.discard++;
        stats->pkt.discard_bytes += pkt_header->caplen;
#ifdef _ND_LOG_PKT_DISCARD
        nd_debug_printf("%s: discard: Unsupported datalink type: 0x%x\n",
            tag.c_str(), (unsigned)pcap_datalink_type);
#endif
        return;
    }

    while (true) {
        if (type == ETHERTYPE_VLAN) {
            vlan_packet = 1;
            // TODO: Replace with struct vlan_tag from <pcap/vlan.h>
            // See: https://en.wikipedia.org/wiki/IEEE_802.1Q
            flow.vlan_id = ((pkt_data[l2_len] << 8) + pkt_data[l2_len + 1]) & 0xFFF;
            type = (pkt_data[l2_len + 2] << 8) + pkt_data[l2_len + 3];
            l2_len += VLAN_TAG_LEN;
        }
        else if (type == ETHERTYPE_MPLS_UC || type == ETHERTYPE_MPLS_MC) {
            stats->pkt.mpls++;
            union mpls {
                uint32_t u32;
                struct nd_mpls_header_t mpls;
            } mpls;
            mpls.u32 = ntohl(*((uint32_t *)&pkt_data[l2_len]));
            type = ETHERTYPE_IP;
            l2_len += 4;

            while (! mpls.mpls.s) {
                l2_len += 4;
                mpls.u32 = ntohl(*((uint32_t *)&pkt_data[l2_len]));
            }
        }
        else if (type == ETHERTYPE_PPPOE) {
            stats->pkt.pppoe++;
            type = ETHERTYPE_IP;
            ppp_proto = (uint16_t)(
                _ND_PPP_PROTOCOL(pkt_data + l2_len + 6)
            );
            if (ppp_proto != PPP_IP && ppp_proto != PPP_IPV6) {
                stats->pkt.discard++;
                stats->pkt.discard_bytes += pkt_header->caplen;
#ifdef _ND_LOG_PKT_DISCARD
                nd_debug_printf("%s: discard: unsupported PPP protocol: 0x%04hx\n",
                    tag.c_str(), ppp_proto);
#endif
                return;
            }

            l2_len += 8;
        }
        else if (type == ETHERTYPE_PPPOEDISC) {
            stats->pkt.pppoe++;
            stats->pkt.discard++;
            stats->pkt.discard_bytes += pkt_header->caplen;
#ifdef _ND_LOG_PKT_DISCARD
            nd_debug_printf("%s: discard: PPPoE discovery protocol.\n", tag.c_str());
#endif
            return;
        }
        else
            break;
    }

    stats->pkt.vlan += vlan_packet;

    hdr_ip = reinterpret_cast<const struct ip *>(&pkt_data[l2_len]);
    flow.ip_version = hdr_ip->ip_v;

    if (flow.ip_version == 4) {

        if (type == 0) type = ETHERTYPE_IP;

        l3_len = ((uint16_t)hdr_ip->ip_hl * 4);
        l4_len = ntohs(hdr_ip->ip_len) - l3_len;
        flow.ip_protocol = hdr_ip->ip_p;
        flow.lower_addr.ss_family = AF_INET;
        flow.upper_addr.ss_family = AF_INET;
        l3 = reinterpret_cast<const uint8_t *>(hdr_ip);

        if (pkt_header->caplen >= l2_len)
            frag_off = ntohs(hdr_ip->ip_off);

        if (pkt_header->caplen - l2_len < sizeof(struct ip)) {
            // XXX: header too small
            stats->pkt.discard++;
            stats->pkt.discard_bytes += pkt_header->caplen;
#ifdef _ND_LOG_PKT_DISCARD
            nd_debug_printf("%s: discard: header too small\n", tag.c_str());
#endif
            return;
        }

        if ((frag_off & 0x3FFF) != 0) {
            // XXX: fragmented packets are not supported
            stats->pkt.frags++;
            stats->pkt.discard++;
            stats->pkt.discard_bytes += pkt_header->caplen;
#ifdef _ND_LOG_PKT_DISCARD
            nd_debug_printf("%s: discard: fragmented 0x3FFF\n", tag.c_str());
#endif
            return;
        }

        if ((frag_off & 0x1FFF) != 0) {
            // XXX: fragmented packets are not supported
            stats->pkt.frags++;
            stats->pkt.discard++;
            stats->pkt.discard_bytes += pkt_header->caplen;
#ifdef _ND_LOG_PKT_DISCARD
            nd_debug_printf("%s: discard: fragmented 0x1FFF\n", tag.c_str());
#endif
            return;
        }

        if (l3_len > (pkt_header->caplen - l2_len)) {
            stats->pkt.discard++;
            stats->pkt.discard_bytes += pkt_header->caplen;
#ifdef _ND_LOG_PKT_DISCARD
            nd_debug_printf("%s: discard: l3_len[%hu] > (pkt_header->caplen[%hu] - l2_len[%hu])(%hu)\n",
                tag.c_str(), l3_len, pkt_header->caplen, l2_len, pkt_header->caplen - l2_len);
#endif
            return;
        }

        if ((pkt_header->caplen - l2_len) < ntohs(hdr_ip->ip_len)) {
            stats->pkt.discard++;
            stats->pkt.discard_bytes += pkt_header->caplen;
#ifdef _ND_LOG_PKT_DISCARD
            nd_debug_printf("%s: discard: (pkt_header->caplen[%hu] - l2_len[%hu](%hu)) < hdr_ip->ip_len[%hu]\n",
                tag.c_str(), pkt_header->caplen, l2_len, pkt_header->caplen - l2_len, ntohs(hdr_ip->ip_len));
#endif
            return;
        }

        addr_cmp = memcmp(&hdr_ip->ip_src, &hdr_ip->ip_dst, 4);

        if (addr_cmp < 0) {
            flow.lower_addr4->sin_addr.s_addr = hdr_ip->ip_src.s_addr;
            flow.upper_addr4->sin_addr.s_addr = hdr_ip->ip_dst.s_addr;
            if (pcap_datalink_type == DLT_EN10MB) {
                memcpy(flow.lower_mac, hdr_eth->ether_shost, ETH_ALEN);
                memcpy(flow.upper_mac, hdr_eth->ether_dhost, ETH_ALEN);
            }
        }
        else {
            flow.lower_addr4->sin_addr.s_addr = hdr_ip->ip_dst.s_addr;
            flow.upper_addr4->sin_addr.s_addr = hdr_ip->ip_src.s_addr;
            if (pcap_datalink_type == DLT_EN10MB) {
                memcpy(flow.lower_mac, hdr_eth->ether_dhost, ETH_ALEN);
                memcpy(flow.upper_mac, hdr_eth->ether_shost, ETH_ALEN);
            }
        }

        l4 = reinterpret_cast<const uint8_t *>(l3 + l3_len);
    }
    else if (flow.ip_version == 6) {

        if (type == 0) type = ETHERTYPE_IPV6;

        hdr_ip6 = reinterpret_cast<const struct ip6_hdr *>(&pkt_data[l2_len]);

        l3 = reinterpret_cast<const uint8_t *>(hdr_ip6);
        l3_len = sizeof(struct ip6_hdr);
        l4 = reinterpret_cast<const uint8_t *>(l3 + l3_len);
        l4_len = ntohs(hdr_ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
        flow.ip_protocol = hdr_ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;

        if (ndpi_handle_ipv6_extension_headers(NULL, &l4, &l4_len, &flow.ip_protocol)) {
            stats->pkt.discard++;
            stats->pkt.discard_bytes += pkt_header->caplen;
#ifdef _ND_LOG_PKT_DISCARD
            nd_debug_printf("%s: discard: Error walking IPv6 extensions.\n", tag.c_str());
#endif
            return;
        }

        flow.lower_addr.ss_family = AF_INET6;
        flow.upper_addr.ss_family = AF_INET6;

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
            memcpy(&flow.lower_addr6->sin6_addr, &hdr_ip6->ip6_src, sizeof(struct in6_addr));
            memcpy(&flow.upper_addr6->sin6_addr, &hdr_ip6->ip6_dst, sizeof(struct in6_addr));
            if (pcap_datalink_type == DLT_EN10MB) {
                memcpy(flow.lower_mac, hdr_eth->ether_shost, ETH_ALEN);
                memcpy(flow.upper_mac, hdr_eth->ether_dhost, ETH_ALEN);
            }
        }
        else {
            memcpy(&flow.lower_addr6->sin6_addr, &hdr_ip6->ip6_dst, sizeof(struct in6_addr));
            memcpy(&flow.upper_addr6->sin6_addr, &hdr_ip6->ip6_src, sizeof(struct in6_addr));
            if (pcap_datalink_type == DLT_EN10MB) {
                memcpy(flow.lower_mac, hdr_eth->ether_dhost, ETH_ALEN);
                memcpy(flow.upper_mac, hdr_eth->ether_shost, ETH_ALEN);
            }
        }
    }
    else {
        // XXX: Warning: unsupported IP protocol version (IPv4/6 only)
        stats->pkt.discard++;
        stats->pkt.discard_bytes += pkt_header->caplen;
#ifdef _ND_LOG_PKT_DISCARD
        nd_debug_printf("%s: discard: invalid IP protocol version: %hhx\n",
            tag.c_str(), pkt_data[l2_len]);
#endif
        return;
    }

    switch (flow.ip_protocol) {
    case IPPROTO_TCP:
        if (l4_len >= 20) {
            hdr_tcp = reinterpret_cast<const struct tcphdr *>(l4);
            stats->pkt.tcp++;

            if (addr_cmp < 0) {
                flow.lower_port = hdr_tcp->th_sport;
                flow.upper_port = hdr_tcp->th_dport;
            }
            else if (addr_cmp > 0) {
                flow.lower_port = hdr_tcp->th_dport;
                flow.upper_port = hdr_tcp->th_sport;
            }
            else {
                if (hdr_tcp->th_sport < hdr_tcp->th_dport) {
                    flow.lower_port = hdr_tcp->th_sport;
                    flow.upper_port = hdr_tcp->th_dport;
                }
                else {
                    flow.lower_port = hdr_tcp->th_dport;
                    flow.upper_port = hdr_tcp->th_sport;
                }
            }

            pkt = reinterpret_cast<const uint8_t *>(l4 + (hdr_tcp->th_off * 4));
            pkt_len = l4_len - (hdr_tcp->th_off * 4);
        }
        break;

    case IPPROTO_UDP:
        if (l4_len >= 8) {
            hdr_udp = reinterpret_cast<const struct udphdr *>(l4);
            stats->pkt.udp++;

            if (addr_cmp < 0) {
                flow.lower_port = hdr_udp->uh_sport;
                flow.upper_port = hdr_udp->uh_dport;
            }
            else if (addr_cmp > 0) {
                flow.lower_port = hdr_udp->uh_dport;
                flow.upper_port = hdr_udp->uh_sport;
            }
            else {
                if (hdr_udp->uh_sport < hdr_udp->uh_dport) {
                    flow.lower_port = hdr_udp->uh_sport;
                    flow.upper_port = hdr_udp->uh_dport;
                }
                else {
                    flow.lower_port = hdr_udp->uh_dport;
                    flow.upper_port = hdr_udp->uh_sport;
                }
            }

            pkt = reinterpret_cast<const uint8_t *>(l4 + sizeof(struct udphdr));
            pkt_len = ntohs(hdr_udp->uh_ulen) - sizeof(struct udphdr);
        }
        break;

    case IPPROTO_ICMP:
    case IPPROTO_ICMPV6:
        stats->pkt.icmp++;
        break;

    case IPPROTO_IGMP:
        stats->pkt.igmp++;
        break;

    default:
        // Non-TCP/UDP protocols, ex: ICMP...
        //nd_debug_printf("%s: non TCP/UDP protocol: %d\n", tag.c_str(), flow.ip_protocol);
        break;
    }

    flow.hash(tag);
    flow_digest.assign((const char *)flow.digest_lower, SHA1_DIGEST_LENGTH);
    fi.first = flows->find(flow_digest);

    if (fi.first != flows->end()) {
        // Flow exists in map.
        nf = fi.first->second;

        if (flow == *nf)
            id_src = nf->id_src, id_dst = nf->id_dst;
        else
            id_src = nf->id_dst, id_dst = nf->id_src;
    }
    else {
        nf = new ndFlow(flow);
        if (nf == NULL) throw ndDetectionThreadException(strerror(ENOMEM));

        fi = flows->insert(nd_flow_pair(flow_digest, nf));

        if (! fi.second) {
            // Flow exists in map!  Impossible!
            throw ndDetectionThreadException(strerror(EINVAL));
        }

        // New flow inserted, initialize...

        nf->ts_first_seen = ts_pkt;

        nf->ndpi_flow = (ndpi_flow_struct *)ndpi_malloc(sizeof(ndpi_flow_struct));
        if (nf->ndpi_flow == NULL)
            throw ndDetectionThreadException(strerror(ENOMEM));

        memset(nf->ndpi_flow, 0, sizeof(ndpi_flow_struct));

        nf->id_src = new ndpi_id_struct;
        if (nf->id_src == NULL)
            throw ndDetectionThreadException(strerror(ENOMEM));
        nf->id_dst = new ndpi_id_struct;
        if (nf->id_dst == NULL)
            throw ndDetectionThreadException(strerror(ENOMEM));

        memset(nf->id_src, 0, sizeof(ndpi_id_struct));
        memset(nf->id_dst, 0, sizeof(ndpi_id_struct));

        id_src = nf->id_src;
        id_dst = nf->id_dst;

        // Set initial flow origin:
        // XXX: A 50-50 guess based on which side we saw first.
        if (addr_cmp < 0)
            nf->origin = ndFlow::ORIGIN_LOWER;
        else
            nf->origin = ndFlow::ORIGIN_UPPER;

        // Try to refine flow origin for TCP flows using SYN/ACK flags
        if (flow.ip_protocol == IPPROTO_TCP) {

            if ((hdr_tcp->th_flags & TH_SYN)) {

                if (! (hdr_tcp->th_flags & TH_ACK)) {
                    if (addr_cmp < 0)
                        nf->origin = ndFlow::ORIGIN_LOWER;
                    else
                        nf->origin = ndFlow::ORIGIN_UPPER;
                }
                else {
                    if (addr_cmp < 0)
                        nf->origin = ndFlow::ORIGIN_UPPER;
                    else
                        nf->origin = ndFlow::ORIGIN_LOWER;
                }
            }
        }
    }

    stats->pkt.wire_bytes += pkt_header->len + 24;

    stats->pkt.ip++;
    stats->pkt.ip_bytes += pkt_header->len;

    if (nf->ip_version == 4) {
        stats->pkt.ip4++;
        stats->pkt.ip4_bytes += pkt_header->len;
    }
    else {
        stats->pkt.ip6++;
        stats->pkt.ip6_bytes += pkt_header->len;
    }

    nf->total_packets++;
    nf->total_bytes += pkt_header->len;

    if (addr_cmp < 0) {
        nf->lower_packets++;
        nf->lower_bytes += pkt_header->len;
    }
    else {
        nf->upper_packets++;
        nf->upper_bytes += pkt_header->len;
    }

    nf->ts_last_seen = ts_pkt;
    if (! nf->ts_first_update)
        nf->ts_first_update = ts_pkt;

    if (nf->ip_protocol == IPPROTO_TCP &&
        (hdr_tcp->th_flags & TH_FIN || hdr_tcp->th_flags & TH_RST))
        nf->tcp_fin = true;

    if (nf->detection_complete) return;

    if (capture_unknown_flows) nf->push(pkt_header, pkt_data);

    nf->detected_protocol = ndpi_detection_process_packet(
        ndpi,
        nf->ndpi_flow,
        (nf->ip_version == 4) ?
            (const uint8_t *)hdr_ip : (const uint8_t *)hdr_ip6,
        pkt_header->caplen - l2_len,
        ts_pkt,
        id_src,
        id_dst
    );

//    nd_debug_printf("%s: %hhu.%hhu\n", tag.c_str(),
//        nf->detected_protocol.master_protocol,
//        nf->detected_protocol.app_protocol);

    if (nf->detected_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN
        || (nf->ip_protocol != IPPROTO_TCP &&
            nf->ip_protocol != IPPROTO_UDP)
        || (nf->ip_protocol == IPPROTO_UDP &&
            nf->total_packets > nd_config.max_udp_pkts)
        || (nf->ip_protocol == IPPROTO_TCP &&
            nf->total_packets > nd_config.max_tcp_pkts)) {

        nf->detection_complete = true;

#ifdef _ND_USE_NETLINK
        if (ND_USE_NETLINK) {
            nf->lower_type = netlink->ClassifyAddress(&nf->lower_addr);
            nf->upper_type = netlink->ClassifyAddress(&nf->upper_addr);
        }
#endif
        if (nf->detected_protocol.master_protocol == NDPI_PROTOCOL_UNKNOWN) {

            nf->detection_guessed |= ND_FLOW_GUESS_PROTO;

            nf->detected_protocol.master_protocol =
                ndpi_guess_undetected_protocol(
                    ndpi,
                    NULL,
                    nf->ip_protocol,
                    ntohs(nf->lower_port),
                    ntohs(nf->upper_port)
            );
        }
        else if (nf->detected_protocol.master_protocol == NDPI_PROTOCOL_SSDP) {
            if (nf->ndpi_flow->packet.packet_lines_parsed_complete) {
                string buffer;
                for (unsigned i = 0;
                    i < nf->ndpi_flow->packet.parsed_lines; i++) {

                    buffer.assign(
                        (const char *)nf->ndpi_flow->packet.line[i].ptr,
                        nf->ndpi_flow->packet.line[i].len
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

                        nf->ssdp.headers[key] = value;
                    }
                }
            }
        }

        if (dhc != NULL) {
            string hostname;
#ifdef _ND_USE_NETLINK
            if (nf->lower_type == ndNETLINK_ATYPE_UNKNOWN)
                nf->dhc_hit = dhc->lookup(&nf->lower_addr, hostname);
            else if (nf->upper_type == ndNETLINK_ATYPE_UNKNOWN) {
                nf->dhc_hit = dhc->lookup(&nf->upper_addr, hostname);
            }
#endif
            if (! nf->dhc_hit) {
                if (nf->origin == ndFlow::ORIGIN_LOWER)
                    nf->dhc_hit = dhc->lookup(&nf->upper_addr, hostname);
                else if (nf->origin == ndFlow::ORIGIN_UPPER)
                    nf->dhc_hit = dhc->lookup(&nf->lower_addr, hostname);
            }

            if (nf->dhc_hit &&
                (nf->ndpi_flow->host_server_name[0] == '\0' ||
                nd_is_ipaddr((const char *)nf->ndpi_flow->host_server_name))) {
                snprintf(
                    (char *)nf->ndpi_flow->host_server_name,
                    sizeof(nf->ndpi_flow->host_server_name) - 1,
                    "%s", hostname.c_str()
                );
            }
        }

        // Sanitize host server name; RFC 952 plus underscore for SSDP.
        for(int i = 0;
            i < ND_MAX_HOSTNAME &&
            i < sizeof(nf->ndpi_flow->host_server_name); i++) {

            if (isalnum(nf->ndpi_flow->host_server_name[i]) ||
                nf->ndpi_flow->host_server_name[i] == '-' ||
                nf->ndpi_flow->host_server_name[i] == '_' ||
                nf->ndpi_flow->host_server_name[i] == '.') {
                nf->host_server_name[i] = tolower(nf->ndpi_flow->host_server_name[i]);
            }
            else {
                nf->host_server_name[i] = '\0';
                break;
            }
        }

        // Determine application protocol
        if (nf->host_server_name[0] != '\0') {
            nf->detected_protocol.app_protocol = ndpi_match_host_app_proto(
                ndpi,
                nf->ndpi_flow,
                (char *)nf->host_server_name,
                strlen((const char *)nf->host_server_name),
                &npmr
            );
        }

        // Determine application protocol based on master protocol
        switch (nf->detected_protocol.master_protocol) {
        case NDPI_PROTOCOL_HTTPS:
        case NDPI_PROTOCOL_SSL:
        case NDPI_PROTOCOL_MAIL_IMAPS:
        case NDPI_PROTOCOL_MAIL_SMTPS:
        case NDPI_PROTOCOL_MAIL_POPS:
        case NDPI_PROTOCOL_SSL_NO_CERT:
        case NDPI_PROTOCOL_OSCAR:
            if (nf->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
                nf->ndpi_flow->protos.stun_ssl.ssl.client_certificate[0] != '\0') {
                nf->detected_protocol.app_protocol = (uint16_t)ndpi_match_host_app_proto(
                    ndpi,
                    nf->ndpi_flow,
                    (char *)nf->ndpi_flow->protos.stun_ssl.ssl.client_certificate,
                    strlen((const char*)nf->ndpi_flow->protos.stun_ssl.ssl.client_certificate),
                    &npmr);
            }
            if (nf->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
                nf->ndpi_flow->protos.stun_ssl.ssl.server_certificate[0] != '\0') {
                nf->detected_protocol.app_protocol = (uint16_t)ndpi_match_host_app_proto(
                    ndpi,
                    nf->ndpi_flow,
                    (char *)nf->ndpi_flow->protos.stun_ssl.ssl.server_certificate,
                    strlen((const char*)nf->ndpi_flow->protos.stun_ssl.ssl.server_certificate),
                    &npmr);
            }
            break;

        case NDPI_PROTOCOL_SPOTIFY:
            nf->detected_protocol.app_protocol = ndpi_get_protocol_id(ndpi, "netify.spotify");
            break;

        case NDPI_PROTOCOL_MDNS:
            if (nf->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN &&
                    nf->ndpi_flow->protos.mdns.answer[0] != '\0') {
                nf->detected_protocol.app_protocol = (uint16_t)ndpi_match_host_app_proto(
                    ndpi, nf->ndpi_flow,
                    (char *)nf->ndpi_flow->protos.mdns.answer,
                    strlen((const char*)nf->ndpi_flow->protos.mdns.answer),
                    &npmr
                );
            }
            break;
        }

        if (nf->detected_protocol.app_protocol == NDPI_PROTOCOL_UNKNOWN) {
            nf->detected_protocol.app_protocol = ndpi_match_host_proto_id(ndpi, nf->ndpi_flow);
        }

        if (nf->detected_protocol.master_protocol == NDPI_PROTOCOL_STUN) {
            if (nf->detected_protocol.app_protocol == NDPI_PROTOCOL_FACEBOOK)
                nf->detected_protocol.app_protocol = NDPI_PROTOCOL_MESSENGER;
            else if (nf->detected_protocol.app_protocol == NDPI_PROTOCOL_GOOGLE)
                nf->detected_protocol.app_protocol = NDPI_PROTOCOL_HANGOUT;
        }

        // Additional protocol-specific processing...
        ndpi_proto = nf->master_protocol();

        switch (ndpi_proto) {

        case NDPI_PROTOCOL_MDNS:
            snprintf(
                nf->mdns.answer, ND_FLOW_MDNS_ANSLEN,
                "%s", nf->ndpi_flow->protos.mdns.answer
            );
            break;

        case NDPI_PROTOCOL_SSL:
            nf->ssl.version =
                (nf->ndpi_flow->protos.stun_ssl.ssl.version) ?
                nf->ndpi_flow->protos.stun_ssl.ssl.version :
                nf->ndpi_flow->protos.stun_ssl.ssl.ssl_version;
            nf->ssl.cipher_suite =
                nf->ndpi_flow->protos.stun_ssl.ssl.server_cipher;

            snprintf(nf->ssl.client_sni, ND_FLOW_SSL_CNLEN,
                "%s", nf->ndpi_flow->protos.stun_ssl.ssl.client_certificate);
            snprintf(nf->ssl.server_cn, ND_FLOW_SSL_CNLEN,
                "%s", nf->ndpi_flow->protos.stun_ssl.ssl.server_certificate);
            snprintf(nf->ssl.server_organization, ND_FLOW_SSL_ORGLEN,
                "%s", nf->ndpi_flow->protos.stun_ssl.ssl.server_organization);
            snprintf(nf->ssl.client_ja3, ND_FLOW_SSL_JA3LEN,
                "%s", nf->ndpi_flow->protos.stun_ssl.ssl.ja3_client);
            snprintf(nf->ssl.server_ja3, ND_FLOW_SSL_JA3LEN,
                "%s", nf->ndpi_flow->protos.stun_ssl.ssl.ja3_server);

            if (nf->ndpi_flow->l4.tcp.tls_fingerprint_len) {
                memcpy(nf->ssl.cert_fingerprint,
                    nf->ndpi_flow->l4.tcp.tls_sha1_certificate_fingerprint,
                    ND_FLOW_SSL_HASH_LEN);
                nf->ssl.cert_fingerprint_found = true;
            }

            break;
        case NDPI_PROTOCOL_HTTP:
            for (size_t i = 0;
                i < strlen((const char *)nf->ndpi_flow->protos.http.user_agent); i++) {
                if (! isprint(nf->ndpi_flow->protos.http.user_agent[i])) {
                    // XXX: Sanitize user_agent of non-printable characters.
                    nf->ndpi_flow->protos.http.user_agent[i] = '\0';
                    break;
                }
            }
            snprintf(
                nf->http.user_agent, ND_FLOW_UA_LEN,
                "%s", nf->ndpi_flow->protos.http.user_agent
            );
            break;
        case NDPI_PROTOCOL_DHCP:
            snprintf(
                nf->dhcp.fingerprint, ND_FLOW_DHCPFP_LEN,
                "%s", nf->ndpi_flow->protos.dhcp.fingerprint
            );
            snprintf(
                nf->dhcp.class_ident, ND_FLOW_DHCPCI_LEN,
                "%s", nf->ndpi_flow->protos.dhcp.class_ident
            );
            break;
        case NDPI_PROTOCOL_SSH:
            snprintf(nf->ssh.client_agent, ND_FLOW_SSH_UALEN,
                "%s", nf->ndpi_flow->protos.ssh.client_signature);
            snprintf(nf->ssh.server_agent, ND_FLOW_SSH_UALEN,
                "%s", nf->ndpi_flow->protos.ssh.server_signature);
            break;
        case NDPI_PROTOCOL_BITTORRENT:
            if (nf->ndpi_flow->protos.bittorrent.hash_valid) {
                nf->bt.info_hash_valid = true;
                memcpy(
                    nf->bt.info_hash,
                    nf->ndpi_flow->protos.bittorrent.hash,
                    ND_FLOW_BTIHASH_LEN
                );
            }
            break;
        }

        if (nf->ndpi_flow->http.url != NULL) {
            snprintf(
                nf->http.url, ND_FLOW_URL_LEN,
                "%s", nf->ndpi_flow->http.url
            );
        }

        if ((ndpi_proto == NDPI_PROTOCOL_DNS &&
            dhc != NULL && pkt != NULL && pkt_len > 12 &&
            ProcessDNSResponse(nf->host_server_name, pkt, pkt_len)) ||
            ndpi_proto == NDPI_PROTOCOL_MDNS) {

            // Rehash M/DNS flows:
            // This is done to uniquely track queries that originate from
            // the same local port.  Some devices re-use their local port
            // which would cause additional queries to not be processed.
            // Rehashing using the host_server_name as an additional key
            // guarantees that we see all DNS queries/responses.

            if (ndpi_proto == NDPI_PROTOCOL_DNS) {
                nf->hash(tag, false,
                    (const uint8_t *)nf->host_server_name,
                    strnlen(nf->host_server_name, ND_MAX_HOSTNAME));
            }
            else {
                nf->hash(tag, false,
                    (const uint8_t *)nf->mdns.answer,
                    strnlen(nf->mdns.answer, ND_FLOW_MDNS_ANSLEN));
            }

            flows->erase(fi.first);

            memcpy(nf->digest_mdata, nf->digest_lower,
                SHA1_DIGEST_LENGTH);
            flow_digest.assign((const char *)nf->digest_lower,
                SHA1_DIGEST_LENGTH);

            fi = flows->insert(nd_flow_pair(flow_digest, nf));

            if (! fi.second) {
                // Flow exists...  update stats and return.
                *fi.first->second += *nf;

                delete nf;

                return;
            }
        }

        if (ND_USE_FHC && nf->lower_port != 0 && nf->upper_port != 0) {
            if (! fhc->pop(flow_digest, flow_digest_mdata)) {

                nf->hash(tag, true);

                flow_digest_mdata.assign(
                    (const char *)nf->digest_mdata, SHA1_DIGEST_LENGTH
                );

                if (memcmp(nf->digest_lower, nf->digest_mdata,
                    SHA1_DIGEST_LENGTH))
                    fhc->push(flow_digest, flow_digest_mdata);
            }
            else {
                if (memcmp(nf->digest_mdata, flow_digest_mdata.c_str(),
                    SHA1_DIGEST_LENGTH)) {
#ifdef _ND_LOG_FHC
                    nd_debug_printf("%s: Resurrected flow metadata hash from cache.\n",
                        tag.c_str());
#endif
                    memcpy(nf->digest_mdata, flow_digest_mdata.c_str(),
                        SHA1_DIGEST_LENGTH);
                }
            }
        }
        else {
            nf->hash(tag, true);
            flow_digest_mdata.assign(
                (const char *)nf->digest_mdata, SHA1_DIGEST_LENGTH
            );
        }

        struct sockaddr_in *laddr4 = nf->lower_addr4;
        struct sockaddr_in6 *laddr6 = nf->lower_addr6;
        struct sockaddr_in *uaddr4 = nf->upper_addr4;
        struct sockaddr_in6 *uaddr6 = nf->upper_addr6;

        if (ND_PRIVATE_EXTADDR &&
            internal == false && pcap_datalink_type == DLT_EN10MB) {

            if (! memcmp(dev_mac, nf->lower_mac, ETH_ALEN)) {
                if (nf->ip_version == 4)
                    laddr4 = (struct sockaddr_in *)&private_addrs.first;
                else
                    laddr6 = (struct sockaddr_in6 *)&private_addrs.second;
            }
            else if (! memcmp(dev_mac, nf->upper_mac, ETH_ALEN)) {
                if (nf->ip_version == 4)
                    uaddr4 = (struct sockaddr_in *)&private_addrs.first;
                else
                    uaddr6 = (struct sockaddr_in6 *)&private_addrs.second;
            }
        }

        switch (nf->ip_version) {
        case 4:
            inet_ntop(AF_INET, &laddr4->sin_addr.s_addr,
                nf->lower_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &uaddr4->sin_addr.s_addr,
                nf->upper_ip, INET_ADDRSTRLEN);
            break;

        case 6:
            inet_ntop(AF_INET6, &laddr6->sin6_addr.s6_addr,
                nf->lower_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &uaddr6->sin6_addr.s6_addr,
                nf->upper_ip, INET6_ADDRSTRLEN);
            break;

        default:
            nd_printf("%s: ERROR: Unknown IP version: %d\n",
                tag.c_str(), nf->ip_version);
            throw ndDetectionThreadException(strerror(EINVAL));
        }

#ifdef _ND_USE_NETLINK
        if (device_addrs != NULL) {
            for (int t = ndFlow::TYPE_LOWER; t < ndFlow::TYPE_MAX; t++) {
                string ip;
                const uint8_t *umac = NULL;

                if (t == ndFlow::TYPE_LOWER &&
                    (nf->lower_type == ndNETLINK_ATYPE_LOCALIP ||
                     nf->lower_type == ndNETLINK_ATYPE_LOCALNET ||
                     nf->lower_type == ndNETLINK_ATYPE_PRIVATE)) {

                    umac = nf->lower_mac;
                    ip = nf->lower_ip;
                }
                else if (t == ndFlow::TYPE_UPPER &&
                    (nf->upper_type == ndNETLINK_ATYPE_LOCALIP ||
                     nf->upper_type == ndNETLINK_ATYPE_LOCALNET ||
                     nf->upper_type == ndNETLINK_ATYPE_PRIVATE)) {

                    umac = nf->upper_mac;
                    ip = nf->upper_ip;
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
        if (capture_unknown_flows &&
            nf->detected_protocol.master_protocol == NDPI_PROTOCOL_UNKNOWN) {
            nf->dump(pcap, flow.digest_lower);
        }

        nf->release();

#if defined(_ND_USE_CONNTRACK) && defined(_ND_USE_NETLINK)
        if (thread_conntrack != NULL) {
            if ((nf->lower_type == ndNETLINK_ATYPE_LOCALIP &&
                nf->upper_type == ndNETLINK_ATYPE_UNKNOWN) ||
                (nf->lower_type == ndNETLINK_ATYPE_UNKNOWN &&
                nf->upper_type == ndNETLINK_ATYPE_LOCALIP)) {

                thread_conntrack->ClassifyFlow(nf);
            }
        }
#endif
        for (vector<uint8_t *>::const_iterator i =
            nd_config.privacy_filter_mac.begin();
            i != nd_config.privacy_filter_mac.end() &&
                nf->privacy_mask !=
                (ndFlow::PRIVATE_LOWER | ndFlow::PRIVATE_UPPER); i++) {
            if (! memcmp((*i), nf->lower_mac, ETH_ALEN))
                nf->privacy_mask |= ndFlow::PRIVATE_LOWER;
            if (! memcmp((*i), nf->upper_mac, ETH_ALEN))
                nf->privacy_mask |= ndFlow::PRIVATE_UPPER;
        }

        for (vector<struct sockaddr *>::const_iterator i =
            nd_config.privacy_filter_host.begin();
            i != nd_config.privacy_filter_host.end() &&
                nf->privacy_mask !=
                (ndFlow::PRIVATE_LOWER | ndFlow::PRIVATE_UPPER); i++) {

            struct sockaddr_in *sa_in;
            struct sockaddr_in6 *sa_in6;

            switch ((*i)->sa_family) {
            case AF_INET:
                sa_in = reinterpret_cast<struct sockaddr_in *>((*i));
                if (! memcmp(&nf->lower_addr4, &sa_in->sin_addr,
                    sizeof(struct in_addr)))
                    nf->privacy_mask |= ndFlow::PRIVATE_LOWER;
                if (! memcmp(&nf->upper_addr4, &sa_in->sin_addr,
                    sizeof(struct in_addr)))
                    nf->privacy_mask |= ndFlow::PRIVATE_UPPER;
                break;
            case AF_INET6:
                sa_in6 = reinterpret_cast<struct sockaddr_in6 *>((*i));
                if (! memcmp(&nf->lower_addr6, &sa_in6->sin6_addr,
                    sizeof(struct in6_addr)))
                    nf->privacy_mask |= ndFlow::PRIVATE_LOWER;
                if (! memcmp(&nf->upper_addr6, &sa_in6->sin6_addr,
                    sizeof(struct in6_addr)))
                    nf->privacy_mask |= ndFlow::PRIVATE_UPPER;
                break;
            }
        }

        if (thread_socket && (ND_FLOW_DUMP_UNKNOWN ||
            nf->detected_protocol.master_protocol != NDPI_PROTOCOL_UNKNOWN)) {

            json j;

            j["type"] = "flow";
            j["interface"] = tag;
            j["internal"] = internal;
            j["established"] = false;

            json jf;
            nf->json_encode(jf, ndpi, false);
            j["flow"] = jf;

            string json_string;
            nd_json_to_string(j, json_string, false);
            json_string.append("\n");

            thread_socket->QueueWrite(json_string);
        }

        if (ND_DEBUG || nd_config.h_flow != stderr)
            nf->print(tag.c_str(), ndpi);
    }

    if (ts_last_idle_scan + ND_TTL_IDLE_SCAN < ts_pkt_last) {
        //uint64_t purged = 0;
        nd_flow_map::iterator i = flows->begin();
        while (i != flows->end()) {
            unsigned ttl = (
                i->second->ip_protocol != IPPROTO_TCP || i->second->tcp_fin
            ) ? nd_config.ttl_idle_flow : nd_config.ttl_idle_tcp_flow;

            if (i->second->ts_last_seen + ttl < ts_pkt_last) {

                delete i->second;
                i = flows->erase(i);
                //purged++;
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
