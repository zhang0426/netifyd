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
#include "nd-dhc.h"
#include "nd-fhc.h"
#include "nd-signal.h"
#include "nd-detection.h"
#include "nd-capture.h"

// Enable to log discarded packets
//#define _ND_LOG_PKT_DISCARD     1

// Enable DNS response debug logging
//#define _ND_LOG_DNS_RESPONSE    1

// Enable DNS hint cache debug logging
//#define _ND_LOG_DHC             1

// Enable flow hash cache debug logging
//#define _ND_LOG_FHC             1

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

struct __attribute__((packed)) nd_dns_header_t {
    uint16_t tr_id;
    uint16_t flags;
    uint16_t num_queries;
    uint16_t num_answers;
    uint16_t authority_rrs;
    uint16_t additional_rrs;
};

ndPacketQueue::ndPacketQueue(const string &tag) : pkt_queue_size(0)
{
    nd_iface_name(tag, this->tag);
}

ndPacketQueue::~ndPacketQueue()
{
    while (! pkt_queue.empty()) {
        delete pkt_queue.front().first;
        delete [] pkt_queue.front().second;
        pkt_queue.pop();
    }
}

size_t ndPacketQueue::push(struct pcap_pkthdr *pkt_header, const uint8_t *pkt_data)
{
    size_t dropped = 0;

    struct pcap_pkthdr *ph = new struct pcap_pkthdr;
    if (ph == NULL) throw ndCaptureThreadException(strerror(ENOMEM));
    memcpy(ph, pkt_header, sizeof(struct pcap_pkthdr));

    uint8_t *pd = new uint8_t[pkt_header->caplen];
    if (pd == NULL) throw ndCaptureThreadException(strerror(ENOMEM));
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

ndCaptureThread::ndCaptureThread(
    int16_t cpu,
    nd_ifaces::iterator iface,
    const uint8_t *dev_mac,
    ndSocketThread *thread_socket,
    const nd_detection_threads &threads_dpi,
    nd_flow_map *flow_map, nd_packet_stats *stats,
    ndDNSHintCache *dhc,
    uint8_t private_addr)
    : ndThread(iface->second, (long)cpu, true),
    iface(iface), thread_socket(thread_socket),
    capture_unknown_flows(ND_CAPTURE_UNKNOWN_FLOWS),
    pcap(NULL), pcap_fd(-1), pcap_snaplen(ND_PCAP_SNAPLEN),
    pcap_datalink_type(0), pkt_header(NULL), pkt_data(NULL),
    ts_pkt_last(0),
    flows(flow_map), stats(stats), dhc(dhc),
    pkt_queue(iface->second),
    threads_dpi(threads_dpi), dpi_thread_id(rand() % threads_dpi.size())
{
    memset(stats, 0, sizeof(nd_packet_stats));

    nd_iface_name(iface->second, tag);
    nd_capture_filename(iface->second, pcap_file);
    if (pcap_file.size())
        nd_debug_printf("%s: capture file: %s\n", tag.c_str(), pcap_file.c_str());

    private_addrs.first.ss_family = AF_INET;
    nd_private_ipaddr(private_addr, private_addrs.first);

    private_addrs.second.ss_family = AF_INET6;
    nd_private_ipaddr(private_addr, private_addrs.second);

    memcpy(this->dev_mac, dev_mac, ETH_ALEN);
    nd_debug_printf(
        "%s: hwaddr: %02hhx:%02hhx:%02hhx:%02hhx:%02hx:%02hhx\n",
        tag.c_str(),
        dev_mac[0], dev_mac[1], dev_mac[2],
        dev_mac[3], dev_mac[4], dev_mac[5]
    );

    nd_debug_printf("%s: capture thread created.\n", tag.c_str());
}

ndCaptureThread::~ndCaptureThread()
{
    Join();

    if (pcap != NULL) pcap_close(pcap);

    nd_debug_printf("%s: capture thread destroyed.\n", tag.c_str());
}

void *ndCaptureThread::Entry(void)
{
    bool dump_flows = false;

    struct ifreq ifr;

    do {
        if (pcap == NULL && ! terminate) {
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

        if (! terminate) {
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
                    throw ndCaptureThreadException(strerror(errno));

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

                    if (from_queue) pkt_queue.pop();
                }
                break;
            case -1:
                nd_printf("%s: %s.\n", tag.c_str(), pcap_geterr(pcap));
                pcap_close(pcap);
                pcap = NULL;
                pcap_fd = -1;
                break;
            case -2:
                nd_debug_printf(
                    "%s: end of capture file: %s, flushing queued packets: %lu\n",
                    tag.c_str(), pcap_file.c_str(), pkt_queue.size());
                pcap_close(pcap);
                pcap = NULL;
                terminate = true;
                pcap_fd = -1;
                break;
            }
        }
    }
    while (terminate == false || ! pkt_queue.empty());

    nd_debug_printf(
        "%s: capture ended on CPU: %lu\n", tag.c_str(), cpu >= 0 ? cpu : 0);
#if 0
    nd_flow_map::iterator i = flows->begin();

    while (i != flows->end()) {

        if (thread_socket && (ND_FLOW_DUMP_UNKNOWN ||
            i->second->detected_protocol.master_protocol > 0)) {

            json j;

            j["type"] = "flow_purge";
            j["reason"] = "terminate";
            j["interface"] = tag;
            j["internal"] = iface->first;
            j["established"] = false;

            json jf;
            i->second->json_encode(jf, ndFlow::ENCODE_STATS | ndFlow::ENCODE_TUNNELS);
            j["flow"] = jf;

            string json_string;
            nd_json_to_string(j, json_string, false);
            json_string.append("\n");

            thread_socket->QueueWrite(json_string);
        }

        i++;
    }
#endif
    return NULL;
}

pcap_t *ndCaptureThread::OpenCapture(void)
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

        nd_device_filter::const_iterator i = nd_config.device_filters.find(tag);

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
void ndCaptureThread::DumpFlows(void)
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
        j["interface"] = tag;
        j["internal"] = iface->first;
        j["established"] = true;

        json jf;
        i->second->json_encode(jf, ndFlow::ENCODE_METADATA);

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
int ndCaptureThread::GetCaptureStats(struct pcap_stat &stats)
{
    memset(&stats, 0, sizeof(struct pcap_stat));

    if (pcap_file.size() || pcap == NULL) return 1;

    return pcap_stats(pcap, &stats);
}

void ndCaptureThread::ProcessPacket(void)
{
    nd_flow_insert fi;
    ndFlow *nf, flow(iface);

    const struct ether_header *hdr_eth = NULL;
    const struct sll_header *hdr_sll = NULL;
    const struct ip *hdr_ip = NULL;
    const struct ip6_hdr *hdr_ip6 = NULL;
    const struct tcphdr *hdr_tcp = NULL;
    const struct udphdr *hdr_udp = NULL;
#ifdef _ND_DISSECT_GTP
    const struct nd_gtpv1_header_t *hdr_gtpv1 = NULL;
    const struct nd_gtpv2_header_t *hdr_gtpv2 = NULL;
#endif
    const uint8_t *l3 = NULL, *l4 = NULL, *pkt = NULL;
    uint16_t l2_len, l3_len, l4_len = 0, pkt_len = 0;
    uint16_t type = 0;
    uint16_t ppp_proto;
    uint16_t frag_off = 0;
    uint8_t vlan_packet = 0;
    int addr_cmp = 0;

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
        switch (ntohl(*((uint32_t *)pkt_data))) {
        case 2:
            type = ETHERTYPE_IP;
            break;
        case 24:
        case 28:
        case 30:
            type = ETHERTYPE_IPV6;
            break;
        default:
#ifdef _ND_LOG_PKT_DISCARD
        stats->pkt.discard++;
        stats->pkt.discard_bytes += pkt_header->caplen;
        nd_debug_printf("%s: discard: Unsupported BSD loopback encapsulation type: %lu\n",
            tag.c_str(), ntohl(*((uint32_t *)pkt_data)));
#endif
            return;
        }

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
    case DLT_IPV4:
    case DLT_IPV6:
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

nd_process_ip:
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
#if _ND_DISSECT_GTP
    if (l4_len > 8 && flow.ip_protocol == IPPROTO_UDP) {
        hdr_udp = reinterpret_cast<const struct udphdr *>(l4);

        if (ntohs(hdr_udp->uh_sport) == _ND_GTP_U_PORT ||
            ntohs(hdr_udp->uh_dport) == _ND_GTP_U_PORT) {

            hdr_gtpv1 = reinterpret_cast<const struct nd_gtpv1_header_t *>(
                l4 + sizeof(struct udphdr)
            );

            if (hdr_gtpv1->flags.version == 1) {

                if (flow.tunnel_type == ndFlow::TUNNEL_NONE) {
                    flow.tunnel_type = ndFlow::TUNNEL_GTP;

                    flow.gtp.version = hdr_gtpv1->flags.version;
                    memcpy(&flow.gtp.lower_addr,
                        &flow.lower_addr, sizeof(struct sockaddr_storage));
                    memcpy(&flow.gtp.upper_addr,
                        &flow.upper_addr, sizeof(struct sockaddr_storage));

                    struct sockaddr_in *laddr4 = flow.lower_addr4;
                    struct sockaddr_in6 *laddr6 = flow.lower_addr6;
                    struct sockaddr_in *uaddr4 = flow.upper_addr4;
                    struct sockaddr_in6 *uaddr6 = flow.upper_addr6;

                    flow.gtp.ip_version = flow.ip_version;

                    switch (flow.ip_version) {
                    case 4:
                        inet_ntop(AF_INET, &laddr4->sin_addr.s_addr,
                            flow.gtp.lower_ip, INET_ADDRSTRLEN);
                        inet_ntop(AF_INET, &uaddr4->sin_addr.s_addr,
                            flow.gtp.upper_ip, INET_ADDRSTRLEN);
                        break;

                    case 6:
                        inet_ntop(AF_INET6, &laddr6->sin6_addr.s6_addr,
                            flow.gtp.lower_ip, INET6_ADDRSTRLEN);
                        inet_ntop(AF_INET6, &uaddr6->sin6_addr.s6_addr,
                            flow.gtp.upper_ip, INET6_ADDRSTRLEN);
                        break;

                    default:
                        nd_printf("%s: ERROR: Unknown GTP IP version: %d\n",
                            tag.c_str(), flow.ip_version);
                        throw ndCaptureThreadException(strerror(EINVAL));
                    }

                    if (addr_cmp < 0) {
                        flow.gtp.lower_port = hdr_udp->uh_sport;
                        flow.gtp.upper_port = hdr_udp->uh_dport;
                    }
                    else if (addr_cmp > 0) {
                        flow.gtp.lower_port = hdr_udp->uh_dport;
                        flow.gtp.upper_port = hdr_udp->uh_sport;
                    }
                    else {
                        if (hdr_udp->uh_sport < hdr_udp->uh_dport) {
                            flow.gtp.lower_port = hdr_udp->uh_sport;
                            flow.gtp.upper_port = hdr_udp->uh_dport;
                        }
                        else {
                            flow.gtp.lower_port = hdr_udp->uh_dport;
                            flow.gtp.upper_port = hdr_udp->uh_sport;
                        }
                    }
                }

                if (hdr_gtpv1->type == _ND_GTP_G_PDU) {

                    l2_len = (l4 - pkt_data) + sizeof(struct udphdr) + 8;

                    if (hdr_gtpv1->flags.ext_hdr) l2_len += 1;
                    if (hdr_gtpv1->flags.seq_num) l2_len += 4;
                    if (hdr_gtpv1->flags.npdu_num) l2_len += 1;

                    goto nd_process_ip;
                }
#if 0
                else {
                    nd_debug_printf("%s: unsupported GTPv1 message type: 0x%hhx (%hhu)\n",
                        tag.c_str(), hdr_gtpv1->type, hdr_gtpv1->type);
                }
#endif
            }
            else if (hdr_gtpv1->flags.version == 2) {
                // TODO: GTPv2...
                hdr_gtpv2 = reinterpret_cast<const struct nd_gtpv2_header_t *>(
                    l4 + sizeof(struct udphdr)
                );
                nd_debug_printf("%s: unimplemented GTP version (TODO): %u\n",
                    tag.c_str(), hdr_gtpv1->flags.version);
            }
            else {
                nd_debug_printf("%s: unsupported GTP version: %u\n",
                    tag.c_str(), hdr_gtpv1->flags.version);
            }
        }
    }
#endif
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

        if (addr_cmp != nf->direction) {
#if _ND_DISSECT_GTP
            if (hdr_gtpv1 != NULL && hdr_gtpv1->flags.version == 1) {
                if (nf->tunnel_type == ndFlow::TUNNEL_GTP) {
                    switch (nf->origin) {
                    case ndFlow::ORIGIN_LOWER:
                        if (nf->gtp.upper_teid == 0)
                            nf->gtp.upper_teid = hdr_gtpv1->teid;
                        else if (hdr_gtpv1->teid != nf->gtp.upper_teid)
                            nf->gtp.upper_teid = hdr_gtpv1->teid;
                        break;
                    case ndFlow::ORIGIN_UPPER:
                        if (nf->gtp.lower_teid == 0)
                            nf->gtp.lower_teid = hdr_gtpv1->teid;
                        else if (hdr_gtpv1->teid != nf->gtp.lower_teid)
                            nf->gtp.lower_teid = hdr_gtpv1->teid;
                        break;
                    }
                }
            }
            else if (hdr_gtpv2 != NULL && hdr_gtpv2->flags.version == 2) {
                // TODO: Implemented GTPv2.
            }
#endif
        }
    }
    else {
        nf = new ndFlow(flow);
        if (nf == NULL) throw ndCaptureThreadException(strerror(ENOMEM));

        nf->direction = addr_cmp;

        fi = flows->insert(nd_flow_pair(flow_digest, nf));

        if (! fi.second) {
            // Flow exists in map!  Impossible!
            throw ndCaptureThreadException(strerror(EINVAL));
        }

        // New flow inserted, initialize...
        nf->ts_first_seen = ts_pkt;

        // Set initial flow origin:
        // XXX: A 50-50 guess based on which side we saw first.
        if (addr_cmp < 0)
            nf->origin = ndFlow::ORIGIN_LOWER;
        else
            nf->origin = ndFlow::ORIGIN_UPPER;

        // Try to refine flow origin for TCP flows using SYN/ACK flags
        if (nf->ip_protocol == IPPROTO_TCP) {

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

        if (nf->tunnel_type == ndFlow::TUNNEL_GTP) {
            switch (nf->origin) {
            case ndFlow::ORIGIN_LOWER:
                nf->gtp.lower_teid = hdr_gtpv1->teid;
                break;
            case ndFlow::ORIGIN_UPPER:
                nf->gtp.upper_teid = hdr_gtpv1->teid;
                break;
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
        nf->flags.tcp_fin = true;

    if (dhc != NULL && pkt != NULL && pkt_len > sizeof(struct nd_dns_header_t)) {
        uint16_t lport = ntohs(nf->lower_port), uport = ntohs(nf->upper_port);

        if (lport == 53 || uport == 53 || lport == 5355 || uport == 5355) {

            const char *host = NULL;
            bool is_query = ProcessDNSPacket(&host, pkt, pkt_len);
#if 0
            if (is_query) {
                // Rehash M/DNS flows:
                // This is done to uniquely track queries that originate from
                // the same local port.  Some devices re-use their local port
                // which would cause additional queries to not be processed.
                // Rehashing using the host_server_name as an additional key
                // guarantees that we see all DNS queries/responses.

//                if (ndpi_proto == NDPI_PROTOCOL_DNS) {
                    nf->hash(tag, false,
                        (const uint8_t *)host,
                        strnlen(host, ND_MAX_HOSTNAME));
//                }
//                else {
//                    nf->hash(tag, false,
//                        (const uint8_t *)nf->mdns.answer,
//                        strnlen(nf->mdns.answer, ND_FLOW_MDNS_ANSLEN));
//                }

                if (memcmp(nf->digest_mdata, nf->digest_lower, SHA1_DIGEST_LENGTH)) {
                    flows->erase(fi.first);

                    memcpy(nf->digest_mdata, nf->digest_lower,
                        SHA1_DIGEST_LENGTH);
                    flow_digest.assign((const char *)nf->digest_lower,
                        SHA1_DIGEST_LENGTH);

                    fi = flows->insert(nd_flow_pair(flow_digest, nf));

                if (! fi.second) {
                    // Flow exists...  update stats and return.
                    *fi.first->second += *nf;

                    nd_debug_printf("%s: delete rehashed DNS flow: %lu packets, detection complete: %s\n",
                        tag.c_str(), nf->total_packets, (nf->flags.detection_complete) ? "yes" : "no");
                    delete nf;

                    return;
                }
            }
#endif
        }
    }

//    if (! nf->flags.detection_complete
//        || (nf->ip_protocol == IPPROTO_UDP &&
//            nf->total_packets <= nd_config.max_udp_pkts)
//        || (nf->ip_protocol == IPPROTO_TCP &&
//            nf->total_packets <= nd_config.max_tcp_pkts)) {
    if (! nf->flags.detection_complete) {

        if (nf->dpi_thread_id < 0) {
            nf->dpi_thread_id = dpi_thread_id;
            if (++dpi_thread_id == (int16_t)threads_dpi.size()) dpi_thread_id = 0;
        }

        nd_detection_threads::const_iterator idpi = threads_dpi.find(nf->dpi_thread_id);

        if (idpi != threads_dpi.end()) {
            idpi->second->QueuePacket(
                nf,
                (nf->ip_version == 4) ?
                    (uint8_t *)hdr_ip : (uint8_t *)hdr_ip6,
                pkt_header->caplen - l2_len, addr_cmp
            );
        }
        else {
            nd_debug_printf("ERROR: CPU thread ID not found: %hd\n", nf->dpi_thread_id);
            throw ndCaptureThreadException("CPU thread ID not found!");
        }
    }

    if (capture_unknown_flows) nf->push(pkt_header, pkt_data);
}

bool ndCaptureThread::ProcessDNSPacket(const char **host, const uint8_t *pkt, uint32_t length)
{
    ns_rr rr;
    int rc = ns_initparse(pkt, length, &ns_h);

    *host = NULL;

    if (rc < 0) {
#ifdef _ND_LOG_DHC
        nd_debug_printf(
            "%s: dns initparse error: %s, length: %hu\n",
            tag.c_str(), strerror(errno), length);
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

#ifdef _ND_LOG_DHC
    nd_debug_printf(
        "%s: type: %d, dns queries: %hu, answers: %hu\n",
        tag.c_str(), ns_msg_getflag(ns_h, ns_f_qr),
        ns_msg_count(ns_h, ns_s_qd), ns_msg_count(ns_h, ns_s_an));
#endif

    for (uint16_t i = 0; i < ns_msg_count(ns_h, ns_s_qd); i++) {
        if (ns_parserr(&ns_h, ns_s_qd, i, &rr)) {
#ifdef _ND_LOG_DHC
            nd_debug_printf(
                "%s: dns error parsing QD RR %hu of %hu.\n", tag.c_str(),
                i + 1, ns_msg_count(ns_h, ns_s_qd));
#endif
            continue;
        }

#ifdef _ND_LOG_DHC
        if (ns_rr_type(rr) != ns_t_a && ns_rr_type(rr) != ns_t_aaaa) {
            nd_debug_printf("%s: Skipping QD RR type: %d\n",
                tag.c_str(), ns_rr_type(rr));
            continue;
        }
#endif
#ifdef _ND_LOG_DHC
        nd_debug_printf("%s: QD RR type: %d, name: %s\n",
            tag.c_str(), ns_rr_type(rr), ns_rr_name(rr));
#endif
        *host = ns_rr_name(rr);
        break;
    }

    // Is query?
    if (*host != NULL && ns_msg_getflag(ns_h, ns_f_qr) == 0)
        return true;

    // If host wasn't found or this isn't a response, return.
    if (*host == NULL || ns_msg_getflag(ns_h, ns_f_qr) != 1)
        return false;

    // Add responses to DHC...
    for (uint16_t i = 0; i < ns_msg_count(ns_h, ns_s_an); i++) {
        if (ns_parserr(&ns_h, ns_s_an, i, &rr)) {
#ifdef _ND_LOG_DHC
            nd_debug_printf(
                "%s: dns error parsing AN RR %hu of %hu.\n", tag.c_str(),
                i + 1, ns_msg_count(ns_h, ns_s_an));
#endif
            continue;
        }
#ifdef _ND_LOG_DHC
        nd_debug_printf("%s: AN RR type: %d\n", tag.c_str(), ns_rr_type(rr));
#endif
        if (ns_rr_type(rr) != ns_t_a && ns_rr_type(rr) != ns_t_aaaa)
            continue;

        dhc->insert(
            (ns_rr_type(rr) == ns_t_a) ? AF_INET : AF_INET6,
            ns_rr_rdata(rr), *host
        );
#ifdef _ND_LOG_DHC
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
            tag.c_str(), *host,
            (ns_rr_type(rr) == ns_t_a) ? "A" : "AAAA",
            ns_rr_ttl(rr), ns_rr_rdlen(rr), addr);
#endif // _ND_LOG_DHC
    }

    return false;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
