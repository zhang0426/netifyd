// Netify Agent
// Copyright (C) 2015-2019 eGloo Incorporated <http://www.egloo.ca>
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

#ifndef _ND_DETECTION_THREAD_H
#define _ND_DETECTION_THREAD_H

class ndSocketThread;

class ndDetectionThreadException : public runtime_error
{
public:
    explicit ndDetectionThreadException(const string &what_arg)
        : runtime_error(what_arg) { }
};

typedef pair<struct pcap_pkthdr *, const uint8_t *> nd_pkt_pair;
typedef queue<nd_pkt_pair> nd_pkt_queue;

class ndPacketQueue
{
public:
    ndPacketQueue(const string &tag) : tag(tag), pkt_queue_size(0) { }
    virtual ~ndPacketQueue() {
        while (! pkt_queue.empty()) {
            delete pkt_queue.front().first;
            delete [] pkt_queue.front().second;
            pkt_queue.pop();
        }
    }

    bool empty(void) { return pkt_queue.empty(); }

    size_t push(struct pcap_pkthdr *pkt_header, const uint8_t *pkt_data);
    bool front(struct pcap_pkthdr **pkt_header, const uint8_t **pkt_data);
    void pop(const string &oper = "pop");

protected:
    string tag;
    size_t pkt_queue_size;
    nd_pkt_queue pkt_queue;
};

class ndDetectionThread : public ndThread
{
public:
    ndDetectionThread(
        const string &dev,
        bool internal,
#ifdef _ND_USE_NETLINK
        const string &netlink_dev,
        ndNetlink *netlink,
#endif
        ndSocketThread *thread_socket,
#ifdef _ND_USE_CONNTRACK
        ndConntrackThread *thread_conntrack,
#endif
        nd_flow_map *flow_map, nd_packet_stats *stats,
        nd_device_addrs *device_addrs = NULL,
        ndDNSHintCache *dhc = NULL,
        uint8_t private_addr = 0,
        long cpu = -1);
    virtual ~ndDetectionThread();

    struct ndpi_detection_module_struct *GetDetectionModule(void) {
        return ndpi;
    }
    virtual void *Entry(void);

    nd_flow_map *GetFlows(void) { return flows; }

    // XXX: Not thread-safe!
    int GetCaptureStats(struct pcap_stat &stats);

protected:
    bool internal;
    bool capture_unknown_flows;
#ifdef _ND_USE_NETLINK
    string netlink_dev;
    ndNetlink *netlink;
#endif
    ndSocketThread *thread_socket;
#ifdef _ND_USE_CONNTRACK
    ndConntrackThread *thread_conntrack;
#endif
    pcap_t *pcap;
    int pcap_fd;
    string pcap_file;
    struct bpf_program pcap_filter;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    int pcap_snaplen;
    int pcap_datalink_type;
    struct pcap_pkthdr *pkt_header;
    const uint8_t *pkt_data;
    uint64_t ts_pkt_last;
    uint64_t ts_last_idle_scan;
    struct ndpi_detection_module_struct *ndpi;
    uint32_t custom_proto_base;
    nd_private_addr private_addrs;
    uint8_t dev_mac[ETH_ALEN];

    nd_flow_map *flows;
    nd_packet_stats *stats;
    nd_device_addrs *device_addrs;
    ns_msg ns_h;

    ndDNSHintCache *dhc;

    ndFlowHashCache *fhc;
    string flow_digest, flow_digest_mdata;

    ndPacketQueue pkt_queue;

    pcap_t *OpenCapture(void);

    void ProcessPacket(void);

    bool ProcessDNSResponse(
        const char *host, const uint8_t *pkt, uint16_t length);
};

typedef map<string, ndDetectionThread *> nd_threads;

#endif // _ND_DETECTION_THREAD_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
