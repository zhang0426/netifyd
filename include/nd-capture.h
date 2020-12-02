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

#ifndef _ND_CAPTURE_THREAD_H
#define _ND_CAPTURE_THREAD_H

class ndSocketThread;

class ndCaptureThreadException : public runtime_error
{
public:
    explicit ndCaptureThreadException(const string &what_arg)
        : runtime_error(what_arg) { }
};

typedef pair<struct pcap_pkthdr *, const uint8_t *> nd_pkt_pair;
typedef queue<nd_pkt_pair> nd_pkt_queue;

class ndPacketQueue
{
public:
    ndPacketQueue(const string &tag);
    virtual ~ndPacketQueue();

    bool empty(void) { return pkt_queue.empty(); }
    size_t size(void) { return pkt_queue.size(); }

    size_t push(struct pcap_pkthdr *pkt_header, const uint8_t *pkt_data);
    bool front(struct pcap_pkthdr **pkt_header, const uint8_t **pkt_data);
    void pop(const string &oper = "pop");

protected:
    string tag;
    size_t pkt_queue_size;
    nd_pkt_queue pkt_queue;
};

class ndCaptureThread : public ndThread
{
public:
    ndCaptureThread(
        int16_t cpu,
        nd_ifaces::iterator iface,
        const uint8_t *dev_mac,
        ndSocketThread *thread_socket,
        const nd_detection_threads &threads_dpi,
        nd_flow_map *flow_map, nd_packet_stats *stats,
        nd_device_addrs *device_addrs = NULL,
        ndDNSHintCache *dhc = NULL,
        uint8_t private_addr = 0);
    virtual ~ndCaptureThread();

    virtual void *Entry(void);

    nd_flow_map *GetFlows(void) { return flows; }

    // XXX: Not thread-safe!
    int GetCaptureStats(struct pcap_stat &stats);

protected:
    nd_ifaces::iterator iface;
    uint8_t dev_mac[ETH_ALEN];
    ndSocketThread *thread_socket;
    bool capture_unknown_flows;
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
    nd_private_addr private_addrs;

    nd_flow_map *flows;
    nd_packet_stats *stats;
    nd_device_addrs *device_addrs;

    string flow_digest, flow_digest_mdata;

    ns_msg ns_h;
    ndDNSHintCache *dhc;

    ndPacketQueue pkt_queue;

    const nd_detection_threads &threads_dpi;
    int16_t dpi_thread_id;

    pcap_t *OpenCapture(void);
#if 0
    void DumpFlows(void);
#endif
    void ProcessPacket(void);

    bool ProcessDNSResponse(
        const char *host, const uint8_t *pkt, uint32_t length);
};

typedef map<string, ndCaptureThread *> nd_capture_threads;

#endif // _ND_CAPTURE_THREAD_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
