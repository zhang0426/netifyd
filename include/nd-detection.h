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

#ifndef _ND_DETECTION_THREAD_H
#define _ND_DETECTION_THREAD_H

class ndDetectionThread : public ndThread
{
public:
    ndDetectionThread(const string &dev, ndNetlink *netlink,
        nd_flow_map *flow_map, ndDetectionStats *stats, long cpu = -1);
    virtual ~ndDetectionThread();

    struct ndpi_detection_module_struct *GetDetectionModule(void) {
        return ndpi;
    }
    virtual void *Entry(void);

protected:
    ndNetlink *netlink;
    pcap_t *pcap;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    int pcap_snaplen;
    int pcap_datalink_type;
    struct pcap_pkthdr *pkt_header;
    const uint8_t *pkt_data;
    uint64_t ts_pkt_last;
    uint64_t ts_last_idle_scan;
    struct ndpi_detection_module_struct *ndpi;

    nd_flow_map *flows;
    ndDetectionStats *stats;

    void ProcessPacket(void);
};

#endif // _ND_DETECTION_THREAD_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
