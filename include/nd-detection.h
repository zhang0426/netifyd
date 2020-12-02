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

#ifndef _ND_DETECTION_THREAD_H
#define _ND_DETECTION_THREAD_H

class ndSocketThread;

class ndDetectionThreadException : public runtime_error
{
public:
    explicit ndDetectionThreadException(const string &what_arg)
        : runtime_error(what_arg) { }
};

class ndDetectionQueueEntry
{
public:
    ndDetectionQueueEntry(ndFlow *flow, uint8_t *pkt_data, uint32_t pkt_length, int addr_cmp);
    virtual ~ndDetectionQueueEntry();

    ndFlow *flow;
    uint8_t *pkt_data;
    uint32_t pkt_length;
    int addr_cmp;
};

class ndDetectionThread : public ndThread
{
public:
    ndDetectionThread(
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
        ndDNSHintCache *dhc = NULL,
        uint8_t private_addr = 0);
    virtual ~ndDetectionThread();

    void QueuePacket(ndFlow *flow, uint8_t *pkt_data, uint32_t pkt_length, int addr_cmp);

    struct ndpi_detection_module_struct *GetDetectionModule(void) {
        return ndpi;
    }
    virtual void *Entry(void);

protected:
    bool internal;
#ifdef _ND_USE_NETLINK
    ndNetlink *netlink;
#endif
    ndSocketThread *thread_socket;
#ifdef _ND_USE_CONNTRACK
    ndConntrackThread *thread_conntrack;
#endif
    struct ndpi_detection_module_struct *ndpi;
    uint32_t custom_proto_base;
    nd_private_addr private_addrs;

    nd_devices &devices;

    ndDNSHintCache *dhc;
    ndFlowHashCache *fhc;

    string flow_digest, flow_digest_mdata;

    queue<ndDetectionQueueEntry *> pkt_queue;
    pthread_cond_t pkt_queue_cond;
    pthread_mutex_t pkt_queue_cond_mutex;

    unsigned flows;
#if 0
    void DumpFlows(void);
#endif
    void ProcessPacket(ndDetectionQueueEntry *entry);
};

typedef map<int16_t, ndDetectionThread *> nd_detection_threads;

#endif // _ND_DETECTION_THREAD_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
