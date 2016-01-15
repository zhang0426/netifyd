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

#include <string>
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <iostream>
#include <unordered_map>
#include <queue>
#include <sstream>

#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if_ether.h>

#include <curl/curl.h>
#include <zlib.h>

extern "C" {
#include "ndpi_api.h"
}

using namespace std;

#define _ND_INTERNAL    1

#include "netifyd.h"
#include "nd-util.h"
#include "nd-sha1.h"
#include "nd-thread.h"

extern bool nd_debug;
extern char *nd_uuid;
extern char *nd_url_upload;
extern int nd_account_id;
extern char *nd_account_key;
extern int nd_system_id;

static void *nd_thread_entry(void *param)
{
    void *rv = NULL;
    ndThread *thread = NULL;

    sigset_t signal_set;
    sigfillset(&signal_set);
    sigdelset(&signal_set, SIGPROF);

    try {
        if (pthread_sigmask(SIG_BLOCK, &signal_set, NULL) != 0)
            throw ndThreadException("pthread_sigmask");

        thread = reinterpret_cast<ndThread *>(param);
        thread->SetProcName();
        rv = thread->Entry();
    }
    catch (exception &e) {
        cerr << thread->GetTag() << ": Exception: " << e.what() << endl;
    }

    return rv;
}

static int nd_curl_debug(CURL *ch, curl_infotype type, char *data, size_t size, void *param)
{
    string buffer;
    if (nd_debug == false) return 0;

    ndThread *thread = reinterpret_cast<ndThread *>(param);

    switch (type) {
    case CURLINFO_TEXT:
        buffer.assign(data, size);
        nd_printf("%s: %s", thread->GetTag().c_str(), buffer.c_str());
        break;
    case CURLINFO_HEADER_IN:
        buffer.assign(data, size);
        nd_printf("%s: <-- %s", thread->GetTag().c_str(), buffer.c_str());
        break;
    case CURLINFO_HEADER_OUT:
        buffer.assign(data, size);
        nd_printf("%s: --> %s", thread->GetTag().c_str(), buffer.c_str());
        break;
    case CURLINFO_DATA_IN:
        nd_printf("%s: <-- %lu data bytes\n", thread->GetTag().c_str(), size);
        break;
    case CURLINFO_DATA_OUT:
        nd_printf("%s: --> %lu data bytes\n", thread->GetTag().c_str(), size);
        break;
    case CURLINFO_SSL_DATA_IN:
        nd_printf("%s: <-- %lu SSL bytes\n", thread->GetTag().c_str(), size);
        break;
    case CURLINFO_SSL_DATA_OUT:
        nd_printf("%s: --> %lu SSL bytes\n", thread->GetTag().c_str(), size);
        break;
    default:
        break;
    }

    return 0;
}

void ndFlow::hash(string &digest)
{
    sha1 ctx;
    uint8_t *_digest;

    sha1_init(&ctx);
    sha1_write(&ctx, (const char *)&vlan_id, sizeof(vlan_id));

    switch (version) {
    case 4:
        sha1_write(&ctx, (const char *)&lower_addr, sizeof(struct in_addr));
        sha1_write(&ctx, (const char *)&upper_addr, sizeof(struct in_addr));
        break;
    case 6:
        sha1_write(&ctx, (const char *)&lower_addr6, sizeof(struct in6_addr));
        sha1_write(&ctx, (const char *)&upper_addr6, sizeof(struct in6_addr));
        break;
    default:
        break;
    }

    sha1_write(&ctx, (const char *)&protocol, sizeof(protocol));
    sha1_write(&ctx, (const char *)&lower_port, sizeof(lower_port));
    sha1_write(&ctx, (const char *)&upper_port, sizeof(upper_port));

    _digest = sha1_result(&ctx);
    digest.assign((const char *)_digest, SHA1_DIGEST_LENGTH);
}

void ndFlow::print(const char *tag, struct ndpi_detection_module_struct *ndpi)
{
    char *p = NULL, buffer[64];

    if (detected_protocol.master_protocol) {
        ndpi_protocol2name(ndpi,
            detected_protocol, buffer, sizeof(buffer));
        p = buffer;
    }
    else
        p = ndpi_get_proto_name(ndpi, detected_protocol.protocol);

    nd_printf(
        "%s: %s%s: %s:%hu <-> %s:%hu [Host: %s] [SSL/C: %s] [SSL/S: %s]\n", tag, p,
        (detection_guessed &&
            detected_protocol.protocol != NDPI_PROTOCOL_UNKNOWN) ? " [GUESSED]" : "",
        lower_ip, ntohs(lower_port),
        upper_ip, ntohs(upper_port),
        (host_server_name[0] != '\0') ? host_server_name : "N/A",
        (ssl.client_cert[0] != '\0') ? ssl.client_cert : "N/A",
        (ssl.server_cert[0] != '\0') ? ssl.server_cert : "N/A"
    );
}

ndThread::ndThread(const string &tag, long cpu)
    : tag(tag), id(0), cpu(cpu), terminate(false)
{
    int rc;

    if ((rc = pthread_attr_init(&attr)) != 0)
        throw ndThreadException(strerror(rc));

    if ((rc = pthread_mutex_init(&lock, NULL)) != 0)
        throw ndThreadException(strerror(rc));

    if (cpu == -1) return;
#ifdef HAVE_PTHREAD_ATTR_SETAFFINITY_NP
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);

    if (cpu >= cpus) cpu = 0;

    cpu_set_t *cpuset = CPU_ALLOC(cpus);
    if (cpuset == NULL) return;

    size_t size = CPU_ALLOC_SIZE(cpus);

    CPU_ZERO_S(size, cpuset);
    CPU_SET_S(cpu, size, cpuset);

    rc = pthread_attr_setaffinity_np(
        &attr,
        CPU_COUNT_S(size, cpuset),
        cpuset
    );

    CPU_FREE(cpuset);
#endif
}

ndThread::~ndThread(void)
{
    pthread_attr_destroy(&attr);
    pthread_mutex_destroy(&lock);
}

void ndThread::SetProcName(void)
{
#ifdef HAVE_PTHREAD_SETNAME_NP
    char name[ND_THREAD_MAX_PROCNAMELEN];

    snprintf(name, ND_THREAD_MAX_PROCNAMELEN, "%s", tag.c_str());
    if (tag.length() >= ND_THREAD_MAX_PROCNAMELEN - 1)
        name[ND_THREAD_MAX_PROCNAMELEN - 2] = '+';

    pthread_setname_np(id, name);
#endif
}

void ndThread::Create(void)
{
    int rc;

    if (id != 0)
        throw ndThreadException("Thread previously created");
    if ((rc = pthread_create(&id, &attr,
        nd_thread_entry, static_cast<void *>(this))) != 0)
        throw ndThreadException(strerror(rc));
}

int ndThread::Join(void)
{
    int rc = -1;

    if (id == 0) {
        cerr << "Thread ID invalid." << endl;
        return rc;
    }

    rc = pthread_join(id, NULL);
    id = 0;

    return rc;
}

ndDetectionThread::ndDetectionThread(const string &dev,
    nd_flow_map *flow_map, ndDetectionStats *stats, long cpu)
    : ndThread(dev, cpu),
    pcap(NULL), pcap_snaplen(ND_PCAP_SNAPLEN), pcap_datalink_type(0),
    pkt_header(NULL), pkt_data(NULL),
    ts_pkt_last(0), ts_last_idle_scan(0),
    ndpi(NULL), flows(flow_map), stats(stats)
{
    memset(stats, 0, sizeof(struct ndDetectionStats));

    ndpi = ndpi_init_detection_module(
        ND_DETECTION_TICKS,
        nd_mem_alloc,
        nd_mem_free,
        nd_debug_printf
    );

    if (ndpi == NULL)
        throw ndThreadException("Detection module initialization failure");

    NDPI_PROTOCOL_BITMASK proto_all;
    NDPI_BITMASK_SET_ALL(proto_all);

    ndpi_set_protocol_detection_bitmask2(ndpi, &proto_all);
}

ndDetectionThread::~ndDetectionThread()
{
    Join();
    if (pcap != NULL) pcap_close(pcap);
}

void *ndDetectionThread::Entry(void)
{
    do {
        if (pcap == NULL) {
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
    flow.version = hdr_ip->version;

    if (flow.version == 4) {
        ip_len = ((uint16_t)hdr_ip->ihl * 4);
        l4_len = ntohs(hdr_ip->tot_len) - ip_len;
        flow.protocol = hdr_ip->protocol;
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
    else if (flow.version == 6) {
        hdr_ip6 = reinterpret_cast<const struct ip6_hdr *>(&pkt_data[ip_offset]);
        ip_len = sizeof(struct ip6_hdr);
        l4_len = ntohs(hdr_ip6->ip6_ctlun.ip6_un1.ip6_un1_plen);
        flow.protocol = hdr_ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
        layer3 = reinterpret_cast<const uint8_t *>(hdr_ip6);

        if (flow.protocol == IPPROTO_DSTOPTS) {
            const uint8_t *options = reinterpret_cast<const uint8_t *>(
                hdr_ip6 + sizeof(const struct ip6_hdr)
            );
            flow.protocol = options[0];
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

    switch (flow.protocol) {
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

    flow.hash(digest);

    ndFlow *new_flow = new ndFlow(flow);
    if (new_flow == NULL) throw ndThreadException(strerror(ENOMEM));

    nd_flow_insert rc = flows->insert(nd_flow_pair(digest, new_flow));

    if (rc.second) {
        new_flow->ndpi_flow = new ndpi_flow_struct;
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
    new_flow->packets++;
    new_flow->bytes += pkt_header->len;
    new_flow->ts_last_seen = ts_pkt;

    if (new_flow->detection_complete) return;

    new_flow->detected_protocol = ndpi_detection_process_packet(
        ndpi,
        new_flow->ndpi_flow,
        (new_flow->version == 4) ?
            (const uint8_t *)hdr_ip : (const uint8_t *)hdr_ip6,
        pkt_header->len - ip_offset,
        pkt_header->len,
        id_src,
        id_dst
    );

    if (new_flow->detected_protocol.protocol != NDPI_PROTOCOL_UNKNOWN
        || (new_flow->protocol == IPPROTO_UDP && new_flow->packets > 8)
        || (new_flow->protocol == IPPROTO_TCP && new_flow->packets > 10)) {

        new_flow->detection_complete = true;

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
                    new_flow->protocol,
                    ntohl(
                        (new_flow->version == 4) ?
                            new_flow->lower_addr.s_addr :
                                new_flow->lower_addr6.s6_addr32[2] +
                                new_flow->lower_addr6.s6_addr32[3]
                    ),
                    ntohs(new_flow->lower_port),
                    ntohl(
                        (new_flow->version == 4) ?
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
            new_flow->host_server_name, HOST_NAME_MAX,
            "%s", new_flow->ndpi_flow->host_server_name
        );

        if (new_flow->protocol == IPPROTO_TCP
            && new_flow->detected_protocol.protocol != NDPI_PROTOCOL_DNS) {
            snprintf(new_flow->ssl.client_cert, ND_SSL_CERTLEN,
                "%s", new_flow->ndpi_flow->protos.ssl.client_certificate);
            snprintf(new_flow->ssl.server_cert, ND_SSL_CERTLEN,
                "%s", new_flow->ndpi_flow->protos.ssl.server_certificate);
        }

        switch (new_flow->version) {
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

ndUploadThread::ndUploadThread()
    : ndThread("upload", -1), headers(NULL), headers_gz(NULL)
{
    int rc;

    if ((ch = curl_easy_init()) == NULL)
        throw ndThreadException("curl_easy_init");

    curl_easy_setopt(ch, CURLOPT_URL, nd_url_upload);
    curl_easy_setopt(ch, CURLOPT_POST, 1);
    curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(ch, CURLOPT_COOKIEFILE, (nd_debug) ? ND_COOKIE_JAR : "");

    if (nd_debug) {
        curl_easy_setopt(ch, CURLOPT_DEBUGFUNCTION, nd_curl_debug);
        curl_easy_setopt(ch, CURLOPT_DEBUGDATA, static_cast<void *>(this));
        curl_easy_setopt(ch, CURLOPT_VERBOSE, 1);
        curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(ch, CURLOPT_COOKIEJAR, ND_COOKIE_JAR);
    }

    ostringstream user_agent;
    user_agent << "User-Agent: " <<
        PACKAGE_NAME << "/" << PACKAGE_VERSION <<
        " (+" << PACKAGE_URL << ")";

    ostringstream uuid;
    uuid << "X-UUID: " << nd_uuid;

    ostringstream zone_uuid;
    account_id << "X-Zone-UUID: " << nd_zone_uuid;

    headers = curl_slist_append(headers, user_agent.str().c_str());
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, uuid.str().c_str());
    headers = curl_slist_append(headers, zone_uuid.str().c_str());

    headers_gz = curl_slist_append(headers_gz, user_agent.str().c_str());
    headers_gz = curl_slist_append(headers_gz, "Content-Type: application/json");
    headers_gz = curl_slist_append(headers_gz, "Content-Encoding: gzip");
    headers_gz = curl_slist_append(headers_gz, uuid.str().c_str());
    headers_gz = curl_slist_append(headers_gz, zone_uuid.str().c_str());

    pthread_condattr_t cond_attr;

    pthread_condattr_init(&cond_attr);
    pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
    if ((rc = pthread_cond_init(&uploads_cond, &cond_attr)) != 0)
        throw ndThreadException(strerror(rc));
    pthread_condattr_destroy(&cond_attr);

    if ((rc = pthread_mutex_init(&uploads_cond_mutex, NULL)) != 0)
        throw ndThreadException(strerror(rc));
}

ndUploadThread::~ndUploadThread()
{
    Join();
    if (ch != NULL) curl_easy_cleanup(ch);
    if (headers != NULL) curl_slist_free_all(headers);
    if (headers_gz != NULL) curl_slist_free_all(headers_gz);
}

void *ndUploadThread::Entry(void)
{
    int rc;

    nd_printf("%s: thread started.\n", tag.c_str());

    while (terminate == false) {
        if ((rc = pthread_mutex_lock(&lock)) != 0)
            throw ndThreadException(strerror(rc));

        if (uploads.size() == 0) {
            if ((rc = pthread_mutex_unlock(&lock)) != 0)
                throw ndThreadException(strerror(rc));

            if ((rc = pthread_mutex_lock(&uploads_cond_mutex)) != 0)
                throw ndThreadException(strerror(rc));
            if ((rc = pthread_cond_wait(&uploads_cond, &uploads_cond_mutex)) != 0)
                throw ndThreadException(strerror(rc));
            if ((rc = pthread_mutex_unlock(&uploads_cond_mutex)) != 0)
                throw ndThreadException(strerror(rc));

            continue;
        }

        if (uploads.back() == "terminate")
            terminate = true;
        else {
            do {
                pending.push(uploads.front());
                uploads.pop();
            }
            while (uploads.size() > 0);
        }

        if ((rc = pthread_mutex_unlock(&lock)) != 0)
            throw ndThreadException(strerror(rc));

        if (terminate == false && pending.size() > 0) Upload();
    }

    return NULL;
}

void ndUploadThread::Authenticate(void)
{
}

void ndUploadThread::QueuePush(const string &json)
{
    int rc;

    if ((rc = pthread_mutex_lock(&lock)) != 0)
        throw ndThreadException(strerror(rc));

    uploads.push(json);

    if ((rc = pthread_cond_broadcast(&uploads_cond)) != 0)
        throw ndThreadException(strerror(rc));
    if ((rc = pthread_mutex_unlock(&lock)) != 0)
        throw ndThreadException(strerror(rc));
}

void ndUploadThread::Upload(void)
{
    CURLcode rc;
    size_t xfer = 0, total = pending.size();

    do {
        if (nd_debug) nd_printf("%s: data %lu/%lu (%d bytes)...\n",
            tag.c_str(), ++xfer, total, pending.front().size());

        if (pending.front().size() <= ND_COMPRESS_SIZE) {
            curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(ch, CURLOPT_POSTFIELDSIZE, pending.front().size());
            curl_easy_setopt(ch, CURLOPT_POSTFIELDS, pending.front().data());
        }
        else {
            curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers_gz);
            Deflate(pending.front());
        }

        if ((rc = curl_easy_perform(ch)) != CURLE_OK)
            break;

        long http_rc = 0;
        if ((rc = curl_easy_getinfo(ch,
            CURLINFO_RESPONSE_CODE, &http_rc)) != CURLE_OK)
            break;

        switch (http_rc) {
        case 200:
            break;

        case 400:
            if (nd_debug) {
                FILE *hf = fopen("/tmp/rejected.json", "w");
                if (hf != NULL) {
                    fwrite(pending.front().data(), 1, pending.front().size(), hf);
                    fclose(hf);
                    nd_printf("Wrote rejected payload to: /tmp/rejected.json\n");
                }
            }
            break;

        default:
            return;
        }

        pending.pop();
    }
    while (pending.size() > 0);
}

void ndUploadThread::Deflate(const string &data)
{
    int rc;
    z_stream zs;
    string buffer;
    uint8_t chunk[ND_ZLIB_CHUNK_SIZE];

    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;
    zs.opaque = Z_NULL;

    if (deflateInit2(
        &zs,
        Z_DEFAULT_COMPRESSION,
        Z_DEFLATED, 15 /* window bits */ | 16 /* enable GZIP format */,
        8,
        Z_DEFAULT_STRATEGY
    ) != Z_OK) throw ndThreadException("deflateInit2");

    zs.next_in = (uint8_t *)data.data();
    zs.avail_in = data.size();

    do {
        zs.avail_out = ND_ZLIB_CHUNK_SIZE;
        zs.next_out = chunk;
        if ((rc = deflate(&zs, Z_FINISH)) == Z_STREAM_ERROR)
            throw ndThreadException("deflate");
        buffer.append((const char *)chunk, ND_ZLIB_CHUNK_SIZE - zs.avail_out);
    } while (zs.avail_out == 0);

    deflateEnd(&zs);

    if (rc != Z_STREAM_END)
        throw ndThreadException("deflate");

    curl_easy_setopt(ch, CURLOPT_POSTFIELDSIZE, buffer.size());
    curl_easy_setopt(ch, CURLOPT_COPYPOSTFIELDS, buffer.data());

    if (nd_debug) {
        nd_printf("%s: payload compressed: %lu -> %lu\n",
            tag.c_str(), data.size(), buffer.size());
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
