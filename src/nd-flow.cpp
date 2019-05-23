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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdexcept>
#include <cstring>
#include <map>
#include <list>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <regex>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <errno.h>

#include <arpa/inet.h>

#ifdef _ND_USE_NETLINK
#include <linux/netlink.h>
#endif

#include <json.h>
#include <pcap/pcap.h>

using namespace std;

#include "netifyd.h"

#include "nd-ndpi.h"
#ifdef _ND_USE_NETLINK
#include "nd-netlink.h"
#endif
#include "nd-json.h"
#include "nd-util.h"

// Enable flow hash cache debug logging
//#define _ND_DEBUG_FHC 1

#include "nd-flow.h"

extern nd_global_config nd_config;
extern nd_device_ethers device_ethers;

ndFlowHashCache::ndFlowHashCache(const string &device, size_t cache_size)
    : device(device), cache_size(cache_size) { }

void ndFlowHashCache::push(const string &lower_hash, const string &upper_hash)
{
    nd_fhc_map::const_iterator i = lookup.find(lower_hash);

    if (i != lookup.end()) {
        nd_debug_printf("%s: WARNING: Found existing hash in flow hash cache on push.\n",
            device.c_str());
    }
    else {
        if (lookup.size() == cache_size) {
//#if _ND_DEBUG_FHC
            nd_debug_printf("%s: Purging old flow hash cache entries.\n", device.c_str());
//#endif
            for (size_t n = 0; n < cache_size / nd_config.fhc_purge_divisor; n++) {
                pair<string, string> j = index.back();

                nd_fhc_map::iterator k = lookup.find(j.first);
                if (k == lookup.end()) {
                    nd_debug_printf("%s: WARNING: flow hash cache index not found in map\n",
                        device.c_str());
                }
                else
                    lookup.erase(k);

                index.pop_back();
            }
        }

        index.push_front(make_pair(lower_hash, upper_hash));
        lookup[lower_hash] = index.begin();
#if _ND_DEBUG_FHC
        nd_debug_printf("%s: Flow hash cache entries: %lu\n", device.c_str(), lookup.size());
#endif
    }
}

bool ndFlowHashCache::pop(const string &lower_hash, string &upper_hash)
{
    nd_fhc_map::iterator i = lookup.find(lower_hash);
    if (i == lookup.end()) return false;

    upper_hash = i->second->second;

    index.erase(i->second);

    index.push_front(make_pair(lower_hash, upper_hash));

    i->second = index.begin();

    return true;
}

void ndFlowHashCache::save(void)
{
    ostringstream os;

    switch (nd_config.fhc_save) {
    case ndFHC_PERSISTENT:
        os << ND_PERSISTENT_STATEDIR << ND_FLOW_HC_FILE_NAME << device << ".dat";
        break;
    case ndFHC_VOLATILE:
        os << ND_VOLATILE_STATEDIR << ND_FLOW_HC_FILE_NAME << device << ".dat";
        break;
    default:
        return;
    }

    FILE *hf = fopen(os.str().c_str(), "wb");
    if (hf == NULL) {
        nd_printf("%s: WARNING: Error saving flow hash cache: %s: %s\n",
            device.c_str(), os.str().c_str(), strerror(errno));
        return;
    }

    nd_fhc_list::iterator i;
    for (i = index.begin(); i != index.end(); i++) {
        fwrite((*i).first.c_str(), 1, SHA1_DIGEST_LENGTH, hf);
        fwrite((*i).second.c_str(), 1, SHA1_DIGEST_LENGTH, hf);
    }
    fclose(hf);

    nd_debug_printf("%s: Saved %lu flow hash cache entries.\n",
        device.c_str(), index.size ());
}

void ndFlowHashCache::load(void)
{
    ostringstream os;

    switch (nd_config.fhc_save) {
    case ndFHC_PERSISTENT:
        os << ND_PERSISTENT_STATEDIR << ND_FLOW_HC_FILE_NAME << device << ".dat";
        break;
    case ndFHC_VOLATILE:
        os << ND_VOLATILE_STATEDIR << ND_FLOW_HC_FILE_NAME << device << ".dat";
        break;
    default:
        return;
    }

    FILE *hf = fopen(os.str().c_str(), "rb");
    if (hf != NULL) {
        do {
            string digest_lower, digest_mdata;
            uint8_t digest[SHA1_DIGEST_LENGTH * 2];

            if (fread(digest, SHA1_DIGEST_LENGTH * 2, 1, hf) != 1) break;

            digest_lower.assign((const char *)digest, SHA1_DIGEST_LENGTH);
            digest_mdata.assign((const char *)&digest[SHA1_DIGEST_LENGTH],
                SHA1_DIGEST_LENGTH);

            push(digest_lower, digest_mdata);
        }
        while (! feof(hf));

        fclose(hf);
    }

    nd_debug_printf("%s: Loaded %lu flow hash cache entries.\n",
        device.c_str(), index.size());
}

ndFlow::ndFlow(bool internal)
    : internal(internal), ip_version(0), ip_protocol(0), vlan_id(0),
    ip_nat(false), tcp_fin(false),
    ts_first_seen(0), ts_first_update(0), ts_last_seen(0),
    lower_port(0), upper_port(0),
    lower_bytes(0), upper_bytes(0), total_bytes(0),
    lower_packets(0), upper_packets(0), total_packets(0),
    detection_complete(false), detection_guessed(0),
    ndpi_flow(NULL), id_src(NULL), id_dst(NULL),
    privacy_mask(0), origin(0)
{
    memset(lower_mac, 0, ETH_ALEN);
    memset(upper_mac, 0, ETH_ALEN);

    memset(&lower_addr, 0, sizeof(struct sockaddr_storage));
    memset(&upper_addr, 0, sizeof(struct sockaddr_storage));

    lower_addr4 = (struct sockaddr_in *)&lower_addr;
    lower_addr6 = (struct sockaddr_in6 *)&lower_addr;
    upper_addr4 = (struct sockaddr_in *)&upper_addr;
    upper_addr6 = (struct sockaddr_in6 *)&upper_addr;

    memset(lower_ip, 0, INET6_ADDRSTRLEN);
    memset(upper_ip, 0, INET6_ADDRSTRLEN);

    memset(&detected_protocol, 0, sizeof(ndpi_protocol));

    memset(digest_lower, 0, SHA1_DIGEST_LENGTH);
    memset(digest_mdata, 0, SHA1_DIGEST_LENGTH);

    memset(host_server_name, 0, ND_MAX_HOSTNAME);

    memset(http.user_agent, 0, ND_FLOW_UA_LEN);

    memset(dhcp.fingerprint, 0, ND_FLOW_DHCPFP_LEN);
    memset(dhcp.class_ident, 0, ND_FLOW_DHCPCI_LEN);

    memset(ssh.client_agent, 0, ND_FLOW_SSH_UALEN);
    memset(ssh.server_agent, 0, ND_FLOW_SSH_UALEN);

    ssl.version = 0;
    ssl.cipher_suite = 0;
    memset(ssl.client_certcn, 0, ND_FLOW_SSL_CNLEN);
    memset(ssl.server_certcn, 0, ND_FLOW_SSL_CNLEN);
    memset(ssl.server_organization, 0, ND_FLOW_SSL_ORGLEN);
    memset(ssl.client_ja3, 0, ND_FLOW_SSL_JA3LEN);
    memset(ssl.server_ja3, 0, ND_FLOW_SSL_JA3LEN);

    smtp.tls = false;

    bt.info_hash_valid = 0;
    memset(bt.info_hash, 0, ND_FLOW_BTIHASH_LEN);

    memset(mdns.answer, 0, ND_FLOW_MDNS_ANSLEN);

    memset(capture_filename, 0, sizeof(ND_FLOW_CAPTURE_TEMPLATE));
}

ndFlow::~ndFlow()
{
    release();
}

void ndFlow::hash(const string &device,
    bool hash_mdata, const uint8_t *key, size_t key_length)
{
    sha1 ctx;

    sha1_init(&ctx);
    sha1_write(&ctx, (const char *)device.c_str(), device.size());

    sha1_write(&ctx, (const char *)&ip_version, sizeof(ip_version));
    sha1_write(&ctx, (const char *)&ip_protocol, sizeof(ip_protocol));
    sha1_write(&ctx, (const char *)&vlan_id, sizeof(vlan_id));

    sha1_write(&ctx, (const char *)&lower_mac, ETH_ALEN);
    sha1_write(&ctx, (const char *)&upper_mac, ETH_ALEN);

    switch (ip_version) {
    case 4:
        sha1_write(&ctx, (const char *)lower_addr4, sizeof(struct in_addr));
        sha1_write(&ctx, (const char *)upper_addr4, sizeof(struct in_addr));
        break;
    case 6:
        sha1_write(&ctx, (const char *)lower_addr6, sizeof(struct in6_addr));
        sha1_write(&ctx, (const char *)upper_addr6, sizeof(struct in6_addr));
        break;
    default:
        break;
    }

    sha1_write(&ctx, (const char *)&lower_port, sizeof(lower_port));
    sha1_write(&ctx, (const char *)&upper_port, sizeof(upper_port));

    if (hash_mdata) {
        sha1_write(&ctx,
            (const char *)&detection_guessed, sizeof(detection_guessed));
        sha1_write(&ctx,
            (const char *)&detected_protocol, sizeof(ndpi_protocol));

        if (host_server_name[0] != '\0') {
            sha1_write(&ctx,
                host_server_name, strnlen(host_server_name, ND_MAX_HOSTNAME));
        }
        if (has_ssl_client_certcn()) {
            sha1_write(&ctx,
                ssl.client_certcn, strnlen(ssl.client_certcn, ND_FLOW_SSL_CNLEN));
        }
        if (has_ssl_server_certcn()) {
            sha1_write(&ctx,
                ssl.server_certcn, strnlen(ssl.server_certcn, ND_FLOW_SSL_CNLEN));
        }
        if (has_bt_info_hash()) {
            sha1_write(&ctx, bt.info_hash, ND_FLOW_BTIHASH_LEN);
        }
        if (has_mdns_answer()) {
            sha1_write(&ctx, mdns.answer, ND_FLOW_MDNS_ANSLEN);
        }
    }

    if (key != NULL && key_length > 0)
        sha1_write(&ctx, (const char *)key, key_length);

    if (! hash_mdata)
        sha1_result(&ctx, digest_lower);
    else
        sha1_result(&ctx, digest_mdata);
}

void ndFlow::push(const struct pcap_pkthdr *pkt_header, const uint8_t *pkt_data)
{
    struct pcap_pkthdr *header = new struct pcap_pkthdr;
    if (header == NULL)
        throw ndSystemException(__PRETTY_FUNCTION__, "new header", ENOMEM);
    uint8_t *data = new uint8_t[pkt_header->len];
    if (data == NULL)
        throw ndSystemException(__PRETTY_FUNCTION__, "new data", ENOMEM);

    memcpy(header, pkt_header, sizeof(struct pcap_pkthdr));
    memcpy(data, pkt_data, pkt_header->caplen);

    capture.push_back(make_pair(header, data));
}

int ndFlow::dump(pcap_t *pcap, const uint8_t *digest)
{
    char *p = capture_filename;
    memcpy(p, ND_FLOW_CAPTURE_TEMPLATE, sizeof(ND_FLOW_CAPTURE_TEMPLATE));

    p += ND_FLOW_CAPTURE_SUB_OFFSET;
    for (int i = 0; i < 4; i++, p += 2) sprintf(p, "%02x", digest[i]);
    strcat(p, ".cap");

    pcap_dumper_t *pcap_dumper = pcap_dump_open(pcap, capture_filename);

    if (pcap_dumper == NULL) {
        nd_debug_printf("%s: pcap_dump_open: %s: %s\n",
            __PRETTY_FUNCTION__, capture_filename, "unknown");
        return -1;
    }

    for (nd_flow_capture::const_iterator i = capture.begin();
        i != capture.end(); i++) {
        pcap_dump((uint8_t *)pcap_dumper, i->first, i->second);
    }

    pcap_dump_close(pcap_dumper);

    return 0;
}

void ndFlow::reset(void)
{
    ts_first_update = 0;
    lower_bytes = upper_bytes = 0;
    lower_packets = upper_packets = 0;
}

void ndFlow::release(void)
{
    if (ndpi_flow != NULL) { ndpi_free_flow(ndpi_flow); ndpi_flow = NULL; }
    if (id_src != NULL) { delete id_src; id_src = NULL; }
    if (id_dst != NULL) { delete id_dst; id_dst = NULL; }

    for (nd_flow_capture::const_iterator i = capture.begin();
        i != capture.end(); i++) {
        delete i->first;
        delete [] i->second;
    }

    capture.clear();
}

uint16_t ndFlow::master_protocol(void)
{
    uint16_t proto = (detected_protocol.master_protocol !=
        NDPI_PROTOCOL_UNKNOWN) ?
            detected_protocol.master_protocol :
            detected_protocol.app_protocol;

    switch (proto) {
    case NDPI_PROTOCOL_GMAIL:
    case NDPI_PROTOCOL_HTTPS:
    case NDPI_PROTOCOL_MAIL_IMAP:
    case NDPI_PROTOCOL_MAIL_IMAPS:
    case NDPI_PROTOCOL_MAIL_POPS:
    case NDPI_PROTOCOL_MAIL_SMTPS:
    case NDPI_PROTOCOL_OSCAR:
    case NDPI_PROTOCOL_SSL:
    case NDPI_PROTOCOL_SSL_NO_CERT:
    case NDPI_PROTOCOL_TOR:
    case NDPI_PROTOCOL_UNENCRYPTED_JABBER:
        return NDPI_PROTOCOL_SSL;
    case NDPI_PROTOCOL_FACEBOOK:
    case NDPI_PROTOCOL_HTTP:
    case NDPI_PROTOCOL_HTTP_CONNECT:
    case NDPI_PROTOCOL_HTTP_PROXY:
    case NDPI_PROTOCOL_NETFLIX:
    case NDPI_PROTOCOL_OOKLA:
    case NDPI_PROTOCOL_PPSTREAM:
    case NDPI_PROTOCOL_QQ:
    case NDPI_PROTOCOL_RTSP:
    case NDPI_PROTOCOL_STEAM:
    case NDPI_PROTOCOL_TEAMVIEWER:
    case NDPI_PROTOCOL_XBOX:
        return NDPI_PROTOCOL_HTTP;
    }

    return proto;
}

bool ndFlow::has_dhcp_fingerprint(void)
{
    return (
        (detected_protocol.master_protocol == NDPI_PROTOCOL_DHCP ||
        detected_protocol.app_protocol == NDPI_PROTOCOL_DHCP) &&
        dhcp.fingerprint[0] != '\0'
    );
}

bool ndFlow::has_dhcp_class_ident(void)
{
    return (
        (detected_protocol.master_protocol == NDPI_PROTOCOL_DHCP ||
        detected_protocol.app_protocol == NDPI_PROTOCOL_DHCP) &&
        dhcp.class_ident[0] != '\0'
    );
}

bool ndFlow::has_http_user_agent(void)
{
    return (
        master_protocol() == NDPI_PROTOCOL_HTTP &&
        http.user_agent[0] != '\0'
    );
}

bool ndFlow::has_ssh_client_agent(void)
{
    return (
        (detected_protocol.master_protocol == NDPI_PROTOCOL_SSH ||
        detected_protocol.app_protocol == NDPI_PROTOCOL_SSH) &&
        ssh.client_agent[0] != '\0'
    );
}

bool ndFlow::has_ssh_server_agent(void)
{
    return (
        (detected_protocol.master_protocol == NDPI_PROTOCOL_SSH ||
        detected_protocol.app_protocol == NDPI_PROTOCOL_SSH) &&
        ssh.server_agent[0] != '\0'
    );
}

bool ndFlow::has_ssl_client_certcn(void)
{
    return (
        master_protocol() == NDPI_PROTOCOL_SSL &&
        ssl.client_certcn[0] != '\0'
    );
}

bool ndFlow::has_ssl_server_certcn(void)
{
    return (
        master_protocol() == NDPI_PROTOCOL_SSL &&
        ssl.server_certcn[0] != '\0'
    );
}

bool ndFlow::has_ssl_server_organization(void)
{
    return (
        master_protocol() == NDPI_PROTOCOL_SSL &&
        ssl.server_organization[0] != '\0'
    );
}

bool ndFlow::has_ssl_client_ja3(void)
{
    return (
        master_protocol() == NDPI_PROTOCOL_SSL &&
        ssl.client_ja3[0] != '\0'
    );
}

bool ndFlow::has_ssl_server_ja3(void)
{
    return (
        master_protocol() == NDPI_PROTOCOL_SSL &&
        ssl.server_ja3[0] != '\0'
    );
}

bool ndFlow::has_bt_info_hash(void)
{
    return (
        (detected_protocol.master_protocol == NDPI_PROTOCOL_BITTORRENT ||
        detected_protocol.app_protocol == NDPI_PROTOCOL_BITTORRENT) &&
        bt.info_hash_valid
    );
}

bool ndFlow::has_mdns_answer(void)
{
    return (
        (detected_protocol.master_protocol == NDPI_PROTOCOL_MDNS ||
        detected_protocol.app_protocol == NDPI_PROTOCOL_MDNS) &&
        mdns.answer[0] != '\0'
    );
}

void ndFlow::print(const char *tag, struct ndpi_detection_module_struct *ndpi)
{
    char *p = NULL, buffer[64];
    const char *lower_name = lower_ip, *upper_name = upper_ip;

    if (ND_DEBUG_WITH_ETHERS) {
        string key;
        nd_device_ethers::const_iterator i;

        key.assign((const char *)lower_mac, ETH_ALEN);

        i = device_ethers.find(key);
        if (i != device_ethers.end())
            lower_name = i->second.c_str();

        key.assign((const char *)upper_mac, ETH_ALEN);

        i = device_ethers.find(key);
        if (i != device_ethers.end())
            upper_name = i->second.c_str();
    }

    if (detected_protocol.app_protocol) {
        ndpi_protocol2name(ndpi,
            detected_protocol, buffer, sizeof(buffer));
        p = buffer;
    }
    else
        p = ndpi_get_proto_name(ndpi, detected_protocol.master_protocol);

    string digest;
    nd_sha1_to_string((const uint8_t *)bt.info_hash, digest);

    nd_flow_printf(
        "%s: [%c%c%c%c%c%c] %s %s:%hu %c%c%c %s:%hu%s%s%s%s%s%s%s%s%s\n",
        tag,
        (internal) ? 'i' : 'e',
        (ip_version == 4) ? '4' : (ip_version == 6) ? '6' : '-',
        ip_nat ? 'n' : '-',
        (detection_guessed & ND_FLOW_GUESS_PROTO) ? 'g' : '-',
        (detection_guessed & ND_FLOW_GUESS_DNS) ? 'G' : '-',
        (privacy_mask & PRIVATE_LOWER) ? 'p' :
            (privacy_mask & PRIVATE_UPPER) ? 'P' :
            (privacy_mask & (PRIVATE_LOWER | PRIVATE_UPPER)) ? 'X' :
            '-',
        p,
        lower_name, ntohs(lower_port),
        (origin == ORIGIN_LOWER || origin == ORIGIN_UNKNOWN) ? '-' : '<',
        (origin == ORIGIN_UNKNOWN) ? '?' : '-',
        (origin == ORIGIN_UPPER || origin == ORIGIN_UNKNOWN) ? '-' : '>',
        upper_name, ntohs(upper_port),
        (host_server_name[0] != '\0' || has_mdns_answer()) ? " H: " : "",
        (host_server_name[0] != '\0' || has_mdns_answer()) ?
            has_mdns_answer() ? mdns.answer : host_server_name : "",
        (has_ssl_client_certcn() || has_ssl_server_certcn()) ? " SSL" : "",
        (has_ssl_client_certcn()) ? " C: " : "",
        (has_ssl_client_certcn()) ? ssl.client_certcn : "",
        (has_ssl_server_certcn()) ? " S: " : "",
        (has_ssl_server_certcn()) ? ssl.server_certcn : "",
        (has_bt_info_hash()) ? " BT-IH: " : "",
        (has_bt_info_hash()) ? digest.c_str() : ""
    );

    if (ND_DEBUG &&
        detected_protocol.master_protocol == NDPI_PROTOCOL_SSL &&
        ! (detection_guessed & ND_FLOW_GUESS_PROTO) && ssl.version == 0x0000) {
        nd_debug_printf("%s: SSL with no SSL/TLS verison.\n", tag);
    }
}

json_object *ndFlow::json_encode(ndJson &json,
    struct ndpi_detection_module_struct *ndpi, bool include_stats)
{
    char mac_addr[ND_STR_ETHALEN + 1];
    string other_type = "unknown";
    string _lower_mac = "local_mac", _upper_mac = "other_mac";
    string _lower_ip = "local_ip", _upper_ip = "other_ip";
    string _lower_port = "local_port", _upper_port = "other_port";
    string _lower_bytes = "local_bytes", _upper_bytes = "other_bytes";
    string _lower_packets = "local_packets", _upper_packets = "other_packets";

    json_object *json_flow = json.CreateObject();

    string digest;
    nd_sha1_to_string(digest_mdata, digest);
    json.AddObject(json_flow, "digest", digest);

    json.AddObject(json_flow, "ip_nat", ip_nat);

    json.AddObject(json_flow, "ip_version", (int32_t)ip_version);

    json.AddObject(json_flow, "ip_protocol", (int32_t)ip_protocol);

    json.AddObject(json_flow, "vlan_id", (int32_t)vlan_id);
#ifndef _ND_USE_NETLINK
    other_type = "unsupported";
#else
    if (lower_type == ndNETLINK_ATYPE_ERROR ||
        upper_type == ndNETLINK_ATYPE_ERROR) {
        other_type = "error";
    }
    else if (lower_type == ndNETLINK_ATYPE_LOCALIP &&
        upper_type == ndNETLINK_ATYPE_LOCALNET) {
        other_type = "local";
        _lower_mac = "other_mac";
        _lower_ip = "other_ip";
        _lower_port = "other_port";
        _lower_bytes = "other_bytes";
        _lower_packets = "other_packets";
        _upper_mac = "local_mac";
        _upper_ip = "local_ip";
        _upper_port = "local_port";
        _upper_bytes = "local_bytes";
        _upper_packets = "local_packets";
    }
    else if (lower_type == ndNETLINK_ATYPE_LOCALNET &&
        upper_type == ndNETLINK_ATYPE_LOCALIP) {
        other_type = "local";
        _lower_mac = "local_mac";
        _lower_ip = "local_ip";
        _lower_port = "local_port";
        _lower_bytes = "local_bytes";
        _lower_packets = "local_packets";
        _upper_mac = "other_mac";
        _upper_ip = "other_ip";
        _upper_port = "other_port";
        _upper_bytes = "other_bytes";
        _upper_packets = "other_packets";
    }
    else if (lower_type == ndNETLINK_ATYPE_MULTICAST) {
        other_type = "multicast";
        _lower_mac = "other_mac";
        _lower_ip = "other_ip";
        _lower_port = "other_port";
        _lower_bytes = "other_bytes";
        _lower_packets = "other_packets";
        _upper_mac = "local_mac";
        _upper_ip = "local_ip";
        _upper_port = "local_port";
        _upper_bytes = "local_bytes";
        _upper_packets = "local_packets";
    }
    else if (upper_type == ndNETLINK_ATYPE_MULTICAST) {
        other_type = "multicast";
        _lower_mac = "local_mac";
        _lower_ip = "local_ip";
        _lower_port = "local_port";
        _lower_bytes = "local_bytes";
        _lower_packets = "local_packets";
        _upper_mac = "other_mac";
        _upper_ip = "other_ip";
        _upper_port = "other_port";
        _upper_bytes = "other_bytes";
        _upper_packets = "other_packets";
    }
    else if (lower_type == ndNETLINK_ATYPE_BROADCAST) {
        other_type = "broadcast";
        _lower_mac = "other_mac";
        _lower_ip = "other_ip";
        _lower_port = "other_port";
        _lower_bytes = "other_bytes";
        _lower_packets = "other_packets";
        _upper_mac = "local_mac";
        _upper_ip = "local_ip";
        _upper_port = "local_port";
        _upper_bytes = "local_bytes";
        _upper_packets = "local_packets";
    }
    else if (upper_type == ndNETLINK_ATYPE_BROADCAST) {
        other_type = "broadcast";
        _lower_mac = "local_mac";
        _lower_ip = "local_ip";
        _lower_port = "local_port";
        _lower_bytes = "local_bytes";
        _lower_packets = "local_packets";
        _upper_mac = "other_mac";
        _upper_ip = "other_ip";
        _upper_port = "other_port";
        _upper_bytes = "other_bytes";
        _upper_packets = "other_packets";
    }
    else if (lower_type == ndNETLINK_ATYPE_PRIVATE &&
        upper_type == ndNETLINK_ATYPE_LOCALNET) {
        other_type = "local";
        _lower_mac = "other_mac";
        _lower_ip = "other_ip";
        _lower_port = "other_port";
        _lower_bytes = "other_bytes";
        _lower_packets = "other_packets";
        _upper_mac = "local_mac";
        _upper_ip = "local_ip";
        _upper_port = "local_port";
        _upper_bytes = "local_bytes";
        _upper_packets = "local_packets";
    }
    else if (lower_type == ndNETLINK_ATYPE_LOCALNET &&
        upper_type == ndNETLINK_ATYPE_PRIVATE) {
        other_type = "local";
        _lower_mac = "local_mac";
        _lower_ip = "local_ip";
        _lower_port = "local_port";
        _lower_bytes = "local_bytes";
        _lower_packets = "local_packets";
        _upper_mac = "other_mac";
        _upper_ip = "other_ip";
        _upper_port = "other_port";
        _upper_bytes = "other_bytes";
        _upper_packets = "other_packets";
    }
#if 0
    // TODO: Further investigation required!
    // This appears to catch corrupted IPv6 headers.
    // Spend some time to figure out if there are any
    // possible over-matches for different methods of
    // deployment (gateway/port mirror modes).
#endif
    else if (ip_version != 6 &&
        lower_type == ndNETLINK_ATYPE_PRIVATE &&
        upper_type == ndNETLINK_ATYPE_PRIVATE) {
        other_type = "local";
        _lower_mac = "local_mac";
        _lower_ip = "local_ip";
        _lower_port = "local_port";
        _lower_bytes = "local_bytes";
        _lower_packets = "local_packets";
        _upper_mac = "other_mac";
        _upper_ip = "other_ip";
        _upper_port = "other_port";
        _upper_bytes = "other_bytes";
        _upper_packets = "other_packets";
    }
    else if (lower_type == ndNETLINK_ATYPE_PRIVATE &&
        upper_type == ndNETLINK_ATYPE_LOCALIP) {
        other_type = "remote";
        _lower_mac = "other_mac";
        _lower_ip = "other_ip";
        _lower_port = "other_port";
        _lower_bytes = "other_bytes";
        _lower_packets = "other_packets";
        _upper_mac = "local_mac";
        _upper_ip = "local_ip";
        _upper_port = "local_port";
        _upper_bytes = "local_bytes";
        _upper_packets = "local_packets";
    }
    else if (lower_type == ndNETLINK_ATYPE_LOCALIP &&
        upper_type == ndNETLINK_ATYPE_PRIVATE) {
        other_type = "remote";
        _lower_mac = "local_mac";
        _lower_ip = "local_ip";
        _lower_port = "local_port";
        _lower_bytes = "local_bytes";
        _lower_packets = "local_packets";
        _upper_mac = "other_mac";
        _upper_ip = "other_ip";
        _upper_port = "other_port";
        _upper_bytes = "other_bytes";
        _upper_packets = "other_packets";
    }
    else if (lower_type == ndNETLINK_ATYPE_LOCALNET &&
        upper_type == ndNETLINK_ATYPE_LOCALNET) {
        other_type = "local";
        _lower_mac = "local_mac";
        _lower_ip = "local_ip";
        _lower_port = "local_port";
        _lower_bytes = "local_bytes";
        _lower_packets = "local_packets";
        _upper_mac = "other_mac";
        _upper_ip = "other_ip";
        _upper_port = "other_port";
        _upper_bytes = "other_bytes";
        _upper_packets = "other_packets";
    }
    else if (lower_type == ndNETLINK_ATYPE_UNKNOWN) {
        other_type = "remote";
        _lower_mac = "other_mac";
        _lower_ip = "other_ip";
        _lower_port = "other_port";
        _lower_bytes = "other_bytes";
        _lower_packets = "other_packets";
        _upper_mac = "local_mac";
        _upper_ip = "local_ip";
        _upper_port = "local_port";
        _upper_bytes = "local_bytes";
        _upper_packets = "local_packets";
    }
    else if (upper_type == ndNETLINK_ATYPE_UNKNOWN) {
        other_type = "remote";
        _lower_mac = "local_mac";
        _lower_ip = "local_ip";
        _lower_port = "local_port";
        _lower_bytes = "local_bytes";
        _lower_packets = "local_packets";
        _upper_mac = "other_mac";
        _upper_ip = "other_ip";
        _upper_port = "other_port";
        _upper_bytes = "other_bytes";
        _upper_packets = "other_packets";
    }
#ifndef _ND_LEAN_AND_MEAN
    // 10.110.80.1: address is: PRIVATE
    // 67.204.229.236: address is: LOCALIP
    if (ND_DEBUG && other_type == "unknown") {
        ndNetlink::PrintType(lower_ip, lower_type);
        ndNetlink::PrintType(upper_ip, upper_type);
        //exit(1);
    }
#endif
#endif
    json.AddObject(json_flow, "other_type", other_type);

    switch (origin) {
    case ORIGIN_UPPER:
        json.AddObject(json_flow, "local_origin",
            (_lower_ip == "local_ip") ? false : true);
        break;
    case ORIGIN_LOWER:
    default:
        json.AddObject(json_flow, "local_origin",
            (_lower_ip == "local_ip") ? true : false);
        break;
    }

    // 00-52-14 to 00-52-FF: Unassigned (small allocations)
    if (privacy_mask & PRIVATE_LOWER)
        snprintf(mac_addr, sizeof(mac_addr), "00:52:14:00:00:00");
    else {
        snprintf(mac_addr, sizeof(mac_addr), "%02x:%02x:%02x:%02x:%02x:%02x",
            lower_mac[0], lower_mac[1], lower_mac[2],
            lower_mac[3], lower_mac[4], lower_mac[5]
        );
    }
    json.AddObject(json_flow, _lower_mac, mac_addr);

    if (privacy_mask & PRIVATE_UPPER)
        snprintf(mac_addr, sizeof(mac_addr), "00:52:FF:00:00:00");
    else {
        snprintf(mac_addr, sizeof(mac_addr), "%02x:%02x:%02x:%02x:%02x:%02x",
            upper_mac[0], upper_mac[1], upper_mac[2],
            upper_mac[3], upper_mac[4], upper_mac[5]
        );
    }
    json.AddObject(json_flow, _upper_mac, mac_addr);

    if (privacy_mask & PRIVATE_LOWER) {
        if (ip_version == 4)
            json.AddObject(json_flow, _lower_ip, ND_PRIVATE_IPV4 "253");
        else
            json.AddObject(json_flow, _lower_ip, ND_PRIVATE_IPV6 "fd");
    }
    else
        json.AddObject(json_flow, _lower_ip, lower_ip);

    if (privacy_mask & PRIVATE_UPPER) {
        if (ip_version == 4)
            json.AddObject(json_flow, _upper_ip, ND_PRIVATE_IPV4 "254");
        else
            json.AddObject(json_flow, _upper_ip, ND_PRIVATE_IPV6 "fe");
    }
    else
        json.AddObject(json_flow, _upper_ip, upper_ip);

    json.AddObject(json_flow, _lower_port, (int32_t)ntohs(lower_port));
    json.AddObject(json_flow, _upper_port, (int32_t)ntohs(upper_port));

    if (include_stats) {
        json.AddObject(json_flow, _lower_bytes, lower_bytes);
        json.AddObject(json_flow, _upper_bytes, upper_bytes);
        json.AddObject(json_flow, _lower_packets, lower_packets);
        json.AddObject(json_flow, _upper_packets, upper_packets);
        json.AddObject(json_flow, "total_packets", total_packets);
        json.AddObject(json_flow, "total_bytes", total_bytes);
    }

    json.AddObject(json_flow, "detected_protocol",
        (int32_t)detected_protocol.master_protocol);
    json.AddObject(json_flow, "detected_protocol_name",
        ndpi_get_proto_name(ndpi, detected_protocol.master_protocol));

    json.AddObject(json_flow, "detected_application",
        (int32_t)detected_protocol.app_protocol);
    json.AddObject(json_flow, "detected_application_name",
        ndpi_get_proto_name(ndpi, detected_protocol.app_protocol));

    json.AddObject(json_flow, "detection_guessed", detection_guessed);

    if (host_server_name[0] != '\0') {
        json.AddObject(json_flow,
            "host_server_name", host_server_name);
    }

    if (has_http_user_agent()) {

        json_object *_http = json.CreateObject(json_flow, "http");

        json.AddObject(_http, "user_agent", http.user_agent);
    }

    if (has_dhcp_fingerprint() || has_dhcp_class_ident()) {

        json_object *_dhcp = json.CreateObject(json_flow, "dhcp");

        if (has_dhcp_fingerprint())
            json.AddObject(_dhcp, "fingerprint", dhcp.fingerprint);

        if (has_dhcp_class_ident())
            json.AddObject(_dhcp, "class_ident", dhcp.class_ident);
    }

    if (has_ssh_client_agent() || has_ssh_server_agent()) {

        json_object *_ssh = json.CreateObject(json_flow, "ssh");

        if (has_ssh_client_agent())
            json.AddObject(_ssh, "client", ssh.client_agent);

        if (has_ssh_server_agent())
            json.AddObject(_ssh, "server", ssh.server_agent);
    }

    if (has_ssl_client_certcn() || has_ssl_server_certcn()) {

        char tohex[7];
        json_object *_ssl = json.CreateObject(json_flow, "ssl");

        sprintf(tohex, "0x%04hx", ssl.version);
        json.AddObject(_ssl, "version", tohex);

        sprintf(tohex, "0x%04hx", ssl.cipher_suite);
        json.AddObject(_ssl, "cipher_suite", tohex);

        if (has_ssl_client_certcn())
            json.AddObject(_ssl, "client", ssl.client_certcn);

        if (has_ssl_server_certcn())
            json.AddObject(_ssl, "server", ssl.server_certcn);

        if (has_ssl_server_organization())
            json.AddObject(_ssl, "organization", ssl.server_organization);

        if (has_ssl_client_ja3())
            json.AddObject(_ssl, "client_ja3", ssl.client_ja3);

        if (has_ssl_server_ja3())
            json.AddObject(_ssl, "server_ja3", ssl.server_ja3);
    }

    if (has_bt_info_hash()) {

        json_object *_bt = json.CreateObject(json_flow, "bt");

        nd_sha1_to_string((const uint8_t *)bt.info_hash, digest);
        json.AddObject(_bt, "info_hash", digest);
    }

    if (has_mdns_answer()) {

        json_object *_mdns = json.CreateObject(json_flow, "mdns");

        json.AddObject(_mdns, "answer", mdns.answer);
    }

    json.AddObject(json_flow, "first_seen_at", ts_first_seen);
    json.AddObject(json_flow, "first_update_at", ts_first_update);
    json.AddObject(json_flow, "last_seen_at", ts_last_seen);

    return json_flow;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
