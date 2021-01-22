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

#include <stdexcept>
#include <cstring>
#include <map>
#include <list>
#include <vector>
#ifdef HAVE_ATOMIC
#include <atomic>
#endif
#include <unordered_map>
#include <sstream>
#include <regex>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#define __FAVOR_BSD 1
#include <netinet/tcp.h>
#undef __FAVOR_BSD

#include <errno.h>

#include <arpa/inet.h>

#include <pcap/pcap.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

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

ndFlow::ndFlow(nd_ifaces::iterator iface)
    : iface(iface), dpi_thread_id(-1), pkt(NULL),
    ip_version(0), ip_protocol(0), vlan_id(0),
    flags{},
#ifdef _ND_USE_CONNTRACK
    ct_id(0), ct_mark(0),
#endif
    ts_first_seen(0), ts_first_update(0), ts_last_seen(0),
    lower_type(ndNETLINK_ATYPE_UNKNOWN), upper_type(ndNETLINK_ATYPE_UNKNOWN),
    lower_map(LOWER_UNKNOWN), other_type(OTHER_UNKNOWN),
    lower_mac{}, upper_mac{}, lower_addr{}, upper_addr{},
    lower_addr4(NULL), lower_addr6(NULL), upper_addr4(NULL), upper_addr6(NULL),
    lower_ip{}, upper_ip{},
    lower_port(0), upper_port(0),
    tunnel_type(TUNNEL_NONE), gtp{},
    lower_bytes(0), upper_bytes(0), total_bytes(0),
    lower_packets(0), upper_packets(0), total_packets(0),
    detection_packets(0), detected_protocol{},
    detected_protocol_name(NULL), detected_application_name(NULL),
    ndpi_flow(NULL), id_src(NULL), id_dst(NULL),
    digest_lower{}, digest_mdata{},
    host_server_name{}, http{},
    privacy_mask(0), origin(0), direction(0),
    capture_filename{}
{
    lower_addr4 = (struct sockaddr_in *)&lower_addr;
    lower_addr6 = (struct sockaddr_in6 *)&lower_addr;
    upper_addr4 = (struct sockaddr_in *)&upper_addr;
    upper_addr6 = (struct sockaddr_in6 *)&upper_addr;

    gtp.version = 0xFF;
}

ndFlow::ndFlow(const ndFlow &flow)
    : iface(flow.iface), dpi_thread_id(-1), pkt(NULL),
    ip_version(flow.ip_version), ip_protocol(flow.ip_protocol),
    vlan_id(flow.vlan_id),
    flags{},
#ifdef _ND_USE_CONNTRACK
    ct_id(0), ct_mark(0),
#endif
    ts_first_seen(flow.ts_first_seen), ts_first_update(flow.ts_first_update),
    ts_last_seen(flow.ts_last_seen),
    lower_type(ndNETLINK_ATYPE_UNKNOWN), upper_type(ndNETLINK_ATYPE_UNKNOWN),
    lower_map(LOWER_UNKNOWN), other_type(OTHER_UNKNOWN),
    lower_addr(flow.lower_addr), upper_addr(flow.upper_addr),
    lower_ip{}, upper_ip{},
    lower_port(flow.lower_port), upper_port(flow.upper_port),
    tunnel_type(flow.tunnel_type), gtp(flow.gtp),
    lower_bytes(0), upper_bytes(0), total_bytes(0),
    lower_packets(0), upper_packets(0), total_packets(0),
    detection_packets(0), detected_protocol{},
    detected_protocol_name(NULL), detected_application_name(NULL),
    ndpi_flow(NULL), id_src(NULL), id_dst(NULL),
    host_server_name{}, http{},
    privacy_mask(0), origin(0), direction(0),
    capture_filename{}
{
    memcpy(lower_mac, flow.lower_mac, ETH_ALEN);
    memcpy(upper_mac, flow.upper_mac, ETH_ALEN);

    memcpy(digest_lower, flow.digest_lower, SHA1_DIGEST_LENGTH);
    memset(digest_mdata, 0, SHA1_DIGEST_LENGTH);

    lower_addr4 = (struct sockaddr_in *)&lower_addr;
    lower_addr6 = (struct sockaddr_in6 *)&lower_addr;
    upper_addr4 = (struct sockaddr_in *)&upper_addr;
    upper_addr6 = (struct sockaddr_in6 *)&upper_addr;
}

ndFlow::~ndFlow()
{
    release();

    if (detected_protocol_name != NULL) {
        free(detected_protocol_name);
        detected_protocol_name = NULL;
    }
    if (detected_application_name != NULL) {
        free(detected_application_name);
        detected_application_name = NULL;
    }
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

//    sha1_write(&ctx, (const char *)&lower_mac, ETH_ALEN);
//    sha1_write(&ctx, (const char *)&upper_mac, ETH_ALEN);

    switch (ip_version) {
    case 4:
        sha1_write(&ctx,
            (const char *)&lower_addr4->sin_addr, sizeof(struct in_addr));
        sha1_write(&ctx,
            (const char *)&upper_addr4->sin_addr, sizeof(struct in_addr));
        break;
    case 6:
        sha1_write(&ctx,
            (const char *)&lower_addr6->sin6_addr, sizeof(struct in6_addr));
        sha1_write(&ctx,
            (const char *)&upper_addr6->sin6_addr, sizeof(struct in6_addr));
        break;
    default:
        break;
    }

    sha1_write(&ctx, (const char *)&lower_port, sizeof(lower_port));
    sha1_write(&ctx, (const char *)&upper_port, sizeof(upper_port));

//    nd_debug_printf("hash: %s, %hhu, %hhu, %hu, [%hhx%hhx%hhx%hhx%hhx%hhx], [%hhx%hhx%hhx%hhx%hhx%hhx], %hhu, %hhu\n",
//        device.c_str(), ip_version, ip_protocol, vlan_id,
//        lower_mac[0], lower_mac[1], lower_mac[2], lower_mac[3], lower_mac[4], lower_mac[5],
//        upper_mac[0], upper_mac[1], upper_mac[2], upper_mac[3], upper_mac[4], upper_mac[5],
//        lower_port, upper_port);

    if (hash_mdata) {
        sha1_write(&ctx,
            (const char *)&detected_protocol, sizeof(ndpi_protocol));

        if (host_server_name[0] != '\0') {
            sha1_write(&ctx,
                host_server_name, strnlen(host_server_name, ND_MAX_HOSTNAME));
        }
        if (has_ssl_client_sni()) {
            sha1_write(&ctx,
                ssl.client_sni, strnlen(ssl.client_sni, ND_FLOW_TLS_CNLEN));
        }
        if (has_ssl_server_cn()) {
            sha1_write(&ctx,
                ssl.server_cn, strnlen(ssl.server_cn, ND_FLOW_TLS_CNLEN));
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
    for (int i = 0; i < 4; i++, p += 2) sprintf(p, "%02hhx", digest[i]);
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
    if (pkt != NULL) { delete [] pkt; pkt = NULL; }
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

bool ndFlow::has_http_url(void)
{
    return (
        http.url[0] != '\0'
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

bool ndFlow::has_ssl_client_sni(void)
{
    return (
        master_protocol() == NDPI_PROTOCOL_SSL &&
        ssl.client_sni[0] != '\0'
    );
}

bool ndFlow::has_ssl_server_cn(void)
{
    return (
        master_protocol() == NDPI_PROTOCOL_SSL &&
        ssl.server_cn[0] != '\0'
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

bool ndFlow::has_ssdp_headers(void)
{
    return (
        detected_protocol.master_protocol == NDPI_PROTOCOL_SSDP &&
        ssdp.headers.size()
    );
}

void ndFlow::print(void)
{
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

    string iface_name;
    nd_iface_name(iface->second, iface_name);

    string digest;
    nd_sha1_to_string((const uint8_t *)bt.info_hash, digest);

    nd_flow_printf(
        "%s: [%c%c%c%c%c%c] %s%s%s %s:%hu %c%c%c %s:%hu%s%s%s%s%s%s%s%s%s\n",
        iface_name.c_str(),
        (iface->first) ? 'i' : 'e',
        (ip_version == 4) ? '4' : (ip_version == 6) ? '6' : '-',
        flags.ip_nat ? 'n' : '-',
        (flags.detection_guessed) ? 'g' : '-',
        (flags.dhc_hit) ? 'd' : '-',
        (privacy_mask & PRIVATE_LOWER) ? 'p' :
            (privacy_mask & PRIVATE_UPPER) ? 'P' :
            (privacy_mask & (PRIVATE_LOWER | PRIVATE_UPPER)) ? 'X' :
            '-',
        detected_protocol_name,
        (detected_application_name != NULL) ? "." : "",
        (detected_application_name != NULL) ? detected_application_name : "",
        lower_name, ntohs(lower_port),
        (origin == ORIGIN_LOWER || origin == ORIGIN_UNKNOWN) ? '-' : '<',
        (origin == ORIGIN_UNKNOWN) ? '?' : '-',
        (origin == ORIGIN_UPPER || origin == ORIGIN_UNKNOWN) ? '-' : '>',
        upper_name, ntohs(upper_port),
        (host_server_name[0] != '\0' || has_mdns_answer()) ? " H: " : "",
        (host_server_name[0] != '\0' || has_mdns_answer()) ?
            has_mdns_answer() ? mdns.answer : host_server_name : "",
        (has_ssl_client_sni() || has_ssl_server_cn()) ? " SSL" : "",
        (has_ssl_client_sni()) ? " C: " : "",
        (has_ssl_client_sni()) ? ssl.client_sni : "",
        (has_ssl_server_cn()) ? " S: " : "",
        (has_ssl_server_cn()) ? ssl.server_cn : "",
        (has_bt_info_hash()) ? " BT-IH: " : "",
        (has_bt_info_hash()) ? digest.c_str() : ""
    );

    if (ND_DEBUG &&
        detected_protocol.master_protocol == NDPI_PROTOCOL_SSL &&
        flags.detection_guessed == false && ssl.version == 0x0000) {
        nd_debug_printf("%s: SSL with no SSL/TLS verison.\n", iface->second.c_str());
    }
}

void ndFlow::get_lower_map(
#ifdef _ND_USE_NETLINK
    ndNetlinkAddressType lt,
    ndNetlinkAddressType ut,
#endif
    uint8_t &lm, uint8_t &ot)
{
    if (lt == ndNETLINK_ATYPE_ERROR ||
        ut == ndNETLINK_ATYPE_ERROR) {
        ot = OTHER_ERROR;
        return;
    }
    else if (lt == ndNETLINK_ATYPE_LOCALIP &&
        ut == ndNETLINK_ATYPE_LOCALNET) {
        lm = LOWER_OTHER;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndNETLINK_ATYPE_LOCALNET &&
        ut == ndNETLINK_ATYPE_LOCALIP) {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndNETLINK_ATYPE_MULTICAST) {
        lm = LOWER_OTHER;
        ot = OTHER_MULTICAST;
    }
    else if (ut == ndNETLINK_ATYPE_MULTICAST) {
        lm = LOWER_LOCAL;
        ot = OTHER_MULTICAST;
    }
    else if (lt == ndNETLINK_ATYPE_BROADCAST) {
        lm = LOWER_OTHER;
        ot = OTHER_BROADCAST;
    }
    else if (ut == ndNETLINK_ATYPE_BROADCAST) {
        lm = LOWER_LOCAL;
        ot = OTHER_BROADCAST;
    }
    else if (lt == ndNETLINK_ATYPE_PRIVATE &&
        ut == ndNETLINK_ATYPE_LOCALNET) {
        lm = LOWER_OTHER;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndNETLINK_ATYPE_LOCALNET &&
        ut == ndNETLINK_ATYPE_PRIVATE) {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
#if 0
    // TODO: Further investigation required!
    // This appears to catch corrupted IPv6 headers.
    // Spend some time to figure out if there are any
    // possible over-matches for different methods of
    // deployment (gateway/port mirror modes).
#endif
    else if (ip_version != 6 &&
        lt == ndNETLINK_ATYPE_PRIVATE &&
        ut == ndNETLINK_ATYPE_PRIVATE) {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndNETLINK_ATYPE_PRIVATE &&
        ut == ndNETLINK_ATYPE_LOCALIP) {
        lm = LOWER_OTHER;
        ot = OTHER_REMOTE;
    }
    else if (lt == ndNETLINK_ATYPE_LOCALIP &&
        ut == ndNETLINK_ATYPE_PRIVATE) {
        lm = LOWER_LOCAL;
        ot = OTHER_REMOTE;
    }
    else if (lt == ndNETLINK_ATYPE_LOCALNET &&
        ut == ndNETLINK_ATYPE_LOCALNET) {
        lm = LOWER_LOCAL;
        ot = OTHER_LOCAL;
    }
    else if (lt == ndNETLINK_ATYPE_UNKNOWN) {
        lm = LOWER_OTHER;
        ot = OTHER_REMOTE;
    }
    else if (ut == ndNETLINK_ATYPE_UNKNOWN) {
        lm = LOWER_LOCAL;
        ot = OTHER_REMOTE;
    }
}

void ndFlow::json_encode(json &j, uint8_t encode_includes)
{
    char mac_addr[ND_STR_ETHALEN + 1];
    string _other_type = "unknown";
    string _lower_mac = "local_mac", _upper_mac = "other_mac";
    string _lower_ip = "local_ip", _upper_ip = "other_ip";
    string _lower_gtp_ip = "local_ip", _upper_gtp_ip = "other_ip";
    string _lower_port = "local_port", _upper_port = "other_port";
    string _lower_gtp_port = "local_port", _upper_gtp_port = "other_port";
    string _lower_bytes = "local_bytes", _upper_bytes = "other_bytes";
    string _lower_packets = "local_packets", _upper_packets = "other_packets";

    string digest;
    uint8_t digest_null[SHA1_DIGEST_LENGTH] = { '\0' };

    if (memcmp(digest_mdata, digest_null, SHA1_DIGEST_LENGTH) != 0) {
        nd_sha1_to_string(digest_mdata, digest);
        j["digest"] = digest;
    } else {
        nd_sha1_to_string(digest_lower, digest);
        j["digest"] = digest;
    }

    j["last_seen_at"] = ts_last_seen;

#ifndef _ND_USE_NETLINK
    _other_type = "unsupported";
#else
    if (lower_map == LOWER_UNKNOWN)
        get_lower_map(lower_type, upper_type, lower_map, other_type);

    switch (lower_map) {
    case LOWER_LOCAL:
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
        break;
    case LOWER_OTHER:
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
        break;
    }

    switch (other_type) {
    case OTHER_LOCAL:
        _other_type = "local";
        break;
    case OTHER_MULTICAST:
        _other_type = "multicast";
        break;
    case OTHER_BROADCAST:
        _other_type = "broadcast";
        break;
    case OTHER_REMOTE:
        _other_type = "remote";
        break;
    case OTHER_UNSUPPORTED:
        _other_type = "unsupported";
        break;
    case OTHER_ERROR:
        _other_type = "error";
        break;
    }

    if (encode_includes & ENCODE_METADATA) {
        j["ip_nat"] = (bool)flags.ip_nat;
        j["dhc_hit"] = (bool)flags.dhc_hit;
    #ifdef _ND_USE_CONNTRACK
        j["ct_id"] = ct_id;
        j["ct_mark"] = ct_mark;
    #endif
        j["ip_version"] = (unsigned)ip_version;
        j["ip_protocol"] = (unsigned)ip_protocol;
        j["vlan_id"] = (unsigned)vlan_id;
    #ifndef _ND_LEAN_AND_MEAN
        // 10.110.80.1: address is: PRIVATE
        // 67.204.229.236: address is: LOCALIP
        if (ND_DEBUG && _other_type == "unknown") {
            ndNetlink::PrintType(lower_ip, lower_type);
            ndNetlink::PrintType(upper_ip, upper_type);
            //exit(1);
        }
    #endif
    #endif
        j["other_type"] = _other_type;

        switch (origin) {
        case ORIGIN_UPPER:
            j["local_origin"] =
                (_lower_ip == "local_ip") ? false : true;
            break;
        case ORIGIN_LOWER:
        default:
            j["local_origin"] =
                (_lower_ip == "local_ip") ? true : false;
            break;
        }

        // 00-52-14 to 00-52-FF: Unassigned (small allocations)
        if (privacy_mask & PRIVATE_LOWER)
            snprintf(mac_addr, sizeof(mac_addr), "00:52:14:00:00:00");
        else {
            snprintf(mac_addr, sizeof(mac_addr),
                "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                lower_mac[0], lower_mac[1], lower_mac[2],
                lower_mac[3], lower_mac[4], lower_mac[5]
            );
        }
        j[_lower_mac] = mac_addr;

        if (privacy_mask & PRIVATE_UPPER)
            snprintf(mac_addr, sizeof(mac_addr), "00:52:FF:00:00:00");
        else {
            snprintf(mac_addr, sizeof(mac_addr),
                "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                upper_mac[0], upper_mac[1], upper_mac[2],
                upper_mac[3], upper_mac[4], upper_mac[5]
            );
        }
        j[_upper_mac] = mac_addr;

        if (privacy_mask & PRIVATE_LOWER) {
            if (ip_version == 4)
                j[_lower_ip] = ND_PRIVATE_IPV4 "253";
            else
                j[_lower_ip] = ND_PRIVATE_IPV6 "fd";
        }
        else
            j[_lower_ip] = lower_ip;

        if (privacy_mask & PRIVATE_UPPER) {
            if (ip_version == 4)
                j[_upper_ip] = ND_PRIVATE_IPV4 "254";
            else
                j[_upper_ip] = ND_PRIVATE_IPV6 "fe";
        }
        else
            j[_upper_ip] = upper_ip;

        j[_lower_port] = (unsigned)ntohs(lower_port);
        j[_upper_port] = (unsigned)ntohs(upper_port);

        j["detected_protocol"] =
            (unsigned)detected_protocol.master_protocol;
        j["detected_protocol_name"] =
            (detected_protocol_name != NULL) ? detected_protocol_name : "Unknown";

        j["detected_application"] =
            (unsigned)detected_protocol.app_protocol;
        j["detected_application_name"] =
            (detected_application_name != NULL) ? detected_application_name : "Unknown";

        j["detection_guessed"] = (unsigned)flags.detection_guessed;

        if (host_server_name[0] != '\0')
            j["host_server_name"] = host_server_name;

        if (has_http_user_agent() || has_http_url()) {

            if (has_http_user_agent())
                j["http"]["user_agent"] = http.user_agent;
            if (has_http_url())
                j["http"]["url"] = http.url;
        }

        if (has_dhcp_fingerprint() || has_dhcp_class_ident()) {

            if (has_dhcp_fingerprint())
                j["dhcp"]["fingerprint"] = dhcp.fingerprint;

            if (has_dhcp_class_ident())
                j["dhcp"]["class_ident"] = dhcp.class_ident;
        }

        if (has_ssh_client_agent() || has_ssh_server_agent()) {

            if (has_ssh_client_agent())
                j["ssh"]["client"] = ssh.client_agent;

            if (has_ssh_server_agent())
                j["ssh"]["server"] = ssh.server_agent;
        }

        if (has_ssl_client_sni() || has_ssl_server_cn()) {

            char tohex[7];

            sprintf(tohex, "0x%04hx", ssl.version);
            j["ssl"]["version"] = tohex;

            sprintf(tohex, "0x%04hx", ssl.cipher_suite);
            j["ssl"]["cipher_suite"] = tohex;

            if (has_ssl_client_sni())
                j["ssl"]["client_sni"] = ssl.client_sni;

            if (has_ssl_server_cn())
                j["ssl"]["server_cn"] = ssl.server_cn;

            if (has_ssl_server_organization())
                j["ssl"]["organization"] = ssl.server_organization;

            if (has_ssl_client_ja3())
                j["ssl"]["client_ja3"] = ssl.client_ja3;

            if (has_ssl_server_ja3())
                j["ssl"]["server_ja3"] = ssl.server_ja3;

            if (ssl.cert_fingerprint_found) {
                nd_sha1_to_string((const uint8_t *)ssl.cert_fingerprint, digest);
                j["ssl"]["fingerprint"] = digest;
            }
        }

        if (has_bt_info_hash()) {

            nd_sha1_to_string((const uint8_t *)bt.info_hash, digest);
            j["bt"]["info_hash"] = digest;
        }

        if (has_mdns_answer()) {

            j["mdns"]["answer"] = mdns.answer;
        }

        if (has_ssdp_headers()) {

            j["ssdp"] = ssdp.headers;

        }

        j["first_seen_at"] = ts_first_seen;
        j["first_update_at"] = ts_first_update;
    }

    if (encode_includes & ENCODE_TUNNELS) {
        switch (tunnel_type) {
        case TUNNEL_GTP:
            if (gtp.lower_map == LOWER_UNKNOWN)
                get_lower_map(gtp.lower_type, gtp.upper_type, gtp.lower_map, gtp.other_type);

            string _lower_teid = "local_teid", _upper_teid = "other_teid";

            switch (gtp.lower_map) {
            case LOWER_LOCAL:
                _lower_ip = "local_ip";
                _lower_port = "local_port";
                _lower_teid = "local_teid";
                _upper_ip = "other_ip";
                _upper_port = "other_port";
                _upper_teid = "other_teid";
                break;
            case LOWER_OTHER:
                _lower_ip = "other_ip";
                _lower_port = "other_port";
                _lower_teid = "other_teid";
                _upper_ip = "local_ip";
                _upper_port = "local_port";
                _upper_teid = "local_teid";
                break;
            }

            switch (gtp.other_type) {
            case OTHER_LOCAL:
                _other_type = "local";
                break;
            case OTHER_REMOTE:
                _other_type = "remote";
                break;
            case OTHER_ERROR:
                _other_type = "error";
                break;
            case OTHER_UNSUPPORTED:
            default:
                _other_type = "unsupported";
                break;
            }

            j["gtp"]["version"] = gtp.version;
            j["gtp"]["ip_version"] = gtp.ip_version;
            j["gtp"][_lower_ip] = gtp.lower_ip;
            j["gtp"][_upper_ip] = gtp.upper_ip;
            j["gtp"][_lower_port] = (unsigned)htons(gtp.lower_port);
            j["gtp"][_upper_port] = (unsigned)htons(gtp.upper_port);
            j["gtp"][_lower_teid] = htonl(gtp.lower_teid);
            j["gtp"][_upper_teid] = htonl(gtp.upper_teid);
            j["gtp"]["other_type"] = _other_type;

            break;
        }
    }

    if (encode_includes & ENCODE_STATS) {
        j[_lower_bytes] = lower_bytes;
        j[_upper_bytes] = upper_bytes;
        j[_lower_packets] = lower_packets;
        j[_upper_packets] = upper_packets;
        j["total_packets"] = total_packets;
        j["total_bytes"] = total_bytes;
        j["detection_packets"] = detection_packets;
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
