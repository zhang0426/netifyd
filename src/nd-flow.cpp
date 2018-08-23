// Netify Agent
// Copyright (C) 2015-2018 eGloo Incorporated <http://www.egloo.ca>
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
#include <vector>
#include <unordered_map>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#ifdef _ND_USE_NETLINK
#include <linux/netlink.h>
#endif
#include <json.h>

using namespace std;

#include "netifyd.h"

#include "nd-ndpi.h"
#include "nd-util.h"
#ifdef _ND_USE_NETLINK
#include "nd-netlink.h"
#endif
#include "nd-json.h"
#include "nd-flow.h"

extern nd_global_config nd_config;
extern nd_device_ethers device_ethers;

void ndFlow::hash(const string &device, string &digest,
    bool full_hash, const uint8_t *key, size_t key_length)
{
    sha1 ctx;
    uint8_t _digest[SHA1_DIGEST_LENGTH];

    sha1_init(&ctx);
    sha1_write(&ctx, (const char *)device.c_str(), device.size());

    sha1_write(&ctx, (const char *)&ip_version, sizeof(ip_version));
    sha1_write(&ctx, (const char *)&ip_protocol, sizeof(ip_protocol));
    sha1_write(&ctx, (const char *)&vlan_id, sizeof(vlan_id));

    sha1_write(&ctx, (const char *)&lower_mac, ETH_ALEN);
    sha1_write(&ctx, (const char *)&upper_mac, ETH_ALEN);

    switch (ip_version) {
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

    sha1_write(&ctx, (const char *)&lower_port, sizeof(lower_port));
    sha1_write(&ctx, (const char *)&upper_port, sizeof(upper_port));

    if (full_hash) {
        sha1_write(&ctx,
            (const char *)&detection_guessed, sizeof(detection_guessed));
        sha1_write(&ctx,
            (const char *)&detected_protocol, sizeof(ndpi_protocol));

        if (host_server_name[0] != '\0') {
            sha1_write(&ctx,
                host_server_name, strnlen(host_server_name, HOST_NAME_MAX));
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

    digest.assign((const char *)sha1_result(&ctx, _digest), SHA1_DIGEST_LENGTH);
}

uint16_t ndFlow::master_protocol(void)
{
    uint16_t proto = (detected_protocol.master_protocol !=
        NDPI_PROTOCOL_UNKNOWN) ?
            detected_protocol.master_protocol :
            detected_protocol.app_protocol;

    switch (proto) {
    case NDPI_PROTOCOL_GMAIL:
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

    //"%s: [%c%c%c%c%c%c] %s %s:%hu <+> %s:%hu%s%s%s%s%s%s%s%s%s\n",
    nd_debug_printf(
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

json_object *ndFlow::json_encode(const string &device,
    ndJson &json, struct ndpi_detection_module_struct *ndpi, bool include_stats)
{
    char mac_addr[ND_STR_ETHALEN + 1];
    string other_type = "unknown";
    string _lower_mac = "local_mac", _upper_mac = "other_mac";
    string _lower_ip = "local_ip", _upper_ip = "other_ip";
    string _lower_port = "local_port", _upper_port = "other_port";
    string _lower_bytes = "local_bytes", _upper_bytes = "other_bytes";
    string _lower_packets = "local_packets", _upper_packets = "other_packets";

    json_object *json_flow = json.CreateObject();

    string digest, digest_bin;
    hash(device, digest_bin, true);
    nd_sha1_to_string((const uint8_t *)digest_bin.c_str(), digest);
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
        exit(1);
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

    if (privacy_mask & PRIVATE_LOWER)
        snprintf(mac_addr, sizeof(mac_addr), "01:02:03:04:05:06");
    else {
        snprintf(mac_addr, sizeof(mac_addr), "%02x:%02x:%02x:%02x:%02x:%02x",
            lower_mac[0], lower_mac[1], lower_mac[2],
            lower_mac[3], lower_mac[4], lower_mac[5]
        );
    }
    json.AddObject(json_flow, _lower_mac, mac_addr);

    if (privacy_mask & PRIVATE_UPPER)
        snprintf(mac_addr, sizeof(mac_addr), "0a:0b:0c:0d:0e:0f");
    else {
        snprintf(mac_addr, sizeof(mac_addr), "%02x:%02x:%02x:%02x:%02x:%02x",
            upper_mac[0], upper_mac[1], upper_mac[2],
            upper_mac[3], upper_mac[4], upper_mac[5]
        );
    }
    json.AddObject(json_flow, _upper_mac, mac_addr);

    if (privacy_mask & PRIVATE_LOWER) {
        if (ip_version == 4)
            json.AddObject(json_flow, _lower_ip, "1.2.3.1");
        else
            json.AddObject(json_flow, _lower_ip, "1230::1");
    }
    else
        json.AddObject(json_flow, _lower_ip, lower_ip);

    if (privacy_mask & PRIVATE_UPPER) {
        if (ip_version == 4)
            json.AddObject(json_flow, _upper_ip, "1.2.3.2");
        else
            json.AddObject(json_flow, _upper_ip, "1230::2");
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

    json.AddObject(json_flow, "detected_service",
        (int32_t)detected_protocol.app_protocol);
    json.AddObject(json_flow, "detected_service_name",
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
    json.AddObject(json_flow, "last_seen_at", ts_last_seen);

    return json_flow;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
