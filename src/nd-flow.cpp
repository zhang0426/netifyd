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

#include <stdexcept>
#include <cstring>
#include <map>
#include <vector>
#include <unordered_map>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>

#include <linux/if_ether.h>
#include <linux/netlink.h>

#include <json.h>

#include "ndpi_main.h"

using namespace std;

#include "nd-netlink.h"
#include "nd-json.h"
#include "nd-flow.h"
#include "nd-sha1.h"
#include "nd-util.h"

void ndFlow::hash(const string &device, string &digest, bool full_hash)
{
    sha1 ctx;
    uint8_t *_digest;

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
        if (ssl.client_cert[0] != '\0') {
            sha1_write(&ctx,
                ssl.client_cert, strnlen(ssl.client_cert, ND_FLOW_SSL_CERTLEN));
        }
        if (ssl.server_cert[0] != '\0') {
            sha1_write(&ctx,
                ssl.server_cert, strnlen(ssl.server_cert, ND_FLOW_SSL_CERTLEN));
        }
    }

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

json_object *ndFlow::json_encode(const string &device,
    ndJson &json, struct ndpi_detection_module_struct *ndpi, bool counters)
{
    char buffer[256];
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

    json.AddObject(json_flow, "ip_version", (int32_t)ip_version);

    json.AddObject(json_flow, "ip_protocol", (int32_t)ip_protocol);

    json.AddObject(json_flow, "vlan_id", (int32_t)vlan_id);

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

    json.AddObject(json_flow, "other_type", other_type);

    snprintf(buffer, sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x",
        lower_mac[0], lower_mac[1], lower_mac[2],
        lower_mac[3], lower_mac[4], lower_mac[5]
    );
    json.AddObject(json_flow, _lower_mac, buffer);

    snprintf(buffer, sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x",
        upper_mac[0], upper_mac[1], upper_mac[2],
        upper_mac[3], upper_mac[4], upper_mac[5]
    );
    json.AddObject(json_flow, _upper_mac, buffer);

    json.AddObject(json_flow, _lower_ip, lower_ip);
    json.AddObject(json_flow, _upper_ip, upper_ip);

    json.AddObject(json_flow, _lower_port, (int32_t)ntohs(lower_port));
    json.AddObject(json_flow, _upper_port, (int32_t)ntohs(upper_port));

    if (counters) {
        json.AddObject(json_flow, _lower_bytes, lower_bytes);
        json.AddObject(json_flow, _upper_bytes, upper_bytes);
        json.AddObject(json_flow, _lower_packets, lower_packets);
        json.AddObject(json_flow, _upper_packets, upper_packets);
        json.AddObject(json_flow, "total_packets", total_packets);
        json.AddObject(json_flow, "total_bytes", total_bytes);
    }

    if (detected_protocol.master_protocol) {
        json.AddObject(json_flow, "detected_service",
            (int32_t)detected_protocol.protocol);
        json.AddObject(json_flow, "detected_protocol",
            (int32_t)detected_protocol.master_protocol);

        snprintf(buffer, sizeof(buffer), "%s.%s",
            ndpi_get_proto_name(ndpi,
                detected_protocol.master_protocol),
            ndpi_get_proto_name(ndpi,
                detected_protocol.protocol));

        json.AddObject(json_flow, "detected_protocol_name", buffer);
    }
    else {
        json.AddObject(json_flow, "detected_service", 0);
        json.AddObject(json_flow, "detected_protocol",
            (int32_t)detected_protocol.protocol);
        json.AddObject(json_flow, "detected_protocol_name",
            ndpi_get_proto_name(ndpi, detected_protocol.protocol));
    }

    json.AddObject(json_flow, "detection_guessed", detection_guessed);

    if (host_server_name[0] != '\0') {
        json.AddObject(json_flow,
            "host_server_name", host_server_name);
    }

    if ((ssl.client_cert[0] != '\0') ||
        (ssl.server_cert[0] != '\0')) {

        json_object *ssl = json.CreateObject(json_flow, "ssl");

        if (this->ssl.client_cert[0] != '\0')
            json.AddObject(ssl, "client", this->ssl.client_cert);

        if (this->ssl.server_cert[0] != '\0')
            json.AddObject(ssl, "server", this->ssl.server_cert);
    }

    json.AddObject(json_flow, "last_seen_at", ts_last_seen);

    return json_flow;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
