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

#include <linux/if_ether.h>
#include <linux/netlink.h>

#include "ndpi_main.h"

using namespace std;

#include "nd-netlink.h"
#include "nd-flow.h"
#include "nd-sha1.h"
#include "nd-util.h"

void ndFlow::hash(const string &device, string &digest, bool full_hash)
{
    sha1 ctx;
    uint8_t *_digest;

    sha1_init(&ctx);
    sha1_write(&ctx, (const char *)device.c_str(), device.size());

    sha1_write(&ctx, (const char *)&version, sizeof(version));
    sha1_write(&ctx, (const char *)&protocol, sizeof(protocol));
    sha1_write(&ctx, (const char *)&vlan_id, sizeof(vlan_id));

    sha1_write(&ctx, (const char *)&lower_mac, ETH_ALEN);
    sha1_write(&ctx, (const char *)&upper_mac, ETH_ALEN);

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

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
