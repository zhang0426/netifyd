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
#include <vector>
#include <map>
#include <unordered_map>
#include <stdexcept>

#include <stdio.h>
#include <sys/stat.h>
#include <arpa/inet.h>

extern "C" {
#include "ndpi_api.h"
}

using namespace std;

#include "netifyd.h"
#include "nd-thread.h"
#include "nd-util.h"

extern bool nd_debug;

extern ndGlobalConfig nd_config;

static void nd_ndpi_load_content_match(
    const string &tag, struct ndpi_detection_module_struct *ndpi)
{
    int rc;
    unsigned loaded = 0, line = 1;
    char header[1024], *match, *name;
    ndpi_protocol_match content_match;
    FILE *fp = fopen(nd_config.csv_content_match, "r");

    if (fp == NULL) {
        if (nd_debug) {
            nd_printf("%s: unable to open content match file: %s\n",
                tag.c_str(), nd_config.csv_content_match);
        }
        return;
    }

    content_match.protocol_breed = NDPI_PROTOCOL_UNRATED;

    if (fgets(header, 1024, fp) == NULL) return;

    while (!feof(fp)) {
        line++;
        if ((rc = fscanf(fp,
            " \"%m[0-9A-z*.-]\" , \"%m[0-9A-z_.()-]\" , %u\n",
            &match, &name, &content_match.protocol_id)) != 3) {
            nd_printf("%s: %s: parse error at line #%u [%d]\n",
                tag.c_str(), nd_config.csv_content_match, line, rc);
            if (rc >= 1) free(match);
            if (rc >= 2) free(name);
            break;
        }

        content_match.string_to_match = match;
        content_match.proto_name = name;

        ndpi_init_protocol_match(ndpi, &content_match);

        free(match);
        free(name);

        loaded++;
    }

    fclose(fp);

    if (nd_debug) {
        nd_printf("%s: loaded %u content match records from: %s\n",
            tag.c_str(), loaded, nd_config.csv_content_match);
    }
}

static void nd_ndpi_load_host_protocol(
    const string &tag, struct ndpi_detection_module_struct *ndpi)
{
    int rc;
    char header[1024];
    char *ip_address;
    struct sockaddr_in saddr_ip4;
    struct sockaddr_in6 saddr_ip6;
    unsigned loaded = 0, line = 1;
    ndpi_network host_entry;
    FILE *fp = fopen(nd_config.csv_host_protocol, "r");

    if (fp == NULL) {
        if (nd_debug) {
            nd_printf("%s: unable to open host protocol file: %s\n",
                tag.c_str(), nd_config.csv_host_protocol);
        }
        return;
    }

    if (fgets(header, 1024, fp) == NULL) return;

    while (!feof(fp)) {
        line++;
        if ((rc = fscanf(fp,
            " \"%m[0-9A-f:.]\" , %hhu , %hhu\n",
            &ip_address, &host_entry.cidr, &host_entry.value)) != 3) {
            nd_printf("%s: %s: parse error at line #%u [%d]\n",
                tag.c_str(), nd_config.csv_host_protocol, line, rc);
            if (rc >= 1) free(ip_address);
            break;
        }

        if (inet_pton(AF_INET6, ip_address, &saddr_ip6.sin6_addr) == 1) {
            // TODO: nDPI doesn't support IPv6 for host_protocol yet.
            if (nd_debug) {
                nd_printf("%s: %s: skipping IPv6 host protocol entry: %s/%hhu\n",
                    tag.c_str(), nd_config.csv_host_protocol, ip_address, host_entry.cidr);
            }
        }
        else if (inet_pton(AF_INET, ip_address, &saddr_ip4.sin_addr) == 1) {
            host_entry.network = ntohl(saddr_ip4.sin_addr.s_addr);
            ndpi_add_to_ptree_ipv4(ndpi, ndpi->protocols_ptree, &host_entry);

            loaded++;
        }

        free(ip_address);
    }

    fclose(fp);

    if (nd_debug) {
        nd_printf("%s: loaded %u host protocol records from: %s\n",
            tag.c_str(), loaded, nd_config.csv_host_protocol);
    }
}

struct ndpi_detection_module_struct *nd_ndpi_init(const string &tag)
{
    struct stat proto_file_stat;
    struct ndpi_detection_module_struct *ndpi = NULL;

    ndpi = ndpi_init_detection_module();

    if (ndpi == NULL)
        throw ndThreadException("Detection module initialization failure");

    nd_ndpi_load_content_match(tag, ndpi);
    nd_ndpi_load_host_protocol(tag, ndpi);

    ndpi_init_string_based_protocols(ndpi);

    set_ndpi_malloc(nd_mem_alloc);
    set_ndpi_free(nd_mem_free);
    set_ndpi_debug_function(nd_debug_printf);

    NDPI_PROTOCOL_BITMASK proto_all;
    NDPI_BITMASK_SET_ALL(proto_all);

    ndpi_set_protocol_detection_bitmask2(ndpi, &proto_all);

    if (nd_config.proto_file != NULL &&
        stat(nd_config.proto_file, &proto_file_stat) == 0) {
        if (nd_debug) {
            nd_printf("%s: loading custom protocols from: %s\n",
                tag.c_str(), nd_config.proto_file);
        }
        ndpi_load_protocols_file(ndpi, nd_config.proto_file);
    }

    return ndpi;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
