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

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <stdexcept>
#include <atomic>

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>

#include <sys/stat.h>
#include <sys/un.h>

#include <arpa/inet.h>

extern "C" {
#include "ndpi_api.h"
}

using namespace std;

#include "netifyd.h"
#include "nd-util.h"
#include "nd-thread.h"

extern nd_global_config nd_config;

static atomic_int ndpi_ref_count(0);
static void *ndpi_host_automa = NULL;
static pthread_mutex_t *ndpi_host_automa_lock = NULL;
static void *ndpi_proto_ptree = NULL;
static struct ndpi_detection_module_struct *ndpi_parent = NULL;

static void nd_ndpi_load_content_match(
    const string &tag, struct ndpi_detection_module_struct *ndpi)
{
    int rc;
    unsigned loaded = 0, line = 1;
    char header[1024], *match, *name;
    ndpi_protocol_match content_match;
    FILE *fp = fopen(nd_config.path_content_match, "r");

    if (fp == NULL) {
        nd_debug_printf("%s: unable to open content match file: %s\n",
            tag.c_str(), nd_config.path_content_match);
        return;
    }

    content_match.protocol_breed = NDPI_PROTOCOL_UNRATED;

    if (fgets(header, 1024, fp) == NULL) { fclose(fp); return; }

    while (! feof(fp)) {
        line++;
        if ((rc = fscanf(fp,
            " \"%m[0-9A-z*$^.-]\" , \"%m[0-9A-z_.()-]\" , %u\n",
            &match, &name, &content_match.protocol_id)) != 3) {
            nd_printf("%s: %s: parse error at line #%u [%d]\n",
                tag.c_str(), nd_config.path_content_match, line, rc);
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

    nd_debug_printf("%s: loaded %u content match records from: %s\n",
        tag.c_str(), loaded, nd_config.path_content_match);
}

static void nd_ndpi_load_host_match(
    const string &tag, struct ndpi_detection_module_struct *ndpi)
{
    int rc;
    char header[1024];
    char *ip_address;
    struct sockaddr_in saddr_ip4;
    struct sockaddr_in6 saddr_ip6;
    unsigned loaded = 0, line = 1;
    ndpi_network host_entry;
    FILE *fp = fopen(nd_config.path_host_match, "r");

    if (fp == NULL) {
        nd_debug_printf("%s: unable to open host protocol file: %s\n",
            tag.c_str(), nd_config.path_host_match);
        return;
    }

    if (fgets(header, 1024, fp) == NULL) { fclose(fp); return; }

    while (! feof(fp)) {
        line++;
        if ((rc = fscanf(fp,
            " \"%m[0-9A-f:.]\" , %hhu , %hhu\n",
            &ip_address, &host_entry.cidr, &host_entry.value)) != 3) {
            nd_printf("%s: %s: parse error at line #%u [%d]\n",
                tag.c_str(), nd_config.path_host_match, line, rc);
            if (rc >= 1) free(ip_address);
            break;
        }

        if (inet_pton(AF_INET6, ip_address, &saddr_ip6.sin6_addr) == 1) {
            // TODO: nDPI doesn't support IPv6 for host_match yet.
            nd_debug_printf("%s: %s: skipping IPv6 host protocol entry: %s/%hhu\n",
                tag.c_str(), nd_config.path_host_match, ip_address, host_entry.cidr);
        }
        else if (inet_pton(AF_INET, ip_address, &saddr_ip4.sin_addr) == 1) {
            host_entry.network = ntohl(saddr_ip4.sin_addr.s_addr);
            ndpi_add_to_ptree_ipv4(ndpi, ndpi->protocols_ptree, &host_entry);

            loaded++;
        }

        free(ip_address);
    }

    fclose(fp);

    nd_debug_printf("%s: loaded %u host protocol records from: %s\n",
        tag.c_str(), loaded, nd_config.path_host_match);
}

struct ndpi_detection_module_struct *nd_ndpi_init(
    const string &tag, uint32_t &custom_proto_base)
{
    struct stat path_custom_match_stat;
    struct ndpi_detection_module_struct *ndpi = NULL;

    ndpi = ndpi_init_detection_module();

    if (ndpi == NULL)
        throw ndThreadException("Detection module initialization failure");

    custom_proto_base = ndpi->ndpi_num_supported_protocols;

    // Enable DNS response dissection
    ndpi->dns_dissect_response = 1;

    if (ndpi_ref_count == 0) {
        ndpi_parent = ndpi;
        ndpi_host_automa = ndpi_init_automa();
        if (ndpi_host_automa == NULL)
            throw ndThreadException("Unable to initialize host_automa");
        ndpi_host_automa_lock = new pthread_mutex_t;
        if (pthread_mutex_init(ndpi_host_automa_lock, NULL) != 0)
            throw ndThreadException("Unable to initialize pthread_mutex");
        ndpi_proto_ptree = ndpi_init_ptree(32 /* IPv4 */);
        if (ndpi_proto_ptree == NULL)
            throw ndThreadException("Unable to initialize proto_ptree");
    }

    ndpi_free_automa(ndpi->host_automa.ac_automa);
    ndpi_free_ptree(ndpi->protocols_ptree);

    ndpi->host_automa.ac_automa = ndpi_host_automa;
    ndpi->host_automa.lock = ndpi_host_automa_lock;
    ndpi->protocols_ptree = ndpi_proto_ptree;

    // XXX: No longer used.
    //nd_ndpi_load_content_match(tag, ndpi);
    //nd_ndpi_load_host_match(tag, ndpi);

    ndpi_init_string_based_protocols(ndpi);

    set_ndpi_malloc(nd_mem_alloc);
    set_ndpi_free(nd_mem_free);
    set_ndpi_debug_function(ndpi, ndpi_debug_printf);

    NDPI_PROTOCOL_BITMASK proto_all;
    NDPI_BITMASK_SET_ALL(proto_all);

    ndpi_set_protocol_detection_bitmask2(ndpi, &proto_all);

    if (ndpi_ref_count == 0 && nd_config.path_custom_match != NULL &&
        stat(nd_config.path_custom_match, &path_custom_match_stat) == 0) {
        nd_debug_printf("%s: loading custom protocols from%s: %s\n",
            tag.c_str(),
            ND_OVERRIDE_CUSTOM_MATCH ? " override" : "",
            nd_config.path_custom_match);
        ndpi_load_protocols_file(ndpi, nd_config.path_custom_match);
    }

    if (ndpi_ref_count > 0) {

        for (int i = 0;
            i < NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS;
            i++) {
            memcpy(&ndpi->proto_defaults[i], &ndpi_parent->proto_defaults[i],
                sizeof(ndpi_proto_defaults_t));
            if (ndpi->proto_defaults[i].protoName != NULL) {
                ndpi->proto_defaults[i].protoName = ndpi_strdup(
                    ndpi_parent->proto_defaults[i].protoName
                );
            }
        }

        ndpi_tdestroy(ndpi->udpRoot, ndpi_free);
        ndpi_tdestroy(ndpi->tcpRoot, ndpi_free);

        ndpi->udpRoot = ndpi_parent->udpRoot;
        ndpi->tcpRoot = ndpi_parent->tcpRoot;

        ndpi->ndpi_num_supported_protocols = ndpi_parent->ndpi_num_supported_protocols;
        ndpi->ndpi_num_custom_protocols = ndpi_parent->ndpi_num_custom_protocols;
    }

    ndpi_ref_count++;

    return ndpi;
}

void nd_ndpi_free(struct ndpi_detection_module_struct *ndpi)
{
    ndpi_ref_count--;

    if (ndpi_ref_count < 0)
        throw ndThreadException("Reference count less than zero");

    if (ndpi_ref_count > 0) {
        ndpi->host_automa.ac_automa = NULL;
        ndpi->protocols_ptree = NULL;
        ndpi->udpRoot = NULL;
        ndpi->tcpRoot = NULL;
    }
    else
        pthread_mutex_destroy(ndpi_host_automa_lock);

    ndpi_exit_detection_module(ndpi);
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
