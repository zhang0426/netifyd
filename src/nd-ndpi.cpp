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

#include <string>
#include <vector>
#include <map>
#include <unordered_map>
#include <stdexcept>
#ifdef HAVE_ATOMIC
#include <atomic>
#endif
#include <regex>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <errno.h>

#include <sys/stat.h>
#include <sys/un.h>

#include <arpa/inet.h>

#include <pcap/pcap.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

using namespace std;

#include "netifyd.h"

#include "nd-thread.h"
#include "nd-json.h"
#include "nd-util.h"
#include "nd-ndpi.h"

extern nd_global_config nd_config;

static pthread_mutex_t *ndpi_host_automa_lock = NULL;
static struct ndpi_detection_module_struct *ndpi_parent = NULL;

void ndpi_global_init(void)
{
    struct stat path_sink_config_stat;

    set_ndpi_malloc(nd_mem_alloc);
    set_ndpi_free(nd_mem_free);

    ndpi_parent = ndpi_init_detection_module();

    if (ndpi_parent == NULL)
        throw ndThreadException("Detection module initialization failure");

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
    ndpi_parent->ndpi_log_level = NDPI_LOG_TRACE;
    //ndpi_parent->ndpi_log_level = NDPI_LOG_DEBUG_EXTRA;
    set_ndpi_debug_function(ndpi_parent, nd_ndpi_debug_printf);
#endif

    if (ndpi_parent->host_automa.ac_automa == NULL)
        throw ndThreadException("Detection host_automa initialization failure");

    ndpi_host_automa_lock = new pthread_mutex_t;
    if (pthread_mutex_init(ndpi_host_automa_lock, NULL) != 0)
        throw ndThreadException("Unable to initialize pthread_mutex");
    ndpi_parent->host_automa.lock = ndpi_host_automa_lock;

    if (ndpi_parent->protocols_ptree == NULL) {
        ndpi_parent->protocols_ptree = ndpi_init_ptree(32); // 32-bit for IPv4
        if (ndpi_parent->protocols_ptree == NULL)
            throw ndThreadException("Unable to initialize proto_ptree");
    }

    ndpi_init_string_based_protocols(ndpi_parent);

    NDPI_PROTOCOL_BITMASK proto_all;
    NDPI_BITMASK_SET_ALL(proto_all);

    ndpi_set_protocol_detection_bitmask2(ndpi_parent, &proto_all);

    if (nd_config.path_sink_config != NULL &&
        stat(nd_config.path_sink_config, &path_sink_config_stat) == 0) {
        nd_debug_printf("Loading custom protocols from%s: %s\n",
            ND_OVERRIDE_SINK_CONFIG ? " override" : "",
            nd_config.path_sink_config);
        ndpi_load_protocols_file(ndpi_parent, nd_config.path_sink_config);
    }
}

void ndpi_global_destroy(void)
{
    pthread_mutex_destroy(ndpi_host_automa_lock);
    delete ndpi_host_automa_lock;
    ndpi_host_automa_lock = NULL;

    ndpi_exit_detection_module(ndpi_parent);
    ndpi_parent = NULL;
}

struct ndpi_detection_module_struct *ndpi_get_parent(void)
{
    return ndpi_parent;
}

struct ndpi_detection_module_struct *nd_ndpi_init(
    const string &tag __attribute__((unused)), uint32_t &custom_proto_base)
{
    struct ndpi_detection_module_struct *ndpi = NULL;

    ndpi = ndpi_init_detection_module();

    if (ndpi == NULL)
        throw ndThreadException("Detection module initialization failure");

    custom_proto_base = ndpi->ndpi_num_supported_protocols;

    // Set nDPI preferences
    ndpi_set_detection_preferences(ndpi, ndpi_pref_http_dont_dissect_response, 0);
    ndpi_set_detection_preferences(ndpi, ndpi_pref_dns_dont_dissect_response, 0);
    ndpi_set_detection_preferences(ndpi, ndpi_pref_direction_detect_disable, 0);
    ndpi_set_detection_preferences(ndpi, ndpi_pref_disable_metadata_export, 0);
    ndpi_set_detection_preferences(ndpi, ndpi_pref_enable_category_substring_match, 0);

    if (ndpi->host_automa.ac_automa != NULL)
        ndpi_free_automa(ndpi->host_automa.ac_automa);

    if (ndpi->protocols_ptree != NULL)
        ndpi_free_ptree(ndpi->protocols_ptree);

    ndpi->host_automa.ac_automa = ndpi_parent->host_automa.ac_automa;
    ndpi->host_automa.lock = ndpi_parent->host_automa.lock;
    ndpi->protocols_ptree = ndpi_parent->protocols_ptree;

    //ndpi_init_string_based_protocols(ndpi);

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
    ndpi->ndpi_log_level = NDPI_LOG_TRACE;
    //ndpi->ndpi_log_level = NDPI_LOG_DEBUG_EXTRA;
    set_ndpi_debug_function(ndpi, nd_ndpi_debug_printf);
#endif

    NDPI_PROTOCOL_BITMASK proto_all;
    NDPI_BITMASK_SET_ALL(proto_all);

    ndpi_set_protocol_detection_bitmask2(ndpi, &proto_all);

    for (int i = 0;
        i < NDPI_MAX_SUPPORTED_PROTOCOLS + NDPI_MAX_NUM_CUSTOM_PROTOCOLS;
        i++) {

        if (ndpi->proto_defaults[i].proto_name != NULL)
            ndpi_free(ndpi->proto_defaults[i].proto_name);

        memcpy(&ndpi->proto_defaults[i], &ndpi_parent->proto_defaults[i],
            sizeof(ndpi_proto_defaults_t));

        if (ndpi->proto_defaults[i].proto_name != NULL) {
            ndpi->proto_defaults[i].proto_name = ndpi_strdup(
                ndpi_parent->proto_defaults[i].proto_name
            );
        }
    }

    ndpi_tdestroy(ndpi->udp_root_node, ndpi_free);
    ndpi_tdestroy(ndpi->tcp_root_node, ndpi_free);

    ndpi->udp_root_node = ndpi_parent->udp_root_node;
    ndpi->tcp_root_node = ndpi_parent->tcp_root_node;

    ndpi->ndpi_num_supported_protocols = ndpi_parent->ndpi_num_supported_protocols;
    ndpi->ndpi_num_custom_protocols = ndpi_parent->ndpi_num_custom_protocols;

    return ndpi;
}

void nd_ndpi_free(struct ndpi_detection_module_struct *ndpi)
{
    ndpi->host_automa.ac_automa = NULL;
    ndpi->protocols_ptree = NULL;
    ndpi->udp_root_node = NULL;
    ndpi->tcp_root_node = NULL;

    ndpi_exit_detection_module(ndpi);
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
