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
#include <unordered_map>
#include <sstream>
#include <regex>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

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

#include "nd-fhc.h"

extern nd_global_config nd_config;

ndFlowHashCache::ndFlowHashCache(size_t cache_size)
    : cache_size(cache_size)
{
    int rc;

    if ((rc = pthread_mutex_init(&lock, NULL)) != 0)
        throw ndSystemException(__PRETTY_FUNCTION__, "pthread_mutex_init", rc);
}

ndFlowHashCache::~ndFlowHashCache()
{
    pthread_mutex_destroy(&lock);
}

void ndFlowHashCache::push(const string &lower_hash, const string &upper_hash)
{
    int rc;

    if ((rc = pthread_mutex_lock(&lock)) != 0)
        throw ndSystemException(__PRETTY_FUNCTION__, "pthread_mutex_lock", rc);

    nd_fhc_map::const_iterator i = lookup.find(lower_hash);

    if (i != lookup.end()) {
        nd_debug_printf("WARNING: Found existing hash in flow hash cache on push.\n");
    }
    else {
        if (lookup.size() == cache_size) {
//#if _ND_DEBUG_FHC
            nd_debug_printf("Purging old flow hash cache entries.\n");
//#endif
            for (size_t n = 0; n < cache_size / nd_config.fhc_purge_divisor; n++) {
                pair<string, string> j = index.back();

                nd_fhc_map::iterator k = lookup.find(j.first);
                if (k == lookup.end()) {
                    nd_debug_printf("WARNING: flow hash cache index not found in map\n");
                }
                else
                    lookup.erase(k);

                index.pop_back();
            }
        }

        index.push_front(make_pair(lower_hash, upper_hash));
        lookup[lower_hash] = index.begin();
#if _ND_DEBUG_FHC
        nd_debug_printf("Flow hash cache entries: %lu\n", lookup.size());
#endif
    }

    if ((rc = pthread_mutex_unlock(&lock)) != 0)
        throw ndSystemException(__PRETTY_FUNCTION__, "pthread_mutex_unlock", rc);
}

bool ndFlowHashCache::pop(const string &lower_hash, string &upper_hash)
{
    int rc;
    bool found = false;

    if ((rc = pthread_mutex_lock(&lock)) != 0)
        throw ndSystemException(__PRETTY_FUNCTION__, "pthread_mutex_lock", rc);

    nd_fhc_map::iterator i = lookup.find(lower_hash);

    if ((found = i != lookup.end())) {

        upper_hash = i->second->second;

        index.erase(i->second);

        index.push_front(make_pair(lower_hash, upper_hash));

        i->second = index.begin();
    }

    if ((rc = pthread_mutex_unlock(&lock)) != 0)
        throw ndSystemException(__PRETTY_FUNCTION__, "pthread_mutex_unlock", rc);

    return found;
}

void ndFlowHashCache::save(void)
{
    ostringstream os;

    switch (nd_config.fhc_save) {
    case ndFHC_PERSISTENT:
        os << ND_PERSISTENT_STATEDIR << ND_FLOW_HC_FILE_NAME;
        break;
    case ndFHC_VOLATILE:
        os << ND_VOLATILE_STATEDIR << ND_FLOW_HC_FILE_NAME;
        break;
    default:
        return;
    }

    FILE *hf = fopen(os.str().c_str(), "wb");
    if (hf == NULL) {
        nd_printf("WARNING: Error saving flow hash cache: %s: %s\n",
            os.str().c_str(), strerror(errno));
        return;
    }

    nd_fhc_list::iterator i;
    for (i = index.begin(); i != index.end(); i++) {
        fwrite((*i).first.c_str(), 1, SHA1_DIGEST_LENGTH, hf);
        fwrite((*i).second.c_str(), 1, SHA1_DIGEST_LENGTH, hf);
    }
    fclose(hf);

    nd_debug_printf("Saved %lu flow hash cache entries.\n", index.size ());
}

void ndFlowHashCache::load(void)
{
    ostringstream os;

    switch (nd_config.fhc_save) {
    case ndFHC_PERSISTENT:
        os << ND_PERSISTENT_STATEDIR << ND_FLOW_HC_FILE_NAME;
        break;
    case ndFHC_VOLATILE:
        os << ND_VOLATILE_STATEDIR << ND_FLOW_HC_FILE_NAME;
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

    nd_debug_printf("Loaded %lu flow hash cache entries.\n", index.size());
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
