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
#include <sstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <unordered_map>
#include <vector>
#ifdef HAVE_ATOMIC
#include <atomic>
#else
typedef bool atomic_bool;
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <stdio.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include <arpa/inet.h>

#define __FAVOR_BSD 1
#include <netinet/in.h>

#include <json.h>
#include <pcap/pcap.h>

using namespace std;

#include "netifyd.h"

#include "nd-json.h"
#include "nd-dns-cache.h"
#include "nd-sha1.h"
#include "nd-util.h"

extern nd_global_config nd_config;

void nd_dns_cache::insert(sa_family_t af, const uint8_t *addr, const string &hostname)
{
    sha1 ctx;
    string digest;
    uint8_t _digest[SHA1_DIGEST_LENGTH];

    sha1_init(&ctx);
    sha1_write(&ctx, (const char *)addr, (af == AF_INET) ?
        sizeof(struct in_addr) : sizeof(struct in6_addr));
    digest.assign((const char *)sha1_result(&ctx, _digest), SHA1_DIGEST_LENGTH);

    pthread_mutex_lock(&lock);

    nd_dns_tuple ar(time_t(time(NULL) + nd_config.ttl_dns_entry), hostname);
    nd_dns_cache_insert i = map_ar.insert(nd_dns_cache_insert_pair(digest, ar));

    if (! i.second)
        i.first->second.first = time(NULL) + nd_config.ttl_dns_entry;

    pthread_mutex_unlock(&lock);
}

void nd_dns_cache::insert(const string &digest, const string &hostname)
{
    int i = 0;
    uint8_t v;
    const char *p = digest.c_str();
    string _digest;

    // TODO: Verify length of digest (must be SHA1_DIGEST_LENGTH).

    do {
        if (sscanf(p, "%2hhx", &v) != 1) break;
        _digest.append(1, v);
        p += 2;
    }
    while (++i < SHA1_DIGEST_LENGTH);

    if (_digest.size() != SHA1_DIGEST_LENGTH) return;

    nd_dns_tuple ar(time_t(time(NULL) + nd_config.ttl_dns_entry), hostname);
    map_ar.insert(nd_dns_cache_insert_pair(_digest, ar));
}

bool nd_dns_cache::lookup(const struct in_addr &addr, string &hostname)
{
    sha1 ctx;
    string digest;
    uint8_t _digest[SHA1_DIGEST_LENGTH];

    sha1_init(&ctx);
    sha1_write(&ctx, (const char *)&addr, sizeof(struct in_addr));
    digest.assign((const char *)sha1_result(&ctx, _digest), SHA1_DIGEST_LENGTH);

    return lookup(digest, hostname);
}

bool nd_dns_cache::lookup(const struct in6_addr &addr, string &hostname)
{
    sha1 ctx;
    string digest;
    uint8_t _digest[SHA1_DIGEST_LENGTH];

    sha1_init(&ctx);
    sha1_write(&ctx, (const char *)&addr, sizeof(struct in6_addr));
    digest.assign((const char *)sha1_result(&ctx, _digest), SHA1_DIGEST_LENGTH);

    return lookup(digest, hostname);
}

bool nd_dns_cache::lookup(const string &digest, string &hostname)
{
    bool found = false;

    pthread_mutex_lock(&lock);

    nd_dns_ar::iterator i = map_ar.find(digest);
    if (i != map_ar.end()) {
        found = true;
        hostname = i->second.second;
        i->second.first = time(NULL) + nd_config.ttl_dns_entry;
    }

    pthread_mutex_unlock(&lock);

    return found;
}

size_t nd_dns_cache::purge(void)
{
    size_t purged = 0, remaining = 0;

    pthread_mutex_lock(&lock);

    nd_dns_ar::iterator i = map_ar.begin();
    while (i != map_ar.end()) {
        if (i->second.first < time(NULL)) {
            i = map_ar.erase(i);
            purged++;
        }
        else
            i++;
    }

    remaining = map_ar.size();

    pthread_mutex_unlock(&lock);

    if (purged > 0 && remaining > 0)
        nd_debug_printf("Purged %u DNS cache entries, %u active.\n", purged, remaining);

    return purged;
}

void nd_dns_cache::load(void)
{
    int rc;
    time_t ttl;
    char header[1024], *host, *digest;
    size_t loaded = 0, line = 1;

    FILE *h_f = fopen(ND_DNS_CACHE_FILE_NAME, "r");
    if (! h_f) return;

    if (fgets(header, sizeof(header), h_f) == NULL) { fclose(h_f); return; }

    pthread_mutex_lock(&lock);

    while (! feof(h_f)) {
        line++;
        if ((rc = fscanf(h_f,
            " \"%m[0-9A-z.-]\" , %m[0-9A-Fa-f] , %ld\n",
            &host, &digest, &ttl)) != 3) {
            nd_printf("%s: parse error at line #%u [%d]\n",
                ND_DNS_CACHE_FILE_NAME, line, rc);
            if (rc >= 1) free(host);
            if (rc >= 2) free(digest);
            break;
        }

        insert(digest, host);

        free(host);
        free(digest);

        loaded++;
    }

    nd_debug_printf("Loaded %u of %u DNS cache entries.\n", map_ar.size(), loaded);

    pthread_mutex_unlock(&lock);

    fclose(h_f);
}

void nd_dns_cache::save(void)
{
    string digest;

    FILE *h_f = fopen(ND_DNS_CACHE_FILE_NAME, "w");
    if (! h_f) return;

    pthread_mutex_lock(&lock);

    fprintf(h_f, "\"host\",\"addr_digest\",\"ttl\"\n");

    for (nd_dns_ar::iterator i = map_ar.begin();
        i != map_ar.end(); i++) {
        nd_sha1_to_string((const uint8_t *)i->first.c_str(), digest);
        fprintf(h_f, "\"%s\",%s,%u\n", i->second.second.c_str(),
            digest.c_str(), (unsigned)(i->second.first - time(NULL)));
    }

    pthread_mutex_unlock(&lock);

    fclose(h_f);
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
