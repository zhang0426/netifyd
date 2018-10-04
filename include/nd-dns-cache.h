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

#ifndef _ND_DNS_CACHE_H
#define _ND_DNS_CACHE_H

#define ND_DNS_CACHE_FILE_NAME  ND_VOLATILE_STATEDIR "/dns-cache.csv"

typedef pair<time_t, string> nd_dns_tuple;
typedef unordered_map<string, nd_dns_tuple> nd_dns_ar;
typedef pair<nd_dns_ar::iterator, bool> nd_dns_cache_insert;
typedef pair<string, nd_dns_tuple> nd_dns_cache_insert_pair;

typedef struct nd_dns_cache_t
{
    pthread_mutex_t lock;
    nd_dns_ar map_ar;

    void insert(sa_family_t af, const uint8_t *addr, const string &hostname);
    void insert(const string &digest, const string &hostname);

    bool lookup(const struct in_addr &addr, string &hostname);
    bool lookup(const struct in6_addr &addr, string &hostname);
    bool lookup(const string &digest, string &hostname);

    size_t purge(void);

    void load(void);
    void save(void);
} nd_dns_cache;

#endif // _ND_DNS_CACHE_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
