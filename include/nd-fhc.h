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

#ifndef _ND_FLOW_HASH_CACHE_H
#define _ND_FLOW_HASH_CACHE_H

// Hash cache filename
#define ND_FLOW_HC_FILE_NAME        "/flow-hash-cache.dat"

typedef list<pair<string, string>> nd_fhc_list;
typedef unordered_map<string, nd_fhc_list::iterator> nd_fhc_map;

class ndFlowHashCache
{
public:
    ndFlowHashCache(size_t cache_size = ND_MAX_FHC_ENTRIES);
    virtual ~ndFlowHashCache();

    void push(const string &lower_hash, const string &upper_hash);
    bool pop(const string &lower_hash, string &upper_hash);

    void save(void);
    void load(void);

protected:
    pthread_mutex_t lock;

    size_t cache_size;
    nd_fhc_list index;
    nd_fhc_map lookup;
};

#endif // _ND_FLOW_HASH_CACHE_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
