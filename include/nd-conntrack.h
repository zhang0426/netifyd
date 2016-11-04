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

#ifndef _ND_CONNTRACK_H
#define _ND_CONNTRACK_H

class ndConntrackThreadException : public runtime_error
{
public:
    explicit ndConntrackThreadException(const string &what_arg)
        : runtime_error(what_arg) { }
};

class ndConntrackSystemException : public ndSystemException
{
public:
    explicit ndConntrackSystemException(
        const string &where_arg, const string &what_arg, int why_arg) throw()
        : ndSystemException(where_arg, what_arg, why_arg) { }
};

typedef map<uint32_t, string> nd_ct_id_map;
typedef map<string, uint32_t> nd_ct_flow_map;

class ndConntrackThread : public ndThread
{
public:
    ndConntrackThread();
    virtual ~ndConntrackThread();

    virtual void Terminate(void) { terminate = true; }

    virtual void *Entry(void);

    void ProcessConntrackEvent(
        enum nf_conntrack_msg_type type, struct nf_conntrack *ct);

protected:
    void DumpConntrackTable(void);

    int ctfd;
    nfct_handle *cth;
    bool terminate;
    int cb_registered;
    pthread_mutex_t *lock;
    nd_ct_id_map ct_id_map;
    nd_ct_flow_map ct_flow_map;
};

#endif // _ND_CONNTRACK_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
