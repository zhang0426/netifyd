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

#include <vector>
#include <map>
#include <unordered_map>
#include <stdexcept>

#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>

#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

using namespace std;

#include "ndpi_api.h"

#include "netifyd.h"
#include "nd-thread.h"
#include "nd-conntrack.h"
#include "nd-util.h"

extern bool nd_debug;

static int nd_conntrack_callback(
    enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data)
{
    ndThread *thread = reinterpret_cast<ndThread *>(data);

    if (nd_debug) {
        char buffer[1024];
        nfct_snprintf(buffer, sizeof(buffer), ct, type, NFCT_O_PLAIN, NFCT_OF_TIME);

        nd_printf("%s: %s\n", thread->GetTag().c_str(), buffer);
    }

    return NFCT_CB_STOP;
}

ndConntrackThread::ndConntrackThread()
    : cth(NULL), terminate(false), cb_registered(-1),
    ndThread("netify-cntrk", -1)
{
    int rc;

    cth = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
    if (cth == NULL) throw ndConntrackThreadException(strerror(errno));

    if ((cb_registered = nfct_callback_register(
        cth,
        NFCT_T_ALL,
        nd_conntrack_callback,
        (void *)this)) < 0)
        throw ndConntrackThreadException(strerror(errno));

    if (nd_debug)
        nd_printf("%s: Created.\n", tag.c_str());
}

ndConntrackThread::~ndConntrackThread()
{
    if (cth != NULL) {
        if (cb_registered != -1)
            nfct_callback_unregister(cth);
        nfct_close(cth);
    }

    if (nd_debug)
        nd_printf("%s: Destroyed.\n", tag.c_str());
}

void *ndConntrackThread::Entry(void)
{
    int rc;

    while (!terminate) {
        if (nfct_catch(cth) < 0) {
            nd_printf("%s: nfct_catch: %s\n", strerror(errno));
            break; 
        }
    }

    if (nd_debug)
        nd_printf("%s: Exit.\n", tag.c_str());
    return NULL;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
