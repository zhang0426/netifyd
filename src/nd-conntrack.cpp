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

#include <map>
#include <set>
#include <stdexcept>
#include <unordered_map>
#include <vector>

#include <sys/stat.h>
#include <sys/select.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

using namespace std;

#include "ndpi_api.h"

#include "netifyd.h"
#include "nd-util.h"
#include "nd-thread.h"
#include "nd-conntrack.h"

extern bool nd_debug;

static int nd_ct_event_callback(
    enum nf_conntrack_msg_type type, struct nf_conntrack *ct, void *data)
{
    ndConntrackThread *thread = reinterpret_cast<ndConntrackThread *>(data);
    thread->ProcessConntrackEvent(type, ct);

    return NFCT_CB_STOP;
}

static int nd_ct_netlink_callback(const struct nlmsghdr *nlh, void *data)
{
    struct nf_conntrack *ct = nfct_new();

    if (ct == NULL)
        throw ndConntrackSystemException(__PRETTY_FUNCTION__, "nfct_new", errno);

    if (nfct_nlmsg_parse(nlh, ct) == 0) {
        ndConntrackThread *thread = reinterpret_cast<ndConntrackThread *>(data);
        thread->ProcessConntrackEvent(NFCT_T_UNKNOWN, ct);
    }

    nfct_destroy(ct);

    return MNL_CB_OK;
}

ndConntrackThread::ndConntrackThread()
    : ctfd(-1), cth(NULL), terminate(false), cb_registered(-1), lock(NULL),
    ndThread("nd-conntrack", -1)
{
    int rc;

    cth = nfct_open(NFNL_SUBSYS_CTNETLINK, NFCT_ALL_CT_GROUPS);
    if (cth == NULL) {
        if (errno == EPROTONOSUPPORT) {
            nd_printf("%s: nfnetlink kernel module not loaded?\n",
                tag.c_str());
        }
        throw ndConntrackSystemException(__PRETTY_FUNCTION__, "nfct_open", errno);
    }

    ctfd = nfct_fd(cth);

    if ((cb_registered = nfct_callback_register(
        cth,
        NFCT_T_ALL,
        nd_ct_event_callback,
        (void *)this)) < 0) {
        throw ndConntrackSystemException(
            __PRETTY_FUNCTION__, "nfct_callback_register", errno);
    }

    lock = new pthread_mutex_t;
    if ((rc = pthread_mutex_init(lock, NULL)) != 0) {
        delete lock;
        lock = NULL;
        throw ndConntrackSystemException(
            __PRETTY_FUNCTION__, "pthread_mutex_init", rc);
    }

    DumpConntrackTable();

    if (nd_debug)
        nd_printf("%s: Created.\n", tag.c_str());
}

ndConntrackThread::~ndConntrackThread()
{
    terminate = true;

    Join();

    if (cth != NULL) {
        if (cb_registered != -1)
            nfct_callback_unregister(cth);
        nfct_close(cth);
    }

    if (lock != NULL) {
        pthread_mutex_destroy(lock);
        delete lock;
        lock = NULL;
    }

    if (nd_debug)
        nd_printf("%s: Destroyed.\n", tag.c_str());
}

void ndConntrackThread::DumpConntrackTable(void)
{
    int rc;
    struct mnl_socket *nl;
    struct nlmsghdr *nlh;
    struct nfgenmsg *nfh;
    char buffer[MNL_SOCKET_BUFFER_SIZE];
    unsigned int seq, portid;

    nl = mnl_socket_open(NETLINK_NETFILTER);
    if (nl == NULL) {
        throw ndConntrackSystemException(
            __PRETTY_FUNCTION__, "mnl_socket_open", errno);
    }

    if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0) {
        throw ndConntrackSystemException(
            __PRETTY_FUNCTION__, "mnl_socket_bind", errno);
    }

    portid = mnl_socket_get_portid(nl);

    nlh = mnl_nlmsg_put_header(buffer);
    nlh->nlmsg_type = (NFNL_SUBSYS_CTNETLINK << 8) | IPCTNL_MSG_CT_GET;
    nlh->nlmsg_flags = NLM_F_REQUEST|NLM_F_DUMP;
    nlh->nlmsg_seq = seq = time(NULL);

    nfh = (struct nfgenmsg *)mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg));
    nfh->nfgen_family = AF_UNSPEC;
    nfh->version = NFNETLINK_V0;
    nfh->res_id = 0;

    rc = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
    if (rc == -1) {
        throw ndConntrackSystemException(
            __PRETTY_FUNCTION__, "mnl_socket_sendto", errno);
    }

    rc = mnl_socket_recvfrom(nl, buffer, sizeof(buffer));
    while (rc > 0) {
        rc = mnl_cb_run(buffer, rc, seq, portid, nd_ct_netlink_callback, this);
        if (rc <= MNL_CB_STOP)
            break;
        rc = mnl_socket_recvfrom(nl, buffer, sizeof(buffer));
    }

    if (rc == -1) {
        throw ndConntrackSystemException(
            __PRETTY_FUNCTION__, "mnl_socket_recvfrom", errno);
    }

    mnl_socket_close(nl);

    if (nd_debug)
        nd_printf("%s: pre-loaded %lu conntrack entries.\n", tag.c_str(), ct_id_map.size());
}

void *ndConntrackThread::Entry(void)
{
    int rc;
    struct timeval tv;

    while (!terminate) {
        fd_set fds_read;

        FD_ZERO(&fds_read);
        FD_SET(ctfd, &fds_read);

        memset(&tv, 0, sizeof(struct timeval));
        tv.tv_sec = 1;

        rc = select(ctfd + 1, &fds_read, NULL, NULL, &tv);

        if (rc == -1)
            throw ndConntrackSystemException(__PRETTY_FUNCTION__, "select", errno);

        if (FD_ISSET(ctfd, &fds_read)) {
            if (nfct_catch(cth) < 0) {
                throw ndConntrackSystemException(
                    __PRETTY_FUNCTION__, "nfct_catch", errno);
            }
        }
    }

    if (nd_debug)
        nd_printf("%s: Exit.\n", tag.c_str());
    return NULL;
}

void ndConntrackThread::ProcessConntrackEvent(
    enum nf_conntrack_msg_type type, struct nf_conntrack *ct)
{
    sha1 ctx;
    string digest;
    uint8_t *_digest;
    sa_family_t af;

    if (!nfct_attr_is_set(ct, ATTR_ORIG_L3PROTO)) {
        nd_printf("%s: ATTR_ORIG_L3PROTO not set.\n", tag.c_str());
        return;
    }

    af = nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO);
    if (af != AF_INET && af != AF_INET6) {
        nd_printf("%s: Unsupported address familty: %d\n", tag.c_str(), af);
        return;
    }

    sha1_init(&ctx);
    sha1_write(&ctx, (const char *)&af, sizeof(sa_family_t));

    switch (af) {
    case AF_INET:
        if (nfct_attr_is_set(ct, ATTR_ORIG_IPV4_SRC)) {
            sha1_write(&ctx,
                (const char *)nfct_get_attr(ct, ATTR_ORIG_IPV4_SRC),
                sizeof(uint32_t));
        }
        if (nfct_attr_is_set(ct, ATTR_ORIG_IPV4_DST)) {
            sha1_write(&ctx,
                (const char *)nfct_get_attr(ct, ATTR_ORIG_IPV4_DST),
                sizeof(uint32_t));
        }
        break;
    case AF_INET6:
        if (nfct_attr_is_set(ct, ATTR_ORIG_IPV6_SRC)) {
            sha1_write(&ctx,
                (const char *)nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC),
                sizeof(uint32_t) * 4);
        }
        if (nfct_attr_is_set(ct, ATTR_ORIG_IPV6_DST)) {
            sha1_write(&ctx,
                (const char *)nfct_get_attr(ct, ATTR_ORIG_IPV6_DST),
                sizeof(uint32_t) * 4);
        }
        break;
    default:
        nd_printf("%s: Unsupported address familty: %d\n", tag.c_str(), af);
        return;
    }

    if (nfct_attr_is_set(ct, ATTR_ORIG_PORT_SRC)) {
        sha1_write(&ctx,
            (const char *)nfct_get_attr(ct, ATTR_ORIG_PORT_SRC), sizeof(uint16_t));
    }
    if (nfct_attr_is_set(ct, ATTR_ORIG_PORT_DST)) {
        sha1_write(&ctx,
            (const char *)nfct_get_attr(ct, ATTR_ORIG_PORT_DST), sizeof(uint16_t));
    }

    if ((nfct_get_attr_u32(ct, ATTR_STATUS) & IPS_SEEN_REPLY) &&
        nfct_attr_is_set(ct, ATTR_REPL_L3PROTO)) {

        af = nfct_get_attr_u8(ct, ATTR_REPL_L3PROTO);
        sha1_write(&ctx, (const char *)&af, sizeof(sa_family_t));

        switch (af) {
        case AF_INET:
            if (nfct_attr_is_set(ct, ATTR_REPL_IPV4_SRC)) {
                sha1_write(&ctx,
                    (const char *)nfct_get_attr(ct, ATTR_REPL_IPV4_SRC),
                    sizeof(uint32_t));
            }
            if (nfct_attr_is_set(ct, ATTR_REPL_IPV4_DST)) {
                sha1_write(&ctx,
                    (const char *)nfct_get_attr(ct, ATTR_REPL_IPV4_DST),
                    sizeof(uint32_t));
            }
            break;
        case AF_INET6:
            if (nfct_attr_is_set(ct, ATTR_REPL_IPV6_SRC)) {
                sha1_write(&ctx,
                    (const char *)nfct_get_attr(ct, ATTR_REPL_IPV6_SRC),
                    sizeof(uint32_t) * 4);
            }
            if (nfct_attr_is_set(ct, ATTR_REPL_IPV6_DST)) {
                sha1_write(&ctx,
                    (const char *)nfct_get_attr(ct, ATTR_REPL_IPV6_DST),
                    sizeof(uint32_t) * 4);
            }
            break;
        default:
            nd_printf("%s: Unsupported address familty: %d\n", tag.c_str(), af);
            return;
        }
    }

    if (nfct_attr_is_set(ct, ATTR_REPL_PORT_SRC)) {
        sha1_write(&ctx,
            (const char *)nfct_get_attr(ct, ATTR_REPL_PORT_SRC), sizeof(uint16_t));
    }
    if (nfct_attr_is_set(ct, ATTR_REPL_PORT_DST)) {
        sha1_write(&ctx,
            (const char *)nfct_get_attr(ct, ATTR_REPL_PORT_DST), sizeof(uint16_t));
    }

    _digest = sha1_result(&ctx);
    digest.assign((const char *)_digest, SHA1_DIGEST_LENGTH);

    pthread_mutex_lock(lock);

    bool ct_new_or_update = true, ct_exists = false;
    uint32_t id = nfct_get_attr_u32(ct, ATTR_ID);
    nd_ct_id_map::iterator i = ct_id_map.find(id);

    if (i != ct_id_map.end()) ct_exists = true;

    if (type & NFCT_T_DESTROY) {
        ct_new_or_update = false;
        if (ct_exists) ct_id_map.erase(i);
    }

    if (ct_new_or_update) ct_id_map[id] = digest;

    pthread_mutex_unlock(lock);

    if (nd_debug) {
        char buffer[1024];
        nfct_snprintf(buffer, sizeof(buffer), ct, type, NFCT_O_PLAIN, NFCT_OF_TIME);

        if (!ct_new_or_update && !ct_exists)
            nd_printf("%s: [%u] %s\n", tag.c_str(), id, buffer);
        /*
        nd_printf("%s: [%s %u] %s\n", tag.c_str(),
            (ct_new_or_update && !ct_exists) ?
                "INSERT" : (ct_new_or_update && ct_exists) ?
                "UPDATE" : (ct_exists && !ct_new_or_update) ?
                "ERASE" : "UNKNOWN", id, buffer);
        */
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
