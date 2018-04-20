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

#include <map>
#include <set>
#include <stdexcept>
#include <unordered_map>
#include <vector>
#include <sstream>
#include <atomic>

#include <sys/stat.h>
#include <sys/select.h>
#include <sys/socket.h>

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#ifdef _ND_USE_NETLINK
#include <linux/netlink.h>
#endif
#include <json.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

using namespace std;

#include "netifyd.h"
#include "nd-ndpi.h"
#include "nd-util.h"
#ifdef _ND_USE_NETLINK
#include "nd-netlink.h"
#endif
#include "nd-json.h"
#include "nd-flow.h"
#include "nd-thread.h"
#include "nd-conntrack.h"

// Enable Conntrack debug logging
//#define _ND_LOG_CONNTRACK       1
//#define _ND_LOG_CONNTRACK_INTV  15

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
    : ndThread("nd-conntrack", -1),
    ctfd(-1), cth(NULL), terminate(false), cb_registered(-1)
{
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

    DumpConntrackTable();

    nd_debug_printf("%s: Created.\n", tag.c_str());
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

    for (nd_ct_flow_map::const_iterator i = ct_flow_map.begin();
        i != ct_flow_map.end(); i++) delete i->second;

    nd_debug_printf("%s: Destroyed.\n", tag.c_str());
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
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
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

    nd_debug_printf("%s: Loaded %lu conntrack entries.\n",
        tag.c_str(), ct_id_map.size());
}

void *ndConntrackThread::Entry(void)
{
    int rc;
    struct timeval tv;
#ifdef _ND_LOG_CONNTRACK
    time_t log_stats = time(NULL) + _ND_LOG_CONNTRACK_INTV;
#endif
    while (! terminate) {
        fd_set fds_read;

        FD_ZERO(&fds_read);
        FD_SET(ctfd, &fds_read);

        memset(&tv, 0, sizeof(struct timeval));
        tv.tv_sec = 1;

        rc = select(ctfd + 1, &fds_read, NULL, NULL, &tv);

        if (rc == -1) {
            throw ndConntrackSystemException(
                __PRETTY_FUNCTION__, "select", errno);
        }

        if (FD_ISSET(ctfd, &fds_read)) {
            if (nfct_catch(cth) < 0) {
                throw ndConntrackSystemException(
                    __PRETTY_FUNCTION__, "nfct_catch", errno);
            }
        }
#ifdef _ND_LOG_CONNTRACK
        if (time(NULL) > log_stats) {
            nd_debug_printf("%s: entries: ids: %lu, flows: %lu\n",
                tag.c_str(), ct_id_map.size(), ct_flow_map.size());
            log_stats = time(NULL) + _ND_LOG_CONNTRACK_INTV;
        }
#endif
    }

    nd_debug_printf("%s: Exit.\n", tag.c_str());
    return NULL;
}

void ndConntrackThread::ProcessConntrackEvent(
    enum nf_conntrack_msg_type type, struct nf_conntrack *ct)
{
    uint32_t id = nfct_get_attr_u32(ct, ATTR_ID);
    ndConntrackFlow *ct_flow = NULL;
    nd_ct_id_map::iterator id_iter = ct_id_map.find(id);
    nd_ct_flow_map::iterator flow_iter;
#ifdef _ND_LOG_CONNTRACK
    bool ct_exists = false, ct_new_or_update = false;
#endif

    if (id_iter == ct_id_map.end()) {
        try {
            ct_flow = new ndConntrackFlow(ct);
        }
        catch (ndConntrackFlowException &e) {
            nd_printf("%s: %s.\n", tag.c_str(), e.what());
            return;
        }

        ct_id_map[id] = ct_flow->digest;
        ct_flow_map[ct_flow->digest] = ct_flow;
#ifdef _ND_LOG_CONNTRACK
        ct_new_or_update = true;
#endif
    }
    else {
#ifdef _ND_LOG_CONNTRACK
        ct_exists = true;
#endif
        flow_iter = ct_flow_map.find(id_iter->second);

        if (type & NFCT_T_DESTROY) {
            if (flow_iter != ct_flow_map.end()) {
                delete flow_iter->second;
                ct_flow_map.erase(flow_iter);
            }
            ct_id_map.erase(id_iter);
        }
        else {
            if (flow_iter == ct_flow_map.end()) {
                nd_printf("%s: [%u] Connection tracking flow not found!\n",
                    tag.c_str(), id);
                ct_id_map.erase(id_iter);
                return;
            }

            ct_flow = flow_iter->second;
            ct_flow->Update(ct);
#ifdef _ND_LOG_CONNTRACK
            ct_new_or_update = true;
#endif
            if (ct_flow->digest != id_iter->second) {
                nd_printf("%s: [%u] Connection tracking flow hash changed!\n",
                    tag.c_str(), id);
                ct_flow_map.erase(flow_iter);
                ct_flow_map[ct_flow->digest] = ct_flow;
                ct_id_map[id] = ct_flow->digest;
            }
        }
    }
#ifdef _ND_LOG_CONNTRACK
    if (nd_debug) {
        char buffer[1024];
        nfct_snprintf(buffer, sizeof(buffer), ct, type, NFCT_O_PLAIN, NFCT_OF_TIME);

        if (! ct_exists && ct_new_or_update)
            nd_debug_printf("%s: [%u] %s\n", tag.c_str(), id, buffer);
//        if (! ct_new_or_update && ! ct_exists)
//            nd_printf("%s: [%u] %s\n", tag.c_str(), id, buffer);
//        nd_printf("%s: [%s %u] %s\n", tag.c_str(),
//            (ct_new_or_update && ! ct_exists) ?
//                "INSERT" : (ct_new_or_update && ct_exists) ?
//                "UPDATE" : (ct_exists && ! ct_new_or_update) ?
//                "ERASE" : "UNKNOWN", id, buffer);
    }
#endif
}

void ndConntrackThread::PrintFlow(
    ndConntrackFlow *flow, string &text, bool reorder, bool withreply)
{
    int addr_cmp = 0;
    ostringstream os;
    char ip[INET6_ADDRSTRLEN];
    struct sockaddr_in *sa_src = NULL, *sa_dst = NULL;
    struct sockaddr_in6 *sa6_src = NULL, *sa6_dst = NULL;
    char buffer[1024];

    sprintf(buffer,
        "l3_proto: %hu, l4_proto: %hhu",
        flow->l3_proto, flow->l4_proto);
    os << buffer;

    switch (flow->orig_addr[ndCT_DIR_SRC]->ss_family) {
    case AF_INET:
        sa_src = (struct sockaddr_in *)flow->orig_addr[ndCT_DIR_SRC];
        sa_dst = (struct sockaddr_in *)flow->orig_addr[ndCT_DIR_DST];
        if (reorder) {
            addr_cmp = memcmp(&sa_src->sin_addr,
                &sa_dst->sin_addr, sizeof(in_addr));
            if (addr_cmp < 0) {
                inet_ntop(AF_INET, &sa_src->sin_addr.s_addr,
                    ip, INET_ADDRSTRLEN);
                os << ", lower_ip: " << ip;
                inet_ntop(AF_INET, &sa_dst->sin_addr.s_addr,
                    ip, INET_ADDRSTRLEN);
                os << ", upper_ip: " << ip;
            }
            else {
                inet_ntop(AF_INET, &sa_dst->sin_addr.s_addr,
                    ip, INET_ADDRSTRLEN);
                os << ", lower_ip: " << ip;
                inet_ntop(AF_INET, &sa_src->sin_addr.s_addr,
                    ip, INET_ADDRSTRLEN);
                os << ", upper_ip: " << ip;
            }
        }
        else {
            inet_ntop(AF_INET, &sa_src->sin_addr.s_addr,
                ip, INET_ADDRSTRLEN);
            os << ", src_ip: " << ip;
            inet_ntop(AF_INET, &sa_dst->sin_addr.s_addr,
                ip, INET_ADDRSTRLEN);
            os << ", dst_ip: " << ip;
        }
        break;
    case AF_INET6:
        sa6_src = (struct sockaddr_in6 *)flow->orig_addr[ndCT_DIR_SRC];
        sa6_dst = (struct sockaddr_in6 *)flow->orig_addr[ndCT_DIR_DST];
        if (reorder) {
            addr_cmp = memcmp(&sa6_src->sin6_addr,
                &sa6_dst->sin6_addr, sizeof(struct in6_addr));
            if (addr_cmp < 0) {
                inet_ntop(AF_INET6, &sa6_src->sin6_addr.s6_addr,
                    ip, INET6_ADDRSTRLEN);
                os << ", lower_ip: " << ip;
                inet_ntop(AF_INET6, &sa6_dst->sin6_addr.s6_addr,
                    ip, INET6_ADDRSTRLEN);
                os << ", upper_ip: " << ip;
            }
            else {
                inet_ntop(AF_INET6, &sa6_dst->sin6_addr.s6_addr,
                    ip, INET6_ADDRSTRLEN);
                os << ", lower_ip: " << ip;
                inet_ntop(AF_INET6, &sa6_src->sin6_addr.s6_addr,
                    ip, INET6_ADDRSTRLEN);
                os << ", upper_ip: " << ip;
            }
        }
        else {
            inet_ntop(AF_INET6, &sa6_src->sin6_addr.s6_addr,
                ip, INET6_ADDRSTRLEN);
            os << ", src_ip: " << ip;
            inet_ntop(AF_INET6, &sa6_dst->sin6_addr.s6_addr,
                ip, INET6_ADDRSTRLEN);
            os << ", dst_ip: " << ip;
        }
        break;
    }

    if (reorder) {
        if (addr_cmp < 0) {
            os << ", lower_port: " << ntohs(flow->orig_port[ndCT_DIR_SRC]);
            os << ", upper_port: " << ntohs(flow->orig_port[ndCT_DIR_DST]);
        }
        else {
            os << ", lower_port: " << ntohs(flow->orig_port[ndCT_DIR_DST]);
            os << ", upper_port: " << ntohs(flow->orig_port[ndCT_DIR_SRC]);
        }
    }
    else {
        os << ", src_port: " << ntohs(flow->orig_port[ndCT_DIR_SRC]);
        os << ", dst_port: " << ntohs(flow->orig_port[ndCT_DIR_DST]);
    }

    if (! withreply ||
        ! flow->repl_addr[ndCT_DIR_SRC] || ! flow->repl_addr[ndCT_DIR_DST]) {
        text = os.str();
        return;
    }

    switch (flow->repl_addr[ndCT_DIR_SRC]->ss_family) {
    case AF_INET:
        sa_src = (struct sockaddr_in *)flow->repl_addr[ndCT_DIR_SRC];
        sa_dst = (struct sockaddr_in *)flow->repl_addr[ndCT_DIR_DST];
        inet_ntop(AF_INET, &sa_src->sin_addr.s_addr,
            ip, INET_ADDRSTRLEN);
        os << ", repl_src_ip: " << ip;
        inet_ntop(AF_INET, &sa_dst->sin_addr.s_addr,
            ip, INET_ADDRSTRLEN);
        os << ", repl_dst_ip: " << ip;
        break;
    case AF_INET6:
        sa6_src = (struct sockaddr_in6 *)flow->repl_addr[ndCT_DIR_SRC];
        sa6_dst = (struct sockaddr_in6 *)flow->repl_addr[ndCT_DIR_DST];
        inet_ntop(AF_INET6, &sa6_src->sin6_addr.s6_addr,
            ip, INET6_ADDRSTRLEN);
        os << ", repl_src_ip: " << ip;
        inet_ntop(AF_INET6, &sa6_dst->sin6_addr.s6_addr,
            ip, INET6_ADDRSTRLEN);
        os << ", repl_dst_ip: " << ip;
        break;
    }

    os << ", repl_src_port: " << ntohs(flow->repl_port[ndCT_DIR_SRC]);
    os << ", repl_dst_port: " << ntohs(flow->repl_port[ndCT_DIR_DST]);

    text = os.str();
}

void ndConntrackThread::PrintFlow(ndFlow *flow, string &text)
{
    ostringstream os;
    char buffer[1024];
    sa_family_t family;

    if (flow->ip_version == 4)
        family = AF_INET;
    else
        family = AF_INET6;

    sprintf(buffer,
        "l3_proto: %hu, l4_proto: %hhu",
        family, flow->ip_protocol);

    os << buffer;
    os << ", lower_ip: " << flow->lower_ip;
    os << ", upper_ip: " << flow->upper_ip;
    os << ", lower_port: " << ntohs(flow->lower_port);
    os << ", upper_port: " << ntohs(flow->upper_port);

    text = os.str();
}

void ndConntrackThread::ClassifyFlow(ndFlow *flow)
{
    sha1 ctx;
    string digest;
    uint8_t _digest[SHA1_DIGEST_LENGTH];
    sa_family_t family;
    struct sockaddr_in *sa_orig_src = NULL, *sa_orig_dst = NULL;
    struct sockaddr_in *sa_repl_src = NULL, *sa_repl_dst = NULL;
    struct sockaddr_in6 *sa6_orig_src = NULL, *sa6_orig_dst = NULL;
    struct sockaddr_in6 *sa6_repl_src = NULL, *sa6_repl_dst = NULL;
    nd_ct_flow_map::iterator flow_iter;

    if (flow->ip_version == 4)
        family = AF_INET;
    else
        family = AF_INET6;

    sha1_init(&ctx);

    sha1_write(&ctx, (const char *)&family, sizeof(sa_family_t));
    sha1_write(&ctx, (const char *)&flow->ip_protocol, sizeof(uint8_t));

    switch (family) {
    case AF_INET:
        sha1_write(&ctx,
            (const char *)&flow->lower_addr, sizeof(struct in_addr));
        sha1_write(&ctx,
            (const char *)&flow->upper_addr, sizeof(struct in_addr));
        break;
    case AF_INET6:
        sha1_write(&ctx,
            (const char *)&flow->lower_addr6, sizeof(struct in6_addr));
        sha1_write(&ctx,
            (const char *)&flow->upper_addr6, sizeof(struct in6_addr));
        break;
    }

    sha1_write(&ctx,
        (const char *)&flow->lower_port, sizeof(uint16_t));
    sha1_write(&ctx,
        (const char *)&flow->upper_port, sizeof(uint16_t));

    digest.assign((const char *)sha1_result(&ctx, _digest), SHA1_DIGEST_LENGTH);

    Lock();

    flow_iter = ct_flow_map.find(digest);
    if (flow_iter != ct_flow_map.end() &&
        flow_iter->second->repl_addr[ndCT_DIR_SRC] &&
        flow_iter->second->repl_addr[ndCT_DIR_DST]) {

        ndConntrackFlow *ct_flow = flow_iter->second;

        switch (ct_flow->l3_proto) {
        case AF_INET:
            sa_orig_src = reinterpret_cast<struct sockaddr_in *>(
                ct_flow->orig_addr[ndCT_DIR_SRC]);
            sa_orig_dst = reinterpret_cast<struct sockaddr_in *>(
                ct_flow->orig_addr[ndCT_DIR_DST]);
            sa_repl_src = reinterpret_cast<struct sockaddr_in *>(
                ct_flow->repl_addr[ndCT_DIR_SRC]);
            sa_repl_dst = reinterpret_cast<struct sockaddr_in *>(
                ct_flow->repl_addr[ndCT_DIR_DST]);
#if 0
            {
                string flow_text;
                PrintFlow(ct_flow, flow_text, false, true);
                nd_debug_printf("%s: %s\n", tag.c_str(), flow_text.c_str());
            }
#endif
            if (memcmp(sa_orig_src, sa_repl_dst, sizeof(struct sockaddr_in)) ||
                memcmp(sa_orig_dst, sa_repl_src, sizeof(struct sockaddr_in)))
                flow->ip_nat = true;

            break;

        case AF_INET6:
            sa6_orig_src = reinterpret_cast<struct sockaddr_in6 *>(
                ct_flow->orig_addr[ndCT_DIR_SRC]);
            sa6_orig_dst = reinterpret_cast<struct sockaddr_in6 *>(
                ct_flow->orig_addr[ndCT_DIR_DST]);
            sa6_repl_src = reinterpret_cast<struct sockaddr_in6 *>(
                ct_flow->repl_addr[ndCT_DIR_SRC]);
            sa6_repl_dst = reinterpret_cast<struct sockaddr_in6 *>(
                ct_flow->repl_addr[ndCT_DIR_DST]);
#if 0
            {
                string flow_text;
                PrintFlow(ct_flow, flow_text, false, true);
                nd_debug_printf("%s: %s\n", tag.c_str(), flow_text.c_str());
            }
#endif
            if (memcmp(sa6_orig_src, sa6_repl_dst, sizeof(struct sockaddr_in6)) ||
                memcmp(sa6_orig_dst, sa6_repl_src, sizeof(struct sockaddr_in6)))
                flow->ip_nat = true;

            break;
        }
    }

    Unlock();
}

ndConntrackFlow::ndConntrackFlow(struct nf_conntrack *ct)
    : l3_proto(0), l4_proto(0)
{
    orig_port[ndCT_DIR_SRC] = 0;
    orig_port[ndCT_DIR_DST] = 0;
    repl_port[ndCT_DIR_SRC] = 0;
    repl_port[ndCT_DIR_DST] = 0;
    orig_addr[ndCT_DIR_SRC] = NULL;
    orig_addr[ndCT_DIR_DST] = NULL;
    repl_addr[ndCT_DIR_SRC] = NULL;
    repl_addr[ndCT_DIR_DST] = NULL;

    Update(ct);
}

ndConntrackFlow::~ndConntrackFlow()
{
    if (orig_addr[ndCT_DIR_SRC] != NULL) delete orig_addr[ndCT_DIR_SRC];
    if (orig_addr[ndCT_DIR_DST] != NULL) delete orig_addr[ndCT_DIR_DST];
    if (repl_addr[ndCT_DIR_SRC] != NULL) delete repl_addr[ndCT_DIR_SRC];
    if (repl_addr[ndCT_DIR_DST] != NULL) delete repl_addr[ndCT_DIR_DST];
}

void ndConntrackFlow::Update(struct nf_conntrack *ct)
{
    struct sockaddr_storage *ss_addr = NULL;

    if (! nfct_attr_is_set(ct, ATTR_ORIG_L3PROTO))
        throw ndConntrackFlowException("ATTR_ORIG_L3PROTO not set");

    sa_family_t af = l3_proto = nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO);
    if (af != AF_INET && af != AF_INET6)
        throw ndConntrackFlowException("Unsupported address family");

    if (! nfct_attr_is_set(ct, ATTR_ORIG_L4PROTO))
        throw ndConntrackFlowException("ATTR_ORIG_L4PROTO not set");

    l4_proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);

    if ((! nfct_attr_is_set(ct, ATTR_ORIG_IPV4_SRC) &&
         ! nfct_attr_is_set(ct, ATTR_ORIG_IPV6_SRC)) ||
        (! nfct_attr_is_set(ct, ATTR_ORIG_IPV4_DST) &&
         ! nfct_attr_is_set(ct, ATTR_ORIG_IPV6_DST)))
        throw ndConntrackFlowException("ATTR_ORIG_SRC/DST not set");

    switch (af) {
    case AF_INET:
        if (nfct_attr_is_set(ct, ATTR_ORIG_IPV4_SRC)) {
            if (orig_addr[ndCT_DIR_SRC] != NULL)
                ss_addr = orig_addr[ndCT_DIR_SRC];
            else {
                ss_addr = new struct sockaddr_storage;
                if (ss_addr == NULL) {
                    throw ndConntrackSystemException(
                        __PRETTY_FUNCTION__, "new", ENOMEM);
                }
                orig_addr[ndCT_DIR_SRC] = ss_addr;
            }

            CopyAddress(af, ss_addr, nfct_get_attr(ct, ATTR_ORIG_IPV4_SRC));
        }
        if (nfct_attr_is_set(ct, ATTR_ORIG_IPV4_DST)) {
            if (orig_addr[ndCT_DIR_DST] != NULL)
                ss_addr = orig_addr[ndCT_DIR_DST];
            else {
                ss_addr = new struct sockaddr_storage;
                if (ss_addr == NULL) {
                    throw ndConntrackSystemException(
                        __PRETTY_FUNCTION__, "new", ENOMEM);
                }
                orig_addr[ndCT_DIR_DST] = ss_addr;
            }

            CopyAddress(af, ss_addr, nfct_get_attr(ct, ATTR_ORIG_IPV4_DST));
        }
        break;
    case AF_INET6:
        if (nfct_attr_is_set(ct, ATTR_ORIG_IPV6_SRC)) {
            if (orig_addr[ndCT_DIR_SRC] != NULL)
                ss_addr = orig_addr[ndCT_DIR_SRC];
            else {
                ss_addr = new struct sockaddr_storage;
                if (ss_addr == NULL) {
                    throw ndConntrackSystemException(
                        __PRETTY_FUNCTION__, "new", ENOMEM);
                }
                orig_addr[ndCT_DIR_SRC] = ss_addr;
            }

            CopyAddress(af, ss_addr, nfct_get_attr(ct, ATTR_ORIG_IPV6_SRC));
        }
        if (nfct_attr_is_set(ct, ATTR_ORIG_IPV6_DST)) {
            if (orig_addr[ndCT_DIR_DST] != NULL)
                ss_addr = orig_addr[ndCT_DIR_DST];
            else {
                ss_addr = new struct sockaddr_storage;
                if (ss_addr == NULL) {
                    throw ndConntrackSystemException(
                        __PRETTY_FUNCTION__, "new", ENOMEM);
                }
                orig_addr[ndCT_DIR_DST] = ss_addr;
            }

            CopyAddress(af, ss_addr, nfct_get_attr(ct, ATTR_ORIG_IPV6_DST));
        }
        break;
    }

    if (nfct_attr_is_set(ct, ATTR_ORIG_PORT_SRC))
        orig_port[ndCT_DIR_SRC] = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_SRC);
    if (nfct_attr_is_set(ct, ATTR_ORIG_PORT_DST))
        orig_port[ndCT_DIR_DST] = nfct_get_attr_u16(ct, ATTR_ORIG_PORT_DST);

    switch (af) {
    case AF_INET:
        if (nfct_attr_is_set(ct, ATTR_REPL_IPV4_SRC)) {
            if (repl_addr[ndCT_DIR_SRC] != NULL)
                ss_addr = repl_addr[ndCT_DIR_SRC];
            else {
                ss_addr = new struct sockaddr_storage;
                if (ss_addr == NULL) {
                    throw ndConntrackSystemException(
                        __PRETTY_FUNCTION__, "new", ENOMEM);
                }
                repl_addr[ndCT_DIR_SRC] = ss_addr;
            }

            CopyAddress(af, ss_addr, nfct_get_attr(ct, ATTR_REPL_IPV4_SRC));
        }
        if (nfct_attr_is_set(ct, ATTR_REPL_IPV4_DST)) {
            if (repl_addr[ndCT_DIR_DST] != NULL)
                ss_addr = repl_addr[ndCT_DIR_DST];
            else {
                ss_addr = new struct sockaddr_storage;
                if (ss_addr == NULL) {
                    throw ndConntrackSystemException(
                        __PRETTY_FUNCTION__, "new", ENOMEM);
                }
                repl_addr[ndCT_DIR_DST] = ss_addr;
            }

            CopyAddress(af, ss_addr, nfct_get_attr(ct, ATTR_REPL_IPV4_DST));
        }
        break;
    case AF_INET6:
        if (nfct_attr_is_set(ct, ATTR_REPL_IPV6_SRC)) {
            if (repl_addr[ndCT_DIR_SRC] != NULL)
                ss_addr = repl_addr[ndCT_DIR_SRC];
            else {
                ss_addr = new struct sockaddr_storage;
                if (ss_addr == NULL) {
                    throw ndConntrackSystemException(
                        __PRETTY_FUNCTION__, "new", ENOMEM);
                }
                repl_addr[ndCT_DIR_SRC] = ss_addr;
            }

            CopyAddress(af, ss_addr, nfct_get_attr(ct, ATTR_REPL_IPV6_SRC));
        }
        if (nfct_attr_is_set(ct, ATTR_REPL_IPV6_DST)) {
            if (repl_addr[ndCT_DIR_DST] != NULL)
                ss_addr = repl_addr[ndCT_DIR_DST];
            else {
                ss_addr = new struct sockaddr_storage;
                if (ss_addr == NULL) {
                    throw ndConntrackSystemException(
                        __PRETTY_FUNCTION__, "new", ENOMEM);
                }
                repl_addr[ndCT_DIR_DST] = ss_addr;
            }

            CopyAddress(af, ss_addr, nfct_get_attr(ct, ATTR_REPL_IPV6_DST));
        }
        break;
    }

    if (nfct_attr_is_set(ct, ATTR_REPL_PORT_SRC))
        repl_port[ndCT_DIR_SRC] = nfct_get_attr_u16(ct, ATTR_REPL_PORT_SRC);
    if (nfct_attr_is_set(ct, ATTR_REPL_PORT_DST))
        repl_port[ndCT_DIR_DST] = nfct_get_attr_u16(ct, ATTR_REPL_PORT_DST);

    Hash();
}

void ndConntrackFlow::CopyAddress(sa_family_t af,
    struct sockaddr_storage *dst, const void *src)
{
    struct sockaddr_in *sa = reinterpret_cast<struct sockaddr_in *>(dst);
    struct sockaddr_in6 *sa6 = reinterpret_cast<struct sockaddr_in6 *>(dst);

    memset(dst, 0, sizeof(struct sockaddr_storage));
    dst->ss_family = af;

    switch (af) {
    case AF_INET:
        memcpy(&sa->sin_addr, src, sizeof(struct in_addr));
        break;
    case AF_INET6:
        memcpy(&sa6->sin6_addr, src, sizeof(struct in6_addr));
        break;
    }
}

void ndConntrackFlow::Hash(void)
{
    sha1 ctx;
    int addr_cmp = 0;
    uint8_t _digest[SHA1_DIGEST_LENGTH];
    struct sockaddr_in *sa_src = NULL, *sa_dst = NULL;
    struct sockaddr_in6 *sa6_src = NULL, *sa6_dst = NULL;

    sha1_init(&ctx);

    sha1_write(&ctx, (const char *)&l3_proto, sizeof(sa_family_t));
    sha1_write(&ctx, (const char *)&l4_proto, sizeof(uint8_t));

    switch (orig_addr[ndCT_DIR_SRC]->ss_family) {
    case AF_INET:
        sa_src = repl_addr[ndCT_DIR_SRC] ?
            (struct sockaddr_in *)repl_addr[ndCT_DIR_SRC] :
            (struct sockaddr_in *)orig_addr[ndCT_DIR_SRC];
        sa_dst = repl_addr[ndCT_DIR_DST] ?
            (struct sockaddr_in *)repl_addr[ndCT_DIR_DST] :
            (struct sockaddr_in *)orig_addr[ndCT_DIR_DST];
        addr_cmp = memcmp(
            &sa_src->sin_addr, &sa_dst->sin_addr, sizeof(in_addr));
        if (addr_cmp < 0) {
            sha1_write(&ctx,
                (const char *)&sa_src->sin_addr, sizeof(struct in_addr));
            sha1_write(&ctx,
                (const char *)&sa_dst->sin_addr, sizeof(struct in_addr));
        }
        else {
            sha1_write(&ctx,
                (const char *)&sa_dst->sin_addr, sizeof(struct in_addr));
            sha1_write(&ctx,
                (const char *)&sa_src->sin_addr, sizeof(struct in_addr));
        }
        break;
    case AF_INET6:
        sa6_src = repl_addr[ndCT_DIR_SRC] ?
            (struct sockaddr_in6 *)repl_addr[ndCT_DIR_SRC] :
            (struct sockaddr_in6 *)orig_addr[ndCT_DIR_SRC];
        sa6_dst = repl_addr[ndCT_DIR_DST] ?
            (struct sockaddr_in6 *)repl_addr[ndCT_DIR_DST] :
            (struct sockaddr_in6 *)orig_addr[ndCT_DIR_DST];
        addr_cmp = memcmp(
            &sa6_src->sin6_addr, &sa6_dst->sin6_addr, sizeof(struct in6_addr));
        if (addr_cmp < 0) {
            sha1_write(&ctx, (const char *)&sa6_src->sin6_addr,
                sizeof(struct in6_addr));
            sha1_write(&ctx, (const char *)&sa6_dst->sin6_addr,
                sizeof(struct in6_addr));
        }
        else {
            sha1_write(&ctx, (const char *)&sa6_dst->sin6_addr,
                sizeof(struct in6_addr));
            sha1_write(&ctx, (const char *)&sa6_src->sin6_addr,
                sizeof(struct in6_addr));
        }
        break;
    }

    if (addr_cmp < 0) {
        sha1_write(&ctx,
            (const char *)&repl_port[ndCT_DIR_SRC], sizeof(uint16_t));
        sha1_write(&ctx,
            (const char *)&repl_port[ndCT_DIR_DST], sizeof(uint16_t));
    }
    else {
        sha1_write(&ctx,
            (const char *)&repl_port[ndCT_DIR_DST], sizeof(uint16_t));
        sha1_write(&ctx,
            (const char *)&repl_port[ndCT_DIR_SRC], sizeof(uint16_t));
    }

    digest.assign((const char *)sha1_result(&ctx, _digest), SHA1_DIGEST_LENGTH);
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
