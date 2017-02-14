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

#include <sstream>

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
#include <linux/netlink.h>
#include <json.h>

#include <libmnl/libmnl.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

using namespace std;

#include "ndpi_api.h"

#include "netifyd.h"
#include "nd-util.h"
#include "nd-netlink.h"
#include "nd-json.h"
#include "nd-flow.h"
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
    : ctfd(-1), cth(NULL), terminate(false), cb_registered(-1),
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

    nd_debug_printf("%s: pre-loaded %lu conntrack entries.\n", tag.c_str(), ct_id_map.size());
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

    nd_debug_printf("%s: Exit.\n", tag.c_str());
    return NULL;
}

void ndConntrackThread::ProcessConntrackEvent(
    enum nf_conntrack_msg_type type, struct nf_conntrack *ct)
{
    bool ct_exists = false, ct_new_or_update = false;
    uint32_t id = nfct_get_attr_u32(ct, ATTR_ID);
    ndConntrackFlow *ct_flow = NULL;
    nd_ct_id_map::iterator id_iter = ct_id_map.find(id);
    nd_ct_flow_map::iterator flow_iter;

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
        ct_new_or_update = true;
    }
    else {
        ct_exists = true;
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
                nd_printf("%s: Connection tracking flow not found! [%u]\n",
                    tag.c_str(), id);
                ct_id_map.erase(id_iter);
                return;
            }

            ct_new_or_update = true;
            ct_flow = flow_iter->second;
            ct_flow->Update(ct);

            if (ct_flow->digest != id_iter->second) {
                nd_printf("%s: [%u] Connection tracking flow hash changed!\n",
                    tag.c_str(), id);
                ct_flow_map.erase(flow_iter);
                ct_flow_map[ct_flow->digest] = ct_flow;
                ct_id_map[id] = ct_flow->digest;
            }
        }
    }
#if 1
    if (nd_debug) {
        char buffer[1024];
        nfct_snprintf(buffer, sizeof(buffer), ct, type, NFCT_O_PLAIN, NFCT_OF_TIME);

        if (ct_new_or_update && !ct_exists)
            nd_debug_printf("%s: [%u] %s\n", tag.c_str(), id, buffer);
//        if (!ct_new_or_update && !ct_exists)
//            nd_printf("%s: [%u] %s\n", tag.c_str(), id, buffer);
//        nd_printf("%s: [%s %u] %s\n", tag.c_str(),
//            (ct_new_or_update && !ct_exists) ?
//                "INSERT" : (ct_new_or_update && ct_exists) ?
//                "UPDATE" : (ct_exists && !ct_new_or_update) ?
//                "ERASE" : "UNKNOWN", id, buffer);
    }
#endif
}

void ndConntrackThread::PrintFlow(ndConntrackFlow *flow, string &text)
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
        addr_cmp = memcmp(
            &sa_src->sin_addr, &sa_dst->sin_addr, sizeof(in_addr));
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
        break;
    case AF_INET6:
        sa6_src = (struct sockaddr_in6 *)flow->orig_addr[ndCT_DIR_SRC];
        sa6_dst = (struct sockaddr_in6 *)flow->orig_addr[ndCT_DIR_DST];
        addr_cmp = memcmp(
            &sa6_src->sin6_addr, &sa6_dst->sin6_addr, sizeof(struct in6_addr));
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
        break;
    }

    if (addr_cmp < 0) {
        os << ", lower_port: " << ntohs(flow->orig_port[ndCT_DIR_SRC]);
        os << ", upper_port: " << ntohs(flow->orig_port[ndCT_DIR_DST]);
    }
    else {
        os << ", lower_port: " << ntohs(flow->orig_port[ndCT_DIR_DST]);
        os << ", upper_port: " << ntohs(flow->orig_port[ndCT_DIR_SRC]);
    }

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
    uint8_t *_digest;
    sa_family_t family;
    struct sockaddr_in *sa_src = NULL, *sa_dst = NULL;
    struct sockaddr_in6 *sa6_src = NULL, *sa6_dst = NULL;
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

    _digest = sha1_result(&ctx);
    digest.assign((const char *)_digest, SHA1_DIGEST_LENGTH);

    Lock();

    flow_iter = ct_flow_map.find(digest);
    if (flow_iter != ct_flow_map.end()) {
        nd_printf("%s: Flow found in conntrack map!\n", tag.c_str());
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

    if (!nfct_attr_is_set(ct, ATTR_ORIG_L3PROTO))
        throw ndConntrackFlowException("ATTR_ORIG_L3PROTO not set");

    sa_family_t af = l3_proto = nfct_get_attr_u8(ct, ATTR_ORIG_L3PROTO);
    if (af != AF_INET && af != AF_INET6)
        throw ndConntrackFlowException("Unsupported address family");

    if (!nfct_attr_is_set(ct, ATTR_ORIG_L4PROTO))
        throw ndConntrackFlowException("ATTR_ORIG_L4PROTO not set");

    l4_proto = nfct_get_attr_u8(ct, ATTR_ORIG_L4PROTO);

    if ((!nfct_attr_is_set(ct, ATTR_ORIG_IPV4_SRC) &&
         !nfct_attr_is_set(ct, ATTR_ORIG_IPV6_SRC)) ||
        (!nfct_attr_is_set(ct, ATTR_ORIG_IPV4_DST) &&
         !nfct_attr_is_set(ct, ATTR_ORIG_IPV6_DST)))
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
    uint8_t *_digest;
    struct sockaddr_in *sa_src = NULL, *sa_dst = NULL;
    struct sockaddr_in6 *sa6_src = NULL, *sa6_dst = NULL;

    sha1_init(&ctx);

    sha1_write(&ctx, (const char *)&l3_proto, sizeof(sa_family_t));
    sha1_write(&ctx, (const char *)&l4_proto, sizeof(uint8_t));

    switch (orig_addr[ndCT_DIR_SRC]->ss_family) {
    case AF_INET:
        sa_src = (struct sockaddr_in *)orig_addr[ndCT_DIR_SRC];
        sa_dst = (struct sockaddr_in *)orig_addr[ndCT_DIR_DST];
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
        sa6_src = (struct sockaddr_in6 *)orig_addr[ndCT_DIR_SRC];
        sa6_dst = (struct sockaddr_in6 *)orig_addr[ndCT_DIR_DST];
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
            (const char *)&orig_port[ndCT_DIR_SRC], sizeof(uint16_t));
        sha1_write(&ctx,
            (const char *)&orig_port[ndCT_DIR_DST], sizeof(uint16_t));
    }
    else {
        sha1_write(&ctx,
            (const char *)&orig_port[ndCT_DIR_DST], sizeof(uint16_t));
        sha1_write(&ctx,
            (const char *)&orig_port[ndCT_DIR_SRC], sizeof(uint16_t));
    }

    _digest = sha1_result(&ctx);
    digest.assign((const char *)_digest, SHA1_DIGEST_LENGTH);
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
