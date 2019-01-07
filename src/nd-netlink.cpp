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

#include <vector>
#include <map>
#include <unordered_map>
#include <stdexcept>

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <netdb.h>
#include <pthread.h>

#include <sys/stat.h>
#include <sys/socket.h>

#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <json.h>
#include <pcap/pcap.h>

using namespace std;

#include "netifyd.h"

#include "nd-ndpi.h"
#include "nd-json.h"
#include "nd-util.h"
#include "nd-netlink.h"

extern nd_global_config nd_config;

inline bool ndNetlinkNetworkAddr::operator==(const ndNetlinkNetworkAddr &n) const
{
    int rc = -1;
    const struct sockaddr_in *ipv4_addr1, *ipv4_addr2;
    const struct sockaddr_in6 *ipv6_addr1, *ipv6_addr2;

    if (this->length != n.length)
        return false;

    if (this->network.ss_family != n.network.ss_family)
        return false;

    switch (this->network.ss_family) {
    case AF_INET:
        ipv4_addr1 = reinterpret_cast<const struct sockaddr_in *>(&this->network);
        ipv4_addr2 = reinterpret_cast<const struct sockaddr_in *>(&n.network);
        rc = memcmp(
            &ipv4_addr1->sin_addr, &ipv4_addr2->sin_addr, sizeof(struct in_addr));
        break;
    case AF_INET6:
        ipv6_addr1 = reinterpret_cast<const struct sockaddr_in6 *>(&this->network);
        ipv6_addr2 = reinterpret_cast<const struct sockaddr_in6 *>(&n.network);
        rc = memcmp(
            &ipv6_addr1->sin6_addr, &ipv6_addr2->sin6_addr, sizeof(struct in6_addr));
        break;
    default:
        return false;
    }

    return (rc == 0);
}

inline bool ndNetlinkNetworkAddr::operator!=(const ndNetlinkNetworkAddr &n) const
{
    int rc = -1;
    const struct sockaddr_in *ipv4_addr1, *ipv4_addr2;
    const struct sockaddr_in6 *ipv6_addr1, *ipv6_addr2;

    if (this->length != n.length)
        return true;

    if (this->network.ss_family != n.network.ss_family)
        return true;

    switch (this->network.ss_family) {
    case AF_INET:
        ipv4_addr1 = reinterpret_cast<const struct sockaddr_in *>(&this->network);
        ipv4_addr2 = reinterpret_cast<const struct sockaddr_in *>(&n.network);
        rc = memcmp(
            &ipv4_addr1->sin_addr, &ipv4_addr2->sin_addr, sizeof(struct in_addr));
        break;
    case AF_INET6:
        ipv6_addr1 = reinterpret_cast<const struct sockaddr_in6 *>(&this->network);
        ipv6_addr2 = reinterpret_cast<const struct sockaddr_in6 *>(&n.network);
        rc = memcmp(
            &ipv6_addr1->sin6_addr, &ipv6_addr2->sin6_addr, sizeof(struct in6_addr));
        break;
    default:
        return true;
    }

    return (rc != 0);
}

ndNetlink::ndNetlink(const nd_ifaces &ifaces)
    : nd(-1), seq(0)
{
    int rc;

    memset(buffer, 0, ND_NETLINK_BUFSIZ);

    memset(&sa, 0, sizeof(struct sockaddr_nl));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = getpid();
    sa.nl_groups =
        RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE |
        RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

    nd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nd < 0) {
        rc = errno;
        nd_printf("Error creating netlink socket: %s\n", strerror(rc));
        throw ndNetlinkException(strerror(rc));
    }

    if (bind(nd,
        (struct sockaddr *)&sa, sizeof(struct sockaddr_nl)) < 0) {
        rc = errno;
        nd_printf("Error binding netlink socket: %s\n", strerror(rc));
        throw ndNetlinkException(strerror(rc));
    }

    if (fcntl(nd, F_SETOWN, getpid()) < 0) {
        rc = errno;
        nd_printf("Error setting netlink socket owner: %s\n", strerror(rc));
        throw ndNetlinkException(strerror(errno));
    }

    if (fcntl(nd, F_SETSIG, SIGIO) < 0) {
        rc = errno;
        nd_printf("Error setting netlink I/O signal: %s\n", strerror(rc));
        throw ndNetlinkException(strerror(errno));
    }

    int flags = fcntl(nd, F_GETFL);
    if (fcntl(nd, F_SETFL, flags | O_ASYNC | O_NONBLOCK) < 0) {
        rc = errno;
        nd_printf("Error setting netlink socket flags: %s\n", strerror(rc));
        throw ndNetlinkException(strerror(rc));
    }

    for (nd_ifaces::const_iterator i = ifaces.begin(); i != ifaces.end(); i++)
        AddInterface((*i).second);

    // Add private networks for when all else fails...
    AddNetwork(AF_INET, _ND_NETLINK_PRIVATE, "10.0.0.0", 8);
    AddNetwork(AF_INET, _ND_NETLINK_PRIVATE, "172.16.0.0", 12);
    AddNetwork(AF_INET, _ND_NETLINK_PRIVATE, "192.168.0.0", 16);
    AddNetwork(AF_INET6, _ND_NETLINK_PRIVATE, "fc00::", 7);

    // Add multicast networks
    AddNetwork(AF_INET, _ND_NETLINK_MULTICAST, "224.0.0.0", 4);
    AddNetwork(AF_INET6, _ND_NETLINK_MULTICAST, "ff00::", 8);

    // Add broadcast addresses
    AddInterface(_ND_NETLINK_BROADCAST);
    AddAddress(AF_INET, _ND_NETLINK_BROADCAST, "169.254.255.255");
    AddAddress(AF_INET, _ND_NETLINK_BROADCAST, "255.255.255.255");
}

ndNetlink::~ndNetlink()
{
    if (nd >= 0) close(nd);
    for (ndNetlinkInterfaces::const_iterator i = ifaces.begin();
        i != ifaces.end(); i++) {
        if (i->second != NULL) {
            pthread_mutex_destroy(i->second);
            delete i->second;
        }
    }
}

void ndNetlink::Refresh(void)
{
    int rc;
    struct nlmsghdr *nlh;

    memset(buffer, 0, ND_NETLINK_BUFSIZ);

    nlh = (struct nlmsghdr *)buffer;

    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlh->nlmsg_type = RTM_GETROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_pid = 0;
    nlh->nlmsg_seq = seq++;

    if (send(nd, nlh, nlh->nlmsg_len, 0) < 0) {
        rc = errno;
        nd_printf("Error refreshing interface routes: %s\n", strerror(rc));
        throw ndNetlinkException(strerror(rc));
    }

    ProcessEvent();

    memset(buffer, 0, ND_NETLINK_BUFSIZ);

    nlh = (struct nlmsghdr *)buffer;

    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    nlh->nlmsg_type = RTM_GETADDR;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_pid = 0;
    nlh->nlmsg_seq = seq++;

    if (send(nd, nlh, nlh->nlmsg_len, 0) < 0) {
        rc = errno;
        nd_printf("Error refreshing interface addresses: %s\n", strerror(rc));
        throw ndNetlinkException(strerror(rc));
    }

    ProcessEvent();
}

bool ndNetlink::ProcessEvent(void)
{
    ssize_t bytes;
    struct nlmsghdr *nlh;
    struct nlmsgerr *nlerror;
    unsigned added_net = 0, removed_net = 0, added_addr = 0, removed_addr = 0;

    while ((bytes = recv(nd, buffer, ND_NETLINK_BUFSIZ, 0)) > 0) {
//        nd_debug_printf("Read %ld netlink bytes.\n", bytes);
        for (nlh = (struct nlmsghdr *)buffer;
            NLMSG_OK(nlh, bytes); nlh = NLMSG_NEXT(nlh, bytes)) {
#if 0
            nd_debug_printf(
                "NLMSG: %hu, len: %u (%u, %u), flags: 0x%x, seq: %u, pid: %u\n",
                nlh->nlmsg_type, nlh->nlmsg_len,
                NLMSG_HDRLEN, NLMSG_LENGTH(nlh->nlmsg_len),
                nlh->nlmsg_flags, nlh->nlmsg_seq, nlh->nlmsg_pid);
#endif
            switch(nlh->nlmsg_type) {
            case NLMSG_DONE:
//              nd_debug_printf("End of multi-part message.\n");
                break;
            case RTM_NEWROUTE:
//              nd_debug_printf("New route.\n");
                if (AddNetwork(nlh)) added_net++;
                break;
            case RTM_DELROUTE:
//              nd_debug_printf("Removed route.\n");
                if (RemoveNetwork(nlh)) removed_net++;
                break;
            case RTM_NEWADDR:
//              nd_debug_printf("New interface address.\n");
                if (AddAddress(nlh)) added_addr++;
                break;
            case RTM_DELADDR:
//              nd_debug_printf("Removed interface address.\n");
                if (RemoveAddress(nlh)) removed_addr++;
                break;
            case NLMSG_ERROR:
                nlerror = static_cast<struct nlmsgerr *>(NLMSG_DATA(nlh));
                if (nlerror->error != 0) {
                    nd_printf("Netlink error: %d\n", -nlerror->error);
                    return false;
                }
                break;
            case NLMSG_OVERRUN:
                nd_printf("Netlink overrun!\n");
                return false;
            default:
                nd_debug_printf("Ignored netlink message: %04x\n", nlh->nlmsg_type);
            }
        }
    }
#ifndef _ND_LEAN_AND_MEAN
    if (ND_DEBUG) {
        if (added_net || removed_net) {
            nd_debug_printf("Networks added: %d, removed: %d\n", added_net, removed_net);
        }
        if (added_addr || removed_addr) {
            nd_debug_printf("Addresses added: %d, removed: %d\n", added_addr, removed_addr);
        }

        if (added_net || removed_net || added_addr || removed_addr) Dump();
    }
#endif
    return (added_net || removed_net || added_addr || removed_addr) ? true : false;
}

ndNetlinkAddressType ndNetlink::ClassifyAddress(
    const struct sockaddr_storage *addr)
{
    ndNetlinkInterfaces::const_iterator iface;
    ndNetlinkAddressType type = ndNETLINK_ATYPE_UNKNOWN;

    for (iface = ifaces.begin();
        type == ndNETLINK_ATYPE_UNKNOWN &&
        iface != ifaces.end(); iface++) {
        type = ClassifyAddress(iface->first, addr);
    }

    vector<ndNetlinkNetworkAddr *>::const_iterator n;
    ndNetlinkNetworks::const_iterator net_list;

    vector<struct sockaddr_storage *>::const_iterator a;
    ndNetlinkAddresses::const_iterator addr_list;

    // Is addr a member of a multicast network?
    net_list = networks.find(_ND_NETLINK_MULTICAST);
    if (net_list == networks.end()) return ndNETLINK_ATYPE_ERROR;

    for (n = net_list->second.begin(); n != net_list->second.end(); n++) {

        if ((*n)->network.ss_family != addr->ss_family) continue;

        if (! InNetwork(
            (*n)->network.ss_family, (*n)->length, &(*n)->network, addr)) continue;

        type = ndNETLINK_ATYPE_MULTICAST;
        break;
    }

    if (type != ndNETLINK_ATYPE_UNKNOWN) return type;

    // Final guess: Is addr a member of a private (reserved/non-routable) network?
    net_list = networks.find(_ND_NETLINK_PRIVATE);
    if (net_list == networks.end()) return ndNETLINK_ATYPE_ERROR;

    for (n = net_list->second.begin(); n != net_list->second.end(); n++) {

        if ((*n)->network.ss_family != addr->ss_family) continue;

        if (! InNetwork(
            (*n)->network.ss_family, (*n)->length, &(*n)->network, addr)) continue;

        type = ndNETLINK_ATYPE_PRIVATE;
        break;
    }

    return type;
}

ndNetlinkAddressType ndNetlink::ClassifyAddress(
    const string &iface, const struct sockaddr_storage *addr)
{
    ndNetlinkAddressType type = ndNETLINK_ATYPE_UNKNOWN;

    ndNetlinkInterfaces::const_iterator lock = ifaces.find(iface);
    if (lock == ifaces.end()) return ndNETLINK_ATYPE_ERROR;

    // Paranoid AF_* check...
    if (addr->ss_family != AF_INET && addr->ss_family != AF_INET6) {
        nd_printf("WARNING: Address in unknown family: %hhu\n", addr->ss_family);
        return ndNETLINK_ATYPE_ERROR;
    }

    vector<ndNetlinkNetworkAddr *>::const_iterator n;
    ndNetlinkNetworks::const_iterator net_list;

    vector<struct sockaddr_storage *>::const_iterator a;
    ndNetlinkAddresses::const_iterator addr_list;

    // Is addr a broadcast address (IPv4 only)?
    if (addr->ss_family == AF_INET) {
        addr_list = addresses.find(_ND_NETLINK_BROADCAST);
        if (addr_list == addresses.end()) return ndNETLINK_ATYPE_ERROR;

        pthread_mutex_lock(lock->second);

        for (a = addr_list->second.begin(); a != addr_list->second.end(); a++) {

            if ((*a)->ss_family != addr->ss_family) continue;

            ndNetlinkNetworkAddr _addr1(addr), _addr2((*a));
            if (_addr1 != _addr2) continue;

            type = ndNETLINK_ATYPE_BROADCAST;
            break;
        }

        pthread_mutex_unlock(lock->second);
        if (type != ndNETLINK_ATYPE_UNKNOWN) return type;
    }

    // Is addr a local address to this interface?
    addr_list = addresses.find(iface);
    if (addr_list != addresses.end()) {

        pthread_mutex_lock(lock->second);

        for (a = addr_list->second.begin(); a != addr_list->second.end(); a++) {

            if ((*a)->ss_family != addr->ss_family) continue;

            ndNetlinkNetworkAddr _addr1(addr), _addr2((*a));
            if (_addr1 != _addr2) continue;

            type = ndNETLINK_ATYPE_LOCALIP;
            break;
        }

        pthread_mutex_unlock(lock->second);
    }
    if (type != ndNETLINK_ATYPE_UNKNOWN) return type;

    // Is addr a member of a local network to this interface?
    net_list = networks.find(iface);
    if (net_list != networks.end()) {

        pthread_mutex_lock(lock->second);

        for (n = net_list->second.begin(); n != net_list->second.end(); n++) {

            if ((*n)->network.ss_family != addr->ss_family) continue;

            if (! InNetwork(
                (*n)->network.ss_family, (*n)->length, &(*n)->network, addr)) continue;

            type = ndNETLINK_ATYPE_LOCALNET;
            break;
        }

        pthread_mutex_unlock(lock->second);
    }

    return type;
}

bool ndNetlink::InNetwork(sa_family_t family, uint8_t length,
    const struct sockaddr_storage *addr_net, const struct sockaddr_storage *addr_host)
{
    const struct sockaddr_in *ipv4_net, *ipv4_host;
    const  struct sockaddr_in6 *ipv6_net, *ipv6_host;
    int bit = (int)length, word, words;
    uint32_t i, word_net[4], word_host[4];

    switch (family) {
    case AF_INET:
        words = 1;

        ipv4_net = reinterpret_cast<const struct sockaddr_in *>(addr_net);
        word_net[0] = ntohl(ipv4_net->sin_addr.s_addr);

        ipv4_host = reinterpret_cast<const struct sockaddr_in *>(addr_host);
        word_host[0] = ntohl(ipv4_host->sin_addr.s_addr);
        break;

    case AF_INET6:
        words = 4;

        ipv6_net = reinterpret_cast<const struct sockaddr_in6 *>(addr_net);
        word_net[0] = ntohl(ipv6_net->sin6_addr.s6_addr32[0]);
        word_net[1] = ntohl(ipv6_net->sin6_addr.s6_addr32[1]);
        word_net[2] = ntohl(ipv6_net->sin6_addr.s6_addr32[2]);
        word_net[3] = ntohl(ipv6_net->sin6_addr.s6_addr32[3]);

        ipv6_host = reinterpret_cast<const struct sockaddr_in6 *>(addr_host);
        word_host[0] = ntohl(ipv6_host->sin6_addr.s6_addr32[0]);
        word_host[1] = ntohl(ipv6_host->sin6_addr.s6_addr32[1]);
        word_host[2] = ntohl(ipv6_host->sin6_addr.s6_addr32[2]);
        word_host[3] = ntohl(ipv6_host->sin6_addr.s6_addr32[3]);
        break;

    default:
        return false;
    }
#if 0
    char host[INET6_ADDRSTRLEN], net[INET6_ADDRSTRLEN];
    switch (addr_net->ss_family) {
    case AF_INET:
        inet_ntop(AF_INET, &ipv4_net->sin_addr.s_addr,
            net, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &ipv4_host->sin_addr.s_addr,
            host, INET_ADDRSTRLEN);
        break;

    case AF_INET6:
        inet_ntop(AF_INET6, &ipv6_net->sin6_addr.s6_addr,
            net, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ipv6_host->sin6_addr.s6_addr,
            host, INET6_ADDRSTRLEN);
        break;
    }

    nd_printf("Network: ");
    for (word = 0; word < words; word++) {
        nd_print_binary(word_net[word]);
        if (word + 1 < words) nd_printf(".");
    }
    nd_printf(" (%s)\n", net);
    nd_printf("   Host: ");
    for (word = 0; word < words; word++) {
        nd_print_binary(word_host[word]);
        if (word + 1 < words) nd_printf(".");
    }
    nd_printf(" (%s)\n\n", host);
#endif

    for (word = 0; word < words && bit > 0; word++) {
        for (i = 0x80000000; i > 0 && bit > 0; i >>= 1) {
#if 0
            nd_printf("%3d: ", bit);
            nd_print_binary(i);
            nd_printf(": ");
            nd_print_binary((word_host[word] & i));
            nd_printf(" ?= ");
            nd_print_binary((word_net[word] & i));
            nd_printf("\n");
#endif
            if ((word_host[word] & i) != (word_net[word] & i)) {
                //nd_printf("Mis-match at prefix bit: %d\n", bit);
                //nd_printf("word_host[%d] & %lu: %lu, word_net[%d] & %lu: %lu\n\n",
                //  word, i, word_host[word] & i, word, i, word_net[word] & i);
                return false;
            }
            bit--;
        }
    }

//    nd_debug_printf("%s: true\n\n", __PRETTY_FUNCTION__);

    return true;
}

bool ndNetlink::CopyNetlinkAddress(
        sa_family_t family, struct sockaddr_storage &dst, void *src)
{
    struct sockaddr_in *saddr_ip4;
    struct sockaddr_in6 *saddr_ip6;

    switch (family) {
    case AF_INET:
        saddr_ip4 = reinterpret_cast<struct sockaddr_in *>(&dst);
        memcpy(&saddr_ip4->sin_addr, src, sizeof(struct in_addr));
        dst.ss_family = family;
        return true;
    case AF_INET6:
        saddr_ip6 = reinterpret_cast<struct sockaddr_in6 *>(&dst);
        memcpy(&saddr_ip6->sin6_addr, src, sizeof(struct in6_addr));
        dst.ss_family = family;
        return true;
    }

    return false;
}

bool ndNetlink::AddInterface(const string &iface)
{
    ndNetlinkInterfaces::const_iterator i = ifaces.find(iface);
    if (i != ifaces.end()) return false;

    pthread_mutex_t *mutex = NULL;
    ND_NETLINK_DEVALLOC(mutex);
    ifaces[iface] = mutex;

    return true;
}

bool ndNetlink::ParseMessage(struct rtmsg *rtm, size_t offset,
    string &iface, ndNetlinkNetworkAddr &addr)
{
    char ifname[IFNAMSIZ];
//    char saddr[NI_MAXHOST];
    bool daddr_set = false;

    iface.clear();

    memset(&addr.network, 0, sizeof(struct sockaddr_storage));
    addr.length = 0;
    addr.network.ss_family = AF_UNSPEC;

    if (rtm->rtm_type != RTN_UNICAST) {
//        nd_debug_printf("Ignorning non-unicast route.\n");
        return false;
    }

    switch (rtm->rtm_family) {
    case AF_INET:
        if (rtm->rtm_dst_len == 0 || rtm->rtm_dst_len == 32) return false;
        break;
    case AF_INET6:
        if (rtm->rtm_dst_len == 0 || rtm->rtm_dst_len == 128) return false;
        break;
    default:
        nd_debug_printf(
            "WARNING: Ignorning non-IPv4/6 route message: %04hx\n", rtm->rtm_family);
        return false;
    }

    addr.length = rtm->rtm_dst_len;
#if 0
    if (nd_debug) {
        switch (rtm->rtm_type) {
        case RTN_UNSPEC:
            nd_debug_printf("         Type: Unknown\n");
            break;
        case RTN_UNICAST:
            nd_debug_printf("         Type: Gateway or direct route\n");
            break;
        case RTN_LOCAL:
            nd_debug_printf("         Type: Local interface route\n");
            break;
        case RTN_BROADCAST:
            nd_debug_printf("         Type: Local broadcast route\n");
            break;
        case RTN_ANYCAST:
            nd_debug_printf("         Type: Local broadcast route (unicast)\n");
            break;
        case RTN_MULTICAST:
            nd_debug_printf("         Type: Multicast route\n");
            break;
        case RTN_BLACKHOLE:
            nd_debug_printf("         Type: Packet dropping route\n");
            break;
        case RTN_UNREACHABLE:
            nd_debug_printf("         Type: An unreachable destination\n");
            break;
        case RTN_PROHIBIT:
            nd_debug_printf("         Type: Packet rejection route\n");
            break;
        case RTN_THROW:
            nd_debug_printf("         Type: Continue routing lookup in next table\n");
            break;
        case RTN_NAT:
            nd_debug_printf("         Type: NAT rule\n");
            break;
        case RTN_XRESOLVE:
            nd_debug_printf("         Type: External resolver (not impl)\n");
            break;
        }

        nd_debug_printf("  Dest length: %hhu\n", rtm->rtm_dst_len);
        nd_debug_printf("Source length: %hhu\n", rtm->rtm_src_len);
        nd_debug_printf("   TOS filter: %hhu\n", rtm->rtm_tos);
        nd_debug_printf("Routing table: %s\n",
            (rtm->rtm_table == RT_TABLE_UNSPEC) ? "Unknown" :
                (rtm->rtm_table == RT_TABLE_DEFAULT) ? "Default" :
                (rtm->rtm_table == RT_TABLE_MAIN) ? "Main" :
                (rtm->rtm_table == RT_TABLE_LOCAL) ? "Local" : "User");
        nd_debug_printf("     Protocol: %s\n",
            (rtm->rtm_protocol == RTPROT_UNSPEC) ? "Unknown" :
                (rtm->rtm_protocol == RTPROT_REDIRECT) ? "Redirect" :
                (rtm->rtm_protocol == RTPROT_KERNEL) ? "Kernel" :
                (rtm->rtm_protocol == RTPROT_BOOT) ? "Boot" :
                (rtm->rtm_protocol == RTPROT_STATIC) ? "Static" : "???");
        nd_debug_printf("        Scope: %s\n",
            (rtm->rtm_scope == RT_SCOPE_UNIVERSE) ? "Global" :
                (rtm->rtm_scope == RT_SCOPE_SITE) ? "Interior local" :
                (rtm->rtm_scope == RT_SCOPE_LINK) ? "Route on this link" :
                (rtm->rtm_scope == RT_SCOPE_HOST) ? "Route on this host" :
                (rtm->rtm_scope == RT_SCOPE_NOWHERE) ? "Doesn't exist" : "???");
    }
#endif
    for (struct rtattr *rta = static_cast<struct rtattr *>(RTM_RTA(rtm));
        RTA_OK(rta, offset); rta = RTA_NEXT(rta, offset)) {
        switch (rta->rta_type) {
            case RTA_UNSPEC:
                break;
            case RTA_DST:
                daddr_set = CopyNetlinkAddress(rtm->rtm_family, addr.network, RTA_DATA(rta));
#if 0
                getnameinfo((struct sockaddr *)&addr.network,
                    (rtm->rtm_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                    saddr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                nd_printf("Has destination address: %s\n", saddr);
#endif
                break;
            case RTA_SRC:
#if 0
                CopyNetlinkAddress(rtm->rtm_family, addr.network, RTA_DATA(rta));
                getnameinfo((struct sockaddr *)&addr.network,
                    (rtm->rtm_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                    saddr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                nd_printf("Has source address: %s\n", saddr);
#endif
                break;
            case RTA_IIF:
#if 0
                if_indextoname(*(int *)RTA_DATA(rta), ifname);
                nd_printf("Has input interface: %s\n", ifname);
#endif
                break;
            case RTA_OIF:
                if_indextoname(*(int *)RTA_DATA(rta), ifname);
                if (ifaces.find(ifname) == ifaces.end()) return false;
                iface.assign(ifname);
#if 0
                nd_printf("Has output interface: %s\n", ifname);
#endif
                break;
            case RTA_GATEWAY:
#if 0
                CopyNetlinkAddress(rtm->rtm_family, addr.network, RTA_DATA(rta));
                getnameinfo((struct sockaddr *)&addr.network,
                    (rtm->rtm_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                    saddr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                nd_printf("Has gateway address: %s\n", saddr);
#endif
                break;
            default:
#if 0
                nd_printf("Ignorning attribute type: %d\n", rta->rta_type);
#endif
                break;
        }
    }

    if (daddr_set != true || iface.size() == 0) {
//        nd_printf("Route message: %saddress set, %siface name set\n",
//            (daddr_set != true) ? "No " : "", (iface.size() == 0) ? "No" : "");
        return false;
    }

    return true;
}

bool ndNetlink::ParseMessage(struct ifaddrmsg *addrm, size_t offset,
    string &iface, struct sockaddr_storage &addr)
{
    bool addr_set = false;
    char ifname[IFNAMSIZ];
    struct sockaddr_storage addr_bcast;

    memset(&addr, 0, sizeof(struct sockaddr_storage));
    addr.ss_family = AF_UNSPEC;

    if_indextoname(addrm->ifa_index, ifname);
    if (ifaces.find(ifname) == ifaces.end()) return false;

    iface.assign(ifname);

    for (struct rtattr *rta = static_cast<struct rtattr *>(IFA_RTA(addrm));
        RTA_OK(rta, offset); rta = RTA_NEXT(rta, offset)) {
        switch (rta->rta_type) {
//        case IFA_UNSPEC:
//            nd_printf("%s: IFA_UNSPEC set\n", ifname);
//            break;
        case IFA_ADDRESS:
//            nd_printf("%s: IFA_ADDRESS set\n", ifname);
            addr_set = CopyNetlinkAddress(addrm->ifa_family, addr, RTA_DATA(rta));
            break;
        case IFA_LOCAL:
//            nd_printf("%s: IFA_LOCAL set\n", ifname);
            addr_set = CopyNetlinkAddress(addrm->ifa_family, addr, RTA_DATA(rta));
            break;
//        case IFA_LABEL:
//            nd_printf("%s: IFA_LABEL set\n", ifname);
//            break;
        case IFA_BROADCAST:
//            nd_printf("%s: IFA_BROADCAST set\n", ifname);
            if (CopyNetlinkAddress(addrm->ifa_family, addr_bcast, RTA_DATA(rta)))
                AddAddress(_ND_NETLINK_BROADCAST, addr_bcast);
            break;
//        case IFA_ANYCAST:
//            nd_printf("%s: IFA_ANYCAST set\n", ifname);
//            break;
//        case IFA_CACHEINFO:
//            nd_printf("%s: IFA_CACHEINFO set\n", ifname);
//            break;
//        case IFA_MULTICAST:
//            nd_printf("%s: IFA_MULTICAST set\n", ifname);
//            break;
//        case IFA_FLAGS:
//            nd_printf("%s: IFA_FLAGS set\n", ifname);
//            break;
//        default:
//            nd_printf("%s: WARNING: rta_type not handled: %2x\n", ifname, rta->rta_type);
//            break;
        }
    }

//    nd_debug_printf("%s: %sddress set\n", ifname, (addr_set) ? "A" : "No a");
    return addr_set;
}

bool ndNetlink::AddNetwork(struct nlmsghdr *nlh)
{
    string iface;
    ndNetlinkNetworkAddr addr;

    if (ParseMessage(
        static_cast<struct rtmsg *>(NLMSG_DATA(nlh)),
        RTM_PAYLOAD(nlh), iface, addr) == false) return false;

    ndNetlinkNetworks::const_iterator i = networks.find(iface);
    if (i != networks.end()) {
        for (vector<ndNetlinkNetworkAddr *>::const_iterator j = i->second.begin();
            j != i->second.end(); j++) {
            if (*(*j) == addr) return false;
        }
    }

    ndNetlinkInterfaces::const_iterator lock = ifaces.find(iface);
    if (lock == ifaces.end()) return false;

    ndNetlinkNetworkAddr *entry;
    ND_NETLINK_NETALLOC(entry, addr);

    pthread_mutex_lock(lock->second);
    networks[iface].push_back(entry);
    pthread_mutex_unlock(lock->second);

    return true;
}

bool ndNetlink::AddNetwork(sa_family_t family,
    const string &type, const string &saddr, uint8_t length)
{
    ndNetlinkNetworkAddr *entry, addr;
    struct sockaddr_in *saddr_ip4;
    struct sockaddr_in6 *saddr_ip6;

    memset(&addr.network, 0, sizeof(struct sockaddr_storage));

    addr.length = length;
    addr.network.ss_family = family;
    saddr_ip4 = reinterpret_cast<struct sockaddr_in *>(&addr.network);
    saddr_ip6 = reinterpret_cast<struct sockaddr_in6 *>(&addr.network);

    switch (family) {
    case AF_INET:
        if (inet_pton(AF_INET, saddr.c_str(), &saddr_ip4->sin_addr) < 1)
            return false;
        break;
    case AF_INET6:
        if (inet_pton(AF_INET6, saddr.c_str(), &saddr_ip6->sin6_addr) < 1)
            return false;
        break;
    default:
        return false;
    }

    ND_NETLINK_NETALLOC(entry, addr);
    networks[type].push_back(entry);

    return true;
}

bool ndNetlink::RemoveNetwork(struct nlmsghdr *nlh)
{
    string iface;
    ndNetlinkNetworkAddr addr;
    bool removed = false;

    if (ParseMessage(
        static_cast<struct rtmsg *>(NLMSG_DATA(nlh)),
        RTM_PAYLOAD(nlh), iface, addr) == false) {
//        nd_debug_printf("Remove network parse error\n");
        return false;
    }

    ndNetlinkNetworks::iterator i = networks.find(iface);
    if (i == networks.end()) {
        nd_debug_printf("WARNING: Couldn't find interface in networks map: %s\n",
            iface.c_str());
        return false;
    }

    ndNetlinkInterfaces::const_iterator lock = ifaces.find(iface);
    if (lock == ifaces.end()) return false;

    pthread_mutex_lock(lock->second);

    for (vector<ndNetlinkNetworkAddr *>::iterator j = i->second.begin();
        j != i->second.end(); j++) {
        if (*(*j) == addr) {
            i->second.erase(j);
            removed = true;
            break;
        }
    }

    pthread_mutex_unlock(lock->second);

//    if (nd_debug) {
//        nd_debug_printf("WARNING: Couldn't find network address in map: %s, ",
//            iface.c_str());
//        nd_print_address(&addr.network);
//        nd_debug_printf("/%hhu\n", addr.length);
//    }

    return removed;
}

bool ndNetlink::AddAddress(struct nlmsghdr *nlh)
{
    string iface;
    struct sockaddr_storage addr;

    if (ParseMessage(
        static_cast<struct ifaddrmsg *>(NLMSG_DATA(nlh)),
        IFA_PAYLOAD(nlh), iface, addr) == false) return false;

    ndNetlinkAddresses::const_iterator i = addresses.find(iface);
    if (i != addresses.end()) {
        for (vector<struct sockaddr_storage *>::const_iterator j = i->second.begin();
            j != i->second.end(); j++) {
            if (memcmp((*j), &addr, sizeof(struct sockaddr_storage)) == 0)
                return false;
        }
    }

    ndNetlinkInterfaces::const_iterator lock = ifaces.find(iface);
    if (lock == ifaces.end()) return false;

    struct sockaddr_storage *entry;
    ND_NETLINK_ADDRALLOC(entry, addr);

    pthread_mutex_lock(lock->second);
    addresses[iface].push_back(entry);
    pthread_mutex_unlock(lock->second);

    return true;
}

bool ndNetlink::AddAddress(
    sa_family_t family, const string &type, const string &saddr)
{
    struct sockaddr_storage *entry, addr;
    struct sockaddr_in *saddr_ip4;
    struct sockaddr_in6 *saddr_ip6;

    memset(&addr, 0, sizeof(struct sockaddr_storage));

    addr.ss_family = family;
    saddr_ip4 = reinterpret_cast<struct sockaddr_in *>(&addr);;
    saddr_ip6 = reinterpret_cast<struct sockaddr_in6 *>(&addr);;

    switch (family) {
    case AF_INET:
        if (inet_pton(AF_INET, saddr.c_str(), &saddr_ip4->sin_addr) < 0)
            return false;
        break;
    case AF_INET6:
        if (inet_pton(AF_INET6, saddr.c_str(), &saddr_ip6->sin6_addr) < 0)
            return false;
        break;
    default:
        return false;
    }

    ND_NETLINK_ADDRALLOC(entry, addr);
    addresses[type].push_back(entry);

    return true;
}

bool ndNetlink::AddAddress(const string &type, const struct sockaddr_storage &addr)
{
    struct sockaddr_storage *entry;

    ndNetlinkInterfaces::const_iterator lock = ifaces.find(type);
    if (lock == ifaces.end()) return false;

    pthread_mutex_lock(lock->second);
    ND_NETLINK_ADDRALLOC(entry, addr);
    addresses[type].push_back(entry);
    pthread_mutex_unlock(lock->second);

    return true;
}

bool ndNetlink::RemoveAddress(struct nlmsghdr *nlh)
{
    string iface;
    struct sockaddr_storage addr;
    bool removed = false;

    if (ParseMessage(
        static_cast<struct ifaddrmsg *>(NLMSG_DATA(nlh)),
        IFA_PAYLOAD(nlh), iface, addr) == false) return false;

    ndNetlinkAddresses::iterator i = addresses.find(iface);
    if (i == addresses.end()) {
        nd_debug_printf("WARNING: Couldn't find interface in addresses map: %s\n",
            iface.c_str());
        return false;
    }

    ndNetlinkInterfaces::const_iterator lock = ifaces.find(iface);
    if (lock == ifaces.end()) return false;

    pthread_mutex_lock(lock->second);

    for (vector<struct sockaddr_storage *>::iterator j = i->second.begin();
        j != i->second.end(); j++) {
        if (memcmp((*j), &addr, sizeof(struct sockaddr_storage)) == 0) {
            i->second.erase(j);
            removed = true;
            break;
        }
    }

    pthread_mutex_unlock(lock->second);

    return removed;
}

#ifndef _ND_LEAN_AND_MEAN
void ndNetlink::Dump(void)
{
#if 0 // TODO: Fix output mangling here
    for (ndNetlinkNetworks::iterator i = networks.begin();
        i != networks.end(); i++) {
        for (vector<ndNetlinkNetworkAddr *>::iterator j = i->second.begin();
            j != i->second.end(); j++) {
            nd_debug_printf("%s: net ", i->first.c_str());
            nd_print_address(&(*j)->network);
            nd_debug_printf("/%hhu\n", (*j)->length);
        }
    }

    for (ndNetlinkAddresses::iterator i = addresses.begin();
        i != addresses.end(); i++) {
        for (vector<struct sockaddr_storage *>::iterator j = i->second.begin();
            j != i->second.end(); j++) {
            nd_debug_printf("%s: addr ", i->first.c_str());
            nd_print_address((*j));
            nd_debug_printf("\n");
        }
    }
#endif
}

void ndNetlink::PrintType(const string &prefix, const ndNetlinkAddressType &type)
{
    switch (type) {
    case ndNETLINK_ATYPE_UNKNOWN:
        nd_debug_printf("%s: address is: UNKNOWN\n", prefix.c_str());
        break;
    case ndNETLINK_ATYPE_LOCALIP:
        nd_debug_printf("%s: address is: LOCALIP\n", prefix.c_str());
        break;
    case ndNETLINK_ATYPE_LOCALNET:
        nd_debug_printf("%s: address is: LOCALNET\n", prefix.c_str());
        break;
    case ndNETLINK_ATYPE_PRIVATE:
        nd_debug_printf("%s: address is: PRIVATE\n", prefix.c_str());
        break;
    case ndNETLINK_ATYPE_MULTICAST:
        nd_debug_printf("%s: address is: MULTICAST\n", prefix.c_str());
        break;
    case ndNETLINK_ATYPE_BROADCAST:
        nd_debug_printf("%s: address is: BROADCAST\n", prefix.c_str());
        break;
    case ndNETLINK_ATYPE_ERROR:
        nd_debug_printf("%s: address is: ERROR!\n", prefix.c_str());
        break;
    default:
        nd_debug_printf("%s: address is: Unhandled!\n", prefix.c_str());
        break;
    }
}
#endif // _ND_LEAN_AND_MEAN

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
