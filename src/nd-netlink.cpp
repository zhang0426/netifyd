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
#include <stdexcept>

#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netdb.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

using namespace std;

#include "ndpi_main.h"

#include "nd-netlink.h"
#include "nd-util.h"

extern bool nd_debug;

static void print_binary(uint32_t byte)
{
	uint32_t i;
	static char b[9];

	b[0] = '\0';
	for (i = 0x80000000; i > 0; i >>= 1) {
		strcat(b, ((byte & i) == i) ? "1" : "0");
	}

	nd_printf(b);
}

ndNetlink::ndNetlink(vector<string> *devices)
    : nd(-1), seq(0), devices(devices)
{
    int rc;

    memset(buffer, 0, ND_NETLINK_BUFSIZ);

    memset(&sa, 0, sizeof(struct sockaddr_nl));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = getpid();
    sa.nl_groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE;

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

    // Add private networks for when all else fails...
    AddPrivateNetwork(AF_INET, "10.0.0.0", 8);
    AddPrivateNetwork(AF_INET, "172.16.0.0", 12);
    AddPrivateNetwork(AF_INET, "192.168.0.0", 16);
    AddPrivateNetwork(AF_INET6, "fc00::", 7);
}

ndNetlink::~ndNetlink()
{
    if (nd >= 0) close(nd);
}

void ndNetlink::Refresh(void)
{
    int rc;
    struct nlmsghdr *nlh;
    struct rtmsg *rtm;

    memset(buffer, 0, ND_NETLINK_BUFSIZ);

    nlh = (struct nlmsghdr *)buffer;
    rtm = (struct rtmsg *)NLMSG_DATA(nlh);

    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlh->nlmsg_type = RTM_GETROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_pid = 0;
    nlh->nlmsg_seq = seq++;

    if (send(nd, nlh, nlh->nlmsg_len, 0) < 0) {
        rc = errno;
        nd_printf("Error sending netlink message: %s\n", strerror(rc));
        throw ndNetlinkException(strerror(rc));
    }
}

void ndNetlink::ProcessEvent(void)
{
    ssize_t bytes;
    struct nlmsghdr *nlh;
    int added = 0, removed = 0;

    while ((bytes = recv(nd, buffer, ND_NETLINK_BUFSIZ, 0)) > 0) {
//        if (nd_debug) nd_printf("Read %ld netlink bytes.\n", bytes);
        for (nlh = (struct nlmsghdr *)buffer;
            NLMSG_OK(nlh, bytes); nlh = NLMSG_NEXT(nlh, bytes)) {
#if 0
            if (nd_debug) {
                nd_printf(
                    "NLMSG: %hu, len: %u (%u, %u), flags: 0x%x, seq: %u, pid: %u\n",
                    nlh->nlmsg_type, nlh->nlmsg_len,
                    NLMSG_HDRLEN, NLMSG_LENGTH(nlh->nlmsg_len),
                    nlh->nlmsg_flags, nlh->nlmsg_seq, nlh->nlmsg_pid);
            }
#endif
            switch(nlh->nlmsg_type) {
            case NLMSG_DONE:
//                if (nd_debug)
//                    nd_printf("End of multi-part message.\n");
                break;
            case RTM_NEWROUTE:
//                if (nd_debug)
//                    nd_printf("New route.\n");
                if (AddNetwork(nlh)) added++;
                break;
            case RTM_DELROUTE:
//                if (nd_debug)
//                    nd_printf("Deleted route.\n");
                if (RemoveNetwork(nlh)) removed++;
                break;
            case NLMSG_ERROR:
                if (nd_debug)
                    nd_printf("Netlink error.\n");
                break;
            case NLMSG_OVERRUN:
                if (nd_debug)
                    nd_printf("Netlink overrun.\n");
                break;
            default:
                if (nd_debug)
                    nd_printf("Ignored netlink message: %04x\n", nlh->nlmsg_type);
            }
        }
    }

    if (nd_debug) {
        if (added > 0 || removed > 0) {
            nd_printf("Networks added: %d, removed: %d\n", added, removed);
            Dump();
        }
    }
}

ndLocalResult ndNetlink::WhichIsLocal(const string &device,
    struct sockaddr_storage *a, struct sockaddr_storage *b)
{
    bool islocal_a = false, islocal_b = false;

    if (a->ss_family != AF_INET && a->ss_family != AF_INET6 &&
        b->ss_family != AF_INET && a->ss_family != AF_INET6) {
        nd_printf("WARNING: Which is local unknown family: A: %hhu, B: %hhu\n",
            a->ss_family, b->ss_family);
        return ndNETLINK_ISLOCAL_ERROR;
    }

    if (a->ss_family != b->ss_family) {
        nd_printf("WARNING: Which is local family mis-match: A: %hhu, B: %hhu\n",
            a->ss_family, b->ss_family);
        return ndNETLINK_ISLOCAL_ERROR;
    }

    for (ndNetlinkNetworks::iterator i = networks.begin();
        i != networks.end(); i++) {

        if (i->first != device) continue;

        for (vector<ndNetlinkNetworkAddr *>::iterator j = i->second.begin();
            j != i->second.end(); j++) {

            if ((*j)->network.ss_family != a->ss_family) continue;

            islocal_a = InNetwork(
                (*j)->network.ss_family, (*j)->length, &(*j)->network, a);
            islocal_b = InNetwork(
                (*j)->network.ss_family, (*j)->length, &(*j)->network, b);

            if (islocal_a == true && islocal_b == true)
                return ndNETLINK_ISLOCAL_BOTH;
        }
    }

    if (islocal_a == true && islocal_b == false)
        return ndNETLINK_ISLOCAL_A;
    if (islocal_a == false && islocal_b == true)
        return ndNETLINK_ISLOCAL_B;

    return ndNETLINK_ISLOCAL_NEITHER;
}

bool ndNetlink::InNetwork(sa_family_t family, uint8_t length,
    struct sockaddr_storage *addr_net, struct sockaddr_storage *addr_host)
{
	struct sockaddr_in *ipv4_net, *ipv4_host;
	struct sockaddr_in6 *ipv6_net, *ipv6_host;
	int o, b = (int)length, octets = 1;
	uint32_t i, octet_net[4], octet_host[4];

	switch (family) {
	case AF_INET:
        ipv4_net = reinterpret_cast<struct sockaddr_in *>(addr_net);
        ipv4_host = reinterpret_cast<struct sockaddr_in *>(addr_host);
		octet_net[0] = ntohl(ipv4_net->sin_addr.s_addr);
		octet_host[0] = ntohl(ipv4_host->sin_addr.s_addr);
		break;
	case AF_INET6:
		octets = 4;
        ipv6_net = reinterpret_cast<struct sockaddr_in6 *>(addr_net);
        ipv6_host = reinterpret_cast<struct sockaddr_in6 *>(addr_host);
		octet_net[0] = ntohl(ipv6_net->sin6_addr.s6_addr32[0]);
		octet_net[1] = ntohl(ipv6_net->sin6_addr.s6_addr32[1]);
		octet_net[2] = ntohl(ipv6_net->sin6_addr.s6_addr32[2]);
		octet_net[3] = ntohl(ipv6_net->sin6_addr.s6_addr32[3]);
		octet_host[0] = ntohl(ipv6_host->sin6_addr.s6_addr32[0]);
		octet_host[1] = ntohl(ipv6_host->sin6_addr.s6_addr32[1]);
		octet_host[2] = ntohl(ipv6_host->sin6_addr.s6_addr32[2]);
		octet_host[3] = ntohl(ipv6_host->sin6_addr.s6_addr32[3]);
		break;
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
	for (o = 0; o < octets; o++) {
		print_binary(octet_net[o]);
		if (o + 1 < octets) nd_printf(".");
	}
	nd_printf(" (%s)\n", net);
	nd_printf("   Host: ");
	for (o = 0; o < octets; o++) {
		print_binary(octet_host[o]);
		if (o + 1 < octets) nd_printf(".");
	}
	nd_printf(" (%s)\n\n", host);
#endif

	for (o = 0; o < octets && b > 0; o++) {
		for (i = 0x80000000; i > 0 && b > 0; i >>= 1) {
#if 0
			nd_printf("%3d: ", b);
			print_binary(i);
			nd_printf(": ");
			print_binary((octet_host[o] & i));
			nd_printf(" ?= ");
			print_binary((octet_net[o] & i));
			nd_printf("\n");
#endif
            if ((octet_host[o] & i) != (octet_net[o] & i)) {
				//nd_printf("Mis-match at prefix bit: %d\n", b);
				//nd_printf("octet_host[%d] & %lu: %lu, octet_net[%d] & %lu: %lu\n",
				//	o, i, octet_host[o] & i, o, i, octet_net[o] & i);
                return false;
            }
            b--;
        }
    }

    return true;
}

bool ndNetlink::CopyNetlinkAddress(
        sa_family_t family, ndNetlinkNetworkAddr &dst, void *src)
{
    struct sockaddr_in *saddr_ip4;
    struct sockaddr_in6 *saddr_ip6;

    switch (family) {
    case AF_INET:
        saddr_ip4 = reinterpret_cast<struct sockaddr_in *>(&dst.network);
        memcpy(&saddr_ip4->sin_addr, src, sizeof(struct in_addr));
        dst.network.ss_family = family;
        return true;
        break;
    case AF_INET6:
        saddr_ip6 = reinterpret_cast<struct sockaddr_in6 *>(&dst.network);
        memcpy(&saddr_ip6->sin6_addr, src, sizeof(struct in6_addr));
        dst.network.ss_family = family;
        return true;
        break;
    }

    return false;
}

bool ndNetlink::ParseRouteMessage(struct rtmsg *rtm, size_t offset,
    string &device, ndNetlinkNetworkAddr &addr)
{
    char ifname[IFNAMSIZ];
//    char saddr[NI_MAXHOST];
    bool daddr_set = false;

    device.clear();

    memset(&addr.network, 0, sizeof(struct sockaddr_storage));
    addr.length = 0;
    addr.network.ss_family = AF_UNSPEC;

    if (rtm->rtm_type != RTN_UNICAST) return false;

    switch (rtm->rtm_family) {
    case AF_INET:
        if (rtm->rtm_dst_len == 0 || rtm->rtm_dst_len == 32) return false;
        break;
    case AF_INET6:
        if (rtm->rtm_dst_len == 0 || rtm->rtm_dst_len == 128) return false;
        break;
    default:
        if (nd_debug)
            nd_printf("Ignorning non-IPv4/6 route message: %04hx\n", rtm->rtm_family);
        return false;
    }
        
    addr.length = rtm->rtm_dst_len;
#if 0
    if (nd_debug) {
        switch (rtm->rtm_type) {
        case RTN_UNSPEC:
            nd_printf("         Type: Unknown\n");
            break;
        case RTN_UNICAST:
            nd_printf("         Type: Gateway or direct route\n");
            break;
        case RTN_LOCAL:
            nd_printf("         Type: Local interface route\n");
            break;
        case RTN_BROADCAST:
            nd_printf("         Type: Local broadcast route\n");
            break;
        case RTN_ANYCAST:
            nd_printf("         Type: Local broadcast route (unicast)\n");
            break;
        case RTN_MULTICAST:
            nd_printf("         Type: Multicast route\n");
            break;
        case RTN_BLACKHOLE:
            nd_printf("         Type: Packet dropping route\n");
            break;
        case RTN_UNREACHABLE:
            nd_printf("         Type: An unreachable destination\n");
            break;
        case RTN_PROHIBIT:
            nd_printf("         Type: Packet rejection route\n");
            break;
        case RTN_THROW:
            nd_printf("         Type: Continue routing lookup in next table\n");
            break;
        case RTN_NAT:
            nd_printf("         Type: NAT rule\n");
            break;
        case RTN_XRESOLVE:
            nd_printf("         Type: External resolver (not impl)\n");
            break;
        }

        nd_printf("  Dest length: %hhu\n", rtm->rtm_dst_len);
        nd_printf("Source length: %hhu\n", rtm->rtm_src_len);
        nd_printf("   TOS filter: %hhu\n", rtm->rtm_tos);
        nd_printf("Routing table: %s\n",
            (rtm->rtm_table == RT_TABLE_UNSPEC) ? "Unknown" :
                (rtm->rtm_table == RT_TABLE_DEFAULT) ? "Default" :
                (rtm->rtm_table == RT_TABLE_MAIN) ? "Main" :
                (rtm->rtm_table == RT_TABLE_LOCAL) ? "Local" : "User");
        nd_printf("     Protocol: %s\n",
            (rtm->rtm_protocol == RTPROT_UNSPEC) ? "Unknown" :
                (rtm->rtm_protocol == RTPROT_REDIRECT) ? "Redirect" :
                (rtm->rtm_protocol == RTPROT_KERNEL) ? "Kernel" :
                (rtm->rtm_protocol == RTPROT_BOOT) ? "Boot" :
                (rtm->rtm_protocol == RTPROT_STATIC) ? "Static" : "???");
        nd_printf("        Scope: %s\n",
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
                daddr_set = CopyNetlinkAddress(rtm->rtm_family, addr, RTA_DATA(rta));
#if 0
                getnameinfo((struct sockaddr *)&addr.network,
                    (rtm->rtm_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                    saddr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                nd_printf("Has destination address: %s\n", saddr);
#endif
                break;
            case RTA_SRC:
#if 0
                CopyNetlinkAddress(rtm->rtm_family, addr, RTA_DATA(rta));
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
                for (vector<string>::const_iterator i = devices->begin();
                    i != devices->end(); i++)
                    if (strncasecmp(ifname, (*i).c_str(), IFNAMSIZ)) return false;
                device.assign(ifname);
#if 0
                nd_printf("Has output interface: %s\n", ifname);
#endif
                break;
            case RTA_GATEWAY:
#if 0
                CopyNetlinkAddress(rtm->rtm_family, addr, RTA_DATA(rta));
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

    if (daddr_set != true || device.size() == 0)
        return false;

    return true;
}

bool ndNetlink::AddNetwork(struct nlmsghdr *nlh)
{
    string device;
    ndNetlinkNetworkAddr addr;

    if (ParseRouteMessage(
        static_cast<struct rtmsg *>(NLMSG_DATA(nlh)),
        RTM_PAYLOAD(nlh), device, addr) == false) return false;

    for (ndNetlinkNetworks::iterator i = networks.begin();
        i != networks.end(); i++) {
        if (device != i->first) continue;

        for (vector<ndNetlinkNetworkAddr *>::iterator j = i->second.begin();
            j != i->second.end(); j++) {
            if (*(*j) == addr) return false;
        }
    }

    ndNetlinkNetworkAddr *entry;
    ND_NETLINK_ALLOC(entry, addr);
    networks[device].push_back(entry);

    return true;
}

bool ndNetlink::AddPrivateNetwork(
    sa_family_t family, const string &saddr, uint8_t length)
{
    ndNetlinkNetworkAddr *entry, addr;
    struct sockaddr_in *saddr_ip4;
    struct sockaddr_in6 *saddr_ip6;

    memset(&addr.network, 0, sizeof(struct sockaddr_storage));

    addr.length = length;
    addr.network.ss_family = family;
    saddr_ip4 = reinterpret_cast<struct sockaddr_in *>(&addr.network);;
    saddr_ip6 = reinterpret_cast<struct sockaddr_in6 *>(&addr.network);;

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

    ND_NETLINK_ALLOC(entry, addr);
    networks["__nd_private__"].push_back(entry);

    return true;
}

bool ndNetlink::RemoveNetwork(struct nlmsghdr *nlh)
{
    string device;
    ndNetlinkNetworkAddr addr;

    if (ParseRouteMessage(
        static_cast<struct rtmsg *>(NLMSG_DATA(nlh)),
        RTM_PAYLOAD(nlh), device, addr) == false) return false;

    ndNetlinkNetworks::iterator i = networks.find(device);
    if (i == networks.end()) {
        if (nd_debug) nd_printf("WARNING: Couldn't find device in networks map: %s\n",
            device.c_str());
        return false;
    }

    for (vector<ndNetlinkNetworkAddr *>::iterator j = i->second.begin();
        j != i->second.end(); j++) {
        if (*(*j) == addr) {
            i->second.erase(j);
            return true;
        }
    }

    return false;
}

void ndNetlink::Dump(void)
{
    char addr[NI_MAXHOST];

    if (!nd_debug) return;

    for (ndNetlinkNetworks::iterator i = networks.begin();
        i != networks.end(); i++) {
        for (vector<ndNetlinkNetworkAddr *>::iterator j = i->second.begin();
            j != i->second.end(); j++) {
            getnameinfo((struct sockaddr *)&(*j)->network,
                ((*j)->network.ss_family == AF_INET) ?
                    sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            nd_printf("%s: %s/%hhu\n", i->first.c_str(), addr, (*j)->length);
        }
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
