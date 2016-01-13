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
#include <errno.h>

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

using namespace std;

#include "ndpi_main.h"

#include "nd-netlink.h"
#include "nd-util.h"

extern bool nd_debug;

ndNetlink::ndNetlink()
    : nd(-1), seq(0)
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

    nlh = (struct nlmsghdr *)buffer;

    while ((bytes = recv(nd, nlh, ND_NETLINK_BUFSIZ, 0)) > 0) {
        while ((NLMSG_OK(nlh, bytes)) && (nlh->nlmsg_type != NLMSG_DONE)) {
            switch(nlh->nlmsg_type) {
            case RTM_NEWROUTE:
                nd_printf("New route.\n");
                break;
            case RTM_DELROUTE:
                nd_printf("Deleted route.\n");
                break;
            default:
                if (nd_debug)
                    nd_printf("Ignored netlink message: %04x\n", nlh->nlmsg_type);
            }
            nlh = NLMSG_NEXT(nlh, bytes);
        }
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
