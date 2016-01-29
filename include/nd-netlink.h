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

#ifndef _ND_NETLINK_H
#define _ND_NETLINK_H

#define ND_NETLINK_BUFSIZ       4096

#define ND_NETLINK_ALLOC(e, a)  { \
    e = new ndNetlinkNetworkAddr(a); \
    if (e == NULL) throw ndNetlinkException(strerror(ENOMEM)); }

class ndNetlinkException : public runtime_error
{
public:
    explicit ndNetlinkException(const string &what_arg)
        : runtime_error(what_arg) { }
};

typedef struct ndNetlinkNetworkAddr {
    uint8_t length;
    struct sockaddr_storage network;

    inline bool operator==(const ndNetlinkNetworkAddr &n) const {
        return (memcmp(this, &n, sizeof(struct ndNetlinkNetworkAddr)) == 0);
    }
} ndNetlinkNetworkAddr;

typedef map<string, vector<ndNetlinkNetworkAddr *> > ndNetlinkNetworks;

enum ndLocalResult
{
    ndNETLINK_ISLOCAL_NEITHER,
    ndNETLINK_ISLOCAL_BOTH,
    ndNETLINK_ISLOCAL_A,
    ndNETLINK_ISLOCAL_B,

    ndNETLINK_ISLOCAL_ERROR,
};

class ndNetlink
{
public:
    ndNetlink(vector<string> *devices);
    virtual ~ndNetlink();

    int GetDescriptor(void) { return nd; }

    void Refresh(void);
    void ProcessEvent(void);

    ndLocalResult WhichIsLocal(const string &device,
        struct sockaddr_storage *a, struct sockaddr_storage *b);
    inline ndLocalResult GuessWhichIsLocal(
        struct sockaddr_storage *a, struct sockaddr_storage *b) {
        return WhichIsLocal("__nd_private__", a, b);
    }

    void Dump(void);

protected:
    bool InNetwork(sa_family_t family, uint8_t length,
        struct sockaddr_storage *addr_host, struct sockaddr_storage *addr_net);

    bool CopyNetlinkAddress(
        sa_family_t family, ndNetlinkNetworkAddr &dst, void *src);
    bool ParseRouteMessage(struct rtmsg *rtm, size_t offset,
        string &device, ndNetlinkNetworkAddr &addr);

    bool AddNetwork(struct nlmsghdr *nlh);
    bool AddPrivateNetwork(sa_family_t family, const string &saddr, uint8_t length);
    bool RemoveNetwork(struct nlmsghdr *nlh);

    int nd;
    int seq;
    struct sockaddr_nl sa;
    uint8_t buffer[ND_NETLINK_BUFSIZ];
    vector<string> *devices;

    ndNetlinkNetworks networks;
};

#endif // _ND_NETLINK_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
