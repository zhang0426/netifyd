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

#ifndef _ND_NETLINK_H
#define _ND_NETLINK_H

#define ND_NETLINK_BUFSIZ       4096

#define _ND_NETLINK_PRIVATE     "__nd_private__"
#define _ND_NETLINK_MULTICAST   "__nd_multicast__"
#define _ND_NETLINK_BROADCAST   "__nd_broadcast__"

#define ND_NETLINK_DEVALLOC(m) { \
    m = new pthread_mutex_t; \
    if (m == NULL) throw ndNetlinkException(strerror(ENOMEM)); \
    int rc = pthread_mutex_init(m, NULL); \
    if (rc != 0) throw ndNetlinkException(strerror(rc)); }

#define ND_NETLINK_NETALLOC(e, a) { \
    e = new ndNetlinkNetworkAddr(a); \
    if (e == NULL) throw ndNetlinkException(strerror(ENOMEM)); }

#define ND_NETLINK_ADDRALLOC(e, a) { \
    e = new struct sockaddr_storage(a); \
    if (e == NULL) throw ndNetlinkException(strerror(ENOMEM)); }

class ndNetlinkException : public runtime_error
{
public:
    explicit ndNetlinkException(const string &what_arg)
        : runtime_error(what_arg) { }
};

class ndNetlinkNetworkAddr
{
public:
    ndNetlinkNetworkAddr() :
        length(0) { memset(&address, 0, sizeof(struct sockaddr_storage)); }
    ndNetlinkNetworkAddr(const struct sockaddr_storage *addr, uint8_t length = 0) :
        length(length) { memcpy(&address, addr, sizeof(struct sockaddr_storage)); }

    uint8_t length;
    union {
        struct sockaddr_storage address;
        struct sockaddr_storage network;
    };

    inline bool operator==(const ndNetlinkNetworkAddr &n) const;
    inline bool operator!=(const ndNetlinkNetworkAddr &n) const;
};

typedef map<string, pthread_mutex_t *> ndNetlinkInterfaces;
typedef map<string, vector<ndNetlinkNetworkAddr *> > ndNetlinkNetworks;
typedef map<string, vector<struct sockaddr_storage *> > ndNetlinkAddresses;

enum ndNetlinkAddressType
{
    ndNETLINK_ATYPE_UNKNOWN,

    ndNETLINK_ATYPE_LOCALIP,
    ndNETLINK_ATYPE_LOCALNET,
    ndNETLINK_ATYPE_PRIVATE,
    ndNETLINK_ATYPE_MULTICAST,
    ndNETLINK_ATYPE_BROADCAST, // IPv4 "limited broadcast": 255.255.255.255

    ndNETLINK_ATYPE_ERROR,
};

class ndNetlink
{
public:
    ndNetlink(const nd_ifaces &iface);
    virtual ~ndNetlink();

#ifdef HAVE_LINUX_NETLINK_H
    int GetDescriptor(void) { return nd; }
    void Refresh(void);
    bool ProcessEvent(void);
#else
    void Refresh(void) { }
    int GetDescriptor(void) { return -1; }
    bool ProcessEvent(void) { return false; }
#endif
    ndNetlinkAddressType ClassifyAddress(
        const struct sockaddr_storage *addr);
    ndNetlinkAddressType ClassifyAddress(
        const string &iface, const struct sockaddr_storage *addr);

    bool AddNetwork(sa_family_t family,
        const string &type, const string &saddr, uint8_t length);

    bool AddInterface(const string &iface);

    bool AddAddress(sa_family_t family, const string &type, const string &saddr);

#ifndef _ND_LEAN_AND_MEAN
    void Dump(void);
    static void PrintType(const string &prefix, const ndNetlinkAddressType &type);
#endif

protected:
    bool InNetwork(
        sa_family_t family, uint8_t length,
        const struct sockaddr_storage *addr_host,
        const struct sockaddr_storage *addr_net);

    bool CopyNetlinkAddress(
        sa_family_t family, struct sockaddr_storage &dst, void *src);
#ifdef HAVE_LINUX_NETLINK_H
    bool ParseMessage(struct rtmsg *rtm, size_t offset,
        string &iface, ndNetlinkNetworkAddr &addr);
    bool ParseMessage(struct ifaddrmsg *addrm, size_t offset,
        string &iface, struct sockaddr_storage &addr);

    bool AddNetwork(struct nlmsghdr *nlh);
    bool RemoveNetwork(struct nlmsghdr *nlh);

    bool AddAddress(struct nlmsghdr *nlh);
    bool RemoveAddress(struct nlmsghdr *nlh);
#endif
    bool AddAddress(const string &type, const struct sockaddr_storage &addr);

    void PrintAddress(const struct sockaddr_storage *addr);
#ifdef HAVE_LINUX_NETLINK_H
    int nd;
    unsigned seq;
    struct sockaddr_nl sa;
    uint8_t buffer[ND_NETLINK_BUFSIZ];
#endif
    ndNetlinkInterfaces ifaces;
    ndNetlinkNetworks networks;
    ndNetlinkAddresses addresses;
};

#endif // _ND_NETLINK_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
