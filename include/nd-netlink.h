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

#define ND_NETLINK_BUFSIZ   4096

class ndNetlinkException : public runtime_error
{
public:
    explicit ndNetlinkException(const string &what_arg)
        : runtime_error(what_arg) { }
};

typedef struct {
    struct sockaddr_storage network;
    struct sockaddr_storage netmask;
} ndNetlinkNetworkAddr;

typedef struct {
    pthread_mutex_t lock;
    vector<ndNetlinkNetworkAddr *> netaddr;
} ndNetlinkNetworks;

typedef map<string, ndNetlinkNetworks *> ndNetlinkDeviceNetwork;

class ndNetlink
{
public:
    ndNetlink();
    virtual ~ndNetlink();

    int GetDescriptor(void) { return nd; }

    void Refresh(void);
    void ProcessEvent(void);

    int WhichIsLocal(const string &dev,
        struct sockaddr_storage *a, struct sockaddr_storage *b);

protected:
    enum ndNetlinkAction {
        ndNETLINK_ROUTE_ADD,
        ndNETLINK_ROUTE_DEL
    };

    void ParseRoute(enum ndNetlinkAction action);

    int nd;
    int seq;
    struct sockaddr_nl sa;
    uint8_t buffer[ND_NETLINK_BUFSIZ];
};

#endif // _ND_NETLINK_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
