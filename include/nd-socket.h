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

#ifndef _ND_SOCKET_H
#define _ND_SOCKET_H

class ndSocketException : public ndException
{
public:
    explicit ndSocketException(
        const string &where_arg, const string &what_arg) throw()
        : ndException(where_arg, what_arg) { }
};

class ndSocketThreadException : public ndSystemException
{
public:
    explicit ndSocketThreadException(
        const string &where_arg, const string &what_arg, int why_arg) throw()
        : ndSystemException(where_arg, what_arg, why_arg) { }
};

class ndSocketSystemException : public ndSystemException
{
public:
    explicit ndSocketSystemException(
        const string &where_arg, const string &what_arg, int why_arg) throw()
        : ndSystemException(where_arg, what_arg, why_arg) { }
};

class ndSocketGetAddrInfoException : public ndSystemException
{
public:
    explicit ndSocketGetAddrInfoException(
        const string &where_arg, const string &what_arg, int why_arg) throw()
        : ndSystemException(where_arg, what_arg, why_arg) { }
};

class ndSocketHangupException : public runtime_error
{
public:
    explicit ndSocketHangupException(const string &what_arg)
        : runtime_error(what_arg) { }
};

class ndSocketLocal;
class ndSocketRemote;
class ndSocketClient;
class ndSocketServer;

enum ndSocketType
{
    ndSOCKET_TYPE_NULL,
    ndSOCKET_TYPE_CLIENT,
    ndSOCKET_TYPE_SERVER
};

enum ndSocketState
{
    ndSOCKET_STATE_INIT,
    ndSOCKET_STATE_CONNECTED,
    ndSOCKET_STATE_ACCEPTED,
    ndSOCKET_STATE_CLOSED,
};

class ndSocket
{
public:
    ndSocket();
    ndSocket(const string &node);
    ndSocket(const string &node, const string &service);
    virtual ~ndSocket();

    void SetBlockingMode(bool enable = false);

    ssize_t Read(uint8_t *buffer, ssize_t length);
    ssize_t Write(const uint8_t *buffer, ssize_t length);

    int GetDescriptor(void) { return sd; }

protected:
    friend class ndSocketLocal;
    friend class ndSocketRemote;
    friend class ndSocketClient;
    friend class ndSocketServer;

    void Create(void);

    int sd;
    int family;
    sockaddr *sa;
    socklen_t sa_size;
    string node;
    string service;

    ndSocketType type;
    ndSocketState state;

    uint64_t bytes_in;
    uint64_t bytes_out;
};

class ndSocketLocal
{
protected:
    ndSocketLocal(ndSocket *base, const string &node);
    virtual ~ndSocketLocal();

    int IsValid(void);

    ndSocket *base;
    bool valid;
};

class ndSocketRemote
{
protected:
    ndSocketRemote(ndSocket *base, const string &node, const string &service);
    virtual ~ndSocketRemote();

    ndSocket *base;
};

class ndSocketClient
{
protected:
    ndSocketClient(ndSocket *base);
    virtual ~ndSocketClient();

    ndSocket *base;
};

class ndSocketServer
{
public:
    ndSocket *Accept(void);

protected:
    ndSocketServer(ndSocket *base);
    virtual ~ndSocketServer();

    ndSocket *base;
};

class ndSocketClientLocal
    : public ndSocket, public ndSocketClient, protected ndSocketLocal
{
public:
    ndSocketClientLocal(const string &node);
    virtual ~ndSocketClientLocal();

protected:
};

class ndSocketServerLocal
    : public ndSocket, public ndSocketServer, protected ndSocketLocal
{
public:
    ndSocketServerLocal(const string &node);
    virtual ~ndSocketServerLocal();

protected:
};

class ndSocketClientRemote
    : public ndSocket, public ndSocketClient, protected ndSocketRemote
{
public:
    ndSocketClientRemote(const string &node, const string &service);
    virtual ~ndSocketClientRemote();

protected:
};

class ndSocketServerRemote
    : public ndSocket, public ndSocketServer, protected ndSocketRemote
{
public:
    ndSocketServerRemote(const string &node, const string &service);
    virtual ~ndSocketServerRemote();

protected:
};

#define _ND_SOCKET_BUFSIZE  8192

class ndSocketBuffer
{
public:
    ndSocketBuffer();
    virtual ~ndSocketBuffer();

    inline int GetDescriptor(void) { return fd_fifo[0]; }
    const uint8_t *GetBuffer(ssize_t &bytes);

    size_t BufferQueueFlush(void);

    void Push(const string &data);
    void Pop(size_t bytes);

protected:
    uint8_t *buffer;
    int fd_fifo[2];

    size_t buffer_queue_offset;
    size_t buffer_queue_length;
    deque<string> buffer_queue;
};

typedef unordered_map<int, ndSocket *> ndSocketClientMap;
typedef unordered_map<int, ndSocketServer *> ndSocketServerMap;
typedef unordered_map<int, ndSocketBuffer *> ndSocketBufferMap;

class ndSocketThread : public ndThread
{
public:
    ndSocketThread();
    virtual ~ndSocketThread();

    virtual void Terminate(void) { terminate = true; }

    void QueueWrite(const string &data);

    virtual void *Entry(void);

protected:
    void ClientAccept(ndSocketServerMap::iterator &si);
    void ClientHangup(ndSocketClientMap::iterator &ci);

    ndSocketClientMap clients;
    ndSocketServerMap servers;
    ndSocketBufferMap buffers;
};

#endif // _ND_SOCKET_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
