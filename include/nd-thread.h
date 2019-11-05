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

#ifndef _ND_THREAD_H
#define _ND_THREAD_H

#define ND_THREAD_MAX_PROCNAMELEN 16

class ndThreadException : public runtime_error
{
public:
    explicit ndThreadException(const string &what_arg)
        : runtime_error(what_arg) { }
};

class ndThreadSystemException : public ndSystemException
{
public:
    explicit ndThreadSystemException(
        const string &where_arg, const string &what_arg, int why_arg) throw()
        : ndSystemException(where_arg, what_arg, why_arg) { }
};

class ndThread
{
public:
    ndThread(const string &tag, long cpu = -1, bool ipc = false);
    virtual ~ndThread();

    string GetTag(void) { return tag; }
    pthread_t GetId(void) { return id; }

    void SetProcName(void);

    virtual void Create(void);
    virtual void *Entry(void) = 0;

    virtual void Terminate(void) { terminate = true; }
    bool ShouldTerminate(void) { return terminate; }

    void SetTerminated(void) { terminated = true; }
    bool HasTerminated(void) { return terminated; }

    void Lock(void);
    void Unlock(void);

    void SendIPC(uint32_t id);
    uint32_t RecvIPC(void);

protected:
    string tag;
    pthread_t id;
    pthread_attr_t attr;
    long cpu;
#ifdef HAVE_ATOMIC
    atomic<bool> terminate;
    atomic<bool> terminated;
#else
    bool terminate;
    bool terminated;
#endif
    pthread_mutex_t lock;

    int fd_ipc[2];

    int Join(void);
};

#endif // _ND_THREAD_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
