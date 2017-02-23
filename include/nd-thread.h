// Netify Daemon
// Copyright (C) 2015-2017 eGloo Incorporated <http://www.egloo.ca>
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

class ndThread
{
public:
    ndThread(const string &tag, long cpu = -1);
    virtual ~ndThread();

    string GetTag(void) { return tag; }
    pthread_t GetId(void) { return id; }

    void SetProcName(void);

    virtual void Create(void);
    virtual void *Entry(void) = 0;

    virtual void Terminate(void) { terminate = true; }

    void Lock(void);
    void Unlock(void);

protected:
    string tag;
    pthread_t id;
    pthread_attr_t attr;
    long cpu;
    bool terminate;
    pthread_mutex_t lock;

    int Join(void);
};

#endif // _ND_THREAD_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
