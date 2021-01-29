// Netify Agent
// Copyright (C) 2015-2020 eGloo Incorporated <http://www.egloo.ca>
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

#include <stdexcept>
#include <vector>
#include <map>
#include <unordered_map>
#ifdef HAVE_ATOMIC
#include <atomic>
#endif
#include <regex>

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
#include <string.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#ifdef HAVE_SYS_CPUSET_H
#include <sys/cpuset.h>
#endif

#include <pcap/pcap.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

using namespace std;

#include "netifyd.h"

#include "nd-ndpi.h"
#include "nd-json.h"
#include "nd-util.h"
#include "nd-thread.h"

extern nd_global_config nd_config;

static void *nd_thread_entry(void *param)
{
    void *rv = NULL;
    ndThread *thread = NULL;

    sigset_t signal_set;
    sigfillset(&signal_set);
    sigdelset(&signal_set, SIGPROF);

    try {
        if (pthread_sigmask(SIG_BLOCK, &signal_set, NULL) != 0)
            throw ndThreadException("pthread_sigmask");

        thread = reinterpret_cast<ndThread *>(param);
        thread->SetProcName();
        rv = thread->Entry();
        thread->SetTerminated();
    }
    catch (exception &e) {
        nd_printf("%s: Exception: %s\n", thread->GetTag().c_str(), e.what());
    }

    return rv;
}

ndThread::ndThread(const string &tag, long cpu, bool ipc)
    : tag(tag), id(0), cpu(cpu), terminate(false), terminated(false),
    fd_ipc{-1, -1}
{
    int rc;

    if ((rc = pthread_attr_init(&attr)) != 0)
        throw ndThreadException(strerror(rc));

    if ((rc = pthread_mutex_init(&lock, NULL)) != 0)
        throw ndThreadException(strerror(rc));

    if (ipc && socketpair(AF_LOCAL, SOCK_STREAM | SOCK_NONBLOCK, 0, fd_ipc) < 0)
        throw ndThreadSystemException(__PRETTY_FUNCTION__, "socketpair", errno);

    if (cpu == -1) return;
#if defined(HAVE_PTHREAD_ATTR_SETAFFINITY_NP)
#ifdef HAVE_SYS_CPUSET_H
    typedef cpuset_t cpu_set_t;
#endif
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);

    rc = pthread_attr_setaffinity_np(
        &attr,
        sizeof(cpuset),
        &cpuset
    );
#endif
}

ndThread::~ndThread(void)
{
    pthread_attr_destroy(&attr);
    pthread_mutex_destroy(&lock);

    if (fd_ipc[0] != -1) close(fd_ipc[0]);
    if (fd_ipc[1] != -1) close(fd_ipc[1]);
}

void ndThread::SetProcName(void)
{
#if defined(HAVE_PTHREAD_SETNAME_NP) && ! defined(_ND_LEAN_AND_MEAN)
    char name[ND_THREAD_MAX_PROCNAMELEN];

    snprintf(name, ND_THREAD_MAX_PROCNAMELEN, "%s", tag.c_str());
    if (tag.length() >= ND_THREAD_MAX_PROCNAMELEN - 1)
        name[ND_THREAD_MAX_PROCNAMELEN - 2] = '+';

    pthread_setname_np(id, name);
#endif
}

void ndThread::Create(void)
{
    int rc;

    if (id != 0)
        throw ndThreadException("Thread previously created");
    if ((rc = pthread_create(&id, &attr,
        nd_thread_entry, static_cast<void *>(this))) != 0)
        throw ndThreadException(strerror(rc));
}

int ndThread::Join(void)
{
    int rc = -1;

    if (id == 0) {
        nd_printf("%s: Thread ID invalid.\n", tag.c_str());
        return rc;
    }

    rc = pthread_join(id, NULL);
    id = 0;

    return rc;
}

void ndThread::Lock(void)
{
    int rc = pthread_mutex_lock(&lock);

    if (rc != 0)
        throw ndThreadException(strerror(rc));
}

void ndThread::Unlock(void)
{
    int rc = pthread_mutex_unlock(&lock);

    if (rc != 0)
        throw ndThreadException(strerror(rc));
}

void ndThread::SendIPC(uint32_t id)
{
    ssize_t bytes_wrote = 0;

    bytes_wrote = send(fd_ipc[1], &id, sizeof(uint32_t), 0);

    if (bytes_wrote != sizeof(uint32_t)) {
        nd_debug_printf("%s: Failed to send IPC message: %s\n",
            tag.c_str(), strerror(errno));
    }
}

uint32_t ndThread::RecvIPC(void)
{
    uint32_t id = 0;
    ssize_t bytes_read = 0;

    bytes_read = recv(fd_ipc[0], &id, sizeof(uint32_t), 0);

    if (bytes_read != sizeof(uint32_t)) {
        nd_debug_printf("%s: Failed to receive IPC message: %s\n",
            tag.c_str(), strerror(errno));
    }

    return id;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
