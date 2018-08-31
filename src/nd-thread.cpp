// Netify Agent
// Copyright (C) 2015-2018 eGloo Incorporated <http://www.egloo.ca>
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
#else
typedef bool atomic_bool;
#endif

#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

using namespace std;

#include "netifyd.h"

#include "nd-ndpi.h"
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

ndThread::ndThread(const string &tag, long cpu)
    : tag(tag), id(0), cpu(cpu), terminate(false), terminated(false)
{
    int rc;

    if ((rc = pthread_attr_init(&attr)) != 0)
        throw ndThreadException(strerror(rc));

    if ((rc = pthread_mutex_init(&lock, NULL)) != 0)
        throw ndThreadException(strerror(rc));

    if (cpu == -1) return;
#if defined(HAVE_PTHREAD_ATTR_SETAFFINITY_NP) && defined(CPU_ALLOC)
    long cpus = sysconf(_SC_NPROCESSORS_ONLN);

    if (cpu >= cpus) cpu = 0;

    cpu_set_t *cpuset = CPU_ALLOC(cpus);
    if (cpuset == NULL) return;

    size_t size = CPU_ALLOC_SIZE(cpus);

    CPU_ZERO_S(size, cpuset);
    CPU_SET_S(cpu, size, cpuset);

    rc = pthread_attr_setaffinity_np(
        &attr,
        CPU_COUNT_S(size, cpuset),
        cpuset
    );

    CPU_FREE(cpuset);
#endif
}

ndThread::~ndThread(void)
{
    pthread_attr_destroy(&attr);
    pthread_mutex_destroy(&lock);
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

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
