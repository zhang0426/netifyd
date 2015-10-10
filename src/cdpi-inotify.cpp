// ClearOS DPI Daemon
// Copyright (C) 2015 ClearFoundation <http://www.clearfoundation.com>
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

#include <string>
#include <stdexcept>
#include <map>

#include <unistd.h>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <assert.h>

#define OPENSSL_THREAD_DEFINES
#include <openssl/opensslconf.h>
#ifndef OPENSSL_THREADS
#error "OpenSSL missing thread support"
#endif
#include <openssl/sha.h>

using namespace std;

#include "ndpi_main.h"

#include "cdpi-util.h"
#include "cdpi-inotify.h"

extern bool cdpi_debug;

cdpiInotify::cdpiInotify()
{
    int flags;

    if ((fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC)) < 0)
        throw cdpiInotifyException(strerror(errno));
    if (fcntl(fd, F_SETOWN, getpid()) < 0)
        throw cdpiInotifyException(strerror(errno));

    flags = fcntl(fd, F_GETFL);
    if (fcntl(fd, F_SETFL, flags | O_ASYNC | O_NONBLOCK) < 0)
        throw cdpiInotifyException(strerror(errno));
}

cdpiInotify::~cdpiInotify()
{
    for (cdpi_inotify_map::iterator i = inotify_watch.begin();
        i != inotify_watch.end(); i++) {
        inotify_rm_watch(fd, i->second->wd);
        delete i->second;
    }

    if (fd > -1)
        close(fd);
}

void cdpiInotify::AddWatch(const string &filename)
{
    if (inotify_watch.find(filename) == inotify_watch.end()) {
        struct cdpi_inotify_watch *watch = new struct cdpi_inotify_watch;
        if (watch == NULL)
            throw cdpiInotifyException(strerror(ENOMEM));
        memset(watch, 0, sizeof(struct cdpi_inotify_watch));
        watch->wd = -1;

        inotify_watch[filename] = watch;
    }
}

void cdpiInotify::RefreshWatches(void)
{
    for (cdpi_inotify_map::iterator i = inotify_watch.begin();
        i != inotify_watch.end(); i++) {
        i->second->wd = inotify_add_watch(
            fd, i->first.c_str(), IN_DELETE_SELF | IN_CLOSE_WRITE | IN_MODIFY);
        if (i->second->wd < 0) {
            cdpi_printf("Error creating inotify watch: %s: %s\n",
                i->first.c_str(), strerror(errno));
        }
    }
}

void cdpiInotify::ProcessWatchEvent(void)
{
    ssize_t bytes;
    uint8_t buffer[CDPI_INOTIFY_BUFSIZ];
    uint8_t *p = buffer;

    do {
        bytes = read(fd, buffer, CDPI_INOTIFY_BUFSIZ);

        if (bytes > 0) {
            struct inotify_event *iev = (struct inotify_event *)p;
            while (bytes > 0) {

                cdpi_inotify_map::iterator watch;
                for (watch = inotify_watch.begin();
                    watch != inotify_watch.end(); watch++) {
                    if (iev->wd != watch->second->wd) continue;
                    break;
                }

                if (watch != inotify_watch.end()) {
                    if (watch->second->event_occured == false &&
                        (iev->mask & IN_DELETE_SELF) ||
                        (iev->mask & IN_MODIFY) || (iev->mask & IN_CLOSE_WRITE))

                        if (cdpi_debug) cdpi_printf("File event occured: %s [%s]\n", watch->first.c_str(),
                            (iev->mask & IN_DELETE_SELF) ? "DELETE_SELF" :
                                (iev->mask & IN_MODIFY) ? "MODIFY" : 
                                    (iev->mask & IN_CLOSE_WRITE) ? "CLOSE_WRITE" : "IGNORE");

                        watch->second->event_occured = true;
                        watch->second->rehash = true;
                }
                else
                    cdpi_printf("Event on unknown inotify watch descriptor!\n");

                p += sizeof(struct inotify_event) + iev->len;
                bytes -= sizeof(struct inotify_event) + iev->len;
                iev = (struct inotify_event *)p;
            }
        }
        else if (bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            throw cdpiInotifyException(strerror(errno));
        }
    }
    while (bytes != 0);

    for (cdpi_inotify_map::iterator i = inotify_watch.begin();
        i != inotify_watch.end(); i++) {

        if (i->second->rehash == false) continue;

        uint8_t digest[SHA_DIGEST_LENGTH];

        if (cdpi_sha1_file(i->first, digest) < 0)
            continue;

        if (i->second->digest == NULL) {
            i->second->digest = new uint8_t[SHA_DIGEST_LENGTH];
            memcpy(i->second->digest, digest, SHA_DIGEST_LENGTH);
        }
        else {
            if (memcmp(i->second->digest, digest, SHA_DIGEST_LENGTH))
                memcpy(i->second->digest, digest, SHA_DIGEST_LENGTH);
            else {
                string hash1, hash2;
                i->second->event_occured = false;
            }
        }

        i->second->rehash = false;
    }
}

bool cdpiInotify::EventOccured(const string &filename)
{
    cdpi_inotify_map::const_iterator i = inotify_watch.find(filename);

    if (i == inotify_watch.end()) return false;

    if (i->second->event_occured) {
        i->second->event_occured = false;
        return true;
    }

    return false; 
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
