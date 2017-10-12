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

#ifndef _ND_INOTIFY_H
#define _ND_INOTIFY_H

#define ND_INOTIFY_BUFSIZ     4096

class ndInotifyException : public runtime_error
{
public:
    explicit ndInotifyException(const string &what_arg)
        : runtime_error(what_arg) { }
};

class ndInotify
{
public:
    ndInotify();
    virtual ~ndInotify();

    void AddWatch(const string &tag, const string &filename);
    void RefreshWatches(void);

    void ProcessEvent(void);

    bool EventOccured(const string &tag);

    int GetDescriptor(void) { return fd; }

protected:
    int fd;

    struct nd_inotify_watch
    {
        int wd;
        const char *filename;
        bool event_occured;
        bool rehash;
        uint8_t *digest;
    };
    typedef map<string, struct nd_inotify_watch *> nd_inotify_map;
    nd_inotify_map inotify_watch;
};

#endif // _ND_INOTIFY_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
