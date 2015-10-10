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

#ifndef _CDPI_INOTIFY_H
#define _CDPI_INOTIFY_H

#define CDPI_INOTIFY_BUFSIZ     4096

class cdpiInotifyException : public runtime_error
{
public:
    explicit cdpiInotifyException(const string &what_arg)
        : runtime_error(what_arg) { }
};

class cdpiInotify
{
public:
    cdpiInotify();
    virtual ~cdpiInotify();

    void AddWatch(const string &filename);
    void RefreshWatches(void);

    void ProcessWatchEvent(void);

    bool EventOccured(const string &filename);

protected:
    int fd;

    struct cdpi_inotify_watch
    {
        int wd;
        bool event_occured;
        bool rehash;
        uint8_t *digest;
    };
    typedef map<string, struct cdpi_inotify_watch *> cdpi_inotify_map;
    cdpi_inotify_map inotify_watch;
};

#endif // _CDPI_INOTIFY_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
