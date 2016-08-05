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

#ifndef _ND_UPLOAD_THREAD_H
#define _ND_UPLOAD_THREAD_H

class ndUploadThread : public ndThread
{
public:
    ndUploadThread();
    virtual ~ndUploadThread();

    virtual void *Entry(void);

    virtual void Terminate(void) { QueuePush("terminate"); }

    void QueuePush(const string &json);

    void AppendData(const char *data, size_t length) {
        body_data.append(data, length);
    }

protected:
    CURL *ch;
    struct curl_slist *headers;
    struct curl_slist *headers_gz;
    queue<string> uploads;
    deque<pair<bool, string> > pending;
    size_t pending_size;
    pthread_cond_t uploads_cond;
    pthread_mutex_t uploads_cond_mutex;
    string body_data;

    void CreateHeaders(void);
    void FreeHeaders(void);

    void Upload(void);
    string Deflate(const string &data);
    void ProcessResponse(void);

    bool LoadRealmUUID(string &uuid);
    bool SaveRealmUUID(const string &uuid);
};

#endif // _ND_UPLOAD_THREAD_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
