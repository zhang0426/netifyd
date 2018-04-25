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

#ifndef _ND_UPLOAD_THREAD_H
#define _ND_UPLOAD_THREAD_H

class ndUploadThreadException : public runtime_error
{
public:
    explicit ndUploadThreadException(const string &what_arg)
        : runtime_error(what_arg) { }
};

class ndUploadThread : public ndThread
{
public:
    ndUploadThread();
    virtual ~ndUploadThread();

    virtual void *Entry(void);

    void QueuePush(const string &json);
    size_t QueuePendingSize(void);

    void AppendData(const char *data, size_t length) {
        try {
            body_data.append(data, length);
        } catch (exception &e) {
            throw ndThreadException(e.what());
        }
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

    bool ExportConfig(ndJsonConfigType type, ndJsonObjectConfig *config);
};

#endif // _ND_UPLOAD_THREAD_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
