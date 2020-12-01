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

#ifndef _ND_SINK_THREAD_H
#define _ND_SINK_THREAD_H

class ndSinkThreadException : public runtime_error
{
public:
    explicit ndSinkThreadException(const string &what_arg)
        : runtime_error(what_arg) { }
};

typedef deque<ndJsonResponse *> ndResponseQueue;

class ndSinkThread : public ndThread
{
public:
    ndSinkThread(int16_t cpu = -1);
    virtual ~ndSinkThread();

    virtual void *Entry(void);

    virtual void Terminate(void);

    void QueuePush(const string &json);
    size_t QueuePendingSize(void);

    void AppendData(const char *data, size_t length)
    {
        try {
            body_data.append(data, length);
        } catch (exception &e) {
            throw ndThreadException(e.what());
        }
    }

    void PushResponse(ndJsonResponse *response = NULL);
    ndJsonResponse *PopResponse(void);

protected:
    CURL *ch;
    struct curl_slist *headers;
    struct curl_slist *headers_gz;
    string body_data;

    deque<pair<bool, string> > pending;
    size_t pending_size;

    queue<string> uploads;
    pthread_cond_t uploads_cond;
    pthread_mutex_t uploads_cond_mutex;

    ndResponseQueue responses;
    pthread_mutex_t response_mutex;

    unsigned post_errors;
    unsigned update_imf;
    unsigned update_count;

    void CreateHandle(void);
    void DestroyHandle(void);

    void CreateHeaders(void);
    void FreeHeaders(void);

    void Upload(void);

    string Deflate(const string &data);

    void ProcessResponse(void);
};

#endif // _ND_SINK_THREAD_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
