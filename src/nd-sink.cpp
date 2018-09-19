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

#include <string>
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <iostream>
#include <iomanip>
#include <map>
#include <vector>
#include <unordered_map>
#include <queue>
#include <deque>
#include <sstream>
#ifdef HAVE_ATOMIC
#include <atomic>
#else
typedef bool atomic_bool;
#endif

#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>

#include <curl/curl.h>

#include <json.h>

#include <zlib.h>

using namespace std;

#include "netifyd.h"

#include "nd-ndpi.h"
#include "nd-json.h"
#include "nd-thread.h"
#include "nd-util.h"
#include "nd-sink.h"

extern nd_global_config nd_config;

static int nd_curl_debug(
    CURL *ch, curl_infotype type, char *data, size_t size, void *param)
{
    string buffer;
    if (! ND_DEBUG_UPLOAD) return 0;

    ndThread *thread = reinterpret_cast<ndThread *>(param);

    switch (type) {
    case CURLINFO_TEXT:
        buffer.assign(data, size);
        nd_debug_printf("%s: %s", thread->GetTag().c_str(), buffer.c_str());
        break;
    case CURLINFO_HEADER_IN:
        buffer.assign(data, size);
        nd_debug_printf("%s: <-- %s", thread->GetTag().c_str(), buffer.c_str());
        break;
    case CURLINFO_HEADER_OUT:
        buffer.assign(data, size);
        nd_debug_printf("%s: --> %s", thread->GetTag().c_str(), buffer.c_str());
        break;
    case CURLINFO_DATA_IN:
        nd_debug_printf("%s: <-- %lu data bytes\n", thread->GetTag().c_str(), size);
        break;
    case CURLINFO_DATA_OUT:
        nd_debug_printf("%s: --> %lu data bytes\n", thread->GetTag().c_str(), size);
        break;
    case CURLINFO_SSL_DATA_IN:
        nd_debug_printf("%s: <-- %lu SSL bytes\n", thread->GetTag().c_str(), size);
        break;
    case CURLINFO_SSL_DATA_OUT:
        nd_debug_printf("%s: --> %lu SSL bytes\n", thread->GetTag().c_str(), size);
        break;
    default:
        break;
    }

    return 0;
}

static size_t ndSinkThread_read_data(
    char *data, size_t size, size_t nmemb, void *user)
{
    size_t length = size * nmemb;
    ndSinkThread *thread_upload = reinterpret_cast<ndSinkThread *>(user);

    thread_upload->AppendData((const char *)data, length);

    return length;
}

#if (LIBCURL_VERSION_NUM < 0x073200)
static int ndSinkThread_progress(void *user,
    double dltotal, double dlnow, double ultotal, double ulnow)
#else
static int ndSinkThread_progress(void *user,
    curl_off_t dltotal, curl_off_t dlnow, curl_off_t ultotal, curl_off_t ulnow)
#endif
{
    ndSinkThread *thread_upload = reinterpret_cast<ndSinkThread *>(user);

    if (thread_upload->ShouldTerminate()) return 1;

    return 0;
}

ndSinkThread::ndSinkThread()
    : ndThread("nd-sink", -1),
    headers(NULL), headers_gz(NULL), pending_size(0)
{
    int rc;

    if ((ch = curl_easy_init()) == NULL)
        throw ndSinkThreadException("curl_easy_init");

    curl_easy_setopt(ch, CURLOPT_URL, nd_config.url_upload);
    curl_easy_setopt(ch, CURLOPT_POST, 1);
    curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(ch, CURLOPT_TIMEOUT, (long)nd_config.upload_timeout);
    curl_easy_setopt(ch, CURLOPT_NOSIGNAL, (long)1);
    curl_easy_setopt(ch, CURLOPT_COOKIEFILE, (ND_DEBUG_UPLOAD) ? ND_COOKIE_JAR : "");

    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, ndSinkThread_read_data);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, static_cast<void *>(this));

    curl_easy_setopt(ch, CURLOPT_NOPROGRESS, 0);
#if (LIBCURL_VERSION_NUM < 0x073200)
    curl_easy_setopt(ch, CURLOPT_PROGRESSFUNCTION, ndSinkThread_progress);
    curl_easy_setopt(ch, CURLOPT_PROGRESSDATA, static_cast<void *>(this));
#else
    curl_easy_setopt(ch, CURLOPT_XFERINFOFUNCTION, ndSinkThread_progress);
    curl_easy_setopt(ch, CURLOPT_XFERINFODATA, static_cast<void *>(this));
#endif
#if (LIBCURL_VERSION_NUM < 0x072106)
    curl_easy_setopt(ch, CURLOPT_ENCODING, "gzip");
#else
    curl_easy_setopt(ch, CURLOPT_ACCEPT_ENCODING, "gzip");
#endif
    if (ND_DEBUG_UPLOAD) {
        curl_easy_setopt(ch, CURLOPT_VERBOSE, 1);
        curl_easy_setopt(ch, CURLOPT_DEBUGFUNCTION, nd_curl_debug);
        curl_easy_setopt(ch, CURLOPT_DEBUGDATA, static_cast<void *>(this));
        curl_easy_setopt(ch, CURLOPT_COOKIEJAR, ND_COOKIE_JAR);
    }

    if (! ND_SSL_VERIFY) {
        curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(ch, CURLOPT_SSL_VERIFYHOST, 0);
    }

    if (ND_SSL_USE_TLSv1)
        curl_easy_setopt(ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);

    CreateHeaders();

    pthread_condattr_t cond_attr;

    pthread_condattr_init(&cond_attr);
    pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
    if ((rc = pthread_cond_init(&uploads_cond, &cond_attr)) != 0)
        throw ndSinkThreadException(strerror(rc));
    pthread_condattr_destroy(&cond_attr);

    if ((rc = pthread_mutex_init(&uploads_cond_mutex, NULL)) != 0)
        throw ndSinkThreadException(strerror(rc));

    if ((rc = pthread_mutex_init(&response_mutex, NULL)) != 0)
        throw ndSinkThreadException(strerror(rc));
}

ndSinkThread::~ndSinkThread()
{
    Join();
    if (ch != NULL) curl_easy_cleanup(ch);
    FreeHeaders();

    pthread_cond_destroy(&uploads_cond);
    pthread_mutex_destroy(&uploads_cond_mutex);

    pthread_mutex_lock(&response_mutex);

    for (ndResponseQueue::const_iterator i = responses.begin();
        i != responses.end(); i++) delete (*i);

    responses.clear();

    pthread_mutex_unlock(&response_mutex);
    pthread_mutex_destroy(&response_mutex);
}

void *ndSinkThread::Entry(void)
{
    int rc;

    nd_debug_printf("%s: thread started.\n", tag.c_str());

    while (terminate == false) {
        if ((rc = pthread_mutex_lock(&lock)) != 0)
            throw ndSinkThreadException(strerror(rc));

        if (uploads.size() == 0) {
            if ((rc = pthread_mutex_unlock(&lock)) != 0)
                throw ndSinkThreadException(strerror(rc));

            if ((rc = pthread_mutex_lock(&uploads_cond_mutex)) != 0)
                throw ndSinkThreadException(strerror(rc));
            if ((rc = pthread_cond_wait(&uploads_cond, &uploads_cond_mutex)) != 0)
                throw ndSinkThreadException(strerror(rc));
            if ((rc = pthread_mutex_unlock(&uploads_cond_mutex)) != 0)
                throw ndSinkThreadException(strerror(rc));

            continue;
        }

        do {
            if (uploads.front().size() <= ND_COMPRESS_SIZE)
                pending.push_back(make_pair(false, uploads.front()));
            else
                pending.push_back(make_pair(true, Deflate(uploads.front())));

            pending_size += pending.back().second.size();
            uploads.pop();

            while (pending_size > nd_config.max_backlog) {
                pending_size -= pending.front().second.size();
                pending.pop_front();
            }
        }
        while (uploads.size() > 0);

        if ((rc = pthread_mutex_unlock(&lock)) != 0)
            throw ndSinkThreadException(strerror(rc));

        if (terminate == false && pending.size() > 0) Upload();
    }

    return NULL;
}

void ndSinkThread::Terminate(void)
{
    int rc;

    if ((rc = pthread_mutex_lock(&lock)) != 0)
        throw ndSinkThreadException(strerror(rc));
    if ((rc = pthread_cond_broadcast(&uploads_cond)) != 0)
        throw ndSinkThreadException(strerror(rc));

    terminate = true;

    if ((rc = pthread_mutex_unlock(&lock)) != 0)
        throw ndSinkThreadException(strerror(rc));
}

void ndSinkThread::QueuePush(const string &json)
{
    int rc;

    if ((rc = pthread_mutex_lock(&lock)) != 0)
        throw ndSinkThreadException(strerror(rc));

    uploads.push(json);

    if ((rc = pthread_cond_broadcast(&uploads_cond)) != 0)
        throw ndSinkThreadException(strerror(rc));
    if ((rc = pthread_mutex_unlock(&lock)) != 0)
        throw ndSinkThreadException(strerror(rc));
}

size_t ndSinkThread::QueuePendingSize(void)
{
    int rc;
    size_t bytes;

    if ((rc = pthread_mutex_lock(&lock)) != 0)
        throw ndSinkThreadException(strerror(rc));

    bytes = pending_size;

    if ((rc = pthread_mutex_unlock(&lock)) != 0)
        throw ndSinkThreadException(strerror(rc));

    return bytes;
}

void ndSinkThread::PushResponse(ndJsonResponse *response)
{
    pthread_mutex_lock(&response_mutex);

    responses.push_back(response);

    pthread_mutex_unlock(&response_mutex);

    kill(getpid(), SIGALRM);
}

ndJsonResponse *ndSinkThread::PopResponse(void)
{
    ndJsonResponse *response = NULL;

    pthread_mutex_lock(&response_mutex);

    if (responses.size()) {
        response = responses.front();
        responses.pop_front();
    }

    pthread_mutex_unlock(&response_mutex);

    return response;
}

void ndSinkThread::CreateHeaders(void)
{
    FreeHeaders();

    ostringstream user_agent;
    user_agent << "User-Agent: " << nd_get_version_and_features();

    ostringstream uuid;
    if (strncmp(nd_config.uuid, ND_AGENT_UUID_NULL, ND_AGENT_UUID_LEN))
        uuid << "X-UUID: " << nd_config.uuid;
    else {
        string _uuid;
        if (nd_load_uuid(_uuid, nd_config.path_uuid, ND_AGENT_UUID_LEN))
            uuid << "X-UUID: " << _uuid;
        else
            uuid << "X-UUID: " << nd_config.uuid;
    }

    ostringstream serial;
    serial << "X-UUID-Serial: " << nd_config.uuid_serial;

    ostringstream site_uuid;
    if (strncmp(nd_config.uuid_site, ND_SITE_UUID_NULL, ND_SITE_UUID_LEN))
        site_uuid << "X-UUID-Site: " << nd_config.uuid_site;
    else {
        string _uuid;
        if (nd_load_uuid(_uuid, nd_config.path_uuid_site, ND_SITE_UUID_LEN))
            site_uuid << "X-UUID-Site: " << _uuid;
        else
            site_uuid << "X-UUID-Site: " << nd_config.uuid_site;
    }

    string digest;
    nd_sha1_to_string(nd_config.digest_sink_config, digest);

    ostringstream conf_digest;
    conf_digest << "X-Digest-Sink: " << digest;

    headers = curl_slist_append(headers, user_agent.str().c_str());
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, uuid.str().c_str());
    headers = curl_slist_append(headers, serial.str().c_str());
    headers = curl_slist_append(headers, site_uuid.str().c_str());
    headers = curl_slist_append(headers, conf_digest.str().c_str());

    headers_gz = curl_slist_append(headers_gz, user_agent.str().c_str());
    headers_gz = curl_slist_append(headers_gz, "Content-Type: application/json");
    headers_gz = curl_slist_append(headers_gz, "Content-Encoding: gzip");
    headers_gz = curl_slist_append(headers_gz, uuid.str().c_str());
    headers_gz = curl_slist_append(headers_gz, serial.str().c_str());
    headers_gz = curl_slist_append(headers_gz, site_uuid.str().c_str());
    headers_gz = curl_slist_append(headers_gz, conf_digest.str().c_str());
}

void ndSinkThread::FreeHeaders(void)
{
    if (headers != NULL) {
        curl_slist_free_all(headers);
        headers = NULL;
    }

    if (headers_gz != NULL) {
        curl_slist_free_all(headers_gz);
        headers_gz = NULL;
    }
}

void ndSinkThread::Upload(void)
{
    CURLcode curl_rc;
    size_t xfer = 0, total = pending.size();

    do {
        nd_debug_printf("%s: payload %lu/%lu (%d of %d bytes)...\n",
            tag.c_str(), ++xfer, total, pending.front().second.size(), pending_size);

        if (! pending.front().first)
            curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);
        else
            curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers_gz);

        curl_easy_setopt(ch, CURLOPT_POSTFIELDSIZE, pending.front().second.size());
        curl_easy_setopt(ch, CURLOPT_POSTFIELDS, pending.front().second.data());

        body_data.clear();

        if ((curl_rc = curl_easy_perform(ch)) != CURLE_OK)
            break;

        long http_rc = 0;
        if ((curl_rc = curl_easy_getinfo(ch,
            CURLINFO_RESPONSE_CODE, &http_rc)) != CURLE_OK)
            break;

        char *content_type = NULL;
        curl_easy_getinfo(ch, CURLINFO_CONTENT_TYPE, &content_type);

        double content_length = 0;
        curl_easy_getinfo(ch, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &content_length);

        if (content_type != NULL && content_length != 0.0f) {
            if (strcasecmp("application/json", content_type) == 0)
                ProcessResponse();
        }

        switch (http_rc) {
        case 200:
            break;

        case 400:
#ifndef _ND_LEAN_AND_MEAN
            if (ND_DEBUG || ND_DEBUG_UPLOAD) {
                FILE *hf = fopen(ND_JSON_FILE_BAD_SEND, "w");
                if (hf != NULL) {
                    fwrite(pending.front().second.data(),
                        1, pending.front().second.size(), hf);
                    fclose(hf);
                    nd_debug_printf(
                        "%s: wrote rejected payload to: %s\n",
                        tag.c_str(), ND_JSON_FILE_BAD_SEND);
                }
            }
#endif
            break;

        default:
            return;
        }

        pending_size -= pending.front().second.size();
        pending.pop_front();
    }
    while (pending.size() > 0 && ! terminate);
}

string ndSinkThread::Deflate(const string &data)
{
    int rc;
    z_stream zs;
    string buffer;
    uint8_t chunk[ND_ZLIB_CHUNK_SIZE];

    zs.zalloc = Z_NULL;
    zs.zfree = Z_NULL;
    zs.opaque = Z_NULL;

    if (deflateInit2(
        &zs,
        Z_DEFAULT_COMPRESSION,
        Z_DEFLATED, 15 /* window bits */ | 16 /* enable GZIP format */,
        8,
        Z_DEFAULT_STRATEGY
    ) != Z_OK) throw ndSinkThreadException("deflateInit2");

    zs.next_in = (uint8_t *)data.data();
    zs.avail_in = data.size();

    do {
        zs.avail_out = ND_ZLIB_CHUNK_SIZE;
        zs.next_out = chunk;
        if ((rc = deflate(&zs, Z_FINISH)) == Z_STREAM_ERROR)
            throw ndSinkThreadException("deflate");
        buffer.append((const char *)chunk, ND_ZLIB_CHUNK_SIZE - zs.avail_out);
    } while (zs.avail_out == 0);

    deflateEnd(&zs);

    if (rc != Z_STREAM_END)
        throw ndSinkThreadException("deflate");

    if (ND_DEBUG || ND_DEBUG_UPLOAD) {
        nd_debug_printf("%s: payload compressed: %lu -> %lu\n",
            tag.c_str(), data.size(), buffer.size());
    }

    return buffer;
}

void ndSinkThread::ProcessResponse(void)
{
    bool create_headers = false;
    ndJsonResponse *response = new ndJsonResponse();

    try {
        if (response == NULL)
            throw runtime_error(strerror(ENOMEM));

        response->Parse(body_data);

        switch (response->resp_code) {
        case ndJSON_RESP_OK:
            if (response->uuid_site.size() == ND_SITE_UUID_LEN
                && nd_save_uuid(
                    response->uuid_site,
                    nd_config.path_uuid_site, ND_SITE_UUID_LEN
                )) {
                nd_printf("%s: saved new site UUID: %s\n", tag.c_str(),
                    response->uuid_site.c_str());

                create_headers = true;
            }

            for (ndJsonData::const_iterator i = response->data.begin();
                i != response->data.end(); i++) {

                if (i->first == ND_CONF_SINK_BASE) {

                    if (nd_save_response_data(ND_CONF_SINK_PATH, i->second) == 0 &&
                        nd_sha1_file(
                            nd_config.path_sink_config, nd_config.digest_sink_config
                        ) == 0)
                        create_headers = true;

                    break;
                }
            }

            if (create_headers) CreateHeaders();

            PushResponse(response);

            nd_debug_printf("%s: [%d] %s\n", tag.c_str(),
                response->resp_code,
                (response->resp_message.size() > 0) ?
                    response->resp_message.c_str() : "(no message)");
            break;

        default:
            nd_printf("%s: [%d] %s\n", tag.c_str(),
                response->resp_code,
                (response->resp_message.size() > 0) ?
                    response->resp_message.c_str() : "(no message)");
            if (response != NULL) delete response;
        }
    } catch (ndJsonParseException &e) {
        if (response != NULL) delete response;
        nd_printf("JSON response parse error: %s\n", e.what());
    } catch (runtime_error &e) {
        nd_printf("JSON response parse error: %s\n", e.what());
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
