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
#endif
#include <regex>

#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include <string.h>

#include <curl/curl.h>

#include <pcap/pcap.h>

#include <zlib.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

using namespace std;

#include "netifyd.h"

#include "nd-ndpi.h"
#include "nd-json.h"
#include "nd-thread.h"
#include "nd-util.h"
#include "nd-sink.h"
#include "nd-signal.h"

extern nd_global_config nd_config;

static int nd_curl_debug(CURL *ch __attribute__((unused)),
    curl_infotype type, char *data, size_t size, void *param)
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
    double dltotal __attribute__((unused)), double dlnow __attribute__((unused)),
    double ultotal __attribute__((unused)), double ulnow __attribute__((unused)))
#else
static int ndSinkThread_progress(void *user,
    curl_off_t dltotal __attribute__((unused)), curl_off_t dlnow __attribute__((unused)),
    curl_off_t ultotal __attribute__((unused)), curl_off_t ulnow __attribute__((unused)))
#endif
{
    ndSinkThread *thread_upload = reinterpret_cast<ndSinkThread *>(user);

    if (thread_upload->ShouldTerminate()) return 1;

    return 0;
}

ndSinkThread::ndSinkThread()
    : ndThread("nd-sink", -1),
    headers(NULL), headers_gz(NULL), pending_size(0), post_errors(0),
    update_imf(1), update_count(0)
{
    CreateHandle();

    int rc;

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
    pthread_cond_broadcast(&uploads_cond);

    Join();

    DestroyHandle();

    pthread_cond_destroy(&uploads_cond);
    pthread_mutex_destroy(&uploads_cond_mutex);

    pthread_mutex_lock(&response_mutex);

    for (ndResponseQueue::const_iterator i = responses.begin();
        i != responses.end(); i++) delete (*i);

    responses.clear();

    pthread_mutex_unlock(&response_mutex);
    pthread_mutex_destroy(&response_mutex);
}

void ndSinkThread::CreateHandle(void)
{
    if ((ch = curl_easy_init()) == NULL)
        throw ndSinkThreadException("curl_easy_init");

    curl_easy_setopt(ch, CURLOPT_URL, nd_config.url_sink);
    curl_easy_setopt(ch, CURLOPT_POST, 1L);
    curl_easy_setopt(ch, CURLOPT_POSTREDIR, 3L);
    curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(ch, CURLOPT_CONNECTTIMEOUT, (long)nd_config.sink_connect_timeout);
    curl_easy_setopt(ch, CURLOPT_TIMEOUT, (long)nd_config.sink_xfer_timeout);
    curl_easy_setopt(ch, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(ch, CURLOPT_COOKIEFILE, (ND_DEBUG_UPLOAD) ? ND_COOKIE_JAR : "");

    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, ndSinkThread_read_data);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, static_cast<void *>(this));

    curl_easy_setopt(ch, CURLOPT_NOPROGRESS, 0L);
#if (LIBCURL_VERSION_NUM < 0x073200)
    curl_easy_setopt(ch, CURLOPT_PROGRESSFUNCTION, ndSinkThread_progress);
    curl_easy_setopt(ch, CURLOPT_PROGRESSDATA, static_cast<void *>(this));
#else
    curl_easy_setopt(ch, CURLOPT_XFERINFOFUNCTION, ndSinkThread_progress);
    curl_easy_setopt(ch, CURLOPT_XFERINFODATA, static_cast<void *>(this));
#endif
#ifdef _ND_WITH_LIBCURL_ZLIB
#if (LIBCURL_VERSION_NUM < 0x072106)
    curl_easy_setopt(ch, CURLOPT_ENCODING, "gzip");
#else
    curl_easy_setopt(ch, CURLOPT_ACCEPT_ENCODING, "gzip");
#endif
#endif // _ND_WITH_LIBCURL_ZLIB
    if (ND_DEBUG_UPLOAD) {
        curl_easy_setopt(ch, CURLOPT_VERBOSE, 1L);
        curl_easy_setopt(ch, CURLOPT_DEBUGFUNCTION, nd_curl_debug);
        curl_easy_setopt(ch, CURLOPT_DEBUGDATA, static_cast<void *>(this));
        curl_easy_setopt(ch, CURLOPT_COOKIEJAR, ND_COOKIE_JAR);
    }

    if (! ND_SSL_VERIFY) {
        curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(ch, CURLOPT_SSL_VERIFYHOST, 0L);
    }

    if (ND_SSL_USE_TLSv1)
        curl_easy_setopt(ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);

    CreateHeaders();
}

void ndSinkThread::DestroyHandle(void)
{
    if (ch != NULL) {
        curl_easy_cleanup(ch);
        ch = NULL;
    }

    FreeHeaders();
}

void *ndSinkThread::Entry(void)
{
    int rc;

    nd_debug_printf("%s: thread started.\n", tag.c_str());

    while (terminate == false) {
        Lock();

        if (uploads.size() == 0) {
            Unlock();

            if ((rc = pthread_mutex_lock(&uploads_cond_mutex)) != 0)
                throw ndSinkThreadException(strerror(rc));
            if ((rc = pthread_cond_wait(&uploads_cond, &uploads_cond_mutex)) != 0)
                throw ndSinkThreadException(strerror(rc));
            if ((rc = pthread_mutex_unlock(&uploads_cond_mutex)) != 0)
                throw ndSinkThreadException(strerror(rc));

            continue;
        }

        do {
            if (! ND_UPLOAD_ENABLED) {
                pending.clear();
                pending_size = 0;
            }

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

        Unlock();

        if (terminate == false && pending.size() > 0) Upload();
    }

    return NULL;
}

void ndSinkThread::Terminate(void)
{
    int rc;

    Lock();

    if ((rc = pthread_cond_broadcast(&uploads_cond)) != 0)
        throw ndSinkThreadException(strerror(rc));

    terminate = true;

    Unlock();
}

void ndSinkThread::QueuePush(const string &json)
{
    int rc;

    Lock();

    if (! ND_UPLOAD_ENABLED) {
        while (! uploads.empty()) uploads.pop();
    }

    uploads.push(json);

    if ((rc = pthread_cond_broadcast(&uploads_cond)) != 0)
        throw ndSinkThreadException(strerror(rc));

    Unlock();
}

size_t ndSinkThread::QueuePendingSize(void)
{
    size_t bytes;

    Lock();

    bytes = pending_size;

    Unlock();

    return bytes;
}

void ndSinkThread::PushResponse(ndJsonResponse *response)
{
    pthread_mutex_lock(&response_mutex);

    responses.push_back(response);

    pthread_mutex_unlock(&response_mutex);

    kill(getpid(), ND_SIG_SINK_REPLY);
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

    ostringstream uuid_serial;
    if (strncmp(nd_config.uuid_serial, ND_AGENT_SERIAL_NULL, ND_AGENT_SERIAL_LEN))
        uuid_serial << "X-UUID-Serial: " << nd_config.uuid_serial;
    else {
        string _uuid;
        if (nd_load_uuid(_uuid, nd_config.path_uuid_serial, ND_AGENT_SERIAL_LEN))
            uuid_serial << "X-UUID-Serial: " << _uuid;
        else
            uuid_serial << "X-UUID-Serial: " << nd_config.uuid_serial;
    }

    ostringstream uuid_site;
    if (strncmp(nd_config.uuid_site, ND_SITE_UUID_NULL, ND_SITE_UUID_LEN))
        uuid_site << "X-UUID-Site: " << nd_config.uuid_site;
    else {
        string _uuid;
        if (nd_load_uuid(_uuid, nd_config.path_uuid_site, ND_SITE_UUID_LEN))
            uuid_site << "X-UUID-Site: " << _uuid;
        else
            uuid_site << "X-UUID-Site: " << nd_config.uuid_site;
    }

    string digest;
    nd_sha1_to_string(nd_config.digest_sink_config, digest);

    ostringstream conf_digest;
    conf_digest << "X-Digest-Sink: " << digest;

    headers = curl_slist_append(headers, user_agent.str().c_str());
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, uuid.str().c_str());
    headers = curl_slist_append(headers, uuid_serial.str().c_str());
    headers = curl_slist_append(headers, uuid_site.str().c_str());
    headers = curl_slist_append(headers, conf_digest.str().c_str());

    headers_gz = curl_slist_append(headers_gz, user_agent.str().c_str());
    headers_gz = curl_slist_append(headers_gz, "Content-Type: application/json");
    headers_gz = curl_slist_append(headers_gz, "Content-Encoding: gzip");
    headers_gz = curl_slist_append(headers_gz, uuid.str().c_str());
    headers_gz = curl_slist_append(headers_gz, uuid_serial.str().c_str());
    headers_gz = curl_slist_append(headers_gz, uuid_site.str().c_str());
    headers_gz = curl_slist_append(headers_gz, conf_digest.str().c_str());

    for (map<string, string>::const_iterator i = nd_config.custom_headers.begin();
        i != nd_config.custom_headers.end(); i++) {
        ostringstream os;
        os << (*i).first << ": " << (*i).second;
        headers = curl_slist_append(headers, os.str().c_str());
        headers_gz = curl_slist_append(headers_gz, os.str().c_str());
    }
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
    bool flush_queue = true;
    size_t xfer = 0, total = pending.size();

    if (post_errors == nd_config.sink_max_post_errors) {
        free(nd_config.url_sink);
        nd_config.url_sink = strdup(ND_URL_SINK);
        nd_printf("%s: reverted to default sink URL: %s\n", tag.c_str(),
            nd_config.url_sink);

        DestroyHandle();
        CreateHandle();

        curl_easy_setopt(ch, CURLOPT_URL, nd_config.url_sink);

        post_errors = 0;
    }

    if (++update_count == update_imf || post_errors > 0)
        update_count = 0;
    else {
        nd_debug_printf("%s: payload upload delay: %u of %u\n",
            tag.c_str(), update_count, update_imf);
        return;
    }

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

        if ((curl_rc = curl_easy_perform(ch)) != CURLE_OK) {

            post_errors++;

            ndJsonResponse *response = new ndJsonResponse(
                ndJSON_RESP_POST_ERROR,
                "Some POST error"
            );

            if (response == NULL)
                throw runtime_error(strerror(ENOMEM));
            else
                PushResponse(response);
            break;
        }

        long http_rc = 0;
        if ((curl_rc = curl_easy_getinfo(ch,
            CURLINFO_RESPONSE_CODE, &http_rc)) != CURLE_OK) {

            post_errors++;

            ndJsonResponse *response = new ndJsonResponse(
                ndJSON_RESP_POST_ERROR,
                "Some POST error"
            );

            if (response == NULL)
                throw runtime_error(strerror(ENOMEM));
            else
                PushResponse(response);
            break;
        }

        char *content_type = NULL;
        curl_easy_getinfo(ch, CURLINFO_CONTENT_TYPE, &content_type);

        double content_length = 0.0f;
        curl_easy_getinfo(ch, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &content_length);

        if (content_type == NULL) {
            nd_debug_printf("%s: Missing content type.\n", tag.c_str());

            ndJsonResponse *response = new ndJsonResponse(
                ndJSON_RESP_INVALID_CONTENT_TYPE,
                "Missing content type, expected: application/json"
            );

            if (response == NULL)
                throw runtime_error(strerror(ENOMEM));
            else
                PushResponse(response);
        }
        else if (content_length == 0.0f) {
            nd_debug_printf("%s: Zero-length content length.\n", tag.c_str());

            ndJsonResponse *response = new ndJsonResponse(
                ndJSON_RESP_INVALID_RESPONSE,
                "Invalid content length (zero-bytes)"
            );

            if (response == NULL)
                throw runtime_error(strerror(ENOMEM));
            else
                PushResponse(response);
        }
        else if (strcasecmp("application/json", content_type) != 0) {

            nd_debug_printf("%s: Unexpected content type.\n", tag.c_str());

            ndJsonResponse *response = new ndJsonResponse(
                ndJSON_RESP_INVALID_CONTENT_TYPE,
                "Invalid content type, expected: application/json"
            );

            if (response == NULL)
                throw runtime_error(strerror(ENOMEM));
            else
                PushResponse(response);
        }
        else
            ProcessResponse();

        switch (http_rc) {
        case 200:
            post_errors = 0;
            break;

        case 400:
            post_errors = 0;
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
        case 404:
            post_errors++;
            return;

        default:
            post_errors = 0;
            return;
        }

        pending_size -= pending.front().second.size();
        pending.pop_front();

        if (pending.size() == 0 || terminate)
            flush_queue = false;
        else {
            Lock();

            // Collect upload queue as soon as possible...
            if (uploads.size() != 0) flush_queue = false;

            Unlock();
        }
    }
    while (flush_queue);
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
        Z_DEFLATED,
        15 /* window bits */ | 16 /* enable GZIP format */,
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

        nd_debug_printf(
            "%s: payload compressed: %lu -> %lu: %.1f%%\n",
            tag.c_str(), data.size(), buffer.size(),
            100.0f - ((float)buffer.size() * 100.0f / (float)data.size())
        );
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

        response->update_imf = update_imf;
        response->upload_enabled = ND_UPLOAD_ENABLED;

        response->Parse(body_data);

        if (response->resp_code == ndJSON_RESP_OK) {

            if (response->uuid_site.size() == ND_SITE_UUID_LEN
                && nd_save_uuid(
                    response->uuid_site,
                    nd_config.path_uuid_site, ND_SITE_UUID_LEN
                )) {
                nd_printf("%s: saved new site UUID: %s\n", tag.c_str(),
                    response->uuid_site.c_str());

                create_headers = true;
            }

            if (response->url_sink.size() &&
                response->url_sink != nd_config.url_sink) {
                if (nd_save_sink_url(response->url_sink)) {
                    free(nd_config.url_sink);
                    nd_config.url_sink = strdup(response->url_sink.c_str());
                    nd_printf("%s: saved new sink URL: %s\n", tag.c_str(),
                        response->url_sink.c_str());

                    curl_easy_setopt(ch, CURLOPT_URL, nd_config.url_sink);
                }
            }

            for (ndJsonData::const_iterator i = response->data.begin();
                i != response->data.end(); i++) {

                if (i->first == ND_CONF_SINK_BASE) {

                    if (nd_save_response_data(ND_CONF_SINK_PATH, i->second) == 0 &&
                        nd_sha1_file(
                            nd_config.path_sink_config, nd_config.digest_sink_config
                        ) == 0)
                        create_headers = true;
                }
            }

            if (create_headers) CreateHeaders();
        }

        if (response->update_imf > 0 && response->update_imf != update_imf) {
            nd_debug_printf("%s: changing update multiplier from: %u"
                " to: %u\n", tag.c_str(), update_imf, response->update_imf);
            update_imf = response->update_imf;
        }

        if (response->upload_enabled != (ND_UPLOAD_ENABLED > 0)) {

            if (response->upload_enabled)
                nd_config.flags |= ndGF_UPLOAD_ENABLED;
            else
                nd_config.flags &= ~ndGF_UPLOAD_ENABLED;

            nd_printf("%s: payload uploads: %s\n",
                tag.c_str(), ND_UPLOAD_ENABLED ? "enabled" : "disabled");
        }

    } catch (ndJsonParseException &e) {
        response->resp_code = ndJSON_RESP_PARSE_ERROR;
        response->resp_message = e.what();
    } catch (runtime_error &e) {
        nd_printf("JSON response parse error: %s\n", e.what());
    }

    if (response != NULL) {
        nd_debug_printf("%s: [%d] %s\n", tag.c_str(),
            response->resp_code,
            (response->resp_message.size() > 0) ?
                response->resp_message.c_str() : "(no message)");

        PushResponse(response);
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
