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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string>
#include <cstring>
#include <cerrno>
#include <stdexcept>
#include <iostream>
#include <map>
#include <vector>
#include <unordered_map>
#include <queue>
#include <deque>
#include <sstream>

#include <unistd.h>
#include <signal.h>
#include <pthread.h>

#include <curl/curl.h>
#include <json.h>
#include <zlib.h>

#include "ndpi_main.h"

using namespace std;

#include "netifyd.h"
#include "nd-json.h"
#include "nd-thread.h"
#include "nd-upload.h"
#include "nd-util.h"

extern bool nd_debug;

extern ndGlobalConfig nd_config;

static int nd_curl_debug(
    CURL *ch, curl_infotype type, char *data, size_t size, void *param)
{
    string buffer;
    if (nd_debug == false) return 0;

    ndThread *thread = reinterpret_cast<ndThread *>(param);

    switch (type) {
    case CURLINFO_TEXT:
        buffer.assign(data, size);
        nd_printf("%s: %s", thread->GetTag().c_str(), buffer.c_str());
        break;
    case CURLINFO_HEADER_IN:
        buffer.assign(data, size);
        nd_printf("%s: <-- %s", thread->GetTag().c_str(), buffer.c_str());
        break;
    case CURLINFO_HEADER_OUT:
        buffer.assign(data, size);
        nd_printf("%s: --> %s", thread->GetTag().c_str(), buffer.c_str());
        break;
    case CURLINFO_DATA_IN:
        nd_printf("%s: <-- %lu data bytes\n", thread->GetTag().c_str(), size);
        break;
    case CURLINFO_DATA_OUT:
        nd_printf("%s: --> %lu data bytes\n", thread->GetTag().c_str(), size);
        break;
    case CURLINFO_SSL_DATA_IN:
        nd_printf("%s: <-- %lu SSL bytes\n", thread->GetTag().c_str(), size);
        break;
    case CURLINFO_SSL_DATA_OUT:
        nd_printf("%s: --> %lu SSL bytes\n", thread->GetTag().c_str(), size);
        break;
    default:
        break;
    }

    return 0;
}

static size_t ndUploadThread_read_data(
    char *data, size_t size, size_t nmemb, void *user)
{
    size_t length = size * nmemb;
    ndUploadThread *thread_upload = reinterpret_cast<ndUploadThread *>(user);

    thread_upload->AppendData((const char *)data, length);

    return length;
}

ndUploadThread::ndUploadThread()
    : ndThread("netify-sink", -1), headers(NULL), headers_gz(NULL), pending_size(0)
{
    int rc;

    if ((ch = curl_easy_init()) == NULL)
        throw ndThreadException("curl_easy_init");

    curl_easy_setopt(ch, CURLOPT_URL, nd_config.url_upload);
    curl_easy_setopt(ch, CURLOPT_POST, 1);
    curl_easy_setopt(ch, CURLOPT_FOLLOWLOCATION, 1);
    curl_easy_setopt(ch, CURLOPT_COOKIEFILE, (nd_debug) ? ND_COOKIE_JAR : "");
    curl_easy_setopt(ch, CURLOPT_WRITEFUNCTION, ndUploadThread_read_data);
    curl_easy_setopt(ch, CURLOPT_WRITEDATA, static_cast<void *>(this));

    if (nd_debug) {
        curl_easy_setopt(ch, CURLOPT_VERBOSE, 1);
        curl_easy_setopt(ch, CURLOPT_DEBUGFUNCTION, nd_curl_debug);
        curl_easy_setopt(ch, CURLOPT_DEBUGDATA, static_cast<void *>(this));
        curl_easy_setopt(ch, CURLOPT_COOKIEJAR, ND_COOKIE_JAR);
    }

    if (nd_config.ssl_verify_peer == false)
        curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 0);

    ostringstream user_agent;
    user_agent << "User-Agent: " <<
        PACKAGE_NAME << "/" << PACKAGE_VERSION <<
        " (+" << PACKAGE_URL << ")";

    ostringstream uuid;
    uuid << "X-UUID: " << nd_config.uuid;

    ostringstream serial;
    serial << "X-UUID-Serial: " <<
        ((nd_config.uuid_serial != NULL) ? nd_config.uuid_serial : "-");

    ostringstream domain_uuid;
    domain_uuid << "X-UUID-Domain: " << nd_config.uuid_domain;

    headers = curl_slist_append(headers, user_agent.str().c_str());
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, uuid.str().c_str());
    headers = curl_slist_append(headers, serial.str().c_str());
    headers = curl_slist_append(headers, domain_uuid.str().c_str());

    headers_gz = curl_slist_append(headers_gz, user_agent.str().c_str());
    headers_gz = curl_slist_append(headers_gz, "Content-Type: application/json");
    headers_gz = curl_slist_append(headers_gz, "Content-Encoding: gzip");
    headers_gz = curl_slist_append(headers_gz, uuid.str().c_str());
    headers_gz = curl_slist_append(headers_gz, serial.str().c_str());
    headers_gz = curl_slist_append(headers_gz, domain_uuid.str().c_str());

    pthread_condattr_t cond_attr;

    pthread_condattr_init(&cond_attr);
    pthread_condattr_setclock(&cond_attr, CLOCK_MONOTONIC);
    if ((rc = pthread_cond_init(&uploads_cond, &cond_attr)) != 0)
        throw ndThreadException(strerror(rc));
    pthread_condattr_destroy(&cond_attr);

    if ((rc = pthread_mutex_init(&uploads_cond_mutex, NULL)) != 0)
        throw ndThreadException(strerror(rc));
}

ndUploadThread::~ndUploadThread()
{
    Join();
    if (ch != NULL) curl_easy_cleanup(ch);
    if (headers != NULL) curl_slist_free_all(headers);
    if (headers_gz != NULL) curl_slist_free_all(headers_gz);
}

void *ndUploadThread::Entry(void)
{
    int rc;

    nd_printf("%s: thread started.\n", tag.c_str());

    while (terminate == false) {
        if ((rc = pthread_mutex_lock(&lock)) != 0)
            throw ndThreadException(strerror(rc));

        if (uploads.size() == 0) {
            if ((rc = pthread_mutex_unlock(&lock)) != 0)
                throw ndThreadException(strerror(rc));

            if ((rc = pthread_mutex_lock(&uploads_cond_mutex)) != 0)
                throw ndThreadException(strerror(rc));
            if ((rc = pthread_cond_wait(&uploads_cond, &uploads_cond_mutex)) != 0)
                throw ndThreadException(strerror(rc));
            if ((rc = pthread_mutex_unlock(&uploads_cond_mutex)) != 0)
                throw ndThreadException(strerror(rc));

            continue;
        }

        if (uploads.back() == "terminate")
            terminate = true;
        else {
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
        }

        if ((rc = pthread_mutex_unlock(&lock)) != 0)
            throw ndThreadException(strerror(rc));

        if (terminate == false && pending.size() > 0) Upload();
    }

    return NULL;
}

void ndUploadThread::QueuePush(const string &json)
{
    int rc;

    if ((rc = pthread_mutex_lock(&lock)) != 0)
        throw ndThreadException(strerror(rc));

    uploads.push(json);

    if ((rc = pthread_cond_broadcast(&uploads_cond)) != 0)
        throw ndThreadException(strerror(rc));
    if ((rc = pthread_mutex_unlock(&lock)) != 0)
        throw ndThreadException(strerror(rc));
}

void ndUploadThread::Upload(void)
{
    CURLcode rc;
    size_t xfer = 0, total = pending.size();

    do {
        if (nd_debug) nd_printf("%s: data %lu/%lu (%d of %d bytes)...\n",
            tag.c_str(), ++xfer, total, pending.front().second.size(), pending_size);

        if (!pending.front().first)
            curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers);
        else
            curl_easy_setopt(ch, CURLOPT_HTTPHEADER, headers_gz);

        curl_easy_setopt(ch, CURLOPT_POSTFIELDSIZE, pending.front().second.size());
        curl_easy_setopt(ch, CURLOPT_POSTFIELDS, pending.front().second.data());

        body_data.clear();

        if ((rc = curl_easy_perform(ch)) != CURLE_OK)
            break;

        long http_rc = 0;
        if ((rc = curl_easy_getinfo(ch,
            CURLINFO_RESPONSE_CODE, &http_rc)) != CURLE_OK)
            break;

        char *content_type = NULL;
        curl_easy_getinfo(ch, CURLINFO_CONTENT_TYPE, &content_type);

        double content_length = 0;
        curl_easy_getinfo(ch, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &content_length);

        if (content_type != NULL && content_length > 0) {
            if (strcasecmp("application/json", content_type) == 0)
                ProcessResponse();
        }

        switch (http_rc) {
        case 200:
            break;

        case 400:
            if (nd_debug) {
                FILE *hf = fopen("/tmp/rejected.json", "w");
                if (hf != NULL) {
                    fwrite(pending.front().second.data(),
                        1, pending.front().second.size(), hf);
                    fclose(hf);
                    nd_printf("Wrote rejected payload to: /tmp/rejected.json\n");
                }
            }
            break;

        default:
            return;
        }

        pending_size -= pending.front().second.size();
        pending.pop_front();
    }
    while (pending.size() > 0);
}

string ndUploadThread::Deflate(const string &data)
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
    ) != Z_OK) throw ndThreadException("deflateInit2");

    zs.next_in = (uint8_t *)data.data();
    zs.avail_in = data.size();

    do {
        zs.avail_out = ND_ZLIB_CHUNK_SIZE;
        zs.next_out = chunk;
        if ((rc = deflate(&zs, Z_FINISH)) == Z_STREAM_ERROR)
            throw ndThreadException("deflate");
        buffer.append((const char *)chunk, ND_ZLIB_CHUNK_SIZE - zs.avail_out);
    } while (zs.avail_out == 0);

    deflateEnd(&zs);

    if (rc != Z_STREAM_END)
        throw ndThreadException("deflate");

    if (nd_debug) {
        nd_printf("%s: payload compressed: %lu -> %lu\n",
            tag.c_str(), data.size(), buffer.size());
    }

    return buffer;
}

void ndUploadThread::ProcessResponse(void)
{
    ndJsonObject *json_obj = NULL;
    ndJsonObjectType json_type;
    ndJsonObjectResult *json_result = NULL;
    ndJsonObjectFactory json_factory;

    try {
        json_type = json_factory.Parse(body_data, &json_obj);
    } catch (ndJsonParseException &e) {
        nd_printf("JSON parse error: %s\n", e.what());
        if (nd_debug)
            nd_printf("Payload:\n\"%s\"\n", body_data.c_str());
    }

    switch (json_type) {
    case ndJSON_OBJ_TYPE_OK:
        break;
    case ndJSON_OBJ_TYPE_RESULT:
        if (nd_debug) break;
        json_result = reinterpret_cast<ndJsonObjectResult *>(json_obj);
        nd_printf("%s: [%d] %s\n", tag.c_str(),
            json_result->GetCode(),
            json_result->GetMessage().c_str());
        break;
    case ndJSON_OBJ_TYPE_NULL:
    default:
        nd_printf("%s: Unexpected JSON result type.\n", tag.c_str());
    }

    if (json_obj != NULL) delete json_obj;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
