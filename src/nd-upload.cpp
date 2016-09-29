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
#include <iomanip>
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
    : ndThread("netify-sink", -1),
    headers(NULL), headers_gz(NULL), pending_size(0)
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
    curl_easy_setopt(ch, CURLOPT_ACCEPT_ENCODING, "gzip");

    if (nd_debug) {
        curl_easy_setopt(ch, CURLOPT_VERBOSE, 1);
        curl_easy_setopt(ch, CURLOPT_DEBUGFUNCTION, nd_curl_debug);
        curl_easy_setopt(ch, CURLOPT_DEBUGDATA, static_cast<void *>(this));
        curl_easy_setopt(ch, CURLOPT_COOKIEJAR, ND_COOKIE_JAR);
    }

    if (nd_config.ssl_verify_peer == false) {
        curl_easy_setopt(ch, CURLOPT_SSL_VERIFYPEER, 0);
        curl_easy_setopt(ch, CURLOPT_SSL_VERIFYHOST, 0);
    }

    if (nd_config.ssl_use_tlsv1)
        curl_easy_setopt(ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);

    CreateHeaders();

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
    FreeHeaders();
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

void ndUploadThread::CreateHeaders(void)
{
    FreeHeaders();

    ostringstream user_agent;
    user_agent << "User-Agent: " <<
        PACKAGE_NAME << "/" << GIT_RELEASE <<
        " JSON/" << fixed << showpoint << setprecision(2) << ND_JSON_VERSION <<
        " nDPI/" << ndpi_revision() <<
        " (+" << PACKAGE_URL << ")";

    ostringstream uuid;
    uuid << "X-UUID: " << nd_config.uuid;

    ostringstream serial;
    serial << "X-UUID-Serial: " <<
        ((nd_config.uuid_serial != NULL) ? nd_config.uuid_serial : "-");

    ostringstream realm_uuid;
    if (nd_config.uuid_realm[0] != '-')
        realm_uuid << "X-UUID-Realm: " << nd_config.uuid_realm;
    else {
        string _uuid;
        if (LoadRealmUUID(_uuid))
            realm_uuid << "X-UUID-Realm: " << _uuid;
        else
            realm_uuid << "X-UUID-Realm: " << nd_config.uuid_realm;
    }

    headers = curl_slist_append(headers, user_agent.str().c_str());
    headers = curl_slist_append(headers, "Content-Type: application/json");
    headers = curl_slist_append(headers, uuid.str().c_str());
    headers = curl_slist_append(headers, serial.str().c_str());
    headers = curl_slist_append(headers, realm_uuid.str().c_str());

    headers_gz = curl_slist_append(headers_gz, user_agent.str().c_str());
    headers_gz = curl_slist_append(headers_gz, "Content-Type: application/json");
    headers_gz = curl_slist_append(headers_gz, "Content-Encoding: gzip");
    headers_gz = curl_slist_append(headers_gz, uuid.str().c_str());
    headers_gz = curl_slist_append(headers_gz, serial.str().c_str());
    headers_gz = curl_slist_append(headers_gz, realm_uuid.str().c_str());
}

void ndUploadThread::FreeHeaders(void)
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

void ndUploadThread::Upload(void)
{
    CURLcode rc;
    size_t xfer = 0, total = pending.size();

    do {
        if (nd_debug) nd_printf("%s: payload %lu/%lu (%d of %d bytes)...\n",
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

        if (content_type != NULL && content_length != 0.0f) {
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
    ndJsonObjectType json_type = ndJSON_OBJ_TYPE_NULL;
    ndJsonObjectResult *json_result = NULL;
    ndJsonObjectConfig *json_config = NULL;
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
        if (nd_debug) nd_printf("%s: upload successful.\n", tag.c_str());
        break;
    case ndJSON_OBJ_TYPE_RESULT:
        json_result = reinterpret_cast<ndJsonObjectResult *>(json_obj);
        if (nd_debug) {
            nd_printf("%s: [%d] %s\n", tag.c_str(),
                json_result->GetCode(),
                (json_result->GetMessage().length() > 0) ?
                    json_result->GetMessage().c_str() : "(null)");
        }
        if (json_result->GetCode() == ndJSON_RES_SET_REALM_UUID) {
            if (json_result->GetMessage().length() == ND_REALM_UUID_LEN
                && SaveRealmUUID(json_result->GetMessage())) {
                if (nd_debug) {
                    nd_printf("%s: saved new realm UUID: %s\n", tag.c_str(),
                        json_result->GetMessage().c_str());
                }
                CreateHeaders();
            }
        }
        break;
    case ndJSON_OBJ_TYPE_CONFIG:
        if (nd_debug) nd_printf("%s: upload successful (w/config).\n", tag.c_str());
        json_config = reinterpret_cast<ndJsonObjectConfig *>(json_obj);

        if (json_config->IsPresent(ndJSON_CFG_TYPE_CONTENT_MATCH))
            ExportConfig(ndJSON_CFG_TYPE_CONTENT_MATCH, json_config);
        if (json_config->IsPresent(ndJSON_CFG_TYPE_HOST_PROTOCOL))
            ExportConfig(ndJSON_CFG_TYPE_HOST_PROTOCOL, json_config);

        kill(getpid(), SIGHUP);

        break;
    case ndJSON_OBJ_TYPE_NULL:
    default:
        nd_printf("%s: unexpected JSON result type.\n", tag.c_str());
    }

    if (json_obj != NULL) delete json_obj;
}

bool ndUploadThread::LoadRealmUUID(string &uuid)
{
    char _uuid[ND_REALM_UUID_LEN + 1];
    FILE *fh = fopen(ND_REALM_UUID_PATH, "r");

    if (fh == NULL) return false;
    if (fread((void *)_uuid,
        1, ND_REALM_UUID_LEN, fh) != ND_REALM_UUID_LEN) {
        fclose(fh);
        return false;
    }

    fclose(fh);
    _uuid[ND_REALM_UUID_LEN] = '\0';
    uuid.assign(_uuid);

    return true;
}

bool ndUploadThread::SaveRealmUUID(const string &uuid)
{
    FILE *fh = fopen(ND_REALM_UUID_PATH, "w");

    if (fwrite((const void *)uuid.c_str(),
        1, ND_REALM_UUID_LEN, fh) != ND_REALM_UUID_LEN) {
        fclose(fh);
        return false;
    }

    fclose(fh);
    return true;
}

bool ndUploadThread::ExportConfig(ndJsonConfigType type, ndJsonObjectConfig *config)
{
    int rc = 0;
    FILE *fp = NULL;
    string config_type_string;
    size_t entries = 0;
    ndJsonConfigContentMatch *content_match;
    ndJsonConfigHostProtocol *host_protocol;
    char ip_addr[INET6_ADDRSTRLEN];
    struct sockaddr_in *saddr_ip4;
    struct sockaddr_in6 *saddr_ip6;

    switch (type) {
    case ndJSON_CFG_TYPE_CONTENT_MATCH:
        fp = fopen(nd_config.csv_content_match, "w");
        config_type_string = "content match";
        entries = config->GetContentMatchCount();
        break;
    case ndJSON_CFG_TYPE_HOST_PROTOCOL:
        fp = fopen(nd_config.csv_host_protocol, "w");
        config_type_string = "host protocol";
        entries = config->GetHostProtocolCount();
        break;
    default:
        throw ndJsonParseException("Unsupported configuration type for export");
    }

    if (fp == NULL)
        throw ndJsonParseException("Error opening file for configuration export");

    switch (type) {
    case ndJSON_CFG_TYPE_CONTENT_MATCH:
        fprintf(fp, "\"match\",\"application_name\",\"application_id\"\n");
        content_match = config->GetFirstContentMatchEntry();
        while (content_match != NULL) {
            fprintf(fp, "\"%s\",\"%s\",%u\n",
                content_match->match.c_str(),
                content_match->app_name.c_str(),
                content_match->app_id);
            content_match = config->GetNextContentMatchEntry();
        }
        fclose(fp);
        nd_sha1_file(
            nd_config.csv_content_match, nd_config.digest_content_match);
        break;
    case ndJSON_CFG_TYPE_HOST_PROTOCOL:
        fprintf(fp, "\"ip_address\",\"ip_prefix\",\"application_id\"\n");
        host_protocol = config->GetFirstHostProtocolEntry();
        while (host_protocol != NULL) {
            memset(ip_addr, '\0', INET6_ADDRSTRLEN);
            switch (host_protocol->ip_addr.ss_family) {
            case AF_INET:
                saddr_ip4 = reinterpret_cast<struct sockaddr_in *>(&host_protocol->ip_addr);
                if (inet_ntop(AF_INET, &saddr_ip4->sin_addr, ip_addr, INET6_ADDRSTRLEN))
                    rc = 1;
                break;
            case AF_INET6:
                saddr_ip6 = reinterpret_cast<struct sockaddr_in6 *>(&host_protocol->ip_addr);
                if (inet_ntop(AF_INET6, &saddr_ip6->sin6_addr, ip_addr, INET6_ADDRSTRLEN))
                    rc = 1;
                break;
            }
            if (rc == 1) {
                fprintf(fp, "\"%s\",%hhu,%u\n",
                    ip_addr, host_protocol->ip_prefix, host_protocol->app_id);
            }
            host_protocol = config->GetNextHostProtocolEntry();
        }
        fclose(fp);
        nd_sha1_file(
            nd_config.csv_host_protocol, nd_config.digest_host_protocol);
        break;
    default:
        fclose(fp);
        break;
    }

    if (nd_debug) {
        if (entries == 0) {
            nd_printf("%s: cleared %s configuration\n", tag.c_str(),
                config_type_string.c_str());
        }
        else {
            nd_printf("%s: exported %lu %s configuration entries\n", tag.c_str(),
                entries, config_type_string.c_str());
        }
    }

    return true;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
