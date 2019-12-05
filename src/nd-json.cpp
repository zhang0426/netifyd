// Netify Agent
// Copyright (C) 2015-2019 eGloo Incorporated <http://www.egloo.ca>
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
#include <vector>
#include <map>
#include <unordered_map>
#include <regex>

#include <sys/types.h>
#include <sys/stat.h>

#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>

#include <pcap/pcap.h>

#include <nlohmann/json.hpp>
using json = nlohmann::json;

using namespace std;

#include "netifyd.h"

#include "nd-ndpi.h"
#include "nd-base64.h"
#include "nd-json.h"
#include "nd-util.h"

extern nd_global_config nd_config;

void nd_json_to_string(const json &j, string &output, bool pretty)
{
    output = j.dump(pretty ? ND_JSON_INDENT : 0);
#ifdef HAVE_WORKING_REGEX
    vector<pair<regex *, string> >::const_iterator i;
    for (i = nd_config.privacy_regex.begin();
        i != nd_config.privacy_regex.end(); i++) {

        string result = regex_replace(output, *((*i).first), (*i).second);
        if (result.size()) output = result;
    }
#endif
}

void nd_json_save_to_file(const json &j, const string &filename, bool pretty)
{
    string output;
    nd_json_to_string(j, output, pretty);

    nd_file_save(filename, output,
        false, ND_JSON_FILE_MODE, ND_JSON_FILE_USER, ND_JSON_FILE_GROUP);
}

void ndJsonStatus::Parse(const string &json)
{
#if 1
#else
    json_object *jtype, *jtimestamp, *juptime, *jflows, *jflows_prev;
    json_object *jmaxrss_kb, *jmaxrss_kb_prev, *jtcm_kb, *jtcm_kb_prev;
    json_object *jdhc_status, *jdhc_size, *jsink_status, *jsink_queue_size_kb;
    json_object *jsink_queue_max_size_kb, *jsink_resp_code;

    json_tokener_reset(jtok);

    json_object *jobj = json_tokener_parse_ex(
        jtok, json.c_str(), json.length()
    );

    try {
        enum json_tokener_error jterr;

        if ((jterr = json_tokener_get_error(jtok)) != json_tokener_success)
            throw ndJsonParseException(json_tokener_error_desc(jterr));

        if (! json_object_is_type(jobj, json_type_object))
            throw ndJsonParseException("Unexpected JSON type; not and object");

        // Extract and validate JSON type
        if (! json_object_object_get_ex(jobj, "type", &jtype))
            throw ndJsonParseException("Missing JSON type");

        if (! json_object_is_type(jtype, json_type_string))
            throw ndJsonParseException("Unexpected JSON type, string required");

        string type = json_object_get_string(jtype);
        if (type != "agent_status")
            throw ndJsonParseException("Unexpected JSON type, must be: agent_status");

        // Extract and validate timestamp
        if (! json_object_object_get_ex(jobj, "timestamp", &jtimestamp))
            throw ndJsonParseException("Missing JSON timestamp");

        if (! json_object_is_type(jtimestamp, json_type_int))
            throw ndJsonParseException("Unexpected JSON timestamp type");

        timestamp = (time_t)json_object_get_int64(jtimestamp);

        // Extract and validate uptime
        if (! json_object_object_get_ex(jobj, "uptime", &juptime))
            throw ndJsonParseException("Missing JSON uptime");

        if (! json_object_is_type(juptime, json_type_int))
            throw ndJsonParseException("Unexpected JSON uptime type");

        uptime = (time_t)json_object_get_int64(juptime);

        // Extract and validate flows
        if (! json_object_object_get_ex(jobj, "flows", &jflows))
            throw ndJsonParseException("Missing JSON flows");

        if (! json_object_is_type(jflows, json_type_int))
            throw ndJsonParseException("Unexpected JSON flows type");

        stats.flows = json_object_get_int(jflows);

        // Extract and validate flows_prev
        if (! json_object_object_get_ex(jobj, "flows_prev", &jflows_prev))
            throw ndJsonParseException("Missing JSON flows_prev");

        if (! json_object_is_type(jflows_prev, json_type_int))
            throw ndJsonParseException("Unexpected JSON flows_prev type");

        stats.flows_prev = json_object_get_int(jflows_prev);
#if (SIZEOF_LONG == 4)
        // Extract and validate maxrss_kb
        if (! json_object_object_get_ex(jobj, "maxrss_kb", &jmaxrss_kb))
            throw ndJsonParseException("Missing JSON maxrss_kb");

        if (! json_object_is_type(jmaxrss_kb, json_type_int))
            throw ndJsonParseException("Unexpected JSON maxrss_kb type");

        stats.maxrss_kb = json_object_get_int(jmaxrss_kb);

        // Extract and validate maxrss_kb_prev
        if (! json_object_object_get_ex(jobj, "maxrss_kb_prev", &jmaxrss_kb_prev))
            throw ndJsonParseException("Missing JSON maxrss_kb_prev");

        if (! json_object_is_type(jmaxrss_kb_prev, json_type_int))
            throw ndJsonParseException("Unexpected JSON maxrss_kb_prev type");

        stats.maxrss_kb_prev = json_object_get_int(jmaxrss_kb_prev);
#elif (SIZEOF_LONG == 8)
        // Extract and validate maxrss_kb
        if (! json_object_object_get_ex(jobj, "maxrss_kb", &jmaxrss_kb))
            throw ndJsonParseException("Missing JSON maxrss_kb");

        if (! json_object_is_type(jmaxrss_kb, json_type_int))
            throw ndJsonParseException("Unexpected JSON maxrss_kb type");

        stats.maxrss_kb = json_object_get_int64(jmaxrss_kb);

        // Extract and validate maxrss_kb_prev
        if (! json_object_object_get_ex(jobj, "maxrss_kb_prev", &jmaxrss_kb_prev))
            throw ndJsonParseException("Missing JSON maxrss_kb_prev");

        if (! json_object_is_type(jmaxrss_kb_prev, json_type_int))
            throw ndJsonParseException("Unexpected JSON maxrss_kb_prev type");

        stats.maxrss_kb_prev = json_object_get_int64(jmaxrss_kb_prev);
#endif
#if defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H)
#if (SIZEOF_LONG == 4)
        // Extract and validate tcm_kb
        if (! json_object_object_get_ex(jobj, "tcm_kb", &jtcm_kb))
            throw ndJsonParseException("Missing JSON tcm_kb");

        if (! json_object_is_type(jtcm_kb, json_type_int))
            throw ndJsonParseException("Unexpected JSON tcm_kb type");

        stats.tcm_alloc_kb = json_object_get_int(jtcm_kb);

        // Extract and validate tcm_kb_prev
        if (! json_object_object_get_ex(jobj, "tcm_kb_prev", &jtcm_kb_prev))
            throw ndJsonParseException("Missing JSON tcm_kb_prev");

        if (! json_object_is_type(jtcm_kb_prev, json_type_int))
            throw ndJsonParseException("Unexpected JSON tcm_kb_prev type");

        stats.tcm_alloc_kb_prev = json_object_get_int(jtcm_kb_prev);
#elif (SIZEOF_LONG == 8)
        // Extract and validate tcm_kb
        if (! json_object_object_get_ex(jobj, "tcm_kb", &jtcm_kb))
            throw ndJsonParseException("Missing JSON tcm_kb");

        if (! json_object_is_type(jtcm_kb, json_type_int))
            throw ndJsonParseException("Unexpected JSON tcm_kb type");

        stats.tcm_alloc_kb = json_object_get_int64(jtcm_kb);

        // Extract and validate tcm_kb_prev
        if (! json_object_object_get_ex(jobj, "tcm_kb_prev", &jtcm_kb_prev))
            throw ndJsonParseException("Missing JSON tcm_kb_prev");

        if (! json_object_is_type(jtcm_kb_prev, json_type_int))
            throw ndJsonParseException("Unexpected JSON tcm_kb_prev type");

        stats.tcm_alloc_kb_prev = json_object_get_int64(jtcm_kb_prev);
#endif
#endif
        // Extract and validate dhc_status
        if (! json_object_object_get_ex(jobj, "dhc_status", &jdhc_status))
            throw ndJsonParseException("Missing JSON dhc_status");

        if (! json_object_is_type(jdhc_status, json_type_boolean))
            throw ndJsonParseException("Unexpected JSON dhc_status type");

        stats.dhc_status = json_object_get_boolean(jdhc_status);

        if (stats.dhc_status) {
            // Extract and validate dhc_size
            if (! json_object_object_get_ex(jobj,
                "dhc_size", &jdhc_size))
                throw ndJsonParseException("Missing JSON dhc_size");

            if (! json_object_is_type(jdhc_size, json_type_int))
                throw ndJsonParseException("Unexpected JSON dhc_size type");

            stats.dhc_size = json_object_get_int(jdhc_size);
        }

        // Extract and validate sink_status
        if (! json_object_object_get_ex(jobj, "sink_status", &jsink_status))
            throw ndJsonParseException("Missing JSON sink_status");

        if (! json_object_is_type(jsink_status, json_type_boolean))
            throw ndJsonParseException("Unexpected JSON sink_status type");

        stats.sink_status = json_object_get_boolean(jsink_status);

        if (stats.sink_status) {
            // Extract and validate sink_queue_size_kb
            if (! json_object_object_get_ex(jobj,
                "sink_queue_size_kb", &jsink_queue_size_kb))
                throw ndJsonParseException("Missing JSON sink_queue_size_kb");

            if (! json_object_is_type(jsink_queue_size_kb, json_type_int))
                throw ndJsonParseException("Unexpected JSON sink_queue_size_kb type");

            stats.sink_queue_size = json_object_get_int(jsink_queue_size_kb) * 1024;

            // Extract and validate sink_queue_max_size_kb
            if (! json_object_object_get_ex(jobj,
                "sink_queue_max_size_kb", &jsink_queue_max_size_kb))
                throw ndJsonParseException("Missing JSON sink_queue_max_size_kb");

            if (! json_object_is_type(jsink_queue_max_size_kb, json_type_int))
                throw ndJsonParseException("Unexpected JSON sink_queue_max_size_kb type");

            sink_queue_max_size_kb = json_object_get_int(jsink_queue_max_size_kb);

            // Extract and validate sink_resp_code
            if (! json_object_object_get_ex(jobj,
                "sink_resp_code", &jsink_resp_code))
                throw ndJsonParseException("Missing JSON sink_resp_code");

            if (! json_object_is_type(jsink_resp_code, json_type_int))
                throw ndJsonParseException("Unexpected JSON sink_resp_code type");

            int resp_code = json_object_get_int(jsink_resp_code);

            if (resp_code > 0 && resp_code < ndJSON_RESP_MAX) {
                stats.sink_resp_code = (ndJsonResponseCode)
                    json_object_get_int(jsink_resp_code);
            }
        }
    }
    catch (ndJsonParseException &e) {
        if (jobj != NULL) json_object_put(jobj);
        throw;
    }

    json_object_put(jobj);
#endif
}

void ndJsonResponse::Parse(const string &json)
{
#if 1
#else
    json_object *jver, *jresp_code, *jresp_message;
    json_object *juuid_site, *jurl_sink, *jupdate_imf, *jupload_enabled, *jdata;
#ifdef _ND_USE_PLUGINS
    json_object *jplugin_params;
    json_object *jplugin_request_service_param, *jplugin_request_task_exec;
#endif
    if (ND_JSON_SAVE) {
        nd_file_save(ND_JSON_FILE_RESPONSE, json,
            false, ND_JSON_FILE_MODE, ND_JSON_FILE_USER, ND_JSON_FILE_GROUP);
    }

    json_tokener_reset(jtok);

    json_object *jobj = json_tokener_parse_ex(
        jtok, json.c_str(), json.length()
    );

    try {
        enum json_tokener_error jterr;

        if ((jterr = json_tokener_get_error(jtok)) != json_tokener_success)
            throw ndJsonParseException(json_tokener_error_desc(jterr));

        if (! json_object_is_type(jobj, json_type_object))
            throw ndJsonParseException("Unexpected JSON type; not and object");

        // Extract and validate JSON version
        if (! json_object_object_get_ex(jobj, "version", &jver))
            throw ndJsonParseException("Missing JSON version");

        if (json_object_get_type(jver) != json_type_double)
            throw ndJsonParseException("Unexpected JSON version type");

        version = json_object_get_double(jver);
        if (version > ND_JSON_VERSION) {
            nd_printf("Unsupported JSON response version: %.02f\n", version);
            throw ndJsonParseException("Unsupported JSON response version");
        }

        // Extract and validate response code
        if (! json_object_object_get_ex(jobj, "resp_code", &jresp_code))
            throw ndJsonParseException("Missing JSON response code");

        if (! json_object_is_type(jresp_code, json_type_int))
            throw ndJsonParseException("Unexpected JSON response code type");

        int rc = json_object_get_int(jresp_code);
        if (rc <= ndJSON_RESP_NULL || rc >= ndJSON_RESP_MAX)
            throw ndJsonParseException("Invalid JSON response code");

        resp_code = (ndJsonResponseCode)rc;

        // Extract and validate response message
        if (! json_object_object_get_ex(jobj, "resp_message", &jresp_message))
            throw ndJsonParseException("Missing JSON response message");

        if (! json_object_is_type(jresp_message, json_type_null)) {

            if (! json_object_is_type(jresp_message, json_type_string))
                throw ndJsonParseException("Unexpected JSON response message type");

            resp_message = json_object_get_string(jresp_message);
        }

        // Extract and validate optional site UUID
        if (json_object_object_get_ex(jobj, "uuid_site", &juuid_site) &&
            ! json_object_is_type(juuid_site, json_type_null)) {

            if (! json_object_is_type(juuid_site, json_type_string))
                throw ndJsonParseException("Unexpected Site UUID type");

            uuid_site = json_object_get_string(juuid_site);
        }

        // Extract and validate optional sink URL
        if (json_object_object_get_ex(jobj, "url_sink", &jurl_sink) &&
            ! json_object_is_type(jurl_sink, json_type_null)) {

            if (! json_object_is_type(jurl_sink, json_type_string))
                throw ndJsonParseException("Unexpected Sink URL type");

            url_sink = json_object_get_string(jurl_sink);
        }

        // Extract and validate optional upload interval multiplication factor
        if (json_object_object_get_ex(jobj, "update_imf", &jupdate_imf) &&
            json_object_is_type(jupdate_imf, json_type_int)) {

            update_imf = (unsigned)json_object_get_int(jupdate_imf);
        }

        // Extract and validate optional upload enabled boolean
        if (json_object_object_get_ex(jobj, "upload_enabled", &jupload_enabled) &&
            json_object_is_type(jupload_enabled, json_type_boolean)) {

            upload_enabled = json_object_get_boolean(jupload_enabled);
        }

        // Extract and validate optional data payloads
        if (json_object_object_get_ex(jobj, "data", &jdata) &&
            json_object_is_type(jdata, json_type_object))
            UnserializeData(jdata);

#ifdef _ND_USE_PLUGINS
        // Extract and validate optional service plugin requests
        if (json_object_object_get_ex(
            jobj, "plugin_request_service_param", &jplugin_request_service_param) &&
            json_object_is_type(jplugin_request_service_param, json_type_object)) {

            UnserializePluginRequest(
                jplugin_request_service_param, plugin_request_service_param
            );
        }

        // Extract and validate optional exec task plugin requests
        if (json_object_object_get_ex(
            jobj, "plugin_request_task_exec", &jplugin_request_task_exec) &&
            json_object_is_type(jplugin_request_task_exec, json_type_object)) {

            UnserializePluginRequest(
                jplugin_request_task_exec, plugin_request_task_exec
            );
        }

        // Extract and validate optional service plugin parameters
        if (json_object_object_get_ex(
            jobj, "plugin_params", &jplugin_params) &&
            json_object_is_type(jplugin_params, json_type_object))
            UnserializePluginDispatch(jplugin_params);
#endif
    }
    catch (ndJsonParseException &e) {
        if (jobj != NULL) json_object_put(jobj);
        throw;
    }

    json_object_put(jobj);
#endif
}

void ndJsonResponse::UnserializeData(json &jdata)
{
#if 1
#else
    int jchunks_length;
    json_object *jchunk;

    // XXX: This is a macro; char *jname, json_object *jchunks
    json_object_object_foreach(jdata, jname, jchunks) {

        if (! json_object_is_type(jchunks, json_type_array))
            throw ndJsonParseException("Unexpected data chunks array type");

        jchunks_length = json_object_array_length(jchunks);

        for (int i = 0; i < jchunks_length; i++) {

            if (! (jchunk = json_object_array_get_idx(jchunks, i)))
                throw ndJsonParseException("Unexpected end of data chunks array.");

            if (! json_object_is_type(jchunk, json_type_string))
                throw ndJsonParseException("Unexpected data chunk type");

            string encoded(json_object_get_string(jchunk));

            data[jname].push_back(
                base64_decode(encoded.c_str(), encoded.size())
            );
        }
    }
#endif
}

#ifdef _ND_USE_PLUGINS

void ndJsonResponse::UnserializePluginRequest(json &jrequest, ndJsonPluginRequest &plugin_request)
{
#if 1
#else
    // XXX: This is a macro; char *juuid_dispatch, json_object *jname
    json_object_object_foreach(jrequest, juuid_dispatch, jname) {

        if (! json_object_is_type(jname, json_type_string))
            throw ndJsonParseException("Unexpected plugin name type");

        plugin_request[juuid_dispatch] = json_object_get_string(jname);
    }
#endif
}

void ndJsonResponse::UnserializePluginDispatch(json &jdispatch)
{
#if 1
#else
    // XXX: This is a macro; char *juuid_dispatch, json_object *jparams
    json_object_object_foreach(jdispatch, juuid_dispatch, jparams) {

        if (! json_object_is_type(jparams, json_type_object))
            throw ndJsonParseException("Unexpected plugin params type");

        // XXX: This is a macro; char *jkey, json_object *jvalue
        json_object_object_foreach(jparams, jkey, jvalue) {

            if (! json_object_is_type(jvalue, json_type_string))
                throw ndJsonParseException("Unexpected param value type");

            string encoded(json_object_get_string(jvalue));

            plugin_params[juuid_dispatch][jkey] =
                base64_decode(encoded.c_str(), encoded.size());
        }
    }
#endif
}

#endif // _ND_USE_PLUGINS

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
