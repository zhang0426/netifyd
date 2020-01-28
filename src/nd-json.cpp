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
    output = j.dump(
        pretty ? ND_JSON_INDENT : -1,
        ' ', false, json::error_handler_t::replace
    );
#ifdef HAVE_WORKING_REGEX
    vector<pair<regex *, string> >::const_iterator i;
    for (i = nd_config.privacy_regex.begin();
        i != nd_config.privacy_regex.end(); i++) {

        string result = regex_replace(output, *((*i).first), (*i).second);
        if (result.size()) output = result;
    }
#endif // HAVE_WORKING_REGEX
}

void nd_json_save_to_file(const json &j, const string &filename, bool pretty)
{
    string json_string;
    nd_json_to_string(j, json_string, pretty);
    nd_json_save_to_file(json_string, filename);
}

void nd_json_save_to_file(const string &j, const string &filename)
{
    nd_file_save(filename, j,
        false, ND_JSON_FILE_MODE, ND_JSON_FILE_USER, ND_JSON_FILE_GROUP);
}

void ndJsonStatus::Parse(const string &json_string)
{
    try {
        json j = json::parse(json_string);

        // Extract and validate JSON type
        string type = j["type"].get<string>();

        if (type != "agent_status")
            throw ndJsonParseException("Required type: agent_status");

        uptime = j["uptime"].get<time_t>();
        timestamp = j["timestamp"].get<time_t>();
        update_interval = j["update_interval"].get<unsigned>();
        update_imf = j["update_imf"].get<unsigned>();

        stats.flows = j["flows"].get<unsigned>();
        stats.flows_prev = j["flows_prev"].get<unsigned>();

        stats.cpus = (long)j["cpu_cores"].get<unsigned>();

        stats.cpu_user = j["cpu_user"].get<double>();
        stats.cpu_user_prev = j["cpu_user_prev"].get<double>();
        stats.cpu_system = j["cpu_system"].get<double>();
        stats.cpu_system_prev = j["cpu_system_prev"].get<double>();

        stats.maxrss_kb = j["maxrss_kb"].get<unsigned>();
        stats.maxrss_kb_prev = j["maxrss_kb_prev"].get<unsigned>();

#if defined(_ND_USE_LIBTCMALLOC) && defined(HAVE_GPERFTOOLS_MALLOC_EXTENSION_H)
        stats.tcm_alloc_kb = j["tcm_kb"].get<unsigned>();
        stats.tcm_alloc_kb_prev = j["tcm_kb_prev"].get<unsigned>();
#endif // _ND_USE_LIBTCMALLOC

        stats.dhc_status = j["dhc_status"].get<bool>();
        if (stats.dhc_status)
            stats.dhc_size = j["dhc_size"].get<unsigned>();

        stats.sink_status = j["sink_status"].get<bool>();
        if (stats.sink_status) {

            stats.sink_uploads = j["sink_uploads"].get<bool>();

            stats.sink_queue_size = j["sink_queue_size_kb"].get<unsigned>();
            stats.sink_queue_size *= 1024;

            sink_queue_max_size_kb = j["sink_queue_max_size_kb"].get<unsigned>();

            unsigned resp_code = j["sink_resp_code"].get<unsigned>();

            if (resp_code > 0 && resp_code < ndJSON_RESP_MAX)
                stats.sink_resp_code = (ndJsonResponseCode)resp_code;
        }
    }
    catch (exception &e) {
        throw ndJsonParseException(e.what());
    }
}

void ndJsonResponse::Parse(const string &json_string)
{
    try {
        if (ND_JSON_SAVE)
            nd_json_save_to_file(json_string, ND_JSON_FILE_RESPONSE);

        json j = json::parse(json_string);

        // Extract and validate JSON version
        version = j["version"].get<double>();
        if (version > ND_JSON_VERSION) {
            nd_printf("Unsupported JSON response version: %.02f\n", version);
            throw ndJsonParseException("Unsupported JSON response version");
        }

        // Extract and validate response code
        unsigned rc = j["resp_code"].get<unsigned>();
        if (rc == ndJSON_RESP_NULL || rc >= ndJSON_RESP_MAX)
            throw ndJsonParseException("Invalid JSON response code");

        resp_code = (ndJsonResponseCode)rc;

        try {
            resp_message = j["resp_message"].get<string>();
        }
        catch (exception &e) { }

        try {
            uuid_site = j["uuid_site"].get<string>();
        }
        catch (exception &e) { }

        try {
            url_sink = j["url_sink"].get<string>();
        }
        catch (exception &e) { }

        try {
            update_imf = j["update_imf"].get<unsigned>();
        }
        catch (exception &e) { }

        try {
            upload_enabled = j["upload_enabled"].get<bool>();
        }
        catch (exception &e) { }

        auto it_data = j.find("data");
        if (it_data != j.end() && (*it_data) != nullptr)
            UnserializeData((*it_data));

#ifdef _ND_USE_PLUGINS
        auto it_rsp = j.find("plugin_request_service_param");
        if (it_rsp != j.end() && (*it_rsp) != nullptr) {
            UnserializePluginRequest((*it_rsp), plugin_request_service_param);
        }

        auto it_rte = j.find("plugin_request_task_exec");
        if (it_rte != j.end() && (*it_rte) != nullptr)
            UnserializePluginRequest((*it_rte), plugin_request_task_exec);

        auto it_pp = j.find("plugin_params");
        if (it_pp != j.end() && (*it_pp) != nullptr)
            UnserializePluginDispatch((*it_pp));
#endif // _ND_USE_PLUGINS
    }
    catch (ndJsonParseException &e) {
        throw;
    }
    catch (exception &e) {
        throw ndJsonParseException(e.what());
    }
}

void ndJsonResponse::UnserializeData(json &jdata)
{
    for (auto it = jdata.begin(); it != jdata.end(); it++) {
        for (auto it_chunk = (*it).begin(); it_chunk != (*it).end(); it_chunk++) {
            string encoded = (*it_chunk).get<string>();
            data[it.key()].push_back(
                base64_decode(encoded.c_str(), encoded.size())
            );
        }
    }
}

#ifdef _ND_USE_PLUGINS

void ndJsonResponse::UnserializePluginRequest(
    json &jrequest, ndJsonPluginRequest &plugin_request)
{
    for (auto it = jrequest.begin(); it != jrequest.end(); it++)
        plugin_request[it.key()] = (*it).get<string>();
}

void ndJsonResponse::UnserializePluginDispatch(json &jdispatch)
{
    for (auto it = jdispatch.begin(); it != jdispatch.end(); it++) {
        for (auto it_param = (*it).begin(); it_param != (*it).end(); it_param++) {
            string encoded = (*it_param).get<string>();
            plugin_params[it.key()][it_param.key()] =
                base64_decode(encoded.c_str(), encoded.size());
        }
    }
}

#endif // _ND_USE_PLUGINS

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
