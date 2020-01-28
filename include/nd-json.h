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

#ifndef _ND_JSON_H
#define _ND_JSON_H

#define ND_JSON_TOKENER_DEPTH   16

class ndJsonInitException : public runtime_error
{
public:
    explicit ndJsonInitException(const string &what_arg)
        : runtime_error(what_arg) { }
};

class ndJsonParseException : public runtime_error
{
public:
    explicit ndJsonParseException(const string &what_arg)
        : runtime_error(what_arg) { }
};

void nd_json_to_string(const json &j, string &output, bool pretty = false);
void nd_json_save_to_file(const json &j, const string &filename, bool pretty = false);
void nd_json_save_to_file(const string &j, const string &filename);

typedef vector<string> ndJsonDataChunks;
typedef map<string, ndJsonDataChunks> ndJsonData;

#ifdef _ND_USE_PLUGINS
typedef map<string, string> ndJsonPluginParams;
typedef ndJsonPluginParams ndJsonPluginReplies;

typedef map<string, string> ndJsonPluginRequest;
typedef map<string, ndJsonPluginParams> ndJsonPluginDispatch;
#endif

class ndJsonObject
{
public:
    ndJsonObject() {}
    virtual ~ndJsonObject() {}

    virtual void Parse(const string &json_string) = 0;
};

class ndJsonStatus : public ndJsonObject
{
public:
    ndJsonStatus()
        : ndJsonObject(), timestamp(0), uptime(0),
        update_interval(0), update_imf(0),
        sink_queue_max_size_kb(0)
    {
        memset(&stats, 0, sizeof(nd_agent_stats));
    }

    virtual void Parse(const string &json_string);

    time_t timestamp, uptime;
    unsigned update_interval, update_imf;
    uint32_t sink_queue_max_size_kb;

    nd_agent_stats stats;
};

class ndJsonResponse : public ndJsonObject
{
public:
    ndJsonResponse()
        : ndJsonObject(), version(0), resp_code(ndJSON_RESP_NULL),
        update_imf(1), upload_enabled(false) { }

    ndJsonResponse(ndJsonResponseCode code, const string &message)
        : ndJsonObject(), version(0), resp_code(code), resp_message(message),
        update_imf(1), upload_enabled(false) { }

    virtual void Parse(const string &json_string);

    double version;

    ndJsonResponseCode resp_code;
    string resp_message;

    string uuid_site;
    string url_sink;

    unsigned update_imf;
    bool upload_enabled;

    ndJsonData data;

#ifdef _ND_USE_PLUGINS
    ndJsonPluginRequest plugin_request_service_param;
    ndJsonPluginRequest plugin_request_task_exec;

    ndJsonPluginDispatch plugin_params;
#endif

protected:
    void UnserializeData(json &jdata);
#ifdef _ND_USE_PLUGINS
    void UnserializePluginRequest(json &jrequest, ndJsonPluginRequest &plugin_request);
    void UnserializePluginDispatch(json &jdispatch);
#endif // _ND_USE_PLUGINS
};

#endif // _ND_JSON_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
