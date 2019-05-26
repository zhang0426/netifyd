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

#include <json.h>
#include <pcap/pcap.h>

using namespace std;

#include "netifyd.h"

#include "nd-ndpi.h"
#include "nd-base64.h"
#include "nd-json.h"
#include "nd-util.h"

extern nd_global_config nd_config;

ndJson::ndJson()
    : root(NULL)
{
    root = json_object_new_object();
    if (root == NULL)
        throw runtime_error(strerror(ENOMEM));
}

ndJson::ndJson(json_object *root)
    : root(root)
{
}

void ndJson::Destroy(void)
{
    if (root != NULL) {
        json_object_put(root);
        root = NULL;
    }
}

json_object *ndJson::CreateObject(void)
{
    json_object *object = json_object_new_object();
    if (object == NULL)
        throw runtime_error(strerror(ENOMEM));

    return object;
}

json_object *ndJson::CreateObject(json_object *parent, const string &name)
{
    json_object *object = json_object_new_object();
    if (object == NULL)
        throw runtime_error(strerror(ENOMEM));

    if (parent == NULL)
        json_object_object_add(root, name.c_str(), object);
    else
        json_object_object_add(parent, name.c_str(), object);

    return object;
}

json_object *ndJson::CreateArray(json_object *parent, const string &name)
{
    json_object *object = json_object_new_array();
    if (object == NULL)
        throw runtime_error(strerror(ENOMEM));

    if (parent == NULL)
        json_object_object_add(root, name.c_str(), object);
    else
        json_object_object_add(parent, name.c_str(), object);

    return object;
}

void ndJson::AddObject(json_object *parent, const string &name, json_object *object)
{
    if (parent == NULL)
        json_object_object_add(root, name.c_str(), object);
    else
        json_object_object_add(parent, name.c_str(), object);
}

void ndJson::AddObject(json_object *parent, const string &name, const char *value)
{
    json_object *object = json_object_new_string(value);
    if (object == NULL)
        throw runtime_error(strerror(ENOMEM));

    if (parent == NULL)
        json_object_object_add(root, name.c_str(), object);
    else
        json_object_object_add(parent, name.c_str(), object);
}

void ndJson::AddObject(json_object *parent, const string &name, const string &value)
{
    json_object *object = json_object_new_string(value.c_str());
    if (object == NULL)
        throw runtime_error(strerror(ENOMEM));

    if (parent == NULL)
        json_object_object_add(root, name.c_str(), object);
    else
        json_object_object_add(parent, name.c_str(), object);
}

void ndJson::AddObject(json_object *parent, const string &name, int32_t value)
{
    json_object *object = json_object_new_int(value);
    if (object == NULL)
        throw runtime_error(strerror(ENOMEM));

    if (parent == NULL)
        json_object_object_add(root, name.c_str(), object);
    else
        json_object_object_add(parent, name.c_str(), object);
}

void ndJson::AddObject(json_object *parent, const string &name, int64_t value)
{
    json_object *object = json_object_new_int64(value);
    if (object == NULL)
        throw runtime_error(strerror(ENOMEM));

    if (parent == NULL)
        json_object_object_add(root, name.c_str(), object);
    else
        json_object_object_add(parent, name.c_str(), object);
}

void ndJson::AddObject(json_object *parent, const string &name, uint32_t value)
{
    json_object *object = json_object_new_int(value);
    if (object == NULL)
        throw runtime_error(strerror(ENOMEM));

    if (parent == NULL)
        json_object_object_add(root, name.c_str(), object);
    else
        json_object_object_add(parent, name.c_str(), object);
}

void ndJson::AddObject(json_object *parent, const string &name, uint64_t value)
{
    json_object *object = json_object_new_int64(value);
    if (object == NULL)
        throw runtime_error(strerror(ENOMEM));

    if (parent == NULL)
        json_object_object_add(root, name.c_str(), object);
    else
        json_object_object_add(parent, name.c_str(), object);
}

void ndJson::AddObject(json_object *parent, const string &name, double value)
{
    json_object *object = json_object_new_double(value);
    if (object == NULL)
        throw runtime_error(strerror(ENOMEM));

    if (parent == NULL)
        json_object_object_add(root, name.c_str(), object);
    else
        json_object_object_add(parent, name.c_str(), object);
}

void ndJson::AddObject(json_object *parent, const string &name, bool value)
{
    json_object *object = json_object_new_boolean(value);
    if (object == NULL)
        throw runtime_error(strerror(ENOMEM));

    if (parent == NULL)
        json_object_object_add(root, name.c_str(), object);
    else
        json_object_object_add(parent, name.c_str(), object);
}

void ndJson::PushObject(json_object *parent, const char *value)
{
    json_object *object = json_object_new_string(value);
    if (object == NULL)
        throw runtime_error(strerror(ENOMEM));

    json_object_array_add(parent, object);
}

void ndJson::PushObject(json_object *parent, const string &value)
{
    json_object *object = json_object_new_string(value.c_str());
    if (object == NULL)
        throw runtime_error(strerror(ENOMEM));

    json_object_array_add(parent, object);
}

void ndJson::PushObject(json_object *parent, int32_t value)
{
    json_object *object = json_object_new_int(value);
    if (object == NULL)
        throw runtime_error(strerror(ENOMEM));

    json_object_array_add(parent, object);
}

void ndJson::PushObject(json_object *parent, int64_t value)
{
    json_object *object = json_object_new_int64(value);
    if (object == NULL)
        throw runtime_error(strerror(ENOMEM));

    json_object_array_add(parent, object);
}

void ndJson::PushObject(json_object *parent, double value)
{
    json_object *object = json_object_new_double(value);
    if (object == NULL)
        throw runtime_error(strerror(ENOMEM));

    json_object_array_add(parent, object);
}

void ndJson::PushObject(json_object *parent, bool value)
{
    json_object *object = json_object_new_boolean(value);
    if (object == NULL)
        throw runtime_error(strerror(ENOMEM));

    json_object_array_add(parent, object);
}

void ndJson::PushObject(json_object *parent, json_object *object)
{
    if (parent == NULL)
        json_object_array_add(root, object);
    else
        json_object_array_add(parent, object);
}

void ndJson::ToString(string &output, bool pretty)
{
    output = json_object_to_json_string_ext(
        root,
        (ND_DEBUG && pretty) ? JSON_C_TO_STRING_PRETTY : JSON_C_TO_STRING_PLAIN
    );
#ifdef HAVE_WORKING_REGEX
    vector<pair<regex *, string> >::const_iterator i;
    for (i = nd_config.privacy_regex.begin();
        i != nd_config.privacy_regex.end(); i++) {

        string result = regex_replace(output, *((*i).first), (*i).second);
        if (result.size()) output = result;
    }
#endif
}

void ndJson::SaveToFile(const string &filename)
{
    string output;
    ToString(output);

    nd_file_save(filename, output,
        false, ND_JSON_FILE_MODE, ND_JSON_FILE_USER, ND_JSON_FILE_GROUP);
}

void ndJsonResponse::Parse(const string &json)
{
    json_object *jver, *jresp_code, *jresp_message;
    json_object *juuid_site, *jurl_sink, *jdata;
#ifdef _ND_USE_PLUGINS
    json_object *jplugin_params;
    json_object *jplugin_request_service_param, *jplugin_request_task_exec;
#endif
    json_tokener_reset(jtok);

    if (ND_JSON_SAVE) {
        FILE *hf = fopen(ND_JSON_FILE_RESPONSE, "w");
        if (hf != NULL) {
            fprintf(hf, "%s\n", json.c_str());
            fclose(hf);
        }
    }

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
}

void ndJsonResponse::UnserializeData(json_object *jdata)
{
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
}

#ifdef _ND_USE_PLUGINS

void ndJsonResponse::UnserializePluginRequest(json_object *jrequest, ndJsonPluginRequest &plugin_request)
{
    // XXX: This is a macro; char *juuid_dispatch, json_object *jname
    json_object_object_foreach(jrequest, juuid_dispatch, jname) {

        if (! json_object_is_type(jname, json_type_string))
            throw ndJsonParseException("Unexpected plugin name type");

        plugin_request[juuid_dispatch] = json_object_get_string(jname);
    }
}

void ndJsonResponse::UnserializePluginDispatch(json_object *jdispatch)
{
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
}

#endif // _ND_USE_PLUGINS

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
