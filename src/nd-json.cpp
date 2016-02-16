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
#include <stdexcept>

#include <unistd.h>
#include <string.h>
#include <errno.h>

#include <json.h>

#include "ndpi_main.h"

using namespace std;

#include "netifyd.h"
#include "nd-json.h"
#include "nd-util.h"

extern bool nd_debug;

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

void ndJson::ToString(string &output)
{
    output = json_object_to_json_string_ext(
        root,
        (nd_debug) ? JSON_C_TO_STRING_PRETTY : JSON_C_TO_STRING_PLAIN
    );
}

ndJsonObjectType ndJsonObjectFactory::Parse(const string &jstring, ndJsonObject **result)
{
	json_object *jver, *jtype, *jdata;

    json_tokener_reset(jtok);

    json_object *jobj = json_tokener_parse_ex(
        jtok, jstring.c_str(), jstring.length()
    );

    enum json_tokener_error jterr;
    if ((jterr = json_tokener_get_error(jtok)) != json_tokener_success)
        throw ndJsonParseException(json_tokener_error_desc(jterr));

    if (!json_object_is_type(jobj, json_type_object))
        throw ndJsonParseException("Unexpected JSON type");

    if (!json_object_object_get_ex(jobj, "version", &jver))
        throw ndJsonParseException("Missing version field");

    if (json_object_get_type(jver) != json_type_double)
        throw ndJsonParseException("Version field type mismatch");

    double version = json_object_get_double(jver);
    nd_printf("version: %.02f\n", version);

    if (!json_object_object_get_ex(jobj, "type", &jtype))
        throw ndJsonParseException("Missing type field");

    if (json_object_get_type(jtype) != json_type_int)
        throw ndJsonParseException("Type field type mismatch");

    int type = json_object_get_int(jtype);
    if (type <= ndJSON_OBJ_TYPE_NULL || type >= ndJSON_OBJ_TYPE_MAX)
        throw ndJsonParseException("Type field invalid value");
    nd_printf("type: %d\n", type);

    switch (type) {
    case ndJSON_OBJ_TYPE_OK:
        *result = NULL;
        return ndJSON_OBJ_TYPE_OK;
    case ndJSON_OBJ_TYPE_RESULT:
        if (!json_object_object_get_ex(jobj, "data", &jdata))
            throw ndJsonParseException("Missing data field");
        if (!json_object_is_type(jdata, json_type_object))
            throw ndJsonParseException("Unexpected data type");
        *result = reinterpret_cast<ndJsonObject *>(new ndJsonObjectResult(jdata));
        return ndJSON_OBJ_TYPE_RESULT;
    default:
        throw ndJsonParseException("Invalid type");
    }

    return ndJSON_OBJ_TYPE_NULL;
}

ndJsonObjectResult::ndJsonObjectResult(json_object *jdata)
    : ndJsonObject(ndJSON_OBJ_TYPE_RESULT),
    code(ndJSON_RES_NULL)
{
    json_object *jcode, *jmessage;

    if (!json_object_object_get_ex(jdata, "code", &jcode))
        throw ndJsonParseException("Missing code field");

    if (json_object_get_type(jcode) != json_type_int)
        throw ndJsonParseException("Code field type mismatch");

    int icode = json_object_get_int(jcode);
    if (icode <= ndJSON_RES_NULL || icode >= ndJSON_RES_MAX)
        throw ndJsonParseException("Code field invalid value");

    code = (ndJsonObjectResultCode)icode;
    if (nd_debug)
        nd_printf("code: %d\n", code);

    if (!json_object_object_get_ex(jdata, "message", &jmessage))
        throw ndJsonParseException("Missing message field");

    if (json_object_get_type(jmessage) != json_type_string)
        throw ndJsonParseException("Message field type mismatch");

    message = json_object_get_string(jmessage);

    if (nd_debug)
        nd_printf("message: %s\n", message.c_str());
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
