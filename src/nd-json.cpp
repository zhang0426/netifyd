// Netify Daemon
// Copyright (C) 2015-2017 eGloo Incorporated <http://www.egloo.ca>
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

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>

#include <json.h>

#include "ndpi_main.h"

using namespace std;

#include "netifyd.h"
#include "nd-util.h"
#include "nd-json.h"

extern ndGlobalConfig nd_config;

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
}

void ndJson::SaveToFile(const string &filename)
{
    int fd = open(filename.c_str(), O_WRONLY);

    if (fd < 0) {
        if (errno != ENOENT)
            throw runtime_error(strerror(errno));
        fd = open(filename.c_str(), O_WRONLY | O_CREAT, ND_JSON_FILE_MODE);
        if (fd < 0)
            throw runtime_error(strerror(errno));

        struct passwd *owner_user = getpwnam(ND_JSON_FILE_USER);
        if (owner_user == NULL)
            throw runtime_error(strerror(errno));

        struct group *owner_group = getgrnam(ND_JSON_FILE_GROUP);
        if (owner_group == NULL)
            throw runtime_error(strerror(errno));

        if (fchown(fd, owner_user->pw_uid, owner_group->gr_gid) < 0)
            throw runtime_error(strerror(errno));
    }

    if (flock(fd, LOCK_EX) < 0)
        throw runtime_error(strerror(errno));

    if (lseek(fd, 0, SEEK_SET) < 0)
        throw runtime_error(strerror(errno));
    if (ftruncate(fd, 0) < 0)
        throw runtime_error(strerror(errno));

    string output;
    ToString(output);

    if (write(fd, (const void *)output.c_str(), output.length()) < 0)
        throw runtime_error(strerror(errno));

    flock(fd, LOCK_UN);
    close(fd);
}

ndJsonObjectType ndJsonObjectFactory::Parse(const string &jstring, ndJsonObject **result)
{
    json_object *jver, *jtype, *jdata;

    json_tokener_reset(jtok);

    json_object *jobj = json_tokener_parse_ex(
        jtok, jstring.c_str(), jstring.length()
    );

    try {
        enum json_tokener_error jterr;
        if ((jterr = json_tokener_get_error(jtok)) != json_tokener_success)
            throw ndJsonParseException(json_tokener_error_desc(jterr));

        if (! json_object_is_type(jobj, json_type_object))
            throw ndJsonParseException("Unexpected JSON type");

        if (! json_object_object_get_ex(jobj, "version", &jver))
            throw ndJsonParseException("Missing version field");

        if (json_object_get_type(jver) != json_type_double)
            throw ndJsonParseException("Version field type mismatch");

        double version = json_object_get_double(jver);
        if (version > ND_JSON_VERSION) {
            nd_printf("Unsupported remote JSON version: %.02f\n", version);
            throw ndJsonParseException("Unsupported remote JSON version");
        }

        if (! json_object_object_get_ex(jobj, "type", &jtype))
            throw ndJsonParseException("Missing type field");

        if (json_object_get_type(jtype) != json_type_int)
            throw ndJsonParseException("Type field type mismatch");

        int type = json_object_get_int(jtype);
        if (type <= ndJSON_OBJ_TYPE_NULL || type >= ndJSON_OBJ_TYPE_MAX)
            throw ndJsonParseException("Type field invalid value");

        switch (type) {
        case ndJSON_OBJ_TYPE_OK:
            *result = NULL;
            json_object_put(jobj);
            return ndJSON_OBJ_TYPE_OK;

        case ndJSON_OBJ_TYPE_RESULT:
            if (! json_object_object_get_ex(jobj, "data", &jdata))
                throw ndJsonParseException("Missing data field");
            if (! json_object_is_type(jdata, json_type_object))
                throw ndJsonParseException("Unexpected data type");
            *result = reinterpret_cast<ndJsonObject *>(new ndJsonObjectResult(jdata));
            json_object_put(jobj);
            return ndJSON_OBJ_TYPE_RESULT;

        case ndJSON_OBJ_TYPE_CONFIG:
            if (! json_object_object_get_ex(jobj, "config", &jdata))
                throw ndJsonParseException("Missing config field");
            if (! json_object_is_type(jdata, json_type_object))
                throw ndJsonParseException("Unexpected config type");
            *result = reinterpret_cast<ndJsonObject *>(new ndJsonObjectConfig(jdata));
            json_object_put(jobj);
            return ndJSON_OBJ_TYPE_CONFIG;

        default:
            throw ndJsonParseException("Invalid type");
        }
    }
    catch (ndJsonParseException &e) {
        if (jobj != NULL) json_object_put(jobj);
        throw;
    }

    json_object_put(jobj);

    return ndJSON_OBJ_TYPE_NULL;
}

ndJsonObjectResult::ndJsonObjectResult(json_object *jdata)
    : ndJsonObject(ndJSON_OBJ_TYPE_RESULT),
    code(ndJSON_RES_NULL)
{
    json_object *jcode, *jmessage;

    if (! json_object_object_get_ex(jdata, "code", &jcode))
        throw ndJsonParseException("Missing code field");

    if (json_object_get_type(jcode) != json_type_int)
        throw ndJsonParseException("Code field type mismatch");

    int icode = json_object_get_int(jcode);
    if (icode <= ndJSON_RES_NULL || icode >= ndJSON_RES_MAX)
        throw ndJsonParseException("Code field invalid value");

    code = (ndJsonObjectResultCode)icode;

    if (! json_object_object_get_ex(jdata, "message", &jmessage))
        throw ndJsonParseException("Missing message field");

    if (json_object_get_type(jmessage) != json_type_string)
        throw ndJsonParseException("Message field type mismatch");

    message = json_object_get_string(jmessage);
}

ndJsonObjectConfig::ndJsonObjectConfig(json_object *jdata)
    : ndJsonObject(ndJSON_OBJ_TYPE_CONFIG)
{
    json_object *jarray;

    if (json_object_object_get_ex(jdata, "content_match", &jarray)) {
        if (json_object_get_type(jarray) != json_type_array)
            throw ndJsonParseException("Content match type mismatch");

        present |= (unsigned)ndJSON_CFG_TYPE_CONTENT_MATCH;
        UnserializeConfig(ndJSON_CFG_TYPE_CONTENT_MATCH, jarray);
    }

    if (json_object_object_get_ex(jdata, "custom_match", &jarray)) {
        if (json_object_get_type(jarray) != json_type_array)
            throw ndJsonParseException("Custom protos type mismatch");

        present |= (unsigned)ndJSON_CFG_TYPE_CUSTOM_MATCH;
        UnserializeConfig(ndJSON_CFG_TYPE_CUSTOM_MATCH, jarray);
    }

    if (json_object_object_get_ex(jdata, "host_match", &jarray)) {
        if (json_object_get_type(jarray) != json_type_array)
            throw ndJsonParseException("Host protocol type mismatch");

        present |= (unsigned)ndJSON_CFG_TYPE_HOST_MATCH;
        UnserializeConfig(ndJSON_CFG_TYPE_HOST_MATCH, jarray);
    }
}

ndJsonObjectConfig::~ndJsonObjectConfig()
{
    for (content_match_iterator = content_match_list.begin();
        content_match_iterator != content_match_list.end();
        content_match_iterator++) delete (*content_match_iterator);
    content_match_list.clear();

    for (custom_match_iterator = custom_match_list.begin();
        custom_match_iterator != custom_match_list.end();
        custom_match_iterator++) delete (*custom_match_iterator);
    custom_match_list.clear();

    for (host_match_iterator = host_match_list.begin();
        host_match_iterator != host_match_list.end();
        host_match_iterator++) delete (*host_match_iterator);
    host_match_list.clear();
}

ndJsonConfigContentMatch *ndJsonObjectConfig::GetFirstContentMatchEntry(void)
{
    content_match_iterator = content_match_list.begin();
    if (content_match_iterator == content_match_list.end()) return NULL;
    return (*content_match_iterator);
}

ndJsonConfigCustomMatch *ndJsonObjectConfig::GetFirstCustomMatchEntry(void)
{
    custom_match_iterator = custom_match_list.begin();
    if (custom_match_iterator == custom_match_list.end()) return NULL;
    return (*custom_match_iterator);
}

ndJsonConfigHostMatch *ndJsonObjectConfig::GetFirstHostMatchEntry(void)
{
    host_match_iterator = host_match_list.begin();
    if (host_match_iterator == host_match_list.end()) return NULL;
    return (*host_match_iterator);
}

ndJsonConfigContentMatch *ndJsonObjectConfig::GetNextContentMatchEntry(void)
{
    if (content_match_iterator == content_match_list.end())
        return NULL;
    content_match_iterator++;
    if (content_match_iterator == content_match_list.end())
        return NULL;
    return (*content_match_iterator);
}

ndJsonConfigCustomMatch *ndJsonObjectConfig::GetNextCustomMatchEntry(void)
{
    if (custom_match_iterator == custom_match_list.end())
        return NULL;
    custom_match_iterator++;
    if (custom_match_iterator == custom_match_list.end())
        return NULL;
    return (*custom_match_iterator);
}

ndJsonConfigHostMatch *ndJsonObjectConfig::GetNextHostMatchEntry(void)
{
    if (host_match_iterator == host_match_list.end())
        return NULL;
    host_match_iterator++;
    if (host_match_iterator == host_match_list.end())
        return NULL;
    return (*host_match_iterator);
}

void ndJsonObjectConfig::UnserializeConfig(ndJsonConfigType type, json_object *jarray)
{
    int jarray_length;
    json_object *jentry;
    string jkey;

    switch (type) {
    case ndJSON_CFG_TYPE_CONTENT_MATCH:
        jkey = "content_type";
        break;
    case ndJSON_CFG_TYPE_CUSTOM_MATCH:
        jkey = "custom_match";
        break;
    case ndJSON_CFG_TYPE_HOST_MATCH:
        jkey = "host_match";
        break;
    case ndJSON_CFG_TYPE_NULL:
    default:
        nd_debug_printf("Invalid config type: %d\n", type);
        return;
    }

    jarray_length = json_object_array_length(jarray);

    for (int i = 0; i < jarray_length; i++) {
        switch (type) {
        case ndJSON_CFG_TYPE_CONTENT_MATCH:
            if ((jentry = json_object_array_get_idx(jarray, i)))
                UnserializeContentMatch(jentry);
            break;
        case ndJSON_CFG_TYPE_CUSTOM_MATCH:
            if ((jentry = json_object_array_get_idx(jarray, i)))
                UnserializeCustomMatch(jentry);
            break;
        case ndJSON_CFG_TYPE_HOST_MATCH:
            if ((jentry = json_object_array_get_idx(jarray, i)))
                UnserializeHostMatch(jentry);
            break;
        default:
            break;
        }

        if (jentry == NULL) {
            nd_debug_printf("Premature end of JSON array: %s\n", jkey.c_str());
            break;
        }
    }
}

void ndJsonObjectConfig::UnserializeContentMatch(json_object *jentry)
{
    json_object *jobj;
    ndJsonConfigContentMatch entry;

    if (! json_object_object_get_ex(jentry, "match", &jobj))
        throw ndJsonParseException("Missing match field");

    if (json_object_get_type(jobj) != json_type_string)
        throw ndJsonParseException("Match field type mismatch");

    entry.match = json_object_get_string(jobj);

    if (! json_object_object_get_ex(jentry, "app_name", &jobj))
        throw ndJsonParseException("Missing application name field");

    if (json_object_get_type(jobj) != json_type_string)
        throw ndJsonParseException("Application name type mismatch");

    entry.app_name = json_object_get_string(jobj);

    if (! json_object_object_get_ex(jentry, "app_id", &jobj))
        throw ndJsonParseException("Missing application ID field");

    if (json_object_get_type(jobj) != json_type_int)
        throw ndJsonParseException("Application ID field type mismatch");

    entry.app_id = (uint32_t)json_object_get_int(jobj);

    content_match_list.push_back(new ndJsonConfigContentMatch(entry));
}

void ndJsonObjectConfig::UnserializeCustomMatch(json_object *jentry)
{
    json_object *jobj;
    ndJsonConfigCustomMatch entry;

    if (! json_object_object_get_ex(jentry, "rule", &jobj))
        throw ndJsonParseException("Missing rule field");

    if (json_object_get_type(jobj) != json_type_string)
        throw ndJsonParseException("Rule field type mismatch");

    entry.rule = json_object_get_string(jobj);

    custom_match_list.push_back(new ndJsonConfigCustomMatch(entry));
}

void ndJsonObjectConfig::UnserializeHostMatch(json_object *jentry)
{
    json_object *jobj;
    ndJsonConfigHostMatch entry;
    struct sockaddr_in *saddr_ip4;
    struct sockaddr_in6 *saddr_ip6;
    saddr_ip4 = reinterpret_cast<struct sockaddr_in *>(&entry.ip_addr);
    saddr_ip6 = reinterpret_cast<struct sockaddr_in6 *>(&entry.ip_addr);

    if (! json_object_object_get_ex(jentry, "ip_address", &jobj))
        throw ndJsonParseException("Missing IP address field");

    if (json_object_get_type(jobj) != json_type_string)
        throw ndJsonParseException("IP address type mismatch");

    const char *ip_addr = json_object_get_string(jobj);

    if (ip_addr == NULL || ip_addr[0] == '\0')
        throw ndJsonParseException("Invalid IP address length");

    if (inet_pton(AF_INET6, ip_addr, &saddr_ip6->sin6_addr) != 1) {
        if (inet_pton(AF_INET, ip_addr, &saddr_ip4->sin_addr) != 1)
            throw ndJsonParseException("Invalid IP address");
        else
            entry.ip_addr.ss_family = AF_INET;
    }
    else
            entry.ip_addr.ss_family = AF_INET6;

    if (! json_object_object_get_ex(jentry, "ip_prefix", &jobj))
        throw ndJsonParseException("Missing IP prefix field");

    if (json_object_get_type(jobj) != json_type_int)
        throw ndJsonParseException("IP prefix field type mismatch");

    entry.ip_prefix = json_object_get_int(jobj);

    if (! json_object_object_get_ex(jentry, "app_id", &jobj))
        throw ndJsonParseException("Missing application ID field");

    if (json_object_get_type(jobj) != json_type_int)
        throw ndJsonParseException("Application ID field type mismatch");

    entry.app_id = json_object_get_int(jobj);

    host_match_list.push_back(new ndJsonConfigHostMatch(entry));
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
