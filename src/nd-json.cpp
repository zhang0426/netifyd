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

using namespace std;

#include "nd-json.h"

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

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
