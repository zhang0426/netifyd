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

class ndJson
{
public:
    ndJson();
    ndJson(json_object *root);
    void Destroy(void);

    json_object *CreateObject(void);
    json_object *CreateObject(json_object *parent, const string &name);
    json_object *CreateArray(json_object *parent, const string &name);

    void AddObject(json_object *parent, const string &name, json_object *object);
    void AddObject(json_object *parent, const string &name, const char *value);
    void AddObject(json_object *parent, const string &name, const string &value);
    void AddObject(json_object *parent, const string &name, int32_t value);
    void AddObject(json_object *parent, const string &name, int64_t value);
    void AddObject(json_object *parent, const string &name, uint32_t value);
    void AddObject(json_object *parent, const string &name, uint64_t value);
    void AddObject(json_object *parent, const string &name, double value);
    void AddObject(json_object *parent, const string &name, bool value);

    void PushObject(json_object *parent, const char *value);
    void PushObject(json_object *parent, const string &value);
    void PushObject(json_object *parent, int32_t value);
    void PushObject(json_object *parent, int64_t value);
    void PushObject(json_object *parent, double value);
    void PushObject(json_object *parent, bool value);
    void PushObject(json_object *parent, json_object *object);

    void ToString(string &output);

    void SaveToFile(const string &filename);

    json_object *GetRoot(void) { return root; }

protected:
    json_object *root;
};

#include "nd-json-object-type.h"

class ndJsonObject
{
public:
    ndJsonObject(ndJsonObjectType type)
        : type(type) { }
    virtual ~ndJsonObject() { }

    ndJsonObjectType GetType(void) { return type; }

protected:
    ndJsonObjectType type;
};

class ndJsonObjectFactory
{
public:
    ndJsonObjectFactory()
    {
        jtok = json_tokener_new_ex(ND_JSON_TOKENER_DEPTH);
        if (jtok == NULL)
            throw ndJsonInitException(strerror(ENOMEM));
    }
    virtual ~ndJsonObjectFactory()
    {
        if (jtok != NULL) json_tokener_free(jtok);
    }

    ndJsonObjectType Parse(const string &jstring, ndJsonObject **result);

protected:
    json_tokener *jtok;
};

#include "nd-json-result-code.h"

class ndJsonObjectResult : public ndJsonObject
{
public:
    ndJsonObjectResult(json_object *jdata);

    ndJsonObjectResultCode GetCode(void) { return code; }
    string GetMessage(void) { return message; }

protected:
    ndJsonObjectResultCode code;
    string message;
};

#endif // _ND_JSON_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
