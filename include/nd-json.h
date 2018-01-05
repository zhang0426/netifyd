// Netify Agent
// Copyright (C) 2015-2018 eGloo Incorporated <http://www.egloo.ca>
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

    static json_object *CreateObject(void);
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

    void ToString(string &output, bool pretty = true);

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

#include "nd-json-config-type.h"

typedef struct
{
    string match;
    string app_name;
    uint32_t app_id;
} ndJsonConfigContentMatch;

typedef vector<ndJsonConfigContentMatch *> ndJsonConfigContentMatchList;

typedef struct
{
    string rule;
} ndJsonConfigCustomMatch;

typedef vector<ndJsonConfigCustomMatch *> ndJsonConfigCustomMatchList;

typedef struct
{
    struct sockaddr_storage ip_addr;
    uint8_t ip_prefix;
    uint32_t app_id;
} ndJsonConfigHostMatch;

typedef vector<ndJsonConfigHostMatch *> ndJsonConfigHostMatchList;

class ndJsonObjectConfig : public ndJsonObject
{
public:
    ndJsonObjectConfig(json_object *jdata);
    virtual ~ndJsonObjectConfig();

    bool IsPresent(ndJsonConfigType type) { return bool(present & (unsigned)type); }

    size_t GetContentMatchCount(void) { return content_match_list.size(); }
    size_t GetCustomMatchCount(void) { return custom_match_list.size(); }
    size_t GetHostMatchCount(void) { return host_match_list.size(); }

    ndJsonConfigContentMatch *GetFirstContentMatchEntry(void);
    ndJsonConfigCustomMatch *GetFirstCustomMatchEntry(void);
    ndJsonConfigHostMatch *GetFirstHostMatchEntry(void);

    ndJsonConfigContentMatch *GetNextContentMatchEntry(void);
    ndJsonConfigCustomMatch *GetNextCustomMatchEntry(void);
    ndJsonConfigHostMatch *GetNextHostMatchEntry(void);

protected:
    void UnserializeConfig(ndJsonConfigType type, json_object *jarray);
    void UnserializeContentMatch(json_object *jentry);
    void UnserializeCustomMatch(json_object *jentry);
    void UnserializeHostMatch(json_object *jentry);

    unsigned present;

    ndJsonConfigContentMatchList content_match_list;
    ndJsonConfigCustomMatchList custom_match_list;
    ndJsonConfigHostMatchList host_match_list;

    ndJsonConfigContentMatchList::const_iterator content_match_iterator;
    ndJsonConfigCustomMatchList::const_iterator custom_match_iterator;
    ndJsonConfigHostMatchList::const_iterator host_match_iterator;
};

#endif // _ND_JSON_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
