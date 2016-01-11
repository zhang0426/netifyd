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
    void AddObject(json_object *parent, const string &name, bool value);

    void PushObject(json_object *parent, const char *value);
    void PushObject(json_object *parent, const string &value);
    void PushObject(json_object *parent, int32_t value);
    void PushObject(json_object *parent, int64_t value);
    void PushObject(json_object *parent, bool value);
    void PushObject(json_object *parent, json_object *object);

    void ToString(string &output);

    json_object *GetRoot(void) { return root; }

protected:
    json_object *root;
};

#endif // _ND_JSON_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
