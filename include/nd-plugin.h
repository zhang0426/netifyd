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

#ifndef _ND_PLUGIN_H
#define _ND_PLUGIN_H

#define _ND_PLUGIN_VER  0x20180813

#define ndPluginInit(class_name) \
    extern "C" { \
    ndPlugin *ndPluginInit(const string &tag) { \
        class_name *p = new class_name(tag); \
        if (p == NULL) return NULL; \
        if (p->GetType() != ndPlugin::TYPE_TASK && \
            p->GetType() != ndPlugin::TYPE_SERVICE) { \
                nd_printf("Invalid plugin type detected during init: %s\n", \
                    tag.c_str()); \
                delete p; \
                return NULL; \
        } \
        return dynamic_cast<ndPlugin *>(p); \
    } }

class ndPluginException : public ndException
{
public:
    explicit ndPluginException(
        const string &where_arg, const string &what_arg) throw()
        : ndException(where_arg, what_arg) { }
};

class ndPlugin : public ndThread
{
public:
    ndPlugin(const string &tag);
    virtual ~ndPlugin();

    virtual void *Entry(void) = 0;

    enum ndPluginType
    {
        TYPE_BASE,
        TYPE_SERVICE,
        TYPE_TASK,
    };

    ndPluginType GetType(void) { return type; };

    virtual void SetParams(const ndJsonPluginParams &params);
    virtual void GetReplies(ndJsonPluginReplies &replies);

protected:
    void PushReply(const string &key, const string &value);

    ndPluginType type;
    ndJsonPluginParams params;
    ndJsonPluginReplies replies;
};

class ndPluginService : public ndPlugin
{
public:
    ndPluginService(const string &tag);
    virtual ~ndPluginService();
};

class ndPluginTask : public ndPlugin
{
public:
    ndPluginTask(const string &tag);
    virtual ~ndPluginTask();
};

#ifdef _ND_INTERNAL

class ndPluginLoader
{
public:
    ndPluginLoader(const string &so_name, const string &tag);
    virtual ~ndPluginLoader();

    inline ndPlugin *GetPlugin(void) { return plugin; };

protected:
    string so_name;
    void *so_handle;
    ndPlugin *plugin;
};
#endif // _ND_INTERNAL

#endif // _ND_PLUGIN_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
