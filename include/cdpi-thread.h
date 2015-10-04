// ClearOS DPI Daemon
// Copyright (C) 2015 ClearFoundation <http://www.clearfoundation.com>
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

#ifndef _CDPI_THREAD_H
#define _CDPI_THREAD_H

#define CDPI_THREAD_MAX_PROCNAMELEN 16

class cdpiThreadException : public runtime_error
{
public:
    explicit cdpiThreadException(const string &what_arg)
        : runtime_error(what_arg) { }
};

class cdpiThread
{
public:
    cdpiThread(const string &tag, long cpu = -1);
    virtual ~cdpiThread();

    string GetTag(void) { return tag; }
    pthread_t GetId(void) { return id; }

    void SetProcName(void);

    virtual void Create(void);
    virtual void *Entry(void) = 0;

    virtual void Terminate(void) { terminate = true; }

    void Lock(void) { pthread_mutex_lock(&lock); }
    void Unlock(void) { pthread_mutex_unlock(&lock); }

protected:
    string tag;
    pthread_t id;
    pthread_attr_t attr;
    long cpu;
    bool terminate;
    pthread_mutex_t lock;

    int Join(void);
};

class cdpiDetectionThread : public cdpiThread
{
public:
    cdpiDetectionThread(const string &dev,
        cdpi_flow_map *flow_map, cdpiDetectionStats *stats, long cpu = -1);
    virtual ~cdpiDetectionThread();

    struct ndpi_detection_module_struct *GetDetectionModule(void) {
        return ndpi;
    }
    virtual void *Entry(void);

protected:
    pcap_t *pcap;
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    int pcap_snaplen;
    int pcap_datalink_type;
    struct pcap_pkthdr *pkt_header;
    const uint8_t *pkt_data;
    uint64_t ts_pkt_last;
    uint64_t ts_last_idle_scan;
    struct ndpi_detection_module_struct *ndpi;

    cdpi_flow_map *flows;
    cdpiDetectionStats *stats;

    void ProcessPacket(void);
};

class cdpiControlThread : public cdpiThread
{
public:
    cdpiControlThread();
    virtual ~cdpiControlThread();

    virtual void *Entry(void);

protected:
    CURL *ch;
};

class cdpiUploadThread : public cdpiThread
{
public:
    cdpiUploadThread();
    virtual ~cdpiUploadThread();

    virtual void *Entry(void);

    virtual void Terminate(void) { QueuePush("terminate"); }

    void QueuePush(const string &json);

protected:
    CURL *ch;
    struct curl_slist *headers;
    struct curl_slist *headers_gz;
    queue<string> uploads;
    queue<string> pending;
    pthread_cond_t uploads_cond;
    pthread_mutex_t uploads_cond_mutex;

    void Upload(void);
    void Deflate(const string &data);
};

#endif // _CDPI_THREAD_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
