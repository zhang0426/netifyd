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

#ifndef _ND_THREAD_H
#define _ND_THREAD_H

#define ND_THREAD_MAX_PROCNAMELEN 16

class ndThreadException : public runtime_error
{
public:
    explicit ndThreadException(const string &what_arg)
        : runtime_error(what_arg) { }
};

class ndThread
{
public:
    ndThread(const string &tag, long cpu = -1);
    virtual ~ndThread();

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

class ndDetectionThread : public ndThread
{
public:
    ndDetectionThread(const string &dev,
        nd_flow_map *flow_map, ndDetectionStats *stats, long cpu = -1);
    virtual ~ndDetectionThread();

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

    nd_flow_map *flows;
    ndDetectionStats *stats;

    void ProcessPacket(void);
};

class ndUploadThread : public ndThread
{
public:
    ndUploadThread();
    virtual ~ndUploadThread();

    virtual void *Entry(void);

    virtual void Terminate(void) { QueuePush("terminate"); }

    void Authenticate(void);

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

#endif // _ND_THREAD_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
