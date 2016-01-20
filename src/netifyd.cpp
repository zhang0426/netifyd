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

#include <iostream>
#include <stdexcept>
#include <map>
#include <unordered_map>
#include <vector>
#include <queue>
#include <deque>

#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <getopt.h>
#include <fcntl.h>
#include <pwd.h>
#include <grp.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <errno.h>

#include <linux/if_ether.h>
#include <linux/netlink.h>

#include <pthread.h>
#include <pcap/pcap.h>
#include <json.h>
#include <curl/curl.h>

#include "INIReader.h"

#include "ndpi_main.h"

using namespace std;

#define _ND_INTERNAL    1

#include "netifyd.h"
#include "nd-util.h"
#include "nd-thread.h"
#include "nd-inotify.h"
#include "nd-netlink.h"
#include "nd-json.h"

bool nd_debug = false;
pthread_mutex_t *nd_output_mutex = NULL;

typedef vector<string> nd_devices;
typedef map<string, nd_flow_map *> nd_flows;
typedef map<string, ndDetectionStats *> nd_stats;
typedef map<string, ndDetectionThread *> nd_threads;

static nd_devices devices;
static nd_flows flows;
static nd_stats stats;
static nd_threads threads;
static ndDetectionStats totals;
static ndUploadThread *thread_upload = NULL;
static ndInotify *inotify_files = NULL;
static ndNetlink *netlink_routes = NULL;

static char *nd_conf_filename = NULL;
static char *nd_json_filename = NULL;

static int nd_stats_interval = ND_STATS_INTERVAL;

char *nd_uuid = NULL;
char *nd_uuid_zone = NULL;
char *nd_url_upload = NULL;

static void usage(int rc = 0, bool version = false)
{
    cerr << "Netify Daemon v" << PACKAGE_VERSION << endl;
    cerr << "Copyright (C) 2015-2016 eGloo Incorporated [" <<
        __DATE__ <<  " " << __TIME__ << "]" << endl;
    if (version) {
        cerr <<
            "  This program comes with ABSOLUTELY NO WARRANTY." << endl;
        cerr <<
            "  This is free software, and you are welcome to redistribute it" << endl;
        cerr <<
            "  under certain conditions according to the GNU General Public" << endl;
        cerr <<
            "  License version 3, or (at your option) any later version." << endl;
#ifdef PACKAGE_BUGREPORT
        cerr << "Report bugs to: " << PACKAGE_BUGREPORT << endl;
#endif
    }
    else {
        cerr <<
            "  -V, --version" << endl;
        cerr <<
            "    Display program version and license information." << endl;
        cerr <<
            "  -d, --debug" << endl;
        cerr <<
            "    Output debug messages and remain in the foreground." << endl;
        cerr <<
            "  -I, --interface <device>" << endl;
        cerr <<
            "    Interface to capture traffic on.  Repeat for multiple interfaces.";
        cerr << endl;
        cerr <<
            "  -c, --config <filename>" << endl;
        cerr <<
            "    Configuration file.  Default: " << ND_CONF_FILE_NAME << endl;;
        cerr <<
            "  -j, --json <filename>" << endl;
        cerr <<
            "    JSON output file.  Default: " << ND_JSON_FILE_NAME << endl;;
        cerr <<
            "  -i, --interval <seconds>" << endl;
        cerr <<
            "    JSON update interval (seconds).  ";
        cerr <<
            "Default: " << ND_STATS_INTERVAL << endl;
    }

    exit(rc);
}

static int nd_conf_load(void)
{
    struct stat extern_config_stat;
    if (stat(nd_conf_filename, &extern_config_stat) < 0) {
        cerr << "Can not stat configuration file: " << nd_conf_filename <<
            ": " << strerror(errno) << endl;
        return -1;
    }
            
    INIReader reader(nd_conf_filename);

    if (reader.ParseError() != 0) {
        cerr << "Can not parse configuration file: " << nd_conf_filename << endl;
        return -1;
    }

    string uuid = reader.Get("netifyd", "uuid", "");
    if (uuid.size() > 0)
        nd_uuid = strdup(uuid.c_str());
    else {
        cerr << "UUID not set in: " << nd_conf_filename << endl;
        return -1;
    }

    string url_upload = reader.Get("netifyd", "url_upload", "");
    if (url_upload.size() > 0)
        nd_url_upload = strdup(url_upload.c_str());

    nd_stats_interval = reader.GetInteger(
        "netifyd", "update_interval", ND_STATS_INTERVAL);

    string zone_uuid = reader.Get("netifyd", "zone_uuid", "-");
    nd_uuid_zone = strdup(zone_uuid.c_str());

#if 0
    nd_account_id = reader.GetInteger("account", "id", 0);
    if (nd_account_id == 0) {
        cerr << "Account ID not set in: " << nd_conf_filename << endl;
        return 0;
    }
    string account_key = reader.Get("account", "key", "");
    if (account_key.size() > 0)
        nd_account_key = strdup(account_key.c_str());
    else {
        cerr << "Account Key not set in: " << nd_conf_filename << endl;
        return -1;
    }

    nd_system_id = reader.GetInteger("system", "id", 0);
    if (nd_system_id == 0) {
        cerr << "System ID not set in: " << nd_conf_filename << endl;
        return -1;
    }
#endif
    return 0;
}

void ndDetectionStats::print(const char *tag)
{
    nd_printf("          RAW: %lu\n", pkt_raw);
    nd_printf("          ETH: %lu\n", pkt_eth);
    nd_printf("           IP: %lu\n", pkt_ip);
    nd_printf("          TCP: %lu\n", pkt_tcp);
    nd_printf("          UDP: %lu\n", pkt_udp);
    nd_printf("         MPLS: %lu\n", pkt_mpls);
    nd_printf("        PPPoE: %lu\n", pkt_pppoe);
    nd_printf("         VLAN: %lu\n", pkt_vlan);
    nd_printf("        Frags: %lu\n", pkt_frags);
    nd_printf("      Largest: %u\n", pkt_maxlen);
    nd_printf("     IP bytes: %u\n", pkt_ip_bytes);
    nd_printf("   Wire bytes: %u\n", pkt_wire_bytes);
    nd_printf("      Discard: %lu\n", pkt_discard);
    nd_printf("Discard bytes: %lu\n", pkt_discard_bytes);
}

static void nd_json_write(ndJson *json)
{
    int fd = open(nd_json_filename, O_WRONLY);

    if (fd < 0) {
        if (errno != ENOENT)
            throw runtime_error(strerror(errno));
        fd = open(nd_json_filename, O_WRONLY | O_CREAT, ND_JSON_FILE_MODE);
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

    string json_string;
    json->ToString(json_string);

    if (write(fd, (const void *)json_string.c_str(), json_string.length()) < 0)
        throw runtime_error(strerror(errno));

    flock(fd, LOCK_UN);
    close(fd);
}

static void nd_json_add_file(
    json_object *parent, const string &type, const string &filename)
{
    char *c, *p, buffer[ND_FILE_BUFSIZ];
    FILE *hf = fopen(filename.c_str(), "r");

    if (hf == NULL) {
        nd_printf("Error opening file for upload: %s: %s\n",
            filename.c_str(), strerror(errno));
        return;
    }

    ndJson json(parent);
    json_object *json_lines = json.CreateArray(NULL, type.c_str());

    p = buffer;
    while (fgets(buffer, ND_FILE_BUFSIZ, hf) != NULL) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\r') continue;
        c = (char *)memchr((void *)p, '\n', ND_FILE_BUFSIZ - (p - buffer));
        if (c != NULL) *c = '\0';

        json.PushObject(json_lines, p);
    }

    fclose(hf);
}

static void nd_json_upload(ndJson *json)
{
    if (inotify_files->EventOccured(ND_WATCH_HOSTS))
        nd_json_add_file(json->GetRoot(), "hosts", ND_WATCH_HOSTS);
    if (inotify_files->EventOccured(ND_WATCH_ETHERS))
        nd_json_add_file(json->GetRoot(), "ethers", ND_WATCH_ETHERS);

    string json_string;
    json->ToString(json_string);

    thread_upload->QueuePush(json_string);
}

static void nd_json_add_stats(json_object *parent, const ndDetectionStats *stats)
{
    ndJson json(parent);

    json.AddObject(NULL, string("raw"), stats->pkt_raw);
    json.AddObject(NULL, "ethernet", stats->pkt_eth);
    json.AddObject(NULL, "mpls", stats->pkt_mpls);
    json.AddObject(NULL, "pppoe", stats->pkt_pppoe);
    json.AddObject(NULL, "vlan", stats->pkt_vlan);
    json.AddObject(NULL, "fragmented", stats->pkt_frags);
    json.AddObject(NULL, "discarded", stats->pkt_discard);
    json.AddObject(NULL, "discarded_bytes", stats->pkt_discard_bytes);
    json.AddObject(NULL, "largest_bytes", stats->pkt_maxlen);
    json.AddObject(NULL, "ip", stats->pkt_ip);
    json.AddObject(NULL, "tcp", stats->pkt_tcp);
    json.AddObject(NULL, "udp", stats->pkt_udp);
    json.AddObject(NULL, "ip_bytes", stats->pkt_ip_bytes);
    json.AddObject(NULL, "wire_bytes", stats->pkt_wire_bytes);
}

static void nd_json_add_flows(json_object *parent,
    struct ndpi_detection_module_struct *ndpi,
    const nd_flow_map *flows, bool unknown = true)
{
    char buffer[256];
    ndJson json(parent);

    for (nd_flow_map::const_iterator i = flows->begin();
        i != flows->end(); i++) {

        if (i->second->detection_complete == false)
            continue;
        if (unknown == false &&
            i->second->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN)
            continue;

        json_object *json_flow = json.CreateObject();

        string digest;
        nd_sha1_to_string((const uint8_t *)i->first.data(), digest);
        json.AddObject(json_flow, "digest", digest);

        json.AddObject(json_flow, "ip_version", (int32_t)i->second->version);

        json.AddObject(json_flow, "ip_protocol", (int32_t)i->second->protocol);

        json.AddObject(json_flow, "vlan_id", (int32_t)i->second->vlan_id);

        snprintf(buffer, sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x",
            i->second->lower_mac[0], i->second->lower_mac[1], i->second->lower_mac[2],
            i->second->lower_mac[3], i->second->lower_mac[4], i->second->lower_mac[5]
        );
        json.AddObject(json_flow, "lower_mac", buffer);

        snprintf(buffer, sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x",
            i->second->upper_mac[0], i->second->upper_mac[1], i->second->upper_mac[2],
            i->second->upper_mac[3], i->second->upper_mac[4], i->second->upper_mac[5]
        );
        json.AddObject(json_flow, "upper_mac", buffer);

        json.AddObject(json_flow, "lower_ip", i->second->lower_ip);
        json.AddObject(json_flow, "upper_ip", i->second->upper_ip);

        json.AddObject(json_flow, "lower_port", (int32_t)i->second->lower_port);
        json.AddObject(json_flow, "upper_port", (int32_t)i->second->upper_port);

        json.AddObject(json_flow, "detected_protocol",
            (int32_t)i->second->detected_protocol.protocol);
        json.AddObject(json_flow, "detected_protocol_master",
            (int32_t)i->second->detected_protocol.master_protocol);

        if (i->second->detected_protocol.master_protocol) {
            snprintf(buffer, sizeof(buffer), "%s.%s",
                ndpi_get_proto_name(ndpi,
                    i->second->detected_protocol.master_protocol),
                ndpi_get_proto_name(ndpi,
                    i->second->detected_protocol.protocol));

            json.AddObject(json_flow, "detected_protocol_name", buffer);
        }
        else {
            json.AddObject(json_flow, "detected_protocol_name",
                ndpi_get_proto_name(ndpi, i->second->detected_protocol.protocol));
        }

        json.AddObject(json_flow, "detection_guessed", i->second->detection_guessed);

        json.AddObject(json_flow, "packets", i->second->packets);
        json.AddObject(json_flow, "bytes", i->second->bytes);

        if (i->second->host_server_name[0] != '\0') {
            json.AddObject(json_flow,
                "host_server_name", i->second->host_server_name);
        }

        if((i->second->ssl.client_cert[0] != '\0') ||
            (i->second->ssl.server_cert[0] != '\0')) {

            json_object *ssl = json.CreateObject(json_flow, "ssl");

            if(i->second->ssl.client_cert[0] != '\0')
                json.AddObject(ssl, "client", i->second->ssl.client_cert);

            if(i->second->ssl.server_cert[0] != '\0')
                json.AddObject(ssl, "server", i->second->ssl.server_cert);
        }

        json.AddObject(json_flow, "last_seen", i->second->ts_last_seen);

        json.PushObject(NULL, json_flow);
    }
}

static void nd_dump_stats(void)
{
    uint64_t flow_count = 0;

    ndJson json;
    json_object *json_obj;

    json.AddObject(NULL, "version", (double)ND_JSON_VERSION);
    json.AddObject(NULL, "timestamp", (int64_t)time(NULL));

    json_object *json_devs = json.CreateArray(NULL, "interfaces");
    json_object *json_stats = json.CreateObject(NULL, "stats");
    json_object *json_flows = json.CreateObject(NULL, "flows");

    for (nd_threads::iterator i = threads.begin();
        i != threads.end(); i++) {

        json.PushObject(json_devs, i->first.c_str());

        i->second->Lock();

        totals += *stats[i->first];
        flow_count += flows[i->first]->size();

        json_obj = json.CreateObject();
        nd_json_add_stats(json_obj, stats[i->first]);
        json_object_object_add(json_stats, i->first.c_str(), json_obj);

        memset(stats[i->first], 0, sizeof(ndDetectionStats));

        json_obj = json.CreateArray(json_flows, i->first);
        nd_json_add_flows(json_obj,
            i->second->GetDetectionModule(), flows[i->first]);

        i->second->Unlock();
    }

    try {
        nd_json_write(&json);
    }
    catch (runtime_error &e) {
        nd_printf("Error writing JSON file: %s: %s\n",
            nd_json_filename, e.what());
    }

#ifdef USE_CLOUD_SYNC
    try {
        nd_json_upload(&json);
    }
    catch (runtime_error &e) {
        nd_printf("Error uploading JSON: %s\n", e.what());
    }
#endif // USE_CLOUD_SYNC
    json.Destroy();

    if (nd_debug) {
        nd_printf("\nCumulative Totals:\n");
        totals.print();
        nd_printf("        Flows: %lu\n\n", flow_count);
    }
}

void debug_test(void)
{
    nd_debug = true;

    ndJsonObject *json_obj = NULL;
    ndJsonObjectType json_type;
    ndJsonObjectFactory json_factory;

        "{\"version\":1.0,\"type\":2,\"data\":{\"code\":1,\"message\":\"unknown error\"}}",
        "{\"version\":1,\"type\":2,\"data\":{\"code\":2,\"message\":\"Authorization failure\"}}",
    json_type = json_factory.Parse(
        "{\"version\":1,\"type\":2,\"data\":{\"code\":2,\"message\":\"Authorization failure\"}}",
        &json_obj
    );

    if (json_obj != NULL) delete json_obj;

    exit(0);
}

int main(int argc, char *argv[])
{
    int rc = 0;
    bool terminate = false;
    sigset_t sigset;
    struct sigevent sigev;
    timer_t timer_id;
    struct itimerspec it_spec;

    nd_output_mutex = new pthread_mutex_t;
    pthread_mutex_init(nd_output_mutex, NULL);

    //debug_test();

    static struct option options[] =
    {
        { "help", 0, 0, 'h' },
        { "version", 0, 0, 'V' },
        { "debug", 0, 0, 'd' },
        { "interface", 1, 0, 'I' },
        { "json", 1, 0, 'j' },
        { "interval", 1, 0, 'i' },
        { "config", 1, 0, 'c' },

        { NULL, 0, 0, 0 }
    };

    for (optind = 1;; ) {
        int o = 0;
        if ((rc = getopt_long(argc, argv,
            "?hVdI:j:i:c:", options, &o)) == -1) break;
        switch (rc) {
        case '?':
            cerr <<
                "Try " << argv[0] << " --help for more information." << endl;
            return 1;
        case 'h':
            usage();
        case 'V':
            usage(0, true);
        case 'd':
            nd_debug = true;
            break;
        case 'I':
            for (nd_devices::iterator i = devices.begin();
                i != devices.end(); i++) {
                if (strcasecmp((*i).c_str(), optarg) == 0) {
                    cerr << "Duplicate interface specified: " << optarg << endl;
                    exit(1);
                }
            }
            devices.push_back(optarg);
            break;
        case 'j':
            nd_json_filename = strdup(optarg);
            break;
        case 'i':
            nd_stats_interval = atoi(optarg);
            break;
        case 'c':
            nd_conf_filename = strdup(optarg);
            break;
        default:
            usage(1);
        }
    }

    if (nd_json_filename == NULL)
        nd_json_filename = strdup(ND_JSON_FILE_NAME);
    if (nd_conf_filename == NULL)
        nd_conf_filename = strdup(ND_CONF_FILE_NAME);

    if (nd_conf_load() < 0)
        return 1;

    if (nd_url_upload == NULL)
        nd_url_upload = strdup(ND_URL_UPLOAD);

    if (devices.size() == 0) {
        cerr << "Required argument, (-I, --iterface) missing." << endl;
        return 1;
    }

    CURLcode cc;
    if ((cc = curl_global_init(CURL_GLOBAL_ALL)) != 0) {
        cerr << "Unable to initialize libCURL: " << cc << endl;
        return 1;
    }

    if (nd_debug == false) {
        if (daemon(1, 0) != 0) {
            nd_printf("daemon: %s\n", strerror(errno));
            return 1;
        }
        FILE *hpid = fopen(ND_PID_FILE_NAME, "w+");
        if (hpid == NULL) {
            nd_printf("Error opening PID file: %s: %s\n",
                ND_PID_FILE_NAME, strerror(errno));
            return 1;
        }
        fprintf(hpid, "%d\n", getpid());
        fclose(hpid);
    }
        
    nd_printf("Netify Daemon v%s\n", PACKAGE_VERSION);

    memset(&totals, 0, sizeof(ndDetectionStats));

    sigfillset(&sigset);
    sigdelset(&sigset, SIGPROF);

    sigprocmask(SIG_BLOCK, &sigset, NULL);

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGRTMIN);
    sigaddset(&sigset, SIGIO);

    thread_upload = new ndUploadThread();
    thread_upload->Create();

    for (nd_devices::iterator i = devices.begin();
        i != devices.end(); i++) {
        flows[(*i)] = new nd_flow_map;
        stats[(*i)] = new ndDetectionStats;
    }

    try {
        inotify_files = new ndInotify();
        inotify_files->AddWatch(ND_WATCH_HOSTS);
        inotify_files->AddWatch(ND_WATCH_ETHERS);
        inotify_files->RefreshWatches();
    }
    catch (exception &e) {
        nd_printf("Error creating file watches: %s\n", e.what());
        return 1;
    }

    try {
        netlink_routes = new ndNetlink();
    }
    catch (exception &e) {
        nd_printf("Error creating netlink watch: %s\n", e.what());
        return 1;
    }

    try {
        long cpu = 0;
        long cpus = sysconf(_SC_NPROCESSORS_ONLN);

        for (nd_devices::iterator i = devices.begin();
            i != devices.end(); i++) {
            threads[(*i)] = new ndDetectionThread(
                (*i),
                flows[(*i)],
                stats[(*i)],
                (devices.size() > 1) ? cpu++ : -1
            );
            threads[(*i)]->Create();
            if (cpu == cpus) cpu = 0;
        }
    }
    catch (exception &e) {
        nd_printf("Runtime error: %s\n", e.what());
        return 1;
    }

    memset(&sigev, 0, sizeof(struct sigevent));
    sigev.sigev_notify = SIGEV_SIGNAL;
    sigev.sigev_signo = SIGRTMIN;

    if (timer_create(CLOCK_REALTIME, &sigev, &timer_id) < 0) {
        nd_printf("timer_create: %s\n", strerror(errno));
        return 1;
    }

    it_spec.it_value.tv_sec = nd_stats_interval;
    it_spec.it_value.tv_nsec = 0;
    it_spec.it_interval.tv_sec = nd_stats_interval;
    it_spec.it_interval.tv_nsec = 0;

    timer_settime(timer_id, 0, &it_spec, NULL);

    netlink_routes->Refresh();

    while (!terminate) {
        int sig;
        siginfo_t si;

        sig = sigwaitinfo(&sigset, &si);
        if (sig < 0) {
            nd_printf("sigwaitinfo: %s\n", strerror(errno));
            rc = -1;
            terminate = true;
            continue;
        }

        if (sig == SIGINT || sig == SIGTERM) {
            rc = 0;
            terminate = true;
            nd_printf("Exiting...\n");
            continue;
        }

        if (sig == sigev.sigev_signo) {
            nd_dump_stats();
            inotify_files->RefreshWatches();
            continue;
        }

        if (sig == SIGIO) {
            if (inotify_files->GetDescriptor() == si.si_fd) {
                inotify_files->ProcessEvent();
                continue;
            }
            else if (netlink_routes->GetDescriptor() == si.si_fd) {
                netlink_routes->ProcessEvent();
                continue;
            }
        }

        nd_printf("Unhandled signal: %s\n", strsignal(sig));
    }

    timer_delete(timer_id);

    for (nd_devices::iterator i = devices.begin();
        i != devices.end(); i++) {
        threads[(*i)]->Terminate();
        delete threads[(*i)];
        delete flows[(*i)];
        delete stats[(*i)];
    }

    thread_upload->Terminate();
    delete thread_upload;

    pthread_mutex_destroy(nd_output_mutex);

    curl_global_cleanup();

    return 0;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
