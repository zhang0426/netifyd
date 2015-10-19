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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <iostream>
#include <stdexcept>
#include <map>
#include <unordered_map>
#include <vector>
#include <queue>

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
#include <linux/if_ether.h>

#include <pcap/pcap.h>
#include <json.h>
#include <curl/curl.h>

#include "INIReader.h"

#include "ndpi_main.h"

using namespace std;

#include "cdpi.h"
#include "cdpi-util.h"
#include "cdpi-thread.h"
#include "cdpi-inotify.h"

bool cdpi_debug = false;
pthread_mutex_t *cdpi_output_mutex = NULL;

typedef vector<string> cdpi_devices;
typedef map<string, cdpi_flow_map *> cdpi_flows;
typedef map<string, cdpiDetectionStats *> cdpi_stats;
typedef map<string, cdpiDetectionThread *> cdpi_threads;

static cdpi_devices devices;
static cdpi_flows flows;
static cdpi_stats stats;
static cdpi_threads threads;
static cdpiDetectionStats totals;
static cdpiControlThread *thread_control = NULL;
static cdpiUploadThread *thread_upload = NULL;
static cdpiInotify *inotify_files = NULL;

static char *cdpi_conf_filename = NULL;
static char *cdpi_json_filename = NULL;

static int cdpi_stats_interval = CDPI_STATS_INTERVAL;

char *cdpi_uuid = NULL;
int cdpi_account_id = 0;
char *cdpi_account_key = NULL;
int cdpi_system_id = 0;

static void usage(int rc = 0, bool version = false)
{
    cerr << "ClearOS DPI Daemon v" << PACKAGE_VERSION << endl;
    cerr << "Copyright (C) 2015 ClearFoundation [" <<
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
            "    Configuration file.  Default: " << CDPI_CONF_FILE_NAME << endl;;
        cerr <<
            "  -j, --json <filename>" << endl;
        cerr <<
            "    JSON output file.  Default: " << CDPI_JSON_FILE_NAME << endl;;
        cerr <<
            "  -i, --interval <seconds>" << endl;
        cerr <<
            "    JSON update interval (seconds).  ";
        cerr <<
            "Default: " << CDPI_STATS_INTERVAL << endl;
    }

    exit(rc);
}

static int cdpi_conf_load(void)
{
    struct stat extern_config_stat;
    if (stat(cdpi_conf_filename, &extern_config_stat) < 0) {
        cerr << "Can not stat configuration file: " << cdpi_conf_filename <<
            ": " << strerror(errno) << endl;
        return -1;
    }
            
    INIReader reader(cdpi_conf_filename);

    if (reader.ParseError() != 0) {
        cerr << "Can not parse configuration file: " << cdpi_conf_filename << endl;
        return -1;
    }

    string uuid = reader.Get("cdpid", "uuid", "");
    if (uuid.size() > 0)
        cdpi_uuid = strdup(uuid.c_str());
    else {
        cerr << "UUID not set in: " << cdpi_conf_filename << endl;
        return -1;
    }

    cdpi_stats_interval = reader.GetInteger(
        "cdpid", "update_interval", CDPI_STATS_INTERVAL);

    cdpi_account_id = reader.GetInteger("account", "id", 0);
    if (cdpi_account_id == 0) {
        cerr << "Account ID not set in: " << cdpi_conf_filename << endl;
        return 0;
    }
    string account_key = reader.Get("account", "key", "");
    if (account_key.size() > 0)
        cdpi_account_key = strdup(account_key.c_str());
    else {
        cerr << "Account Key not set in: " << cdpi_conf_filename << endl;
        return -1;
    }

    cdpi_system_id = reader.GetInteger("system", "id", 0);
    if (cdpi_system_id == 0) {
        cerr << "System ID not set in: " << cdpi_conf_filename << endl;
        return -1;
    }

    return 0;
}

void cdpiDetectionStats::print(const char *tag)
{
    cdpi_printf("          RAW: %lu\n", pkt_raw);
    cdpi_printf("          ETH: %lu\n", pkt_eth);
    cdpi_printf("           IP: %lu\n", pkt_ip);
    cdpi_printf("          TCP: %lu\n", pkt_tcp);
    cdpi_printf("          UDP: %lu\n", pkt_udp);
    cdpi_printf("         MPLS: %lu\n", pkt_mpls);
    cdpi_printf("        PPPoE: %lu\n", pkt_pppoe);
    cdpi_printf("         VLAN: %lu\n", pkt_vlan);
    cdpi_printf("        Frags: %lu\n", pkt_frags);
    cdpi_printf("      Largest: %u\n", pkt_maxlen);
    cdpi_printf("     IP bytes: %u\n", pkt_ip_bytes);
    cdpi_printf("   Wire bytes: %u\n", pkt_wire_bytes);
    cdpi_printf("      Discard: %lu\n", pkt_discard);
    cdpi_printf("Discard bytes: %lu\n", pkt_discard_bytes);
}

static void cdpi_json_write(json_object *json)
{
    int fd = open(cdpi_json_filename, O_WRONLY);

    if (fd < 0) {
        if (errno != ENOENT)
            throw runtime_error(strerror(errno));
        fd = open(cdpi_json_filename, O_WRONLY | O_CREAT, CDPI_JSON_FILE_MODE);
        if (fd < 0)
            throw runtime_error(strerror(errno));

        struct passwd *owner_user = getpwnam(CDPI_JSON_FILE_USER);
        if (owner_user == NULL)
            throw runtime_error(strerror(errno));

        struct group *owner_group = getgrnam(CDPI_JSON_FILE_GROUP);
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

    string json_string = json_object_to_json_string_ext(
        json,
        (cdpi_debug) ? JSON_C_TO_STRING_PRETTY : JSON_C_TO_STRING_PLAIN
    );

    if (write(fd, (const void *)json_string.c_str(), json_string.length()) < 0)
        throw runtime_error(strerror(errno));

    flock(fd, LOCK_UN);
    close(fd);
}

static void cdpi_json_add_file(
    json_object *json, const string &type, const string &filename)
{
    char *c, *p, buffer[CDPI_FILE_BUFSIZ];
    FILE *hf = fopen(filename.c_str(), "r");

    if (hf == NULL) {
        cdpi_printf("Error opening file for upload: %s: %s\n",
            filename.c_str(), strerror(errno));
        return;
    }

    json_object *json_obj;
    json_object *json_lines = json_object_new_array();
        if (json_lines == NULL)
            throw runtime_error(strerror(ENOMEM));

    p = buffer;
    while (fgets(buffer, CDPI_FILE_BUFSIZ, hf) != NULL) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '#' || *p == '\n' || *p == '\r') continue;
        c = (char *)memchr((void *)p, '\n', CDPI_FILE_BUFSIZ - (p - buffer));
        if (c != NULL) *c = '\0';

        json_obj = json_object_new_string(p);
        if (json_obj == NULL)
            throw runtime_error(strerror(ENOMEM));
        json_object_array_add(json_lines, json_obj);
    }

    fclose(hf);

    json_object_object_add(json, type.c_str(), json_lines);
}

static void cdpi_json_upload(json_object *json)
{
    if (inotify_files->EventOccured(CDPI_WATCH_HOSTS))
        cdpi_json_add_file(json, "hosts", CDPI_WATCH_HOSTS);
    if (inotify_files->EventOccured(CDPI_WATCH_ETHERS))
        cdpi_json_add_file(json, "ethers", CDPI_WATCH_ETHERS);

    string json_string = json_object_to_json_string_ext(
        json,
        (cdpi_debug) ? JSON_C_TO_STRING_PRETTY : JSON_C_TO_STRING_PLAIN
    );

    thread_upload->QueuePush(json_string);
}

static void cdpi_json_add_stats(json_object *json_parent, const cdpiDetectionStats *stats)
{
    json_object *json_obj;

    json_obj = json_object_new_int64(stats->pkt_raw);
    if (json_obj == NULL)
        throw runtime_error(strerror(ENOMEM));
    json_object_object_add(json_parent, "raw", json_obj);

    json_obj = json_object_new_int64(stats->pkt_eth);
    if (json_obj == NULL)
        throw runtime_error(strerror(ENOMEM));
    json_object_object_add(json_parent, "ethernet", json_obj);

    json_obj = json_object_new_int64(stats->pkt_mpls);
    if (json_obj == NULL)
        throw runtime_error(strerror(ENOMEM));
    json_object_object_add(json_parent, "mpls", json_obj);

    json_obj = json_object_new_int64(stats->pkt_pppoe);
    if (json_obj == NULL)
        throw runtime_error(strerror(ENOMEM));
    json_object_object_add(json_parent, "pppoe", json_obj);

    json_obj = json_object_new_int64(stats->pkt_vlan);
    if (json_obj == NULL)
        throw runtime_error(strerror(ENOMEM));
    json_object_object_add(json_parent, "vlan", json_obj);

    json_obj = json_object_new_int64(stats->pkt_frags);
    if (json_obj == NULL)
        throw runtime_error(strerror(ENOMEM));
    json_object_object_add(json_parent, "fragmented", json_obj);

    json_obj = json_object_new_int64(stats->pkt_discard);
    if (json_obj == NULL)
        throw runtime_error(strerror(ENOMEM));
    json_object_object_add(json_parent, "discarded", json_obj);

    json_obj = json_object_new_int64(stats->pkt_discard_bytes);
    if (json_obj == NULL)
        throw runtime_error(strerror(ENOMEM));
    json_object_object_add(json_parent, "discarded_bytes", json_obj);

    json_obj = json_object_new_int64(stats->pkt_maxlen);
    if (json_obj == NULL)
        throw runtime_error(strerror(ENOMEM));
    json_object_object_add(json_parent, "largest_bytes", json_obj);

    json_obj = json_object_new_int64(stats->pkt_ip);
    if (json_obj == NULL)
        throw runtime_error(strerror(ENOMEM));
    json_object_object_add(json_parent, "ip", json_obj);

    json_obj = json_object_new_int64(stats->pkt_tcp);
    if (json_obj == NULL)
        throw runtime_error(strerror(ENOMEM));
    json_object_object_add(json_parent, "tcp", json_obj);

    json_obj = json_object_new_int64(stats->pkt_udp);
    if (json_obj == NULL)
        throw runtime_error(strerror(ENOMEM));
    json_object_object_add(json_parent, "udp", json_obj);

    json_obj = json_object_new_int64(stats->pkt_ip_bytes);
    if (json_obj == NULL)
        throw runtime_error(strerror(ENOMEM));
    json_object_object_add(json_parent, "ip_bytes", json_obj);

    json_obj = json_object_new_int64(stats->pkt_wire_bytes);
    if (json_obj == NULL)
        throw runtime_error(strerror(ENOMEM));
    json_object_object_add(json_parent, "wire_bytes", json_obj);
}

static void cdpi_json_add_flows(
    json_object *json_parent,
    struct ndpi_detection_module_struct *ndpi,
    const cdpi_flow_map *flows, bool unknown = true)
{
    char buffer[256];
    json_object *json_flow = NULL, *json_obj = NULL;

    for (cdpi_flow_map::const_iterator i = flows->begin();
        i != flows->end(); i++) {

        if (i->second->detection_complete == false)
            continue;
        if (unknown == false &&
            i->second->detected_protocol.protocol == NDPI_PROTOCOL_UNKNOWN)
            continue;

        json_flow = json_object_new_object();
        if (json_flow == NULL)
            throw runtime_error(strerror(ENOMEM));

        string digest;
        cdpi_sha1_to_string((const uint8_t *)i->first.data(), digest);
        json_obj = json_object_new_string(digest.c_str());
        if (json_obj == NULL)
            throw runtime_error(strerror(ENOMEM));
        json_object_object_add(json_flow, "digest", json_obj);

        json_obj = json_object_new_int(i->second->version);
        if (json_obj == NULL)
            throw runtime_error(strerror(ENOMEM));
        json_object_object_add(json_flow, "ip_version", json_obj);

        json_obj = json_object_new_int(i->second->protocol);
        if (json_obj == NULL)
            throw runtime_error(strerror(ENOMEM));
        json_object_object_add(json_flow, "ip_protocol", json_obj);

        json_obj = json_object_new_int(i->second->vlan_id);
        if (json_obj == NULL)
            throw runtime_error(strerror(ENOMEM));
        json_object_object_add(json_flow, "vlan_id", json_obj);

        snprintf(buffer, sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x",
            i->second->lower_mac[0], i->second->lower_mac[1], i->second->lower_mac[2],
            i->second->lower_mac[3], i->second->lower_mac[4], i->second->lower_mac[5]
        );
        json_obj = json_object_new_string(buffer);
        if (json_obj == NULL)
            throw runtime_error(strerror(ENOMEM));
        json_object_object_add(json_flow, "lower_mac", json_obj);

        snprintf(buffer, sizeof(buffer), "%02x:%02x:%02x:%02x:%02x:%02x",
            i->second->upper_mac[0], i->second->upper_mac[1], i->second->upper_mac[2],
            i->second->upper_mac[3], i->second->upper_mac[4], i->second->upper_mac[5]
        );
        json_obj = json_object_new_string(buffer);
        if (json_obj == NULL)
            throw runtime_error(strerror(ENOMEM));
        json_object_object_add(json_flow, "upper_mac", json_obj);

        json_obj = json_object_new_string(i->second->lower_ip);
        if (json_obj == NULL)
            throw runtime_error(strerror(ENOMEM));
        json_object_object_add(json_flow, "lower_ip", json_obj);

        json_obj = json_object_new_string(i->second->upper_ip);
        if (json_obj == NULL)
            throw runtime_error(strerror(ENOMEM));
        json_object_object_add(json_flow, "upper_ip", json_obj);

        json_obj = json_object_new_int(ntohs(i->second->lower_port));
        if (json_obj == NULL)
            throw runtime_error(strerror(ENOMEM));
        json_object_object_add(json_flow, "lower_port", json_obj);

        json_obj = json_object_new_int(ntohs(i->second->upper_port));
        if (json_obj == NULL)
            throw runtime_error(strerror(ENOMEM));
        json_object_object_add(json_flow, "upper_port", json_obj);

        json_obj = json_object_new_int(i->second->detected_protocol.protocol);
        if (json_obj == NULL)
            throw runtime_error(strerror(ENOMEM));
        json_object_object_add(json_flow, "detected_protocol", json_obj);

        json_obj = json_object_new_int(
            i->second->detected_protocol.master_protocol);
        if (json_obj == NULL)
            throw runtime_error(strerror(ENOMEM));
        json_object_object_add(json_flow, "detected_protocol_master", json_obj);

        if (i->second->detected_protocol.master_protocol) {
            snprintf(buffer, sizeof(buffer), "%s.%s",
                ndpi_get_proto_name(ndpi,
                    i->second->detected_protocol.master_protocol),
                ndpi_get_proto_name(ndpi,
                    i->second->detected_protocol.protocol));

            json_obj = json_object_new_string(buffer);
            if (json_obj == NULL)
                throw runtime_error(strerror(ENOMEM));
            json_object_object_add(json_flow, "detected_protocol_name", json_obj);
        }
        else {
            json_obj = json_object_new_string(
                ndpi_get_proto_name(ndpi, i->second->detected_protocol.protocol));
            if (json_obj == NULL)
                throw runtime_error(strerror(ENOMEM));
            json_object_object_add(json_flow, "detected_protocol_name", json_obj);
        }

        json_obj = json_object_new_boolean(i->second->detection_guessed);
        if (json_obj == NULL)
            throw runtime_error(strerror(ENOMEM));
        json_object_object_add(json_flow, "detection_guessed", json_obj);

        json_obj = json_object_new_int(i->second->packets);
        if (json_obj == NULL)
            throw runtime_error(strerror(ENOMEM));
        json_object_object_add(json_flow, "packets", json_obj);

        json_obj = json_object_new_int64(i->second->bytes);
        if (json_obj == NULL)
            throw runtime_error(strerror(ENOMEM));
        json_object_object_add(json_flow, "bytes", json_obj);

        if (i->second->host_server_name[0] != '\0') {
            json_obj = json_object_new_string(i->second->host_server_name);
            if (json_obj == NULL)
                throw runtime_error(strerror(ENOMEM));
            json_object_object_add(json_flow, "host_server_name", json_obj);
        }

        if((i->second->ssl.client_cert[0] != '\0') ||
            (i->second->ssl.server_cert[0] != '\0')) {

            json_object *ssl = json_object_new_object();
            if (ssl == NULL)
                throw runtime_error(strerror(ENOMEM));

            if(i->second->ssl.client_cert[0] != '\0') {
                json_obj = json_object_new_string(i->second->ssl.client_cert);
                if (json_obj == NULL)
                    throw runtime_error(strerror(ENOMEM));
                json_object_object_add(ssl, "client", json_obj);
            }

            if(i->second->ssl.server_cert[0] != '\0') {
                json_obj = json_object_new_string(i->second->ssl.server_cert);
                if (json_obj == NULL)
                    throw runtime_error(strerror(ENOMEM));
                json_object_object_add(ssl, "server", json_obj);
            }

          json_object_object_add(json_flow, "ssl", ssl);
        }

        json_obj = json_object_new_int64(i->second->ts_last_seen);
        if (json_obj == NULL)
            throw runtime_error(strerror(ENOMEM));
        json_object_object_add(json_flow, "last_seen", json_obj);

        json_object_array_add(json_parent, json_flow);
    }
}

static void cdpi_dump_stats(void)
{
    uint64_t flow_count = 0;
    json_object *json_obj = NULL;
    json_object *json_main = json_object_new_object();
    json_object *json_devs = json_object_new_array();
    json_object *json_stats = json_object_new_object();
    json_object *json_flows = json_object_new_object();

    if (json_main == NULL || json_devs == NULL ||
        json_stats == NULL || json_flows == NULL)
        throw runtime_error(strerror(ENOMEM));

    json_obj = json_object_new_string(PACKAGE_VERSION);
    if (json_obj == NULL)
        throw runtime_error(strerror(ENOMEM));
    json_object_object_add(json_main, "version", json_obj);

    json_obj = json_object_new_int64((int64_t)time(NULL));
    if (json_obj == NULL)
        throw runtime_error(strerror(ENOMEM));
    json_object_object_add(json_main, "date_time", json_obj);

    for (cdpi_threads::iterator i = threads.begin();
        i != threads.end(); i++) {

        json_obj = json_object_new_string(i->first.c_str());
        if (json_obj == NULL)
            throw runtime_error(strerror(ENOMEM));
        json_object_array_add(json_devs, json_obj);

        i->second->Lock();

        totals += *stats[i->first];
        flow_count += flows[i->first]->size();

        json_obj = json_object_new_object();
        if (json_obj == NULL)
            throw runtime_error(strerror(ENOMEM));
        cdpi_json_add_stats(json_obj, stats[i->first]);
        json_object_object_add(json_stats, i->first.c_str(), json_obj);

        memset(stats[i->first], 0, sizeof(cdpiDetectionStats));

        json_obj = json_object_new_array();
        if (json_obj == NULL)
            throw runtime_error(strerror(ENOMEM));
        cdpi_json_add_flows(json_obj,
            i->second->GetDetectionModule(), flows[i->first]);

        i->second->Unlock();

        json_object_object_add(json_flows, i->first.c_str(), json_obj);
    }

    json_object_object_add(json_main, "devices", json_devs);
    json_object_object_add(json_main, "stats", json_stats);
    json_object_object_add(json_main, "flows", json_flows);

    try {
        cdpi_json_write(json_main);
    }
    catch (runtime_error &e) {
        cdpi_printf("Error writing JSON file: %s: %s\n",
            cdpi_json_filename, e.what());
    }

    try {
        cdpi_json_upload(json_main);
    }
    catch (runtime_error &e) {
        cdpi_printf("Error uploading JSON: %s\n", e.what());
    }

    json_object_put(json_main);

    if (cdpi_debug) {
        cdpi_printf("\nCumulative Totals:\n");
        totals.print();
        cdpi_printf("        Flows: %lu\n\n", flow_count);
    }
}

int main(int argc, char *argv[])
{
    int rc = 0;
    bool terminate = false;
    sigset_t sigset;
    struct sigevent sigev;
    timer_t timer_id;
    struct itimerspec it_spec;

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
            cdpi_debug = true;
            break;
        case 'I':
            for (cdpi_devices::iterator i = devices.begin();
                i != devices.end(); i++) {
                if (strcasecmp((*i).c_str(), optarg) == 0) {
                    cerr << "Duplicate interface specified: " << optarg << endl;
                    exit(1);
                }
            }
            devices.push_back(optarg);
            break;
        case 'j':
            cdpi_json_filename = strdup(optarg);
            break;
        case 'i':
            cdpi_stats_interval = atoi(optarg);
            break;
        case 'c':
            cdpi_conf_filename = strdup(optarg);
            break;
        default:
            usage(1);
        }
    }

    if (cdpi_json_filename == NULL)
        cdpi_json_filename = strdup(CDPI_JSON_FILE_NAME);
    if (cdpi_conf_filename == NULL)
        cdpi_conf_filename = strdup(CDPI_CONF_FILE_NAME);

    if (cdpi_conf_load() < 0)
        return 1;

    if (devices.size() == 0) {
        cerr << "Required argument, (-I, --iterface) missing." << endl;
        return 1;
    }

    CURLcode cc;
    if ((cc = curl_global_init(CURL_GLOBAL_ALL)) != 0) {
        cerr << "Unable to initialize libCURL: " << cc << endl;
        return 1;
    }

    if (cdpi_debug == false) {
        if (daemon(1, 0) != 0) {
            cdpi_printf("daemon: %s\n", strerror(errno));
            return 1;
        }
        FILE *hpid = fopen(CDPI_PID_FILE_NAME, "w+");
        if (hpid == NULL) {
            cdpi_printf("Error opening PID file: %s: %s\n",
                CDPI_PID_FILE_NAME, strerror(errno));
            return 1;
        }
        fprintf(hpid, "%d\n", getpid());
        fclose(hpid);
    }
        
    cdpi_output_mutex = new pthread_mutex_t;
    pthread_mutex_init(cdpi_output_mutex, NULL);

    cdpi_printf("ClearOS DPI Daemon v%s\n", PACKAGE_VERSION);

    memset(&totals, 0, sizeof(cdpiDetectionStats));

    sigfillset(&sigset);
    sigdelset(&sigset, SIGPROF);

    sigprocmask(SIG_BLOCK, &sigset, NULL);

    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    sigaddset(&sigset, SIGTERM);
    sigaddset(&sigset, SIGRTMIN);
    sigaddset(&sigset, SIGIO);

    thread_control = new cdpiControlThread();
    thread_control->Create();

    thread_upload = new cdpiUploadThread();
    thread_upload->Create();

    for (cdpi_devices::iterator i = devices.begin();
        i != devices.end(); i++) {
        flows[(*i)] = new cdpi_flow_map;
        stats[(*i)] = new cdpiDetectionStats;
    }

    try {
        inotify_files = new cdpiInotify();
        inotify_files->AddWatch(CDPI_WATCH_HOSTS);
        inotify_files->AddWatch(CDPI_WATCH_ETHERS);
        inotify_files->RefreshWatches();
    }
    catch (exception &e) {
        cdpi_printf("Error creating file watches: %s\n", e.what());
        return 1;
    }

    try {
        long cpu = 0;
        long cpus = sysconf(_SC_NPROCESSORS_ONLN);

        for (cdpi_devices::iterator i = devices.begin();
            i != devices.end(); i++) {
            threads[(*i)] = new cdpiDetectionThread(
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
        cdpi_printf("Runtime error: %s\n", e.what());
        return 1;
    }

    memset(&sigev, 0, sizeof(struct sigevent));
    sigev.sigev_notify = SIGEV_SIGNAL;
    sigev.sigev_signo = SIGRTMIN;

    if (timer_create(CLOCK_REALTIME, &sigev, &timer_id) < 0) {
        cdpi_printf("timer_create: %s\n", strerror(errno));
        return 1;
    }

    it_spec.it_value.tv_sec = cdpi_stats_interval;
    it_spec.it_value.tv_nsec = 0;
    it_spec.it_interval.tv_sec = cdpi_stats_interval;
    it_spec.it_interval.tv_nsec = 0;

    timer_settime(timer_id, 0, &it_spec, NULL);

    while (!terminate) {
        int sig;
        siginfo_t si;

        sig = sigwaitinfo(&sigset, &si);
        if (sig < 0) {
            cdpi_printf("sigwaitinfo: %s\n", strerror(errno));
            rc = -1;
            terminate = true;
            continue;
        }

        if (sig == SIGINT || sig == SIGTERM) {
            rc = 0;
            terminate = true;
            cdpi_printf("Exiting...\n");
            continue;
        }

        if (sig == sigev.sigev_signo) {
            cdpi_dump_stats();
            inotify_files->RefreshWatches();
            continue;
        }

        if (sig == SIGIO) {
            inotify_files->ProcessWatchEvent();
            continue;
        }

        cdpi_printf("Unhandled signal: %s\n", strsignal(sig));
    }

    timer_delete(timer_id);

    for (cdpi_devices::iterator i = devices.begin();
        i != devices.end(); i++) {
        threads[(*i)]->Terminate();
        delete threads[(*i)];
        delete flows[(*i)];
        delete stats[(*i)];
    }

    thread_control->Terminate();
    thread_upload->Terminate();
    delete thread_control;
    delete thread_upload;

    pthread_mutex_destroy(cdpi_output_mutex);

    curl_global_cleanup();

    return 0;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
