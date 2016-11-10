// Netify Content Match Export Tool
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

#include <stdio.h>
#include <getopt.h>

#include <arpa/inet.h>

#include "ndpi_main.h"
#include "ndpi_content_match.c.inc"

using namespace std;

static bool nd_debug = false;

static void nd_usage(int rc = 0, bool version = false)
{
    cerr << "Netify Content Match Export Tool v" << PACKAGE_VERSION << endl;
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
        cerr << endl;
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
            "  -H, --hosts <filename>" << endl;
        cerr <<
            "    Export host/protocol CSV.  Use '-' for stdout." << endl;
        cerr <<
            "  -C, --content-match <filename>" << endl;
        cerr <<
            "    Export content match/protocol CSV.  Use '-' for stdout." << endl;
    }

    exit(rc);
}

static void nd_dump_host_protocol_list(FILE *fp)
{
    struct sockaddr_in saddr_ip4;
    char ip_addr[INET6_ADDRSTRLEN];

    fprintf(fp, "\"ip_address\",\"ip_prefix\",\"application_id\"\n");
    for (unsigned i = 0; host_protocol_list[i].network != 0; i++) {
        saddr_ip4.sin_addr.s_addr = htonl(host_protocol_list[i].network);
        if (!inet_ntop(AF_INET, &saddr_ip4.sin_addr, ip_addr, INET6_ADDRSTRLEN))
            continue;

        fprintf(fp, "\"%s\",%hhu,%hhu\n", ip_addr,
            host_protocol_list[i].cidr, host_protocol_list[i].value);
    }
}

static void nd_dump_content_match_list(FILE *fp)
{
    fprintf(fp, "\"match\",\"application_name\",\"application_id\"\n");
    for (unsigned i = 0; host_match[i].string_to_match != NULL; i++) {
        fprintf(fp, "\"%s\",\"%s\",%u\n",
            host_match[i].string_to_match, host_match[i].proto_name,
            (unsigned)host_match[i].protocol_id);
    }
}

int main(int argc, char *argv[])
{
    int rc;
    FILE *csv_host = NULL;
    FILE *csv_content_match = NULL;

    static struct option options[] =
    {
        { "help", 0, 0, 'h' },
        { "version", 0, 0, 'V' },
        { "debug", 0, 0, 'd' },

        { NULL, 0, 0, 0 }
    };

    for (optind = 1;; ) {
        int o = 0;
        if ((rc = getopt_long(argc, argv,
            "?hVdH:C:", options, &o)) == -1) break;
        switch (rc) {
        case '?':
            cerr <<
                "Try " << argv[0] << " --help for more information." << endl;
            return 1;
        case 'h':
            nd_usage();
        case 'V':
            nd_usage(0, true);
        case 'd':
            nd_debug = true;
            break;
        case 'H':
            if (strnlen(optarg, 2) == 1 && optarg[0] == '-')
                csv_host = stdout;
            else
                csv_host = fopen(optarg, "w");
            break;
        case 'C':
            if (strnlen(optarg, 2) == 1 && optarg[0] == '-')
                csv_content_match = stdout;
            else
                csv_content_match = fopen(optarg, "w");
            break;
        }
    }

    if (csv_host != NULL) {
        nd_dump_host_protocol_list(csv_host);
        fclose(csv_host);
    }

    if (csv_content_match != NULL) {
        nd_dump_content_match_list(csv_content_match);
        fclose(csv_content_match);
    }

    if (csv_host == NULL && csv_content_match == NULL) {
        cerr << "Error, nothing to do. " << endl;
        cerr <<
            "Try " << argv[0] << " --help for more information." << endl;
        return 1;
    }

    return 0;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
