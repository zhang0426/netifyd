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

#ifndef _ND_FLOW_H
#define _ND_FLOW_H

// XXX: These lengths are extracted from:
//      ndpi/src/include/ndpi_typedefs.h
//
// Unfortunately they don't define such constants so we have to define
// them here.  If they change in nDPI, they'll need to be updated
// manually.
#define ND_FLOW_UA_LEN      512     // User agent length
#define ND_FLOW_SSH_UALEN   48      // SSH user-agent (signature) length
#define ND_FLOW_SSL_CNLEN   48      // SSL certificate common-name length
#define ND_FLOW_DHCPFP_LEN  48      // DHCP fingerprint length
#define ND_FLOW_DHCPCI_LEN  96      // DHCP class identifier
#define ND_FLOW_MDNS_ANSLEN 96      // MDNS answer length
// BitTorrent info hash length
#define ND_FLOW_BTIHASH_LEN SHA1_DIGEST_LENGTH

// Bits for detection guess types
#define ND_FLOW_GUESS_NONE  0x00    // No guesses made
#define ND_FLOW_GUESS_PROTO 0x01    // Protocol guesses (ports)
#define ND_FLOW_GUESS_DNS   0x02    // Application guessed by DNS cache hint

struct ndFlow
{
    bool internal;
    uint8_t ip_version;
    uint8_t ip_protocol;
    bool ip_nat;

    uint16_t vlan_id;
    uint64_t ts_first_seen;
    uint64_t ts_last_seen;
#ifdef _ND_USE_NETLINK
    ndNetlinkAddressType lower_type;
    ndNetlinkAddressType upper_type;
#endif
    uint8_t lower_mac[ETH_ALEN];
    uint8_t upper_mac[ETH_ALEN];

//    struct sockaddr_storage lower_addr;
//    struct sockaddr_storage upper_addr;

    struct in_addr lower_addr;
    struct in_addr upper_addr;

    struct in6_addr lower_addr6;
    struct in6_addr upper_addr6;

    char lower_ip[INET6_ADDRSTRLEN];
    char upper_ip[INET6_ADDRSTRLEN];

    uint16_t lower_port;
    uint16_t upper_port;

    uint64_t lower_bytes;
    uint64_t upper_bytes;
    uint64_t total_bytes;

    uint32_t lower_packets;
    uint32_t upper_packets;
    uint32_t total_packets;

    bool detection_complete;
    uint8_t detection_guessed;

    ndpi_protocol detected_protocol;

    struct ndpi_flow_struct *ndpi_flow;

    struct ndpi_id_struct *id_src;
    struct ndpi_id_struct *id_dst;

    char host_server_name[HOST_NAME_MAX];

    union {
        struct {
            char user_agent[ND_FLOW_UA_LEN];
        } http;

        struct {
            char fingerprint[ND_FLOW_DHCPFP_LEN];
            char class_ident[ND_FLOW_DHCPCI_LEN];
        } dhcp;

        struct {
            char client_agent[ND_FLOW_SSH_UALEN];
            char server_agent[ND_FLOW_SSH_UALEN];
        } ssh;

        struct {
            char client_certcn[ND_FLOW_SSL_CNLEN];
            char server_certcn[ND_FLOW_SSL_CNLEN];
        } ssl;

        struct {
            uint8_t info_hash_valid:1;
            char info_hash[ND_FLOW_BTIHASH_LEN];
        } bt;

        struct {
            char answer[ND_FLOW_MDNS_ANSLEN];
        } mdns;
    };

    enum {
        PRIVATE_LOWER = 0x01,
        PRIVATE_UPPER = 0x02
    };

    uint8_t privacy_mask;

    void hash(const string &device, string &digest,
        bool full_hash = false, const uint8_t *key = NULL, size_t key_length = 0);

    inline bool operator==(const ndFlow &f) const {
        if (lower_port != f.lower_port || upper_port != f.upper_port) return false;
        switch (ip_version) {
        case 4:
            if (memcmp(&lower_addr, &f.lower_addr, sizeof(struct in_addr)) == 0 &&
                memcmp(&upper_addr, &f.upper_addr, sizeof(struct in_addr)) == 0)
                return true;
            break;
        case 6:
            if (memcmp(&lower_addr6, &f.lower_addr6, sizeof(struct in6_addr)) == 0 &&
                memcmp(&upper_addr6, &f.upper_addr6, sizeof(struct in6_addr)) == 0)
                return true;
            break;
        }
        return false;
    }

    inline void release(void) {
        if (ndpi_flow != NULL) { ndpi_free_flow(ndpi_flow); ndpi_flow = NULL; }
        if (id_src != NULL) { delete id_src; id_src = NULL; }
        if (id_dst != NULL) { delete id_dst; id_dst = NULL; }
    }

    uint16_t master_protocol(void);

    bool has_dhcp_fingerprint(void);
    bool has_dhcp_class_ident(void);
    bool has_http_user_agent(void);
    bool has_ssh_client_agent(void);
    bool has_ssh_server_agent(void);
    bool has_ssl_client_certcn(void);
    bool has_ssl_server_certcn(void);
    bool has_bt_info_hash(void);
    bool has_mdns_answer(void);

    void print(const char *tag, struct ndpi_detection_module_struct *ndpi);

    json_object *json_encode(const string &device, ndJson &json,
        struct ndpi_detection_module_struct *ndpi, bool include_stats = true);
};

typedef unordered_map<string, struct ndFlow *> nd_flow_map;
typedef map<string, nd_flow_map *> nd_flows;
typedef pair<string, struct ndFlow *> nd_flow_pair;
typedef pair<nd_flow_map::iterator, bool> nd_flow_insert;

#endif // _ND_FLOW_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
