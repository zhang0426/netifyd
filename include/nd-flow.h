// Netify Agent
// Copyright (C) 2015-2019 eGloo Incorporated <http://www.egloo.ca>
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
#define ND_FLOW_URL_LEN     512     // HTTP URL length
#define ND_FLOW_SSH_UALEN   48      // SSH user-agent (signature) length
#define ND_FLOW_SSL_CNLEN   64      // SSL certificate SNI/common-name length
#define ND_FLOW_SSL_ORGLEN  64      // SSL certificate organization name length
#define ND_FLOW_SSL_JA3LEN  33      // SSL JA3 hash length (MD5)
#define ND_FLOW_DHCPFP_LEN  48      // DHCP fingerprint length
#define ND_FLOW_DHCPCI_LEN  96      // DHCP class identifier
#define ND_FLOW_MDNS_ANSLEN 96      // MDNS answer length
// BitTorrent info hash length
#define ND_FLOW_BTIHASH_LEN SHA1_DIGEST_LENGTH

// Bits for detection guess types
#define ND_FLOW_GUESS_NONE  0x00    // No guesses made
#define ND_FLOW_GUESS_PROTO 0x01    // Protocol guesses (ports)
#define ND_FLOW_GUESS_DNS   0x02    // Application guessed by DNS cache hint

// Capture filename template
#define ND_FLOW_CAPTURE_TEMPLATE    ND_VOLATILE_STATEDIR "/nd-flow-XXXXXXXX.cap"
#define ND_FLOW_CAPTURE_SUB_OFFSET  (sizeof(ND_FLOW_CAPTURE_TEMPLATE) - 8 - 4 - 1)

// Hash cache filename
#define ND_FLOW_HC_FILE_NAME        "/flow-hash-cache-"

typedef list<pair<string, string>> nd_fhc_list;
typedef unordered_map<string, nd_fhc_list::iterator> nd_fhc_map;

class ndFlowHashCache
{
public:
    ndFlowHashCache(const string &device, size_t cache_size = ND_MAX_FHC_ENTRIES);

    void push(const string &lower_hash, const string &upper_hash);
    bool pop(const string &lower_hash, string &upper_hash);

    void save(void);
    void load(void);

protected:
    string device;
    size_t cache_size;
    nd_fhc_list index;
    nd_fhc_map lookup;
};

typedef pair<const struct pcap_pkthdr *, const uint8_t *> nd_flow_push;
typedef vector<nd_flow_push> nd_flow_capture;

class ndFlow
{
public:
    bool internal;
    uint8_t ip_version;
    uint8_t ip_protocol;
    uint16_t vlan_id;

    bool ip_nat;
    bool tcp_fin;

    uint64_t ts_first_seen;
    uint64_t ts_first_update;
    uint64_t ts_last_seen;
#ifdef _ND_USE_NETLINK
    ndNetlinkAddressType lower_type;
    ndNetlinkAddressType upper_type;
#endif
    uint8_t lower_mac[ETH_ALEN];
    uint8_t upper_mac[ETH_ALEN];

    struct sockaddr_storage lower_addr;
    struct sockaddr_storage upper_addr;

    struct sockaddr_in *lower_addr4;
    struct sockaddr_in6 *lower_addr6;

    struct sockaddr_in *upper_addr4;
    struct sockaddr_in6 *upper_addr6;

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

    uint8_t digest_lower[SHA1_DIGEST_LENGTH];
    uint8_t digest_mdata[SHA1_DIGEST_LENGTH];

    char host_server_name[ND_MAX_HOSTNAME];

    union {
        struct {
            char user_agent[ND_FLOW_UA_LEN];
            char url[ND_FLOW_URL_LEN];
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
            uint16_t version;
            uint16_t cipher_suite;
            char client_sni[ND_FLOW_SSL_CNLEN];
            char server_cn[ND_FLOW_SSL_CNLEN];
            char server_organization[ND_FLOW_SSL_ORGLEN];
            char client_ja3[ND_FLOW_SSL_JA3LEN];
            char server_ja3[ND_FLOW_SSL_JA3LEN];
        } ssl;

        struct {
            bool tls;
        } smtp;

        struct {
            uint8_t info_hash_valid:1;
            char info_hash[ND_FLOW_BTIHASH_LEN];
        } bt;

        struct {
            char answer[ND_FLOW_MDNS_ANSLEN];
        } mdns;
    };

    enum {
        TYPE_LOWER,
        TYPE_UPPER,

        TYPE_MAX
    };

    enum {
        PRIVATE_LOWER = 0x01,
        PRIVATE_UPPER = 0x02
    };

    uint8_t privacy_mask;

    // Indicate flow origin.  This indicates which side sent the first packet.
    // XXX: If the service has missed a flow's initial packets, the origin's
    // accuracy would be 50%.
    enum {
        ORIGIN_UNKNOWN = 0x00,
        ORIGIN_LOWER = 0x01,
        ORIGIN_UPPER = 0x02
    };

    uint8_t origin;

    nd_flow_capture capture;
    char capture_filename[sizeof(ND_FLOW_CAPTURE_TEMPLATE)];

    ndFlow(bool internal = true);
    virtual ~ndFlow();

    void hash(const string &device, bool hash_mdata = false,
        const uint8_t *key = NULL, size_t key_length = 0);

    void push(const struct pcap_pkthdr *pkt_header, const uint8_t *pkt_data);

    int dump(pcap_t *pcap, const uint8_t *digest);

    void reset(void);

    void release(void);

    uint16_t master_protocol(void);

    bool has_dhcp_fingerprint(void);
    bool has_dhcp_class_ident(void);
    bool has_http_user_agent(void);
    bool has_http_url(void);
    bool has_ssh_client_agent(void);
    bool has_ssh_server_agent(void);
    bool has_ssl_client_sni(void);
    bool has_ssl_server_cn(void);
    bool has_ssl_server_organization(void);
    bool has_ssl_client_ja3(void);
    bool has_ssl_server_ja3(void);
    bool has_bt_info_hash(void);
    bool has_mdns_answer(void);

    void print(const char *tag, struct ndpi_detection_module_struct *ndpi);

    json_object *json_encode(ndJson &json,
        struct ndpi_detection_module_struct *ndpi, bool include_stats = true);

    inline bool operator==(const ndFlow &f) const {
        if (lower_port != f.lower_port || upper_port != f.upper_port) return false;
        if (memcmp(&lower_addr, &f.lower_addr, sizeof(struct sockaddr_storage)) == 0 &&
            memcmp(&upper_addr, &f.upper_addr, sizeof(struct sockaddr_storage)) == 0)
            return true;
        return false;
    }

    inline ndFlow& operator+=(const ndFlow &f)
    {
        this->lower_bytes += f.lower_bytes;
        this->upper_bytes += f.upper_bytes;
        this->total_bytes += f.total_bytes;
        this->lower_packets += f.lower_packets;
        this->upper_packets += f.upper_packets;
        this->total_packets += f.total_packets;
        return *this;
    }
};

typedef unordered_map<string, ndFlow *> nd_flow_map;
typedef map<string, nd_flow_map *> nd_flows;
typedef pair<string, ndFlow *> nd_flow_pair;
typedef pair<nd_flow_map::iterator, bool> nd_flow_insert;

#endif // _ND_FLOW_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
