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

#ifndef _ND_UTIL_H
#define _ND_UTIL_H

#define ND_SHA1_BUFFER      4096

#define ND_C_RESET          "\033[0m"
#define ND_C_RED            "\033[0;31m"
#define ND_C_GREEN          "\033[0;32m"
#define ND_C_YELLOW         "\033[0;33m"

void *nd_mem_alloc(size_t size);

void nd_mem_free(void *ptr);

void nd_printf(const char *format, ...);
void nd_debug_printf(const char *format, ...);
void nd_flow_printf(const char *format, ...);

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
void nd_ndpi_debug_printf(uint32_t protocol, void *ndpi,
    ndpi_log_level_t level, const char *file, const char *func, unsigned line,
    const char *format, ...);
#endif

void nd_print_address(const struct sockaddr_storage *addr);

void nd_print_binary(uint32_t byte);

void nd_print_number(ostringstream &os, uint64_t value, bool units_binary = true);

int nd_sha1_file(const string &filename, uint8_t *digest);
void nd_sha1_to_string(const uint8_t *digest_bin, string &digest_str);

void nd_iface_name(const string &iface, string &result);

bool nd_is_ipaddr(const char *ip);

void nd_private_ipaddr(uint8_t index, struct sockaddr_storage &addr);

bool nd_load_uuid(string &uuid, const char *path, size_t length);
bool nd_save_uuid(const string &uuid, const char *path, size_t length);

bool nd_load_sink_url(string &url);
bool nd_save_sink_url(const string &url);

void nd_generate_uuid(string &uuid);

string nd_get_version_and_features(void);

#ifdef _ND_USE_WATCHDOGS
int nd_touch(const string &filename);
#endif

int nd_file_load(const string &filename, string &data);

void nd_file_save(const string &filename, const string &data,
    bool append = false, mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP,
    const char *user = NULL, const char *group = NULL);

int nd_save_response_data(const char *filename, const ndJsonDataChunks &data);

int nd_ifreq(const string &name, unsigned long request, struct ifreq *ifr);

int nd_ifaddrs(nd_interface_addr_map &addr_map);
int nd_ifaddrs_update(nd_interface_addr_map &addr_map);
void nd_ifaddrs_free(nd_interface_addr_map &addr_map);
bool nd_ifaddrs_get_mac(
    nd_interface_addr_map &addr_map,
    const string &name, uint8_t *addr);

pid_t nd_is_running(pid_t pid, const char *exe_base);

int nd_file_exists(const char *path);

void nd_uptime(time_t ut, string &uptime);

int nd_functions_exec(const string &func, string &output);

void nd_os_detect(string &os);

#endif // _ND_UTIL_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
