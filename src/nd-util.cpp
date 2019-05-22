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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdexcept>
#include <cstdlib>
#include <cstdarg>
#include <string>
#include <iostream>
#include <locale>
#include <iomanip>
#include <sstream>
#include <vector>
#include <map>
#include <deque>
#include <unordered_map>
#include <regex>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/socket.h>

#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>
#ifdef _ND_USE_WATCHDOGS
#include <time.h>
#endif
#include <pwd.h>
#include <grp.h>

#include <arpa/inet.h>
#include <netdb.h>

#include <json.h>
#include <pcap/pcap.h>

using namespace std;

#include "netifyd.h"

#include "nd-ndpi.h"
#include "nd-sha1.h"
#include "nd-json.h"
#include "nd-util.h"

extern nd_global_config nd_config;

ndException::ndException(const string &where_arg, const string &what_arg) throw()
    : runtime_error(what_arg), where_arg(where_arg), what_arg(what_arg), message(NULL)
{
    ostringstream os;
    os << where_arg << ": " << what_arg;
    message = strdup(os.str().c_str());
}

ndException::~ndException() throw()
{
    if (message != NULL) free((void *)message);
}

const char *ndException::what() const throw()
{
    return message;
}

ndSystemException::ndSystemException(
    const string &where_arg, const string &what_arg, int why_arg) throw()
    : runtime_error(what_arg),
    where_arg(where_arg), what_arg(what_arg), why_arg(why_arg), message(NULL)
{
    ostringstream os;
    os << where_arg << ": " << what_arg << ": " << strerror(why_arg);
    message = strdup(os.str().c_str());
}

ndSystemException::~ndSystemException() throw()
{
    if (message != NULL) free((void *)message);
}

const char *ndSystemException::what() const throw()
{
    return message;
}

void *nd_mem_alloc(size_t size)
{
    return malloc(size);
}

void nd_mem_free(void *ptr)
{
    free(ptr);
}

extern pthread_mutex_t *nd_printf_mutex;

void nd_printf(const char *format, ...)
{
    pthread_mutex_lock(nd_printf_mutex);

    va_list ap;
    va_start(ap, format);
    vsyslog(LOG_DAEMON | LOG_INFO, format, ap);
    va_end(ap);

    pthread_mutex_unlock(nd_printf_mutex);
}

void nd_debug_printf(const char *format, ...)
{
    if (ND_DEBUG) {

        pthread_mutex_lock(nd_printf_mutex);

        va_list ap;
        va_start(ap, format);
        vfprintf(stderr, format, ap);
        va_end(ap);

        pthread_mutex_unlock(nd_printf_mutex);
    }
}

void nd_flow_printf(const char *format, ...)
{
    pthread_mutex_lock(nd_printf_mutex);

    va_list ap;
    va_start(ap, format);
    vfprintf(nd_config.h_flow, format, ap);
    va_end(ap);

    pthread_mutex_unlock(nd_printf_mutex);
}

#ifdef NDPI_ENABLE_DEBUG_MESSAGES
void nd_ndpi_debug_printf(uint32_t protocol, void *ndpi,
    ndpi_log_level_t level, const char *file, const char *func, unsigned line,
    const char *format, ...)
{
    if (ND_DEBUG) {

        pthread_mutex_lock(nd_printf_mutex);

        va_list ap;
        va_start(ap, format);

        fprintf(stderr, "[nDPI:%08x:%p:%s]: %s/%s:%d: ", protocol, ndpi,
            (level == NDPI_LOG_ERROR) ? "ERROR" :
                (level == NDPI_LOG_TRACE) ? "TRACE" :
                    (level == NDPI_LOG_DEBUG) ? "DEBUG" :
                        (level == NDPI_LOG_DEBUG_EXTRA) ? "DEXTRA" :
                            "UNK???",
            file, func, line
        );
        vfprintf(stderr, format, ap);

        va_end(ap);

        pthread_mutex_unlock(nd_printf_mutex);
    }
}
#endif // NDPI_ENABLE_DEBUG_MESSAGES

void nd_print_address(const struct sockaddr_storage *addr)
{
    int rc;
    char _addr[NI_MAXHOST];

    switch (addr->ss_family) {
    case AF_INET:
        rc = getnameinfo((const struct sockaddr *)addr, sizeof(struct sockaddr_in),
            _addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        break;
    case AF_INET6:
        rc = getnameinfo((const struct sockaddr *)addr, sizeof(struct sockaddr_in6),
            _addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        break;
    default:
        nd_debug_printf("(unsupported AF:%x)", addr->ss_family);
        return;
    }

    if (rc == 0)
        nd_debug_printf("%s", _addr);
    else
        nd_debug_printf("???");
}

void nd_print_binary(uint32_t byte)
{
    uint32_t i;
    char b[sizeof(byte) * 8 + 1];

    b[0] = '\0';
    for (i = 0x80000000; i > 0; i >>= 1)
        strcat(b, ((byte & i) == i) ? "1" : "0");

    nd_debug_printf("%s", b);
}

void nd_print_number(ostringstream &os, uint64_t value, bool units_binary)
{
    float fvalue = value;

    os.str("");
    //os << setiosflags(ios::fixed) << setw(14) << setprecision(3);
    os << setw(8) << setprecision(3);

    if (units_binary) {
        if (fvalue >= 1099511627776.0f) {
            fvalue /= 1099511627776.0f;
            os << fvalue << setw(4) << " TiB";
        }
        else if (fvalue >= 1073741824.0f) {
            fvalue /= 1073741824.0f;
            os << fvalue << setw(4) << " GiB";
        }
        else if (fvalue >= 1048576.0f) {
            fvalue /= 1048576.0f;
            os << fvalue << setw(4) << " MiB";
        }
        else if (fvalue >= 1024.0f) {
            fvalue /= 1024.0f;
            os << fvalue << setw(4) << " KiB";
        }
        else {
            os << fvalue << setw(4) << " ";
        }
    }
    else {
        if (fvalue >= 1000000000000.0f) {
            fvalue /= 1000000000000.0f;
            os << fvalue << setw(4) << " TP ";
        }
        else if (fvalue >= 1000000000.0f) {
            fvalue /= 1000000000.0f;
            os << fvalue << setw(4) << " GP ";
        }
        else if (fvalue >= 1000000.0f) {
            fvalue /= 1000000.0f;
            os << fvalue << setw(4) << " MP ";
        }
        else if (fvalue >= 1000.0f) {
            fvalue /= 1000.0f;
            os << fvalue << setw(4) << " KP ";
        }
        else {
            os << fvalue << setw(4) << " ";
        }
    }
}

int nd_sha1_file(const string &filename, uint8_t *digest)
{
    sha1 ctx;
    int fd = open(filename.c_str(), O_RDONLY);
    uint8_t buffer[ND_SHA1_BUFFER], _digest[SHA1_DIGEST_LENGTH];
    ssize_t bytes;

    sha1_init(&ctx);

    if (fd < 0) {
        nd_printf("Unable to hash file: %s: %s\n",
            filename.c_str(), strerror(errno));
        return -1;
    }

    do {
        bytes = read(fd, buffer, ND_SHA1_BUFFER);

        if (bytes > 0)
            sha1_write(&ctx, (const char *)buffer, bytes);
        else if (bytes < 0) {
            nd_printf("Unable to hash file: %s: %s\n",
                filename.c_str(), strerror(errno));
            close(fd);
            return -1;
        }
    }
    while (bytes != 0);

    close(fd);
    memcpy(digest, sha1_result(&ctx, _digest), SHA1_DIGEST_LENGTH);

    return 0;
}

void nd_sha1_to_string(const uint8_t *digest_bin, string &digest_str)
{
    char _digest[SHA1_DIGEST_LENGTH * 2 + 1];
    char *p = _digest;

    for (int i = 0; i < SHA1_DIGEST_LENGTH; i++, p += 2)
        sprintf(p, "%02x", digest_bin[i]);

    digest_str.assign(_digest);
}

void nd_iface_name(const string &iface, string &result)
{
    result = iface;
    size_t p = string::npos;
    if ((p = iface.find_first_of(",")) != string::npos)
        result = iface.substr(0, p);
}

bool nd_is_ipaddr(const char *ip)
{
    struct in_addr addr4;
    struct in6_addr addr6;

    if (inet_pton(AF_INET, ip, &addr4) == 1) return true;
    return (inet_pton(AF_INET6, ip, &addr6) == 1) ? true : false;
}

bool nd_load_uuid(string &uuid, const char *path, size_t length)
{
    char _uuid[length + 1];
    FILE *fh = fopen(path, "r");

    if (fh == NULL) {
        nd_printf("Error loading uuid: %s: %s\n", path, strerror(errno));
        return false;
    }

    if (fread((void *)_uuid, 1, length, fh) != length) {
        fclose(fh);
        nd_printf("Error reading uuid: %s: %s\n", path, strerror(errno));
        return false;
    }

    fclose(fh);
    _uuid[length] = '\0';
    uuid.assign(_uuid);

    return true;
}

bool nd_save_uuid(const string &uuid, const char *path, size_t length)
{
    FILE *fh = fopen(path, "w");

    if (fh == NULL) {
        nd_printf("Error saving uuid: %s: %s\n", path, strerror(errno));
        return false;
    }

    if (fwrite((const void *)uuid.c_str(),
        1, length, fh) != length) {
        fclose(fh);
        nd_printf("Error writing uuid: %s: %s\n", path, strerror(errno));
        return false;
    }

    fclose(fh);
    return true;
}

void nd_generate_uuid(string &uuid)
{
    int digit = 0;
    deque<char> result;
    uint64_t input = 623714775;
    unsigned int seed = (unsigned int)time(NULL);
    const char *clist = { "0123456789abcdefghijklmnpqrstuvwxyz" };
    FILE *fh = fopen("/dev/urandom", "r");
    ostringstream os;

    if (fh == NULL)
        nd_printf("Error opening random device: %s\n", strerror(errno));
    else {
        if (fread((void *)&seed, sizeof(unsigned int), 1, fh) != 1)
            nd_printf("Error reading from random device: %s\n", strerror(errno));
        fclose(fh);
    }

    srand(seed);
    input = (uint64_t)rand();
    input += (uint64_t)rand() << 32;

    while (input != 0) {
        result.push_front(toupper(clist[input % strlen(clist)]));
        input /= strlen(clist);
    }

    for (size_t i = result.size(); i < 8; i++)
        result.push_back('0');

    while (result.size() && digit < 8) {
        os << result.front();
        result.pop_front();
        if (digit == 1) os << "-";
        if (digit == 3) os << "-";
        if (digit == 5) os << "-";
        digit++;
    }

    uuid = os.str();
}

string nd_get_version_and_features(void)
{
    ostringstream ident;
    ident <<
        PACKAGE_NAME << "/" << GIT_RELEASE << " (" << _ND_HOST_CPU;

    if (ND_USE_CONNTRACK) ident << "; conntrack";
    if (ND_USE_NETLINK) ident << "; netlink";
    if (ND_USE_DHC) ident << "; dns-cache";
#ifdef _ND_USE_PLUGINS
    ident << "; plugins";
#endif
#ifdef _ND_USE_LIBTCMALLOC
    ident << "; tcmalloc";
#endif
    if (ND_SSL_USE_TLSv1) ident << "; ssl-tlsv1";
    if (! ND_SSL_VERIFY) ident << "; ssl-no-verify";
#ifdef _HAVE_WORKING_REGEX
    ident << "; regex";
#endif
    ident << ")" <<
        " nDPI/" << ndpi_revision() <<
        " JSON/" << fixed << showpoint << setprecision(2) << ND_JSON_VERSION;

    return ident.str();
}

#ifdef _ND_USE_WATCHDOGS
int nd_touch(const string &filename)
{
    int fd;
    struct timespec now[2];

    fd = open(filename.c_str(), O_WRONLY | O_CREAT | O_NONBLOCK | O_NOCTTY,
        S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);

    if (fd < 0) return fd;

    clock_gettime(CLOCK_REALTIME, &now[0]);
    clock_gettime(CLOCK_REALTIME, &now[1]);

    if (futimens(fd, now) < 0) return -1;

    close(fd);

    return 0;
}
#endif

void nd_file_save(const string &filename,
    const string &data, bool append, mode_t mode, const char *user, const char *group)
{
    int fd = open(filename.c_str(), O_WRONLY);
    struct passwd *owner_user = NULL;
    struct group *owner_group = NULL;

    if (fd < 0) {
        if (errno != ENOENT)
            throw runtime_error(strerror(errno));
        fd = open(filename.c_str(), O_WRONLY | O_CREAT, mode);
        if (fd < 0)
            throw runtime_error(strerror(errno));

        if (user != NULL) {
            owner_user = getpwnam(user);
            if (owner_user == NULL)
                throw runtime_error(strerror(errno));
        }

        if (group != NULL) {
            owner_group = getgrnam(group);
            if (owner_group == NULL)
                throw runtime_error(strerror(errno));
        }

        if (fchown(fd,
            (owner_user != NULL) ? owner_user->pw_uid : -1,
            (owner_group != NULL) ? owner_group->gr_gid : -1) < 0)
            throw runtime_error(strerror(errno));
    }

    if (flock(fd, LOCK_EX) < 0)
        throw runtime_error(strerror(errno));

    if (lseek(fd, 0, (! append) ? SEEK_SET: SEEK_END) < 0)
        throw runtime_error(strerror(errno));

    if (! append && ftruncate(fd, 0) < 0)
        throw runtime_error(strerror(errno));

    if (write(fd, (const void *)data.c_str(), data.length()) < 0)
        throw runtime_error(strerror(errno));

    flock(fd, LOCK_UN);
    close(fd);
}

int nd_save_response_data(const char *filename, const ndJsonDataChunks &data)
{
    try {
        int chunks = 0;
        for (ndJsonDataChunks::const_iterator i = data.begin(); i != data.end(); i++)
            nd_file_save(filename, (*i), (0 != chunks++));
    }
    catch (runtime_error &e) {
        nd_printf("Error saving file: %s: %s\n", filename, e.what());
        return -1;
    }

    return 0;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
