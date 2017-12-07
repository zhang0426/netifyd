// Netify Agent
// Copyright (C) 2015-2017 eGloo Incorporated <http://www.egloo.ca>
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
#include <unordered_map>

#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/socket.h>

#include <arpa/inet.h>
#include <netdb.h>

#include "ndpi_main.h"

using namespace std;

#include "netifyd.h"
#include "nd-util.h"
#include "nd-sha1.h"

extern nd_global_config nd_config;

#ifdef _ND_USE_NCURSES
extern WINDOW *win_output;
#endif

void *nd_mem_alloc(size_t size)
{
    return malloc(size);
}

void nd_mem_free(void *ptr)
{
    free(ptr);
}

extern pthread_mutex_t *nd_printf_mutex;
#ifdef _ND_USE_NCURSES
void nd_printf_lock(void)
{
    pthread_mutex_lock(nd_printf_mutex);
}

void nd_printf_unlock(void)
{
    pthread_mutex_unlock(nd_printf_mutex);
}
#endif
void nd_printf(const char *format, ...)
{
    pthread_mutex_lock(nd_printf_mutex);

    va_list ap;
    va_start(ap, format);

    if (ND_DEBUG) {
#ifndef _ND_USE_NCURSES
        vfprintf(stdout, format, ap);
#else
        if (! ND_USE_NCURSES || win_output == NULL)
            vfprintf(stdout, format, ap);
        else {
            vwprintw(win_output, format, ap);
            wrefresh(win_output);
        }
#endif
    }
    else
        vsyslog(LOG_DAEMON | LOG_INFO, format, ap);

    va_end(ap);

    pthread_mutex_unlock(nd_printf_mutex);
}

#ifdef _ND_USE_NCURSES
void nd_printw(WINDOW *win, const char *format, ...)
{
    if (ND_DEBUG) {
        pthread_mutex_lock(nd_printf_mutex);

        va_list ap;
        va_start(ap, format);
        vwprintw(win, format, ap);
        wrefresh(win);
        va_end(ap);

        pthread_mutex_unlock(nd_printf_mutex);
    }
}
#endif

void nd_debug_printf(const char *format, ...)
{
    if (ND_DEBUG) {

        pthread_mutex_lock(nd_printf_mutex);

        va_list ap;
        va_start(ap, format);
#ifndef _ND_USE_NCURSES
        vfprintf(stderr, format, ap);
#else
        if (! ND_USE_NCURSES)
            vfprintf(stderr, format, ap);
        else {
            vwprintw(win_output, format, ap);
            wrefresh(win_output);
        }
#endif
        va_end(ap);

        pthread_mutex_unlock(nd_printf_mutex);
    }
}

void nd_verbose_printf(const char *format, ...)
{
    if (ND_VERBOSE) {

        pthread_mutex_lock(nd_printf_mutex);

        va_list ap;
        va_start(ap, format);
#ifndef _ND_USE_NCURSES
        vfprintf(stderr, format, ap);
#else
        if (! ND_USE_NCURSES)
            vfprintf(stderr, format, ap);
        else {
            vwprintw(win_output, format, ap);
            wrefresh(win_output);
        }
#endif
        va_end(ap);

        pthread_mutex_unlock(nd_printf_mutex);
    }
}

void ndpi_debug_printf(
    unsigned int i, void *p, ndpi_log_level_t l, const char *format, ...)
{
    if (ND_DEBUG) {

        pthread_mutex_lock(nd_printf_mutex);

        va_list ap;
        va_start(ap, format);
#ifndef _ND_USE_NCURSES
        vfprintf(stderr, format, ap);
#else
        vwprintw(win_output, format, ap);
        wrefresh(win_output);
#endif
        va_end(ap);

        pthread_mutex_unlock(nd_printf_mutex);
    }
}

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
        nd_printf("(unsupported AF:%x)", addr->ss_family);
        return;
    }

    if (rc == 0)
        nd_printf(_addr);
    else
        nd_printf("???");
}

void nd_print_binary(uint32_t byte)
{
    uint32_t i;
    char b[sizeof(byte) * 8 + 1];

    b[0] = '\0';
    for (i = 0x80000000; i > 0; i >>= 1)
        strcat(b, ((byte & i) == i) ? "1" : "0");

    nd_printf(b);
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
    uint8_t buffer[ND_SHA1_BUFFER];
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
    memcpy(digest, sha1_result(&ctx), SHA1_DIGEST_LENGTH);

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

    if (inet_pton(AF_INET, ip, &addr4) == 0) return true;
    return (inet_pton(AF_INET6, ip, &addr6) == 0) ? true : false;
}

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

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
