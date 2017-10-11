// Netify Daemon
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

#ifndef _ND_UTIL_H
#define _ND_UTIL_H

#define ND_SHA1_BUFFER    4096

#ifdef _ND_USE_NCURSES
#include <ncurses.h>
#endif

void *nd_mem_alloc(size_t size);

void nd_mem_free(void *ptr);

void nd_printf(const char *format, ...);
#ifdef _ND_USE_NCURSES
void nd_printw(WINDOW *win, const char *format, ...);

void nd_printf_lock(void);
void nd_printf_unlock(void);
#endif
void nd_debug_printf(const char *format, ...);
void nd_verbose_printf(const char *format, ...);

void ndpi_debug_printf(
    unsigned int i, void *p, ndpi_log_level_t l, const char *format, ...);

void nd_print_address(const struct sockaddr_storage *addr);

void nd_print_binary(uint32_t byte);

void nd_print_number(ostringstream &os, uint64_t value, bool units_binary = true);

int nd_sha1_file(const string &filename, uint8_t *digest);

void nd_sha1_to_string(const uint8_t *digest_bin, string &digest_str);

class ndException : public runtime_error
{
public:
    explicit ndException(
        const string &where_arg, const string &what_arg) throw();
    virtual ~ndException() throw();

    virtual const char *what() const throw();

    string where_arg;
    string what_arg;
    const char *message;
};

class ndSystemException : public runtime_error
{
public:
    explicit ndSystemException(
        const string &where_arg, const string &what_arg, int why_arg) throw();
    virtual ~ndSystemException() throw();

    virtual const char *what() const throw();

    string where_arg;
    string what_arg;
    int why_arg;
    const char *message;
};

#endif // _ND_UTIL_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
