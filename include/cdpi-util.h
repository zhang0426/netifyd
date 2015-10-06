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

#ifndef _CDPI_UTIL_H
#define _CDPI_UTIL_H

void *cdpi_mem_alloc(unsigned long size);

void cdpi_mem_free(void *ptr);

void cdpi_printf(const char *format, ...);

void cdpi_debug_printf(
    unsigned int i, void *p, ndpi_log_level_t l, const char *format, ...);

void cdpi_sha1_to_string(const uint8_t *digest_bin, string &digest_str);

#endif // _CDPI_UTIL_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
