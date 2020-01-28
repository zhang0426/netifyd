// Netify Agent
// Copyright (C) 2015-2020 eGloo Incorporated <http://www.egloo.ca>
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

#ifndef _ND_NDPI_H
#define _ND_NDPI_H

#include <ndpi_api.h>

void ndpi_global_init(void);
void ndpi_global_destroy(void);

struct ndpi_detection_module_struct *nd_ndpi_init(
    const string &tag, uint32_t &custom_proto_base);

void nd_ndpi_free(struct ndpi_detection_module_struct *ndpi);

struct ndpi_detection_module_struct *ndpi_get_parent(void);

#endif // _ND_NDPI_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
