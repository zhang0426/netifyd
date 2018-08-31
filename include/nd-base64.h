/*
* Base64 encoding/decoding (RFC1341)
* Copyright (c) 2005-2011, Jouni Malinen <j@w1.fi>
*
* This software may be distributed under the terms of the BSD license.
* See README for more details.
*/

// 2016-12-12 - Gaspard Petit : Slightly modified to return a std::string
// instead of a buffer allocated with malloc.

#ifndef _ND_BASE64_H
#define _ND_BASE64_H

string base64_encode(const unsigned char *src, size_t len);

string base64_decode(const void* data, const size_t len);

#endif // _ND_BASE64_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
