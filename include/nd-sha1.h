/* Declarations of functions and data types used for SHA1 sum
   library functions.
   Copyright (C) 2000-2001, 2003, 2005-2006, 2008-2017 Free Software
   Foundation, Inc.

   This program is free software; you can redistribute it and/or modify it
   under the terms of the GNU General Public License as published by the
   Free Software Foundation; either version 3, or (at your option) any
   later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <https://www.gnu.org/licenses/>.  */

#ifndef _SHA1_H
#define _SHA1_H

#ifdef  __cplusplus
extern "C" {
#endif

#define SHA1_DIGEST_LENGTH  20

/* Structure to save state of computation between the single steps.  */
typedef struct sha1_t
{
    uint32_t A, B, C, D, E;

    uint32_t total[2];
    uint32_t buflen;     /* ≥ 0, ≤ 128 */
    uint32_t buffer[32]; /* 128 bytes; the first buflen bytes are in use */
} sha1;

/* Initialize structure containing state of computation. */
extern void sha1_init(sha1 *ctx);

/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is necessary that LEN is a multiple of 64!!! */
extern void sha1_write_block(sha1 *ctx, const void *buffer, size_t len);

/* Starting with the result of former calls of this function (or the
   initialization function update the context for the next LEN bytes
   starting at BUFFER.
   It is NOT required that LEN is a multiple of 64.  */
extern void sha1_write(sha1 *ctx, const void *buffer, size_t len);

/* Put result from CTX in first 20 bytes following RESBUF.  The result is
   always in little endian byte order, so that a byte-wise output yields
   to the wanted ASCII representation of the message digest.  */
extern void *sha1_read(const sha1 *ctx, void *resbuf);

/* Process the remaining bytes in the buffer and put result from CTX
   in first 20 bytes following RESBUF.  The result is always in little
   endian byte order, so that a byte-wise output yields to the wanted
   ASCII representation of the message digest.  */
extern void *sha1_result(sha1 *ctx, void *resbuf);

#ifdef  __cplusplus
}
#endif
#endif // _SHA1_H

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
