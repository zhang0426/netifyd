/*
 * Copyright (c) 2004 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (c) 1996,1999 by Internet Software Consortium.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
 * OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/* Import. */

#include <sys/types.h>

#include <netinet/in.h>
#include <arpa/nameser.h>

#include <errno.h>
#include <resolv.h>
#include <string.h>

#define NS_TYPE_ELT         0x40 /*%< EDNS0 extended label type */
#define DNS_LABELTYPE_BITSTRING     0x41
# define SPRINTF(x) ((size_t)sprintf x)
#define __set_errno(e) (errno = (e))

static const char	digits[] = "0123456789";

/* Forward. */

static void	setsection(ns_msg *msg, ns_sect sect);

/*%
 *	Thinking in noninternationalized USASCII (per the DNS spec),
 *	is this character visible and not a space when printed ?
 *
 * return:
 *\li	boolean.
 */
static int
printable(int ch) {
	return (ch > 0x20 && ch < 0x7f);
}

static int
decode_bitstring(const unsigned char **cpp, char *dn, const char *eom)
{
	const unsigned char *cp = *cpp;
	char *beg = dn, tc;
	int b, blen, plen, i;

	if ((blen = (*cp & 0xff)) == 0)
		blen = 256;
	plen = (blen + 3) / 4;
	plen += sizeof("\\[x/]") + (blen > 99 ? 3 : (blen > 9) ? 2 : 1);
	if (dn + plen >= eom)
		return(-1);

	cp++;
	i = SPRINTF((dn, "\\[x"));
	if (i < 0)
		return (-1);
	dn += i;
	for (b = blen; b > 7; b -= 8, cp++) {
		i = SPRINTF((dn, "%02x", *cp & 0xff));
		if (i < 0)
			return (-1);
		dn += i;
	}
	if (b > 4) {
		tc = *cp++;
		i = SPRINTF((dn, "%02x", tc & (0xff << (8 - b))));
		if (i < 0)
			return (-1);
		dn += i;
	} else if (b > 0) {
		tc = *cp++;
		i = SPRINTF((dn, "%1x",
			       ((tc >> 4) & 0x0f) & (0x0f << (4 - b))));
		if (i < 0)
			return (-1);
		dn += i;
	}
	i = SPRINTF((dn, "/%d]", blen));
	if (i < 0)
		return (-1);
	dn += i;

	*cpp = cp;
	return(dn - beg);
}

/*%
 *	Thinking in noninternationalized USASCII (per the DNS spec),
 *	is this characted special ("in need of quoting") ?
 *
 * return:
 *\li	boolean.
 */
static int
special(int ch) {
	switch (ch) {
	case 0x22: /*%< '"' */
	case 0x2E: /*%< '.' */
	case 0x3B: /*%< ';' */
	case 0x5C: /*%< '\\' */
	case 0x28: /*%< '(' */
	case 0x29: /*%< ')' */
	/* Special modifiers in zone files. */
	case 0x40: /*%< '@' */
	case 0x24: /*%< '$' */
		return (1);
	default:
		return (0);
	}
}
/* Macros. */

#define RETERR(err) do { __set_errno (err); fprintf(stderr, "%d: Error: %s [%d]\n", __LINE__, strerror(err), err); return (-1); } while (0)

/* Public. */

/* These need to be in the same order as the nres.h:ns_flag enum. */
const struct _ns_flagdata _ns_flagdata[16] = {
	{ 0x8000, 15 },		/*%< qr. */
	{ 0x7800, 11 },		/*%< opcode. */
	{ 0x0400, 10 },		/*%< aa. */
	{ 0x0200, 9 },		/*%< tc. */
	{ 0x0100, 8 },		/*%< rd. */
	{ 0x0080, 7 },		/*%< ra. */
	{ 0x0040, 6 },		/*%< z. */
	{ 0x0020, 5 },		/*%< ad. */
	{ 0x0010, 4 },		/*%< cd. */
	{ 0x000f, 0 },		/*%< rcode. */
	{ 0x0000, 0 },		/*%< expansion (1/6). */
	{ 0x0000, 0 },		/*%< expansion (2/6). */
	{ 0x0000, 0 },		/*%< expansion (3/6). */
	{ 0x0000, 0 },		/*%< expansion (4/6). */
	{ 0x0000, 0 },		/*%< expansion (5/6). */
	{ 0x0000, 0 },		/*%< expansion (6/6). */
};

static int
labellen(const u_char *lp)
{
    int bitlen;
    u_char l = *lp;

    if ((l & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
        /* should be avoided by the caller */
        return(-1);
    }

    if ((l & NS_CMPRSFLGS) == NS_TYPE_ELT) {
        if (l == DNS_LABELTYPE_BITSTRING) {
            if ((bitlen = *(lp + 1)) == 0)
                bitlen = 256;
            return((bitlen + 7 ) / 8 + 1);
        }
        return(-1); /*%< unknwon ELT */
    }
    return(l);
}

/*%
 *	Unpack a domain name from a message, source may be compressed.
 *
 * return:
 *\li	-1 if it fails, or consumed octets if it succeeds.
 */
int
ns_name_unpack(const u_char *msg, const u_char *eom, const u_char *src,
	       u_char *dst, size_t dstsiz)
{
	const u_char *srcp, *dstlim;
	u_char *dstp;
	int n, len, checked, l;

	len = -1;
	checked = 0;
	dstp = dst;
	srcp = src;
	dstlim = dst + dstsiz;
	if (srcp < msg || srcp >= eom) {
		__set_errno (EMSGSIZE);
		return (-1);
	}
	/* Fetch next label in domain name. */
	while ((n = *srcp++) != 0) {
		/* Check for indirection. */
		switch (n & NS_CMPRSFLGS) {
		case 0:
		case NS_TYPE_ELT:
			/* Limit checks. */
			if ((l = labellen(srcp - 1)) < 0) {
				__set_errno (EMSGSIZE);
				return(-1);
			}
			if (dstp + l + 1 >= dstlim || srcp + l >= eom) {
				__set_errno (EMSGSIZE);
				return (-1);
			}
			checked += l + 1;
			*dstp++ = n;
			memcpy(dstp, srcp, l);
			dstp += l;
			srcp += l;
			break;

		case NS_CMPRSFLGS:
			if (srcp >= eom) {
				__set_errno (EMSGSIZE);
				return (-1);
			}
			if (len < 0)
				len = srcp - src + 1;
			srcp = msg + (((n & 0x3f) << 8) | (*srcp & 0xff));
			if (srcp < msg || srcp >= eom) {  /*%< Out of range. */
				__set_errno (EMSGSIZE);
				return (-1);
			}
			checked += 2;
			/*
			 * Check for loops in the compressed name;
			 * if we've looked at the whole message,
			 * there must be a loop.
			 */
			if (checked >= eom - msg) {
				__set_errno (EMSGSIZE);
				return (-1);
			}
			break;

		default:
			__set_errno (EMSGSIZE);
			return (-1);			/*%< flag error */
		}
	}
	*dstp = '\0';
	if (len < 0)
		len = srcp - src;
	return (len);
}

/*%
 *	Convert an encoded domain name to printable ascii as per RFC1035.

 * return:
 *\li	Number of bytes written to buffer, or -1 (with errno set)
 *
 * notes:
 *\li	The root is returned as "."
 *\li	All other domains are returned in non absolute form
 */
int
ns_name_ntop(const u_char *src, char *dst, size_t dstsiz)
{
	const u_char *cp;
	char *dn, *eom;
	u_char c;
	u_int n;
	int l;

	cp = src;
	dn = dst;
	eom = dst + dstsiz;

	while ((n = *cp++) != 0) {
		if ((n & NS_CMPRSFLGS) == NS_CMPRSFLGS) {
			/* Some kind of compression pointer. */
			__set_errno (EMSGSIZE);
			return (-1);
		}
		if (dn != dst) {
			if (dn >= eom) {
				__set_errno (EMSGSIZE);
				return (-1);
			}
			*dn++ = '.';
		}
		if ((l = labellen(cp - 1)) < 0) {
			__set_errno (EMSGSIZE);
			return(-1);
		}
		if (dn + l >= eom) {
			__set_errno (EMSGSIZE);
			return (-1);
		}
		if ((n & NS_CMPRSFLGS) == NS_TYPE_ELT) {
			int m;

			if (n != DNS_LABELTYPE_BITSTRING) {
				/* XXX: labellen should reject this case */
				__set_errno (EINVAL);
				return(-1);
			}
			if ((m = decode_bitstring(&cp, dn, eom)) < 0)
			{
				__set_errno (EMSGSIZE);
				return(-1);
			}
			dn += m;
			continue;
		}
		for ((void)NULL; l > 0; l--) {
			c = *cp++;
			if (special(c)) {
				if (dn + 1 >= eom) {
					__set_errno (EMSGSIZE);
					return (-1);
				}
				*dn++ = '\\';
				*dn++ = (char)c;
			} else if (!printable(c)) {
				if (dn + 3 >= eom) {
					__set_errno (EMSGSIZE);
					return (-1);
				}
				*dn++ = '\\';
				*dn++ = digits[c / 100];
				*dn++ = digits[(c % 100) / 10];
				*dn++ = digits[c % 10];
			} else {
				if (dn >= eom) {
					__set_errno (EMSGSIZE);
					return (-1);
				}
				*dn++ = (char)c;
			}
		}
	}
	if (dn == dst) {
		if (dn >= eom) {
			__set_errno (EMSGSIZE);
			return (-1);
		}
		*dn++ = '.';
	}
	if (dn >= eom) {
		__set_errno (EMSGSIZE);
		return (-1);
	}
	*dn++ = '\0';
	return (dn - dst);
}

/*%
 *  Expand compressed domain name to presentation format.
 *
 * return:
 *\li   Number of bytes read out of `src', or -1 (with errno set).
 *
 * note:
 *\li   Root domain returns as "." not "".
 */
int
ns_name_uncompress(const u_char *msg, const u_char *eom, const u_char *src,
           char *dst, size_t dstsiz)
{
    u_char tmp[NS_MAXCDNAME];
    int n;

    if ((n = ns_name_unpack(msg, eom, src, tmp, sizeof tmp)) == -1)
        return (-1);
    if (ns_name_ntop(tmp, dst, dstsiz) == -1)
        return (-1);
    return (n);
}

/*
 * Expand compressed domain name 'comp_dn' to full domain name.
 * 'msg' is a pointer to the begining of the message,
 * 'eomorig' points to the first location after the message,
 * 'exp_dn' is a pointer to a buffer of size 'length' for the result.
 * Return size of compressed name or -1 if there was an error.
 */
int
dn_expand(const u_char *msg, const u_char *eom, const u_char *src,
      char *dst, int dstsiz)
{
    int n = ns_name_uncompress(msg, eom, src, dst, (size_t)dstsiz);

    if (n > 0 && dst[0] == '.')
        dst[0] = '\0';
    return (n);
}

/*%
 *  Advance *ptrptr to skip over the compressed name it points at.
 *
 * return:
 *\li   0 on success, -1 (with errno set) on failure.
 */
int
ns_name_skip(const u_char **ptrptr, const u_char *eom)
{
    const u_char *cp;
    u_int n;
    int l;

    cp = *ptrptr;
    while (cp < eom && (n = *cp++) != 0) {
        /* Check for indirection. */
        switch (n & NS_CMPRSFLGS) {
        case 0:         /*%< normal case, n == len */
            cp += n;
            continue;
        case NS_TYPE_ELT: /*%< EDNS0 extended label */
            if ((l = labellen(cp - 1)) < 0) {
                __set_errno (EMSGSIZE);
                return(-1);
            }
            cp += l;
            continue;
        case NS_CMPRSFLGS:  /*%< indirection */
            cp++;
            break;
        default:        /*%< illegal type */
            __set_errno (EMSGSIZE);
            return (-1);
        }
        break;
    }
    if (cp > eom) {
        __set_errno (EMSGSIZE);
        return (-1);
    }
    *ptrptr = cp;
    return (0);
}

/*
 *  * Skip over a compressed domain name. Return the size or -1.
 *   */
int
dn_skipname(const u_char *ptr, const u_char *eom) {
    const u_char *saveptr = ptr;

    if (ns_name_skip(&ptr, eom) == -1)
        return (-1);
    return (ptr - saveptr);
}

#undef ns_msg_getflag
int ns_msg_getflag(ns_msg handle, int flag) {
	return(((handle)._flags & _ns_flagdata[flag].mask) >> _ns_flagdata[flag].shift);
}

int
ns_skiprr(const u_char *ptr, const u_char *eom, ns_sect section, int count) {
	const u_char *optr = ptr;

	for ((void)NULL; count > 0; count--) {
		int b, rdlength;

		b = dn_skipname(ptr, eom);
		if (b < 0)
			RETERR(EMSGSIZE);
		ptr += b/*Name*/ + NS_INT16SZ/*Type*/ + NS_INT16SZ/*Class*/;
		if (section != ns_s_qd) {
			if (ptr + NS_INT32SZ + NS_INT16SZ > eom)
				RETERR(EMSGSIZE);
			ptr += NS_INT32SZ/*TTL*/;
			NS_GET16(rdlength, ptr);
			ptr += rdlength/*RData*/;
		}
	}
	if (ptr > eom)
		RETERR(EMSGSIZE);
	return (ptr - optr);
}

int
ns_initparse(const u_char *msg, int msglen, ns_msg *handle) {
	const u_char *eom = msg + msglen;
	int i;

	memset(handle, 0x5e, sizeof *handle);
	handle->_msg = msg;
	handle->_eom = eom;
	if (msg + NS_INT16SZ > eom)
		RETERR(EMSGSIZE);
	NS_GET16(handle->_id, msg);
	if (msg + NS_INT16SZ > eom)
		RETERR(EMSGSIZE);
	NS_GET16(handle->_flags, msg);
	for (i = 0; i < ns_s_max; i++) {
		if (msg + NS_INT16SZ > eom)
			RETERR(EMSGSIZE);
		NS_GET16(handle->_counts[i], msg);
	}
	for (i = 0; i < ns_s_max; i++)
		if (handle->_counts[i] == 0)
			handle->_sections[i] = NULL;
		else {
			int b = ns_skiprr(msg, eom, (ns_sect)i,
					  handle->_counts[i]);

			if (b < 0)
				return (-1);
			handle->_sections[i] = msg;
			msg += b;
		}
	if (msg != eom)
		RETERR(EMSGSIZE);
	setsection(handle, ns_s_max);
	return (0);
}

/* Private. */

static void
setsection(ns_msg *msg, ns_sect sect) {
	msg->_sect = sect;
	if (sect == ns_s_max) {
		msg->_rrnum = -1;
		msg->_msg_ptr = NULL;
	} else {
		msg->_rrnum = 0;
		msg->_msg_ptr = msg->_sections[(int)sect];
	}
}

/*! \file */
