/**
 * @file sipe-tls.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011 SIPE Project <http://sipe.sourceforge.net/>
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 *
 * TLS Protocol Version 1.0/1.1 - Handshake Messages
 *
 * TLS-DSK uses the handshake messages during authentication and session key
 * exchange. This module *ONLY* implements this part of the TLS specification!
 *
 * Specification references:
 *
 *   - RFC2246: http://www.ietf.org/rfc/rfc2246.txt
 *   - RFC3546: http://www.ietf.org/rfc/rfc3546.txt
 *   - RFC4346: http://www.ietf.org/rfc/rfc4346.txt
 */

#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "sipe-cert-crypto.h"
#include "sipe-tls.h"

static const guchar const client_hello[] = {

#if 0
/* Extracted from log file */
	/* TLS Record */
	0x16,                   /* ContenType: handshake(22)        */
	0x03, 0x01,             /* ProtocolVersion: 3.1 (= TLS 1.0) */
	0x00, 0x48,             /* length: 72 bytes                 */
	/* TLS Record fragment -> 72 bytes                          */
	/* Handshake (header)                                       */
	0x01,                   /* msg_type: client_hello(1)        */
	0x00, 0x00, 0x44,       /* length: 68 bytes                 */
	/* Handshake (body)                                         */
	/* ClientHello                                              */
	0x03, 0x01,             /* ProtocolVersion: 3.1 (= TLS 1.0) */
	                        /* Random: (32 bytes)               */
	0x4e, 0x81, 0xa7, 0x63, /*  uint32 gmt_unix_time            */
	0x15, 0xfd, 0x06, 0x46, /*  random_bytes[28]                */
	0x0a, 0xb2, 0xdf, 0xf0,
	0x85, 0x14, 0xac, 0x60,
	0x7e, 0xda, 0x48, 0x3c,
	0xb2, 0xad, 0x5b, 0x0f,
	0xf3, 0xe4, 0x4e, 0x5d,
	0x4b, 0x9f, 0x8e, 0xd6,
	                        /* session_id: (0..32 bytes)        */
	0x00,                   /* = 0 -> no SessionID              */
                                /* cipher_suites: (2..2^16-1 bytes) */
        0x00, 0x16,             /* = 22 bytes -> 11 CipherSuites    */
	0x00, 0x04,             /* TLS_RSA_WITH_RC4_128_MD5         */
	0x00, 0x05,             /* TLS_RSA_WITH_RC4_128_SHA         */
	0x00, 0x0a,             /* TLS_RSA_WITH_3DES_EDE_CBC_SHA    */
	0x00, 0x09,             /* TLS_RSA_WITH_DES_CBC_SHA         */
	0x00, 0x64,             /* NON-STANDARD */
	0x00, 0x62,             /* NON-STANDARD */
	0x00, 0x03,             /* TLS_RSA_EXPORT_WITH_RC4_40_MD5  */
	0x00, 0x06,             /* TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5 */
	0x00, 0x13,             /* TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA */
	0x00, 0x12,             /* TLS_DHE_DSS_WITH_DES_CBC_SHA    */
	0x00, 0x63,             /* NON-STANDARD */
	                        /* compr_methods: (1..2^8-1 bytes) */
        0x01,                   /* = 1 byte -> 1 CompressionMethod */
        0x00,                   /* null(0)                         */
        /* TLS Extended Client Hello (RFC3546) */
	                        /* extensions: (0..2^16-1)         */
	0x00, 0x05,             /* = 5 bytes                       */
        0xff, 0x01,             /* ExtensionType: (= 0xFF01)       */
                                /* extension_data: (0..2^16-1 byt) */
        0x00, 0x01,             /* = 1 byte                        */
	0x00
#else
	/* TLS Record */
	0x16,                   /* ContenType: handshake(22)        */
	0x03, 0x01,             /* ProtocolVersion: 3.1 (= TLS 1.0) */
	0x00, 0x31,             /* length: 49 bytes                 */
	/* TLS Record fragment -> 72 bytes                          */
	/* Handshake (header)                                       */
	0x01,                   /* msg_type: client_hello(1)        */
	0x00, 0x00, 0x2d,       /* length: 45 bytes                 */
	/* Handshake (body)                                         */
	/* ClientHello                                              */
	0x03, 0x01,             /* ProtocolVersion: 3.1 (= TLS 1.0) */
	                        /* Random: (32 bytes)               */
#define GMT_OFFSET 11
	0x4e, 0x81, 0xa7, 0x63, /*  uint32 gmt_unix_time            */
#define RANDOM_OFFSET 15
	0x15, 0xfd, 0x06, 0x46, /*  random_bytes[28]                */
	0x0a, 0xb2, 0xdf, 0xf0,
	0x85, 0x14, 0xac, 0x60,
	0x7e, 0xda, 0x48, 0x3c,
	0xb2, 0xad, 0x5b, 0x0f,
	0xf3, 0xe4, 0x4e, 0x5d,
	0x4b, 0x9f, 0x8e, 0xd6,
	                        /* session_id: (0..32 bytes)        */
	0x00,                   /* = 0 -> no SessionID              */
                                /* cipher_suites: (2..2^16-1 bytes) */
        0x00, 0x06,             /* = 6 bytes ->  3 CipherSuites     */
	0x00, 0x04,             /* TLS_RSA_WITH_RC4_128_MD5         */
	0x00, 0x05,             /* TLS_RSA_WITH_RC4_128_SHA         */
	0x00, 0x03,             /* TLS_RSA_EXPORT_WITH_RC4_40_MD5  */
	                        /* compr_methods: (1..2^8-1 bytes) */
        0x01,                   /* = 1 byte -> 1 CompressionMethod */
        0x00                    /* null(0)                         */
#endif
};

guchar *sipe_tls_client_hello(gsize *length)
{
	guchar *msg = g_memdup(client_hello, sizeof(client_hello));
	guint32 now = time(NULL);
	guint32 now_N = GUINT32_TO_BE(now);
	guchar *p;
	guint i;

	memcpy(msg + GMT_OFFSET, &now_N, sizeof(now_N));
	for (p = msg + RANDOM_OFFSET, i = 0; i < 2; i++)
		*p++ = rand() & 0xFF;

	*length = sizeof(client_hello);
	return(msg);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
