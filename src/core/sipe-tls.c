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
#include <stdarg.h>

#include <glib.h>

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-cert-crypto.h"
#include "sipe-tls.h"

/*
 * Private part of TLS state tracking
 */
enum tls_handshake_state {
	TLS_HANDSHAKE_STATE_START,
	TLS_HANDSHAKE_STATE_SERVER_HELLO,
	TLS_HANDSHAKE_STATE_FINISHED,
	TLS_HANDSHAKE_STATE_COMPLETED,
	TLS_HANDSHAKE_STATE_FAILED
};

struct tls_internal_state {
	struct sipe_tls_state common;
	gpointer certificate;
	enum tls_handshake_state state;
};

/*
 * TLS message debugging
 */
static void debug_hex(GString *str,
		      const guchar *bytes,
		      gsize length)
{
	gint count = -1;

	if (!str) return;

	while (length-- > 0) {
		if (++count == 0) {
			/* do nothing */;
		} else if ((count % 16) == 0) {
			g_string_append(str, "\n");
		} else if ((count %  8) == 0) {
			g_string_append(str, "  ");
		}
		g_string_append_printf(str, " %02X", *bytes++);
	}
	g_string_append(str, "\n");
}

static void debug_print(GString *str,
			const gchar *string)
{
	if (str)
		g_string_append(str, string);
}

static void debug_printf(GString *str,
			 const gchar *format,
			 ...) G_GNUC_PRINTF(2, 3);
static void debug_printf(GString *str,
			 const gchar *format,
			 ...)
{
	va_list ap;

	if (!str) return;

	va_start(ap, format);
	g_string_append_vprintf(str, format, ap);
	va_end(ap);
}


/*
 * TLS message parsing
 */
struct parse_descriptor {
	int temporary;
};

struct msg_descriptor {
	guint type;
	const gchar *description;
	const struct parse_descriptor *parse;
};

static void free_parsed_data(gpointer parsed_data)
{
	if (!parsed_data)
		return;
}

static gpointer generic_parser(const guchar *bytes,
			       gsize length,
			       gboolean incoming,
			       GString *str,
			       const struct parse_descriptor *desc,
			       gpointer parsed_data)
{
	/* temporary */
	debug_hex(str, bytes, length);
	(void)parsed_data;
	(void)incoming;
	(void)desc;
	return(NULL);
}

#define TLS_HANDSHAKE_HEADER_LENGTH           4
#define TLS_HANDSHAKE_OFFSET_TYPE             0
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO       1
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO       2
#define TLS_HANDSHAKE_TYPE_CERTIFICATE       11
#define TLS_HANDSHAKE_TYPE_CERTIFICATE_REQ   13
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE 14
#define TLS_HANDSHAKE_OFFSET_LENGTH           1

static gpointer handshake_parse(const guchar *bytes,
				gsize length,
				gboolean incoming,
				GString *str)
{
	static const struct msg_descriptor const handshake_descriptors[] = {
		{ TLS_HANDSHAKE_TYPE_CLIENT_HELLO,      "Client Hello",        NULL},
		{ TLS_HANDSHAKE_TYPE_SERVER_HELLO,      "Server Hello",        NULL},
		{ TLS_HANDSHAKE_TYPE_CERTIFICATE,       "Certificate",         NULL},
		{ TLS_HANDSHAKE_TYPE_CERTIFICATE_REQ,   "Certificate Request", NULL},
		{ TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE, "Server Hello Done",   NULL}
	};
#define HANDSHAKE_DESCRIPTORS (sizeof(handshake_descriptors)/sizeof(struct msg_descriptor))

	gpointer parsed_data = NULL;
	gboolean success = FALSE;

	while (length > 0) {
		const struct msg_descriptor *desc;
		gsize msg_length;
		guint i, msg_type;

		/* header check */
		if (length < TLS_HANDSHAKE_HEADER_LENGTH) {
			debug_print(str, "CORRUPTED HANDSHAKE HEADER");
			break;
		}

 		/* msg length check */
		msg_length = (bytes[TLS_HANDSHAKE_OFFSET_LENGTH]     << 16) +
			     (bytes[TLS_HANDSHAKE_OFFSET_LENGTH + 1] <<  8) +
			      bytes[TLS_HANDSHAKE_OFFSET_LENGTH + 2];
		if (msg_length > length) {
			debug_print(str, "HANDSHAKE MESSAGE TOO LONG");
			break;
		}

		/* msg type */
		msg_type = bytes[TLS_HANDSHAKE_OFFSET_TYPE];
		for (desc = handshake_descriptors, i = 0;
		     i < HANDSHAKE_DESCRIPTORS;
		     desc++, i++) {
			if (msg_type == desc->type)
				break;
		}

		debug_printf(str, "TLS handshake (%" G_GSIZE_FORMAT " bytes) (%d)",
			     msg_length, msg_type);

		length -= TLS_HANDSHAKE_HEADER_LENGTH;
		bytes  += TLS_HANDSHAKE_HEADER_LENGTH;

		if (i < HANDSHAKE_DESCRIPTORS) {
			debug_printf(str, "%s\n", desc->description);
			parsed_data = generic_parser(bytes,
						     msg_length,
						     incoming,
						     str,
						     desc->parse,
						     parsed_data);
			/* temporary */
#if 0
			if (!parsed_data)
				break;
#endif
		} else {
			debug_print(str, "ignored\n");
			debug_hex(str, bytes, msg_length);
		}

		/* next message */
		length -= msg_length;
		bytes  += msg_length;
		if (length > 0) {
			debug_print(str, "------\n");
		} else {
			success = TRUE;
		}
	}

	if (!success) {
		free_parsed_data(parsed_data);
		parsed_data = NULL;
	}

	return(parsed_data);
}

#define TLS_RECORD_HEADER_LENGTH   5
#define TLS_RECORD_OFFSET_TYPE     0
#define TLS_RECORD_TYPE_HANDSHAKE 22
#define TLS_RECORD_OFFSET_MAJOR    1
#define TLS_RECORD_OFFSET_MINOR    2
#define TLS_RECORD_OFFSET_LENGTH   3

/* NOTE: we don't support record fragmentation */
static gpointer tls_record_parse(const guchar *bytes,
				 gsize length,
				 gboolean incoming)
{
	gpointer parsed_data = NULL;
	GString *str         = NULL;
	const gchar *version = NULL;
	guchar major;
	guchar minor;
	gsize record_length;
	guint content_type;

	if (sipe_backend_debug_enabled()) {
		str = g_string_new("");
		debug_printf(str, "TLS MESSAGE %s\n",
			     incoming ? "INCOMING" : "OUTGOING");
	}

	/* truncated header check */
	if (length < TLS_RECORD_HEADER_LENGTH) {
		SIPE_DEBUG_ERROR("tls_record_parse: too short TLS record header (%" G_GSIZE_FORMAT " bytes)",
				 length);
		return(NULL);
	}

	/* protocol version check */
	major = bytes[TLS_RECORD_OFFSET_MAJOR];
	minor = bytes[TLS_RECORD_OFFSET_MINOR];
	if (major < 3) {
		SIPE_DEBUG_ERROR_NOFORMAT("tls_record_parse: SSL1/2 not supported");
		return(NULL);
	}
	if (major == 3) {
		switch (minor) {
		case 0:
			SIPE_DEBUG_ERROR_NOFORMAT("tls_record_parse: SSL3.0 not supported");
			return(NULL);
		case 1:
			version = "1.0 (RFC2246)";
			break;
		case 2:
			version = "1.1 (RFC4346)";
			break;
		}
	}
	if (!version) {
		/* should be backwards compatible */
		version = "<future protocol version>";
	}

	/* record length check */
	record_length = TLS_RECORD_HEADER_LENGTH +
		(bytes[TLS_RECORD_OFFSET_LENGTH] << 8) +
		bytes[TLS_RECORD_OFFSET_LENGTH + 1];
	if (record_length > length) {
		SIPE_DEBUG_ERROR_NOFORMAT("tls_record_parse: record too long");
		return(NULL);
	}

	/* TLS record header OK */
	debug_printf(str, "TLS %s record (%" G_GSIZE_FORMAT " bytes)\n",
		     version, length);
	content_type = bytes[TLS_RECORD_OFFSET_TYPE];
	length -= TLS_RECORD_HEADER_LENGTH;
	bytes  += TLS_RECORD_HEADER_LENGTH;

	switch (content_type) {
	case TLS_RECORD_TYPE_HANDSHAKE:
		parsed_data = handshake_parse(bytes, length, incoming, str);
		break;

	default:
		debug_printf(str, "TLS ignored type %d\n", content_type);
		debug_hex(str, bytes, length);
		break;
	}

	if (str) {
		SIPE_DEBUG_INFO_NOFORMAT(str->str);
		g_string_free(str, TRUE);
	}

	return(parsed_data);
}

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

static gboolean tls_client_hello(struct tls_internal_state *state)
{
	guchar *msg = g_memdup(client_hello, sizeof(client_hello));
	guint32 now = time(NULL);
	guint32 now_N = GUINT32_TO_BE(now);
	guchar *p;
	guint i;

	memcpy(msg + GMT_OFFSET, &now_N, sizeof(now_N));
	for (p = msg + RANDOM_OFFSET, i = 0; i < 2; i++)
		*p++ = rand() & 0xFF;

	state->common.out_buffer = msg;
	state->common.out_length = sizeof(client_hello);
	state->state             = TLS_HANDSHAKE_STATE_SERVER_HELLO;

	tls_record_parse(msg, sizeof(client_hello), FALSE);

	return(TRUE);
}

static gboolean tls_server_hello(struct tls_internal_state *state)
{
	gpointer parsed_data = tls_record_parse(state->common.in_buffer,
						state->common.in_length,
						TRUE);

	if (!parsed_data)
		return(FALSE);

	/* temporary */
	state->common.out_buffer = NULL;
	state->common.out_length = 0;
	state->state             = TLS_HANDSHAKE_STATE_FINISHED;

	tls_record_parse(state->common.out_buffer,
			 state->common.out_length,
			 FALSE);

	return(state->common.out_buffer != NULL);
}

static gboolean tls_finished(struct tls_internal_state *state)
{
	gpointer parsed_data = tls_record_parse(state->common.in_buffer,
						state->common.in_length,
						TRUE);

	if (!parsed_data)
		return(FALSE);

	/* TBD: data is really not needed? */
	free_parsed_data(parsed_data);

	state->common.out_buffer = NULL;
	state->common.out_length = 0;
	state->state             = TLS_HANDSHAKE_STATE_COMPLETED;

	/* temporary */
	return(TRUE);
}

/* Public API */

struct sipe_tls_state *sipe_tls_start(gpointer certificate)
{
	struct tls_internal_state *state;

	if (!certificate)
		return(NULL);

	state = g_new0(struct tls_internal_state, 1);
	state->certificate = certificate;
	state->state       = TLS_HANDSHAKE_STATE_START;

	return((struct sipe_tls_state *) state);
}

gboolean sipe_tls_next(struct sipe_tls_state *state)
{
	struct tls_internal_state *internal = (struct tls_internal_state *) state;
	gboolean success = FALSE;

	if (!state)
		return(FALSE);

	state->out_buffer = NULL;

	switch (internal->state) {
	case TLS_HANDSHAKE_STATE_START:
		success = tls_client_hello(internal);
		break;

	case TLS_HANDSHAKE_STATE_SERVER_HELLO:
		success = tls_server_hello(internal);
		break;

	case TLS_HANDSHAKE_STATE_FINISHED:
		success = tls_finished(internal);
		break;

	case TLS_HANDSHAKE_STATE_COMPLETED:
	case TLS_HANDSHAKE_STATE_FAILED:
		/* This should not happen */
		SIPE_DEBUG_ERROR_NOFORMAT("sipe_tls_next: called in incorrect state!");
		break;
	}

	if (!success) {
		internal->state = TLS_HANDSHAKE_STATE_FAILED;
	}

	return(success);
}

void sipe_tls_free(struct sipe_tls_state *state)
{
	if (state) {
		g_free(state->session_key);
		g_free(state->out_buffer);
		g_free(state);
	}
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
