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
	const guchar *parse_buffer;
	gsize parse_length;
	GHashTable *data;
	GString *debug;
};

/*
 * TLS message debugging
 */
static void debug_hex(struct tls_internal_state *state,
		      gsize alternative_length)
{
	GString *str = state->debug;
	const guchar *bytes;
	gsize length;
	gint count;

	if (!str) return;

	bytes  = state->parse_buffer;
	length = alternative_length ? alternative_length : state->parse_length;
	count  = -1;

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

#define debug_print(state, string) \
	if (state->debug) g_string_append(state->debug, string)
#define debug_printf(state, format, ...) \
	if (state->debug) g_string_append_printf(state->debug, format, __VA_ARGS__)

/*
 * Low-level data conversion routines
 *
 *  - host alignment agnostic, i.e. can fetch a word from uneven address
 *  - TLS -> host endianess conversion
 *  - no length check, caller has to do it
 *  - don't modify state
 */
static guint lowlevel_integer_to_host(const guchar *bytes,
				      gsize length)
{
	guint sum = 0;
	while (length--) sum = (sum << 8) + *bytes++;
	return(sum);
}

/*
 * Simple data type parser routines
 */
static gboolean parse_length_check(struct tls_internal_state *state,
				   const gchar *label,
				   gsize length)
{
	if (length > state->parse_length) {
		SIPE_DEBUG_ERROR("parse_length_check: '%s' expected %" G_GSIZE_FORMAT " bytes, remaining %" G_GSIZE_FORMAT,
				 label, length, state->parse_length);
		return(FALSE);
	}
	return(TRUE);
}

static gboolean parse_integer_quiet(struct tls_internal_state *state,
				    const gchar *label,
				    gsize length,
				    guint *result)
{
	if (!parse_length_check(state, label, length)) return(FALSE);
	*result = lowlevel_integer_to_host(state->parse_buffer, length);
	state->parse_buffer += length;
	state->parse_length -= length;
	return(TRUE);
}

static gboolean parse_integer(struct tls_internal_state *state,
			      const gchar *label,
			      gsize length,
			      guint *result)
{
	if (!parse_integer_quiet(state, label, length, result)) return(FALSE);
	debug_printf(state, "'%s/INTEGER%" G_GSIZE_FORMAT " = %d\n",
		     label, length, *result);
	return(TRUE);
}

struct tls_parsed_integer {
	guint value;
};
static gboolean parse_integer_store(struct tls_internal_state *state,
				    const gchar *label,
				    gsize length)
{
	guint value;
	if (!parse_integer(state, label, length, &value)) return(FALSE);
	if (state->data) {
		struct tls_parsed_integer *save = g_new0(struct tls_parsed_integer, 1);
		save->value = value;
		g_hash_table_insert(state->data, (gpointer) label, save);
	}
	return(TRUE);
}

/*
 * TLS message parsing
 */
#define TLS_TYPE_FIXED  0x00
#define TLS_TYPE_ARRAY  0x01
#define TLS_TYPE_VECTOR 0x02

#define TLS_VECTOR_MAX8       255 /* 2^8  - 1 */
#define TLS_VECTOR_MAX16    65535 /* 2^16 - 1 */
#define TLS_VECTOR_MAX24 16777215 /* 2^24 - 1 */

struct parse_descriptor;
typedef gboolean parse_func(struct tls_internal_state *state,
			    const struct parse_descriptor *desc);
struct parse_descriptor {
	const gchar *label;
	parse_func *parser;
	guint type;
	gsize min; /* 0 for fixed/array */
	gsize max;
};

#define TLS_PARSE_DESCRIPTOR_END { NULL, NULL, 0, 0, 0 }

static const struct parse_descriptor const ClientHello[] = {
	{ "Client Protocol Version", NULL, TLS_TYPE_FIXED,    0,  2 },
	{ "Random",                  NULL, TLS_TYPE_ARRAY,    0, 32 },
	{ "SessionID",               NULL, TLS_TYPE_VECTOR,   0, 32 },
	{ "CipherSuite",             NULL, TLS_TYPE_VECTOR,   2, TLS_VECTOR_MAX16 },
	{ "CompressionMethod",       NULL, TLS_TYPE_VECTOR,   1, TLS_VECTOR_MAX8  },
	TLS_PARSE_DESCRIPTOR_END
};

static const struct parse_descriptor const ServerHello[] = {
	{ "Server Protocol Version", NULL, TLS_TYPE_FIXED,    0,  2 },
	{ "Random",                  NULL, TLS_TYPE_ARRAY,    0, 32 },
	{ "SessionID",               NULL, TLS_TYPE_VECTOR,   0, 32 },
	{ "CipherSuite",             NULL, TLS_TYPE_FIXED,    0,  2 },
	{ "CompressionMethod",       NULL, TLS_TYPE_FIXED,    0,  1 },
	TLS_PARSE_DESCRIPTOR_END
};

static const struct parse_descriptor const Certificate[] = {
	{ "Certificate",             NULL, TLS_TYPE_VECTOR,   0, TLS_VECTOR_MAX24 },
	TLS_PARSE_DESCRIPTOR_END
};

static const struct parse_descriptor const CertificateRequest[] = {
	{ "CertificateType",         NULL, TLS_TYPE_VECTOR,   1, TLS_VECTOR_MAX8 },
	{ "DistinguishedName",       NULL, TLS_TYPE_VECTOR,   0, TLS_VECTOR_MAX16 },
	TLS_PARSE_DESCRIPTOR_END
};

static const struct parse_descriptor const ServerHelloDone[] = {
	TLS_PARSE_DESCRIPTOR_END
};

static gboolean parse_ignored_field(struct tls_internal_state *state,
				    const struct parse_descriptor *desc)
{
	gboolean success = FALSE;

	switch (desc->type) {
	case TLS_TYPE_FIXED:
	{
		guint value;
		success = parse_integer(state, desc->label, desc->max, &value);
	}
	break;

	case TLS_TYPE_ARRAY:
		if (parse_length_check(state, desc->label, desc->max)) {
			/* temporary */
			debug_printf(state, "%s/ARRAY[%" G_GSIZE_FORMAT "]\n",
				     desc->label, desc->max);
			debug_hex(state, desc->max);
			state->parse_buffer += desc->max;
			state->parse_length -= desc->max;
			success = TRUE;
		}
		break;

	case TLS_TYPE_VECTOR:
	{
		guint length;
		if (parse_integer_quiet(state, desc->label,
					(desc->max > TLS_VECTOR_MAX16) ? 3 :
					(desc->max > TLS_VECTOR_MAX8)  ? 2 : 1,
					&length)) {

			if (length < desc->min) {
				SIPE_DEBUG_ERROR("generic_parser: too short vector type %d (minimum %" G_GSIZE_FORMAT ")",
						 length, desc->min);
			} else {
				/* temporary */
				debug_printf(state, "%s/VECTOR<%d>\n",
					     desc->label, length);
				if (length)
					debug_hex(state, length);
				state->parse_buffer += length;
				state->parse_length -= length;
				success = TRUE;
			}
		}
	}
	break;

	default:
		SIPE_DEBUG_ERROR("generic_parser: unknown descriptor type %d",
				 desc->type);
		break;
	}

	return(success);
}

static gboolean generic_parser(struct tls_internal_state *state,
			       const struct parse_descriptor *desc)
{
	while (desc->label) {
		if (desc->parser) {
			/* TBD... */
			(void)parse_integer_store;
		} else {
			if (!parse_ignored_field(state, desc))
				return(FALSE);
		}
		desc++;
	}

	return(TRUE);
}

#define TLS_HANDSHAKE_HEADER_LENGTH           4
#define TLS_HANDSHAKE_OFFSET_TYPE             0
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO       1
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO       2
#define TLS_HANDSHAKE_TYPE_CERTIFICATE       11
#define TLS_HANDSHAKE_TYPE_CERTIFICATE_REQ   13
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE 14
#define TLS_HANDSHAKE_OFFSET_LENGTH           1

struct msg_descriptor {
	guint type;
	const gchar *description;
	const struct parse_descriptor *parse;
};

static gboolean handshake_parse(struct tls_internal_state *state)
{
	static const struct msg_descriptor const handshake_descriptors[] = {
		{ TLS_HANDSHAKE_TYPE_CLIENT_HELLO,      "Client Hello",        ClientHello},
		{ TLS_HANDSHAKE_TYPE_SERVER_HELLO,      "Server Hello",        ServerHello},
		{ TLS_HANDSHAKE_TYPE_CERTIFICATE,       "Certificate",         Certificate},
		{ TLS_HANDSHAKE_TYPE_CERTIFICATE_REQ,   "Certificate Request", CertificateRequest},
		{ TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE, "Server Hello Done",   ServerHelloDone}
	};
#define HANDSHAKE_DESCRIPTORS (sizeof(handshake_descriptors)/sizeof(struct msg_descriptor))

	const guchar *bytes  = state->parse_buffer;
	gsize length         = state->parse_length;
	gboolean success     = FALSE;

	while (length > 0) {
		const struct msg_descriptor *desc;
		gsize msg_length;
		guint i, msg_type;

		/* header check */
		if (length < TLS_HANDSHAKE_HEADER_LENGTH) {
			debug_print(state, "CORRUPTED HANDSHAKE HEADER");
			break;
		}

 		/* msg length check */
		msg_length = lowlevel_integer_to_host(bytes + TLS_HANDSHAKE_OFFSET_LENGTH,
						      3);
		if (msg_length > length) {
			debug_print(state, "HANDSHAKE MESSAGE TOO LONG");
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

		debug_printf(state, "TLS handshake (%" G_GSIZE_FORMAT " bytes) (%d)",
			     msg_length, msg_type);

		state->parse_buffer = bytes + TLS_HANDSHAKE_HEADER_LENGTH;
		state->parse_length = msg_length;

		if (i < HANDSHAKE_DESCRIPTORS) {
			debug_printf(state, "%s\n", desc->description);
			success = generic_parser(state, desc->parse);
			if (!success)
				break;
		} else {
			debug_print(state, "ignored\n");
			debug_hex(state, 0);
		}

		/* next message */
		bytes  += TLS_HANDSHAKE_HEADER_LENGTH + msg_length;
		length -= TLS_HANDSHAKE_HEADER_LENGTH + msg_length;
		if (length > 0) {
			debug_print(state, "------\n");
		} else {
			success = TRUE;
		}
	}

	return(success);
}

static void free_parse_data(struct tls_internal_state *state)
{
	if (state->data) {
		g_hash_table_destroy(state->data);
		state->data = NULL;
	}
}

#define TLS_RECORD_HEADER_LENGTH   5
#define TLS_RECORD_OFFSET_TYPE     0
#define TLS_RECORD_TYPE_HANDSHAKE 22
#define TLS_RECORD_OFFSET_MAJOR    1
#define TLS_RECORD_OFFSET_LENGTH   3

/* NOTE: we don't support record fragmentation */
static gboolean tls_record_parse(struct tls_internal_state *state,
				 gboolean incoming)
{
	const guchar *bytes  = incoming ? state->common.in_buffer : state->common.out_buffer;
	gsize length         = incoming ? state->common.in_length : state->common.out_length;
	guint version;
	const gchar *version_str;
	gsize record_length;
	gboolean success = FALSE;

	debug_printf(state, "TLS MESSAGE %s\n", incoming ? "INCOMING" : "OUTGOING");

	/* truncated header check */
	if (length < TLS_RECORD_HEADER_LENGTH) {
		SIPE_DEBUG_ERROR("tls_record_parse: too short TLS record header (%" G_GSIZE_FORMAT " bytes)",
				 length);
		return(FALSE);
	}

	/* protocol version check */
	version = lowlevel_integer_to_host(bytes + TLS_RECORD_OFFSET_MAJOR, 2);
	if (version < 0x0301) {
		SIPE_DEBUG_ERROR_NOFORMAT("tls_record_parse: SSL1/2/3 not supported");
		return(FALSE);
	}
	switch (version) {
	case 0x0301:
		version_str = "1.0 (RFC2246)";
		break;
	case 0x0302:
		version_str = "1.1 (RFC4346)";
		break;
	default:
		version_str = "<future protocol version>";
		break;
	}

	/* record length check */
	record_length = TLS_RECORD_HEADER_LENGTH +
		lowlevel_integer_to_host(bytes + TLS_RECORD_OFFSET_LENGTH, 2);
	if (record_length > length) {
		SIPE_DEBUG_ERROR_NOFORMAT("tls_record_parse: record too long");
		return(FALSE);
	}

	/* TLS record header OK */
	debug_printf(state, "TLS %s record (%" G_GSIZE_FORMAT " bytes)\n",
		     version_str, length);
	state->parse_buffer = bytes  + TLS_RECORD_HEADER_LENGTH;
	state->parse_length = length - TLS_RECORD_HEADER_LENGTH;

	/* Collect parser data for incoming messages */
	if (incoming)
		state->data = g_hash_table_new_full(g_str_hash, g_str_equal,
						    NULL, g_free);

	switch (bytes[TLS_RECORD_OFFSET_TYPE]) {
	case TLS_RECORD_TYPE_HANDSHAKE:
		success = handshake_parse(state);
		break;

	default:
		debug_print(state, "Unsupported TLS message\n");
		debug_hex(state, 0);
		break;
	}

	if (!success)
		free_parse_data(state);

	if (state->debug) {
		SIPE_DEBUG_INFO_NOFORMAT(state->debug->str);
		g_string_truncate(state->debug, 0);
	}

	return(success);
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

	if (sipe_backend_debug_enabled())
		state->debug = g_string_new("");

	tls_record_parse(state, FALSE);

	return(TRUE);
}

static gboolean tls_server_hello(struct tls_internal_state *state)
{
	if (!tls_record_parse(state, TRUE))
		return(FALSE);

	/* temporary */
	free_parse_data(state);
	state->common.out_buffer = NULL;
	state->common.out_length = 0;
	state->state             = TLS_HANDSHAKE_STATE_FINISHED;

	tls_record_parse(state, FALSE);

	return(state->common.out_buffer != NULL);
}

static gboolean tls_finished(struct tls_internal_state *state)
{
	if (!tls_record_parse(state, TRUE))
		return(FALSE);

	/* TBD: data is really not needed? */
	free_parse_data(state);

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
		struct tls_internal_state *internal = (struct tls_internal_state *) state;

		free_parse_data(internal);
		if (internal->debug)
			g_string_free(internal->debug, TRUE);
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
