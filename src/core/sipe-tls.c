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
#include "sipe-svc.h"
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
	guchar *msg_current;
	gsize msg_remainder;
	GHashTable *data;
	GString *debug;
	struct sipe_svc_random client_random;
	struct sipe_svc_random server_random;
};

/*
 * TLS messages & layout descriptors
 */

/* constants */
#define TLS_VECTOR_MAX8       255 /* 2^8  - 1 */
#define TLS_VECTOR_MAX16    65535 /* 2^16 - 1 */
#define TLS_VECTOR_MAX24 16777215 /* 2^24 - 1 */

#define TLS_DATATYPE_RANDOM_LENGTH 32

#define TLS_PROTOCOL_VERSION_1_0 0x0301
#define TLS_PROTOCOL_VERSION_1_1 0x0302

/* CipherSuites */
#define TLS_RSA_EXPORT_WITH_RC4_40_MD5 0x0003
#define TLS_RSA_WITH_RC4_128_MD5       0x0004
#define TLS_RSA_WITH_RC4_128_SHA       0x0005

/* CompressionMethods */
#define TLS_COMP_METHOD_NULL 0

#define TLS_RECORD_HEADER_LENGTH   5
#define TLS_RECORD_OFFSET_TYPE     0
#define TLS_RECORD_TYPE_HANDSHAKE 22
#define TLS_RECORD_OFFSET_VERSION  1
#define TLS_RECORD_OFFSET_LENGTH   3

#define TLS_HANDSHAKE_HEADER_LENGTH           4
#define TLS_HANDSHAKE_OFFSET_TYPE             0
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO       1
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO       2
#define TLS_HANDSHAKE_TYPE_CERTIFICATE       11
#define TLS_HANDSHAKE_TYPE_CERTIFICATE_REQ   13
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE 14
#define TLS_HANDSHAKE_OFFSET_LENGTH           1

struct layout_descriptor;
typedef gboolean parse_func(struct tls_internal_state *state,
			    const struct layout_descriptor *desc);

/* Defines the strictest alignment requirement */
struct tls_compile_integer;
typedef void compile_func(struct tls_internal_state *state,
			  const struct layout_descriptor *desc,
			  const struct tls_compile_integer *data);

struct layout_descriptor {
	const gchar *label;
	parse_func *parser;
	compile_func *compiler;
	gsize min; /* 0 for fixed/array */
	gsize max;
	gsize offset;
};

#define TLS_LAYOUT_DESCRIPTOR_END { NULL, NULL, NULL, 0, 0, 0 }
#define TLS_LAYOUT_IS_VALID(desc) (desc->label)

struct msg_descriptor  {
	const struct msg_descriptor *next;
	const gchar *description;
	const struct layout_descriptor *layouts;
	guint type;
};

/* parsed data */
struct tls_parsed_integer {
	guint value;
};

struct tls_parsed_array {
	gsize length; /* bytes */
	const guchar data[0];
};

/* compile data */
struct tls_compile_integer {
	gsize value;
};

struct tls_compile_array {
	gsize elements; /* unused */
	guchar placeholder[];
};

struct tls_compile_random {
	gsize elements; /* unused */
	guchar random[TLS_DATATYPE_RANDOM_LENGTH];
};

struct tls_compile_vector {
	gsize elements; /* VECTOR */
	guint placeholder[];
};

struct tls_compile_sessionid {
	gsize elements; /* VECTOR */
};

struct tls_compile_cipher {
	gsize elements; /* VECTOR */
	guint suites[3];
};

struct tls_compile_compression {
	gsize elements; /* VECTOR */
	guint methods[1];
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

	bytes  = state->msg_current;
	length = alternative_length ? alternative_length : state->msg_remainder;
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
 * TLS data parsers
 *
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
 * Generic data type parser routines
 */
static gboolean msg_remainder_check(struct tls_internal_state *state,
				   const gchar *label,
				   gsize length)
{
	if (length > state->msg_remainder) {
		SIPE_DEBUG_ERROR("msg_remainder_check: '%s' expected %" G_GSIZE_FORMAT " bytes, remaining %" G_GSIZE_FORMAT,
				 label, length, state->msg_remainder);
		return(FALSE);
	}
	return(TRUE);
}

static gboolean parse_integer_quiet(struct tls_internal_state *state,
				    const gchar *label,
				    gsize length,
				    guint *result)
{
	if (!msg_remainder_check(state, label, length)) return(FALSE);
	*result = lowlevel_integer_to_host(state->msg_current, length);
	state->msg_current   += length;
	state->msg_remainder -= length;
	return(TRUE);
}

static gboolean parse_integer(struct tls_internal_state *state,
			      const struct layout_descriptor *desc)
{
	guint value;
	if (!parse_integer_quiet(state, desc->label, desc->max, &value))
		return(FALSE);
	debug_printf(state, "%s/INTEGER%" G_GSIZE_FORMAT " = %d\n",
		     desc->label, desc->max, value);
	if (state->data) {
		struct tls_parsed_integer *save = g_new0(struct tls_parsed_integer, 1);
		save->value = value;
		g_hash_table_insert(state->data, (gpointer) desc->label, save);
	}
	return(TRUE);
}

static gboolean parse_array(struct tls_internal_state *state,
			    const struct layout_descriptor *desc)
{
	if (!msg_remainder_check(state, desc->label, desc->max))
		return(FALSE);
	debug_printf(state, "%s/ARRAY[%" G_GSIZE_FORMAT "]\n",
		     desc->label, desc->max);
	if (state->data) {
		struct tls_parsed_array *save = g_malloc0(sizeof(struct tls_parsed_array) +
							  desc->max);
		save->length = desc->max;
		memcpy((guchar *)save->data, state->msg_current, desc->max);
		g_hash_table_insert(state->data, (gpointer) desc->label, save);

	}
	state->msg_current   += desc->max;
	state->msg_remainder -= desc->max;
	return(TRUE);
}

static gboolean parse_vector(struct tls_internal_state *state,
			     const struct layout_descriptor *desc)
{
	guint length;
	if (!parse_integer_quiet(state, desc->label,
				 (desc->max > TLS_VECTOR_MAX16) ? 3 :
				 (desc->max > TLS_VECTOR_MAX8)  ? 2 : 1,
				 &length))
		return(FALSE);
	if (length < desc->min) {
		SIPE_DEBUG_ERROR("parse_vector: '%s' too short %d, expected %" G_GSIZE_FORMAT,
				 desc->label, length, desc->min);
		return(FALSE);
	}
	debug_printf(state, "%s/VECTOR<%d>\n", desc->label, length);
	if (state->data) {
		struct tls_parsed_array *save = g_malloc0(sizeof(struct tls_parsed_array) +
							  length);
		save->length = length;
		memcpy((guchar *)save->data, state->msg_current, length);
		g_hash_table_insert(state->data, (gpointer) desc->label, save);
	}
	state->msg_current   += length;
	state->msg_remainder -= length;
	return(TRUE);
}

/*
 * Specific data type parser routines
 */

/* TBD... */

/*
 * TLS data compilers
 *
 * Low-level data conversion routines
 *
 *  - host alignment agnostic, i.e. can fetch a word from uneven address
 *  - host -> TLS host endianess conversion
 *  - don't modify state
 */
static void lowlevel_integer_to_tls(guchar *bytes,
				    gsize length,
				    guint value)
{
	while (length--) {
		bytes[length] = value & 0xFF;
		value >>= 8;
	}
}

/*
 * Generic data type compiler routines
 */
static void compile_integer(struct tls_internal_state *state,
			    const struct layout_descriptor *desc,
			    const struct tls_compile_integer *data)
{
	lowlevel_integer_to_tls(state->msg_current, desc->max, data->value);
	state->msg_current   += desc->max;
	state->msg_remainder += desc->max;
}

static void compile_array(struct tls_internal_state *state,
			  const struct layout_descriptor *desc,
			  const struct tls_compile_integer *data)
{
	const struct tls_compile_array *array = (struct tls_compile_array *) data;
	memcpy(state->msg_current, array->placeholder, desc->max);
	state->msg_current   += desc->max;
	state->msg_remainder += desc->max;
}

static void compile_vector(struct tls_internal_state *state,
			   const struct layout_descriptor *desc,
			   const struct tls_compile_integer *data)
{
	const struct tls_compile_vector *vector = (struct tls_compile_vector *) data;
	gsize length = vector->elements;
	gsize length_field = (desc->max > TLS_VECTOR_MAX16) ? 3 :
		             (desc->max > TLS_VECTOR_MAX8)  ? 2 : 1;

	lowlevel_integer_to_tls(state->msg_current, length_field, length);
	state->msg_current   += length_field;
	state->msg_remainder += length_field;
	memcpy(state->msg_current, vector->placeholder, length);
	state->msg_current   += length;
	state->msg_remainder += length;
}

static void compile_vector_int2(struct tls_internal_state *state,
				const struct layout_descriptor *desc,
				const struct tls_compile_integer *data)
{
	const struct tls_compile_vector *vector = (struct tls_compile_vector *) data;
	gsize elements = vector->elements;
	gsize length   = elements * sizeof(guint16);
	gsize length_field = (desc->max > TLS_VECTOR_MAX16) ? 3 :
		             (desc->max > TLS_VECTOR_MAX8)  ? 2 : 1;
	const guint *p = vector->placeholder;

	lowlevel_integer_to_tls(state->msg_current, length_field, length);
	state->msg_current   += length_field;
	state->msg_remainder += length_field;
	while (elements--) {
		lowlevel_integer_to_tls(state->msg_current, sizeof(guint16), *p++);
		state->msg_current   += sizeof(guint16);
		state->msg_remainder += sizeof(guint16);
	}
}

/*
 * Specific data type compiler routines
 */

/* TBD... */

/*
 * TLS handshake message layout descriptors
 */
struct ClientHello_host {
	const struct tls_compile_integer protocol_version;
	const struct tls_compile_random random;
	const struct tls_compile_sessionid sessionid;
	const struct tls_compile_cipher cipher;
	const struct tls_compile_compression compression;
};
#define CLIENTHELLO_OFFSET(a) offsetof(struct ClientHello_host, a)

static const struct layout_descriptor const ClientHello_l[] = {
	{ "Client Protocol Version", parse_integer, compile_integer,     0,  2,                         CLIENTHELLO_OFFSET(protocol_version) },
	{ "Random",                  parse_array,   compile_array,       0, TLS_DATATYPE_RANDOM_LENGTH, CLIENTHELLO_OFFSET(random) },
	{ "SessionID",               parse_vector,  compile_vector,      0, 32,                         CLIENTHELLO_OFFSET(sessionid) },
	{ "CipherSuite",             parse_vector,  compile_vector_int2, 2, TLS_VECTOR_MAX16,           CLIENTHELLO_OFFSET(cipher)},
	{ "CompressionMethod",       parse_vector,  compile_vector,      1, TLS_VECTOR_MAX8,            CLIENTHELLO_OFFSET(compression) },
	TLS_LAYOUT_DESCRIPTOR_END
};
static const struct msg_descriptor const ClientHello_m = {
	NULL, "Client Hello", ClientHello_l, TLS_HANDSHAKE_TYPE_CLIENT_HELLO
};

static const struct layout_descriptor const ServerHello_l[] = {
	{ "Server Protocol Version", parse_integer, NULL, 0,  2,                         0 },
	{ "Random",                  parse_array,   NULL, 0, TLS_DATATYPE_RANDOM_LENGTH, 0 },
	{ "SessionID",               parse_vector,  NULL, 0, 32,                         0 },
	{ "CipherSuite",             parse_integer, NULL, 0,  2,                         0 },
	{ "CompressionMethod",       parse_integer, NULL, 0,  1,                         0 },
	TLS_LAYOUT_DESCRIPTOR_END
};
static const struct msg_descriptor const ServerHello_m = {
	&ClientHello_m, "Server Hello", ServerHello_l, TLS_HANDSHAKE_TYPE_SERVER_HELLO
};

struct Certificate_host {
	struct tls_compile_vector certificate;
};
#define CERTIFICATE_OFFSET(a) offsetof(struct Certificate_host, a)

static const struct layout_descriptor const Certificate_l[] = {
	{ "Certificate",             parse_vector, compile_vector, 0, TLS_VECTOR_MAX24, CERTIFICATE_OFFSET(certificate) },
	TLS_LAYOUT_DESCRIPTOR_END
};
static const struct msg_descriptor const Certificate_m = {
	&ServerHello_m, "Certificate", Certificate_l, TLS_HANDSHAKE_TYPE_CERTIFICATE
};

static const struct layout_descriptor const CertificateRequest_l[] = {
	{ "CertificateType",         parse_vector, NULL, 1, TLS_VECTOR_MAX8,  0 },
	{ "DistinguishedName",       parse_vector, NULL, 0, TLS_VECTOR_MAX16, 0 },
	TLS_LAYOUT_DESCRIPTOR_END
};
static const struct msg_descriptor const CertificateRequest_m = {
	&Certificate_m, "Certificate Request", CertificateRequest_l, TLS_HANDSHAKE_TYPE_CERTIFICATE_REQ
};

static const struct layout_descriptor const ServerHelloDone_l[] = {
	TLS_LAYOUT_DESCRIPTOR_END
};
static const struct msg_descriptor const ServerHelloDone_m = {
	&CertificateRequest_m, "Server Hello Done", ServerHelloDone_l, TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE
};

#define HANDSHAKE_MSG_DESCRIPTORS &ServerHelloDone_m

/*
 * TLS message parsers
 */
static gboolean handshake_parse(struct tls_internal_state *state)
{
	const guchar *bytes = state->msg_current;
	gsize length        = state->msg_remainder;
	gboolean success    = FALSE;

	while (length > 0) {
		const struct msg_descriptor *desc;
		gsize msg_length;
		guint msg_type;

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
		for (desc = HANDSHAKE_MSG_DESCRIPTORS;
		     desc;
		     desc = desc->next)
			if (msg_type == desc->type)
				break;

		debug_printf(state, "TLS handshake (%" G_GSIZE_FORMAT " bytes) (%d)",
			     msg_length, msg_type);

		state->msg_current   = (guchar *) bytes + TLS_HANDSHAKE_HEADER_LENGTH;
		state->msg_remainder = msg_length;

		if (desc->layouts) {
			const struct layout_descriptor *ldesc = desc->layouts;

			debug_printf(state, "%s\n", desc->description);
			while (TLS_LAYOUT_IS_VALID(ldesc)) {
				success = ldesc->parser(state, ldesc);
				if (!success)
					break;
				ldesc++;
			}
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
	version = lowlevel_integer_to_host(bytes + TLS_RECORD_OFFSET_VERSION, 2);
	if (version < TLS_PROTOCOL_VERSION_1_0) {
		SIPE_DEBUG_ERROR_NOFORMAT("tls_record_parse: SSL1/2/3 not supported");
		return(FALSE);
	}
	switch (version) {
	case TLS_PROTOCOL_VERSION_1_0:
		version_str = "1.0 (RFC2246)";
		break;
	case TLS_PROTOCOL_VERSION_1_1:
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
	state->msg_current   = (guchar *) bytes  + TLS_RECORD_HEADER_LENGTH;
	state->msg_remainder = length - TLS_RECORD_HEADER_LENGTH;

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

/*
 * TLS message compiler
 */
static void compile_msg(struct tls_internal_state *state,
			gsize size,
			gsize messages,
			...)
{
	/*
	 * Estimate the size of the compiled message
	 *
	 * The data structures in the host format have zero or more padding
	 * bytes added by the compiler to ensure correct element alignments.
	 * So the sizeof() of the data structure is always equal or greater
	 * than the space needed for the compiled data. By adding the space
	 * required for the headers we arrive at a safe estimate
	 *
	 * Therefore we don't need space checks in the compiler functions
	 */
	gsize total_size = size +
		TLS_RECORD_HEADER_LENGTH +
		TLS_HANDSHAKE_HEADER_LENGTH * messages;
	guchar *buffer = g_malloc0(total_size);
	va_list ap;

	SIPE_DEBUG_INFO("compile_msg: buffer size %" G_GSIZE_FORMAT,
			total_size);

	state->msg_current   = buffer + TLS_RECORD_HEADER_LENGTH;
	state->msg_remainder = 0;

	va_start(ap, messages);
	while (messages--) {
		const struct msg_descriptor *desc = va_arg(ap, struct msg_descriptor *);
		const guchar *data = va_arg(ap, gpointer);
		const struct layout_descriptor *ldesc = desc->layouts;
		guchar *handshake = state->msg_current;
		gsize length;

		/* add TLS handshake header */
		handshake[TLS_HANDSHAKE_OFFSET_TYPE] = desc->type;
		state->msg_current   += TLS_HANDSHAKE_HEADER_LENGTH;
		state->msg_remainder += TLS_HANDSHAKE_HEADER_LENGTH;

		while (TLS_LAYOUT_IS_VALID(ldesc)) {
			/*
			 * Avoid "cast increases required alignment" errors
			 *
			 * (void *) tells the compiler that we know what we're
			 * doing, i.e. we know that the calculated address
			 * points to correctly aligned data.
			 */
			ldesc->compiler(state, ldesc,
					(void *) (data + ldesc->offset));
			ldesc++;
		}

		length = state->msg_current - handshake - TLS_HANDSHAKE_HEADER_LENGTH;
		lowlevel_integer_to_tls(handshake + TLS_HANDSHAKE_OFFSET_LENGTH,
					3, length);
		SIPE_DEBUG_INFO("compile_msg: (%d)%s, size %" G_GSIZE_FORMAT,
				desc->type, desc->description, length);


	}
	va_end(ap);

	/* add TLS record header */
	buffer[TLS_RECORD_OFFSET_TYPE] = TLS_RECORD_TYPE_HANDSHAKE;
	lowlevel_integer_to_tls(buffer + TLS_RECORD_OFFSET_VERSION, 2,
				TLS_PROTOCOL_VERSION_1_0);
	lowlevel_integer_to_tls(buffer + TLS_RECORD_OFFSET_LENGTH, 2,
				state->msg_remainder);

	state->common.out_buffer = buffer;
	state->common.out_length = state->msg_remainder + TLS_RECORD_HEADER_LENGTH;

	SIPE_DEBUG_INFO("compile_msg: compiled size %" G_GSIZE_FORMAT,
			state->common.out_length);
}

static gboolean tls_client_hello(struct tls_internal_state *state)
{
	guint32 now   = time(NULL);
	guint32 now_N = GUINT32_TO_BE(now);
	struct ClientHello_host msg = {
		{ TLS_PROTOCOL_VERSION_1_0 },
		{ 0, { } },
		{ 0 /* empty SessionID */ },
		{ 3,
		  {
			  TLS_RSA_WITH_RC4_128_MD5,
			  TLS_RSA_WITH_RC4_128_SHA,
			  TLS_RSA_EXPORT_WITH_RC4_40_MD5
		  }
		},
		{ 1,
		  {
			  TLS_COMP_METHOD_NULL
		  }
		}
	};

	/* First 4 bytes of client_random is the current timestamp */
	sipe_svc_fill_random(&state->client_random,
			     TLS_DATATYPE_RANDOM_LENGTH * 8); /* -> bits */
	memcpy(state->client_random.buffer, &now_N, sizeof(now_N));
	memcpy((guchar *) msg.random.random, state->client_random.buffer,
	       TLS_DATATYPE_RANDOM_LENGTH);

	compile_msg(state,
		    sizeof(msg),
		    1,
		    &ClientHello_m, &msg);

	if (sipe_backend_debug_enabled())
		state->debug = g_string_new("");

	state->state = TLS_HANDSHAKE_STATE_SERVER_HELLO;
	return(tls_record_parse(state, FALSE));
}

static gboolean tls_server_hello(struct tls_internal_state *state)
{
	struct tls_parsed_array *server_random;
	struct Certificate_host *certificate;
	gsize certificate_length = sipe_cert_crypto_raw_length(state->certificate);

	if (!tls_record_parse(state, TRUE))
		return(FALSE);

	/* check for required data fields */
	server_random = g_hash_table_lookup(state->data, "Random");
	if (!server_random) {
		SIPE_DEBUG_ERROR_NOFORMAT("tls_server_hello: no server random");
		return(FALSE);
	}

	/* found all the required fields */
	state->server_random.length = server_random->length;
	state->server_random.buffer = g_memdup(server_random->data,
					       server_random->length);

	/* done with parsed data */
	free_parse_data(state);

	/* setup our response */
	certificate = g_malloc0(sizeof(struct Certificate_host) +
				certificate_length);
	certificate->certificate.elements = certificate_length;
	memcpy(certificate->certificate.placeholder,
	       sipe_cert_crypto_raw(state->certificate),
	       certificate_length);

	compile_msg(state,
		    sizeof(struct Certificate_host) +
		    certificate_length,
		    1,
		    &Certificate_m, certificate);

	g_free(certificate);

	state->state = TLS_HANDSHAKE_STATE_FINISHED;
	return(tls_record_parse(state, FALSE));
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
		sipe_svc_free_random(&internal->client_random);
		g_free(internal->server_random.buffer);
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
