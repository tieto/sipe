/**
 * @file sipe-tls.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-12 SIPE Project <http://sipe.sourceforge.net/>
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
#include "sipe-crypt.h"
#include "sipe-digest.h"
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
	gpointer md5_context;
	gpointer sha1_context;
	gpointer server_certificate;
	struct sipe_tls_random client_random;
	struct sipe_tls_random server_random;
	struct sipe_tls_random pre_master_secret;
	gsize mac_length;
	gsize key_length;
	guchar *master_secret;
	guchar *key_block;
	guchar *tls_dsk_key_block;
	const guchar *client_write_mac_secret;
	const guchar *server_write_mac_secret;
	const guchar *client_write_secret;
	const guchar *server_write_secret;
	void (*mac_func)(const guchar *key, gsize key_length,
			 const guchar *data, gsize data_length,
			 guchar *digest);
	gpointer cipher_context;
	guint64 sequence_number;
	gboolean encrypted;
};

/*
 * TLS messages & layout descriptors
 */

/* constants */
#define TLS_VECTOR_MAX8       255 /* 2^8  - 1 */
#define TLS_VECTOR_MAX16    65535 /* 2^16 - 1 */
#define TLS_VECTOR_MAX24 16777215 /* 2^24 - 1 */

#define TLS_PROTOCOL_VERSION_1_0 0x0301
#define TLS_PROTOCOL_VERSION_1_1 0x0302

/* CipherSuites */
#define TLS_RSA_EXPORT_WITH_RC4_40_MD5 0x0003
#define TLS_RSA_WITH_RC4_128_MD5       0x0004
#define TLS_RSA_WITH_RC4_128_SHA       0x0005

/* CompressionMethods */
#define TLS_COMP_METHOD_NULL 0

/* various array lengths */
#define TLS_ARRAY_RANDOM_LENGTH        32
#define TLS_ARRAY_MASTER_SECRET_LENGTH 48
#define TLS_ARRAY_VERIFY_LENGTH        12

#define TLS_RECORD_HEADER_LENGTH            5
#define TLS_RECORD_OFFSET_TYPE              0
#define TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC 20
#define TLS_RECORD_TYPE_HANDSHAKE          22
#define TLS_RECORD_OFFSET_VERSION           1
#define TLS_RECORD_OFFSET_LENGTH            3

#define TLS_HANDSHAKE_HEADER_LENGTH             4
#define TLS_HANDSHAKE_OFFSET_TYPE               0
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO         1
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO         2
#define TLS_HANDSHAKE_TYPE_CERTIFICATE         11
#define TLS_HANDSHAKE_TYPE_CERTIFICATE_REQ     13
#define TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE   14
#define TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY  15
#define TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE 16
#define TLS_HANDSHAKE_TYPE_FINISHED            20
#define TLS_HANDSHAKE_OFFSET_LENGTH             1

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
	guchar random[TLS_ARRAY_RANDOM_LENGTH];
};

struct tls_compile_verify {
	gsize elements; /* unused */
	guchar verify[TLS_ARRAY_VERIFY_LENGTH];
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

/* compiled message */
struct tls_compiled_message {
	gsize size;
	guchar data[];
};

/*
 * Random byte buffers
 */
void sipe_tls_fill_random(struct sipe_tls_random *random,
			  guint bits)
{
	guint bytes = ((bits + 15) / 16) * 2;
	guint16 *p  = g_malloc(bytes);

	SIPE_DEBUG_INFO("sipe_tls_fill_random: %d bits -> %d bytes",
			bits, bytes);

	random->buffer = (guint8*) p;
	random->length = bytes;

	for (bytes /= 2; bytes; bytes--)
		*p++ = rand() & 0xFFFF;
}

void sipe_tls_free_random(struct sipe_tls_random *random)
{
	g_free(random->buffer);
}

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

static void debug_secrets(struct tls_internal_state *state,
			  const gchar *label,
			  const guchar *secret,
			  gsize secret_length)
{
	if (state->debug && secret) {
		g_string_append_printf(state->debug, "%s (%3" G_GSIZE_FORMAT ") = ",
				       label, secret_length);
		while (secret_length--)
			g_string_append_printf(state->debug, "%02X", *secret++);
		SIPE_DEBUG_INFO_NOFORMAT(state->debug->str);
		g_string_truncate(state->debug, 0);
	}
}

/*
 * TLS Pseudorandom Function (PRF) - RFC2246, Section 5
 */
static guchar *sipe_tls_p_md5(const guchar *secret,
			      gsize secret_length,
			      const guchar *seed,
			      gsize seed_length,
			      gsize output_length)
{
	guchar *output = NULL;

	/*
	 * output_length ==  0     -> illegal
	 * output_length ==  1..16 -> iterations = 1
	 * output_length == 17..32 -> iterations = 2
	 */
	if (secret && seed && (output_length > 0)) {
		guint iterations = (output_length + SIPE_DIGEST_HMAC_MD5_LENGTH - 1) / SIPE_DIGEST_HMAC_MD5_LENGTH;
		guchar *concat   = g_malloc(SIPE_DIGEST_HMAC_MD5_LENGTH + seed_length);
		guchar A[SIPE_DIGEST_HMAC_MD5_LENGTH];
		guchar *p;

		SIPE_DEBUG_INFO("p_md5: secret %" G_GSIZE_FORMAT " bytes, seed %" G_GSIZE_FORMAT " bytes",
				secret_length, seed_length);
		SIPE_DEBUG_INFO("p_md5: output %" G_GSIZE_FORMAT " bytes -> %d iterations",
				output_length, iterations);

		/* A(1) = HMAC_MD5(secret, A(0)), A(0) = seed */
		sipe_digest_hmac_md5(secret, secret_length,
				      seed, seed_length,
				      A);

		/* Each iteration adds SIPE_DIGEST_HMAC_MD5_LENGTH bytes */
		p = output = g_malloc(iterations * SIPE_DIGEST_HMAC_MD5_LENGTH);

		while (iterations-- > 0) {
			/* P_MD5(i) = HMAC_MD5(secret, A(i) + seed), i = 1, 2, ... */
			guchar P[SIPE_DIGEST_HMAC_MD5_LENGTH];
			memcpy(concat, A, SIPE_DIGEST_HMAC_MD5_LENGTH);
			memcpy(concat + SIPE_DIGEST_HMAC_MD5_LENGTH, seed, seed_length);
			sipe_digest_hmac_md5(secret, secret_length,
					      concat, SIPE_DIGEST_HMAC_MD5_LENGTH + seed_length,
					      P);
			memcpy(p, P, SIPE_DIGEST_HMAC_MD5_LENGTH);
			p += SIPE_DIGEST_HMAC_MD5_LENGTH;

			/* A(i+1) = HMAC_MD5(secret, A(i)) */
			sipe_digest_hmac_md5(secret, secret_length,
					      A, SIPE_DIGEST_HMAC_MD5_LENGTH,
					      A);
		}
		g_free(concat);
	}

	return(output);
}

guchar *sipe_tls_p_sha1(const guchar *secret,
			gsize secret_length,
			const guchar *seed,
			gsize seed_length,
			gsize output_length)
{
	guchar *output = NULL;

	/*
	 * output_length ==  0     -> illegal
	 * output_length ==  1..20 -> iterations = 1
	 * output_length == 21..40 -> iterations = 2
	 */
	if (secret && seed && (output_length > 0)) {
		guint iterations = (output_length + SIPE_DIGEST_HMAC_SHA1_LENGTH - 1) / SIPE_DIGEST_HMAC_SHA1_LENGTH;
		guchar *concat   = g_malloc(SIPE_DIGEST_HMAC_SHA1_LENGTH + seed_length);
		guchar A[SIPE_DIGEST_HMAC_SHA1_LENGTH];
		guchar *p;

		SIPE_DEBUG_INFO("p_sha1: secret %" G_GSIZE_FORMAT " bytes, seed %" G_GSIZE_FORMAT " bytes",
				secret_length, seed_length);
		SIPE_DEBUG_INFO("p_sha1: output %" G_GSIZE_FORMAT " bytes -> %d iterations",
				output_length, iterations);

		/* A(1) = HMAC_SHA1(secret, A(0)), A(0) = seed */
		sipe_digest_hmac_sha1(secret, secret_length,
				      seed, seed_length,
				      A);

		/* Each iteration adds SIPE_DIGEST_HMAC_SHA1_LENGTH bytes */
		p = output = g_malloc(iterations * SIPE_DIGEST_HMAC_SHA1_LENGTH);

		while (iterations-- > 0) {
			/* P_SHA1(i) = HMAC_SHA1(secret, A(i) + seed), i = 1, 2, ... */
			guchar P[SIPE_DIGEST_HMAC_SHA1_LENGTH];
			memcpy(concat, A, SIPE_DIGEST_HMAC_SHA1_LENGTH);
			memcpy(concat + SIPE_DIGEST_HMAC_SHA1_LENGTH, seed, seed_length);
			sipe_digest_hmac_sha1(secret, secret_length,
					      concat, SIPE_DIGEST_HMAC_SHA1_LENGTH + seed_length,
					      P);
			memcpy(p, P, SIPE_DIGEST_HMAC_SHA1_LENGTH);
			p += SIPE_DIGEST_HMAC_SHA1_LENGTH;

			/* A(i+1) = HMAC_SHA1(secret, A(i)) */
			sipe_digest_hmac_sha1(secret, secret_length,
					      A, SIPE_DIGEST_HMAC_SHA1_LENGTH,
					      A);
		}
		g_free(concat);
	}

	return(output);
}

static guchar *sipe_tls_prf(SIPE_UNUSED_PARAMETER struct tls_internal_state *state,
			    const guchar *secret,
			    gsize secret_length,
			    const guchar *label,
			    gsize label_length,
			    const guchar *seed,
			    gsize seed_length,
			    gsize output_length)
{
	gsize half           = (secret_length + 1) / 2;
	gsize newseed_length = label_length + seed_length;
	/* secret: used as S1; secret2: last half of original secret (S2) */
	guchar *secret2 = g_memdup(secret + secret_length - half, half);
	guchar *newseed = g_malloc(newseed_length);
	guchar *md5, *dest;
	guchar *sha1, *src;
	gsize count;

	/* make Coverity happy - lengths could be 0 */
	if (!secret2 || !newseed) {
		g_free(secret2);
		g_free(newseed);
		return(NULL);
	}

	/*
	 * PRF(secret, label, seed) = P_MD5(S1, label + seed) XOR
	 *                            P_SHA-1(S2, label + seed);
	 */
	memcpy(newseed, label, label_length);
	memcpy(newseed + label_length, seed, seed_length);
#undef __SIPE_TLS_CRYPTO_DEBUG
#ifdef __SIPE_TLS_CRYPTO_DEBUG
	debug_secrets(state, "sipe_tls_prf: secret                    ",
		      secret,  secret_length);
	debug_secrets(state, "sipe_tls_prf: combined seed             ",
		      newseed, newseed_length);
	SIPE_DEBUG_INFO("total seed length %" G_GSIZE_FORMAT,
			newseed_length);
	debug_secrets(state, "sipe_tls_prf: S1                        ",
		      secret,  half);
	debug_secrets(state, "sipe_tls_prf: S2                        ",
		      secret2, half);
#endif
	md5  = sipe_tls_p_md5(secret,   half, newseed, newseed_length, output_length);
	sha1 = sipe_tls_p_sha1(secret2, half, newseed, newseed_length, output_length);
#ifdef __SIPE_TLS_CRYPTO_DEBUG
	debug_secrets(state, "sipe_tls_prf: P_md5()                   ",
		      md5,  output_length);
	debug_secrets(state, "sipe_tls_prf: P_sha1()                  ",
		      sha1, output_length);
#endif
	for (dest = md5, src = sha1, count = output_length;
	     count > 0;
	     count--)
		*dest++ ^= *src++;

	g_free(sha1);
	g_free(newseed);
	g_free(secret2);

#ifdef __SIPE_TLS_CRYPTO_DEBUG
	debug_secrets(state, "sipe_tls_prf: PRF()                     ",
		      md5,  output_length);
#endif

	return(md5);
}

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
	state->msg_current += desc->max;
}

static void compile_array(struct tls_internal_state *state,
			  const struct layout_descriptor *desc,
			  const struct tls_compile_integer *data)
{
	const struct tls_compile_array *array = (struct tls_compile_array *) data;
	memcpy(state->msg_current, array->placeholder, desc->max);
	state->msg_current += desc->max;
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
	state->msg_current += length_field;
	memcpy(state->msg_current, vector->placeholder, length);
	state->msg_current += length;
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
	state->msg_current += length_field;
	while (elements--) {
		lowlevel_integer_to_tls(state->msg_current, sizeof(guint16), *p++);
		state->msg_current += sizeof(guint16);
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
	struct tls_compile_integer protocol_version;
	struct tls_compile_random random;
	struct tls_compile_sessionid sessionid;
	struct tls_compile_cipher cipher;
	struct tls_compile_compression compression;
};
#define CLIENTHELLO_OFFSET(a) offsetof(struct ClientHello_host, a)

static const struct layout_descriptor ClientHello_l[] = {
	{ "Client Protocol Version", parse_integer, compile_integer,     0,  2,                      CLIENTHELLO_OFFSET(protocol_version) },
	{ "Random",                  parse_array,   compile_array,       0, TLS_ARRAY_RANDOM_LENGTH, CLIENTHELLO_OFFSET(random) },
	{ "SessionID",               parse_vector,  compile_vector,      0, 32,                      CLIENTHELLO_OFFSET(sessionid) },
	{ "CipherSuite",             parse_vector,  compile_vector_int2, 2, TLS_VECTOR_MAX16,        CLIENTHELLO_OFFSET(cipher)},
	{ "CompressionMethod",       parse_vector,  compile_vector,      1, TLS_VECTOR_MAX8,         CLIENTHELLO_OFFSET(compression) },
	TLS_LAYOUT_DESCRIPTOR_END
};
static const struct msg_descriptor ClientHello_m = {
	NULL, "Client Hello", ClientHello_l, TLS_HANDSHAKE_TYPE_CLIENT_HELLO
};

static const struct layout_descriptor ServerHello_l[] = {
	{ "Server Protocol Version", parse_integer, NULL, 0,  2,                      0 },
	{ "Random",                  parse_array,   NULL, 0, TLS_ARRAY_RANDOM_LENGTH, 0 },
	{ "SessionID",               parse_vector,  NULL, 0, 32,                      0 },
	{ "CipherSuite",             parse_integer, NULL, 0,  2,                      0 },
	{ "CompressionMethod",       parse_integer, NULL, 0,  1,                      0 },
	TLS_LAYOUT_DESCRIPTOR_END
};
static const struct msg_descriptor ServerHello_m = {
	&ClientHello_m, "Server Hello", ServerHello_l, TLS_HANDSHAKE_TYPE_SERVER_HELLO
};

struct Certificate_host {
	struct tls_compile_vector certificate;
};
#define CERTIFICATE_OFFSET(a) offsetof(struct Certificate_host, a)

static const struct layout_descriptor Certificate_l[] = {
	{ "Certificate",             parse_vector, compile_vector, 0, TLS_VECTOR_MAX24, CERTIFICATE_OFFSET(certificate) },
	TLS_LAYOUT_DESCRIPTOR_END
};
static const struct msg_descriptor Certificate_m = {
	&ServerHello_m, "Certificate", Certificate_l, TLS_HANDSHAKE_TYPE_CERTIFICATE
};

static const struct layout_descriptor CertificateRequest_l[] = {
	{ "CertificateType",         parse_vector, NULL, 1, TLS_VECTOR_MAX8,  0 },
	{ "DistinguishedName",       parse_vector, NULL, 0, TLS_VECTOR_MAX16, 0 },
	TLS_LAYOUT_DESCRIPTOR_END
};
static const struct msg_descriptor CertificateRequest_m = {
	&Certificate_m, "Certificate Request", CertificateRequest_l, TLS_HANDSHAKE_TYPE_CERTIFICATE_REQ
};

static const struct layout_descriptor ServerHelloDone_l[] = {
	TLS_LAYOUT_DESCRIPTOR_END
};
static const struct msg_descriptor ServerHelloDone_m = {
	&CertificateRequest_m, "Server Hello Done", ServerHelloDone_l, TLS_HANDSHAKE_TYPE_SERVER_HELLO_DONE
};

struct ClientKeyExchange_host {
	struct tls_compile_vector secret;
};
#define CLIENTKEYEXCHANGE_OFFSET(a) offsetof(struct ClientKeyExchange_host, a)

static const struct layout_descriptor ClientKeyExchange_l[] = {
	{ "Exchange Keys",           parse_vector, compile_vector, 0, TLS_VECTOR_MAX16, CLIENTKEYEXCHANGE_OFFSET(secret) },
	TLS_LAYOUT_DESCRIPTOR_END
};
static const struct msg_descriptor ClientKeyExchange_m = {
	&ServerHelloDone_m, "Client Key Exchange", ClientKeyExchange_l, TLS_HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE
};

struct CertificateVerify_host {
	struct tls_compile_vector signature;
};
#define CERTIFICATEVERIFY_OFFSET(a) offsetof(struct CertificateVerify_host, a)

static const struct layout_descriptor CertificateVerify_l[] = {
	{ "Signature",               parse_vector, compile_vector, 0, TLS_VECTOR_MAX16, CERTIFICATEVERIFY_OFFSET(signature) },
	TLS_LAYOUT_DESCRIPTOR_END
};
static const struct msg_descriptor CertificateVerify_m = {
	&ClientKeyExchange_m, "Certificate Verify", CertificateVerify_l, TLS_HANDSHAKE_TYPE_CERTIFICATE_VERIFY
};

struct Finished_host {
	struct tls_compile_verify verify;
};
#define FINISHED_OFFSET(a) offsetof(struct Finished_host, a)

static const struct layout_descriptor Finished_l[] = {
	{ "Verify Data",             parse_array, compile_array, 0, TLS_ARRAY_VERIFY_LENGTH, FINISHED_OFFSET(verify) },
	TLS_LAYOUT_DESCRIPTOR_END
};
static const struct msg_descriptor Finished_m = {
	&CertificateVerify_m, "Finished", Finished_l, TLS_HANDSHAKE_TYPE_FINISHED
};

#define HANDSHAKE_MSG_DESCRIPTORS &Finished_m

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

		if (desc && desc->layouts) {
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

static gboolean tls_record_parse(struct tls_internal_state *state,
				 gboolean incoming)
{
	const guchar *bytes  = incoming ? state->common.in_buffer : state->common.out_buffer;
	gsize length         = incoming ? state->common.in_length : state->common.out_length;
	guint version;
	const gchar *version_str;
	gsize record_length;
	gboolean success = TRUE;

	debug_printf(state, "TLS MESSAGE %s\n", incoming ? "INCOMING" : "OUTGOING");

	/* Collect parser data for incoming messages */
	if (incoming)
		state->data = g_hash_table_new_full(g_str_hash, g_str_equal,
						    NULL, g_free);

	while (success && (length > 0)) {

		/* truncated header check */
		if (length < TLS_RECORD_HEADER_LENGTH) {
			SIPE_DEBUG_ERROR("tls_record_parse: too short TLS record header (%" G_GSIZE_FORMAT " bytes)",
					 length);
			success = FALSE;
			break;
		}

		/* protocol version check */
		version = lowlevel_integer_to_host(bytes + TLS_RECORD_OFFSET_VERSION, 2);
		if (version < TLS_PROTOCOL_VERSION_1_0) {
			SIPE_DEBUG_ERROR_NOFORMAT("tls_record_parse: SSL1/2/3 not supported");
			success = FALSE;
			break;
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
			success = FALSE;
			break;
		}

		/* TLS record header OK */
		debug_printf(state, "TLS %s record (%" G_GSIZE_FORMAT " bytes)\n",
			     version_str, record_length);
		state->msg_current   = (guchar *) bytes + TLS_RECORD_HEADER_LENGTH;
		state->msg_remainder = record_length - TLS_RECORD_HEADER_LENGTH;

		/* Add incoming message contents to digest contexts */
		if (incoming) {
			sipe_digest_md5_update(state->md5_context,
					       state->msg_current,
					       state->msg_remainder);
			sipe_digest_sha1_update(state->sha1_context,
						state->msg_current,
						state->msg_remainder);
		}

		switch (bytes[TLS_RECORD_OFFSET_TYPE]) {
		case TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC:
			debug_print(state, "Change Cipher Spec\n");
			if (incoming) state->encrypted = TRUE;
			break;

		case TLS_RECORD_TYPE_HANDSHAKE:
			if (incoming && state->encrypted) {
				debug_print(state, "Encrypted handshake message\n");
				debug_hex(state, 0);
			} else {
				success = handshake_parse(state);
			}
			break;

		default:
			debug_print(state, "Unsupported TLS message\n");
			debug_hex(state, 0);
			break;
		}

		/* next fragment */
		bytes  += record_length;
		length -= record_length;
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
static void compile_tls_record(struct tls_internal_state *state,
			       ...)
{
	gsize total_size = 0;
	guchar *current;
	va_list ap;

	/* calculate message size */
	va_start(ap, state);
	while (1) {
		const struct tls_compiled_message *msg = va_arg(ap, struct tls_compiled_message *);
		if (!msg) break;
		total_size += msg->size;
	}
	va_end(ap);

	SIPE_DEBUG_INFO("compile_tls_record: total size %" G_GSIZE_FORMAT,
			total_size);

	state->common.out_buffer = current = g_malloc(total_size + TLS_RECORD_HEADER_LENGTH);
	state->common.out_length = total_size + TLS_RECORD_HEADER_LENGTH;

	/* add TLS record header */
	current[TLS_RECORD_OFFSET_TYPE] = TLS_RECORD_TYPE_HANDSHAKE;
	lowlevel_integer_to_tls(current + TLS_RECORD_OFFSET_VERSION, 2,
				TLS_PROTOCOL_VERSION_1_0);
	lowlevel_integer_to_tls(current + TLS_RECORD_OFFSET_LENGTH, 2,
				total_size);
	current += TLS_RECORD_HEADER_LENGTH;

	/* copy messages */
	va_start(ap, state);
	while (1) {
		const struct tls_compiled_message *msg = va_arg(ap, struct tls_compiled_message *);
		if (!msg) break;

		memcpy(current, msg->data, msg->size);
		current += msg->size;
	}
	va_end(ap);
}

static void compile_encrypted_tls_record(struct tls_internal_state *state,
					 const struct tls_compiled_message *msg)
{
	guchar *plaintext;
	gsize plaintext_length;
	guchar *mac;
	gsize mac_length;
	guchar *message;
	guchar *encrypted;
	gsize encrypted_length;

	/* Create plaintext TLS record */
	compile_tls_record(state, msg, NULL);
	plaintext        = state->common.out_buffer;
	plaintext_length = state->common.out_length;
	if (plaintext_length == 0) /* make Coverity happy */
		return;

	/* Prepare encryption buffer */
	encrypted_length = plaintext_length + state->mac_length;
	SIPE_DEBUG_INFO("compile_encrypted_tls_record: total size %" G_GSIZE_FORMAT,
			encrypted_length - TLS_RECORD_HEADER_LENGTH);
	message          = g_malloc(encrypted_length);
	memcpy(message, plaintext, plaintext_length);
	lowlevel_integer_to_tls(message + TLS_RECORD_OFFSET_LENGTH, 2,
				encrypted_length - TLS_RECORD_HEADER_LENGTH);

	/*
	 * Calculate MAC
	 *
	 * HMAC_hash(client_write_mac_secret,
	 *           sequence_number + type + version + length + fragment)
	 *                             \---  == original TLS record  ---/
	 */
	mac_length = sizeof(guint64) + plaintext_length;
	mac        = g_malloc(mac_length);
	lowlevel_integer_to_tls(mac,
				sizeof(guint64),
				state->sequence_number++);
	memcpy(mac + sizeof(guint64), plaintext, plaintext_length);
	g_free(plaintext);
	state->mac_func(state->client_write_mac_secret,
			state->mac_length,
			mac,
			mac_length,
			message + plaintext_length);
	g_free(mac);

	/* Encrypt message + MAC */
	encrypted = g_malloc(encrypted_length);
	memcpy(encrypted, message, TLS_RECORD_HEADER_LENGTH);
	sipe_crypt_tls_stream(state->cipher_context,
			      message + TLS_RECORD_HEADER_LENGTH,
			      encrypted_length - TLS_RECORD_HEADER_LENGTH,
			      encrypted + TLS_RECORD_HEADER_LENGTH);
	g_free(message);

	/* swap buffers */
	state->common.out_buffer = encrypted;
	state->common.out_length = encrypted_length;
}

static struct tls_compiled_message *compile_handshake_msg(struct tls_internal_state *state,
							  const struct msg_descriptor *desc,
							  gpointer data,
							  gsize size)
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
	gsize total_size = sizeof(struct tls_compiled_message) +
		size + TLS_HANDSHAKE_HEADER_LENGTH;
	struct tls_compiled_message *msg = g_malloc(total_size);
	guchar *handshake = msg->data;
	const struct layout_descriptor *ldesc = desc->layouts;
	gsize length;

	SIPE_DEBUG_INFO("compile_handshake_msg: buffer size %" G_GSIZE_FORMAT,
			total_size);

	/* add TLS handshake header */
	handshake[TLS_HANDSHAKE_OFFSET_TYPE] = desc->type;
	state->msg_current = handshake  + TLS_HANDSHAKE_HEADER_LENGTH;

	while (TLS_LAYOUT_IS_VALID(ldesc)) {
		/*
		 * Avoid "cast increases required alignment" errors
		 *
		 * (void *) tells the compiler that we know what we're
		 * doing, i.e. we know that the calculated address
		 * points to correctly aligned data.
		 */
		ldesc->compiler(state, ldesc,
				(void *) ((guchar *) data + ldesc->offset));
		ldesc++;
	}

	length = state->msg_current - handshake - TLS_HANDSHAKE_HEADER_LENGTH;
	lowlevel_integer_to_tls(handshake + TLS_HANDSHAKE_OFFSET_LENGTH,
				3, length);
	SIPE_DEBUG_INFO("compile_handshake_msg: (%d)%s, size %" G_GSIZE_FORMAT,
			desc->type, desc->description, length);

	msg->size = length + TLS_HANDSHAKE_HEADER_LENGTH;

	/* update digest contexts */
	sipe_digest_md5_update(state->md5_context, handshake, msg->size);
	sipe_digest_sha1_update(state->sha1_context, handshake, msg->size);

	return(msg);
}

/*
 * Specific TLS data verficiation & message compilers
 */
static struct tls_compiled_message *tls_client_certificate(struct tls_internal_state *state)
{
	struct Certificate_host *certificate;
	gsize certificate_length = sipe_cert_crypto_raw_length(state->certificate);
	struct tls_compiled_message *msg;

	/* setup our response */
	/* Client Certificate is VECTOR_MAX24 of VECTOR_MAX24s */
	certificate = g_malloc0(sizeof(struct Certificate_host) + 3 +
				certificate_length);
	certificate->certificate.elements = certificate_length + 3;
	lowlevel_integer_to_tls((guchar *) certificate->certificate.placeholder, 3,
				certificate_length);
	memcpy((guchar *) certificate->certificate.placeholder + 3,
	       sipe_cert_crypto_raw(state->certificate),
	       certificate_length);

	msg = compile_handshake_msg(state, &Certificate_m, certificate,
				    sizeof(struct Certificate_host) + certificate_length + 3);
	g_free(certificate);

	return(msg);
}

static gboolean check_cipher_suite(struct tls_internal_state *state)
{
	struct tls_parsed_integer *cipher_suite = g_hash_table_lookup(state->data,
								      "CipherSuite");
	const gchar *label = NULL;

	if (!cipher_suite) {
		SIPE_DEBUG_ERROR_NOFORMAT("check_cipher_suite: server didn't specify the cipher suite");
		return(FALSE);
	}

	switch (cipher_suite->value) {
	case TLS_RSA_EXPORT_WITH_RC4_40_MD5:
		state->mac_length = SIPE_DIGEST_HMAC_MD5_LENGTH;
		state->key_length = 40 / 8;
		state->mac_func   = sipe_digest_hmac_md5;
		label             = "MD5";
		state->common.algorithm = SIPE_TLS_DIGEST_ALGORITHM_MD5;
		break;

	case TLS_RSA_WITH_RC4_128_MD5:
		state->mac_length = SIPE_DIGEST_HMAC_MD5_LENGTH;
		state->key_length = 128 / 8;
		state->mac_func   = sipe_digest_hmac_md5;
		label             = "MD5";
		state->common.algorithm = SIPE_TLS_DIGEST_ALGORITHM_MD5;
		break;

	case TLS_RSA_WITH_RC4_128_SHA:
		state->mac_length = SIPE_DIGEST_HMAC_SHA1_LENGTH;
		state->key_length = 128 / 8;
		state->mac_func   = sipe_digest_hmac_sha1;
		label             = "SHA-1";
		state->common.algorithm = SIPE_TLS_DIGEST_ALGORITHM_SHA1;
		break;

	default:
		SIPE_DEBUG_ERROR("check_cipher_suite: unsupported cipher suite %d",
				 cipher_suite->value);
		break;
	}

	if (label)
		SIPE_DEBUG_INFO("check_cipher_suite: KEY(stream cipher RC4) %" G_GSIZE_FORMAT ", MAC(%s) %" G_GSIZE_FORMAT,
				state->key_length, label, state->mac_length);

	return(label != NULL);
}

static void tls_calculate_secrets(struct tls_internal_state *state)
{
	gsize length = 2 * (state->mac_length + state->key_length);
	guchar *random;

	/* Generate pre-master secret */
	sipe_tls_fill_random(&state->pre_master_secret,
			     TLS_ARRAY_MASTER_SECRET_LENGTH * 8); /* bits */
	lowlevel_integer_to_tls(state->pre_master_secret.buffer, 2,
				TLS_PROTOCOL_VERSION_1_0);
	debug_secrets(state, "tls_calculate_secrets: pre-master secret",
		      state->pre_master_secret.buffer,
		      state->pre_master_secret.length);

	/*
	 * Calculate master secret
	 *
	 * master_secret = PRF(pre_master_secret,
	 *                     "master secret",
	 *                     ClientHello.random + ServerHello.random)
	 */
	random = g_malloc(TLS_ARRAY_RANDOM_LENGTH * 2);
	memcpy(random,
	       state->client_random.buffer,
	       TLS_ARRAY_RANDOM_LENGTH);
	memcpy(random + TLS_ARRAY_RANDOM_LENGTH,
	       state->server_random.buffer,
	       TLS_ARRAY_RANDOM_LENGTH);
	state->master_secret = sipe_tls_prf(state,
					    state->pre_master_secret.buffer,
					    state->pre_master_secret.length,
					    (guchar *) "master secret",
					    13,
					    random,
					    TLS_ARRAY_RANDOM_LENGTH * 2,
					    TLS_ARRAY_MASTER_SECRET_LENGTH);
	debug_secrets(state, "tls_calculate_secrets: master secret    ",
		      state->master_secret,
		      TLS_ARRAY_MASTER_SECRET_LENGTH);

	/*
	 * Calculate session key material
	 *
	 * key_block = PRF(master_secret,
	 *                 "key expansion",
	 *                 ServerHello.random + ClientHello.random)
	 */
	SIPE_DEBUG_INFO("tls_calculate_secrets: key_block length %" G_GSIZE_FORMAT,
			length);
	memcpy(random,
	       state->server_random.buffer,
	       TLS_ARRAY_RANDOM_LENGTH);
	memcpy(random + TLS_ARRAY_RANDOM_LENGTH,
	       state->client_random.buffer,
	       TLS_ARRAY_RANDOM_LENGTH);
	state->key_block = sipe_tls_prf(state,
					state->master_secret,
					TLS_ARRAY_MASTER_SECRET_LENGTH,
					(guchar *) "key expansion",
					13,
					random,
					TLS_ARRAY_RANDOM_LENGTH * 2,
					length);
	g_free(random);
	debug_secrets(state, "tls_calculate_secrets: key block        ",
		      state->key_block, length);

	/* partition key block */
	state->client_write_mac_secret = state->key_block;
	state->server_write_mac_secret = state->key_block + state->mac_length;
	state->client_write_secret     = state->key_block + 2 * state->mac_length;
	state->server_write_secret     = state->key_block + 2 * state->mac_length + state->key_length;

	/* initialize cipher context */
	state->cipher_context = sipe_crypt_tls_start(state->client_write_secret,
						     state->key_length);
}

#if 0 /* NOT NEEDED? */
/* signing */
static guchar *tls_pkcs1_private_padding(SIPE_UNUSED_PARAMETER struct tls_internal_state *state,
					 const guchar *data,
					 gsize data_length,
					 gsize buffer_length)
{
	gsize pad_length;
	guchar *pad_buffer;

	if (data_length + 3 > buffer_length) ||
	    (buffer_length == 0)) /* this is dead code, but makes Coverity happy */)
		return(NULL);

	pad_length = buffer_length - data_length - 3;
	pad_buffer = g_malloc(buffer_length);

	/* PKCS1 private key block padding */
	pad_buffer[0]                       = 0; /* +1 */
	pad_buffer[1]                       = 1; /* +2 */
	memset(pad_buffer + 2,              0xFF, pad_length);
	pad_buffer[2 + pad_length]          = 0; /* +3 */
	memcpy(pad_buffer + 3 + pad_length, data, data_length);

#ifdef __SIPE_TLS_CRYPTO_DEBUG
	debug_secrets(state, "tls_pkcs1_private_padding:              ",
		      pad_buffer, buffer_length);
#endif

	return(pad_buffer);
}
#endif

/* encryption */
static guchar *tls_pkcs1_public_padding(SIPE_UNUSED_PARAMETER struct tls_internal_state *state,
					const guchar *data,
					gsize data_length,
					gsize buffer_length)
{
	gsize pad_length, random_count;
	guchar *pad_buffer, *random;

	if ((data_length + 3 > buffer_length) ||
	    (buffer_length == 0)) /* this is dead code, but makes Coverity happy */
		return(NULL);

	pad_length = buffer_length - data_length - 3;
	pad_buffer = g_malloc(buffer_length);

	/* PKCS1 public key block padding */
	pad_buffer[0]                       = 0; /* +1 */
	pad_buffer[1]                       = 2; /* +2 */
	for (random = pad_buffer + 2, random_count = pad_length;
	     random_count > 0;
	     random_count--) {
		guchar byte;
		/* non-zero random byte */
		while ((byte = rand() & 0xFF) == 0);
		*random++ = byte;
	}
	pad_buffer[2 + pad_length]          = 0; /* +3 */
	memcpy(pad_buffer + 3 + pad_length, data, data_length);

#ifdef __SIPE_TLS_CRYPTO_DEBUG
	debug_secrets(state, "tls_pkcs1_private_padding:              ",
		      pad_buffer, buffer_length);
#endif

	return(pad_buffer);
}

static struct tls_compiled_message *tls_client_key_exchange(struct tls_internal_state *state)
{
	struct tls_parsed_array *server_random;
	struct tls_parsed_array *server_certificate;
	struct ClientKeyExchange_host *exchange;
	gsize server_certificate_length;
	guchar *padded;
	struct tls_compiled_message *msg;

	/* check for required data fields */
	if (!check_cipher_suite(state))
		return(NULL);
	server_random = g_hash_table_lookup(state->data, "Random");
	if (!server_random) {
		SIPE_DEBUG_ERROR_NOFORMAT("tls_client_key_exchange: no server random");
		return(NULL);
	}
	server_certificate = g_hash_table_lookup(state->data, "Certificate");
	/* Server Certificate is VECTOR_MAX24 of VECTOR_MAX24s */
	if (!server_certificate || (server_certificate->length < 3)) {
		SIPE_DEBUG_ERROR_NOFORMAT("tls_client_key_exchange: no server certificate");
		return(FALSE);
	}
	SIPE_DEBUG_INFO("tls_client_key_exchange: server certificate list %" G_GSIZE_FORMAT" bytes",
			server_certificate->length);
	/* first certificate is the server certificate */
	server_certificate_length = lowlevel_integer_to_host(server_certificate->data,
							     3);
	SIPE_DEBUG_INFO("tls_client_key_exchange: server certificate %" G_GSIZE_FORMAT" bytes",
			server_certificate_length);
	if ((server_certificate_length + 3) > server_certificate->length) {
		SIPE_DEBUG_ERROR_NOFORMAT("tls_client_key_exchange: truncated server certificate");
	}
	state->server_certificate = sipe_cert_crypto_import(server_certificate->data + 3,
							    server_certificate_length);
	if (!state->server_certificate) {
		SIPE_DEBUG_ERROR_NOFORMAT("tls_client_key_exchange: corrupted server certificate");
		return(FALSE);
	}
	/* server public key modulus length */
	server_certificate_length = sipe_cert_crypto_modulus_length(state->server_certificate);
	if (server_certificate_length < TLS_ARRAY_MASTER_SECRET_LENGTH) {
		SIPE_DEBUG_ERROR("tls_client_key_exchange: server public key strength too low (%" G_GSIZE_FORMAT ")",
				 server_certificate_length);
		return(FALSE);
	}
	SIPE_DEBUG_INFO("tls_client_key_exchange: server public key strength = %" G_GSIZE_FORMAT,
			server_certificate_length);

	/* found all the required fields */
	state->server_random.length = server_random->length;
	state->server_random.buffer = g_memdup(server_random->data,
					       server_random->length);
	tls_calculate_secrets(state);

	/* ClientKeyExchange */
	padded = tls_pkcs1_public_padding(state,
					  state->pre_master_secret.buffer,
					  state->pre_master_secret.length,
					  server_certificate_length);
	if (!padded) {
		SIPE_DEBUG_ERROR_NOFORMAT("tls_client_key_exchange: padding of pre-master secret failed");
		return(NULL);
	}
	exchange = g_malloc0(sizeof(struct ClientKeyExchange_host) +
			     server_certificate_length);
	exchange->secret.elements = server_certificate_length;
	if (!sipe_crypt_rsa_encrypt(sipe_cert_crypto_public_key(state->server_certificate),
				    server_certificate_length,
				    padded,
				    (guchar *) exchange->secret.placeholder)) {
		SIPE_DEBUG_ERROR_NOFORMAT("tls_client_key_exchange: encryption of pre-master secret failed");
		g_free(exchange);
		g_free(padded);
		return(NULL);
	}
	g_free(padded);

#ifdef __SIPE_TLS_CRYPTO_DEBUG
	debug_secrets(state, "tls_client_key_exchange: secret (encr)  ",
		      (guchar *) exchange->secret.placeholder,
		      server_certificate_length);
#endif

	msg = compile_handshake_msg(state, &ClientKeyExchange_m, exchange,
				    sizeof(struct ClientKeyExchange_host) + server_certificate_length);
	g_free(exchange);

	return(msg);
}

static struct tls_compiled_message *tls_certificate_verify(struct tls_internal_state *state)
{
	struct CertificateVerify_host *verify;
	struct tls_compiled_message *msg;
	guchar *digests = g_malloc(SIPE_DIGEST_MD5_LENGTH + SIPE_DIGEST_SHA1_LENGTH);
	guchar *signature;
	gsize length;

	/* calculate digests */
	sipe_digest_md5_end(state->md5_context, digests);
	sipe_digest_sha1_end(state->sha1_context, digests + SIPE_DIGEST_MD5_LENGTH);

	/* sign digests */
	signature = sipe_crypt_rsa_sign(sipe_cert_crypto_private_key(state->certificate),
					digests,
					SIPE_DIGEST_MD5_LENGTH + SIPE_DIGEST_SHA1_LENGTH,
					&length);
	g_free(digests);
	if (!signature) {
		SIPE_DEBUG_ERROR_NOFORMAT("tls_certificate_verify: signing of handshake digests failed");
		return(NULL);
	}

	/* CertificateVerify */
	verify = g_malloc0(sizeof(struct CertificateVerify_host) +
			   length);
	verify->signature.elements = length;
	memcpy(verify->signature.placeholder, signature, length);
	g_free(signature);

	msg = compile_handshake_msg(state, &CertificateVerify_m, verify,
				    sizeof(struct CertificateVerify_host) + length);
	g_free(verify);

	return(msg);
}

static struct tls_compiled_message *tls_client_finished(struct tls_internal_state *state)
{
	guchar *digests = g_malloc(SIPE_DIGEST_MD5_LENGTH + SIPE_DIGEST_SHA1_LENGTH);
	guchar *verify;
	struct tls_compiled_message *cmsg;
	struct Finished_host msg;

	/* calculate digests */
	sipe_digest_md5_end(state->md5_context, digests);
	sipe_digest_sha1_end(state->sha1_context, digests + SIPE_DIGEST_MD5_LENGTH);

	/*
	 * verify_data = PRF(master_secret, "client finished",
	 *                   MD5(handshake_messages) +
	 *                   SHA-1(handshake_messages)) [0..11];
	 */
	verify = sipe_tls_prf(state,
			      state->master_secret,
			      TLS_ARRAY_MASTER_SECRET_LENGTH,
			      (guchar *) "client finished",
			      15,
			      digests,
			      SIPE_DIGEST_MD5_LENGTH + SIPE_DIGEST_SHA1_LENGTH,
			      TLS_ARRAY_VERIFY_LENGTH);
	g_free(digests);
	memcpy(msg.verify.verify, verify, TLS_ARRAY_VERIFY_LENGTH);
	g_free(verify);

	cmsg = compile_handshake_msg(state, &Finished_m, &msg, sizeof(msg));

	return(cmsg);
}

/*
 * TLS state handling
 */

static gboolean tls_client_hello(struct tls_internal_state *state)
{
	guint32 now   = time(NULL);
	guint32 now_N = GUINT32_TO_BE(now);
	struct ClientHello_host msg = {
		{ TLS_PROTOCOL_VERSION_1_0 },
		{ 0, { 0 } },
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
	struct tls_compiled_message *cmsg;

	/* First 4 bytes of client_random is the current timestamp */
	sipe_tls_fill_random(&state->client_random,
			     TLS_ARRAY_RANDOM_LENGTH * 8); /* -> bits */
	memcpy(state->client_random.buffer, &now_N, sizeof(now_N));
	memcpy(msg.random.random, state->client_random.buffer,
	       TLS_ARRAY_RANDOM_LENGTH);

	cmsg = compile_handshake_msg(state, &ClientHello_m, &msg, sizeof(msg));
        compile_tls_record(state, cmsg, NULL);
	g_free(cmsg);

	if (sipe_backend_debug_enabled())
		state->debug = g_string_new("");

	state->state = TLS_HANDSHAKE_STATE_SERVER_HELLO;
	return(tls_record_parse(state, FALSE));
}

static gboolean tls_server_hello(struct tls_internal_state *state)
{
	struct tls_compiled_message *certificate = NULL;
	struct tls_compiled_message *exchange    = NULL;
	struct tls_compiled_message *verify      = NULL;
	struct tls_compiled_message *finished    = NULL;
	gboolean success = FALSE;

	if (!tls_record_parse(state, TRUE))
		return(FALSE);

	if (((certificate = tls_client_certificate(state))  != NULL) &&
	    ((exchange    = tls_client_key_exchange(state)) != NULL) &&
	    ((verify      = tls_certificate_verify(state))  != NULL) &&
	    ((finished    = tls_client_finished(state))     != NULL)) {

		/* Part 1 */
		compile_tls_record(state, certificate, exchange, verify, NULL);

		success = tls_record_parse(state, FALSE);
		if (success) {
			guchar *part1      = state->common.out_buffer;
			gsize part1_length = state->common.out_length;
			guchar *part3;
			gsize part3_length;
			guchar *merged;
			gsize length;
			/* ChangeCipherSpec is always the same */
			static const guchar part2[] = {
				TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC,
				(TLS_PROTOCOL_VERSION_1_0 >> 8) & 0xFF,
				TLS_PROTOCOL_VERSION_1_0 & 0xFF,
				0x00, 0x01, /* length: 1 byte        */
				0x01        /* change_cipher_spec(1) */
			};

			state->common.out_buffer = NULL;

			/* Part 3 - this is the first encrypted record */
			compile_encrypted_tls_record(state, finished);
			part3        = state->common.out_buffer;
			part3_length = state->common.out_length;

				/* merge TLS records */
			length = part1_length + sizeof(part2) + part3_length;
			merged = g_malloc(length);

			memcpy(merged,                                part1, part1_length);
			memcpy(merged + part1_length,                 part2, sizeof(part2));
			memcpy(merged + part1_length + sizeof(part2), part3, part3_length);
			g_free(part3);
			g_free(part1);

			/* replace output buffer with merged message */
			state->common.out_buffer = merged;
			state->common.out_length = length;

			state->state = TLS_HANDSHAKE_STATE_FINISHED;
		}
	}

	g_free(finished);
	g_free(verify);
	g_free(exchange);
	g_free(certificate);
	free_parse_data(state);

	return(success);
}

static gboolean tls_finished(struct tls_internal_state *state)
{
	guchar *random;

	if (!tls_record_parse(state, TRUE))
		return(FALSE);

	/* we don't need the data */
	free_parse_data(state);

	/*
	 * Calculate session keys [MS-SIPAE section 3.2.5.1]
	 *
	 * key_material = PRF (master_secret,
	 *                     "client EAP encryption",
	 *                     ClientHello.random + ServerHello.random)[128]
	 *              = 4 x 32 Bytes
	 *
	 * client key = key_material[3rd 32 Bytes]
	 * server key = key_material[4th 32 Bytes]
	 */
	random = g_malloc(TLS_ARRAY_RANDOM_LENGTH * 2);
	memcpy(random,
	       state->client_random.buffer,
	       TLS_ARRAY_RANDOM_LENGTH);
	memcpy(random + TLS_ARRAY_RANDOM_LENGTH,
	       state->server_random.buffer,
	       TLS_ARRAY_RANDOM_LENGTH);
	state->tls_dsk_key_block = sipe_tls_prf(state,
						state->master_secret,
						TLS_ARRAY_MASTER_SECRET_LENGTH,
						(guchar *) "client EAP encryption",
						21,
						random,
						TLS_ARRAY_RANDOM_LENGTH * 2,
						4 * 32);
	g_free(random);

#ifdef __SIPE_TLS_CRYPTO_DEBUG
	debug_secrets(state, "tls_finished: TLS-DSK key block         ",
		      state->tls_dsk_key_block, 4 * 32);
#endif

	state->common.client_key = state->tls_dsk_key_block + 2 * 32;
	state->common.server_key = state->tls_dsk_key_block + 3 * 32;
	state->common.key_length = 32;

	debug_secrets(state, "tls_finished: TLS-DSK client key        ",
		      state->common.client_key,
		      state->common.key_length);
	debug_secrets(state, "tls_finished: TLS-DSK server key        ",
		      state->common.server_key,
		      state->common.key_length);

	state->common.out_buffer = NULL;
	state->common.out_length = 0;
	state->state             = TLS_HANDSHAKE_STATE_COMPLETED;

	return(TRUE);
}

/*
 * TLS public API
 */

struct sipe_tls_state *sipe_tls_start(gpointer certificate)
{
	struct tls_internal_state *state;

	if (!certificate)
		return(NULL);

	state = g_new0(struct tls_internal_state, 1);
	state->certificate  = certificate;
	state->state        = TLS_HANDSHAKE_STATE_START;
	state->md5_context  = sipe_digest_md5_start();
	state->sha1_context = sipe_digest_sha1_start();
	state->common.algorithm = SIPE_TLS_DIGEST_ALGORITHM_NONE;

	return((struct sipe_tls_state *) state);
}

gboolean sipe_tls_next(struct sipe_tls_state *state)
{
	/* Avoid "cast increases required alignment" errors */
	struct tls_internal_state *internal = (void *) state;
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

guint sipe_tls_expires(struct sipe_tls_state *state)
{
	/* Avoid "cast increases required alignment" errors */
	struct tls_internal_state *internal = (void *) state;

	if (!state)
		return(0);

	return(sipe_cert_crypto_expires(internal->certificate));
}

void sipe_tls_free(struct sipe_tls_state *state)
{
	if (state) {
		/* Avoid "cast increases required alignment" errors */
		struct tls_internal_state *internal = (void *) state;

		free_parse_data(internal);
		if (internal->debug)
			g_string_free(internal->debug, TRUE);
		g_free(internal->tls_dsk_key_block);
		g_free(internal->key_block);
		g_free(internal->master_secret);
		sipe_tls_free_random(&internal->pre_master_secret);
		sipe_tls_free_random(&internal->client_random);
		sipe_tls_free_random(&internal->server_random);
		if (internal->cipher_context)
			sipe_crypt_tls_destroy(internal->cipher_context);
		if (internal->md5_context)
			sipe_digest_md5_destroy(internal->md5_context);
		if (internal->sha1_context)
			sipe_digest_sha1_destroy(internal->sha1_context);
		sipe_cert_crypto_destroy(internal->server_certificate);
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
