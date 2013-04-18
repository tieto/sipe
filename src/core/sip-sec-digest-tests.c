/**
 * @file sip-sec-digest-test.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2013 SIPE Project <http://sipe.sourceforge.net/>
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
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include <glib.h>

#include "sipe-common.h"
#include "sipe-crypt.h"
#include "uuid.h"

#define SIP_SEC_DIGEST_COMPILING_TEST
static const gchar *cnonce_fixed;
#include "sip-sec-digest.c"

/*
 * Stubs
 */
gboolean sipe_backend_debug_enabled(void)
{
	return(TRUE);
}

void sipe_backend_debug_literal(sipe_debug_level level,
				const gchar *msg)
{
	printf("DEBUG(%d): %s\n", level, msg);
}

void sipe_backend_debug(sipe_debug_level level,
			const gchar *format,
			...)
{
	va_list ap;
	gchar *newformat = g_strdup_printf("DEBUG(%d): %s\n", level, format);

	va_start(ap, format);
	vprintf(newformat, ap);
	va_end(ap);

	g_free(newformat);
}

const gchar *sipe_backend_network_ip_address(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public)
{
	return(NULL);
}

char *generateUUIDfromEPID(SIPE_UNUSED_PARAMETER const gchar *epid)
{
	return(NULL);
}

char *sipe_get_epid(SIPE_UNUSED_PARAMETER const char *self_sip_uri,
		    SIPE_UNUSED_PARAMETER const char *hostname,
		    SIPE_UNUSED_PARAMETER const char *ip_address)
{
	return(NULL);
}

/*
 * Tester code
 */
#define PARSED_USERNAME 0
#define PARSED_REALM    1
#define PARSED_NONCE    2
#define PARSED_URI      3
#define PARSED_QOP      4
#define PARSED_NC       5
#define PARSED_CNONCE   6
#define PARSED_RESPONSE 7
#define PARSED_OPAQUE   8
#define PARSED_MAX      9
static void parse(const gchar *string,
		  gchar *parsed[PARSED_MAX])
{
	const gchar *header;
	const gchar *param;
	guint i;

	for (i = 0; i < PARSED_MAX; i++)
		parsed[i] = NULL;

	if (strstr(string, "Digest ") == NULL)
		return;
	header = string + 7;

	/* skip white space */
	while (*header == ' ')
		header++;

	/* start of next parameter value */
	while ((param = strchr(header, '=')) != NULL) {
		const gchar *end;

		/* parameter value type */
		param++;
		if (*param == '"') {
			/* string: xyz="..."(,) */
			end = strchr(++param, '"');
			if (!end) {
				SIPE_DEBUG_ERROR("parse: corrupted string parameter near '%s'", header);
				break;
			}
		} else {
			/* number: xyz=12345(,) */
			end = strchr(param, ',');
			if (!end) {
				/* last parameter */
				end = param + strlen(param);
			}
		}

#define COMPARE(string, index) \
	if (g_str_has_prefix(header, #string "=")) { \
		g_free(parsed[ PARSED_ ## index]);  \
		parsed[ PARSED_ ## index] = g_strndup(param, end - param); \
	} else

		COMPARE(username, USERNAME)
		COMPARE(realm, REALM)
		COMPARE(nonce, NONCE)
		COMPARE(uri, URI)
		COMPARE(qop, QOP)
		COMPARE(nc, NC)
		COMPARE(cnonce, CNONCE)
		COMPARE(response, RESPONSE)
		COMPARE(opaque, OPAQUE)
                { /* ignore */ }

		/* skip to next parameter */
		while ((*end == '"') || (*end == ',') || (*end == ' '))
			end++;
		header = end;
	}
}

static guint expected(const gchar *reference,
		      const gchar *testvalue)
{
	gchar *reference_parsed[PARSED_MAX];
	gchar *testvalue_parsed[PARSED_MAX];
	guint i;
	guint failed = 0;

	parse(reference, reference_parsed);
	parse(testvalue, testvalue_parsed);
	for (i = 0; i < PARSED_MAX; i++) {
		gchar *ref  = reference_parsed[i];
		gchar *test = testvalue_parsed[i];
		if (!sipe_strequal(ref, test) && (ref || test)) {
			SIPE_DEBUG_ERROR("FAILED(%d): expected '%s' got '%s'",
					 i, ref, test);
			failed = 1;
		}
		g_free(test);
		g_free(ref);
	}
	SIPE_DEBUG_INFO("Response:  %s", testvalue);

	return(failed);
}

int main(SIPE_UNUSED_PARAMETER int argc, SIPE_UNUSED_PARAMETER char *argv[])
{
	guint failed = 0;

	/* Initialization for crypto backend (test mode) */
	sipe_crypto_init(FALSE);

#define RUNTEST(_user, _password, _cnonce, _header, _method, _uri, _reference) \
	{								\
		struct sipe_core_private sipe_private;			\
		gchar *response;					\
		printf("\n");						\
		sipe_private.authuser = _user ;				\
		sipe_private.password = _password ;			\
		cnonce_fixed          = _cnonce;			\
		response = sip_sec_digest_authorization(&sipe_private, _header, _method, _uri); \
		failed  += expected(_reference, response);		\
		g_free(response); \
	}

	/*
	 * RFC-2617 Section 3.5
	 */
	RUNTEST("Mufasa", "Circle Of Life", "0a4f113b",
		"realm=\"testrealm@host.com\", qop=\"auth,auth-int\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
		"GET",
		"/dir/index.html",
		"Digest username=\"Mufasa\", realm=\"testrealm@host.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", uri=\"/dir/index.html\", qop=auth, nc=00000001, cnonce=\"0a4f113b\", response=\"6629fae49393a05397450978507c4ef1\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");

	/*
	 * http://www.ntu.edu.sg/home/ehchua/programming/webprogramming/HTTP_Authentication.html
	 */
	RUNTEST("bob", "bob", "1672b410efa182c061c2f0a58acaa17d",
		/*
		 * The Server challenge shown does not correspond to the
		 * Client response. Use realm/nonce from the Client response.
		 *
		 * "realm=\"Members only\", nonce=\"LHOKe1l2BAA=5c373ae0d933a0bb6321125a56a2fcdb6fd7c93b\", algorithm=MD5, qop=\"auth\"",
		 */
		"realm=\"members only\", nonce=\"5UImQA==3d76b2ab859e1770ec60ed285ec68a3e63028461\", algorithm=MD5, qop=\"auth\"",
		"GET",
		"/digest_auth/test.html",
		"Digest username=\"bob\", realm=\"members only\", qop=\"auth\", algorithm=\"MD5\", uri=\"/digest_auth/test.html\", nonce=\"5UImQA==3d76b2ab859e1770ec60ed285ec68a3e63028461\", nc=00000001, cnonce=\"1672b410efa182c061c2f0a58acaa17d\", response=\"3d9ebe6b9534a7135a3fde59a5a72668\"");

	return(failed);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
