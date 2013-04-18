/**
 * @file sip-sec-digest.c
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
#include <string.h>

#include <glib.h>

#include "sip-sec-digest.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-digest.h"
#include "sipe-utils.h"

/*
 * Calculate a response for HTTP MD5 Digest authentication (RFC 2617)
 */
static gchar *digest_HA1(const gchar *user,
			 const gchar *realm,
			 const gchar *password)
{
	/* H(A1): H(user ":" realm ":" password) */
	gchar *string = g_strdup_printf("%s:%s:%s", user, realm, password);
	gchar *HA1;
	guchar digest[SIPE_DIGEST_MD5_LENGTH];
	sipe_digest_md5((guchar *)string, strlen(string), digest);
	g_free(string);

	/* Result: LOWER(HEXSTRING(H(A1))) */
	string = buff_to_hex_str(digest, sizeof(digest));
	HA1 = g_ascii_strdown(string, -1);
	g_free(string);
	return(HA1);
}

static gchar *digest_HA2(const gchar *method,
			 const gchar *target)
{
	/* H(A2): H(method ":" target) */
	gchar *string = g_strdup_printf("%s:%s", method, target);
	gchar *HA2;
	guchar digest[SIPE_DIGEST_MD5_LENGTH];
	sipe_digest_md5((guchar *)string, strlen(string), digest);
	g_free(string);

	/* Result: LOWER(HEXSTRING(H(A1))) */
	string = buff_to_hex_str(digest, sizeof(digest));
	HA2 = g_ascii_strdown(string, -1);
	g_free(string);
	return(HA2);
}

static gchar *generate_cnonce(void)
{
#ifdef SIP_SEC_DIGEST_COMPILING_TEST
	return(g_strdup(cnonce_fixed));
#else
	return(g_strdup_printf("%04x%04x", rand() & 0xFFFF, rand() & 0xFFFF));
#endif
}

static gchar *digest_response(const gchar *user,
			      const gchar *realm,
			      const gchar *password,
			      const gchar *nonce,
			      const gchar *nc,
			      const gchar *cnonce,
			      const gchar *qop,
			      const gchar *method,
			      const gchar *target)
{
	gchar *HA1 = digest_HA1(user, realm, password);
	gchar *HA2 = digest_HA2(method, target);
	gchar *string, *Digest;
	guchar digest[SIPE_DIGEST_MD5_LENGTH];

#ifdef SIP_SEC_DIGEST_COMPILING_TEST
	SIPE_DEBUG_INFO("HA1 %s", HA1);
	SIPE_DEBUG_INFO("HA2 %s", HA2);
#endif

	/* Digest: H(H(A1) ":" nonce ":" nc ":" cnonce ":" qop ":" H(A2) */
	string = g_strdup_printf("%s:%s:%s:%s:%s:%s", HA1, nonce, nc, cnonce, qop, HA2);
	g_free(HA2);
	g_free(HA1);
	sipe_digest_md5((guchar *)string, strlen(string), digest);
	g_free(string);

	/* Result: LOWER(HEXSTRING(H(A1))) */
	string = buff_to_hex_str(digest, sizeof(digest));
	Digest = g_ascii_strdown(string, -1);
	g_free(string);
	return(Digest);
}

gchar *sip_sec_digest_authorization(struct sipe_core_private *sipe_private,
				    const gchar *header,
				    const gchar *method,
				    const gchar *target)
{
	const gchar *param;
	gchar *nonce  = NULL;
	gchar *opaque = NULL;
	gchar *realm  = NULL;
	gchar *authorization = NULL;

	/* sanity checks */
	if (!sipe_private->password)
		return(NULL);

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
				SIPE_DEBUG_ERROR("sip_sec_digest_authorization: corrupted string parameter near '%s'", header);
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

		/* parameter type */
		if        (g_str_has_prefix(header, "nonce=\"")) {
			g_free(nonce);
			nonce = g_strndup(param, end - param);
		} else if (g_str_has_prefix(header, "opaque=\"")) {
			g_free(opaque);
			opaque = g_strndup(param, end - param);
		} else if (g_str_has_prefix(header, "realm=\"")) {
			g_free(realm);
			realm = g_strndup(param, end - param);
		}

		/* skip to next parameter */
		while ((*end == '"') || (*end == ',') || (*end == ' '))
			end++;
		header = end;
	}

	if (nonce && realm) {
		const gchar *authuser = sipe_private->authuser ? sipe_private->authuser : sipe_private->username;
		const gchar *nc       = "00000001";
		gchar *cnonce         = generate_cnonce();
		gchar *opt_opaque     = opaque ? g_strdup_printf("opaque=\"%s\", ", opaque) : g_strdup("");
		gchar *response = digest_response(authuser,
						  realm,
						  sipe_private->password,
						  nonce,
						  nc,
						  cnonce,
						  "auth",
						  method,
						  target);

#ifdef SIP_SEC_DIGEST_COMPILING_TEST
		SIPE_DEBUG_INFO("RES %s", response);
#endif

		authorization = g_strdup_printf("Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", qop=auth, nc=%s, cnonce=\"%s\", %sresponse=\"%s\"",
						authuser,
						realm,
						nonce,
						target,
						nc,
						cnonce,
						opt_opaque,
						response);
		g_free(response);
		g_free(opt_opaque);
		g_free(cnonce);

	} else
		SIPE_DEBUG_ERROR_NOFORMAT("sip_sec_digest_authorization: no digest parameters found. Giving up.");

	g_free(realm);
	g_free(opaque);
	g_free(nonce);

	return(authorization);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
