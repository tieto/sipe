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

#include <string.h>

#include <glib.h>

#include "sip-sec-digest.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-digest.h"
#include "sipe-utils.h"

/*
 * Calculate a session key for HTTP MD5 Digest authentication (RFC 2617)
 */
static gchar *digest_opaque(const gchar *authuser,
			    const gchar *password,
			    const gchar *realm)
{
	gchar *string = g_strdup_printf("%s:%s:%s", authuser, realm, password);
	guchar digest[SIPE_DIGEST_MD5_LENGTH];

	sipe_digest_md5((guchar *)string, strlen(string), digest);
	g_free(string);
	return(buff_to_hex_str(digest, sizeof(digest)));
}

/*
 * Calculate a response for HTTP MD5 Digest authentication (RFC 2617)
 */
static gchar *digest_response(const gchar *opaque,
			      const gchar *nonce,
			      const gchar *method,
			      const gchar *target)
{
	gchar *string = g_strdup_printf("%s:%s", method, target);
	gchar *hex_digest;
	guchar digest[SIPE_DIGEST_MD5_LENGTH];

	sipe_digest_md5((guchar *)string, strlen(string), digest);
	g_free(string);

	hex_digest = buff_to_hex_str(digest, sizeof(digest));
	string = g_strdup_printf("%s:%s:%s", opaque, nonce, hex_digest);
	g_free(hex_digest);

	sipe_digest_md5((guchar *)string, strlen(string), digest);
	g_free(string);

	return(buff_to_hex_str(digest, sizeof(digest)));
}

gchar *sip_sec_digest_authorization(struct sipe_core_private *sipe_private,
				    const gchar *header,
				    const gchar *method,
				    const gchar *target)
{
	const gchar *param;
	gchar *nonce = NULL;
	gchar *realm = NULL;
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
		gchar *opaque = digest_opaque(authuser,
					      sipe_private->password,
					      realm);
		gchar *response = digest_response(opaque,
						  nonce,
						  method,
						  target);
		g_free(opaque);

		authorization = g_strdup_printf("Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", nc=\"1\", response=\"%s\"",
						authuser,
						realm,
						nonce,
						target,
						response);
		g_free(response);

	} else
		SIPE_DEBUG_ERROR_NOFORMAT("sip_sec_digest_authorization: no digest parameters found. Giving up.");

	g_free(realm);
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
