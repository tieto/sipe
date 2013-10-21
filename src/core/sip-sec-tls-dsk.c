/**
 * @file sip-sec-tls-dsk.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-2013 SIPE Project <http://sipe.sourceforge.net/>
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
 * Specification references:
 *
 *   - [MS-SIPAE]:    http://msdn.microsoft.com/en-us/library/cc431510.aspx
 *   - [MS-OCAUTHWS]: http://msdn.microsoft.com/en-us/library/ff595592.aspx
 *   - MS Tech-Ed Europe 2010 "UNC310: Microsoft Lync 2010 Technology Explained"
 *     http://ecn.channel9.msdn.com/o9/te/Europe/2010/pptx/unc310.pptx
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include <glib.h>

#include "sipe-common.h"
#include "sip-sec.h"
#include "sip-sec-mech.h"
#include "sip-sec-tls-dsk.h"
#include "sipe-backend.h"
#include "sipe-digest.h"
#include "sipe-tls.h"

/* Security context for TLS-DSK */
typedef struct _context_tls_dsk {
	struct sip_sec_context common;
	struct sipe_tls_state *state;
	enum sipe_tls_digest_algorithm algorithm;
	guchar *client_key;
	guchar *server_key;
	gsize key_length;
} *context_tls_dsk;

/* sip-sec-mech.h API implementation for TLS-DSK */

static gboolean
sip_sec_acquire_cred__tls_dsk(SipSecContext context,
			      SIPE_UNUSED_PARAMETER const gchar *domain,
			      SIPE_UNUSED_PARAMETER const gchar *username,
			      const gchar *password)
{
	context_tls_dsk ctx = (context_tls_dsk) context;

	return((ctx->state = sipe_tls_start((gpointer) password)) != NULL);
}

static gboolean
sip_sec_init_sec_context__tls_dsk(SipSecContext context,
				  SipSecBuffer in_buff,
				  SipSecBuffer *out_buff,
				  SIPE_UNUSED_PARAMETER const gchar *service_name)
{
	context_tls_dsk ctx = (context_tls_dsk) context;
	struct sipe_tls_state *state = ctx->state;

	state->in_buffer = in_buff.value;
	state->in_length = in_buff.length;

	if (sipe_tls_next(state)) {
		if ((state->algorithm != SIPE_TLS_DIGEST_ALGORITHM_NONE) &&
		    state->client_key && state->server_key) {
			/* Authentication is completed */
			context->flags |= SIP_SEC_FLAG_COMMON_READY;

			/* copy key pair */
			ctx->algorithm  = state->algorithm;
			ctx->key_length = state->key_length;
			ctx->client_key = g_memdup(state->client_key,
						   state->key_length);
			ctx->server_key = g_memdup(state->server_key,
						   state->key_length);

			/* [MS-SIPAE] Section 3.2.2 Timers
			 *
			 * ... For an SA established using the TLS-DSK
			 * authentication protocol, the client MUST
			 * retrieve the expiration time of its certificate.
			 * The expiration timer value is the lesser of the
			 * interval to the certificate expiration and eight
			 * hours, ...
			 */
			ctx->common.expires = sipe_tls_expires(state);
			if (ctx->common.expires > (8 * 60 * 60))
				ctx->common.expires = 8 * 60 * 60;

			SIPE_DEBUG_INFO("sip_sec_init_sec_context__tls_dsk: handshake completed, algorithm %d, key length %" G_GSIZE_FORMAT ", expires %d",
					ctx->algorithm, ctx->key_length, ctx->common.expires);

			sipe_tls_free(state);
			ctx->state = NULL;
		} else {
			out_buff->value  = state->out_buffer;
			out_buff->length = state->out_length;
			/* we take ownership of the buffer */
			state->out_buffer = NULL;
		}
	} else {
		sipe_tls_free(state);
		ctx->state = NULL;
	}

	return(((context->flags & SIP_SEC_FLAG_COMMON_READY) ||
		ctx->state));
}

static gboolean
sip_sec_make_signature__tls_dsk(SipSecContext context,
				const gchar *message,
				SipSecBuffer *signature)
{
	context_tls_dsk ctx = (context_tls_dsk) context;
	gboolean result = FALSE;

	switch (ctx->algorithm) {
	case SIPE_TLS_DIGEST_ALGORITHM_MD5:
		signature->length = SIPE_DIGEST_HMAC_MD5_LENGTH;
		signature->value  = g_malloc0(signature->length);
		sipe_digest_hmac_md5(ctx->client_key, ctx->key_length,
				     (guchar *) message, strlen(message),
				     signature->value);
		result = TRUE;
		break;

	case SIPE_TLS_DIGEST_ALGORITHM_SHA1:
		signature->length = SIPE_DIGEST_HMAC_SHA1_LENGTH;
		signature->value  = g_malloc0(signature->length);
		sipe_digest_hmac_sha1(ctx->client_key, ctx->key_length,
				      (guchar *) message, strlen(message),
				      signature->value);
		result = TRUE;
		break;

	default:
		/* this should not happen */
		break;
	}

	return(result);
}

static gboolean
sip_sec_verify_signature__tls_dsk(SipSecContext context,
				  const gchar *message,
				  SipSecBuffer signature)
{
	context_tls_dsk ctx = (context_tls_dsk) context;
	SipSecBuffer mac    = { 0, NULL };
	gboolean result     = FALSE;

	switch (ctx->algorithm) {
	case SIPE_TLS_DIGEST_ALGORITHM_MD5:
		mac.length = SIPE_DIGEST_HMAC_MD5_LENGTH;
		mac.value  = g_malloc0(mac.length);
		sipe_digest_hmac_md5(ctx->server_key, ctx->key_length,
				     (guchar *) message, strlen(message),
				     mac.value);
		break;

	case SIPE_TLS_DIGEST_ALGORITHM_SHA1:
		mac.length = SIPE_DIGEST_HMAC_SHA1_LENGTH;
		mac.value  = g_malloc0(mac.length);
		sipe_digest_hmac_sha1(ctx->server_key, ctx->key_length,
				      (guchar *) message, strlen(message),
				      mac.value);
		break;

	default:
		/* this should not happen */
		break;
	}

	if (mac.value) {
		result = memcmp(signature.value, mac.value, mac.length) == 0;
		g_free(mac.value);
	}

	return(result);
}

static void
sip_sec_destroy_sec_context__tls_dsk(SipSecContext context)
{
	context_tls_dsk ctx = (context_tls_dsk) context;

	sipe_tls_free(ctx->state);
	g_free(ctx->client_key);
	g_free(ctx->server_key);
	g_free(ctx);
}

static const gchar *
sip_sec_context_name__tls_dsk(SIPE_UNUSED_PARAMETER SipSecContext context)
{
	return("TLS-DSK");
}

SipSecContext
sip_sec_create_context__tls_dsk(SIPE_UNUSED_PARAMETER guint type)
{
	context_tls_dsk context = g_malloc0(sizeof(struct _context_tls_dsk));
	if (!context) return(NULL);

	context->common.acquire_cred_func     = sip_sec_acquire_cred__tls_dsk;
	context->common.init_context_func     = sip_sec_init_sec_context__tls_dsk;
	context->common.destroy_context_func  = sip_sec_destroy_sec_context__tls_dsk;
	context->common.make_signature_func   = sip_sec_make_signature__tls_dsk;
	context->common.verify_signature_func = sip_sec_verify_signature__tls_dsk;
	context->common.context_name_func     = sip_sec_context_name__tls_dsk;

	return((SipSecContext) context);
}

gboolean sip_sec_password__tls_dsk(void)
{
#if defined(HAVE_SSPI) || defined(HAVE_GSSAPI_GSSAPI_H)
	/*
	 * TLS-DSK authenticates with a published client certificate. This
	 * process uses Web Tickets and therefore goes through HTTP. If we
	 * have authentication schemes compiled in which allow Single Sign-On
	 * then we should allow password-less configurations.
	 */
	return(FALSE);
#else
	return(TRUE);
#endif
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
