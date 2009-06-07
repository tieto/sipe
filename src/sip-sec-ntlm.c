/**
 * @file sip-sec-ntlm.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009 pier11 <pier11@kinozal.tv>
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

#include <glib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "debug.h"
#ifdef _WIN32
#include "libc_interface.h"
#endif //_WIN32

#include "sip-sec.h"
#include "sip-sec-mech.h"
#include "sip-sec-ntlm.h"
#include "sip-ntlm.h"

char *sipe_get_host_name();

gchar *purple_base64_encode(const guchar *data, gsize len);
guchar *purple_base64_decode(const char *str, gsize *ret_len);

/* Security context for NTLM */
typedef struct _context_ntlm {
	struct sip_sec_context common;
	char* domain;
	char *username;
	char *password;
	int step;
	gchar *key;
} *context_ntlm;

static sip_uint32
sip_sec_init_sec_context_(SipSecContext context,
			  SipSecBuffer in_buff,
			  SipSecBuffer *out_buff,
			  const char *service_name)
{
	context_ntlm ctx = (context_ntlm) context;

	ctx->step++;
	if (ctx->step == 1) {
		out_buff->length = 0;
		out_buff->value = NULL;
		// same behaviour as sspi
		return SIP_SEC_I_CONTINUE_NEEDED;

	} else 	{
		gchar *ntlm_key;
		gchar *nonce;
		guint32 flags;
		gchar *input_toked_base64;
		gchar *gssapi_data;

		input_toked_base64 = purple_base64_encode(in_buff.value,
							  in_buff.length);

		nonce = g_memdup(purple_ntlm_parse_challenge(input_toked_base64, &flags), 8);
		g_free(input_toked_base64);

		gssapi_data = purple_ntlm_gen_authenticate(&ntlm_key,
							   ctx->username,
							   ctx->password,
							   sipe_get_host_name(),
							   ctx->domain,
							   nonce,
							   &flags);
		g_free(nonce);

		out_buff->value = purple_base64_decode(gssapi_data, &(out_buff->length));
		g_free(gssapi_data);

		g_free(ctx->key);
		ctx->key = ntlm_key;
		return SIP_SEC_E_OK;
	}
}

/**
 * @param message a NULL terminated string to sign
 *
 */
static sip_uint32
sip_sec_make_signature_(SipSecContext context,
			const char *message,
			SipSecBuffer *signature)
{
	gchar *signature_hex = purple_ntlm_sipe_signature_make(message,
							       ((context_ntlm) context)->key);

	hex_str_to_bytes(signature_hex, signature);
	g_free(signature_hex);

	return SIP_SEC_E_OK;
}

/**
 * @param message a NULL terminated string to check signature of
 * @return SIP_SEC_E_OK on success
 */
static sip_uint32
sip_sec_verify_signature_(SipSecContext context,
			  const char *message,
			  SipSecBuffer signature)
{
	char *signature_hex = bytes_to_hex_str(&signature);
	gchar *signature_calc = purple_ntlm_sipe_signature_make(message,
								((context_ntlm) context)->key);
	sip_uint32 res;

	if (purple_ntlm_verify_signature(signature_calc, signature_hex)) {
		res = SIP_SEC_E_OK;
	} else {
		res = SIP_SEC_E_INTERNAL_ERROR;
	}
	g_free(signature_calc);
	g_free(signature_hex);
	return(res);
}

static void
sip_sec_destroy_sec_context_(SipSecContext context)
{
	context_ntlm ctx = (context_ntlm) context;

	g_free(ctx->domain);
	g_free(ctx->username);
	g_free(ctx->password);
	g_free(ctx->key);
	g_free(ctx);
}

SipSecContext
sip_sec_acquire_cred__ntlm(const char *domain,
			   const char *username,
			   const char *password)
{
	context_ntlm context = g_malloc0(sizeof(struct _context_ntlm));
	if (!context) return(NULL);

	context->common.init_context_func     = sip_sec_init_sec_context_;
	context->common.destroy_context_func  = sip_sec_destroy_sec_context_;
	context->common.make_signature_func   = sip_sec_make_signature_;
	context->common.verify_signature_func = sip_sec_verify_signature_;
	context->domain   = strdup(domain);
	context->username = strdup(username);
	context->password = strdup(password);

	return((SipSecContext) context);
}

//@TODO refactor it somewhere to utils. Do we need compat with glib < 2.8 ?
char *sipe_get_host_name()
{
#if GLIB_CHECK_VERSION(2,8,0)
	const gchar * hostname = g_get_host_name();
#else
	static char hostname[256];
	int ret = gethostname(hostname, sizeof(hostname));
	hostname[sizeof(hostname) - 1] = '\0';
	if (ret == -1 || hostname[0] == '\0') {
		purple_debug(PURPLE_DEBUG_MISC, "sipe", "Error when getting host name.  Using \"localhost.\"\n");
		g_strerror(errno);
		strcpy(hostname, "localhost");
	}
#endif
	/*const gchar * hostname = purple_get_host_name();*/
	return (char *)hostname;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
