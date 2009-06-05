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
#include "debug.h"
#ifdef _WIN32
#include "libc_interface.h"
#endif //_WIN32

#include "sip-sec.h"
#include "sip-sec-ntlm.h"
#include "sip-ntlm.h"

gchar *purple_base64_encode(const guchar *data, gsize len);
guchar *purple_base64_decode(const char *str, gsize *ret_len);

typedef struct credentials_ntlm_struct {
	char* domain;
	char *username;
	char *password;
} credentials_ntlm, *credentials_ntlm_t;

typedef struct context_ntlm_struct {
	int step;
	const gchar *key;
} context_ntlm, *context_ntlm_t;


sip_uint32
sip_sec_acquire_cred__ntlm(SipSecCred *cred_handle, char* sec_package, char* domain, char *username, char *password)
{
	credentials_ntlm_t credentials = (credentials_ntlm_t)malloc(sizeof(credentials_ntlm));
	credentials->domain = strdup(domain);
	credentials->username = strdup(username);
	credentials->password = strdup(password);
	*cred_handle = credentials;
	return SIP_SEC_E_OK;
}

sip_uint32
sip_sec_init_sec_context__ntlm(SipSecCred cred_handle, char* sec_package, SipSecContext *context,
						SipSecBuffer in_buff,
						SipSecBuffer *out_buff,
						char *service_name)
{
	context_ntlm_t ctx;
	if (!*context) {
		ctx = (context_ntlm_t)malloc(sizeof(context_ntlm));
		ctx->step = 1;
	} else {
		ctx = *context;
		ctx->step++;
	}
	
	if (ctx->step == 1) 
	{
		out_buff->length = 0;
		out_buff->value = NULL;
		*context = ctx;
		// same behaviour as sspi
		return SIP_SEC_I_CONTINUE_NEEDED;
	} 
	else 
	{
		credentials_ntlm_t credentials = (credentials_ntlm_t)cred_handle;
		const gchar *ntlm_key;
		gchar *nonce;
		guint32 flags;
		
//@TODO refactor it somewhere to utils
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
		
		gchar *input_toked_base64;
		input_toked_base64 = purple_base64_encode(in_buff.value, in_buff.length);
		
		nonce = g_memdup(purple_ntlm_parse_challenge(input_toked_base64, &flags), 8);	
		gchar *gssapi_data = purple_ntlm_gen_authenticate(&ntlm_key, credentials->username, 
								credentials->password, hostname, credentials->domain, (const guint8 *)nonce, &flags);
		
		out_buff->value = purple_base64_decode(gssapi_data, &(out_buff->length));	

		ctx->key = ntlm_key;
		*context = ctx;
		return SIP_SEC_E_OK;
	}
}

/**
 * @param message a NULL terminated string to sign
 *
 */
sip_uint32
sip_sec_make_signature__ntlm(SipSecContext context, 
							char *message,
							SipSecBuffer *signature)
{
	context_ntlm_t ctx = (context_ntlm_t)context;
	gchar *ntlm_key = ctx->key;
	gchar *signature_hex = purple_ntlm_sipe_signature_make(message, ntlm_key);
	
	hex_str_to_bytes(signature_hex, signature);	
	return SIP_SEC_E_OK;
}

/**
 * @param message a NULL terminated string to check signature of
 * @return SIP_SEC_E_OK on success
 */
sip_uint32
sip_sec_verify_signature__ntlm(SipSecContext context, char* message, SipSecBuffer signature)
{
	context_ntlm_t ctx = (context_ntlm_t)context;
	gchar *ntlm_key = ctx->key;
	char *signature_hex = bytes_to_hex_str(signature);
	gchar *signature_calc = purple_ntlm_sipe_signature_make(message, ntlm_key);

	if (purple_ntlm_verify_signature (signature_calc, signature_hex)) {
		return SIP_SEC_E_OK;
	} else {
		return SIP_SEC_E_INTERNAL_ERROR;
	}
}
