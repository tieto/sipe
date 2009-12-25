/**
 * @file sip-sec.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009 pier11 <pier11@operamail.com>
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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "debug.h"
/* #include "util.h" */
#include "sip-sec.h"
#include "sip-sec-mech.h"

#ifndef _WIN32
#include "sip-sec-ntlm.h"
#define sip_sec_create_context__NTLM		sip_sec_create_context__ntlm

#ifdef USE_KERBEROS
#include "sip-sec-krb5.h"
#define sip_sec_create_context__Kerberos	sip_sec_create_context__krb5
#else
#define sip_sec_create_context__Kerberos	sip_sec_create_context__NONE
#endif

#else /* _WIN32 */
#ifdef USE_KERBEROS
#include "sip-sec-sspi.h"
#define sip_sec_create_context__NTLM		sip_sec_create_context__sspi
#define sip_sec_create_context__Kerberos	sip_sec_create_context__sspi
#else /* USE_KERBEROS */
#include "sip-sec-ntlm.h"
#define sip_sec_create_context__NTLM		sip_sec_create_context__ntlm
#define sip_sec_create_context__Kerberos	sip_sec_create_context__NONE
#endif /* USE_KERBEROS */

#endif /* _WIN32 */

gchar *purple_base64_encode(const guchar *data, gsize len);
guchar *purple_base64_decode(const char *str, gsize *ret_len);

/* Dummy initialization hook */
static SipSecContext
sip_sec_create_context__NONE(SIPE_UNUSED_PARAMETER SipSecAuthType type)
{
	return(NULL);
}

/* sip_sec API methods */
void
sip_sec_create_context(SipSecContext *context,
		       SipSecAuthType type,
		       const int  sso,
		       int is_connection_based,
		       const char *domain,
		       const char *username,
		       const char *password)
{
	sip_uint32 ret;

	/* Map authentication type to module initialization hook & name */
	static const sip_sec_create_context_func const auth_to_hook[] = {
		sip_sec_create_context__NONE,     /* AUTH_TYPE_UNSET    */
		sip_sec_create_context__NONE,     /* AUTH_TYPE_DIGEST   */
		sip_sec_create_context__NTLM,     /* AUTH_TYPE_NTLM     */
		sip_sec_create_context__Kerberos, /* AUTH_TYPE_KERBEROS */
	};

	/* @TODO: Can *context != NULL actually happen? */
	sip_sec_destroy_context(*context);

	*context = (*(auth_to_hook[type]))(type);
	if (!*context) return;

	(*context)->sso = sso;
	(*context)->is_connection_based = is_connection_based;

	ret = (*(*context)->acquire_cred_func)(*context, domain, username, password);
	if (ret != SIP_SEC_E_OK) {
		purple_debug_info("sipe", "ERROR: sip_sec_init_context failed to acquire credentials.\n");
		return;
	}
}

unsigned long
sip_sec_init_context_step(SipSecContext context,
			  const char *target,
			  const char *input_toked_base64,
			  char **output_toked_base64,
			  int *expires)
{
	SipSecBuffer in_buff  = {0, NULL};
	SipSecBuffer out_buff = {0, NULL};
	sip_uint32 ret;
	
	/* Not NULL for NTLM Type 2 */
	if (input_toked_base64)
		in_buff.value = purple_base64_decode(input_toked_base64, &(in_buff.length));
	
	ret = (*context->init_context_func)(context, in_buff, &out_buff, target);
	
	if (input_toked_base64)
		free_bytes_buffer(&in_buff);
	
	if (ret == SIP_SEC_E_OK || ret == SIP_SEC_I_CONTINUE_NEEDED) {
		*output_toked_base64 = purple_base64_encode(out_buff.value, out_buff.length);
		free_bytes_buffer(&out_buff);
	}
	
	*expires = context->expires;
	
	return ret;
}

char *
sip_sec_init_context(SipSecContext *context,
		     int *expires,
		     SipSecAuthType type,
		     const int  sso,
		     const char *domain,
		     const char *username,
		     const char *password,
		     const char *target,
		     const char *input_toked_base64)
{
	sip_uint32 ret;
	char *output_toked_base64 = NULL;
	int exp;

	sip_sec_create_context(context,
			       type,
			       sso,
			       0, /* Connectionless for SIP */
			       domain,
			       username,
			       password);
			       
	ret = sip_sec_init_context_step(*context,
					target,
					NULL,
					&output_toked_base64,
					&exp);			
					
	/* for NTLM type 3 */
	if (ret == SIP_SEC_I_CONTINUE_NEEDED) {
		g_free(output_toked_base64);
		ret = sip_sec_init_context_step(*context,
						target,
						input_toked_base64,
						&output_toked_base64,
						&exp);
	}
	
	*expires = exp;

	return output_toked_base64;
}

void
sip_sec_destroy_context(SipSecContext context)
{
	if (context) (*context->destroy_context_func)(context);
}

char * sip_sec_make_signature(SipSecContext context, const char *message)
{
	SipSecBuffer signature;
	char *signature_hex;

	if(((*context->make_signature_func)(context, message, &signature)) != SIP_SEC_E_OK) {
		purple_debug_info("sipe", "ERROR: sip_sec_make_signature failed. Unable to sign message!\n");
		return NULL;
	}
	signature_hex = bytes_to_hex_str(&signature);
	free_bytes_buffer(&signature);
	return signature_hex;
}

int sip_sec_verify_signature(SipSecContext context, const char *message, const char *signature_hex)
{
	SipSecBuffer signature;
	sip_uint32 res;
	
	purple_debug_info("sipe", "sip_sec_verify_signature: message is:%s signature to verify is:%s\n",
			  message ? message : "", signature_hex ? signature_hex : "");

	hex_str_to_bytes(signature_hex, &signature);
	res = (*context->verify_signature_func)(context, message, signature);
	free_bytes_buffer(&signature);
	return res;
}


/* Utility Methods */

void hex_str_to_bytes(const char *hex_str, SipSecBuffer *bytes)
{
	guint8 *buff;
	char two_digits[3];
	size_t i;

	bytes->length = strlen(hex_str)/2;
	bytes->value = g_malloc(bytes->length);

	buff = (guint8 *)bytes->value;
	for (i = 0; i < bytes->length; i++) {
		two_digits[0] = hex_str[i * 2];
		two_digits[1] = hex_str[i * 2 + 1];
		two_digits[2] = '\0';
		buff[i] = (guint8)strtoul(two_digits, NULL, 16);
	}
}

void free_bytes_buffer(SipSecBuffer *bytes)
{
	g_free(bytes->value);
	bytes->length = 0;
	bytes->value = NULL;
}

char *bytes_to_hex_str(SipSecBuffer *bytes)
{
	guint8 *buff = (guint8 *)bytes->value;
	char *res    = g_malloc(bytes->length * 2 + 1);
	size_t i, j;
	for (i = 0, j = 0; i < bytes->length; i++, j+=2) {
		sprintf(&res[j], "%02X", buff[i]);
	}
	res[j] = '\0';
	return res;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
