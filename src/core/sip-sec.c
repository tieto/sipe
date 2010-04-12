/**
 * @file sip-sec.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#include <glib.h>

#include "sipe-common.h"
#include "sip-sec.h"
#include "sipe-backend.h"
#include "sipe-utils.h"

#include "sip-sec-mech.h"
#include "sip-sec-ntlm.h"
#ifndef _WIN32
#define sip_sec_create_context__NTLM		sip_sec_create_context__ntlm
#define sip_sec_create_context__Negotiate	sip_sec_create_context__NONE

#ifdef HAVE_LIBKRB5
#include "sip-sec-krb5.h"
#define sip_sec_create_context__Kerberos	sip_sec_create_context__krb5
#else
#define sip_sec_create_context__Kerberos	sip_sec_create_context__NONE
#endif

#else /* _WIN32 */
#ifdef HAVE_LIBKRB5
#include "sip-sec-sspi.h"
#define sip_sec_create_context__NTLM		sip_sec_create_context__sspi
#define sip_sec_create_context__Negotiate	sip_sec_create_context__sspi
#define sip_sec_create_context__Kerberos	sip_sec_create_context__sspi
#else /* HAVE_LIBKRB5 */
#define sip_sec_create_context__NTLM		sip_sec_create_context__ntlm
#define sip_sec_create_context__Negotiate	sip_sec_create_context__NONE
#define sip_sec_create_context__Kerberos	sip_sec_create_context__NONE
#endif /* HAVE_LIBKRB5 */

#endif /* _WIN32 */

/* Dummy initialization hook */
static SipSecContext
sip_sec_create_context__NONE(SIPE_UNUSED_PARAMETER guint type)
{
	return(NULL);
}

/* sip_sec API methods */
SipSecContext
sip_sec_create_context(guint type,
		       const int  sso,
		       int is_connection_based,
		       const char *domain,
		       const char *username,
		       const char *password)
{
	SipSecContext context = NULL;

	/* Map authentication type to module initialization hook & name */
	static sip_sec_create_context_func const auth_to_hook[] = {
		sip_sec_create_context__NONE,      /* AUTH_TYPE_UNSET     */
		sip_sec_create_context__NONE,      /* AUTH_TYPE_DIGEST    */
		sip_sec_create_context__NTLM,      /* AUTH_TYPE_NTLM      */
		sip_sec_create_context__Kerberos,  /* AUTH_TYPE_KERBEROS  */
		sip_sec_create_context__Negotiate, /* AUTH_TYPE_NEGOTIATE */
	};

	context = (*(auth_to_hook[type]))(type);
	if (context) {
		sip_uint32 ret;

		context->sso = sso;
		context->is_connection_based = is_connection_based;

		ret = (*context->acquire_cred_func)(context, domain, username, password);
		if (ret != SIP_SEC_E_OK) {
			SIPE_DEBUG_INFO_NOFORMAT("ERROR: sip_sec_init_context failed to acquire credentials.");
			(*context->destroy_context_func)(context);
			context = NULL;
		}
	}

	return(context);
}

unsigned long
sip_sec_init_context_step(SipSecContext context,
			  const char *target,
			  const char *input_toked_base64,
			  char **output_toked_base64,
			  int *expires)
{
	sip_uint32 ret = SIP_SEC_E_INTERNAL_ERROR;

	if (context) {
		SipSecBuffer in_buff  = {0, NULL};
		SipSecBuffer out_buff = {0, NULL};
		char *tmp;

		/* Not NULL for NTLM Type 2 */
		if (input_toked_base64) {
			in_buff.value = g_base64_decode(input_toked_base64, &in_buff.length);

			tmp = sip_sec_ntlm_message_describe(in_buff);
			if (tmp) {
				SIPE_DEBUG_INFO("sip_sec_init_context_step: Challenge message is:\n%s", tmp);
			}
			g_free(tmp);
		}

		ret = (*context->init_context_func)(context, in_buff, &out_buff, target);

		if (input_toked_base64)
			g_free(in_buff.value);

		if (ret == SIP_SEC_E_OK || ret == SIP_SEC_I_CONTINUE_NEEDED) {
			*output_toked_base64 = g_base64_encode(out_buff.value, out_buff.length);

			if (out_buff.length > 0 && out_buff.value) {
				tmp = sip_sec_ntlm_message_describe(out_buff);
				if (tmp) {
					SIPE_DEBUG_INFO("sip_sec_init_context_step: Negotiate or Authenticate message is:\n%s", tmp);
				}
				g_free(tmp);
			}

			g_free(out_buff.value);
		}

		if (expires) {
			*expires = context->expires;
		}
	}

	return ret;
}

char *
sip_sec_init_context(SipSecContext *context,
		     int *expires,
		     guint type,
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

	*context = sip_sec_create_context(type,
					  sso,
					  0, /* Connectionless for SIP */
					  domain,
					  username,
					  password);
	if (!*context) {
		SIPE_DEBUG_INFO_NOFORMAT("ERROR: sip_sec_init_context: failed sip_sec_create_context()");
		return NULL;
	}

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

	if (expires) {
		*expires = exp;
	}

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
		SIPE_DEBUG_INFO_NOFORMAT("ERROR: sip_sec_make_signature failed. Unable to sign message!");
		return NULL;
	}
	signature_hex = buff_to_hex_str(signature.value, signature.length);
	g_free(signature.value);
	return signature_hex;
}

int sip_sec_verify_signature(SipSecContext context, const char *message, const char *signature_hex)
{
	SipSecBuffer signature;
	sip_uint32 res;

	SIPE_DEBUG_INFO("sip_sec_verify_signature: message is:%s signature to verify is:%s",
			message ? message : "", signature_hex ? signature_hex : "");

	if (!message || !signature_hex) return SIP_SEC_E_INTERNAL_ERROR;

	signature.length = hex_str_to_buff(signature_hex, &signature.value);
	res = (*context->verify_signature_func)(context, message, signature);
	g_free(signature.value);
	return res;
}

/* Initialize & Destroy */
void sip_sec_init(void)
{
	sip_sec_init__ntlm();
}

void sip_sec_destroy(void)
{
	sip_sec_destroy__ntlm();
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
