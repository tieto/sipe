/**
 * @file sip-sec.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2013 SIPE Project <http://sipe.sourceforge.net/>
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
#include "sipe-core.h"
#include "sipe-utils.h"

#include "sip-sec-mech.h"

/* SSPI is only supported on Windows platform */
#if defined(_WIN32) && defined(HAVE_SSPI)
#include "sip-sec-sspi.h"
#define SIP_SEC_WINDOWS_SSPI 1
#else
#define SIP_SEC_WINDOWS_SSPI 0
#endif

#ifdef HAVE_GSSAPI_GSSAPI_H
#include "sip-sec-gssapi.h"
#endif

/* SIPE_AUTHENTICATION_TYPE_BASIC */
#include "sip-sec-basic.h"
#define sip_sec_create_context__Basic      sip_sec_create_context__basic
/* Basic is only used for HTTP, not for SIP */
#define sip_sec_password__Basic            sip_sec_password__NONE

/* SIPE_AUTHENTICATION_TYPE_NTLM */
#if SIP_SEC_WINDOWS_SSPI
#define sip_sec_create_context__NTLM       sip_sec_create_context__sspi
#define sip_sec_password__NTLM             sip_sec_password__sspi
#elif defined(HAVE_GSSAPI_ONLY)
#define sip_sec_create_context__NTLM       sip_sec_create_context__gssapi
#define sip_sec_password__NTLM             sip_sec_password__gssapi
#else
#include "sip-sec-ntlm.h"
#define sip_sec_create_context__NTLM       sip_sec_create_context__ntlm
#define sip_sec_password__NTLM             sip_sec_password__ntlm
#endif

/* SIPE_AUTHENTICATION_TYPE_KERBEROS */
#if SIP_SEC_WINDOWS_SSPI
#define sip_sec_create_context__Kerberos   sip_sec_create_context__sspi
#define sip_sec_password__Kerberos         sip_sec_password__sspi
#elif defined(HAVE_GSSAPI_GSSAPI_H)
#define sip_sec_create_context__Kerberos   sip_sec_create_context__gssapi
#define sip_sec_password__Kerberos         sip_sec_password__gssapi
#else
#define sip_sec_create_context__Kerberos   sip_sec_create_context__NONE
#define sip_sec_password__Kerberos         sip_sec_password__NONE
#endif

/* SIPE_AUTHENTICATION_TYPE_NEGOTIATE */
#if SIP_SEC_WINDOWS_SSPI
#define sip_sec_create_context__Negotiate  sip_sec_create_context__sspi
#elif defined(HAVE_GSSAPI_ONLY)
#define sip_sec_create_context__Negotiate  sip_sec_create_context__gssapi
#elif defined(HAVE_GSSAPI_GSSAPI_H)
#include "sip-sec-negotiate.h"
#define sip_sec_create_context__Negotiate  sip_sec_create_context__negotiate
#else
#define sip_sec_create_context__Negotiate  sip_sec_create_context__NONE
#endif
/* Negotiate is only used for HTTP, not for SIP */
#define sip_sec_password__Negotiate        sip_sec_password__NONE

/* SIPE_AUTHENTICATION_TYPE_TLS_DSK */
#include "sip-sec-tls-dsk.h"
#define sip_sec_create_context__TLS_DSK    sip_sec_create_context__tls_dsk
#define sip_sec_password__TLS_DSK          sip_sec_password__tls_dsk

/* Dummy initialization hook */
static SipSecContext
sip_sec_create_context__NONE(SIPE_UNUSED_PARAMETER guint type)
{
	return(NULL);
}

/* Dummy SIP password hook */
static gboolean sip_sec_password__NONE(void)
{
	return(TRUE);
}

/* sip_sec API methods */
SipSecContext
sip_sec_create_context(guint type,
		       gboolean sso,
		       gboolean http,
		       const gchar *domain,
		       const gchar *username,
		       const gchar *password)
{
	SipSecContext context = NULL;

	/* Map authentication type to module initialization hook & name */
	static sip_sec_create_context_func const auth_to_hook[] = {
		sip_sec_create_context__NONE,      /* SIPE_AUTHENTICATION_TYPE_UNSET     */
		sip_sec_create_context__Basic,     /* SIPE_AUTHENTICATION_TYPE_BASIC     */
		sip_sec_create_context__NTLM,      /* SIPE_AUTHENTICATION_TYPE_NTLM      */
		sip_sec_create_context__Kerberos,  /* SIPE_AUTHENTICATION_TYPE_KERBEROS  */
		sip_sec_create_context__Negotiate, /* SIPE_AUTHENTICATION_TYPE_NEGOTIATE */
		sip_sec_create_context__TLS_DSK,   /* SIPE_AUTHENTICATION_TYPE_TLS_DSK   */
	};

	SIPE_DEBUG_INFO("sip_sec_create_context: type: %d, Single Sign-On: %s, protocol: %s",
			type, sso ? "yes" : "no", http ? "HTTP" : "SIP");

	context = (*(auth_to_hook[type]))(type);
	if (context) {

		context->type = type;

		/* NOTE: mechanism must set private flags acquire_cred_func()! */
		context->flags = 0;

		/* set common flags */
		if (sso)
			context->flags |= SIP_SEC_FLAG_COMMON_SSO;
		if (http)
			context->flags |= SIP_SEC_FLAG_COMMON_HTTP;

		if (!(*context->acquire_cred_func)(context, domain, username, password)) {
			SIPE_DEBUG_INFO_NOFORMAT("ERROR: sip_sec_create_context: failed to acquire credentials.");
			(*context->destroy_context_func)(context);
			context = NULL;
		}
	}

	return(context);
}

gboolean
sip_sec_init_context_step(SipSecContext context,
			  const gchar *target,
			  const gchar *input_toked_base64,
			  gchar **output_toked_base64,
			  guint *expires)
{
	gboolean ret = FALSE;

	if (context) {
		SipSecBuffer in_buff  = {0, NULL};
		SipSecBuffer out_buff = {0, NULL};

		/* Not NULL for NTLM Type 2 or TLS-DSK */
		if (input_toked_base64)
			in_buff.value = g_base64_decode(input_toked_base64, &in_buff.length);

		ret = (*context->init_context_func)(context, in_buff, &out_buff, target);

		if (input_toked_base64)
			g_free(in_buff.value);

		if (ret) {

			if (out_buff.value) {
				if (out_buff.length > 0) {
					*output_toked_base64 = g_base64_encode(out_buff.value, out_buff.length);
				} else {
					/* special string: caller takes ownership */
					*output_toked_base64 = (gchar *) out_buff.value;
					out_buff.value = NULL;
				}
			}

			g_free(out_buff.value);
		}

		if (expires) {
			*expires = context->expires;
		}
	}

	return ret;
}

gboolean sip_sec_context_is_ready(SipSecContext context)
{
	return(context && (context->flags & SIP_SEC_FLAG_COMMON_READY));
}

const gchar *sip_sec_context_name(SipSecContext context)
{
	if (context)
		return((*context->context_name_func)(context));
	else
		return(NULL);
}

guint sip_sec_context_type(SipSecContext context)
{
	if (context)
		return(context->type);
	else
		return(SIPE_AUTHENTICATION_TYPE_UNSET);
}

void sip_sec_destroy_context(SipSecContext context)
{
	if (context) (*context->destroy_context_func)(context);
}

gchar *sip_sec_make_signature(SipSecContext context, const gchar *message)
{
	SipSecBuffer signature;
	gchar *signature_hex;

	if (!(*context->make_signature_func)(context, message, &signature)) {
		SIPE_DEBUG_INFO_NOFORMAT("ERROR: sip_sec_make_signature failed. Unable to sign message!");
		return NULL;
	}
	signature_hex = buff_to_hex_str(signature.value, signature.length);
	g_free(signature.value);
	return signature_hex;
}

gboolean sip_sec_verify_signature(SipSecContext context,
				  const gchar *message,
				  const gchar *signature_hex)
{
	SipSecBuffer signature;
	gboolean res;

	SIPE_DEBUG_INFO("sip_sec_verify_signature: message is:%s signature to verify is:%s",
			message ? message : "", signature_hex ? signature_hex : "");

	if (!message || !signature_hex)
		return FALSE;

	signature.length = hex_str_to_buff(signature_hex, &signature.value);
	res = (*context->verify_signature_func)(context, message, signature);
	g_free(signature.value);
	return res;
}

/* Does authentication type require a password? */
gboolean sip_sec_requires_password(guint authentication,
				   gboolean sso)
{
	/* Map authentication type to module initialization hook & name */
	static sip_sec_password_func const auth_to_hook[] = {
		sip_sec_password__NONE,      /* SIPE_AUTHENTICATION_TYPE_UNSET     */
		sip_sec_password__Basic,     /* SIPE_AUTHENTICATION_TYPE_BASIC     */
		sip_sec_password__NTLM,      /* SIPE_AUTHENTICATION_TYPE_NTLM      */
		sip_sec_password__Kerberos,  /* SIPE_AUTHENTICATION_TYPE_KERBEROS  */
		sip_sec_password__Negotiate, /* SIPE_AUTHENTICATION_TYPE_NEGOTIATE */
		sip_sec_password__TLS_DSK,   /* SIPE_AUTHENTICATION_TYPE_TLS_DSK   */
	};

	/* If Single-Sign On is disabled then a password is required */
	if (!sso)
		return(TRUE);

	/* Check if authentation method supports Single-Sign On */
	return((*(auth_to_hook[authentication]))());
}

/* Initialize & Destroy */
void sip_sec_init(void)
{
#if !defined(HAVE_GSSAPI_ONLY) && !defined(HAVE_SSPI)
	sip_sec_init__ntlm();
#endif
}

void sip_sec_destroy(void)
{
#if !defined(HAVE_GSSAPI_ONLY) && !defined(HAVE_SSPI)
	sip_sec_destroy__ntlm();
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
