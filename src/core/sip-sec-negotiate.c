/**
 * @file sip-sec-negotiate.c
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
 *
 *
 * Implementation for HTTP "WWW-Authenticate: Negotiate" scheme.
 * It is a wrapper that will always try Kerberos first and fall back to NTLM.
 */

#include <glib.h>

#include "sipe-common.h"
#include "sip-sec.h"
#include "sip-sec-mech.h"
#include "sip-sec-gssapi.h" /* for Kerberos */
#include "sip-sec-negotiate.h"
#include "sip-sec-ntlm.h"
#include "sipe-backend.h"
#include "sipe-core.h"

/* Security context for Negotiate */
typedef struct _context_negotiate {
	struct sip_sec_context common;
	const gchar *domain;
	const gchar *username;
	const gchar *password;
	SipSecContext krb5;
	SipSecContext ntlm;
} *context_negotiate;

#define SIP_SEC_FLAG_NEGOTIATE_DISABLE_FALLBACK 0x80000000

static void sip_sec_negotiate_drop_krb5(context_negotiate context)
{
	if (context->krb5)
		context->krb5->destroy_context_func(context->krb5);
	context->krb5 = NULL;
}

static void sip_sec_negotiate_copy_flags(context_negotiate ctx,
					 SipSecContext context)
{
	context->flags = ctx->common.flags;
}

static void sip_sec_negotiate_copy_settings(context_negotiate ctx,
					    SipSecContext context)
{
	if (context->flags & SIP_SEC_FLAG_COMMON_READY)
		ctx->common.flags |= SIP_SEC_FLAG_COMMON_READY;
	else
		ctx->common.flags &= ~SIP_SEC_FLAG_COMMON_READY;
	ctx->common.expires = context->expires;
}

static gboolean sip_sec_negotiate_ntlm_fallback(context_negotiate context)
{
	if (context->common.flags & SIP_SEC_FLAG_NEGOTIATE_DISABLE_FALLBACK) {
		SIPE_DEBUG_ERROR_NOFORMAT("sip_sec_negotiate_ntlm_fallback: forbidden");
		return(FALSE);
	}

	sip_sec_negotiate_drop_krb5(context);
	sip_sec_negotiate_copy_flags(context, context->ntlm);

	return(context->ntlm->acquire_cred_func(context->ntlm,
						context->domain,
						context->username,
						context->password));
}

/* sip-sec-mech.h API implementation for Negotiate */

static gboolean
sip_sec_acquire_cred__negotiate(SipSecContext context,
				const gchar *domain,
				const gchar *username,
				const gchar *password)
{
	context_negotiate ctx = (context_negotiate) context;
	gboolean ret;

	SIPE_DEBUG_INFO_NOFORMAT("sip_sec_acquire_cred__negotiate: entering");

	ctx->domain   = domain;
	ctx->username = username;
	ctx->password = password;

	context = ctx->krb5;
	sip_sec_negotiate_copy_flags(ctx, context);
	ret = context->acquire_cred_func(context,
					 domain,
					 username,
					 password);
	if (!ret) {
		/* Kerberos failed -> fall back to NTLM immediately */
		SIPE_DEBUG_INFO_NOFORMAT("sip_sec_acquire_cred__negotiate: fallback to NTLM");
		ret = sip_sec_negotiate_ntlm_fallback(ctx);
	}

	return(ret);
}

static gboolean
sip_sec_init_sec_context__negotiate(SipSecContext context,
				    SipSecBuffer in_buff,
				    SipSecBuffer *out_buff,
				    const gchar *service_name)
{
	context_negotiate ctx = (context_negotiate) context;
	gboolean ret;

	SIPE_DEBUG_INFO_NOFORMAT("sip_sec_init_sec_context__negotiate: entering");

	/* Kerberos available? */
	context = ctx->krb5;
	if (context) {
		ret = context->init_context_func(context,
						 in_buff,
						 out_buff,
						 service_name);

		if (!ret) {
			/* Kerberos failed -> fall back to NTLM */
			SIPE_DEBUG_INFO_NOFORMAT("sip_sec_init_sec_context__negotiate: fallback to NTLM");
			ret = sip_sec_negotiate_ntlm_fallback(ctx);

			if (ret) {
				context = ctx->ntlm;
				ret = context->init_context_func(context,
								 in_buff,
								 out_buff,
								 service_name);
			}
		} else {
			/* Kerberos succeeded -> disable fallback to NTLM */
			ctx->common.flags |= SIP_SEC_FLAG_NEGOTIATE_DISABLE_FALLBACK;
		}

	/* No Kerberos available -> use NTLM */
	} else {
		context = ctx->ntlm;
		ret = context->init_context_func(context,
						 in_buff,
						 out_buff,
						 service_name);
	}

	/* context points to the last used child context */
	if (ret)
		sip_sec_negotiate_copy_settings(ctx, context);

	return(ret);
}

static gboolean
sip_sec_make_signature__negotiate(SIPE_UNUSED_PARAMETER SipSecContext context,
				  SIPE_UNUSED_PARAMETER const gchar *message,
				  SIPE_UNUSED_PARAMETER SipSecBuffer *signature)
{
	/* No implementation needed, as Negotiate is not used for SIP */
	return(FALSE);
}

static gboolean
sip_sec_verify_signature__negotiate(SIPE_UNUSED_PARAMETER SipSecContext context,
				    SIPE_UNUSED_PARAMETER const gchar *message,
				    SIPE_UNUSED_PARAMETER SipSecBuffer signature)
{
	/* No implementation needed, as Negotiate is not used for SIP */
	return(FALSE);
}

static void
sip_sec_destroy_sec_context__negotiate(SipSecContext context)
{
	context_negotiate ctx = (context_negotiate) context;

	if (ctx->ntlm)
		ctx->ntlm->destroy_context_func(ctx->ntlm);
	sip_sec_negotiate_drop_krb5(ctx);
	g_free(ctx);
}

/*
 * This module doesn't implement SPNEGO (RFC 4559) but instead returns raw
 * NTLM. Therefore we should not use "Authorization: Negotiate" for NTLM
 * although Microsoft servers *do* accept them.
 */
static const gchar *
sip_sec_context_name__negotiate(SipSecContext context)
{
	context_negotiate ctx = (context_negotiate) context;
	if (ctx->krb5)
		return("Negotiate");
	else
		return("NTLM");
}

SipSecContext
sip_sec_create_context__negotiate(SIPE_UNUSED_PARAMETER guint type)
{
	context_negotiate context = NULL;
	SipSecContext krb5 = sip_sec_create_context__gssapi(SIPE_AUTHENTICATION_TYPE_KERBEROS);

	if (krb5) {
		SipSecContext ntlm = sip_sec_create_context__ntlm(SIPE_AUTHENTICATION_TYPE_NTLM);

		if (ntlm) {
			context = g_malloc0(sizeof(struct _context_negotiate));

			if (context) {
				context->common.acquire_cred_func     = sip_sec_acquire_cred__negotiate;
				context->common.init_context_func     = sip_sec_init_sec_context__negotiate;
				context->common.destroy_context_func  = sip_sec_destroy_sec_context__negotiate;
				context->common.make_signature_func   = sip_sec_make_signature__negotiate;
				context->common.verify_signature_func = sip_sec_verify_signature__negotiate;
				context->common.context_name_func     = sip_sec_context_name__negotiate;
				context->krb5 = krb5;
				context->ntlm = ntlm;

				krb5->type = SIPE_AUTHENTICATION_TYPE_KERBEROS;
				ntlm->type = SIPE_AUTHENTICATION_TYPE_NTLM;

			} else {
				ntlm->destroy_context_func(ntlm);
			}
		}

		if (!context) {
			krb5->destroy_context_func(krb5);
		}
	}

	return((SipSecContext) context);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
