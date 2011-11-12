/**
 * @file sip-sec-tls-dsk.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011 SIPE Project <http://sipe.sourceforge.net/>
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

#include <glib.h>

#include "sipe-common.h"
#include "sip-sec.h"
#include "sip-sec-mech.h"
#include "sip-sec-tls-dsk.h"
#include "sipe-tls.h"
#include "sipe-utils.h"

/* Security context for TLS-DSK */
typedef struct _context_tls_dsk {
	struct sip_sec_context common;
	gpointer certificate;
} *context_tls_dsk;

/* TLS-DSK implementation */

/* TBD.... */

/* sip-sec-mech.h API implementation for TLS-DSK */

static sip_uint32
sip_sec_acquire_cred__tls_dsk(SipSecContext context,
			      SIPE_UNUSED_PARAMETER const char *domain,
			      SIPE_UNUSED_PARAMETER const char *username,
			      const char *password)
{
	context_tls_dsk ctx = (context_tls_dsk)context;

	/* TLS-DSK requires a certificate. Everything else is ignored */
	if (!password)
		return SIP_SEC_E_INTERNAL_ERROR;

	ctx->certificate = (gpointer) password;

	/* Authentication not yet completed */
	ctx->common.is_ready = FALSE;

	return SIP_SEC_E_OK;
}

static sip_uint32
sip_sec_init_sec_context__tls_dsk(SipSecContext context,
				  SipSecBuffer in_buff,
				  SipSecBuffer *out_buff,
				  SIPE_UNUSED_PARAMETER const char *service_name)
{
	context_tls_dsk ctx = (context_tls_dsk) context;

	/* temporary */
	(void)ctx;
	(void)in_buff;


	out_buff->value = sipe_tls_client_hello(&out_buff->length);

	return SIP_SEC_E_OK;
}

static sip_uint32
sip_sec_make_signature__tls_dsk(SipSecContext context,
				const char *message,
				SipSecBuffer *signature)
{
	context_tls_dsk ctx = (context_tls_dsk) context;

	/* temporary */
	(void)ctx;
	(void)message;
	(void)signature;

	return SIP_SEC_E_INTERNAL_ERROR;
}

static sip_uint32
sip_sec_verify_signature__tls_dsk(SipSecContext context,
				  const char *message,
				  SipSecBuffer signature)
{
	context_tls_dsk ctx = (context_tls_dsk) context;

	/* temporary */
	(void)ctx;
	(void)message;
	(void)signature;

	return SIP_SEC_E_INTERNAL_ERROR;
}

static void
sip_sec_destroy_sec_context__tls_dsk(SipSecContext context)
{
	context_tls_dsk ctx = (context_tls_dsk) context;

	g_free(ctx);
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
