/**
 * @file sip-sec-basic.c
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
 * Implementation for HTTP "WWW-Authenticate: Basic" scheme (RFC1945).
 */

#include <string.h>

#include <glib.h>

#include "sipe-common.h"
#include "sip-sec.h"
#include "sip-sec-mech.h"
#include "sip-sec-basic.h"
#include "sipe-backend.h"

/* Security context for Basic */
typedef struct _context_basic {
	struct sip_sec_context common;
	gchar *token;
	guint length;
} *context_basic;

/* sip-sec-mech.h API implementation for Basic */

static gboolean
sip_sec_acquire_cred__basic(SipSecContext context,
			    SIPE_UNUSED_PARAMETER const gchar *domain,
			    const gchar *username,
			    const gchar *password)
{
	context_basic ctx = (context_basic) context;

	SIPE_DEBUG_INFO_NOFORMAT("sip_sec_acquire_cred__basic: entering");

	if (!username || !password)
		return(FALSE);

	/* calculate Basic token (RFC1945 section 11.1) */
	ctx->token  = g_strdup_printf("%s:%s", username, password);
	ctx->length = strlen(ctx->token);

	return(TRUE);
}

static gboolean
sip_sec_init_sec_context__basic(SipSecContext context,
				SIPE_UNUSED_PARAMETER SipSecBuffer in_buff,
				SipSecBuffer *out_buff,
				SIPE_UNUSED_PARAMETER const gchar *service_name)
{
	context_basic ctx = (context_basic) context;

	out_buff->length = ctx->length;
	out_buff->value  = (guint8 *) g_strdup(ctx->token);

	return(TRUE);
}

static gboolean
sip_sec_make_signature__basic(SIPE_UNUSED_PARAMETER SipSecContext context,
			      SIPE_UNUSED_PARAMETER const gchar *message,
			      SIPE_UNUSED_PARAMETER SipSecBuffer *signature)
{
	/* No implementation needed, as Basic is not used for SIP */
	return(FALSE);
}

static gboolean
sip_sec_verify_signature__basic(SIPE_UNUSED_PARAMETER SipSecContext context,
				SIPE_UNUSED_PARAMETER const gchar *message,
				SIPE_UNUSED_PARAMETER SipSecBuffer signature)
{
	/* No implementation needed, as Basic is not used for SIP */
	return(FALSE);
}

static void
sip_sec_destroy_sec_context__basic(SipSecContext context)
{
	context_basic ctx = (context_basic) context;

	g_free(ctx->token);
	g_free(ctx);
}

static const gchar *
sip_sec_context_name__basic(SIPE_UNUSED_PARAMETER SipSecContext context)
{
	return("Basic");
}

SipSecContext
sip_sec_create_context__basic(SIPE_UNUSED_PARAMETER guint type)
{
	context_basic context = g_malloc0(sizeof(struct _context_basic));
	if (!context) return(NULL);

	context->common.acquire_cred_func     = sip_sec_acquire_cred__basic;
	context->common.init_context_func     = sip_sec_init_sec_context__basic;
	context->common.destroy_context_func  = sip_sec_destroy_sec_context__basic;
	context->common.make_signature_func   = sip_sec_make_signature__basic;
	context->common.verify_signature_func = sip_sec_verify_signature__basic;
	context->common.context_name_func     = sip_sec_context_name__basic;

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
