/**
 * @file sip-sec-gssapi.c
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
 *
 *
 * This module implements sip-sec authentication API using GSSAPI.
 *
 * It can be compiled in two different modes:
 *
 *  - Kerberos-only: NTLM & SPNEGO are using SIPE internal implementation
 *                   [HAVE_GSSAPI_ONLY is not defined]
 *
 *  - pure GSSAPI:   this modules handles Kerberos, NTLM & SPNEGO
 *                   [HAVE_GSSAPI_ONLY is defined]
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <string.h>
#include <gssapi/gssapi.h>
#ifdef HAVE_GSSAPI_PASSWORD_SUPPORT
#include <gssapi/gssapi_ext.h>
#endif
#include <gssapi/gssapi_krb5.h>
#ifdef HAVE_GSSAPI_ONLY
#include <gssapi/gssapi_ntlmssp.h>
#endif

#include "sipe-common.h"
#include "sip-sec.h"
#include "sip-sec-mech.h"
#include "sip-sec-gssapi.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-utils.h"

/* Security context for Kerberos */
typedef struct _context_gssapi {
	struct sip_sec_context common;
	gss_cred_id_t cred_gssapi;
	gss_ctx_id_t ctx_gssapi;
	gss_name_t target_name;
} *context_gssapi;

#ifdef HAVE_GSSAPI_ONLY
static const gss_OID_desc gss_mech_ntlmssp = {
	GSS_NTLMSSP_OID_LENGTH,
	GSS_NTLMSSP_OID_STRING
};

static const gss_OID_desc gss_mech_spnego = {
	6,
	"\x2b\x06\x01\x05\x05\x02"
};

/*
 * The SPNEGO implementation on older Microsoft IIS servers sends a
 * non-conformant final empty token that is not accepted by the SPNEGO
 * implementation in older MIT KRB5 releases:
 *
 *  Base64-encoded DER: oRgwFqADCgEAoQsGCSqGSIb3EgECAqICBAA=
 *
 *  Decoded ASN.1:
 *     0:d=0  hl=2 l=  24 cons: cont [ 1 ]
 *     2:d=1  hl=2 l=  22 cons: SEQUENCE
 *     4:d=2  hl=2 l=   3 cons: cont [ 0 ]
 *     6:d=3  hl=2 l=   1 prim: ENUMERATED        :00
 *     9:d=2  hl=2 l=  11 cons: cont [ 1 ]
 *    11:d=3  hl=2 l=   9 prim: OBJECT            :1.2.840.113554.1.2.2
 *    22:d=2  hl=2 l=   2 cons: cont [ 2 ]     | this empty element is not
 *    24:d=3  hl=2 l=   0 prim: OCTET STRING   | correct according to spec
 *
 * We can circumvent this problem by setting GSS_C_MUTUAL_FLAG which causes
 * the server to send a non-empty final token. We set the following flag to
 * TRUE after the first time gss_init_sec_context() returns with a
 * "defective token" error.
 */
static gboolean spnego_mutual_flag = FALSE;
#endif

#define SIP_SEC_FLAG_GSSAPI_SIP_NTLM           0x00010000
#define SIP_SEC_FLAG_GSSAPI_NEGOTIATE_FALLBACK 0x00020000

static void sip_sec_gssapi_print_gss_error0(char *func,
					    OM_uint32 status,
					    int type)
{
	OM_uint32 minor;
	OM_uint32 message_context = 0;
	gss_buffer_desc status_string;

	do {
		gss_display_status(&minor,
				   status,
				   type,
				   GSS_C_NO_OID,
				   &message_context,
				   &status_string);

		SIPE_DEBUG_ERROR("sip_sec_gssapi: GSSAPI error in %s (%s): %s",
				 func,
				 (type == GSS_C_GSS_CODE ? "GSS" : "Mech"),
				 (gchar *) status_string.value);
		gss_release_buffer(&minor, &status_string);
	} while (message_context != 0);
}

/* Prints out errors of GSSAPI function invocation */
static void sip_sec_gssapi_print_gss_error(char *func,
					   OM_uint32 ret,
					   OM_uint32 minor)
{
	sip_sec_gssapi_print_gss_error0(func, ret,   GSS_C_GSS_CODE);
	sip_sec_gssapi_print_gss_error0(func, minor, GSS_C_MECH_CODE);
}

#if defined(HAVE_GSSAPI_PASSWORD_SUPPORT) || defined(HAVE_GSSAPI_ONLY)
/* NOTE: releases "set" on error */
static gboolean add_mech(gss_OID_set set,
			 gss_OID mech,
			 const gchar *name)
{
	OM_uint32 ret;
	OM_uint32 minor;

	ret = gss_add_oid_set_member(&minor, mech, &set);
	if (GSS_ERROR(ret)) {
		sip_sec_gssapi_print_gss_error("gss_add_oid_set_member", ret, minor);
		SIPE_DEBUG_ERROR("add_mech: can't add %s to mech set (ret=%u)", name, ret);
		gss_release_oid_set(&minor, &set);
		return(FALSE);
	}
	SIPE_DEBUG_INFO("add_mech: added %s to mech set", name);

	return(TRUE);
}

static gss_OID_set create_mechs_set(guint type)
{
	OM_uint32 ret;
	OM_uint32 minor;
	gss_OID_set set = GSS_C_NO_OID_SET;
	gss_OID mech_oid;
	const gchar *name;

	ret = gss_create_empty_oid_set(&minor, &set);
	if (GSS_ERROR(ret)) {
		sip_sec_gssapi_print_gss_error("gss_create_empty_oid_set", ret, minor);
		SIPE_DEBUG_ERROR("create_mechs_set: can't create mech set (ret=%u)", ret);
		return(GSS_C_NO_OID_SET);
	}

#ifdef HAVE_GSSAPI_ONLY
	switch (type) {
	case SIPE_AUTHENTICATION_TYPE_NTLM:
		mech_oid = (gss_OID) &gss_mech_ntlmssp;
		name     = "NTLM";
		break;

	case SIPE_AUTHENTICATION_TYPE_KERBEROS:
#else
		(void) type; /* keep compiler happy */
#endif
		mech_oid = (gss_OID) gss_mech_krb5;
		name     = "Kerberos";
#ifdef HAVE_GSSAPI_ONLY
		break;

	case SIPE_AUTHENTICATION_TYPE_NEGOTIATE:
		mech_oid = (gss_OID) &gss_mech_spnego;
		name     = "SPNEGO";
		break;

	default:
		SIPE_DEBUG_ERROR("create_mechs_set: invoked with invalid type %u",
				 type);
		gss_release_oid_set(&minor, &set);
		return(GSS_C_NO_OID_SET);
		break;
	}
#endif

	return(add_mech(set, mech_oid, name) ? set : GSS_C_NO_OID_SET);
}
#endif

#ifdef HAVE_GSSAPI_ONLY
static gss_OID_set create_neg_mechs_set(void)
{
	OM_uint32 ret;
	OM_uint32 minor;
	gss_OID_set set = GSS_C_NO_OID_SET;

	ret = gss_create_empty_oid_set(&minor, &set);
	if (GSS_ERROR(ret)) {
		sip_sec_gssapi_print_gss_error("gss_create_empty_oid_set", ret, minor);
		SIPE_DEBUG_ERROR("create_neg_mechs_set: can't create mech set (ret=%u)", ret);
		return(GSS_C_NO_OID_SET);
	}

	return((add_mech(set, (gss_OID)  gss_mech_krb5,    "Kerberos") &&
		add_mech(set, (gss_OID) &gss_mech_ntlmssp, "NTLM")) ?
	       set : GSS_C_NO_OID_SET);
}

static gboolean gssntlm_reset_mic_sequence(context_gssapi context)
{
	OM_uint32 ret;
	OM_uint32 minor;
	gss_buffer_desc value;
	guint sequence = 100;

	static const gss_OID_desc set_sequence_num_oid = {
		GSS_NTLMSSP_SET_SEQ_NUM_OID_LENGTH,
		GSS_NTLMSSP_SET_SEQ_NUM_OID_STRING
	};

	value.length = sizeof(sequence);
	value.value  = &sequence;

	ret = gss_set_sec_context_option(&minor,
					 &context->ctx_gssapi,
					 (gss_OID_desc *) &set_sequence_num_oid,
					 &value);
	if (GSS_ERROR(ret)) {
		sip_sec_gssapi_print_gss_error("gss_set_sec_context_option", ret, minor);
		SIPE_DEBUG_ERROR("gssntlm_reset_mic_sequence: failed to reset MIC sequence number (ret=%u)", ret);
		return(FALSE);
	}

	return(TRUE);
}
#endif

static void drop_gssapi_context(SipSecContext context)
{
	context_gssapi ctx = (context_gssapi) context;
	OM_uint32 ret;
	OM_uint32 minor;

	ret = gss_delete_sec_context(&minor,
				     &(ctx->ctx_gssapi),
				     GSS_C_NO_BUFFER);
	if (GSS_ERROR(ret)) {
		sip_sec_gssapi_print_gss_error("gss_delete_sec_context", ret, minor);
		SIPE_DEBUG_ERROR("drop_gssapi_context: failed to delete security context (ret=%u)", ret);
	}
	ctx->ctx_gssapi = GSS_C_NO_CONTEXT;
	context->flags &= ~SIP_SEC_FLAG_COMMON_READY;
}

/* sip-sec-mech.h API implementation for Kerberos/GSSAPI */

static gboolean
sip_sec_acquire_cred__gssapi(SipSecContext context,
			     const gchar *domain,
			     const gchar *username,
			     const gchar *password)
{
	context_gssapi ctx = (context_gssapi) context;

	SIPE_DEBUG_INFO_NOFORMAT("sip_sec_acquire_cred__gssapi: started");

	/* this is the first time we are allowed to set private flags */
	if (((context->flags & SIP_SEC_FLAG_COMMON_HTTP) == 0) &&
	    (context->type == SIPE_AUTHENTICATION_TYPE_NTLM))
		context->flags |= SIP_SEC_FLAG_GSSAPI_SIP_NTLM;

	/* With SSO we use the default credentials */
	if ((context->flags & SIP_SEC_FLAG_COMMON_SSO) == 0) {
#ifdef HAVE_GSSAPI_PASSWORD_SUPPORT
		gchar *username_new;
		OM_uint32 ret;
		OM_uint32 minor, minor_ignore;
		gss_OID_set mechs_set;
		gss_cred_id_t credentials;
		gss_buffer_desc input_name_buffer;
		gss_name_t user_name;

		/* Without SSO we need user name and password */
		if (!username || !password) {
			SIPE_DEBUG_ERROR_NOFORMAT("sip_sec_acquire_cred__gssapi: no valid authentication information provided");
			return(FALSE);
		}

		mechs_set = create_mechs_set(context->type);
		if (mechs_set == GSS_C_NO_OID_SET)
			return(FALSE);

		/* Construct user name to acquire credentials for */
		if (!is_empty(domain)) {
			/* User specified a domain */
			gchar *realm = g_ascii_strup(domain, -1);

			username_new = g_strdup_printf("%s@%s",
						       username,
						       realm);
			g_free(realm);

		} else if (strchr(username, '@')) {
			/* No domain, username matches XXX@YYY */
			gchar **user_realm = g_strsplit(username, "@", 2);
			gchar *realm       = g_ascii_strup(user_realm[1], -1);

			/*
			 * We should escape the "@" to generate a enterprise
			 * principal, i.e. XXX\@YYY
			 *
			 * But krb5 libraries currently don't support this:
			 *
			 * http://krbdev.mit.edu/rt/Ticket/Display.html?id=7729
			 *
			 * username_new = g_strdup_printf("%s\\@%s",
			 */
			username_new = g_strdup_printf("%s@%s",
						       user_realm[0],
						       realm);
			g_free(realm);
			g_strfreev(user_realm);
		} else {
			/* Otherwise use username as is */
			username_new = g_strdup(username);
		}
		SIPE_DEBUG_INFO("sip_sec_acquire_cred__gssapi: username '%s'",
				username_new);

		/* Import user name into GSS format */
		input_name_buffer.value  = (void *) username_new;
		input_name_buffer.length = strlen(username_new) + 1;

		ret = gss_import_name(&minor,
				      &input_name_buffer,
				      (gss_OID) GSS_C_NT_USER_NAME,
				      &user_name);
		g_free(username_new);

		if (GSS_ERROR(ret)) {
			sip_sec_gssapi_print_gss_error("gss_import_name", ret, minor);
			SIPE_DEBUG_ERROR("sip_sec_acquire_cred__gssapi: failed to construct user name (ret=%u)", ret);
			gss_release_oid_set(&minor, &mechs_set);
			return(FALSE);
		}

		/* Acquire user credentials with password */
		input_name_buffer.value  = (void *) password;
		input_name_buffer.length = strlen(password) + 1;
		ret = gss_acquire_cred_with_password(&minor,
						     user_name,
						     &input_name_buffer,
						     GSS_C_INDEFINITE,
						     mechs_set,
						     GSS_C_INITIATE,
						     &credentials,
						     NULL,
						     NULL);
		gss_release_name(&minor_ignore, &user_name);
		gss_release_oid_set(&minor_ignore, &mechs_set);

		if (GSS_ERROR(ret)) {
			sip_sec_gssapi_print_gss_error("gss_acquire_cred_with_password", ret, minor);
			SIPE_DEBUG_ERROR("sip_sec_acquire_cred__gssapi: failed to acquire credentials (ret=%u)", ret);
			return(FALSE);
		}

		ctx->cred_gssapi = credentials;

#else
		/*
		 * non-SSO support requires gss_acquire_cred_with_password()
		 * which is not available on older GSSAPI releases.
		 */
		(void) domain;   /* keep compiler happy */
		(void) username; /* keep compiler happy */
		(void) password; /* keep compiler happy */
		(void) ctx;      /* keep compiler happy */
		SIPE_DEBUG_ERROR_NOFORMAT("sip_sec_acquire_cred__gssapi: non-SSO mode not supported");
		return(FALSE);
#endif
	}
#ifdef HAVE_GSSAPI_ONLY
	else {
		OM_uint32 ret;
		OM_uint32 minor, minor_ignore;
		gss_OID_set mechs_set;
		gss_cred_id_t credentials;

		mechs_set = create_mechs_set(context->type);
		if (mechs_set == GSS_C_NO_OID_SET)
			return(FALSE);

		ret = gss_acquire_cred(&minor,
				       GSS_C_NO_NAME,
				       GSS_C_INDEFINITE,
				       mechs_set,
				       GSS_C_INITIATE,
				       &credentials,
				       NULL,
				       NULL);
		gss_release_oid_set(&minor_ignore, &mechs_set);

		if (GSS_ERROR(ret)) {
			sip_sec_gssapi_print_gss_error("gss_acquire_cred", ret, minor);
			SIPE_DEBUG_ERROR("sip_sec_acquire_cred__gssapi: failed to acquire credentials (ret=%u)", ret);
			return(FALSE);
		}

		ctx->cred_gssapi = credentials;
	}

	if (context->type == SIPE_AUTHENTICATION_TYPE_NEGOTIATE) {
		OM_uint32 ret;
		OM_uint32 minor, minor_ignore;
		gss_OID_set mechs_set = create_neg_mechs_set();

		if (mechs_set == GSS_C_NO_OID_SET)
			return(FALSE);

		ret = gss_set_neg_mechs(&minor,
					ctx->cred_gssapi,
					mechs_set);
		gss_release_oid_set(&minor_ignore, &mechs_set);

		if (GSS_ERROR(ret)) {
			sip_sec_gssapi_print_gss_error("gss_set_neg_mechs", ret, minor);
			SIPE_DEBUG_ERROR("sip_sec_acquire_cred__gssapi: failed to set negotiate mechanisms (ret=%u)", ret);
			return(FALSE);
		}
	}
#endif

	return(TRUE);
}

static gboolean
sip_sec_init_sec_context__gssapi(SipSecContext context,
				 SipSecBuffer in_buff,
				 SipSecBuffer *out_buff,
				 const gchar *service_name)
{
	context_gssapi ctx = (context_gssapi) context;
	OM_uint32 ret;
	OM_uint32 minor, minor_ignore;
	OM_uint32 expiry;
	gss_buffer_desc input_token;
	gss_buffer_desc output_token;
#ifdef HAVE_GSSAPI_ONLY
	gss_OID mech_oid;
	OM_uint32 flags = GSS_C_INTEG_FLAG;
#endif

	SIPE_DEBUG_INFO_NOFORMAT("sip_sec_init_sec_context__gssapi: started");

	/*
	 * If authentication was already completed, then this mean a new
	 * authentication handshake has started on the existing connection.
	 * We must throw away the old context, because we need a new one.
	 */
	if ((context->flags & SIP_SEC_FLAG_COMMON_READY) &&
	    (ctx->ctx_gssapi != GSS_C_NO_CONTEXT)) {
		SIPE_DEBUG_INFO_NOFORMAT("sip_sec_init_sec_context__gssapi: dropping old context");
		drop_gssapi_context(context);
	}

	/* Import service name to GSS */
	if (ctx->target_name == GSS_C_NO_NAME) {
		gchar *hostbased_service_name = sipe_utils_str_replace(service_name,
								       "/",
								       "@");

		input_token.value = (void *) hostbased_service_name;
		input_token.length = strlen(input_token.value) + 1;
		ret = gss_import_name(&minor,
				      &input_token,
				      (gss_OID) GSS_C_NT_HOSTBASED_SERVICE,
				      &(ctx->target_name));
		g_free(hostbased_service_name);

		if (GSS_ERROR(ret)) {
			sip_sec_gssapi_print_gss_error("gss_import_name", ret, minor);
			SIPE_DEBUG_ERROR("sip_sec_init_sec_context__gssapi: failed to construct target name (ret=%u)", ret);
			return(FALSE);
		}
	}

#ifdef HAVE_GSSAPI_ONLY
	switch(context->type) {
	case SIPE_AUTHENTICATION_TYPE_NTLM:
		mech_oid = (gss_OID) &gss_mech_ntlmssp;
		if (context->flags & SIP_SEC_FLAG_GSSAPI_SIP_NTLM)
			flags |= GSS_C_DATAGRAM_FLAG;
		break;

	case SIPE_AUTHENTICATION_TYPE_KERBEROS:
		mech_oid = (gss_OID) gss_mech_krb5;
		break;

	case SIPE_AUTHENTICATION_TYPE_NEGOTIATE:
		/*
		 * Some servers do not accept SPNEGO for Negotiate.
		 * If come back here with an existing security context
		 * and NULL input token we will fall back to NTLM
		 */
		if (ctx->ctx_gssapi && (in_buff.value == NULL)) {

			/* Only try this once */
			if (context->flags & SIP_SEC_FLAG_GSSAPI_NEGOTIATE_FALLBACK) {
				SIPE_DEBUG_ERROR_NOFORMAT("sip_sec_init_sec_context__gssapi: SPNEGO-to-NTLM fallback failed");
				return(FALSE);
			}

			SIPE_DEBUG_INFO_NOFORMAT("sip_sec_init_sec_context__gssapi: SPNEGO failed. Falling back to NTLM");
			drop_gssapi_context(context);

			context->flags |= SIP_SEC_FLAG_GSSAPI_NEGOTIATE_FALLBACK;
		}

		if (context->flags & SIP_SEC_FLAG_GSSAPI_NEGOTIATE_FALLBACK) {
			mech_oid = (gss_OID) &gss_mech_ntlmssp;
		} else {
			mech_oid = (gss_OID) &gss_mech_spnego;
			if (spnego_mutual_flag)
				flags |= GSS_C_MUTUAL_FLAG;
		}
		break;

	default:
		SIPE_DEBUG_ERROR("sip_sec_init_sec_context__gssapi: invoked for invalid type %u",
				 context->type);
		return(FALSE);
	}
#endif

	/* Create context */
	input_token.length = in_buff.length;
	input_token.value = in_buff.value;

	output_token.length = 0;
	output_token.value = NULL;

	ret = gss_init_sec_context(&minor,
				   ctx->cred_gssapi,
				   &(ctx->ctx_gssapi),
				   ctx->target_name,
#ifdef HAVE_GSSAPI_ONLY
				   mech_oid,
				   flags,
#else
				   (gss_OID) gss_mech_krb5,
				   GSS_C_INTEG_FLAG,
#endif
				   GSS_C_INDEFINITE,
				   GSS_C_NO_CHANNEL_BINDINGS,
				   &input_token,
				   NULL,
				   &output_token,
				   NULL,
				   &expiry);

	if (GSS_ERROR(ret)) {
		gss_release_buffer(&minor_ignore, &output_token);
		sip_sec_gssapi_print_gss_error("gss_init_sec_context", ret, minor);
		SIPE_DEBUG_ERROR("sip_sec_init_sec_context__gssapi: failed to initialize context (ret=%u)", ret);

#ifdef HAVE_GSSAPI_ONLY
		/* Enable workaround for SPNEGO (see above) */
		if (ret == GSS_S_DEFECTIVE_TOKEN) {
			SIPE_DEBUG_ERROR_NOFORMAT("sip_sec_init_sec_context__gssapi: enabling workaround for SPNEGO");
			spnego_mutual_flag = TRUE;
		}
#endif

		return(FALSE);
	}

	out_buff->length = output_token.length;
	if (out_buff->length)
		out_buff->value = g_memdup(output_token.value, output_token.length);
	else
		/* Special case: empty token */
		out_buff->value = (guint8 *) g_strdup("");

	gss_release_buffer(&minor_ignore, &output_token);

	context->expires = (int)expiry;

	if (ret == GSS_S_COMPLETE) {
		/* Authentication is completed */
		context->flags |= SIP_SEC_FLAG_COMMON_READY;

#ifdef HAVE_GSSAPI_ONLY
		if ((context->flags & SIP_SEC_FLAG_GSSAPI_SIP_NTLM) &&
		    !gssntlm_reset_mic_sequence(ctx))
			return(FALSE);
#endif
	}

	return(TRUE);
}

/**
 * @param message a NULL terminated string to sign
 */
static gboolean
sip_sec_make_signature__gssapi(SipSecContext context,
			       const gchar *message,
			       SipSecBuffer *signature)
{
	OM_uint32 ret;
	OM_uint32 minor;
	gss_buffer_desc input_message;
	gss_buffer_desc output_token;

	input_message.value = (void *)message;
	input_message.length = strlen(input_message.value);

	ret = gss_get_mic(&minor,
			  ((context_gssapi)context)->ctx_gssapi,
			  GSS_C_QOP_DEFAULT,
			  &input_message,
			  &output_token);

	if (GSS_ERROR(ret)) {
		sip_sec_gssapi_print_gss_error("gss_get_mic", ret, minor);
		SIPE_DEBUG_ERROR("sip_sec_make_signature__gssapi: failed to make signature (ret=%u)", ret);
		return FALSE;
	} else {
		signature->length = output_token.length;
		signature->value  = g_memdup(output_token.value,
					     output_token.length);
		gss_release_buffer(&minor, &output_token);
		return TRUE;
	}
}

/**
 * @param message a NULL terminated string to check signature of
 */
static gboolean
sip_sec_verify_signature__gssapi(SipSecContext context,
				 const gchar *message,
				 SipSecBuffer signature)
{
	OM_uint32 ret;
	OM_uint32 minor;
	gss_buffer_desc input_message;
	gss_buffer_desc input_token;

	input_message.value = (void *)message;
	input_message.length = strlen(input_message.value);

	input_token.value = signature.value;
	input_token.length = signature.length;

	ret = gss_verify_mic(&minor,
			     ((context_gssapi)context)->ctx_gssapi,
			     &input_message,
			     &input_token,
			     NULL);

	if (GSS_ERROR(ret)) {
		sip_sec_gssapi_print_gss_error("gss_verify_mic", ret, minor);
		SIPE_DEBUG_ERROR("sip_sec_verify_signature__gssapi: failed to verify signature (ret=%u)", ret);
		return FALSE;
	} else {
		return TRUE;
	}
}

static void
sip_sec_destroy_sec_context__gssapi(SipSecContext context)
{
	context_gssapi ctx = (context_gssapi) context;
	OM_uint32 ret;
	OM_uint32 minor;

	if (ctx->ctx_gssapi != GSS_C_NO_CONTEXT)
		drop_gssapi_context(context);

	if (ctx->cred_gssapi != GSS_C_NO_CREDENTIAL) {
		ret = gss_release_cred(&minor, &(ctx->cred_gssapi));
		if (GSS_ERROR(ret)) {
			sip_sec_gssapi_print_gss_error("gss_release_cred", ret, minor);
			SIPE_DEBUG_ERROR("sip_sec_destroy_sec_context__gssapi: failed to release credentials (ret=%u)", ret);
		}
		ctx->cred_gssapi = GSS_C_NO_CREDENTIAL;
	}

	if (ctx->target_name != GSS_C_NO_NAME) {
		ret = gss_release_name(&minor, &(ctx->target_name));
		if (GSS_ERROR(ret)) {
			sip_sec_gssapi_print_gss_error("gss_release_name", ret, minor);
			SIPE_DEBUG_ERROR("sip_sec_destroy_sec_context__gssapi: failed to release name (ret=%u)", ret);
		}
		ctx->target_name = GSS_C_NO_NAME;
	}

	g_free(context);
}

static const gchar *
sip_sec_context_name__gssapi(SipSecContext context)
{
#ifdef HAVE_GSSAPI_ONLY
	const gchar *name;

	switch(context->type) {
	case SIPE_AUTHENTICATION_TYPE_NTLM:
		name = "NTLM";
		break;

	case SIPE_AUTHENTICATION_TYPE_KERBEROS:
		name = "Kerberos";
		break;

	case SIPE_AUTHENTICATION_TYPE_NEGOTIATE:
		if (context->flags & SIP_SEC_FLAG_GSSAPI_NEGOTIATE_FALLBACK)
			name = "NTLM";
		else
			name = "Negotiate";
		break;

	default:
		SIPE_DEBUG_ERROR("sip_sec_context_name__gssapi: invoked for invalid type %u",
				 context->type);
		name = "";
		break;
	}

	return(name);

#else
	(void) context; /* keep compiler happy */
	return("Kerberos");
#endif
}

SipSecContext
sip_sec_create_context__gssapi(SIPE_UNUSED_PARAMETER guint type)
{
	context_gssapi context = g_malloc0(sizeof(struct _context_gssapi));
	if (!context) return(NULL);

	context->common.acquire_cred_func     = sip_sec_acquire_cred__gssapi;
	context->common.init_context_func     = sip_sec_init_sec_context__gssapi;
	context->common.destroy_context_func  = sip_sec_destroy_sec_context__gssapi;
	context->common.make_signature_func   = sip_sec_make_signature__gssapi;
	context->common.verify_signature_func = sip_sec_verify_signature__gssapi;
	context->common.context_name_func     = sip_sec_context_name__gssapi;

	context->cred_gssapi = GSS_C_NO_CREDENTIAL;
	context->ctx_gssapi  = GSS_C_NO_CONTEXT;
	context->target_name = GSS_C_NO_NAME;

	return((SipSecContext) context);
}

gboolean sip_sec_password__gssapi(void)
{
	/* Kerberos supports Single-Sign On */
	return(FALSE);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
