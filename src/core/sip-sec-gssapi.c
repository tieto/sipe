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
#endif

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

static gss_OID_set create_mechs_set(guint type)
{
	OM_uint32 ret;
	OM_uint32 minor;
	gss_OID_set set = GSS_C_NO_OID_SET;

	ret = gss_create_empty_oid_set(&minor, &set);
	if (GSS_ERROR(ret)) {
		sip_sec_gssapi_print_gss_error("gss_create_empty_oid_set", ret, minor);
		SIPE_DEBUG_ERROR("create_mech_set: can't create mech set (ret=%d)", (int)ret);
		return(GSS_C_NO_OID_SET);
	}

#ifdef HAVE_GSSAPI_ONLY
	if ((type == SIPE_AUTHENTICATION_TYPE_NEGOTIATE) ||
	    (type == SIPE_AUTHENTICATION_TYPE_KERBEROS)) {
#else
		(void) type; /* keep compiler happy */
#endif
		ret = gss_add_oid_set_member(&minor,
					     (gss_OID) gss_mech_krb5,
					     &set);
		if (GSS_ERROR(ret)) {
			sip_sec_gssapi_print_gss_error("gss_add_oid_set_member(krb5)", ret, minor);
			SIPE_DEBUG_ERROR("create_mech_set: can't add Kerberos to mech set (ret=%d)", (int)ret);
			gss_release_oid_set(&minor, &set);
			return(GSS_C_NO_OID_SET);
		}
#ifdef HAVE_GSSAPI_ONLY
	}

	if ((type == SIPE_AUTHENTICATION_TYPE_NEGOTIATE) ||
	    (type == SIPE_AUTHENTICATION_TYPE_NTLM)) {
		ret = gss_add_oid_set_member(&minor,
					     (gss_OID) &gss_mech_ntlmssp,
					     &set);
		if (GSS_ERROR(ret)) {
			sip_sec_gssapi_print_gss_error("gss_add_oid_set_member(ntlmssp)", ret, minor);
			SIPE_DEBUG_ERROR("create_mech_set: can't add NTLM to mech set (ret=%d)", (int)ret);
			gss_release_oid_set(&minor, &set);
			return(GSS_C_NO_OID_SET);
		}
	}
#endif

	return(set);
}

/* sip-sec-mech.h API implementation for Kerberos/GSSAPI */

static gboolean
sip_sec_acquire_cred__gssapi(SipSecContext context,
			     const gchar *domain,
			     const gchar *username,
			     const gchar *password)
{
	SIPE_DEBUG_INFO_NOFORMAT("sip_sec_acquire_cred__gssapi: started");

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
			SIPE_DEBUG_ERROR("sip_sec_acquire_cred__gssapi: failed to construct user name (ret=%d)", (int)ret);
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
		gss_release_oid_set(&minor, &mechs_set);

		if (GSS_ERROR(ret)) {
			sip_sec_gssapi_print_gss_error("gss_acquire_cred_with_password", ret, minor);
			SIPE_DEBUG_ERROR("sip_sec_acquire_cred__gssapi: failed to acquire credentials (ret=%d)", (int)ret);
			return(FALSE);
		} else {
			((context_gssapi) context)->cred_gssapi = credentials;
			return(TRUE);
		}
#else
		/*
		 * non-SSO support requires gss_acquire_cred_with_password()
		 * which is not available on older GSSAPI releases.
		 */
		(void) domain;   /* keep compiler happy */
		(void) username; /* keep compiler happy */
		(void) password; /* keep compiler happy */
		SIPE_DEBUG_ERROR_NOFORMAT("sip_sec_acquire_cred__gssapi: non-SSO mode not supported");
		return(FALSE);
#endif
	}
#ifdef HAVE_GSSAPI_ONLY
	else {
		OM_uint32 ret;
		OM_uint32 minor;
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
		gss_release_oid_set(&minor, &mechs_set);

		if (GSS_ERROR(ret)) {
			sip_sec_gssapi_print_gss_error("gss_acquire_cred", ret, minor);
			SIPE_DEBUG_ERROR("sip_sec_acquire_cred__gssapi: failed to acquire credentials (ret=%d)", (int)ret);
			return(FALSE);
		} else {
			((context_gssapi) context)->cred_gssapi = credentials;
			return(TRUE);
		}
	}
#else
	return(TRUE);
#endif
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
	OM_uint32 flags = GSS_C_INTEG_FLAG;
	gss_OID name_oid, mech_oid;
	gss_buffer_desc input_token;
	gss_buffer_desc output_token;
	gss_name_t target_name;
#ifdef HAVE_GSSAPI_ONLY
	gchar *hostbased_service_name = NULL;
	gboolean sip_ntlm =
		(((context->flags & SIP_SEC_FLAG_COMMON_HTTP) == 0) &&
		(context->type == SIPE_AUTHENTICATION_TYPE_NTLM));
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
		ret = gss_delete_sec_context(&minor,
					     &(ctx->ctx_gssapi),
					     GSS_C_NO_BUFFER);
		if (GSS_ERROR(ret)) {
			sip_sec_gssapi_print_gss_error("gss_delete_sec_context", ret, minor);
			SIPE_DEBUG_ERROR("sip_sec_init_sec_context__gssapi: failed to delete security context (ret=%d)", (int)ret);
		}
		ctx->ctx_gssapi = GSS_C_NO_CONTEXT;
		context->flags &= ~SIP_SEC_FLAG_COMMON_READY;
	}

#ifdef HAVE_GSSAPI_ONLY
	switch(context->type) {
	case SIPE_AUTHENTICATION_TYPE_NTLM:
		name_oid          = (gss_OID) GSS_C_NT_HOSTBASED_SERVICE;
		mech_oid          = (gss_OID) &gss_mech_ntlmssp;
		input_token.value = (void *)  service_name;
		if (sip_ntlm)
			flags |= GSS_C_DATAGRAM_FLAG;
		break;

	case SIPE_AUTHENTICATION_TYPE_KERBEROS:
#endif
		name_oid          = (gss_OID) GSS_KRB5_NT_PRINCIPAL_NAME;
		mech_oid          = (gss_OID) gss_mech_krb5;
		input_token.value = (void *)  service_name;
#ifdef HAVE_GSSAPI_ONLY
		break;

	case SIPE_AUTHENTICATION_TYPE_NEGOTIATE: {
			/* Convert to hostbased so NTLM fallback can work */
			gchar **type_service = g_strsplit(service_name, "/", 2);
			if (type_service[1]) {
				gchar *type_lower = g_ascii_strdown(type_service[0], -1);
				hostbased_service_name = g_strdup_printf("%s@%s",
									 type_lower,
									 type_service[1]);
				g_free(type_lower);
				input_token.value = (void *) hostbased_service_name;
			} else {
				input_token.value = (void *) service_name;
			}
			g_strfreev(type_service);

			name_oid = (gss_OID) GSS_C_NT_HOSTBASED_SERVICE;
			mech_oid = (gss_OID) &gss_mech_spnego;
		}
		break;

	default:
		SIPE_DEBUG_ERROR("sip_sec_gssapi_initialize_context invoked for invalid type %d",
				 context->type);
		return(FALSE);
	}
#endif

	/* Import service name to GSS */
	input_token.length = strlen(input_token.value) + 1;

	ret = gss_import_name(&minor,
			      &input_token,
			      name_oid,
			      &target_name);

#ifdef HAVE_GSSAPI_ONLY
	g_free(hostbased_service_name);
#endif

	if (GSS_ERROR(ret)) {
		sip_sec_gssapi_print_gss_error("gss_import_name", ret, minor);
		SIPE_DEBUG_ERROR("sip_sec_init_sec_context__gssapi: failed to construct target name (ret=%d)", (int)ret);
		return(FALSE);
	}

	/* Create context */
	input_token.length = in_buff.length;
	input_token.value = in_buff.value;

	output_token.length = 0;
	output_token.value = NULL;

	ret = gss_init_sec_context(&minor,
				   ctx->cred_gssapi,
				   &(ctx->ctx_gssapi),
				   target_name,
				   mech_oid,
				   flags,
				   GSS_C_INDEFINITE,
				   GSS_C_NO_CHANNEL_BINDINGS,
				   &input_token,
				   NULL,
				   &output_token,
				   NULL,
				   &expiry);
	gss_release_name(&minor_ignore, &target_name);

	if (GSS_ERROR(ret)) {
		gss_release_buffer(&minor_ignore, &output_token);
		sip_sec_gssapi_print_gss_error("gss_init_sec_context", ret, minor);
		SIPE_DEBUG_ERROR("sip_sec_init_sec_context__gssapi: failed to initialize context (ret=%d)", (int)ret);
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
		SIPE_DEBUG_ERROR("sip_sec_make_signature__gssapi: failed to make signature (ret=%d)", (int)ret);
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
		SIPE_DEBUG_ERROR("sip_sec_verify_signature__gssapi: failed to make signature (ret=%d)", (int)ret);
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

	if (ctx->ctx_gssapi != GSS_C_NO_CONTEXT) {
		ret = gss_delete_sec_context(&minor, &(ctx->ctx_gssapi), GSS_C_NO_BUFFER);
		if (GSS_ERROR(ret)) {
			sip_sec_gssapi_print_gss_error("gss_delete_sec_context", ret, minor);
			SIPE_DEBUG_ERROR("sip_sec_destroy_sec_context__gssapi: failed to delete security context (ret=%d)", (int)ret);
		}
		ctx->ctx_gssapi = GSS_C_NO_CONTEXT;
	}

	if (ctx->cred_gssapi != GSS_C_NO_CREDENTIAL) {
		ret = gss_release_cred(&minor, &(ctx->cred_gssapi));
		if (GSS_ERROR(ret)) {
			sip_sec_gssapi_print_gss_error("gss_release_cred", ret, minor);
			SIPE_DEBUG_ERROR("sip_sec_destroy_sec_context__gssapi: failed to release credentials (ret=%d)", (int)ret);
		}
		ctx->cred_gssapi = GSS_C_NO_CREDENTIAL;
	}

	g_free(context);
}

static const gchar *
sip_sec_context_name__gssapi(SIPE_UNUSED_PARAMETER SipSecContext context)
{
	return("Kerberos");
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
