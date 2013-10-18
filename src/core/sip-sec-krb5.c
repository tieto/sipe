/**
 * @file sip-sec-krb5.c
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

#include <glib.h>
#include <string.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_ext.h>
#include <gssapi/gssapi_krb5.h>

#include "sipe-common.h"
#include "sip-sec.h"
#include "sip-sec-mech.h"
#include "sip-sec-krb5.h"
#include "sipe-backend.h"

/* Security context for Kerberos */
typedef struct _context_krb5 {
	struct sip_sec_context common;
	gss_cred_id_t cred_krb5;
	gss_ctx_id_t ctx_krb5;
	const gchar *domain;
	const gchar *username;
	const gchar *password;
} *context_krb5;

#define SIP_SEC_FLAG_KRB5_RETRY_AUTH 0x00010000

static void sip_sec_krb5_print_gss_error(char *func, OM_uint32 ret, OM_uint32 minor);

static void sip_sec_krb5_destroy_context(context_krb5 context)
{
	OM_uint32 ret;
	OM_uint32 minor;

	if (context->ctx_krb5 != GSS_C_NO_CONTEXT) {
		ret = gss_delete_sec_context(&minor, &(context->ctx_krb5), GSS_C_NO_BUFFER);
		if (GSS_ERROR(ret)) {
			sip_sec_krb5_print_gss_error("gss_delete_sec_context", ret, minor);
			SIPE_DEBUG_ERROR("sip_sec_krb5_destroy_context: failed to delete security context (ret=%d)", (int)ret);
		}
		context->ctx_krb5 = GSS_C_NO_CONTEXT;
	}

	if (context->cred_krb5 != GSS_C_NO_CREDENTIAL) {
		ret = gss_release_cred(&minor, &(context->cred_krb5));
		if (GSS_ERROR(ret)) {
			sip_sec_krb5_print_gss_error("gss_release_cred", ret, minor);
			SIPE_DEBUG_ERROR("sip_sec_krb5_destroy_context: failed to release credentials (ret=%d)", (int)ret);
		}
		context->cred_krb5 = GSS_C_NO_CREDENTIAL;
	}
}

static gboolean sip_sec_krb5_acquire_credentials(context_krb5 context)
{
	gchar **user_realm;
	const gchar *user, *realm;
	gchar *username, *tmp;
	OM_uint32 ret;
	OM_uint32 minor, minor_ignore;
	gss_cred_id_t credentials;
	gss_buffer_desc input_name_buffer;
	gss_name_t user_name;

	if (!(context->username || context->password)) {
		SIPE_DEBUG_ERROR_NOFORMAT("sip_sec_krb5_acquire_credentials: no valid authentication information provided");
		return(FALSE);
	}

	user_realm = g_strsplit(context->username, "@", 2);
	if (user_realm[1]) {
		/* "user@domain" -> use domain as realm */
		user  = user_realm[0];
		realm = user_realm[1];
	} else {
		/* use provided domain as realm */
		user  = context->username;
		realm = context->domain;
	}
	username = g_strdup_printf("%s@%s",
				   user, tmp = g_ascii_strup(realm, -1));
	g_free(tmp);
	g_strfreev(user_realm);

	input_name_buffer.value  = (void *) username;
	input_name_buffer.length = strlen(username) + 1;

	ret = gss_import_name(&minor,
			      &input_name_buffer,
			      (gss_OID) GSS_C_NT_USER_NAME,
			      &user_name);
	g_free(username);
	if (GSS_ERROR(ret)) {
		sip_sec_krb5_print_gss_error("gss_import_name", ret, minor);
		SIPE_DEBUG_ERROR("sip_sec_krb5_acquire_credentials: failed to construct user name (ret=%d)", (int)ret);
		return(FALSE);
	}

	/* Acquire user credentials with password */
	input_name_buffer.value  = (void *) context->password;
	input_name_buffer.length = strlen(context->password) + 1;
	ret = gss_acquire_cred_with_password(&minor,
					     user_name,
					     &input_name_buffer,
					     GSS_C_INDEFINITE,
					     GSS_C_NO_OID_SET,
					     GSS_C_INITIATE,
					     &credentials,
					     NULL,
					     NULL);
	gss_release_name(&minor_ignore, &user_name);

	if (GSS_ERROR(ret)) {
		sip_sec_krb5_print_gss_error("gss_acquire_cred_with_password", ret, minor);
		SIPE_DEBUG_ERROR("sip_sec_krb5_acquire_credentials: failed to acquire credentials (ret=%d)", (int)ret);
		return(FALSE);
	} else {
		context->cred_krb5 = credentials;
		return(TRUE);
	}
}

static gboolean sip_sec_krb5_initialize_context(context_krb5 context,
						SipSecBuffer in_buff,
						SipSecBuffer *out_buff,
						const gchar *service_name)
{
	OM_uint32 ret;
	OM_uint32 minor, minor_ignore;
	OM_uint32 expiry;
	gss_buffer_desc input_token;
	gss_buffer_desc output_token;
	gss_buffer_desc input_name_buffer;
	gss_name_t target_name;

	input_name_buffer.value  = (void *) service_name;
	input_name_buffer.length = strlen(service_name) + 1;

	ret = gss_import_name(&minor,
			      &input_name_buffer,
			      (gss_OID) GSS_KRB5_NT_PRINCIPAL_NAME,
			      &target_name);
	if (GSS_ERROR(ret)) {
		sip_sec_krb5_print_gss_error("gss_import_name", ret, minor);
		SIPE_DEBUG_ERROR("sip_sec_krb5_initialize_context: failed to construct target name (ret=%d)", (int)ret);
		return(FALSE);
	}

	input_token.length = in_buff.length;
	input_token.value = in_buff.value;

	output_token.length = 0;
	output_token.value = NULL;

	ret = gss_init_sec_context(&minor,
				   context->cred_krb5,
				   &(context->ctx_krb5),
				   target_name,
				   (gss_OID) gss_mech_krb5,
				   GSS_C_INTEG_FLAG,
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
		sip_sec_krb5_print_gss_error("gss_init_sec_context", ret, minor);
		SIPE_DEBUG_ERROR("sip_sec_krb5_initialize_context: failed to initialize context (ret=%d)", (int)ret);
		return(FALSE);
	}

	out_buff->length = output_token.length;
	out_buff->value  = g_memdup(output_token.value, output_token.length);
	gss_release_buffer(&minor_ignore, &output_token);

	context->common.expires = (int)expiry;

	/* Authentication is completed */
	context->common.flags |= SIP_SEC_FLAG_COMMON_READY;

	return(TRUE);
}

/* sip-sec-mech.h API implementation for Kerberos/GSS-API */

static gboolean
sip_sec_acquire_cred__krb5(SipSecContext context,
			   const gchar *domain,
			   const gchar *username,
			   const gchar *password)
{
	context_krb5 ctx = (context_krb5) context;

	SIPE_DEBUG_INFO_NOFORMAT("sip_sec_acquire_cred__krb5: started");

	/* remember authentication information */
	ctx->domain   = domain ? domain : "";
	ctx->username = username;
	ctx->password = password;

	/*
	 * This will be TRUE for SIP, which is the first time when we'll try
	 * to authenticate with Kerberos. We'll allow one retry with the
	 * authentication information provided by the user (see above).
	 *
	 * This will be FALSE for HTTP connections. If Kerberos authentication
	 * succeeded for SIP already, then there is no need to retry.
	 */
	if ((context->flags & SIP_SEC_FLAG_COMMON_HTTP) == 0)
		context->flags |= SIP_SEC_FLAG_KRB5_RETRY_AUTH;

	return(TRUE);
}

static gboolean
sip_sec_init_sec_context__krb5(SipSecContext context,
			       SipSecBuffer in_buff,
			       SipSecBuffer *out_buff,
			       const gchar *service_name)
{
	OM_uint32 ret;
	OM_uint32 minor;
	context_krb5 ctx = (context_krb5) context;
	gboolean result;

	SIPE_DEBUG_INFO_NOFORMAT("sip_sec_init_sec_context__krb5: started");

	/*
	 * If authentication was already completed, then this mean a new
	 * authentication handshake has started on the existing connection.
	 * We must throw away the old context, because we need a new one.
	 */
	if ((context->flags & SIP_SEC_FLAG_COMMON_READY) &&
	    (ctx->ctx_krb5 != GSS_C_NO_CONTEXT)) {
		ret = gss_delete_sec_context(&minor,
					     &(ctx->ctx_krb5),
					     GSS_C_NO_BUFFER);
		if (GSS_ERROR(ret)) {
			sip_sec_krb5_print_gss_error("gss_delete_sec_context", ret, minor);
			SIPE_DEBUG_ERROR("sip_sec_init_sec_context__krb5: failed to delete security context (ret=%d)", (int)ret);
		}
		ctx->ctx_krb5 = GSS_C_NO_CONTEXT;
	}

	result = sip_sec_krb5_initialize_context(ctx,
						 in_buff,
						 out_buff,
						 service_name);

	/*
	 * If context initialization fails then retry after trying to obtaining
	 * a TGT. This will will only succeed if we have been provided with
	 * valid authentication information by the user.
	 */
	if (!result && (context->flags & SIP_SEC_FLAG_KRB5_RETRY_AUTH)) {
		sip_sec_krb5_destroy_context(ctx);
		result = sip_sec_krb5_acquire_credentials(ctx) &&
			 sip_sec_krb5_initialize_context(ctx,
							 in_buff,
							 out_buff,
							 service_name);
	}

	/* Only retry once */
	context->flags &= ~SIP_SEC_FLAG_KRB5_RETRY_AUTH;

	return(result);
}

/**
 * @param message a NULL terminated string to sign
 */
static gboolean
sip_sec_make_signature__krb5(SipSecContext context,
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
			  ((context_krb5)context)->ctx_krb5,
			  GSS_C_QOP_DEFAULT,
			  &input_message,
			  &output_token);

	if (GSS_ERROR(ret)) {
		sip_sec_krb5_print_gss_error("gss_get_mic", ret, minor);
		SIPE_DEBUG_ERROR("sip_sec_make_signature__krb5: failed to make signature (ret=%d)", (int)ret);
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
sip_sec_verify_signature__krb5(SipSecContext context,
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
			     ((context_krb5)context)->ctx_krb5,
			     &input_message,
			     &input_token,
			     NULL);

	if (GSS_ERROR(ret)) {
		sip_sec_krb5_print_gss_error("gss_verify_mic", ret, minor);
		SIPE_DEBUG_ERROR("sip_sec_verify_signature__krb5: failed to make signature (ret=%d)", (int)ret);
		return FALSE;
	} else {
		return TRUE;
	}
}

static void
sip_sec_destroy_sec_context__krb5(SipSecContext context)
{
	sip_sec_krb5_destroy_context((context_krb5) context);
	g_free(context);
}

SipSecContext
sip_sec_create_context__krb5(SIPE_UNUSED_PARAMETER guint type)
{
	context_krb5 context = g_malloc0(sizeof(struct _context_krb5));
	if (!context) return(NULL);

	context->common.acquire_cred_func     = sip_sec_acquire_cred__krb5;
	context->common.init_context_func     = sip_sec_init_sec_context__krb5;
	context->common.destroy_context_func  = sip_sec_destroy_sec_context__krb5;
	context->common.make_signature_func   = sip_sec_make_signature__krb5;
	context->common.verify_signature_func = sip_sec_verify_signature__krb5;

	context->cred_krb5 = GSS_C_NO_CREDENTIAL;
	context->ctx_krb5  = GSS_C_NO_CONTEXT;

	return((SipSecContext) context);
}

gboolean sip_sec_password__krb5(void)
{
	/* Kerberos supports Single-Sign On */
	return(FALSE);
}

static void
sip_sec_krb5_print_gss_error0(char *func,
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

		SIPE_DEBUG_ERROR("sip_sec_krb5: GSS-API error in %s (%s): %s", func, (type == GSS_C_GSS_CODE ? "GSS" : "Mech"), (char *)status_string.value);
		gss_release_buffer(&minor, &status_string);
	} while (message_context != 0);
}

/**
 * Prints out errors of GSS-API function invocation
 */
static void sip_sec_krb5_print_gss_error(char *func, OM_uint32 ret, OM_uint32 minor)
{
	sip_sec_krb5_print_gss_error0(func, ret, GSS_C_GSS_CODE);
	sip_sec_krb5_print_gss_error0(func, minor, GSS_C_MECH_CODE);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
