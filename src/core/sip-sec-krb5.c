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
#include <gssapi/gssapi_krb5.h>
#include <krb5.h>

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
} *context_krb5;

static void sip_sec_krb5_print_gss_error(char *func, OM_uint32 ret, OM_uint32 minor);

static void
sip_sec_krb5_obtain_tgt(const char *realm,
		        const char *username,
			const char *password);

/* sip-sec-mech.h API implementation for Kerberos/GSS-API */

/**
 * Depending on Single Sign-On flag (sso),
 * obtains existing credentials stored in credentials cash in case of Kerberos,
 * or attemps to obtain TGT on its own first.
 */
static sip_uint32
sip_sec_acquire_cred__krb5(SipSecContext context,
			    const char *domain,
			    const char *username,
			    const char *password)
{
	OM_uint32 ret;
	OM_uint32 minor;
	OM_uint32 expiry;
	gss_cred_id_t credentials;

	if (!context->sso) {
		/* Do not use default credentials, obtain a new one and store it in cache */
		sip_sec_krb5_obtain_tgt(g_ascii_strup(domain, -1), username, password);
	}

	/* Acquire default user credentials */
	ret = gss_acquire_cred(&minor,
			       GSS_C_NO_NAME,
			       GSS_C_INDEFINITE,
			       GSS_C_NO_OID_SET,
			       GSS_C_INITIATE,
			       &credentials,
			       NULL,
			       &expiry);

	if (GSS_ERROR(ret)) {
		sip_sec_krb5_print_gss_error("gss_acquire_cred", ret, minor);
		SIPE_DEBUG_ERROR("sip_sec_acquire_cred__krb5: failed to acquire credentials (ret=%d)", (int)ret);
		return SIP_SEC_E_INTERNAL_ERROR;
	} else {
		((context_krb5)context)->cred_krb5 = credentials;
		return SIP_SEC_E_OK;
	}
}

static sip_uint32
sip_sec_init_sec_context__krb5(SipSecContext context,
			       SipSecBuffer in_buff,
			       SipSecBuffer *out_buff,
			       const char *service_name)
{
	OM_uint32 ret;
	OM_uint32 minor;
	OM_uint32 expiry;
	gss_buffer_desc input_token;
	gss_buffer_desc output_token;
	gss_buffer_desc input_name_buffer;
	gss_name_t target_name;
	context_krb5 ctx = (context_krb5) context;

	SIPE_DEBUG_INFO_NOFORMAT("sip_sec_init_sec_context__krb5: started");

	/* Delete old context first */
	if (ctx->ctx_krb5 != GSS_C_NO_CONTEXT) {
		ret = gss_delete_sec_context(&minor,
					     &(ctx->ctx_krb5),
					     GSS_C_NO_BUFFER);
		if (GSS_ERROR(ret)) {
			sip_sec_krb5_print_gss_error("gss_delete_sec_context", ret, minor);
			SIPE_DEBUG_ERROR("sip_sec_init_sec_context__krb5: failed to delete security context (ret=%d)", (int)ret);
		}
		ctx->ctx_krb5 = GSS_C_NO_CONTEXT;
	}

	input_name_buffer.value = (void *)service_name;
	input_name_buffer.length = strlen(input_name_buffer.value) + 1;

	ret = gss_import_name(&minor,
			      &input_name_buffer,
			      (gss_OID) GSS_KRB5_NT_PRINCIPAL_NAME,
			      &target_name);
	if (GSS_ERROR(ret)) {
		sip_sec_krb5_print_gss_error("gss_import_name", ret, minor);
		SIPE_DEBUG_ERROR("sip_sec_init_sec_context__krb5: failed to construct target name (ret=%d)", (int)ret);
		return SIP_SEC_E_INTERNAL_ERROR;
	}

	input_token.length = in_buff.length;
	input_token.value = in_buff.value;

	output_token.length = 0;
	output_token.value = NULL;

	ret = gss_init_sec_context(&minor,
				   ctx->cred_krb5,
				   &(ctx->ctx_krb5),
				   target_name,
				   GSS_C_NO_OID,
				   GSS_C_INTEG_FLAG,
				   GSS_C_INDEFINITE,
				   GSS_C_NO_CHANNEL_BINDINGS,
				   &input_token,
				   NULL,
				   &output_token,
				   NULL,
				   &expiry);

	if (GSS_ERROR(ret)) {
		sip_sec_krb5_print_gss_error("gss_init_sec_context", ret, minor);
		SIPE_DEBUG_ERROR("sip_sec_init_sec_context__krb5: failed to initialize context (ret=%d)", (int)ret);
		return SIP_SEC_E_INTERNAL_ERROR;
	}

	out_buff->length = output_token.length;
	out_buff->value = output_token.value;

	context->expires = (int)expiry;

	/* Authentication is completed */
	context->is_ready = TRUE;

	return SIP_SEC_E_OK;
}

/**
 * @param message a NULL terminated string to sign
 */
static sip_uint32
sip_sec_make_signature__krb5(SipSecContext context,
			     const char *message,
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
		return SIP_SEC_E_INTERNAL_ERROR;
	} else {
		signature->value = output_token.value;
		signature->length = output_token.length;

		return SIP_SEC_E_OK;
	}
}

/**
 * @param message a NULL terminated string to check signature of
 */
static sip_uint32
sip_sec_verify_signature__krb5(SipSecContext context,
			       const char *message,
			       SipSecBuffer signature)
{
	OM_uint32 ret;
	OM_uint32 minor;
	gss_qop_t qop_state;
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
			     &qop_state);

	if (GSS_ERROR(ret)) {
		sip_sec_krb5_print_gss_error("gss_verify_mic", ret, minor);
		SIPE_DEBUG_ERROR("sip_sec_verify_signature__krb5: failed to make signature (ret=%d)", (int)ret);
		return SIP_SEC_E_INTERNAL_ERROR;
	} else {
		return SIP_SEC_E_OK;
	}
}

static void
sip_sec_destroy_sec_context__krb5(SipSecContext context)
{
	OM_uint32 ret;
	OM_uint32 minor;
	context_krb5 ctx = (context_krb5) context;

	if (ctx->cred_krb5) {
		ret = gss_release_cred(&minor, &(ctx->cred_krb5));
		if (GSS_ERROR(ret)) {
			sip_sec_krb5_print_gss_error("gss_release_cred", ret, minor);
			SIPE_DEBUG_ERROR("sip_sec_destroy_sec_context__krb5: failed to release credentials (ret=%d)", (int)ret);
		}
	}

	if (ctx->ctx_krb5 != GSS_C_NO_CONTEXT) {
		ret = gss_delete_sec_context(&minor, &(ctx->ctx_krb5), GSS_C_NO_BUFFER);
		if (GSS_ERROR(ret)) {
			sip_sec_krb5_print_gss_error("gss_delete_sec_context", ret, minor);
			SIPE_DEBUG_ERROR("sip_sec_destroy_sec_context__krb5: failed to delete security context (ret=%d)", (int)ret);
		}
	}

	g_free(ctx);
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

	context->ctx_krb5 = GSS_C_NO_CONTEXT;

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

/**
 * Prints out errors of Kerberos 5 function invocation
 */
static void
sip_sec_krb5_print_error(const char *func,
			 krb5_context context,
			 krb5_error_code ret);

/**
 * Obtains Kerberos TGT and stores it in default credentials cache.
 * Similar what kinit util would do.
 * Can be checked with klist util.
 *
 * kinit would require the following name:
 * alice@ATLANTA.LOCAL
 * where 'alice' is a username and
 * 'ATLANTA.LOCAL' is a realm (domain) .
 */
static void
sip_sec_krb5_obtain_tgt(SIPE_UNUSED_PARAMETER const char *realm_in,
		        const char *username_in,
			const char *password)
{
	krb5_context	context;
	krb5_principal	principal = NULL;
	krb5_creds	credentials;
	krb5_ccache	ccdef;
	krb5_error_code	ret;
	char *realm;
	char *username;
	gchar **domain_user;
	gchar **user_realm;

	SIPE_DEBUG_INFO_NOFORMAT("sip_sec_krb5_obtain_tgt: started");

	memset(&credentials, 0, sizeof(krb5_creds));

	/* extracts realm as domain part of username
	 * either before '\' or after '@'
	 */
	domain_user = g_strsplit(username_in, "\\", 2);
	if (domain_user && domain_user[1]) {
		realm = g_ascii_strup(domain_user[0], -1);
		username = g_strdup(domain_user[1]);
	} else {
		realm = g_strdup("");
		username = g_strdup(username_in);
	}
	g_strfreev(domain_user);

	user_realm = g_strsplit(username, "@", 2);
	if (user_realm && user_realm[1]) {
		g_free(username);
		g_free(realm);
		username = g_strdup(user_realm[0]);
		realm = g_ascii_strup(user_realm[1], -1);
	}
	g_strfreev(user_realm);

	/* Obtait TGT */
	if ((ret = krb5_init_context(&context))) {
		sip_sec_krb5_print_error("krb5_init_context", context, ret);
	}

	if (!ret && (ret = krb5_build_principal(context, &principal, strlen(realm), realm, username, NULL))) {
		sip_sec_krb5_print_error("krb5_build_principal", context, ret);
	}
	g_free(username);
	g_free(realm);

	if (!ret && (ret = krb5_get_init_creds_password(context, &credentials, principal, (char *)password, NULL, NULL, 0, NULL, NULL))) {
		sip_sec_krb5_print_error("krb5_get_init_creds_password", context, ret);
	}

	if (!ret) {
		SIPE_DEBUG_INFO_NOFORMAT("sip_sec_krb5_obtain_tgt: new TGT obtained");
	}


	/* Store TGT in default credential cache */
	if (!ret && (ret = krb5_cc_default(context, &ccdef))) {
		sip_sec_krb5_print_error("krb5_cc_default", context, ret);
	}

	if (!ret && (ret = krb5_cc_initialize(context, ccdef, credentials.client))) {
		sip_sec_krb5_print_error("krb5_cc_initialize", context, ret);
	}

	if (!ret && (ret = krb5_cc_store_cred(context, ccdef, &credentials))) {
		sip_sec_krb5_print_error("krb5_cc_store_cred", context, ret);
	}

	if (!ret) {
		SIPE_DEBUG_INFO_NOFORMAT("sip_sec_krb5_obtain_tgt: new TGT stored in default credentials cache");
	}


	if (principal)
		krb5_free_principal(context, principal);

	if (context)
		krb5_free_context(context);
}

#if defined(HAVE_KRB5_GET_ERROR_MESSAGE)
static void
sip_sec_krb5_print_error(const char *func,
			 krb5_context context,
			 krb5_error_code ret)
{
	const char *error_message = krb5_get_error_message(context, ret);
	SIPE_DEBUG_ERROR("Kerberos 5 ERROR in %s: %s", func, error_message);
	krb5_free_error_message(context, error_message);
}
#else
static void
sip_sec_krb5_print_error(const char *func,
			 SIPE_UNUSED_PARAMETER krb5_context context,
			 SIPE_UNUSED_PARAMETER krb5_error_code ret)
{
	SIPE_DEBUG_ERROR("Kerberos 5 ERROR in %s: %s", func, "unknown error");
}
#endif

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
