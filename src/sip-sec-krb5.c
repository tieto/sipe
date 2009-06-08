/**
 * @file sip-sec-krb5.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009 pier11 <pier11@kinozal.tv>
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
#include <stdio.h>
#include <string.h>
#include <gssapi.h>
#include <gssapi/gssapi_krb5.h>

#include "sip-sec.h"
#include "sip-sec-mech.h"

/* Security context for Kerberos */
typedef struct _context_krb5 {
	struct sip_sec_context common;
	gss_cred_id_t cred_krb5;
	gss_ctx_id_t ctx_krb5;
	sip_uint32 expiry;
} *context_krb5;

void sip_sec_krb5_print_gss_error(char *func, OM_uint32 ret, OM_uint32 minor);


static sip_uint32
sip_sec_init_sec_context__krb5(SipSecContext context,
			       SipSecBuffer in_buff,
			       SipSecBuffer *out_buff,
			       const char *service_name)
{
	OM_uint32 ret;
	OM_uint32 minor;
	OM_uint32 expiry;
	OM_uint32 request_flags;
	OM_uint32 response_flags;
	gss_buffer_desc input_token;
	gss_buffer_desc output_token;
	gss_buffer_desc input_name_buffer;
	gss_name_t target_name;
	context_krb5 ctx = (context_krb5) context;
	
	input_name_buffer.value = (void *)service_name;
	input_name_buffer.length = strlen(input_name_buffer.value) + 1;

	ret = gss_import_name(&minor,
			      &input_name_buffer,
			      (const gss_OID)GSS_KRB5_NT_PRINCIPAL_NAME,
			      &target_name);
	if (GSS_ERROR(ret)) {
		sip_sec_krb5_print_gss_error("gss_import_name", ret, minor);
		printf("ERROR: sip_sec_init_sec_context__krb5: failed to construct target name. Returned. ret=%d\n", (int)ret);
		return SIP_SEC_E_INTERNAL_ERROR;
	}
					
	request_flags = GSS_C_INTEG_FLAG;
	
	input_token.length = in_buff.length;
	input_token.value = in_buff.value;	

	output_token.length = 0;
	output_token.value = NULL;

	ret = gss_init_sec_context(&minor,
				   ctx->cred_krb5,
				   &(ctx->ctx_krb5),
				   target_name,
				   GSS_C_NO_OID,
				   request_flags,
				   GSS_C_INDEFINITE,
				   GSS_C_NO_CHANNEL_BINDINGS,
				   &input_token,
				   NULL,
				   &output_token,
				   &response_flags,
				   &expiry);

	if (GSS_ERROR(ret)) {
		sip_sec_krb5_print_gss_error("gss_init_sec_context", ret, minor);
		printf("ERROR: sip_sec_init_sec_context__krb5: failed to initialize context. ret=%d\n", (int)ret);
		return SIP_SEC_E_INTERNAL_ERROR;
	} else {
		ret = gss_release_cred(&minor, &(ctx->cred_krb5));
		if (GSS_ERROR(ret)) {
			sip_sec_krb5_print_gss_error("gss_release_cred", ret, minor);
			printf("ERROR: sip_sec_init_sec_context__krb5: failed to release credentials. ret=%d\n", (int)ret);
		}
	
		input_token.value = NULL;
		input_token.length = 0;
	
		out_buff->length = output_token.length;
		out_buff->value = output_token.value;

		ctx->expiry = expiry;
		return SIP_SEC_E_OK;
	}
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
		printf("ERROR: sip_ssp_make_signature: failed to make signature. ret=%d\n", (int)ret);
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
		printf("ERROR: sip_sec_verify_signature__krb5: failed to make signature. ret=%d\n", (int)ret);
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
			printf("ERROR: sip_sec_destroy_sec_context__krb5: failed to release credentials. ret=%d\n", (int)ret);
		}
	}
	
	if (ctx->ctx_krb5) {
		ret = gss_delete_sec_context(&minor, &(ctx->ctx_krb5), GSS_C_NO_BUFFER);
		if (GSS_ERROR(ret)) {
			sip_sec_krb5_print_gss_error("gss_delete_sec_context", ret, minor);
			printf("ERROR: sip_sec_destroy_sec_context__krb5: failed to delete security context. ret=%d\n", (int)ret);
		}
	}
		
	g_free(ctx);
}

/**
 * Obtains existing credentials stored in credentials cash in case of Kerberos
 */
SipSecContext
sip_sec_acquire_cred0__krb5(const char *domain,
			   const char *username,
			   const char *password)
{
	OM_uint32 ret;
	OM_uint32 minor;
	OM_uint32 expiry;
	struct gss_cred_id_struct* credentials;
	
	context_krb5 context = g_malloc0(sizeof(struct _context_krb5));
	if (!context) return(NULL);

	context->common.init_context_func     = sip_sec_init_sec_context__krb5;
	context->common.destroy_context_func  = sip_sec_destroy_sec_context__krb5;
	context->common.make_signature_func   = sip_sec_make_signature__krb5;
	context->common.verify_signature_func = sip_sec_verify_signature__krb5;

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
		printf("ERROR: sip_sec_acquire_cred0__krb5: failed to acquire credentials. ret=%d\n", (int)ret);
		return NULL;
	} else {
		context->cred_krb5 = credentials;
		return((SipSecContext) context);
	}
}

void
sip_sec_krb5_obtain_tgt(const char *realm,
		        const char *username,
			const char *password);

/**
 * Tries to obtain credentials from cache. On failure attemps to obtain TGT on its own.
 */
SipSecContext
sip_sec_acquire_cred__krb5(const char *domain,
			   const char *username,
			   const char *password)
{
	SipSecContext ret;
	/* Attempt to get stored credentials, likely after user login to domain. */
	ret = sip_sec_acquire_cred0__krb5(domain, username, password);
	if (!ret) {
		/* get TGT ourselves. */
		sip_sec_krb5_obtain_tgt(g_ascii_strup(domain, -1), username, password);
		ret = sip_sec_acquire_cred0__krb5(domain, username, password);
	}
	
	return ret;
}


static void
sip_sec_krb5_print_gss_error0(char *func,
			     OM_uint32 status,
			     int type)
{
	OM_uint32 ret;
	OM_uint32 minor;
	OM_uint32 message_context = 0;
	gss_buffer_desc status_string;
	
	do {
		ret = gss_display_status(&minor,
					 status,
					 type,
					 GSS_C_NO_OID,
					 &message_context,
					 &status_string);		

		printf("GSS-API error in %s (%s): %s\n", func, (type == GSS_C_GSS_CODE ? "GSS" : "Mech"), (char *)status_string.value);			
		gss_release_buffer(&minor, &status_string);
	} while (message_context != 0);
}

/**
 * Prints out errors of GSS-API function invocation
 */
void sip_sec_krb5_print_gss_error(char *func, OM_uint32 ret, OM_uint32 minor)
{
	sip_sec_krb5_print_gss_error0(func, ret, GSS_C_GSS_CODE);
	sip_sec_krb5_print_gss_error0(func, minor, GSS_C_MECH_CODE);
}

/**
 * Prints out errors of Kerberos 5 function invocation
 */
void
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
void
sip_sec_krb5_obtain_tgt(const char *realm,
		        const char *username,
			const char *password)
{
	krb5_context	context;
	krb5_principal	principal;
	krb5_creds	credentials;
	krb5_ccache	ccdef;
	krb5_error_code	ret;
	
	printf("sip_sec_krb5_obtain_tgt started\n");

	memset(&credentials, 0, sizeof(krb5_creds));

	/* Obtait TGT */
	if (ret = krb5_init_context(&context)) {
		sip_sec_krb5_print_error("krb5_init_context", context, ret);
	}
	
	if (!ret && (ret = krb5_build_principal(context, &principal, strlen(realm), realm, username, NULL))) {
		sip_sec_krb5_print_error("krb5_build_principal", context, ret);
	}

	if (!ret && (ret = krb5_get_init_creds_password(context, &credentials, principal, (char *)password, NULL, NULL, 0, NULL, NULL))) { 
		sip_sec_krb5_print_error("krb5_get_init_creds_password", context, ret);
	}
	
	if (!ret) {
		printf("sip_sec_krb5_obtain_tgt: new TGT obtained.\n");
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
		printf("sip_sec_krb5_obtain_tgt: new TGT stored in default credentials cache.\n");
	}
	

	if (principal)
		krb5_free_principal(context, principal);

	if (context)
		krb5_free_context(context);
}

void
sip_sec_krb5_print_error(const char *func,
			 krb5_context context,
			 krb5_error_code ret)
{
	const char *error_message = krb5_get_error_message(context, ret);
	printf("Kerberos 5 ERROR in %s: %s\n", func, error_message);
	
	krb5_free_error_message(context, error_message);
}
