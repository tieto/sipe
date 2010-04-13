/**
 * @file sip-sec-sspi.c
 *
 * pidgin-sipe
 *
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

#include <stdio.h>
#include <windows.h>
#include <rpc.h>
#include <security.h>

#include <glib.h>

#include "sip-sec.h"
#include "sip-sec-mech.h"
#include "sip-sec-sspi.h"
#include "sipe-backend.h"

/* Mechanism names */
#define SSPI_MECH_NTLM      "NTLM"
#define SSPI_MECH_KERBEROS  "Kerberos"
#define SSPI_MECH_NEGOTIATE "Negotiate"

#define ISC_REQ_IDENTIFY               0x00002000

typedef struct _context_sspi {
	struct sip_sec_context common;
	CredHandle* cred_sspi;
	CtxtHandle* ctx_sspi;
	/** Kerberos or NTLM */
	const char *mech;
} *context_sspi;

static int
sip_sec_get_interval_from_now_sec(TimeStamp timestamp);

void
sip_sec_sspi_print_error(const char *func,
			 SECURITY_STATUS ret);

/** internal method */
static void
sip_sec_destroy_sspi_context(context_sspi context)
{
	if (context->ctx_sspi)
		DeleteSecurityContext(context->ctx_sspi);
	if (context->cred_sspi)
		FreeCredentialsHandle(context->cred_sspi);
}

/* sip-sec-mech.h API implementation for SSPI - Kerberos and NTLM */

static sip_uint32
sip_sec_acquire_cred__sspi(SipSecContext context,
			   const char *domain,
			   const char *username,
			   const char *password)
{
	SECURITY_STATUS ret;
	TimeStamp expiry;
	SEC_WINNT_AUTH_IDENTITY auth_identity;
	context_sspi ctx = (context_sspi)context;
	CredHandle *cred_handle;

	if (username) {
		if (!password) {
			return SIP_SEC_E_INTERNAL_ERROR;
		}

		memset(&auth_identity, 0, sizeof(auth_identity));
		auth_identity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;

		if ( domain && (strlen(domain) > 0) ) {
			auth_identity.Domain = (unsigned char*)domain;
			auth_identity.DomainLength = strlen(domain);
		}

		auth_identity.User = (unsigned char*)username;
		auth_identity.UserLength = strlen(username);

		auth_identity.Password = (unsigned char*)password;
		auth_identity.PasswordLength = strlen(password);
	}
	
	cred_handle = g_malloc0(sizeof(CredHandle));
	
	ret = AcquireCredentialsHandle(	NULL,
					(SEC_CHAR *)ctx->mech,
					SECPKG_CRED_OUTBOUND,
					NULL,
					(context->sso || !username) ? NULL : &auth_identity,
					NULL,
					NULL,
					cred_handle,
					&expiry
					);

	if (ret != SEC_E_OK) {
		sip_sec_sspi_print_error("sip_sec_acquire_cred__sspi: AcquireCredentialsHandle", ret);
		ctx->cred_sspi = NULL;
		return SIP_SEC_E_INTERNAL_ERROR;
	} else {
		ctx->cred_sspi = cred_handle;
		return SIP_SEC_E_OK;
	}
}

static sip_uint32
sip_sec_init_sec_context__sspi(SipSecContext context,
			       SipSecBuffer in_buff,
			       SipSecBuffer *out_buff,
			       const char *service_name)
{
	TimeStamp expiry;
	SecBufferDesc input_desc, output_desc;
	SecBuffer in_token, out_token;
	SECURITY_STATUS ret;
	ULONG req_flags;
	ULONG ret_flags;
	context_sspi ctx = (context_sspi)context;
	CtxtHandle* out_context = g_malloc0(sizeof(CtxtHandle));
	
	SIPE_DEBUG_INFO_NOFORMAT("sip_sec_init_sec_context__sspi: in use");

	input_desc.cBuffers = 1;
	input_desc.pBuffers = &in_token;
	input_desc.ulVersion = SECBUFFER_VERSION;

	/* input token */
	in_token.BufferType = SECBUFFER_TOKEN;
	in_token.cbBuffer = in_buff.length;
	in_token.pvBuffer = in_buff.value;

	output_desc.cBuffers = 1;
	output_desc.pBuffers = &out_token;
	output_desc.ulVersion = SECBUFFER_VERSION;

	/* to hold output token */
	out_token.BufferType = SECBUFFER_TOKEN;
	out_token.cbBuffer = 0;
	out_token.pvBuffer = NULL;

	req_flags = (ISC_REQ_ALLOCATE_MEMORY |
		     ISC_REQ_INTEGRITY |
		     ISC_REQ_IDENTIFY);

	if (ctx->mech && !strcmp(ctx->mech, SSPI_MECH_NTLM) &&
	    !context->is_connection_based)
	{
		req_flags |= (ISC_REQ_DATAGRAM);
	}

	ret = InitializeSecurityContext(ctx->cred_sspi,
					ctx->ctx_sspi,
					(SEC_CHAR *)service_name,
					req_flags,
					0,
					SECURITY_NATIVE_DREP,
					&input_desc,
					0,
					out_context,
					&output_desc,
					&ret_flags,
					&expiry
					);

	if (ret != SEC_E_OK && ret != SEC_I_CONTINUE_NEEDED) {
		sip_sec_destroy_sspi_context(ctx);
		sip_sec_sspi_print_error("sip_sec_init_sec_context__sspi: InitializeSecurityContext", ret);
		return SIP_SEC_E_INTERNAL_ERROR;
	}

	out_buff->length = out_token.cbBuffer;
	out_buff->value = NULL;
	if (out_token.cbBuffer) {
		out_buff->value = g_malloc0(out_token.cbBuffer);
		memmove(out_buff->value, out_token.pvBuffer, out_token.cbBuffer);
		FreeContextBuffer(out_token.pvBuffer);
	}
	
	ctx->ctx_sspi = out_context;
	if (ctx->mech && !strcmp(ctx->mech, SSPI_MECH_KERBEROS)) {
		context->expires = sip_sec_get_interval_from_now_sec(expiry);
	}
	
	if (ret == SEC_I_CONTINUE_NEEDED) {
		return SIP_SEC_I_CONTINUE_NEEDED;
	} else	{
		return SIP_SEC_E_OK;
	}
}

static void
sip_sec_destroy_sec_context__sspi(SipSecContext context)
{
	sip_sec_destroy_sspi_context((context_sspi)context);
	g_free(context);
}

/**
 * @param message a NULL terminated string to sign
 *
 */
static sip_uint32
sip_sec_make_signature__sspi(SipSecContext context,
			     const char *message,
			     SipSecBuffer *signature)
{
	SecBufferDesc buffs_desc;
	SecBuffer buffs[2];
	SECURITY_STATUS ret;
	SecPkgContext_Sizes context_sizes;
	unsigned char *signature_buff;
	size_t signature_buff_length;
	context_sspi ctx = (context_sspi) context;

	ret = QueryContextAttributes(ctx->ctx_sspi,
					SECPKG_ATTR_SIZES,
					&context_sizes);

	if (ret != SEC_E_OK) {
		sip_sec_sspi_print_error("sip_sec_make_signature__sspi: QueryContextAttributes", ret);
		return SIP_SEC_E_INTERNAL_ERROR;
	}

	signature_buff_length = context_sizes.cbMaxSignature;
	signature_buff = g_malloc0(signature_buff_length);

	buffs_desc.cBuffers = 2;
	buffs_desc.pBuffers = buffs;
	buffs_desc.ulVersion = SECBUFFER_VERSION;

	/* message to sign */
	buffs[0].BufferType = SECBUFFER_DATA;
	buffs[0].cbBuffer = strlen(message);
	buffs[0].pvBuffer = (PVOID)message;

	/* to hold signature */
	buffs[1].BufferType = SECBUFFER_TOKEN;
	buffs[1].cbBuffer = signature_buff_length;
	buffs[1].pvBuffer = signature_buff;

	ret = MakeSignature(ctx->ctx_sspi,
			    (ULONG)0,
			    &buffs_desc,
			    100);
	if (ret != SEC_E_OK) {
		sip_sec_sspi_print_error("sip_sec_make_signature__sspi: MakeSignature", ret);
		g_free(signature_buff);
		return SIP_SEC_E_INTERNAL_ERROR;
	}

	signature->value = signature_buff;
	signature->length = buffs[1].cbBuffer;

	return SIP_SEC_E_OK;
}

/**
 * @param message a NULL terminated string to check signature of
 * @return SIP_SEC_E_OK on success
 */
static sip_uint32
sip_sec_verify_signature__sspi(SipSecContext context,
			       const char *message,
			       SipSecBuffer signature)
{
	SecBufferDesc buffs_desc;
	SecBuffer buffs[2];
	SECURITY_STATUS ret;

	buffs_desc.cBuffers = 2;
	buffs_desc.pBuffers = buffs;
	buffs_desc.ulVersion = SECBUFFER_VERSION;

	/* message to sign */
	buffs[0].BufferType = SECBUFFER_DATA;
	buffs[0].cbBuffer = strlen(message);
	buffs[0].pvBuffer = (PVOID)message;

	/* signature to check */
	buffs[1].BufferType = SECBUFFER_TOKEN;
	buffs[1].cbBuffer = signature.length;
	buffs[1].pvBuffer = signature.value;

	ret = VerifySignature(((context_sspi)context)->ctx_sspi,
			      &buffs_desc,
			      0,
			      0);

	if (ret != SEC_E_OK) {
		sip_sec_sspi_print_error("sip_sec_verify_signature__sspi: VerifySignature", ret);
		return SIP_SEC_E_INTERNAL_ERROR;
	}

	return SIP_SEC_E_OK;
}

SipSecContext
sip_sec_create_context__sspi(guint type)
{
	context_sspi context = g_malloc0(sizeof(struct _context_sspi));
	if (!context) return(NULL);

	context->common.acquire_cred_func     = sip_sec_acquire_cred__sspi;
	context->common.init_context_func     = sip_sec_init_sec_context__sspi;
	context->common.destroy_context_func  = sip_sec_destroy_sec_context__sspi;
	context->common.make_signature_func   = sip_sec_make_signature__sspi;
	context->common.verify_signature_func = sip_sec_verify_signature__sspi;
	context->mech = (type == AUTH_TYPE_NTLM) ? SSPI_MECH_NTLM : 
			((type == AUTH_TYPE_KERBEROS) ? SSPI_MECH_KERBEROS : SSPI_MECH_NEGOTIATE);

	return((SipSecContext) context);
}

/* Utility Functions */

/** 
 * Returns interval in seconds from now till provided value
 */
static int
sip_sec_get_interval_from_now_sec(TimeStamp timestamp)
{
	SYSTEMTIME stNow;
	FILETIME ftNow;
	ULARGE_INTEGER uliNow, uliTo;
	
	GetLocalTime(&stNow);
	SystemTimeToFileTime(&stNow, &ftNow);
	
	uliNow.LowPart = ftNow.dwLowDateTime;
	uliNow.HighPart = ftNow.dwHighDateTime;
	
	uliTo.LowPart = timestamp.LowPart;
	uliTo.HighPart = timestamp.HighPart;
	
	return (int)((uliTo.QuadPart - uliNow.QuadPart)/10/1000/1000);
}

void
sip_sec_sspi_print_error(const char *func,
			 SECURITY_STATUS ret)
{
	char *error_message;	
	static char *buff;
	int buff_length;

	buff_length = FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM |
				    FORMAT_MESSAGE_ALLOCATE_BUFFER |
				    FORMAT_MESSAGE_IGNORE_INSERTS,
				    0,
				    ret,
				    0,
				    (LPTSTR)&buff,
				    16384,
				    0);
	error_message = g_strndup(buff, buff_length);
	LocalFree(buff);

	printf("SSPI ERROR [%d] in %s: %s", (int)ret, func, error_message);
	g_free(error_message);
}


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
