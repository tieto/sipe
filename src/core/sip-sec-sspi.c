/**
 * @file sip-sec-sspi.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-2013 SIPE Project <http://sipe.sourceforge.net/>
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

#ifndef _WIN32
#error sip-sec-sspi.c can only be compiled for Windows builds
#endif

#include <windows.h>
#include <rpc.h>
#ifndef SECURITY_WIN32
#define SECURITY_WIN32 1
#endif
#include <security.h>

#include <string.h>

#include <glib.h>

#include "sipe-common.h"
#include "sip-sec.h"
#include "sip-sec-mech.h"
#include "sip-sec-sspi.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-utils.h"

/* Mechanism names */
static const gchar * const mech_names[] = {
	"",          /* SIPE_AUTHENTICATION_TYPE_UNSET     */
	"",          /* SIPE_AUTHENTICATION_TYPE_BASIC     */
	"NTLM",      /* SIPE_AUTHENTICATION_TYPE_NTLM      */
	"Kerberos",  /* SIPE_AUTHENTICATION_TYPE_KERBEROS  */
	"Negotiate", /* SIPE_AUTHENTICATION_TYPE_NEGOTIATE */
	"",          /* SIPE_AUTHENTICATION_TYPE_TLS_DSK   */
};

#ifndef ISC_REQ_IDENTIFY
#define ISC_REQ_IDENTIFY               0x00002000
#endif

typedef struct _context_sspi {
	struct sip_sec_context common;
	CredHandle* cred_sspi;
	CtxtHandle* ctx_sspi;
} *context_sspi;

#define SIP_SEC_FLAG_SSPI_SIP_NTLM 0x00010000

/* Utility Functions */

static void
sip_sec_sspi_print_error(const gchar *func,
			 SECURITY_STATUS ret)
{
	gchar *error_message;
	static char *buff;
	guint buff_length;

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

	SIPE_DEBUG_ERROR("SSPI ERROR [%d] in %s: %s", (int)ret, func, error_message);
	g_free(error_message);
}

/* Returns interval in seconds from now till provided value */
static guint
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

	return((uliTo.QuadPart - uliNow.QuadPart)/10/1000/1000);
}

static void
sip_sec_destroy_sspi_context(context_sspi context)
{
	if (context->ctx_sspi) {
		DeleteSecurityContext(context->ctx_sspi);
		g_free(context->ctx_sspi);
		context->ctx_sspi = NULL;
	}
	if (context->cred_sspi) {
		FreeCredentialsHandle(context->cred_sspi);
		g_free(context->cred_sspi);
		context->cred_sspi = NULL;
	}
}

/* sip-sec-mech.h API implementation for SSPI - Kerberos, NTLM and Negotiate */

static gboolean
sip_sec_acquire_cred__sspi(SipSecContext context,
			   const gchar *domain,
			   const gchar *username,
			   const gchar *password)
{
	SECURITY_STATUS ret;
	TimeStamp expiry;
	SEC_WINNT_AUTH_IDENTITY auth_identity;
	context_sspi ctx = (context_sspi)context;

	/* this is the first time we are allowed to set private flags */
	if (((context->flags & SIP_SEC_FLAG_COMMON_HTTP) == 0) &&
	    (context->type == SIPE_AUTHENTICATION_TYPE_NTLM))
		context->flags |= SIP_SEC_FLAG_SSPI_SIP_NTLM;

	if ((context->flags & SIP_SEC_FLAG_COMMON_SSO) == 0) {
		if (!username || !password) {
			return FALSE;
		}

		memset(&auth_identity, 0, sizeof(auth_identity));
		auth_identity.Flags = SEC_WINNT_AUTH_IDENTITY_ANSI;

		if (!is_empty(domain)) {
			auth_identity.Domain = (unsigned char*)domain;
			auth_identity.DomainLength = strlen(domain);
		}

		auth_identity.User = (unsigned char*)username;
		auth_identity.UserLength = strlen(username);

		auth_identity.Password = (unsigned char*)password;
		auth_identity.PasswordLength = strlen(password);
	}

	ctx->cred_sspi = g_malloc0(sizeof(CredHandle));

	ret = AcquireCredentialsHandleA(NULL,
					(SEC_CHAR *)mech_names[context->type],
					SECPKG_CRED_OUTBOUND,
					NULL,
					(context->flags & SIP_SEC_FLAG_COMMON_SSO) ? NULL : &auth_identity,
					NULL,
					NULL,
					ctx->cred_sspi,
					&expiry);

	if (ret != SEC_E_OK) {
		sip_sec_sspi_print_error("sip_sec_acquire_cred__sspi: AcquireCredentialsHandleA", ret);
		g_free(ctx->cred_sspi);
		ctx->cred_sspi = NULL;
		return FALSE;
	} else {
		return TRUE;
	}
}

static gboolean
sip_sec_init_sec_context__sspi(SipSecContext context,
			       SipSecBuffer in_buff,
			       SipSecBuffer *out_buff,
			       const gchar *service_name)
{
	TimeStamp expiry;
	SecBufferDesc input_desc, output_desc;
	SecBuffer in_token, out_token;
	SECURITY_STATUS ret;
	ULONG req_flags;
	ULONG ret_flags;
	context_sspi ctx = (context_sspi)context;
	CtxtHandle* out_context;

	SIPE_DEBUG_INFO_NOFORMAT("sip_sec_init_sec_context__sspi: in use");

	/*
	 * If authentication was already completed, then this mean a new
	 * authentication handshake has started on the existing connection.
	 * We must throw away the old context, because we need a new one.
	 */
	if ((context->flags & SIP_SEC_FLAG_COMMON_READY) &&
	    ctx->ctx_sspi) {
		SIPE_DEBUG_INFO_NOFORMAT("sip_sec_init_sec_context__sspi: dropping old context");
		DeleteSecurityContext(ctx->ctx_sspi);
		g_free(ctx->ctx_sspi);
		ctx->ctx_sspi = NULL;
		context->flags &= ~SIP_SEC_FLAG_COMMON_READY;
	}

	/* reuse existing context on following calls */
	out_context = ctx->ctx_sspi ? ctx->ctx_sspi : g_malloc0(sizeof(CtxtHandle));

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

	if (context->flags & SIP_SEC_FLAG_SSPI_SIP_NTLM) {
		req_flags |= (ISC_REQ_DATAGRAM);
	}

	ret = InitializeSecurityContextA(ctx->cred_sspi,
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
					 &expiry);

	if (ret != SEC_E_OK && ret != SEC_I_CONTINUE_NEEDED) {
		if (!ctx->ctx_sspi)
			g_free(out_context);
		sip_sec_destroy_sspi_context(ctx);
		sip_sec_sspi_print_error("sip_sec_init_sec_context__sspi: InitializeSecurityContextA", ret);
		return FALSE;
	}

	out_buff->length = out_token.cbBuffer;
	if (out_token.cbBuffer) {
		out_buff->value = g_malloc(out_token.cbBuffer);
		memcpy(out_buff->value, out_token.pvBuffer, out_token.cbBuffer);
	} else {
		/* Special case: empty token */
		out_buff->value = (guint8 *) g_strdup("");
	}
	FreeContextBuffer(out_token.pvBuffer);

	ctx->ctx_sspi = out_context;

	if (context->type == SIPE_AUTHENTICATION_TYPE_KERBEROS) {
		context->expires = sip_sec_get_interval_from_now_sec(expiry);
	}

	if (ret != SEC_I_CONTINUE_NEEDED) {
		/* Authentication is completed */
		context->flags |= SIP_SEC_FLAG_COMMON_READY;
	}

	return TRUE;
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
static gboolean
sip_sec_make_signature__sspi(SipSecContext context,
			     const gchar *message,
			     SipSecBuffer *signature)
{
	SecBufferDesc buffs_desc;
	SecBuffer buffs[2];
	SECURITY_STATUS ret;
	SecPkgContext_Sizes context_sizes;
	guchar *signature_buff;
	size_t signature_buff_length;
	context_sspi ctx = (context_sspi) context;

	ret = QueryContextAttributes(ctx->ctx_sspi,
				     SECPKG_ATTR_SIZES,
				     &context_sizes);

	if (ret != SEC_E_OK) {
		sip_sec_sspi_print_error("sip_sec_make_signature__sspi: QueryContextAttributes", ret);
		return FALSE;
	}

	signature_buff_length = context_sizes.cbMaxSignature;
	signature_buff = g_malloc(signature_buff_length);

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
		return FALSE;
	}

	signature->value = signature_buff;
	signature->length = buffs[1].cbBuffer;

	return TRUE;
}

/**
 * @param message a NULL terminated string to check signature of
 * @return TRUE on success
 */
static gboolean
sip_sec_verify_signature__sspi(SipSecContext context,
			       const gchar *message,
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
		return FALSE;
	}

	return TRUE;
}

/* SSPI implements SPNEGO (RFC 4559) */
static const gchar *
sip_sec_context_name__sspi(SipSecContext context)
{
	return(mech_names[context->type]);
}

SipSecContext
sip_sec_create_context__sspi(SIPE_UNUSED_PARAMETER guint type)
{
	context_sspi context = g_malloc0(sizeof(struct _context_sspi));
	if (!context) return(NULL);

	context->common.acquire_cred_func     = sip_sec_acquire_cred__sspi;
	context->common.init_context_func     = sip_sec_init_sec_context__sspi;
	context->common.destroy_context_func  = sip_sec_destroy_sec_context__sspi;
	context->common.make_signature_func   = sip_sec_make_signature__sspi;
	context->common.verify_signature_func = sip_sec_verify_signature__sspi;
	context->common.context_name_func     = sip_sec_context_name__sspi;

	return((SipSecContext) context);
}

gboolean sip_sec_password__sspi(void)
{
	/* SSPI supports Single-Sign On */
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
