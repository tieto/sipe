/**
 * @file sip-sec-mech.h
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

/* Mechanism wrappers API  (Inspired by GSS-API)
 * All mechanisms should implement this API
 *
 * Current mechanisms are: Kerberos/GSS-API, sipe's NTLM and SSPI.
 */

#define SIP_SEC_E_OK 0
#define SIP_SEC_E_INTERNAL_ERROR (-2146893052)
#define SIP_SEC_I_CONTINUE_NEEDED 590610

typedef unsigned long sip_uint32;

typedef struct {
	gsize   length;
	guint8 *value;
} SipSecBuffer;

typedef SipSecContext
(*sip_sec_create_context_func)(guint type);

typedef sip_uint32
(*sip_sec_acquire_cred_func)(SipSecContext context,
			     const char *domain,
			     const char *username,
			     const char *password);

typedef sip_uint32
(*sip_sec_init_context_func)(SipSecContext context,
			     SipSecBuffer in_buff,
			     SipSecBuffer *out_buff,
			     const char *service_name);

typedef void
(*sip_sec_destroy_context_func)(SipSecContext context);

typedef sip_uint32
(*sip_sec_make_signature_func)(SipSecContext context,
			       const char *message,
			       SipSecBuffer *signature);

typedef sip_uint32
(*sip_sec_verify_signature_func)(SipSecContext context,
				 const char *message,
				 SipSecBuffer signature);

struct sip_sec_context {
	sip_sec_acquire_cred_func     acquire_cred_func;
	sip_sec_init_context_func     init_context_func;
	sip_sec_destroy_context_func  destroy_context_func;
	sip_sec_make_signature_func   make_signature_func;
	sip_sec_verify_signature_func verify_signature_func;
	/** Single Sign-On request flag 0=FALSE */
	int sso;
	/** Security Context expiration interval in seconds */
	int expires;
	/** 0 - FALSE; otherwise TRUE */
	int is_connection_based;
};
