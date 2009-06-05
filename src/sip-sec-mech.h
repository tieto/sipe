/**
 * @file sip-sec-mech.h
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
 
							
/* Mechanism wrappers API  (Inspired by GSS-API) 
 * All mechanisms should implement this API
 *
 * Current mechanisms are: Kerberos/GSS-API, sipe's NTLM and SSPI.
 */
 
#ifndef _SIP_SEC_MECH_H
#define _SIP_SEC_MECH_H

#define SIP_SEC_E_OK 0
#define SIP_SEC_E_INTERNAL_ERROR (-2146893052)
#define SIP_SEC_I_CONTINUE_NEEDED 590610

typedef unsigned long sip_uint32;

typedef void* SipSecCred;
typedef void* SipSecContext;

typedef struct sip_buffer_desc_struct {
	size_t length;
	void *value;
} SipSecBuffer;


typedef sip_uint32 
(*sip_sec_acquire_cred_func)(SipSecCred *cred_handle, const char *sec_package, const char *domain, const char *username, const char *password);

typedef sip_uint32
(*sip_sec_init_sec_context_func)(SipSecCred cred_handle, const char *sec_package, SipSecContext *context,
				 SipSecBuffer in_buff,
				 SipSecBuffer *out_buff,
				 const char *service_name);
						
typedef sip_uint32
(*sip_sec_make_signature_func)(SipSecContext context, const char *message, SipSecBuffer *signature);
							
typedef sip_uint32
(*sip_sec_verify_signature_func)(SipSecContext context,	const char *message, SipSecBuffer signature);
						
#endif /* _SIP_SEC_MECH_H */
