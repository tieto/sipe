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

typedef struct {
	size_t length;
	void *value;
} SipSecBuffer;


typedef SipSecContext
(*sip_sec_acquire_cred_func)(const char *domain,
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
	sip_sec_init_context_func     init_context_func;
	sip_sec_destroy_context_func  destroy_context_func;
	sip_sec_make_signature_func   make_signature_func;
	sip_sec_verify_signature_func verify_signature_func;
};

/// Utility methods (implemented in sip-sec.c)

/**
 * Converts a string of hex digits into bytes.
 *
 * Allocates memory for 'bytes', must be freed after use
 */
void hex_str_to_bytes(const char *hex_str, SipSecBuffer *bytes);
void free_bytes_buffer(SipSecBuffer *bytes);

/** Allocates memory for output, must be freed after use */
char *bytes_to_hex_str(SipSecBuffer *bytes);

#endif /* _SIP_SEC_MECH_H */
