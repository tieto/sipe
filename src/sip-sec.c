/**
 * @file sip-sec.c
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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "debug.h"
#include "sip-sec.h"
//#include "sip-sec-mech.h"

#ifndef _WIN32
#include "sip-sec-ntlm.h"
#define sip_sec_acquire_cred__NTLM	sip_sec_acquire_cred__ntlm
//#include "sip-sec-krb5.h"
#define sip_sec_acquire_cred__Kerberos	NULL

#else //_WIN32
#if 0 //with SSPI
#include "sip-sec-sspi.h"
#define sip_sec_acquire_cred__NTLM	sip_sec_acquire_cred__sspi
#define sip_sec_acquire_cred__Kerberos	sip_sec_acquire_cred__sspi

#else //with SSPI
#include "sip-sec-ntlm.h"
#define sip_sec_acquire_cred__NTLM	sip_sec_acquire_cred__ntlm
#define sip_sec_acquire_cred__Kerberos	NULL
#endif //with SSPI

#endif //_WIN32


gchar *purple_base64_encode(const guchar *data, gsize len);
guchar *purple_base64_decode(const char *str, gsize *ret_len);

/* sip_sec API method */
char * sip_sec_init_context(SipSecContext *context, const char *mech,
			    const char *domain, const char *username, const char *password,
			    const char *target,
			    const char *input_toked_base64)
{
	SipSecCred cred_handle_p;
	sip_uint32 ret2;

	sip_sec_acquire_cred_func acquire_cred_func = !strncmp("Kerberos", mech, strlen(mech)) ? 
						sip_sec_acquire_cred__Kerberos : sip_sec_acquire_cred__NTLM;
						
	ret2 = (*acquire_cred_func)(&cred_handle_p, context, domain, username, password);

	char *service_name;
	sip_uint32 ret3, ret4;
	
	SipSecBuffer in_buff;
	in_buff.length = 0;
	in_buff.value = NULL;
	
	SipSecBuffer out_buff;
	gchar *out_buff_base64;
	
	ret3 = (*((struct sip_sec_context_struct *) *context)->init_context_func)(cred_handle_p, *context,
										  in_buff,
										  &out_buff,
										  target);
	out_buff_base64 = purple_base64_encode(out_buff.value, out_buff.length);
	//Type1 (empty) to send

	if (ret3 == SIP_SEC_I_CONTINUE_NEEDED) {
		SipSecBuffer in_buff;
		SipSecBuffer out_buff;
		
		//answer (Type2) 
		in_buff.value = purple_base64_decode(input_toked_base64, &(in_buff.length));
	
		ret4 = (*((struct sip_sec_context_struct *) *context)->init_context_func)(cred_handle_p, *context,
											  in_buff,
											  &out_buff,
											  target);
		
		// Type 3 to send
		g_free(out_buff_base64);
		out_buff_base64 = purple_base64_encode(out_buff.value, out_buff.length);
	}	
	
	return out_buff_base64;	
}

void
sip_sec_destroy_context(SipSecContext context)
{
	if (context) (*((struct sip_sec_context_struct *) context)->destroy_context_func)(context);
}

char * sip_sec_make_signature(SipSecContext context, const char *message)
{						
	SipSecBuffer signature;

	if(((*((struct sip_sec_context_struct *) context)->make_signature_func)(context,	message, &signature)) != SIP_SEC_E_OK) {
		purple_debug_info("sipe", "ERROR: sip_sec_make_signature failed. Unable to sign message!\n");
		return NULL;
	}
	char *signature_hex = bytes_to_hex_str(&signature);
	return signature_hex;
}

int sip_sec_verify_signature(SipSecContext context, const char* message, const char* signature_hex)
{
	SipSecBuffer signature;

	sip_uint32 res = SIP_SEC_E_INTERNAL_ERROR;

	hex_str_to_bytes(signature_hex, &signature);
	res = (*((struct sip_sec_context_struct *) context)->verify_signature_func)(context, message, signature);
	free_bytes_buffer(&signature);
	return res;
}								


// Utility Methods //

void hex_str_to_bytes(const char *hex_str, SipSecBuffer *bytes)
{
	guint8 *buff;
	char two_digits[3];
	int i;
	
	bytes->length = strlen(hex_str)/2;
	bytes->value = g_malloc(bytes->length);

	buff = (guint8 *)bytes->value;
	for (i = 0; i < bytes->length; i++) {		
		two_digits[0] = hex_str[i * 2];
		two_digits[1] = hex_str[i * 2 + 1];
		two_digits[2] = '\0';
		guint8 tmp = (guint8)strtoul(two_digits, NULL, 16);
		buff[i] = tmp;		
	}
}

void free_bytes_buffer(SipSecBuffer *bytes)
{
	g_free(bytes->value);
}

char *bytes_to_hex_str(SipSecBuffer *bytes)
{
	guint8 *buff = (guint8 *)bytes->value;
	char *res    = g_malloc(bytes->length * 2 + 1);
	int i, j;
	for (i = 0, j = 0; i < bytes->length; i++, j+=2) {
		sprintf(&res[j], "%02X", buff[i]);
	}
	res[j] = '\0';
	return res;
}
