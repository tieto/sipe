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
#define sip_sec_acquire_cred__NTLM			sip_sec_acquire_cred__ntlm
#define sip_sec_init_sec_context__NTLM		sip_sec_init_sec_context__ntlm
#define sip_sec_make_signature__NTLM		sip_sec_make_signature__ntlm
#define sip_sec_verify_signature__NTLM		sip_sec_verify_signature__ntlm

//#include "sip-sec-krb5.h"
#define sip_sec_acquire_cred__Kerberos		NULL
#define sip_sec_init_sec_context__Kerberos	NULL
#define sip_sec_make_signature__Kerberos	NULL
#define sip_sec_verify_signature__Kerberos	NULL

#else //_WIN32
#if 0 //with SSPI
#include "sip-sec-sspi.h"
#define sip_sec_acquire_cred__NTLM			sip_sec_acquire_cred__sspi
#define sip_sec_init_sec_context__NTLM		sip_sec_init_sec_context__sspi
#define sip_sec_make_signature__NTLM		sip_sec_make_signature__sspi
#define sip_sec_verify_signature__NTLM		sip_sec_verify_signature__sspi

#define sip_sec_acquire_cred__Kerberos		sip_sec_acquire_cred__sspi
#define sip_sec_init_sec_context__Kerberos	sip_sec_init_sec_context__sspi
#define sip_sec_make_signature__Kerberos	sip_sec_make_signature__sspi
#define sip_sec_verify_signature__Kerberos	sip_sec_verify_signature__sspi

#else //with SSPI
#include "sip-sec-ntlm.h"
#define sip_sec_acquire_cred__NTLM			sip_sec_acquire_cred__ntlm
#define sip_sec_init_sec_context__NTLM		sip_sec_init_sec_context__ntlm
#define sip_sec_make_signature__NTLM		sip_sec_make_signature__ntlm
#define sip_sec_verify_signature__NTLM		sip_sec_verify_signature__ntlm

#define sip_sec_acquire_cred__Kerberos		NULL
#define sip_sec_init_sec_context__Kerberos	NULL
#define sip_sec_make_signature__Kerberos	NULL
#define sip_sec_verify_signature__Kerberos	NULL
#endif //with SSPI

#endif //_WIN32


gchar *purple_base64_encode(const guchar *data, gsize len);
guchar *purple_base64_decode(const char *str, gsize *ret_len);

/* sip_sec API method */
char * sip_sec_init_context(SipSecContext *context, const char* mech,
								const char *domain, const char *username, const char *password,
								const char *target,
								const char *input_toked_base64)
{	
	SipSecCred cred_handle_p;
	sip_uint32 ret2;

	sip_sec_acquire_cred_func acquire_cred_func = !strncmp("Kerberos", mech, strlen(mech)) ? 
						sip_sec_acquire_cred__Kerberos : sip_sec_acquire_cred__NTLM;
	sip_sec_init_sec_context_func init_sec_context_func = !strncmp("Kerberos", mech, strlen(mech)) ? 
						sip_sec_init_sec_context__Kerberos : sip_sec_init_sec_context__NTLM;
						
	ret2 = (*acquire_cred_func)(&cred_handle_p, mech, (char *)domain, (char *)username, password); 

	char *service_name;
	sip_uint32 ret3, ret4;
	
	SipSecBuffer in_buff;
	in_buff.length = 0;
	in_buff.value = NULL;
	
	SipSecBuffer out_buff;
	gchar *out_buff_base64;
	
	*context = NULL;
	ret3 = (*init_sec_context_func)(cred_handle_p, mech, context,
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
					
		ret4 = (*init_sec_context_func)(cred_handle_p, mech, context, 
										in_buff,
										&out_buff,
										target);
		
		// Type 3 to send
		g_free(out_buff_base64);
		out_buff_base64 = purple_base64_encode(out_buff.value, out_buff.length);
	}	
	
	return out_buff_base64;	
}

char * sip_sec_make_signature(SipSecContext context, const char* mech, const char *message)
{						
	SipSecBuffer signature;
	
	sip_sec_make_signature_func make_signature_func = !strncmp("Kerberos", mech, strlen(mech)) ? 
						sip_sec_make_signature__Kerberos : sip_sec_make_signature__NTLM;
	
	if(((*make_signature_func)(context,	message, &signature)) != SIP_SEC_E_OK) {
		purple_debug_info("sipe", "ERROR: sip_sec_make_signature failed. Unable to sign message!\n");
		return NULL;
	}
	char *signature_hex = bytes_to_hex_str(signature);
	//@TODO clean up buffers.
	return signature_hex;
}			
 
int sip_sec_verify_signature(SipSecContext context, const char* mech, const char* message, const char* signature_hex)
{								
	SipSecBuffer signature;
	
	sip_uint32 res = SIP_SEC_E_INTERNAL_ERROR;
	sip_sec_verify_signature_func verify_signature_func = !strncmp("Kerberos", mech, strlen(mech)) ? 
						sip_sec_verify_signature__Kerberos : sip_sec_verify_signature__NTLM;
	
	hex_str_to_bytes(signature_hex, &signature);
	res = (*verify_signature_func)(context, message, signature);
	//@TODO free 'signature' buffer with dedicated function
	return res;
}								


// Utility Methods //

void hex_str_to_bytes(char *hex_str, SipSecBuffer *bytes)
{
	guint8 *buff;
	char two_digits[3];
	int i;
	
	bytes->length = strlen(hex_str)/2;
	bytes->value = malloc(bytes->length);

	buff = (guint8 *)bytes->value;
	for (i = 0; i < bytes->length; i++) {		
		two_digits[0] = hex_str[i * 2];
		two_digits[1] = hex_str[i * 2 + 1];
		two_digits[2] = '\0';
		guint8 tmp = (guint8)strtoul(two_digits, NULL, 16);
		buff[i] = tmp;		
	}
}

char * bytes_to_hex_str(SipSecBuffer bytes)
{
	guint8 *buff = (guint8 *)bytes.value;
	char res[bytes.length * 2 + 1];
	int i, j;
	for (i = 0, j = 0; i < bytes.length; i++, j+=2) {
		sprintf(&res[j], "%02X", buff[i]);
	}
	res[++j] = '\0';
	return g_strdup(res);
}
