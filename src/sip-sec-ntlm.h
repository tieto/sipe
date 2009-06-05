/**
 * @file sip-sec-ntlm.c
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

#include "sip-sec-mech.h"

sip_uint32 
sip_sec_acquire_cred__ntlm(SipSecCred *cred_handle, char* sec_package, char* domain, char *username, char *password);

sip_uint32
sip_sec_init_sec_context__ntlm(SipSecCred cred_handle, char* sec_package, SipSecContext *context, 
						SipSecBuffer in_buff,
						SipSecBuffer *out_buff,
						char *service_name);

/**
 * @param message a NULL terminated string to sign
 *
 */
sip_uint32
sip_sec_make_signature__ntlm(SipSecContext context, char *message, SipSecBuffer *signature);

/**
 * @param message a NULL terminated string to check signature of
 */
sip_uint32
sip_sec_verify_signature__ntlm(SipSecContext context, char* message, SipSecBuffer signature);
