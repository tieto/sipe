/**
 * @file sip-sec.h
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
 
/* Opaque type definition for security context */
typedef struct sip_sec_context *SipSecContext;

typedef enum
{
	AUTH_TYPE_UNSET = 0,
	AUTH_TYPE_DIGEST,
	AUTH_TYPE_NTLM,
	AUTH_TYPE_KERBEROS
} SipSecAuthType;

//// Sipe convenience methods ////

/**
 * A convenience method for sipe.
 * Initializes security context.
 * Obtains cashed initial credentials (TGT for Kerberos) or requests new ones if required. In former case domain/username/password information is unnecessary.
 * Then obtains Service ticket (for Kerberos) , base64 encodes it and provide as output.
 *
 * @param context (in,out) security context to store and pass between security method invocations
 * @param mech (in) security mechanism - NTLM or Kerberos
 * @param domain (in) NTLM Domain/Kerberos Realm.
 * @param target (in) security target. Service principal name on case of Kerberos.
 * @param input_toked_base64 (in) base64 encoded input security token. This is Type2 NTLM message or NULL for Kerberos.
 *
 * @return base64 encoded output token to send to server.
 */
char *sip_sec_init_context(SipSecContext *context,
			   SipSecAuthType type,
			   const int  sso,
			   const char *domain,
			   const char *username,
			   const char *password,
			   const char *target,
			   const char *input_toked_base64);

/**
 * A convenience method for sipe.
 * Destroys security context.
 *
 * @param context (in,out) security context to destroy
 */
void sip_sec_destroy_context(SipSecContext context);

/**
 * A convenience method for sipe.
 * Signs incoming message.
 *
 * @param message (in) a message to sign.
 *
 * @return signature for the message. Converted to Hex null terminated string;
 */
char *sip_sec_make_signature(SipSecContext context,
			     const char *message);

/**
 * A convenience method for sipe.
 * Verifies signature for the message.
 *
 * @param mesage (in) which signature to verify. Null terminated string.
 * @param signature_hex (in) signature to test in Hex representation. Null terminated string. Example: "602306092A864886F71201020201011100FFFFFFFF1A306ACB7BE311827BBF7208D80D15E3"
 *
 * @return FALSE on error
 */
int sip_sec_verify_signature(SipSecContext context,
			     const char *message,
			     const char *signature_hex);
