/**
 * @file sip-sec.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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

/* Opaque type definition for security context */
typedef struct sip_sec_context *SipSecContext;

#define AUTH_TYPE_UNSET     0
#define AUTH_TYPE_DIGEST    1
#define AUTH_TYPE_NTLM      2
#define AUTH_TYPE_KERBEROS  3
#define AUTH_TYPE_NEGOTIATE 4

/*** Sipe convenience methods ***/

/**
 * Initializes Sipe security context.
 * Obtains cashed initial credentials (TGT for Kerberos) or requests new ones if required.
 * In former case domain/username/password information is unnecessary.
 *
 * @param type (in) authentication type
 * @param sso (in) use Single Sign-On
 * @param is_connection_based (in) context is used for a connection
 * @param domain (in) NTLM Domain/Kerberos Realm.
 * @param username (in) user name (can be NULL)
 * @param password (in) password (can be NULL)
 *
 * @return context security context to store and pass between security method invocations
 */
SipSecContext
sip_sec_create_context(guint type,
		       const int  sso,
		       int is_connection_based,
		       const char *domain,
		       const char *username,
		       const char *password);

/**
 * Obtains Service ticket (for Kerberos), base64 encodes it and provide as output.
 *
 * @param context (in) security context to pass between security method invocations
 * @param target (in) security target. Service principal name on case of Kerberos.
 * @param input_toked_base64 (in) base64 encoded input security token. This is Type2 NTLM message or NULL.
 * @param output_toked_base64 (out) base64 encoded output token to send to server.
 * @param expires (out) security context expiration time in seconds.
 *
 * @return SIP_SEC_* value signifying success of the operation.
 *
 */
unsigned long
sip_sec_init_context_step(SipSecContext context,
			  const char *target,
			  const char *input_toked_base64,
			  char **output_toked_base64,
			  int *expires);

/**
 * A convenience method for sipe. Combines execution on sip_sec_create_context()
 * and sip_sec_init_context_step(). Suitable for connectionless NTLM (as in SIP).
 * Unsuitable for connection-based (TCP, TLS) Web authentication.
 *
 * Initializes security context.
 * Obtains cashed initial credentials (TGT for Kerberos) or requests new ones if required. In former case domain/username/password information is unnecessary.
 * Then obtains Service ticket (for Kerberos) , base64 encodes it and provide as output.
 *
 * @param context (in,out) security context to store and pass between security method invocations
 * @param mech (in) security mechanism - NTLM or Kerberos
 * @param domain (in) NTLM Domain/Kerberos Realm.
 * @param target (in) security target. Service principal name on case of Kerberos.
 * @param input_toked_base64 (in) base64 encoded input security token. This is Type2 NTLM message or NULL for Kerberos.
 * @param expires (out) security context expiration time in seconds.
 *
 * @return base64 encoded output token to send to server.
 */
char *sip_sec_init_context(SipSecContext *context,
			   int *expires,
			   guint type,
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

/**
 * Initialize & destroy functions for sip-sec.
 * Should be called on loading and unloading of the core.
 */
void sip_sec_init(void);
void sip_sec_destroy(void);
