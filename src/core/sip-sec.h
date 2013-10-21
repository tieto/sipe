/**
 * @file sip-sec.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2013 SIPE Project <http://sipe.sourceforge.net/>
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

/*** Sipe convenience methods ***/

/**
 * Initializes Sipe security context.
 * Obtains cashed initial credentials (TGT for Kerberos) or requests new ones if required.
 * In former case domain/username/password information is unnecessary.
 *
 * @param type     (in) authentication type
 * @param sso      (in) @c TRUE if Single Sign-On should be used
 * @param http     (in) @c TRUE if HTTP, @c FALSE for SIP
 * @param domain   (in) NTLM Domain/Kerberos Realm (ignored for SSO)
 * @param username (in) user name (can be NULL)    (ignored for SSO)
 * @param password (in) password (can be NULL)     (ignored for SSO)
 *
 * @return context security context to store and pass between security method invocations
 */
SipSecContext
sip_sec_create_context(guint type,
		       gboolean sso,
		       gboolean http,
		       const gchar *domain,
		       const gchar *username,
		       const gchar *password);

/**
 * Obtains Service ticket (for Kerberos), base64 encodes it and provide as output.
 *
 * @param context (in) security context to pass between security method invocations
 * @param target (in) security target. Service principal name on case of Kerberos.
 * @param input_toked_base64 (in) base64 encoded input security token. This is Type2 NTLM message or NULL.
 * @param output_toked_base64 (out) base64 encoded output token to send to server.
 * @param expires (out) security context expiration time in seconds.
 *
 * @return @c TRUE if successful
 *
 */
gboolean
sip_sec_init_context_step(SipSecContext context,
			  const gchar *target,
			  const gchar *input_toked_base64,
			  gchar **output_toked_base64,
			  guint *expires);

/**
 * Check if the authentication of a security context is completed and it is
 * ready to be used for message signing and signature verification
 *
 * @param context (in) security context. May be @c NULL.
 *
 * @return @c TRUE if authentication is completed
 */
gboolean sip_sec_context_is_ready(SipSecContext context);

/**
 * Return authentication name of a security context
 *
 * @param context (in) security context. May be @c NULL.
 *
 * @return string or @c NULL
 */
const gchar *sip_sec_context_name(SipSecContext context);

/**
 * Return type of a security context
 *
 * @param context (in) security context. May be @c NULL.
 *
 * @return context type or @c SIPE_SIPE_AUTHENTICATION_TYPE_UNSET
 */
guint sip_sec_context_type(SipSecContext context);

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
 * @param context (in) security context
 * @param message (in) a message to sign.
 *
 * @return signature for the message. Converted to Hex null terminated string;
 */
gchar *sip_sec_make_signature(SipSecContext context,
			      const gchar *message);

/**
 * A convenience method for sipe.
 * Verifies signature for the message.
 *
 * @param context (in) security context
 * @param message (in) which signature to verify. Null terminated string.
 * @param signature_hex (in) signature to test in Hex representation. Null terminated string. Example: "602306092A864886F71201020201011100FFFFFFFF1A306ACB7BE311827BBF7208D80D15E3"
 *
 * @return FALSE on error
 */
gboolean sip_sec_verify_signature(SipSecContext context,
				  const gchar *message,
				  const gchar *signature_hex);

/**
 * Check if authentication scheme requires a password
 *
 * @param type authentication type
 * @param sso  TRUE if user selected Single-Sign On
 *
 * @return @c TRUE if password is required
 */
gboolean sip_sec_requires_password(guint authentication,
				   gboolean sso);

/**
 * Initialize & destroy functions for sip-sec.
 * Should be called on loading and unloading of the core.
 */
void sip_sec_init(void);
void sip_sec_destroy(void);
