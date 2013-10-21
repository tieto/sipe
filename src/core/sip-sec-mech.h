/**
 * @file sip-sec-mech.h
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

/* Mechanism wrappers API  (Inspired by GSS-API)
 * All mechanisms should implement this API
 *
 * Current mechanisms are: Kerberos/GSS-API, sipe's NTLM and SSPI.
 */

typedef struct {
	gsize   length;
	guint8 *value;
} SipSecBuffer;

typedef SipSecContext
(*sip_sec_create_context_func)(guint type);

typedef gboolean
(*sip_sec_acquire_cred_func)(SipSecContext context,
			     const gchar *domain,
			     const gchar *username,
			     const gchar *password);

typedef gboolean
(*sip_sec_init_context_func)(SipSecContext context,
			     SipSecBuffer in_buff,
			     SipSecBuffer *out_buff,
			     const gchar *service_name);

typedef void
(*sip_sec_destroy_context_func)(SipSecContext context);

typedef gboolean
(*sip_sec_make_signature_func)(SipSecContext context,
			       const gchar *message,
			       SipSecBuffer *signature);

typedef gboolean
(*sip_sec_verify_signature_func)(SipSecContext context,
				 const gchar *message,
				 SipSecBuffer signature);

typedef const gchar *(*sip_sec_context_name_func)(SipSecContext context);

typedef gboolean (*sip_sec_password_func)(void);


struct sip_sec_context {
	sip_sec_acquire_cred_func     acquire_cred_func;
	sip_sec_init_context_func     init_context_func;
	sip_sec_destroy_context_func  destroy_context_func;
	sip_sec_make_signature_func   make_signature_func;
	sip_sec_verify_signature_func verify_signature_func;
	sip_sec_context_name_func     context_name_func;
	guint type;
	/** Security Context expiration interval in seconds */
	guint expires;
	guint flags;
};

/**
 * sip_sec_context.flags
 *
 * 0x00000001 - 0x00008000: common flags
 * 0x00010000 - 0x80000000: mechanism private flags
 *
 * NOTE: private flags must be set in acquire_cred_func()!
 */
#define SIP_SEC_FLAG_COMMON_SSO   0x00000001
#define SIP_SEC_FLAG_COMMON_HTTP  0x00000002
#define SIP_SEC_FLAG_COMMON_READY 0x00000004
