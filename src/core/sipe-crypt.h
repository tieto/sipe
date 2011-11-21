/**
 * @file sipe-crypt.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-11 SIPE Project <http://sipe.sourceforge.net/>
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

/**
 * Crypto backend specific initialization/shutdown
 *
 * TRUE  - production mode, i.e. called from sipe-core.c
 * FALSE - test mode
 */
void sipe_crypto_init(gboolean production_mode);
void sipe_crypto_shutdown(void);

void sipe_crypt_des(const guchar *key,
		    const guchar *plaintext, gsize plaintext_length,
		    guchar *encrypted_text);

void sipe_crypt_rc4(const guchar *key, gsize key_length,
		    const guchar *plaintext, gsize plaintext_length,
		    guchar *encrypted_text);

/* plaintext & encrypted_text must point to modulus_length long spaces */
gboolean sipe_crypt_rsa_encrypt(gpointer public, gsize modulus_length,
				const guchar *plaintext,
				guchar *encrypted_text);
gboolean sipe_crypt_rsa_decrypt(gpointer private, gsize modulus_length,
				const guchar *encrypted_text,
				guchar *plaintext);
/* must be g_free'd() */
guchar *sipe_crypt_rsa_sign(gpointer private,
			    const guchar *digest, gsize digest_length,
			    gsize *signature_length);
gboolean sipe_crypt_verify_rsa(gpointer public,
			       const guchar *digest, gsize digest_length,
			       const guchar *signature, gsize signature_length);

/* Stream RC4 cipher for file transfer */
gpointer sipe_crypt_ft_start(const guchar *key);
void sipe_crypt_ft_stream(gpointer context,
			  const guchar *in, gsize length,
			  guchar *out);
void sipe_crypt_ft_destroy(gpointer context);

/* Stream RC4 cipher for TLS */
gpointer sipe_crypt_tls_start(const guchar *key, gsize key_length);
void sipe_crypt_tls_stream(gpointer context,
			   const guchar *in, gsize length,
			   guchar *out);
void sipe_crypt_tls_destroy(gpointer context);
