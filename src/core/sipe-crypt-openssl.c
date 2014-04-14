/**
 * @file sipe-crypt-openssl.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2013 SIPE Project <http://sipe.sourceforge.net/>
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
 * Cipher routines implementation based on OpenSSL.
 */
#include <openssl/evp.h>
#include <openssl/rsa.h>

#include "glib.h"

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-crypt.h"

/* OpenSSL specific initialization/shutdown */
void sipe_crypto_init(SIPE_UNUSED_PARAMETER gboolean production_mode)
{
	/* nothing to do here */
}

void sipe_crypto_shutdown(void)
{
	/* nothing to do here */
}

static void openssl_oneshot_crypt(const EVP_CIPHER *type,
				  const guchar *key, gsize key_length,
				  const guchar *plaintext, gsize plaintext_length,
				  guchar *encrypted_text)
{
	EVP_CIPHER_CTX ctx;
	int encrypted_length = 0;

	/* initialize context */
	EVP_CIPHER_CTX_init(&ctx);
	EVP_EncryptInit_ex(&ctx, type, NULL, key, NULL);

	/* set encryption parameters */
	if (key_length)
		EVP_CIPHER_CTX_set_key_length(&ctx, key_length);
	EVP_EncryptInit_ex(&ctx, NULL, NULL, key, NULL);

	/* encrypt */
	EVP_EncryptUpdate(&ctx,
			  encrypted_text, &encrypted_length,
			  plaintext, plaintext_length);
	encrypted_text += encrypted_length;
	EVP_EncryptFinal_ex(&ctx, encrypted_text, &encrypted_length);

	/* cleanup */
	EVP_CIPHER_CTX_cleanup(&ctx);
}

/* DES CBC with 56-bit key */
void sipe_crypt_des(const guchar *key,
		    const guchar *plaintext, gsize plaintext_length,
		    guchar *encrypted_text)
{
	openssl_oneshot_crypt(EVP_des_cbc(),
			      key, 0 /* fixed length */,
			      plaintext, plaintext_length,
			      encrypted_text);
}

/* RC4 with variable length key */
void sipe_crypt_rc4(const guchar *key, gsize key_length,
		    const guchar *plaintext, gsize plaintext_length,
		    guchar *encrypted_text)
{
	openssl_oneshot_crypt(EVP_rc4(),
			      key, key_length,
			      plaintext, plaintext_length,
			      encrypted_text);
}

gboolean sipe_crypt_rsa_encrypt(gpointer public,
				gsize modulus_length,
				const guchar *plaintext,
				guchar *encrypted_text)
{
	return(RSA_public_encrypt(modulus_length,
				  plaintext,
				  encrypted_text,
				  public,
				  RSA_NO_PADDING)
	       != -1);
}

gboolean sipe_crypt_rsa_decrypt(gpointer private,
				gsize modulus_length,
				const guchar *encrypted_text,
				guchar *plaintext)
{
	return(RSA_private_decrypt(modulus_length,
				   encrypted_text,
				   plaintext,
				   private,
				   RSA_NO_PADDING)
	       != -1);
}

guchar *sipe_crypt_rsa_sign(gpointer private,
			    const guchar *digest, gsize digest_length,
			    gsize *signature_length)
{
	guchar *signature = g_malloc(RSA_size(private));
	unsigned int length;

	if (!RSA_sign(NID_md5_sha1,
		      digest, digest_length,
		      signature, &length,
		      private)) {
		g_free(signature);
		return(NULL);
	}

	*signature_length = length;
	return(signature);
}

gboolean sipe_crypt_verify_rsa(gpointer public,
			       const guchar *digest, gsize digest_length,
			       const guchar *signature, gsize signature_length)
{
	return(RSA_verify(NID_md5_sha1,
			  digest, digest_length,
			  /* older OpenSSL version don't have "const" here */
			  (guchar *) signature, signature_length,
			  public));
}

static gpointer openssl_rc4_init(const guchar *key, gsize key_length)
{
	EVP_CIPHER_CTX *ctx = g_malloc(sizeof(EVP_CIPHER_CTX));

	/* initialize context */
	EVP_CIPHER_CTX_init(ctx);
	EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, key, NULL);

	/* set encryption parameters */
	EVP_CIPHER_CTX_set_key_length(ctx, key_length);
	EVP_EncryptInit_ex(ctx, NULL, NULL, key, NULL);

	return(ctx);
}

/* Stream RC4 cipher for file transfer with fixed-length 128-bit key */
gpointer sipe_crypt_ft_start(const guchar *key)
{
	return(openssl_rc4_init(key, 16));
}

void sipe_crypt_ft_stream(gpointer context,
			  const guchar *in, gsize length,
			  guchar *out)
{
	int tmp;
	EVP_EncryptUpdate(context, out, &tmp, in, length);
}

void sipe_crypt_ft_destroy(gpointer context)
{
	EVP_CIPHER_CTX_cleanup(context);
	g_free(context);
}

/* Stream RC4 cipher for TLS with variable key length */
gpointer sipe_crypt_tls_start(const guchar *key, gsize key_length)
{
	return(openssl_rc4_init(key, key_length));
}

void sipe_crypt_tls_stream(gpointer context,
			   const guchar *in, gsize length,
			   guchar *out)
{
	int tmp;
	EVP_EncryptUpdate(context, out, &tmp, in, length);
}

void sipe_crypt_tls_destroy(gpointer context)
{
	EVP_CIPHER_CTX_cleanup(context);
	g_free(context);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
