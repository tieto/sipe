/**
 * @file sipe-crypt-nss.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011 SIPE Project <http://sipe.sourceforge.net/>
 * Copyright (C) 2010 pier11 <pier11@operamail.com>
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
 * Cypher routines implementation based on NSS.
 * Includes: RC4, DES
 */

#include "glib.h"

#include "nss.h"
/*
 * Work around a compiler error in NSS 3.13.x. Let's hope they fix it for
 * 3.14.x. See also: https://bugzilla.mozilla.org/show_bug.cgi?id=702090
 */
#if (NSS_VMAJOR == 3) && (NSS_VMINOR == 13)
#define __GNUC_MINOR __GNUC_MINOR__
#endif
#include "pk11pub.h"

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-crypt.h"

/* NSS specific initialization/shutdown */
void sipe_crypto_init(SIPE_UNUSED_PARAMETER gboolean production_mode)
{
	if (!NSS_IsInitialized()) {
		/*
		 * I have a bad feeling about this: according to the NSS
		 * documentation, NSS can only be initialized once.
		 * Unfortunately there seems to be no way to initialize a
		 * "NSS context" that could then be used by the SIPE code
		 * to avoid colliding with other NSS users.
		 *
		 * This seems to work, so it'll have to do for now.
		 *
		 * It might also be required to move this to the backend
		 * so that the backend code can decide when it is OK to
		 * initialize NSS.
		 */
		NSS_NoDB_Init(".");
		SIPE_DEBUG_INFO_NOFORMAT("NSS initialised");
	}
}

void sipe_crypto_shutdown(void)
{
	/* do nothing for NSS.
	 * We don't want accedently switch off NSS possibly used by other plugin -
	 * ssl-nss in Pidgin for example.
	 */
}

/* PRIVATE methods */

static PK11Context*
sipe_crypt_ctx_create(CK_MECHANISM_TYPE cipherMech, const guchar *key, gsize key_length)
{
	PK11SlotInfo* slot;
	SECItem keyItem;
	SECItem ivItem;
	PK11SymKey* SymKey;
	SECItem *SecParam;
	PK11Context* EncContext;

	/* For key */
	slot = PK11_GetBestSlot(cipherMech, NULL);

	keyItem.type = siBuffer;
	keyItem.data = (unsigned char *)key;
	keyItem.len = key_length;

	SymKey = PK11_ImportSymKey(slot, cipherMech, PK11_OriginUnwrap, CKA_ENCRYPT, &keyItem, NULL);

	/* Parameter for crypto context */
	ivItem.type = siBuffer;
	ivItem.data = NULL;
	ivItem.len = 0;
	SecParam = PK11_ParamFromIV(cipherMech, &ivItem);

	EncContext = PK11_CreateContextBySymKey(cipherMech, CKA_ENCRYPT, SymKey, SecParam);

	PK11_FreeSymKey(SymKey);
	SECITEM_FreeItem(SecParam, PR_TRUE);
	PK11_FreeSlot(slot);

	return EncContext;
}

static void
sipe_crypt_ctx_encrypt(PK11Context* EncContext, const guchar *in, gsize length, guchar *out)
{
	int tmp1_outlen;

	PK11_CipherOp(EncContext, out, &tmp1_outlen, length, (unsigned char *)in, length);
}

static void
sipe_crypt_ctx_destroy(PK11Context* EncContext)
{
	PK11_DestroyContext(EncContext, PR_TRUE);
}

static void
sipe_crypt(CK_MECHANISM_TYPE cipherMech,
	   const guchar *key, gsize key_length,
	   const guchar *plaintext, gsize plaintext_length,
	   guchar *encrypted_text)
{
	void *EncContext;

	EncContext = sipe_crypt_ctx_create(cipherMech, key, key_length);
	sipe_crypt_ctx_encrypt(EncContext, plaintext, plaintext_length, encrypted_text);
	sipe_crypt_ctx_destroy(EncContext);
}


/* PUBLIC methods */

void
sipe_crypt_des(const guchar *key,
	       const guchar *plaintext, gsize plaintext_length,
	       guchar *encrypted_text)
{
	sipe_crypt(CKM_DES_ECB, key, 8, plaintext, plaintext_length, encrypted_text);
}

void
sipe_crypt_rc4(const guchar *key, gsize key_length,
	       const guchar *plaintext, gsize plaintext_length,
	       guchar *encrypted_text)
{
	sipe_crypt(CKM_RC4, key, key_length, plaintext, plaintext_length, encrypted_text);
}

gboolean
sipe_crypt_rsa_encrypt(gpointer public, gsize modulus_length,
		       const guchar *plaintext,
		       guchar *encrypted_text)
{
  SECStatus result = PK11_PubEncryptRaw(public,
					encrypted_text, (guchar *) plaintext,
					modulus_length, NULL);
  return(result == SECSuccess);
}

gboolean
sipe_crypt_rsa_decrypt(gpointer private, gsize modulus_length,
		       const guchar *encrypted_text,
		       guchar *plaintext)
{
  unsigned int length;
  SECStatus result = PK11_PubDecryptRaw(private,
					(guchar *) encrypted_text, &length, modulus_length,
					plaintext, modulus_length);
  return((result == SECSuccess) && (length == modulus_length));
}

guchar *sipe_crypt_rsa_sign(gpointer private,
		 	    const guchar *digest, gsize digest_length,
			    gsize *signature_length)
{
  SECItem digItem;
  SECItem sigItem;
  SECStatus length;

  length = PK11_SignatureLen(private);
  if (length < 0) return(NULL);

  /* digest to sign (= encrypt) with private key */
  digItem.data = (guchar *) digest;
  digItem.len  = digest_length;

  /* signature */
  sigItem.data = g_malloc(length);
  sigItem.len  = length;

  length = PK11_Sign(private, &sigItem, &digItem);
  if (length != SECSuccess) {
	  g_free(sigItem.data);
	  return(NULL);
  }

  *signature_length = sigItem.len;
  return(sigItem.data);
}

gboolean sipe_crypt_verify_rsa(gpointer public,
			       const guchar *digest, gsize digest_length,
			       const guchar *signature, gsize signature_length)
{
  SECItem digItem;
  SECItem sigItem;

  /* digest to verify against */
  digItem.data = (guchar *) digest;
  digItem.len  = digest_length;

  /* signature to decrypt with public key -> digest to compare */
  sigItem.data = (guchar *) signature;
  sigItem.len  = signature_length;

  return(PK11_Verify(public, &sigItem, &digItem, NULL) == SECSuccess);
}


/* Stream RC4 cipher for file transfer */
gpointer
sipe_crypt_ft_start(const guchar *key)
{
	return sipe_crypt_ctx_create(CKM_RC4, key, 16);
}

void
sipe_crypt_ft_stream(gpointer context,
		     const guchar *in, gsize length,
		     guchar *out)
{
	sipe_crypt_ctx_encrypt(context, in, length, out);
}

void
sipe_crypt_ft_destroy(gpointer context)
{
	sipe_crypt_ctx_destroy(context);
}

/*
 * Stream RC4 cipher for TLS
 *
 * basically the same as for FT, but with variable key length
 */
gpointer sipe_crypt_tls_start(const guchar *key, gsize key_length)
{
	return sipe_crypt_ctx_create(CKM_RC4, key, key_length);
}

void sipe_crypt_tls_stream(gpointer context,
			   const guchar *in, gsize length,
			   guchar *out)
{
	sipe_crypt_ctx_encrypt(context, in, length, out);
}

void sipe_crypt_tls_destroy(gpointer context)
{
	sipe_crypt_ctx_destroy(context);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
