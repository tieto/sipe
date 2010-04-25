 /**
 * @file sipe-crypt.c
 *
 * pidgin-sipe
 *
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
#include "pk11pub.h"

#include "sipe-crypt.h"


/* PRIVATE methons */

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


/* PUBLIC methons */

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
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
