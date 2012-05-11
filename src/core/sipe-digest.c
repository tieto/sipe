/**
 * @file sipe-digest.c
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
 * Digest routines implementation based on NSS.
 * Includes: SHA1, MD5, MD4, HMAC_SHA_1, HMAC_MD5
 */

#include "glib.h"

#include "nss.h"
#include "pk11pub.h"
#include "md4.h"

#include "sipe-digest.h"


/* PRIVATE methods */

static void sipe_digest(const SECOidTag algorithm,
			const guchar *data, gsize data_length,
			guchar *digest, gsize digest_length)
{
	PK11Context *context = 0;
	SECStatus s;
	unsigned int len;
	
	context = PK11_CreateDigestContext(algorithm);
	s = PK11_DigestBegin(context);
	s = PK11_DigestOp(context, data, data_length);
	s = PK11_DigestFinal(context, digest, &len, digest_length);
	PK11_DestroyContext(context, PR_TRUE);
}

static PK11Context*
sipe_digest_hmac_ctx_create(CK_MECHANISM_TYPE hmacMech, const guchar *key, gsize key_length)
{
	PK11SlotInfo* slot;
	SECItem keyItem;
	SECItem noParams;
	PK11SymKey* SymKey;
	PK11Context* DigestContext;
	SECStatus s;

	/* For key */
	slot = PK11_GetBestSlot(hmacMech, NULL);

	keyItem.type = siBuffer;
	keyItem.data = (unsigned char *)key;
	keyItem.len = key_length;

	SymKey = PK11_ImportSymKey(slot, hmacMech, PK11_OriginUnwrap, CKA_SIGN,  &keyItem, NULL);
	
	/* Parameter for crypto context */
	noParams.type = siBuffer;
	noParams.data = NULL;
	noParams.len = 0;

	DigestContext = PK11_CreateContextBySymKey(hmacMech, CKA_SIGN, SymKey, &noParams);
	
	s = PK11_DigestBegin(DigestContext);
	
	PK11_FreeSymKey(SymKey);
	PK11_FreeSlot(slot);
	
	return DigestContext;
}

static void sipe_digest_hmac_ctx_append(PK11Context* DigestContext, const guchar *data, gsize data_length)
{
	PK11_DigestOp(DigestContext, data, data_length);
}

static void sipe_digest_hmac_ctx_digest(PK11Context* DigestContext, guchar *digest, gsize digest_length)
{
	unsigned int len;

	PK11_DigestFinal(DigestContext, digest, &len, digest_length);
}

static void sipe_digest_hmac_ctx_destroy(PK11Context* DigestContext)
{
	PK11_DestroyContext(DigestContext, PR_TRUE);
}



/* PUBLIC methods */

void sipe_digest_md4(const guchar *data, gsize length, guchar *digest)
{
	/* From Firefox's complementing implementation for NSS.
	 * NSS doesn't include MD4 as weak algorithm
	 */
	md4sum(data, length, digest);
}

void sipe_digest_md5(const guchar *data, gsize length, guchar *digest)
{
	sipe_digest(SEC_OID_MD5, data, length, digest, SIPE_DIGEST_MD5_LENGTH);
}

void sipe_digest_sha1(const guchar *data, gsize length, guchar *digest)
{
	sipe_digest(SEC_OID_SHA1, data, length, digest, SIPE_DIGEST_SHA1_LENGTH);
}

void sipe_digest_hmac_md5(const guchar *key, gsize key_length,
			  const guchar *data, gsize data_length,
			  guchar *digest)
{
	void *DigestContext;

	DigestContext = sipe_digest_hmac_ctx_create(CKM_MD5_HMAC, key, key_length);
	sipe_digest_hmac_ctx_append(DigestContext, data, data_length);
	sipe_digest_hmac_ctx_digest(DigestContext, digest, SIPE_DIGEST_HMAC_MD5_LENGTH);
	sipe_digest_hmac_ctx_destroy(DigestContext);
}

/* Stream HMAC(SHA1) digest for file transfer */
gpointer sipe_digest_ft_start(const guchar *sha1_digest)
{
	/* used only the first 16 bytes of the 20 byte SHA1 digest */
	return sipe_digest_hmac_ctx_create(CKM_SHA_1_HMAC, sha1_digest, 16);
}

void sipe_digest_ft_update(gpointer context, const guchar *data, gsize length)
{
	sipe_digest_hmac_ctx_append(context, data, length);
}

void sipe_digest_ft_end(gpointer context, guchar *digest)
{
	sipe_digest_hmac_ctx_digest(context, digest, SIPE_DIGEST_FILETRANSFER_LENGTH);
}

void sipe_digest_ft_destroy(gpointer context)
{
	sipe_digest_hmac_ctx_destroy(context);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
