/**
 * @file sipe-digest-nss.c
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
 * Digest routines implementation based on NSS.
 * Includes: SHA1, MD5, HMAC_SHA_1, HMAC_MD5
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

#include "sipe-digest.h"


/* PRIVATE methods */

static PK11Context *sipe_digest_ctx_create(const SECOidTag algorithm)
{
	PK11Context *context = PK11_CreateDigestContext(algorithm);
	PK11_DigestBegin(context);
	return(context);
}

static PK11Context*
sipe_digest_hmac_ctx_create(CK_MECHANISM_TYPE hmacMech, const guchar *key, gsize key_length)
{
	PK11SlotInfo* slot;
	SECItem keyItem;
	SECItem noParams;
	PK11SymKey* SymKey;
	PK11Context* DigestContext;

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

	PK11_DigestBegin(DigestContext);

	PK11_FreeSymKey(SymKey);
	PK11_FreeSlot(slot);

	return DigestContext;
}

static void sipe_digest_ctx_append(PK11Context* DigestContext, const guchar *data, gsize data_length)
{
	PK11_DigestOp(DigestContext, data, data_length);
}

static void sipe_digest_ctx_digest(PK11Context* DigestContext, guchar *digest, gsize digest_length)
{
	unsigned int len;

	PK11_DigestFinal(DigestContext, digest, &len, digest_length);
}

static void sipe_digest_ctx_destroy(PK11Context* DigestContext)
{
	PK11_DestroyContext(DigestContext, PR_TRUE);
}

static void sipe_digest(const SECOidTag algorithm,
			const guchar *data, gsize data_length,
			guchar *digest, gsize digest_length)
{
	void *DigestContext;

	DigestContext = sipe_digest_ctx_create(algorithm);
	sipe_digest_ctx_append(DigestContext, data, data_length);
	sipe_digest_ctx_digest(DigestContext, digest, digest_length);
	sipe_digest_ctx_destroy(DigestContext);
}

static void sipe_digest_hmac(CK_MECHANISM_TYPE hmacMech,
			     const guchar *key, gsize key_length,
			     const guchar *data, gsize data_length,
			     guchar *digest, gsize digest_length)
{
	void *DigestContext;

	DigestContext = sipe_digest_hmac_ctx_create(hmacMech, key, key_length);
	sipe_digest_ctx_append(DigestContext, data, data_length);
	sipe_digest_ctx_digest(DigestContext, digest, digest_length);
	sipe_digest_ctx_destroy(DigestContext);
}


/* PUBLIC methods */

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
	sipe_digest_hmac(CKM_MD5_HMAC, key, key_length, data, data_length, digest, SIPE_DIGEST_HMAC_MD5_LENGTH);
}

void sipe_digest_hmac_sha1(const guchar *key, gsize key_length,
			   const guchar *data, gsize data_length,
			   guchar *digest)
{
	sipe_digest_hmac(CKM_SHA_1_HMAC, key, key_length, data, data_length, digest, SIPE_DIGEST_HMAC_SHA1_LENGTH);
}

/* Stream HMAC(SHA1) digest for file transfer */
gpointer sipe_digest_ft_start(const guchar *sha1_digest)
{
	/* used only the first 16 bytes of the 20 byte SHA1 digest */
	return sipe_digest_hmac_ctx_create(CKM_SHA_1_HMAC, sha1_digest, 16);
}

void sipe_digest_ft_update(gpointer context, const guchar *data, gsize length)
{
	sipe_digest_ctx_append(context, data, length);
}

void sipe_digest_ft_end(gpointer context, guchar *digest)
{
	sipe_digest_ctx_digest(context, digest, SIPE_DIGEST_FILETRANSFER_LENGTH);
}

void sipe_digest_ft_destroy(gpointer context)
{
	sipe_digest_ctx_destroy(context);
}

/* Stream digests, e.g. for TLS */
gpointer sipe_digest_md5_start(void)
{
	return sipe_digest_ctx_create(SEC_OID_MD5);
}

void sipe_digest_md5_update(gpointer context, const guchar *data, gsize length)
{
	sipe_digest_ctx_append(context, data, length);
}

void sipe_digest_md5_end(gpointer context, guchar *digest)
{
	unsigned int saved_length;
	/* save context to ensure this function can be called multiple times */
	guchar *saved = PK11_SaveContextAlloc(context,
					      NULL,
					      0,
					      &saved_length);
	sipe_digest_ctx_digest(context, digest, SIPE_DIGEST_MD5_LENGTH);
	PK11_RestoreContext(context, saved, saved_length);
	PORT_Free(saved);
}

void sipe_digest_md5_destroy(gpointer context)
{
	sipe_digest_ctx_destroy(context);
}

gpointer sipe_digest_sha1_start(void)
{
	return sipe_digest_ctx_create(SEC_OID_SHA1);
}

void sipe_digest_sha1_update(gpointer context, const guchar *data, gsize length)
{
	sipe_digest_ctx_append(context, data, length);
}

void sipe_digest_sha1_end(gpointer context, guchar *digest)
{
	unsigned int saved_length;
	/* save context to ensure this function can be called multiple times */
	guchar *saved = PK11_SaveContextAlloc(context,
					      NULL,
					      0,
					      &saved_length);
	sipe_digest_ctx_digest(context, digest, SIPE_DIGEST_SHA1_LENGTH);
	PK11_RestoreContext(context, saved, saved_length);
	PORT_Free(saved);
}

void sipe_digest_sha1_destroy(gpointer context)
{
	sipe_digest_ctx_destroy(context);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
