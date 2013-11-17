/**
 * @file sipe-digest-macosx.c
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
 * Digest routines implementation based on Mac OS X Security Framework
 *
 * According to the documentation CDSA is a deprecated API since
 * Mac OS X 10.7. But unfortunately its replacement SecTransform
 * only supports one-shot hashing.
 *
 * See also: rdar://<TBD>
 */
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>

#include "glib.h"

#include "sipe-digest.h"

/* One-shot MD5/SHA-1 digests */
void sipe_digest_md5(const guchar *data, gsize length, guchar *digest)
{
	CC_MD5(data, length, digest);
}

void sipe_digest_sha1(const guchar *data, gsize length, guchar *digest)
{
	CC_SHA1(data, length, digest);
}

/* One-shot HMAC(MD5/SHA-1) digests */
void sipe_digest_hmac_md5(const guchar *key, gsize key_length,
						  const guchar *data, gsize data_length,
						  guchar *digest)
{
	CCHmac(kCCHmacAlgMD5, key, key_length, data, data_length, digest);
}

void sipe_digest_hmac_sha1(const guchar *key, gsize key_length,
						   const guchar *data, gsize data_length,
						   guchar *digest)
{
	CCHmac(kCCHmacAlgSHA1, key, key_length, data, data_length, digest);
}

/* Stream HMAC(SHA1) digest for file transfer */
gpointer sipe_digest_ft_start(const guchar *sha1_digest)
{
	CCHmacContext *ctx = g_malloc(sizeof(CCHmacContext));
	/* used are only the first 16 bytes of the 20 byte SHA1 digest */
	CCHmacInit(ctx, kCCHmacAlgSHA1, sha1_digest, 16);
	return(ctx);
}

void sipe_digest_ft_update(gpointer context, const guchar *data, gsize length)
{
	CCHmacUpdate(context, data, length);
}

void sipe_digest_ft_end(gpointer context, guchar *digest)
{
	CCHmacFinal(context, digest);
}

void sipe_digest_ft_destroy(gpointer context)
{
	g_free(context);
}

/* Stream digests, e.g. for TLS */
gpointer sipe_digest_md5_start(void)
{
	CC_MD5_CTX *ctx = g_malloc(sizeof(CC_MD5_CTX));
	CC_MD5_Init(ctx);
	return(ctx);
}

void sipe_digest_md5_update(gpointer context, const guchar *data, gsize length)
{
	CC_MD5_Update(context, data, length);
}

void sipe_digest_md5_end(gpointer context, guchar *digest)
{
	/* save context to ensure this function can be called multiple times */
	CC_MD5_CTX *orig_ctx = context;
	CC_MD5_CTX saved_ctx = *orig_ctx;
	CC_MD5_Final(digest, orig_ctx);
	*orig_ctx = saved_ctx;
}

void sipe_digest_md5_destroy(gpointer context)
{
	g_free(context);
}

gpointer sipe_digest_sha1_start(void)
{
	CC_SHA1_CTX *ctx = g_malloc(sizeof(CC_SHA1_CTX));
	CC_SHA1_Init(ctx);
	return(ctx);
}

void sipe_digest_sha1_update(gpointer context, const guchar *data, gsize length)
{
	CC_SHA1_Update(context, data, length);
}

void sipe_digest_sha1_end(gpointer context, guchar *digest)
{
	/* save context to ensure this function can be called multiple times */
	CC_SHA1_CTX *orig_ctx = context;
	CC_SHA1_CTX saved_ctx = *orig_ctx;
	CC_SHA1_Final(digest, orig_ctx);
	*orig_ctx = saved_ctx;
}

void sipe_digest_sha1_destroy(gpointer context)
{
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
