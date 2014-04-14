/**
 * @file sipe-digest-openssl.c
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
 * Digest routines implementation based on OpenSSL
 */
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include "glib.h"

#include "sipe-digest.h"

/* One-shot MD5/SHA-1 digests */
void sipe_digest_md5(const guchar *data, gsize length, guchar *digest)
{
	MD5(data, length, digest);
}

void sipe_digest_sha1(const guchar *data, gsize length, guchar *digest)
{
	SHA1(data, length, digest);
}

/* One-shot HMAC(MD5/SHA-1) digests */
void sipe_digest_hmac_md5(const guchar *key, gsize key_length,
			  const guchar *data, gsize data_length,
			  guchar *digest)
{
	HMAC(EVP_md5(), key, key_length, data, data_length, digest, NULL);
}

void sipe_digest_hmac_sha1(const guchar *key, gsize key_length,
			   const guchar *data, gsize data_length,
			   guchar *digest)
{
	HMAC(EVP_sha1(), key, key_length, data, data_length, digest, NULL);
}

/* Stream HMAC(SHA1) digest for file transfer */
gpointer sipe_digest_ft_start(const guchar *sha1_digest)
{
	HMAC_CTX *ctx = g_malloc(sizeof(HMAC_CTX));
	HMAC_CTX_init(ctx);
	/* used are only the first 16 bytes of the 20 byte SHA1 digest */
	HMAC_Init(ctx, sha1_digest, 16, EVP_sha1());
	return(ctx);
}

void sipe_digest_ft_update(gpointer context, const guchar *data, gsize length)
{
	HMAC_Update(context, data, length);
}

void sipe_digest_ft_end(gpointer context, guchar *digest)
{
	HMAC_Final(context, digest, NULL);
}

void sipe_digest_ft_destroy(gpointer context)
{
	HMAC_CTX_cleanup(context);
	g_free(context);
}

/* Stream digests, e.g. for TLS */
gpointer sipe_digest_md5_start(void)
{
	MD5_CTX *ctx = g_malloc(sizeof(MD5_CTX));
	MD5_Init(ctx);
	return(ctx);
}

void sipe_digest_md5_update(gpointer context, const guchar *data, gsize length)
{
	MD5_Update(context, data, length);
}

void sipe_digest_md5_end(gpointer context, guchar *digest)
{
	/* save context to ensure this function can be called multiple times */
	MD5_CTX *orig_ctx = context;
	MD5_CTX saved_ctx = *orig_ctx;
	MD5_Final(digest, orig_ctx);
	*orig_ctx = saved_ctx;
}

void sipe_digest_md5_destroy(gpointer context)
{
	g_free(context);
}

gpointer sipe_digest_sha1_start(void)
{
	SHA_CTX *ctx = g_malloc(sizeof(SHA_CTX));
	SHA1_Init(ctx);
	return(ctx);
}

void sipe_digest_sha1_update(gpointer context, const guchar *data, gsize length)
{
	SHA1_Update(context, data, length);
}

void sipe_digest_sha1_end(gpointer context, guchar *digest)
{
	/* save context to ensure this function can be called multiple times */
	SHA_CTX *orig_ctx = context;
	SHA_CTX saved_ctx = *orig_ctx;
	SHA1_Final(digest, orig_ctx);
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
