/**
 * @file purple-digest.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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

#include "glib.h"
#include "cipher.h"

#include "sipe-digest.h"

void sipe_digest_hmac_md5(const guchar *key, gsize key_length,
			  const guchar *data, gsize data_length,
			  guchar *digest)
{
	PurpleCipherContext *context = purple_cipher_context_new_by_name("hmac", NULL);
	purple_cipher_context_set_option(context, "hash", "md5");
	purple_cipher_context_set_key_with_len(context, key, key_length);
	purple_cipher_context_append(context, data, data_length);
	purple_cipher_context_digest(context, SIPE_DIGEST_HMAC_MD5_LENGTH, digest, NULL);
	purple_cipher_context_destroy(context);
}

static void purple_digest(const gchar *algorithm,
			  const guchar *data, gsize data_length,
			  guchar *digest, gsize digest_length)
{
	PurpleCipherContext *ctx = purple_cipher_context_new_by_name(algorithm, NULL);
	purple_cipher_context_append(ctx, data, data_length);
	purple_cipher_context_digest(ctx, digest_length, digest, NULL);
	purple_cipher_context_destroy(ctx);
}

void sipe_digest_md4(const guchar *data, gsize length, guchar *digest)
{
	purple_digest("md4", data, length, digest, SIPE_DIGEST_MD4_LENGTH);
}

void sipe_digest_md5(const guchar *data, gsize length, guchar *digest)
{
	purple_digest("md5", data, length, digest, SIPE_DIGEST_MD5_LENGTH);
}

void sipe_digest_sha1(const guchar *data, gsize length, guchar *digest)
{
	purple_digest("sha1", data, length, digest, SIPE_DIGEST_SHA1_LENGTH);
}

/* Stream HMAC(SHA1) digest for file transfer */
gpointer sipe_digest_ft_start(const guchar *sha1_digest)
{
	PurpleCipherContext *context = purple_cipher_context_new_by_name("hmac", NULL);
	purple_cipher_context_set_option(context, "hash", "sha1");
	/* used only the first 16 bytes of the 20 byte SHA1 digest */
	purple_cipher_context_set_key_with_len(context, sha1_digest, 16);
	return(context);
}

void sipe_digest_ft_update(gpointer context, const guchar *data, gsize length)
{
	purple_cipher_context_append(context, data, length);
}

void sipe_digest_ft_end(gpointer context, guchar *digest)
{
	purple_cipher_context_digest(context, SIPE_DIGEST_FILETRANSFER_LENGTH, digest, NULL);
}

void sipe_digest_ft_destroy(gpointer context)
{
	purple_cipher_context_destroy(context);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
