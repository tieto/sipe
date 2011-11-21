/**
 * @file sipe-digest.h
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

/* Plain digests */
#define SIPE_DIGEST_MD5_LENGTH 16
void sipe_digest_md5(const guchar *data, gsize length, guchar *digest);

#define SIPE_DIGEST_SHA1_LENGTH 20
void sipe_digest_sha1(const guchar *data, gsize length, guchar *digest);

/* HMAC digests */
#define SIPE_DIGEST_HMAC_MD5_LENGTH SIPE_DIGEST_MD5_LENGTH
void sipe_digest_hmac_md5(const guchar *key, gsize key_length,
			  const guchar *data, gsize data_length,
			  guchar *digest);

#define SIPE_DIGEST_HMAC_SHA1_LENGTH SIPE_DIGEST_SHA1_LENGTH
void sipe_digest_hmac_sha1(const guchar *key, gsize key_length,
			  const guchar *data, gsize data_length,
			  guchar *digest);

/* Stream HMAC(SHA1) digest for file transfer */
#define SIPE_DIGEST_FILETRANSFER_LENGTH SIPE_DIGEST_SHA1_LENGTH
gpointer sipe_digest_ft_start(const guchar *sha1_digest);
void sipe_digest_ft_update(gpointer context, const guchar *data, gsize length);
void sipe_digest_ft_end(gpointer context, guchar *digest);
void sipe_digest_ft_destroy(gpointer context);

/* Stream digests, e.g. for TLS */
gpointer sipe_digest_md5_start(void);
void sipe_digest_md5_update(gpointer context, const guchar *data, gsize length);
void sipe_digest_md5_end(gpointer context, guchar *digest);
void sipe_digest_md5_destroy(gpointer context);
gpointer sipe_digest_sha1_start(void);
void sipe_digest_sha1_update(gpointer context, const guchar *data, gsize length);
void sipe_digest_sha1_end(gpointer context, guchar *digest);
void sipe_digest_sha1_destroy(gpointer context);
