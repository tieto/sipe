/**
 * @file sipe-tls.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-12 SIPE Project <http://sipe.sourceforge.net/>
 *
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

/*
 * Interface dependencies:
 *
 * <glib.h>
 */

/**
 * Random bytes buffer
 */
struct sipe_tls_random {
  guchar *buffer;
  guint length;   /* in bytes */
};

/**
 * Allocate a buffer with N random bits
 *
 * @param random pointer to random bytes buffer
 * @param bits   number of random bits (will be rounded up be dividable by 16)
 */
void sipe_tls_fill_random(struct sipe_tls_random *random,
			  guint bits);

/**
 * Free a random bytes buffer
 *
 * @param random pointer to random bytes buffer
 */
void sipe_tls_free_random(struct sipe_tls_random *random);


/**
 * Public part of TLS state tracking
 *
 * If @c session_key != @c NULL then handshake is complete
 */
enum sipe_tls_digest_algorithm {
  SIPE_TLS_DIGEST_ALGORITHM_NONE,
  SIPE_TLS_DIGEST_ALGORITHM_MD5,
  SIPE_TLS_DIGEST_ALGORITHM_SHA1
};
struct sipe_tls_state {
  const guchar *in_buffer;
  guchar *out_buffer;
  gsize in_length;
  gsize out_length;
  enum sipe_tls_digest_algorithm algorithm;
  const guchar *client_key;
  const guchar *server_key;
  gsize key_length;
};

/**
 * TLS data expansion function P_SHA1(secret, seed)
 *
 * @param secret        pointer to binary secret
 * @param secret_length length of secret
 * @param seed          pointer to binary seed
 * @param seed_length   length of seed
 * @param output_length how much data to generate
 *
 * @return generated data. Must be g_free()'d
 */
guchar *sipe_tls_p_sha1(const guchar *secret,
			gsize secret_length,
			const guchar *seed,
			gsize seed_length,
			gsize output_length);

/**
 * Initialize TLS state
 *
 * @param certificate opaque pointer to the user certificate
 *
 * @return TLS state structure
 */
struct sipe_tls_state *sipe_tls_start(gpointer certificate);

/**
 * Proceed to next TLS state
 *
 * @param state     pointer to TLS state structure
 * @param incoming  pointer to incoming message (NULL for initial transition)
 * @param in_length length of incoming message
 *
 * @return TLS state structure
 */
gboolean sipe_tls_next(struct sipe_tls_state *state);

/**
 * Extract expiration time from TLS certificate
 *
 * @param state     pointer to TLS state structure
 *
 * @return expiration time in seconds
 */
guint sipe_tls_expires(struct sipe_tls_state *state);

/**
 * Free TLS state
 *
 * @param state pointer to TLS state structure
 */
void sipe_tls_free(struct sipe_tls_state *state);
