/**
 * @file sipe-tls.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011 SIPE Project <http://sipe.sourceforge.net/>
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
 * Public part of TLS state tracking
 *
 * If @c session_key != @c NULL then handshake is complete
 */
struct sipe_tls_state {
  const guchar *in_buffer;
  guchar *out_buffer;
  gsize in_length;
  gsize out_length;
  guchar *session_key;
  gsize key_length;
};

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
 * Free TLS state
 *
 * @param state pointer to TLS state structure
 */
void sipe_tls_free(struct sipe_tls_state *state);
