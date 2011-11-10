/**
 * @file sipe-cert-crypto.h
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
 * Internal interface between sipe-certificate and the crypto implementation
 */

/*
 * Interface dependencies:
 *
 * <glib.h>
 */

/**
 * Unwrap data wrapped with the KW-AESxxx algorithm
 *
 * @param aes_key       AES key
 * @param aes_key_len   length of AES key (32 for 256-Bit AES key)
 * @param wrapped       wrapped binary data
 * @param wrapped_len   length of wrapped data
 * @param unwrapped_len [out] length of unwrapped data
 *
 * @return              @c unwrapped data or NULL. Must be g_free'd()
 */
guchar *sipe_cert_crypto_unwrap_kw_aes(const guchar *aes_key,
				       gsize aes_key_len,
				       const guchar *wrapped,
				       gsize wrapped_len,
				       gsize *unwrapped_len);
