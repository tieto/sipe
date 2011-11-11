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

/* Forward declarations */
struct sipe_cert_crypto;

/**
 * Free certificate crypto backend data
 *
 * @return opaque pointer to backend private data
 */
struct sipe_cert_crypto *sipe_cert_crypto_init(void);

/**
 * Free certificate crypto backend data
 *
 * @param ssc opaque pointer to backend private data
 */
void sipe_cert_crypto_free(struct sipe_cert_crypto *ssc);

/**
 * Create a certificate request as Base64 encoded string
 *
 * @param ssc     opaque pointer to backend private data
 * @param subject subject for certificate request
 *
 * @return Base64 encoded string. Must be @g_free'd()
 */
gchar *sipe_cert_crypto_request(struct sipe_cert_crypto *ssc,
				const gchar *subject);

/**
 * Destroy certificate (this is a @GDestroyNotify)
 *
 * @param certificate opaque pointer to backend certificate structure
 */
void sipe_cert_crypto_destroy(gpointer certificate);
