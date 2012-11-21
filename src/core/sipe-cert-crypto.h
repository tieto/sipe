/**
 * @file sipe-cert-crypto.h
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
 * Internal interface between sipe-certificate/sipe-tls
 * and the certificate crypto implementation
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
 * @param scc opaque pointer to backend private data
 */
void sipe_cert_crypto_free(struct sipe_cert_crypto *scc);

/**
 * Create a certificate request as Base64 encoded string
 *
 * @param scc     opaque pointer to backend private data
 * @param subject subject for certificate request
 *
 * @return Base64 encoded string. Must be @g_free'd()
 */
gchar *sipe_cert_crypto_request(struct sipe_cert_crypto *scc,
				const gchar *subject);

/**
 * Destroy certificate (this is a @GDestroyNotify)
 *
 * @param certificate opaque pointer to backend certificate structure
 *                    May be @c NULL
 */
void sipe_cert_crypto_destroy(gpointer certificate);

/**
 * Decode a client certificate from Base64 string
 *
 * @param base64 Base64 encoded DER data
 *
 * @return opaque pointer to certificate. Must be @sipe_cert_crypto_destroy()'d.
 */
gpointer sipe_cert_crypto_decode(struct sipe_cert_crypto *scc,
				 const gchar *base64);

/**
 * Import a server certificate from DER data
 *
 * @param raw    DER data
 * @param length length of DER data
 *
 * @return opaque pointer to certificate. Must be @sipe_cert_crypto_destroy()'d.
 */
gpointer sipe_cert_crypto_import(const guchar *raw, gsize length);

/**
 * Check if certificate is valid until @c offset seconds from now
 *
 * @param certificate opaque pointer to backend certificate structure
 * @param offset      seconds from now
 *
 * @return @c TRUE if certificate is still valid at that time
 */
gboolean sipe_cert_crypto_valid(gpointer certificate,
				guint offset);

/**
 * Return how many seconds until the certificate expires
 *
 * @param certificate opaque pointer to backend certificate structure
 *
 * @return offset in seconds
 */
guint sipe_cert_crypto_expires(gpointer certificate);

/**
 * Return length of certificate in DER form
 *
 * @param certificate opaque pointer to backend certificate structure
 *
 * @return length in bytes
 */
gsize sipe_cert_crypto_raw_length(gpointer certificate);

/**
 * Return certificate in DER form
 *
 * @param certificate opaque pointer to backend certificate structure
 *
 * @return pointer to DER data
 */
const guchar *sipe_cert_crypto_raw(gpointer certificate);

/**
 * Get public key for certificate
 *
 * @param certificate opaque pointer to backend certificate structure
 *
 * @return opaque pointer to backend public key structure
 */
gpointer sipe_cert_crypto_public_key(gpointer certificate);

/**
 * Get public key modulus length for server certificate
 *
 * @param certificate opaque pointer to backend certificate structure
 *
 * @return server public key strength
 */
gsize sipe_cert_crypto_modulus_length(gpointer certificate);

/**
 * Get private key for client certificate
 *
 * @param certificate opaque pointer to backend certificate structure
 *
 * @return opaque pointer to backend private key structure
 */
gpointer sipe_cert_crypto_private_key(gpointer certificate);

/**
 * Create test certificate for internal key pair (ONLY USE FOR TEST CODE!!!)
 *
 * @param scc opaque pointer to backend private data
 *
 * @return opaque pointer to backend certificate structure
 */
gpointer sipe_cert_crypto_test_certificate(struct sipe_cert_crypto *scc);
