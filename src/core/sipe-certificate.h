/**
 * @file sipe-certificate.h
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

/* Forward declarations */
struct sipe_core_private;

/**
 * Find TLS-DSK user certificate for a given target
 *
 * @param sipe_private SIPE core private data
 * @param target       target name from authentication header
 *
 * @return opaque      pointer to the certificate. The caller does not own
 *                     the certificate, i.e. he must not free it!
 */
gpointer sipe_certificate_tls_dsk_find(struct sipe_core_private *sipe_private,
				       const gchar *target);


/**
 * Trigger the generation of TLS-DSK user certificate for a given target
 *
 * @param sipe_private SIPE core private data
 * @param target       target name from authentication header
 * @param uri          URI for the Certificate Provisioning Service
 * @return             @c TRUE if certificate generation was triggered
 */
gboolean sipe_certificate_tls_dsk_generate(struct sipe_core_private *sipe_private,
					   const gchar *target,
					   const gchar *uri);

/**
 * Initialize certificate data
 *
 * @param sipe_private SIPE core private data
 */
gboolean sipe_certificate_init(struct sipe_core_private *sipe_private);

/**
 * Free certificate data
 *
 * @param sipe_private SIPE core private data
 */
void sipe_certificate_free(struct sipe_core_private *sipe_private);
