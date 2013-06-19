/**
 * @file sip-sec-digest.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2013 SIPE Project <http://sipe.sourceforge.net/>
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

/* Forward declarations */
struct sipe_core_private;

/**
 * Generate Digest authorization header
 *
 * @param sipe_private SIPE core private data
 * @param header       Digest authentication header contents
 *
 * @return Digest authorization header or @c NULL. Must be @c g_free'd().
 */
gchar *sip_sec_digest_authorization(struct sipe_core_private *sipe_private,
				    const gchar *header,
				    const gchar *method,
				    const gchar *target);
