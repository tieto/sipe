/**
 * @file sip-csta.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011 SIPE Project <http://sipe.sourceforge.net/>
 * Copyright (C) 2009 pier11 <pier11@operamail.com>
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
struct sipmsg;
struct sipe_core_private;

/**
 * Transform telephone number representation to tel: URI form.
 * Removes white space, parenthesis ( ), hyphen - symbols
 *
 * @param phone Ex. +32 2 245 00 00
 * @return Ex. tel:+3222450000 or @c NULL. Must be @c g_free()'d after use.
 */
gchar *sip_to_tel_uri(const gchar *phone);

/**
 * Transform telephone number from tel: URI representation
 * to more human readable form.
 * Removes tel: prefix if such exist.
 * (Maybe will add spaces in the future according to local phone patterns.)
 *
 * @param tel_uri Ex. tel:+3222450000
 * @return Ex. +3222450000. Must be @c g_free()'d after use.
 */
gchar *sip_tel_uri_denormalize(const gchar *tel_uri);

/**
 * Initializes CSTA
 *
 * @param line_uri (in) our line tel URI.            Ex.: tel:73124;phone-context=dialstring;partition=BE_BRS_INT
 * @param server   (in) SIP URI of SIP/CSTA Gateway. Ex.: sip:73124@euuklhccups01.eu.company.local
 */
void sip_csta_open(struct sipe_core_private *sipe_private,
		   const gchar *line_uri,
		   const gchar *server);

/**
 * Closes CSTA
 */
void sip_csta_close(struct sipe_core_private *sipe_private);

/**
 * Processes incoming CSTA commands
 */
void process_incoming_info_csta(struct sipe_core_private *sipe_private,
				struct sipmsg *msg);

/**
 * Is CSTA in idle state?
 */
gboolean sip_csta_is_idle(struct sipe_core_private *sipe_private);
