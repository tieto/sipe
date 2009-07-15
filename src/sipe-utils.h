/**
 * @file sipe-utils.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009 SIPE Project <http://sipe.sourceforge.net/>
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

/**
 * Generate Call ID
 *
 * @return Call ID. Must be g_free()'d.
 */
gchar *gencallid(void);

/**
 * Generate Tag
 *
 * @return Tag. Must be g_free()'d.
 */
gchar *gentag(void);

/**
 * Get contact information from SIPE account
 *
 * @param sip (in) SIPE account
 *
 * @return Contact. Must be g_free()'d.
 */
gchar *get_contact(const struct sipe_account_data *sip);

/**
 * Parses URI from SIP header
 *
 * @param hdr (in) To/From header
 *
 * @return URI with sip: prefix. Must be g_free()'d.
 */
gchar *parse_from(const gchar *hdr);

/**
 * Create sip: URI from name
 *
 * @param name (in)
 *
 * @return URI with sip: prefix. Must be g_free()'d.
 */
gchar *sip_uri_from_name(const gchar *name);

/**
 * Create sip: URI from SIP account user name
 *
 * @param sip (in) SIP account data
 *
 * @return URI with sip: prefix. Must be g_free()'d.
 */
#define sip_uri_self(sip) (sip_uri_from_name(sip->username))

/**
 * Create sip: URI from name or sip: URI
 *
 * @param string (in) name or sip: URI
 *
 * @return URI with sip: prefix. Must be g_free()'d.
 */
gchar *sip_uri(const gchar *string);

/**
 * Find a XML node from the parent with the specified path
 *
 * @param parent (in) XML node to start search from
 * @param ...    (in) Names of the descendant nodes
 *
 * @return descendant XML node
 */
xmlnode * xmlnode_get_descendant(const xmlnode *parent, ...);
