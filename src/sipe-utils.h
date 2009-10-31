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
 * Returns epid value.
 * Uses cache.
 */ 
gchar *
get_epid(struct sipe_account_data *sip);
 
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
 * Generate conference-id
 * 32 characters long. Value space is restricted to printable ASCII characters
 *
 * Ex.: 8386E6AEAAA41E4AA6627BA76D43B6D1
 *
 * @return conference-id. Must be g_free()'d.
 */
gchar *genconfid(void);

/**
 * Returns instance value for particular publication type.
 * It should be consistent for the same endpoint
 * but different between distinct endpoints.
 *
 * See defined constants for keys patterned SIPE_PUB_*
 */ 
guint
sipe_get_pub_instance(struct sipe_account_data *sip,
		      const char *publication_key);

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
 * Parses CSeq from SIP header
 *
 * @param hdr (in) CSeqm header
 *
 * @return int type CSeq value (i.e. without method).
 */
int parse_cseq(const gchar *hdr);

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
 * Tries to figure out if contact alias which stored locally
 * is just SIP URI, not a proper display name or local alias.
 *
 * @param uri SIP URI with 'sip:' prefix.
 * @param alias as returned by purple.
 */ 
gboolean
sipe_is_bad_alias(const char *uri,
		  const char *alias);

/**
 * Find a XML node from the parent with the specified path
 *
 * @param parent (in) XML node to start search from
 * @param ...    (in) Names of the descendant nodes
 *
 * @return descendant XML node
 */
xmlnode * xmlnode_get_descendant(const xmlnode *parent, ...);

/**
 * For glib < 2.8 compatibility
 */
char *sipe_get_host_name(void);

/**
 * Checks if provided string is empty - NULL, zero size or just series of white spaces.
 * Doesn't modify input string.
 */
gboolean
is_empty(const char *st);
