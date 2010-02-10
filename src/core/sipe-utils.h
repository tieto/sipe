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

/* Our publication type keys. OCS 2007+
 * Format: SIPE_PUB_{Category}[_{SubSategory}]
 */
/**
 * device
 * -
 *
 * -
 * Unique to the device.
 */
#define SIPE_PUB_DEVICE		0
/**
 * state
 * Machine state
 *
 * Availability, activity, end-point location, time zone, and device type.
 * First hexadecimal digit is 0x3; remaining seven hexadecimal digits are unique per device.
 */
#define SIPE_PUB_STATE_MACHINE	3
/**
 * state
 * User state
 *
 * Availability and activity.
 * 0x20000000
 */
#define SIPE_PUB_STATE_USER	2
/**
 * state
 * Calendar state
 *
 * Availability, activity, meeting subject, and meeting location.
 * First hexadecimal digit is 0x4; remaining seven hexadecimal digits are unique per device.
 */
#define SIPE_PUB_STATE_CALENDAR	4
/**
 * state
 * Calendar state for an Out of Office meeting
 *
 * (??)Activity for when a user sets or removes an Out of Office message in Exchange.
 * (+)user sets in Outlook for an Out of Office meeting
 * First hexadecimal digit is 0x5; remaining seven hexadecimal digits are unique per device.
 */
#define SIPE_PUB_STATE_CALENDAR_OOF	5
/**
 * state
 * RCC Phone State
 *
 * Availability and activity for RCC call connect/disconnect or participant count changes from 0 to 2, 2 to N, N to 2, 2 to 0.
 * First hexadecimal digit is 0x7; remaining seven hexadecimal digits are unique per device.
 */
#define SIPE_PUB_STATE_PHONE	7
/**
 * calendarData
 * Free/busy data
 *
 * Start time, granularity, and free/busy data.
 * First hexadecimal digit is 0x4; last seven hexadecimal digits uniquely define the calendar.
 */
#define SIPE_PUB_CALENDAR_DATA	400
/**
 * note
 * Out of Office note
 *
 * Out of Office note that a user sets in Outlook using the Out of Office assistant.
 * First hexadecimal digit is 0x4; last seven hexadecimal digits uniquely define the calendar.
 */
#define SIPE_PUB_NOTE_OOF	400

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
		      int publication_key);

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
 * Convert a XML attribute to an integer
 * @param node     (in) XML node
 * @param attr     (in) name of the attribute
 * @param fallback (in) default value if the attribute doesn't exist
 *
 * @return attribute value converted to integer or the fallback value
 */
gint xmlnode_get_int_attrib(xmlnode *node,
			    const char *attr,
			    gint fallback);

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

/** Returns newly allocated string. Must be g_free()'d */
char *
replace(const char *st,
	const char *search,
	const char *replace);

/**
 * Replaces \r\n to \n
 * Returns newly allocated string. Must be g_free()'d
 */
char *
fix_newlines(const char *st);

/**
 * Tests two strings for equality.
 *
 * Unlike strcmp(), this function will not crash if one or both of the
 * strings are @c NULL.
 *
 * Same as purple_strequal (defined only for 2.6) to maintain
 * our backward compatibility.
 *
 * @param left	A string
 * @param right A string to compare with left
 *
 * @return @c TRUE if the strings are the same, else @c FALSE.
 *
 */
gboolean sipe_strequal(const gchar *left, const gchar *right);

/**
 * Parses a timestamp in ISO8601 format and returns a time_t.
 * Assumes UTC if no timezone specified
 *
 * @param timestamp The timestamp
 */
time_t
sipe_utils_str_to_time(const char *timestamp);

/**
 * Converts time_t to ISO8601 string.
 * Timezone is UTC.
 *
 * Must be g_free()'d after use.
 *
 * Example: 2010-02-03T23:59:59Z
 */
char *
sipe_utils_time_to_str(time_t timestamp);
