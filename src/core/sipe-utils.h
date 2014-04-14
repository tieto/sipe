/**
 * @file sipe-utils.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009-2013 SIPE Project <http://sipe.sourceforge.net/>
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
 * <time.h>
 * <glib.h>
 */

/* Forward declarations */
struct sipe_core_private;
struct sipe_transport_connection;

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
#define SIPE_PUB_STATE_PHONE_RCC	7
/**
 * state
 * VOIP Phone State
 *
 * Availability and activity for VOIP call connect/disconnect or participant count changes from 0 to 2, 2 to N, N to 2, 2 to 0.
 * First hexadecimal digit is 0x8; remaining seven hexadecimal digits uniquely define the SIP URI and device.
 */
#define SIPE_PUB_STATE_PHONE_VOIP	8
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
 *
 * @param sipe_private (in) SIPE core private data
 *
 * @return epid. Must be g_free()'d.
 */
gchar *
get_epid(struct sipe_core_private *sipe_private);

/**
 * Returns UUID value.
 *
 * @param sipe_private (in) SIPE core private data
 *
 * @return uuid. Must be g_free()'d.
 */
gchar *
get_uuid(struct sipe_core_private *sipe_private);

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
sipe_get_pub_instance(struct sipe_core_private *sipe_private,
		      int publication_key);

/**
 * Get contact information from SIPE account
 *
 * @param sipe_private (in) SIPE core private data
 *
 * @return Contact. Must be g_free()'d.
 */
gchar *get_contact(const struct sipe_core_private *sipe_private);

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
 * @param sipe_private (in) SIPE core private data
 *
 * @return URI with sip: prefix. Must be g_free()'d.
 */
#define sip_uri_self(sipe_private) (sip_uri_from_name(sipe_private->username))

/**
 * Create sip: URI from name or sip: URI
 *
 * @param string (in) name or sip: URI
 *
 * @return URI with sip: prefix. Must be g_free()'d.
 */
gchar *sip_uri(const gchar *string);

/**
 * Create sip: URI from name or sip: URI. Checks for invalid characters
 *
 * @param string (in) name or sip: URI
 *
 * @return URI with sip: prefix. Returns NULL if @c string contains invalid
 *         characters. Must be g_free()'d.
 */
gchar *sip_uri_if_valid(const gchar *string);

/**
 * Returns pointer to URI without sip: prefix if any (doesn't allocate memory)
 *
 * @param sip_uri SIP URI possibly with sip: prefix. Example: sip:first.last@hq.company.com
 *
 * @return pointer to URL without sip: prefix. Coresponding example: first.last@hq.company.com
 */
const gchar *sipe_get_no_sip_uri(const gchar *sip_uri);

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
 * Checks if provided string is empty - NULL, zero size or just series of white spaces.
 * Doesn't modify input string.
 */
gboolean
is_empty(const char *st);

/**
 * Message debugging
 *
 * @param type    message type description (SIP or HTTP).
 * @param header  message header
 * @param body    message body or NULL
 * @param sending TRUE if outgoing message
 */
void sipe_utils_message_debug(const gchar *type,
			      const gchar *header,
			      const gchar *body,
			      gboolean sending);

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
 * Tests two strings for equality, ignoring the case
 *
 * Same as glib @c g_ascii_strcasecmp() but works correctly for @c NULL
 * pointers too. Plus it doesn't complain loudly about them...
 *
 * @param left	A string
 * @param right A string to compare with left
 *
 * @return @c TRUE if the strings are the same, else @c FALSE.
 *
 */
gboolean sipe_strcase_equal(const gchar *left, const gchar *right);

/**
 * Compares two strings
 *
 * Unlike strcmp(), this function will not crash if one or both of the
 * strings are @c NULL.
 *
 * Same as g_strcmp0 (defined only for >= 2.16) to maintain
 * our backward compatibility. The declaration is compatible to
 * @c GCompareFunc.
 *
 * @param a A string
 * @param b A string to compare with a
 *
 * @return negative value if a < b; zero if a = b; positive value if a > b.
 *
 */
gint sipe_strcompare(gconstpointer a, gconstpointer b);

/**
 * Parses a timestamp in ISO8601 format and returns a time_t.
 * Assumes UTC if no timezone specified
 *
 * @param timestamp The timestamp (may be @c NULL)
 *
 * @return time_t or 0 if timestamp parsing failed
 */
time_t
sipe_utils_str_to_time(const gchar *timestamp);

/**
 * Converts time_t to ISO8601 string.
 * Timezone is UTC.
 *
 * Must be g_free()'d after use.
 *
 * Example: 2010-02-03T23:59:59Z
 */
gchar *
sipe_utils_time_to_str(time_t timestamp);

struct sipnameval {
	gchar *name;
	gchar *value;
};

/**
 * Parses string of hex digits to buffer.
 * Allocates memory.
 *
 * @param hex_str (in)	string of hex digits to convert.
 * @param buff (out)	newly allocated buffer. Must be g_free()'d after use.
 *
 * @return		size of newly allocated buffer
 */
size_t
hex_str_to_buff(const char *hex_str, guint8 **buff);

/**
 * Composes hex string out of provided buffer.
 * Allocates memory.
 *
 * @param buff		input buffer
 * @param buff_len	length of buffer
 *
 * @result		newly allocated hex string representing buffer. Must be g_free()'d after use.
 */
char *
buff_to_hex_str(const guint8 *buff, const size_t buff_len);

/**
 * Creates name-value pairs from given lines and appends them to @c list
 *
 * Lines must be in format 'name [delimiter] value'
 *
 * @param list      a list of @c sipnameval structures
 * @param lines     array of strings in format 'name: value'
 * @param delimiter sequence of characters between name and value
 *
 * @return @c FALSE if any of @c lines has incorrect format, @c TRUE otherwise
 */
gboolean
sipe_utils_parse_lines(GSList **list, gchar **lines, gchar *delimiter);

/**
 * Adds a name-value pair to @c list
 *
 * @param list  a list of @c sipnameval structures
 * @param name  attribute's name
 * @param value value of attribute @c name
 *
 * @return the new start of the GSList
 */
GSList *
sipe_utils_nameval_add(GSList *list, const gchar *name, const gchar *value);

/**
 * Finds a value of attribute @c name in @c list
 *
 * @param list a list of @c sipnameval structures
 * @param name attribute to find
 *
 * @return value of @c name or NULL if @c name is not found
 */
const gchar *
sipe_utils_nameval_find(const GSList *list, const gchar *name);

/**
 * Returns @c which occurrence of attribute @c name in @c list
 *
 * @c which is zero based, so 0 means first occurrence of @c name in @c list.
 *
 * @param list  a list of @c sipnameval structures
 * @param name  attribute to find
 * @param which specifies occurrence of @name in @c list
 *
 * @return value of @c name or NULL if @c name is not found
 */
const gchar *
sipe_utils_nameval_find_instance(const GSList *list, const gchar *name, int which);

/**
 * Frees memory allocated by @c list
 *
 * @param list a list of @c sipnameval structures
 */
void
sipe_utils_nameval_free(GSList *list);

/**
 * Given a string, this replaces one substring with another
 * and returns a newly allocated string.
 *
 * @param string      the string from which to replace stuff.
 * @param delimiter   the substring you want replaced.
 * @param replacement the substring you want as replacement.
 *
 * @return string with the substitution or NULL. Must be g_free()'d after use.
 */
gchar *sipe_utils_str_replace(const gchar *string,
			      const gchar *delimiter,
			      const gchar *replacement);

/**
 * Remove read characters from transport buffer
 *
 * @param conn   the transport connection
 * @param unread pointer to the first character in the buffer
 */
void sipe_utils_shrink_buffer(struct sipe_transport_connection *conn,
			      const gchar *unread);
/**
 * Checks whether given IP address belongs to private block as defined in RFC1918
 *
 * @param ip IPv4 address in "X.X.X.X" format
 * @return @c TRUE if address is private
 */
gboolean sipe_utils_ip_is_private(const char *ip);

/**
 * Generate presence key
 *
 * @param uri presence URI
 *
 * @return key string. Must be g_free()'d after use.
 */
gchar *sipe_utils_presence_key(const gchar *uri);

/**
 * Decodes a URI into a plain string.
 *
 * @param string the string to translate.
 *
 * @return the resulting string. Must be g_free()'d after use.
 */
gchar *sipe_utils_uri_unescape(const gchar *string);

/**
 * Inserts in item in the list only if the value isn't already in that list
 *
 * @param list    a singly linked list
 * @param data    the item to insert. Will not be copied.
 * @param func    function to use to compare the values
 * @param destroy if @c NULL call to destroy @c data if is already on list
 *
 * @return the new list head
 */
GSList *sipe_utils_slist_insert_unique_sorted(GSList *list,
					      gpointer data,
					      GCompareFunc func,
					      GDestroyNotify destroy);

/**
 * Same as @c g_slist_free_full() which is only defined for >= 2.28
 *
 * @param list a singly linked list
 * @param free function to free list data
 */
void sipe_utils_slist_free_full(GSList *list,
				GDestroyNotify free);
