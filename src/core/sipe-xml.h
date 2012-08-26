/**
 * @file sipe-xml.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-11 SIPE Project <http://sipe.sourceforge.net/>
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

typedef struct _sipe_xml sipe_xml;

/**
 * Parse XML from a string.
 *
 * @param string String with the XML to be parsed.
 * @param length Length of the string.
 *
 * @return Parsed XML information. Must be @c sipe_xml_free()'d.
 */
sipe_xml *sipe_xml_parse(const gchar *string, gsize length);

/**
 * Free XML information.
 *
 * @param string XML information to be freed.
 */
void sipe_xml_free(sipe_xml *xml);

/**
 * Convert XML information to string.
 *
 * @param xml XML information.
 *
 * @return XML converted to a string. Must be @c g_free()'d.
 */
gchar *sipe_xml_stringify(const sipe_xml *xml);

/**
 * Gets a child node named name.
 *
 * @param parent The parent node.
 * @param name   relative XPATH of the child (a, a/b, a/b/c, etc.).
 *
 * @return The child or @c NULL. Never try to @c sipe_xml_free() it!
 */
const sipe_xml *sipe_xml_child(const sipe_xml *parent, const gchar *name);

/**
 * Gets the next node with the same name as node.
 *
 * @param node The node of a twin to find.
 *
 * @return The twin of node or @c NULL.
 */
const sipe_xml *sipe_xml_twin(const sipe_xml *node);

/**
 * Gets the name from the current XML node.
 *
 * @param node The node to get the name from.
 *
 * @return The name of the node
 */
const gchar *sipe_xml_name(const sipe_xml *node);

/**
 * Gets an attribute from the current XML node.
 *
 * @param node The node to get an attribute from.
 * @param attr The attribute to get.
 *
 * @return The value of the attribute or @c NULL.
 */
const gchar *sipe_xml_attribute(const sipe_xml *node, const gchar *attr);

/**
 * Gets an attribute from the current XML node and convert it to an
 * unsigned integer.
 *
 * @param node     The node to get an attribute from.
 * @param attr     The attribute to get.
 * @param fallback Default value if the attribute doesn't exist.
 *
 * @return Attribute value converted to an integer or the fallback value.
 */
guint sipe_xml_int_attribute(const sipe_xml *node, const gchar *attr,
			     guint fallback);

/**
 * Gets escaped data from the current XML node.
 *
 * @param node The node to get data from.
 *
 * @return The data from the node or @c NULL. Must be @c g_free()'d.
 */
gchar *sipe_xml_data(const sipe_xml *node);

/**
 * For debugging while writing XML processing code.
 * NOTE: the code for this function is flagged out by default!
 *
 * @param node The node to start dumping from
 * @param path The path to this node (can be NULL)
 */
void sipe_xml_dump(const sipe_xml *node, const gchar *path);

/* Other XML convenience functions */

/**
 * Apply "Exclusive XML Canonicalization" to a XML string
 * See also http://www.w3.org/TR/xml-exc-c14n/
 *
 * @param string String with the XML to be canonicalized.
 *
 * @return canonicalized XML string. Must be @c g_free()'d.
 */
gchar *sipe_xml_exc_c14n(const gchar *string);

/**
 * Extracts raw data between a pair of XML tags.
 *
 * @param xml XML document
 * @param tag XML tag enclosing the data
 * @param include_tag whether the enclosing tags should be included in the result
 *
 * @return a first substring from the XML document enclosed by @c tag.
 * Must be @c g_free()'d.
 */
gchar *sipe_xml_extract_raw(const gchar *xml, const gchar *tag,
			    gboolean include_tag);
