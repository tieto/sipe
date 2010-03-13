/**
 * @file sipe-xml.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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
 * @return Parsed XML information. Must be sipe_xml_free()'d.
 */
sipe_xml *sipe_xml_parse(const gchar *string, gsize length);

/**
 * Free XML information
 *
 * @param string XML information to be freed.
 */
void sipe_xml_free(sipe_xml *xml);

/**
 * Convert XML information to string
 *
 * @param xml XML information
 *
 * @return XML converted to a string. Must be g_free()'d
 */
gchar *sipe_xml_to_string(const sipe_xml *xml);

/**
 * Gets a child node named name.
 *
 * @param parent The parent node.
 * @param name   The childs name.
 *
 * @return The child or NULL.
 */
sipe_xml *sipe_xml_get_child(const sipe_xml *parent, const gchar *name);

/**
 * Find a XML node from the parent with the specified path
 *
 * @param parent The parent node.
 * @param ...    Names of the descendant nodes
 *
 * @return descendant XML node or NULL.
 */
sipe_xml *sipe_xml_get_descendant(const sipe_xml *parent, ...);

/**
 * Gets the next node with the same name as node.
 *
 * @param node The node of a twin to find.
 *
 * @return The twin of node or NULL.
 */
sipe_xml *sipe_xml_get_next_twin(const sipe_xml *node);

/**
 * Gets an attribute from the current XML node.
 *
 * @param node The node to get an attribute from.
 * @param attr The attribute to get.
 *
 * @return The value of the attribute or NULL.
 */
const gchar *sipe_xml_get_attribute(const sipe_xml *node, const gchar *attr);

/**
 * Gets an attribute from the current XML node and convert it to an integer.
 *
 * @param node     The node to get an attribute from.
 * @param attr     The attribute to get.
 * @param fallback Default value if the attribute doesn't exist
 *
 * @return Attribute value converted to an integer or the fallback value
 */
gint sipe_xml_get_int_attribute(const sipe_xml *node, const gchar *attr,
				gint fallback);

/**
 * Gets escaped data from the curretn XML node.
 *
 * @param node The node to get data from.
 *
 * @return The data from the node or NULL. Must be g_free()'d.
 */
gchar *sipe_xml_get_data(const sipe_xml *node);
