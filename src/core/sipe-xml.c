/**
 * @file sipe-xml.c
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

#include <stdarg.h>

#include "glib.h"

#include "sipe-xml.h"

struct _sipe_xml {
	sipe_xml *twin;
	sipe_xml *children;
	gchar **attributes;
	gchar *data;
};

sipe_xml *sipe_xml_parse(const gchar *string, gsize length)
{
	/* @TODO: implement me :-) */
	(void) string;
	(void) length;
	return NULL;
}

void sipe_xml_free(sipe_xml *xml)
{
	/* @TODO: implement me :-) */
	(void) xml;
}

gchar *sipe_xml_to_string(const sipe_xml *xml)
{
	/* @TODO: implement me :-) */
	(void) xml;
	return NULL;
}

sipe_xml *sipe_xml_get_child(const sipe_xml *parent, const gchar *name)
{
	/* @TODO: implement me :-) */
	(void) parent;
	(void) name;
	return NULL;
}

sipe_xml *sipe_xml_get_descendant(const sipe_xml *parent, ...)
{
	va_list ap;

	/* @TODO: implement me :-) */
	va_start(ap, parent);
	va_end(ap);

	return NULL;
}

sipe_xml *sipe_xml_get_next_twin(const sipe_xml *node)
{
	/* @TODO: implement me :-) */
	(void) node;
	return NULL;
}

const gchar *sipe_xml_get_attribute(const sipe_xml *node, const gchar *attr)
{
	/* @TODO: implement me :-) */
	(void) node;
	(void) attr;
	return NULL;
}

gint sipe_xml_get_int_attribute(const sipe_xml *node, const gchar *attr,
				gint fallback)
{
	/* @TODO: implement me :-) */
	(void) node;
	(void) attr;
	return fallback;
}

gchar *sipe_xml_get_data(const sipe_xml *node)
{
	/* @TODO: implement me :-) */
	(void) node;
	return NULL;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
