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

/*
 * This code is loosely based on libpurple xmlnode.c
 */

#include <stdarg.h>

#include "libxml/parser.h"
#include "glib.h"
#include "glib/gprintf.h"

#include "sipe-xml.h"
#include "sipe.h"       /* TEMPORARY: to include sipe-utils.h without errors */
#include "sipe-utils.h"
#include "sipe-backend-debug.h"

struct _sipe_xml {
	gchar *name;
	sipe_xml *parent;
	sipe_xml *next;
	sipe_xml *child;
	gchar **attributes;
	GString *data;
};

struct _parser_data {
	sipe_xml *root;
	sipe_xml *current;
	gboolean error;
};

static void callback_start_element(void *user_data, const xmlChar *text, const xmlChar **attrs)
{
	/* @TODO: implement me :-) */
	(void) user_data;
	(void) text;
	(void) attrs;
}

static void callback_end_element(void *user_data, const xmlChar *name)
{
	/* @TODO: implement me :-) */
	(void) user_data;
	(void) name;
}

static void callback_characters(void *user_data, const xmlChar *text, int text_len)
{
	struct _parser_data *pd = user_data;
	sipe_xml *node;

	if (!pd->current || pd->error || !text || !text_len) return;

	node = pd->current;
	if (node->data)
		node->data = g_string_append_len(node->data, (gchar *)text, text_len);
	else
		node->data = g_string_new_len((gchar *)text, text_len);
}

static void callback_error(void *user_data, const char *msg, ...)
{
	struct _parser_data *pd = user_data;
	gchar *errmsg;
	va_list args;

	pd->error = TRUE;

	va_start(args, msg);
	errmsg = g_strdup_vprintf(msg, args);
	va_end(args);

	SIPE_DEBUG_ERROR("error parsing xml string: %s", errmsg);
	g_free(errmsg);
}

static void callback_serror(void *user_data, xmlErrorPtr error)
{
	struct _parser_data *pd = user_data;

	if (error && (error->level == XML_ERR_ERROR ||
	              error->level == XML_ERR_FATAL)) {
		pd->error = TRUE;
		SIPE_DEBUG_ERROR("XML parser error: Domain %i, code %i, level %i: %s",
				 error->domain, error->code, error->level,
				 error->message ? error->message : "(null)");
	} else if (error) {
		SIPE_DEBUG_WARNING("XML parser error: Domain %i, code %i, level %i: %s",
		                   error->domain, error->code, error->level,
				   error->message ? error->message : "(null)");
	} else {
		/* *sigh* macro expects at least two parameters */
		SIPE_DEBUG_WARNING("XML parser error%s", "");
	}
}

/* API doesn't accept const data structure */
static xmlSAXHandler parser = {
	NULL,                   /* internalSubset */
	NULL,                   /* isStandalone */
	NULL,                   /* hasInternalSubset */
	NULL,                   /* hasExternalSubset */
	NULL,                   /* resolveEntity */
	NULL,                   /* getEntity */
	NULL,                   /* entityDecl */
	NULL,                   /* notationDecl */
	NULL,                   /* attributeDecl */
	NULL,                   /* elementDecl */
	NULL,                   /* unparsedEntityDecl */
	NULL,                   /* setDocumentLocator */
	NULL,                   /* startDocument */
	NULL,                   /* endDocument */
	callback_start_element, /* startElement */
	callback_end_element,   /* endElement   */
	NULL,                   /* reference */
	callback_characters,    /* characters */
	NULL,                   /* ignorableWhitespace */
	NULL,                   /* processingInstruction */
	NULL,                   /* comment */
	NULL,                   /* warning */
	callback_error,         /* error */
	NULL,                   /* fatalError */
	NULL,                   /* getParameterEntity */
	NULL,                   /* cdataBlock */
	NULL,                   /* externalSubset */
	XML_SAX2_MAGIC,         /* initialized */
	NULL,                   /* _private */
	NULL,                   /* startElementNs */
	NULL,                   /* endElementNs   */
	callback_serror,        /* serror */
};

sipe_xml *sipe_xml_parse(const gchar *string, gsize length)
{
	sipe_xml *result = NULL;

	if (string && length) {
		struct _parser_data *pd = g_new0(struct _parser_data, 1);

		if (xmlSAXUserParseMemory(&parser, pd, string, length))
			pd->error = TRUE;

		if (pd->error) {
			sipe_xml_free(pd->root);
		} else {
			result = pd->current;
		}

		g_free(pd);
	}

	return result;
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
	gchar **names;
	sipe_xml *child = NULL;

	if (!parent || !name) return NULL;

	/* 0: child name */
	/* 1: trailing path (optional) */
	names = g_strsplit(name, "/", 2);

	for (child = parent->child; child; child = child->next) {
		if (sipe_strequal(names[0], child->name))
			break;
	}

	/* recurse into path */
	if (child && names[1])
		child = sipe_xml_get_child(child, names[1]);

	g_strfreev(names);
	return child;
}

sipe_xml *sipe_xml_get_descendant(const sipe_xml *parent, ...)
{
	va_list args;
	sipe_xml *node = NULL;
	const gchar *name;

	va_start(args, parent);
	while ((name = va_arg(args, const char *)) != NULL) {
		node = sipe_xml_get_child(parent, name);
		if (node == NULL) break;
		parent = node;
	}
	va_end(args);

	return node;
}

sipe_xml *sipe_xml_get_next_twin(const sipe_xml *node)
{
	sipe_xml *sibling;

	if (!node) return NULL;

	for (sibling = node->next; sibling; sibling = sibling->next) {
		if (sipe_strequal(node->name, sibling->name))
			return sibling;
	}		
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
	if (!node || !node->data || !node->data->str) return NULL;
	return g_strdup(node->data->str);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
