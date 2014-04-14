/**
 * @file sipe-xml.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2013 SIPE Project <http://sipe.sourceforge.net/>
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
#include <string.h>
#include <time.h>

#include "libxml/parser.h"
#include "libxml/c14n.h"
#include "libxml/xmlversion.h"

#include "glib.h"

#include "sipe-backend.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

struct _sipe_xml {
	gchar *name;
	sipe_xml *parent;
	sipe_xml *sibling;
	sipe_xml *first;
	sipe_xml *last;
	GString *data;
	GHashTable *attributes;
};

struct _parser_data {
	sipe_xml *root;
	sipe_xml *current;
	gboolean error;
};

/* our string equal function is case insensitive -> hash must be too! */
static guint sipe_ascii_strdown_hash(gconstpointer key)
{
	gchar *lc = g_ascii_strdown((const gchar *) key, -1);
	guint bucket = g_str_hash(lc);
	g_free(lc);

	return(bucket);
}

static void callback_start_element(void *user_data, const xmlChar *name, const xmlChar **attrs)
{
	struct _parser_data *pd = user_data;
	const char *tmp;
	sipe_xml *node;

	if (!name || pd->error) return;

	node = g_new0(sipe_xml, 1);

	if ((tmp = strchr((char *)name, ':')) != NULL) {
		name = (xmlChar *)tmp + 1;
	}
	node->name = g_strdup((gchar *)name);

	if (!pd->root) {
		pd->root = node;
	} else {
		sipe_xml *current = pd->current;

		node->parent = current;
		if (current->last) {
			current->last->sibling = node;
		} else {
			current->first = node;
		}
		current->last = node;
	}

	if (attrs) {
		const xmlChar *key;

		node->attributes = g_hash_table_new_full(sipe_ascii_strdown_hash,
							 (GEqualFunc) sipe_strcase_equal,
							 g_free, g_free);
		while ((key = *attrs++) != NULL) {
			if ((tmp = strchr((char *)key, ':')) != NULL) {
				key = (xmlChar *)tmp + 1;
			}
			/* libxml2 decodes all entities except &amp;.
			   &amp; is replaced by the equivalent &#38; */
			g_hash_table_insert(node->attributes,
					    g_strdup((gchar *) key),
					    sipe_utils_str_replace((gchar *) *attrs++, "&#38;", "&"));
		}
	}

	pd->current = node;
}

static void callback_end_element(void *user_data, const xmlChar *name)
{
	struct _parser_data *pd = user_data;

	if (!name || !pd->current || pd->error) return;

	if (pd->current->parent)
		pd->current = pd->current->parent;
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
		SIPE_DEBUG_WARNING_NOFORMAT("XML parser error");
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
			result = pd->root;
		}

		g_free(pd);
	}

	return result;
}

void sipe_xml_free(sipe_xml *node)
{
	sipe_xml *child;

	if (!node) return;

	/* we don't support partial tree deletion */
	if (node->parent != NULL) {
		SIPE_DEBUG_ERROR_NOFORMAT("sipe_xml_free: partial delete attempt! Expect crash or memory leaks...");
	}

	/* free children */
	child = node->first;
	while (child) {
		sipe_xml *tmp = child->sibling;
		child->parent = NULL; /* detach from tree, see above */
		sipe_xml_free(child);
		child = tmp;
	}

	/* free node */
	g_free(node->name);
	if (node->data)       g_string_free(node->data, TRUE);
	if (node->attributes) g_hash_table_destroy(node->attributes);
	g_free(node);
}

static void sipe_xml_stringify_attribute(gpointer key, gpointer value,
					 gpointer user_data)
{
	g_string_append_printf(user_data, " %s=\"%s\"",
			       (const gchar *) key, (const gchar *) value);
}

static void sipe_xml_stringify_node(GString *s, const sipe_xml *node)
{
	g_string_append_printf(s, "<%s", node->name);

	if (node->attributes) {
		g_hash_table_foreach(node->attributes,
				     (GHFunc) sipe_xml_stringify_attribute,
				     s);
	}

	if (node->data || node->first) {
		const sipe_xml *child;

		g_string_append_printf(s, ">%s",
				       node->data ? node->data->str : "");

		for (child = node->first; child; child = child->sibling)
			sipe_xml_stringify_node(s, child);

		g_string_append_printf(s, "</%s>", node->name);
	} else {
		g_string_append(s, "/>");
	}
}

gchar *sipe_xml_stringify(const sipe_xml *node)
{
	GString *s;

	if (!node) return NULL;

	s = g_string_new("");
	sipe_xml_stringify_node(s, node);
	return g_string_free(s, FALSE);
}

const sipe_xml *sipe_xml_child(const sipe_xml *parent, const gchar *name)
{
	gchar **names;
	const sipe_xml *child = NULL;

	if (!parent || !name) return NULL;

	/* 0: child name */
	/* 1: trailing path (optional) */
	names = g_strsplit(name, "/", 2);

	for (child = parent->first; child; child = child->sibling) {
		if (sipe_strequal(names[0], child->name))
			break;
	}

	/* recurse into path */
	if (child && names[1])
		child = sipe_xml_child(child, names[1]);

	g_strfreev(names);
	return child;
}

const sipe_xml *sipe_xml_twin(const sipe_xml *node)
{
	sipe_xml *sibling;

	if (!node) return NULL;

	for (sibling = node->sibling; sibling; sibling = sibling->sibling) {
		if (sipe_strequal(node->name, sibling->name))
			return sibling;
	}
	return NULL;
}

const gchar *sipe_xml_name(const sipe_xml *node)
{
	return(node ? node->name : NULL);
}

const gchar *sipe_xml_attribute(const sipe_xml *node, const gchar *attr)
{
	if (!node || !attr || !node->attributes) return NULL;
	return(g_hash_table_lookup(node->attributes, attr));
}

guint sipe_xml_int_attribute(const sipe_xml *node, const gchar *attr,
			     guint fallback)
{
	const gchar *value = sipe_xml_attribute(node, attr);
	return(value ? g_ascii_strtoull(value, NULL, 10) : fallback);
}

gchar *sipe_xml_data(const sipe_xml *node)
{
	if (!node || !node->data || !node->data->str) return NULL;
	return g_strdup(node->data->str);
}

/**
 * Set to 1 to enable debugging code and then add this line to your code:
 *
 *      sipe_xml_dump(node, NULL);
 */
#if 0
void sipe_xml_dump(const sipe_xml *node, const gchar *path)
{
	const sipe_xml *child;
	gchar *new_path;
	if (!node) return;
	new_path = g_strdup_printf("%s/%s", path ? path : "", node->name);
	if (node->attributes) {
		GList *attrs = g_hash_table_get_keys(node->attributes);
		GString *buf = g_string_new("");
		GList *entry = attrs;
		while (entry) {
			g_string_append_printf(buf, "%s ", (gchar *)entry->data);
			entry = entry->next;
		}
		SIPE_DEBUG_INFO("%s [%s]", new_path, buf->str);
		g_string_free(buf, TRUE);
		g_list_free(attrs);
	} else {
		SIPE_DEBUG_INFO_NOFORMAT(new_path);
	}
	for (child = node->first; child; child = child->sibling)
		sipe_xml_dump(child, new_path);
	g_free(new_path);
}
#endif

/*
 * Other XML convenience functions not based on libpurple xmlnode.c
 */

gchar *sipe_xml_exc_c14n(const gchar *string)
{
	/* Parse string to XML document */
	xmlDocPtr doc = xmlReadMemory(string, strlen(string), "", NULL, 0);
	gchar *canon = NULL;

	if (doc) {
		xmlChar *buffer;
		int size;

		/* Apply canonicalization */
		size = xmlC14NDocDumpMemory(doc,
					    NULL,
#if LIBXML_VERSION > 20703
					    /* new API: int mode (a xmlC14NMode) */
					    XML_C14N_EXCLUSIVE_1_0,
#else
					    /* old API: int exclusive */
					    1,
#endif
					    NULL,
					    0,
					    &buffer);
		xmlFreeDoc(doc);

		if (size >= 0) {
			SIPE_DEBUG_INFO("sipe_xml_exc_c14n:\noriginal:      %s\ncanonicalized: %s",
					string, buffer);
			canon = g_strndup((gchar *) buffer, size);
			xmlFree(buffer);
		} else {
			SIPE_DEBUG_ERROR("sipe_xml_exc_c14n: failed to canonicalize xml string:\n%s",
					 string);
		}
	} else {
		SIPE_DEBUG_ERROR("sipe_xml_exc_c14n: error parsing xml string:\n%s",
				 string);
	}

	return(canon);
}

gchar *sipe_xml_extract_raw(const gchar *xml, const gchar *tag,
			    gboolean include_tag)
{
	gchar *tag_start = g_strdup_printf("<%s", tag);
	gchar *tag_end = g_strdup_printf("</%s>", tag);
	gchar *data = NULL;
	const gchar *start = strstr(xml, tag_start);

	if (start) {
		const gchar *end = strstr(start + strlen(tag_start), tag_end);
		if (end) {
			if (include_tag) {
				data = g_strndup(start, end + strlen(tag_end) - start);
			} else {
				const gchar *tmp = strchr(start + strlen(tag_start), '>') + 1;
				data = g_strndup(tmp, end - tmp);
			}
		}
	}

	g_free(tag_end);
	g_free(tag_start);
	return data;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
