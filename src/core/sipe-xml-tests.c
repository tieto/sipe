/**
 * @file sipe-xml-tests.c
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

/* Tests for sipe-xml.c */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "glib.h"
#include "sipe.h"
#include "sipe-xml.h"
#include "sipe-utils.h"
#include "sipe-backend-debug.h"
#include "sipe-common.h"

/* stub functions for backend API */
void sipe_backend_debug(sipe_debug_level level,
			const gchar *format,
			...)
{
	va_list args;
	gchar *msg;
	va_start(args, format);
	msg = g_strdup_vprintf(format, args);
	va_end(args);

	printf("DEBUG %d: %s", level, msg);
	g_free(msg);
}

/* test helpers */
static guint succeeded = 0;
static guint failed    = 0;
static const gchar *teststring;

static sipe_xml *assert_parse(const gchar *s, gboolean ok)
{
	sipe_xml *xml = sipe_xml_parse(s, s ? strlen(s) : 0);

	teststring = s ? s : "(nil)";

	if ((ok && xml) || (!ok && !xml)) {
		succeeded++;
	} else {
		printf("[%s]\nXML parse FAILED: %p\n",
		       teststring, xml);
		failed++;
	}
	return(xml);
}

static sipe_xml *assert_child(const sipe_xml *xml, const gchar *s, gboolean ok)
{
	sipe_xml *child = sipe_xml_get_child(xml, s);

	if ((ok && child) || (!ok && !child)) {
		succeeded++;
	} else {
		printf("[%s]\nXML child FAILED: %p '%s'\n",
		       teststring, xml, s ? s : "(nil)");
		failed++;
	}
	return(child);
}

static void assert_data(const sipe_xml *xml, const gchar *s)
{
	gchar *data = sipe_xml_get_data(xml);

	if (sipe_strequal(s, data)) {
		succeeded++;
	} else {
		printf("[%s]\nXML data FAILED: '%s' expected: '%s'\n",
		       teststring, data ? data : "(nil)", s ? s : "(nil)");
		failed++;
	}
	g_free(data);
}

static void assert_attribute(const sipe_xml *xml,
			     const gchar *key, const gchar *value)
{
	const gchar *attr = sipe_xml_get_attribute(xml, key);

	if (sipe_strequal(value, attr)) {
		succeeded++;
	} else {
		printf("[%s]\nXML attr FAILED: '%s': '%s' expected: '%s'\n",
		       teststring, key ? key : "(nil)",
		       attr ? attr : "(nil)", value ? value : "(nil)");
		failed++;
	}
}

/* memory leak check */
static gsize allocated = 0;

static gpointer test_malloc(gsize n_bytes)
{
	gsize *m;
	if (n_bytes == 0) return(NULL);
	m = malloc(sizeof(gsize) + n_bytes);
	if (!m) return(NULL);
	allocated += n_bytes;
	m[0] = n_bytes;
	return(&m[1]);
}

static void test_free(gpointer mem)
{
	gsize *m;
	if (!mem) return;
	m = (gsize *) mem - 1;
	allocated -= m[0];
	free(m);
}

static gpointer test_realloc(gpointer mem, gsize n_bytes)
{
	guint8 *n = NULL;
	if (n_bytes) {
		n = test_malloc(n_bytes);
		if (mem && n) {
			memcpy(n, mem, n_bytes);
		}
	}
	test_free(mem);
	return(n);
}

static GMemVTable memory_leak_check = {
	&test_malloc,
	&test_realloc,
	&test_free,
	NULL,
	NULL,
	NULL,
};

int main(SIPE_UNUSED_PARAMETER int argc, SIPE_UNUSED_PARAMETER char **argv)
{
	sipe_xml *xml, *child1, *child2;

	g_mem_set_vtable(&memory_leak_check);

	/* empty XML */
	xml = assert_parse(NULL, FALSE);
	sipe_xml_free(xml);
	xml = assert_parse("",   FALSE);
	sipe_xml_free(xml);
	xml = assert_parse("<?xml version=\"1.0\" ?>", FALSE);
	sipe_xml_free(xml);

	/* one node */
	xml = assert_parse("<test></test>", TRUE);
	assert_data(xml, NULL);
	sipe_xml_free(xml);
	xml = assert_parse("<test>a</test>", TRUE);
	assert_data(xml, "a");
	sipe_xml_free(xml);
	xml = assert_parse("<test>a\nb</test>", TRUE);
	assert_data(xml, "a\nb");
	sipe_xml_free(xml);

	/* child node */
	xml = assert_parse("<test>a<child>b</child></test>", TRUE);
	assert_data(xml, "a");
	child1 = assert_child(xml, NULL, FALSE);
	child1 = assert_child(xml, "child", TRUE);
	assert_data(child1, "b");
	child1 = assert_child(xml, "shouldnotmatch", FALSE);
	assert_data(child1, NULL);
	sipe_xml_free(xml);

	xml = assert_parse("<test>a<child/></test>", TRUE);
	assert_data(xml, "a");
	child1 = assert_child(xml, "child", TRUE);
	assert_data(child1, NULL);
	child1 = assert_child(xml, "shouldnotmatch", FALSE);
	assert_data(child1, NULL);
	sipe_xml_free(xml);

	xml = assert_parse("<test>a<child>b<inner>c</inner></child></test>", TRUE);
	assert_data(xml, "a");
	child1 = assert_child(xml, "child", TRUE);
	assert_data(child1, "b");
	child1 = assert_child(child1, "inner", TRUE);
	assert_data(child1, "c");
	child1 = assert_child(xml, "child/inner", TRUE);
	assert_data(child1, "c");
	sipe_xml_free(xml);

	xml = assert_parse("<test>a<child>b<inner>c<innerinner>d</innerinner></inner></child></test>", TRUE);
	assert_data(xml, "a");
	child1 = assert_child(xml, "child", TRUE);
	assert_data(child1, "b");
	child2 = assert_child(child1, "inner/innerinner", TRUE);
	assert_data(child2, "d");
	child1 = assert_child(child1, "inner", TRUE);
	assert_data(child1, "c");
	child1 = assert_child(child1, "innerinner", TRUE);
	assert_data(child1, "d");
	child1 = assert_child(xml, "child/inner", TRUE);
	assert_data(child1, "c");
	child1 = assert_child(xml, "child/inner/innerinner", TRUE);
	assert_data(child1, "d");
	sipe_xml_free(xml);

	/* attributes */
	xml = assert_parse("<test a=\"\">a</test>", TRUE);
	assert_data(xml, "a");
	assert_attribute(xml, NULL, NULL);
	assert_attribute(xml, "a", "");
	assert_attribute(xml, "b", NULL);
	sipe_xml_free(xml);

	xml = assert_parse("<test a=\"1\" b=\"abc\">a</test>", TRUE);
	assert_data(xml, "a");
	assert_attribute(xml, "a", "1");
	assert_attribute(xml, "b", "abc");
	assert_attribute(xml, "c", NULL);
	sipe_xml_free(xml);

	/* broken XML */
	xml = assert_parse("t", FALSE);
	sipe_xml_free(xml);
	xml = assert_parse("<>", FALSE);
	sipe_xml_free(xml);
	xml = assert_parse("<></>", FALSE);
	sipe_xml_free(xml);
	xml = assert_parse("<test>", FALSE);
	sipe_xml_free(xml);

	if (allocated) {
		printf("MEMORY LEAK: %" G_GSIZE_FORMAT " still allocated\n", allocated);
		failed++;
	} else {
		printf("MEMORY LEAK CHECK OK\n");
		succeeded++;
	}

	printf("Result: %d PASSED %d FAILED\n", succeeded, failed);
	return(failed);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
