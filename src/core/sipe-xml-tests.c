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

/**
 * These are not real tests for sipe-xml.c.
 *
 * Just exercise the code a bit to see what happens :-)
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include "glib.h"
#include "sipe-xml.h"
#include "sipe-backend-debug.h"
#include "sipe-common.h"

void sipe_backend_debug(sipe_debug_level level,
			const gchar *format,
			...)
{
	va_list args;
	gchar *msg;
	va_start(args, format);
	msg = g_strdup_vprintf(format, args);
	va_end(args);

	printf("DEBUG %d: %s\n", level, msg);
	g_free(msg);
}

gboolean sipe_strequal(const gchar *a, const gchar *b)
{
	return !g_strcmp0(a, b);
}

void testfunc(const gchar *text)
{
	gsize len = text ? strlen(text) : 0;
	sipe_xml *node = sipe_xml_parse(text, len);
	printf("NODE: %p\n", node);

	if (node) {
		gchar *data = sipe_xml_get_data(node);
		if (data) printf("DATA: %s (%p)\n", data, data);
		g_free(data);

		sipe_xml *child = sipe_xml_get_child(node, "sub");
		if (child) {
			data = sipe_xml_get_data(child);
			if (data) printf("CHILD 1 DATA: %s (%p)\n", data, data);
			g_free(data);

			child = sipe_xml_get_child(child, "not");
			if (child) {
				data = sipe_xml_get_data(child);
				if (data) printf("CHILD 2 DATA: %s (%p)\n", data, data);
				g_free(data);
			}
		}

		child = sipe_xml_get_child(node, "sub/not");
		if (child) {
			data = sipe_xml_get_data(child);
			if (data) printf("CHILD 2 DATA: %s (%p)\n", data, data);
			g_free(data);
		}
	}
	sipe_xml_free(node);
}

int main(SIPE_UNUSED_PARAMETER int argc, SIPE_UNUSED_PARAMETER char **argv)
{
	testfunc(NULL);
	testfunc("");
	testfunc("<test></test>");
	testfunc("<test>a\n\nb</test>");
	testfunc("<test>a<sub>b</sub></test>");
	testfunc("<test>d1<not>f1</not><sub>e1</sub></test>");
	testfunc("<test>d2<not>f2</not><sub>e2</sub></test>");
	testfunc("<test>d3<not>f3<a>g3</a></not><sub>e3</sub></test>");
	testfunc("<test>d4<not>f4<a>g4</b></not><sub>e4</sub></test>");
	testfunc("<test/>");
	testfunc("<test><sub/></test>");
	testfunc("<test><sub><not/></sub></test>");
	testfunc("<test>d5<sub>e4<not>f4</not></sub></test>");
	return(0);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
