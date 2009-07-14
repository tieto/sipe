/**
 * @file sipe-utils.c
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

#include <string.h>
#include <glib.h>

#include "debug.h"
#include "xmlnode.h"

#include "sipe.h"
#include "sipe-utils.h"

/* Generate 32 random bits */
#define RANDOM32BITS (rand() & 0xFFFF)

gchar *gencallid(void)
{
	return g_strdup_printf("%04Xg%04Xa%04Xi%04Xm%04Xt%04Xb%04Xx%04Xx",
			       RANDOM32BITS, RANDOM32BITS, RANDOM32BITS,
			       RANDOM32BITS, RANDOM32BITS, RANDOM32BITS,
			       RANDOM32BITS, RANDOM32BITS);
}

gchar *gentag()
{
	return g_strdup_printf("%04d%04d", RANDOM32BITS, RANDOM32BITS);
}

gchar *get_contact(const struct sipe_account_data  *sip)
{
	return g_strdup(sip->contact);
}

gchar *parse_from(const gchar *hdr)
{
	gchar *from;
	const gchar *tmp, *tmp2 = hdr;

	if (!hdr) return NULL;
	purple_debug_info("sipe", "parsing address out of %s\n", hdr);
	tmp = strchr(hdr, '<');

	/* i hate the different SIP UA behaviours... */
	if (tmp) { /* sip address in <...> */
		tmp2 = tmp + 1;
		tmp = strchr(tmp2, '>');
		if (tmp) {
			from = g_strndup(tmp2, tmp - tmp2);
		} else {
			purple_debug_info("sipe", "found < without > in From\n");
			return NULL;
		}
	} else {
		tmp = strchr(tmp2, ';');
		if (tmp) {
			from = g_strndup(tmp2, tmp - tmp2);
		} else {
			from = g_strdup(tmp2);
		}
	}
	purple_debug_info("sipe", "got %s\n", from);
	return from;
}

xmlnode *xmlnode_get_descendant(const xmlnode *parent, ...)
{
	va_list args;
	xmlnode *node = NULL;
	const gchar *name;

	va_start(args, parent);
	while ((name = va_arg(args, const char *)) != NULL) {
		node = xmlnode_get_child(parent, name);
		if (node == NULL) return NULL;
		parent = node;
	}
	va_end(args);

	return node;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
