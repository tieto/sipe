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
#include <ctype.h>
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

gchar *gentag(void)
{
	return g_strdup_printf("%04d%04d", RANDOM32BITS, RANDOM32BITS);
}

gchar *genconfid(void)
{
	return g_strdup_printf("%04X%04X%04X%04X%04X%04X%04X%04X",
			       RANDOM32BITS, RANDOM32BITS, RANDOM32BITS,
			       RANDOM32BITS, RANDOM32BITS, RANDOM32BITS,
			       RANDOM32BITS, RANDOM32BITS);
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

int parse_cseq(const gchar *hdr)
{
	int res = -1;
	gchar **items;
	items = g_strsplit(hdr, " ", 1);
	if (items[0]) {
		res = atoi(items[0]);
	}
	g_strfreev(items);
	return res;
}

gchar *sip_uri_from_name(const gchar *name)
{
	return(g_strdup_printf("sip:%s", name));
}

gchar *sip_uri(const gchar *string)
{
	return(strstr(string, "sip:") ? g_strdup(string) : sip_uri_from_name(string));
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

//* @TODO Do we need compat with glib < 2.8 ? */
char *sipe_get_host_name(void)
{
#if GLIB_CHECK_VERSION(2,8,0)
	const gchar * hostname = g_get_host_name();
#else
	static char hostname[256];
	int ret = gethostname(hostname, sizeof(hostname));
	hostname[sizeof(hostname) - 1] = '\0';
	if (ret == -1 || hostname[0] == '\0') {
		purple_debug(PURPLE_DEBUG_MISC, "sipe", "Error when getting host name.  Using \"localhost.\"\n");
		g_strerror(errno);
		strcpy(hostname, "localhost");
	}
#endif
	/*const gchar * hostname = purple_get_host_name();*/
	return (char *)hostname;
}

gchar *
get_epid(struct sipe_account_data *sip)
{
	if (!sip->epid) {
		gchar *self_sip_uri = sip_uri_self(sip);
		sip->epid = sipe_get_epid(self_sip_uri,
					  sipe_get_host_name(),
					  purple_network_get_my_ip(-1));
		g_free(self_sip_uri);
	}
	return g_strdup(sip->epid);
}

guint
sipe_get_pub_instance(struct sipe_account_data *sip,
		      const char *publication_key)
{
	unsigned part_1;
	unsigned part_2;
	gchar *epid = get_epid(sip);
	sscanf(epid, "%08x", &part_1);
	g_free(epid);
	sscanf(publication_key, "%uh", &part_2);
	return part_1 + part_2;
}

gboolean
sipe_is_bad_alias(const char *uri,
		  const char *alias)
{
	char *uri_alias;
	gboolean result = FALSE;

	if (!uri) return FALSE;
	if (!alias) return TRUE;

	if (g_str_has_prefix(alias, "sip:") || g_str_has_prefix(alias, "sips:")) return TRUE;

	/* check if alias is just SIP URI but without 'sip:' prefix */
	uri_alias = sip_uri_from_name(alias);
	if (!g_ascii_strcasecmp(uri, uri_alias)) {
		result = TRUE;
	}
	g_free(uri_alias);

	return result;
}

char *trim(char *b)
{
	char *e = b + strlen(b);

	while (b < e && isspace((unsigned char) *b))
		++b;
	while (e > b && isspace((unsigned char) *(e - 1)))
		--e;
	*e='\0';

	return b;
}

gboolean
is_empty(const char *st)
{
	if (!st || strlen(st) == 0)
	{
		return TRUE;
	}
	/* suspecious leading or trailing staces */
	else if (isspace((unsigned char) *st) ||
		 isspace((unsigned char) *(st + strlen(st) - 1)))
	{
		/* to not modify original string */
		char *dup = g_strdup(st);
		if (strlen(trim(dup)) == 0) {
			g_free(dup);
			return TRUE;
		}
		g_free(dup);
	}
	return FALSE;
}


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
