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

#if _WIN32 && !GLIB_CHECK_VERSION(2,8,0)
/* for gethostname() */
#include "libc_interface.h"
#endif

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
		if (node == NULL) break;
		parent = node;
	}
	va_end(args);

	return node;
}

gint xmlnode_get_int_attrib(xmlnode *node,
			    const char *attr,
			    gint fallback)
{
	const char *value = xmlnode_get_attrib(node, attr);
	return(value ? atoi(value) : fallback);
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
		      int publication_key)
{
	unsigned res = 0;
	gchar *epid = get_epid(sip);

	sscanf(epid, "%08x", &res);
	g_free(epid);

	if (publication_key == SIPE_PUB_DEVICE) {
		/* as is */
	} else if (publication_key == SIPE_PUB_STATE_MACHINE) {		/* First hexadecimal digit is 0x3 */
		res = (res >> 4) | 0x30000000;
	} else if (publication_key == SIPE_PUB_STATE_USER) {
		res = 0x20000000; /* fixed */
	} else if (publication_key == SIPE_PUB_STATE_CALENDAR) {	/* First hexadecimal digit is 0x4 */
		res = (res >> 4) | 0x40000000;
	} else if (publication_key == SIPE_PUB_STATE_CALENDAR_OOF) {	/* First hexadecimal digit is 0x5 */
		res = (res >> 4) | 0x50000000;
	} else if (publication_key == SIPE_PUB_CALENDAR_DATA ||
		   publication_key == SIPE_PUB_NOTE_OOF)
	{ /* First hexadecimal digit is 0x4 */
		unsigned calendar_id = 0;
		char *mail_hash = sipe_get_epid(sip->email, "", "");

		sscanf(mail_hash, "%08x", &calendar_id);
		g_free(mail_hash);
		res = (calendar_id >> 4) | 0x40000000;
	}

	return res;
}
/* an old version
guint
sipe_get_pub_instance_(struct sipe_account_data *sip,
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
*/
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
	if (sipe_strcase_equal(uri, uri_alias)) {
		result = TRUE;
	}
	g_free(uri_alias);

	return result;
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
		if (strlen(g_strstrip(dup)) == 0) {
			g_free(dup);
			return TRUE;
		}
		g_free(dup);
	}
	return FALSE;
}

/** Returns newly allocated string. Must be g_free()'d */
char *
replace(const char *st,
	const char *search,
	const char *replace)
{
	char **tmp;
	char *res;

	if (!st) return NULL;

	res = g_strjoinv(replace, tmp = g_strsplit(st, search, -1));
	g_strfreev(tmp);
	return res;
}

char *
fix_newlines(const char *st)
{
	return replace(st, "\r\n", "\n");
}

gboolean
sipe_strequal(const gchar *left, const gchar *right)
{
#if GLIB_CHECK_VERSION(2,16,0)
	return (g_strcmp0(left, right) == 0);
#else
	return ((left == NULL && right == NULL) ||
	        (left != NULL && right != NULL && strcmp(left, right) == 0));
#endif
}

gboolean
sipe_strcase_equal(const gchar *left, const gchar *right)
{
	return ((left == NULL && right == NULL) ||
	        (left != NULL && right != NULL && g_ascii_strcasecmp(left, right) == 0));
}

time_t
sipe_utils_str_to_time(const char *timestamp)
{
	return purple_str_to_time(timestamp, TRUE, NULL, NULL, NULL);
}

char *
sipe_utils_time_to_str(time_t timestamp)
{
#define SIPE_XML_DATE_PATTERN	"%Y-%m-%dT%H:%M:%SZ"
	return g_strdup(purple_utf8_strftime(SIPE_XML_DATE_PATTERN, gmtime(&timestamp)));
}

size_t
hex_str_to_buff(const char *hex_str, guint8 **buff)
{
	char two_digits[3];
	size_t length;
	size_t i;

	if (!buff) return 0;
	if (!hex_str) return 0;

	length = strlen(hex_str)/2;
	*buff = (unsigned char *)g_malloc(length);
	for (i = 0; i < length; i++) {
		two_digits[0] = hex_str[i * 2];
		two_digits[1] = hex_str[i * 2 + 1];
		two_digits[2] = '\0';
		(*buff)[i] = (unsigned char)strtoul(two_digits, NULL, 16);
	}

	return length;
}

char *
buff_to_hex_str(const guint8 *buff, const size_t buff_len)
{
	char *res;
	size_t i, j;

	if (!buff) return NULL;

	res = g_malloc(buff_len * 2 + 1);
	for (i = 0, j = 0; i < buff_len; i++, j+=2) {
		sprintf(&res[j], "%02X", buff[i]);
	}
	res[j] = '\0';
	return res;
}

gboolean
sipe_utils_parse_lines(GSList **list, gchar **lines)
{
	int i;
	gchar **parts;
	gchar *dummy;
	gchar *dummy2;
	gchar *tmp;

	for(i = 0; lines[i] && strlen(lines[i]) > 2; i++) {
		parts = g_strsplit(lines[i], ":", 2);
		if(!parts[0] || !parts[1]) {
			g_strfreev(parts);
			return FALSE;
		}
		dummy = parts[1];
		dummy2 = 0;
		while(*dummy==' ' || *dummy=='\t') dummy++;
		dummy2 = g_strdup(dummy);
		while(lines[i+1] && (lines[i+1][0]==' ' || lines[i+1][0]=='\t')) {
			i++;
			dummy = lines[i];
			while(*dummy==' ' || *dummy=='\t') dummy++;
			tmp = g_strdup_printf("%s %s",dummy2, dummy);
			g_free(dummy2);
			dummy2 = tmp;
		}
		*list = sipe_utils_nameval_add(*list, parts[0], dummy2);
		g_free(dummy2);
		g_strfreev(parts);
	}

	return TRUE;
}

GSList*
sipe_utils_nameval_add(GSList* list, const gchar *name, const gchar *value)
{
	struct sipnameval *element = g_new0(struct sipnameval,1);

	/* SANITY CHECK: the calling code must be fixed if this happens! */
	if (!value) {
		purple_debug(PURPLE_DEBUG_ERROR, "sipe", "sipe_utils_nameval_add: NULL value for %s\n",
			     name);
		value = "";
	}

	element->name = g_strdup(name);
	element->value = g_strdup(value);
	return g_slist_append(list, element);
}

void
sipe_utils_nameval_free(GSList *list) {
	struct sipnameval *elem;
	while(list) {
		elem = list->data;
		list = g_slist_remove(list,elem);
		g_free(elem->name);
		g_free(elem->value);
		g_free(elem);
	}
}

const gchar *
sipe_utils_nameval_find(const GSList *list, const gchar *name)
{
	return sipe_utils_nameval_find_instance (list, name, 0);
}

const gchar *
sipe_utils_nameval_find_instance(const GSList *list, const gchar *name, int which)
{
	const GSList *tmp;
	struct sipnameval *elem;
	int i = 0;
	tmp = list;
	while(tmp) {
		elem = tmp->data;
		// OCS2005 can send the same header in either all caps or mixed case
		if (sipe_strcase_equal(elem->name, name)) {
			if (i == which) {
				return elem->value;
			}
			i++;
		}
		tmp = g_slist_next(tmp);
	}
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
