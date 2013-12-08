/**
 * @file sipe-utils.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009-2013 SIPE Project <http://sipe.sourceforge.net/>
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include <glib.h>

#include "sipe-backend.h"
#include "sipe-core.h"    /* to ensure same API for backends */
#include "sipe-core-private.h"
#include "sipe-utils.h"
#include "uuid.h"

/* Generate 16 random bits */
#define RANDOM16BITS (rand() & 0xFFFF)

gchar *gencallid(void)
{
	return g_strdup_printf("%04Xg%04Xa%04Xi%04Xm%04Xt%04Xb%04Xx%04Xx",
			       RANDOM16BITS, RANDOM16BITS, RANDOM16BITS,
			       RANDOM16BITS, RANDOM16BITS, RANDOM16BITS,
			       RANDOM16BITS, RANDOM16BITS);
}

gchar *gentag(void)
{
	return g_strdup_printf("%04d%04d", RANDOM16BITS, RANDOM16BITS);
}

gchar *genconfid(void)
{
	return g_strdup_printf("%04X%04X%04X%04X%04X%04X%04X%04X",
			       RANDOM16BITS, RANDOM16BITS, RANDOM16BITS,
			       RANDOM16BITS, RANDOM16BITS, RANDOM16BITS,
			       RANDOM16BITS, RANDOM16BITS);
}

gchar *get_contact(const struct sipe_core_private *sipe_private)
{
	return g_strdup(sipe_private->contact);
}

gchar *parse_from(const gchar *hdr)
{
	gchar *from;
	const gchar *tmp, *tmp2 = hdr;

	if (!hdr) return NULL;
	SIPE_DEBUG_INFO("parsing address out of %s", hdr);
	tmp = strchr(hdr, '<');

	/* i hate the different SIP UA behaviours... */
	if (tmp) { /* sip address in <...> */
		tmp2 = tmp + 1;
		tmp = strchr(tmp2, '>');
		if (tmp) {
			from = g_strndup(tmp2, tmp - tmp2);
		} else {
			SIPE_DEBUG_INFO_NOFORMAT("found < without > in From");
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
	SIPE_DEBUG_INFO("got %s", from);
	return from;
}

gchar *sip_uri_from_name(const gchar *name)
{
	return(g_strdup_printf("sip:%s", name));
}

gchar *sip_uri(const gchar *string)
{
	return(strstr(string, "sip:") ? g_strdup(string) : sip_uri_from_name(string));
}

static gchar *escape_uri_part(const gchar *in, guint len)
{
	gchar *escaped = NULL;

	if (len) {
		gchar *s;

		/* reserve space for worst case, i.e. every character needs escaping */
		escaped = s = g_malloc(3 * len + 1);
		while (len--) {
			gchar c = *in++;

			/* only allow ASCII characters */
			if (!isascii(c)) {
				g_free(escaped);
				return(NULL);
			}

			/*
			 * RFC 3986 Appendix A
			 *
			 * authority     = [ userinfo "@" ] host [ ":" port ]
			 * userinfo      = *( unreserved / pct-encoded / sub-delims / ":" )
			 * host          = IP-literal / IPv4address / reg-name
			 * reg-name      = *( unreserved / pct-encoded / sub-delims )
			 * pct-encoded   = "%" HEXDIG HEXDIG
			 * unreserved    = ALPHA / DIGIT / "-" / "." / "_" / "~"
			 *
			 * Escape everything that isn't in "unreserved"
			 */
			if (isalnum(c) ||
			    (c == '.') ||
			    (c == '-') ||
			    (c == '_') ||
			    (c == '~')) {
				*s++ = c;
			} else {
				sprintf(s, "%%%1X%1X", c / 16, c % 16);
				s += 3;
			}
		}
		*s = '\0';
	}

	return(escaped);
}

gchar *sip_uri_if_valid(const gchar *string)
{
	/* strip possible sip: prefix */
	const gchar *uri = sipe_get_no_sip_uri(string);
	const gchar *at;
	gchar *result    = NULL;

	/* only XXX@YYY is valid */
	if (uri && ((at = strchr(uri, '@')) != NULL)) {
		gchar *userinfo = escape_uri_part(uri, at - uri);

		if (userinfo) {
			gchar *host = escape_uri_part(at + 1, strlen(at + 1));

			if (host) {
				/* name is valid for URI, convert it */
				result = g_strdup_printf("sip:%s@%s",
							 userinfo,
							 host);
				g_free(host);
			}
			g_free(userinfo);
		}
	}

	return(result);
}

const gchar *sipe_get_no_sip_uri(const gchar *sip_uri)
{
#define SIP_PREFIX "sip:"

	if (!sip_uri) return NULL;

	if (g_str_has_prefix(sip_uri, SIP_PREFIX)) {
		return(sip_uri + strlen(SIP_PREFIX));
	} else {
		return sip_uri;
	}
}

gchar *
get_epid(struct sipe_core_private *sipe_private)
{
	if (!sipe_private->epid) {
		gchar *self_sip_uri = sip_uri_self(sipe_private);
		sipe_private->epid = sipe_get_epid(self_sip_uri,
						   g_get_host_name(),
						   sipe_backend_network_ip_address(SIPE_CORE_PUBLIC));
		g_free(self_sip_uri);
	}
	return g_strdup(sipe_private->epid);
}

gchar *get_uuid(struct sipe_core_private *sipe_private)
{
	gchar *epid = get_epid(sipe_private);
	gchar *uuid = generateUUIDfromEPID(epid);
	g_free(epid);
	return(uuid);
}


guint
sipe_get_pub_instance(struct sipe_core_private *sipe_private,
		      int publication_key)
{
	unsigned res = 0;
	gchar *epid = get_epid(sipe_private);

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
		char *mail_hash = sipe_get_epid(sipe_private->email, "", "");

		sscanf(mail_hash, "%08x", &calendar_id);
		g_free(mail_hash);
		res = (calendar_id >> 4) | 0x40000000;
	} else if (publication_key == SIPE_PUB_STATE_PHONE_VOIP) {	/* First hexadecimal digit is 0x8 */
		res = (res >> 4) | 0x80000000;
	}

	return res;
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

void sipe_utils_message_debug(const gchar *type,
			      const gchar *header,
			      const gchar *body,
			      gboolean sending)
{
	if (sipe_backend_debug_enabled()) {
		GString *str         = g_string_new("");
		GTimeVal currtime;
		gchar *time_str;
		const char *marker   = sending ?
			">>>>>>>>>>" :
			"<<<<<<<<<<";
		gchar *tmp;

		g_get_current_time(&currtime);
		time_str = g_time_val_to_iso8601(&currtime);
		g_string_append_printf(str, "\nMESSAGE START %s %s - %s\n", marker, type, time_str);
		g_string_append(str, tmp = sipe_utils_str_replace(header, "\r\n", "\n"));
		g_free(tmp);
		g_string_append(str, "\n");
		if (body) {
			g_string_append(str, tmp = sipe_utils_str_replace(body, "\r\n", "\n"));
			g_free(tmp);
			g_string_append(str, "\n");
		}
		g_string_append_printf(str, "MESSAGE END %s %s - %s", marker, type, time_str);
		g_free(time_str);
		SIPE_DEBUG_INFO_NOFORMAT(str->str);
		g_string_free(str, TRUE);
	}
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

gint sipe_strcompare(gconstpointer a, gconstpointer b)
{
#if GLIB_CHECK_VERSION(2,16,0)
	return (g_strcmp0(a, b));
#else
	if (!a)
		return -(a != b);
	if (!b)
		return a != b;
	return strcmp(a, b);
#endif
}

time_t
sipe_utils_str_to_time(const gchar *timestamp)
{
	GTimeVal time;
	gboolean success = FALSE;

	/* g_time_val_from_iso8601() warns about NULL pointer */
	if (timestamp) {
		guint len;

		/* We have to make sure that the ISO8601 contains a time zone offset,
		   otherwise the time is interpreted as local time, not UTC!
		   @TODO: is there a better way to check this? */
		if (((len = strlen(timestamp)) > 0) &&
		    isdigit(timestamp[len-1])) {
			gchar *tmp = g_strdup_printf("%sZ", timestamp);
			success = g_time_val_from_iso8601(tmp, &time);
			g_free(tmp);
		} else {
			success = g_time_val_from_iso8601(timestamp, &time);
		}
	}

	if (!success) {
		SIPE_DEBUG_ERROR("sipe_utils_str_to_time: failed to parse ISO8601 string '%s'",
				 timestamp ? timestamp : "");
		time.tv_sec = 0;
	}

	return time.tv_sec;
}

gchar *
sipe_utils_time_to_str(time_t timestamp)
{
	GTimeVal time = { timestamp, 0 };
	return g_time_val_to_iso8601(&time);
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
sipe_utils_parse_lines(GSList **list, gchar **lines, gchar *delimiter)
{
	int i;
	gchar **parts;
	gchar *dummy;
	gchar *dummy2;
	gchar *tmp;

	for(i = 0; lines[i] && strlen(lines[i]) > 2; i++) {
		parts = g_strsplit(lines[i], delimiter, 2);
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
		SIPE_DEBUG_ERROR("sipe_utils_nameval_add: NULL value for %s",
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

gchar *sipe_utils_str_replace(const gchar *string,
			      const gchar *delimiter,
			      const gchar *replacement)
{
	gchar **split;
	gchar *result;

	if (!string || !delimiter || !replacement) return NULL;

	split = g_strsplit(string, delimiter, 0);
	result = g_strjoinv(replacement, split);
	g_strfreev(split);

	return result;
}

void sipe_utils_shrink_buffer(struct sipe_transport_connection *conn,
			      const gchar *unread)
{
	conn->buffer_used -= unread - conn->buffer;
	/* string terminator is not included in buffer_used */
	memmove(conn->buffer, unread, conn->buffer_used + 1);
}

gboolean sipe_utils_ip_is_private(const char *ip)
{
	return g_str_has_prefix(ip, "10.")      ||
	       g_str_has_prefix(ip, "172.16.")  ||
	       g_str_has_prefix(ip, "192.168.");
}

gchar *sipe_utils_presence_key(const gchar *uri)
{
	return g_strdup_printf("<presence><%s>", uri);
}

gchar *
sipe_utils_uri_unescape(const gchar *string)
{
	gchar *unescaped;
	gchar *tmp;

	if (!string)
		return NULL;

#if GLIB_CHECK_VERSION(2,16,0)
	unescaped = g_uri_unescape_string(string, NULL);
#else
	// based on libpurple/util.c:purple_url_decode()
	{
		GString *buf = g_string_new(NULL);
		size_t len = strlen(string);
		char hex[3];

		hex[2] = '\0';

		while (len--) {
			gchar c = *string++;

			if ((len >= 2) && (c == '%')) {
				strncpy(hex, string, 2);
				c = strtol(hex, NULL, 16);

				string += 2;
				len -= 2;
			}

			g_string_append_c(buf, c);
		}

		unescaped = g_string_free(buf, FALSE);
	}
#endif
	if (unescaped && !g_utf8_validate(unescaped, -1, (const gchar **)&tmp))
		*tmp = '\0';

	return unescaped;
}

GSList *sipe_utils_slist_insert_unique_sorted(GSList *list,
					      gpointer data,
					      GCompareFunc func,
					      GDestroyNotify destroy)
{
	if (g_slist_find_custom(list, data, func)) {
		/* duplicate */
		if (destroy)
			(*destroy)(data);
		return(list);
	} else {
		/* unique: list takes ownership of "data" */
		return(g_slist_insert_sorted(list, data, func));
	}
}

void sipe_utils_slist_free_full(GSList *list,
				GDestroyNotify free)
{
#if GLIB_CHECK_VERSION(2,28,0)
	g_slist_free_full(list, free);
#else
	GSList *entry = list;
	while (entry) {
		(*free)(entry->data);
		entry = entry->next;
	}
	g_slist_free(list);
#endif
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
