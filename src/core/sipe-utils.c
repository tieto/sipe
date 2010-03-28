/**
 * @file sipe-utils.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009-2010 SIPE Project <http://sipe.sourceforge.net/>
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
#include <time.h>

#include <glib.h>

#ifdef _WIN32
#include <nspapi.h>
#else
#include <unistd.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#include "sipe-backend.h"
#include "sipe-core.h"    /* to ensure same API for backends */
#include "sipe-utils.h"
#include "uuid.h"
#include "sipe.h"

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

gchar *
get_epid(struct sipe_account_data *sip)
{
	if (!sip->epid) {
		gchar *self_sip_uri = sip_uri_self(sip);
		sip->epid = sipe_get_epid(self_sip_uri,
					  g_get_host_name(),
					  sipe_backend_network_ip_address());
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
sipe_utils_str_to_time(const gchar *timestamp)
{
	GTimeVal time;
	g_time_val_from_iso8601(timestamp, &time);
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

/*
 * Calling sizeof(struct ifreq) isn't always correct on
 * Mac OS X (and maybe others).
 */
#ifdef _SIZEOF_ADDR_IFREQ
#  define HX_SIZE_OF_IFREQ(a) _SIZEOF_ADDR_IFREQ(a)
#else
#  define HX_SIZE_OF_IFREQ(a) sizeof(a)
#endif

const char * sipe_utils_get_suitable_local_ip(int fd)
{
	int source = (fd >= 0) ? fd : socket(PF_INET,SOCK_STREAM, 0);

	if (source >= 0) {
		char buffer[1024];
		static char ip[16];
		char *tmp;
		struct ifconf ifc;
		guint32 lhost = htonl(127 * 256 * 256 * 256 + 1);
		guint32 llocal = htonl((169 << 24) + (254 << 16));

		ifc.ifc_len = sizeof(buffer);
		ifc.ifc_req = (struct ifreq *)buffer;
		ioctl(source, SIOCGIFCONF, &ifc);

		if (fd < 0)
			close(source);

		tmp = buffer;
		while (tmp < buffer + ifc.ifc_len)
		{
			struct ifreq *ifr = (struct ifreq *)tmp;
			tmp += HX_SIZE_OF_IFREQ(*ifr);

			if (ifr->ifr_addr.sa_family == AF_INET)
			{
				struct sockaddr_in *sinptr = (struct sockaddr_in *)&ifr->ifr_addr;
				if (sinptr->sin_addr.s_addr != lhost
				    && (sinptr->sin_addr.s_addr & htonl(0xFFFF0000)) != llocal)
				{
					long unsigned int add = ntohl(sinptr->sin_addr.s_addr);
					g_snprintf(ip, 16, "%lu.%lu.%lu.%lu",
						   ((add >> 24) & 255),
						   ((add >> 16) & 255),
						   ((add >> 8) & 255),
						   add & 255);

					return ip;
				}
			}
		}
	}

	return "0.0.0.0";
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
