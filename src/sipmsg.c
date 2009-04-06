/**
 * @file sipmsg.c
 *
 * gaim
 *
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2005 Thomas Butter <butter@uni-mannheim.de>
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

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#else /* _WIN32 */
#ifdef _DLL
#define _WS2TCPIP_H_
#define _WINSOCK2API_
#define _LIBC_INTERNAL_
#endif /* _DLL */

#include "internal.h"
#endif /* _WIN32 */

#include <string.h>

#include "accountopt.h"
#include "blist.h"
#include "conversation.h"
#include "debug.h"
#include "notify.h"
#include "prpl.h"
#include "plugin.h"
#include "util.h"
#include "version.h"

#include "sipe.h"
#include "sipmsg.h"

struct sipmsg *sipmsg_parse_msg(const gchar *msg) {
	const char *tmp = strstr(msg, "\r\n\r\n");
	char *line;
	struct sipmsg *smsg;

	if(!tmp) return NULL;

	line = g_strndup(msg, tmp - msg);

	smsg = sipmsg_parse_header(line);
	smsg->body = g_strdup(tmp + 4);

	g_free(line);
	return smsg;
}

struct sipmsg *sipmsg_parse_header(const gchar *header) {
	struct sipmsg *msg = g_new0(struct sipmsg,1);
	gchar **lines = g_strsplit(header,"\r\n",0);
	gchar **parts;
	gchar *dummy;
	gchar *dummy2;
	gchar *tmp;
	int i=1;
	if(!lines[0]) return NULL;
	parts = g_strsplit(lines[0], " ", 3);
	if(!parts[0] || !parts[1] || !parts[2]) {
		g_strfreev(parts);
		g_strfreev(lines);
		g_free(msg);
		return NULL;
	}
	if(strstr(parts[0],"SIP")) { /* numeric response */
		msg->method = g_strdup(parts[2]);
		msg->response = strtol(parts[1],NULL,10);
	} else { /* request */
		msg->method = g_strdup(parts[0]);
		msg->target = g_strdup(parts[1]);
		msg->response = 0;
	}
	g_strfreev(parts);
	for(i=1; lines[i] && strlen(lines[i])>2; i++) {
		parts = g_strsplit(lines[i], ":", 2);
		if(!parts[0] || !parts[1]) {
			g_strfreev(parts);
			g_strfreev(lines);
			g_free(msg);
			return NULL;
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
		sipmsg_add_header(msg, parts[0], dummy2);
		g_strfreev(parts);
	}
	g_strfreev(lines);
	gchar *contentlength = sipmsg_find_header(msg, "Content-Length");
	if (contentlength) {
		msg->bodylen = strtol(contentlength,NULL,10);
	} else {
		purple_debug_fatal("sipe", "sipmsg_parse_header(): Content-Length header not found\n");
	}
	if(msg->response) {
		tmp = sipmsg_find_header(msg, "CSeq");
		if(!tmp) {
			/* SHOULD NOT HAPPEN */
			msg->method = 0;
		} else {
			parts = g_strsplit(tmp, " ", 2);
			msg->method = g_strdup(parts[1]);
			g_strfreev(parts);
		}
	}
	return msg;
}

void sipmsg_print(const struct sipmsg *msg) {
	GSList *cur;
	struct siphdrelement *elem;
	purple_debug(PURPLE_DEBUG_MISC, "sipe", "SIP MSG\n");
	purple_debug(PURPLE_DEBUG_MISC, "sipe", "response: %d\nmethod: %s\nbodylen: %d\n",msg->response,msg->method,msg->bodylen);
	if(msg->target) purple_debug(PURPLE_DEBUG_MISC, "sipe", "target: %s\n",msg->target);
	cur = msg->headers;
	while(cur) {
		elem = cur->data;
		purple_debug(PURPLE_DEBUG_MISC, "sipe", "name: %s value: %s\n",elem->name, elem->value);
		cur = g_slist_next(cur);
	}
}

char *sipmsg_to_string(const struct sipmsg *msg) {
	GSList *cur;
	GString *outstr = g_string_new("");
	struct siphdrelement *elem;

	if(msg->response)
		g_string_append_printf(outstr, "SIP/2.0 %d Unknown\r\n",
			msg->response);
	else
		g_string_append_printf(outstr, "%s %s SIP/2.0\r\n",
			msg->method, msg->target);

	cur = msg->headers;
	while(cur) {
		elem = cur->data;
                /*Todo: remove the LFCR in a good way*/
                /*if(!strcmp(elem->name,"Proxy-Authorization"))
                  g_string_append_printf(outstr, "%s: %s", elem->name,
			elem->value);
                else     */
		   g_string_append_printf(outstr, "%s: %s\r\n", elem->name,
			elem->value);
		cur = g_slist_next(cur);
	}

	g_string_append_printf(outstr, "\r\n%s", msg->bodylen ? msg->body : "");

	return g_string_free(outstr, FALSE);
}
void sipmsg_add_header(struct sipmsg *msg, const gchar *name, const gchar *value) {
	struct siphdrelement *element = g_new0(struct siphdrelement,1);
	element->name = g_strdup(name);
	element->value = g_strdup(value);
	msg->headers = g_slist_append(msg->headers, element);
}

void sipmsg_add_header_pos(struct sipmsg *msg, const gchar *name, const gchar *value, int pos) {
	struct siphdrelement *element = g_new0(struct siphdrelement,1);
	element->name = g_strdup(name);
	element->value = g_strdup(value);
	msg->headers = g_slist_insert(msg->headers, element,pos);
}

void sipmsg_free(struct sipmsg *msg) {
	struct siphdrelement *elem;
	while(msg->headers) {
		elem = msg->headers->data;
		msg->headers = g_slist_remove(msg->headers,elem);
		g_free(elem->name);
		g_free(elem->value);
		g_free(elem);
	}
	g_free(msg->method);
	g_free(msg->target);
	g_free(msg->body);
	g_free(msg);
}

void sipmsg_remove_header(struct sipmsg *msg, const gchar *name) {
	struct siphdrelement *elem;
	GSList *tmp = msg->headers;
	while(tmp) {
		elem = tmp->data;
		// OCS2005 can send the same header in either all caps or mixed case
		if (g_ascii_strcasecmp(elem->name, name)==0) {
			msg->headers = g_slist_remove(msg->headers, elem);
			g_free(elem->name);
			g_free(elem->value);
			g_free(elem);
			return;
		}
		tmp = g_slist_next(tmp);
	}
	return;
}

gchar *sipmsg_find_header(struct sipmsg *msg, const gchar *name) {
	return sipmsg_find_header_instance (msg, name, 0);
}

gchar *sipmsg_find_header_instance(struct sipmsg *msg, const gchar *name, int which) {
	GSList *tmp;
	struct siphdrelement *elem;
	tmp = msg->headers;
	int i = 0;
	while(tmp) {
		elem = tmp->data;
		// OCS2005 can send the same header in either all caps or mixed case
		if (g_ascii_strcasecmp(elem->name,name)==0) {
			if (i == which) {
				return elem->value;
			}
			i++;
		}
		tmp = g_slist_next(tmp);
	}
	return NULL;
}

gchar *
sipmsg_find_part_of_header(const char *hdr, const char * before, const char * after, const char * def)
{
	if (!hdr) {
		return NULL;
	}

	//printf("partof %s w/ %s before and %s after\n", hdr, before, after);
	const char *tmp;
	const char *tmp2;

	tmp = before == NULL ? hdr : strstr(hdr, before);
	if (!tmp) {
		//printf ("not found, returning null\n");
		return (gchar *)def;
	}

	if (before != NULL) {
		tmp += strlen(before);
		//printf ("tmp now %s\n", tmp);
	}

	if (after != NULL && (tmp2 = strstr(tmp, after))) {
		gchar * res = g_strndup(tmp, tmp2 - tmp);
		//printf("returning %s\n", res);
		return res;
	}
	gchar * res2 = g_strdup(tmp);
	//printf("returning %s\n", res2);
	return res2;
}

/*
 *  sipmsg_find_auth_header will return the particular WWW-Authenticate
 *  header specified by *name.
 *
 *  Use this function when you want to look for a specific authentication
 *  method such as NTLM or Kerberos
 */

gchar *sipmsg_find_auth_header(struct sipmsg *msg, const gchar *name) {
        GSList *tmp;
        struct siphdrelement *elem;
        tmp = msg->headers;
	int name_len = strlen(name);
        while(tmp) {
                elem = tmp->data;
		//purple_debug(PURPLE_DEBUG_MISC, "sipmsg", "Current header: %s\r\n", elem->value);
                if (elem && elem->name && !g_ascii_strcasecmp(elem->name,"WWW-Authenticate")) {
			if (!g_strncasecmp((gchar *)elem->value, name, name_len)) {
				//purple_debug(PURPLE_DEBUG_MISC, "sipmsg", "elem->value: %s\r\n", elem->value);
                        	return elem->value;
			}
                }
		//purple_debug(PURPLE_DEBUG_MISC, "sipmsg", "moving to next header\r\n");
                tmp = g_slist_next(tmp);
        }
	purple_debug(PURPLE_DEBUG_MISC, "sipmsg", "Did not found auth header %s\r\n", name);
        return NULL;
}

gchar *sipmsg_get_x_mms_im_format(gchar *msgr) {
		if (!msgr) return NULL;
		gchar *msgr2 = g_strdup(msgr);
		while (strlen(msgr2) % 4 != 0) msgr2 = strcat(msgr2, "=");
		gsize * msgr_dec64_len;
		guchar * msgr_dec64 = purple_base64_decode(msgr2, &msgr_dec64_len);
		gchar * msgr_utf8 = g_convert(msgr_dec64, msgr_dec64_len, "UTF-8", "UTF-16LE", NULL, NULL, NULL);
		g_free(msgr_dec64);
		//g_free(msgr2);
		gchar **lines = g_strsplit(msgr_utf8,"\r\n\r\n",0);
		g_free(msgr_utf8);
		//@TODO: make extraction like parsing of message headers.
		gchar **parts = g_strsplit(lines[0],"X-MMS-IM-Format:",0);
		gchar *x_mms_im_format = g_strdup(parts[1]);
		g_strfreev(parts);
		g_strfreev(lines);
		gchar * tmp = x_mms_im_format;
		if (x_mms_im_format) {
			while(*x_mms_im_format==' ' || *x_mms_im_format=='\t') x_mms_im_format++;
		}
		x_mms_im_format = g_strdup(x_mms_im_format);
		g_free(tmp);
		return x_mms_im_format;
}

gchar *sipmsg_get_msgr_string(gchar *x_mms_im_format) {
		if (!x_mms_im_format) return NULL;
		gchar *msgr_orig = g_strdup_printf("X-MMS-IM-Format: %s\r\n\r\n", x_mms_im_format);
		gsize msgr_utf16_len;
		gchar *msgr_utf16 = g_convert(msgr_orig, -1, "UTF-16LE", "UTF-8", NULL, &msgr_utf16_len, NULL);
		g_free(msgr_orig);
		gchar *msgr_enc = purple_base64_encode(msgr_utf16, msgr_utf16_len);
		g_free(msgr_utf16);
		int len = strlen(msgr_enc);
		while (msgr_enc[len - 1] == '=') len--;
		gchar *res = g_strndup(msgr_enc, len);
		g_free(msgr_enc);
		return res;
}

void msn_parse_format(const char *mime, char **pre_ret, char **post_ret);

gchar *sipmsg_apply_x_mms_im_format(x_mms_im_format, body) {
		if (!x_mms_im_format) {
			return body ? g_strdup(body) : NULL;
		}
		char *pre, *post;
		msn_parse_format(x_mms_im_format, &pre, &post);
		gchar *res = g_strdup_printf("%s%s%s", pre ? pre :  "", body ? body : "", post ? post : "");
		g_free(pre);
		g_free(post);
		return res;
}





//------------------------------------------------------------------------------------------
//TEMP solution to include it here (copy from purple's msn protocol
//How to reuse msn's util methods from sipe?
void
msn_parse_format(const char *mime, char **pre_ret, char **post_ret)
{
	char *cur;
	GString *pre  = g_string_new(NULL);
	GString *post = g_string_new(NULL);
	unsigned int colors[3];

	if (pre_ret  != NULL) *pre_ret  = NULL;
	if (post_ret != NULL) *post_ret = NULL;

	cur = strstr(mime, "FN=");

	if (cur && (*(cur = cur + 3) != ';'))
	{
		pre = g_string_append(pre, "<FONT FACE=\"");

		while (*cur && *cur != ';')
		{
			pre = g_string_append_c(pre, *cur);
			cur++;
		}

		pre = g_string_append(pre, "\">");
		post = g_string_prepend(post, "</FONT>");
	}

	cur = strstr(mime, "EF=");

	if (cur && (*(cur = cur + 3) != ';'))
	{
		while (*cur && *cur != ';')
		{
			pre = g_string_append_c(pre, '<');
			pre = g_string_append_c(pre, *cur);
			pre = g_string_append_c(pre, '>');
			post = g_string_prepend_c(post, '>');
			post = g_string_prepend_c(post, *cur);
			post = g_string_prepend_c(post, '/');
			post = g_string_prepend_c(post, '<');
			cur++;
		}
	}

	cur = strstr(mime, "CO=");

	if (cur && (*(cur = cur + 3) != ';'))
	{
		int i;

		i = sscanf(cur, "%02x%02x%02x;", &colors[0], &colors[1], &colors[2]);

		if (i > 0)
		{
			char tag[64];

			if (i == 1)
			{
				colors[1] = 0;
				colors[2] = 0;
			}
			else if (i == 2)
			{
				unsigned int temp = colors[0];

				colors[0] = colors[1];
				colors[1] = temp;
				colors[2] = 0;
			}
			else if (i == 3)
			{
				unsigned int temp = colors[2];

				colors[2] = colors[0];
				colors[0] = temp;
			}

			g_snprintf(tag, sizeof(tag),
					   "<FONT COLOR=\"#%02hhx%02hhx%02hhx\">",
					   colors[0], colors[1], colors[2]);

			pre = g_string_append(pre, tag);
			post = g_string_prepend(post, "</FONT>");
		}
	}

	cur = strstr(mime, "RL=");

	if (cur && (*(cur = cur + 3) != ';'))
	{
		if (*cur == '1')
		{
			/* RTL text was received */
			pre = g_string_append(pre, "<SPAN style=\"direction:rtl;text-align:right;\">");
			post = g_string_prepend(post, "</SPAN>");
		}
	}

	cur = g_strdup(purple_url_decode(pre->str));
	g_string_free(pre, TRUE);

	if (pre_ret != NULL)
		*pre_ret = cur;
	else
		g_free(cur);

	cur = g_strdup(purple_url_decode(post->str));
	g_string_free(post, TRUE);

	if (post_ret != NULL)
		*post_ret = cur;
	else
		g_free(cur);
}

static const char *
encode_spaces(const char *str)
{
	static char buf[BUF_LEN];
	const char *c;
	char *d;

	g_return_val_if_fail(str != NULL, NULL);

	for (c = str, d = buf; *c != '\0'; c++)
	{
		if (*c == ' ')
		{
			*d++ = '%';
			*d++ = '2';
			*d++ = '0';
		}
		else
			*d++ = *c;
	}
	*d = '\0';

	return buf;
}

void
msn_import_html(const char *html, char **attributes, char **message)
{
	int len, retcount = 0;
	const char *c;
	char *msg;
	char *fontface = NULL;
	char fonteffect[4];
	char fontcolor[7];
	char direction = '0';

	gboolean has_bold = FALSE;
	gboolean has_italic = FALSE;
	gboolean has_underline = FALSE;
	gboolean has_strikethrough = FALSE;

	g_return_if_fail(html       != NULL);
	g_return_if_fail(attributes != NULL);
	g_return_if_fail(message    != NULL);

	len = strlen(html);
	msg = g_malloc0(len + 1);

	memset(fontcolor, 0, sizeof(fontcolor));
	strcat(fontcolor, "0");
	memset(fonteffect, 0, sizeof(fonteffect));

	for (c = html; *c != '\0';)
	{
		if (*c == '<')
		{
			if (!g_ascii_strncasecmp(c + 1, "br>", 3))
			{
				msg[retcount++] = '\r';
				msg[retcount++] = '\n';
				c += 4;
			}
			else if (!g_ascii_strncasecmp(c + 1, "i>", 2))
			{
				if (!has_italic)
				{
					strcat(fonteffect, "I");
					has_italic = TRUE;
				}
				c += 3;
			}
			else if (!g_ascii_strncasecmp(c + 1, "b>", 2))
			{
				if (!has_bold)
				{
					strcat(fonteffect, "B");
					has_bold = TRUE;
				}
				c += 3;
			}
			else if (!g_ascii_strncasecmp(c + 1, "u>", 2))
			{
				if (!has_underline)
				{
					strcat(fonteffect, "U");
					has_underline = TRUE;
				}
				c += 3;
			}
			else if (!g_ascii_strncasecmp(c + 1, "s>", 2))
			{
				if (!has_strikethrough)
				{
					strcat(fonteffect, "S");
					has_strikethrough = TRUE;
				}
				c += 3;
			}
			else if (!g_ascii_strncasecmp(c + 1, "a href=\"", 8))
			{
				c += 9;

				if (!g_ascii_strncasecmp(c, "mailto:", 7))
					c += 7;

				while ((*c != '\0') && g_ascii_strncasecmp(c, "\">", 2))
					msg[retcount++] = *c++;

				if (*c != '\0')
					c += 2;

				/* ignore descriptive string */
				while ((*c != '\0') && g_ascii_strncasecmp(c, "</a>", 4))
					c++;

				if (*c != '\0')
					c += 4;
			}
			else if (!g_ascii_strncasecmp(c + 1, "span", 4))
			{
				/* Bi-directional text support using CSS properties in span tags */
				c += 5;

				while (*c != '\0' && *c != '>')
				{
					while (*c == ' ')
						c++;
					if (!g_ascii_strncasecmp(c, "dir=\"rtl\"", 9))
					{
						c += 9;
						direction = '1';
					}
					else if (!g_ascii_strncasecmp(c, "style=\"", 7))
					{
						/* Parse inline CSS attributes */
						char *attributes;
						int attr_len = 0;
						c += 7;
						while (*(c + attr_len) != '\0' && *(c + attr_len) != '"')
							attr_len++;
						if (*(c + attr_len) == '"')
						{
							char *attr_dir;
							attributes = g_strndup(c, attr_len);
							attr_dir = purple_markup_get_css_property(attributes, "direction");
							if (attr_dir && (!g_ascii_strncasecmp(attr_dir, "RTL", 3)))
								direction = '1';
							g_free(attr_dir);
							g_free(attributes);
						}

					}
					else
					{
						c++;
					}
				}
				if (*c == '>')
					c++;
			}
			else if (!g_ascii_strncasecmp(c + 1, "font", 4))
			{
				c += 5;

				while ((*c != '\0') && !g_ascii_strncasecmp(c, " ", 1))
					c++;

				if (!g_ascii_strncasecmp(c, "color=\"#", 7))
				{
					c += 8;

					fontcolor[0] = *(c + 4);
					fontcolor[1] = *(c + 5);
					fontcolor[2] = *(c + 2);
					fontcolor[3] = *(c + 3);
					fontcolor[4] = *c;
					fontcolor[5] = *(c + 1);

					c += 8;
				}
				else if (!g_ascii_strncasecmp(c, "face=\"", 6))
				{
					const char *end = NULL;
					const char *comma = NULL;
					unsigned int namelen = 0;

					c += 6;
					end = strchr(c, '\"');
					comma = strchr(c, ',');

					if (comma == NULL || comma > end)
						namelen = (unsigned int)(end - c);
					else
						namelen = (unsigned int)(comma - c);

					fontface = g_strndup(c, namelen);
					c = end + 2;
				}
				else
				{
					/* Drop all unrecognized/misparsed font tags */
					while ((*c != '\0') && g_ascii_strncasecmp(c, "\">", 2))
						c++;

					if (*c != '\0')
						c += 2;
				}
			}
			else
			{
				while ((*c != '\0') && (*c != '>'))
					c++;
				if (*c != '\0')
					c++;
			}
		}
		else if (*c == '&')
		{
			if (!g_ascii_strncasecmp(c, "&lt;", 4))
			{
				msg[retcount++] = '<';
				c += 4;
			}
			else if (!g_ascii_strncasecmp(c, "&gt;", 4))
			{
				msg[retcount++] = '>';
				c += 4;
			}
			else if (!g_ascii_strncasecmp(c, "&nbsp;", 6))
			{
				msg[retcount++] = ' ';
				c += 6;
			}
			else if (!g_ascii_strncasecmp(c, "&quot;", 6))
			{
				msg[retcount++] = '"';
				c += 6;
			}
			else if (!g_ascii_strncasecmp(c, "&amp;", 5))
			{
				msg[retcount++] = '&';
				c += 5;
			}
			else if (!g_ascii_strncasecmp(c, "&apos;", 6))
			{
				msg[retcount++] = '\'';
				c += 6;
			}
			else
				msg[retcount++] = *c++;
		}
		else
			msg[retcount++] = *c++;
	}

	if (fontface == NULL)
		fontface = g_strdup("MS Sans Serif");

	*attributes = g_strdup_printf("FN=%s; EF=%s; CO=%s; PF=0; RL=%c",
								  encode_spaces(fontface),
								  fonteffect, fontcolor, direction);
	*message = msg;

	g_free(fontface);
}
// End of TEMP

