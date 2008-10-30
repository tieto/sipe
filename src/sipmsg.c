/**
 * @file sipmsg.c
 *
 * gaim
 *
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
#include "sip-internal.h"
#else /* _WIN32 */
#ifdef _DLL
#define _WS2TCPIP_H_
#define _WINSOCK2API_
#define _LIBC_INTERNAL_
#endif /* _DLL */

#include "internal.h"
#endif /* _WIN32 */

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
	msg->bodylen = strtol(sipmsg_find_header(msg, "Content-Length"),NULL,10);
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
                if(!strcmp(elem->name,"Proxy-Authorization"))
                  g_string_append_printf(outstr, "%s: %s", elem->name,
			elem->value);
                else     
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
		if(strcmp(elem->name, name)==0) {
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
	GSList *tmp;
	struct siphdrelement *elem;
	tmp = msg->headers;
	while(tmp) {
		elem = tmp->data;
		if(strcmp(elem->name,name)==0) {
			return elem->value;
		}
		tmp = g_slist_next(tmp);
	}
	return NULL;
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
		purple_debug(PURPLE_DEBUG_MISC, "sipmsg", "Current header: %s\r\n", elem->value);
                if(elem && elem->name && !strcmp(elem->name,"WWW-Authenticate")) {
			if (!g_strncasecmp((gchar *)elem->value, name, name_len)) {
				purple_debug(PURPLE_DEBUG_MISC, "sipmsg", "elem->value: %s\r\n", elem->value);
                        	return elem->value;
			}
                }
		purple_debug(PURPLE_DEBUG_MISC, "sipmsg", "moving to next header\r\n");
                tmp = g_slist_next(tmp);
        }
	purple_debug(PURPLE_DEBUG_MISC, "sipmsg", "Did not found auth header %s\r\n", name);
        return NULL;
}

