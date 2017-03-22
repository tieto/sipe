/**
 * @file sipmsg.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2014 SIPE Project <http://sipe.sourceforge.net/>
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <glib.h>

#include "sipmsg.h"
#include "sipe-backend.h"
#include "sipe-mime.h"
#include "sipe-utils.h"

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
	const gchar *contentlength;
	if(!lines[0]) {
		g_strfreev(lines);
		g_free(msg);
		return NULL;
	}
	parts = g_strsplit(lines[0], " ", 3);
	if(!parts[0] || !parts[1] || !parts[2]) {
		g_strfreev(parts);
		g_strfreev(lines);
		g_free(msg);
		return NULL;
	}
	if(strstr(parts[0],"SIP") || strstr(parts[0],"HTTP")) { /* numeric response */
		msg->responsestr = g_strdup(parts[2]);
		msg->response = strtol(parts[1],NULL,10);
	} else { /* request */
		msg->method = g_strdup(parts[0]);
		msg->target = g_strdup(parts[1]);
		msg->response = 0;
	}
	g_strfreev(parts);
	if (sipe_utils_parse_lines(&msg->headers, lines + 1, ":") == FALSE) {
		g_strfreev(lines);
		sipmsg_free(msg);
		return NULL;
	}
	g_strfreev(lines);
	contentlength = sipmsg_find_header(msg, "Content-Length");
	if (contentlength) {
		msg->bodylen = strtol(contentlength,NULL,10);
	} else {
		const gchar *tmp = sipmsg_find_header(msg, "Transfer-Encoding");
		if (tmp && sipe_strcase_equal(tmp, "chunked")) {
			msg->bodylen = SIPMSG_BODYLEN_CHUNKED;
		} else {
			tmp = sipmsg_find_header(msg, "Content-Type");
			if (tmp) {
				/*
				 * This is a fatal error situation: the message
				 * is corrupted and we can't proceed. Set the
				 * response code to a special value so that the
				 * caller can abort correctly.
				 */
				SIPE_DEBUG_ERROR_NOFORMAT("sipmsg_parse_header: Content-Length header not found. Aborting!");
				msg->response = SIPMSG_RESPONSE_FATAL_ERROR;
				return(msg);
			} else {
				msg->bodylen = 0;
			}
		}
	}
	if(msg->response) {
		const gchar *tmp;
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

struct sipmsg *sipmsg_copy(const struct sipmsg *other) {
	struct sipmsg *msg = g_new0(struct sipmsg, 1);
	GSList *list;

	msg->response		= other->response;
	msg->responsestr	= g_strdup(other->responsestr);
	msg->method		= g_strdup(other->method);
	msg->target		= g_strdup(other->target);

	list = other->headers;
	while(list) {
		struct sipnameval *elem = list->data;
		sipmsg_add_header_now(msg, elem->name, elem->value);
		list = list->next;
	}

	list = other->new_headers;
	while(list) {
		struct sipnameval *elem = list->data;
		sipmsg_add_header(msg, elem->name, elem->value);
		list = list->next;
	}

	msg->bodylen	= other->bodylen;
	msg->body	= g_strdup(other->body);
	msg->signature	= g_strdup(other->signature);
	msg->rand	= g_strdup(other->rand);
	msg->num	= g_strdup(other->num);

	return msg;
}

char *sipmsg_to_string(const struct sipmsg *msg) {
	GSList *cur;
	GString *outstr = g_string_new("");
	struct sipnameval *elem;

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
                /*if(sipe_strequal(elem->name,"Proxy-Authorization"))
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

/**
 * Adds header to current message headers
 */
void sipmsg_add_header_now(struct sipmsg *msg, const gchar *name, const gchar *value) {
	struct sipnameval *element = g_new0(struct sipnameval,1);

	/* SANITY CHECK: the calling code must be fixed if this happens! */
	if (!value) {
		SIPE_DEBUG_ERROR("sipmsg_add_header_now: NULL value for %s",
				 name);
		value = "";
	}

	element->name = g_strdup(name);
	element->value = g_strdup(value);
	msg->headers = g_slist_append(msg->headers, element);
}

/**
 * Adds header to separate storage for future merge
 */
void sipmsg_add_header(struct sipmsg *msg, const gchar *name, const gchar *value) {
	struct sipnameval *element = g_new0(struct sipnameval,1);

	/* SANITY CHECK: the calling code must be fixed if this happens! */
	if (!value) {
		SIPE_DEBUG_ERROR("sipmsg_add_header: NULL value for %s", name);
		value = "";
	}

	element->name = g_strdup(name);
	element->value = g_strdup(value);
	msg->new_headers = g_slist_append(msg->new_headers, element);
}

/**
 * Removes header if it's not in keepers array
 */
void sipmsg_strip_headers(struct sipmsg *msg, const gchar *keepers[]) {
	GSList *entry;
	struct sipnameval *elem;

	entry = msg->headers;
	while(entry) {
		int i = 0;
		gboolean keeper = FALSE;

		elem = entry->data;
		while (keepers[i]) {
			if (!g_ascii_strcasecmp(elem->name, keepers[i])) {
				keeper = TRUE;
				break;
			}
			i++;
		}

		if (!keeper) {
			GSList *to_delete = entry;
			SIPE_DEBUG_INFO("sipmsg_strip_headers: removing %s", elem->name);
			entry = g_slist_next(entry);
			msg->headers = g_slist_delete_link(msg->headers, to_delete);
			g_free(elem->name);
			g_free(elem->value);
			g_free(elem);
		} else {
			entry = g_slist_next(entry);
		}
	}
}

/**
 * Merges newly added headers to message
 */
void sipmsg_merge_new_headers(struct sipmsg *msg) {
	while(msg->new_headers) {
		msg->headers = g_slist_append(msg->headers, msg->new_headers->data);
		msg->new_headers = g_slist_remove(msg->new_headers, msg->new_headers->data);
	}
}

void sipmsg_free(struct sipmsg *msg) {
	if (msg) {
		sipe_utils_nameval_free(msg->headers);
		sipe_utils_nameval_free(msg->new_headers);
		g_free(msg->signature);
		g_free(msg->rand);
		g_free(msg->num);
		g_free(msg->responsestr);
		g_free(msg->method);
		g_free(msg->target);
		g_free(msg->body);
		g_free(msg);
	}
}

void sipmsg_remove_header_now(struct sipmsg *msg, const gchar *name) {
	struct sipnameval *elem;
	GSList *tmp = msg->headers;
	while(tmp) {
		elem = tmp->data;
		// OCS2005 can send the same header in either all caps or mixed case
		if (sipe_strcase_equal(elem->name, name)) {
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

const gchar *sipmsg_find_header(const struct sipmsg *msg, const gchar *name) {
	return sipe_utils_nameval_find_instance (msg->headers, name, 0);
}

const gchar *sipmsg_find_header_instance(const struct sipmsg *msg, const gchar *name, int which) {
	return sipe_utils_nameval_find_instance(msg->headers, name, which);
}

gchar *sipmsg_find_part_of_header(const char *hdr, const char * before, const char * after, const char * def) {
	const char *tmp;
	const char *tmp2;
	gchar *res2;
	if (!hdr) {
		return NULL;
	}

	//printf("partof %s w/ %s before and %s after\n", hdr, before, after);

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
	res2 = g_strdup(tmp);
	//printf("returning %s\n", res2);
	return res2;
}

int sipmsg_parse_cseq(struct sipmsg *msg)
{
	int res = -1;
	gchar **items;
	items = g_strsplit(sipmsg_find_header(msg, "CSeq"), " ", 1);
	if (items[0]) {
		res = atoi(items[0]);
	}
	g_strfreev(items);
	return res;
}

/**
 * Parse EndPoints header from INVITE request
 * Returns a list of end points: contact URI plus optional epid.
 * You must free the values and the list.
 *
 * Example headers:
 * EndPoints: "alice alisson" <sip:alice@atlanta.local>, <sip:bob@atlanta.local>;epid=ebca82d94d, <sip:carol@atlanta.local>
 * EndPoints: "alice, alisson" <sip:alice@atlanta.local>, <sip:bob@atlanta.local>
 * EndPoints: "alice alisson" <sip:alice@atlanta.local>, "Super, Man" <sip:super@atlanta.local>
 *
 * @param header (in) EndPoints header contents
 *
 * @return GSList with struct sipendpoint as elements
 */
GSList *sipmsg_parse_endpoints_header(const gchar *header)
{
	GSList *list = NULL;
	gchar **parts = g_strsplit(header, ",", 0);
	gchar *part;
	int i;

	for (i = 0; (part = parts[i]) != NULL; i++) {
		/* Does the part contain a URI? */
		gchar *contact = sipmsg_find_part_of_header(part, "<", ">", NULL);
		if (contact) {
			struct sipendpoint *end_point = g_new(struct sipendpoint, 1);
			end_point->contact = contact;
			end_point->epid = sipmsg_find_part_of_header(part, "epid=", NULL, NULL);
			list = g_slist_append(list, end_point);
		}
	}
	g_strfreev(parts);

	return(list);
}

void sipmsg_parse_p_asserted_identity(const gchar *header, gchar **sip_uri,
				      gchar **tel_uri) {
	gchar **parts, **p;

	*sip_uri = NULL;
	*tel_uri = NULL;

	if (g_ascii_strncasecmp(header, "tel:", 4) == 0) {
		*tel_uri = g_strdup(header);
		return;
	}

	parts = g_strsplit(header, ",", 0);

	for (p = parts; *p; p++) {
		gchar *uri = sipmsg_find_part_of_header(*p, "<", ">", NULL);
		if (!uri)
			continue;

		if (g_ascii_strncasecmp(uri, "sip:", 4) == 0) {
			if (*sip_uri) {
				SIPE_DEBUG_WARNING_NOFORMAT("More than one "
					"sip: URI found in P-Asserted-Identity!");
			} else {
				*sip_uri = uri;
				uri = NULL;
			}
		} else if (g_ascii_strncasecmp(uri, "tel:", 4) == 0){
			if (*tel_uri) {
				SIPE_DEBUG_WARNING_NOFORMAT("More than one "
					"tel: URI found in P-Asserted-Identity!");
			} else {
				*tel_uri = uri;
				uri = NULL;
			}
		}

		g_free(uri);
	}

	g_strfreev(parts);
}

/*
 *  sipmsg_find_auth_header will return the particular WWW-Authenticate
 *  header specified by *name.
 *
 *  Use this function when you want to look for a specific authentication
 *  method such as NTLM or Kerberos
 */

const gchar *sipmsg_find_auth_header(struct sipmsg *msg, const gchar *name) {
	GSList *tmp;
	struct sipnameval *elem;
	int name_len;

	if (!name) {
		SIPE_DEBUG_INFO_NOFORMAT("sipmsg_find_auth_header: no authentication scheme specified");
		return NULL;
	}

	name_len = strlen(name);
	tmp = msg->headers;
	while(tmp) {
		elem = tmp->data;
		/* SIPE_DEBUG_INFO("Current header: %s", elem->value); */
		if (elem && elem->name &&
		    (sipe_strcase_equal(elem->name,"WWW-Authenticate") ||
		     sipe_strcase_equal(elem->name,"Authentication-Info")) ) {
			if (!g_ascii_strncasecmp((gchar *)elem->value, name, name_len)) {
				/* SIPE_DEBUG_INFO("elem->value: %s", elem->value); */
				return elem->value;
			}
		}
		/* SIPE_DEBUG_INFO_NOFORMAT("moving to next header"); */
		tmp = g_slist_next(tmp);
	}
	SIPE_DEBUG_INFO("sipmsg_find_auth_header: '%s' not found", name);
	return NULL;
}

/**
 * Parses headers-like 'msgr' attribute of INVITE's 'ms_text_format' header.
 * Then retrieves value of 'X-MMS-IM-Format'.

 * 'msgr' typically looks like:
 * X-MMS-IM-Format: FN=Microsoft%20Sans%20Serif; EF=BI; CO=800000; CS=0; PF=22
 */
static gchar *sipmsg_get_x_mms_im_format(gchar *msgr) {
	gchar *msgr2;
	gsize msgr_dec64_len;
	guchar *msgr_dec64;
	gchar *msgr_utf8;
	gchar **lines;
	gchar **parts;
	gchar *x_mms_im_format;
	gchar *tmp;

	if (!msgr) return NULL;
	msgr2 = g_strdup(msgr);
	while (strlen(msgr2) % 4 != 0) {
		gchar *tmp_msgr2 = msgr2;
		msgr2 = g_strdup_printf("%s=", msgr2);
		g_free(tmp_msgr2);
	}
	msgr_dec64 = g_base64_decode(msgr2, &msgr_dec64_len);
	msgr_utf8 = g_convert((gchar *) msgr_dec64, msgr_dec64_len, "UTF-8", "UTF-16LE", NULL, NULL, NULL);
	g_free(msgr_dec64);
	g_free(msgr2);
	lines = g_strsplit(msgr_utf8,"\r\n\r\n",0);
	g_free(msgr_utf8);
	//@TODO: make extraction like parsing of message headers.
	parts = g_strsplit(lines[0],"X-MMS-IM-Format:",0);
	x_mms_im_format = g_strdup(parts[1]);
	g_strfreev(parts);
	g_strfreev(lines);
	tmp = x_mms_im_format;
	if (x_mms_im_format) {
		while(*x_mms_im_format==' ' || *x_mms_im_format=='\t') x_mms_im_format++;
	}
	x_mms_im_format = g_strdup(x_mms_im_format);
	g_free(tmp);
	return x_mms_im_format;
}

gchar *sipmsg_get_msgr_string(gchar *x_mms_im_format) {
	gchar *msgr_orig;
	gsize msgr_utf16_len;
	gchar *msgr_utf16;
	gchar *msgr_enc;
	gchar *res;
	int len;

	if (!x_mms_im_format) return NULL;
	msgr_orig = g_strdup_printf("X-MMS-IM-Format: %s\r\n\r\n", x_mms_im_format);
	msgr_utf16 = g_convert(msgr_orig, -1, "UTF-16LE", "UTF-8", NULL, &msgr_utf16_len, NULL);
	g_free(msgr_orig);
	msgr_enc = g_base64_encode((guchar *) msgr_utf16, msgr_utf16_len);
	g_free(msgr_utf16);
	len = strlen(msgr_enc);
	while (msgr_enc[len - 1] == '=') len--;
	res = g_strndup(msgr_enc, len);
	g_free(msgr_enc);
	return res;
}

static void msn_parse_format(const char *mime, char **pre_ret, char **post_ret);

/**
 * Translates X-MMS-IM format to HTML presentation.
 */
static gchar *sipmsg_apply_x_mms_im_format(const char *x_mms_im_format, gchar *body) {
	char *pre, *post;
	gchar *res;

	if (!x_mms_im_format) {
		return body ? g_strdup(body) : NULL;
	}
	msn_parse_format(x_mms_im_format, &pre, &post);
	res = g_strdup_printf("%s%s%s", pre ? pre :  "", body ? body : "", post ? post : "");
	g_free(pre);
	g_free(post);
	return res;
}

struct html_message_data {
	gchar *ms_text_format;
	gchar *body;
	gboolean preferred;
};

static void get_html_message_mime_cb(gpointer user_data,
				     const GSList *fields,
				     const gchar *body,
				     gsize length)
{
	const gchar *type = sipe_utils_nameval_find(fields, "Content-Type");
	struct html_message_data *data = user_data;

	if (!data->preferred) {
		gboolean copy = FALSE;

		/* preferred format */
		if (g_str_has_prefix(type, "text/html")) {
			copy = TRUE;
			data->preferred = TRUE;

		/* fallback format */
		} else if (g_str_has_prefix(type, "text/plain")) {
			copy = TRUE;
		}

		if (copy) {
			g_free(data->ms_text_format);
			g_free(data->body);
			data->ms_text_format = g_strdup(type);
			data->body = g_strndup(body, length);
		}
	}
}

/* ms-text-format: text/plain; charset=UTF-8;msgr=WAAtAE0...DIADQAKAA0ACgA;ms-body=SGk= */
gchar *get_html_message(const gchar *ms_text_format_in, const gchar *body_in)
{
	gchar *msgr;
	gchar *res;
	gchar *ms_text_format = NULL;
	gchar *body = NULL;

	if (g_str_has_prefix(ms_text_format_in, "multipart/related") ||
	    g_str_has_prefix(ms_text_format_in, "multipart/alternative")) {
		struct html_message_data data = { NULL, NULL, FALSE };

		sipe_mime_parts_foreach(ms_text_format_in, body_in,
					get_html_message_mime_cb, &data);

		ms_text_format = data.ms_text_format;
		body = data.body;

	} else {
		ms_text_format = g_strdup(ms_text_format_in);
		body = g_strdup(body_in);
	}

	if (body) {
		res = body;
	} else {
		gchar *tmp = sipmsg_find_part_of_header(ms_text_format, "ms-body=", NULL, NULL);
		gsize len;
		if (!tmp) {
			g_free(ms_text_format);
			return NULL;
		}
		res = (gchar *) g_base64_decode(tmp, &len);
		g_free(tmp);
		if (!res) {
			g_free(ms_text_format);
			return NULL;
		}
	}

	if (g_str_has_prefix(ms_text_format, "text/html")) {
		/*
		 * HTML uses tags for formatting, not line breaks. But
		 * clients still might render them, so we need to remove
		 * them to avoid incorrect text rendering.
		 */
		gchar *d = res;
		const gchar *s = res;
		gchar c;

		/* No ANSI C nor glib function seems to exist for this :-( */
		while ((c = *s++))
			if ((c != '\n') && (c != '\r'))
				*d++ = c;
		*d = c;

	} else {
		char *tmp = res;
		res = g_markup_escape_text(res, -1); // as this is not html
		g_free(tmp);
	}

	msgr = sipmsg_find_part_of_header(ms_text_format, "msgr=", ";", NULL);
	if (msgr) {
		gchar *x_mms_im_format = sipmsg_get_x_mms_im_format(msgr);
		gchar *tmp = res;
		g_free(msgr);
		res = sipmsg_apply_x_mms_im_format(x_mms_im_format, res);
		g_free(tmp);
		g_free(x_mms_im_format);
	}

	g_free(ms_text_format);

	return res;
}

static gchar *
get_reason(struct sipmsg *msg, const gchar *header)
{
	const gchar *diagnostics = sipmsg_find_header(msg, header);
	if (diagnostics)
		return sipmsg_find_part_of_header(diagnostics, "reason=\"", "\"", NULL);

	return NULL;
}

gchar *
sipmsg_get_ms_diagnostics_reason(struct sipmsg *msg)
{
	return get_reason(msg, "ms-diagnostics");
}

gchar *
sipmsg_get_ms_diagnostics_public_reason(struct sipmsg *msg)
{
	return get_reason(msg, "ms-diagnostics-public");
}

int
sipmsg_parse_warning(struct sipmsg *msg, gchar **reason)
{
	/*
	 * Example header:
	 * Warning: 310 lcs.microsoft.com "You are currently not using the recommended version of the client"
	 */
	const gchar *hdr = sipmsg_find_header(msg, "Warning");
	int code = -1;

	if (reason)
		*reason = NULL;

	if (hdr) {
		gchar **parts = g_strsplit(hdr, " ", 3);

		if (parts[0]) {
			code = atoi(parts[0]);

			if (reason && parts[1] && parts[2]) {
				size_t len = strlen(parts[2]);
				if (len > 2 && parts[2][0] == '"' && parts[2][len - 1] == '"')
					*reason = g_strndup(parts[2] + 1, len - 2);
			}
		}

		g_strfreev(parts);
	}

	return code;
}



//------------------------------------------------------------------------------------------
//TEMP solution to include it here (copy from purple's msn protocol
//How to reuse msn's util methods from sipe?

/* from internal.h */
#define MSG_LEN 2048
#define BUF_LEN MSG_LEN

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

			/* hh is undefined in mingw's gcc 4.4
			 *  https://sourceforge.net/tracker/index.php?func=detail&aid=2818436&group_id=2435&atid=102435
			 */
			g_snprintf(tag, sizeof(tag),
					   "<FONT COLOR=\"#%02x%02x%02x\">",
					   (unsigned char)colors[0], (unsigned char)colors[1], (unsigned char)colors[2]);

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

	cur = sipe_utils_uri_unescape(pre->str);
	g_string_free(pre, TRUE);

	if (pre_ret != NULL)
		*pre_ret = cur;
	else
		g_free(cur);

	cur = sipe_utils_uri_unescape(post->str);
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
sipe_parse_html(const char *html, char **attributes, char **message)
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

#define _HTML_UNESCAPE \
	if (!g_ascii_strncasecmp(c, "&lt;", 4)) { \
		msg[retcount++] = '<'; \
		c += 4; \
	} else if (!g_ascii_strncasecmp(c, "&gt;", 4)) { \
		msg[retcount++] = '>'; \
		c += 4; \
	} else if (!g_ascii_strncasecmp(c, "&nbsp;", 6)) { \
		msg[retcount++] = ' '; \
		c += 6; \
	} else if (!g_ascii_strncasecmp(c, "&quot;", 6)) { \
		msg[retcount++] = '"'; \
		c += 6; \
	} else if (!g_ascii_strncasecmp(c, "&amp;", 5)) { \
		msg[retcount++] = '&'; \
		c += 5; \
	} else if (!g_ascii_strncasecmp(c, "&apos;", 6)) { \
		msg[retcount++] = '\''; \
		c += 6; \
	} else { \
		msg[retcount++] = *c++; \
	}

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
			else if (!g_ascii_strncasecmp(c + 1, "div>", 4))
			{
				msg[retcount++] = '\r';
				msg[retcount++] = '\n';
				c += 5;
				if (!g_ascii_strncasecmp(c, "<br></div>", 10)) {
					/* This is an empty paragraph; replace it with
					 * one line break. */
					c += 10;
				}
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
					if (*c == '&') {
						_HTML_UNESCAPE;
					} else
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
						int attr_len = 0;
						c += 7;
						while (*(c + attr_len) != '\0' && *(c + attr_len) != '"')
							attr_len++;
						if (*(c + attr_len) == '"')
						{
							char *css_attributes;
							char *attr_dir;
							css_attributes = g_strndup(c, attr_len);
							attr_dir = sipe_backend_markup_css_property(css_attributes, "direction");
							g_free(css_attributes);
							if (attr_dir && (!g_ascii_strncasecmp(attr_dir, "RTL", 3)))
								direction = '1';
							g_free(attr_dir);
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

					g_free(fontface);
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
			_HTML_UNESCAPE;
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

#undef _HTML_UNESCAPE
}
// End of TEMP

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
