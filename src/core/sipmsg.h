/**
 * @file sipmsg.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2005, Thomas Butter <butter@uni-mannheim.de>
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

/*
 * Interface dependencies:
 *
 * <glib.h>
 */

struct sipmsg {
	int response; /* 0 means request, otherwise response code */
	gchar *method;
	gchar *target;
	GSList *headers;
	GSList *new_headers;
	int bodylen;
	gchar *body;
	gchar *signature;
	gchar *rand;
	gchar *num;
};

struct sipendpoint {
	gchar *contact;
	gchar *epid;
};


struct sipmsg *sipmsg_parse_msg(const gchar *msg);
struct sipmsg *sipmsg_parse_header(const gchar *header);
struct sipmsg *sipmsg_copy(const struct sipmsg *other);
void sipmsg_add_header_now(struct sipmsg *msg, const gchar *name, const gchar *value);
void sipmsg_add_header(struct sipmsg *msg, const gchar *name, const gchar *value);
void sipmsg_add_header_now_pos(struct sipmsg *msg, const gchar *name, const gchar *value, int pos);
void sipmsg_strip_headers(struct sipmsg *msg, const gchar *keepers[]);
void sipmsg_merge_new_headers(struct sipmsg *msg);
void sipmsg_free(struct sipmsg *msg);
GSList *sipmsg_parse_endpoints_header(const gchar *header);
const gchar *sipmsg_find_header(const struct sipmsg *msg, const gchar *name);
const gchar *sipmsg_find_header_instance(const struct sipmsg *msg, const gchar *name, int which);
gchar *sipmsg_find_part_of_header(const char *hdr, const char * before, const char * after, const char * def);
gchar *sipmsg_find_auth_header(struct sipmsg *msg, const gchar *name);
void sipmsg_remove_header_now(struct sipmsg *msg, const gchar *name);
char *sipmsg_to_string(const struct sipmsg *msg);

/**
 * Formats message to html if not yet.
 * Either - keep as is if text/html, or escape text, or escape text and apply format string if any
 *
 * @param body in case of 'ms_text_format is Content-Type header' or NULL otherwise
 * @param ms_text_format either ms-text-format ot Content-Type header.
 *
 * Allocates memory. Must be feed when done.
 */
gchar *get_html_message(const gchar *ms_text_format, const gchar *body);

/**
 * Parses headers-like 'msgr' attribute of INVITE's 'ms_text_format' header.
 * Then retrieves value of 'X-MMS-IM-Format'.

 * 'msgr' typically looks like:
 * X-MMS-IM-Format: FN=Microsoft%20Sans%20Serif; EF=BI; CO=800000; CS=0; PF=22
 */
gchar *sipmsg_get_x_mms_im_format(gchar *msgr);

/**
 * Returns UTF-16LE/'modified base64' encoded X-MMS-IM-Format
 * based on input x_mms_im_format.
 */
gchar *sipmsg_get_msgr_string(gchar *x_mms_im_format);

/**
 * Translates X-MMS-IM format to HTML presentation.
 */
gchar *sipmsg_apply_x_mms_im_format(const char *x_mms_im_format, gchar *body);

#define sipe_parse_html            msn_import_html
/**
 * Parses the Purple message formatting (html) into the MSN format.
 *
 * @param html			The html message to format.
 * @param attributes	The returned attributes string.
 * @param message		The returned message string.
 *
 * @return The new message.
 */
void sipe_parse_html(const char *html, char **attributes, char **message);

void msn_parse_format(const char *mime, char **pre_ret, char **post_ret);
void msn_import_html(const char *html, char **attributes, char **message);
