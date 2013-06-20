/**
 * @file sipmsg.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2013 SIPE Project <http://sipe.sourceforge.net/>
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

#define SIPMSG_BODYLEN_CHUNKED -1

struct sipmsg {
	int response; /* 0 means request, otherwise response code */
	gchar *responsestr;
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
void sipmsg_strip_headers(struct sipmsg *msg, const gchar *keepers[]);
void sipmsg_merge_new_headers(struct sipmsg *msg);
void sipmsg_free(struct sipmsg *msg);

/**
 * Parses CSeq from SIP message
 *
 * @param msg (in) SIP message
 *
 * @return int type CSeq value (i.e. without method).
 */
int sipmsg_parse_cseq(struct sipmsg *msg);

GSList *sipmsg_parse_endpoints_header(const gchar *header);
/**
 * Parses sip: and tel: URI out of P-Asserted-Identity header from INVITE request.
 * You must free the values.
 *
 * Example headers:
 * P-Asserted-Identity: "Cullen Jennings" <sip:fluffy@cisco.com>
 * P-Asserted-Identity: tel:+14085264000
 * P-Asserted-Identity: "Lunch, Lucas" <sip:llucas@cisco.com>,<tel:+420123456;ext=88463>
 *
 * @param header (in) P-Asserted-Identity header contents
 * @param sip_uri (out) parsed sip: URI or NULL if missing
 * @param tel_uri (out) parsed tel: URI or NULL if missing
 */
void sipmsg_parse_p_asserted_identity(const gchar *header, gchar **sip_uri,
				      gchar **tel_uri);
const gchar *sipmsg_find_header(const struct sipmsg *msg, const gchar *name);
const gchar *sipmsg_find_header_instance(const struct sipmsg *msg, const gchar *name, int which);
gchar *sipmsg_find_part_of_header(const char *hdr, const char * before, const char * after, const char * def);
const gchar *sipmsg_find_auth_header(struct sipmsg *msg, const gchar *name);
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
 * Returns UTF-16LE/'modified base64' encoded X-MMS-IM-Format
 * based on input x_mms_im_format.
 */
gchar *sipmsg_get_msgr_string(gchar *x_mms_im_format);

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

/**
 * Extracts reason string from ms-diagnostics header of SIP message
 *
 * @param msg SIP message
 *
 * @return reason string. Must be g_free()'d after use.
 */
gchar *sipmsg_get_ms_diagnostics_reason(struct sipmsg *msg);

/**
 * Extracts reason string from ms-diagnostics-public header of SIP message
 *
 * @param msg SIP message
 *
 * @return reason string. Must be g_free()'d after use.
 */
gchar *sipmsg_get_ms_diagnostics_public_reason(struct sipmsg *msg);

/**
 * Parses Warning header of SIP message, if present.
 *
 * @param msg (in) SIP message
 * @param reason (out) parsed warning text or NULL if missing. Must be g_free()'d
 *               after use.
 *
 * @return warning code or -1 if warning header is not present in message.
 */
int sipmsg_parse_warning(struct sipmsg *msg, gchar **reason);
