/*
 * sipe-sign.c 
 *
 */

/* 
 * Copyright (C) 2008 Novell, Inc.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <et/com_err.h>

#include "debug.h"
#include "util.h"

#include "sipe-sign.h"

void sipmsg_breakdown_parse(struct sipmsg_breakdown * msg, gchar * realm, gchar * target)
{
	if (msg == NULL || msg->msg == NULL) {
		purple_debug(PURPLE_DEBUG_MISC, "sipmsg_breakdown_parse msg or msg->msg is NULL", "\n");
		return;
	}

	gchar * hdr;

	msg->rand = msg->num = msg->realm = msg->target_name = msg->call_id = 
		msg->cseq = msg->from_url = msg->from_tag = msg->to_tag = msg->expires = empty_string;

	if ((hdr = sipmsg_find_header(msg->msg, "Proxy-Authorization")) ||
	    (hdr = sipmsg_find_header(msg->msg, "Proxy-Authenticate")) ||
	    (hdr = sipmsg_find_header(msg->msg, "Proxy-Authentication-Info")) ||
	    (hdr = sipmsg_find_header(msg->msg, "Authentication-Info")) ) {
		msg->rand   = sipmsg_find_part_of_header(hdr, "rand=\"", "\"", empty_string);
		msg->num    = sipmsg_find_part_of_header(hdr, "num=\"", "\"", empty_string);
		msg->realm  = sipmsg_find_part_of_header(hdr, "realm=\"", "\"", empty_string);
		msg->target_name = sipmsg_find_part_of_header(hdr, "targetname=\"", "\"", empty_string);
	} else {
		msg->realm = realm;
		msg->target_name = target;
	}

	msg->call_id = sipmsg_find_header(msg->msg, "Call-ID");

	if (hdr = sipmsg_find_header(msg->msg, "CSeq")) {
		msg->cseq = sipmsg_find_part_of_header(hdr, NULL, " ", empty_string);
	}

	if (hdr = sipmsg_find_header(msg->msg, "From")) {
		msg->from_url = sipmsg_find_part_of_header(hdr, "<", ">", empty_string);
		msg->from_tag = sipmsg_find_part_of_header(hdr, ";tag=", ";", empty_string);
	}

	if (hdr = sipmsg_find_header(msg->msg, "To")) {
		msg->to_tag = sipmsg_find_part_of_header(hdr, ";tag=", ";", empty_string);
	}

	msg->expires = sipmsg_find_header(msg->msg, "Expires");
}

void
sipmsg_breakdown_free(struct sipmsg_breakdown * msg)
{
	if (msg->rand != empty_string)
		g_free(msg->rand);
	if (msg->num != empty_string)
		g_free(msg->num);
	//if (msg->realm != empty_string)
		//g_free(msg->realm);
	//if (msg->target_name != empty_string)
		//g_free(msg->target_name);

	// straight from header
	//g_free(msg->call_id);

	if (msg->cseq != empty_string)
		g_free(msg->cseq);
	if (msg->from_url != empty_string)
		g_free(msg->from_url);
	if (msg->from_tag != empty_string)
		g_free(msg->from_tag);
	if (msg->to_tag != empty_string)
		g_free(msg->to_tag);

	// straight from header
	//g_free (msg->expires);
}

gchar *
sipmsg_breakdown_get_string(struct sipmsg_breakdown * msgbd)
{
	if (msgbd->realm == empty_string || msgbd->realm == NULL) {
		purple_debug(PURPLE_DEBUG_MISC, "sipe", "realm NULL, so returning NULL signature string\n");
		return NULL;
	}

	gchar * response_str = msgbd->msg->response != 0 ? g_strdup_printf("<%d>", msgbd->msg->response) : empty_string;
	gchar * msg = g_strdup_printf(
		"<%s><%s><%s><%s><%s><%s><%s><%s><%s><%s><%s>" // 1 - 11
		"<%s>%s", // 12 - 13
		"NTLM", msgbd->rand, msgbd->num, msgbd->realm, msgbd->target_name, msgbd->call_id, msgbd->cseq,
		msgbd->msg->method, msgbd->from_url, msgbd->from_tag, msgbd->to_tag,
		msgbd->expires ? msgbd->expires : empty_string, response_str
	);

	if (response_str != empty_string) {
		g_free(response_str);
	}

	return msg;
}
