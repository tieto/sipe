/*
 * @file sipe-sign.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-2013 SIPE Project <http://sipe.sourceforge.net/>
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

#include <string.h>

#include <glib.h>

#include "sipmsg.h"
#include "sipe-backend.h"
#include "sipe-sign.h"

static gchar * const empty_string = "";

void sipmsg_breakdown_parse(struct sipmsg_breakdown * msg, gchar * realm, gchar * target,
			    const gchar *protocol)
{
	const gchar * hdr;
	if (msg == NULL || msg->msg == NULL) {
		SIPE_DEBUG_INFO_NOFORMAT("sipmsg_breakdown_parse msg or msg->msg is NULL");
		return;
	}

	msg->rand = msg->num = msg->realm = msg->target_name =
		msg->cseq = msg->from_url = msg->from_tag = msg->to_url = msg->to_tag =
		msg->p_assertet_identity_sip_uri = msg->p_assertet_identity_tel_uri = empty_string;
	msg->call_id = msg->expires = empty_string;

	if ((hdr = sipmsg_find_header(msg->msg, "Proxy-Authorization")) ||
	    (hdr = sipmsg_find_header(msg->msg, "Proxy-Authentication-Info")) ||
	    (hdr = sipmsg_find_header(msg->msg, "Authentication-Info")) ) {
		msg->protocol = sipmsg_find_part_of_header(hdr, NULL, " ", empty_string);
		msg->rand   = sipmsg_find_part_of_header(hdr, "rand=\"", "\"", empty_string);
		msg->num    = sipmsg_find_part_of_header(hdr, "num=\"", "\"", empty_string);
		msg->realm  = sipmsg_find_part_of_header(hdr, "realm=\"", "\"", empty_string);
		msg->target_name = sipmsg_find_part_of_header(hdr, "targetname=\"", "\"", empty_string);
	} else {
		msg->protocol = g_strdup(protocol);
		msg->realm = g_strdup(realm);
		msg->target_name = g_strdup(target);
	}

	msg->call_id = sipmsg_find_header(msg->msg, "Call-ID");

	hdr = sipmsg_find_header(msg->msg, "CSeq");
	if (NULL != hdr) {
		msg->cseq = sipmsg_find_part_of_header(hdr, NULL, " ", empty_string);
	}

	hdr = sipmsg_find_header(msg->msg, "From");
	if (NULL != hdr) {
		msg->from_url = sipmsg_find_part_of_header(hdr, "<", ">", empty_string);
		msg->from_tag = sipmsg_find_part_of_header(hdr, ";tag=", ";", empty_string);
	}

	hdr = sipmsg_find_header(msg->msg, "To");
	if (NULL != hdr) {
		msg->to_url = sipmsg_find_part_of_header(hdr, "<", ">", empty_string);
		msg->to_tag = sipmsg_find_part_of_header(hdr, ";tag=", ";", empty_string);
	}

	hdr = sipmsg_find_header(msg->msg, "P-Asserted-Identity");
	if (NULL == hdr) {
		hdr = sipmsg_find_header(msg->msg, "P-Preferred-Identity");
	}
	if (NULL != hdr) {
		gchar *sip_uri = NULL;
		gchar *tel_uri = NULL;

		sipmsg_parse_p_asserted_identity(hdr, &sip_uri, &tel_uri);
		if (sip_uri)
			msg->p_assertet_identity_sip_uri = sip_uri;
		if (tel_uri)
			msg->p_assertet_identity_tel_uri = tel_uri;
	}

	msg->expires = sipmsg_find_header(msg->msg, "Expires");
}

void
sipmsg_breakdown_free(struct sipmsg_breakdown * msg)
{
	if (msg->protocol != empty_string)
		g_free(msg->protocol);
	if (msg->rand != empty_string)
		g_free(msg->rand);
	if (msg->num != empty_string)
		g_free(msg->num);
	if (msg->realm != empty_string)
		g_free(msg->realm);
	if (msg->target_name != empty_string)
		g_free(msg->target_name);

	// straight from header
	//g_free(msg->call_id);

	if (msg->cseq != empty_string)
		g_free(msg->cseq);
	if (msg->from_url != empty_string)
		g_free(msg->from_url);
	if (msg->from_tag != empty_string)
		g_free(msg->from_tag);
	if (msg->to_url != empty_string)
		g_free(msg->to_url);
	if (msg->to_tag != empty_string)
		g_free(msg->to_tag);

	if (msg->p_assertet_identity_sip_uri != empty_string)
		g_free(msg->p_assertet_identity_sip_uri);
	if (msg->p_assertet_identity_tel_uri != empty_string)
		g_free(msg->p_assertet_identity_tel_uri);

	// straight from header
	//g_free (msg->expires);
}

gchar *
sipmsg_breakdown_get_string(int version,
			    struct sipmsg_breakdown * msgbd)
{
	gchar *response_str;
	gchar *msg;
	if (msgbd->realm == empty_string || msgbd->realm == NULL) {
		SIPE_DEBUG_INFO_NOFORMAT("realm NULL, so returning NULL signature string");
		return NULL;
	}

	response_str = msgbd->msg->response != 0 ? g_strdup_printf("<%d>", msgbd->msg->response) : empty_string;
	if (version < 3) {
		msg = g_strdup_printf(
			"<%s><%s><%s><%s><%s><%s><%s><%s><%s><%s><%s>" // 1 - 11
			"<%s>%s", // 12 - 13
			msgbd->protocol, msgbd->rand, msgbd->num, msgbd->realm, msgbd->target_name, msgbd->call_id, msgbd->cseq,
			msgbd->msg->method, msgbd->from_url, msgbd->from_tag, msgbd->to_tag,
			msgbd->expires ? msgbd->expires : empty_string, response_str
		);
	} else {
		msg = g_strdup_printf(
			"<%s><%s><%s><%s><%s><%s><%s><%s><%s><%s><%s><%s><%s><%s>" // 1 - 14
			"<%s>%s", // 15 - 16
			msgbd->protocol, msgbd->rand, msgbd->num, msgbd->realm, msgbd->target_name, msgbd->call_id, msgbd->cseq,
			msgbd->msg->method, msgbd->from_url, msgbd->from_tag, msgbd->to_url, msgbd->to_tag,
			msgbd->p_assertet_identity_sip_uri, msgbd->p_assertet_identity_tel_uri,
			msgbd->expires ? msgbd->expires : empty_string, response_str
		);
	}

	if (response_str != empty_string) {
		g_free(response_str);
	}

	return msg;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
