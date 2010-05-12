/**
 * @file sipe-media.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 Jakub Adam <jakub.adam@tieto.com>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include <glib.h>

#include "sipe-common.h"
#include "sipmsg.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-dialog.h"
#include "sipe-media.h"
#include "sipe-session.h"
#include "sipe-utils.h"
#include "sipe.h"

struct sipe_media_call_private {
	struct sipe_media_call public;

	/* private part starts here */
	struct sipe_core_private *sipe_private;
	struct sip_session *session;
	struct sip_dialog *dialog;

	gchar				*remote_ip;
	guint16				remote_port;

	GSList				*sdp_attrs;
	struct sipmsg			*invitation;
	GList				*remote_candidates;
	gboolean			legacy_mode;

	unsigned			invite_cnt;
};
#define SIPE_MEDIA_CALL         ((struct sipe_media_call *) call_private)
#define SIPE_MEDIA_CALL_PRIVATE ((struct sipe_media_call_private *) call)

gchar *
sipe_media_get_callid(struct sipe_media_call_private *call)
{
	return call->dialog->callid;
}

static void sipe_media_codec_list_free(GList *codecs)
{
	for (; codecs; codecs = g_list_delete_link(codecs, codecs))
		sipe_backend_codec_free(codecs->data);
}

static void sipe_media_candidate_list_free(GList *candidates)
{
	for (; candidates; candidates = g_list_delete_link(candidates, candidates))
		sipe_backend_candidate_free(candidates->data);
}

static void
sipe_media_call_free(struct sipe_media_call_private *call_private)
{
	if (call_private) {
		sipe_utils_nameval_free(call_private->sdp_attrs);
		if (call_private->invitation)
			sipmsg_free(call_private->invitation);
		sipe_media_codec_list_free(call_private->public.remote_codecs);
		sipe_media_candidate_list_free(call_private->remote_candidates);
		g_free(call_private);
	}
}

static GList *
sipe_media_parse_codecs(GSList *sdp_attrs)
{
	int			i = 0;
	const gchar	*attr;
	GList		*codecs	= NULL;

	while ((attr = sipe_utils_nameval_find_instance(sdp_attrs, "rtpmap", i++))) {
		gchar	**tokens	= g_strsplit_set(attr, " /", 3);

		int		id			= atoi(tokens[0]);
		gchar	*name		= tokens[1];
		int		clock_rate	= atoi(tokens[2]);
		SipeMediaType type	= SIPE_MEDIA_AUDIO;

		struct sipe_backend_codec *codec = sipe_backend_codec_new(id, name, clock_rate, type);

		// TODO: more secure and effective implementation
		int j = 0;
		const gchar* params;
		while((params = sipe_utils_nameval_find_instance(sdp_attrs, "fmtp", j++))) {
			gchar **tokens = g_strsplit_set(params, " ", 0);
			gchar **next = tokens + 1;

			if (atoi(tokens[0]) == id) {
				while (*next) {
					gchar name[50];
					gchar value[50];

					if (sscanf(*next, "%[a-zA-Z0-9]=%s", name, value) == 2)
						sipe_backend_codec_add_optional_parameter(codec, name, value);

					++next;
				}
			}

			g_strfreev(tokens);
		}

		codecs = g_list_append(codecs, codec);
		g_strfreev(tokens);
	}

	return codecs;
}

static gint
codec_name_compare(struct sipe_backend_codec *codec1, struct sipe_backend_codec *codec2)
{
	gchar *name1 = sipe_backend_codec_get_name(codec1);
	gchar *name2 = sipe_backend_codec_get_name(codec2);

	gint result = g_strcmp0(name1, name2);

	g_free(name1);
	g_free(name2);

	return result;
}

static GList *
sipe_media_prune_remote_codecs(GList *local_codecs, GList *remote_codecs)
{
	GList *remote_codecs_head = remote_codecs;
	GList *pruned_codecs = NULL;

	while (remote_codecs) {
		struct sipe_backend_codec *c = remote_codecs->data;

		if (g_list_find_custom(local_codecs, c, (GCompareFunc)codec_name_compare)) {
			pruned_codecs = g_list_append(pruned_codecs, c);
			remote_codecs->data = NULL;
		}
		remote_codecs = remote_codecs->next;
	}

	sipe_media_codec_list_free(remote_codecs_head);

	return pruned_codecs;
}

static GList *
sipe_media_parse_remote_candidates_legacy(gchar *remote_ip, guint16	remote_port)
{
	struct sipe_backend_candidate *candidate;
	GList *candidates = NULL;

	candidate = sipe_backend_candidate_new("foundation",
									SIPE_COMPONENT_RTP,
									SIPE_CANDIDATE_TYPE_HOST,
									SIPE_NETWORK_PROTOCOL_UDP,
									remote_ip, remote_port);
	candidates = g_list_append(candidates, candidate);

	candidate = sipe_backend_candidate_new("foundation",
									SIPE_COMPONENT_RTCP,
									SIPE_CANDIDATE_TYPE_HOST,
									SIPE_NETWORK_PROTOCOL_UDP,
									remote_ip, remote_port + 1);
	candidates = g_list_append(candidates, candidate);

	return candidates;
}

static GList *
sipe_media_parse_remote_candidates(GSList *sdp_attrs)
{
	struct sipe_backend_candidate *candidate;
	GList *candidates = NULL;
	const gchar *attr;
	int i = 0;

	const gchar* username = sipe_utils_nameval_find(sdp_attrs, "ice-ufrag");
	const gchar* password = sipe_utils_nameval_find(sdp_attrs, "ice-pwd");

	while ((attr = sipe_utils_nameval_find_instance(sdp_attrs, "candidate", i++))) {
		gchar **tokens;
		gchar *foundation;
		SipeComponentType component;
		SipeNetworkProtocol protocol;
		guint32 priority;
		gchar* ip;
		guint16 port;
		SipeCandidateType type;

		tokens = g_strsplit_set(attr, " ", 0);

		foundation = tokens[0];

		switch (atoi(tokens[1])) {
			case 1:
				component = SIPE_COMPONENT_RTP;
				break;
			case 2:
				component = SIPE_COMPONENT_RTCP;
				break;
			default:
				component = SIPE_COMPONENT_NONE;
		}

		if (sipe_strequal(tokens[2], "UDP"))
			protocol = SIPE_NETWORK_PROTOCOL_UDP;
		else {
			// Ignore TCP candidates, at least for now...
			g_strfreev(tokens);
			continue;
		}

		priority = atoi(tokens[3]);
		ip = tokens[4];
		port = atoi(tokens[5]);

		if (sipe_strequal(tokens[7], "host"))
			type = SIPE_CANDIDATE_TYPE_HOST;
		else if (sipe_strequal(tokens[7], "relay"))
			type = SIPE_CANDIDATE_TYPE_RELAY;
		else if (sipe_strequal(tokens[7], "srflx"))
			type = SIPE_CANDIDATE_TYPE_SRFLX;
		else {
			g_strfreev(tokens);
			continue;
		}

		candidate = sipe_backend_candidate_new(foundation, component,
								type, protocol, ip, port);
		sipe_backend_candidate_set_priority(candidate, priority);
		candidates = g_list_append(candidates, candidate);

		g_strfreev(tokens);
	}

	if (username) {
		GList *it = candidates;
		while (it) {
			sipe_backend_candidate_set_username_and_pwd(it->data, username, password);
			it = it->next;
		}
	}

	return candidates;
}

static gchar *
sipe_media_sdp_codec_ids_format(GList *codecs)
{
	GString *result = g_string_new(NULL);

	while (codecs) {
		struct sipe_backend_codec *c = codecs->data;

		gchar *tmp = g_strdup_printf(" %d", sipe_backend_codec_get_id(c));
		g_string_append(result,tmp);
		g_free(tmp);

		codecs = codecs->next;
	}

	return g_string_free(result, FALSE);
}

static gchar *
sipe_media_sdp_codecs_format(GList *codecs)
{
	GString *result = g_string_new(NULL);

	while (codecs) {
		struct sipe_backend_codec *c = codecs->data;
		GList *params = NULL;
		gchar *name = sipe_backend_codec_get_name(c);

		gchar *tmp = g_strdup_printf("a=rtpmap:%d %s/%d\r\n",
			sipe_backend_codec_get_id(c),
			name,
			sipe_backend_codec_get_clock_rate(c));

		g_free(name);
		g_string_append(result, tmp);
		g_free(tmp);

		if ((params = sipe_backend_codec_get_optional_parameters(c))) {
			tmp = g_strdup_printf("a=fmtp:%d",sipe_backend_codec_get_id(c));
			g_string_append(result, tmp);
			g_free(tmp);

			while (params) {
				struct sipnameval* par = params->data;
				tmp = g_strdup_printf(" %s=%s", par->name, par->value);
				g_string_append(result, tmp);
				g_free(tmp);
				params = params->next;
			}
			g_string_append(result, "\r\n");
		}

		codecs = codecs->next;
	}

	return g_string_free(result, FALSE);
}

static gchar *
sipe_media_sdp_candidates_format(GList *candidates, struct sipe_media_call_private *call_private)
{
	GString *result = g_string_new("");
	gchar *tmp;
	gchar *username = sipe_backend_candidate_get_username(candidates->data);
	gchar *password = sipe_backend_candidate_get_password(candidates->data);
	guint16 rtcp_port = 0;

	if (call_private->legacy_mode)
		return g_string_free(result, FALSE);

	tmp = g_strdup_printf("a=ice-ufrag:%s\r\na=ice-pwd:%s\r\n",username, password);
	g_string_append(result, tmp);
	g_free(tmp);

	while (candidates) {
		struct sipe_backend_candidate *c = candidates->data;

		guint16 port;
		guint16 component;
		gchar *protocol;
		gchar *type;

		port = sipe_backend_candidate_get_port(c);

		switch (sipe_backend_candidate_get_component_type(c)) {
			case SIPE_COMPONENT_RTP:
				component = 1;
				break;
			case SIPE_COMPONENT_RTCP:
				component = 2;
				if (rtcp_port == 0)
					rtcp_port = port;
				break;
			case SIPE_COMPONENT_NONE:
				component = 0;
		}

		switch (sipe_backend_candidate_get_protocol(c)) {
			case SIPE_NETWORK_PROTOCOL_TCP:
				protocol = "TCP";
				break;
			case SIPE_NETWORK_PROTOCOL_UDP:
				protocol = "UDP";
				break;
		}

		switch (sipe_backend_candidate_get_type(c)) {
			case SIPE_CANDIDATE_TYPE_HOST:
				type = "host";
				break;
			case SIPE_CANDIDATE_TYPE_RELAY:
				type = "relay";
				break;
			case SIPE_CANDIDATE_TYPE_SRFLX:
				type = "srflx";
				break;
			default:
				// TODO: error unknown/unsupported type
				break;
		}

		tmp = g_strdup_printf("a=candidate:%s %u %s %u %s %d typ %s \r\n",
			sipe_backend_candidate_get_foundation(c),
			component,
			protocol,
			sipe_backend_candidate_get_priority(c),
			sipe_backend_candidate_get_ip(c),
			port,
			type);

		g_string_append(result, tmp);
		g_free(tmp);

		candidates = candidates->next;
	}

	// No exchange of remote candidates in the first round of negotiation
	if ((call_private->invite_cnt > 1) && call_private->remote_candidates) {
		struct sipe_backend_candidate *first = call_private->remote_candidates->data;
		struct sipe_backend_candidate *second = call_private->remote_candidates->next->data;
		tmp = g_strdup_printf("a=remote-candidates:1 %s %u 2 %s %u\r\n",
			sipe_backend_candidate_get_ip(first), sipe_backend_candidate_get_port(first),
			sipe_backend_candidate_get_ip(second), sipe_backend_candidate_get_port(second));

		g_string_append(result, tmp);
		g_free(tmp);
	}


	if (rtcp_port != 0) {
		tmp = g_strdup_printf("a=maxptime:200\r\na=rtcp:%u\r\n", rtcp_port);
		g_string_append(result, tmp);
		g_free(tmp);
	}

	return g_string_free(result, FALSE);
}

static gchar*
sipe_media_create_sdp(struct sipe_media_call_private *call_private) {
	GList *usable_codecs = sipe_backend_get_local_codecs(SIPE_MEDIA_CALL);
	GList *local_candidates = sipe_backend_get_local_candidates(SIPE_MEDIA_CALL,
								    call_private->dialog->with);
	gchar *body = NULL;

	if (local_candidates) {
		// TODO: more  sophisticated
		guint16	local_port = sipe_backend_candidate_get_port(local_candidates->data);
		const char *ip = sipe_utils_get_suitable_local_ip(-1);

		gchar *sdp_codecs = sipe_media_sdp_codecs_format(usable_codecs);
		gchar *sdp_codec_ids = sipe_media_sdp_codec_ids_format(usable_codecs);
		gchar *sdp_candidates = sipe_media_sdp_candidates_format(local_candidates,
								 call_private);
		gchar *inactive = (call_private->public.local_on_hold ||
				   call_private->public.remote_on_hold) ? "a=inactive\r\n" : "";

		body = g_strdup_printf(
			"v=0\r\n"
			"o=- 0 0 IN IP4 %s\r\n"
			"s=session\r\n"
			"c=IN IP4 %s\r\n"
			"b=CT:99980\r\n"
			"t=0 0\r\n"
			"m=audio %d RTP/AVP%s\r\n"
			"%s"
			"%s"
			"%s"
			"a=encryption:rejected\r\n"
			,ip, ip, local_port, sdp_codec_ids, sdp_candidates, inactive, sdp_codecs);

		g_free(sdp_codecs);
		g_free(sdp_codec_ids);
		g_free(sdp_candidates);
	}
	sipe_media_codec_list_free(usable_codecs);

	return body;
}

static void
sipe_invite_call(struct sipe_core_private *sipe_private, TransCallback tc)
{
	gchar *hdr;
	gchar *contact;
	gchar *body;
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	struct sipe_media_call_private *call_private = sipe_private->media_call;
	struct sip_dialog *dialog = call_private->dialog;

	++(call_private->invite_cnt);

	contact = get_contact(sipe_private);
	hdr = g_strdup_printf(
		"Supported: ms-early-media\r\n"
		"Supported: 100rel\r\n"
		"ms-keep-alive: UAC;hop-hop=yes\r\n"
		"Contact: %s%s\r\n"
		"Content-Type: application/sdp\r\n",
		contact,
		(call_private->public.local_on_hold || call_private->public.remote_on_hold) ? ";+sip.rendering=\"no\"" : "");
	g_free(contact);

	body = sipe_media_create_sdp(call_private);

	send_sip_request(SIP_TO_CORE_PRIVATE, "INVITE", dialog->with, dialog->with, hdr, body,
			  dialog, tc);

	g_free(body);
	g_free(hdr);
}

static gboolean
sipe_media_parse_remote_codecs(struct sipe_media_call_private *call_private);

static gboolean
sipe_media_parse_sdp_attributes_and_candidates(struct sipe_media_call_private *call_private, gchar *frame) {
	gchar		**lines = g_strsplit(frame, "\r\n", 0);
	GSList		*sdp_attrs = NULL;
	gchar		*remote_ip = NULL;
	guint16 	remote_port = 0;
	GList		*remote_candidates;
	gchar		**ptr;
	gboolean	no_error = TRUE;

	for (ptr = lines; *ptr != NULL; ++ptr) {
		if (g_str_has_prefix(*ptr, "a=")) {
			gchar **parts = g_strsplit(*ptr + 2, ":", 2);
			if(!parts[0]) {
				g_strfreev(parts);
				sipe_utils_nameval_free(sdp_attrs);
				sdp_attrs = NULL;
				no_error = FALSE;
				break;
			}
			sdp_attrs = sipe_utils_nameval_add(sdp_attrs, parts[0], parts[1]);
			g_strfreev(parts);

		} else if (g_str_has_prefix(*ptr, "o=")) {
			gchar **parts = g_strsplit(*ptr + 2, " ", 6);
			remote_ip = g_strdup(parts[5]);
			g_strfreev(parts);
		} else if (g_str_has_prefix(*ptr, "m=")) {
			gchar **parts = g_strsplit(*ptr + 2, " ", 3);
			remote_port = atoi(parts[1]);
			g_strfreev(parts);
		}
	}

	g_strfreev(lines);

	remote_candidates = sipe_media_parse_remote_candidates(sdp_attrs);
	if (!remote_candidates) {
		// No a=candidate in SDP message, revert to OC2005 behaviour
		sipe_media_parse_remote_candidates_legacy(remote_ip, remote_port);
		// This seems to be pre-OC2007 R2 UAC
		call_private->legacy_mode = TRUE;
	}

	if (no_error) {
		sipe_utils_nameval_free(call_private->sdp_attrs);
		sipe_media_candidate_list_free(call_private->remote_candidates);

		call_private->sdp_attrs			= sdp_attrs;
		call_private->remote_ip			= remote_ip;
		call_private->remote_port		= remote_port;
		call_private->remote_candidates	= remote_candidates;
	} else {
		sipe_utils_nameval_free(sdp_attrs);
		sipe_media_candidate_list_free(remote_candidates);
	}

	return no_error;
}

static gboolean
sipe_media_parse_remote_codecs(struct sipe_media_call_private *call_private)
{
	GList *local_codecs = sipe_backend_get_local_codecs(SIPE_MEDIA_CALL);
	GList *remote_codecs;

	remote_codecs = sipe_media_parse_codecs(call_private->sdp_attrs);
	remote_codecs = sipe_media_prune_remote_codecs(local_codecs, remote_codecs);

	sipe_media_codec_list_free(local_codecs);

	if (remote_codecs) {
		sipe_media_codec_list_free(call_private->public.remote_codecs);

		call_private->public.remote_codecs = remote_codecs;

		if (!sipe_backend_set_remote_codecs(SIPE_MEDIA_CALL,
						    call_private->dialog->with)) {
			SIPE_DEBUG_ERROR_NOFORMAT("ERROR SET REMOTE CODECS"); // TODO
			return FALSE;
		}

		return TRUE;
	} else {
		sipe_media_codec_list_free(remote_codecs);
		SIPE_DEBUG_ERROR_NOFORMAT("ERROR NO CANDIDATES OR CODECS");

		return FALSE;
	}
}

static struct sip_dialog *
sipe_media_dialog_init(struct sip_session* session, struct sipmsg *msg)
{
	gchar *newTag = gentag();
	const gchar *oldHeader;
	gchar *newHeader;
	struct sip_dialog *dialog;

	oldHeader = sipmsg_find_header(msg, "To");
	newHeader = g_strdup_printf("%s;tag=%s", oldHeader, newTag);
	sipmsg_remove_header_now(msg, "To");
	sipmsg_add_header_now(msg, "To", newHeader);
	g_free(newHeader);

	dialog = sipe_dialog_add(session);
	dialog->callid = g_strdup(session->callid);
	dialog->with = parse_from(sipmsg_find_header(msg, "From"));
	sipe_dialog_parse(dialog, msg, FALSE);

	return dialog;
}

static void
send_response_with_session_description(struct sipe_media_call_private *call_private, int code, gchar *text)
{
	gchar *body = sipe_media_create_sdp(call_private);
	sipmsg_add_header(call_private->invitation, "Content-Type", "application/sdp");
	send_sip_response(call_private->sipe_private, call_private->invitation, code, text, body);
	g_free(body);
}

static gboolean
sipe_media_process_invite_response(struct sipe_core_private *sipe_private,
								   struct sipmsg *msg,
								   struct transaction *trans);

static void candidates_prepared_cb(struct sipe_media_call *call)
{
	struct sipe_media_call_private *call_private = (struct sipe_media_call_private *) call;

	if (sipe_backend_media_is_initiator(call_private->public.backend_private,
					    call_private->dialog->with)) {
		sipe_invite_call(call_private->sipe_private, sipe_media_process_invite_response);
	} else if (!call_private->legacy_mode) {
		if (!sipe_media_parse_remote_codecs(call_private)) {
			g_free(call_private);
			return;
		}

		send_response_with_session_description(call_private, 183, "Session Progress");
	}
}

static void media_connected_cb(SIPE_UNUSED_PARAMETER struct sipe_media_call_private *call_private)
{
}

static void call_accept_cb(struct sipe_media_call *call, gboolean local)
{
	if (local) {
		send_response_with_session_description(SIPE_MEDIA_CALL_PRIVATE,
						       200, "OK");
	}
}

static void call_reject_cb(struct sipe_media_call *call, gboolean local)
{
	struct sipe_media_call_private *call_private = SIPE_MEDIA_CALL_PRIVATE;

	if (local) {
		send_sip_response(call_private->sipe_private, call_private->invitation, 603, "Decline", NULL);
	}
	call_private->sipe_private->media_call = NULL;
	sipe_media_call_free(call_private);
}

static gboolean
sipe_media_send_ack(struct sipe_core_private *sipe_private, struct sipmsg *msg,
					struct transaction *trans);

static void call_hold_cb(struct sipe_media_call *call, gboolean local, gboolean state)
{
	struct sipe_media_call_private *call_private = SIPE_MEDIA_CALL_PRIVATE;

	if (local && (call_private->public.local_on_hold != state)) {
		call_private->public.local_on_hold = state;
		sipe_invite_call(call_private->sipe_private, sipe_media_send_ack);
	} else if (call_private->public.remote_on_hold != state) {
		call_private->public.remote_on_hold = state;
		send_response_with_session_description(call_private, 200, "OK");
	}
}

static void call_hangup_cb(struct sipe_media_call *call, gboolean local)
{
	struct sipe_media_call_private *call_private = SIPE_MEDIA_CALL_PRIVATE;

	if (local) {
		send_sip_request(call_private->sipe_private, "BYE", call_private->dialog->with, call_private->dialog->with,
				 NULL, NULL, call_private->dialog, NULL);
	}
	call_private->sipe_private->media_call = NULL;
	sipe_media_call_free(call_private);
}

static struct sipe_media_call_private *
sipe_media_call_init(struct sipe_core_private *sipe_private, const gchar* participant, gboolean initiator)
{
	struct sipe_media_call_private *call_private = g_new0(struct sipe_media_call_private, 1);

	call_private->sipe_private = sipe_private;
	call_private->public.backend_private = sipe_backend_media_new(SIPE_CORE_PUBLIC,
								      SIPE_MEDIA_CALL,
								      participant,
								      initiator);

	call_private->legacy_mode = FALSE;

	call_private->public.candidates_prepared_cb = candidates_prepared_cb;
	call_private->public.media_connected_cb     = media_connected_cb;
	call_private->public.call_accept_cb         = call_accept_cb;
	call_private->public.call_reject_cb         = call_reject_cb;
	call_private->public.call_hold_cb           = call_hold_cb;
	call_private->public.call_hangup_cb         = call_hangup_cb;

	call_private->public.local_on_hold  = FALSE;
	call_private->public.remote_on_hold = FALSE;

	return call_private;
}

void sipe_media_hangup(struct sipe_core_private *sipe_private)
{
	struct sipe_media_call_private *call_private = sipe_private->media_call;
	if (call_private)
		sipe_backend_media_hangup(call_private->public.backend_private,
					  FALSE);
}

void
sipe_core_media_initiate_call(struct sipe_core_public *sipe_public,
			      const char *participant)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_media_call_private *call_private;

	if (sipe_private->media_call)
		return;

	call_private = sipe_media_call_init(sipe_private, participant, TRUE);

	sipe_private->media_call = call_private;

	call_private->session = sipe_session_add_chat(sipe_private);
	call_private->dialog = sipe_dialog_add(call_private->session);
	call_private->dialog->callid = gencallid();
	call_private->dialog->with = g_strdup(participant);
	call_private->dialog->ourtag = gentag();

	sipe_backend_media_add_stream(call_private->public.backend_private,
				      participant,
				      SIPE_MEDIA_AUDIO,
				      !call_private->legacy_mode, TRUE);
}


void
sipe_media_incoming_invite(struct sipe_core_private *sipe_private,
			   struct sipmsg *msg)
{
	const gchar					*callid = sipmsg_find_header(msg, "Call-ID");

	struct sipe_media_call_private *call_private = sipe_private->media_call;
	struct sip_session *session;
	struct sip_dialog *dialog;

	if (call_private) {
		if (sipe_strequal(call_private->dialog->callid, callid)) {
			++(call_private->invite_cnt);

			if (call_private->invitation)
				sipmsg_free(call_private->invitation);
			call_private->invitation = sipmsg_copy(msg);

			sipe_utils_nameval_free(call_private->sdp_attrs);
			call_private->sdp_attrs = NULL;
			if (!sipe_media_parse_sdp_attributes_and_candidates(call_private,
									    call_private->invitation->body)) {
				// TODO: handle error
			}
			if (!sipe_media_parse_remote_codecs(call_private)) {
				g_free(call_private);
				return;
			}

			if (call_private->legacy_mode && !call_private->public.remote_on_hold) {
				sipe_backend_media_hold(call_private->public.backend_private,
							FALSE);
			} else if (sipe_utils_nameval_find(call_private->sdp_attrs, "inactive")) {
				sipe_backend_media_hold(call_private->public.backend_private, FALSE);
			} else if (call_private->public.remote_on_hold) {
				sipe_backend_media_unhold(call_private->public.backend_private, FALSE);
			} else {
				send_response_with_session_description(call_private,
								       200, "OK");
			}
		} else {
			send_sip_response(sipe_private, msg, 486, "Busy Here", NULL);
		}
		return;
	}

	session = sipe_session_find_or_add_chat_by_callid(sipe_private, callid);
	dialog = sipe_media_dialog_init(session, msg);

	call_private = sipe_media_call_init(sipe_private, dialog->with, FALSE);
	call_private->invitation = sipmsg_copy(msg);
	call_private->session = session;
	call_private->dialog = dialog;
	call_private->invite_cnt = 1;

	sipe_private->media_call = call_private;

	if (!sipe_media_parse_sdp_attributes_and_candidates(call_private,
							    msg->body)) {
		// TODO error
	}

	sipe_backend_media_add_stream(call_private->public.backend_private, dialog->with, SIPE_MEDIA_AUDIO, !call_private->legacy_mode, FALSE);
	sipe_backend_media_add_remote_candidates(call_private->public.backend_private, dialog->with, call_private->remote_candidates);

	send_sip_response(sipe_private, call_private->invitation, 180, "Ringing", NULL);

	// Processing continues in candidates_prepared_cb
}

static gboolean
sipe_media_send_ack(struct sipe_core_private *sipe_private,
					SIPE_UNUSED_PARAMETER struct sipmsg *msg,
					struct transaction *trans)
{
	struct sipe_media_call_private *call_private = sipe_private->media_call;
	struct sip_dialog *dialog;
	int trans_cseq;
	int tmp_cseq;

	if (!call_private || !call_private->dialog)
		return FALSE;

	dialog = call_private->dialog;
	tmp_cseq = dialog->cseq;

	sscanf(trans->key, "<%*[a-zA-Z0-9]><%d INVITE>", &trans_cseq);
	dialog->cseq = trans_cseq - 1;
	send_sip_request(sipe_private, "ACK", dialog->with, dialog->with, NULL, NULL, dialog, NULL);
	dialog->cseq = tmp_cseq;

	return TRUE;
}

static gboolean
sipe_media_process_invite_response(struct sipe_core_private *sipe_private,
				   struct sipmsg *msg,
				   struct transaction *trans)
{
	const gchar* callid = sipmsg_find_header(msg, "Call-ID");
	struct sipe_media_call_private *call_private = sipe_private->media_call;

	if (!call_private ||
	    !sipe_strequal(sipe_media_get_callid(call_private), callid))
		return FALSE;

	if (msg->response == 183) {
		// Session in progress
		const gchar *rseq = sipmsg_find_header(msg, "RSeq");
		const gchar *cseq = sipmsg_find_header(msg, "CSeq");
		gchar *rack = g_strdup_printf("RAck: %s %s\r\n", rseq, cseq);

		if (!sipe_media_parse_sdp_attributes_and_candidates(call_private,
								    msg->body)) {
			// TODO: handle error
		}

		if (!sipe_media_parse_remote_codecs(call_private)) {
			g_free(call_private);
			return FALSE;
		}

		sipe_backend_media_add_remote_candidates(call_private->public.backend_private, call_private->dialog->with, call_private->remote_candidates);

		sipe_dialog_parse(call_private->dialog, msg, TRUE);

		send_sip_request(sipe_private, "PRACK", call_private->dialog->with, call_private->dialog->with, rack, NULL, call_private->dialog, NULL);
		g_free(rack);
	} else if (msg->response == 603) {
		sipe_backend_media_reject(call_private->public.backend_private, FALSE);
		sipe_media_send_ack(sipe_private, msg, trans);
	} else {
		//PurpleMedia* m = (PurpleMedia*) call_private->public.backend_private;
		//purple_media_stream_info(m, PURPLE_MEDIA_INFO_ACCEPT, NULL, NULL, FALSE);
		sipe_media_send_ack(sipe_private, msg, trans);
		sipe_invite_call(sipe_private, sipe_media_send_ack);
	}

	return TRUE;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
