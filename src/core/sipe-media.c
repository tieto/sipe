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

#include <glib.h>
#include <stdio.h>
#include <stdlib.h>

#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe.h"
#include "sipmsg.h"
#include "sipe-session.h"
#include "sipe-media.h"
#include "sipe-dialog.h"
#include "sipe-utils.h"
#include "sipe-common.h"
#include "sip-transport.h"

gchar *
sipe_media_get_callid(sipe_media_call *call)
{
	return call->dialog->callid;
}

void sipe_media_codec_list_free(GList *codecs)
{
	for (; codecs; codecs = g_list_delete_link(codecs, codecs))
		sipe_backend_codec_free(codecs->data);
}

void sipe_media_candidate_list_free(GList *candidates)
{
	for (; candidates; candidates = g_list_delete_link(candidates, candidates))
		sipe_backend_candidate_free(candidates->data);
}

static void
sipe_media_call_free(sipe_media_call *call)
{
	if (call) {
		sipe_utils_nameval_free(call->sdp_attrs);
		if (call->invitation)
			sipmsg_free(call->invitation);
		sipe_media_codec_list_free(call->remote_codecs);
		sipe_media_candidate_list_free(call->remote_candidates);
		g_free(call);
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

		sipe_codec	*codec = sipe_backend_codec_new(id, name, clock_rate, type);

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
codec_name_compare(sipe_codec* codec1, sipe_codec* codec2)
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
		sipe_codec *c = remote_codecs->data;

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
	sipe_candidate *candidate;
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
	sipe_candidate *candidate;
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
		sipe_codec *c = codecs->data;

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
		sipe_codec *c = codecs->data;
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
sipe_media_sdp_candidates_format(GList *candidates, sipe_media_call* call)
{
	GString *result = g_string_new("");
	gchar *tmp;
	gchar *username = sipe_backend_candidate_get_username(candidates->data);
	gchar *password = sipe_backend_candidate_get_password(candidates->data);
	guint16 rtcp_port = 0;

	if (call->legacy_mode)
		return g_string_free(result, FALSE);

	tmp = g_strdup_printf("a=ice-ufrag:%s\r\na=ice-pwd:%s\r\n",username, password);
	g_string_append(result, tmp);
	g_free(tmp);

	while (candidates) {
		sipe_candidate *c = candidates->data;

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
	if ((call->invite_cnt > 1) && call->remote_candidates) {
		sipe_candidate *first = call->remote_candidates->data;
		sipe_candidate *second = call->remote_candidates->next->data;
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
sipe_media_create_sdp(sipe_media_call *call) {
	GList *usable_codecs = sipe_backend_get_local_codecs(call);
	GList *local_candidates = sipe_backend_get_local_candidates(call, call->dialog->with);

	// TODO: more  sophisticated
	guint16	local_port = sipe_backend_candidate_get_port(local_candidates->data);
	const char *ip = sipe_utils_get_suitable_local_ip(-1);

	gchar *sdp_codecs = sipe_media_sdp_codecs_format(usable_codecs);
	gchar *sdp_codec_ids = sipe_media_sdp_codec_ids_format(usable_codecs);
	gchar *sdp_candidates = sipe_media_sdp_candidates_format(local_candidates, call);
	gchar *inactive = (call->local_on_hold || call->remote_on_hold) ? "a=inactive\r\n" : "";

	gchar *body = g_strdup_printf(
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
	sipe_media_call *call = sip->media_call;
	struct sip_dialog *dialog = call->dialog;

	++(call->invite_cnt);

	contact = get_contact(sip);
	hdr = g_strdup_printf(
		"Supported: ms-early-media\r\n"
		"Supported: 100rel\r\n"
		"ms-keep-alive: UAC;hop-hop=yes\r\n"
		"Contact: %s%s\r\n"
		"Content-Type: application/sdp\r\n",
		contact,
		(call->local_on_hold || call->remote_on_hold) ? ";+sip.rendering=\"no\"" : "");
	g_free(contact);

	body = sipe_media_create_sdp(call);

	send_sip_request(SIP_TO_CORE_PRIVATE, "INVITE", dialog->with, dialog->with, hdr, body,
			  dialog, tc);

	g_free(body);
	g_free(hdr);
}

static gboolean
sipe_media_parse_remote_codecs(sipe_media_call *call);

static gboolean
sipe_media_parse_sdp_attributes_and_candidates(sipe_media_call* call, gchar *frame) {
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
		call->legacy_mode = TRUE;
	}

	if (no_error) {
		sipe_utils_nameval_free(call->sdp_attrs);
		sipe_media_candidate_list_free(call->remote_candidates);

		call->sdp_attrs			= sdp_attrs;
		call->remote_ip			= remote_ip;
		call->remote_port		= remote_port;
		call->remote_candidates	= remote_candidates;
	} else {
		sipe_utils_nameval_free(sdp_attrs);
		sipe_media_candidate_list_free(remote_candidates);
	}

	return no_error;
}

static gboolean
sipe_media_parse_remote_codecs(sipe_media_call *call)
{
	GList		*local_codecs = sipe_backend_get_local_codecs(call);
	GList		*remote_codecs;

	remote_codecs = sipe_media_parse_codecs(call->sdp_attrs);
	remote_codecs = sipe_media_prune_remote_codecs(local_codecs, remote_codecs);

	sipe_media_codec_list_free(local_codecs);

	if (remote_codecs) {
		sipe_media_codec_list_free(call->remote_codecs);

		call->remote_codecs		= remote_codecs;

		if (!sipe_backend_set_remote_codecs(call, call->dialog->with)) {
			printf("ERROR SET REMOTE CODECS"); // TODO
			return FALSE;
		}

		return TRUE;
	} else {
		sipe_media_codec_list_free(remote_codecs);
		printf("ERROR NO CANDIDATES OR CODECS");

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
send_response_with_session_description(sipe_media_call *call, int code, gchar *text)
{
	gchar *body = sipe_media_create_sdp(call);
	sipmsg_add_header(call->invitation, "Content-Type", "application/sdp");
	send_sip_response(call->sipe_private, call->invitation, code, text, body);
	g_free(body);
}

static gboolean
sipe_media_process_invite_response(struct sipe_core_private *sipe_private,
								   struct sipmsg *msg,
								   struct transaction *trans);

static void candidates_prepared_cb(sipe_media_call *call)
{
	if (sipe_backend_media_is_initiator(call->media, call->dialog->with)) {
		sipe_invite_call(call->sipe_private, sipe_media_process_invite_response);
	} else if (!call->legacy_mode) {
		if (!sipe_media_parse_remote_codecs(call)) {
			g_free(call);
			return;
		}

		send_response_with_session_description(call, 183, "Session Progress");
	}
}

static void media_connected_cb(sipe_media_call *call)
{
	call = call;
}

static void call_accept_cb(sipe_media_call *call, gboolean local)
{
	if (local) {
		send_response_with_session_description(call, 200, "OK");
	}
}

static void call_reject_cb(sipe_media_call *call, gboolean local)
{
	struct sipe_core_private *sipe_private = call->sipe_private;
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

	if (local) {
		send_sip_response(call->sipe_private, call->invitation, 603, "Decline", NULL);
	}
	sip->media_call = NULL;
	sipe_media_call_free(call);
}

static gboolean
sipe_media_send_ack(struct sipe_core_private *sipe_private, struct sipmsg *msg,
					struct transaction *trans);

static void call_hold_cb(sipe_media_call *call, gboolean local, gboolean state)
{
	if (local && (call->local_on_hold != state)) {
		call->local_on_hold = state;
		sipe_invite_call(call->sipe_private, sipe_media_send_ack);
	} else if (call->remote_on_hold != state) {
		call->remote_on_hold = state;
		send_response_with_session_description(call, 200, "OK");
	}
}

static void call_hangup_cb(sipe_media_call *call, gboolean local)
{
	struct sipe_core_private *sipe_private = call->sipe_private;
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

	if (local) {
		send_sip_request(call->sipe_private, "BYE", call->dialog->with, call->dialog->with,
						NULL, NULL, call->dialog, NULL);
	}
	sip->media_call = NULL;
	sipe_media_call_free(call);
}

static sipe_media_call *
sipe_media_call_init(struct sipe_core_private *sipe_private, const gchar* participant, gboolean initiator)
{
	sipe_media_call *call = g_new0(sipe_media_call, 1);


	call->sipe_private = sipe_private;
	call->media = sipe_backend_media_new(call, participant, initiator);

	call->legacy_mode = FALSE;

	call->candidates_prepared_cb	= candidates_prepared_cb;
	call->media_connected_cb		= media_connected_cb;
	call->call_accept_cb			= call_accept_cb;
	call->call_reject_cb			= call_reject_cb;
	call->call_hold_cb				= call_hold_cb;
	call->call_hangup_cb			= call_hangup_cb;

	call->local_on_hold				= FALSE;
	call->remote_on_hold			= FALSE;

	return call;
}

void sipe_media_hangup(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	if (sip->media_call)
		sipe_backend_media_hangup(sip->media_call->media, FALSE);
}

void
sipe_media_initiate_call(struct sipe_core_private *sipe_private, const char *participant)
{
	sipe_media_call *call;
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

	if (sip->media_call)
		return;

	call = sipe_media_call_init(sipe_private, participant, TRUE);

	sip->media_call = call;

	call->session = sipe_session_add_chat(sip);
	call->dialog = sipe_dialog_add(call->session);
	call->dialog->callid = gencallid();
	call->dialog->with = g_strdup(participant);
	call->dialog->ourtag = gentag();

	sipe_backend_media_add_stream(call->media, participant, SIPE_MEDIA_AUDIO,
								  !call->legacy_mode, TRUE);
}


void
sipe_media_incoming_invite(struct sipe_core_private *sipe_private, struct sipmsg *msg)
{
	const gchar					*callid = sipmsg_find_header(msg, "Call-ID");

	sipe_media_call				*call;
	struct sip_session			*session;
	struct sip_dialog			*dialog;
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

	if (sip->media_call) {
		if (sipe_strequal(sip->media_call->dialog->callid, callid)) {
			++(sip->media_call->invite_cnt);
			call = sip->media_call;

			if (call->invitation)
				sipmsg_free(call->invitation);
			call->invitation = sipmsg_copy(msg);

			sipe_utils_nameval_free(call->sdp_attrs);
			call->sdp_attrs = NULL;
			if (!sipe_media_parse_sdp_attributes_and_candidates(call, call->invitation->body)) {
				// TODO: handle error
			}
			if (!sipe_media_parse_remote_codecs(call)) {
				g_free(call);
				return;
			}

			if (call->legacy_mode && !call->remote_on_hold) {
				sipe_backend_media_hold(call->media, FALSE);
			} else if (sipe_utils_nameval_find(call->sdp_attrs, "inactive")) {
				sipe_backend_media_hold(call->media, FALSE);
			} else if (call->remote_on_hold) {
				sipe_backend_media_unhold(call->media, FALSE);
			} else {
				send_response_with_session_description(call, 200, "OK");
			}
		} else {
			send_sip_response(SIP_TO_CORE_PRIVATE, msg, 486, "Busy Here", NULL);
		}
		return;
	}

	session = sipe_session_find_or_add_chat_by_callid(sip, callid);
	dialog = sipe_media_dialog_init(session, msg);

	call = sipe_media_call_init(sipe_private, dialog->with, FALSE);
	call->invitation = sipmsg_copy(msg);
	call->session = session;
	call->dialog = dialog;
	call->invite_cnt = 1;

	sip->media_call = call;

	if (!sipe_media_parse_sdp_attributes_and_candidates(call, msg->body)) {
		// TODO error
	}

	sipe_backend_media_add_stream(call->media, dialog->with, SIPE_MEDIA_AUDIO, !call->legacy_mode, FALSE);
	sipe_backend_media_add_remote_candidates(call->media, dialog->with, call->remote_candidates);

	send_sip_response(SIP_TO_CORE_PRIVATE, call->invitation, 180, "Ringing", NULL);

	// Processing continues in candidates_prepared_cb
}

static gboolean
sipe_media_send_ack(struct sipe_core_private *sipe_private,
					SIPE_UNUSED_PARAMETER struct sipmsg *msg,
					struct transaction *trans)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	struct sip_dialog *dialog;
	int trans_cseq;
	int tmp_cseq;

	if (!sip->media_call || !sip->media_call->dialog)
		return FALSE;

	dialog = sip->media_call->dialog;
	tmp_cseq = dialog->cseq;

	sscanf(trans->key, "<%*[a-zA-Z0-9]><%d INVITE>", &trans_cseq);
	dialog->cseq = trans_cseq - 1;
	send_sip_request(SIP_TO_CORE_PRIVATE, "ACK", dialog->with, dialog->with, NULL, NULL, dialog, NULL);
	dialog->cseq = tmp_cseq;

	return TRUE;
}

static gboolean
sipe_media_process_invite_response(struct sipe_core_private *sipe_private,
								   struct sipmsg *msg,
								   struct transaction *trans)
{
	const gchar* callid = sipmsg_find_header(msg, "Call-ID");
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	sipe_media_call *call = sip->media_call;

	if (!call || !sipe_strequal(sipe_media_get_callid(call), callid))
		return FALSE;

	if (msg->response == 183) {
		// Session in progress
		const gchar *rseq = sipmsg_find_header(msg, "RSeq");
		const gchar *cseq = sipmsg_find_header(msg, "CSeq");
		gchar *rack = g_strdup_printf("RAck: %s %s\r\n", rseq, cseq);

		if (!sipe_media_parse_sdp_attributes_and_candidates(call, msg->body)) {
			// TODO: handle error
		}

		if (!sipe_media_parse_remote_codecs(call)) {
			g_free(call);
			return FALSE;
		}

		sipe_backend_media_add_remote_candidates(call->media, call->dialog->with, call->remote_candidates);

		sipe_dialog_parse(call->dialog, msg, TRUE);

		send_sip_request(SIP_TO_CORE_PRIVATE, "PRACK", call->dialog->with, call->dialog->with, rack, NULL, call->dialog, NULL);
		g_free(rack);
	} else if (msg->response == 603) {
		sipe_backend_media_reject(call->media, FALSE);
		sipe_media_send_ack(sipe_private, msg, trans);
	} else {
		//PurpleMedia* m = (PurpleMedia*) call->media;
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
