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
#include <string.h>
#include <stdlib.h>
#include <libpurple/mediamanager.h>
#include <nice/agent.h>

#include "sipe-core.h"
#include "sipe.h"
#include "sipmsg.h"
#include "sipe-session.h"
#include "sipe-media.h"
#include "sipe-dialog.h"
#include "sipe-utils.h"
#include "sipe-common.h"

gchar *
sipe_media_get_callid(sipe_media_call *call)
{
	return call->dialog->callid;
}

void sipe_media_codec_list_free(GList *codecs)
{
	for (; codecs; codecs = g_list_delete_link(codecs, codecs)) {
		sipe_backend_codec_free(codecs->data);
	}
}

void sipe_media_candidate_list_free(GList *candidates)
{
	for (; candidates; candidates = g_list_delete_link(candidates, candidates)) {
		sipe_backend_candidate_free(candidates->data);
	}
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
sipe_media_parse_remote_codecs(const sipe_media_call *call)
{
	int			i = 0;
	const gchar	*attr;
	GList		*codecs	= NULL;

	while ((attr = sipe_utils_nameval_find_instance(call->sdp_attrs, "rtpmap", i++))) {
		gchar	**tokens	= g_strsplit_set(attr, " /", 3);

		int		id			= atoi(tokens[0]);
		gchar	*name		= tokens[1];
		int		clock_rate	= atoi(tokens[2]);
		SipeMediaType type	= SIPE_MEDIA_AUDIO;

		sipe_codec	*codec = sipe_backend_codec_new(id, name, clock_rate, type);

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

	return g_strcmp0(name1, name2);
}

static GList *
sipe_media_prune_remote_codecs(sipe_media_call *call, GList *codecs)
{
	GList *remote_codecs = codecs;
	GList *local_codecs = sipe_backend_get_local_codecs(call);
	GList *pruned_codecs = NULL;

	while (remote_codecs) {
		sipe_codec *c = remote_codecs->data;

		if (g_list_find_custom(local_codecs, c, (GCompareFunc)codec_name_compare)) {
			pruned_codecs = g_list_append(pruned_codecs, c);
			remote_codecs->data = NULL;
		}
		remote_codecs = remote_codecs->next;
	}

	sipe_media_codec_list_free(codecs);

	return pruned_codecs;
}

static GList *
sipe_media_parse_remote_candidates(sipe_media_call *call)
{
	GSList *sdp_attrs = call->sdp_attrs;
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
		g_object_set(candidate, "priority", priority, NULL);
		candidates = g_list_append(candidates, candidate);

		g_strfreev(tokens);
	}

	if (!candidates) {
		// No a=candidate in SDP message, revert to OC2005 behaviour
		candidate = sipe_backend_candidate_new("foundation",
										SIPE_COMPONENT_RTP,
										SIPE_CANDIDATE_TYPE_HOST,
										SIPE_NETWORK_PROTOCOL_UDP,
										call->remote_ip, call->remote_port);
		candidates = g_list_append(candidates, candidate);

		candidate = sipe_backend_candidate_new("foundation",
										SIPE_COMPONENT_RTCP,
										SIPE_CANDIDATE_TYPE_HOST,
										SIPE_NETWORK_PROTOCOL_UDP,
										call->remote_ip, call->remote_port + 1);
		candidates = g_list_append(candidates, candidate);

		// This seems to be pre-OC2007 R2 UAC
		call->legacy_mode = TRUE;
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

		gchar *tmp = g_strdup_printf("a=rtpmap:%d %s/%d\r\n",
			sipe_backend_codec_get_id(c),
			sipe_backend_codec_get_name(c),
			sipe_backend_codec_get_clock_rate(c));

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
sipe_media_sdp_candidates_format(GList *candidates, sipe_media_call* call, gboolean remote_candidate)
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

	if (remote_candidate) {
		PurpleMediaCandidate *first = call->remote_candidates->data;
		PurpleMediaCandidate *second = call->remote_candidates->next->data;
		tmp = g_strdup_printf("a=remote-candidates:1 %s %u 2 %s %u\r\n",
			purple_media_candidate_get_ip(first), purple_media_candidate_get_port(first),
			purple_media_candidate_get_ip(second), purple_media_candidate_get_port(second));

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
sipe_media_create_sdp(sipe_media_call *call, gboolean remote_candidate) {
	PurpleMedia *media = call->media;
	GList *local_codecs = purple_media_get_codecs(media, "sipe-voice");
	GList *local_candidates = purple_media_get_local_candidates(media, "sipe-voice", call->dialog->with);

	// TODO: more  sophisticated
	guint16	local_port = purple_media_candidate_get_port(local_candidates->data);
	const char *ip = sipe_utils_get_suitable_local_ip(-1);

	gchar *sdp_codecs = sipe_media_sdp_codecs_format(local_codecs);
	gchar *sdp_codec_ids = sipe_media_sdp_codec_ids_format(local_codecs);
	gchar *sdp_candidates = sipe_media_sdp_candidates_format(local_candidates, call, remote_candidate);
	gchar *inactive = call->state == SIPE_CALL_HELD ? "a=inactive\r\n" : "";

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

	return body;
}

static void
sipe_media_session_ready_cb(sipe_media_call *call)
{
	PurpleMedia *media = call->media;
	PurpleAccount *account = purple_media_get_account(media);

	if (!purple_media_candidates_prepared(media, NULL, NULL))
		return;

	if (!call->sdp_response)
		call->sdp_response = sipe_media_create_sdp(call, FALSE);

	if (!purple_media_accepted(media, NULL, NULL)) {
		if (!call->legacy_mode)
			send_sip_response(account->gc, call->invitation, 183, "Session Progress", call->sdp_response);
	} else {
		send_sip_response(account->gc, call->invitation, 200, "OK", call->sdp_response);
		call->state = SIPE_CALL_RUNNING;
	}
}

static void
sipe_invite_call(struct sipe_account_data *sip)
{
	gchar *hdr;
	gchar *contact;
	gchar *body;
	sipe_media_call *call = sip->media_call;
	struct sip_dialog *dialog = call->dialog;

	contact = get_contact(sip);
	hdr = g_strdup_printf(
		"Supported: ms-sender\r\n"
		"ms-keep-alive: UAC;hop-hop=yes\r\n"
		"Contact: %s%s\r\n"
		"Supported: Replaces\r\n"
		"Content-Type: application/sdp\r\n",
		contact,
		call->state == SIPE_CALL_HELD ? ";+sip.rendering=\"no\"" : "");
	g_free(contact);

	body = sipe_media_create_sdp(call, TRUE);

	send_sip_request(sip->gc, "INVITE", dialog->with, dialog->with, hdr, body,
			  dialog, NULL);

	g_free(body);
	g_free(hdr);
}

static void
notify_state_change(struct sipe_account_data *sip, gboolean local) {
	if (local) {
		sipe_invite_call(sip);
	} else {
		gchar* body = sipe_media_create_sdp(sip->media_call, TRUE);
		send_sip_response(sip->gc, sip->media_call->invitation, 200, "OK", body);
		g_free(body);
	}
}

static void
sipe_media_stream_info_cb(PurpleMedia *media,
							PurpleMediaInfoType type,
							SIPE_UNUSED_PARAMETER gchar *sid,
							SIPE_UNUSED_PARAMETER gchar *name,
							gboolean local, struct sipe_account_data *sip)
{
	sipe_media_call *call = sip->media_call;

	if (type == PURPLE_MEDIA_INFO_ACCEPT)
		sipe_media_session_ready_cb(call);
	else if (type == PURPLE_MEDIA_INFO_REJECT) {
		PurpleAccount *account = purple_media_get_account(media);
		send_sip_response(account->gc, call->invitation, 603, "Decline", NULL);
		sipe_media_call_free(call);
		sip->media_call = NULL;
	} else if (type == PURPLE_MEDIA_INFO_HOLD) {
		if (call->state == SIPE_CALL_HELD)
			return;

		call->state = SIPE_CALL_HELD;
		notify_state_change(sip, local);
		purple_media_stream_info(media, PURPLE_MEDIA_INFO_HOLD, NULL, NULL, TRUE);

	} else if (type == PURPLE_MEDIA_INFO_UNHOLD) {
		if (call->state == SIPE_CALL_RUNNING)
			return;

		call->state = SIPE_CALL_RUNNING;
		notify_state_change(sip, local);

		purple_media_stream_info(media, PURPLE_MEDIA_INFO_UNHOLD, NULL, NULL, TRUE);
	} else if (type == PURPLE_MEDIA_INFO_HANGUP) {
		call->state = SIPE_CALL_FINISHED;
		if (local)
			send_sip_request(sip->gc, "BYE", call->dialog->with, call->dialog->with,
							NULL, NULL, call->dialog, NULL);
		sipe_media_call_free(call);
		sip->media_call = NULL;
	}
}

static gboolean
sipe_media_parse_sdp_frame(sipe_media_call* call, gchar *frame) {
	gchar		**lines = g_strsplit(frame, "\r\n", 0);
	GSList		*sdp_attrs = NULL;
	gchar		*remote_ip = NULL;
	guint16 	remote_port = 0;
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

	if (no_error) {
		sipe_utils_nameval_free(call->sdp_attrs);
		call->sdp_attrs = sdp_attrs;
		call->remote_ip = remote_ip;
		call->remote_port = remote_port;
	}

	return no_error;
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

static sipe_media_call *
sipe_media_call_init(struct sipmsg *msg)
{
	sipe_media_call *call;

	call = g_new0(sipe_media_call, 1);

	if (sipe_media_parse_sdp_frame(call, msg->body) == FALSE) {
		g_free(call);
		return NULL;
	}

	call->invitation = msg;
	call->legacy_mode = FALSE;
	call->state = SIPE_CALL_CONNECTING;
	call->remote_candidates = sipe_media_parse_remote_candidates(call);
	return call;
}

void sipe_media_hold(struct sipe_account_data *sip) {
	if (sip->media_call) {
		purple_media_stream_info(sip->media_call->media, PURPLE_MEDIA_INFO_HOLD,
								NULL, NULL, FALSE);
	}
}

void sipe_media_unhold(struct sipe_account_data *sip) {
	if (sip->media_call) {
		purple_media_stream_info(sip->media_call->media, PURPLE_MEDIA_INFO_UNHOLD,
								NULL, NULL, FALSE);
	}
}

void sipe_media_incoming_invite(struct sipe_account_data *sip, struct sipmsg *msg)
{
	PurpleMediaManager			*manager = purple_media_manager_get();
	PurpleMedia					*media;

	const gchar					*callid = sipmsg_find_header(msg, "Call-ID");

	sipe_media_call				*call;
	struct sip_session			*session;
	struct sip_dialog			*dialog;

	GParameter *params;

	if (sip->media_call) {
		if (sipe_strequal(sip->media_call->dialog->callid, callid)) {
			gchar *rsp;

			call = sip->media_call;

			sipmsg_free(call->invitation);
			msg->dont_free = TRUE;
			call->invitation = msg;

			sipmsg_add_header(msg, "Supported", "Replaces");

			sipe_utils_nameval_free(call->sdp_attrs);
			call->sdp_attrs = NULL;
			if (!sipe_media_parse_sdp_frame(call, msg->body)) {
				// TODO: handle error
			}

			if (call->legacy_mode && call->state == SIPE_CALL_RUNNING) {
				sipe_media_hold(sip);
				return;
			}

			if (sipe_utils_nameval_find(call->sdp_attrs, "inactive")) {
				sipe_media_hold(sip);
				return;
			}

			if (call->state == SIPE_CALL_HELD) {
				sipe_media_unhold(sip);
				return;
			}

			call->remote_codecs = sipe_media_parse_remote_codecs(call);
			call->remote_codecs = sipe_media_prune_remote_codecs(call->media, call->remote_codecs);
			if (!call->remote_codecs) {
				// TODO: error no remote codecs
			}
			if (sipe_backend_set_remote_codecs(call, call->dialog->with) == FALSE)
				printf("ERROR SET REMOTE CODECS"); // TODO

			rsp = sipe_media_create_sdp(sip->media_call, TRUE);
			send_sip_response(sip->gc, msg, 200, "OK", rsp);
			g_free(rsp);
		} else {
			// TODO: send Busy Here
			printf("MEDIA SESSION ALREADY IN PROGRESS");
		}
		return;
	}

	call = sipe_media_call_init(msg);

	session = sipe_session_find_or_add_chat_by_callid(sip, callid);
	dialog = sipe_media_dialog_init(session, msg);

	media = purple_media_manager_create_media(manager, sip->account,
							"fsrtpconference", dialog->with, FALSE);

	g_signal_connect(G_OBJECT(media), "stream-info",
						G_CALLBACK(sipe_media_stream_info_cb), sip);
	g_signal_connect_swapped(G_OBJECT(media), "candidates-prepared",
						G_CALLBACK(sipe_media_session_ready_cb), call);


	call->session = session;
	call->dialog = dialog;
	call->media = media;

	if (call->legacy_mode) {
		purple_media_add_stream(media, "sipe-voice", dialog->with,
							PURPLE_MEDIA_AUDIO, FALSE, "rawudp", 0, NULL);
	} else {
		params = g_new0(GParameter, 2);
		params[0].name = "controlling-mode";
		g_value_init(&params[0].value, G_TYPE_BOOLEAN);
		g_value_set_boolean(&params[0].value, FALSE);
		params[1].name = "compatibility-mode";
		g_value_init(&params[1].value, G_TYPE_UINT);
		g_value_set_uint(&params[1].value, NICE_COMPATIBILITY_OC2007R2);


		purple_media_add_stream(media, "sipe-voice", dialog->with,
								PURPLE_MEDIA_AUDIO, FALSE, "nice", 2, params);
	}

	purple_media_add_remote_candidates(media, "sipe-voice", dialog->with,
			                           call->remote_candidates);

	call->remote_codecs = sipe_media_parse_remote_codecs(call);
	call->remote_codecs = sipe_media_prune_remote_codecs(call, call->remote_codecs);
	if (!call->remote_candidates || !call->remote_codecs) {
		sipe_media_call_free(call);
		sip->media_call = NULL;
		printf("ERROR NO CANDIDATES OR CODECS");
		return;
	}
	if (sipe_backend_set_remote_codecs(call, dialog->with) == FALSE)
		printf("ERROR SET REMOTE CODECS"); // TODO

	sip->media_call = call;

	// TODO: copy message instead of this don't free thing
	msg->dont_free = TRUE;
	send_sip_response(sip->gc, msg, 180, "Ringing", NULL);
}

void sipe_media_hangup(struct sipe_account_data *sip)
{
	if (sip->media_call) {
		purple_media_stream_info(sip->media_call->media, PURPLE_MEDIA_INFO_HANGUP,
								NULL, NULL, FALSE);
	}
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
