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

#include "mediamanager.h"

#include "sip-sec.h"
#include "sipe.h"
#include "sipmsg.h"
#include "sipe-media.h"
#include "sipe-dialog.h"
#include "sipe-utils.h"
#include "sipe-common.h"

//#include <nice/agent.h>
#include "../../../libnice/agent/agent.h"

#include <string.h>

static void
sipe_media_call_free(sipe_media_call *call)
{
	if (call) {
		sipe_dialog_free(call->dialog);
		sipe_utils_nameval_free(call->sdp_attrs);
		if (call->invitation)
			sipmsg_free(call->invitation);
		purple_media_codec_list_free(call->remote_codecs);
		purple_media_candidate_list_free(call->remote_candidates);
		g_free(call);
	}
}

static GList *
sipe_media_parse_remote_codecs(const sipe_media_call *call)
{
	int			i = 0;
	const gchar	*attr;
	GList		*codecs	= NULL;

	while ((attr = sipe_utils_nameval_find_instance(call->sdp_attrs, "a", i++))) {
		gchar **tokens;
		int id;
		int clock_rate;
		gchar *codec_name;
		PurpleMediaCodec *codec;

		if (!g_str_has_prefix(attr, "rtpmap:"))
			continue;

		tokens = g_strsplit_set(attr + 7, " /", 3);

		id = atoi(tokens[0]);
		codec_name = tokens[1];
		clock_rate = atoi(tokens[2]);

		codec = purple_media_codec_new(id, codec_name, PURPLE_MEDIA_AUDIO, clock_rate);
		codecs = g_list_append(codecs, codec);

		g_strfreev(tokens);

		printf("REMOTE CODEC: %s\n",purple_media_codec_to_string(codec));
	}

	return codecs;
}

static gint
codec_name_compare(PurpleMediaCodec* codec1, PurpleMediaCodec* codec2)
{
	gchar *name1 = purple_media_codec_get_encoding_name(codec1);
	gchar *name2 = purple_media_codec_get_encoding_name(codec2);

	return g_strcmp0(name1, name2);
}

static GList *
sipe_media_prune_remote_codecs(PurpleMedia *media, GList *codecs)
{
	GList *remote_codecs = codecs;
	GList *local_codecs = purple_media_get_codecs(media, "sipe-voice");
	GList *pruned_codecs = NULL;

	while (remote_codecs) {
		PurpleMediaCodec *c = remote_codecs->data;

		if (g_list_find_custom(local_codecs, c, (GCompareFunc)codec_name_compare)) {
			pruned_codecs = g_list_append(pruned_codecs, c);
			remote_codecs->data = NULL;
		} else {
			printf("Pruned codec %s\n", purple_media_codec_get_encoding_name(c));
		}

		remote_codecs = remote_codecs->next;
	}

	purple_media_codec_list_free(codecs);

	return pruned_codecs;
}

/*static gchar *
sipe_media_generate_stun_username(gchar *remote_pwd)
{
	guchar *remote_pwd_bin = purple_base64_decode(remote_pwd, NULL);
	gchar *local_pwd_bin = g_new0(gchar, 32);

	gchar *buf = g_new0(gchar, 32 + 3 + 32 + 5);
	memcpy(buf, remote_pwd_bin, 32);
	buf[32] = 0x3a;
	buf[33] = 0x32;
	buf[34] = 0x3a;
	memcpy(buf + 35, local_pwd_bin, 32);
	buf[67] = 0x3a;
	buf[68] = 0x32;
	buf[69] = 0x00;
	buf[70] = 0x00;
	buf[71] = 0x00;

	g_free(remote_pwd_bin);
	g_free(local_pwd_bin);

	return buf;
}*/

/*static GList *
sipe_media_parse_remote_candidates(const sipe_media_call *call)
{
	PurpleMediaCandidate *candidate;
	GList *candidates = NULL;
	const gchar *attr;
	int i = 0;

	while ((attr = sipe_utils_nameval_find_instance(call->sdp_attrs, "a", i++))) {
		gchar **tokens;
		gchar *username;
		gchar *password;
		PurpleMediaComponentType component;
		gchar *ip;
		int port;

		if (!g_str_has_prefix(attr, "candidate:"))
			continue;

		tokens = g_strsplit_set(attr + 10, " ", 7);

		username = sipe_media_generate_stun_username(tokens[0]);

		switch (atoi(tokens[1])) {
			case 1:
				component = PURPLE_MEDIA_COMPONENT_RTP;
				break;
			case 2:
				component = PURPLE_MEDIA_COMPONENT_RTCP;
				break;
			default:
				component = PURPLE_MEDIA_COMPONENT_NONE;
		}

		password = g_strdup(tokens[2]);
		ip = g_strdup(tokens[5]);
		port = atoi(tokens[6]);

		g_strfreev(tokens);

		candidate = purple_media_candidate_new("foundation?",
									component,
									PURPLE_MEDIA_CANDIDATE_TYPE_HOST,
									PURPLE_MEDIA_NETWORK_PROTOCOL_UDP, ip, port);
		g_object_set(candidate, "username", username, "password", password, NULL);
		candidates = g_list_append(candidates, candidate);
	}

	if (candidates != NULL)
		return candidates;

	gchar **tokens = g_strsplit(sipe_utils_nameval_find(call->sdp_attrs, "o"), " ", 6);
	gchar *ip = g_strdup(tokens[5]);
	guint port;

	g_strfreev(tokens);

	tokens = g_strsplit(sipe_utils_nameval_find(call->sdp_attrs, "m"), " ", 3);
	port = atoi(tokens[1]);
	g_strfreev(tokens);

	candidate = purple_media_candidate_new("foundation?",
									PURPLE_MEDIA_COMPONENT_RTP,
									PURPLE_MEDIA_CANDIDATE_TYPE_HOST,
									PURPLE_MEDIA_NETWORK_PROTOCOL_UDP, ip, port);
	candidates = g_list_append(candidates, candidate);

	candidate = purple_media_candidate_new("foundation?",
									PURPLE_MEDIA_COMPONENT_RTCP,
									PURPLE_MEDIA_CANDIDATE_TYPE_HOST,
									PURPLE_MEDIA_NETWORK_PROTOCOL_UDP, ip, port + 1);
	candidates = g_list_append(candidates, candidate);

	return candidates;
}*/

static GList *
sipe_media_parse_remote_candidates(GSList *sdp_attrs)
{
	PurpleMediaCandidate *candidate;
	GList *candidates = NULL;
	const gchar *attr;
	int i = 0;

	gchar* username = NULL;
	gchar* password = NULL;

	while ((attr = sipe_utils_nameval_find_instance(sdp_attrs, "a", i++))) {
		const char ICE_UFRAG[] = "ice-ufrag:";
		const char ICE_PWD[] = "ice-pwd:";
		const char CANDIDATE[] = "candidate:";

		if (g_str_has_prefix(attr, ICE_UFRAG) && !username) {
			username = g_strdup(attr + sizeof (ICE_UFRAG) - 1);
		} else if (g_str_has_prefix(attr, ICE_PWD) && !password) {
			password = g_strdup(attr + sizeof (ICE_PWD) - 1);
		} else if (g_str_has_prefix(attr, CANDIDATE)) {
			gchar **tokens;
			gchar *foundation;
			PurpleMediaComponentType component;
			PurpleMediaNetworkProtocol protocol;
			guint32 priority;
			gchar* ip;
			guint16 port;
			PurpleMediaCandidateType type;

			tokens = g_strsplit_set(attr + sizeof (CANDIDATE) - 1, " ", 0);

			foundation = tokens[0];

			switch (atoi(tokens[1])) {
				case 1:
					component = PURPLE_MEDIA_COMPONENT_RTP;
					break;
				case 2:
					component = PURPLE_MEDIA_COMPONENT_RTCP;
					break;
				default:
					component = PURPLE_MEDIA_COMPONENT_NONE;
			}

			if (sipe_strequal(tokens[2], "UDP"))
				protocol = PURPLE_MEDIA_NETWORK_PROTOCOL_UDP;
			else {
				// Ignore TCP candidates, at least for now...
				g_strfreev(tokens);
				continue;
			}

			priority = atoi(tokens[3]);
			ip = tokens[4];
			port = atoi(tokens[5]);

			if (sipe_strequal(tokens[7], "host"))
				type = PURPLE_MEDIA_CANDIDATE_TYPE_HOST;
			else if (sipe_strequal(tokens[7], "relay"))
				type = PURPLE_MEDIA_CANDIDATE_TYPE_RELAY;
			else if (sipe_strequal(tokens[7], "srflx"))
				type = PURPLE_MEDIA_CANDIDATE_TYPE_SRFLX;
			else {
				g_strfreev(tokens);
				continue;
			}

			candidate = purple_media_candidate_new(foundation, component,
									type, protocol, ip, port);
			g_object_set(candidate, "priority", priority, NULL);
			candidates = g_list_append(candidates, candidate);

			g_strfreev(tokens);
		}
	}

	if (!candidates) {
		// No a=candidate in SDP message, revert to OC2005 behaviour
		gchar **tokens = g_strsplit(sipe_utils_nameval_find(sdp_attrs, "o"), " ", 6);
		gchar *ip = g_strdup(tokens[5]);
		guint port;

		g_strfreev(tokens);

		tokens = g_strsplit(sipe_utils_nameval_find(sdp_attrs, "m"), " ", 3);
		port = atoi(tokens[1]);
		g_strfreev(tokens);

		candidate = purple_media_candidate_new("foundation",
										PURPLE_MEDIA_COMPONENT_RTP,
										PURPLE_MEDIA_CANDIDATE_TYPE_HOST,
										PURPLE_MEDIA_NETWORK_PROTOCOL_UDP, ip, port);
		candidates = g_list_append(candidates, candidate);

		candidate = purple_media_candidate_new("foundation",
										PURPLE_MEDIA_COMPONENT_RTCP,
										PURPLE_MEDIA_CANDIDATE_TYPE_HOST,
										PURPLE_MEDIA_NETWORK_PROTOCOL_UDP, ip, port + 1);
		candidates = g_list_append(candidates, candidate);
	}

	if (username) {
		GList *it = candidates;
		while (it) {
			g_object_set(it->data, "username", username, "password", password, NULL);
			it = it->next;
		}
	}

	g_free(username);
	g_free(password);

	return candidates;
}

static gchar *
sipe_media_sdp_codec_ids_format(GList *codecs)
{
	GString *result = g_string_new(NULL);

	while (codecs) {
		PurpleMediaCodec *c = codecs->data;

		gchar *tmp = g_strdup_printf(" %d", purple_media_codec_get_id(c));
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
		PurpleMediaCodec *c = codecs->data;

		gchar *tmp = g_strdup_printf("a=rtpmap:%d %s/%d\r\n",
			purple_media_codec_get_id(c),
			purple_media_codec_get_encoding_name(c),
			purple_media_codec_get_clock_rate(c));

		g_string_append(result, tmp);
		g_free(tmp);

		codecs = codecs->next;
	}

	return g_string_free(result, FALSE);
}

static gchar *
sipe_media_sdp_candidates_format(GList *candidates, sipe_media_call* call, gboolean remote_candidate)
{
	GString *result = g_string_new(NULL);
	gchar *tmp;
	gchar *username = purple_media_candidate_get_username(candidates->data);
	gchar *password = purple_media_candidate_get_password(candidates->data);
	guint16 rtcp_port = 0;

	tmp = g_strdup_printf("a=ice-ufrag:%s\r\na=ice-pwd:%s\r\n",username, password);
	g_string_append(result, tmp);
	g_free(tmp);


	while (candidates) {
		PurpleMediaCandidate *c = candidates->data;

		guint16 port;
		guint16 component;
		gchar *protocol;
		gchar *type;

		port = purple_media_candidate_get_port(c);

		switch (purple_media_candidate_get_component_id(c)) {
			case PURPLE_MEDIA_COMPONENT_RTP:
				component = 1;
				break;
			case PURPLE_MEDIA_COMPONENT_RTCP:
				component = 2;
				if (rtcp_port == 0)
					rtcp_port = port;
				break;
		}

		switch (purple_media_candidate_get_protocol(c)) {
			case PURPLE_MEDIA_NETWORK_PROTOCOL_TCP:
				protocol = "TCP";
				break;
			case PURPLE_MEDIA_NETWORK_PROTOCOL_UDP:
				protocol = "UDP";
				break;
		}

		switch (purple_media_candidate_get_candidate_type(c)) {
			case PURPLE_MEDIA_CANDIDATE_TYPE_HOST:
				type = "host";
				break;
			case PURPLE_MEDIA_CANDIDATE_TYPE_RELAY:
				type = "relay";
				break;
			case PURPLE_MEDIA_CANDIDATE_TYPE_SRFLX:
				type = "srflx";
				break;
			default:
				// TODO: error unknown/unsupported type
				break;
		}

		tmp = g_strdup_printf("a=candidate:%s %u %s %u %s %d typ %s \r\n",
			purple_media_candidate_get_foundation(c),
			component,
			protocol,
			purple_media_candidate_get_priority(c),
			purple_media_candidate_get_ip(c),
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
		"a=encryption:rejected\r\n"
		,ip, ip, local_port, sdp_codec_ids, sdp_candidates, sdp_codecs);

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

	if (!purple_media_accepted(media, NULL, NULL)) {
		call->sdp_response = sipe_media_create_sdp(call, FALSE);
		send_sip_response(account->gc, call->invitation, 183, "Session Progress", call->sdp_response);
	} else {
		send_sip_response(account->gc, call->invitation, 200, "OK", call->sdp_response);
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
	} else if (type == PURPLE_MEDIA_INFO_HANGUP) {
		if (local)
			send_sip_request(sip->gc, "BYE", call->dialog->with, call->dialog->with,
							NULL, NULL, call->dialog, NULL);
		sipe_media_call_free(call);
		sip->media_call = NULL;
	}
}

static GSList *
sipe_media_parse_sdp_frame(gchar *frame)
{
	gchar	**lines = g_strsplit(frame, "\r\n", 0);
	GSList	*sdp_attrs = NULL;

	gboolean result = sipe_utils_parse_lines(&sdp_attrs, lines, "=");
	g_strfreev(lines);

	if (result == FALSE) {
		sipe_utils_nameval_free(sdp_attrs);
		return NULL;
	}

	return sdp_attrs;
}

void sipe_media_incoming_invite(struct sipe_account_data *sip, struct sipmsg *msg)
{
	PurpleMediaManager			*manager = purple_media_manager_get();
	PurpleMedia					*media;

	sipe_media_call				*call;
	struct sip_dialog			*dialog;

	gchar *newTag;
	const gchar *oldHeader;
	gchar *newHeader;

	GParameter *params;

	if (sip->media_call) {
		const gchar *incoming_callid = sipmsg_find_header(msg, "Call-ID");
		if (sipe_strequal(sip->media_call->dialog->callid, incoming_callid)) {
			gchar *rsp;
			sipe_media_call *call = sip->media_call;
			sipe_utils_nameval_free(call->sdp_attrs);
			call->sdp_attrs = NULL;
			call->sdp_attrs = sipe_media_parse_sdp_frame(msg->body);

			call->remote_codecs = sipe_media_parse_remote_codecs(call);
			call->remote_codecs = sipe_media_prune_remote_codecs(call->media, call->remote_codecs);
			if (!call->remote_codecs) {
				// TODO: error no remote codecs
			}
			if (purple_media_set_remote_codecs(call->media, "sipe-voice", call->dialog->with,
					call->remote_codecs) == FALSE)
				printf("ERROR SET REMOTE CODECS"); // TODO

			rsp = sipe_media_create_sdp(sip->media_call, TRUE);
			send_sip_response(sip->gc, msg, 200, "OK", rsp);
			g_free(rsp);
		} else {
			// TODO:
			printf("MEDIA SESSION ALREADY IN PROGRESS");
		}
		return;
	}

	newTag = gentag();
	oldHeader = sipmsg_find_header(msg, "To");
	newHeader = g_strdup_printf("%s;tag=%s", oldHeader, newTag);
	sipmsg_remove_header_now(msg, "To");
	sipmsg_add_header_now(msg, "To", newHeader);
	g_free(newHeader);

	dialog = g_new0(struct sip_dialog, 1);
	dialog->callid = g_strdup(sipmsg_find_header(msg, "Call-ID"));
	dialog->with = parse_from(sipmsg_find_header(msg, "From"));
	sipe_dialog_parse(dialog, msg, FALSE);

	call = g_new0(sipe_media_call, 1);
	call->dialog = dialog;
	call->sdp_attrs = sipe_media_parse_sdp_frame(msg->body);
	call->invitation = msg;


	media = purple_media_manager_create_media(manager, sip->account,
							"fsrtpconference", dialog->with, FALSE);

	call->media = media;

	g_signal_connect(G_OBJECT(media), "stream-info",
						G_CALLBACK(sipe_media_stream_info_cb), sip);
	g_signal_connect_swapped(G_OBJECT(media), "candidates-prepared",
						G_CALLBACK(sipe_media_session_ready_cb), call);

	params = g_new0(GParameter, 2);
	params[0].name = "controlling-mode";
	g_value_init(&params[0].value, G_TYPE_BOOLEAN);
	g_value_set_boolean(&params[0].value, FALSE);
	params[1].name = "compatibility-mode";
	g_value_init(&params[1].value, G_TYPE_UINT);
	g_value_set_uint(&params[1].value, NICE_COMPATIBILITY_OC2007R2);

	/*purple_media_add_stream(media, "sipe-voice", dialog->with,
							PURPLE_MEDIA_AUDIO, FALSE, "rawudp", 0, NULL);*/
	purple_media_add_stream(media, "sipe-voice", dialog->with,
							PURPLE_MEDIA_AUDIO, FALSE, "nice", 2, params);

	call->remote_candidates = sipe_media_parse_remote_candidates(call->sdp_attrs);
	if (!call->remote_candidates) {
		// TODO: error no remote candidates
	}
	purple_media_add_remote_candidates(media, "sipe-voice", dialog->with,
			                           call->remote_candidates);

	call->remote_codecs = sipe_media_parse_remote_codecs(call);
	call->remote_codecs = sipe_media_prune_remote_codecs(media, call->remote_codecs);
	if (!call->remote_codecs) {
		// TODO: error no remote codecs
	}
	if (purple_media_set_remote_codecs(media, "sipe-voice", dialog->with,
			call->remote_codecs) == FALSE)
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
