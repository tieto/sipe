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

#include "sipe.h"
#include "sipe-media.h"
#include "sipe-dialog.h"
#include "sipe-utils.h"

static void
sipe_media_call_free(sipe_media_call *call)
{
	if (call) {
		sipe_dialog_free(call->dialog);
		sipe_utils_nameval_free(call->sdp_attrs);
		if (call->invitation)
			sipmsg_free(call->invitation);
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

static GList *
sipe_media_parse_remote_candidates(const sipe_media_call *call)
{
	PurpleMediaCandidate *candidate;
	GList *candidates = NULL;

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

static void
sipe_media_session_ready_cb(sipe_media_call *call)
{
	PurpleMedia *media = call->media;
	gchar* with = call->dialog->with;

	if (!purple_media_candidates_prepared(media, NULL, NULL))
		return;

	GList *list = purple_media_get_local_candidates(media, "sipe-voice", with);
	if (list == NULL) {
		// TODO: error no local candidates
	}

	call->local_port = purple_media_candidate_get_port(list->data);

	if (purple_media_accepted(media, NULL, NULL)) {
		PurpleAccount *account = purple_media_get_account(media);
		GList *codecs = sipe_media_parse_remote_codecs(call);
		GList *candidates;
		const char *ip;
		gchar *body;
		gchar *codec_ids;
		gchar *sdp_codecs;

		if (!codecs) {
			// TODO: error no remote codecs
		}

		codecs = sipe_media_prune_remote_codecs(media, codecs);

		if (purple_media_set_remote_codecs(media, "sipe-voice", with, codecs) == FALSE)
			printf("ERROR SET REMOTE CODECS");

		GList *cdcs = purple_media_get_codecs(media, "sipe-voice");
		while (cdcs) {
			PurpleMediaCodec *c = cdcs->data;

			printf("CODEC: %s\n",purple_media_codec_to_string(c));

			cdcs = cdcs->next;
		}

		candidates = sipe_media_parse_remote_candidates(call);
		if (candidates) {
			purple_media_add_remote_candidates(media, "sipe-voice", with, candidates);

			for (; candidates; candidates = g_list_delete_link(candidates, candidates))
				g_object_unref(candidates->data);
		}

		ip = sipe_utils_get_suitable_local_ip(-1);
		sdp_codecs = sipe_media_sdp_codecs_format(codecs);
		codec_ids = sipe_media_sdp_codec_ids_format(codecs);

		body = g_strdup_printf(
			"v=0\r\n"
			"o=- 0 0 IN IP4 %s\r\n"
			"s=session\r\n"
			"c=IN IP4 %s\r\n"
			"b=CT:1000\r\n"
			"t=0 0\r\n"
			"m=audio %d RTP/AVP%s\r\n"
			"%s"
			//"a=encryption:optional\r\n",
			,ip, ip, call->local_port, codec_ids, sdp_codecs);

		send_sip_response(account->gc, call->invitation, 200, "OK", body);

		purple_media_codec_list_free(codecs);
		sipmsg_free(call->invitation);
		call->invitation = NULL;
		g_free(sdp_codecs);
		g_free(codec_ids);
		g_free(body);
	}
}

static void
sipe_media_stream_info_cb(SIPE_UNUSED_PARAMETER PurpleMedia *media,
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

	if (sip->media_call) {
		printf("MEDIA SESSION ALREADY IN PROGRESS");
		return;
	}

	dialog = g_new0(struct sip_dialog, 1);
	dialog->callid = g_strdup(sipmsg_find_header(msg, "Call-ID"));
	dialog->with = parse_from(sipmsg_find_header(msg, "From"));
	sipe_dialog_parse(dialog, msg, FALSE);

	call = g_new0(sipe_media_call, 1);
	call->dialog = dialog;
	call->sdp_attrs = sipe_media_parse_sdp_frame(msg->body);
	call->invitation = msg;

	sip->media_call = call;

	msg->dont_free = TRUE;

	media = purple_media_manager_create_media(manager, sip->account,
							"fsrtpconference", dialog->with, FALSE);

	call->media = media;

	g_signal_connect(G_OBJECT(media), "stream-info",
						G_CALLBACK(sipe_media_stream_info_cb), sip);
	g_signal_connect_swapped(G_OBJECT(media), "candidates-prepared",
						G_CALLBACK(sipe_media_session_ready_cb), call);

	purple_media_add_stream(media, "sipe-voice", dialog->with,
							PURPLE_MEDIA_AUDIO, FALSE, "rawudp", 0, NULL);
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
