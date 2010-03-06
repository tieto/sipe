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

#include <libpurple/mediamanager.h>

#include "sipe.h"
#include "sipe-utils.h"

struct _sipe_media_session {
	PurpleMedia		*media;
	gchar			*with;
	GSList			*sdp_attrs;
	guint16			local_port;
	struct sipmsg	*invitation;
};
typedef struct _sipe_media_session sipe_media_session;

void
sipe_media_session_free(sipe_media_session* session)
{
	if (session) {
		g_free(session->with);
		sipe_utils_nameval_free(session->sdp_attrs);
		if (session->invitation)
			sipmsg_free(session->invitation);
		g_free(session);
	}
}

static GList *
sipe_media_parse_remote_codecs(const sipe_media_session *session)
{
	int			i = 0;
	const gchar	*attr;
	GList		*codecs	= NULL;

	while ((attr = sipe_utils_nameval_find_instance(session->sdp_attrs, "a", i++))) {
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

gint
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
sipe_media_parse_remote_candidates(const sipe_media_session *session)
{
	PurpleMediaCandidate *candidate;
	GList *candidates = NULL;

	gchar **tokens = g_strsplit(sipe_utils_nameval_find(session->sdp_attrs, "o"), " ", 6);
	gchar *ip = g_strdup(tokens[5]);
	guint port;

	g_strfreev(tokens);

	tokens = g_strsplit(sipe_utils_nameval_find(session->sdp_attrs, "m"), " ", 3);
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
sipe_media_session_ready_cb(sipe_media_session *session)
{
	PurpleMedia *media = session->media;

	if (!purple_media_candidates_prepared(media, NULL, NULL))
		return;

	GList *list = purple_media_get_local_candidates(media, "sipe-voice", session->with);
	if (list == NULL) {
		// TODO: error no local candidates
	}

	session->local_port = purple_media_candidate_get_port(list->data);

	if (purple_media_accepted(media, NULL, NULL)) {
		PurpleAccount *account = purple_media_get_account(media);
		GList *codecs = sipe_media_parse_remote_codecs(session);
		GList *candidates;
		const char *ip;
		gchar *body;
		gchar *codec_ids;
		gchar *sdp_codecs;

		if (!codecs) {
			// TODO: error no remote codecs
		}

		codecs = sipe_media_prune_remote_codecs(media, codecs);

		if (purple_media_set_remote_codecs(media, "sipe-voice", session->with, codecs) == FALSE)
			printf("ERROR SET REMOTE CODECS");

		GList *cdcs = purple_media_get_codecs(media, "sipe-voice");
		while (cdcs) {
			PurpleMediaCodec *c = cdcs->data;

			printf("CODEC: %s\n",purple_media_codec_to_string(c));

			cdcs = cdcs->next;
		}

		candidates = sipe_media_parse_remote_candidates(session);
		if (candidates) {
			purple_media_add_remote_candidates(media, "sipe-voice", session->with, candidates);

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
			,ip, ip, session->local_port, codec_ids, sdp_codecs);

		send_sip_response(account->gc, session->invitation, 200, "OK", body);

		purple_media_codec_list_free(codecs);
		sipmsg_free(session->invitation);
		session->invitation = NULL;
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
							SIPE_UNUSED_PARAMETER gboolean local,
							sipe_media_session *session)
{
	if (type == PURPLE_MEDIA_INFO_ACCEPT) {
		sipe_media_session_ready_cb(session);
	} else if (type == PURPLE_MEDIA_INFO_REJECT) {
		PurpleAccount *account = purple_media_get_account(media);
		send_sip_response(account->gc, session->invitation, 603, "Decline", NULL);
		sipe_media_session_free(session);
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

void sipe_media_incoming_invite(PurpleAccount *account, struct sipmsg *msg)
{
	struct sipe_account_data	*sip = account->gc->proto_data;

	PurpleMediaManager			*manager = purple_media_manager_get();
	PurpleMedia					*media;

	sipe_media_session			*session;

	session = g_new0(sipe_media_session, 1);
	session->with = parse_from(sipmsg_find_header(msg,"From"));
	session->sdp_attrs = sipe_media_parse_sdp_frame(msg->body);
	session->invitation = msg;

	msg->dont_free = TRUE;

	media = purple_media_manager_create_media(manager, sip->account,
							"fsrtpconference", session->with, FALSE);

	session->media = media;

	g_signal_connect(G_OBJECT(media), "stream-info",
						G_CALLBACK(sipe_media_stream_info_cb), session);
	g_signal_connect_swapped(G_OBJECT(media), "candidates-prepared",
						G_CALLBACK(sipe_media_session_ready_cb), session);

	purple_media_add_stream(session->media, "sipe-voice", session->with,
							PURPLE_MEDIA_AUDIO, FALSE, "rawudp", 0, NULL);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
