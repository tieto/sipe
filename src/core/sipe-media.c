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

void sipe_media_incoming_invite(PurpleAccount *account, struct sipmsg *msg)
{
	struct sipe_account_data *sip = account->gc->proto_data;
	PurpleMediaManager *manager = purple_media_manager_get();
	const gchar *from = sipmsg_find_header(msg,"From");

	PurpleMedia *media = purple_media_manager_create_media(manager, sip->account,
							"fsrtpconference", from, FALSE);
	PurpleMediaCodec		*codec;
	PurpleMediaCandidate	*candidate;

	gchar **lines;
	GList  *codecs		= NULL;
	GList  *candidates	= NULL;
	GSList *sdp_attrs	= NULL;
	const gchar *attr;
	gchar *body;
	int i = 0;

	purple_media_add_stream(media, "sipe-voice", from, PURPLE_MEDIA_AUDIO, FALSE,
							"nice", 0, NULL);

	lines = g_strsplit(msg->body, "\r\n", 0);
	sipe_utils_parse_lines(&sdp_attrs, lines, "=");
	g_strfreev(lines);

	while ((attr = sipe_utils_nameval_find_instance(sdp_attrs, "a", i++))) {
		if (!g_str_has_prefix(attr, "rtpmap:"))
			continue;

		gchar **tokens = g_strsplit_set(attr + 7, " /", 3);

		int id = atoi(tokens[0]);
		gchar* codec_name = tokens[1];
		int clock_rate = atoi(tokens[2]);

		codec = purple_media_codec_new(id, codec_name, PURPLE_MEDIA_AUDIO, clock_rate);
		codecs = g_list_append(codecs, codec);

		g_strfreev(tokens);
	}

	if (codecs) {
		purple_media_set_remote_codecs(media, "sipe-voice", from, codecs);
		purple_media_set_send_codec(media, "sipe-voice", codecs->data);

		for (; codecs; codecs = g_list_delete_link(codecs, codecs))
			g_object_unref(codecs->data);
	}

	gchar **tokens = g_strsplit(sipe_utils_nameval_find(sdp_attrs, "o"), " ", 5);
	gchar *ip = g_strdup(tokens[4]);
	g_strfreev(tokens);

	tokens = g_strsplit(sipe_utils_nameval_find(sdp_attrs, "m"), " ", 3);
	guint port = atoi(tokens[1]);
	g_strfreev(tokens);

	sipe_utils_nameval_free(sdp_attrs);

	candidate = purple_media_candidate_new("foundation?",
									PURPLE_MEDIA_COMPONENT_RTP,
									PURPLE_MEDIA_CANDIDATE_TYPE_HOST,
									PURPLE_MEDIA_NETWORK_PROTOCOL_UDP, ip, port);
	candidates = g_list_append(candidates, candidate);

	purple_media_add_remote_candidates(media, "sipe-voice", from, candidates);

	for (; candidates; candidates = g_list_delete_link(candidates, candidates))
			g_object_unref(candidates->data);

	body = g_strdup_printf(
		"v=0\r\n"
		"o=- 0 0 IN IP4 %s\r\n"
		"s=session\r\n"
		"c=IN IP4 %s\r\n"
		"b=CT:1000\r\n"
		"t=0 0\r\n"
		"m=audio 6804 RTP/AVP 97 111 101\r\n"
		"k=base64:oPI/otNCy6dGWwyVOIPzcIX2iSij5RISzLhSd1WZxG0\r\n"
		"a=rtpmap:97 red/8000\r\n"
		"a=rtpmap:111 SIREN/16000\r\n"
		"a=fmtp:111 bitrate=16000\r\n"
		"a=rtpmap:101 telephone-event/8000\r\n"
		"a=fmtp:101 0-16\r\n"
		"a=encryption:optional\r\n", "192.168.1.2", "192.168.1.2");

	send_sip_response(account->gc, msg, 200, "OK", body);

	g_free(body);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
