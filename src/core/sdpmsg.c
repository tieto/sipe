/**
 * @file sdpmsg.c
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

#include <stdio.h>
#include <stdlib.h>

#include <glib.h>

#include "sipe-backend.h"
#include "sdpmsg.h"
#include "sipe-utils.h"

static gboolean
append_attribute(struct sdpmedia *media, gchar *attr)
{
	gchar **parts = g_strsplit(attr + 2, ":", 2);

	if(!parts[0]) {
		g_strfreev(parts);
		return FALSE;
	}

	media->attributes = sipe_utils_nameval_add(media->attributes,
						   parts[0],
						   parts[1] ? parts[1] : "");
	g_strfreev(parts);
	return TRUE;
}

static gboolean
parse_attributes(struct sdpmsg *smsg, gchar *msg) {
	gchar		**lines = g_strsplit(msg, "\r\n", 0);
	gchar		**ptr = lines;

	while (*ptr != NULL) {
		if (g_str_has_prefix(*ptr, "o=")) {
			gchar **parts = g_strsplit(*ptr + 2, " ", 6);
			smsg->ip = g_strdup(parts[5]);
			g_strfreev(parts);
		} else if (g_str_has_prefix(*ptr, "m=")) {
			gchar **parts = g_strsplit(*ptr + 2, " ", 3);
			struct sdpmedia *media = g_new0(struct sdpmedia, 1);

			smsg->media = g_slist_append(smsg->media, media);

			media->name = parts[0];
			parts[0] = NULL;

			media->port = atoi(parts[1]);

			g_strfreev(parts);

			while (*(++ptr) && !g_str_has_prefix(*ptr, "m=")) {

				if (g_str_has_prefix(*ptr, "a=")) {
					if (!append_attribute(media, *ptr)) {
						g_strfreev(lines);
						return FALSE;
					}
				}
			}
			continue;
		}

		++ptr;
	}

	g_strfreev(lines);

	return TRUE;
}

static void sdpcandidate_free(struct sdpcandidate *candidate);

static GSList *
parse_candidates(GSList *attrs)
{
	GSList *candidates = NULL;
	const gchar *attr;
	int i = 0;

	while ((attr = sipe_utils_nameval_find_instance(attrs, "candidate", i++))) {
		struct sdpcandidate *candidate = g_new0(struct sdpcandidate, 1);
		gchar **tokens = g_strsplit_set(attr, " ", 0);

		candidate->foundation = g_strdup(tokens[0]);

		switch (atoi(tokens[1])) {
			case 1:
				candidate->component = SIPE_COMPONENT_RTP;
				break;
			case 2:
				candidate->component = SIPE_COMPONENT_RTCP;
				break;
			default:
				candidate->component = SIPE_COMPONENT_NONE;
		}

		if (sipe_strequal(tokens[2], "UDP"))
			candidate->protocol = SIPE_NETWORK_PROTOCOL_UDP;
		else {
			// Ignore TCP candidates, at least for now...
			// Also, if this is ICEv6 candidate list, candidates are dropped here
			g_strfreev(tokens);
			sdpcandidate_free(candidate);
			continue;
		}

		candidate->priority = atoi(tokens[3]);
		candidate->ip = g_strdup(tokens[4]);
		candidate->port = atoi(tokens[5]);

		if (sipe_strequal(tokens[7], "host"))
			candidate->type = SIPE_CANDIDATE_TYPE_HOST;
		else if (sipe_strequal(tokens[7], "relay"))
			candidate->type = SIPE_CANDIDATE_TYPE_RELAY;
		else if (sipe_strequal(tokens[7], "srflx"))
			candidate->type = SIPE_CANDIDATE_TYPE_SRFLX;
		else if (sipe_strequal(tokens[7], "prflx"))
			candidate->type = SIPE_CANDIDATE_TYPE_PRFLX;
		else {
			g_strfreev(tokens);
			sdpcandidate_free(candidate);
			continue;
		}

		candidates = g_slist_append(candidates, candidate);

		g_strfreev(tokens);
	}

	return candidates;
}

static GSList *
create_legacy_candidates(gchar *ip, guint16 port)
{
	struct sdpcandidate *candidate;
	GSList *candidates = NULL;

	candidate = g_new0(struct sdpcandidate, 1);
	candidate->foundation = g_strdup("1");
	candidate->component = SIPE_COMPONENT_RTP;
	candidate->type = SIPE_CANDIDATE_TYPE_HOST;
	candidate->protocol = SIPE_NETWORK_PROTOCOL_UDP;
	candidate->ip = g_strdup(ip);
	candidate->port = port;

	candidates = g_slist_append(candidates, candidate);

	candidate = g_new0(struct sdpcandidate, 1);
	candidate->foundation = g_strdup("1");
	candidate->component = SIPE_COMPONENT_RTCP;
	candidate->type = SIPE_CANDIDATE_TYPE_HOST;
	candidate->protocol = SIPE_NETWORK_PROTOCOL_UDP;
	candidate->ip = g_strdup(ip);
	candidate->port = port + 1;

	candidates = g_slist_append(candidates, candidate);

	return candidates;
}

static GSList *
parse_codecs(GSList *attrs, SipeMediaType type)
{
	int i = 0;
	const gchar *attr;
	GSList *codecs = NULL;

	while ((attr = sipe_utils_nameval_find_instance(attrs, "rtpmap", i++))) {
		struct sdpcodec *codec = g_new0(struct sdpcodec, 1);
		gchar **tokens = g_strsplit_set(attr, " /", 3);

		int j = 0;
		const gchar* params;

		codec->id = atoi(tokens[0]);
		codec->name = g_strdup(tokens[1]);
		codec->clock_rate = atoi(tokens[2]);
		codec->type = type;

		// TODO: more secure and effective implementation
		while((params = sipe_utils_nameval_find_instance(attrs, "fmtp", j++))) {
			gchar **tokens = g_strsplit_set(params, " ", 0);
			gchar **next = tokens + 1;

			if (atoi(tokens[0]) == codec->id) {
				while (*next) {
					gchar name[50];
					gchar value[50];

					if (sscanf(*next, "%[a-zA-Z0-9]=%s", name, value) == 2)
						codec->parameters = sipe_utils_nameval_add(codec->parameters, name, value);

					++next;
				}
			}

			g_strfreev(tokens);
		}

		codecs = g_slist_append(codecs, codec);
		g_strfreev(tokens);
	}

	return codecs;
}

struct sdpmsg *
sdpmsg_parse_msg(gchar *msg)
{
	struct sdpmsg *smsg = g_new0(struct sdpmsg, 1);
	GSList *i;

	smsg->legacy = FALSE;

	if (!parse_attributes(smsg, msg)) {
		sdpmsg_free(smsg);
		return NULL;
	}

	for (i = smsg->media; i; i = i->next) {
		struct sdpmedia *media = i->data;
		SipeMediaType type;

		media->candidates = parse_candidates(media->attributes);
		if (!media->candidates && media->port != 0) {
			// No a=candidate in SDP message, this seems to be pre-OC2007 R2 UAC
			media->candidates = create_legacy_candidates(smsg->ip, media->port);
			smsg->legacy = TRUE;
		}

		if (sipe_strequal(media->name, "audio"))
			type = SIPE_MEDIA_AUDIO;
		else if (sipe_strequal(media->name, "video"))
			type = SIPE_MEDIA_VIDEO;
		else {
			// TODO unknown media type
		}

		media->codecs = parse_codecs(media->attributes, type);
	}

	return smsg;
}

static gchar *
codecs_to_string(GSList *codecs)
{
	GString *result = g_string_new(NULL);

	for (; codecs; codecs = codecs->next) {
		struct sdpcodec *c = codecs->data;
		GSList *params = c->parameters;

		g_string_append_printf(result,
				       "a=rtpmap:%d %s/%d\r\n",
				       c->id,
				       c->name,
				       c->clock_rate);

		if (params) {
			g_string_append_printf(result, "a=fmtp:%d", c->id);

			for (; params; params = params->next) {
				struct sipnameval* par = params->data;
				g_string_append_printf(result, " %s=%s",
						       par->name, par->value);
			}

			g_string_append(result, "\r\n");
		}
	}

	return g_string_free(result, FALSE);
}

static gchar *
codec_ids_to_string(GSList *codecs)
{
	GString *result = g_string_new(NULL);

	for (; codecs; codecs = codecs->next) {
		struct sdpcodec *c = codecs->data;
		g_string_append_printf(result, " %d", c->id);
	}

	return g_string_free(result, FALSE);
}

static gchar *
candidates_to_string(GSList *candidates)
{
	GString *result = g_string_new("");

	for (; candidates; candidates = candidates->next) {
		struct sdpcandidate *c = candidates->data;
		const gchar *protocol;
		const gchar *type;
		gchar *related = NULL;

		switch (c->protocol) {
			case SIPE_NETWORK_PROTOCOL_TCP:
				protocol = "TCP";
				break;
			case SIPE_NETWORK_PROTOCOL_UDP:
				protocol = "UDP";
				break;
		}

		switch (c->type) {
			case SIPE_CANDIDATE_TYPE_HOST:
				type = "host";
				break;
			case SIPE_CANDIDATE_TYPE_RELAY:
				type = "relay";
				break;
			case SIPE_CANDIDATE_TYPE_SRFLX:
				type = "srflx";
				related = g_strdup_printf("raddr %s rport %d",
							  c->base_ip,
							  c->base_port);
				break;
			case SIPE_CANDIDATE_TYPE_PRFLX:
				type = "prflx";
				break;
			default:
				// TODO: error unknown/unsupported type
				break;
		}

		g_string_append_printf(result,
				       "a=candidate:%s %u %s %u %s %d typ %s %s\r\n",
				       c->foundation,
				       c->component,
				       protocol,
				       c->priority,
				       c->ip,
				       c->port,
				       type,
				       related ? related : "");

		g_free(related);
	}

	return g_string_free(result, FALSE);
}

static gint
candidate_compare_by_component_id(struct sdpcandidate *c1,
				  struct sdpcandidate *c2)
{
	return c1->component - c2->component;
}

static gchar *
remote_candidates_to_string(GSList *candidates)
{
	GString *result = g_string_new("");

	candidates = g_slist_copy(candidates);
	candidates = g_slist_sort(candidates,
				  (GCompareFunc)candidate_compare_by_component_id);

	if (candidates) {
		GSList *i;
		g_string_append(result, "a=remote-candidates:");

		for (i = candidates; i; i = i->next) {
			struct sdpcandidate *c = i->data;
			g_string_append_printf(result, "%u %s %u ",
					       c->component, c->ip, c->port);
		}

		g_string_append(result, "\r\n");
	}

	g_slist_free(candidates);

	return g_string_free(result, FALSE);
}

static gchar *
attributes_to_string(GSList *attributes)
{
	GString *result = g_string_new("");

	for (; attributes; attributes = attributes->next) {
		struct sipnameval *a = attributes->data;
		g_string_append_printf(result, "a=%s", a->name);
		if (!sipe_strequal(a->value, ""))
			g_string_append_printf(result, ":%s", a->value);
		g_string_append(result, "\r\n");
	}

	return g_string_free(result, FALSE);
}

gchar *
media_to_string(const struct sdpmedia *media, gboolean legacy)
{
	gchar *media_str;

	gchar *codecs_str = codecs_to_string(media->codecs);
	gchar *codec_ids_str = codec_ids_to_string(media->codecs);

	gchar *candidates_str = legacy ? g_strdup("")
				       : candidates_to_string(media->candidates);
	gchar *remote_candidates_str = remote_candidates_to_string(media->remote_candidates);

	gchar *attributes_str = attributes_to_string(media->attributes);

	media_str = g_strdup_printf("m=%s %d RTP/AVP%s\r\n"
				    "%s"
				    "%s"
				    "%s"
				    "%s",
				    media->name, media->port, codec_ids_str,
				    candidates_str,
				    remote_candidates_str,
				    codecs_str,
				    attributes_str);

	g_free(codecs_str);
	g_free(codec_ids_str);
	g_free(candidates_str);
	g_free(remote_candidates_str);
	g_free(attributes_str);

	return media_str;
}

gchar *
sdpmsg_to_string(const struct sdpmsg *msg)
{
	GString *body = g_string_new(NULL);
	GSList *i;

	g_string_append_printf(
		body,
		"v=0\r\n"
		"o=- 0 0 IN IP4 %s\r\n"
		"s=session\r\n"
		"c=IN IP4 %s\r\n"
		"b=CT:99980\r\n"
		"t=0 0\r\n",
		msg->ip, msg->ip);


	for (i = msg->media; i; i = i->next) {
		gchar *media_str = media_to_string(i->data, msg->legacy);
		g_string_append(body, media_str);
		g_free(media_str);
	}

	return g_string_free(body, FALSE);
}

static void
sdpcandidate_free(struct sdpcandidate *candidate)
{
	if (candidate) {
		g_free(candidate->foundation);
		g_free(candidate->ip);
		g_free(candidate->base_ip);
		g_free(candidate);
	}
}

static void
sdpcodec_free(struct sdpcodec *codec)
{
	if (codec) {
		g_free(codec->name);
		sipe_utils_nameval_free(codec->parameters);
		g_free(codec);
	}
}

static void
sdpmedia_free(struct sdpmedia *media)
{
	if (media) {
		GSList *item;

		g_free(media->name);

		sipe_utils_nameval_free(media->attributes);

		for (item = media->candidates; item; item = item->next)
			sdpcandidate_free(item->data);
		g_slist_free(media->candidates);

		for (item = media->codecs; item; item = item->next)
			sdpcodec_free(item->data);
		g_slist_free(media->codecs);

		for (item = media->remote_candidates; item; item = item->next)
			sdpcandidate_free(item->data);
		g_slist_free(media->remote_candidates);

		g_free(media);
	}
}

void
sdpmsg_free(struct sdpmsg *msg)
{
	if (msg) {
		GSList *item;

		g_free(msg->ip);
		for (item = msg->media; item; item = item->next)
			sdpmedia_free(item->data);
		g_slist_free(msg->media);
		g_free(msg);
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
