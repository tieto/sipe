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
parse_attributes(struct sdpmsg *smsg, gchar *msg) {
	gchar		**lines = g_strsplit(msg, "\r\n", 0);
	GSList		*attributes = NULL;
	gchar		**ptr;

	for (ptr = lines; *ptr != NULL; ++ptr) {
		if (g_str_has_prefix(*ptr, "a=")) {
			gchar **parts = g_strsplit(*ptr + 2, ":", 2);
			if(!parts[0]) {
				g_strfreev(parts);
				g_strfreev(lines);
				sipe_utils_nameval_free(attributes);
				return FALSE;
				break;
			}
			attributes = sipe_utils_nameval_add(attributes, parts[0], parts[1]);
			g_strfreev(parts);

		} else if (g_str_has_prefix(*ptr, "o=")) {
			gchar **parts = g_strsplit(*ptr + 2, " ", 6);
			smsg->ip = g_strdup(parts[5]);
			g_strfreev(parts);
		} else if (g_str_has_prefix(*ptr, "m=")) {
			gchar **parts = g_strsplit(*ptr + 2, " ", 3);
			smsg->port = atoi(parts[1]);
			g_strfreev(parts);
		}
	}

	g_strfreev(lines);

	smsg->attributes = attributes;
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
parse_codecs(GSList *attrs)
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
		codec->type = SIPE_MEDIA_AUDIO;

		// TODO: more secure and effective implementation
		while((params = sipe_utils_nameval_find_instance(attrs, "fmtp", j++))) {
			gchar **tokens = g_strsplit_set(params, " ", 0);
			gchar **next = tokens + 1;

			if (atoi(tokens[0]) == codec->id) {
				while (*next) {
					gchar name[50];
					gchar value[50];

					if (sscanf(*next, "%[a-zA-Z0-9]=%s", name, value) == 2)
						codec->attributes = sipe_utils_nameval_add(codec->attributes, name, value);

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
	smsg->legacy = FALSE;

	if (!parse_attributes(smsg, msg)) {
		sdpmsg_free(smsg);
		return NULL;
	}

	smsg->candidates = parse_candidates(smsg->attributes);
	if (!smsg->candidates) {
		// No a=candidate in SDP message, this seems to be pre-OC2007 R2 UAC
		smsg->candidates = create_legacy_candidates(smsg->ip, smsg->port);
		smsg->legacy = TRUE;
	}

	smsg->codecs = parse_codecs(smsg->attributes);

	return smsg;
}

static void
sdpcandidate_free(struct sdpcandidate *candidate)
{
	if (candidate) {
		g_free(candidate->foundation);
		g_free(candidate->ip);
		g_free(candidate);
	}
}

static void
sdpcodec_free(struct sdpcodec *codec)
{
	if (codec) {
		g_free(codec->name);
		sipe_utils_nameval_free(codec->attributes);
		g_free(codec);
	}
}

void
sdpmsg_free(struct sdpmsg *msg)
{
	if (msg) {
		GSList *item;

		sipe_utils_nameval_free(msg->attributes);

		for (item = msg->candidates; item; item = item->next)
			sdpcandidate_free(item->data);
		g_slist_free(msg->candidates);

		for (item = msg->codecs; item; item = item->next)
			sdpcodec_free(item->data);
		g_slist_free(msg->codecs);

		g_free(msg->ip);
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
