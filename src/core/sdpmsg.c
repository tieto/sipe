/**
 * @file sdpmsg.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2013 SIPE Project <http://sipe.sourceforge.net/>
 * Copyright (C) 2010 Jakub Adam <jakub.adam@ktknet.cz>
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
#include <string.h>

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

			media->name = g_strdup(parts[0]);
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

static struct sdpcandidate * sdpcandidate_copy(struct sdpcandidate *candidate);
static void sdpcandidate_free(struct sdpcandidate *candidate);

static SipeComponentType
parse_component(const gchar *str)
{
	switch (atoi(str)) {
		case 1: return  SIPE_COMPONENT_RTP;
		case 2: return  SIPE_COMPONENT_RTCP;
		default: return SIPE_COMPONENT_NONE;
	}
}

static gchar *
base64_pad(const gchar* str)
{
	size_t str_len = strlen(str);
	int mod = str_len % 4;

	if (mod > 0) {
		gchar *result = NULL;
		int pad = 4 - mod;
		gchar *ptr = result = g_malloc(str_len + pad + 1);

		memcpy(ptr, str, str_len);
		ptr += str_len;
		memset(ptr, '=', pad);
		ptr += pad;
		*ptr = '\0';

		return result;
	} else
		return g_strdup(str);
}

static GSList *
parse_append_candidate_draft_6(gchar **tokens, GSList *candidates)
{
	struct sdpcandidate *candidate = g_new0(struct sdpcandidate, 1);

	candidate->username = base64_pad(tokens[0]);
	candidate->component = parse_component(tokens[1]);
	candidate->password = base64_pad(tokens[2]);

	if (sipe_strequal(tokens[3], "UDP"))
		candidate->protocol = SIPE_NETWORK_PROTOCOL_UDP;
	else if (sipe_strequal(tokens[3], "TCP"))
		candidate->protocol = SIPE_NETWORK_PROTOCOL_TCP_ACTIVE;
	else {
		sdpcandidate_free(candidate);
		return candidates;
	}

	candidate->priority = atoi(tokens[4] + 2);
	candidate->ip = g_strdup(tokens[5]);
	candidate->port = atoi(tokens[6]);

	candidates = g_slist_append(candidates, candidate);

	// draft 6 candidates are both active and passive
	if (candidate->protocol == SIPE_NETWORK_PROTOCOL_TCP_ACTIVE) {
		candidate = sdpcandidate_copy(candidate);
		candidate->protocol = SIPE_NETWORK_PROTOCOL_TCP_PASSIVE;
		candidates = g_slist_append(candidates, candidate);
	}

	return candidates;
}

static GSList *
parse_append_candidate_rfc_5245(gchar **tokens, GSList *candidates)
{
	struct sdpcandidate *candidate = g_new0(struct sdpcandidate, 1);

	candidate->foundation = g_strdup(tokens[0]);
	candidate->component = parse_component(tokens[1]);

	if (sipe_strequal(tokens[2], "UDP"))
		candidate->protocol = SIPE_NETWORK_PROTOCOL_UDP;
	else if (sipe_strequal(tokens[2], "TCP-ACT"))
		candidate->protocol = SIPE_NETWORK_PROTOCOL_TCP_ACTIVE;
	else if (sipe_strequal(tokens[2], "TCP-PASS"))
		candidate->protocol = SIPE_NETWORK_PROTOCOL_TCP_PASSIVE;
	else {
		sdpcandidate_free(candidate);
		return candidates;
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
		sdpcandidate_free(candidate);
		return candidates;
	}

	return g_slist_append(candidates, candidate);
}

static GSList *
parse_candidates(GSList *attrs, SipeIceVersion *ice_version)
{
	GSList *candidates = NULL;
	const gchar *attr;
	int i = 0;

	while ((attr = sipe_utils_nameval_find_instance(attrs, "candidate", i++))) {
		gchar **tokens = g_strsplit_set(attr, " ", 0);

		if (sipe_strequal(tokens[6], "typ")) {
			candidates = parse_append_candidate_rfc_5245(tokens, candidates);
			if (candidates)
				*ice_version = SIPE_ICE_RFC_5245;
		} else {
			candidates = parse_append_candidate_draft_6(tokens, candidates);
			if (candidates)
				*ice_version = SIPE_ICE_DRAFT_6;
		}

		g_strfreev(tokens);
	}

	if (!candidates)
		*ice_version = SIPE_ICE_NO_ICE;

	if (*ice_version == SIPE_ICE_RFC_5245) {
		const gchar *username = sipe_utils_nameval_find(attrs, "ice-ufrag");
		const gchar *password = sipe_utils_nameval_find(attrs, "ice-pwd");

		if (username && password) {
			GSList *i;
			for (i = candidates; i; i = i->next) {
				struct sdpcandidate *c = i->data;
				c->username = g_strdup(username);
				c->password = g_strdup(password);
			}
		}
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

	if (!parse_attributes(smsg, msg)) {
		sdpmsg_free(smsg);
		return NULL;
	}

	for (i = smsg->media; i; i = i->next) {
		struct sdpmedia *media = i->data;
		SipeMediaType type;

		media->candidates = parse_candidates(media->attributes,
						     &smsg->ice_version);

		if (!media->candidates && media->port != 0) {
			// No a=candidate in SDP message, this seems to be MSOC 2005
			media->candidates = create_legacy_candidates(smsg->ip, media->port);
		}

		if (sipe_strequal(media->name, "audio"))
			type = SIPE_MEDIA_AUDIO;
		else if (sipe_strequal(media->name, "video"))
			type = SIPE_MEDIA_VIDEO;
		else {
			// Unknown media type
			sdpmsg_free(smsg);
			return NULL;
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
			GString *param_str = g_string_new(NULL);
			int written_params = 0;

			g_string_append_printf(param_str, "a=fmtp:%d", c->id);

			for (; params; params = params->next) {
				struct sipnameval* par = params->data;
				if (sipe_strequal(par->name, "farsight-send-profile")) {
					// Lync AVMCU doesn't like this property.
					continue;
				}

				g_string_append_printf(param_str, " %s=%s",
						       par->name, par->value);
				++written_params;
			}

			g_string_append(param_str, "\r\n");

			if (written_params > 0) {
				g_string_append(result, param_str->str);
			}

			g_string_free(param_str, TRUE);
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
base64_unpad(const gchar *str)
{
	gchar *result = g_strdup(str);
	gchar *ptr;

	for (ptr = result + strlen(result); ptr != result; --ptr) {
		if (*(ptr - 1) != '=') {
			*ptr = '\0';
			break;
		}
	}

	return result;
}

static gchar *
candidates_to_string(GSList *candidates, SipeIceVersion ice_version)
{
	GString *result = g_string_new("");
	GSList *i;
	GSList *processed_tcp_candidates = NULL;

	for (i = candidates; i; i = i->next) {
		struct sdpcandidate *c = i->data;
		const gchar *protocol;
		const gchar *type;
		gchar *related = NULL;

		if (ice_version == SIPE_ICE_RFC_5245) {

			switch (c->protocol) {
				case SIPE_NETWORK_PROTOCOL_TCP_ACTIVE:
					protocol = "TCP-ACT";
					break;
				case SIPE_NETWORK_PROTOCOL_TCP_PASSIVE:
					protocol = "TCP-PASS";
					break;
				case SIPE_NETWORK_PROTOCOL_UDP:
					protocol = "UDP";
					break;
				default:
					/* error unknown/unsupported type */
					protocol = "UNKNOWN";
					break;
			}

			switch (c->type) {
				case SIPE_CANDIDATE_TYPE_HOST:
					type = "host";
					break;
				case SIPE_CANDIDATE_TYPE_RELAY:
					type = "relay";
					related = g_strdup_printf("raddr %s rport %d ",
								  c->base_ip,
								  c->base_port);
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
					/* error unknown/unsupported type */
					type = "unknown";
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

		} else if (ice_version == SIPE_ICE_DRAFT_6) {
			gchar *username;
			gchar *password;

			switch (c->protocol) {
				case SIPE_NETWORK_PROTOCOL_TCP_ACTIVE:
				case SIPE_NETWORK_PROTOCOL_TCP_PASSIVE: {
					GSList *prev_cand = processed_tcp_candidates;
					for (; prev_cand; prev_cand = prev_cand->next) {
						struct sdpcandidate *c2 = (struct sdpcandidate *)prev_cand->data;

						if (sipe_strequal(c->ip, c2->ip) &&
						    c->component == c2->component) {
							break;
						}
					}

					if (prev_cand) {
						protocol = NULL;
					} else {
						protocol = "TCP";
						processed_tcp_candidates =
							g_slist_append(processed_tcp_candidates, c);
					}
					break;
				}
				case SIPE_NETWORK_PROTOCOL_UDP:
					protocol = "UDP";
					break;
				default:
					/* unknown/unsupported type, ignore */
					protocol = NULL;
					break;
			}

			if (!protocol) {
				continue;
			}

			username = base64_unpad(c->username);
			password = base64_unpad(c->password);

			g_string_append_printf(result,
					       "a=candidate:%s %u %s %s 0.%u %s %d\r\n",
					       username,
					       c->component,
					       password,
					       protocol,
					       c->priority,
					       c->ip,
					       c->port);

			g_free(username);
			g_free(password);
		}
	}

	g_slist_free(processed_tcp_candidates);

	return g_string_free(result, FALSE);
}

static gchar *
remote_candidates_to_string(GSList *candidates, SipeIceVersion ice_version)
{
	GString *result = g_string_new("");

	if (candidates) {
		if (ice_version == SIPE_ICE_RFC_5245) {
			GSList *i;
			g_string_append(result, "a=remote-candidates:");

			for (i = candidates; i; i = i->next) {
				struct sdpcandidate *c = i->data;
				g_string_append_printf(result, "%u %s %u ",
						       c->component, c->ip, c->port);
			}

			g_string_append(result, "\r\n");
		} else if (ice_version == SIPE_ICE_DRAFT_6) {
			struct sdpcandidate *c = candidates->data;
			g_string_append_printf(result, "a=remote-candidate:%s\r\n",
					       c->username);
		}
	}

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

static gchar *
media_to_string(const struct sdpmsg *msg, const struct sdpmedia *media)
{
	gchar *media_str;

	gchar *media_conninfo = NULL;

	gchar *codecs_str = NULL;
	gchar *codec_ids_str = codec_ids_to_string(media->codecs);

	gchar *candidates_str = NULL;
	gchar *remote_candidates_str = NULL;

	gchar *tcp_setup_str = NULL;
	gchar *attributes_str = NULL;
	gchar *credentials = NULL;

	gboolean uses_tcp_transport = FALSE;

	if (media->port != 0) {
		if (!sipe_strequal(msg->ip, media->ip)) {
			media_conninfo = g_strdup_printf("c=IN IP4 %s\r\n", media->ip);
		}

		codecs_str = codecs_to_string(media->codecs);
		candidates_str = candidates_to_string(media->candidates, msg->ice_version);
		remote_candidates_str = remote_candidates_to_string(media->remote_candidates,
								    msg->ice_version);

		if (media->remote_candidates) {
			struct sdpcandidate *c = media->remote_candidates->data;
			uses_tcp_transport =
				c->protocol == SIPE_NETWORK_PROTOCOL_TCP_ACTIVE ||
				c->protocol == SIPE_NETWORK_PROTOCOL_TCP_PASSIVE;
			if (uses_tcp_transport) {
				tcp_setup_str = g_strdup_printf(
					"a=connection:existing\r\n"
					"a=setup:%s\r\n",
					(c->protocol == SIPE_NETWORK_PROTOCOL_TCP_ACTIVE) ? "passive" : "active");
			}
		}

		attributes_str = attributes_to_string(media->attributes);

		if (msg->ice_version == SIPE_ICE_RFC_5245 && media->candidates) {
			struct sdpcandidate *c = media->candidates->data;

			credentials = g_strdup_printf("a=ice-ufrag:%s\r\n"
						      "a=ice-pwd:%s\r\n",
						      c->username,
						      c->password);
		}
	}

	media_str = g_strdup_printf("m=%s %d %sRTP/AVP%s\r\n"
				    "%s"
				    "%s"
				    "%s"
				    "%s"
				    "%s"
				    "%s"
				    "%s",
				    media->name, media->port, uses_tcp_transport ? "TCP/" : "", codec_ids_str,
				    media_conninfo ? media_conninfo : "",
				    candidates_str ? candidates_str : "",
				    remote_candidates_str ? remote_candidates_str : "",
				    tcp_setup_str ? tcp_setup_str : "",
				    codecs_str ? codecs_str : "",
				    attributes_str ? attributes_str : "",
				    credentials ? credentials : "");

	g_free(media_conninfo);
	g_free(codecs_str);
	g_free(codec_ids_str);
	g_free(candidates_str);
	g_free(remote_candidates_str);
	g_free(tcp_setup_str);
	g_free(attributes_str);
	g_free(credentials);

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
		gchar *media_str = media_to_string(msg, i->data);
		g_string_append(body, media_str);
		g_free(media_str);
	}

	return g_string_free(body, FALSE);
}

static struct sdpcandidate *
sdpcandidate_copy(struct sdpcandidate *candidate)
{
	if (candidate) {
		struct sdpcandidate *copy = g_new0(struct sdpcandidate, 1);

		copy->foundation = g_strdup(candidate->foundation);
		copy->component  = candidate->component;
		copy->type       = candidate->type;
		copy->protocol   = candidate->protocol;
		copy->priority   = candidate->priority;
		copy->ip         = g_strdup(candidate->ip);
		copy->port       = candidate->port;
		copy->base_ip    = g_strdup(candidate->base_ip);
		copy->base_port  = candidate->base_port;
		copy->username   = g_strdup(candidate->username);
		copy->password   = g_strdup(candidate->password);

		return copy;
	} else
		return NULL;
}

static void
sdpcandidate_free(struct sdpcandidate *candidate)
{
	if (candidate) {
		g_free(candidate->foundation);
		g_free(candidate->ip);
		g_free(candidate->base_ip);
		g_free(candidate->username);
		g_free(candidate->password);
		g_free(candidate);
	}
}

void
sdpcodec_free(struct sdpcodec *codec)
{
	if (codec) {
		g_free(codec->name);
		sipe_utils_nameval_free(codec->parameters);
		g_free(codec);
	}
}

void
sdpmedia_free(struct sdpmedia *media)
{
	if (media) {
		g_free(media->name);
		g_free(media->ip);

		sipe_utils_nameval_free(media->attributes);

		sipe_utils_slist_free_full(media->candidates,
				  (GDestroyNotify) sdpcandidate_free);
		sipe_utils_slist_free_full(media->codecs,
				  (GDestroyNotify) sdpcodec_free);
		sipe_utils_slist_free_full(media->remote_candidates,
				  (GDestroyNotify) sdpcandidate_free);

		g_free(media);
	}
}

void
sdpmsg_free(struct sdpmsg *msg)
{
	if (msg) {
		g_free(msg->ip);
		sipe_utils_slist_free_full(msg->media,
				  (GDestroyNotify) sdpmedia_free);
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
