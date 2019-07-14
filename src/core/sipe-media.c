/**
 * @file sipe-media.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-2019 SIPE Project <http://sipe.sourceforge.net/>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "sipe-common.h"
#include "sipmsg.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sdpmsg.h"
#include "sipe-conf.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-dialog.h"
#include "sipe-media.h"
#include "sipe-ocs2007.h"
#include "sipe-session.h"
#include "sipe-utils.h"
#include "sipe-nls.h"
#include "sipe-schedule.h"
#include "sipe-xml.h"

/* [MS-SDPEXT] 3.1.5.31.2 says a range size of 100 SHOULD be used for video and
 * some clients really demand this. */
#define VIDEO_SSRC_COUNT 100

struct sipe_media_call_private {
	struct sipe_media_call public;

	/* private part starts here */
	struct sipe_core_private	*sipe_private;

	struct sip_session		*session;
	struct sip_session		*conference_session;

	GSList				*streams;

	struct sipmsg			*invitation;
	SipeIceVersion			 ice_version;
	gboolean			 encryption_compatible;
	gchar				*extra_invite_section;
	gchar				*invite_content_type;

	GSList				*ssrc_ranges;

	struct sdpmsg			*smsg;
	GSList				*failed_media;
	gchar 				*ringing_key;
	gchar 				*timeout_key;
};
#define SIPE_MEDIA_CALL         ((struct sipe_media_call *) call_private)
#define SIPE_MEDIA_CALL_PRIVATE ((struct sipe_media_call_private *) call)

struct sipe_media_stream_private {
	struct sipe_media_stream public;

	gchar *timeout_key;

	guchar *encryption_key;
	int encryption_key_id;
	gboolean remote_candidates_and_codecs_set;
	gboolean established;
#ifdef HAVE_XDATA
	gboolean sdp_negotiation_concluded;
	gboolean writable;
#endif

	GSList *extra_sdp;

	GQueue *write_queue;
	GQueue *async_reads;
	gssize read_pos;

	/* User data associated with the stream. */
	gpointer data;
	GDestroyNotify data_free_func;
};
#define SIPE_MEDIA_STREAM         ((struct sipe_media_stream *) stream_private)
#define SIPE_MEDIA_STREAM_PRIVATE ((struct sipe_media_stream_private *) stream)

#define SIPE_MEDIA_STREAM_CONNECTION_TIMEOUT_SECONDS 30
#define SIPE_MEDIA_CALL_RINGING_TIMEOUT_SECONDS 60
#define SIPE_MEDIA_CALL_TIMEOUT_SECONDS 120

struct async_read_data {
	guint8 *buffer;
	gssize len;
	sipe_media_stream_read_callback callback;
};

static void stream_schedule_cancel_timeout(struct sipe_media_call *call,
					   struct sipe_media_stream_private *stream_private);

static void call_schedule_cancel_request_timeout(struct sipe_media_call *call);
static void call_schedule_cancel_ringing_timeout(struct sipe_media_call *call);

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
sipe_media_stream_free(struct sipe_media_stream_private *stream_private)
{
	struct sipe_media_call_private *call_private;

	call_private = (struct sipe_media_call_private *)SIPE_MEDIA_STREAM->call;

	stream_schedule_cancel_timeout(SIPE_MEDIA_CALL, stream_private);

	sipe_media_stream_set_data(SIPE_MEDIA_STREAM, NULL, NULL);

	if (call_private) {
		call_private->streams = g_slist_remove(call_private->streams,
						       stream_private);

		if (SIPE_MEDIA_STREAM->ssrc_range) {
			call_private->ssrc_ranges =
				g_slist_remove(call_private->ssrc_ranges,
					       SIPE_MEDIA_STREAM->ssrc_range);
			g_free(SIPE_MEDIA_STREAM->ssrc_range);
		}
	}

	if (SIPE_MEDIA_STREAM->backend_private) {
		sipe_backend_media_stream_free(SIPE_MEDIA_STREAM->backend_private);
	}
	g_free(SIPE_MEDIA_STREAM->id);
	g_free(stream_private->encryption_key);
	g_queue_free_full(stream_private->write_queue,
			  (GDestroyNotify)g_byte_array_unref);
	g_queue_free_full(stream_private->async_reads, g_free);
	sipe_utils_nameval_free(stream_private->extra_sdp);
	g_free(stream_private);
}

static gboolean
call_private_equals(SIPE_UNUSED_PARAMETER const gchar *callid,
		    struct sipe_media_call_private *call_private1,
		    struct sipe_media_call_private *call_private2)
{
	return call_private1 == call_private2;
}

static void
sipe_media_call_free(struct sipe_media_call_private *call_private)
{
	if (call_private) {
		g_hash_table_foreach_remove(call_private->sipe_private->media_calls,
					    (GHRFunc) call_private_equals, call_private);

		call_schedule_cancel_request_timeout(SIPE_MEDIA_CALL);
		call_schedule_cancel_ringing_timeout(SIPE_MEDIA_CALL);

		while (call_private->streams) {
			sipe_media_stream_free(call_private->streams->data);
		}

		sipe_backend_media_free(call_private->public.backend_private);

		if (call_private->session) {
			sipe_session_remove(call_private->sipe_private,
					    call_private->session);
		}

		if (call_private->invitation)
			sipmsg_free(call_private->invitation);

		// Frees any referenced extra invite data.
		sipe_media_add_extra_invite_section(SIPE_MEDIA_CALL, NULL, NULL);

		sipe_utils_slist_free_full(call_private->ssrc_ranges, g_free);

		sdpmsg_free(call_private->smsg);
		sipe_utils_slist_free_full(call_private->failed_media,
				  (GDestroyNotify)sdpmedia_free);
		g_free(SIPE_MEDIA_CALL->with);
		g_free(call_private);
	}
}

static gint
candidate_sort_cb(struct sdpcandidate *c1, struct sdpcandidate *c2)
{
	int cmp = g_strcmp0(c1->foundation, c2->foundation);
	if (cmp == 0) {
		cmp = g_strcmp0(c1->username, c2->username);
		if (cmp == 0)
			cmp = c1->component - c2->component;
	}

	return cmp;
}

static GSList *
backend_candidates_to_sdpcandidate(GList *candidates)
{
	GSList *result = NULL;
	GList *i;

	for (i = candidates; i; i = i->next) {
		struct sipe_backend_candidate *candidate = i->data;
		struct sdpcandidate *c;

		gchar *ip = sipe_backend_candidate_get_ip(candidate);
		gchar *base_ip = sipe_backend_candidate_get_base_ip(candidate);
		if (is_empty(ip) || strchr(ip, ':') ||
		    (base_ip && strchr(base_ip, ':'))) {
			/* Ignore IPv6 candidates. */
			g_free(ip);
			g_free(base_ip);
			continue;
		}

		c = g_new(struct sdpcandidate, 1);
		c->foundation = sipe_backend_candidate_get_foundation(candidate);
		c->component = sipe_backend_candidate_get_component_type(candidate);
		c->type = sipe_backend_candidate_get_type(candidate);
		c->protocol = sipe_backend_candidate_get_protocol(candidate);
		c->ip = ip;
		c->port = sipe_backend_candidate_get_port(candidate);
		c->base_ip = base_ip;
		c->base_port = sipe_backend_candidate_get_base_port(candidate);
		c->priority = sipe_backend_candidate_get_priority(candidate);
		c->username = sipe_backend_candidate_get_username(candidate);
		c->password = sipe_backend_candidate_get_password(candidate);

		result = g_slist_insert_sorted(result, c,
					       (GCompareFunc)candidate_sort_cb);
	}

	return result;
}

static void
get_stream_ip_and_ports(GSList *candidates,
			gchar **ip, guint *rtp_port, guint *rtcp_port)
{
	guint32 rtp_max_priority = 0;
	guint32 rtcp_max_priority = 0;

	*ip = 0;
	*rtp_port = 0;
	*rtcp_port = 0;

	for (; candidates; candidates = candidates->next) {
		struct sdpcandidate *candidate = candidates->data;

		if (candidate->component == SIPE_COMPONENT_RTP &&
		    candidate->priority > rtp_max_priority) {
			rtp_max_priority = candidate->priority;
			*rtp_port = candidate->port;

			g_free(*ip);
			*ip = g_strdup(candidate->ip);
		} else if (candidate->component == SIPE_COMPONENT_RTCP &&
			   candidate->priority > rtcp_max_priority) {
			rtcp_max_priority = candidate->priority;
			*rtcp_port = candidate->port;
		}
	}
}

static gint
sdpcodec_compare(gconstpointer a, gconstpointer b)
{
	return ((const struct sdpcodec *)a)->id -
	       ((const struct sdpcodec *)b)->id;
}

static GList *
remove_wrong_farstream_0_1_tcp_candidates(GList *candidates)
{
	GList *i = candidates;
	GHashTable *foundation_to_candidate = g_hash_table_new_full(g_str_hash,
								    g_str_equal,
								    g_free,
								    NULL);

	while (i) {
		GList *next = i->next;
		struct sipe_backend_candidate *c1 = i->data;

		if (sipe_backend_candidate_get_protocol(c1) == SIPE_NETWORK_PROTOCOL_UDP) {
			gchar *foundation                 = sipe_backend_candidate_get_foundation(c1);
			struct sipe_backend_candidate *c2 = g_hash_table_lookup(foundation_to_candidate,
										foundation);

			if (c2) {
				g_free(foundation);

				if (sipe_backend_candidate_get_port(c1) ==
				    sipe_backend_candidate_get_port(c2) ||
				    (sipe_backend_candidate_get_type(c1) !=
				     SIPE_CANDIDATE_TYPE_HOST &&
				     sipe_backend_candidate_get_base_port(c1) ==
				     sipe_backend_candidate_get_base_port(c2))) {
					/*
					 * We assume that RTP+RTCP UDP pairs
					 * that share the same port are
					 * actually mistagged TCP candidates.
					 */
					candidates = g_list_remove(candidates, c2);
					candidates = g_list_delete_link(candidates, i);
					sipe_backend_candidate_free(c1);
					sipe_backend_candidate_free(c2);
				}
			} else
				/* hash table takes ownership of "foundation" */
				g_hash_table_insert(foundation_to_candidate, foundation, c1);
		}

		i = next;
	}

	g_hash_table_destroy(foundation_to_candidate);

	return candidates;
}

static void
fill_zero_tcp_act_ports_from_tcp_pass(GSList *candidates, GSList *all_candidates)
{
	GSList *i;
	GHashTable *ip_to_port = g_hash_table_new(g_str_hash, g_str_equal);

	for (i = candidates; i; i = i->next) {
		struct sdpcandidate *c = i->data;
		GSList *j;

		if (c->protocol != SIPE_NETWORK_PROTOCOL_TCP_ACTIVE) {
			continue;
		}

		for (j = all_candidates; j; j = j->next) {
			struct sdpcandidate *passive = j->data;
			if (passive->protocol != SIPE_NETWORK_PROTOCOL_TCP_PASSIVE ||
			    c->type != passive->type) {
				continue;
			}

			if (sipe_strequal(c->ip, passive->ip) &&
			    sipe_strequal(c->base_ip, passive->base_ip)) {
				if (c->port == 0) {
					c->port = passive->port;
				}

				if (c->base_port == 0) {
					c->base_port = passive->base_port;
				}
				break;
			}
		}
	}

	for (i = all_candidates; i; i = i->next) {
		struct sdpcandidate *c = i->data;

		if (c->protocol == SIPE_NETWORK_PROTOCOL_TCP_PASSIVE &&
		    c->type == SIPE_CANDIDATE_TYPE_HOST) {
			g_hash_table_insert(ip_to_port, c->ip, &c->port);
		}
	}

	/* Fill base ports of all TCP relay candidates using what we have
	 * collected from host candidates. */
	for (i = candidates; i; i = i->next) {
		struct sdpcandidate *c = i->data;
		if (c->type == SIPE_CANDIDATE_TYPE_RELAY && c->base_port == 0) {
			guint *base_port = (guint*)g_hash_table_lookup(ip_to_port, c->base_ip);
			if (base_port) {
				c->base_port = *base_port;
			} else {
				SIPE_DEBUG_WARNING("Couldn't determine base port for candidate "
						   "with foundation %s", c->foundation);
			}
		}
	}

	g_hash_table_destroy(ip_to_port);
}

static SipeEncryptionPolicy
get_encryption_policy(struct sipe_core_private *sipe_private)
{
	SipeEncryptionPolicy result =
			sipe_backend_media_get_encryption_policy(SIPE_CORE_PUBLIC);
	if (result == SIPE_ENCRYPTION_POLICY_OBEY_SERVER) {
		result = sipe_private->server_av_encryption_policy;
	}

	return result;
}

static struct sdpmedia *
media_stream_to_sdpmedia(struct sipe_media_call_private *call_private,
			 struct sipe_media_stream_private *stream_private)
{
	struct sdpmedia *sdpmedia = g_new0(struct sdpmedia, 1);
	GList *codecs = sipe_backend_get_local_codecs(SIPE_MEDIA_CALL,
						      SIPE_MEDIA_STREAM);
	SipeEncryptionPolicy encryption_policy =
			get_encryption_policy(call_private->sipe_private);
	guint rtcp_port = 0;
	SipeMediaType type;
	GSList *attributes = NULL;
	GSList *sdpcandidates;
	GSList *all_sdpcandidates;
	GList *candidates;
	GList *i;
	GSList *j;

	sdpmedia->name = g_strdup(SIPE_MEDIA_STREAM->id);

	if (sipe_strequal(sdpmedia->name, "audio"))
		type = SIPE_MEDIA_AUDIO;
	else if (sipe_strequal(sdpmedia->name, "video"))
		type = SIPE_MEDIA_VIDEO;
	else if (sipe_strequal(sdpmedia->name, "data"))
		type = SIPE_MEDIA_APPLICATION;
	else if (sipe_strequal(sdpmedia->name, "applicationsharing"))
		type = SIPE_MEDIA_APPLICATION;
	else {
		// TODO: incompatible media, should not happen here
		g_free(sdpmedia->name);
		g_free(sdpmedia);
		sipe_media_codec_list_free(codecs);
		return(NULL);
	}

	// Process codecs
	for (i = codecs; i; i = i->next) {
		struct sipe_backend_codec *codec = i->data;
		struct sdpcodec *c = g_new0(struct sdpcodec, 1);
		GList *params;

		c->id = sipe_backend_codec_get_id(codec);
		c->name = sipe_backend_codec_get_name(codec);
		c->clock_rate = sipe_backend_codec_get_clock_rate(codec);
		c->type = type;

		params = sipe_backend_codec_get_optional_parameters(codec);
		for (; params; params = params->next) {
			struct sipnameval *param = params->data;
			struct sipnameval *copy = g_new0(struct sipnameval, 1);

			copy->name = g_strdup(param->name);
			copy->value = g_strdup(param->value);

			c->parameters = g_slist_append(c->parameters, copy);
		}

		/* Buggy(?) codecs may report non-unique id (a.k.a. payload
		 * type) that must not appear in SDP messages we send. Thus,
		 * let's ignore any codec having the same id as one we already
		 * have in the converted list. */
		if (g_slist_find_custom(sdpmedia->codecs, c, sdpcodec_compare)) {
			sdpcodec_free(c);
		} else {
			sdpmedia->codecs = g_slist_append(sdpmedia->codecs, c);
		}
	}

	sipe_media_codec_list_free(codecs);

	// Process local candidates
	// If we have established candidate pairs, send them in SDP response.
	// Otherwise send all available local candidates.
	candidates = sipe_backend_media_stream_get_active_local_candidates(SIPE_MEDIA_STREAM);
	sdpcandidates = backend_candidates_to_sdpcandidate(candidates);
	sipe_media_candidate_list_free(candidates);

	candidates = sipe_backend_get_local_candidates(SIPE_MEDIA_CALL,
						       SIPE_MEDIA_STREAM);
	candidates = remove_wrong_farstream_0_1_tcp_candidates(candidates);
	all_sdpcandidates = backend_candidates_to_sdpcandidate(candidates);
	sipe_media_candidate_list_free(candidates);

	if (!sdpcandidates) {
		sdpcandidates = all_sdpcandidates;
	}

	fill_zero_tcp_act_ports_from_tcp_pass(sdpcandidates, all_sdpcandidates);

	sdpmedia->candidates = sdpcandidates;

	if (all_sdpcandidates != sdpcandidates) {
		sipe_utils_slist_free_full(all_sdpcandidates,
					   (GDestroyNotify)sdpcandidate_free);
	}

	get_stream_ip_and_ports(sdpmedia->candidates, &sdpmedia->ip,
				&sdpmedia->port, &rtcp_port);

	if (sipe_backend_stream_is_held(SIPE_MEDIA_STREAM))
		attributes = sipe_utils_nameval_add(attributes, "inactive", "");

	if (rtcp_port) {
		gchar *tmp = g_strdup_printf("%u", rtcp_port);
		attributes  = sipe_utils_nameval_add(attributes, "rtcp", tmp);
		g_free(tmp);
	}

	if (encryption_policy != call_private->sipe_private->server_av_encryption_policy) {
		const gchar *encryption = NULL;
		switch (encryption_policy) {
			case SIPE_ENCRYPTION_POLICY_REJECTED:
				encryption = "rejected";
				break;
			case SIPE_ENCRYPTION_POLICY_OPTIONAL:
				encryption = "optional";
				break;
			case SIPE_ENCRYPTION_POLICY_REQUIRED:
			default:
				encryption = "required";
				break;
		}

		attributes = sipe_utils_nameval_add(attributes, "encryption", encryption);
	}

	if (SIPE_MEDIA_STREAM->ssrc_range) {
		gchar *tmp;

		tmp = g_strdup_printf("%u-%u",
				      SIPE_MEDIA_STREAM->ssrc_range->begin,
				      SIPE_MEDIA_STREAM->ssrc_range->end);
		attributes = sipe_utils_nameval_add(attributes,
						    "x-ssrc-range", tmp);
		g_free(tmp);
	}

	// Process remote candidates
	candidates = sipe_backend_media_stream_get_active_remote_candidates(SIPE_MEDIA_STREAM);
	sdpmedia->remote_candidates = backend_candidates_to_sdpcandidate(candidates);
	sipe_media_candidate_list_free(candidates);

	sdpmedia->encryption_active = stream_private->encryption_key &&
				      call_private->encryption_compatible &&
				      stream_private->remote_candidates_and_codecs_set &&
				      encryption_policy != SIPE_ENCRYPTION_POLICY_REJECTED;

	// Set our key if encryption is enabled.
	if (stream_private->encryption_key &&
	    encryption_policy != SIPE_ENCRYPTION_POLICY_REJECTED) {
		sdpmedia->encryption_key = g_memdup(stream_private->encryption_key,
						    SIPE_SRTP_KEY_LEN);
		sdpmedia->encryption_key_id = stream_private->encryption_key_id;
	}

	// Append extra attributes assigned to the stream.
	for (j = stream_private->extra_sdp; j; j = g_slist_next(j)) {
		struct sipnameval *attr = j->data;
		attributes = sipe_utils_nameval_add(attributes,
						    attr->name, attr->value);
	}

	sdpmedia->attributes = attributes;

	return sdpmedia;
}

static struct sdpmsg *
sipe_media_to_sdpmsg(struct sipe_media_call_private *call_private)
{
	struct sdpmsg *msg = g_new0(struct sdpmsg, 1);
	GSList *streams = call_private->streams;

	for (; streams; streams = streams->next) {
		struct sdpmedia *media = media_stream_to_sdpmedia(call_private,
								  streams->data);
		if (media) {
			msg->media = g_slist_append(msg->media, media);

			if (msg->ip == NULL)
				msg->ip = g_strdup(media->ip);
		}
	}

	msg->media = g_slist_concat(msg->media, call_private->failed_media);
	call_private->failed_media = NULL;

	msg->ice_version = call_private->ice_version;

	return msg;
}

static void
sipe_invite_call(struct sipe_media_call_private *call_private, TransCallback tc)
{
	struct sipe_core_private *sipe_private = call_private->sipe_private;
	gchar *hdr;
	gchar *contact;
	gchar *p_preferred_identity = NULL;
	gchar *body;
	struct sip_dialog *dialog;
	struct sdpmsg *msg;

	dialog = sipe_media_get_sip_dialog(SIPE_MEDIA_CALL);

	contact = get_contact(sipe_private);

	if (sipe_private->uc_line_uri) {
		gchar *self = sip_uri_self(sipe_private);
		p_preferred_identity = g_strdup_printf(
			"P-Preferred-Identity: <%s>, <%s>\r\n",
			self, sipe_private->uc_line_uri);
		g_free(self);
	}

	hdr = g_strdup_printf(
		"ms-keep-alive: UAC;hop-hop=yes\r\n"
		"Contact: %s\r\n"
		"%s"
		"Content-Type: %s%s\r\n",
		contact,
		p_preferred_identity ? p_preferred_identity : "",
		call_private->invite_content_type ?
			  call_private->invite_content_type : "application/sdp",
		call_private->invite_content_type ?
			";boundary=\"----=_NextPart_000_001E_01CB4397.0B5EB570\"" : "");

	g_free(contact);
	g_free(p_preferred_identity);

	msg = sipe_media_to_sdpmsg(call_private);
	body = sdpmsg_to_string(msg);

	if (call_private->extra_invite_section) {
		gchar *tmp;
		tmp = g_strdup_printf(
			"------=_NextPart_000_001E_01CB4397.0B5EB570\r\n"
			"%s"
			"\r\n"
			"------=_NextPart_000_001E_01CB4397.0B5EB570\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Transfer-Encoding: 7bit\r\n"
			"Content-Disposition: session; handling=optional\r\n"
			"\r\n"
			"%s"
			"\r\n"
			"------=_NextPart_000_001E_01CB4397.0B5EB570--\r\n",
			call_private->extra_invite_section, body);
		g_free(body);
		body = tmp;
		sipe_media_add_extra_invite_section(SIPE_MEDIA_CALL, NULL, NULL);
	}

	sdpmsg_free(msg);

	dialog->outgoing_invite = sip_transport_invite(sipe_private,
						       hdr,
						       body,
						       dialog,
						       tc);

	g_free(body);
	g_free(hdr);
}

static void
send_response_with_session_description(struct sipe_media_call_private *call_private, int code, gchar *text)
{
	struct sdpmsg *msg = sipe_media_to_sdpmsg(call_private);
	gchar *body = sdpmsg_to_string(msg);
	sdpmsg_free(msg);
	sipmsg_add_header(call_private->invitation, "Content-Type", "application/sdp");
	sip_transport_response(call_private->sipe_private, call_private->invitation, code, text, body);
	g_free(body);
}

static gboolean
process_invite_call_response(struct sipe_core_private *sipe_private,
								   struct sipmsg *msg,
								   struct transaction *trans);

struct sipe_media_stream *
sipe_core_media_get_stream_by_id(struct sipe_media_call *call, const gchar *id)
{
	GSList *i;
	for (i = SIPE_MEDIA_CALL_PRIVATE->streams; i; i = i->next) {
		struct sipe_media_stream *stream = i->data;
		if (sipe_strequal(stream->id, id))
			return stream;
	}
	return NULL;
}

static gboolean
update_call_from_remote_sdp(struct sipe_media_call_private* call_private,
			    struct sdpmedia *media)
{
	struct sipe_media_stream *stream;
	GList *backend_candidates = NULL;
	GList *backend_codecs = NULL;
	GSList *i;
	gboolean result = TRUE;

	stream = sipe_core_media_get_stream_by_id(SIPE_MEDIA_CALL, media->name);
	if (media->port == 0) {
		if (stream) {
			sipe_backend_media_stream_end(SIPE_MEDIA_CALL, stream);
		}
		return FALSE;
	}

	if (!stream)
		return FALSE;

	if (sipe_utils_nameval_find(media->attributes, "inactive")) {
		sipe_backend_stream_hold(SIPE_MEDIA_CALL, stream, FALSE);
	} else if (sipe_backend_stream_is_held(stream)) {
		sipe_backend_stream_unhold(SIPE_MEDIA_CALL, stream, FALSE);
	}

	if (SIPE_MEDIA_STREAM_PRIVATE->remote_candidates_and_codecs_set) {
		return TRUE;
	}

	for (i = media->codecs; i; i = i->next) {
		struct sdpcodec *c = i->data;
		struct sipe_backend_codec *codec;
		GSList *j;

		codec = sipe_backend_codec_new(c->id,
					       c->name,
					       c->type,
					       c->clock_rate,
					       c->channels);

		for (j = c->parameters; j; j = j->next) {
			struct sipnameval *attr = j->data;

			sipe_backend_codec_add_optional_parameter(codec,
								  attr->name,
								  attr->value);
		}

		backend_codecs = g_list_append(backend_codecs, codec);
	}

	if (media->encryption_key && SIPE_MEDIA_STREAM_PRIVATE->encryption_key) {
		sipe_backend_media_set_encryption_keys(SIPE_MEDIA_CALL, stream,
				SIPE_MEDIA_STREAM_PRIVATE->encryption_key,
				media->encryption_key);
		SIPE_MEDIA_STREAM_PRIVATE->encryption_key_id = media->encryption_key_id;
	} else {
		// We now know that the stream won't be encrypted.
		// Allow unencrypted data to pass srtpdec freely
		sipe_backend_media_set_require_encryption(SIPE_MEDIA_CALL,
							  stream,
							  FALSE);
	}

	result = sipe_backend_set_remote_codecs(SIPE_MEDIA_CALL, stream,
						backend_codecs);
	sipe_media_codec_list_free(backend_codecs);

	if (result == FALSE) {
		sipe_backend_media_stream_end(SIPE_MEDIA_CALL, stream);
		return FALSE;
	}

	for (i = media->candidates; i; i = i->next) {
		struct sdpcandidate *c = i->data;
		struct sipe_backend_candidate *candidate;
		candidate = sipe_backend_candidate_new(c->foundation,
						       c->component,
						       c->type,
						       c->protocol,
						       c->ip,
						       c->port,
						       c->username,
						       c->password);
		sipe_backend_candidate_set_priority(candidate, c->priority);

		backend_candidates = g_list_append(backend_candidates, candidate);
	}

	sipe_backend_media_add_remote_candidates(SIPE_MEDIA_CALL, stream,
						 backend_candidates);
	sipe_media_candidate_list_free(backend_candidates);

	SIPE_MEDIA_STREAM_PRIVATE->remote_candidates_and_codecs_set = TRUE;

	return TRUE;
}

static void
apply_remote_message(struct sipe_media_call_private* call_private,
		     struct sdpmsg* msg)
{
	GSList *i;

	sipe_utils_slist_free_full(call_private->failed_media, (GDestroyNotify)sdpmedia_free);
	call_private->failed_media = NULL;
	call_private->encryption_compatible = TRUE;

	for (i = msg->media; i; i = i->next) {
		struct sdpmedia *media = i->data;
		const gchar *enc_level =
				sipe_utils_nameval_find(media->attributes, "encryption");
		if (sipe_strequal(enc_level, "rejected") &&
		    get_encryption_policy(call_private->sipe_private) == SIPE_ENCRYPTION_POLICY_REQUIRED) {
			call_private->encryption_compatible = FALSE;
		}

		if (!update_call_from_remote_sdp(call_private, media)) {
			media->port = 0;
			call_private->failed_media =
				g_slist_append(call_private->failed_media, media);
		}
	}

	/* We need to keep failed medias until response is sent, remove them
	 * from sdpmsg that is to be freed. */
	for (i = call_private->failed_media; i; i = i->next) {
		msg->media = g_slist_remove(msg->media, i->data);
	}
}

static gboolean
call_initialized(struct sipe_media_call *call)
{
	GSList *streams = SIPE_MEDIA_CALL_PRIVATE->streams;
	for (; streams; streams = streams->next) {
		if (!sipe_backend_stream_initialized(call, streams->data)) {
			return FALSE;
		}
	}

	return TRUE;
}

static void
stream_connection_timeout_cb(struct sipe_core_private *sipe_private,
			    gpointer data)
{
	struct sipe_media_call_private *call_private = data;

	sipe_backend_notify_error(SIPE_CORE_PUBLIC,
				  _("Couldn't create stream"),
				  _("Connection timed out"));
	sipe_backend_media_hangup(SIPE_MEDIA_CALL->backend_private, TRUE);
}

static void
stream_schedule_timeout(struct sipe_media_call *call)
{
	GSList *i;
	for (i = SIPE_MEDIA_CALL_PRIVATE->streams; i; i = i->next) {
		struct sipe_media_stream_private *stream_private = i->data;

                if (stream_private->established)
				continue;
		stream_private->timeout_key =
			g_strdup_printf("<media-stream-connect><%s><%s>",
					sipe_media_get_sip_dialog(call)->callid,
					SIPE_MEDIA_STREAM->id);

		sipe_schedule_seconds(SIPE_MEDIA_CALL_PRIVATE->sipe_private,
				      stream_private->timeout_key,
				      SIPE_MEDIA_CALL_PRIVATE,
				      SIPE_MEDIA_STREAM_CONNECTION_TIMEOUT_SECONDS,
				      stream_connection_timeout_cb,
				      NULL);
	}
}

static void
stream_schedule_cancel_timeout(struct sipe_media_call *call,
			       struct sipe_media_stream_private *stream_private)
{
	if (stream_private->timeout_key) {
		sipe_schedule_cancel(SIPE_MEDIA_CALL_PRIVATE->sipe_private,
				     stream_private->timeout_key);
		g_free(stream_private->timeout_key);
	}
	stream_private->timeout_key = NULL;
}

static void
call_request_timeout_cb(struct sipe_core_private *sipe_private,
			    gpointer data)
{
	struct sipe_media_call_private *call_private = data;

	sipe_backend_notify_error(SIPE_CORE_PUBLIC,
				  _("Request timed out"),
				  _("Call could not be answered"));
	sipe_backend_media_hangup(SIPE_MEDIA_CALL->backend_private, TRUE);
}

static void
call_schedule_request_timeout(struct sipe_media_call *call)
{
	SIPE_MEDIA_CALL_PRIVATE->timeout_key =
		g_strdup_printf("<media-call-request><%s>", sipe_media_get_sip_dialog(call)->callid);

	sipe_schedule_seconds(SIPE_MEDIA_CALL_PRIVATE->sipe_private,
			      SIPE_MEDIA_CALL_PRIVATE->timeout_key,
			      SIPE_MEDIA_CALL_PRIVATE,
			      SIPE_MEDIA_CALL_TIMEOUT_SECONDS,
			      call_request_timeout_cb,
			      NULL);
}

static void
call_schedule_cancel_request_timeout(struct sipe_media_call *call)
{
	if (SIPE_MEDIA_CALL_PRIVATE->timeout_key) {
		sipe_schedule_cancel(SIPE_MEDIA_CALL_PRIVATE->sipe_private,
				     SIPE_MEDIA_CALL_PRIVATE->timeout_key);
		g_free(SIPE_MEDIA_CALL_PRIVATE->timeout_key);
	}
	SIPE_MEDIA_CALL_PRIVATE->timeout_key = NULL;
}


static void
call_ringing_timeout_cb(struct sipe_core_private *sipe_private,
			    gpointer data)
{
	struct sipe_media_call_private *call_private = data;

	sip_transport_response(sipe_private, call_private->invitation,
				       408, "Request Timeout", NULL);
	sipe_backend_media_hangup(SIPE_MEDIA_CALL->backend_private, FALSE);
}

static void
call_schedule_ringing_timeout(struct sipe_media_call *call)
{
	SIPE_MEDIA_CALL_PRIVATE->ringing_key =
		g_strdup_printf("<media-call-ringing><%s>", sipe_media_get_sip_dialog(call)->callid);

	sipe_schedule_seconds(SIPE_MEDIA_CALL_PRIVATE->sipe_private,
			      SIPE_MEDIA_CALL_PRIVATE->ringing_key,
			      SIPE_MEDIA_CALL_PRIVATE,
			      SIPE_MEDIA_CALL_RINGING_TIMEOUT_SECONDS,
			      call_ringing_timeout_cb,
			      NULL);
}

static void
call_schedule_cancel_ringing_timeout(struct sipe_media_call *call)
{
	if (SIPE_MEDIA_CALL_PRIVATE->ringing_key) {
		sipe_schedule_cancel(SIPE_MEDIA_CALL_PRIVATE->sipe_private,
				     SIPE_MEDIA_CALL_PRIVATE->ringing_key);
		g_free(SIPE_MEDIA_CALL_PRIVATE->ringing_key);
	}
	SIPE_MEDIA_CALL_PRIVATE->ringing_key = NULL;
}

// Sends an invite response when the call is accepted and local candidates were
// prepared, otherwise does nothing. If error response is sent, call_private is
// disposed before function returns.
static void
maybe_send_first_invite_response(struct sipe_media_call_private *call_private)
{
	struct sipe_backend_media *backend_media;

	backend_media = call_private->public.backend_private;

	if (!sipe_backend_media_accepted(backend_media) ||
	    !call_initialized(&call_private->public))
		return;

	if (!call_private->encryption_compatible) {
		struct sipe_core_private *sipe_private = call_private->sipe_private;

		sipmsg_add_header(call_private->invitation, "Warning",
			"308 lcs.microsoft.com \"Encryption Levels not compatible\"");
		sip_transport_response(sipe_private,
			call_private->invitation,
			488, "Encryption Levels not compatible",
			NULL);
		sipe_backend_media_reject(backend_media, FALSE);
		sipe_backend_notify_error(SIPE_CORE_PUBLIC,
					  _("Unable to establish a call"),
					  _("Encryption settings of peer are incompatible with ours."));
	} else {
		send_response_with_session_description(call_private, 200, "OK");
		stream_schedule_timeout(SIPE_MEDIA_CALL);
		call_schedule_cancel_ringing_timeout(SIPE_MEDIA_CALL);
		sipmsg_free(call_private->invitation);
		call_private->invitation = NULL;
	}
}

static void
stream_initialized_cb(struct sipe_media_call *call,
		      struct sipe_media_stream *stream)
{
	if (call_initialized(call)) {
		struct sipe_media_call_private *call_private = SIPE_MEDIA_CALL_PRIVATE;

		if (sipe_backend_media_is_initiator(call, stream)) {
			sipe_invite_call(call_private,
					 process_invite_call_response);
		} else if (call_private->smsg) {
			struct sdpmsg *smsg = call_private->smsg;
			call_private->smsg = NULL;

			apply_remote_message(call_private, smsg);
			maybe_send_first_invite_response(call_private);
			sdpmsg_free(smsg);
		}
	}
}

static void phone_state_publish(struct sipe_core_private *sipe_private)
{
	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		sipe_ocs2007_phone_state_publish(sipe_private);
	} else {
		// TODO: OCS 2005 support. Is anyone still using it at all?
	}
}

void
sipe_core_media_stream_end(struct sipe_media_stream *stream)
{
	sipe_media_stream_free(SIPE_MEDIA_STREAM_PRIVATE);
}

static void
media_end_cb(struct sipe_media_call *call)
{
	struct sipe_core_private *sipe_private;

	g_return_if_fail(call);

	sipe_private = SIPE_MEDIA_CALL_PRIVATE->sipe_private;

	sipe_media_call_free(SIPE_MEDIA_CALL_PRIVATE);
	phone_state_publish(sipe_private);
}

static void
call_accept_cb(struct sipe_media_call *call, gboolean local)
{
	if (local) {
		maybe_send_first_invite_response(SIPE_MEDIA_CALL_PRIVATE);
	}
	phone_state_publish(SIPE_MEDIA_CALL_PRIVATE->sipe_private);
}

static void
call_reject_cb(struct sipe_media_call *call, gboolean local)
{
	if (local) {
		struct sipe_media_call_private *call_private = SIPE_MEDIA_CALL_PRIVATE;

		sip_transport_response(call_private->sipe_private,
				       call_private->invitation,
				       603, "Decline", NULL);

		if (call_private->session) {
			sipe_session_remove(call_private->sipe_private,
					    call_private->session);
			call_private->session = NULL;
		}
	}
}

static void
av_call_reject_cb(struct sipe_media_call *call, gboolean local)
{
	if (!local) {
		struct sipe_core_private *sipe_private;
		gchar *desc;

		sipe_private = SIPE_MEDIA_CALL_PRIVATE->sipe_private;

		desc = g_strdup_printf(_("User %s rejected call"), call->with);
		sipe_backend_notify_error(SIPE_CORE_PUBLIC, _("Call rejected"),
					  desc);
		g_free(desc);
	}

	call_reject_cb(call, local);
}

static gboolean
sipe_media_send_ack(struct sipe_core_private *sipe_private, struct sipmsg *msg,
					struct transaction *trans);

static void call_hold_cb(struct sipe_media_call *call,
			 gboolean local,
			 SIPE_UNUSED_PARAMETER gboolean state)
{
	if (local) {
		sipe_invite_call(SIPE_MEDIA_CALL_PRIVATE, sipe_media_send_ack);
	}
}

static void call_hangup_cb(struct sipe_media_call *call, gboolean local)
{
	if (local) {
		struct sipe_media_call_private *call_private = SIPE_MEDIA_CALL_PRIVATE;

		if (call_private->session) {
			sipe_session_close(call_private->sipe_private,
					   call_private->session);
			call_private->session = NULL;
		}
	}
}

static void
error_cb(struct sipe_media_call *call, gchar *message)
{
	struct sipe_media_call_private *call_private = SIPE_MEDIA_CALL_PRIVATE;
	struct sipe_core_private *sipe_private = call_private->sipe_private;
	gboolean initiator = sipe_backend_media_is_initiator(call, NULL);
	gboolean accepted = sipe_backend_media_accepted(call->backend_private);

	gchar *title = g_strdup_printf("Call with %s failed", call->with);
	sipe_backend_notify_error(SIPE_CORE_PUBLIC, title, message);
	g_free(title);

	if (!initiator && !accepted && call_private->invitation) {
		sip_transport_response(sipe_private,
				       call_private->invitation,
				       488, "Not Acceptable Here", NULL);
	}
}

struct sipe_media_call *
sipe_media_call_new(struct sipe_core_private *sipe_private, const gchar* with,
		    struct sipmsg *msg, SipeIceVersion ice_version,
		    SipeMediaCallFlags flags)
{
	struct sipe_media_call_private *call_private;
	struct sip_session *session;
	struct sip_dialog *dialog;
	gchar *cname;

	session = sipe_session_add_call(sipe_private, with);

	dialog = sipe_dialog_add(session);
	dialog->with = g_strdup(with);

	if (msg) {
		sipmsg_update_to_header_tag(msg);
		dialog->callid = g_strdup(sipmsg_find_call_id_header(msg));
		sipe_dialog_parse(dialog, msg, FALSE);
	} else {
		dialog->callid = gencallid();
		dialog->ourtag = gentag();
		flags |= SIPE_MEDIA_CALL_INITIATOR;
	}

	if (g_hash_table_lookup(sipe_private->media_calls, dialog->callid)) {
		SIPE_DEBUG_ERROR("sipe_media_call_new: call already exists for "
				 "Call-ID %s", dialog->callid);
		sipe_session_remove(sipe_private, session);
		return NULL;
	}

	call_private = g_new0(struct sipe_media_call_private, 1);
	call_private->sipe_private = sipe_private;
	call_private->session = session;
	SIPE_MEDIA_CALL->with = g_strdup(with);

	g_hash_table_insert(sipe_private->media_calls,
			    g_strdup(dialog->callid), call_private);

	cname = g_strdup(sipe_private->contact + 1);
	cname[strlen(cname) - 1] = '\0';

	call_private->public.backend_private = sipe_backend_media_new(SIPE_CORE_PUBLIC,
								      SIPE_MEDIA_CALL,
								      with,
								      flags);
	sipe_backend_media_set_cname(call_private->public.backend_private, cname);

	call_private->ice_version = ice_version;
	call_private->encryption_compatible = TRUE;

	call_private->public.stream_initialized_cb  = stream_initialized_cb;
	call_private->public.media_end_cb           = media_end_cb;
	call_private->public.call_accept_cb         = call_accept_cb;
	call_private->public.call_reject_cb         = call_reject_cb;
	call_private->public.call_hold_cb           = call_hold_cb;
	call_private->public.call_hangup_cb         = call_hangup_cb;
	call_private->public.error_cb               = error_cb;

	g_free(cname);

	return SIPE_MEDIA_CALL;
}

static gboolean
find_call_cb(SIPE_UNUSED_PARAMETER const gchar *callid,
	     struct sipe_media_call *call,
	     const gchar *with)
{
	return sipe_strequal(call->with, with);
}

struct sipe_media_call *
sipe_media_call_find(struct sipe_core_private *sipe_private, const gchar *with)
{
	return g_hash_table_find(sipe_private->media_calls,
				 (GHRFunc)find_call_cb,
				 (gpointer)with);
}

void sipe_media_hangup(struct sipe_media_call_private *call_private)
{
	if (call_private) {
		sipe_backend_media_hangup(call_private->public.backend_private,
					  FALSE);
	}
}

static gint
ssrc_range_compare(const struct ssrc_range *a, const struct ssrc_range *b)
{
	if (a->begin < b->begin) {
		return -1;
	}
	if (a->begin > b->begin) {
		return 1;
	}
	return 0;
}

static void
ssrc_range_update(GSList **ranges, GSList *media)
{
	for (; media; media = media->next) {
		struct sdpmedia *m;
		const char *ssrc_range;
		gchar **parts;

		m = media->data;
		ssrc_range = sipe_utils_nameval_find(m->attributes,
						     "x-ssrc-range");
		if (!ssrc_range) {
			continue;
		}

		parts = g_strsplit(ssrc_range, "-", 2);

		if (parts[0] && parts[1]) {
			struct ssrc_range *range;

			range = g_new0(struct ssrc_range, 1);
			range->begin = atoi(parts[0]);
			range->end = atoi(parts[1]);

			*ranges = sipe_utils_slist_insert_unique_sorted(
					*ranges, range,
					(GCompareFunc)ssrc_range_compare,
					g_free);
		}

		g_strfreev(parts);
	}
}

static struct ssrc_range *
ssrc_range_allocate(GSList **ranges, guint32 len)
{
	struct ssrc_range *range;
	GSList *i;

	range = g_new0(struct ssrc_range, 1);
	range->begin = 1;
	range->end = range->begin + (len - 1);

	for (i = *ranges; i; i = i->next) {
		struct ssrc_range *r = i->data;

		if (range->begin < r->begin && range->end < r->begin) {
			break;
		}

		range->begin = r->end + 1;
		range->end = range->begin + (len - 1);
	}

	/* As per [MS-SDPEXT] 3.1.5.31.1, a SSRC MUST be from 1 to 4294967040
	 * inclusive. */
	if (range->begin > range->end || range->end > 0xFFFFFF00) {
		g_free(range);
		SIPE_DEBUG_ERROR("Couldn't allocate SSRC range of %u", len);
		return NULL;
	}

	*ranges = g_slist_insert_sorted(*ranges, range,
					(GCompareFunc)ssrc_range_compare);

	return range;
}

struct sipe_media_stream *
sipe_media_stream_add(struct sipe_media_call *call, const gchar *id,
		      SipeMediaType type, SipeIceVersion ice_version,
		      gboolean initiator, guint32 ssrc_count)
{
	struct sipe_core_private *sipe_private;
	struct sipe_media_stream_private *stream_private;
	struct sipe_backend_media_relays *backend_media_relays;
	guint min_port;
	guint max_port;

	sipe_private = SIPE_MEDIA_CALL_PRIVATE->sipe_private;

	backend_media_relays = sipe_backend_media_relays_convert(
						sipe_private->media_relays,
						sipe_private->media_relay_username,
						sipe_private->media_relay_password);

	min_port = sipe_private->min_media_port;
	max_port = sipe_private->max_media_port;
	switch (type) {
		case SIPE_MEDIA_AUDIO:
			min_port = sipe_private->min_audio_port;
			max_port = sipe_private->max_audio_port;
			break;
		case SIPE_MEDIA_VIDEO:
			min_port = sipe_private->min_video_port;
			max_port = sipe_private->max_audio_port;
			break;
		case SIPE_MEDIA_APPLICATION:
			if (sipe_strequal(id, "data")) {
				min_port = sipe_private->min_filetransfer_port;
				max_port = sipe_private->max_filetransfer_port;
			} else if (sipe_strequal(id, "applicationsharing")) {
				min_port = sipe_private->min_appsharing_port;
				max_port = sipe_private->max_appsharing_port;
			}
			break;
	}

	stream_private = g_new0(struct sipe_media_stream_private, 1);
	SIPE_MEDIA_STREAM->call = call;
	SIPE_MEDIA_STREAM->id = g_strdup(id);
	stream_private->write_queue = g_queue_new();
	stream_private->async_reads = g_queue_new();

	if (ssrc_count > 0) {
		SIPE_MEDIA_STREAM->ssrc_range =
			ssrc_range_allocate(&SIPE_MEDIA_CALL_PRIVATE->ssrc_ranges,
					    ssrc_count);
	}

	SIPE_MEDIA_STREAM->backend_private =
			sipe_backend_media_add_stream(SIPE_MEDIA_STREAM,
						      type, ice_version,
						      initiator,
						      backend_media_relays,
						      min_port, max_port);

	sipe_backend_media_relays_free(backend_media_relays);

	if (!SIPE_MEDIA_STREAM->backend_private) {
		sipe_media_stream_free(stream_private);
		return NULL;
	}

	if (type == SIPE_MEDIA_VIDEO) {
		/* Declare that we can send and receive Video Source Requests
		 * as per [MS-SDPEXT] 3.1.5.30.2. */
		sipe_media_stream_add_extra_attribute(SIPE_MEDIA_STREAM,
				"rtcp-fb", "* x-message app send:src recv:src");

		sipe_media_stream_add_extra_attribute(SIPE_MEDIA_STREAM,
				"rtcp-rsize", NULL);
		sipe_media_stream_add_extra_attribute(SIPE_MEDIA_STREAM,
				"label", "main-video");
		sipe_media_stream_add_extra_attribute(SIPE_MEDIA_STREAM,
				"x-source", "main-video");
	}

#ifdef HAVE_SRTP
	if (get_encryption_policy(sipe_private) != SIPE_ENCRYPTION_POLICY_REJECTED) {
		int i;
		stream_private->encryption_key = g_new0(guchar, SIPE_SRTP_KEY_LEN);
		for (i = 0; i != SIPE_SRTP_KEY_LEN; ++i) {
			stream_private->encryption_key[i] = rand() & 0xff;
		}
		stream_private->encryption_key_id = 1;
		// We don't know yet whether the stream will be
		// encrypted or not. Enable the require-encryption
		// property at stream creation time anyway, we may
		// disable it later if we don't receive encryption keys.
		sipe_backend_media_set_require_encryption(call,
							  SIPE_MEDIA_STREAM,
							  TRUE);
	}
#endif

	SIPE_MEDIA_CALL_PRIVATE->streams =
			g_slist_append(SIPE_MEDIA_CALL_PRIVATE->streams,
				       stream_private);

	return SIPE_MEDIA_STREAM;
}

static void
append_2007_fallback_if_needed(struct sipe_media_call_private *call_private)
{
	struct sipe_core_private *sipe_private = call_private->sipe_private;
	const gchar *marker = sip_transport_sdp_address_marker(sipe_private);
	const gchar *ip = sip_transport_ip_address(sipe_private);
	gchar *body;

	if (SIPE_CORE_PRIVATE_FLAG_IS(SFB) ||
	    sipe_media_get_sip_dialog(SIPE_MEDIA_CALL)->cseq != 0 ||
	    call_private->ice_version != SIPE_ICE_RFC_5245 ||
	    sipe_strequal(SIPE_MEDIA_CALL->with, sipe_private->test_call_bot_uri)) {
		return;
	}

	body = g_strdup_printf("Content-Type: application/sdp\r\n"
			       "Content-Transfer-Encoding: 7bit\r\n"
			       "Content-Disposition: session; handling=optional; ms-proxy-2007fallback\r\n"
			       "\r\n"
			       "o=- 0 0 IN %s %s\r\n"
			       "s=session\r\n"
			       "c=IN %s %s\r\n"
			       "m=audio 0 RTP/AVP\r\n",
			       marker, ip,
			       marker, ip);
	sipe_media_add_extra_invite_section(SIPE_MEDIA_CALL,
					    "multipart/alternative", body);
}

static void
sipe_media_initiate_call(struct sipe_core_private *sipe_private,
			 const char *with, SipeIceVersion ice_version,
			 gboolean with_video)
{
	struct sipe_media_call_private *call_private;

	if (sipe_core_media_get_call(SIPE_CORE_PUBLIC)) {
		return;
	}

	call_private = (struct sipe_media_call_private *)
				sipe_media_call_new(sipe_private, with, NULL,
						    ice_version, 0);

	SIPE_MEDIA_CALL->call_reject_cb = av_call_reject_cb;

	if (!sipe_media_stream_add(SIPE_MEDIA_CALL, "audio", SIPE_MEDIA_AUDIO,
				   call_private->ice_version,
				   TRUE, 0)) {
		sipe_backend_notify_error(SIPE_CORE_PUBLIC,
					  _("Error occurred"),
					  _("Error creating audio stream"));
		sipe_media_hangup(call_private);
		return;
	}

	if (with_video &&
	    !sipe_media_stream_add(SIPE_MEDIA_CALL, "video", SIPE_MEDIA_VIDEO,
				   call_private->ice_version,
				   TRUE, VIDEO_SSRC_COUNT)) {
		sipe_backend_notify_error(SIPE_CORE_PUBLIC,
					  _("Error occurred"),
					  _("Error creating video stream"));
		sipe_media_hangup(call_private);
		return;
	}

	append_2007_fallback_if_needed(call_private);

	call_schedule_request_timeout(SIPE_MEDIA_CALL);
	// Processing continues in stream_initialized_cb
}

void
sipe_core_media_initiate_call(struct sipe_core_public *sipe_public,
			      const char *with,
			      gboolean with_video)
{
	sipe_media_initiate_call(SIPE_CORE_PRIVATE, with,
				 SIPE_ICE_RFC_5245, with_video);
}

static void
conference_audio_muted_cb(struct sipe_media_stream *stream, gboolean is_muted)
{
	struct sipe_media_call *call = stream->call;

	if (!SIPE_MEDIA_CALL_PRIVATE->conference_session) {
		return;
	}

	sipe_conf_announce_audio_mute_state(SIPE_MEDIA_CALL_PRIVATE->sipe_private,
					    SIPE_MEDIA_CALL_PRIVATE->conference_session,
					    is_muted);
}

void sipe_core_media_connect_conference(struct sipe_core_public *sipe_public,
					struct sipe_chat_session *chat_session)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_media_call_private *call_private;
	struct sipe_media_stream *stream;
	struct sip_session *session;
	SipeIceVersion ice_version;
	gchar *av_uri;

	if (!sipe_conf_supports_mcu_type(sipe_private, "audio-video")) {
		sipe_backend_notify_error(sipe_public, _("Join conference call"),
				_("Conference calls are not supported on this server."));
		return;
	}

	session = sipe_session_find_chat(sipe_private, chat_session);

	if (sipe_core_media_get_call(sipe_public) || !session) {
		return;
	}

	av_uri = sipe_conf_build_uri(sipe_core_chat_id(sipe_public, chat_session),
				     "audio-video");
	if (!av_uri) {
		return;
	}

	session->is_call = TRUE;

	ice_version = SIPE_CORE_PRIVATE_FLAG_IS(LYNC2013) ? SIPE_ICE_RFC_5245 :
							    SIPE_ICE_DRAFT_6;

	call_private = (struct sipe_media_call_private *)
				sipe_media_call_new(sipe_private, av_uri, NULL,
						    ice_version, 0);
	call_private->conference_session = session;
	SIPE_MEDIA_CALL->call_reject_cb = av_call_reject_cb;

	stream = sipe_media_stream_add(SIPE_MEDIA_CALL, "audio",
				       SIPE_MEDIA_AUDIO,
				       call_private->ice_version,
				       TRUE, 0);
	if (!stream) {
		sipe_backend_notify_error(sipe_public,
					  _("Error occurred"),
					  _("Error creating audio stream"));

		sipe_media_hangup(call_private);
	}

	stream->mute_cb = conference_audio_muted_cb;

	g_free(av_uri);

	// Processing continues in stream_initialized_cb
}

struct sipe_media_call *
sipe_core_media_get_call(struct sipe_core_public *sipe_public)
{
	struct sipe_media_call * result = NULL;
	GList *calls = g_hash_table_get_values(SIPE_CORE_PRIVATE->media_calls);
	GList *entry = calls;

	while (entry) {
		if (sipe_core_media_get_stream_by_id(entry->data, "audio")) {
			result = entry->data;
			break;
		}
		entry = entry->next;
	}
	g_list_free(calls);

	return result;
}

static gboolean phone_number_is_valid(const gchar *phone_number)
{
	if (!phone_number || sipe_strequal(phone_number, "")) {
		return FALSE;
	}

	if (*phone_number == '+') {
		++phone_number;
	}

	while (*phone_number != '\0') {
		if (!g_ascii_isdigit(*phone_number)) {
			return FALSE;
		}
		++phone_number;
	}

	return TRUE;
}

void sipe_core_media_phone_call(struct sipe_core_public *sipe_public,
				const gchar *phone_number)
{
	g_return_if_fail(sipe_public);

	SIPE_DEBUG_INFO("sipe_core_media_phone_call: %s", phone_number ? phone_number : "(null)");

	if (phone_number_is_valid(phone_number)) {
		gchar *phone_uri = g_strdup_printf("sip:%s@%s;user=phone",
				phone_number, sipe_public->sip_domain);

		sipe_core_media_initiate_call(sipe_public, phone_uri, FALSE);

		g_free(phone_uri);
	} else {
		sipe_backend_notify_error(sipe_public,
					  _("Unable to establish a call"),
					  _("Invalid phone number"));
	}
}

void sipe_core_media_test_call(struct sipe_core_public *sipe_public)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	if (!sipe_private->test_call_bot_uri) {
		sipe_backend_notify_error(sipe_public,
					  _("Unable to establish a call"),
					  _("Audio Test Service is not available."));
		return;
	}

	sipe_core_media_initiate_call(sipe_public,
				      sipe_private->test_call_bot_uri, FALSE);
}

static struct sipe_media_call_private *
sipe_media_from_sipmsg(struct sipe_core_private *sipe_private,
		       struct sipmsg *msg)
{
	return g_hash_table_lookup(sipe_private->media_calls,
				   sipmsg_find_call_id_header(msg));
}

static void
transport_response_unsupported_sdp(struct sipe_core_private *sipe_private,
				   struct sipmsg *msg)
{
	sipmsg_add_header(msg, "ms-client-diagnostics",
			  "52063;reason=\"Unsupported session description\"");
	sip_transport_response(sipe_private, msg,
			       488, "Not Acceptable Here", NULL);
}

static void
maybe_send_second_invite_response(struct sipe_media_call_private *call_private)
{
	GSList *it;

	/* Second INVITE request had to be received and all streams must have
	 * established candidate pairs before the response can be sent. */

	if (!call_private->invitation) {
		return;
	}

	for (it = call_private->streams; it; it = it->next) {
		struct sipe_media_stream_private *stream_private = it->data;
		if (!stream_private->established) {
			return;
		}
	}

	send_response_with_session_description(call_private, 200, "OK");

#ifdef HAVE_XDATA
	for (it = call_private->streams; it; it = it->next) {
		struct sipe_media_stream_private *stream_private = it->data;

		stream_private->sdp_negotiation_concluded = TRUE;
		if (stream_private->writable) {
			// We've become writable.
			sipe_core_media_stream_writable(SIPE_MEDIA_STREAM, TRUE);
		}
	}
#endif
}

struct sipe_media_call *
process_incoming_invite_call(struct sipe_core_private *sipe_private,
			     struct sipmsg *msg,
			     const gchar *sdp)
{
	return(process_incoming_invite_call_parsed_sdp(sipe_private,
						       msg,
						       sdpmsg_parse_msg(sdp)));
}

struct sipe_media_call *
process_incoming_invite_call_parsed_sdp(struct sipe_core_private *sipe_private,
					struct sipmsg *msg,
					struct sdpmsg *smsg)
{
	struct sipe_media_call_private *call_private;
	gboolean has_new_media = FALSE;
	GSList *i;

	// Don't allow two voice calls in parallel.
	if (!strstr(msg->body, "m=data") &&
	    !strstr(msg->body, "m=applicationsharing")) {
		struct sipe_media_call *call =
				sipe_core_media_get_call(SIPE_CORE_PUBLIC);
		if (call && !is_media_session_msg(SIPE_MEDIA_CALL_PRIVATE, msg)) {
			sip_transport_response(sipe_private, msg,
					       486, "Busy Here", NULL);
			sdpmsg_free(smsg);
			return NULL;
		}
	}

	call_private = sipe_media_from_sipmsg(sipe_private, msg);

	if (call_private) {
		char *self = sip_uri_self(sipe_private);
		if (sipe_strequal(SIPE_MEDIA_CALL->with, self)) {
			g_free(self);
			sip_transport_response(sipe_private, msg, 488, "Not Acceptable Here", NULL);
			sdpmsg_free(smsg);
			return NULL;
		}
		g_free(self);
	}

	if (!smsg) {
		transport_response_unsupported_sdp(sipe_private, msg);
		if (call_private) {
			sipe_media_hangup(call_private);
		}
		return NULL;
	}

	if (!call_private) {
		gchar *with = sipmsg_parse_from_address(msg);
		SipeMediaCallFlags flags = 0;

		if (strstr(msg->body, "m=data") ||
		    strstr(msg->body, "m=applicationsharing")) {
			flags |= SIPE_MEDIA_CALL_NO_UI;
		}

		call_private = (struct sipe_media_call_private *)
					sipe_media_call_new(sipe_private, with,
							    msg, smsg->ice_version,
							    flags);

		if (!(flags & SIPE_MEDIA_CALL_NO_UI)) {
			SIPE_MEDIA_CALL->call_reject_cb = av_call_reject_cb;
		}
		g_free(with);
	}

	if (call_private->invitation)
		sipmsg_free(call_private->invitation);
	call_private->invitation = sipmsg_copy(msg);

	ssrc_range_update(&call_private->ssrc_ranges, smsg->media);

	// Create any new media streams
	for (i = smsg->media; i; i = i->next) {
		struct sdpmedia *media = i->data;
		gchar *id = media->name;
		SipeMediaType type;

		if (   media->port != 0
		    && !sipe_core_media_get_stream_by_id(SIPE_MEDIA_CALL, id)) {
			guint32 ssrc_count = 0;

			if (sipe_strequal(id, "audio"))
				type = SIPE_MEDIA_AUDIO;
			else if (sipe_strequal(id, "video")) {
				type = SIPE_MEDIA_VIDEO;
				ssrc_count = VIDEO_SSRC_COUNT;
			} else if (sipe_strequal(id, "data"))
				type = SIPE_MEDIA_APPLICATION;
			else if (sipe_strequal(id, "applicationsharing"))
				type = SIPE_MEDIA_APPLICATION;
			else
				continue;

			sipe_media_stream_add(SIPE_MEDIA_CALL, id, type,
					      smsg->ice_version, FALSE,
					      ssrc_count);
			has_new_media = TRUE;
		}
	}

	if (has_new_media) {
		sdpmsg_free(call_private->smsg);
		call_private->smsg = smsg;
		sip_transport_response(sipe_private, call_private->invitation,
				       180, "Ringing", NULL);
		call_schedule_ringing_timeout(SIPE_MEDIA_CALL);
		// Processing continues in stream_initialized_cb
	} else {
		apply_remote_message(call_private, smsg);
		sdpmsg_free(smsg);
		maybe_send_second_invite_response(call_private);
	}

	return SIPE_MEDIA_CALL;
}

void process_incoming_cancel_call(struct sipe_media_call_private *call_private,
				  struct sipmsg *msg)
{
	// We respond to the CANCEL request with 200 OK response and
	// with 487 Request Terminated to the remote INVITE in progress.
	sip_transport_response(call_private->sipe_private, msg, 200, "OK", NULL);

	if (call_private->invitation) {
		sip_transport_response(call_private->sipe_private,
				       call_private->invitation,
				       487, "Request Terminated", NULL);
	}

	sipe_backend_media_reject(SIPE_MEDIA_CALL->backend_private, FALSE);
}

static gboolean
sipe_media_send_ack(struct sipe_core_private *sipe_private,
		    struct sipmsg *msg,
		    struct transaction *trans)
{
	struct sipe_media_call_private *call_private;
	struct sip_dialog *dialog;
	int tmp_cseq;

	call_private = sipe_media_from_sipmsg(sipe_private, msg);

	if (!is_media_session_msg(call_private, msg))
		return FALSE;

	dialog = sipe_media_get_sip_dialog(SIPE_MEDIA_CALL);
	if (!dialog)
		return FALSE;

	tmp_cseq = dialog->cseq;

	dialog->cseq = sip_transaction_cseq(trans) - 1;
	sip_transport_ack(sipe_private, dialog);
	dialog->cseq = tmp_cseq;

	dialog->outgoing_invite = NULL;

	return TRUE;
}

static gboolean
sipe_media_send_final_ack(struct sipe_core_private *sipe_private,
			  struct sipmsg *msg,
			  struct transaction *trans)
{
	struct sipe_media_call_private *call_private;
#ifdef HAVE_XDATA
	GSList *it;
#endif

	if (!sipe_media_send_ack(sipe_private, msg, trans))
		return FALSE;

	call_private = sipe_media_from_sipmsg(sipe_private, msg);

	sipe_backend_media_accept(SIPE_MEDIA_CALL->backend_private, FALSE);

#ifdef HAVE_XDATA
	for (it = call_private->streams; it; it = it->next) {
		struct sipe_media_stream_private *stream_private = it->data;

		stream_private->sdp_negotiation_concluded = TRUE;
		if (stream_private->writable) {
			// We've become writable.
			sipe_core_media_stream_writable(SIPE_MEDIA_STREAM, TRUE);
		}
	}
#endif

	return TRUE;
}

void
sipe_core_media_stream_candidate_pair_established(struct sipe_media_stream *stream)
{
	struct sipe_media_call *call = stream->call;

	GList *active_candidates =
			sipe_backend_media_stream_get_active_local_candidates(stream);
	guint ready_components = g_list_length(active_candidates);

	sipe_media_candidate_list_free(active_candidates);

	if (ready_components != 2) {
		// We must have both RTP+RTCP candidate pairs established first.
		return;
	}

	if (SIPE_MEDIA_STREAM_PRIVATE->established) {
		return;
	}
	SIPE_MEDIA_STREAM_PRIVATE->established = TRUE;

	stream_schedule_cancel_timeout(call, SIPE_MEDIA_STREAM_PRIVATE);

	if (stream->candidate_pairs_established_cb) {
		stream->candidate_pairs_established_cb(stream);
	}

	if (sipe_backend_media_is_initiator(stream->call, NULL)) {
		GSList *streams = SIPE_MEDIA_CALL_PRIVATE->streams;
		for (; streams; streams = streams->next) {
			struct sipe_media_stream_private *s = streams->data;
			if (!s->established) {
				break;
			}
		}

		if (streams == NULL) {
			// All call streams have been established.
			sipe_invite_call(SIPE_MEDIA_CALL_PRIVATE,
					 sipe_media_send_final_ack);
		}
	} else {
		maybe_send_second_invite_response(SIPE_MEDIA_CALL_PRIVATE);
	}
}

static gboolean
maybe_retry_call_with_ice_version(struct sipe_core_private *sipe_private,
				  struct sipe_media_call_private *call_private,
				  SipeIceVersion ice_version,
				  struct transaction *trans)
{
	if (call_private->ice_version != ice_version &&
	    sip_transaction_cseq(trans) == 1) {
		GSList *i;
		gchar *with;
		gboolean with_video = FALSE;

		for (i = call_private->streams; i; i = i->next) {
			struct sipe_media_stream *stream = i->data;

			if (sipe_strequal(stream->id, "video")) {
				with_video = TRUE;
			} else if (!sipe_strequal(stream->id, "audio")) {
				/* Don't retry calls which are neither audio
				 * nor video. */
				return FALSE;
			}
		}

		with = g_strdup(SIPE_MEDIA_CALL->with);

		sipe_media_hangup(call_private);
		SIPE_DEBUG_INFO("Retrying call with ICEv%d.",
				ice_version == SIPE_ICE_DRAFT_6 ? 6 : 19);
		sipe_media_initiate_call(sipe_private,
					 with,
					 ice_version,
					 with_video);

		g_free(with);
		return TRUE;
	}

	return FALSE;
}

static gboolean
process_invite_call_response(struct sipe_core_private *sipe_private,
			     struct sipmsg *msg,
			     struct transaction *trans)
{
	const gchar *with;
	struct sipe_media_call_private *call_private;
	struct sip_dialog *dialog;
	struct sdpmsg *smsg;

	call_private = sipe_media_from_sipmsg(sipe_private,msg);

	if (!is_media_session_msg(call_private, msg))
		return FALSE;

	dialog = sipe_media_get_sip_dialog(SIPE_MEDIA_CALL);

	with = dialog->with;

	dialog->outgoing_invite = NULL;

	if (msg->response == 603 || msg->response == 605) {
		// Call rejected by remote peer
		sipe_media_send_ack(sipe_private, msg, trans);
		sipe_backend_media_reject(SIPE_MEDIA_CALL->backend_private, FALSE);

		return TRUE;
	}

	if (msg->response >= 400) {
		// An error occurred
		const gchar *title;
		GString *desc = g_string_new("");
		gboolean append_responsestr = FALSE;

		switch (msg->response) {
			case 480: {
				title = _("User unavailable");

				if (sipmsg_parse_warning(msg, NULL) == 391) {
					g_string_append_printf(desc, _("%s does not want to be disturbed"), with);
				} else
					g_string_append_printf(desc, _("User %s is not available"), with);
				break;
			}
			case 415:
				// OCS/Lync really sends response string with 'Mutipart' typo.
				if (sipe_strequal(msg->responsestr, "Mutipart mime in content type not supported by Archiving CDR service") &&
				    maybe_retry_call_with_ice_version(sipe_private,
								      call_private,
								      SIPE_ICE_DRAFT_6,
								      trans)) {
					return TRUE;
				}
				title = _("Unsupported media type");
				break;
			case 488: {
				/* Check for incompatible encryption levels error.
				 *
				 * MS Lync 2010:
				 * 488 Not Acceptable Here
				 * ms-client-diagnostics: 52017;reason="Encryption levels dont match"
				 *
				 * older clients (and SIPE itself):
				 * 488 Encryption Levels not compatible
				 */
				const gchar *ms_diag = sipmsg_find_header(msg, "ms-client-diagnostics");
				SipeIceVersion retry_ice_version = SIPE_ICE_DRAFT_6;

				if (sipe_strequal(msg->responsestr, "Encryption Levels not compatible") ||
				    (ms_diag && g_str_has_prefix(ms_diag, "52017;"))) {
					title = _("Unable to establish a call");
					g_string_append(desc, _("Encryption settings of peer are incompatible with ours."));
					break;
				}

				/* Check if this is failed conference using
				 * ICEv6 with reason "Error parsing SDP" and
				 * retry using ICEv19. */
				ms_diag = sipmsg_find_header(msg, "ms-diagnostics");
				if (ms_diag && g_str_has_prefix(ms_diag, "7008;")) {
					retry_ice_version = SIPE_ICE_RFC_5245;
				}

				if (maybe_retry_call_with_ice_version(sipe_private,
								      call_private,
								      retry_ice_version,
								      trans)) {
					return TRUE;
				}
				SIPE_FALLTHROUGH
			}
			default:
				title = _("Error occurred");
				g_string_append(desc, _("Unable to establish a call"));
				append_responsestr = TRUE;
				break;
		}

		if (append_responsestr) {
			gchar *reason = sipmsg_get_ms_diagnostics_reason(msg);

			g_string_append_printf(desc, "\n%d %s",
					       msg->response, msg->responsestr);
			if (reason) {
				g_string_append_printf(desc, "\n\n%s", reason);
				g_free(reason);
			}
		}

		sipe_backend_notify_error(SIPE_CORE_PUBLIC, title, desc->str);
		g_string_free(desc, TRUE);

		sipe_media_send_ack(sipe_private, msg, trans);
		sipe_media_hangup(call_private);

		return TRUE;
	}

	sipe_dialog_parse(dialog, msg, TRUE);
	smsg = sdpmsg_parse_msg(msg->body);
	if (!smsg) {
		transport_response_unsupported_sdp(sipe_private, msg);
		sipe_media_hangup(call_private);
		return FALSE;
	}

	ssrc_range_update(&call_private->ssrc_ranges, smsg->media);
	apply_remote_message(call_private, smsg);
	sdpmsg_free(smsg);

	stream_schedule_timeout(SIPE_MEDIA_CALL);
	call_schedule_cancel_request_timeout(SIPE_MEDIA_CALL);
	sipe_media_send_ack(sipe_private, msg, trans);

	return TRUE;

	// Waits until sipe_core_media_candidate_pair_established() is invoked.
}

gboolean is_media_session_msg(struct sipe_media_call_private *call_private,
			      struct sipmsg *msg)
{
	if (!call_private) {
		return FALSE;
	}

	return sipe_media_from_sipmsg(call_private->sipe_private, msg) == call_private;
}

static void
end_call(SIPE_UNUSED_PARAMETER gpointer key,
	 struct sipe_media_call_private *call_private,
	 SIPE_UNUSED_PARAMETER gpointer user_data)
{
	struct sipe_backend_media *backend_private;

	backend_private = call_private->public.backend_private;

	if (!sipe_backend_media_is_initiator(SIPE_MEDIA_CALL, NULL) &&
	    !sipe_backend_media_accepted(backend_private)) {
		sip_transport_response(call_private->sipe_private,
				       call_private->invitation,
				       480, "Temporarily Unavailable", NULL);
	} else if (call_private->session) {
		sipe_session_close(call_private->sipe_private,
				   call_private->session);
		call_private->session = NULL;
	}

	sipe_media_hangup(call_private);
}

void
sipe_media_handle_going_offline(struct sipe_core_private *sipe_private)
{
	g_hash_table_foreach(sipe_private->media_calls, (GHFunc) end_call, NULL);
}

gboolean sipe_media_is_conference_call(struct sipe_media_call_private *call_private)
{
	return g_strstr_len(SIPE_MEDIA_CALL->with, -1, "app:conf:audio-video:") != NULL;
}

struct sipe_core_private *
sipe_media_get_sipe_core_private(struct sipe_media_call *call)
{
	g_return_val_if_fail(call, NULL);

	return SIPE_MEDIA_CALL_PRIVATE->sipe_private;
}

struct sip_dialog *
sipe_media_get_sip_dialog(struct sipe_media_call *call)
{
	struct sip_session *session;

	g_return_val_if_fail(call, NULL);

	session = SIPE_MEDIA_CALL_PRIVATE->session;

	if (!session || !session->dialogs) {
		return NULL;
	}

	return session->dialogs->data;
}

static void
sipe_media_relay_free(struct sipe_media_relay *relay)
{
	g_free(relay->hostname);
	if (relay->dns_query)
		sipe_backend_dns_query_cancel(relay->dns_query);
	g_free(relay);
}

void
sipe_media_relay_list_free(GSList *list)
{
	for (; list; list = g_slist_delete_link(list, list))
		sipe_media_relay_free(list->data);
}

static void
relay_ip_resolved_cb(struct sipe_media_relay* relay,
		     const gchar *ip, SIPE_UNUSED_PARAMETER guint port)
{
	gchar *hostname = relay->hostname;
	relay->dns_query = NULL;

	if (ip && port) {
		relay->hostname = g_strdup(ip);
		SIPE_DEBUG_INFO("Media relay %s resolved to %s.", hostname, ip);
	} else {
		relay->hostname = NULL;
		SIPE_DEBUG_INFO("Unable to resolve media relay %s.", hostname);
	}

	g_free(hostname);
}

static gboolean
process_get_av_edge_credentials_response(struct sipe_core_private *sipe_private,
					 struct sipmsg *msg,
					 SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	g_free(sipe_private->media_relay_username);
	g_free(sipe_private->media_relay_password);
	sipe_media_relay_list_free(sipe_private->media_relays);
	sipe_private->media_relay_username = NULL;
	sipe_private->media_relay_password = NULL;
	sipe_private->media_relays = NULL;

	if (msg->response >= 400) {
		SIPE_DEBUG_INFO_NOFORMAT("process_get_av_edge_credentials_response: SERVICE response is not 200. "
					 "Failed to obtain A/V Edge credentials.");
		return FALSE;
	}

	if (msg->response == 200) {
		sipe_xml *xn_response = sipe_xml_parse(msg->body, msg->bodylen);

		if (sipe_strequal("OK", sipe_xml_attribute(xn_response, "reasonPhrase"))) {
			const sipe_xml *xn_credentials = sipe_xml_child(xn_response, "credentialsResponse/credentials");
			const sipe_xml *xn_relays = sipe_xml_child(xn_response, "credentialsResponse/mediaRelayList");
			const sipe_xml *item;
			GSList *relays = NULL;

			item = sipe_xml_child(xn_credentials, "username");
			sipe_private->media_relay_username = sipe_xml_data(item);
			item = sipe_xml_child(xn_credentials, "password");
			sipe_private->media_relay_password = sipe_xml_data(item);

			for (item = sipe_xml_child(xn_relays, "mediaRelay"); item; item = sipe_xml_twin(item)) {
				struct sipe_media_relay *relay = g_new0(struct sipe_media_relay, 1);
				const sipe_xml *node;
				gchar *tmp;

				node = sipe_xml_child(item, "hostName");
				relay->hostname = sipe_xml_data(node);

				node = sipe_xml_child(item, "udpPort");
				if (node) {
					tmp = sipe_xml_data(node);
					if (tmp) {
						relay->udp_port = atoi(tmp);
						g_free(tmp);
					}
				}

				node = sipe_xml_child(item, "tcpPort");
				if (node) {
					tmp = sipe_xml_data(node);
					if (tmp) {
						relay->tcp_port = atoi(tmp);
						g_free(tmp);
					}
				}

				relays = g_slist_append(relays, relay);

				relay->dns_query = sipe_backend_dns_query_a(
							SIPE_CORE_PUBLIC,
							relay->hostname,
							relay->udp_port,
							(sipe_dns_resolved_cb) relay_ip_resolved_cb,
							relay);

				SIPE_DEBUG_INFO("Media relay: %s TCP: %d UDP: %d",
						relay->hostname,
						relay->tcp_port, relay->udp_port);
			}

			sipe_private->media_relays = relays;
		}

		sipe_xml_free(xn_response);
	}

	return TRUE;
}

void
sipe_media_get_av_edge_credentials(struct sipe_core_private *sipe_private)
{
	// TODO: re-request credentials after duration expires?
	static const char CRED_REQUEST_XML[] =
		"<request requestID=\"%d\" "
		         "from=\"%s\" "
			 "version=\"1.0\" "
			 "to=\"%s\" "
			 "xmlns=\"http://schemas.microsoft.com/2006/09/sip/mrasp\" "
			 "xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\">"
			"<credentialsRequest credentialsRequestID=\"%d\">"
				"<identity>%s</identity>"
				"<location>%s</location>"
				"<duration>480</duration>"
			"</credentialsRequest>"
		"</request>";

	int request_id = rand();
	gchar *self;
	gchar *body;

	if (!sipe_private->mras_uri)
		return;

	self = sip_uri_self(sipe_private);

	body = g_strdup_printf(
		CRED_REQUEST_XML,
		request_id,
		self,
		sipe_private->mras_uri,
		request_id,
		self,
		SIPE_CORE_PRIVATE_FLAG_IS(REMOTE_USER) ? "internet" : "intranet");
	g_free(self);

	sip_transport_service(sipe_private,
			      sipe_private->mras_uri,
			      "Content-Type: application/msrtc-media-relay-auth+xml\r\n",
			      body,
			      process_get_av_edge_credentials_response);

	g_free(body);
}

void
sipe_media_add_extra_invite_section(struct sipe_media_call *call,
				    const gchar *invite_content_type,
				    gchar *body)
{
	g_free(SIPE_MEDIA_CALL_PRIVATE->extra_invite_section);
	g_free(SIPE_MEDIA_CALL_PRIVATE->invite_content_type);
	SIPE_MEDIA_CALL_PRIVATE->extra_invite_section = body;
	SIPE_MEDIA_CALL_PRIVATE->invite_content_type =
			g_strdup(invite_content_type);
}

void
sipe_media_stream_add_extra_attribute(struct sipe_media_stream *stream,
				      const gchar *name, const gchar *value)
{
	SIPE_MEDIA_STREAM_PRIVATE->extra_sdp =
			sipe_utils_nameval_add(SIPE_MEDIA_STREAM_PRIVATE->extra_sdp,
					       name, value);
}

#ifdef HAVE_XDATA
void
sipe_core_media_stream_readable(struct sipe_media_stream *stream)
{
	g_return_if_fail(stream);

	if (g_queue_is_empty(SIPE_MEDIA_STREAM_PRIVATE->async_reads) &&
	    stream->read_cb) {
		stream->read_cb(stream);
	}

	while (!g_queue_is_empty(SIPE_MEDIA_STREAM_PRIVATE->async_reads)) {
		struct async_read_data *data;
		guint8 *pos;
		gssize len;
		gssize bytes_read;

		data = g_queue_peek_head(SIPE_MEDIA_STREAM_PRIVATE->async_reads);
		pos = data->buffer + SIPE_MEDIA_STREAM_PRIVATE->read_pos;
		len = data->len - SIPE_MEDIA_STREAM_PRIVATE->read_pos;

		bytes_read = sipe_backend_media_stream_read(stream, pos, len);
		if (bytes_read == -1) {
			struct sipe_media_call *call = stream->call;
			struct sipe_core_private *sipe_private =
					SIPE_MEDIA_CALL_PRIVATE->sipe_private;

			sipe_backend_notify_error(SIPE_CORE_PUBLIC,
						  _("Media error"),
						  _("Error while reading from stream"));
			sipe_media_hangup(SIPE_MEDIA_CALL_PRIVATE);
			return;
		}

		SIPE_MEDIA_STREAM_PRIVATE->read_pos += bytes_read;

		if (SIPE_MEDIA_STREAM_PRIVATE->read_pos == data->len) {
			data->callback(stream, data->buffer, data->len);
			SIPE_MEDIA_STREAM_PRIVATE->read_pos = 0;
			g_queue_pop_head(SIPE_MEDIA_STREAM_PRIVATE->async_reads);
			g_free(data);
		} else {
			// Still not enough data to finish the read.
			return;
		}
	}
}

void
sipe_media_stream_read_async(struct sipe_media_stream *stream,
			     gpointer buffer, gsize len,
			     sipe_media_stream_read_callback callback)
{
	struct async_read_data *data;

	g_return_if_fail(stream && buffer && callback);

	data = g_new0(struct async_read_data, 1);
	data->buffer = buffer;
	data->len = len;
	data->callback = callback;

	g_queue_push_tail(SIPE_MEDIA_STREAM_PRIVATE->async_reads, data);
}

static void
stream_append_buffer(struct sipe_media_stream *stream,
		     guint8 *buffer, guint len)
{
	GByteArray *b = g_byte_array_sized_new(len);
	g_byte_array_append(b, buffer, len);
	g_queue_push_tail(SIPE_MEDIA_STREAM_PRIVATE->write_queue, b);
}

gboolean
sipe_media_stream_write(struct sipe_media_stream *stream,
			gpointer buffer, gsize len)
{
	if (!sipe_media_stream_is_writable(stream)) {
		stream_append_buffer(stream, buffer, len);
		return FALSE;
	} else {
		guint written;

		written = sipe_backend_media_stream_write(stream, buffer, len);
		if (written == len) {
			return TRUE;
		}

		stream_append_buffer(stream,
				     (guint8 *)buffer + written, len - written);
		return FALSE;
	}
}

void
sipe_core_media_stream_writable(struct sipe_media_stream *stream,
				gboolean writable)
{
	SIPE_MEDIA_STREAM_PRIVATE->writable = writable;

	if (!writable) {
		return;
	}

	while (!g_queue_is_empty(SIPE_MEDIA_STREAM_PRIVATE->write_queue)) {
		GByteArray *b;
		guint written;

		b = g_queue_peek_head(SIPE_MEDIA_STREAM_PRIVATE->write_queue);

		written = sipe_backend_media_stream_write(stream, b->data, b->len);
		if (written != b->len) {
			g_byte_array_remove_range(b, 0, written);
			return;
		}

		g_byte_array_unref(b);
		g_queue_pop_head(SIPE_MEDIA_STREAM_PRIVATE->write_queue);
	}

	if (sipe_media_stream_is_writable(stream) && stream->writable_cb) {
		stream->writable_cb(stream);
	}
}

gboolean
sipe_media_stream_is_writable(struct sipe_media_stream *stream)
{
	return SIPE_MEDIA_STREAM_PRIVATE->writable &&
	       SIPE_MEDIA_STREAM_PRIVATE->sdp_negotiation_concluded &&
	       g_queue_is_empty(SIPE_MEDIA_STREAM_PRIVATE->write_queue);
}
#endif

void
sipe_media_stream_set_data(struct sipe_media_stream *stream, gpointer data,
			   GDestroyNotify free_func)
{
	struct sipe_media_stream_private *stream_private =
			SIPE_MEDIA_STREAM_PRIVATE;

	g_return_if_fail(stream_private);

	if (stream_private->data && stream_private->data_free_func) {
		stream_private->data_free_func(stream_private->data);
	}

	stream_private->data = data;
	stream_private->data_free_func = free_func;
}

gpointer
sipe_media_stream_get_data(struct sipe_media_stream *stream)
{
	g_return_val_if_fail(stream, NULL);

	return SIPE_MEDIA_STREAM_PRIVATE->data;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
