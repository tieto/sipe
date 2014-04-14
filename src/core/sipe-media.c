/**
 * @file sipe-media.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-2014 SIPE Project <http://sipe.sourceforge.net/>
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
#include "sipe-chat.h"
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

struct sipe_media_call_private {
	struct sipe_media_call public;

	/* private part starts here */
	struct sipe_core_private	*sipe_private;
	gchar				*with;

	struct sipmsg			*invitation;
	SipeIceVersion			 ice_version;
	gboolean			 encryption_compatible;

	struct sdpmsg			*smsg;
	GSList				*failed_media;
};
#define SIPE_MEDIA_CALL         ((struct sipe_media_call *) call_private)
#define SIPE_MEDIA_CALL_PRIVATE ((struct sipe_media_call_private *) call)

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
sipe_media_call_free(struct sipe_media_call_private *call_private)
{
	if (call_private) {
		struct sip_session *session;
		sipe_backend_media_free(call_private->public.backend_private);

		session = sipe_session_find_call(call_private->sipe_private,
						 call_private->with);
		if (session)
			sipe_session_remove(call_private->sipe_private, session);

		if (call_private->invitation)
			sipmsg_free(call_private->invitation);

		sdpmsg_free(call_private->smsg);
		sipe_utils_slist_free_full(call_private->failed_media,
				  (GDestroyNotify)sdpmedia_free);
		g_free(call_private->with);
		g_free(call_private);
	}
}

static gint
candidate_sort_cb(struct sdpcandidate *c1, struct sdpcandidate *c2)
{
	int cmp = sipe_strcompare(c1->foundation, c2->foundation);
	if (cmp == 0) {
		cmp = sipe_strcompare(c1->username, c2->username);
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
		struct sdpcandidate *c = g_new(struct sdpcandidate, 1);

		c->foundation = sipe_backend_candidate_get_foundation(candidate);
		c->component = sipe_backend_candidate_get_component_type(candidate);
		c->type = sipe_backend_candidate_get_type(candidate);
		c->protocol = sipe_backend_candidate_get_protocol(candidate);
		c->ip = sipe_backend_candidate_get_ip(candidate);
		c->port = sipe_backend_candidate_get_port(candidate);
		c->base_ip = sipe_backend_candidate_get_base_ip(candidate);
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
			gchar **ip, guint *rtp_port, guint *rtcp_port,
			SipeCandidateType type)
{
	*ip = 0;
	*rtp_port = 0;
	*rtcp_port = 0;

	for (; candidates; candidates = candidates->next) {
		struct sdpcandidate *candidate = candidates->data;

		if (type == SIPE_CANDIDATE_TYPE_ANY || candidate->type == type) {
			if (!*ip) {
				*ip = g_strdup(candidate->ip);
			} else if (!sipe_strequal(*ip, candidate->ip)) {
				continue;
			}

			if (candidate->component == SIPE_COMPONENT_RTP) {
				*rtp_port = candidate->port;
			} else if (candidate->component == SIPE_COMPONENT_RTCP)
				*rtcp_port = candidate->port;
		}

		if (*rtp_port != 0 && *rtcp_port != 0)
			return;
	}
}

static gint
sdpcodec_compare(gconstpointer a, gconstpointer b)
{
	return ((const struct sdpcodec *)a)->id -
	       ((const struct sdpcodec *)b)->id;
}

static struct sdpmedia *
backend_stream_to_sdpmedia(struct sipe_backend_media *backend_media,
			   struct sipe_backend_stream *backend_stream)
{
	struct sdpmedia *media = g_new0(struct sdpmedia, 1);
	GList *codecs = sipe_backend_get_local_codecs(backend_media,
						      backend_stream);
	guint rtcp_port = 0;
	SipeMediaType type;
	GSList *attributes = NULL;
	GList *candidates;
	GList *i;

	media->name = g_strdup(sipe_backend_stream_get_id(backend_stream));

	if (sipe_strequal(media->name, "audio"))
		type = SIPE_MEDIA_AUDIO;
	else if (sipe_strequal(media->name, "video"))
		type = SIPE_MEDIA_VIDEO;
	else {
		// TODO: incompatible media, should not happen here
		g_free(media->name);
		g_free(media);
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
		media->codecs = sipe_utils_slist_insert_unique_sorted(
				media->codecs, c, sdpcodec_compare,
				(GDestroyNotify)sdpcodec_free);
	}

	sipe_media_codec_list_free(codecs);

	// Process local candidates
	// If we have established candidate pairs, send them in SDP response.
	// Otherwise send all available local candidates.
	candidates = sipe_backend_media_get_active_local_candidates(backend_media,
								    backend_stream);
	if (!candidates)
		candidates = sipe_backend_get_local_candidates(backend_media,
							       backend_stream);

	media->candidates = backend_candidates_to_sdpcandidate(candidates);

	sipe_media_candidate_list_free(candidates);

	get_stream_ip_and_ports(media->candidates, &media->ip, &media->port,
				&rtcp_port, SIPE_CANDIDATE_TYPE_HOST);
	// No usable HOST candidates, use any candidate
	if (media->ip == NULL && media->candidates) {
		get_stream_ip_and_ports(media->candidates, &media->ip, &media->port,
					&rtcp_port, SIPE_CANDIDATE_TYPE_ANY);
	}

	if (sipe_backend_stream_is_held(backend_stream))
		attributes = sipe_utils_nameval_add(attributes, "inactive", "");

	if (rtcp_port) {
		gchar *tmp = g_strdup_printf("%u", rtcp_port);
		attributes  = sipe_utils_nameval_add(attributes, "rtcp", tmp);
		g_free(tmp);
	}

	attributes = sipe_utils_nameval_add(attributes, "encryption", "rejected");

	media->attributes = attributes;

	// Process remote candidates
	candidates = sipe_backend_media_get_active_remote_candidates(backend_media,
								     backend_stream);
	media->remote_candidates = backend_candidates_to_sdpcandidate(candidates);
	sipe_media_candidate_list_free(candidates);

	return media;
}

static struct sdpmsg *
sipe_media_to_sdpmsg(struct sipe_media_call_private *call_private)
{
	struct sipe_backend_media *backend_media = call_private->public.backend_private;
	struct sdpmsg *msg = g_new0(struct sdpmsg, 1);
	GSList *streams = sipe_backend_media_get_streams(backend_media);

	for (; streams; streams = streams->next) {
		struct sdpmedia *media = backend_stream_to_sdpmedia(backend_media, streams->data);
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
sipe_invite_call(struct sipe_core_private *sipe_private, TransCallback tc)
{
	gchar *hdr;
	gchar *contact;
	gchar *p_preferred_identity = NULL;
	gchar *body;
	struct sipe_media_call_private *call_private = sipe_private->media_call;
	struct sip_session *session;
	struct sip_dialog *dialog;
	struct sdpmsg *msg;
	gboolean add_2007_fallback = FALSE;

	session = sipe_session_find_call(sipe_private, call_private->with);
	dialog = session->dialogs->data;
	add_2007_fallback = dialog->cseq == 0 &&
		call_private->ice_version == SIPE_ICE_RFC_5245 &&
		!sipe_strequal(call_private->with, sipe_private->test_call_bot_uri);

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
		"Content-Type: %s\r\n",
		contact,
		p_preferred_identity ? p_preferred_identity : "",
		add_2007_fallback ?
			  "multipart/alternative;boundary=\"----=_NextPart_000_001E_01CB4397.0B5EB570\""
			: "application/sdp");
	g_free(contact);
	g_free(p_preferred_identity);

	msg = sipe_media_to_sdpmsg(call_private);
	body = sdpmsg_to_string(msg);

	if (add_2007_fallback) {
		gchar *tmp;
		tmp = g_strdup_printf(
			"------=_NextPart_000_001E_01CB4397.0B5EB570\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Transfer-Encoding: 7bit\r\n"
			"Content-Disposition: session; handling=optional; ms-proxy-2007fallback\r\n"
			"\r\n"
			"o=- 0 0 IN IP4 %s\r\n"
			"s=session\r\n"
			"c=IN IP4 %s\r\n"
			"m=audio 0 RTP/AVP\r\n"
			"\r\n"
			"------=_NextPart_000_001E_01CB4397.0B5EB570\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Transfer-Encoding: 7bit\r\n"
			"Content-Disposition: session; handling=optional\r\n"
			"\r\n"
			"%s"
			"\r\n"
			"------=_NextPart_000_001E_01CB4397.0B5EB570--\r\n",
			msg->ip, msg->ip, body);
		g_free(body);
		body = tmp;
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
	dialog->callid = g_strdup(sipmsg_find_header(msg, "Call-ID"));
	dialog->with = parse_from(sipmsg_find_header(msg, "From"));
	sipe_dialog_parse(dialog, msg, FALSE);

	return dialog;
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
encryption_levels_compatible(struct sdpmsg *msg)
{
	GSList *i;

	for (i = msg->media; i; i = i->next) {
		const gchar *enc_level;
		struct sdpmedia *m = i->data;

		enc_level = sipe_utils_nameval_find(m->attributes, "encryption");

		// Decline call if peer requires encryption as we don't support it yet.
		if (sipe_strequal(enc_level, "required"))
			return FALSE;
	}

	return TRUE;
}

static gboolean
process_invite_call_response(struct sipe_core_private *sipe_private,
								   struct sipmsg *msg,
								   struct transaction *trans);

static gboolean
update_remote_media(struct sipe_media_call_private* call_private,
		    struct sdpmedia *media)
{
	struct sipe_backend_media *backend_media = SIPE_MEDIA_CALL->backend_private;
	struct sipe_backend_stream *backend_stream;
	GList *backend_candidates = NULL;
	GList *backend_codecs = NULL;
	GSList *i;
	gboolean result = TRUE;

	backend_stream = sipe_backend_media_get_stream_by_id(backend_media,
							     media->name);
	if (media->port == 0) {
		if (backend_stream)
			sipe_backend_media_remove_stream(backend_media, backend_stream);
		return TRUE;
	}

	if (!backend_stream)
		return FALSE;

	for (i = media->codecs; i; i = i->next) {
		struct sdpcodec *c = i->data;
		struct sipe_backend_codec *codec;
		GSList *j;

		codec = sipe_backend_codec_new(c->id,
					       c->name,
					       c->type,
					       c->clock_rate);

		for (j = c->parameters; j; j = j->next) {
			struct sipnameval *attr = j->data;

			sipe_backend_codec_add_optional_parameter(codec,
								  attr->name,
								  attr->value);
		}

		backend_codecs = g_list_append(backend_codecs, codec);
	}

	result = sipe_backend_set_remote_codecs(backend_media,
						backend_stream,
						backend_codecs);
	sipe_media_codec_list_free(backend_codecs);

	if (result == FALSE) {
		sipe_backend_media_remove_stream(backend_media, backend_stream);
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

	sipe_backend_media_add_remote_candidates(backend_media,
						 backend_stream,
						 backend_candidates);
	sipe_media_candidate_list_free(backend_candidates);

	if (sipe_utils_nameval_find(media->attributes, "inactive")) {
		sipe_backend_stream_hold(backend_media, backend_stream, FALSE);
	} else if (sipe_backend_stream_is_held(backend_stream)) {
		sipe_backend_stream_unhold(backend_media, backend_stream, FALSE);
	}

	return TRUE;
}

static void
apply_remote_message(struct sipe_media_call_private* call_private,
		     struct sdpmsg* msg)
{
	GSList *i;

	sipe_utils_slist_free_full(call_private->failed_media, (GDestroyNotify)sdpmedia_free);
	call_private->failed_media = NULL;

	for (i = msg->media; i; i = i->next) {
		struct sdpmedia *media = i->data;
		if (!update_remote_media(call_private, media)) {
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

	call_private->encryption_compatible = encryption_levels_compatible(msg);
}

static gboolean
call_initialized(struct sipe_media_call *call)
{
	GSList *streams =
		sipe_backend_media_get_streams(call->backend_private);

	for (; streams; streams = streams->next) {
		if (!sipe_backend_stream_initialized(call->backend_private,
						     streams->data)) {
			return FALSE;
		}
	}

	return TRUE;
}

// Sends an invite response when the call is accepted and local candidates were
// prepared, otherwise does nothing. If error response is sent, call_private is
// disposed before function returns. Returns true when response was sent.
static gboolean
send_invite_response_if_ready(struct sipe_media_call_private *call_private)
{
	struct sipe_backend_media *backend_media;

	backend_media = call_private->public.backend_private;

	if (!sipe_backend_media_accepted(backend_media) ||
	    !call_initialized(&call_private->public))
		return FALSE;

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
	}

	return TRUE;
}

static void
stream_initialized_cb(struct sipe_media_call *call,
		      struct sipe_backend_stream *stream)
{
	if (call_initialized(call)) {
		struct sipe_media_call_private *call_private = SIPE_MEDIA_CALL_PRIVATE;
		struct sipe_backend_media *backend_private = call->backend_private;

		if (sipe_backend_media_is_initiator(backend_private, stream)) {
			sipe_invite_call(call_private->sipe_private,
					 process_invite_call_response);
		} else if (call_private->smsg) {
			struct sdpmsg *smsg = call_private->smsg;
			call_private->smsg = NULL;

			apply_remote_message(call_private, smsg);
			send_invite_response_if_ready(call_private);
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

static void
media_end_cb(struct sipe_media_call *call)
{
	g_return_if_fail(call);

	SIPE_MEDIA_CALL_PRIVATE->sipe_private->media_call = NULL;
	phone_state_publish(SIPE_MEDIA_CALL_PRIVATE->sipe_private);
	sipe_media_call_free(SIPE_MEDIA_CALL_PRIVATE);
}

static void
call_accept_cb(struct sipe_media_call *call, gboolean local)
{
	if (local) {
		send_invite_response_if_ready(SIPE_MEDIA_CALL_PRIVATE);
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
	}
}

static gboolean
sipe_media_send_ack(struct sipe_core_private *sipe_private, struct sipmsg *msg,
					struct transaction *trans);

static void call_hold_cb(struct sipe_media_call *call,
			 gboolean local,
			 SIPE_UNUSED_PARAMETER gboolean state)
{
	if (local)
		sipe_invite_call(SIPE_MEDIA_CALL_PRIVATE->sipe_private,
				 sipe_media_send_ack);
}

static void call_hangup_cb(struct sipe_media_call *call, gboolean local)
{
	if (local) {
		struct sipe_media_call_private *call_private = SIPE_MEDIA_CALL_PRIVATE;
		struct sip_session *session;
		session = sipe_session_find_call(call_private->sipe_private,
						 call_private->with);

		if (session) {
			sipe_session_close(call_private->sipe_private, session);
		}
	}
}

static void
error_cb(struct sipe_media_call *call, gchar *message)
{
	struct sipe_media_call_private *call_private = SIPE_MEDIA_CALL_PRIVATE;
	struct sipe_core_private *sipe_private = call_private->sipe_private;
	gboolean initiator = sipe_backend_media_is_initiator(call->backend_private, NULL);
	gboolean accepted = sipe_backend_media_accepted(call->backend_private);

	gchar *title = g_strdup_printf("Call with %s failed", call_private->with);
	sipe_backend_notify_error(SIPE_CORE_PUBLIC, title, message);
	g_free(title);

	if (!initiator && !accepted) {
		sip_transport_response(sipe_private,
				       call_private->invitation,
				       488, "Not Acceptable Here", NULL);
	}

	sipe_backend_media_hangup(call->backend_private, initiator || accepted);
}

static struct sipe_media_call_private *
sipe_media_call_new(struct sipe_core_private *sipe_private,
		    const gchar* with, gboolean initiator, SipeIceVersion ice_version)
{
	struct sipe_media_call_private *call_private = g_new0(struct sipe_media_call_private, 1);
	gchar *cname;

	call_private->sipe_private = sipe_private;

	cname = g_strdup(sipe_private->contact + 1);
	cname[strlen(cname) - 1] = '\0';

	call_private->public.backend_private = sipe_backend_media_new(SIPE_CORE_PUBLIC,
								      SIPE_MEDIA_CALL,
								      with,
								      initiator);
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

	return call_private;
}

void sipe_media_hangup(struct sipe_media_call_private *call_private)
{
	if (call_private) {
		sipe_backend_media_hangup(call_private->public.backend_private,
					  FALSE);
	}
}

static void
sipe_media_initiate_call(struct sipe_core_private *sipe_private,
			 const char *with, SipeIceVersion ice_version,
			 gboolean with_video)
{
	struct sipe_media_call_private *call_private;
	struct sipe_backend_media *backend_media;
	struct sipe_backend_media_relays *backend_media_relays;
	struct sip_session *session;
	struct sip_dialog *dialog;

	if (sipe_private->media_call)
		return;

	call_private = sipe_media_call_new(sipe_private, with, TRUE, ice_version);

	session = sipe_session_add_call(sipe_private, with);
	dialog = sipe_dialog_add(session);
	dialog->callid = gencallid();
	dialog->with = g_strdup(session->with);
	dialog->ourtag = gentag();

	call_private->with = g_strdup(session->with);

	backend_media = call_private->public.backend_private;

	backend_media_relays =
		sipe_backend_media_relays_convert(sipe_private->media_relays,
						  sipe_private->media_relay_username,
						  sipe_private->media_relay_password);

	if (!sipe_backend_media_add_stream(backend_media,
					   "audio", with, SIPE_MEDIA_AUDIO,
					   call_private->ice_version, TRUE,
					   backend_media_relays)) {
		sipe_backend_notify_error(SIPE_CORE_PUBLIC,
					  _("Error occured"),
					  _("Error creating audio stream"));
		sipe_media_hangup(call_private);
		sipe_backend_media_relays_free(backend_media_relays);
		return;
	}

	if (   with_video
	    && !sipe_backend_media_add_stream(backend_media,
			    	    	      "video", with, SIPE_MEDIA_VIDEO,
			    	    	      call_private->ice_version, TRUE,
			    	    	      backend_media_relays)) {
		sipe_backend_notify_error(SIPE_CORE_PUBLIC,
					  _("Error occured"),
					  _("Error creating video stream"));
		sipe_media_hangup(call_private);
		sipe_backend_media_relays_free(backend_media_relays);
		return;
	}

	sipe_private->media_call = call_private;

	sipe_backend_media_relays_free(backend_media_relays);

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

void sipe_core_media_connect_conference(struct sipe_core_public *sipe_public,
					struct sipe_chat_session *chat_session)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_backend_media_relays *backend_media_relays;
	struct sip_session *session;
	struct sip_dialog *dialog;
	SipeIceVersion ice_version;
	gchar **parts;
	gchar *av_uri;

	session = sipe_session_find_chat(sipe_private, chat_session);

	if (sipe_private->media_call || !session)
		return;

	session->is_call = TRUE;

	parts = g_strsplit(chat_session->id, "app:conf:focus:", 2);
	av_uri = g_strjoinv("app:conf:audio-video:", parts);
	g_strfreev(parts);

	ice_version = SIPE_CORE_PRIVATE_FLAG_IS(LYNC2013) ? SIPE_ICE_RFC_5245 :
							    SIPE_ICE_DRAFT_6;

	sipe_private->media_call = sipe_media_call_new(sipe_private, av_uri,
						       TRUE, ice_version);

	session = sipe_session_add_call(sipe_private, av_uri);
	dialog = sipe_dialog_add(session);
	dialog->callid = gencallid();
	dialog->with = g_strdup(session->with);
	dialog->ourtag = gentag();

	g_free(av_uri);

	sipe_private->media_call->with = g_strdup(session->with);

	backend_media_relays =
		sipe_backend_media_relays_convert(sipe_private->media_relays,
						  sipe_private->media_relay_username,
						  sipe_private->media_relay_password);

	if (!sipe_backend_media_add_stream(sipe_private->media_call->public.backend_private,
					   "audio", dialog->with,
					   SIPE_MEDIA_AUDIO,
					   sipe_private->media_call->ice_version,
					   TRUE, backend_media_relays)) {
		sipe_backend_notify_error(sipe_public,
					  _("Error occured"),
					  _("Error creating audio stream"));
		sipe_media_hangup(sipe_private->media_call);
		sipe_private->media_call = NULL;
	}

	sipe_backend_media_relays_free(backend_media_relays);

	// Processing continues in stream_initialized_cb
}

gboolean sipe_core_media_in_call(struct sipe_core_public *sipe_public)
{
	if (sipe_public) {
		return SIPE_CORE_PRIVATE->media_call != NULL;
	}
	return FALSE;
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

void
process_incoming_invite_call(struct sipe_core_private *sipe_private,
			     struct sipmsg *msg)
{
	struct sipe_media_call_private *call_private = sipe_private->media_call;
	struct sipe_backend_media *backend_media;
	struct sipe_backend_media_relays *backend_media_relays = NULL;
	struct sdpmsg *smsg;
	gboolean has_new_media = FALSE;
	GSList *i;

	if (call_private) {
		char *self;

		if (!is_media_session_msg(call_private, msg)) {
			sip_transport_response(sipe_private, msg, 486, "Busy Here", NULL);
			return;
		}

		self = sip_uri_self(sipe_private);
		if (sipe_strequal(call_private->with, self)) {
			g_free(self);
			sip_transport_response(sipe_private, msg, 488, "Not Acceptable Here", NULL);
			return;
		}
		g_free(self);
	}

	smsg = sdpmsg_parse_msg(msg->body);
	if (!smsg) {
		sip_transport_response(sipe_private, msg,
				       488, "Not Acceptable Here", NULL);
		sipe_media_hangup(call_private);
		return;
	}

	if (!call_private) {
		gchar *with = parse_from(sipmsg_find_header(msg, "From"));
		struct sip_session *session;

		call_private = sipe_media_call_new(sipe_private, with, FALSE, smsg->ice_version);
		session = sipe_session_add_call(sipe_private, with);
		sipe_media_dialog_init(session, msg);

		call_private->with = g_strdup(session->with);
		sipe_private->media_call = call_private;
		g_free(with);
	}

	backend_media = call_private->public.backend_private;

	if (call_private->invitation)
		sipmsg_free(call_private->invitation);
	call_private->invitation = sipmsg_copy(msg);

	if (smsg->media)
		backend_media_relays = sipe_backend_media_relays_convert(
						sipe_private->media_relays,
						sipe_private->media_relay_username,
						sipe_private->media_relay_password);

	// Create any new media streams
	for (i = smsg->media; i; i = i->next) {
		struct sdpmedia *media = i->data;
		gchar *id = media->name;
		SipeMediaType type;

		if (   media->port != 0
		    && !sipe_backend_media_get_stream_by_id(backend_media, id)) {
			gchar *with;

			if (sipe_strequal(id, "audio"))
				type = SIPE_MEDIA_AUDIO;
			else if (sipe_strequal(id, "video"))
				type = SIPE_MEDIA_VIDEO;
			else
				continue;

			with = parse_from(sipmsg_find_header(msg, "From"));
			sipe_backend_media_add_stream(backend_media, id, with,
						      type,
						      smsg->ice_version,
						      FALSE,
						      backend_media_relays);
			has_new_media = TRUE;
			g_free(with);
		}
	}

	sipe_backend_media_relays_free(backend_media_relays);

	if (has_new_media) {
		sdpmsg_free(call_private->smsg);
		call_private->smsg = smsg;
		sip_transport_response(sipe_private, call_private->invitation,
				       180, "Ringing", NULL);
		// Processing continues in stream_initialized_cb
	} else {
		apply_remote_message(call_private, smsg);
		send_response_with_session_description(call_private, 200, "OK");

		sdpmsg_free(smsg);
	}
}

void process_incoming_cancel_call(struct sipe_core_private *sipe_private,
				  struct sipmsg *msg)
{
	struct sipe_media_call_private *call_private = sipe_private->media_call;

	// We respond to the CANCEL request with 200 OK response and
	// with 487 Request Terminated to the remote INVITE in progress.
	sip_transport_response(sipe_private, msg, 200, "OK", NULL);

	if (call_private->invitation) {
		sip_transport_response(sipe_private, call_private->invitation,
				       487, "Request Terminated", NULL);
	}

	sipe_media_hangup(call_private);
}

static gboolean
sipe_media_send_ack(struct sipe_core_private *sipe_private,
		    struct sipmsg *msg,
		    struct transaction *trans)
{
	struct sipe_media_call_private *call_private = sipe_private->media_call;
	struct sip_session *session;
	struct sip_dialog *dialog;
	int tmp_cseq;

	if (!is_media_session_msg(call_private, msg))
		return FALSE;

	session = sipe_session_find_call(sipe_private, call_private->with);
	dialog = session->dialogs->data;
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
	if (!sipe_media_send_ack(sipe_private, msg, trans))
		return FALSE;

	sipe_backend_media_accept(sipe_private->media_call->public.backend_private,
				  FALSE);

	return TRUE;
}

static void
reinvite_on_candidate_pair_cb(struct sipe_core_public *sipe_public)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_media_call_private *media_call = sipe_private->media_call;
	struct sipe_backend_media *backend_media;
	GSList *streams;

	if (!media_call)
		return;

	backend_media = media_call->public.backend_private;
	streams = sipe_backend_media_get_streams(backend_media);

	for (; streams; streams = streams->next) {
		struct sipe_backend_stream *s = streams->data;
		GList *remote_candidates =  sipe_backend_media_get_active_remote_candidates(backend_media, s);
		guint components = g_list_length(remote_candidates);

		sipe_media_candidate_list_free(remote_candidates);

		// We must have candidates for both (RTP + RTCP) components ready
		if (components < 2) {
			sipe_schedule_mseconds(sipe_private,
					       "<+media-reinvite-on-candidate-pair>",
					       NULL,
					       500,
					       (sipe_schedule_action) reinvite_on_candidate_pair_cb,
					       NULL);
			return;
		}
	}

	sipe_invite_call(sipe_private, sipe_media_send_final_ack);
}

static gboolean
maybe_retry_call_with_ice_version(struct sipe_core_private *sipe_private,
				  SipeIceVersion ice_version,
				  struct transaction *trans)
{
	struct sipe_media_call_private *call_private = sipe_private->media_call;

	if (call_private->ice_version != ice_version &&
	    sip_transaction_cseq(trans) == 1) {
		gchar *with = g_strdup(call_private->with);
		struct sipe_backend_media *backend_private = call_private->public.backend_private;
		gboolean with_video = sipe_backend_media_get_stream_by_id(backend_private, "video") != NULL;

		sipe_media_hangup(call_private);
		SIPE_DEBUG_INFO("Retrying call with ICEv%d.",
				ice_version == SIPE_ICE_DRAFT_6 ? 6 : 19);
		sipe_media_initiate_call(sipe_private, with, ice_version,
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
	struct sipe_media_call_private *call_private = sipe_private->media_call;
	struct sip_session *session;
	struct sip_dialog *dialog;
	struct sdpmsg *smsg;

	if (!is_media_session_msg(call_private, msg))
		return FALSE;

	session = sipe_session_find_call(sipe_private, call_private->with);
	dialog = session->dialogs->data;

	with = dialog->with;

	dialog->outgoing_invite = NULL;

	if (msg->response >= 400) {
		// Call rejected by remote peer or an error occurred
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
			case 603:
			case 605:
				title = _("Call rejected");
				g_string_append_printf(desc, _("User %s rejected call"), with);
				break;
			case 415:
				// OCS/Lync really sends response string with 'Mutipart' typo.
				if (sipe_strequal(msg->responsestr, "Mutipart mime in content type not supported by Archiving CDR service") &&
				    maybe_retry_call_with_ice_version(sipe_private, SIPE_ICE_DRAFT_6, trans)) {
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

				if (maybe_retry_call_with_ice_version(sipe_private, retry_ice_version, trans)) {
					return TRUE;
				}
				// Break intentionally omitted
			}
			default:
				title = _("Error occured");
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
		sip_transport_response(sipe_private, msg,
				       488, "Not Acceptable Here", NULL);
		sipe_media_hangup(call_private);
		return FALSE;
	}

	apply_remote_message(call_private, smsg);
	sdpmsg_free(smsg);

	sipe_media_send_ack(sipe_private, msg, trans);
	reinvite_on_candidate_pair_cb(SIPE_CORE_PUBLIC);

	return TRUE;
}

gboolean is_media_session_msg(struct sipe_media_call_private *call_private,
			      struct sipmsg *msg)
{
	if (call_private) {
		const gchar *callid = sipmsg_find_header(msg, "Call-ID");
		struct sip_session *session;

		session = sipe_session_find_call(call_private->sipe_private,
						 call_private->with);
		if (session) {
			struct sip_dialog *dialog = session->dialogs->data;
			return sipe_strequal(dialog->callid, callid);
		}
	}
	return FALSE;
}

void sipe_media_handle_going_offline(struct sipe_media_call_private *call_private)
{
	struct sipe_backend_media *backend_private;

	backend_private = call_private->public.backend_private;

	if (   !sipe_backend_media_is_initiator(backend_private, NULL)
	    && !sipe_backend_media_accepted(backend_private)) {
		sip_transport_response(call_private->sipe_private,
				       call_private->invitation,
				       480, "Temporarily Unavailable", NULL);
	} else {
		struct sip_session *session;

		session = sipe_session_find_call(call_private->sipe_private,
						 call_private->with);
		if (session)
			sipe_session_close(call_private->sipe_private, session);
	}

	sipe_media_hangup(call_private);
}

gboolean sipe_media_is_conference_call(struct sipe_media_call_private *call_private)
{
	return g_strstr_len(call_private->with, -1, "app:conf:audio-video:") != NULL;
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
					relay->udp_port = atoi(tmp = sipe_xml_data(node));
					g_free(tmp);
				}

				node = sipe_xml_child(item, "tcpPort");
				if (node) {
					relay->tcp_port = atoi(tmp = sipe_xml_data(node));
					g_free(tmp);
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
	const char CRED_REQUEST_XML[] =
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

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
