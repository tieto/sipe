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

#include <stdio.h>
#include <stdlib.h>

#include <glib.h>

#include "sipe-common.h"
#include "sipmsg.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sdpmsg.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-dialog.h"
#include "sipe-media.h"
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

	unsigned short			 medias_initialized;
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
		sipe_backend_media_free(call_private->public.backend_private_legacy);

		session = sipe_session_find_call(call_private->sipe_private,
						 call_private->with);
		if (session)
			sipe_session_remove(call_private->sipe_private, session);

		if (call_private->invitation)
			sipmsg_free(call_private->invitation);

		sdpmsg_free(call_private->smsg);
		g_free(call_private->with);
		g_free(call_private);
	}
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

		result = g_slist_append(result, c);
	}

	return result;
}

static void
get_stream_ip_and_ports(GSList *candidates,
			gchar **ip, guint *rtp_port, guint *rtcp_port,
			SipeCandidateType type)
{
	*rtp_port = 0;
	*rtcp_port = 0;

	for (; candidates; candidates = candidates->next) {
		struct sdpcandidate *candidate = candidates->data;

		if (type == SIPE_CANDIDATE_TYPE_ANY || candidate->type == type) {
			if (candidate->component == SIPE_COMPONENT_RTP) {
				*rtp_port = candidate->port;
				*ip = g_strdup(candidate->ip);
			} else if (candidate->component == SIPE_COMPONENT_RTCP)
				*rtcp_port = candidate->port;
		}

		if (*rtp_port != 0 && *rtcp_port != 0)
			return;
	}
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

		media->codecs = g_slist_append(media->codecs, c);
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
sipe_media_to_sdpmsg(struct sipe_backend_media *backend_media, SipeIceVersion ice_version)
{
	struct sdpmsg *msg = g_new0(struct sdpmsg, 1);
	GSList *streams = sipe_backend_media_get_streams(backend_media);

	for (; streams; streams = streams->next) {
		struct sdpmedia *media;
		media = backend_stream_to_sdpmedia(backend_media, streams->data);
		msg->media = g_slist_append(msg->media, media);

		if (msg->ip == NULL)
			msg->ip = g_strdup(media->ip);
	}

	msg->ice_version = ice_version;

	return msg;
}

static void
sipe_invite_call(struct sipe_core_private *sipe_private, TransCallback tc)
{
	gchar *hdr;
	gchar *contact;
	gchar *body;
	struct sipe_media_call_private *call_private = sipe_private->media_call;
	struct sip_session *session;
	struct sip_dialog *dialog;
	struct sdpmsg *msg1;
	struct sdpmsg *msg2 = NULL;

	session = sipe_session_find_call(sipe_private, call_private->with);
	dialog = session->dialogs->data;

	contact = get_contact(sipe_private);
	hdr = g_strdup_printf(
		"Supported: ms-early-media\r\n"
		"Supported: 100rel\r\n"
		"ms-keep-alive: UAC;hop-hop=yes\r\n"
		"Contact: %s\r\n"
		"Content-Type: %s\r\n",
		contact,
		call_private->public.backend_private_legacy ?
			  "multipart/alternative;boundary=\"----=_NextPart_000_001E_01CB4397.0B5EB570\""
			: "application/sdp");
	g_free(contact);

	msg1 = sipe_media_to_sdpmsg(call_private->public.backend_private,
				    call_private->ice_version);

	if (call_private->public.backend_private_legacy) {
		gchar *body1 = body = sdpmsg_to_string(msg1);
		gchar *body2;

		msg2 = sipe_media_to_sdpmsg(call_private->public.backend_private_legacy,
					    SIPE_ICE_DRAFT_6);

		body2 = sdpmsg_to_string(msg2);

		body = g_strdup_printf(
			"------=_NextPart_000_001E_01CB4397.0B5EB570\r\n"
			"Content-Type: application/sdp\r\n"
			"Content-Transfer-Encoding: 7bit\r\n"
			"Content-Disposition: session; handling=optional; ms-proxy-2007fallback\r\n"
			"\r\n"
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
			body2,
			body1);

		g_free(body1);
		g_free(body2);
	} else
		body = sdpmsg_to_string(msg1);

	sdpmsg_free(msg1);
	sdpmsg_free(msg2);

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
	struct sdpmsg *msg = sipe_media_to_sdpmsg(call_private->public.backend_private,
						  call_private->ice_version);
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

static void
handle_incompatible_encryption_level(struct sipe_media_call_private *call_private)
{
	sipmsg_add_header(call_private->invitation, "Warning",
			  "308 lcs.microsoft.com \"Encryption Levels not compatible\"");
	sip_transport_response(call_private->sipe_private,
			       call_private->invitation,
			       488, "Encryption Levels not compatible",
			       NULL);
	sipe_backend_media_reject(call_private->public.backend_private, FALSE);
	sipe_backend_notify_error(_("Unable to establish a call"),
		_("Encryption settings of peer are incompatible with ours."));
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

	if (sipe_utils_nameval_find(media->attributes, "inactive")) {
		sipe_backend_stream_hold(backend_media, backend_stream, FALSE);
	} else if (sipe_backend_stream_is_held(backend_stream)) {
		sipe_backend_stream_unhold(backend_media, backend_stream, FALSE);
	}

	return result;
}

static gboolean
apply_remote_message(struct sipe_media_call_private* call_private,
		     struct sdpmsg* msg)
{
	GSList *i;
	for (i = msg->media; i; i = i->next) {
		if (!update_remote_media(call_private, i->data))
			return FALSE;
	}

	call_private->ice_version = msg->ice_version;
	call_private->encryption_compatible = encryption_levels_compatible(msg);

	return TRUE;
}

static void
do_apply_remote_message(struct sipe_media_call_private *call_private,
			struct sdpmsg *smsg)
{
	if (!apply_remote_message(call_private, smsg)) {
		sip_transport_response(call_private->sipe_private,
				       call_private->invitation,
				       487, "Request Terminated", NULL);
		sipe_media_hangup(call_private->sipe_private);
		return;
	}

	sdpmsg_free(call_private->smsg);
	call_private->smsg = NULL;

	if (sipe_backend_media_accepted(call_private->public.backend_private)) {
		send_response_with_session_description(call_private,
						       200, "OK");
		return;
	}

	if (   call_private->ice_version == SIPE_ICE_RFC_5245
	    && call_private->encryption_compatible)
		send_response_with_session_description(call_private,
						       183, "Session Progress");
}

static void candidates_prepared_cb(struct sipe_media_call *call,
				   struct sipe_backend_stream *stream)
{
	struct sipe_media_call_private *call_private = SIPE_MEDIA_CALL_PRIVATE;

	++call_private->medias_initialized;
	if (call->backend_private_legacy && call_private->medias_initialized == 1)
		return;

	if (sipe_backend_media_is_initiator(call_private->public.backend_private,
					    stream)) {
		sipe_invite_call(call_private->sipe_private,
				 process_invite_call_response);
		return;
	} else {
		struct sdpmsg *smsg = call_private->smsg;
		call_private->smsg = NULL;

		do_apply_remote_message(call_private, smsg);
		sdpmsg_free(call_private->smsg);
	}
}

static void media_connected_cb(SIPE_UNUSED_PARAMETER struct sipe_media_call_private *call_private)
{
}

static void call_accept_cb(struct sipe_media_call *call, gboolean local)
{
	if (local) {
		struct sipe_media_call_private *call_private = SIPE_MEDIA_CALL_PRIVATE;

		if (!call_private->encryption_compatible) {
			handle_incompatible_encryption_level(call_private);
			return;
		}

		send_response_with_session_description(call_private, 200, "OK");
	}
}

static void call_reject_cb(struct sipe_media_call *call, gboolean local)
{
	struct sipe_media_call_private *call_private = SIPE_MEDIA_CALL_PRIVATE;

	if (local) {
		sip_transport_response(call_private->sipe_private, call_private->invitation, 603, "Decline", NULL);
	}
	call_private->sipe_private->media_call = NULL;
	sipe_media_call_free(call_private);
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

static void call_hangup_cb(struct sipe_media_call *call,
			   struct sipe_backend_media *backend_media,
			   gboolean local)
{
	sipe_backend_media_free(backend_media);

	if (call->backend_private == backend_media)
		call->backend_private = NULL;
	else if (call->backend_private_legacy == backend_media)
		call->backend_private_legacy = NULL;

	if (!call->backend_private && !call->backend_private_legacy) {
		// All backend medias freed, hangup whole media call
		struct sipe_media_call_private *call_private = SIPE_MEDIA_CALL_PRIVATE;

		if (local) {
			struct sip_session *session;
			session = sipe_session_find_call(call_private->sipe_private,
							 call_private->with);

			if (session) {
				sipe_session_close(call_private->sipe_private, session);
			}
		}

		call_private->sipe_private->media_call = NULL;
		sipe_media_call_free(call_private);
	}
}

static struct sipe_media_call_private *
sipe_media_call_new(struct sipe_core_private *sipe_private,
		    const gchar* with, gboolean initiator)
{
	struct sipe_media_call_private *call_private = g_new0(struct sipe_media_call_private, 1);

	call_private->sipe_private = sipe_private;
	call_private->public.backend_private = sipe_backend_media_new(SIPE_CORE_PUBLIC,
								      SIPE_MEDIA_CALL,
								      with,
								      initiator);
	call_private->ice_version = SIPE_ICE_RFC_5245;
	call_private->encryption_compatible = TRUE;

	call_private->public.candidates_prepared_cb = candidates_prepared_cb;
	call_private->public.media_connected_cb     = media_connected_cb;
	call_private->public.call_accept_cb         = call_accept_cb;
	call_private->public.call_reject_cb         = call_reject_cb;
	call_private->public.call_hold_cb           = call_hold_cb;
	call_private->public.call_hangup_cb         = call_hangup_cb;

	return call_private;
}

void sipe_media_hangup(struct sipe_core_private *sipe_private)
{
	struct sipe_media_call_private *call_private = sipe_private->media_call;
	if (call_private) {
		// This MUST be freed first
		sipe_backend_media_hangup(call_private->public.backend_private_legacy,
					  FALSE);
		sipe_backend_media_hangup(call_private->public.backend_private,
					  FALSE);
	}
}

void
sipe_core_media_initiate_call(struct sipe_core_public *sipe_public,
			      const char *with,
			      gboolean with_video)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_media_call_private *call_private;
	struct sipe_backend_media *backend_media;
	struct sipe_backend_media *backend_media_legacy;
	struct sipe_backend_media_relays *backend_media_relays;
	struct sip_session *session;
	struct sip_dialog *dialog;

	if (sipe_private->media_call)
		return;

	call_private = sipe_media_call_new(sipe_private, with, TRUE);

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
					   SIPE_ICE_RFC_5245, TRUE,
					   backend_media_relays)) {
		sipe_backend_notify_error(_("Error occured"),
					  _("Error creating audio stream"));
		sipe_media_call_free(call_private);
		return;
	}

	if (   with_video
	    && !sipe_backend_media_add_stream(backend_media,
			    	    	      "video", with, SIPE_MEDIA_VIDEO,
			    	    	      SIPE_ICE_RFC_5245, TRUE,
			    	    	      backend_media_relays)) {
		sipe_backend_notify_error(_("Error occured"),
					  _("Error creating video stream"));
		sipe_media_call_free(call_private);
		return;
	}

	backend_media_legacy = 	sipe_backend_media_new(SIPE_CORE_PUBLIC,
						       SIPE_MEDIA_CALL,
						       with, TRUE);

	call_private->public.backend_private_legacy = backend_media_legacy;

	sipe_backend_media_add_stream(backend_media_legacy,
				      "audio", with, SIPE_MEDIA_AUDIO,
				      SIPE_ICE_DRAFT_6, TRUE,
				      backend_media_relays);

	if (with_video)
		sipe_backend_media_add_stream(backend_media_legacy,
						"video", with, SIPE_MEDIA_VIDEO,
						SIPE_ICE_DRAFT_6, TRUE,
						backend_media_relays);

	sipe_private->media_call = call_private;

	sipe_backend_media_relays_free(backend_media_relays);

	// Processing continues in candidates_prepared_cb
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

	if (call_private && !is_media_session_msg(call_private, msg)) {
		sip_transport_response(sipe_private, msg, 486, "Busy Here", NULL);
		return;
	}

	smsg = sdpmsg_parse_msg(msg->body);
	if (!smsg) {
		sip_transport_response(sipe_private, msg,
				       488, "Not Acceptable Here", NULL);
		sipe_media_hangup(sipe_private);
		return;
	}

	if (!call_private) {
		gchar *with = parse_from(sipmsg_find_header(msg, "From"));
		struct sip_session *session;
		struct sip_dialog *dialog;

		call_private = sipe_media_call_new(sipe_private, with, FALSE);
		session = sipe_session_add_call(sipe_private, with);
		dialog = sipe_media_dialog_init(session, msg);

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
		call_private->smsg = smsg;
		sip_transport_response(sipe_private, call_private->invitation,
				       180, "Ringing", NULL);
		// Processing continues in candidates_prepared_cb
	} else {
		do_apply_remote_message(call_private, smsg);
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

	sipe_media_hangup(sipe_private);
}

static gboolean
sipe_media_send_ack(struct sipe_core_private *sipe_private,
					SIPE_UNUSED_PARAMETER struct sipmsg *msg,
					struct transaction *trans)
{
	struct sipe_media_call_private *call_private = sipe_private->media_call;
	struct sip_session *session;
	struct sip_dialog *dialog;
	int trans_cseq;
	int tmp_cseq;

	session = sipe_session_find_call(sipe_private, call_private->with);
	dialog = session->dialogs->data;
	if (!dialog)
		return FALSE;

	tmp_cseq = dialog->cseq;

	sscanf(trans->key, "<%*[a-zA-Z0-9]><%d INVITE>", &trans_cseq);
	dialog->cseq = trans_cseq - 1;
	sip_transport_ack(sipe_private, dialog);
	dialog->cseq = tmp_cseq;

	dialog->outgoing_invite = NULL;

	return TRUE;
}

static gboolean
sipe_media_send_final_ack(struct sipe_core_private *sipe_private,
			  SIPE_UNUSED_PARAMETER struct sipmsg *msg,
			  struct transaction *trans)
{
	sipe_media_send_ack(sipe_private, msg, trans);
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
		if (remote_candidates) {
			sipe_media_candidate_list_free(remote_candidates);
			continue;
		}

		sipe_schedule_mseconds(sipe_private,
				       "<+media-reinvite-on-candidate-pair>",
				       NULL,
				       500,
				       (sipe_schedule_action) reinvite_on_candidate_pair_cb,
				       NULL);
		return;
	}

	sipe_invite_call(sipe_private, sipe_media_send_final_ack);
}

static gboolean
process_invite_call_response(struct sipe_core_private *sipe_private,
			     struct sipmsg *msg,
			     struct transaction *trans)
{
	const gchar *with;
	struct sipe_media_call_private *call_private = sipe_private->media_call;
	struct sipe_backend_media *backend_private;
	struct sip_session *session;
	struct sip_dialog *dialog;
	struct sdpmsg *smsg;

	if (!is_media_session_msg(call_private, msg))
		return FALSE;

	session = sipe_session_find_call(sipe_private, call_private->with);
	dialog = session->dialogs->data;

	backend_private = call_private->public.backend_private;
	with = dialog->with;

	dialog->outgoing_invite = NULL;

	if (msg->response >= 400) {
		// Call rejected by remote peer or an error occurred
		gchar *title;
		GString *desc = g_string_new("");
		gboolean append_responsestr = FALSE;

		switch (msg->response) {
			case 480: {
				const gchar *warn = sipmsg_find_header(msg, "Warning");
				title = _("User unavailable");

				if (warn && g_str_has_prefix(warn, "391 lcs.microsoft.com")) {
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
			default:
				title = _("Error occured");
				g_string_append(desc, _("Unable to establish a call"));
				append_responsestr = TRUE;
				break;
		}

		if (append_responsestr)
			g_string_append_printf(desc, "\n%d %s",
					       msg->response, msg->responsestr);

		sipe_backend_notify_error(title, desc->str);
		g_string_free(desc, TRUE);

		sipe_media_send_ack(sipe_private, msg, trans);
		sipe_media_hangup(sipe_private);

		return TRUE;
	}

	sipe_dialog_parse(dialog, msg, TRUE);
	smsg = sdpmsg_parse_msg(msg->body);
	if (!smsg) {
		sip_transport_response(sipe_private, msg,
				       488, "Not Acceptable Here", NULL);
		sipe_media_hangup(sipe_private);
		return FALSE;
	}

	if (call_private->public.backend_private_legacy) {
		if (smsg->ice_version == SIPE_ICE_RFC_5245) {
			sipe_backend_media_hangup(call_private->public.backend_private_legacy, FALSE);
		} else {
			sipe_backend_media_hangup(call_private->public.backend_private, FALSE);
			call_private->public.backend_private = call_private->public.backend_private_legacy;
		}

		call_private->public.backend_private_legacy = NULL;
	}

	if (!apply_remote_message(call_private, smsg)) {
		sip_transport_response(sipe_private, msg,
				       487, "Request Terminated", NULL);
		sipe_media_hangup(sipe_private);
	} else if (msg->response == 183) {
		// Session in progress
		const gchar *rseq = sipmsg_find_header(msg, "RSeq");
		const gchar *cseq = sipmsg_find_header(msg, "CSeq");
		gchar *rack = g_strdup_printf("RAck: %s %s\r\n", rseq, cseq);
		sip_transport_request(sipe_private,
		      "PRACK",
		      with,
		      with,
		      rack,
		      NULL,
		      dialog,
		      NULL);
		g_free(rack);
	} else {
		sipe_media_send_ack(sipe_private, msg, trans);
		reinvite_on_candidate_pair_cb(SIPE_CORE_PUBLIC);
	}

	sdpmsg_free(smsg);

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

	sipe_media_hangup(call_private->sipe_private);
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
			sipe_private->media_relay_username = g_strdup(sipe_xml_data(item));
			item = sipe_xml_child(xn_credentials, "password");
			sipe_private->media_relay_password = g_strdup(sipe_xml_data(item));

			for (item = sipe_xml_child(xn_relays, "mediaRelay"); item; item = sipe_xml_twin(item)) {
				struct sipe_media_relay *relay = g_new0(struct sipe_media_relay, 1);
				const sipe_xml *node;

				node = sipe_xml_child(item, "hostName");
				relay->hostname = g_strdup(sipe_xml_data(node));

				node = sipe_xml_child(item, "udpPort");
				relay->udp_port = atoi(sipe_xml_data(node));

				node = sipe_xml_child(item, "tcpPort");
				relay->tcp_port = atoi(sipe_xml_data(node));

				relays = g_slist_append(relays, relay);

				relay->dns_query = sipe_backend_dns_query_a(
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
