/**
 * @file purple-media.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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

#include "glib.h"

#include "sipe-core.h"
#include "../core/sipe.h"
#include "../core/sipe-core-private.h"
#include "sipe-common.h"
#include "sipe-media.h"
#include "mediamanager.h"
#include <nice/agent.h>

#include "request.h"
#include "core-depurple.h"

gboolean sipe_initiate_media(PurpleAccount *account, const char *who,
		      SIPE_UNUSED_PARAMETER PurpleMediaSessionType type)
{
	struct sipe_account_data *sip = PURPLE_ACCOUNT_TO_SIPE_ACCOUNT_DATA;
	sipe_media_initiate_call(sip, who);
	return TRUE;
}

PurpleMediaCaps sipe_get_media_caps(SIPE_UNUSED_PARAMETER PurpleAccount *account,
									SIPE_UNUSED_PARAMETER const char *who)
{
	return PURPLE_MEDIA_CAPS_AUDIO;
}

static PurpleMediaSessionType sipe_media_to_purple(SipeMediaType type);
static PurpleMediaCandidateType sipe_candidate_type_to_purple(SipeCandidateType type);
static PurpleMediaNetworkProtocol sipe_network_protocol_to_purple(SipeNetworkProtocol proto);
static SipeNetworkProtocol purple_network_protocol_to_sipe(PurpleMediaNetworkProtocol proto);

static void
on_candidates_prepared_cb(sipe_media_call *call)
{
	if (call->candidates_prepared_cb)
		call->candidates_prepared_cb(call);
}

static void
on_state_changed_cb(SIPE_UNUSED_PARAMETER PurpleMedia *media,
					PurpleMediaState state,
					gchar* sessionid,
					gchar* participant,
					sipe_media_call *call)
{
	printf("sipe_media_state_changed_cb: %d %s %s\n", state, sessionid, participant);
	if (state == PURPLE_MEDIA_STATE_CONNECTED && call->media_connected_cb)
		call->media_connected_cb(call);
}

static void
on_stream_info_cb(SIPE_UNUSED_PARAMETER PurpleMedia *media,
				  PurpleMediaInfoType type,
				  SIPE_UNUSED_PARAMETER gchar *sid,
				  SIPE_UNUSED_PARAMETER gchar *name,
				  gboolean local, sipe_media_call *call)
{
	if (type == PURPLE_MEDIA_INFO_ACCEPT && call->call_accept_cb)
		call->call_accept_cb(call, local);
	else if (type == PURPLE_MEDIA_INFO_REJECT && call->call_reject_cb)
		call->call_reject_cb(call, local);
	else if (type == PURPLE_MEDIA_INFO_HOLD && call->call_hold_cb)
		call->call_hold_cb(call, local);
	else if (type == PURPLE_MEDIA_INFO_UNHOLD && call->call_unhold_cb)
		call->call_unhold_cb(call, local);
	else if (type == PURPLE_MEDIA_INFO_HANGUP && call->call_hangup_cb)
		call->call_hangup_cb(call, local);
}

sipe_media *
sipe_backend_media_new(sipe_media_call *call, const gchar* participant, gboolean initiator)
{
	PurpleAccount		*acc = call->sip->account;
	PurpleMediaManager	*manager = purple_media_manager_get();
	PurpleMedia			*media;

	media = purple_media_manager_create_media(manager, acc,
							"fsrtpconference", participant, initiator);

	g_signal_connect_swapped(G_OBJECT(media), "candidates-prepared",
						G_CALLBACK(on_candidates_prepared_cb), call);
	g_signal_connect(G_OBJECT(media), "stream-info",
						G_CALLBACK(on_stream_info_cb), call);

	g_signal_connect(G_OBJECT(media), "state-changed",
						G_CALLBACK(on_state_changed_cb), call);

	return (sipe_media*) media;
}

gboolean
sipe_backend_media_add_stream(sipe_media *media, const gchar* participant,
							  SipeMediaType type, gboolean use_nice,
							  gboolean initiator)
{
	PurpleMedia *prpl_media = (PurpleMedia *) media;
	PurpleMediaSessionType prpl_type = sipe_media_to_purple(type);
	GParameter *params = NULL;
	guint params_cnt = 0;
	gchar *transmitter;

	if (use_nice) {
		transmitter = "nice";
		params_cnt = 2;

		params = g_new0(GParameter, params_cnt);
		params[0].name = "controlling-mode";
		g_value_init(&params[0].value, G_TYPE_BOOLEAN);
		g_value_set_boolean(&params[0].value, initiator);
		params[1].name = "compatibility-mode";
		g_value_init(&params[1].value, G_TYPE_UINT);
		g_value_set_uint(&params[1].value, NICE_COMPATIBILITY_OC2007R2);
	} else {
		transmitter = "rawudp";
	}

	return purple_media_add_stream(prpl_media, "sipe-voice", participant, prpl_type,
								   initiator, transmitter, params_cnt, params);
}

void
sipe_backend_media_add_remote_candidates(sipe_media *media, gchar* participant, GList *candidates)
{
	purple_media_add_remote_candidates((PurpleMedia *)media, "sipe-voice",
										participant, candidates);
}

gboolean sipe_backend_media_is_initiator(sipe_media *media, gchar *participant)
{
	return purple_media_is_initiator((PurpleMedia *)media, "sipe-voice", participant);
}

sipe_codec *
sipe_backend_codec_new(int id, const char *name, SipeMediaType type, guint clock_rate)
{
	return (sipe_codec *)purple_media_codec_new(id, name,
										sipe_media_to_purple(type), clock_rate);
}

void
sipe_backend_codec_free(sipe_codec *codec)
{
	g_object_unref(codec);
}

int
sipe_backend_codec_get_id(sipe_codec *codec)
{
	return purple_media_codec_get_id((PurpleMediaCodec *)codec);
}

gchar *
sipe_backend_codec_get_name(sipe_codec *codec)
{
	return purple_media_codec_get_encoding_name((PurpleMediaCodec *)codec);
}

guint
sipe_backend_codec_get_clock_rate(sipe_codec *codec)
{
	return purple_media_codec_get_clock_rate((PurpleMediaCodec *)codec);
}

GList *
sipe_backend_codec_get_optional_parameters(sipe_codec *codec)
{
	return purple_media_codec_get_optional_parameters((PurpleMediaCodec *)codec);
}

gboolean
sipe_backend_set_remote_codecs(sipe_media_call* call, gchar* participant)
{
	PurpleMedia	*media	= call->media;
	GList		*codecs	= call->remote_codecs;

	return purple_media_set_remote_codecs(media, "sipe-voice", participant, codecs);
}

GList*
sipe_backend_get_local_codecs(struct _sipe_media_call* call)
{
	return purple_media_get_codecs(call->media, "sipe-voice");
}

sipe_candidate *
sipe_backend_candidate_new(const gchar *foundation, SipeComponentType component,
						   SipeCandidateType type, SipeNetworkProtocol proto,
						   const gchar *ip, guint port)
{
	return (sipe_candidate *)purple_media_candidate_new(
								foundation,
								component,
								sipe_candidate_type_to_purple(type),
								sipe_network_protocol_to_purple(proto),
								ip,
								port);
}

void
sipe_backend_candidate_free(sipe_candidate *codec)
{
	g_object_unref(codec);
}

gchar *
sipe_backend_candidate_get_username(sipe_candidate *candidate)
{
	return purple_media_candidate_get_username((PurpleMediaCandidate*)candidate);
}

gchar *
sipe_backend_candidate_get_password(sipe_candidate *candidate)
{
	return purple_media_candidate_get_password((PurpleMediaCandidate*)candidate);
}

gchar *
sipe_backend_candidate_get_foundation(sipe_candidate *candidate)
{
	return purple_media_candidate_get_foundation((PurpleMediaCandidate*)candidate);
}

gchar *
sipe_backend_candidate_get_ip(sipe_candidate *candidate)
{
	return purple_media_candidate_get_ip((PurpleMediaCandidate*)candidate);
}

guint
sipe_backend_candidate_get_port(sipe_candidate *candidate)
{
	return purple_media_candidate_get_port((PurpleMediaCandidate*)candidate);
}

guint32
sipe_backend_candidate_get_priority(sipe_candidate *candidate)
{
	return purple_media_candidate_get_priority((PurpleMediaCandidate*)candidate);
}

void
sipe_backend_candidate_set_priority(sipe_candidate *candidate, guint32 priority)
{
	g_object_set(candidate, "priority", priority, NULL);
}

SipeComponentType
sipe_backend_candidate_get_component_type(sipe_candidate *candidate)
{
	return purple_media_candidate_get_component_id((PurpleMediaCandidate*)candidate);
}

SipeCandidateType
sipe_backend_candidate_get_type(sipe_candidate *candidate)
{
	return purple_media_candidate_get_candidate_type((PurpleMediaCandidate*)candidate);
}

SipeNetworkProtocol
sipe_backend_candidate_get_protocol(sipe_candidate *candidate)
{
	PurpleMediaNetworkProtocol proto =
		purple_media_candidate_get_protocol((PurpleMediaCandidate*)candidate);
	return purple_network_protocol_to_sipe(proto);
}

void
sipe_backend_candidate_set_username_and_pwd(sipe_candidate *candidate,
											const gchar *username,
											const gchar *password)
{
	g_object_set(candidate, "username", username, "password", password, NULL);
}

GList*
sipe_backend_get_local_candidates(sipe_media_call* call, gchar* participant)
{
	return purple_media_get_local_candidates(call->media, "sipe-voice", participant);
}

void
sipe_backend_media_hold(sipe_media* media, gboolean local)
{
	PurpleMedia* m = (PurpleMedia*) media;
	purple_media_stream_info(m, PURPLE_MEDIA_INFO_HOLD, NULL, NULL, local);
}

void
sipe_backend_media_unhold(sipe_media* media, gboolean local)
{
	PurpleMedia* m = (PurpleMedia*) media;
	purple_media_stream_info(m, PURPLE_MEDIA_INFO_UNHOLD, NULL, NULL, local);
}

void
sipe_backend_media_hangup(sipe_media* media, gboolean local)
{
	PurpleMedia* m = (PurpleMedia*) media;
	purple_media_stream_info(m, PURPLE_MEDIA_INFO_HANGUP, NULL, NULL, local);
}

PurpleMediaSessionType sipe_media_to_purple(SipeMediaType type)
{
	switch (type) {
		case SIPE_MEDIA_AUDIO: return PURPLE_MEDIA_AUDIO;
		case SIPE_MEDIA_VIDEO: return PURPLE_MEDIA_VIDEO;
		default:			   return PURPLE_MEDIA_NONE;
	}
}

/*SipeMediaType purple_media_to_sipe(PurpleMediaSessionType type)
{
	switch (type) {
		case PURPLE_MEDIA_AUDIO: return SIPE_MEDIA_AUDIO;
		case PURPLE_MEDIA_VIDEO: return SIPE_MEDIA_VIDEO;
		default:				 return SIPE_MEDIA_AUDIO;
	}
}*/

static PurpleMediaCandidateType
sipe_candidate_type_to_purple(SipeCandidateType type)
{
	switch (type) {
		case SIPE_CANDIDATE_TYPE_HOST:	return PURPLE_MEDIA_CANDIDATE_TYPE_HOST;
		case SIPE_CANDIDATE_TYPE_RELAY:	return PURPLE_MEDIA_CANDIDATE_TYPE_RELAY;
		case SIPE_CANDIDATE_TYPE_SRFLX:	return PURPLE_MEDIA_CANDIDATE_TYPE_SRFLX;
		default:						return PURPLE_MEDIA_CANDIDATE_TYPE_HOST;
	}
}

static PurpleMediaNetworkProtocol
sipe_network_protocol_to_purple(SipeNetworkProtocol proto)
{
	switch (proto) {
		case SIPE_NETWORK_PROTOCOL_TCP:	return PURPLE_MEDIA_NETWORK_PROTOCOL_TCP;
		case SIPE_NETWORK_PROTOCOL_UDP:	return PURPLE_MEDIA_NETWORK_PROTOCOL_UDP;
		default:						return PURPLE_MEDIA_NETWORK_PROTOCOL_TCP;
	}
}

static SipeNetworkProtocol
purple_network_protocol_to_sipe(PurpleMediaNetworkProtocol proto)
{
	switch (proto) {
		case PURPLE_MEDIA_NETWORK_PROTOCOL_TCP: return SIPE_NETWORK_PROTOCOL_TCP;
		case PURPLE_MEDIA_NETWORK_PROTOCOL_UDP: return SIPE_NETWORK_PROTOCOL_UDP;
		default:								return SIPE_NETWORK_PROTOCOL_UDP;
	}
}

/*
void sipe_media_error_cb(SIPE_UNUSED_PARAMETER PurpleMedia *media, gchar* error, SIPE_UNUSED_PARAMETER struct sipe_account_data *sip)
{
	printf("sipe_media_error_cb: %s\n", error);
}

void sipe_media_codecs_changed_cb(SIPE_UNUSED_PARAMETER PurpleMedia *media, gchar* codec, SIPE_UNUSED_PARAMETER struct sipe_account_data *sip)
{
	printf("sipe_media_codecs_changed_cb: %s\n", codec);
}

void sipe_media_level_cb(SIPE_UNUSED_PARAMETER PurpleMedia *media, gchar* sessionid, gchar* participant, gdouble percent, SIPE_UNUSED_PARAMETER struct sipe_account_data *sip)
{
	printf("sipe_media_level_cb: %s %s %f\n", sessionid, participant, percent);
}

void sipe_media_new_candidate_cb(SIPE_UNUSED_PARAMETER PurpleMedia *media, gchar* sessionid, gchar* cname, PurpleMediaCandidate *candidate, SIPE_UNUSED_PARAMETER struct sipe_account_data *sip)
{
	printf("sipe_media_new_candidate_cb: %s cname: %s %s %d\n", sessionid, cname,
			purple_media_candidate_get_ip(candidate),
			purple_media_candidate_get_port(candidate));
}

void sipe_media_state_changed_cb(SIPE_UNUSED_PARAMETER PurpleMedia *media, PurpleMediaState state, gchar* sessionid, gchar* participant, SIPE_UNUSED_PARAMETER struct sipe_account_data *sip)
{
	printf("sipe_media_state_changed_cb: %d %s %s\n", state, sessionid, participant);
}

g_signal_connect(G_OBJECT(media), "error", G_CALLBACK(sipe_media_error_cb), call);
g_signal_connect(G_OBJECT(media), "codecs-changed", G_CALLBACK(sipe_media_codecs_changed_cb), call);
g_signal_connect(G_OBJECT(media), "level", G_CALLBACK(sipe_media_level_cb), call);
g_signal_connect(G_OBJECT(media), "new-candidate", G_CALLBACK(sipe_media_new_candidate_cb), call);
g_signal_connect(G_OBJECT(media), "state-changed", G_CALLBACK(sipe_media_state_changed_cb), call);

*/

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
