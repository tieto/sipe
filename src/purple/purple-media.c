/**
 * @file purple-media.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2016 SIPE Project <http://sipe.sourceforge.net/>
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

#include "glib.h"
#include "glib/gstdio.h"
#include <fcntl.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "sipe-common.h"

#include "mediamanager.h"
#include "agent.h"

#ifdef _WIN32
/* wrappers for write() & friends for socket handling */
#include "win32/win32dep.h"
#endif

#include "sipe-backend.h"
#include "sipe-core.h"

#include "purple-private.h"

/*
 * GStreamer interfaces fail to compile on ARM architecture with -Wcast-align
 *
 * Diagnostic #pragma was added in GCC 4.2.0
 */
#if defined(__GNUC__)
#if ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 2)) || (__GNUC__ >= 5)
#if defined(__ARMEL__) || defined(__ARMEB__) || defined(__hppa__) || defined(__mips__) || defined(__sparc__) || (defined(__powerpc__) && defined(__NO_FPRS__))
#pragma GCC diagnostic ignored "-Wcast-align"
#endif
#endif
#endif

#include "media-gst.h"
#include <gst/rtp/gstrtcpbuffer.h>
#include <farstream/fs-session.h>

struct sipe_backend_media {
	PurpleMedia *m;
	/**
	 * Number of media streams that were not yet locally accepted or rejected.
	 */
	guint unconfirmed_streams;
};

struct sipe_backend_media_stream {
	gboolean local_on_hold;
	gboolean remote_on_hold;
	gboolean accepted;
	gboolean initialized_cb_was_fired;
	gboolean peer_started_sending;

	gulong gst_bus_cb_id;
	gulong on_sending_rtcp_cb_id;

	FsSession *fssession;
};

#if PURPLE_VERSION_CHECK(3,0,0)
#define SIPE_RELAYS_G_TYPE G_TYPE_PTR_ARRAY
#else
#define SIPE_RELAYS_G_TYPE G_TYPE_VALUE_ARRAY
#endif

void
sipe_backend_media_stream_free(struct sipe_backend_media_stream *stream)
{
	if (stream->gst_bus_cb_id != 0) {
		GstElement *pipe;

		pipe = purple_media_manager_get_pipeline(
				purple_media_manager_get());
		if (pipe) {
			GstBus *bus;

			bus = gst_element_get_bus(pipe);
			g_signal_handler_disconnect(bus, stream->gst_bus_cb_id);
			stream->gst_bus_cb_id = 0;
			gst_object_unref(bus);
		}
	}

	if (stream->fssession) {
		gst_object_unref(stream->fssession);
	}

	g_free(stream);
}

static PurpleMediaSessionType sipe_media_to_purple(SipeMediaType type);
static PurpleMediaCandidateType sipe_candidate_type_to_purple(SipeCandidateType type);
static SipeCandidateType purple_candidate_type_to_sipe(PurpleMediaCandidateType type);
static PurpleMediaNetworkProtocol sipe_network_protocol_to_purple(SipeNetworkProtocol proto);
static SipeNetworkProtocol purple_network_protocol_to_sipe(PurpleMediaNetworkProtocol proto);

static void
maybe_signal_stream_initialized(struct sipe_media_call *call, gchar *sessionid)
{
	if (call->stream_initialized_cb) {
		struct sipe_media_stream *stream;
		stream = sipe_core_media_get_stream_by_id(call, sessionid);

		if (sipe_backend_stream_initialized(call, stream) &&
		    !stream->backend_private->initialized_cb_was_fired) {
			call->stream_initialized_cb(call, stream);
			stream->backend_private->initialized_cb_was_fired = TRUE;
		}
	}
}

static void
on_candidates_prepared_cb(SIPE_UNUSED_PARAMETER PurpleMedia *media,
			  gchar *sessionid,
			  SIPE_UNUSED_PARAMETER gchar *participant,
			  struct sipe_media_call *call)
{
	maybe_signal_stream_initialized(call, sessionid);
}

static void
on_codecs_changed_cb(SIPE_UNUSED_PARAMETER PurpleMedia *media,
		    gchar *sessionid,
		    struct sipe_media_call *call)
{
	maybe_signal_stream_initialized(call, sessionid);
}

static void
on_state_changed_cb(SIPE_UNUSED_PARAMETER PurpleMedia *media,
		    PurpleMediaState state,
		    gchar *sessionid,
		    gchar *participant,
		    struct sipe_media_call *call)
{
	SIPE_DEBUG_INFO("sipe_media_state_changed_cb: %d %s %s\n", state, sessionid, participant);

	if (state == PURPLE_MEDIA_STATE_CONNECTED && sessionid && participant) {
		struct sipe_media_stream *stream;

		stream = sipe_core_media_get_stream_by_id(call, sessionid);
		if (stream) {
			stream->backend_private->peer_started_sending = TRUE;
		}
	} else if (state == PURPLE_MEDIA_STATE_END) {
		if (sessionid && participant) {
			struct sipe_media_stream *stream =
					sipe_core_media_get_stream_by_id(call, sessionid);
			if (stream) {
				sipe_core_media_stream_end(stream);
			}
		} else if (!sessionid && !participant && call->media_end_cb) {
			call->media_end_cb(call);
		}
	}
}

void
capture_pipeline(const gchar *label) {
	PurpleMediaManager *manager = purple_media_manager_get();
	GstElement *pipeline = purple_media_manager_get_pipeline(manager);
	GST_DEBUG_BIN_TO_DOT_FILE_WITH_TS(GST_BIN(pipeline), GST_DEBUG_GRAPH_SHOW_ALL, label);
}

static void
on_error_cb(SIPE_UNUSED_PARAMETER PurpleMedia *media, gchar *message,
	    struct sipe_media_call *call)
{
	capture_pipeline("ERROR");

	if (call->error_cb)
		call->error_cb(call, message);
}

static void
on_stream_info_cb(PurpleMedia *media,
		  PurpleMediaInfoType type,
		  gchar *sessionid,
		  gchar *participant,
		  gboolean local,
		  struct sipe_media_call *call)
{
	if (type == PURPLE_MEDIA_INFO_ACCEPT) {
		if (call->call_accept_cb && !sessionid && !participant)
			call->call_accept_cb(call, local);
		else if (sessionid && participant) {
			struct sipe_media_stream *stream;
			stream = sipe_core_media_get_stream_by_id(call, sessionid);
			if (stream) {
				if (!stream->backend_private->accepted && local)
					 --call->backend_private->unconfirmed_streams;
				stream->backend_private->accepted = TRUE;
			}
		}
	} else if (type == PURPLE_MEDIA_INFO_HOLD || type == PURPLE_MEDIA_INFO_UNHOLD) {

		gboolean state = (type == PURPLE_MEDIA_INFO_HOLD);

		if (sessionid) {
			// Hold specific stream
			struct sipe_media_stream *stream;
			stream = sipe_core_media_get_stream_by_id(call, sessionid);

			if (local)
				stream->backend_private->local_on_hold = state;
			else
				stream->backend_private->remote_on_hold = state;
		} else {
			// Hold all streams
			GList *session_ids = purple_media_get_session_ids(media);

			for (; session_ids; session_ids = session_ids->next) {
				struct sipe_media_stream *stream =
						sipe_core_media_get_stream_by_id(call, session_ids->data);

				if (local)
					stream->backend_private->local_on_hold = state;
				else
					stream->backend_private->remote_on_hold = state;
			}

			g_list_free(session_ids);
		}

		if (call->call_hold_cb)
			call->call_hold_cb(call, local, state);
	} else if (type == PURPLE_MEDIA_INFO_HANGUP || type == PURPLE_MEDIA_INFO_REJECT) {
		if (!sessionid && !participant) {
			if (type == PURPLE_MEDIA_INFO_HANGUP && call->call_hangup_cb)
				call->call_hangup_cb(call, local);
			else if (type == PURPLE_MEDIA_INFO_REJECT && call->call_reject_cb && !local)
				call->call_reject_cb(call, local);
		} else if (sessionid && participant) {
			struct sipe_media_stream *stream;
			stream = sipe_core_media_get_stream_by_id(call, sessionid);

#ifdef HAVE_XDATA
			purple_media_manager_set_application_data_callbacks(
					purple_media_manager_get(), media,
					sessionid, participant, NULL, NULL, NULL);
#endif

			if (stream) {
				if (local && --call->backend_private->unconfirmed_streams == 0 &&
				    call->call_reject_cb)
					call->call_reject_cb(call, local);
			}
		}
	} else if (type == PURPLE_MEDIA_INFO_MUTE || type == PURPLE_MEDIA_INFO_UNMUTE) {
		struct sipe_media_stream *stream =
				sipe_core_media_get_stream_by_id(call, "audio");

		if (stream && stream->mute_cb) {
			stream->mute_cb(stream, type == PURPLE_MEDIA_INFO_MUTE);
		}
	}
}

static void
on_candidate_pair_established_cb(SIPE_UNUSED_PARAMETER PurpleMedia *media,
				 const gchar *sessionid,
				 SIPE_UNUSED_PARAMETER const gchar *participant,
				 SIPE_UNUSED_PARAMETER PurpleMediaCandidate *local_candidate,
				 SIPE_UNUSED_PARAMETER PurpleMediaCandidate *remote_candidate,
				 struct sipe_media_call *call)
{
	struct sipe_media_stream *stream =
			sipe_core_media_get_stream_by_id(call, sessionid);

	if (!stream) {
		return;
	}

#ifdef HAVE_PURPLE_NEW_TCP_ENUMS
	if (purple_media_candidate_get_protocol(local_candidate) != PURPLE_MEDIA_NETWORK_PROTOCOL_UDP) {
		purple_media_set_send_rtcp_mux(media, sessionid, participant, TRUE);
	}
#endif

	sipe_core_media_stream_candidate_pair_established(stream);
}

struct sipe_backend_media *
sipe_backend_media_new(struct sipe_core_public *sipe_public,
		       struct sipe_media_call *call,
		       const gchar *participant,
		       SipeMediaCallFlags flags)
{
	struct sipe_backend_media *media = g_new0(struct sipe_backend_media, 1);
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleMediaManager *manager = purple_media_manager_get();
	GstElement *pipeline;

	if (flags & SIPE_MEDIA_CALL_NO_UI) {
#ifdef HAVE_XDATA
		media->m = purple_media_manager_create_private_media(manager,
				purple_private->account, "fsrtpconference",
				participant, flags & SIPE_MEDIA_CALL_INITIATOR);
#else
		SIPE_DEBUG_ERROR_NOFORMAT("Purple doesn't support private media");
#endif
	} else {
		media->m = purple_media_manager_create_media(manager,
				purple_private->account, "fsrtpconference",
				participant, flags & SIPE_MEDIA_CALL_INITIATOR);
	}

	g_signal_connect(G_OBJECT(media->m), "candidates-prepared",
			 G_CALLBACK(on_candidates_prepared_cb), call);
	g_signal_connect(G_OBJECT(media->m), "codecs-changed",
			 G_CALLBACK(on_codecs_changed_cb), call);
	g_signal_connect(G_OBJECT(media->m), "stream-info",
			 G_CALLBACK(on_stream_info_cb), call);
	g_signal_connect(G_OBJECT(media->m), "error",
			 G_CALLBACK(on_error_cb), call);
	g_signal_connect(G_OBJECT(media->m), "state-changed",
			 G_CALLBACK(on_state_changed_cb), call);
	g_signal_connect(G_OBJECT(media->m), "candidate-pair-established",
			 G_CALLBACK(on_candidate_pair_established_cb), call);


	/* On error, the pipeline is no longer in PLAYING state and libpurple
	 * will not switch it back to PLAYING, preventing any more calls until
	 * application restart. We switch the state ourselves here to negate
	 * effect of any error in previous call (if any). */
	pipeline = purple_media_manager_get_pipeline(manager);
	gst_element_set_state(pipeline, GST_STATE_PLAYING);

	return media;
}

void
sipe_backend_media_free(struct sipe_backend_media *media)
{
	g_free(media);
}

void
sipe_backend_media_set_cname(struct sipe_backend_media *media, gchar *cname)
{
	if (media) {
		guint num_params = 3;
		GParameter *params = g_new0(GParameter, num_params);
		params[0].name = "sdes-cname";
		g_value_init(&params[0].value, G_TYPE_STRING);
		g_value_set_string(&params[0].value, cname);
		params[1].name = "sdes-name";
		g_value_init(&params[1].value, G_TYPE_STRING);
		params[2].name = "sdes-tool";
		g_value_init(&params[2].value, G_TYPE_STRING);

		purple_media_set_params(media->m, num_params, params);

		g_value_unset(&params[0].value);
		g_free(params);
	}
}

#define FS_CODECS_CONF \
	"# Automatically created by SIPE plugin\n" \
	"[application/X-DATA]\n" \
	"id=127\n"

static void
ensure_codecs_conf()
{
	gchar *filename;
	const gchar *fs_codecs_conf = FS_CODECS_CONF;
	GError *error = NULL;

	filename = g_build_filename(purple_user_dir(), "fs-codec.conf", NULL);

	g_file_set_contents(filename, fs_codecs_conf, strlen(fs_codecs_conf),
			    &error);
	if (error) {
		SIPE_DEBUG_ERROR("Couldn't create fs-codec.conf: %s",
				 error->message);
		g_error_free(error);
	}

	g_free(filename);
}

static void
append_relay(struct sipe_backend_media_relays *relay_info, const gchar *ip,
	     guint port, gchar *type, gchar *username, gchar *password)
{
	GstStructure *gst_relay_info;

	gst_relay_info = gst_structure_new("relay-info",
			"ip", G_TYPE_STRING, ip,
			"port", G_TYPE_UINT, port,
			"relay-type", G_TYPE_STRING, type,
			"username", G_TYPE_STRING, username,
			"password", G_TYPE_STRING, password,
			NULL);

	if (gst_relay_info) {
#if PURPLE_VERSION_CHECK(3,0,0)
		g_ptr_array_add((GPtrArray *)relay_info, gst_relay_info);
#else
		GValue value;
		memset(&value, 0, sizeof(GValue));
		g_value_init(&value, GST_TYPE_STRUCTURE);
		gst_value_set_structure(&value, gst_relay_info);

		g_value_array_append((GValueArray *)relay_info, &value);
		gst_structure_free(gst_relay_info);
#endif
	}
}

struct sipe_backend_media_relays *
sipe_backend_media_relays_convert(GSList *media_relays, gchar *username, gchar *password)
{
	struct sipe_backend_media_relays *relay_info;

	relay_info = (struct sipe_backend_media_relays *)
#if PURPLE_VERSION_CHECK(3,0,0)
			g_ptr_array_new_with_free_func((GDestroyNotify) gst_structure_free);
#else
			g_value_array_new(0);
#endif

	for (; media_relays; media_relays = media_relays->next) {\
		struct sipe_media_relay *relay = media_relays->data;

		/* Skip relays where IP could not be resolved. */
		if (!relay->hostname)
			continue;

		if (relay->udp_port != 0)
			append_relay(relay_info, relay->hostname, relay->udp_port,
				     "udp", username, password);

#ifdef HAVE_PURPLE_NEW_TCP_ENUMS
		if (relay->tcp_port != 0) {
			gchar *type = "tcp";
			if (relay->tcp_port == 443)
				type = "tls";
			append_relay(relay_info, relay->hostname, relay->tcp_port,
				     type, username, password);
		}
#endif
	}

	return relay_info;
}

void
sipe_backend_media_relays_free(struct sipe_backend_media_relays *media_relays)
{
#if !PURPLE_VERSION_CHECK(3,0,0)
	g_value_array_free((GValueArray *)media_relays);
#else
	g_ptr_array_unref((GPtrArray *)media_relays);
#endif
}

#ifdef HAVE_XDATA
static void
stream_readable_cb(SIPE_UNUSED_PARAMETER PurpleMediaManager *manager,
		 SIPE_UNUSED_PARAMETER PurpleMedia *media,
		 const gchar *session_id,
		 SIPE_UNUSED_PARAMETER const gchar *participant,
		 gpointer user_data)
{
	struct sipe_media_call *call = (struct sipe_media_call *)user_data;
	struct sipe_media_stream *stream;

	SIPE_DEBUG_INFO("stream_readable_cb: %s is readable", session_id);

	stream = sipe_core_media_get_stream_by_id(call, session_id);

	if (stream) {
		sipe_core_media_stream_readable(stream);
	}
}

gssize
sipe_backend_media_stream_read(struct sipe_media_stream *stream,
			       guint8 *buffer, gsize len)
{
	return purple_media_manager_receive_application_data(
			purple_media_manager_get(),
			stream->call->backend_private->m,
			stream->id, stream->call->with, buffer, len, FALSE);
}

gssize
sipe_backend_media_stream_write(struct sipe_media_stream *stream,
				guint8 *buffer, gsize len)
{
	return purple_media_manager_send_application_data(
			purple_media_manager_get(),
			stream->call->backend_private->m,
			stream->id, stream->call->with, buffer, len, FALSE);
}

static void
stream_writable_cb(SIPE_UNUSED_PARAMETER PurpleMediaManager *manager,
		   SIPE_UNUSED_PARAMETER PurpleMedia *media,
		   const gchar *session_id,
		   SIPE_UNUSED_PARAMETER const gchar *participant,
		   gboolean writable,
		   gpointer user_data)
{
	struct sipe_media_call *call = (struct sipe_media_call *)user_data;
	struct sipe_media_stream *stream;

	stream = sipe_core_media_get_stream_by_id(call, session_id);

	if (!stream) {
		SIPE_DEBUG_ERROR("stream_writable_cb: stream %s not found!",
				 session_id);
		return;
	}

	SIPE_DEBUG_INFO("stream_writable_cb: %s has become %swritable",
			session_id, writable ? "" : "not ");

	sipe_core_media_stream_writable(stream, writable);
}
#endif

static gboolean
write_ms_h264_video_source_request(GstRTCPBuffer *buffer, guint32 ssrc,
                                   guint8 payload_type)
{
	GstRTCPPacket packet;
	guint8 *fci_data;

	if (!gst_rtcp_buffer_add_packet(buffer, GST_RTCP_TYPE_PSFB, &packet)) {
		return FALSE;
	}

	gst_rtcp_packet_fb_set_type(&packet, GST_RTCP_PSFB_TYPE_AFB);
	gst_rtcp_packet_fb_set_sender_ssrc(&packet, ssrc);
	gst_rtcp_packet_fb_set_media_ssrc(&packet, SIPE_MSRTP_VSR_SOURCE_ANY);

	if (!gst_rtcp_packet_fb_set_fci_length(&packet,
					       SIPE_MSRTP_VSR_FCI_WORDLEN)) {
		gst_rtcp_packet_remove(&packet);
		return FALSE;
	}

	fci_data = gst_rtcp_packet_fb_get_fci(&packet);

	sipe_core_msrtp_write_video_source_request(fci_data, payload_type);

	return TRUE;
}

static gboolean
on_sending_rtcp_cb(GObject *rtpsession,
		   GstBuffer *buffer,
		   SIPE_UNUSED_PARAMETER gboolean is_early,
		   struct sipe_backend_media_stream *backend_stream)
{
	gboolean was_changed = FALSE;
	FsCodec *send_codec;
	
	if (!backend_stream || !backend_stream->fssession) {
		return FALSE;
	}

	if (backend_stream->peer_started_sending &&
	    backend_stream->on_sending_rtcp_cb_id != 0) {
		g_signal_handler_disconnect(rtpsession,
				backend_stream->on_sending_rtcp_cb_id);
		backend_stream->on_sending_rtcp_cb_id = 0;
		SIPE_DEBUG_INFO_NOFORMAT("Peer started sending. Ceasing video "
					 "source requests.");
	}

	g_object_get(backend_stream->fssession,
		     "current-send-codec", &send_codec, NULL);
	if (!send_codec) {
		return FALSE;
	}

	if (sipe_strequal(send_codec->encoding_name, "H264")) {
		GstRTCPBuffer rtcp_buffer = GST_RTCP_BUFFER_INIT;
		guint32 ssrc;

		g_object_get(backend_stream->fssession, "ssrc", &ssrc, NULL);

		gst_rtcp_buffer_map(buffer, GST_MAP_READWRITE, &rtcp_buffer);
		was_changed = write_ms_h264_video_source_request(&rtcp_buffer,
				ssrc, send_codec->id);
		gst_rtcp_buffer_unmap(&rtcp_buffer);
	}

	fs_codec_destroy(send_codec);

	return was_changed;
}

static gint
find_sinkpad(GValue *value, GstPad *fssession_sinkpad)
{
	GstElement *tee_srcpad = g_value_get_object(value);

	return !(GST_PAD_PEER(tee_srcpad) == fssession_sinkpad);
}

static void
gst_bus_cb(GstBus *bus, GstMessage *msg, struct sipe_media_stream *stream)
{
	const GstStructure *s;
	FsSession *fssession;
	GstElement *tee;
	GstPad *sinkpad;
	GstIterator *it;
	GValue val = G_VALUE_INIT;

	if (GST_MESSAGE_TYPE(msg) != GST_MESSAGE_ELEMENT) {
		return;
	}

	s = gst_message_get_structure(msg);
	if (!gst_structure_has_name(s, "farstream-codecs-changed")) {
		return;
	}

	fssession = g_value_get_object(gst_structure_get_value(s, "session"));
	g_return_if_fail(fssession);

	tee = purple_media_get_tee(stream->call->backend_private->m, stream->id,
				   NULL);
	g_return_if_fail(tee);

	g_object_get(fssession, "sink-pad", &sinkpad, NULL);
	g_return_if_fail(sinkpad);

	/* Check whether this message is from the FsSession we're waiting for.
	 * For this to be true, the tee we got from libpurple has to be linked
	 * to "sink-pad" of the message's FsSession. */
	it = gst_element_iterate_src_pads(tee);
	if (gst_iterator_find_custom(it, (GCompareFunc)find_sinkpad, &val,
				     sinkpad)) {
		GObject *rtpsession;

		g_object_get(fssession, "internal-session", &rtpsession, NULL);
		if (rtpsession) {
			stream->backend_private->fssession =
					gst_object_ref(fssession);
			stream->backend_private->on_sending_rtcp_cb_id =
					g_signal_connect(rtpsession,
						"on-sending-rtcp",
						G_CALLBACK(on_sending_rtcp_cb),
						stream->backend_private);

			g_object_unref (rtpsession);
		}

		g_signal_handler_disconnect(bus,
				stream->backend_private->gst_bus_cb_id);
		stream->backend_private->gst_bus_cb_id = 0;
	}

	gst_iterator_free(it);
	gst_object_unref(sinkpad);
}

struct sipe_backend_media_stream *
sipe_backend_media_add_stream(struct sipe_media_stream *stream,
			      SipeMediaType type,
			      SipeIceVersion ice_version,
			      gboolean initiator,
			      struct sipe_backend_media_relays *media_relays,
			      guint min_port, guint max_port)
{
	struct sipe_backend_media *media = stream->call->backend_private;
	struct sipe_backend_media_stream *backend_stream = NULL;
	GstElement *pipe;
	// Preallocate enough space for all potential parameters to fit.
	GParameter *params = g_new0(GParameter, 6);
	guint params_cnt = 0;
	gchar *transmitter;
	GValue *relay_info = NULL;
#ifdef HAVE_XDATA
	PurpleMediaAppDataCallbacks callbacks = {
			stream_readable_cb, stream_writable_cb
	};
#endif

	if (ice_version != SIPE_ICE_NO_ICE) {
		transmitter = "nice";

		params[params_cnt].name = "compatibility-mode";
		g_value_init(&params[params_cnt].value, G_TYPE_UINT);
		g_value_set_uint(&params[params_cnt].value,
				 ice_version == SIPE_ICE_DRAFT_6 ?
				 NICE_COMPATIBILITY_OC2007 :
				 NICE_COMPATIBILITY_OC2007R2);
		++params_cnt;

		if (min_port != 0) {
			params[params_cnt].name = "min-port";
			g_value_init(&params[params_cnt].value, G_TYPE_UINT);
			g_value_set_uint(&params[params_cnt].value, min_port);
			++params_cnt;
		}

		if (max_port != 0) {
			params[params_cnt].name = "max-port";
			g_value_init(&params[params_cnt].value, G_TYPE_UINT);
			g_value_set_uint(&params[params_cnt].value, max_port);
			++params_cnt;
		}

		if (media_relays) {
			params[params_cnt].name = "relay-info";
			g_value_init(&params[params_cnt].value, SIPE_RELAYS_G_TYPE);
			g_value_set_boxed(&params[params_cnt].value, media_relays);
			relay_info = &params[params_cnt].value;
			++params_cnt;
		}

		if (type == SIPE_MEDIA_APPLICATION) {
			params[params_cnt].name = "ice-udp";
			g_value_init(&params[params_cnt].value, G_TYPE_BOOLEAN);
			g_value_set_boolean(&params[params_cnt].value, FALSE);
			++params_cnt;

			params[params_cnt].name = "reliable";
			g_value_init(&params[params_cnt].value, G_TYPE_BOOLEAN);
			g_value_set_boolean(&params[params_cnt].value, TRUE);
			++params_cnt;
		}
	} else {
		// TODO: session naming here, Communicator needs audio/video
		transmitter = "rawudp";
		//sessionid = "sipe-voice-rawudp";
	}

	ensure_codecs_conf();

#ifdef HAVE_XDATA
	if (type == SIPE_MEDIA_APPLICATION) {
		purple_media_manager_set_application_data_callbacks(
				purple_media_manager_get(),
				media->m, stream->id, stream->call->with,
				&callbacks, stream->call, NULL);
	}
#endif

	backend_stream = g_new0(struct sipe_backend_media_stream, 1);
	backend_stream->initialized_cb_was_fired = FALSE;

	pipe = purple_media_manager_get_pipeline(purple_media_manager_get());
	if (type == SIPE_MEDIA_VIDEO && pipe) {
		GstBus *bus;

		bus = gst_element_get_bus(pipe);
		backend_stream->gst_bus_cb_id = g_signal_connect(bus, "message",
				G_CALLBACK(gst_bus_cb), stream);
		gst_object_unref(bus);
	}

	if (purple_media_add_stream(media->m, stream->id, stream->call->with,
				    sipe_media_to_purple(type),
				    initiator, transmitter, params_cnt,
				    params)) {
		if (!initiator)
			++media->unconfirmed_streams;
	} else {
		sipe_backend_media_stream_free(backend_stream);
	}

	if (relay_info) {
		g_value_unset(relay_info);
	}

	g_free(params);

	return backend_stream;
}

void
sipe_backend_media_stream_end(struct sipe_media_call *media,
			      struct sipe_media_stream *stream)
{
	purple_media_end(media->backend_private->m, stream->id, NULL);
}

void
sipe_backend_media_add_remote_candidates(struct sipe_media_call *media,
					 struct sipe_media_stream *stream,
					 GList *candidates)
{
	GList *udp_candidates = NULL;

#ifndef HAVE_PURPLE_NEW_TCP_ENUMS
	/* Keep only UDP candidates in the list to set. */
	while (candidates) {
		PurpleMediaCandidate *candidate = candidates->data;
		PurpleMediaNetworkProtocol proto;

		proto = purple_media_candidate_get_protocol(candidate);
		if (proto == PURPLE_MEDIA_NETWORK_PROTOCOL_UDP)
			udp_candidates = g_list_append(udp_candidates, candidate);

		candidates = candidates->next;
	}

	candidates = udp_candidates;
#endif

	purple_media_add_remote_candidates(media->backend_private->m,
					   stream->id, media->with, candidates);

	g_list_free(udp_candidates);
}

gboolean sipe_backend_media_is_initiator(struct sipe_media_call *media,
					 struct sipe_media_stream *stream)
{
	return purple_media_is_initiator(media->backend_private->m,
					 stream ? stream->id : NULL,
					 stream ? media->with : NULL);
}

gboolean sipe_backend_media_accepted(struct sipe_backend_media *media)
{
	return purple_media_accepted(media->m, NULL, NULL);
}

gboolean
sipe_backend_stream_initialized(struct sipe_media_call *media,
				struct sipe_media_stream *stream)
{
	g_return_val_if_fail(media, FALSE);
	g_return_val_if_fail(stream, FALSE);

	if (purple_media_candidates_prepared(media->backend_private->m,
					     stream->id, media->with)) {
		GList *codecs;
		codecs = purple_media_get_codecs(media->backend_private->m,
						 stream->id);
		if (codecs) {
			purple_media_codec_list_free(codecs);
			return TRUE;
		}
	}
	return FALSE;
}

static GList *
duplicate_tcp_candidates(GList *candidates)
{
	GList *i;
	GList *result = NULL;

	for (i = candidates; i; i = i->next) {
		PurpleMediaCandidate *candidate = i->data;
		PurpleMediaNetworkProtocol protocol =
				purple_media_candidate_get_protocol(candidate);
		guint component_id =
				purple_media_candidate_get_component_id(candidate);

		if (protocol != PURPLE_MEDIA_NETWORK_PROTOCOL_UDP) {
			PurpleMediaCandidate *c2;

			if (component_id != PURPLE_MEDIA_COMPONENT_RTP) {
				/* Ignore TCP candidates for other than
				 * the first component. */
				g_object_unref(candidate);
				continue;
			}

			c2 = purple_media_candidate_copy(candidate);
			g_object_set(c2,
				     "component-id", PURPLE_MEDIA_COMPONENT_RTCP,
				     NULL);
			result = g_list_append(result, c2);
		}

		result = g_list_append(result, candidate);
	}

	g_list_free(candidates);

	return result;
}

GList *
sipe_backend_media_stream_get_active_local_candidates(struct sipe_media_stream *stream)
{
	GList *candidates = purple_media_get_active_local_candidates(
			stream->call->backend_private->m, stream->id,
			stream->call->with);
	return duplicate_tcp_candidates(candidates);
}

GList *
sipe_backend_media_stream_get_active_remote_candidates(struct sipe_media_stream *stream)
{
	GList *candidates = purple_media_get_active_remote_candidates(
			stream->call->backend_private->m, stream->id,
			stream->call->with);
	return duplicate_tcp_candidates(candidates);
}

#ifdef HAVE_SRTP
void
sipe_backend_media_set_encryption_keys(struct sipe_media_call *media,
				       struct sipe_media_stream *stream,
				       const guchar *encryption_key,
				       const guchar *decryption_key)
{
	purple_media_set_encryption_parameters(media->backend_private->m,
			stream->id,
			"aes-128-icm",
			"hmac-sha1-80",
			(gchar *)encryption_key, SIPE_SRTP_KEY_LEN);
	purple_media_set_decryption_parameters(media->backend_private->m,
			stream->id, media->with,
			"aes-128-icm",
			"hmac-sha1-80",
			(gchar *)decryption_key, SIPE_SRTP_KEY_LEN);
}
#else
void
sipe_backend_media_set_encryption_keys(SIPE_UNUSED_PARAMETER struct sipe_media_call *media,
				       SIPE_UNUSED_PARAMETER struct sipe_media_stream *stream,
				       SIPE_UNUSED_PARAMETER const guchar *encryption_key,
				       SIPE_UNUSED_PARAMETER const guchar *decryption_key)
{}
#endif

void sipe_backend_stream_hold(struct sipe_media_call *media,
			      struct sipe_media_stream *stream,
			      gboolean local)
{
	purple_media_stream_info(media->backend_private->m, PURPLE_MEDIA_INFO_HOLD,
				 stream->id, media->with, local);
}

void sipe_backend_stream_unhold(struct sipe_media_call *media,
				struct sipe_media_stream *stream,
				gboolean local)
{
	purple_media_stream_info(media->backend_private->m, PURPLE_MEDIA_INFO_UNHOLD,
				 stream->id, media->with, local);
}

gboolean sipe_backend_stream_is_held(struct sipe_media_stream *stream)
{
	g_return_val_if_fail(stream, FALSE);

	return stream->backend_private->local_on_hold ||
	       stream->backend_private->remote_on_hold;
}

struct sipe_backend_codec *
sipe_backend_codec_new(int id, const char *name, SipeMediaType type, guint clock_rate)
{
	if (sipe_strequal(name, "X-H264UC")) {
		name = "H264";
	}

	return (struct sipe_backend_codec *)purple_media_codec_new(id, name,
						    sipe_media_to_purple(type),
						    clock_rate);
}

void
sipe_backend_codec_free(struct sipe_backend_codec *codec)
{
	if (codec)
		g_object_unref(codec);
}

int
sipe_backend_codec_get_id(struct sipe_backend_codec *codec)
{
	return purple_media_codec_get_id((PurpleMediaCodec *)codec);
}

gchar *
sipe_backend_codec_get_name(struct sipe_backend_codec *codec)
{
	/* Not explicitly documented, but return value must be g_free()'d */
	return purple_media_codec_get_encoding_name((PurpleMediaCodec *)codec);
}

guint
sipe_backend_codec_get_clock_rate(struct sipe_backend_codec *codec)
{
	return purple_media_codec_get_clock_rate((PurpleMediaCodec *)codec);
}

void
sipe_backend_codec_add_optional_parameter(struct sipe_backend_codec *codec,
										  const gchar *name, const gchar *value)
{
	purple_media_codec_add_optional_parameter((PurpleMediaCodec *)codec, name, value);
}

GList *
sipe_backend_codec_get_optional_parameters(struct sipe_backend_codec *codec)
{
	return purple_media_codec_get_optional_parameters((PurpleMediaCodec *)codec);
}

gboolean
sipe_backend_set_remote_codecs(struct sipe_media_call *media,
			       struct sipe_media_stream *stream,
			       GList *codecs)
{
	return purple_media_set_remote_codecs(media->backend_private->m,
					      stream->id, media->with, codecs);
}

GList*
sipe_backend_get_local_codecs(struct sipe_media_call *media,
			      struct sipe_media_stream *stream)
{
	GList *codecs = purple_media_get_codecs(media->backend_private->m,
						stream->id);
	GList *i = codecs;
	gboolean is_conference = (g_strstr_len(media->with, strlen(media->with),
					       "app:conf:audio-video:") != NULL);

	/*
	 * Do not announce Theora. Its optional parameters are too long,
	 * Communicator rejects such SDP message and does not support the codec
	 * anyway.
	 *
	 * For some yet unknown reason, A/V conferencing server does not accept
	 * voice stream sent by SIPE when SIREN codec is in use. Nevertheless,
	 * we are able to decode incoming SIREN from server and with MSOC
	 * client, bidirectional call using the codec works. Until resolved,
	 * do not try to negotiate SIREN usage when conferencing. PCMA or PCMU
	 * seems to work properly in this scenario.
	 */
	while (i) {
		PurpleMediaCodec *codec = i->data;
		gchar *encoding_name = purple_media_codec_get_encoding_name(codec);

		if (sipe_strequal(encoding_name,"THEORA") ||
		    (is_conference && sipe_strequal(encoding_name,"SIREN"))) {
			GList *tmp;
			g_object_unref(codec);
			tmp = i->next;
			codecs = g_list_delete_link(codecs, i);
			i = tmp;
		} else if (sipe_strequal(encoding_name, "H264")) {
			/*
			 * Sanitize H264 codec:
			 * - the encoding name must be "X-H264UC"
			 * - remove "sprop-parameter-sets" parameter which is
			 *   rejected by Lync
			 * - add "packetization-mode" parameter if not already
			 *   present
			 */

			PurpleMediaCodec *new_codec;
			GList *it;

			new_codec = purple_media_codec_new(
					purple_media_codec_get_id(codec),
					"X-H264UC",
					PURPLE_MEDIA_VIDEO,
					purple_media_codec_get_clock_rate(codec));

			g_object_set(new_codec, "channels",
					purple_media_codec_get_channels(codec),
					NULL);

			it = purple_media_codec_get_optional_parameters(codec);

			for (; it; it = g_list_next(it)) {
				PurpleKeyValuePair *pair = it->data;

				if (sipe_strequal(pair->key, "sprop-parameter-sets")) {
					continue;
				}

				purple_media_codec_add_optional_parameter(new_codec,
						pair->key, pair->value);
			}

			if (!purple_media_codec_get_optional_parameter(new_codec,
					"packetization-mode", NULL)) {
				purple_media_codec_add_optional_parameter(new_codec,
						"packetization-mode",
						"1;mst-mode=NI-TC");
			}

			i->data = new_codec;

			g_object_unref(codec);
		} else
			i = i->next;

		g_free(encoding_name);
	}

	return codecs;
}

struct sipe_backend_candidate *
sipe_backend_candidate_new(const gchar *foundation,
			   SipeComponentType component,
			   SipeCandidateType type, SipeNetworkProtocol proto,
			   const gchar *ip, guint port,
			   const gchar *username,
			   const gchar *password)
{
	PurpleMediaCandidate *c = purple_media_candidate_new(
		/* Libnice and Farsight rely on non-NULL foundation to
		 * distinguish between candidates of a component. When NULL
		 * foundation is passed (ie. ICE draft 6 does not use foudation),
		 * use username instead. If no foundation is provided, Farsight
		 * may signal an active candidate different from the one actually
		 * in use. See Farsight's agent_new_selected_pair() in
		 * fs-nice-stream-transmitter.h where first candidate in the
		 * remote list is always selected when no foundation. */
		foundation ? foundation : username,
		component,
		sipe_candidate_type_to_purple(type),
		sipe_network_protocol_to_purple(proto),
		ip,
		port);
	g_object_set(c, "username", username, "password", password, NULL);
	return (struct sipe_backend_candidate *)c;
}

void
sipe_backend_candidate_free(struct sipe_backend_candidate *candidate)
{
	if (candidate)
		g_object_unref(candidate);
}

gchar *
sipe_backend_candidate_get_username(struct sipe_backend_candidate *candidate)
{
	/* Not explicitly documented, but return value must be g_free()'d */
	return purple_media_candidate_get_username((PurpleMediaCandidate*)candidate);
}

gchar *
sipe_backend_candidate_get_password(struct sipe_backend_candidate *candidate)
{
	/* Not explicitly documented, but return value must be g_free()'d */
	return purple_media_candidate_get_password((PurpleMediaCandidate*)candidate);
}

gchar *
sipe_backend_candidate_get_foundation(struct sipe_backend_candidate *candidate)
{
	/* Not explicitly documented, but return value must be g_free()'d */
	return purple_media_candidate_get_foundation((PurpleMediaCandidate*)candidate);
}

gchar *
sipe_backend_candidate_get_ip(struct sipe_backend_candidate *candidate)
{
	/* Not explicitly documented, but return value must be g_free()'d */
	return purple_media_candidate_get_ip((PurpleMediaCandidate*)candidate);
}

guint
sipe_backend_candidate_get_port(struct sipe_backend_candidate *candidate)
{
	return purple_media_candidate_get_port((PurpleMediaCandidate*)candidate);
}

gchar *
sipe_backend_candidate_get_base_ip(struct sipe_backend_candidate *candidate)
{
	/* Not explicitly documented, but return value must be g_free()'d */
	return purple_media_candidate_get_base_ip((PurpleMediaCandidate*)candidate);
}

guint
sipe_backend_candidate_get_base_port(struct sipe_backend_candidate *candidate)
{
	return purple_media_candidate_get_base_port((PurpleMediaCandidate*)candidate);
}

guint32
sipe_backend_candidate_get_priority(struct sipe_backend_candidate *candidate)
{
	return purple_media_candidate_get_priority((PurpleMediaCandidate*)candidate);
}

void
sipe_backend_candidate_set_priority(struct sipe_backend_candidate *candidate, guint32 priority)
{
	g_object_set(candidate, "priority", priority, NULL);
}

SipeComponentType
sipe_backend_candidate_get_component_type(struct sipe_backend_candidate *candidate)
{
	return purple_media_candidate_get_component_id((PurpleMediaCandidate*)candidate);
}

SipeCandidateType
sipe_backend_candidate_get_type(struct sipe_backend_candidate *candidate)
{
	PurpleMediaCandidateType type =
		purple_media_candidate_get_candidate_type((PurpleMediaCandidate*)candidate);
	return purple_candidate_type_to_sipe(type);
}

SipeNetworkProtocol
sipe_backend_candidate_get_protocol(struct sipe_backend_candidate *candidate)
{
	PurpleMediaNetworkProtocol proto =
		purple_media_candidate_get_protocol((PurpleMediaCandidate*)candidate);
	return purple_network_protocol_to_sipe(proto);
}

static void
remove_lone_candidate_cb(SIPE_UNUSED_PARAMETER gpointer key,
			 gpointer value,
			 gpointer user_data)
{
	GList  *entry = value;
	GList **candidates = user_data;

	g_object_unref(entry->data);
	*candidates = g_list_delete_link(*candidates, entry);
}

static GList *
ensure_candidate_pairs(GList *candidates)
{
	GHashTable *lone_cand_links;
	GList	   *i;

	lone_cand_links = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

	for (i = candidates; i; i = i->next) {
		PurpleMediaCandidate *c = i->data;
		gchar *foundation = purple_media_candidate_get_foundation(c);

		if (g_hash_table_lookup(lone_cand_links, foundation)) {
			g_hash_table_remove(lone_cand_links, foundation);
			g_free(foundation);
		} else {
			g_hash_table_insert(lone_cand_links, foundation, i);
		}
	}

	g_hash_table_foreach(lone_cand_links, remove_lone_candidate_cb, &candidates);
	g_hash_table_destroy(lone_cand_links);

	return candidates;
}

GList *
sipe_backend_get_local_candidates(struct sipe_media_call *media,
				  struct sipe_media_stream *stream)
{
	GList *candidates =
			purple_media_get_local_candidates(media->backend_private->m,
							  stream->id,
							  media->with);
	candidates = duplicate_tcp_candidates(candidates);

	/*
	 * Sometimes purple will not return complete list of candidates, even
	 * after "candidates-prepared" signal is emitted. This is a feature of
	 * libnice, namely affecting candidates discovered via UPnP. Nice does
	 * not wait until discovery is finished and can signal end of candidate
	 * gathering before all responses from UPnP enabled gateways are received.
	 *
	 * Remove any incomplete RTP+RTCP candidate pairs from the list.
	 */
	candidates = ensure_candidate_pairs(candidates);
	return candidates;
}

void
sipe_backend_media_accept(struct sipe_backend_media *media, gboolean local)
{
	if (media)
		purple_media_stream_info(media->m, PURPLE_MEDIA_INFO_ACCEPT,
					 NULL, NULL, local);
}

void
sipe_backend_media_hangup(struct sipe_backend_media *media, gboolean local)
{
	if (media)
		purple_media_stream_info(media->m, PURPLE_MEDIA_INFO_HANGUP,
					 NULL, NULL, local);
}

void
sipe_backend_media_reject(struct sipe_backend_media *media, gboolean local)
{
	if (media)
		purple_media_stream_info(media->m, PURPLE_MEDIA_INFO_REJECT,
					 NULL, NULL, local);
}

static PurpleMediaSessionType sipe_media_to_purple(SipeMediaType type)
{
	switch (type) {
		case SIPE_MEDIA_AUDIO: return PURPLE_MEDIA_AUDIO;
		case SIPE_MEDIA_VIDEO: return PURPLE_MEDIA_VIDEO;
#ifdef HAVE_XDATA
		case SIPE_MEDIA_APPLICATION: return PURPLE_MEDIA_APPLICATION;
#endif
		default:               return PURPLE_MEDIA_NONE;
	}
}

static PurpleMediaCandidateType
sipe_candidate_type_to_purple(SipeCandidateType type)
{
	switch (type) {
		case SIPE_CANDIDATE_TYPE_HOST:	return PURPLE_MEDIA_CANDIDATE_TYPE_HOST;
		case SIPE_CANDIDATE_TYPE_RELAY:	return PURPLE_MEDIA_CANDIDATE_TYPE_RELAY;
		case SIPE_CANDIDATE_TYPE_SRFLX:	return PURPLE_MEDIA_CANDIDATE_TYPE_SRFLX;
		case SIPE_CANDIDATE_TYPE_PRFLX: return PURPLE_MEDIA_CANDIDATE_TYPE_PRFLX;
		default:			return PURPLE_MEDIA_CANDIDATE_TYPE_HOST;
	}
}

static SipeCandidateType
purple_candidate_type_to_sipe(PurpleMediaCandidateType type)
{
	switch (type) {
		case PURPLE_MEDIA_CANDIDATE_TYPE_HOST:	return SIPE_CANDIDATE_TYPE_HOST;
		case PURPLE_MEDIA_CANDIDATE_TYPE_RELAY:	return SIPE_CANDIDATE_TYPE_RELAY;
		case PURPLE_MEDIA_CANDIDATE_TYPE_SRFLX:	return SIPE_CANDIDATE_TYPE_SRFLX;
		case PURPLE_MEDIA_CANDIDATE_TYPE_PRFLX: return SIPE_CANDIDATE_TYPE_PRFLX;
		default:				return SIPE_CANDIDATE_TYPE_HOST;
	}
}

static PurpleMediaNetworkProtocol
sipe_network_protocol_to_purple(SipeNetworkProtocol proto)
{
	switch (proto) {
#ifdef HAVE_PURPLE_NEW_TCP_ENUMS
		case SIPE_NETWORK_PROTOCOL_TCP_ACTIVE:
			return PURPLE_MEDIA_NETWORK_PROTOCOL_TCP_ACTIVE;
		case SIPE_NETWORK_PROTOCOL_TCP_PASSIVE:
			return PURPLE_MEDIA_NETWORK_PROTOCOL_TCP_PASSIVE;
		case SIPE_NETWORK_PROTOCOL_TCP_SO:
			return PURPLE_MEDIA_NETWORK_PROTOCOL_TCP_SO;
#else
		case SIPE_NETWORK_PROTOCOL_TCP_ACTIVE:
		case SIPE_NETWORK_PROTOCOL_TCP_PASSIVE:
		case SIPE_NETWORK_PROTOCOL_TCP_SO:
			return PURPLE_MEDIA_NETWORK_PROTOCOL_TCP;
#endif
		default:
		case SIPE_NETWORK_PROTOCOL_UDP:
			return PURPLE_MEDIA_NETWORK_PROTOCOL_UDP;
	}
}

static SipeNetworkProtocol
purple_network_protocol_to_sipe(PurpleMediaNetworkProtocol proto)
{
	switch (proto) {
#ifdef HAVE_PURPLE_NEW_TCP_ENUMS
		case PURPLE_MEDIA_NETWORK_PROTOCOL_TCP_ACTIVE:
			return SIPE_NETWORK_PROTOCOL_TCP_ACTIVE;
		case PURPLE_MEDIA_NETWORK_PROTOCOL_TCP_PASSIVE:
			return SIPE_NETWORK_PROTOCOL_TCP_PASSIVE;
		case PURPLE_MEDIA_NETWORK_PROTOCOL_TCP_SO:
			return SIPE_NETWORK_PROTOCOL_TCP_SO;
#else
		case PURPLE_MEDIA_NETWORK_PROTOCOL_TCP:
			return SIPE_NETWORK_PROTOCOL_TCP_ACTIVE;
#endif
		default:
		case PURPLE_MEDIA_NETWORK_PROTOCOL_UDP:
			return SIPE_NETWORK_PROTOCOL_UDP;
	}
}

#ifdef HAVE_SRTP
SipeEncryptionPolicy
sipe_backend_media_get_encryption_policy(struct sipe_core_public *sipe_public)
{
	PurpleAccount *account = sipe_public->backend_private->account;

	const char *policy =
			purple_account_get_string(account, "encryption-policy",
						  "obey-server");

	if (sipe_strequal(policy, "disabled")) {
		return SIPE_ENCRYPTION_POLICY_REJECTED;
	} else if (sipe_strequal(policy, "optional")) {
		return SIPE_ENCRYPTION_POLICY_OPTIONAL;
	} else if (sipe_strequal(policy, "required")) {
		return SIPE_ENCRYPTION_POLICY_REQUIRED;
	} else {
		return SIPE_ENCRYPTION_POLICY_OBEY_SERVER;
	}
}
#else
SipeEncryptionPolicy
sipe_backend_media_get_encryption_policy(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public)
{
	return SIPE_ENCRYPTION_POLICY_REJECTED;
}
#endif

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
