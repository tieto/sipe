/**
 * @file sipe-appshare.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2014-2016 SIPE Project <http://sipe.sourceforge.net/>
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

#include <glib.h>

#include <gio/gio.h>

#include "sipmsg.h"
#include "sipe-appshare.h"
#include "sipe-appshare-xfreerdp.h"
#include "sipe-appshare-remmina.h"
#include "sipe-backend.h"
#include "sipe-buddy.h"
#include "sipe-chat.h"
#include "sipe-common.h"
#include "sipe-conf.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-media.h"
#include "sipe-nls.h"
#include "sipe-schedule.h"
#include "sipe-user.h"
#include "sipe-utils.h"

struct sipe_appshare {
	struct sipe_media_stream *stream;
	GSocket *socket;
	GIOChannel *channel;
	guint rdp_channel_readable_watch_id;
	guint rdp_channel_writable_watch_id;
	struct sipe_user_ask_ctx *ask_ctx;

	gchar rdp_channel_buffer[0x800];
	gchar *rdp_channel_buffer_pos;
	gsize rdp_channel_buffer_len;

	struct sipe_rdp_client client;
};

typedef gboolean (*rdp_init_func)(struct sipe_rdp_client *);

rdp_init_func rdp_init_functions[] = {
		sipe_appshare_remmina_init,
		sipe_appshare_xfreerdp_init,
		NULL
};

static void
sipe_appshare_free(struct sipe_appshare *appshare)
{
	if (appshare->rdp_channel_readable_watch_id != 0) {
		g_source_destroy(g_main_context_find_source_by_id(NULL,
				appshare->rdp_channel_readable_watch_id));
	}

	if (appshare->rdp_channel_writable_watch_id != 0) {
		g_source_destroy(g_main_context_find_source_by_id(NULL,
				appshare->rdp_channel_writable_watch_id));
	}

	if (appshare->channel) {
		GError *error = NULL;

		g_io_channel_shutdown(appshare->channel, TRUE, &error);
		if (error) {
			SIPE_DEBUG_ERROR("Error shutting down RDP channel: %s",
					 error->message);
			g_error_free(error);
		}
		g_io_channel_unref(appshare->channel);
	}

	if (appshare->socket) {
		g_object_unref(appshare->socket);
	}

	if (appshare->ask_ctx) {
		sipe_user_close_ask(appshare->ask_ctx);
	}

	if (appshare->client.free_cb) {
		appshare->client.free_cb(&appshare->client);
	}

	g_free(appshare);
}

static gboolean
rdp_channel_readable_cb(GIOChannel *channel,
			GIOCondition condition,
			gpointer data)
{
	struct sipe_appshare *appshare = data;
	GError *error = NULL;
	gchar *buffer;
	gsize bytes_read;

	if (condition & G_IO_HUP) {
		struct sipe_media_call *call = appshare->stream->call;

		sipe_backend_media_hangup(call->backend_private, TRUE);
		return FALSE;
	}

	buffer = g_malloc(2048);
	while (sipe_media_stream_is_writable(appshare->stream)) {
		GIOStatus status;

		status = g_io_channel_read_chars(channel,
						 buffer, 2048,
						 &bytes_read, &error);
		if (error) {
			struct sipe_media_call *call = appshare->stream->call;

			SIPE_DEBUG_ERROR("Error reading from RDP channel: %s",
					 error->message);
			g_error_free(error);
			sipe_backend_media_hangup(call->backend_private, TRUE);
			g_free(buffer);
			return FALSE;
		}

		if (status == G_IO_STATUS_EOF) {
			struct sipe_media_call *call = appshare->stream->call;

			sipe_backend_media_hangup(call->backend_private, TRUE);
			g_free(buffer);
			return FALSE;
		}

		if (bytes_read == 0) {
			break;
		}

		sipe_media_stream_write(appshare->stream, (guint8 *)buffer,
					bytes_read);
		SIPE_DEBUG_INFO("Written: %" G_GSIZE_FORMAT "\n", bytes_read);
	}
	g_free(buffer);

	return TRUE;
}

static gboolean
socket_connect_cb(SIPE_UNUSED_PARAMETER GIOChannel *channel,
		  SIPE_UNUSED_PARAMETER GIOCondition condition,
		  gpointer data)
{
	struct sipe_appshare *appshare = data;
	GError *error = NULL;
	GSocket *data_socket;

	data_socket = g_socket_accept(appshare->socket, NULL, &error);
	if (error) {
		struct sipe_media_call *call = appshare->stream->call;

		SIPE_DEBUG_ERROR("Error accepting RDP client connection: %s",
				 error->message);
		g_error_free(error);
		sipe_backend_media_hangup(call->backend_private, TRUE);
		return FALSE;
	}

	g_io_channel_shutdown(appshare->channel, TRUE, &error);
	if (error) {
		struct sipe_media_call *call = appshare->stream->call;

		SIPE_DEBUG_ERROR("Error shutting down RDP channel: %s",
				 error->message);
		g_error_free(error);
		g_object_unref(data_socket);
		sipe_backend_media_hangup(call->backend_private, TRUE);
		return FALSE;
	}
	g_io_channel_unref(appshare->channel);

	g_object_unref(appshare->socket);
	appshare->socket = data_socket;

	appshare->channel = g_io_channel_unix_new(
			g_socket_get_fd(appshare->socket));

	// No encoding for binary data
	g_io_channel_set_encoding(appshare->channel, NULL, &error);
	if (error) {
		struct sipe_media_call *call = appshare->stream->call;

		SIPE_DEBUG_ERROR("Error setting RDP channel encoding: %s",
				 error->message);
		g_error_free(error);
		sipe_backend_media_hangup(call->backend_private, TRUE);
		return FALSE;
	}

	appshare->rdp_channel_readable_watch_id =
			g_io_add_watch(appshare->channel, G_IO_IN | G_IO_HUP,
				       rdp_channel_readable_cb, appshare);

	return FALSE;
}

static void
launch_rdp_client(struct sipe_appshare *appshare)
{
	struct sipe_rdp_client *client = &appshare->client;
	struct sipe_media_call *call = appshare->stream->call;
	GSocketAddress *address;
	GError *error = NULL;

	address = client->get_listen_address_cb(client);
	if (!address) {
		sipe_backend_media_hangup(call->backend_private, TRUE);
		return;
	}

	appshare->socket = g_socket_new(g_socket_address_get_family(address),
					G_SOCKET_TYPE_STREAM,
					G_SOCKET_PROTOCOL_DEFAULT,
					&error);
	if (error) {
		SIPE_DEBUG_ERROR("Can't create RDP client listen socket: %s",
				 error->message);
		g_error_free(error);
		sipe_backend_media_hangup(call->backend_private, TRUE);
		return;
	}

	g_socket_set_blocking(appshare->socket, FALSE);

	g_socket_bind(appshare->socket, address, TRUE, &error);
	g_object_unref(address);
	if (error) {
		SIPE_DEBUG_ERROR("Can't bind to RDP client socket: %s",
				 error->message);
		g_error_free(error);
		sipe_backend_media_hangup(call->backend_private, TRUE);
		return;
	}

	g_socket_listen(appshare->socket, &error);
	if (error) {
		SIPE_DEBUG_ERROR("Can't listen on RDP client socket: %s",
				 error->message);
		g_error_free(error);
		sipe_backend_media_hangup(call->backend_private, TRUE);
		return;
	}

	appshare->channel = g_io_channel_unix_new(
			g_socket_get_fd(appshare->socket));
	appshare->rdp_channel_readable_watch_id =
			g_io_add_watch(appshare->channel, G_IO_IN,
				       socket_connect_cb, appshare);

	address = g_socket_get_local_address(appshare->socket, &error);
	if (error) {
		SIPE_DEBUG_ERROR("Couldn't get appshare socket address: %s",
				 error->message);
		g_error_free(error);
		sipe_backend_media_hangup(call->backend_private, TRUE);
		return;
	}

	if (!client->launch_cb(client, address, appshare->stream)) {
		sipe_backend_media_hangup(call->backend_private, TRUE);
	}

	g_object_unref(address);
}

static gssize
rdp_client_channel_write(struct sipe_appshare *appshare)
{
	gsize bytes_written;
	GError *error = NULL;

	g_io_channel_write_chars(appshare->channel,
				 appshare->rdp_channel_buffer_pos,
				 appshare->rdp_channel_buffer_len,
				 &bytes_written, &error);
	if (error) {
		SIPE_DEBUG_ERROR("Couldn't write data to RDP client: %s",
				 error->message);
		g_error_free(error);
		return -1;
	}

	g_io_channel_flush(appshare->channel, &error);
	if (error) {
		if (g_error_matches(error, G_IO_CHANNEL_ERROR,
				    G_IO_CHANNEL_ERROR_PIPE)) {
			/* Ignore broken pipe here and wait for the call to be
			 * hung up upon G_IO_HUP in client_channel_cb(). */
			g_error_free(error);
			return 0;
		}

		SIPE_DEBUG_ERROR("Couldn't flush RDP channel: %s",
				 error->message);
		g_error_free(error);
		return -1;
	}

	appshare->rdp_channel_buffer_pos += bytes_written;
	appshare->rdp_channel_buffer_len -= bytes_written;

	return bytes_written;
}

static void
delayed_hangup_cb(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private,
		  gpointer data)
{
	struct sipe_media_call *call = data;

	sipe_backend_media_hangup(call->backend_private, TRUE);
}

static gboolean
rdp_channel_writable_cb(SIPE_UNUSED_PARAMETER GIOChannel *channel,
			SIPE_UNUSED_PARAMETER GIOCondition condition,
			gpointer data)
{
	struct sipe_appshare *appshare = data;
	struct sipe_media_call *call = appshare->stream->call;

	if (rdp_client_channel_write(appshare) < 0) {
		sipe_backend_media_hangup(call->backend_private, TRUE);
		return FALSE;
	}

	if (appshare->rdp_channel_buffer_len == 0) {
		// Writing done, disconnect writable watch.
		appshare->rdp_channel_writable_watch_id = 0;
		return FALSE;
	}

	return TRUE;
}

static void
read_cb(struct sipe_media_stream *stream)
{
	struct sipe_appshare *appshare = sipe_media_stream_get_data(stream);
	gint bytes_read = 0;
	gssize bytes_written = 0;

	if (appshare->rdp_channel_writable_watch_id != 0) {
		// Data still in the buffer. Let the client read it first.
		return;
	}

	while (bytes_read == (gint)bytes_written) {
		bytes_read = sipe_backend_media_stream_read(stream,
				(guint8 *)appshare->rdp_channel_buffer,
				sizeof (appshare->rdp_channel_buffer));
		if (bytes_read == 0) {
			return;
		}

		appshare->rdp_channel_buffer_pos = appshare->rdp_channel_buffer;
		appshare->rdp_channel_buffer_len = bytes_read;

		bytes_written = rdp_client_channel_write(appshare);

		if (bytes_written < 0) {
			/* Don't deallocate stream while in its read callback.
			 * Schedule call hangup to be executed after we're back
			 * in the message loop. */
			sipe_schedule_seconds(sipe_media_get_sipe_core_private(stream->call),
					      "appshare delayed hangup",
					      stream->call->backend_private,
					      0,
					      delayed_hangup_cb,
					      NULL);
			return;
		}
	}

	if (bytes_read != (gint)bytes_written) {
		/* Schedule writing of the buffer's remainder to when
		 * RDP channel becomes writable again. */
		appshare->rdp_channel_writable_watch_id =
				g_io_add_watch(appshare->channel, G_IO_OUT,
					       rdp_channel_writable_cb,
					       appshare);
	}
}

static void
writable_cb(struct sipe_media_stream *stream)
{
	struct sipe_appshare *appshare = sipe_media_stream_get_data(stream);

	if (!appshare->socket) {
		launch_rdp_client(appshare);
	}
}

static void
accept_cb(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private,
	  gpointer data)
{
	struct sipe_appshare *appshare = data;
	appshare->ask_ctx = NULL;

	sipe_backend_media_accept(appshare->stream->call->backend_private, TRUE);
}

static void
decline_cb(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private,
	  gpointer data)
{
	struct sipe_appshare *appshare = data;
	appshare->ask_ctx = NULL;

	sipe_backend_media_hangup(appshare->stream->call->backend_private, TRUE);
}

static struct sipe_user_ask_ctx *
ask_accept_applicationsharing(struct sipe_core_private *sipe_private,
			      const gchar *from,
			      SipeUserAskCb accept_cb,
			      SipeUserAskCb decline_cb,
			      gpointer user_data)
{
	struct sipe_user_ask_ctx *ctx;
	gchar *alias = sipe_buddy_get_alias(sipe_private, from);
	gchar *ask_msg = g_strdup_printf(_("%s wants to start presenting"),
					 alias ? alias : from);

	ctx = sipe_user_ask(sipe_private, ask_msg,
			     _("Accept"), accept_cb,
			     _("Decline"), decline_cb,
			     user_data);

	g_free(ask_msg);
	g_free(alias);

	return ctx;
}

static struct sipe_appshare *
initialize_appshare(struct sipe_media_stream *stream)
{
	struct sipe_appshare *appshare;
	struct sipe_media_call *call;
	struct sipe_core_private *sipe_private;
	SipeRDPClient client;

	call = stream->call;
	sipe_private = sipe_media_get_sipe_core_private(call);

	appshare = g_new0(struct sipe_appshare, 1);
	appshare->stream = stream;

	sipe_media_stream_set_data(stream, appshare,
				   (GDestroyNotify)sipe_appshare_free);

	client = sipe_backend_appshare_get_rdp_client(SIPE_CORE_PUBLIC);
	if (!rdp_init_functions[client](&appshare->client)) {
		/* Preferred client isn't available. Fall back to whatever
		 * application we can find. */
		rdp_init_func *init;

		for (init = rdp_init_functions; *init; ++init) {
			if ((*init)(&appshare->client)) {
				break;
			}
		}

		if (*init == NULL) {
			sipe_backend_notify_error(SIPE_CORE_PUBLIC,
				_("Application sharing error"),
				_("Remote desktop client isn't installed."));
			sipe_backend_media_hangup(call->backend_private, TRUE);
			return NULL;
		}
	}

	sipe_media_stream_add_extra_attribute(stream,
			"x-applicationsharing-session-id", "1");
	sipe_media_stream_add_extra_attribute(stream,
			"x-applicationsharing-role", "viewer");
	sipe_media_stream_add_extra_attribute(stream,
			"x-applicationsharing-media-type", "rdp");

	stream->read_cb = read_cb;
	stream->writable_cb = writable_cb;

	return appshare;
}

void
process_incoming_invite_appshare(struct sipe_core_private *sipe_private,
				 struct sipmsg *msg)
{
	struct sipe_media_call *call;
	struct sipe_media_stream *stream;
	struct sipe_appshare *appshare;

	call = process_incoming_invite_call(sipe_private, msg);
	if (!call) {
		return;
	}

	stream = sipe_core_media_get_stream_by_id(call, "applicationsharing");
	if (!stream) {
		sipe_backend_media_hangup(call->backend_private, TRUE);
		return;
	}

	appshare = initialize_appshare(stream);

	if (appshare) {
		gchar *from;

		from = parse_from(sipmsg_find_header(msg, "From"));
		appshare->ask_ctx = ask_accept_applicationsharing(sipe_private, from,
								  accept_cb,
								  decline_cb,
								  appshare);
		g_free(from);
	}
}

static void
connect_conference(struct sipe_core_private *sipe_private,
		   struct sipe_chat_session *chat_session)
{
	struct sipe_media_call *call;
	struct sipe_media_stream *stream;
	gchar * uri;

	uri = sipe_conf_build_uri(chat_session->id, "applicationsharing");

	call = sipe_media_call_new(sipe_private, uri, NULL,
				   SIPE_ICE_RFC_5245,
				   SIPE_MEDIA_CALL_NO_UI);

	g_free(uri);

	stream = sipe_media_stream_add(call, "applicationsharing",
				       SIPE_MEDIA_APPLICATION,
				       SIPE_ICE_RFC_5245, TRUE, 0);
	if (!stream) {
		sipe_backend_notify_error(SIPE_CORE_PUBLIC,
					  _("Application sharing error"),
					  _("Couldn't connect application sharing"));
		sipe_backend_media_hangup(call->backend_private, FALSE);
	}

	sipe_media_stream_add_extra_attribute(stream, "connection", "new");
	sipe_media_stream_add_extra_attribute(stream, "setup", "active");

	initialize_appshare(stream);
}

void
sipe_appshare_connect_conference(struct sipe_core_private *sipe_private,
				 struct sipe_chat_session *chat_session)
{
	const gchar *from;

	if (chat_session->title) {
		from = chat_session->title;
	} else if (chat_session->organizer) {
		from = chat_session->organizer;
	} else {
		from = chat_session->id;
	}

	ask_accept_applicationsharing(sipe_private, from,
				      (SipeUserAskCb)connect_conference,
				      NULL,
				      chat_session);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
