/**
 * @file sipe-appshare.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2014-2017 SIPE Project <http://sipe.sourceforge.net/>
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

#include <glib.h>
#include <string.h>

#include <gio/gio.h>

#ifdef HAVE_RDP_SERVER
#include <glib/gstdio.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <freerdp/server/shadow.h>
#endif // HAVE_RDP_SERVER

#include "sipmsg.h"
#include "sipe-appshare.h"
#include "sipe-appshare-client.h"
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
#include "sdpmsg.h"

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

#ifdef HAVE_RDP_SERVER
	rdpShadowServer *server;
#endif // HAVE_RDP_SERVER
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

#ifdef HAVE_RDP_SERVER
	if (appshare->server) {
		if (appshare->server->ipcSocket) {
			g_unlink(appshare->server->ipcSocket);
		}

		shadow_server_stop(appshare->server);
		shadow_server_uninit(appshare->server);
		shadow_server_free(appshare->server);
	}
#endif // HAVE_RDP_SERVER

	if (appshare->ask_ctx) {
		sipe_user_close_ask(appshare->ask_ctx);
	}

	g_free(appshare->client.cmdline);
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
	int fd;

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

	fd = g_socket_get_fd(appshare->socket);
	if (fd < 0) {
		struct sipe_media_call *call = appshare->stream->call;

		SIPE_DEBUG_ERROR_NOFORMAT("Invalid file descriptor for RDP client connection socket");
		sipe_backend_media_hangup(call->backend_private, TRUE);
		return FALSE;
	}
	appshare->channel = g_io_channel_unix_new(fd);

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
	int fd;

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
		g_object_unref(address);
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

	fd = g_socket_get_fd(appshare->socket);
	if (fd < 0) {
		SIPE_DEBUG_ERROR_NOFORMAT("Invalid file descriptor for RDP client listen socket");
		sipe_backend_media_hangup(call->backend_private, TRUE);
		return;
	}
	appshare->channel = g_io_channel_unix_new(fd);

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
	const gchar *cmdline;

	call = stream->call;
	sipe_private = sipe_media_get_sipe_core_private(call);

	appshare = g_new0(struct sipe_appshare, 1);
	appshare->stream = stream;

	sipe_media_stream_set_data(stream, appshare,
				   (GDestroyNotify)sipe_appshare_free);

	cmdline = sipe_backend_setting(SIPE_CORE_PUBLIC,
				       SIPE_SETTING_RDP_CLIENT);
	if (is_empty(cmdline))
		cmdline = "remmina";
	appshare->client.cmdline = g_strdup(cmdline);

	if (strstr(cmdline, "xfreerdp")) {
		sipe_appshare_xfreerdp_init(&appshare->client);
	} else if (strstr(cmdline, "remmina")) {
		sipe_appshare_remmina_init(&appshare->client);
	} else {
		sipe_backend_notify_error(SIPE_CORE_PUBLIC,
					  _("Application sharing error"),
					  _("Unknown remote desktop client configured."));
		sipe_backend_media_hangup(call->backend_private, TRUE);
		return NULL;
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
	struct sdpmsg *sdpmsg;
	GSList *i;

	sdpmsg = sdpmsg_parse_msg(msg->body);

	/* Skype for Business compatibility - ignore desktop video. */
	i = sdpmsg->media;
	while (i) {
		struct sdpmedia *media = i->data;
		const gchar *label;

		i = i->next;

		label = sipe_utils_nameval_find(media->attributes, "label");

		if (sipe_strequal(media->name, "video") &&
		    sipe_strequal(label, "applicationsharing-video")) {
			sdpmsg->media = g_slist_remove(sdpmsg->media, media);
			sdpmedia_free(media);
		}
	}

	call = process_incoming_invite_call_parsed_sdp(sipe_private,
						       msg,
						       sdpmsg);
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

	chat_session->appshare_ask_ctx = NULL;

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
sipe_core_appshare_connect_conference(struct sipe_core_public *sipe_public,
				      struct sipe_chat_session *chat_session,
				      gboolean user_must_accept)
{
	if (user_must_accept) {
		const gchar *from;

		if (chat_session->appshare_ask_ctx) {
			// Accept dialog already opened.
			return;
		}

		if (chat_session->title) {
			from = chat_session->title;
		} else if (chat_session->organizer) {
			from = chat_session->organizer;
		} else {
			from = chat_session->id;
		}

		chat_session->appshare_ask_ctx =
				ask_accept_applicationsharing(SIPE_CORE_PRIVATE,
							      from,
							      (SipeUserAskCb)connect_conference,
							      NULL,
							      chat_session);
	} else {
		connect_conference(SIPE_CORE_PRIVATE, chat_session);
	}
}

#ifdef HAVE_RDP_SERVER
static void
candidate_pairs_established_cb(struct sipe_media_stream *stream)
{
	struct sipe_appshare *appshare;
	GSocketAddress *address;
	GError *error = NULL;
	struct sockaddr_un native;
	rdpShadowServer* server;
	const gchar *server_error = NULL;

	g_return_if_fail(sipe_strequal(stream->id, "applicationsharing"));

	appshare = sipe_media_stream_get_data(stream);

	shadow_subsystem_set_entry_builtin("X11");

	server = shadow_server_new();
	if(!server) {
		server_error = _("Could not create RDP server.");
	} else {
		server->ipcSocket = g_strdup_printf("%s/sipe-appshare-%u-%p",
						    g_get_user_runtime_dir(),
						    getpid(), stream);
		server->authentication = FALSE;

		/* Experimentally determined cap on multifrag max request size
		 * Lync client would accept. Higher values result in a black
		 * screen being displayed on the remote end.
		 *
		 * See related https://github.com/FreeRDP/FreeRDP/pull/3669. */
		server->settings->MultifragMaxRequestSize = 0x3EFFFF;

		if(shadow_server_init(server) < 0) {
			server_error = _("Could not initialize RDP server.");
		} else if(shadow_server_start(server) < 0) {
			server_error = _("Could not start RDP server.");
		}
	}
	if (server_error) {
		struct sipe_core_private *sipe_private;

		sipe_private = sipe_media_get_sipe_core_private(stream->call);
		sipe_backend_notify_error(SIPE_CORE_PUBLIC,
					  _("Application sharing error"),
					  server_error);
		sipe_backend_media_hangup(stream->call->backend_private, TRUE);
		if (server) {
			shadow_server_uninit(server);
			shadow_server_free(server);
		}
		return;
	}

	appshare->server = server;
	appshare->socket = g_socket_new(G_SOCKET_FAMILY_UNIX,
					G_SOCKET_TYPE_STREAM,
					G_SOCKET_PROTOCOL_DEFAULT,
					&error);
	if (error) {
		SIPE_DEBUG_ERROR("Can't create RDP server socket: %s",
				 error->message);
		g_error_free(error);
		sipe_backend_media_hangup(stream->call->backend_private, TRUE);
		return;
	}

	g_socket_set_blocking(appshare->socket, FALSE);

	native.sun_family = AF_LOCAL;
	strncpy(native.sun_path, server->ipcSocket, sizeof (native.sun_path) - 1);
	native.sun_path[sizeof (native.sun_path) - 1] = '\0';
	address = g_socket_address_new_from_native(&native, sizeof native);

	g_socket_connect(appshare->socket, address, NULL, &error);
	if (error) {
		SIPE_DEBUG_ERROR("Can't connect to RDP server: %s", error->message);
		g_error_free(error);
		sipe_backend_media_hangup(stream->call->backend_private, TRUE);
		return;
	}

	appshare->channel = g_io_channel_unix_new(g_socket_get_fd(appshare->socket));

	// No encoding for binary data
	g_io_channel_set_encoding(appshare->channel, NULL, &error);
	if (error) {
		SIPE_DEBUG_ERROR("Error setting RDP channel encoding: %s",
				 error->message);
		g_error_free(error);
		sipe_backend_media_hangup(stream->call->backend_private, TRUE);
		return;
	}

	appshare->rdp_channel_readable_watch_id =
			g_io_add_watch(appshare->channel, G_IO_IN | G_IO_HUP,
				       rdp_channel_readable_cb, appshare);

	// Appshare structure initialized; don't call this again.
	stream->candidate_pairs_established_cb = NULL;
}

void
sipe_core_appshare_share_desktop(struct sipe_core_public *sipe_public,
				 const gchar *with)
{
	struct sipe_media_call *call;
	struct sipe_media_stream *stream;
	struct sipe_appshare *appshare;

	call = sipe_media_call_new(SIPE_CORE_PRIVATE, with, NULL,
				   SIPE_ICE_RFC_5245,
				   SIPE_MEDIA_CALL_INITIATOR |
				   SIPE_MEDIA_CALL_NO_UI);

	stream = sipe_media_stream_add(call, "applicationsharing",
				       SIPE_MEDIA_APPLICATION,
				       SIPE_ICE_RFC_5245, TRUE, 0);
	if (!stream) {
		sipe_backend_notify_error(sipe_public,
				_("Application sharing error"),
				_("Couldn't initialize application sharing"));
		sipe_backend_media_hangup(call->backend_private, TRUE);
		return;
	}

	stream->candidate_pairs_established_cb = candidate_pairs_established_cb;
	stream->read_cb = read_cb;

	sipe_media_stream_add_extra_attribute(stream,
					      "mid",
					      "1");
	sipe_media_stream_add_extra_attribute(stream,
					      "x-applicationsharing-session-id",
					      "1");
	sipe_media_stream_add_extra_attribute(stream,
					      "x-applicationsharing-role",
					      "sharer");
	sipe_media_stream_add_extra_attribute(stream,
					      "x-applicationsharing-media-type",
					      "rdp");

	appshare = g_new0(struct sipe_appshare, 1);
	appshare->stream = stream;

	sipe_media_stream_set_data(stream, appshare,
				   (GDestroyNotify)sipe_appshare_free);
}
#endif // HAVE_RDP_SERVER

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
