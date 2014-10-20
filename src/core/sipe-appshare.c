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
#include "sipe-backend.h"
#include "sipe-buddy.h"
#include "sipe-common.h"
#include "sipe-core.h"
#include "sipe-media.h"
#include "sipe-nls.h"
#include "sipe-user.h"
#include "sipe-utils.h"

struct sipe_appshare {
	struct sipe_media_stream *stream;
	GSocket *socket;
	GIOChannel *channel;
	guint rdp_channel_readable_watch_id;
	struct sipe_user_ask_ctx *ask_ctx;

	struct sipe_rdp_client client;
};

static void
sipe_appshare_free(struct sipe_appshare *appshare)
{
	GError *error = NULL;

	g_source_destroy(g_main_context_find_source_by_id(NULL,
			appshare->rdp_channel_readable_watch_id));

	g_io_channel_shutdown(appshare->channel, TRUE, &error);
	g_io_channel_unref(appshare->channel);

	g_object_unref(appshare->socket);

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
	struct sipe_media_call *call = appshare->stream->call;
	GError *error = NULL;
	gchar buffer[2048];
	gsize bytes_read;

	if (condition & G_IO_HUP) {
		sipe_backend_media_hangup(call->backend_private, TRUE);
		return FALSE;
	}

	while (sipe_media_stream_is_writable(appshare->stream)) {
		g_io_channel_read_chars(channel, buffer, sizeof (buffer), &bytes_read, &error);
		g_assert_no_error(error);

		if (bytes_read == 0) {
			break;
		}

		sipe_media_stream_write(appshare->stream, (guint8 *)buffer,
					bytes_read);
		SIPE_DEBUG_INFO("Written: %" G_GSIZE_FORMAT "\n", bytes_read);
	}

	return TRUE;
}

static gboolean
socket_connect_cb (SIPE_UNUSED_PARAMETER GIOChannel *channel,
		   SIPE_UNUSED_PARAMETER GIOCondition condition,
		   gpointer data)
{
	struct sipe_appshare *appshare = data;
	GError *error = NULL;
	GSocket *data_socket;

	data_socket = g_socket_accept(appshare->socket, NULL, &error);

	g_io_channel_shutdown(appshare->channel, TRUE, &error);
	g_io_channel_unref(appshare->channel);
	g_object_unref(appshare->socket);

	appshare->socket = data_socket;

	appshare->channel = g_io_channel_unix_new(g_socket_get_fd(appshare->socket));
	g_io_channel_set_encoding(appshare->channel, NULL, &error);
	g_assert_no_error(error);
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
		// Intentionally not returning here.
	}

	g_object_unref(address);
}

static void
read_cb(struct sipe_media_stream *stream)
{
	struct sipe_appshare *appshare = sipe_media_stream_get_data(stream);
	guint8 buffer[0x800];
	gint bytes_read;
	gsize bytes_written;
	GError *error = 0;

	SIPE_DEBUG_INFO_NOFORMAT("INCOMING APPSHARE DATA");
	bytes_read = sipe_backend_media_stream_read(stream, buffer,
						    sizeof (buffer));

	if (bytes_read == 0) {
		return;
	}

	g_io_channel_write_chars(appshare->channel, (gchar *)buffer,
				 bytes_read, &bytes_written, &error);
	if (g_io_channel_flush(appshare->channel, &error) == G_IO_STATUS_ERROR &&
	    g_error_matches(error, G_IO_CHANNEL_ERROR, G_IO_CHANNEL_ERROR_PIPE)) {
		g_error_free(error);
		return;
	}

	g_assert_no_error(error);
	g_assert(bytes_read == (gint)bytes_written);
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

static void
ask_accept_applicationsharing(struct sipe_core_private *sipe_private,
			      struct sipmsg *msg,
			      struct sipe_appshare *appshare)
{
	gchar *from = parse_from(sipmsg_find_header(msg, "From"));
	gchar *alias = sipe_buddy_get_alias(sipe_private, from);
	gchar *ask_msg = g_strdup_printf(_("%s wants to start presenting"),
					 alias ? alias : from);

	appshare->ask_ctx = sipe_user_ask(sipe_private, ask_msg,
			     _("Accept"), accept_cb,
			     _("Decline"), decline_cb,
			     appshare);

	g_free(ask_msg);
	g_free(alias);
	g_free(from);
}

void
process_incoming_invite_appshare(struct sipe_core_private *sipe_private,
				 struct sipmsg *msg)
{
	struct sipe_media_call *call = NULL;
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

	appshare = g_new0(struct sipe_appshare, 1);
	appshare->stream = stream;
	sipe_appshare_xfreerdp_init(&appshare->client);

	sipe_media_stream_set_data(stream, appshare,
				   (GDestroyNotify)sipe_appshare_free);

	sipe_media_stream_add_extra_attribute(stream,
			"x-applicationsharing-session-id", "1");
	sipe_media_stream_add_extra_attribute(stream,
			"x-applicationsharing-role", "viewer");
	sipe_media_stream_add_extra_attribute(stream,
			"x-applicationsharing-media-type", "rdp");

	stream->read_cb = read_cb;
	stream->writable_cb = writable_cb;

	ask_accept_applicationsharing(sipe_private, msg, appshare);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
