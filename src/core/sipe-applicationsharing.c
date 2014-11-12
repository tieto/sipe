/**
 * @file sipe-applicationsharing.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2014 SIPE Project <http://sipe.sourceforge.net/>
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
#include <glib/gstdio.h>
#include <gio/gio.h>
#include <gio/gunixsocketaddress.h>

#include <stdlib.h>

#include "sipmsg.h"
#include "sipe-applicationsharing.h"
#include "sipe-backend.h"
#include "sipe-buddy.h"
#include "sipe-common.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-dialog.h"
#include "sipe-media.h"
#include "sipe-nls.h"
#include "sipe-user.h"
#include "sipe-utils.h"

struct sipe_appshare {
	struct sipe_media_call *media;
	struct sipe_media_stream *stream;
	GSocket *socket;
	GIOChannel *channel;
	guint rdp_channel_readable_watch_id;
	struct sipe_user_ask_ctx *ask_ctx;
};

static void
unlink_appshare_socket(GSocket *socket)
{
	GError *error = NULL;
	GSocketAddress *address = g_socket_get_local_address(socket, &error);

	g_return_if_fail(address);

	unlink(g_unix_socket_address_get_path(G_UNIX_SOCKET_ADDRESS(address)));
	g_object_unref(address);
}

static void
sipe_appshare_free(struct sipe_appshare *appshare)
{
	GError *error = NULL;

	g_source_destroy(g_main_context_find_source_by_id(NULL,
			appshare->rdp_channel_readable_watch_id));

	g_io_channel_shutdown(appshare->channel, TRUE, &error);
	g_io_channel_unref(appshare->channel);

	unlink_appshare_socket(appshare->socket);
	g_object_unref(appshare->socket);

	if (appshare->ask_ctx) {
		sipe_user_close_ask(appshare->ask_ctx);
	}

	g_free(appshare);
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

static gboolean
rdp_channel_readable_cb(GIOChannel *channel,
			GIOCondition condition,
			gpointer data)
{
	struct sipe_appshare *appshare = data;
	GError *error = NULL;
	gchar buffer[2048];
	gsize bytes_read;

	if (condition & G_IO_HUP) {
		sipe_backend_media_hangup(appshare->media->backend_private, TRUE);
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

	unlink_appshare_socket(appshare->socket);
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

static gchar*
build_socket_path(struct sipe_media_call *call)
{
	gchar *socket_path;
	gchar *runtime_dir;
	struct sip_dialog *dialog;

	dialog = sipe_media_get_sip_dialog(call);
	if (!dialog) {
		return NULL;
	}

	runtime_dir = g_strdup_printf("%s/sipe", g_get_user_runtime_dir());

	g_mkdir_with_parents(runtime_dir, 0700);

	socket_path = g_strdup_printf("%s/applicationsharing-%u-%s",
				      runtime_dir, getpid(), dialog->callid);

	g_free(runtime_dir);

	return socket_path;
}

static void
writable_cb(struct sipe_media_call *call, struct sipe_media_stream *stream,
	    gboolean writable)
{
	struct sipe_appshare *appshare = sipe_media_stream_get_data(stream);

	if (writable && !appshare->socket) {
		gchar *socket_path;
		gchar *cmdline;
		GSocketAddress *address;
		GError *error = NULL;

		socket_path = build_socket_path(call);

		appshare->socket = g_socket_new(G_SOCKET_FAMILY_UNIX,
					     G_SOCKET_TYPE_STREAM,
					     G_SOCKET_PROTOCOL_DEFAULT,
					     &error);
		g_assert_no_error(error);
		g_socket_set_blocking(appshare->socket, FALSE);

		address = g_unix_socket_address_new(socket_path);

		g_unlink(socket_path);

		g_socket_bind(appshare->socket, address, TRUE, &error);
		g_assert_no_error(error);
		g_socket_listen(appshare->socket, &error);
		g_assert_no_error(error);

		appshare->channel = g_io_channel_unix_new(g_socket_get_fd(appshare->socket));
		appshare->rdp_channel_readable_watch_id =
				g_io_add_watch(appshare->channel, G_IO_IN,
					       socket_connect_cb, appshare);

		cmdline = g_strdup_printf("xfreerdp /v:%s /sec:rdp",socket_path);

		g_spawn_command_line_async(cmdline, &error);
		g_assert_no_error(error);

		g_free(cmdline);
		g_free(socket_path);
	}
}

static void
accept_cb(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private,
	  gpointer data)
{
	struct sipe_appshare *appshare = data;
	appshare->ask_ctx = NULL;

	sipe_backend_media_accept(appshare->media->backend_private, TRUE);
}

static void
decline_cb(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private,
	  gpointer data)
{
	struct sipe_appshare *appshare = data;
	appshare->ask_ctx = NULL;

	sipe_backend_media_hangup(appshare->media->backend_private, TRUE);
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
process_incoming_invite_applicationsharing(struct sipe_core_private *sipe_private,
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
	appshare->media = call;
	appshare->stream = stream;

	ask_accept_applicationsharing(sipe_private, msg, appshare);

	sipe_media_stream_set_data(stream, appshare,
				   (GDestroyNotify)sipe_appshare_free);

	stream->read_cb = read_cb;

	call->writable_cb = writable_cb;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
