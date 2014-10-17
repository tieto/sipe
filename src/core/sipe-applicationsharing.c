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

#include "sipe-applicationsharing.h"
#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-dialog.h"
#include "sipe-media.h"

struct {
	struct sipe_media_call *media;
	struct sipe_media_stream *stream;
	GSocket *socket;
	GSocket *data_socket;
	GIOChannel *listen_channel;
	GIOChannel *data_channel;
} foobar;

static void
read_cb(struct sipe_media_stream *stream)
{
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

	g_io_channel_write_chars(foobar.data_channel, (gchar *)buffer, bytes_read, &bytes_written, &error);
	g_assert_no_error(error);
	g_io_channel_flush(foobar.data_channel, &error);
	g_assert_no_error(error);
	g_assert(bytes_read == (gint)bytes_written);
}

static gboolean
rdp_channel_readable_cb(GIOChannel *channel,
			SIPE_UNUSED_PARAMETER GIOCondition condition,
			SIPE_UNUSED_PARAMETER gpointer data)
{
	GError *error = NULL;
	gchar buffer[2048];
	gsize bytes_read;

	while (1) {
		g_io_channel_read_chars(channel, buffer, sizeof (buffer), &bytes_read, &error);
		g_assert_no_error(error);

		if (bytes_read > 0) {
			sipe_backend_media_write(foobar.media, foobar.stream, (guint8 *)buffer, bytes_read, TRUE);
		} else {
			break;
		}
	}

	return TRUE;
}

static gboolean
socket_connect_cb (SIPE_UNUSED_PARAMETER GIOChannel *channel,
		   SIPE_UNUSED_PARAMETER GIOCondition condition,
		   SIPE_UNUSED_PARAMETER gpointer data)
{
	GError *error = NULL;

	foobar.data_socket = g_socket_accept(foobar.socket, NULL, &error);
	g_assert_no_error(error);
	g_io_channel_shutdown(channel, TRUE, &error);

	foobar.data_channel = g_io_channel_unix_new(g_socket_get_fd(foobar.data_socket));
	g_io_channel_set_encoding(foobar.data_channel, NULL, &error);
	g_assert_no_error(error);
	g_io_add_watch(foobar.data_channel, G_IO_IN , rdp_channel_readable_cb,
		       NULL);

	return FALSE;
}

static void
writable_cb(struct sipe_media_call *call, struct sipe_media_stream *stream,
	    gboolean writable)
{
	if (writable && !foobar.socket) {
		gchar *runtime_dir;
		gchar *socket_path;
		gchar *cmdline;
		struct sip_dialog *dialog;
		GSocketAddress *address;
		GError *error = NULL;

		dialog = sipe_media_get_sip_dialog(call);
		if (!dialog) {
			return;
		}

		runtime_dir = g_strdup_printf("%s/sipe",
					      g_get_user_runtime_dir());

		g_mkdir_with_parents(runtime_dir, 0700);

		socket_path = g_strdup_printf("%s/applicationsharing-%u-%s",
					      runtime_dir,
					      getpid(),
					      dialog->callid);

		foobar.socket = g_socket_new(G_SOCKET_FAMILY_UNIX,
					     G_SOCKET_TYPE_STREAM,
					     G_SOCKET_PROTOCOL_DEFAULT,
					     &error);
		g_assert_no_error(error);
		g_socket_set_blocking(foobar.socket, FALSE);

		address = g_unix_socket_address_new(socket_path);

		g_unlink(socket_path);

		g_socket_bind(foobar.socket, address, TRUE, &error);
		g_assert_no_error(error);
		g_socket_listen(foobar.socket, &error);
		g_assert_no_error(error);

		foobar.listen_channel = g_io_channel_unix_new(g_socket_get_fd(foobar.socket));
		g_io_add_watch(foobar.listen_channel, G_IO_IN, socket_connect_cb, NULL);

		/* We need to send the data after the reinvite, or need to set the encryption params after the first invite*/
		foobar.media = call;
		foobar.stream = stream;

		cmdline = g_strdup_printf("xfreerdp /v:%s /sec:rdp",socket_path);

		g_spawn_command_line_async(cmdline, &error);
		g_assert_no_error(error);

		g_free(cmdline);
		g_free(socket_path);
		g_free(runtime_dir);
	}
}

void
process_incoming_invite_applicationsharing(struct sipe_core_private *sipe_private,
					   struct sipmsg *msg)
{
	struct sipe_media_call *call = NULL;
	struct sipe_media_stream *stream;

	call = process_incoming_invite_call(sipe_private, msg);
	if (!call) {
		return;
	}

	foobar.socket = 0;

	sipe_backend_media_accept(call->backend_private, TRUE);

	call->writable_cb = writable_cb;

	stream = sipe_core_media_get_stream_by_id(call, "applicationsharing");
	stream->read_cb = read_cb;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
