/**
 * @file sipe-appshare-xfreerdp.c
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
#include <glib/gstdio.h>

#include <gio/gio.h>

#include <sys/socket.h>
#include <sys/un.h>

#include "sipe-appshare.h"
#include "sipe-appshare-xfreerdp.h"
#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-utils.h"

struct xfreerdp_data {
	gchar *socket_path;
};

static GSocketAddress *
xfreerdp_get_listen_address(struct sipe_rdp_client *client)
{
	struct xfreerdp_data *data = client->client_data;
	struct sockaddr_un address;

	data->socket_path = g_strdup_printf("%s/sipe-appshare-%u-%p",
					    g_get_user_runtime_dir(), getpid(),
					    client);

	g_unlink(data->socket_path);

	address.sun_family = AF_LOCAL;
	strncpy(address.sun_path, data->socket_path, sizeof (address.sun_path));

	return g_socket_address_new_from_native(&address, sizeof (address));
}

static gboolean
xfreerdp_launch(struct sipe_rdp_client *client,
		SIPE_UNUSED_PARAMETER GSocketAddress *listen_address,
		SIPE_UNUSED_PARAMETER struct sipe_media_stream *stream)
{
	struct xfreerdp_data *client_data = client->client_data;
	gchar *cmdline;
	GError *error = NULL;

	cmdline = g_strdup_printf("xfreerdp /v:%s /sec:rdp",
				  client_data->socket_path);

	g_spawn_command_line_async(cmdline, &error);
	g_free(cmdline);
	if (error) {
		SIPE_DEBUG_ERROR("Can't launch xfreerdp: %s", error->message);
		g_error_free(error);
		return FALSE;
	}

	return TRUE;
}

static void
xfreerdp_free(struct sipe_rdp_client *client)
{
	struct xfreerdp_data *client_data = client->client_data;

	if (client_data->socket_path) {
		g_unlink(client_data->socket_path);
		g_free(client_data->socket_path);
	}

	g_free(client_data);
}

gboolean
sipe_appshare_xfreerdp_init(struct sipe_rdp_client *client)
{
	gchar *program_path;

	program_path = g_find_program_in_path("xfreerdp");
	if (!program_path) {
		SIPE_DEBUG_WARNING_NOFORMAT("Couldn't locate xfreerdp binary");
		return FALSE;
	}
	g_free(program_path);

	client->client_data = g_new0(struct xfreerdp_data, 1);

	client->get_listen_address_cb = xfreerdp_get_listen_address;
	client->launch_cb = xfreerdp_launch;
	client->free_cb = xfreerdp_free;

	return TRUE;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
