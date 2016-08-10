/**
 * @file sipe-appshare-remmina.c
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

#include <string.h>

#include "sipe-appshare.h"
#include "sipe-appshare-remmina.h"
#include "sipe-backend.h"
#include "sipe-buddy.h"
#include "sipe-common.h"
#include "sipe-media.h"
#include "sipe-utils.h"

struct remmina_data {
	gchar *config_file;
};

static GSocketAddress *
remmina_get_listen_address(SIPE_UNUSED_PARAMETER struct sipe_rdp_client *client)
{
	GInetAddress *loopback;
	GSocketAddress *address;

	loopback = g_inet_address_new_loopback(G_SOCKET_FAMILY_IPV4);
	address = g_inet_socket_address_new(loopback, 0);
	g_object_unref(loopback);

	return address;
}

static void
cleanup_stale_remmina_files()
{
	gchar *runtime_dir;
	const gchar *file_name;
	GDir *dir;
	GError *error = NULL;

	runtime_dir = sipe_utils_get_user_runtime_dir();

	dir = g_dir_open(runtime_dir, 0, &error);
	if (!error) {
		gchar *prefix;

		prefix = g_strdup_printf("applicationsharing-%u-", getpid());

		while ((file_name = g_dir_read_name(dir))) {
			if (!g_str_has_prefix(file_name, prefix)) {
				gchar *file = g_build_filename(runtime_dir,
							       file_name, NULL);
				g_unlink(file);
				g_free(file);
			}
		}

		g_free(prefix);
		g_dir_close(dir);
	} else {
		g_error_free(error);
	}

	g_free(runtime_dir);
}

static gboolean
remmina_launch(struct sipe_rdp_client *client, GSocketAddress *listen_address,
	       struct sipe_media_stream *stream)
{
	struct remmina_data *client_data = client->client_data;
	struct sipe_core_private *sipe_private;
	GInetAddress *address;
	gchar *address_string;
	gchar *runtime_dir;
	gchar *alias;
	gchar *config_file;
	gchar *cmdline;
	guint16 port;
	GError *error = NULL;

	sipe_private = sipe_media_get_sipe_core_private(stream->call);

	cleanup_stale_remmina_files();

	address = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(listen_address));
	address_string = g_inet_address_to_string(address);

	port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(listen_address));

	alias = sipe_buddy_get_alias(sipe_private, stream->call->with);

	config_file = g_strdup_printf("[remmina]\n"
				      "name=%s (Sipe desktop)\n"
				      "protocol=RDP\n"
				      "server=%s:%u\n"
				      "security=rdp\n"
				      "scale=1\n"
				      "aspectscale=1\n"
				      "viewmode=1\n"
				      "disableautoreconnect=1\n",
				      alias ? alias : stream->call->with,
				      address_string,
				      port);

	g_free(alias);
	g_free(address_string);

	runtime_dir = sipe_utils_get_user_runtime_dir();
	client_data->config_file =
			g_strdup_printf("%s/applicationsharing-%u-%p.remmina",
					runtime_dir, getpid(), client);
	g_free(runtime_dir);

	g_file_set_contents(client_data->config_file, config_file,
			    strlen(config_file), &error);
	g_free(config_file);
	if (error) {
		SIPE_DEBUG_ERROR("Couldn't write remmina config file: %s",
				 error->message);
		g_error_free(error);
		return FALSE;
	}

	cmdline = g_strdup_printf("remmina -c %s", client_data->config_file);

	g_spawn_command_line_async(cmdline, &error);
	g_free(cmdline);
	if (error) {
		SIPE_DEBUG_ERROR("Couldn't launch remmina: %s", error->message);
		return FALSE;
	}

	return TRUE;
}

static void
remmina_free(struct sipe_rdp_client *client)
{
	struct remmina_data *client_data = client->client_data;

	if (client_data->config_file) {
		g_unlink(client_data->config_file);
		g_free(client_data->config_file);
	}

	g_free(client_data);
}

gboolean
sipe_appshare_remmina_init(struct sipe_rdp_client *client)
{
	gchar *program_path;

	program_path = g_find_program_in_path("remmina");
	if (!program_path) {
		SIPE_DEBUG_WARNING_NOFORMAT("Couldn't locate remmina binary");
		return FALSE;
	}
	g_free(program_path);

	client->client_data = g_new0(struct remmina_data, 1);

	client->get_listen_address_cb = remmina_get_listen_address;
	client->launch_cb = remmina_launch;
	client->free_cb = remmina_free;

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
