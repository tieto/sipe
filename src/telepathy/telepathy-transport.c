/**
 * @file telepathy-transport.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2012 SIPE Project <http://sipe.sourceforge.net/>
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

#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-core.h"

#include "telepathy-private.h"

struct sipe_transport_telepathy {
	/* public part shared with core */
	struct sipe_transport_connection public;

	/* telepathy private part */
	transport_connected_cb *connected;
	transport_input_cb *input;
	transport_error_cb *error;
	struct sipe_backend_private *private;
	GSocketConnection *socket;
};

#define TELEPATHY_TRANSPORT ((struct sipe_transport_telepathy *) conn)
#define SIPE_TRANSPORT_CONNECTION ((struct sipe_transport_connection *) transport)

static void socket_connected(GObject *client,
			     GAsyncResult *result,
			     gpointer data)
{
	struct sipe_transport_telepathy *transport = data;
	GError *error = NULL;

	transport->socket = g_socket_client_connect_finish(G_SOCKET_CLIENT(client),
							   result,
							   &error);

	if (transport->socket) {
		SIPE_DEBUG_INFO_NOFORMAT("socket_connected: success");
		transport->connected(SIPE_TRANSPORT_CONNECTION);
	} else {
		SIPE_DEBUG_ERROR("socket_connected: failed: %s", error->message);
		transport->error(SIPE_TRANSPORT_CONNECTION, error->message);
	}
}

struct sipe_transport_connection *sipe_backend_transport_connect(struct sipe_core_public *sipe_public,
								 const sipe_connect_setup *setup)
{
	struct sipe_transport_telepathy *transport = g_new0(struct sipe_transport_telepathy, 1);
	struct sipe_backend_private *telepathy_private = sipe_public->backend_private;

	SIPE_DEBUG_INFO("sipe_backend_transport_connect - hostname: %s port: %d",
			setup->server_name, setup->server_port);

	transport->public.type      = setup->type;
	transport->public.user_data = setup->user_data;
	transport->connected        = setup->connected;
	transport->input            = setup->input;
	transport->error            = setup->error;
	transport->private          = telepathy_private;

	if ((setup->type == SIPE_TRANSPORT_TLS) ||
	    (setup->type == SIPE_TRANSPORT_TCP)) {
		GSocketClient *client = g_socket_client_new();

		/* request TLS connection */
		if (setup->type == SIPE_TRANSPORT_TLS) {
			SIPE_DEBUG_INFO_NOFORMAT("using TLS");
			g_socket_client_set_tls(client,
						setup->type == SIPE_TRANSPORT_TLS);
			/* @TODO certificate handling - now accept all*/
			g_socket_client_set_tls_validation_flags(client, 0);
		} else
			SIPE_DEBUG_INFO_NOFORMAT("using TCP");

		g_socket_client_connect_async(client,
					      g_network_address_new(setup->server_name,
								    setup->server_port),
					      NULL,
					      socket_connected,
					      transport);
		g_object_unref(client);
	} else {
		setup->error(SIPE_TRANSPORT_CONNECTION,
			     "This should not happen...");
		sipe_backend_transport_disconnect(SIPE_TRANSPORT_CONNECTION);
		return(NULL);
	}

	/* the first connection is always to the server */
	if (telepathy_private->transport == NULL)
		telepathy_private->transport = transport;

	return(SIPE_TRANSPORT_CONNECTION);
}

void sipe_backend_transport_disconnect(struct sipe_transport_connection *conn)
{
	struct sipe_transport_telepathy *transport = TELEPATHY_TRANSPORT;

	if (!transport) return;

	if (transport->socket)
		g_object_unref(transport->socket);

	/* connection to the server dropped? */
	if (transport->private->transport == transport)
		transport->private->transport = NULL;

	g_free(transport);
}

void sipe_backend_transport_message(SIPE_UNUSED_PARAMETER struct sipe_transport_connection *conn,
				    SIPE_UNUSED_PARAMETER const gchar *buffer)
{
	/* @TODO */
}

void sipe_backend_transport_flush(SIPE_UNUSED_PARAMETER struct sipe_transport_connection *conn)
{
	/* @TODO */
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
