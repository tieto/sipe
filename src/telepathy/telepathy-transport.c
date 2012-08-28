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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include <glib.h>
#include <gio/gio.h>

#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-core.h"
#include "sipe-nls.h"

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
	GInputStream *istream;
	GOutputStream *ostream;
	GSList *buffers;
	gboolean is_writing;
};

#define TELEPATHY_TRANSPORT ((struct sipe_transport_telepathy *) conn)
#define SIPE_TRANSPORT_CONNECTION ((struct sipe_transport_connection *) transport)

#define BUFFER_SIZE_INCREMENT 4096

static void read_completed(GObject *stream,
			   GAsyncResult *result,
			   gpointer data)
{
	struct sipe_transport_telepathy *transport = data;
	struct sipe_transport_connection *conn = SIPE_TRANSPORT_CONNECTION;

	SIPE_DEBUG_INFO_NOFORMAT("read_completed: entry");

	do {
		if (conn->buffer_length < conn->buffer_used + BUFFER_SIZE_INCREMENT) {
			conn->buffer_length += BUFFER_SIZE_INCREMENT;
			conn->buffer = g_realloc(conn->buffer, conn->buffer_length);
			SIPE_DEBUG_INFO("read_completed: new buffer length %" G_GSIZE_FORMAT,
					conn->buffer_length);
		}

		/* callback result is valid */
		if (result) {
			GError *error = NULL;
			gssize len    = g_input_stream_read_finish(G_INPUT_STREAM(stream),
								   result,
								   &error);

			if (len < 0) {
				SIPE_DEBUG_ERROR("read error: %s", error->message);
				transport->error(conn, error->message);
				g_error_free(error);
				return;
			} else if (len == 0) {
				SIPE_DEBUG_ERROR_NOFORMAT("Server has disconnected");
				transport->error(conn, _("Server has disconnected"));
				return;
			}

			/* Forward data to core */
			conn->buffer_used               += len;
			conn->buffer[conn->buffer_used]  = '\0';
			transport->input(conn);

			/* we processed the result */
			result = NULL;
		}

		/* buffer too short? */
	} while (conn->buffer_length - conn->buffer_used - 1 == 0);

	/* setup next read */
	g_input_stream_read_async(G_INPUT_STREAM(stream),
				  conn->buffer + conn->buffer_used,
				  conn->buffer_length - conn->buffer_used - 1,
				  G_PRIORITY_DEFAULT,
				  NULL,
				  read_completed,
				  transport);
}

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
		GSocketAddress *saddr = g_socket_connection_get_local_address(transport->socket,
									      &error);

		if (saddr) {
			SIPE_DEBUG_INFO_NOFORMAT("socket_connected: success");

			transport->public.client_port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(saddr));
			g_object_unref(saddr);

			transport->istream    = g_io_stream_get_input_stream(G_IO_STREAM(transport->socket));
			transport->ostream    = g_io_stream_get_output_stream(G_IO_STREAM(transport->socket));
			transport->buffers    = NULL;
			transport->is_writing = FALSE;

			/* this sets up the async read handler */
			read_completed(G_OBJECT(transport->istream), NULL, transport);
			transport->connected(SIPE_TRANSPORT_CONNECTION);
		} else {
			g_object_unref(transport->socket);
			transport->socket = NULL;
			SIPE_DEBUG_ERROR("socket_connected: failed: %s", error->message);
			transport->error(SIPE_TRANSPORT_CONNECTION, error->message);
			g_error_free(error);
		}
	} else {
		SIPE_DEBUG_ERROR("socket_connected: failed: %s", error->message);
		transport->error(SIPE_TRANSPORT_CONNECTION, error->message);
		g_error_free(error);
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
	GSList *entry;

	if (!transport) return;

	for (entry = transport->buffers; entry; entry = entry->next)
		g_free(entry->data);
	g_slist_free(transport->buffers);
	transport->buffers    = NULL;
	transport->is_writing = FALSE;

	if (transport->socket)
		g_object_unref(transport->socket);
	transport->socket = NULL;

	/* connection to the server dropped? */
	if (transport->private->transport == transport)
		transport->private->transport = NULL;

	g_free(transport);
}

static void do_write(struct sipe_transport_telepathy *transport,
		     const gchar *buffer);
static void write_completed(GObject *stream,
			    GAsyncResult *result,
			    gpointer data)
{
	struct sipe_transport_telepathy *transport = data;
	GError                          *error     = NULL;

	g_output_stream_write_finish(G_OUTPUT_STREAM(stream), result, &error);

	if (error) {
		SIPE_DEBUG_ERROR("write error: %s", error->message);
		transport->error(SIPE_TRANSPORT_CONNECTION, error->message);
		g_error_free(error);
	} else {
		/* more to write? */
		if (transport->buffers) {
			/* yes */
			gchar *buffer = transport->buffers->data;
			transport->buffers = g_slist_remove(transport->buffers,
							    buffer);
			do_write(transport, buffer);
			g_free(buffer);
		} else
			/* no, we're done for now... */
			transport->is_writing = FALSE;
	}
}

static void do_write(struct sipe_transport_telepathy *transport,
		     const gchar *buffer)
{
	transport->is_writing = TRUE;
	g_output_stream_write_async(transport->ostream,
				    buffer,
				    strlen(buffer),
				    G_PRIORITY_DEFAULT,
				    NULL,
				    write_completed,
				    transport);
}

void sipe_backend_transport_message(struct sipe_transport_connection *conn,
				    const gchar *buffer)
{
	struct sipe_transport_telepathy *transport = TELEPATHY_TRANSPORT;

	/* currently writing? */
	if (transport->is_writing) {
		/* yes, append copy of buffer to list */
		transport->buffers = g_slist_append(transport->buffers,
						    g_strdup(buffer));
	} else
		/* no, write directly to stream */
		do_write(transport, buffer);
}

void sipe_backend_transport_flush(SIPE_UNUSED_PARAMETER struct sipe_transport_connection *conn)
{
	/* @TODO? */
}

const gchar *sipe_backend_network_ip_address(struct sipe_core_public *sipe_public)
{
	struct sipe_backend_private *telepathy_private = sipe_public->backend_private;
	const gchar *ipstr = telepathy_private->ipaddress;

	/* address cached? */
	if (!ipstr) {
		struct sipe_transport_telepathy *transport = telepathy_private->transport;

		/* default if everything should fail */
		ipstr = "127.0.0.1";

		/* connection to server established - get local IP from socket */
		if (transport && transport->socket) {
			GSocketAddress *saddr = g_socket_connection_get_local_address(transport->socket,
										      NULL);

			if (saddr) {
				GInetAddress *iaddr = g_inet_socket_address_get_address(G_INET_SOCKET_ADDRESS(saddr));

				if (iaddr) {
					/* cache address string */
					ipstr = telepathy_private->ipaddress = g_inet_address_to_string(iaddr);
					SIPE_DEBUG_INFO("sipe_backend_network_ip_address: %s", ipstr);
				}
				g_object_unref(saddr);
			}
		}
	}

	return(ipstr);
}


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
