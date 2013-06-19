/**
 * @file telepathy-transport.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2012-2013 SIPE Project <http://sipe.sourceforge.net/>
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
	gchar *hostname;
	struct sipe_tls_info *tls_info;
	struct sipe_backend_private *private;
	GCancellable *cancel;
	GSocketConnection *socket;
	GInputStream *istream;
	GOutputStream *ostream;
	GSList *buffers;
	guint port;
	gboolean is_writing;
	gboolean do_flush;
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
				const gchar *msg = error ? error->message : "UNKNOWN";
				SIPE_DEBUG_ERROR("read_completed: error: %s", msg);
				if (transport->error)
					transport->error(conn, msg);
				g_error_free(error);
				return;
			} else if (len == 0) {
				SIPE_DEBUG_ERROR_NOFORMAT("read_completed: server has disconnected");
				transport->error(conn, _("Server has disconnected"));
				return;
			} else if (transport->do_flush) {
				/* read completed while disconnected transport is flushing */
				SIPE_DEBUG_INFO_NOFORMAT("read_completed: ignored during flushing");
				return;
			} else if (g_cancellable_is_cancelled(transport->cancel)) {
				/* read completed when transport was disconnected */
				SIPE_DEBUG_INFO_NOFORMAT("read_completed: cancelled");
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
				  transport->cancel,
				  read_completed,
				  transport);
}

static gboolean internal_connect(gpointer data);
static void certificate_result(SIPE_UNUSED_PARAMETER GObject *unused,
			       GAsyncResult *result,
			       gpointer data)
{
	struct sipe_transport_telepathy *transport = data;
	GError *error = NULL;

	g_simple_async_result_propagate_error(G_SIMPLE_ASYNC_RESULT(result),
					      &error);
	if (error) {
		SIPE_DEBUG_INFO("certificate_result: %s", error->message);
		if (transport->error)
			transport->error(SIPE_TRANSPORT_CONNECTION,
					 error->message);
		g_error_free(error);
	} else {
		SIPE_DEBUG_INFO("certificate_result: trigger reconnect %p", transport);
		g_idle_add(internal_connect, transport);
	}
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

	if (transport->socket == NULL) {
		if (transport->tls_info) {
			SIPE_DEBUG_INFO_NOFORMAT("socket_connected: need to wait for user interaction");
			sipe_telepathy_tls_verify_async(G_OBJECT(transport->private->connection),
							transport->tls_info,
							certificate_result,
							transport);
		} else {
			const gchar *msg = error ? error->message : "UNKNOWN";
			SIPE_DEBUG_ERROR("socket_connected: failed: %s", msg);
			if (transport->error)
				transport->error(SIPE_TRANSPORT_CONNECTION, msg);
			g_error_free(error);
		}
	} else if (g_cancellable_is_cancelled(transport->cancel)) {
		/* connect already succeeded when transport was disconnected */
		g_object_unref(transport->socket);
		transport->socket = NULL;
		SIPE_DEBUG_INFO_NOFORMAT("socket_connected: succeeded, but cancelled");
	} else {
		GSocketAddress *saddr = g_socket_connection_get_local_address(transport->socket,
									      &error);

		if (saddr) {
			SIPE_DEBUG_INFO_NOFORMAT("socket_connected: success");

			transport->public.client_port = g_inet_socket_address_get_port(G_INET_SOCKET_ADDRESS(saddr));
			g_object_unref(saddr);

			transport->istream = g_io_stream_get_input_stream(G_IO_STREAM(transport->socket));
			transport->ostream = g_io_stream_get_output_stream(G_IO_STREAM(transport->socket));

			/* the first connection is always to the server */
			if (transport->private->transport == NULL)
				transport->private->transport = transport;

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
	}
}

static gboolean accept_certificate_signal(SIPE_UNUSED_PARAMETER GTlsConnection *tls,
					  GTlsCertificate *peer_cert,
					  SIPE_UNUSED_PARAMETER GTlsCertificateFlags errors,
					  gpointer user_data)
{
	struct sipe_transport_telepathy *transport = user_data;

	SIPE_DEBUG_INFO("accept_certificate_signal: %p", transport);

	/* second connection attempt after feedback from user? */
	if (transport->tls_info) {
		/* user accepted certificate */
		sipe_telepathy_tls_info_free(transport->tls_info);
		transport->tls_info = NULL;
		return(TRUE);
	} else {
		/* retry after user accepted certificate */
		transport->tls_info = sipe_telepathy_tls_info_new(transport->hostname,
								  peer_cert);
		return(FALSE);
	}
}

static void tls_handshake_starts(SIPE_UNUSED_PARAMETER GSocketClient *client,
				 GSocketClientEvent event,
				 SIPE_UNUSED_PARAMETER GSocketConnectable *connectable,
				 GIOStream *connection,
				 gpointer user_data)
{
	if (event == G_SOCKET_CLIENT_TLS_HANDSHAKING) {
		SIPE_DEBUG_INFO("tls_handshake_starts: %p", connection);
		g_signal_connect(connection, /* is a GTlsConnection */
				 "accept-certificate",
				 G_CALLBACK(accept_certificate_signal),
				 user_data);
	}
}

static gboolean internal_connect(gpointer data)
{
	struct sipe_transport_telepathy *transport = data;
	GSocketClient *client = g_socket_client_new();

	SIPE_DEBUG_INFO("internal_connect - hostname: %s port: %d",
			transport->hostname, transport->port);

	/* request TLS connection */
	if (transport->public.type == SIPE_TRANSPORT_TLS) {
		SIPE_DEBUG_INFO_NOFORMAT("using TLS");
		g_socket_client_set_tls(client, TRUE);
		g_signal_connect(client,
				 "event",
				 G_CALLBACK(tls_handshake_starts),
				 transport);
	} else
		SIPE_DEBUG_INFO_NOFORMAT("using TCP");

	g_socket_client_connect_async(client,
				      g_network_address_new(transport->hostname,
							    transport->port),
				      transport->cancel,
				      socket_connected,
				      transport);
	g_object_unref(client);

	return(FALSE);
}

struct sipe_transport_connection *sipe_backend_transport_connect(struct sipe_core_public *sipe_public,
								 const sipe_connect_setup *setup)
{
	struct sipe_transport_telepathy *transport = g_new0(struct sipe_transport_telepathy, 1);

	transport->public.type      = setup->type;
	transport->public.user_data = setup->user_data;
	transport->connected        = setup->connected;
	transport->input            = setup->input;
	transport->error            = setup->error;
	transport->hostname         = g_strdup(setup->server_name);
	transport->tls_info         = NULL;
	transport->private          = sipe_public->backend_private;
	transport->cancel           = g_cancellable_new();
	transport->buffers          = NULL;
	transport->port             = setup->server_port;
	transport->is_writing       = FALSE;
	transport->do_flush         = FALSE;

	if ((setup->type == SIPE_TRANSPORT_TLS) ||
	    (setup->type == SIPE_TRANSPORT_TCP)) {

		internal_connect(transport);
		return(SIPE_TRANSPORT_CONNECTION);

	} else {
		setup->error(SIPE_TRANSPORT_CONNECTION,
			     "This should not happen...");
		sipe_backend_transport_disconnect(SIPE_TRANSPORT_CONNECTION);
		return(NULL);
	}
}

static gboolean free_transport(gpointer data)
{
	struct sipe_transport_telepathy *transport = data;
	GSList *entry;

	SIPE_DEBUG_INFO("free_transport %p", transport);

	if (transport->tls_info)
		sipe_telepathy_tls_info_free(transport->tls_info);
	g_free(transport->hostname);

	/* free unflushed buffers */
	for (entry = transport->buffers; entry; entry = entry->next)
		g_free(entry->data);
	g_slist_free(transport->buffers);

	if (transport->cancel)
		g_object_unref(transport->cancel);

	g_free(transport);

	return(FALSE);
}

static void close_completed(GObject *stream,
			    GAsyncResult *result,
			    gpointer data)
{
	struct sipe_transport_telepathy *transport = data;
	SIPE_DEBUG_INFO("close_completed: transport %p", data);
	g_io_stream_close_finish(G_IO_STREAM(stream), result, NULL);
	g_idle_add(free_transport, transport);
}

static void do_close(struct sipe_transport_telepathy *transport)
{
	SIPE_DEBUG_INFO("do_close: %p", transport);

	/* cancel outstanding asynchronous operations */
	transport->do_flush = FALSE;
	g_cancellable_cancel(transport->cancel);
	g_io_stream_close_async(G_IO_STREAM(transport->socket),
				G_PRIORITY_DEFAULT,
				NULL,
				close_completed,
				transport);
}

void sipe_backend_transport_disconnect(struct sipe_transport_connection *conn)
{
	struct sipe_transport_telepathy *transport = TELEPATHY_TRANSPORT;

	if (!transport) return;

	SIPE_DEBUG_INFO("sipe_backend_transport_disconnect: %p", transport);

	/* error callback is invalid now, do no longer call! */
	transport->error = NULL;

	/* dropping connection to the server? */
	if (transport->private->transport == transport)
		transport->private->transport = NULL;

	/* already connected? */
	if (transport->socket) {

		/* flush required? */
		if (transport->do_flush && transport->is_writing)
			SIPE_DEBUG_INFO("sipe_backend_transport_disconnect: %p needs flushing",
					transport);
		else
			do_close(transport);

	} else {
		/* cancel outstanding connect operation */
		if (transport->cancel)
			g_cancellable_cancel(transport->cancel);

		/* queue transport to be deleted */
		g_idle_add(free_transport, transport);
	}
}

static void do_write(struct sipe_transport_telepathy *transport,
		     const gchar *buffer);
static void write_completed(GObject *stream,
			    GAsyncResult *result,
			    gpointer data)
{
	struct sipe_transport_telepathy *transport = data;
	GError                          *error     = NULL;
	gssize written = g_output_stream_write_finish(G_OUTPUT_STREAM(stream),
						      result,
						      &error);

	if ((written < 0) || error) {
		const gchar *msg = error ? error->message : "UNKNOWN";
		SIPE_DEBUG_ERROR("write_completed: error: %s", msg);
		if (transport->error)
			transport->error(SIPE_TRANSPORT_CONNECTION, msg);
		g_error_free(error);

		/* error during flush: give up and close transport */
		if (transport->do_flush)
			do_close(transport);

	} else if (g_cancellable_is_cancelled(transport->cancel)) {
		/* write completed when transport was disconnected */
		SIPE_DEBUG_INFO_NOFORMAT("write_completed: cancelled");
		transport->is_writing = FALSE;
	} else {
		/* more to write? */
		if (transport->buffers) {
			/* yes */
			gchar *buffer = transport->buffers->data;
			transport->buffers = g_slist_remove(transport->buffers,
							    buffer);
			do_write(transport, buffer);
			g_free(buffer);
		} else {
			/* no, we're done for now... */
			transport->is_writing = FALSE;

			/* flush completed */
			if (transport->do_flush)
				do_close(transport);
		}
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
				    transport->cancel,
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

void sipe_backend_transport_flush(struct sipe_transport_connection *conn)
{
	struct sipe_transport_telepathy *transport = TELEPATHY_TRANSPORT;
	transport->do_flush = TRUE;
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
