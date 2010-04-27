/**
 * @file purple-transport.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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

#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <glib.h>

#include "sipe-common.h"

#include "circbuffer.h"
#include "connection.h"
#include "eventloop.h"
#include "network.h"
#include "proxy.h"
#include "sslconn.h"

#include "purple-private.h"

#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-nls.h"

struct sipe_transport_purple {
	/* public part shared with core */
	struct sipe_transport_connection public;

	/* purple private part */
	transport_connected_cb *connected;
	transport_input_cb *input;
	transport_error_cb *error;
	PurpleConnection *gc;
	PurpleSslConnection *gsc;
	PurpleCircBuffer *transmit_buffer;
	guint transmit_handler;
	guint receive_handler;
	int socket;
};

#define PURPLE_TRANSPORT ((struct sipe_transport_purple *) conn)
#define SIPE_TRANSPORT_CONNECTION ((struct sipe_transport_connection *) transport)

#define BUFFER_SIZE_INCREMENT 4096



/*****************************************************************************
 *
 * Common transport handling
 *
 *****************************************************************************/
static void transport_common_input(struct sipe_transport_purple *transport)
{
	struct sipe_transport_connection *conn = SIPE_TRANSPORT_CONNECTION;
	gssize readlen, len;
	gboolean firstread = TRUE;

	/* Read all available data from the connection */
	do {
		/* Increase input buffer size as needed */
		if (conn->buffer_length < conn->buffer_used + BUFFER_SIZE_INCREMENT) {
			conn->buffer_length += BUFFER_SIZE_INCREMENT;
			conn->buffer = g_realloc(conn->buffer, conn->buffer_length);
			SIPE_DEBUG_INFO("transport_input_common: new buffer length %" G_GSIZE_FORMAT,
					conn->buffer_length);
		}

		/* Try to read as much as there is space left in the buffer */
		/* minus 1 for the string terminator */
		readlen = conn->buffer_length - conn->buffer_used - 1;
		len = transport->gsc ?
			(gssize) purple_ssl_read(transport->gsc,
						 conn->buffer + conn->buffer_used,
						 readlen) :
			read(transport->socket,
			     conn->buffer + conn->buffer_used,
			     readlen);

		if (len < 0 && errno == EAGAIN) {
			/* Try again later */
			return;
		} else if (len < 0) {
			SIPE_DEBUG_ERROR_NOFORMAT("Read error");
			transport->error(SIPE_TRANSPORT_CONNECTION, _("Read error"));
			return;
		} else if (firstread && (len == 0)) {
			SIPE_DEBUG_ERROR_NOFORMAT("Server has disconnected");
			transport->error(SIPE_TRANSPORT_CONNECTION, _("Server has disconnected"));
			return;
		}

		conn->buffer_used += len;
		firstread = FALSE;

	/* Equivalence indicates that there is possibly more data to read */
	} while (len == readlen);

	conn->buffer[conn->buffer_used] = '\0';
        transport->input(conn);
}

static void transport_ssl_input(gpointer data,
				PurpleSslConnection *gsc,
				SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	struct sipe_transport_purple *transport = data;

	/* NOTE: This check *IS* necessary */
	if (!PURPLE_CONNECTION_IS_VALID(transport->gc)) {
		purple_ssl_close(gsc);
		transport->gsc = NULL;
		return;
	}
	transport_common_input(transport);
}

static void transport_tcp_input(gpointer data,
				gint source,
				SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	struct sipe_transport_purple *transport = data;

	/* NOTE: This check *IS* necessary */
	if (!PURPLE_CONNECTION_IS_VALID(transport->gc)) {
		close(source);
		transport->socket = -1;
		return;
	}
	transport_common_input(transport);
}

static void transport_ssl_connect_failure(SIPE_UNUSED_PARAMETER PurpleSslConnection *gsc,
					  PurpleSslErrorType error,
					  gpointer data)
{
	struct sipe_transport_purple *transport = data;

        /* If the connection is already disconnected
	   then we don't need to do anything else */
        if (!PURPLE_CONNECTION_IS_VALID(transport->gc))
		return;

	transport->socket = -1;
        transport->gsc = NULL;
	transport->error(SIPE_TRANSPORT_CONNECTION,
			 purple_ssl_strerror(error));
}

static void transport_common_connected(struct sipe_transport_purple *transport,
				       PurpleSslConnection *gsc,
				       int fd)
{
	if (!PURPLE_CONNECTION_IS_VALID(transport->gc))
	{
		if (gsc) {
			purple_ssl_close(gsc);
		} else if (fd >= 0) {
			close(fd);
		}
		return;
	}

	if (fd < 0) {
		transport->error(SIPE_TRANSPORT_CONNECTION,
				 _("Could not connect"));
		return;
	}

	transport->socket = fd;
	transport->public.client_port = purple_network_get_port_from_fd(fd);

	if (gsc) {
		transport->gsc = gsc;
		purple_ssl_input_add(gsc, transport_ssl_input, transport);
	} else {
		transport->receive_handler = purple_input_add(fd,
							      PURPLE_INPUT_READ,
							      transport_tcp_input,
							      transport);
	}

	transport->connected(SIPE_TRANSPORT_CONNECTION);
}

static void transport_ssl_connected(gpointer data,
				    PurpleSslConnection *gsc,
				    SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	transport_common_connected(data, gsc, gsc ? gsc->fd : -1);
}

static void transport_tcp_connected(gpointer data,
				    gint source,
				    SIPE_UNUSED_PARAMETER const gchar *error_message)
{
	transport_common_connected(data, NULL, source);
}

struct sipe_transport_connection *
sipe_backend_transport_connect(struct sipe_core_public *sipe_public,
			       const sipe_connect_setup *setup)
{
	struct sipe_transport_purple *transport = g_new0(struct sipe_transport_purple, 1);
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleConnection *gc = purple_private->gc;
	PurpleAccount *account = purple_connection_get_account(gc);

	SIPE_DEBUG_INFO("transport_connect - hostname: %s port: %d",
			setup->server_name, setup->server_port);

	transport->public.type      = setup->type;
	transport->public.user_data = setup->user_data;
	transport->connected        = setup->connected;
	transport->input            = setup->input;
	transport->error            = setup->error;
	transport->gc               = gc;
	transport->transmit_buffer  = purple_circ_buffer_new(0);

	if (setup->type == SIPE_TRANSPORT_TLS) {
		/* SSL case */
		SIPE_DEBUG_INFO_NOFORMAT("using SSL");

		if (purple_ssl_connect(account,
				       setup->server_name,
				       setup->server_port,
				       transport_ssl_connected,
				       transport_ssl_connect_failure,
				       transport) == NULL) {
			setup->error(SIPE_TRANSPORT_CONNECTION,
				     _("Could not create SSL context"));
			g_free(transport);
			return(NULL);
		}
	} else if (setup->type == SIPE_TRANSPORT_TCP) {
		/* TCP case */
		SIPE_DEBUG_INFO_NOFORMAT("using TCP");

		if (purple_proxy_connect(gc, account,
					 setup->server_name,
					 setup->server_port,
					 transport_tcp_connected,
					 transport) == NULL) {
			setup->error(SIPE_TRANSPORT_CONNECTION,
				     _("Could not create socket"));
			g_free(transport);
			return(NULL);
		}
	} else {
		setup->error(SIPE_TRANSPORT_CONNECTION,
			     "This should not happen...");
		g_free(transport);
		return(NULL);
	}

	return(SIPE_TRANSPORT_CONNECTION);
}

void sipe_backend_transport_disconnect(struct sipe_transport_connection *conn)
{
	struct sipe_transport_purple *transport = PURPLE_TRANSPORT;

	if (!transport) return;

	if (transport->gsc) {
		purple_ssl_close(transport->gsc);
	} else if (transport->socket > 0) {
		close(transport->socket);
	}

	if (transport->transmit_handler)
		purple_input_remove(transport->transmit_handler);
	if (transport->receive_handler)
		purple_input_remove(transport->receive_handler);

	if (transport->transmit_buffer)
		purple_circ_buffer_destroy(transport->transmit_buffer);
	g_free(transport->public.buffer);

	g_free(transport);
}

static void transport_canwrite_cb(gpointer data,
				  SIPE_UNUSED_PARAMETER gint source,
				  SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	struct sipe_transport_purple *transport = data;
	gsize max_write;

	max_write = purple_circ_buffer_get_max_read(transport->transmit_buffer);
	if (max_write > 0) {
		gssize written = transport->gsc ? 
			(gssize) purple_ssl_write(transport->gsc,
						  transport->transmit_buffer->outptr,
						  max_write) :
			write(transport->socket,
			      transport->transmit_buffer->outptr,
			      max_write);

		if (written < 0 && errno == EAGAIN) {
			return;
		} else if (written <= 0) {
			SIPE_DEBUG_INFO_NOFORMAT("transport_canwrite_cb: written <= 0, exiting");
			transport->error(SIPE_TRANSPORT_CONNECTION,
					 _("Write error"));
			return;
		}

		purple_circ_buffer_mark_read(transport->transmit_buffer,
					     written);

	} else {
		/* buffer is empty -> stop sending */
		purple_input_remove(transport->transmit_handler);
		transport->transmit_handler = 0;
	}
}

void sipe_backend_transport_message(struct sipe_transport_connection *conn,
				    const gchar *buffer)
{
	struct sipe_transport_purple *transport = PURPLE_TRANSPORT;
	time_t currtime = time(NULL);
	char *tmp;

	SIPE_DEBUG_INFO("sending - %s######\n%s######",
			ctime(&currtime), tmp = fix_newlines(buffer));
	g_free(tmp);

	/* add packet to circular buffer */
	purple_circ_buffer_append(transport->transmit_buffer,
				  buffer, strlen(buffer));

	/* initiate transmission */
	if (!transport->transmit_handler) {
		transport->transmit_handler = purple_input_add(transport->socket,
							       PURPLE_INPUT_WRITE,
							       transport_canwrite_cb,
							       transport);
	}
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
