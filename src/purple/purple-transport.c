/**
 * @file purple-transport.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2015 SIPE Project <http://sipe.sourceforge.net/>
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
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <glib.h>

#include "sipe-common.h"

#include "connection.h"
#include "eventloop.h"
#include "network.h"
#include "proxy.h"
#include "sslconn.h"

#include "version.h"
#if PURPLE_VERSION_CHECK(3,0,0)
#include "circularbuffer.h"
#else
#include "circbuffer.h"
#define PurpleCircularBuffer PurpleCircBuffer
#define purple_circular_buffer_append(b, s, n) purple_circ_buffer_append(b, s, n)
#define purple_circular_buffer_get_max_read(b) purple_circ_buffer_get_max_read(b)
#define purple_circular_buffer_get_output(b)   b->outptr
#define purple_circular_buffer_mark_read(b, s) purple_circ_buffer_mark_read(b, s)
#define purple_circular_buffer_new(s)          purple_circ_buffer_new(s)
#endif

#ifdef _WIN32
/* wrappers for write() & friends for socket handling */
#include "win32/win32dep.h"
#endif

#include "purple-private.h"

#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-nls.h"

struct sipe_transport_purple {
	/* public part shared with core */
	struct sipe_transport_connection public;

	/* purple private part */
	struct sipe_backend_private *purple_private;
	transport_connected_cb *connected;
	transport_input_cb *input;
	transport_error_cb *error;
	PurpleSslConnection *gsc;
	PurpleProxyConnectData *proxy;
	PurpleCircularBuffer *transmit_buffer;
	guint transmit_handler;
	guint receive_handler;
	int socket;

	gboolean is_valid;
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
			SIPE_DEBUG_ERROR("Read error: %s (%d)", strerror(errno), errno);
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
				SIPE_UNUSED_PARAMETER PurpleSslConnection *gsc,
				SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	struct sipe_transport_purple *transport = data;

	/* Ignore spurious "SSL input" events after disconnect */
	if (transport->is_valid)
		transport_common_input(transport);
}

static void transport_tcp_input(gpointer data,
				SIPE_UNUSED_PARAMETER gint source,
				SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	struct sipe_transport_purple *transport = data;

	/* Ignore spurious "TCP input" events after disconnect */
	if (transport->is_valid)
		transport_common_input(transport);
}

static void transport_ssl_connect_failure(SIPE_UNUSED_PARAMETER PurpleSslConnection *gsc,
					  PurpleSslErrorType error,
					  gpointer data)
{
	struct sipe_transport_purple *transport = data;

        /* Ignore spurious "SSL connect failure" events after disconnect */
	if (transport->is_valid) {
		transport->socket = -1;
		transport->gsc = NULL;
		transport->error(SIPE_TRANSPORT_CONNECTION,
				 purple_ssl_strerror(error));
		sipe_backend_transport_disconnect(SIPE_TRANSPORT_CONNECTION);
	}
}

static void transport_common_connected(struct sipe_transport_purple *transport,
				       int fd)
{
        /* Ignore spurious "connected" events after disconnect */
	if (transport->is_valid) {

		transport->proxy = NULL;

		if (fd < 0) {
			transport->error(SIPE_TRANSPORT_CONNECTION,
					 _("Could not connect"));
			sipe_backend_transport_disconnect(SIPE_TRANSPORT_CONNECTION);
			return;
		}

		transport->socket = fd;
		transport->public.client_port = purple_network_get_port_from_fd(fd);

		if (transport->gsc) {
			purple_ssl_input_add(transport->gsc, transport_ssl_input, transport);
		} else {
			transport->receive_handler = purple_input_add(fd,
								      PURPLE_INPUT_READ,
								      transport_tcp_input,
								      transport);
		}

		transport->connected(SIPE_TRANSPORT_CONNECTION);
	}
}

static void transport_ssl_connected(gpointer data,
				    PurpleSslConnection *gsc,
				    SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	transport_common_connected(data, gsc->fd);
}

static void transport_tcp_connected(gpointer data,
				    gint source,
				    SIPE_UNUSED_PARAMETER const gchar *error_message)
{
	transport_common_connected(data, source);
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
	transport->purple_private   = purple_private;
	transport->connected        = setup->connected;
	transport->input            = setup->input;
	transport->error            = setup->error;
	transport->transmit_buffer  = purple_circular_buffer_new(0);
	transport->is_valid         = TRUE;

	purple_private->transports = g_slist_prepend(purple_private->transports,
						     transport);

	if (setup->type == SIPE_TRANSPORT_TLS) {
		/* SSL case */
		SIPE_DEBUG_INFO_NOFORMAT("using SSL");

		if ((transport->gsc = purple_ssl_connect(account,
							 setup->server_name,
							 setup->server_port,
							 transport_ssl_connected,
							 transport_ssl_connect_failure,
							 transport)) == NULL) {
			setup->error(SIPE_TRANSPORT_CONNECTION,
				     _("Could not create SSL context"));
			sipe_backend_transport_disconnect(SIPE_TRANSPORT_CONNECTION);
			return(NULL);
		}
	} else if (setup->type == SIPE_TRANSPORT_TCP) {
		/* TCP case */
		SIPE_DEBUG_INFO_NOFORMAT("using TCP");

		/*
		 * NOTE: during shutdown libpurple calls
		 *
		 *    purple_proxy_connect_cancel_with_handle(gc);
		 *
		 * before our cleanup code. Therefore we can't use "gc" as
		 * handle. We are not using it for anything thus NULL is fine.
		 */
		if ((transport->proxy = purple_proxy_connect(NULL, account,
							     setup->server_name,
							     setup->server_port,
							     transport_tcp_connected,
							     transport)) == NULL) {
			setup->error(SIPE_TRANSPORT_CONNECTION,
				     _("Could not create socket"));
			sipe_backend_transport_disconnect(SIPE_TRANSPORT_CONNECTION);
			return(NULL);
		}
	} else {
		setup->error(SIPE_TRANSPORT_CONNECTION,
			     "This should not happen...");
		sipe_backend_transport_disconnect(SIPE_TRANSPORT_CONNECTION);
		return(NULL);
	}

	return(SIPE_TRANSPORT_CONNECTION);
}

static gboolean transport_deferred_destroy(gpointer user_data)
{
	/*
	 * All pending events on transport have been processed.
	 * Now it is safe to destroy the data structure.
	 */
	SIPE_DEBUG_INFO("transport_deferred_destroy: %p", user_data);
	g_free(user_data);
	return(FALSE);
}

void sipe_backend_transport_disconnect(struct sipe_transport_connection *conn)
{
	struct sipe_transport_purple *transport = PURPLE_TRANSPORT;
	struct sipe_backend_private *purple_private;

	if (!transport || !transport->is_valid) return;

	purple_private = transport->purple_private;
	purple_private->transports = g_slist_remove(purple_private->transports,
						    transport);

	if (transport->gsc) {
		purple_ssl_close(transport->gsc);
	} else if (transport->socket > 0) {
		close(transport->socket);
	}

	if (transport->proxy)
		purple_proxy_connect_cancel(transport->proxy);

	if (transport->transmit_handler)
		purple_input_remove(transport->transmit_handler);
	if (transport->receive_handler)
		purple_input_remove(transport->receive_handler);

	if (transport->transmit_buffer)
#if PURPLE_VERSION_CHECK(3,0,0)
		g_object_unref(transport->transmit_buffer);
#else
		purple_circ_buffer_destroy(transport->transmit_buffer);
#endif
	g_free(transport->public.buffer);

	/* defer deletion of transport data structure to idle callback */
	transport->is_valid = FALSE;
	g_idle_add(transport_deferred_destroy, transport);
}

void sipe_purple_transport_close_all(struct sipe_backend_private *purple_private)
{
	GSList *entry;
	SIPE_DEBUG_INFO_NOFORMAT("sipe_purple_transport_close_all: entered");
	while ((entry = purple_private->transports) != NULL)
		sipe_backend_transport_disconnect(entry->data);
}

/* returns FALSE on write error */
static gboolean transport_write(struct sipe_transport_purple *transport)
{
	gsize max_write;

	max_write = purple_circular_buffer_get_max_read(transport->transmit_buffer);
	if (max_write > 0) {
		gssize written = transport->gsc ?
			(gssize) purple_ssl_write(transport->gsc,
						  purple_circular_buffer_get_output(transport->transmit_buffer),
						  max_write) :
			write(transport->socket,
			      purple_circular_buffer_get_output(transport->transmit_buffer),
			      max_write);

		if (written < 0 && errno == EAGAIN) {
			return TRUE;
		} else if (written <= 0) {
			SIPE_DEBUG_ERROR("Write error: %s (%d)", strerror(errno), errno);
			transport->error(SIPE_TRANSPORT_CONNECTION,
					 _("Write error"));
			return FALSE;
		}

		purple_circular_buffer_mark_read(transport->transmit_buffer,
						 written);

	} else {
		/* buffer is empty -> stop sending */
		purple_input_remove(transport->transmit_handler);
		transport->transmit_handler = 0;
	}

	return TRUE;
}

static void transport_canwrite_cb(gpointer data,
				  SIPE_UNUSED_PARAMETER gint source,
				  SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	struct sipe_transport_purple *transport = data;

	/* Ignore spurious "can write" events after disconnect */
	if (transport->is_valid)
		transport_write(data);
}

void sipe_backend_transport_message(struct sipe_transport_connection *conn,
				    const gchar *buffer)
{
	struct sipe_transport_purple *transport = PURPLE_TRANSPORT;

	/* add packet to circular buffer */
	purple_circular_buffer_append(transport->transmit_buffer,
				      buffer, strlen(buffer));

	/* initiate transmission */
	if (!transport->transmit_handler) {
		transport->transmit_handler = purple_input_add(transport->socket,
							       PURPLE_INPUT_WRITE,
							       transport_canwrite_cb,
							       transport);
	}
}

void sipe_backend_transport_flush(struct sipe_transport_connection *conn)
{
	struct sipe_transport_purple *transport = PURPLE_TRANSPORT;

	while (	purple_circular_buffer_get_max_read(transport->transmit_buffer)
		&& transport_write(transport));
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
