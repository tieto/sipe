/**
 * @file miranda-transport.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-11 SIPE Project <http://sipe.sourceforge.net/>
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

#include <windows.h>
#include <stdio.h>
#include <glib.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sipe-common.h"
#include "sipe-core.h"
#include "sipe-backend.h"
#include "sipe-nls.h"

#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "m_netlib.h"
#include "miranda-private.h"

#define MIRANDA_TRANSPORT ((struct sipe_transport_miranda *) conn)
#define SIPE_TRANSPORT_CONNECTION ((struct sipe_transport_connection *) transport)

#define BUFFER_SIZE_INCREMENT 4096

struct sipe_transport_miranda {
	/* public part shared with core */
	struct sipe_transport_connection public;

	/* miranda private part */
	transport_connected_cb *connected;
	transport_input_cb *input;
	transport_error_cb *error;
	HANDLE fd;
	struct sipe_miranda_sel_entry *inputhandler;

	SIPPROTO *pr;

	/* Private. For locking only */
	HANDLE hDoneEvent;
};

static void __stdcall
transport_input_cb_async(void *data)
{
	struct sipe_transport_miranda *transport = (struct sipe_transport_miranda *)data;
	struct sipe_transport_connection *conn = SIPE_TRANSPORT_CONNECTION;
	SIPPROTO *pr = transport->pr;
	LOCK;
        transport->input(conn);
	UNLOCK;
	SetEvent(transport->hDoneEvent);
}

static void
miranda_sipe_input_cb(gpointer data,
		      SIPE_UNUSED_PARAMETER gint source,
		      SIPE_UNUSED_PARAMETER sipe_miranda_input_condition cond)
{
	struct sipe_transport_miranda *transport = (struct sipe_transport_miranda *)data;
	struct sipe_transport_connection *conn = SIPE_TRANSPORT_CONNECTION;
	SIPPROTO *pr = transport->pr;
	int len;
	int readlen;
	gboolean firstread = TRUE;

	LOCK;

	if (!pr->valid)
	{
		UNLOCK;
		return;
	}

	if (!transport->fd)
	{
		UNLOCK;
		return;
	}

	do {
		/* Increase input buffer size as needed */
		if (conn->buffer_length < conn->buffer_used + BUFFER_SIZE_INCREMENT) {
			conn->buffer_length += BUFFER_SIZE_INCREMENT;
			conn->buffer = g_realloc(conn->buffer, conn->buffer_length);
			SIPE_DEBUG_INFO("miranda_sipe_input_cb: new buffer length %" G_GSIZE_FORMAT,
					conn->buffer_length);
		}

		/* Try to read as much as there is space left in the buffer */
		/* minus 1 for the string terminator */
		readlen = conn->buffer_length - conn->buffer_used - 1;

		len = Netlib_Recv(transport->fd, conn->buffer + conn->buffer_used, readlen, MSG_NODUMP);

		if (len == SOCKET_ERROR) {
			SIPE_DEBUG_INFO("miranda_sipe_input_cb: read error");
			if (transport)
				transport->error(SIPE_TRANSPORT_CONNECTION, "Read error");

			UNLOCK;
			return;
		} else if (firstread && (len == 0)) {
			SIPE_DEBUG_ERROR_NOFORMAT("miranda_sipe_input_cb: server has disconnected");
			transport->error(SIPE_TRANSPORT_CONNECTION, "Server has disconnected");
			UNLOCK;
			return;
		}

		conn->buffer_used += len;
		firstread = FALSE;

	/* Equivalence indicates that there is possibly more data to read */
	} while (len == readlen);

	conn->buffer[conn->buffer_used] = '\0';
	UNLOCK;

	transport->hDoneEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
	CallFunctionAsync(transport_input_cb_async, transport);
	WaitForSingleObject(transport->hDoneEvent, INFINITE);
	CloseHandle(transport->hDoneEvent);
}

static void
connected_callback(HANDLE fd, void* data, const gchar *reason)
{
	struct sipe_transport_miranda *transport = (struct sipe_transport_miranda*)data;
	SIPPROTO *pr = transport->pr;

	if (!pr) return;

	LOCK;
	if (!fd)
	{
		transport->error(SIPE_TRANSPORT_CONNECTION, reason);
	} else {
		transport->fd = fd;
		transport->public.client_port = sipe_miranda_network_get_port_from_fd( transport->fd );
		transport->inputhandler = sipe_miranda_input_add(transport->fd, SIPE_MIRANDA_INPUT_READ, miranda_sipe_input_cb, transport );
		transport->connected(SIPE_TRANSPORT_CONNECTION);
	}
	UNLOCK;
}

struct sipe_transport_connection *
sipe_backend_transport_connect(struct sipe_core_public *sipe_public,
			       const sipe_connect_setup *setup)
{
	struct sipe_transport_miranda *transport = g_new0(struct sipe_transport_miranda, 1);
	SIPPROTO *pr = sipe_public->backend_private;

	NETLIBOPENCONNECTION ncon = {0};

	transport->public.type      = setup->type;
	transport->public.user_data = setup->user_data;
	transport->connected        = setup->connected;
	transport->input            = setup->input;
	transport->error            = setup->error;
	transport->pr               = pr;

	sipe_miranda_connect(pr, setup->server_name, setup->server_port, (setup->type == SIPE_TRANSPORT_TLS), 5, connected_callback, transport);

	return(SIPE_TRANSPORT_CONNECTION);
}

void sipe_backend_transport_disconnect(struct sipe_transport_connection *conn)
{
	struct sipe_transport_miranda *transport = MIRANDA_TRANSPORT;

	SIPE_DEBUG_INFO("Disconnecting transport <%08x>", transport);

	if (!transport) return;

	Netlib_CloseHandle(transport->fd);
	transport->fd = NULL;

	if (transport->inputhandler)
		sipe_miranda_input_remove(transport->inputhandler);

	g_free(transport->public.buffer);
	g_free(transport);
}

void sipe_backend_transport_message(struct sipe_transport_connection *conn,
				    const gchar *buffer)
{
	struct sipe_transport_miranda *transport = MIRANDA_TRANSPORT;
	guint written = 0;

	do {
		int len = Netlib_Send(transport->fd, buffer + written, strlen(buffer + written), MSG_NODUMP);

		if (len == SOCKET_ERROR) {
			SIPE_DEBUG_INFO_NOFORMAT("sipe_backend_transport_message: error, exiting");
			transport->error(SIPE_TRANSPORT_CONNECTION,
					 "Write error");
			return;
		}

		written += len;
	} while (written < strlen(buffer));
}

void sipe_backend_transport_flush(struct sipe_transport_connection *conn)
{
	/* N/A */
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
