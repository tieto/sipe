/**
 * @file miranda-transport.c
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

#include <windows.h>
#include <stdio.h>
#include <glib.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sipe-common.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-backend.h"
#include "sip-transport.h"
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
};

static unsigned __stdcall connected_callback(void* data)
{
	struct sipe_transport_miranda *transport = (struct sipe_transport_miranda*)data;
	SIPE_DEBUG_INFO_NOFORMAT("About to call connected callback");
	transport->connected(SIPE_TRANSPORT_CONNECTION);
	return 0;
}

static void
miranda_sipe_input_cb(gpointer data,
		      SIPE_UNUSED_PARAMETER gint source,
		      SIPE_UNUSED_PARAMETER sipe_miranda_input_condition cond)
{
	struct sipe_transport_miranda *transport = (struct sipe_transport_miranda *)data;
	struct sipe_transport_connection *conn = SIPE_TRANSPORT_CONNECTION;
	int len;
	int readlen;
	gboolean firstread = TRUE;

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

		len = Netlib_Recv(transport->fd, conn->buffer + conn->buffer_used, readlen, 0);

		if (len == SOCKET_ERROR) {
			SIPE_DEBUG_INFO_NOFORMAT("miranda_sipe_input_cb: read error");
			transport->error(SIPE_TRANSPORT_CONNECTION, _("Read error"));
			return;
		} else if (firstread && (len == 0)) {
			SIPE_DEBUG_ERROR_NOFORMAT("miranda_sipe_input_cb: server has disconnected");
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

struct sipe_transport_connection *
sipe_backend_transport_connect(struct sipe_core_public *sipe_public,
			       const sipe_connect_setup *setup)
{
	struct sipe_transport_miranda *transport = g_new0(struct sipe_transport_miranda, 1);
	SIPPROTO *pr = sipe_public->backend_private;

	NETLIBOPENCONNECTION ncon = {0};

	ncon.cbSize = sizeof(ncon);
	ncon.flags = NLOCF_V2;
	ncon.szHost = setup->server_name;
	ncon.wPort = setup->server_port;
	ncon.timeout = 5;

	transport->public.type      = setup->type;
	transport->public.user_data = setup->user_data;
	transport->connected        = setup->connected;
	transport->input            = setup->input;
	transport->error            = setup->error;

	transport->fd = (HANDLE)CallService(MS_NETLIB_OPENCONNECTION, (WPARAM)pr->m_hServerNetlibUser, (LPARAM)&ncon);
	if (transport->fd == NULL)  {
		setup->error(SIPE_TRANSPORT_CONNECTION,
			     _("Could not connect"));
		sipe_backend_transport_disconnect(SIPE_TRANSPORT_CONNECTION);
		return NULL;
	}

	SIPE_DEBUG_INFO("miranda_sipe_create_connection: connected %d", (int)transport->fd);

	if (setup->type == SIPE_TRANSPORT_TLS)
	{
		if (!CallService(MS_NETLIB_STARTSSL, (WPARAM)transport->fd, 0))
		{
			setup->error(SIPE_TRANSPORT_CONNECTION,
				     _("Could not negotiate SSL on connection"));
			sipe_backend_transport_disconnect(SIPE_TRANSPORT_CONNECTION);
			return NULL;
		}
		SIPE_DEBUG_INFO_NOFORMAT("miranda_sipe_create_connection: SSL enabled");
	}

	
	transport->public.client_port = sipe_miranda_network_get_port_from_fd( transport->fd );
	transport->input = setup->input;
	transport->inputhandler = sipe_miranda_input_add(transport->fd, SIPE_MIRANDA_INPUT_READ, miranda_sipe_input_cb, transport);

	CloseHandle((HANDLE) mir_forkthreadex( connected_callback, transport, 65536, NULL ));
//	transport->connected(SIPE_TRANSPORT_CONNECTION);

	return(SIPE_TRANSPORT_CONNECTION);
}

void sipe_backend_transport_disconnect(struct sipe_transport_connection *conn)
{
	struct sipe_transport_miranda *transport = MIRANDA_TRANSPORT;

	if (!transport) return;

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
		int len = Netlib_Send(transport->fd, buffer + written, strlen(buffer + written), 0);

		if (len == SOCKET_ERROR) {
			SIPE_DEBUG_INFO_NOFORMAT("sipe_backend_transport_message: error, exiting");
			transport->error(SIPE_TRANSPORT_CONNECTION,
					 _("Write error"));
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
