/**
 * @file sipe-http-transport.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2013 SIPE Project <http://sipe.sourceforge.net/>
 *
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

#include <time.h>

#include <glib.h>

#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-http.h"
#include "sipe-schedule.h"

#define _SIPE_HTTP_PRIVATE_IF_REQUEST
#include "sipe-http-request.h"
#define _SIPE_HTTP_PRIVATE_IF_TRANSPORT
#include "sipe-http-transport.h"

#define SIPE_HTTP_CONNECTION ((struct sipe_http_connection_public *) connection->user_data)

#define SIPE_HTTP_TIMEOUT_ACTION  "<+http-timeout>"
#define SIPE_HTTP_DEFAULT_TIMEOUT 60 /* in seconds */

struct sipe_http_connection_private {
	struct sipe_transport_connection *connection;
	gchar *host_port;
	time_t timeout;  /* in seconds from epoch */
};

struct sipe_http {
	GHashTable *connections;
	GQueue *timeouts;
	time_t next_timeout; /* in seconds from epoch, 0 if timer isn't running */
};

static gint timeout_compare(gconstpointer a,
			    gconstpointer b,
                            SIPE_UNUSED_PARAMETER gpointer user_data)
{
	return(((struct sipe_http_connection_private *) a)->timeout -
	       ((struct sipe_http_connection_private *) b)->timeout);
}

static void sipe_http_transport_free(gpointer data)
{
	struct sipe_http_connection_public  *conn_public  = data;
	struct sipe_http_connection_private *conn_private = conn_public->conn_private;
	struct sipe_http *http = conn_public->sipe_private->http;

	SIPE_DEBUG_INFO("sipe_http_transport_free: destroying connection to %s",
			conn_private->host_port);

	sipe_backend_transport_disconnect(conn_private->connection);
	g_queue_remove(http->timeouts, conn_private);
	g_free(conn_private->host_port);
	g_free(conn_private);
	conn_public->conn_private = NULL;

	sipe_http_request_shutdown(conn_public);
}

static void sipe_http_transport_drop(struct sipe_http *http,
				     struct sipe_http_connection_private *conn_private)
{
	/* this triggers sipe_http_transport_new */
	g_hash_table_remove(http->connections,
			    conn_private->host_port);
}

static void start_timer(struct sipe_core_private *sipe_private,
			time_t current_time);
static void sipe_http_transport_timeout(struct sipe_core_private *sipe_private,
					gpointer data)
{
	struct sipe_http *http = sipe_private->http;
	struct sipe_http_connection_private *conn_private = data;
	time_t current_time = time(NULL);

	/* timer has expired */
	http->next_timeout = 0;

	while (1) {
		SIPE_DEBUG_INFO("sipe_http_transport_timeout: dropping connection to %s",
				conn_private->host_port);
		sipe_http_transport_drop(http, conn_private);
		/* conn_private is no longer valid */

		/* is there another active connection? */
		conn_private = g_queue_peek_head(http->timeouts);
		if (!conn_private)
			break;

		/* restart timer for next connection */
		if (conn_private->timeout > current_time) {
			start_timer(sipe_private, current_time);
			break;
		}

		/* next connection timed-out too, loop around */
	}
}

static void start_timer(struct sipe_core_private *sipe_private,
			time_t current_time)
{
	struct sipe_http *http = sipe_private->http;
	struct sipe_http_connection_private *conn_private = g_queue_peek_head(http->timeouts);

	http->next_timeout = conn_private->timeout;
	sipe_schedule_seconds(sipe_private,
			      SIPE_HTTP_TIMEOUT_ACTION,
			      conn_private,
			      http->next_timeout - current_time,
			      sipe_http_transport_timeout,
			      NULL);
}

void sipe_http_free(struct sipe_core_private *sipe_private)
{
	struct sipe_http *http = sipe_private->http;
	if (!http)
		return;

	sipe_schedule_cancel(sipe_private, SIPE_HTTP_TIMEOUT_ACTION);
	g_hash_table_destroy(http->connections);
	g_queue_free(http->timeouts);
	g_free(http);
	sipe_private->http = NULL;
}

static void sipe_http_init(struct sipe_core_private *sipe_private)
{
	struct sipe_http *http;
	if (sipe_private->http)
		return;

	sipe_private->http = http = g_new0(struct sipe_http, 1);
	http->connections = g_hash_table_new_full(g_str_hash, g_str_equal,
						  NULL,
						  sipe_http_transport_free);
	http->timeouts = g_queue_new();
}

static void sipe_http_transport_connected(struct sipe_transport_connection *connection)
{
	struct sipe_http_connection_public *conn_public = SIPE_HTTP_CONNECTION;

	/* TBD */
	SIPE_DEBUG_INFO("sipe_http_transport_connected: %s",
			conn_public->conn_private->host_port);
}

static void sipe_http_transport_input(struct sipe_transport_connection *connection)
{
	struct sipe_http_connection_public *conn_public = SIPE_HTTP_CONNECTION;

	/* TBD */
	(void)conn_public;
}

static void sipe_http_transport_error(struct sipe_transport_connection *connection,
				      const gchar *msg)
{
	struct sipe_http_connection_public *conn_public = SIPE_HTTP_CONNECTION;

	/* TBD */
	(void)msg;

	sipe_http_transport_drop(conn_public->sipe_private->http,
				 conn_public->conn_private);
	/* conn_public is no longer valid */
}

struct sipe_http_connection_public *sipe_http_transport_new(struct sipe_core_private *sipe_private,
							    const gchar *host,
							    const guint32 port)
{
	struct sipe_http *http;
	struct sipe_http_connection_public *conn_public;
	gchar *host_port = g_strdup_printf("%s:%" G_GUINT32_FORMAT, host, port);

	sipe_http_init(sipe_private);

	http = sipe_private->http;
	conn_public = g_hash_table_lookup(http->connections, host_port);
	if (!conn_public) {
		struct sipe_http_connection_private *conn_private;
		time_t current_time = time(NULL);
		sipe_connect_setup setup = {
			SIPE_TRANSPORT_TLS, /* TBD: we only support TLS for now */
			host,
			port,
			NULL,
			sipe_http_transport_connected,
			sipe_http_transport_input,
			sipe_http_transport_error
		};

		SIPE_DEBUG_INFO("sipe_http_transport_new: %s", host_port);

		conn_public = sipe_http_connection_new(sipe_private,
						       host,
						       port);
		setup.user_data = conn_public;

		conn_public->conn_private = conn_private = g_new0(struct sipe_http_connection_private, 1);

		conn_private->connection = sipe_backend_transport_connect(SIPE_CORE_PUBLIC,
									  &setup);
		conn_private->host_port  = host_port;
		conn_private->timeout    = current_time + SIPE_HTTP_DEFAULT_TIMEOUT;

		g_queue_insert_sorted(http->timeouts,
				      conn_private,
				      timeout_compare,
				      NULL);

		/* start timeout timer if necessary */
		if (http->next_timeout == 0)
			start_timer(sipe_private, current_time);

		g_hash_table_insert(http->connections,
				    host_port,
				    conn_public);
		host_port = NULL; /* conn_private takes ownership of the key */
	}

	g_free(host_port);
	return(conn_public);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
