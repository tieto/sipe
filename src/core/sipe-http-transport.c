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
 *
 *
 * SIPE HTTP transport layer implementation
 *
 *  - connection handling: opening, closing, timeout
 *  - interface to backend: sending & receiving of raw messages
 *  - request queue pulling
 */

#include <string.h>
#include <time.h>

#include <glib.h>

#include "sipmsg.h"
#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-http.h"
#include "sipe-schedule.h"
#include "sipe-utils.h"

#define _SIPE_HTTP_PRIVATE_IF_REQUEST
#include "sipe-http-request.h"
#define _SIPE_HTTP_PRIVATE_IF_TRANSPORT
#include "sipe-http-transport.h"

#define SIPE_HTTP_CONNECTION         ((struct sipe_http_connection *) connection->user_data)
#define SIPE_HTTP_CONNECTION_PRIVATE ((struct sipe_http_connection *) conn_public)
#define SIPE_HTTP_CONNECTION_PUBLIC  ((struct sipe_http_connection_public *) conn)

#define SIPE_HTTP_TIMEOUT_ACTION  "<+http-timeout>"
#define SIPE_HTTP_DEFAULT_TIMEOUT 60 /* in seconds */

struct sipe_http_connection {
	struct sipe_http_connection_public public;

	struct sipe_transport_connection *connection;

	gchar *host_port;
	time_t timeout;  /* in seconds from epoch */
	gboolean use_tls;
};

struct sipe_http {
	GHashTable *connections;
	GQueue *timeouts;
	time_t next_timeout; /* in seconds from epoch, 0 if timer isn't running */
	gboolean shutting_down;
};

static gint timeout_compare(gconstpointer a,
			    gconstpointer b,
                            SIPE_UNUSED_PARAMETER gpointer user_data)
{
	return(((struct sipe_http_connection *) a)->timeout -
	       ((struct sipe_http_connection *) b)->timeout);
}

static void sipe_http_transport_update_timeout_queue(struct sipe_http_connection *conn,
						     gboolean remove);
static void sipe_http_transport_free(gpointer data)
{
	struct sipe_http_connection *conn = data;

	SIPE_DEBUG_INFO("sipe_http_transport_free: destroying connection '%s'",
			conn->host_port);

	if (conn->connection)
		sipe_backend_transport_disconnect(conn->connection);
	conn->connection = NULL;

	sipe_http_transport_update_timeout_queue(conn, TRUE);

	sipe_http_request_shutdown(SIPE_HTTP_CONNECTION_PUBLIC,
				   conn->public.sipe_private->http->shutting_down);

	g_free(conn->public.host);

	g_free(conn->host_port);
	g_free(conn);
}

static void sipe_http_transport_drop(struct sipe_http *http,
				     struct sipe_http_connection *conn,
				     const gchar *message)
{
	SIPE_DEBUG_INFO("sipe_http_transport_drop: dropping connection '%s': %s",
			conn->host_port,
			message ? message : "REASON UNKNOWN");

	/* this triggers sipe_http_transport_free */
	g_hash_table_remove(http->connections,
			    conn->host_port);
}

static void start_timer(struct sipe_core_private *sipe_private,
			time_t current_time);
static void sipe_http_transport_timeout(struct sipe_core_private *sipe_private,
					gpointer data)
{
	struct sipe_http *http = sipe_private->http;
	struct sipe_http_connection *conn = data;
	time_t current_time = time(NULL);

	/* timer has expired */
	http->next_timeout = 0;

	while (1) {
		sipe_http_transport_drop(http, conn, "timeout");
		/* conn is no longer valid */

		/* is there another active connection? */
		conn = g_queue_peek_head(http->timeouts);
		if (!conn)
			break;

		/* restart timer for next connection */
		if (conn->timeout > current_time) {
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
	struct sipe_http_connection *conn = g_queue_peek_head(http->timeouts);

	http->next_timeout = conn->timeout;
	sipe_schedule_seconds(sipe_private,
			      SIPE_HTTP_TIMEOUT_ACTION,
			      conn,
			      http->next_timeout - current_time,
			      sipe_http_transport_timeout,
			      NULL);
}

static void sipe_http_transport_update_timeout_queue(struct sipe_http_connection *conn,
						     gboolean remove)
{
	struct sipe_core_private *sipe_private = conn->public.sipe_private;
	struct sipe_http *http = sipe_private->http;
	GQueue *timeouts = http->timeouts;
	time_t current_time = time(NULL);

	/* is this connection at head of queue? */
	gboolean update = (conn == g_queue_peek_head(timeouts));

	/* update timeout queue */
	if (remove) {
		g_queue_remove(timeouts, conn);
	} else {
		conn->timeout = current_time + SIPE_HTTP_DEFAULT_TIMEOUT;
		g_queue_sort(timeouts,
			     timeout_compare,
			     NULL);
	}

	/* update timer if necessary */
	if (update) {
		sipe_schedule_cancel(sipe_private, SIPE_HTTP_TIMEOUT_ACTION);
		if (g_queue_is_empty(timeouts)) {
			http->next_timeout = 0;
		} else {
			start_timer(sipe_private, current_time);
		}
	}
}

gboolean sipe_http_shutting_down(struct sipe_core_private *sipe_private)
{
	struct sipe_http *http = sipe_private->http;
	/* We need to return FALSE in case HTTP stack isn't initialized yet */
	if (!http)
		return(FALSE);
	return(http->shutting_down);
}

void sipe_http_free(struct sipe_core_private *sipe_private)
{
	struct sipe_http *http = sipe_private->http;
	if (!http)
		return;

	/* HTTP stack is shutting down: reject all new requests */
	http->shutting_down = TRUE;

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
	struct sipe_http_connection *conn = SIPE_HTTP_CONNECTION;
	struct sipe_core_private *sipe_private = conn->public.sipe_private;
	struct sipe_http *http = sipe_private->http;
	time_t current_time = time(NULL);

	SIPE_DEBUG_INFO("sipe_http_transport_connected: %s", conn->host_port);
	conn->public.connected = TRUE;

	/* add active connection to timeout queue */
	conn->timeout = current_time + SIPE_HTTP_DEFAULT_TIMEOUT;
	g_queue_insert_sorted(http->timeouts,
			      conn,
			      timeout_compare,
			      NULL);

	/* start timeout timer if necessary */
	if (http->next_timeout == 0)
		start_timer(sipe_private, current_time);

	sipe_http_request_next(SIPE_HTTP_CONNECTION_PUBLIC);
}

static void sipe_http_transport_input(struct sipe_transport_connection *connection)
{
	struct sipe_http_connection *conn = SIPE_HTTP_CONNECTION;
	char *current = connection->buffer;

	/* according to the RFC remove CRLF at the beginning */
	while (*current == '\r' || *current == '\n') {
		current++;
	}
	if (current != connection->buffer)
		sipe_utils_shrink_buffer(connection, current);

	if ((current = strstr(connection->buffer, "\r\n\r\n")) != NULL) {
		struct sipmsg *msg;
		gboolean next;

		current += 2;
		current[0] = '\0';
		msg = sipmsg_parse_header(connection->buffer);
		if (!msg) {
			/* restore header for next try */
			current[0] = '\r';
			return;
		}

		/* HTTP/1.1 Transfer-Encoding: chunked */
		if (msg->bodylen == SIPMSG_BODYLEN_CHUNKED) {
			gchar *start        = current + 2;
			GSList *chunks      = NULL;
			gboolean incomplete = TRUE;

			msg->bodylen = 0;
			while (strlen(start) > 0) {
				gchar *tmp;
				guint length = g_ascii_strtoll(start, &tmp, 16);
				guint remainder;
				struct _chunk {
					guint length;
					const gchar *start;
				} *chunk;

				/* Illegal number */
				if ((length == 0) && (start == tmp))
					break;
				msg->bodylen += length;

				/* Chunk header not finished yet */
				tmp = strstr(tmp, "\r\n");
				if (tmp == NULL)
					break;

				/* Chunk not finished yet */
				tmp += 2;
				remainder = connection->buffer_used - (tmp - connection->buffer);
				if (remainder < length + 2)
					break;

				/* Next chunk */
				start = tmp + length + 2;

				/* Body completed */
				if (length == 0) {
					gchar *dummy  = g_malloc(msg->bodylen + 1);
					gchar *p      = dummy;
					GSList *entry = chunks;

					while (entry) {
						chunk = entry->data;
						memcpy(p, chunk->start, chunk->length);
						p += chunk->length;
						entry = entry->next;
					}
					p[0] = '\0';

					msg->body = dummy;
					sipe_utils_message_debug("HTTP",
								 connection->buffer,
								 msg->body,
								 FALSE);

					current = start;
					sipe_utils_shrink_buffer(connection,
								 current);

					incomplete = FALSE;
					break;
				}

				/* Append completed chunk */
				chunk = g_new0(struct _chunk, 1);
				chunk->length = length;
				chunk->start  = tmp;
				chunks = g_slist_append(chunks, chunk);
			}

			if (chunks)
				sipe_utils_slist_free_full(chunks, g_free);

			if (incomplete) {
				/* restore header for next try */
				sipmsg_free(msg);
				current[0] = '\r';
				return;
			}

		} else {
			guint remainder = connection->buffer_used - (current + 2 - connection->buffer);

			if (remainder >= (guint) msg->bodylen) {
				char *dummy = g_malloc(msg->bodylen + 1);
				current += 2;
				memcpy(dummy, current, msg->bodylen);
				dummy[msg->bodylen] = '\0';
				msg->body = dummy;
				current += msg->bodylen;
				sipe_utils_message_debug("HTTP",
							 connection->buffer,
							 msg->body,
							 FALSE);
				sipe_utils_shrink_buffer(connection, current);
			} else {
				SIPE_DEBUG_INFO("sipe_http_transport_input: body too short (%d < %d, strlen %" G_GSIZE_FORMAT ") - ignoring message",
						remainder, msg->bodylen, strlen(connection->buffer));

				/* restore header for next try */
				sipmsg_free(msg);
				current[0] = '\r';
				return;
			}
		}

		sipe_http_request_response(SIPE_HTTP_CONNECTION_PUBLIC, msg);
		next = sipe_http_request_pending(SIPE_HTTP_CONNECTION_PUBLIC);

		if (sipe_strcase_equal(sipmsg_find_header(msg, "Connection"), "close")) {
			/* drop backend connection */
			SIPE_DEBUG_INFO("sipe_http_transport_input: server requested close '%s'",
					conn->host_port);
			sipe_backend_transport_disconnect(conn->connection);
			conn->connection       = NULL;
			conn->public.connected = FALSE;

			/* if we have pending requests we need to trigger re-connect */
			if (next)
				sipe_http_transport_new(conn->public.sipe_private,
							conn->public.host,
							conn->public.port,
							conn->use_tls);

		} else if (next) {
			/* trigger sending of next pending request */
			sipe_http_request_next(SIPE_HTTP_CONNECTION_PUBLIC);
		}

		sipmsg_free(msg);
	}
}

static void sipe_http_transport_error(struct sipe_transport_connection *connection,
				      const gchar *msg)
{
	struct sipe_http_connection *conn = SIPE_HTTP_CONNECTION;
	sipe_http_transport_drop(conn->public.sipe_private->http,
				 conn,
				 msg);
	/* conn is no longer valid */
}

struct sipe_http_connection_public *sipe_http_transport_new(struct sipe_core_private *sipe_private,
							    const gchar *host_in,
							    const guint32 port,
							    gboolean use_tls)
{
	struct sipe_http *http;
	struct sipe_http_connection *conn = NULL;
	/* host name matching should be case insensitive */
	gchar *host = g_ascii_strdown(host_in, -1);
	gchar *host_port = g_strdup_printf("%s:%" G_GUINT32_FORMAT, host, port);

	sipe_http_init(sipe_private);

	http = sipe_private->http;
	if (http->shutting_down) {
		SIPE_DEBUG_ERROR("sipe_http_transport_new: new connection requested during shutdown: THIS SHOULD NOT HAPPEN! Debugging information:\n"
				 "Host/Port: %s", host_port);
	} else {
		conn = g_hash_table_lookup(http->connections, host_port);

		if (conn) {
			/* re-establishing connection */
			if (!conn->connection) {
				SIPE_DEBUG_INFO("sipe_http_transport_new: re-establishing %s", host_port);

				/* will be re-inserted after connect */
				sipe_http_transport_update_timeout_queue(conn, TRUE);
			}

		} else {
			/* new connection */
			SIPE_DEBUG_INFO("sipe_http_transport_new: new %s", host_port);

			conn = g_new0(struct sipe_http_connection, 1);

			conn->public.sipe_private = sipe_private;
			conn->public.host         = g_strdup(host);
			conn->public.port         = port;

			conn->host_port           = host_port;
			conn->use_tls             = use_tls;

			g_hash_table_insert(http->connections,
					    host_port,
					    conn);
			host_port = NULL; /* conn_private takes ownership of the key */
		}

		if (!conn->connection) {
			sipe_connect_setup setup = {
				use_tls ? SIPE_TRANSPORT_TLS : SIPE_TRANSPORT_TCP,
				host,
				port,
				conn,
				sipe_http_transport_connected,
				sipe_http_transport_input,
				sipe_http_transport_error
			};

			conn->public.connected = FALSE;
			conn->connection = sipe_backend_transport_connect(SIPE_CORE_PUBLIC,
									  &setup);
		}
	}

	g_free(host_port);
	g_free(host);
	return(SIPE_HTTP_CONNECTION_PUBLIC);
}

void sipe_http_transport_send(struct sipe_http_connection_public *conn_public,
			      const gchar *header,
			      const gchar *body)
{
	struct sipe_http_connection *conn = SIPE_HTTP_CONNECTION_PRIVATE;
	GString *message = g_string_new(header);

	g_string_append_printf(message, "\r\n%s", body ? body : "");

	sipe_utils_message_debug("HTTP", message->str, NULL, TRUE);
	sipe_backend_transport_message(conn->connection, message->str);
	g_string_free(message, TRUE);

	sipe_http_transport_update_timeout_queue(conn, FALSE);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
