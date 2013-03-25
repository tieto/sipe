/**
 * @file sipe-http-request.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include <glib.h>

#include "sipe-http.h"

#define _SIPE_HTTP_PRIVATE_IF_REQUEST
#include "sipe-http-request.h"
#define _SIPE_HTTP_PRIVATE_IF_TRANSPORT
#include "sipe-http-transport.h"

struct sipe_http_connection {
	struct sipe_http_connection_public public;
	GSList *pending_requests;
};

struct sipe_http_request {
	struct sipe_http_connection *connection;
	gchar *path;
	gchar *headers;
	gchar *body;         /* NULL for GET */
	gchar *content_type; /* NULL if body == NULL */
};

struct sipe_http_connection_public *sipe_http_connection_new(struct sipe_core_private *sipe_private,
							     const gchar *host,
							     guint32 port)
{
	struct sipe_http_connection *conn = g_new0(struct sipe_http_connection, 1);

	conn->public.sipe_private = sipe_private;
	conn->public.host         = g_strdup(host);
	conn->public.port         = port;

	return((struct sipe_http_connection_public *) conn);
}

static void sipe_http_request_free(gpointer data)
{
	struct sipe_http_request *req = data;

	g_free(req->path);
	g_free(req->headers);
	g_free(req->body);
	g_free(req->content_type);
	g_free(req);
}

static void sipe_http_request_send(struct sipe_http_connection *conn)
{
	struct sipe_http_request *req = conn->pending_requests->data;
	gchar *header;
	gchar *content = NULL;

	if (req->body)
		content = g_strdup_printf("Content-Length: %" G_GSIZE_FORMAT "\r\n"
					  "Content-Type: %s\r\n",
					  strlen(req->body),
					  req->content_type);

	header = g_strdup_printf("%s /%s HTTP/1.1\r\n"
				 "Host: %s\r\n"
				 "User-Agent: Sipe/" PACKAGE_VERSION "\r\n"
				 "%s%s",
				 content ? "POST" : "GET",
				 req->path,
				 conn->public.host,
				 req->headers ? req->headers : "",
				 content ? content : "");
	g_free(content);

	sipe_http_transport_send((struct sipe_http_connection_public *) conn,
				 header,
				 req->body);
	g_free(header);
}

void sipe_http_request_connected(struct sipe_http_connection_public *conn_public)
{
	sipe_http_request_send((struct sipe_http_connection *) conn_public);
}

void sipe_http_request_shutdown(struct sipe_http_connection_public *conn_public)
{
	struct sipe_http_connection *conn = (struct sipe_http_connection *) conn_public;

	if (conn->pending_requests) {
		GSList *entry = conn->pending_requests;
		while (entry) {
			sipe_http_request_free(entry->data);
			entry = entry->next;
		}
		g_slist_free(conn->pending_requests);
	}

	g_free(conn->public.host);
	g_free(conn);
}

struct sipe_http_request *sipe_http_request_new(struct sipe_core_private *sipe_private,
						const gchar *host,
						guint32 port,
						const gchar *path,
						const gchar *headers,
						const gchar *body,
						const gchar *content_type)
{
	struct sipe_http_request *req = g_new0(struct sipe_http_request, 1);
	struct sipe_http_connection *conn;

	req->path                 = g_strdup(path);
	if (headers)
		req->headers      = g_strdup(headers);
	if (body) {
		req->body         = g_strdup(body);
		req->content_type = g_strdup(content_type);
	}

	req->connection = conn = (struct sipe_http_connection *) sipe_http_transport_new(sipe_private,
											 host,
											 port);
	conn->pending_requests = g_slist_append(conn->pending_requests, req);

	return(req);
}

void sipe_http_request_cancel(struct sipe_http_request *request)
{
	struct sipe_http_connection *conn = request->connection;
	conn->pending_requests = g_slist_remove(conn->pending_requests,
						request);
	sipe_http_request_free(request);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
