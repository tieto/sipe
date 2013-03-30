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

#include "sipmsg.h"
#include "sipe-backend.h"
#include "sipe-http.h"

#define _SIPE_HTTP_PRIVATE_IF_REQUEST
#include "sipe-http-request.h"
#define _SIPE_HTTP_PRIVATE_IF_TRANSPORT
#include "sipe-http-transport.h"

struct sipe_http_connection {
	struct sipe_http_connection_public public;
	GSList *pending_requests;
};

struct sipe_http_session {
	gchar *cookie; /* extremely simplistic cookie jar :-) */
};

struct sipe_http_request {
	struct sipe_http_connection *connection;

	struct sipe_http_session *session;

	gchar *path;
	gchar *headers;
	gchar *body;         /* NULL for GET */
	gchar *content_type; /* NULL if body == NULL */

	sipe_http_response_callback *cb;
	gpointer cb_data;
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

static void sipe_http_request_free(struct sipe_core_private *sipe_private,
				   struct sipe_http_request *req)
{
	if (req->cb)
		/* Callback: aborted */
		(*req->cb)(sipe_private, 0, NULL, NULL, req->cb_data);
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
	gchar *cookie  = NULL;

	if (req->body)
		content = g_strdup_printf("Content-Length: %" G_GSIZE_FORMAT "\r\n"
					  "Content-Type: %s\r\n",
					  strlen(req->body),
					  req->content_type);

	if (req->session && req->session->cookie)
		cookie = g_strdup_printf("Cookie: %s\r\n", req->session->cookie);

	header = g_strdup_printf("%s /%s HTTP/1.1\r\n"
				 "Host: %s\r\n"
				 "User-Agent: Sipe/" PACKAGE_VERSION "\r\n"
				 "%s%s%s",
				 content ? "POST" : "GET",
				 req->path,
				 conn->public.host,
				 req->headers ? req->headers : "",
				 cookie ? cookie : "",
				 content ? content : "");
	g_free(cookie);
	g_free(content);

	sipe_http_transport_send((struct sipe_http_connection_public *) conn,
				 header,
				 req->body);
	g_free(header);
}

gboolean sipe_http_request_pending(struct sipe_http_connection_public *conn_public)
{
	return(((struct sipe_http_connection *) conn_public)->pending_requests != NULL);
}

void sipe_http_request_next(struct sipe_http_connection_public *conn_public)
{
	sipe_http_request_send((struct sipe_http_connection *) conn_public);
}

void sipe_http_request_response(struct sipe_http_connection_public *conn_public,
				struct sipmsg *msg)
{
	struct sipe_core_private *sipe_private = conn_public->sipe_private;
	struct sipe_http_connection *conn = (struct sipe_http_connection *) conn_public;
	struct sipe_http_request *req = conn->pending_requests->data;
	const gchar *hdr;

	/* Set-Cookie: RMID=732423sdfs73242; expires=Fri, 31-Dec-2010 23:59:59 GMT; path=/; domain=.example.net */
	if (req->session &&
	    ((hdr = sipmsg_find_header(msg, "Set-Cookie")) != NULL)) {
		gchar **parts, **current;
		const gchar *part;
		gchar *new = NULL;

		g_free(req->session->cookie);
		req->session->cookie = NULL;

		current = parts = g_strsplit(hdr, ";", 0);
		while ((part = *current++) != NULL) {
			/* strip these parts from cookie */
			if (!(strstr(part, "path=")    ||
			      strstr(part, "domain=")  ||
			      strstr(part, "expires=") ||
			      strstr(part, "secure"))) {
				gchar *tmp = new;
				new = new ?
					g_strconcat(new, ";", part, NULL) :
					g_strdup(part);
				g_free(tmp);
			}
		}
		g_strfreev(parts);

		if (new) {
			req->session->cookie = new;
			SIPE_DEBUG_INFO("sipe_http_request_response: cookie: %s", new);
		}
	}

	/* Callback: success */
	(*req->cb)(sipe_private,
		   msg->response,
		   msg->headers,
		   msg->body,
		   req->cb_data);

	/* remove completed request */
	sipe_http_request_cancel(req);
}

void sipe_http_request_shutdown(struct sipe_http_connection_public *conn_public)
{
	struct sipe_http_connection *conn = (struct sipe_http_connection *) conn_public;

	if (conn->pending_requests) {
		GSList *entry = conn->pending_requests;
		while (entry) {
			sipe_http_request_free(conn_public->sipe_private,
					       entry->data);
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
						const gchar *content_type,
						sipe_http_response_callback *callback,
						gpointer callback_data)
{
	struct sipe_http_request *req = g_new0(struct sipe_http_request, 1);
	struct sipe_http_connection *conn;
	gboolean initial;

	req->path                 = g_strdup(path);
	if (headers)
		req->headers      = g_strdup(headers);
	if (body) {
		req->body         = g_strdup(body);
		req->content_type = g_strdup(content_type);
	}

	req->cb      = callback;
	req->cb_data = callback_data;

	req->connection = conn = (struct sipe_http_connection *) sipe_http_transport_new(sipe_private,
											 host,
											 port);
	initial = conn->pending_requests == NULL;

	conn->pending_requests = g_slist_append(conn->pending_requests, req);

	/* pass first request on already opened connection through directly */
	if (initial && conn->public.connected)
		sipe_http_request_send(conn);

	return(req);
}

struct sipe_http_session *sipe_http_session_start(void)
{
	return(g_new0(struct sipe_http_session, 1));
}

void sipe_http_session_close(struct sipe_http_session *session)
{
	if (session) {
		g_free(session->cookie);
		g_free(session);
	}
}

void sipe_http_request_cancel(struct sipe_http_request *request)
{
	struct sipe_http_connection *conn = request->connection;
	conn->pending_requests = g_slist_remove(conn->pending_requests,
						request);

	/* cancelled by requester, don't use callback */
	request->cb = NULL;

	sipe_http_request_free(conn->public.sipe_private, request);
}

void sipe_http_request_session(struct sipe_http_request *request,
			       struct sipe_http_session *session)
{
	request->session = session;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
