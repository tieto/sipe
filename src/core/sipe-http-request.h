/**
 * @file sipe-http-request.h
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

/* Private interface between HTTP Public <-> Request <-> Transport layers */
#ifndef _SIPE_HTTP_PRIVATE_IF_REQUEST
#error "you are not allowed to include sipe-http-request.h!"
#endif

/*
 * Interface dependencies:
 *
 * <glib.h>
 */

/* Forward declarations */
struct sipmsg;
struct sipe_core_private;
struct sipe_http_connection_private;
struct sipe_http_request;

struct sipe_http_connection_public {
	struct sipe_core_private *sipe_private;
	struct sipe_http_connection_private *conn_private;

	gchar *host;
	guint32 port;
	gboolean connected;
};

/**
 * Create new HTTP connection data
 *
 * @param sipe_private SIPE core private data
 * @param host         name of the host to connect to
 * @param port         port number to connect to
 *
 * @return HTTP connection public data
 */
struct sipe_http_connection_public *sipe_http_connection_new(struct sipe_core_private *sipe_private,
							     const gchar *host,
							     guint32 port);

/**
 * Is there pending request for HTTP connection?
 *
 * @param conn_public HTTP connection public data
 */
gboolean sipe_http_request_pending(struct sipe_http_connection_public *conn_public);

/**
 * HTTP connection is ready for next request
 *
 * @param conn_public HTTP connection public data
 */
void sipe_http_request_next(struct sipe_http_connection_public *conn_public);

/**
 * HTTP response received
 *
 * @param conn_public HTTP connection public data
 * @param msg         parsed message
 */
void sipe_http_request_response(struct sipe_http_connection_public *conn_public,
				struct sipmsg *msg);

/**
 * HTTP connection shutdown
 *
 * @param conn_public HTTP connection public data
 */
void sipe_http_request_shutdown(struct sipe_http_connection_public *conn_public);

/**
 * Create new HTTP request (internal raw version)
 *
 * @param sipe_private  SIPE core private data
 * @param host          name of the host to connect to
 * @param port          port number to connect to
 * @param path          relative path
 * @param headers       additional headers to add (may be @c NULL)
 * @param body          body                      (may be @c NULL)
 * @param content_type  MIME type for body (may be @c NULL if body is @c NULL)
 * @param callback      callback function
 * @param callback_data callback data
 *
 * @return pointer to opaque HTTP request data structure
 */
struct sipe_http_request *sipe_http_request_new(struct sipe_core_private *sipe_private,
						const gchar *host,
						guint32 port,
						const gchar *path,
						const gchar *headers,
						const gchar *body,
						const gchar *content_type,
						sipe_http_response_callback *callback,
						gpointer callback_data);
