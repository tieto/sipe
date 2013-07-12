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
struct sipe_http_connection_public;
struct sipe_http_request;

struct sipe_http_parsed_uri {
	gchar *host;
	gchar *path;
	guint port;
        gboolean tls;
};

/**
 * Parse URI
 *
 * @param uri text to parse
 *
 * @return pointer to parsed URI. Must be freed with @c sipe_http_parsed_uri_free()
 */
struct sipe_http_parsed_uri *sipe_http_parse_uri(const gchar *uri);

/**
 * Free parsed URI data structure
 *
 * @param pointer to parsed URI (may be @c NULL)
 */
void sipe_http_parsed_uri_free(struct sipe_http_parsed_uri *parsed_uri);


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
 * @param abort       @c TRUE if HTTP stack is shutting down
 */
void sipe_http_request_shutdown(struct sipe_http_connection_public *conn_public,
				gboolean abort);

/**
 * Create new HTTP request (internal raw version)
 *
 * @param sipe_private  SIPE core private data
 * @param parsed_uri    pointer to parsed URI
 * @param headers       additional headers to add (may be @c NULL)
 * @param body          body                      (may be @c NULL)
 * @param content_type  MIME type for body (may be @c NULL if body is @c NULL)
 * @param callback      callback function
 * @param callback_data callback data
 *
 * @return pointer to opaque HTTP request data structure
 */
struct sipe_http_request *sipe_http_request_new(struct sipe_core_private *sipe_private,
						const struct sipe_http_parsed_uri *parsed_uri,
						const gchar *headers,
						const gchar *body,
						const gchar *content_type,
						sipe_http_response_callback *callback,
						gpointer callback_data);
