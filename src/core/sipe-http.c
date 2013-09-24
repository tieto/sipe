/**
 * @file sipe-http.c
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
 * SIPE HTTP API implementation
 *
 *  - convenience functions for public API: GET & POST requests
 *  - URL parsing
 *  - all other public API functions are implemented by lower layers
 */

#include <glib.h>

#include "sipe-backend.h"
#include "sipe-http.h"

#define _SIPE_HTTP_PRIVATE_IF_REQUEST
#include "sipe-http-request.h"

void sipe_http_parsed_uri_free(struct sipe_http_parsed_uri *parsed_uri)
{
	if (parsed_uri) {
		g_free(parsed_uri->host);
		g_free(parsed_uri->path);
		g_free(parsed_uri);
	}
}

struct sipe_http_parsed_uri *sipe_http_parse_uri(const gchar *uri)
{
	struct sipe_http_parsed_uri *parsed_uri = NULL;
	guint offset = 0;
	gboolean tls = FALSE;

//	SIPE_DEBUG_INFO("sipe_http_parse_uri: '%s'", uri);

	if (g_str_has_prefix(uri, "https://")) {
		offset = 8;
		tls    = TRUE;
	} else if (g_str_has_prefix(uri, "http://")) {
		offset = 7;
	}

	if (offset) {
		gchar **hostport_path = g_strsplit(uri + offset, "/", 2);

		if (hostport_path && hostport_path[0] && hostport_path[1]) {
			gchar **host_port = g_strsplit(hostport_path[0], ":", 2);

//			SIPE_DEBUG_INFO("sipe_http_parse_uri: hostport '%s' path '%s'", hostport_path[0], hostport_path[1]);

			/* ":port" is optional */
			if (host_port && host_port[0]) {

				parsed_uri = g_new0(struct sipe_http_parsed_uri, 1);
				parsed_uri->host = g_strdup(host_port[0]);
				parsed_uri->path = g_strdup(hostport_path[1]);
				parsed_uri->tls  = tls;

				if (host_port[1])
					parsed_uri->port = g_ascii_strtoull(host_port[1],
									    NULL,
									    10);
				if (parsed_uri->port == 0) {
					if (tls)
						/* default port for https */
						parsed_uri->port = 443;
					else
						/* default port for http */
						parsed_uri->port = 80;
				}

				SIPE_DEBUG_INFO("sipe_http_parse_uri: host '%s' port %d path '%s'",
						parsed_uri->host, parsed_uri->port, parsed_uri->path);

			}
			g_strfreev(host_port);
		}
		g_strfreev(hostport_path);
	}

	if (!parsed_uri)
		SIPE_DEBUG_ERROR("sipe_http_parse_uri: FAILED '%s'", uri);

	return(parsed_uri);
}

struct sipe_http_request *sipe_http_request_get(struct sipe_core_private *sipe_private,
						const gchar *uri,
						const gchar *headers,
						sipe_http_response_callback *callback,
						gpointer callback_data)
{
	struct sipe_http_request *req;
	struct sipe_http_parsed_uri *parsed_uri = sipe_http_parse_uri(uri);

	req = sipe_http_request_new(sipe_private,
				    parsed_uri,
				    headers,
				    NULL,
				    NULL,
				    callback,
				    callback_data);
	sipe_http_parsed_uri_free(parsed_uri);

	return(req);
}

struct sipe_http_request *sipe_http_request_post(struct sipe_core_private *sipe_private,
						 const gchar *uri,
						 const gchar *headers,
						 const gchar *body,
						 const gchar *content_type,
						 sipe_http_response_callback *callback,
						 gpointer callback_data)
{
	struct sipe_http_request *req;
	struct sipe_http_parsed_uri *parsed_uri = sipe_http_parse_uri(uri);

	req = sipe_http_request_new(sipe_private,
				    parsed_uri,
				    headers,
				    body,
				    content_type,
				    callback,
				    callback_data);
	sipe_http_parsed_uri_free(parsed_uri);

	return(req);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
