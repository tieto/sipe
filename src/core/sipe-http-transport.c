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

#include <glib.h>

#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-http.h"

#define _SIPE_HTTP_PRIVATE_IF_REQUEST
#include "sipe-http-request.h"
#define _SIPE_HTTP_PRIVATE_IF_TRANSPORT
#include "sipe-http-transport.h"

struct sipe_http_connection_private {
	/* TBD */
};

struct sipe_http {
	GHashTable *connections;
};

static void sipe_http_connection_free(gpointer data)
{
	struct sipe_http_connection_public  *conn_public  = data;
	struct sipe_http_connection_private *conn_private = conn_public->conn_private;

	/* TBD */
	g_free(conn_private);
	conn_public->conn_private = NULL;

	sipe_http_request_shutdown(conn_public);
}

void sipe_http_free(struct sipe_core_private *sipe_private)
{
	struct sipe_http *http = sipe_private->http;
	if (!http)
		return;

	g_hash_table_destroy(http->connections);
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
						  g_free,
						  sipe_http_connection_free);
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
		conn_public = sipe_http_connection_new(sipe_private,
						       host,
						       port);

		/* TBD */
		conn_public->conn_private = NULL;

		g_hash_table_insert(http->connections,
				    host_port,
				    conn_public);
		host_port = NULL; /* hash table takes ownership of the key */
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
