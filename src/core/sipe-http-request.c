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

#include <glib.h>

#include "sipe-http.h"

#define _SIPE_HTTP_PRIVATE_IF_REQUEST
#include "sipe-http-request.h"
#define _SIPE_HTTP_PRIVATE_IF_TRANSPORT
#include "sipe-http-transport.h"

struct sipe_http_connection {
	struct sipe_http_connection_public public;
	/* TBD */
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


void sipe_http_request_shutdown(struct sipe_http_connection_public *conn_public)
{
	struct sipe_http_connection *conn = (struct sipe_http_connection *) conn_public;

	g_free(conn->public.host);
	g_free(conn);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
