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
struct sipe_core_private;
struct sipe_http_connection_private;

struct sipe_http_connection_public {
	struct sipe_core_private *sipe_private;
	struct sipe_http_connection_private *conn_private;

	gchar *host;
        guint32 port;
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
 * HTTP connection shutdown
 *
 * @param conn_public HTTP connection public data
 */
void sipe_http_request_shutdown(struct sipe_http_connection_public *conn_public);
