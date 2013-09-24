/**
 * @file sipe-http-transport.h
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

/* Private interface between HTTP Request <-> Transport layers */
#ifndef _SIPE_HTTP_PRIVATE_IF_TRANSPORT
#error "you are not allowed to include sipe-http-transport.h!"
#endif

/*
 * Interface dependencies:
 *
 * <glib.h>
 */

/* Forward declarations */
struct sipe_core_private;
struct sip_sec_context;

struct sipe_http_connection_public {
	struct sipe_core_private *sipe_private;

	GSList *pending_requests;        /* handled by sipe-http-request.c */
	struct sip_sec_context *context; /* handled by sipe-http-request.c */
	gchar *cached_authorization;     /* handled by sipe-http-request.c */

	gchar *host;
	guint32 port;
	gboolean connected;
};

/**
 * Check if we're shutting down the HTTP stack
 *
 * @param sipe_private SIPE core private data
 *
 * @return return @c TRUE if HTTP stack is shutting down
 */
gboolean sipe_http_shutting_down(struct sipe_core_private *sipe_private);

/**
 * Initiate HTTP connection
 *
 * If a connection to this host/port already exists it will be reused.
 *
 * @param sipe_private SIPE core private data
 * @param host         name of the host to connect to
 * @param port         port number to connect to
 * @param use_tls      use TLS if @c TRUE, otherwise TCP
 *
 * @return HTTP connection public data
 */
struct sipe_http_connection_public *sipe_http_transport_new(struct sipe_core_private *sipe_private,
							    const gchar *host,
							    guint32 port,
							    gboolean use_tls);

/**
 * Send HTTP request
 *
 * @param conn_public HTTP connection public data
 * @param header      HTTP header
 * @param body        HTTP body (may be @c NULL)
 */
void sipe_http_transport_send(struct sipe_http_connection_public *conn_public,
			      const gchar *header,
			      const gchar *body);
