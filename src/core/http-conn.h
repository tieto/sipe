/**
 * @file http-conn.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
 * Copyright (C) 2009 pier11 <pier11@operamail.com>
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

/* Forward declarations */
struct sipe_core_public;

#define HTTP_CONN_GET  "GET"
#define HTTP_CONN_POST "POST"

#define HTTP_CONN_SSL  SIPE_TRANSPORT_TLS
#define HTTP_CONN_TCP  SIPE_TRANSPORT_TCP

#define HTTP_CONN_ALLOW_REDIRECT	TRUE
#define HTTP_CONN_NO_REDIRECT		FALSE

#define HTTP_CONN_ERROR		-100
#define HTTP_CONN_ERROR_FATAL	-200


struct http_conn_auth {
	char *domain;
	char *user;
	char *password;
	int use_negotiate;
};
typedef struct http_conn_auth HttpConnAuth;

struct http_conn_struct;
typedef struct http_conn_struct HttpConn;
typedef struct http_session_struct HttpSession;

/** callback */
typedef void (*HttpConnCallback) (int return_code, const char *body, const char *content_type,
				  HttpConn *conn, void *data);

/**
 * Creates SSL connection and sends.
 */
HttpConn *
http_conn_create(struct sipe_core_public *sipe_public,
		 HttpSession *http_session,
		 const char *method,
		 guint conn_type,
		 gboolean allow_redirect,
		 const char *full_url,
		 const char *body,
		 const char *content_type,
		 HttpConnAuth *auth,
		 HttpConnCallback callback,
		 void *data);

/**
 * Sends on existing http_conn connection.
 */
void
http_conn_send(	HttpConn *http_conn,
		const char *method,
		const char *full_url,
		const char *body,
		const char *content_type,
		HttpConnCallback callback,
		void *data);

gboolean
http_conn_is_closed(HttpConn *http_conn);

/**
 * Marks connection for close
 */
void
http_conn_set_close(HttpConn* http_conn);

void
http_conn_free(HttpConn* http_conn);

void
http_conn_auth_free(HttpConnAuth* auth);

HttpSession *
http_conn_session_create(void);

void
http_conn_session_free(HttpSession *http_session);
