/**
 * @file http-conn.h
 *
 * pidgin-sipe
 *
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

#define HTTP_CONN_SSL  "SSL"
#define HTTP_CONN_TCP  "TCP"

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

/** callback */
typedef void (*HttpConnCallback) (int return_code, const char *body,
				  HttpConn *conn, void *data);

/**
 * Creates SSL connection and POST.
 */
HttpConn *
http_conn_create(PurpleAccount *account,
		 const char *conn_type,
		 const char *full_url,
		 const char *body,
		 const char *content_type,
		 HttpConnAuth *auth,
		 HttpConnCallback callback,
		 void *data);

/**
 * POST on existing http_conn connection.
 */
void
http_conn_post(	HttpConn *http_conn,
		const char *full_url,
		const char *body,
		const char *content_type,
		HttpConnCallback callback,
		void *data);

/**
 * Marks connection for close
 */
void
http_conn_set_close(HttpConn* http_conn);

void
http_conn_auth_free(struct http_conn_auth* auth);

