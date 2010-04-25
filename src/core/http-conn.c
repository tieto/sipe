/**
 * @file http-conn.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
 * Copyright (C) 2009 pier11 <pier11@operamail.com>
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

/**
 * Operates with HTTPS connection.
 * Support Negotiate (Windows only) and NTLM authentications, redirect, cookie, GET/POST.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "http-conn.h"
#include "sipmsg.h"
#include "sip-sec.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-utils.h"

/**
 * HTTP header
 * @param method (%s)		Ex.: GET or POST
 * @param url (%s)		Ex.: /EWS/Exchange.asmx
 * @param host (%s)		Ex.: cosmo-ocs-r2.cosmo.local
 */
#define HTTP_CONN_HEADER \
"%s %s HTTP/1.1\r\n"\
"Host: %s\r\n"\
"User-Agent: Sipe/" PACKAGE_VERSION "\r\n"


struct http_conn_struct {
	struct sipe_core_public *sipe_public;

	/* GET, POST */
	char *method;
	guint conn_type;
	gboolean allow_redirect;
	char *host;
	guint port;
	char *url;
	char *body;
	char *content_type;
	HttpConnAuth *auth;
	HttpConnCallback callback;
	void *data;

	struct sipe_transport_connection *conn;

	SipSecContext sec_ctx;
	int retries;

	HttpSession *http_session;

	/* if server sends "Connection: close" header */
	gboolean closed;
	HttpConn* do_close;
};
#define HTTP_CONN ((HttpConn *) conn->user_data)

struct http_session_struct {
	char *cookie;
};

static HttpConn*
http_conn_clone(HttpConn* http_conn)
{
	HttpConn *res = g_new0(HttpConn, 1);

	res->http_session = http_conn->http_session;
	res->method = g_strdup(http_conn->method);
	res->conn_type = http_conn->conn_type;
	res->allow_redirect = http_conn->allow_redirect;
	res->host = g_strdup(http_conn->host);
	res->port = http_conn->port;
	res->url = g_strdup(http_conn->url);
	res->body = g_strdup(http_conn->body);
	res->content_type = g_strdup(http_conn->content_type);
	res->auth = http_conn->auth;
	res->callback = http_conn->callback;
	res->data = http_conn->data;

	res->conn = http_conn->conn;
	res->sec_ctx = http_conn->sec_ctx;
	res->retries = http_conn->retries;

	res->do_close = NULL;

	return res;
}

void
http_conn_free(HttpConn* http_conn)
{
	if (!http_conn) return;

	/* don't free "http_conn->http_session" - client should do */
	g_free(http_conn->method);
	g_free(http_conn->host);
	g_free(http_conn->url);
	g_free(http_conn->body);
	g_free(http_conn->content_type);

	if (http_conn->sec_ctx) {
		sip_sec_destroy_context(http_conn->sec_ctx);
	}

	g_free(http_conn);
}

gboolean
http_conn_is_closed(HttpConn *http_conn)
{
	return http_conn->closed;
}

HttpSession *
http_conn_session_create()
{
	HttpSession *res = g_new0(HttpSession, 1);
	return res;
}

void
http_conn_session_free(HttpSession *http_session)
{
	if (!http_session) return;

	g_free(http_session->cookie);
	g_free(http_session);
}

void
http_conn_auth_free(struct http_conn_auth* auth)
{
	g_free(auth->domain);
	g_free(auth->user);
	g_free(auth->password);
	g_free(auth);
}

void
http_conn_set_close(HttpConn* http_conn)
{
	http_conn->do_close = http_conn;
}

static void
http_conn_close(HttpConn *http_conn, const char *message)
{
	SIPE_DEBUG_INFO("http_conn_close: closing http connection: %s", message ? message : "");
	
	g_return_if_fail(http_conn);

	sipe_backend_transport_disconnect(http_conn->conn);
	http_conn_free(http_conn);
}

/**
 * Extracts host, port and relative url
 * Ex. url: https://machine.domain.Contoso.com/EWS/Exchange.asmx
 *
 * Allocates memory, must be g_free'd.
 */
static void
http_conn_parse_url(const char *url,
		    char **host,
		    guint *port,
		    char **rel_url)
{
        char **parts = g_strsplit(url, "://", 2);
        char *no_proto;
        guint port_tmp;
        char *tmp;
        char *host_port;

        if(!parts) {
                return;
        } else if(!parts[0]) {
                g_strfreev(parts);
                return;
        }

        no_proto = parts[1] ? g_strdup(parts[1]) : g_strdup(parts[0]);
        port_tmp = sipe_strequal(parts[0], "https") ? 443 : 80;
        g_strfreev(parts);

        if(!no_proto) {
		return;
        }

        tmp = strstr(no_proto, "/");
        if (tmp && rel_url) *rel_url = g_strdup(tmp);
        host_port = tmp ? g_strndup(no_proto, tmp - no_proto) : g_strdup(no_proto);
        g_free(no_proto);

        if(!host_port) {
                return;
        }

        parts = g_strsplit(host_port, ":", 2);

        if(parts) {
                if (host) *host = g_strdup(parts[0]);
                if(parts[0]) {
			port_tmp = parts[1] ? (guint) atoi(parts[1]) : port_tmp;
                }
                if (port) *port = port_tmp;
                g_strfreev(parts);
        }

        g_free(host_port);
}

static void http_conn_error(struct sipe_transport_connection *conn,
			    const gchar *msg)
{
	HttpConn *http_conn = HTTP_CONN;
	if (http_conn->callback) {
		(*http_conn->callback)(HTTP_CONN_ERROR, NULL, NULL, http_conn, http_conn->data);
	}
	http_conn_close(http_conn, msg);
}

static void http_conn_send0(HttpConn *http_conn,
			    const char *authorization);
static void http_conn_connected(struct sipe_transport_connection *conn)
{
	http_conn_send0(HTTP_CONN, NULL);
}

static void http_conn_input(struct sipe_transport_connection *conn);
static struct sipe_transport_connection *http_conn_setup(HttpConn *http_conn,
							 struct sipe_core_public *sipe_public,
							 guint type,
							 const gchar *host,
							 guint port) {
	sipe_connect_setup setup = {
		type,
		host,
		port,
		http_conn,
		http_conn_connected,
		http_conn_input,
		http_conn_error
	};
	return(sipe_backend_transport_connect(sipe_public, &setup));
}

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
		 void *data)
{
	HttpConn *http_conn;
	struct sipe_transport_connection *conn;
	gchar *host, *url;
	guint port;

	if (!full_url || (strlen(full_url) == 0)) {
		SIPE_DEBUG_INFO_NOFORMAT("no URL supplied!");
		return NULL;
	}

	http_conn_parse_url(full_url, &host, &port, &url);
	http_conn = g_new0(HttpConn, 1);
	conn = http_conn_setup(http_conn, sipe_public, conn_type, host, port);
	if (!conn) {
		g_free(http_conn);
		g_free(host);
		g_free(url);
		return NULL;
	}

	http_conn->sipe_public = sipe_public;
	conn->user_data = http_conn;

	http_conn->http_session = http_session;
	http_conn->method = g_strdup(method);
	http_conn->conn_type = conn_type;
	http_conn->allow_redirect = allow_redirect;
	http_conn->host = host;
	http_conn->port = port;
	http_conn->url = url;
	http_conn->body = g_strdup(body);
	http_conn->content_type = g_strdup(content_type);
	http_conn->auth = auth;
	http_conn->callback = callback;
	http_conn->data = data;
	http_conn->conn = conn;

	return http_conn;
}

/* Data part */
static void
http_conn_send0(HttpConn *http_conn,
		const char *authorization)
{
	GString *outstr = g_string_new("");

	g_string_append_printf(outstr, HTTP_CONN_HEADER,
				http_conn->method ? http_conn->method : "GET",
				http_conn->url,
				http_conn->host);
	if (sipe_strequal(http_conn->method, "POST")) {
		g_string_append_printf(outstr, "Content-Length: %d\r\n",
			http_conn->body ? (int)strlen(http_conn->body) : 0);

		g_string_append_printf(outstr, "Content-Type: %s\r\n",
			http_conn->content_type ? http_conn->content_type : "text/plain");
	}
	if (http_conn->http_session && http_conn->http_session->cookie) {
		g_string_append_printf(outstr, "Cookie: %s\r\n", http_conn->http_session->cookie);
	}
	if (authorization) {
		g_string_append_printf(outstr, "Authorization: %s\r\n", authorization);
	}
	g_string_append_printf(outstr, "\r\n%s", http_conn->body ? http_conn->body : "");

	sipe_backend_transport_message(http_conn->conn, outstr->str);
	g_string_free(outstr, TRUE);
}

void
http_conn_send(	HttpConn *http_conn,
		const char *method,
		const char *full_url,
		const char *body,
		const char *content_type,
		HttpConnCallback callback,
		void *data)
{
	if (!http_conn) {
		SIPE_DEBUG_INFO_NOFORMAT("http_conn_send: NULL http_conn, exiting.");
		return;
	}

	g_free(http_conn->method);
	g_free(http_conn->url);
	g_free(http_conn->body);
	g_free(http_conn->content_type);
	http_conn->method = g_strdup(method);
	http_conn_parse_url(full_url, NULL, NULL, &http_conn->url);
	http_conn->body = g_strdup(body);
	http_conn->content_type = g_strdup(content_type);
	http_conn->callback = callback;
	http_conn->data = data;

	http_conn_send0(http_conn, NULL);
}

static void
http_conn_process_input_message(HttpConn *http_conn,
			        struct sipmsg *msg)
{
	/* Redirect */
	if ((msg->response == 300 ||
	     msg->response == 301 ||
	     msg->response == 302 ||
	     msg->response == 307) &&
	     http_conn->allow_redirect)
	{
		const char *location = sipmsg_find_header(msg, "Location");

		SIPE_DEBUG_INFO("http_conn_process_input_message: Redirect to: %s", location ? location : "");

		http_conn->do_close = http_conn_clone(http_conn);
		http_conn->sec_ctx = NULL;

		g_free(http_conn->host);
		g_free(http_conn->url);
		http_conn_parse_url(location, &http_conn->host, &http_conn->port, &http_conn->url);
		http_conn->conn = http_conn_setup(http_conn,
						  http_conn->sipe_public,
						  http_conn->conn_type,
						  http_conn->host,
						  http_conn->port);
	}
	/* Authentication required */
	else if (msg->response == 401) {
		char *ptmp;
#ifdef _WIN32
#ifdef HAVE_LIBKRB5
		char *tmp;
#endif
#endif
		guint auth_type;
		const char *auth_name;
		char *authorization;
		char *output_toked_base64;
		int use_sso = !http_conn->auth || (http_conn->auth && !http_conn->auth->user);
		long ret = -1;

		http_conn->retries++;
		if (http_conn->retries > 2) {
			if (http_conn->callback) {
				(*http_conn->callback)(HTTP_CONN_ERROR_FATAL, NULL, NULL, http_conn, http_conn->data);
			}
			SIPE_DEBUG_INFO_NOFORMAT("http_conn_process_input_message: Authentication failed");
			http_conn_set_close(http_conn);
			return;
		}

		ptmp = sipmsg_find_auth_header(msg, "NTLM");
		auth_type = AUTH_TYPE_NTLM;
		auth_name = "NTLM";
#ifdef _WIN32
#ifdef HAVE_LIBKRB5
		tmp = sipmsg_find_auth_header(msg, "Negotiate");
		if (tmp && http_conn->auth && http_conn->auth->use_negotiate) {
			ptmp = tmp;
			auth_type = AUTH_TYPE_NEGOTIATE;
			auth_name = "Negotiate";
		}
#endif
#endif
		if (!ptmp) {
			SIPE_DEBUG_INFO("http_conn_process_input_message: Only %s supported in the moment, exiting",
#ifdef _WIN32
#ifdef HAVE_LIBKRB5
				"NTLM and Negotiate authentications are"
#else /* !HAVE_LIBKRB5 */
				"NTLM authentication is"
#endif /* HAVE_LIBKRB5 */
#else /* !_WIN32 */
				"NTLM authentication is"
#endif /* _WIN32 */

			);
		}

		if (!http_conn->sec_ctx) {
			http_conn->sec_ctx =
				sip_sec_create_context(auth_type,
						       use_sso,
						       1,
						       http_conn->auth && http_conn->auth->domain ? http_conn->auth->domain : "",
						       http_conn->auth ? http_conn->auth->user : NULL,
						       http_conn->auth ? http_conn->auth->password : NULL);
		}

		if (http_conn->sec_ctx) {
			char **parts = g_strsplit(ptmp, " ", 0);
			char *spn = g_strdup_printf("HTTP/%s", http_conn->host);
			ret = sip_sec_init_context_step(http_conn->sec_ctx,
							spn,
							parts[1],
							&output_toked_base64,
							NULL);
			g_free(spn);
			g_strfreev(parts);
		}

		if (ret < 0) {
			if (http_conn->callback) {
				(*http_conn->callback)(HTTP_CONN_ERROR_FATAL, NULL, NULL, http_conn, http_conn->data);
			}
			SIPE_DEBUG_INFO_NOFORMAT("http_conn_process_input_message: Failed to initialize security context");
			http_conn_set_close(http_conn);
			return;
		}

		authorization = g_strdup_printf("%s %s", auth_name, output_toked_base64 ? output_toked_base64 : "");
		g_free(output_toked_base64);

		http_conn_send0(http_conn, authorization);
		g_free(authorization);
	}
	/* Other response */
	else {
		const char *set_cookie_hdr;
		const char *content_type = sipmsg_find_header(msg, "Content-Type");
		http_conn->retries = 0;

		/* Set cookies.
		 * Set-Cookie: RMID=732423sdfs73242; expires=Fri, 31-Dec-2010 23:59:59 GMT; path=/; domain=.example.net
		 */
		if (http_conn->http_session && (set_cookie_hdr = sipmsg_find_header(msg, "Set-Cookie"))) {
			char **parts;
			char *tmp;
			int i;

			g_free(http_conn->http_session->cookie);
			http_conn->http_session->cookie = NULL;

			parts = g_strsplit(set_cookie_hdr, ";", 0);
			for (i = 0; parts[i]; i++) {
				if (!strstr(parts[i], "path=") &&
				    !strstr(parts[i], "domain=") &&
				    !strstr(parts[i], "expires=") &&
				    !strstr(parts[i], "secure"))
				{
					tmp = http_conn->http_session->cookie;
					http_conn->http_session->cookie = !tmp ?
						g_strdup(parts[i]) :
						g_strconcat(http_conn->http_session->cookie, ";", parts[i], NULL);
					g_free(tmp);
				}
			}
			g_strfreev(parts);
			SIPE_DEBUG_INFO("http_conn_process_input_message: Set cookie: %s",
				http_conn->http_session->cookie ? http_conn->http_session->cookie : "");
		}

		if (http_conn->callback) {
			(*http_conn->callback)(msg->response, msg->body, content_type, http_conn, http_conn->data);
		}
	}
}

static void http_conn_input(struct sipe_transport_connection *conn)
{
	HttpConn *http_conn = HTTP_CONN;
	char *cur = conn->buffer;

	/* according to the RFC remove CRLF at the beginning */
	while (*cur == '\r' || *cur == '\n') {
		cur++;
	}
	if (cur != conn->buffer)
		sipe_utils_shrink_buffer(conn, cur);

	while ((cur = strstr(conn->buffer, "\r\n\r\n")) != NULL) {
		struct sipmsg *msg;
		char *tmp;
		guint remainder;
		time_t currtime = time(NULL);
		cur += 2;
		cur[0] = '\0';
		SIPE_DEBUG_INFO("received - %s******\n%s\n******", ctime(&currtime), tmp = fix_newlines(conn->buffer));
		g_free(tmp);

		msg = sipmsg_parse_header(conn->buffer);
		cur[0] = '\r';
		cur += 2;
		remainder = conn->buffer_used - (cur - conn->buffer);
		if (msg && remainder >= (guint) msg->bodylen) {
			char *dummy = g_malloc(msg->bodylen + 1);
			memcpy(dummy, cur, msg->bodylen);
			dummy[msg->bodylen] = '\0';
			msg->body = dummy;
			cur += msg->bodylen;
			sipe_utils_shrink_buffer(conn, cur);
		} else {
			if (msg){
				SIPE_DEBUG_INFO("process_input: body too short (%d < %d, strlen %d) - ignoring message", remainder, msg->bodylen, (int)strlen(conn->buffer));
				sipmsg_free(msg);
                        }
			return;
		}

		if (msg->body) {
			SIPE_DEBUG_INFO("body:\n%s", msg->body);
		}

		/* important to set before callback call */
		if (sipe_strcase_equal(sipmsg_find_header(msg, "Connection"), "close")) {
			http_conn->closed = TRUE;
		}

		http_conn_process_input_message(http_conn, msg);

		sipmsg_free(msg);
	}

	if (http_conn->closed) {
		http_conn_close(http_conn->do_close, "Server closed connection");
	} else if (http_conn->do_close) {
		http_conn_close(http_conn->do_close, "User initiated");
	}
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
