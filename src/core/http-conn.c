/**
 * @file http-conn.c
 *
 * pidgin-sipe
 *
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
 * Support Negotiate (Windows only) and NTLM authentications, redirect.
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <errno.h>
#include <time.h>

#include <glib.h>

#include "account.h"
#include "eventloop.h"
#include "network.h"
#include "sslconn.h"

#include "sipe-common.h"
#include "sipmsg.h"
#include "sip-sec.h"
#include "sipe-backend.h"
#include "sipe-utils.h"
#include "http-conn.h"
#include "sipe.h"

/**
 * HTTP POST headers
 * @param url (%s)		Ex.: /EWS/Exchange.asmx
 * @param host (%s)		Ex.: cosmo-ocs-r2.cosmo.local
 * @param content_length (%d)	length of body part
 * @param content_type (%s)	Ex.: text/xml; charset=UTF-8
 */
#define HTTP_CONN_POST_HEADER \
"POST %s HTTP/1.1\r\n"\
"Host: %s\r\n"\
"User-Agent: Sipe/" PACKAGE_VERSION "\r\n"\
"Content-Length: %d\r\n"\
"Content-Type: %s\r\n"


struct http_conn_struct {
	PurpleAccount *account;
	char *conn_type;
	char *host;
	int port;
	char *url;
	char *body;
	char *content_type;
	HttpConnAuth *auth;
	HttpConnCallback callback;
	void *data;

	/* SSL connection */
	PurpleSslConnection *gsc;
	int fd;
	int listenport;
	time_t last_keepalive;
	struct sip_connection *conn;
	SipSecContext sec_ctx;
	int retries;

	HttpConn* do_close;
};

static HttpConn*
http_conn_clone(HttpConn* http_conn)
{
	HttpConn *res = g_new0(HttpConn, 1);

	res->account = http_conn->account;
	res->conn_type = g_strdup(http_conn->conn_type);
	res->host = g_strdup(http_conn->host);
	res->port = http_conn->port;
	res->url = g_strdup(http_conn->url);
	res->body = g_strdup(http_conn->body);
	res->content_type = g_strdup(http_conn->content_type);
	res->auth = http_conn->auth;
	res->callback = http_conn->callback;
	res->data = http_conn->data;

	/* SSL connection */
	res->gsc = http_conn->gsc;
	res->fd = http_conn->fd;
	res->listenport = http_conn->listenport;
	res->last_keepalive = http_conn->last_keepalive;
	res->conn = http_conn->conn;
	res->sec_ctx = http_conn->sec_ctx;
	res->retries = http_conn->retries;

	res->do_close = NULL;

	return res;
}

static void
http_conn_free(HttpConn* http_conn)
{
	if (!http_conn) return;

	g_free(http_conn->conn_type);
	g_free(http_conn->host);
	g_free(http_conn->url);
	g_free(http_conn->body);
	g_free(http_conn->content_type);

	if (http_conn->sec_ctx) {
		sip_sec_destroy_context(http_conn->sec_ctx);
	}

	g_free(http_conn);
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
http_conn_invalidate_ssl_connection(HttpConn *http_conn);

static void
http_conn_close(HttpConn *http_conn, const char *message)
{
	SIPE_DEBUG_INFO("http_conn_close: closing http connection: %s", message ? message : "");

	http_conn_invalidate_ssl_connection(http_conn);
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
		    int *port,
		    char **rel_url)
{
        char **parts = g_strsplit(url, "://", 2);
        char *no_proto;
        int port_tmp;
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
			port_tmp = parts[1] ? atoi(parts[1]) : port_tmp;
                }
                if (port) *port = port_tmp;
                g_strfreev(parts);
        }

        g_free(host_port);
}

static void
http_conn_ssl_connect_failure(SIPE_UNUSED_PARAMETER PurpleSslConnection *gsc,
			     PurpleSslErrorType error,
                             gpointer data)
{
        HttpConn *http_conn = data;
	const char *message = NULL;

        http_conn->gsc = NULL;

        switch(error) {
		case PURPLE_SSL_CONNECT_FAILED:
			message = "Connection failed";
			break;
		case PURPLE_SSL_HANDSHAKE_FAILED:
			message = "SSL handshake failed";
			break;
		case PURPLE_SSL_CERTIFICATE_INVALID:
			message = "SSL certificate invalid";
			break;
        }

	if (http_conn->callback) {
		(*http_conn->callback)(HTTP_CONN_ERROR, NULL, http_conn, http_conn->data);
	}
	http_conn_close(http_conn, message);
}

static void
http_conn_connection_remove(struct sip_connection *conn)
{
	if (conn) {
		if (conn->inputhandler) purple_input_remove(conn->inputhandler);
		g_free(conn->inbuf);
		g_free(conn);
	}
}

static void
http_conn_invalidate_ssl_connection(HttpConn *http_conn)
{
	if (http_conn) {
		PurpleSslConnection *gsc = http_conn->gsc;

		/* Invalidate this connection. Next send will open a new one */
		if (gsc) {
			struct sip_connection *conn = http_conn->conn;

			http_conn_connection_remove(conn);
			http_conn->conn = NULL;
			purple_ssl_close(gsc);
		}
		http_conn->gsc = NULL;
		http_conn->fd = -1;
	}
}

static void
http_conn_process_input(HttpConn *http_conn);

static void
http_conn_input_cb_ssl(gpointer data,
		       PurpleSslConnection *gsc,
		       SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	HttpConn *http_conn = data;
	struct sip_connection *conn = http_conn ? http_conn->conn : NULL;
	int readlen, len;
	gboolean firstread = TRUE;

	if (conn == NULL) {
		SIPE_DEBUG_ERROR_NOFORMAT("Connection not found; Please try to connect again.");
		return;
	}

	/* Read all available data from the SSL connection */
	do {
		/* Increase input buffer size as needed */
		if (conn->inbuflen < conn->inbufused + SIMPLE_BUF_INC) {
			conn->inbuflen += SIMPLE_BUF_INC;
			conn->inbuf = g_realloc(conn->inbuf, conn->inbuflen);
			SIPE_DEBUG_INFO("http_conn_input_cb_ssl: new input buffer length %d", conn->inbuflen);
		}

		/* Try to read as much as there is space left in the buffer */
		readlen = conn->inbuflen - conn->inbufused - 1;
		len = purple_ssl_read(gsc, conn->inbuf + conn->inbufused, readlen);

		if (len < 0 && errno == EAGAIN) {
			/* Try again later */
			return;
		} else if (len < 0) {
			if (http_conn->callback) {
				(*http_conn->callback)(HTTP_CONN_ERROR, NULL, http_conn, http_conn->data);
			}
			http_conn_close(http_conn, "SSL read error");
			return;
		} else if (firstread && (len == 0)) {
			if (http_conn->callback) {
				(*http_conn->callback)(HTTP_CONN_ERROR, NULL, http_conn, http_conn->data);
			}
			http_conn_close(http_conn, "Server has disconnected");
			return;
		}

		conn->inbufused += len;
		firstread = FALSE;

	/* Equivalence indicates that there is possibly more data to read */
	} while (len == readlen);

	conn->inbuf[conn->inbufused] = '\0';
        http_conn_process_input(http_conn);
}
static void
http_conn_post0(HttpConn *http_conn,
	       const char *authorization);

static void
http_conn_input0_cb_ssl(gpointer data,
			PurpleSslConnection *gsc,
			SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	HttpConn *http_conn = data;

	http_conn->fd = gsc->fd;
	http_conn->gsc = gsc;
	http_conn->listenport = purple_network_get_port_from_fd(gsc->fd);
	//http_conn->connecting = FALSE;
	http_conn->last_keepalive = time(NULL);

	http_conn->conn = g_new0(struct sip_connection, 1);

	purple_ssl_input_add(gsc, http_conn_input_cb_ssl, http_conn);

	http_conn_post0(http_conn, NULL);
}

HttpConn *
http_conn_create(PurpleAccount *account,
		 const char *conn_type,
		 const char *full_url,
		 const char *body,
		 const char *content_type,
		 HttpConnAuth *auth,
		 HttpConnCallback callback,
		 void *data)
{
	HttpConn *http_conn;

	if (!full_url || (strlen(full_url) == 0)) {
		SIPE_DEBUG_INFO_NOFORMAT("no URL supplied!");
		return NULL;
	}
	if (sipe_strequal(conn_type, HTTP_CONN_SSL) &&
	    !purple_ssl_is_supported())
	{
		SIPE_DEBUG_INFO_NOFORMAT("SSL support is not installed. Either install SSL support or configure a different connection type in the account editor.");
		return NULL;
	}

	http_conn = g_new0(HttpConn, 1);
	http_conn_parse_url(full_url, &http_conn->host, &http_conn->port, &http_conn->url);

	http_conn->account = account;
	http_conn->conn_type = g_strdup(conn_type);
	http_conn->body = g_strdup(body);
	http_conn->content_type = g_strdup(content_type);
	http_conn->auth = auth;
	http_conn->callback = callback;
	http_conn->data = data;

	http_conn->gsc = purple_ssl_connect(http_conn->account, /* can we pass just NULL ? */
					    http_conn->host,
					    http_conn->port,
					    http_conn_input0_cb_ssl,
					    http_conn_ssl_connect_failure,
					    http_conn);

	return http_conn;
}

/* Data part */
static void
http_conn_process_input_message(HttpConn *http_conn,
			        struct sipmsg *msg);

static void
http_conn_process_input(HttpConn *http_conn)
{
	char *cur;
	char *dummy;
	char *tmp;
	struct sipmsg *msg;
	int restlen;
	struct sip_connection *conn = http_conn->conn;

	cur = conn->inbuf;

	/* according to the RFC remove CRLF at the beginning */
	while (*cur == '\r' || *cur == '\n') {
		cur++;
	}
	if (cur != conn->inbuf) {
		memmove(conn->inbuf, cur, conn->inbufused - (cur - conn->inbuf));
		conn->inbufused = strlen(conn->inbuf);
	}

	while ((cur = strstr(conn->inbuf, "\r\n\r\n")) != NULL) {
		time_t currtime = time(NULL);
		cur += 2;
		cur[0] = '\0';
		SIPE_DEBUG_INFO("received - %s******\n%s\n******", ctime(&currtime), tmp = fix_newlines(conn->inbuf));
		g_free(tmp);

		msg = sipmsg_parse_header(conn->inbuf);
		cur[0] = '\r';
		cur += 2;
		restlen = conn->inbufused - (cur - conn->inbuf);
		if (msg && restlen >= msg->bodylen) {
			dummy = g_malloc(msg->bodylen + 1);
			memcpy(dummy, cur, msg->bodylen);
			dummy[msg->bodylen] = '\0';
			msg->body = dummy;
			cur += msg->bodylen;
			memmove(conn->inbuf, cur, conn->inbuflen - (cur - conn->inbuf));
			conn->inbufused = strlen(conn->inbuf);
		} else {
			if (msg){
                           SIPE_DEBUG_INFO("process_input: body too short (%d < %d, strlen %d) - ignoring message", restlen, msg->bodylen, (int)strlen(conn->inbuf));
			sipmsg_free(msg);
                        }
			return;
		}

		if (msg->body) {
			SIPE_DEBUG_INFO("body:\n%s", msg->body);
		}

		http_conn_process_input_message(http_conn, msg);

		sipmsg_free(msg);
	}

	if (http_conn->do_close) {
		http_conn_close(http_conn->do_close, "User initiated");
	}
}

static void
http_conn_sendout_pkt(HttpConn *http_conn,
		      const char *buf)
{
	time_t currtime = time(NULL);
	int writelen = strlen(buf);
	char *tmp;
	int ret = 0;

	SIPE_DEBUG_INFO("sending - %s******\n%s\n******", ctime(&currtime), tmp = fix_newlines(buf));
	g_free(tmp);

	if (http_conn->fd < 0) {
		SIPE_DEBUG_INFO_NOFORMAT("http_conn_sendout_pkt: http_conn->fd < 0, exiting");
		return;
	}

	if (http_conn->gsc) {
		ret = purple_ssl_write(http_conn->gsc, buf, writelen);
	}

	if (ret < 0 && errno == EAGAIN)
		ret = 0;
	else if (ret <= 0) { /* XXX: When does this happen legitimately? */
		SIPE_DEBUG_INFO_NOFORMAT("http_conn_sendout_pkt: ret <= 0, exiting");
		return;
	}

	if (ret < writelen) {
		SIPE_DEBUG_INFO_NOFORMAT("http_conn_sendout_pkt: ret < writelen, exiting");
	}
}

static void
http_conn_post0(HttpConn *http_conn,
		const char *authorization)
{
	GString *outstr = g_string_new("");

	g_string_append_printf(outstr, HTTP_CONN_POST_HEADER,
				http_conn->url,
				http_conn->host,
				http_conn->body ? (int)strlen(http_conn->body) : 0,
				http_conn->content_type ? http_conn->content_type : "text/plain");
	if (authorization) {
		g_string_append_printf(outstr, "Authorization: %s\r\n", authorization);
	}
	g_string_append_printf(outstr, "\r\n%s", http_conn->body ? http_conn->body : "");

	http_conn_sendout_pkt(http_conn, outstr->str);
	g_string_free(outstr, TRUE);
}

void
http_conn_post(	HttpConn *http_conn,
		const char *full_url,
		const char *body,
		const char *content_type,
		HttpConnCallback callback,
		void *data)
{
	if (!http_conn) {
		SIPE_DEBUG_INFO_NOFORMAT("http_conn_post: NULL http_conn, exiting.");
		return;
	}

	g_free(http_conn->url);
	g_free(http_conn->body);
	g_free(http_conn->content_type);
	http_conn_parse_url(full_url, NULL, NULL, &http_conn->url);
	http_conn->body = g_strdup(body);
	http_conn->content_type = g_strdup(content_type);
	http_conn->callback = callback;
	http_conn->data = data;

	http_conn_post0(http_conn, NULL);
}

static void
http_conn_process_input_message(HttpConn *http_conn,
			        struct sipmsg *msg)
{
	/* Redirect */
	if (msg->response == 300 ||
	    msg->response == 301 ||
	    msg->response == 302 ||
	    msg->response == 307)
	{
		const char *location = sipmsg_find_header(msg, "Location");

		SIPE_DEBUG_INFO("http_conn_process_input_message: Redirect to: %s", location ? location : "");

		http_conn->do_close = http_conn_clone(http_conn);
		http_conn->sec_ctx = NULL;

		g_free(http_conn->host);
		g_free(http_conn->url);
		http_conn_parse_url(location, &http_conn->host, &http_conn->port, &http_conn->url);

		http_conn->gsc = purple_ssl_connect(http_conn->account,
						    http_conn->host,
						    http_conn->port,
						    http_conn_input0_cb_ssl,
						    http_conn_ssl_connect_failure,
						    http_conn);

	}
	/* Authentication required */
	else if (msg->response == 401) {
		char *ptmp;
#ifdef _WIN32
#ifdef HAVE_LIBKRB5
		char *tmp;
#endif
#endif
		SipSecAuthType auth_type;
		const char *auth_name;
		char *authorization;
		char *output_toked_base64;
		int use_sso = !http_conn->auth || (http_conn->auth && !http_conn->auth->user);
		long ret = -1;

		http_conn->retries++;
		if (http_conn->retries > 2) {
			if (http_conn->callback) {
				(*http_conn->callback)(HTTP_CONN_ERROR_FATAL, NULL, http_conn, http_conn->data);
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
				(*http_conn->callback)(HTTP_CONN_ERROR_FATAL, NULL, http_conn, http_conn->data);
			}
			SIPE_DEBUG_INFO_NOFORMAT("http_conn_process_input_message: Failed to initialize security context");
			http_conn_set_close(http_conn);
			return;
		}

		authorization = g_strdup_printf("%s %s", auth_name, output_toked_base64 ? output_toked_base64 : "");
		g_free(output_toked_base64);

		http_conn_post0(http_conn, authorization);
		g_free(authorization);
	}
	/* Other response */
	else {
		http_conn->retries = 0;

		if (http_conn->callback) {
			(*http_conn->callback)(msg->response, msg->body, http_conn, http_conn->data);
		}
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
