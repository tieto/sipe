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
 * Support NTLM authentication, redirect.
*/

#include "debug.h"
#include "sipe.h"
#include "sipe-utils.h"

#include "http-conn.h"

/**
 * HTTP POST headers
 * @param url (%s)		Ex.: https://cosmo-ocs-r2.cosmo.local/EWS/Exchange.asmx
 * @param host (%s)		Ex.: cosmo-ocs-r2.cosmo.local
 * @param content_length (%d)	length of body part
 * @param content_type (%s)	Ex.: text/xml; charset=UTF-8
 */
#define HTTP_CONN_POST_HEADER \
"POST %s HTTP/1.1\r\n"\
"Host: %s\r\n"\
"User-Agent: Sipe/" SIPE_VERSION "\r\n"\
"Content-Length: %d\r\n"\
"Content-Type: %s\r\n"


struct http_conn_struct {
	char *conn_type;
	char *host;
	int port;
	char *url;
	char *body;
	char *content_type;
	HttpConnAuth *auth;
	HttpConnCallback callback;
		 
	/* SSL connection */
	PurpleSslConnection *gsc;
	int fd;
	int listenport;
	time_t last_keepalive;
	struct sip_connection *conn;
	SipSecContext sec_ctx;
	int retries;
};

void
http_conn_auth_free(struct http_conn_auth* auth)
{
	g_free(auth->domain);
	g_free(auth->user);
	g_free(auth->password);
	g_free(auth);
}

//@TODO: destroy http_conn

static void
http_conn_ssl_connect_failure(SIPE_UNUSED_PARAMETER PurpleSslConnection *gsc,
			     PurpleSslErrorType error,
                             gpointer data)
{
        HttpConn *http_conn = data;

        http_conn->gsc = NULL;

        switch(error) {
		case PURPLE_SSL_CONNECT_FAILED:
			purple_debug_info("sipe-http", _("Connection failed\n"));
			break;
		case PURPLE_SSL_HANDSHAKE_FAILED:
			purple_debug_info("sipe-http", _("SSL handshake failed\n"));
			break;
		case PURPLE_SSL_CERTIFICATE_INVALID:
			purple_debug_info("sipe-http", _("SSL certificate invalid\n"));
			break;
        }
	
	//@TODO call callback with error code
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
http_conn_invalidate_ssl_connection(HttpConn *http_conn,
				    const char *msg)
{
	PurpleSslConnection *gsc = http_conn ? http_conn->gsc : NULL;

	purple_debug_error("sipe-http", "%s\n", msg);

	/* Invalidate this connection. Next send will open a new one */
	if (gsc) {
		struct sip_connection *conn = http_conn ? http_conn->conn : NULL;

		http_conn_connection_remove(conn);
		if (http_conn) {
			http_conn->conn = NULL;
		}
		purple_ssl_close(gsc);
	}
	http_conn->gsc = NULL;
	http_conn->fd = -1;
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
		purple_debug_error("sipe-http", "Connection not found; Please try to connect again.\n");
	}

	/* Read all available data from the SSL connection */
	do {
		/* Increase input buffer size as needed */
		if (conn->inbuflen < conn->inbufused + SIMPLE_BUF_INC) {
			conn->inbuflen += SIMPLE_BUF_INC;
			conn->inbuf = g_realloc(conn->inbuf, conn->inbuflen);
			purple_debug_info("sipe-http", "http_conn_input_cb_ssl: new input buffer length %d\n", conn->inbuflen);
		}

		/* Try to read as much as there is space left in the buffer */
		readlen = conn->inbuflen - conn->inbufused - 1;
		len = purple_ssl_read(gsc, conn->inbuf + conn->inbufused, readlen);

		if (len < 0 && errno == EAGAIN) {
			/* Try again later */
			return;
		} else if (len < 0) {
			http_conn_invalidate_ssl_connection(http_conn, _("SSL read error"));
			return;
		} else if (firstread && (len == 0)) {
			http_conn_invalidate_ssl_connection(http_conn, _("Server has disconnected"));
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
http_conn_post(HttpConn *http_conn,
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

	http_conn_post(http_conn, NULL);
}

HttpConn *
http_conn_create(PurpleAccount *account,
		 const char *conn_type,
		 const char *host,
		 int port,
		 const char *url,
		 const char *body,
		 const char *content_type,
		 HttpConnAuth *auth,
		 HttpConnCallback callback)
{

	HttpConn *http_conn = g_new0(HttpConn, 1);

	if (!strcmp(conn_type, HTTP_CONN_SSL) && 
	    !purple_ssl_is_supported())
	{
		purple_debug_info("sipe-http", _("SSL support is not installed. Either install SSL support or configure a different connection type in the account editor\n"));
		return NULL;
	}

	http_conn->conn_type = g_strdup(conn_type);
	http_conn->host = g_strdup(host);
	http_conn->port = port;
	http_conn->url = g_strdup(url);
	http_conn->body = g_strdup(body);
	http_conn->content_type = g_strdup(content_type);
	http_conn->auth = auth;
	http_conn->callback = callback;

	http_conn->gsc = purple_ssl_connect(account, /* can we pass just NULL ? */
					    host,
					    port,
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
		purple_debug_info("sipe-http", "received - %s******\n%s\n******\n", ctime(&currtime), tmp = fix_newlines(conn->inbuf));
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
                           purple_debug_info("sipe-http", "process_input: body too short (%d < %d, strlen %d) - ignoring message\n", restlen, msg->bodylen, (int)strlen(conn->inbuf));
			sipmsg_free(msg);
                        }
			return;
		}

		if (msg->body) {
			purple_debug_info("sipe-http", "body:\n%s", msg->body);
		}

		http_conn_process_input_message(http_conn, msg);

		sipmsg_free(msg);
	}
}

static void
http_conn_sendout_pkt(HttpConn *http_conn,
		      const char *buf)
{
	time_t currtime = time(NULL);
	int writelen = strlen(buf);
	char *tmp;
	int ret;

	purple_debug(PURPLE_DEBUG_MISC, "sipe-http", "sending - %s******\n%s******\n", ctime(&currtime), tmp = fix_newlines(buf));
	g_free(tmp);

	if (http_conn->fd < 0) {
		purple_debug_info("sipe-http", "http_conn_sendout_pkt: http_conn->fd < 0, exiting\n");
		return;
	}

	if (http_conn->gsc) {
		ret = purple_ssl_write(http_conn->gsc, buf, writelen);
	}

	if (ret < 0 && errno == EAGAIN)
		ret = 0;
	else if (ret <= 0) { /* XXX: When does this happen legitimately? */
		purple_debug_info("sipe-http", "http_conn_sendout_pkt: ret <= 0, exiting\n");
		return;
	}

	if (ret < writelen) {
		purple_debug_info("sipe-http", "http_conn_sendout_pkt: ret < writelen, exiting\n");
	}
	
	//TODO: call callback with error
}

static void 
http_conn_post(HttpConn *http_conn,
	       const char *authorization)
{
	GString *outstr = g_string_new("");
 
	g_string_append_printf(outstr, HTTP_CONN_POST_HEADER,
				http_conn->url,
				http_conn->host,
				http_conn->body ? strlen(http_conn->body) : 0,
				http_conn->content_type ? http_conn->content_type : "text/plain");
	if (authorization) {
		g_string_append_printf(outstr, "Authorization: %s\r\n", authorization);
	}
	g_string_append_printf(outstr, "\r\n%s", http_conn->body ? http_conn->body : "");

	http_conn_sendout_pkt(http_conn, outstr->str);
	g_string_free(outstr, TRUE);
}

static void
http_conn_process_input_message(HttpConn *http_conn,
			        struct sipmsg *msg)
{
	if (msg->response == 401) {
		char *ptmp;
		char **parts;
		char *authorization;
		char *output_toked_base64;
		char *spn = g_strdup_printf("HTTP/%s", http_conn->host);
		int use_sso = !http_conn->auth || (http_conn->auth && !http_conn->auth->user);
		
		if (http_conn->retries > 2) return;
		
		http_conn->retries++;
		ptmp = sipmsg_find_auth_header(msg, "NTLM");
		if (!ptmp) {
			purple_debug_info("sipe-http", "http_conn_process_input_message: Only NTLM authentication is supported in the moment, exiting\n");
		}
		
		if (!http_conn->sec_ctx) {
			sip_sec_create_context(&http_conn->sec_ctx,
					       AUTH_TYPE_NTLM,
					       use_sso,
					       1,
					       http_conn->auth && http_conn->auth->domain ? http_conn->auth->domain : "",
					       http_conn->auth ? http_conn->auth->user : NULL,
					       http_conn->auth ? http_conn->auth->password : NULL);
		}

		parts = g_strsplit(ptmp, " ", 0);
		sip_sec_init_context_step(http_conn->sec_ctx,
					  spn,
					  parts[1],
					  &output_toked_base64,
					  NULL);
		g_free(spn);
		g_strfreev(parts);

		authorization = g_strdup_printf("NTLM %s", output_toked_base64);
		g_free(output_toked_base64);
		
		http_conn_post(http_conn, authorization);
		g_free(authorization);
	} else {
		http_conn->retries = 0;
		g_free(http_conn->body);
		g_free(http_conn->content_type);
		
		if (http_conn->callback) {
			(*http_conn->callback)(msg->response, msg->body);
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
