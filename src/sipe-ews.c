/**
 * @file sipe-ews.c
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
For communication with Exchange 2007/2010 Web Server/Web Services:

1) Autodiscover (HTTPS POST request). With redirect support. XML content.
1.1) DNS SRV record _autodiscover._tcp.<domain> may also be resolved.
2) Availability Web service (SOAP = HTTPS POST + XML) call.
3) Out of Office (OOF) Web Service (SOAP = HTTPS POST + XML) call.
4) Web server authentication required - NTLM and/or Negotiate (Kerberos).

Note: ews - EWS stands for Exchange Web Services.

It will be able to retrieve our Calendar information (FreeBusy, WorkingHours,
Meetings Subject and Location, Is_Meeting) as well as our Out of Office (OOF) note
from Exchange Web Services for subsequent publishing.

Ref. for more implementation details:
http://sourceforge.net/projects/sipe/forums/forum/688535/topic/3403462

Similar functionality for Lotus Notes/Domino, iCalendar/CalDAV/Google would
be great to implement too.
*/

#include "debug.h"

#include "sipe.h"
#include "sipe-ews.h"
#include "sipe-utils.h"

/**
 * HTTP POST headers
 * @param content_length (%d) length of body part
 */
#define SIP_EWS_HTTP_POST_HEADER \
"POST https://cosmo-ocs-r2.cosmo.local/EWS/Exchange.asmx HTTP/1.1\r\n"\
"Host: cosmo-ocs-r2.cosmo.local\r\n"\
"User-Agent: Sipe/1.7.1\r\n"\
"Content-Length: %d\r\n"\
"Content-Type: text/xml; charset=UTF-8\r\n"

/**
 * GetUserOofSettingsRequest request to Exchange Web Services
 * to obtain our Out-of-office (OOF) information.
 * @param email (%s) Ex.: Alice@cosmo.local
 */
#define SIPE_EWS_USER_OOF_SETTINGS_REQUEST \
"<?xml version=\"1.0\" encoding=\"utf-8\"?>"\
"<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">"\
  "<soap:Body>"\
    "<GetUserOofSettingsRequest xmlns=\"http://schemas.microsoft.com/exchange/services/2006/messages\">"\
      "<Mailbox xmlns=\"http://schemas.microsoft.com/exchange/services/2006/types\">"\
        "<Address>%s</Address>"\
      "</Mailbox>"\
    "</GetUserOofSettingsRequest>"\
  "</soap:Body>"\
"</soap:Envelope>"


struct sipe_ews {
	/* SSL connection */
	PurpleSslConnection *gsc;
	int fd;
	int listenport;
	time_t last_keepalive;
	struct sip_connection *conn;
	SipSecContext sec_ctx;
	char *body;
	int retries;
};


static void
sipe_ews_ssl_connect_failure(SIPE_UNUSED_PARAMETER PurpleSslConnection *gsc,
			     PurpleSslErrorType error,
                             gpointer data)
{
        struct sipe_account_data *sip = data;

        sip->ews->conn = NULL;

        switch(error) {
		case PURPLE_SSL_CONNECT_FAILED:
			purple_debug_info("sipe", _("Connection failed\n"));
			break;
		case PURPLE_SSL_HANDSHAKE_FAILED:
			purple_debug_info("sipe", _("SSL handshake failed\n"));
			break;
		case PURPLE_SSL_CERTIFICATE_INVALID:
			purple_debug_info("sipe", _("SSL certificate invalid\n"));
			break;
        }
}

static void
sipe_ews_connection_remove(struct sip_connection *conn)
{
	if (conn) {
		if (conn->inputhandler) purple_input_remove(conn->inputhandler);
		g_free(conn->inbuf);
		g_free(conn);
	}
}

static void
sipe_ews_invalidate_ssl_connection(struct sipe_account_data *sip,
				   const char *msg)
{
	PurpleSslConnection *gsc = sip && sip->ews ? sip->ews->gsc : NULL;

	purple_debug_error("sipe", "%s\n", msg);

	/* Invalidate this connection. Next send will open a new one */
	if (gsc) {
		struct sip_connection *conn = sip && sip->ews ? sip->ews->conn : NULL;

		sipe_ews_connection_remove(conn);
		if (sip && sip->ews) {
			sip->ews->conn = NULL;
		}
		purple_ssl_close(gsc);
	}
	sip->ews->gsc = NULL;
	sip->ews->fd = -1;
}

static void
sip_ews_process_input(struct sipe_account_data *sip,
		      struct sip_connection *conn);

static void
sipe_ews_input_cb_ssl(gpointer data,
		  PurpleSslConnection *gsc,
		  SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	struct sipe_account_data *sip = data;
	struct sip_connection *conn = sip && sip->ews ? sip->ews->conn : NULL;
	int readlen, len;
	gboolean firstread = TRUE;

	if (conn == NULL) {
		purple_debug_error("sipe", "Connection not found; Please try to connect again.\n");
	}

	/* Read all available data from the SSL connection */
	do {
		/* Increase input buffer size as needed */
		if (conn->inbuflen < conn->inbufused + SIMPLE_BUF_INC) {
			conn->inbuflen += SIMPLE_BUF_INC;
			conn->inbuf = g_realloc(conn->inbuf, conn->inbuflen);
			purple_debug_info("sipe", "sipe_ews_input_cb_ssl: new input buffer length %d\n", conn->inbuflen);
		}

		/* Try to read as much as there is space left in the buffer */
		readlen = conn->inbuflen - conn->inbufused - 1;
		len = purple_ssl_read(gsc, conn->inbuf + conn->inbufused, readlen);

		if (len < 0 && errno == EAGAIN) {
			/* Try again later */
			return;
		} else if (len < 0) {
			sipe_ews_invalidate_ssl_connection(sip, _("SSL read error"));
			return;
		} else if (firstread && (len == 0)) {
			sipe_ews_invalidate_ssl_connection(sip, _("Server has disconnected"));
			return;
		}

		conn->inbufused += len;
		firstread = FALSE;

	/* Equivalence indicates that there is possibly more data to read */
	} while (len == readlen);

	conn->inbuf[conn->inbufused] = '\0';
        sip_ews_process_input(sip, conn);
}

static void
sipe_ews_send_oof_request(struct sipe_account_data *sip);

static void
sipe_ews_input0_cb_ssl(gpointer data,
		      PurpleSslConnection *gsc,
		      SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{	
	struct sipe_account_data *sip = data;
	
	sip->ews->fd = gsc->fd;
	sip->ews->gsc = gsc;
	sip->ews->listenport = purple_network_get_port_from_fd(gsc->fd);
	//sip->ews->connecting = FALSE;
	sip->ews->last_keepalive = time(NULL);
	
	sip->ews->conn = g_new0(struct sip_connection, 1);

	purple_ssl_input_add(gsc, sipe_ews_input_cb_ssl, sip);

	sipe_ews_send_oof_request(sip);
}

void
sipe_ews_initialize(struct sipe_account_data *sip)
{
	if (!sip->ews) {
		sip->ews = g_new0(struct sipe_ews, 1);
		// can populate host/port too here from acc config
	}
	
	// going to create SSL connection
	if (!purple_ssl_is_supported()) {
		purple_debug_info("sipe", _("SSL support is not installed. Either install SSL support or configure a different connection type in the account editor\n"));
		return;
	}
	
	sip->ews->gsc = purple_ssl_connect(sip->account,
					   "cosmo-ocs-r2.cosmo.local",
					   443,
					   sipe_ews_input0_cb_ssl,
					   sipe_ews_ssl_connect_failure,
					   sip);
}


/* Data part */
static void
sip_ews_process_input_message(struct sipe_account_data *sip,
			      struct sipmsg *msg);

static void
sip_ews_process_input(struct sipe_account_data *sip,
		      struct sip_connection *conn)
{
	char *cur;
	char *dummy;
	char *tmp;
	struct sipmsg *msg;
	int restlen;
	cur = conn->inbuf;

	/* according to the RFC remove CRLF at the beginning */
	while (*cur == '\r' || *cur == '\n') {
		cur++;
	}
	if (cur != conn->inbuf) {
		memmove(conn->inbuf, cur, conn->inbufused - (cur - conn->inbuf));
		conn->inbufused = strlen(conn->inbuf);
	}

	/* Received a full Header? */
	sip->processing_input = TRUE;
	while (sip->processing_input &&
	       ((cur = strstr(conn->inbuf, "\r\n\r\n")) != NULL)) {
		time_t currtime = time(NULL);
		cur += 2;
		cur[0] = '\0';
		purple_debug_info("sipe", "received - %s******\n%s\n******\n", ctime(&currtime), tmp = fix_newlines(conn->inbuf));
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
                           purple_debug_info("sipe", "process_input: body too short (%d < %d, strlen %d) - ignoring message\n", restlen, msg->bodylen, (int)strlen(conn->inbuf));
			sipmsg_free(msg);
                        }
			return;
		}

		if (msg->body) {
			purple_debug_info("sipe", "body:\n%s", msg->body);
		}

		sip_ews_process_input_message(sip, msg);

		sipmsg_free(msg);
	}
}

static void
sipe_ews_sendout_pkt(struct sipe_account_data *sip,
		     const char *buf)
{
	time_t currtime = time(NULL);
	int writelen = strlen(buf);
	char *tmp;
	int ret;

	purple_debug(PURPLE_DEBUG_MISC, "sipe", "sending - %s******\n%s******\n", ctime(&currtime), tmp = fix_newlines(buf));
	g_free(tmp);

	if (sip->ews && sip->ews->fd < 0) {
		purple_debug_info("sipe", "sipe_ews_sendout_pkt: sip->ews->fd < 0, exiting\n");
		return;
	}

	if (sip->ews && sip->ews->gsc) {
		ret = purple_ssl_write(sip->ews->gsc, buf, writelen);
	}

	if (ret < 0 && errno == EAGAIN)
		ret = 0;
	else if (ret <= 0) { /* XXX: When does this happen legitimately? */
		purple_debug_info("sipe", "sipe_ews_sendout_pkt: ret <= 0, exiting\n");
		return;
	}

	if (ret < writelen) {
		purple_debug_info("sipe", "sipe_ews_sendout_pkt: ret < writelen, exiting\n");
	}
}

static void 
sip_ews_http_post(struct sipe_account_data *sip,
		  const char *body,
		  const char *authorization)
{
	GString *outstr = g_string_new("");
	
	g_string_append_printf(outstr, SIP_EWS_HTTP_POST_HEADER, body ? strlen(body) : 0);
	if (authorization) {
		g_string_append_printf(outstr, "Authorization: %s\r\n", authorization);
	}
	g_string_append_printf(outstr, "\r\n%s", body ? body : "");
	
	sipe_ews_sendout_pkt(sip, outstr->str);
	g_string_free(outstr, TRUE);
}

static void
sip_ews_process_input_message(struct sipe_account_data *sip,
			      struct sipmsg *msg)
{
	if (msg->response == 401) {
		char *ptmp;
		char **parts;
		char *authorization;
		char *output_toked_base64;
		
		if (sip->ews->retries > 2) return;
		
		sip->ews->retries++;
		ptmp = sipmsg_find_auth_header(msg, "NTLM");
		if (!ptmp) {
			purple_debug_info("sipe", "sip_ews_process_input_message: Only NTLM authentication is supported in the moment, exiting\n");
		}
		
		if (!sip->ews->sec_ctx) {
			sip_sec_create_context(&sip->ews->sec_ctx,
					       AUTH_TYPE_NTLM,
					       purple_account_get_bool(sip->account, "sso", TRUE),
					       1,
					       sip->authdomain ? sip->authdomain : "",
					       sip->authuser,
					       sip->password);
		}

		parts = g_strsplit(ptmp, " ", 0);
		sip_sec_init_context_step(sip->ews->sec_ctx,
					  "HOST/cosmo-ocs-r2.cosmo.local",
					  parts[1],
					  &output_toked_base64,
					  NULL);
		g_strfreev(parts);

		authorization = g_strdup_printf("NTLM %s", output_toked_base64);
		g_free(output_toked_base64);
		
		sip_ews_http_post(sip, sip->ews->body, authorization);
		g_free(authorization);
	} else {
		sip->ews->retries = 0;
		g_free(sip->ews->body);
		
		//process response
	}
}

/* Business Logic part */
static void
sipe_ews_send_oof_request(struct sipe_account_data *sip)
{
	g_free(sip->ews->body);
	sip->ews->body = g_strdup_printf(SIPE_EWS_USER_OOF_SETTINGS_REQUEST, "alice@cosmo.local");

	sip_ews_http_post(sip, sip->ews->body, NULL);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
