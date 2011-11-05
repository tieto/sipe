/**
 * @file sipe-svc.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011 SIPE Project <http://sipe.sourceforge.net/>
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
 *
 *
 * Specification references:
 *
 *   - [MS-SIPAE]:    http://msdn.microsoft.com/en-us/library/cc431510.aspx
 *   - [MS-OCAUTHWS]: http://msdn.microsoft.com/en-us/library/ff595592.aspx
 *   - MS Tech-Ed Europe 2010 "UNC310: Microsoft Lync 2010 Technology Explained"
 *     http://ecn.channel9.msdn.com/o9/te/Europe/2010/pptx/unc310.pptx
 */

#include <string.h>

#include <glib.h>

#include "sipe-common.h"
#include "http-conn.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-svc.h"
#include "sipe-xml.h"

/* forward declaration */
struct svc_request;
typedef void (svc_callback)(struct svc_request *data,
			    sipe_xml *xml);

struct svc_request {
	struct sipe_core_private *sipe_private;
	svc_callback *internal_cb;
	sipe_svc_callback *cb;
	gpointer *cb_data;
	HttpConn *conn;
	gchar *uri;
};

struct sipe_svc {
	GSList *pending_requests;
};

static void sipe_svc_request_free(struct svc_request *data)
{
	if (data->conn)
		http_conn_free(data->conn);
	if (data->cb)
		/* Callback: aborted */
		(*data->cb)(data->sipe_private, NULL, NULL, data->cb_data);
	g_free(data->uri);
	g_free(data);
}

void sipe_svc_free(struct sipe_core_private *sipe_private)
{
	struct sipe_svc *svc = sipe_private->svc;
	if (!svc)
		return;

	if (svc->pending_requests) {
		GSList *entry = svc->pending_requests;
		while (entry) {
			sipe_svc_request_free(entry->data);
			entry = entry->next;
		}
		g_slist_free(svc->pending_requests);
	}

	g_free(svc);
	sipe_private->svc = NULL;
}

static void sipe_svc_init(struct sipe_core_private *sipe_private)
{
	if (sipe_private->svc)
		return;

	sipe_private->svc = g_new0(struct sipe_svc, 1);
}

static void sipe_svc_https_response(int return_code,
				    const gchar *body,
				    SIPE_UNUSED_PARAMETER const gchar *content_type,
				    HttpConn *conn,
				    void *callback_data)
{
	struct svc_request *data = callback_data;
	struct sipe_svc *svc = data->sipe_private->svc;

	SIPE_DEBUG_INFO("sipe_svc_https_response: code %d", return_code);
	http_conn_set_close(conn);
	data->conn = NULL;

	if ((return_code == 200) && body) {
		sipe_xml *xml = sipe_xml_parse(body, strlen(body));
		/* Internal callback: success */
		(*data->internal_cb)(data, xml);
		sipe_xml_free(xml);
	} else {
		/* Internal callback: failed */
		(*data->internal_cb)(data, NULL);
	}

	/* Internal callback has already called this */
	data->cb = NULL;

	svc->pending_requests = g_slist_remove(svc->pending_requests,
					       data);
	sipe_svc_request_free(data);
}

static gboolean sipe_svc_https_request(struct sipe_core_private *sipe_private,
				       const gchar *method,
				       const gchar *uri,
				       const gchar *content_type,
				       const gchar *body,
				       svc_callback *internal_callback,
				       sipe_svc_callback *callback,
				       gpointer callback_data)
{
	struct svc_request *data = g_new0(struct svc_request, 1);
	gboolean ret = FALSE;

	data->sipe_private = sipe_private;
	data->uri          = g_strdup(uri);

	data->conn = http_conn_create(SIPE_CORE_PUBLIC,
				      NULL, /* HttpSession */
				      method,
				      HTTP_CONN_SSL,
				      HTTP_CONN_NO_REDIRECT,
				      uri,
				      body,
				      content_type,
				      NULL, /* HttpConnAuth */
				      sipe_svc_https_response,
				      data);

	if (data->conn) {
		data->internal_cb = internal_callback;
		data->cb          = callback;
		data->cb_data     = callback_data;
		sipe_svc_init(sipe_private);
		sipe_private->svc->pending_requests = g_slist_prepend(sipe_private->svc->pending_requests,
								      data);
		ret = TRUE;
	} else {
		SIPE_DEBUG_ERROR("failed to create HTTP connection to %s", uri);
		sipe_svc_request_free(data);
	}

	return(ret);
}

static gboolean sipe_svc_wsdl_request(struct sipe_core_private *sipe_private,
				       const gchar *uri,
				       const gchar *wsse_security,
				       const gchar *soap_action,
				       const gchar *soap_body,
				       svc_callback *internal_callback,
				       sipe_svc_callback *callback,
				       gpointer callback_data)
{
	gchar *body = g_strdup_printf("<?xml version=\"1.0\"?>\r\n"
				      "<soap:Envelope"
				      " xmlns:auth=\"http://schemas.xmlsoap.org/ws/2006/12/authorization\""
				      " xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\""
				      " xmlns:wsa=\"http://www.w3.org/2005/08/addressing\""
				      " xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\""
				      " xmlns:wsse=\"http://www.docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\""
				      " xmlns:wst=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\""
				      " >"
				      " <soap:Header>"
				      "  <wsa:To>%s</wsa:To>"
				      "  <wsa:ReplyTo>"
				      "   <wsa:Address>http://www.w3.org/2005/08/addressing/anonymous</wsa:Address>"
				      "  </wsa:ReplyTo>"
				      "  <wsa:Action>%s</wsa:Action>"
				      "  <wsse:Security>%s</wsse:Security>"
				      " </soap:Header>"
				      " <soap:Body>%s</soap:Body>"
				      "</soap:Envelope>",
				      uri,
				      soap_action,
				      wsse_security,
				      soap_body);

	gboolean ret = sipe_svc_https_request(sipe_private,
				     HTTP_CONN_POST,
				     uri,
				     "text/xml",
				     body,
				     internal_callback,
				     callback,
				     callback_data);
	g_free(body);

	return(ret);
}

static void sipe_svc_webticket_response(struct svc_request *data,
					sipe_xml *xml)
{
	if (xml) {
		/* Callback: success */
		(*data->cb)(data->sipe_private, data->uri, xml, data->cb_data);
	} else {
		/* Callback: failed */
		(*data->cb)(data->sipe_private, data->uri, NULL, data->cb_data);
	}
}

gboolean sipe_svc_webticket(struct sipe_core_private *sipe_private,
			    const gchar *uri,
			    const gchar *authuser,
			    const gchar *service_uri,
			    sipe_svc_callback *callback,
			    gpointer callback_data)
{
	/* temporary */
	(void)authuser;
	(void)service_uri;

	return(sipe_svc_wsdl_request(sipe_private,
				     uri,
				     "",
				     "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue",
				      "",
				      sipe_svc_webticket_response,
				      callback,
				      callback_data));
}

static void sipe_svc_metadata_response(struct svc_request *data,
					sipe_xml *xml)
{
	if (xml) {
		/* Callback: success */
		(*data->cb)(data->sipe_private, data->uri, xml, data->cb_data);
	} else {
		/* Callback: failed */
		(*data->cb)(data->sipe_private, data->uri, NULL, data->cb_data);
	}
}

gboolean sipe_svc_metadata(struct sipe_core_private *sipe_private,
			   const gchar *uri,
			   sipe_svc_callback *callback,
			   gpointer callback_data)
{
	gchar *mex_uri = g_strdup_printf("%s/mex", uri);
	gboolean ret = sipe_svc_https_request(sipe_private,
					      HTTP_CONN_GET,
					      mex_uri,
					      "text",
					      "",
					      sipe_svc_metadata_response,
					      callback,
					      callback_data);
	g_free(mex_uri);
	return(ret);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
