/**
 * @file sipe-lync-autodiscover.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2016 SIPE Project <http://sipe.sourceforge.net/>
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
 * Specification references:
 *
 *   - [MS-OCDISCWS]: https://msdn.microsoft.com/en-us/library/hh623245.aspx
 *   - Understanding Autodiscover in Lync Server 2013
 *                    https://technet.microsoft.com/en-us/library/jj945654.aspx
 */

#include <string.h>

#include <glib.h>

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-http.h"
#include "sipe-lync-autodiscover.h"
#include "sipe-utils.h"
#include "sipe-svc.h"
#include "sipe-webticket.h"
#include "sipe-xml.h"

#define LYNC_AUTODISCOVER_ACCEPT_HEADER \
	"Accept: application/vnd.microsoft.rtc.autodiscover+xml;v=1\r\n"

struct lync_autodiscover_request {
	sipe_lync_autodiscover_callback *cb;
	gpointer cb_data;
	struct sipe_http_request *request;
	struct sipe_svc_session *session;
	const gchar **method;
	gchar *uri;
};

struct sipe_lync_autodiscover {
	GSList *pending_requests;
};

static void sipe_lync_autodiscover_request_free(struct sipe_core_private *sipe_private,
						struct lync_autodiscover_request *request)
{
	struct sipe_lync_autodiscover *sla = sipe_private->lync_autodiscover;

	sla->pending_requests = g_slist_remove(sla->pending_requests, request);

	if (request->request)
		sipe_http_request_cancel(request->request);
	if (request->cb)
		/* Callback: aborted */
		(*request->cb)(sipe_private, NULL, request->cb_data);
	sipe_svc_session_close(request->session);
	g_free(request->uri);
	g_free(request);
}

static void sipe_lync_autodiscover_cb(struct sipe_core_private *sipe_private,
				      guint status,
				      GSList *headers,
				      const gchar *body,
				      gpointer callback_data);
static void lync_request(struct sipe_core_private *sipe_private,
			 struct lync_autodiscover_request *request,
			 const gchar *uri,
			 const gchar *headers)
{
	request->request = sipe_http_request_get(sipe_private,
						 uri,
						 headers ? headers : LYNC_AUTODISCOVER_ACCEPT_HEADER,
						 sipe_lync_autodiscover_cb,
						 request);
}

static GSList *sipe_lync_autodiscover_add(GSList *servers,
					  const sipe_xml *node,
					  const gchar *name)
{
	const sipe_xml *child = sipe_xml_child(node, name);
	const gchar *fqdn = sipe_xml_attribute(child, "fqdn");
	guint port = sipe_xml_int_attribute(child, "port", 0);

	/* Add new entry to head of list */
	if (fqdn && (port != 0)) {
		struct sipe_lync_autodiscover_data *lync_data = g_new0(struct sipe_lync_autodiscover_data, 1);
		lync_data->server = g_strdup(fqdn);
		lync_data->port   = port;
		servers = g_slist_prepend(servers, lync_data);
	}

	return(servers);
}

GSList *sipe_lync_autodiscover_pop(GSList *servers)
{
	if (servers) {
		struct sipe_lync_autodiscover_data *lync_data = servers->data;
		servers = g_slist_remove(servers, lync_data);

		if (lync_data) {
			g_free((gchar *) lync_data->server);
			g_free(lync_data);
		}
	}

	return(servers);
}

static void sipe_lync_autodiscover_request(struct sipe_core_private *sipe_private,
					   struct lync_autodiscover_request *request);
static void sipe_lync_autodiscover_parse(struct sipe_core_private *sipe_private,
					 struct lync_autodiscover_request *request,
					 const gchar *body)
{
	sipe_xml *xml = sipe_xml_parse(body, strlen(body));
	const sipe_xml *node;
	gboolean next = TRUE;

	/* Root: resources exposed by this server */
	for (node = sipe_xml_child(xml, "Root/Link");
	     node;
	     node = sipe_xml_twin(node)) {
		const gchar *token = sipe_xml_attribute(node, "token");
		const gchar *uri = sipe_xml_attribute(node, "href");

		if (token && uri) {
			/* Redirect? */
			if (sipe_strcase_equal(token, "Redirect")) {
				SIPE_DEBUG_INFO("sipe_lync_autodiscover_parse: redirect to %s",
						uri);
				lync_request(sipe_private, request, uri, NULL);
				next = FALSE;
				break;

			/* User? */
			} else if (sipe_strcase_equal(token, "User")) {
				SIPE_DEBUG_INFO("sipe_lync_autodiscover_parse: user %s",
						uri);

				/* rememebr URI for authentication failure */
				request->uri = g_strdup(uri);

				lync_request(sipe_private, request, uri, NULL);
				next = FALSE;
				break;

			} else
				SIPE_DEBUG_INFO("sipe_lync_autodiscover_parse: unknown token %s",
						token);
		}
	}

	/* User: topology information of the user’s home server */
	if ((node = sipe_xml_child(xml, "User")) != NULL) {
		GSList *servers;

		/* List is reversed, i.e. internal will be tried first */
		servers = g_slist_prepend(NULL, NULL);
		servers = sipe_lync_autodiscover_add(servers,
						     node,
						     "SipClientExternalAccess");
		servers = sipe_lync_autodiscover_add(servers,
						     node,
						     "SipClientInternalAccess");

		/* Callback takes ownership of servers list */
		(*request->cb)(sipe_private, servers, request->cb_data);

		/* Request completed */
		next        = FALSE;
		request->cb = NULL;
		sipe_lync_autodiscover_request_free(sipe_private, request);
		/* request is invalid */
	}

	sipe_xml_free(xml);

	if (next)
		sipe_lync_autodiscover_request(sipe_private, request);
}

static void sipe_lync_autodiscover_webticket(struct sipe_core_private *sipe_private,
					     SIPE_UNUSED_PARAMETER const gchar *base_uri,
					     const gchar *auth_uri,
					     const gchar *wsse_security,
					     SIPE_UNUSED_PARAMETER const gchar *failure_msg,
					     gpointer callback_data)
{
	struct lync_autodiscover_request *request = callback_data;
	gchar *saml;

	/* Extract SAML Assertion from WSSE Security XML text */
	if (wsse_security &&
	    ((saml = sipe_xml_extract_raw(wsse_security,
					  "Assertion",
					  TRUE)) != NULL)) {
		gchar *base64 = g_base64_encode((const guchar *) saml,
						strlen(saml));
		gchar *headers = g_strdup_printf(LYNC_AUTODISCOVER_ACCEPT_HEADER
						 "X-MS-WebTicket: opaque=%s\r\n",
						 base64);
		g_free(base64);

		SIPE_DEBUG_INFO("sipe_lync_autodiscover_webticket: got ticket for Auth URI %s",
				auth_uri);
		g_free(saml);

		lync_request(sipe_private, request, auth_uri, headers);
		g_free(headers);

	} else
		sipe_lync_autodiscover_request(sipe_private, request);
}

static void sipe_lync_autodiscover_cb(struct sipe_core_private *sipe_private,
				      guint status,
				      GSList *headers,
				      const gchar *body,
				      gpointer callback_data)
{
	struct lync_autodiscover_request *request = callback_data;
	const gchar *type = sipe_utils_nameval_find(headers, "Content-Type");
	gchar *uri = request->uri;

	request->request = NULL;
	request->uri     = NULL;

	switch (status) {
	case SIPE_HTTP_STATUS_OK:
		/* only accept Autodiscover XML responses */
		if (body && g_str_has_prefix(type, "application/vnd.microsoft.rtc.autodiscover+xml"))
			sipe_lync_autodiscover_parse(sipe_private, request, body);
		else
			sipe_lync_autodiscover_request(sipe_private, request);
		break;

	case SIPE_HTTP_STATUS_FAILED:
		{
			if (uri) {
				/* check for authentication failure */
				const gchar *webticket_uri = sipe_utils_nameval_find(headers,
										     "X-MS-WebTicketURL");

				if (!(webticket_uri &&
				      sipe_webticket_request_with_auth(sipe_private,
								       request->session,
								       webticket_uri,
								       uri, /* Auth URI */
								       sipe_lync_autodiscover_webticket,
								       request)))
					sipe_lync_autodiscover_request(sipe_private, request);
			} else
				sipe_lync_autodiscover_request(sipe_private, request);
	        }
		break;

	case SIPE_HTTP_STATUS_ABORTED:
		/* we are not allowed to generate new requests */
		sipe_lync_autodiscover_request_free(sipe_private, request);
		break;

	default:
		sipe_lync_autodiscover_request(sipe_private, request);
		break;
	}

	g_free(uri);
}

static void sipe_lync_autodiscover_request(struct sipe_core_private *sipe_private,
					   struct lync_autodiscover_request *request)
{
	static const gchar *methods[] = {
		"http://LyncDiscoverInternal.%s/?sipuri=%s",
		"https://LyncDiscoverInternal.%s/?sipuri=%s",
		"http://LyncDiscover.%s/?sipuri=%s",
		"https://LyncDiscover.%s/?sipuri=%s",
		NULL
	};

	if (request->method)
		request->method++;
	else
		request->method = methods;

	if (*request->method) {
		gchar *uri = g_strdup_printf(*request->method,
					     SIPE_CORE_PUBLIC->sip_domain,
					     sipe_private->username);

		SIPE_DEBUG_INFO("sipe_lync_autodiscover_request: trying '%s'", uri);

		lync_request(sipe_private, request, uri, NULL);
		g_free(uri);

	} else {
		/* create list with NULL entry */
		GSList *servers = g_slist_prepend(NULL, NULL);

		/* All methods tried, indicate failure to caller */
		SIPE_DEBUG_INFO_NOFORMAT("sipe_lync_autodiscover_request: no more methods to try!");

		/* Callback takes ownership of servers list */
		(*request->cb)(sipe_private, servers, request->cb_data);

		/* Request completed */
		request->cb = NULL;
		sipe_lync_autodiscover_request_free(sipe_private, request);
		/* request is invalid */
	}
}

void sipe_lync_autodiscover_start(struct sipe_core_private *sipe_private,
				  sipe_lync_autodiscover_callback *callback,
				  gpointer callback_data)
{
	struct sipe_lync_autodiscover *sla = sipe_private->lync_autodiscover;
	struct lync_autodiscover_request *request = g_new0(struct lync_autodiscover_request, 1);

	request->cb      = callback;
	request->cb_data = callback_data;
	request->session = sipe_svc_session_start();

	sla->pending_requests = g_slist_prepend(sla->pending_requests,
						request);

	sipe_lync_autodiscover_request(sipe_private, request);
}

void sipe_lync_autodiscover_init(struct sipe_core_private *sipe_private)
{
	struct sipe_lync_autodiscover *sla = g_new0(struct sipe_lync_autodiscover, 1);

	sipe_private->lync_autodiscover = sla;
}

void sipe_lync_autodiscover_free(struct sipe_core_private *sipe_private)
{
	struct sipe_lync_autodiscover *sla = sipe_private->lync_autodiscover;

	while (sla->pending_requests)
		sipe_lync_autodiscover_request_free(sipe_private,
						    sla->pending_requests->data);

	g_free(sla);
	sipe_private->lync_autodiscover = NULL;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
