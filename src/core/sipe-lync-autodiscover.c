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
#include "sipe-xml.h"

struct lync_autodiscover_request {
	sipe_lync_autodiscover_callback *cb;
	gpointer cb_data;
	struct sipe_http_request *request;
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
			 const gchar *uri)
{
	request->request = sipe_http_request_get(sipe_private,
						 uri,
						 "Accept: application/vnd.microsoft.rtc.autodiscover+xml;v=1\r\n",
						 sipe_lync_autodiscover_cb,
						 request);
}

static void sipe_lync_autodiscover_request(struct sipe_core_private *sipe_private,
					   struct lync_autodiscover_request *request);
static void sipe_lync_autodiscover_parse(struct sipe_core_private *sipe_private,
					 struct lync_autodiscover_request *request,
					 const gchar *body)
{
	sipe_xml *xml = sipe_xml_parse(body, strlen(body));
	const sipe_xml *link;
	gboolean next = TRUE;

	for (link = sipe_xml_child(xml, "Root/Link");
	     link;
	     link = sipe_xml_twin(link)) {
		const gchar *token = sipe_xml_attribute(link, "token");
		const gchar *uri = sipe_xml_attribute(link, "href");

		if (token && uri) {
			/* Redirect? */
			if (sipe_strcase_equal(token, "Redirect")) {
				SIPE_DEBUG_INFO("sipe_lync_autodiscover_parse: redirect to %s",
						uri);
				lync_request(sipe_private, request, uri);
				next = FALSE;
				break;

			/* User? */
			} else if (sipe_strcase_equal(token, "User")) {
				SIPE_DEBUG_INFO("sipe_lync_autodiscover_parse: user %s",
						uri);

				/* remember URI for */
				request->uri = g_strdup(uri);

				lync_request(sipe_private, request, uri);
				next = FALSE;
				break;

			} else
				SIPE_DEBUG_INFO("sipe_lync_autodiscover_parse: unknown token %s",
						token);
		}
	}
	sipe_xml_free(xml);

	if (next)
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
			/* check for authentication failure */
			const gchar *webticket_uri = sipe_utils_nameval_find(headers,
									     "X-MS-WebTicketURL");

			/* @TODO: request webticket - go to next method for now*/
			if (webticket_uri)
				SIPE_DEBUG_INFO("sipe_lync_autodiscover_cb: webticket URI %s",
						webticket_uri);
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

	if (uri)
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

		lync_request(sipe_private, request, uri);
		g_free(uri);

	} else {
		struct sipe_lync_autodiscover_data lync_data = { NULL, 0 };

		/* All methods tried, indicate failure to caller */
		SIPE_DEBUG_INFO_NOFORMAT("sipe_lync_autodiscover_request: no more methods to try!");
		(*request->cb)(sipe_private, &lync_data, request->cb_data);

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
