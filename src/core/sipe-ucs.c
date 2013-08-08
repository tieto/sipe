/**
 * @file sipe-ucs.c
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
 *
 *
 * Implementation for Unified Contact Store [MS-OXWSCOS]
 *  <http://msdn.microsoft.com/en-us/library/jj194130.aspx>
 */

#include <string.h>

#include <glib.h>

#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-ews-autodiscover.h"
#include "sipe-http.h"
#include "sipe-ucs.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

typedef void (ucs_callback)(struct sipe_core_private *sipe_private,
			    const sipe_xml *xml);

struct ucs_deferred {
	ucs_callback *cb;
	gchar *body;
};

struct ucs_request {
	ucs_callback *cb;
	struct sipe_http_request *request;
};

struct sipe_ucs {
	gchar *ews_url;
	GSList *deferred_requests;
	GSList *pending_requests;
	gboolean shutting_down;
};

static void sipe_ucs_deferred_free(struct ucs_deferred *data)
{
	g_free(data->body);
	g_free(data);
}

static void sipe_ucs_request_free(struct sipe_core_private *sipe_private,
				  struct ucs_request *data)
{
	if (data->request)
		sipe_http_request_cancel(data->request);
	if (data->cb)
		/* Callback: aborted */
		(*data->cb)(sipe_private, NULL);
	g_free(data);
}

static void sipe_ucs_http_response(struct sipe_core_private *sipe_private,
				   guint status,
				   SIPE_UNUSED_PARAMETER GSList *headers,
				   const gchar *body,
				   gpointer callback_data)
{
	struct ucs_request *data = callback_data;
	struct sipe_ucs *ucs = sipe_private->ucs;

	SIPE_DEBUG_INFO("sipe_ucs_http_response: code %d", status);
	data->request = NULL;

	if ((status == SIPE_HTTP_STATUS_OK) && body) {
		sipe_xml *xml = sipe_xml_parse(body, strlen(body));
		/* Callback: success */
		(*data->cb)(sipe_private, xml);
		sipe_xml_free(xml);
	} else {
		/* Callback: failed */
		(*data->cb)(sipe_private, NULL);
	}

	/* already been called */
	data->cb = NULL;

	ucs->pending_requests = g_slist_remove(ucs->pending_requests,
					       data);
	sipe_ucs_request_free(sipe_private, data);
}

static void sipe_ucs_http_request(struct sipe_core_private *sipe_private,
				  const gchar *body,
				  ucs_callback *callback)
{
	struct sipe_ucs *ucs = sipe_private->ucs;

	if (ucs->shutting_down) {
		SIPE_DEBUG_ERROR("sipe_ucs_http_request: new UCS request during shutdown: THIS SHOULD NOT HAPPEN! Debugging information:\n"
				 "Body:   %s\n",
				 body ? body : "<EMPTY>");

	} else if (ucs->ews_url) {
		struct ucs_request *data = g_new0(struct ucs_request, 1);
		gchar *soap = g_strdup_printf("<?xml version=\"1.0\"?>\r\n"
					      "<soap:Envelope"
					      " xmlns:m=\"http://schemas.microsoft.com/exchange/services/2006/messages\""
					      " xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\""
					      " xmlns:t=\"http://schemas.microsoft.com/exchange/services/2006/types\""
					      " >"
					      " <soap:Header>"
					      "  <t:RequestServerVersion Version=\"Exchange2013\" />"
					      " </soap:Header>"
					      " <soap:Body>"
					      "  %s"
					      " </soap:Body>"
					      "</soap:Envelope>",
					      body);
		struct sipe_http_request *request = sipe_http_request_post(sipe_private,
									   ucs->ews_url,
									   NULL,
									   soap,
									   "text/xml; charset=UTF-8",
									   sipe_ucs_http_response,
									   data);
		g_free(soap);

		if (request) {
			data->cb      = callback;
			data->request = request;

			ucs->pending_requests = g_slist_prepend(ucs->pending_requests,
								data);

			sipe_core_email_authentication(sipe_private,
						       request);
			sipe_http_request_allow_redirect(request);
			sipe_http_request_ready(request);
		} else {
			SIPE_DEBUG_ERROR_NOFORMAT("sipe_ucs_http_request: failed to create HTTP connection");
			g_free(data);
		}

	} else {
		struct ucs_deferred *data = g_new0(struct ucs_deferred, 1);
		data->body = g_strdup(body);
		data->cb   = callback;

		ucs->deferred_requests = g_slist_prepend(ucs->deferred_requests,
							 data);
	}
}

static void sipe_ucs_get_user_photo_response(struct sipe_core_private *sipe_private,
					     const sipe_xml *xml)
{
	/* temporary */
	(void)sipe_private;
	(void)xml;
}

void sipe_ucs_get_photo(struct sipe_core_private *sipe_private,
			const gchar *uri)
{
	gchar *body = g_strdup_printf("<m:GetUserPhoto>"
				      " <m:Email>%s</m:Email>"
				      " <m:SizeRequested>HR48x48</m:SizeRequested>"
				      "</m:GetUserPhoto>",
				      sipe_get_no_sip_uri(uri));

	sipe_ucs_http_request(sipe_private,
			      body,
			      sipe_ucs_get_user_photo_response);
	g_free(body);
}

static void sipe_ucs_get_im_item_list_response(struct sipe_core_private *sipe_private,
					       const sipe_xml *xml)
{
	/* temporary */
	(void)sipe_private;
	(void)xml;
}

static void ucs_ews_autodiscover_cb(struct sipe_core_private *sipe_private,
				    const struct sipe_ews_autodiscover_data *ews_data,
				    SIPE_UNUSED_PARAMETER gpointer callback_data)
{
	struct sipe_ucs *ucs = sipe_private->ucs;
	const gchar *ews_url = ews_data->ews_url;

	if (!ucs)
		return;

	if (is_empty(ews_url)) {
		SIPE_DEBUG_ERROR_NOFORMAT("ucs_ews_autodiscover_cb: can't detect EWS URL, contact list operations will not work!");
		return;
	}

	SIPE_DEBUG_INFO("ucs_ews_autodiscover_cb: EWS URL '%s'", ews_url);
	ucs->ews_url = g_strdup(ews_url);

	sipe_ucs_http_request(sipe_private,
			      "<m:GetImItemList/>",
			      sipe_ucs_get_im_item_list_response);

	/* EWS URL is valid, send all deferred requests now */
	if (ucs->deferred_requests) {
		GSList *entry = ucs->deferred_requests;
		while (entry) {
			struct ucs_deferred *data = entry->data;
			sipe_ucs_http_request(sipe_private,
					      data->body,
					      data->cb);
			sipe_ucs_deferred_free(data);
			entry = entry->next;
		}
		g_slist_free(ucs->deferred_requests);
		ucs->deferred_requests = NULL;
	}
}

void sipe_ucs_init(struct sipe_core_private *sipe_private)
{
	if (sipe_private->ucs)
		return;

	sipe_private->ucs = g_new0(struct sipe_ucs, 1);

	sipe_ews_autodiscover_start(sipe_private,
				    ucs_ews_autodiscover_cb,
				    NULL);
}

void sipe_ucs_free(struct sipe_core_private *sipe_private)
{
	struct sipe_ucs *ucs = sipe_private->ucs;

	if (!ucs)
		return;

	/* UCS stack is shutting down: reject all new requests */
	ucs->shutting_down = TRUE;

	if (ucs->deferred_requests) {
		GSList *entry = ucs->deferred_requests;
		while (entry) {
			sipe_ucs_deferred_free(entry->data);
			entry = entry->next;
		}
		g_slist_free(ucs->deferred_requests);
	}

	if (ucs->pending_requests) {
		GSList *entry = ucs->pending_requests;
		while (entry) {
			sipe_ucs_request_free(sipe_private, entry->data);
			entry = entry->next;
		}
		g_slist_free(ucs->pending_requests);
	}

	g_free(ucs->ews_url);
	g_free(ucs);
	sipe_private->ucs = NULL;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
