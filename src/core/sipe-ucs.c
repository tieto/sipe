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

struct sipe_ucs {
	gchar *ews_url;
	struct sipe_http_request *request;
};

typedef void (sipe_ucs_callback)(struct sipe_core_private *sipe_private,
				 const sipe_xml *xml);

static void ucs_process_get_im_item_list_response(struct sipe_core_private *sipe_private,
						  const sipe_xml *xml)
{
	/* temporary */
	(void)sipe_private;
	(void)xml;
}

static void ucs_response(struct sipe_core_private *sipe_private,
			 guint status,
			 SIPE_UNUSED_PARAMETER GSList *headers,
			 const gchar *body,
			 gpointer data)
{
	struct sipe_ucs *ucs = sipe_private->ucs;

	if (!ucs)
		return;

	ucs->request = NULL;

	if ((status == SIPE_HTTP_STATUS_OK) && body) {
		sipe_xml *xml = sipe_xml_parse(body, strlen(body));
		sipe_ucs_callback *callback = data;

		SIPE_DEBUG_INFO_NOFORMAT("ucs_response: received valid SOAP response");
		(*callback)(sipe_private, xml);

		sipe_xml_free(xml);
	}
}

static void ucs_request(struct sipe_core_private *sipe_private,
			const gchar *body,
			sipe_ucs_callback *callback)
{
	struct sipe_ucs *ucs = sipe_private->ucs;
	const gchar *soap = g_strdup_printf("<?xml version=\"1.0\"?>\r\n"
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

	ucs->request = sipe_http_request_post(sipe_private,
					      ucs->ews_url,
					      NULL,
					      soap,
					      "text/xml; charset=UTF-8",
					      ucs_response,
					      callback);
	if (ucs->request) {
		sipe_core_email_authentication(sipe_private,
					       ucs->request);
		sipe_http_request_allow_redirect(ucs->request);
		sipe_http_request_ready(ucs->request);
	}
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

	ucs_request(sipe_private,
		    "<m:GetImItemList/>",
		    ucs_process_get_im_item_list_response);
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

	if (ucs->request)
		sipe_http_request_cancel(ucs->request);
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
