/**
 * @file sipe-ews-autodiscover.c
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
 */

#include <string.h>

#include <glib.h>

#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-ews-autodiscover.h"
#include "sipe-http.h"

struct sipe_ews_autodiscover_cb {
	sipe_ews_autodiscover_callback *cb;
	gpointer cb_data;
};

struct sipe_ews_autodiscover {
	struct sipe_ews_autodiscover_data *data;
	struct sipe_http_request *request;
	GSList *callbacks;
	const gchar *domain;
	const gchar * const *method;
	gboolean retry;
	gboolean completed;
};

static void sipe_ews_autodiscover_complete(struct sipe_core_private *sipe_private,
					   struct sipe_ews_autodiscover_data *ews_data)
{
	struct sipe_ews_autodiscover *sea = sipe_private->ews_autodiscover;
	GSList *entry = sea->callbacks;

	while (entry) {
		struct sipe_ews_autodiscover_cb *sea_cb = entry->data;
		sea_cb->cb(sipe_private, ews_data, sea_cb->cb_data);
		g_free(sea_cb);
		entry = entry->next;
	}
	g_slist_free(sea->callbacks);
	sea->callbacks = NULL;
	sea->completed = TRUE;
}

static void sipe_ews_autodiscover_request(struct sipe_core_private *sipe_private,
					  gboolean next_method);
static void sipe_ews_autodiscover_response(struct sipe_core_private *sipe_private,
					   guint status,
					   SIPE_UNUSED_PARAMETER GSList *headers,
					   const gchar *body,
					   gpointer data)
{
	struct sipe_ews_autodiscover *sea = data;

	sea->request = NULL;

	switch (status) {
	case SIPE_HTTP_STATUS_OK:
		/* @TODO */
		SIPE_DEBUG_INFO("sipe_ews_autodiscover_response: XML received: %p", body);
		break;

	case SIPE_HTTP_STATUS_CLIENT_FORBIDDEN:
		/*
		 * Authentication succeeded but we still weren't allowed to
		 * view the page. At least at our work place this error is
		 * temporary, i.e. the next access with the exact same
		 * authentication succeeds.
		 *
		 * Let's try again, but only once...
		 */
		sipe_ews_autodiscover_request(sipe_private, !sea->retry);
		break;

	case SIPE_HTTP_STATUS_ABORTED:
		/* we are not allowed to generate new requests */
		break;

	default:
		sipe_ews_autodiscover_request(sipe_private, TRUE);
		break;
	}
}

static void sipe_ews_autodiscover_request(struct sipe_core_private *sipe_private,
					  gboolean next_method)
{
	struct sipe_ews_autodiscover *sea = sipe_private->ews_autodiscover;
	static const gchar * const methods[] = {
		"https://Autodiscover.%s/Autodiscover/Autodiscover.xml",
		"http://Autodiscover.%s/Autodiscover/Autodiscover.xml",
		"https://%s/Autodiscover/Autodiscover.xml",
		NULL
	};

	if (sea->method) {
		if (next_method) {
			sea->method++;
			sea->retry = TRUE;
		}
	} else
		sea->method = methods;

	if (*sea->method) {
		gchar *url = g_strdup_printf(*sea->method, sea->domain);
		gchar *body = g_strdup_printf("<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006\">"
					      " <Request>"
					      "  <EMailAddress>%s</EMailAddress>"
					      "  <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>"
					      " </Request>"
					      "</Autodiscover>",
					      sipe_private->email);

		SIPE_DEBUG_INFO("sipe_ews_autodiscover_next_method: trying '%s'", url);

		sea->request = sipe_http_request_post(sipe_private,
						      url,
						      NULL,
						      body,
						      "text/xml",
						      sipe_ews_autodiscover_response,
						      sea);
		g_free(body);
		g_free(url);

		if (sea->request) {
			/* @TODO: sipe_cal_http_authentication(cal); */
			sipe_http_request_allow_redirect(sea->request);
			sipe_http_request_ready(sea->request);
		} else
			sipe_ews_autodiscover_request(sipe_private, TRUE);

	} else {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_ews_autodiscover_start: no more methods to try!");
		sipe_ews_autodiscover_complete(sipe_private, NULL);
	}
}

void sipe_ews_autodiscover_start(struct sipe_core_private *sipe_private,
				 sipe_ews_autodiscover_callback *callback,
				 gpointer callback_data)
{
	struct sipe_ews_autodiscover *sea = sipe_private->ews_autodiscover;

	if (sea->completed) {
		(*callback)(sipe_private, sea->data, callback_data);
	} else {
		struct sipe_ews_autodiscover_cb *sea_cb = g_new(struct sipe_ews_autodiscover_cb, 1);
		sea_cb->cb      = callback;
		sea_cb->cb_data = callback_data;
		sea->callbacks  = g_slist_prepend(sea->callbacks, sea_cb);

		if (!sea->method)
			sipe_ews_autodiscover_request(sipe_private, TRUE);
	}
}

void sipe_ews_autodiscover_init(struct sipe_core_private *sipe_private)
{
	struct sipe_ews_autodiscover *sea = g_new0(struct sipe_ews_autodiscover, 1);

	sea->domain = strstr(sipe_private->email, "@") + 1;
	sipe_private->ews_autodiscover = sea;
}

void sipe_ews_autodiscover_free(struct sipe_core_private *sipe_private)
{
	struct sipe_ews_autodiscover *sea = sipe_private->ews_autodiscover;
	sipe_ews_autodiscover_complete(sipe_private, NULL);
	g_free(sea->data);
	g_free(sea);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
