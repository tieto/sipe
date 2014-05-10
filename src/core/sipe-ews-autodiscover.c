/**
 * @file sipe-ews-autodiscover.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2013-2014 SIPE Project <http://sipe.sourceforge.net/>
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
 *   - POX: plain old XML autodiscover
 *   - [MS-OXDSCLI]:     http://msdn.microsoft.com/en-us/library/cc463896.aspx
 *   - Autdiscover for Exchange:
 *                       http://msdn.microsoft.com/en-us/library/office/jj900169.aspx
 *   - POX autodiscover: http://msdn.microsoft.com/en-us/library/office/aa581522.aspx
 *   - POX redirect:     http://msdn.microsoft.com/en-us/library/office/dn467392.aspx
 */

#include <string.h>

#include <glib.h>

#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-ews-autodiscover.h"
#include "sipe-http.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

struct sipe_ews_autodiscover_cb {
	sipe_ews_autodiscover_callback *cb;
	gpointer cb_data;
};

struct autodiscover_method {
	const gchar *template;
	gboolean redirect;
};

struct sipe_ews_autodiscover {
	struct sipe_ews_autodiscover_data *data;
	struct sipe_http_request *request;
	GSList *callbacks;
	gchar *email;
	const struct autodiscover_method *method;
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
static gboolean sipe_ews_autodiscover_url(struct sipe_core_private *sipe_private,
					  const gchar *url);
static void sipe_ews_autodiscover_parse(struct sipe_core_private *sipe_private,
					const gchar *body)
{
	struct sipe_ews_autodiscover *sea = sipe_private->ews_autodiscover;
	struct sipe_ews_autodiscover_data *ews_data = sea->data =
		g_new0(struct sipe_ews_autodiscover_data, 1);
	sipe_xml *xml = sipe_xml_parse(body, strlen(body));
	const sipe_xml *account = sipe_xml_child(xml, "Response/Account");
	gboolean complete = TRUE;

	/* valid POX autodiscover response? */
	if (account) {
		const sipe_xml *node;

		/* POX autodiscover settings? */
		if ((node = sipe_xml_child(account, "Protocol")) != NULL) {

			/* Autodiscover/Response/User/LegacyDN (requires trimming) */
			gchar *tmp = sipe_xml_data(sipe_xml_child(xml,
								  "Response/User/LegacyDN"));
			if (tmp)
				ews_data->legacy_dn = g_strstrip(tmp);

			/* extract settings */
			for (; node; node = sipe_xml_twin(node)) {
				gchar *type = sipe_xml_data(sipe_xml_child(node,
									   "Type"));

				/* Exchange or Office 365 */
				if (sipe_strequal("EXCH", type) ||
				    sipe_strequal("EXPR", type)) {

#define _URL(name, field) \
			if (!ews_data->field) {	\
				ews_data->field = sipe_xml_data(sipe_xml_child(node, #name)); \
				SIPE_DEBUG_INFO("sipe_ews_autodiscover_parse: " #field " = '%s'", \
						ews_data->field ? ews_data->field : "<NOT FOUND>"); \
			}

					/* use first entry */
					_URL(ASUrl,  as_url);
					_URL(EwsUrl, ews_url);
					_URL(OABUrl, oab_url);
					_URL(OOFUrl, oof_url);
#undef _URL

				}
				g_free(type);
			}

		/* POX autodiscover redirect to new email address? */
		} else if ((node = sipe_xml_child(account, "RedirectAddr")) != NULL) {
			gchar *addr = sipe_xml_data(node);

			/*
			 * Sanity checks for new email address:
			 *  - must contain a "@" character
			 *  - must be different from current address
			 */
			if (addr && strchr(addr, '@') &&
			    !sipe_strequal(sea->email, addr)) {
				g_free(sea->email);
				sea->email = addr;
				addr = NULL; /* sea takes ownership */

				SIPE_DEBUG_INFO("sipe_ews_autodiscover_parse: restarting with email address '%s'",
						sea->email);

				/* restart process with new email address */
				sea->method = NULL;
				complete    = FALSE;
				sipe_ews_autodiscover_request(sipe_private,
							      TRUE);
			}
			g_free(addr);

		/* POX autodiscover redirect to new URL? */
		} else if ((node = sipe_xml_child(account, "RedirectUrl")) != NULL) {
			gchar *url = sipe_xml_data(node);

			if (!is_empty(url)) {
				SIPE_DEBUG_INFO("sipe_ews_autodiscover_parse: redirected to URL '%s'",
						url);
				complete = !sipe_ews_autodiscover_url(sipe_private,
								      url);
			}
			g_free(url);

		/* ignore all other POX autodiscover responses */
		} else {
			SIPE_DEBUG_ERROR_NOFORMAT("sipe_ews_autodiscover_parse: unknown response detected");
		}
	}
	sipe_xml_free(xml);

	if (complete)
		sipe_ews_autodiscover_complete(sipe_private, ews_data);
}

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
		if (body)
			sipe_ews_autodiscover_parse(sipe_private, body);
		else
			sipe_ews_autodiscover_request(sipe_private, TRUE);
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

static gboolean sipe_ews_autodiscover_url(struct sipe_core_private *sipe_private,
					  const gchar *url)
{
	struct sipe_ews_autodiscover *sea = sipe_private->ews_autodiscover;
	gchar *body = g_strdup_printf("<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006\">"
				      " <Request>"
				      "  <EMailAddress>%s</EMailAddress>"
				      "  <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>"
				      " </Request>"
				      "</Autodiscover>",
				      sea->email);

	SIPE_DEBUG_INFO("sipe_ews_autodiscover_url: trying '%s'", url);

	sea->request = sipe_http_request_post(sipe_private,
					      url,
					      NULL,
					      body,
					      "text/xml",
					      sipe_ews_autodiscover_response,
					      sea);
	g_free(body);

	if (sea->request) {
		sipe_core_email_authentication(sipe_private,
					       sea->request);
		sipe_http_request_allow_redirect(sea->request);
		sipe_http_request_ready(sea->request);
		return(TRUE);
	}

	return(FALSE);
}

static void sipe_ews_autodiscover_redirect_response(struct sipe_core_private *sipe_private,
						    guint status,
						    GSList *headers,
						    SIPE_UNUSED_PARAMETER const gchar *body,
						    gpointer data)
{
	struct sipe_ews_autodiscover *sea = data;
	gboolean failed = TRUE;

	sea->request = NULL;

	/* Start attempt with URL from redirect (3xx) response */
	if ((status >= SIPE_HTTP_STATUS_REDIRECTION) &&
	    (status <  SIPE_HTTP_STATUS_CLIENT_ERROR)) {
		const gchar *location = sipe_utils_nameval_find_instance(headers,
									 "Location",
									 0);
		if (location)
			failed = !sipe_ews_autodiscover_url(sipe_private,
							    location);
	}

	if (failed)
		sipe_ews_autodiscover_request(sipe_private, TRUE);
}

static gboolean sipe_ews_autodiscover_redirect(struct sipe_core_private *sipe_private,
					       const gchar *url)
{
	struct sipe_ews_autodiscover *sea = sipe_private->ews_autodiscover;

	SIPE_DEBUG_INFO("sipe_ews_autodiscover_redirect: trying '%s'", url);

	sea->request = sipe_http_request_get(sipe_private,
					     url,
					     NULL,
					     sipe_ews_autodiscover_redirect_response,
					     sea);

	if (sea->request) {
		sipe_http_request_ready(sea->request);
		return(TRUE);
	}

	return(FALSE);
}

static void sipe_ews_autodiscover_request(struct sipe_core_private *sipe_private,
					  gboolean next_method)
{
	struct sipe_ews_autodiscover *sea = sipe_private->ews_autodiscover;
	static const struct autodiscover_method const methods[] = {
		{ "https://Autodiscover.%s/Autodiscover/Autodiscover.xml", FALSE },
		{ "http://Autodiscover.%s/Autodiscover/Autodiscover.xml",  TRUE  },
		{ "http://Autodiscover.%s/Autodiscover/Autodiscover.xml",  FALSE },
		{ "https://%s/Autodiscover/Autodiscover.xml",              FALSE },
		{ NULL,                                                    FALSE },
	};

	sea->retry = next_method;
	if (sea->method) {
		if (next_method)
			sea->method++;
	} else
		sea->method = methods;

	if (sea->method->template) {
		gchar *url = g_strdup_printf(sea->method->template,
					     strstr(sea->email, "@") + 1);

		if (!(sea->method->redirect ?
		      sipe_ews_autodiscover_redirect(sipe_private, url) :
		      sipe_ews_autodiscover_url(sipe_private, url)))
			sipe_ews_autodiscover_request(sipe_private, TRUE);

		g_free(url);

	} else {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_ews_autodiscover_request: no more methods to try!");
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

	sea->email = g_strdup(sipe_private->email);

	sipe_private->ews_autodiscover = sea;
}

void sipe_ews_autodiscover_free(struct sipe_core_private *sipe_private)
{
	struct sipe_ews_autodiscover *sea = sipe_private->ews_autodiscover;
	struct sipe_ews_autodiscover_data *ews_data = sea->data;
	sipe_ews_autodiscover_complete(sipe_private, NULL);
	if (ews_data) {
		g_free((gchar *)ews_data->as_url);
		g_free((gchar *)ews_data->ews_url);
		g_free((gchar *)ews_data->legacy_dn);
		g_free((gchar *)ews_data->oab_url);
		g_free((gchar *)ews_data->oof_url);
		g_free(ews_data);
	}
	g_free(sea->email);
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
