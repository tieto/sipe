/**
 * @file sip-soap.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-2013 SIPE Project <http://sipe.sourceforge.net/>
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
 * SOAP requests over SIP SERVICE messages
 *
 * Specification references:
 *
 *   - [MS-SIP]:  http://msdn.microsoft.com/en-us/library/cc246115.aspx
 *   - [MS-PRES]: http://msdn.microsoft.com/en-us/library/cc431501.aspx
 *
 */

#include <glib.h>

#include "sip-soap.h"
#include "sip-transport.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-utils.h"

void sip_soap_raw_request_cb(struct sipe_core_private *sipe_private,
			     const gchar *from,
			     const gchar *soap,
			     SoapTransCallback callback,
			     struct transaction_payload *payload)
{
	gchar *contact = get_contact(sipe_private);
	gchar *hdr = g_strdup_printf("Contact: %s\r\n"
				     "Content-Type: application/SOAP+xml\r\n",
				     contact);

	struct transaction *trans = sip_transport_service(sipe_private,
							  from,
							  hdr,
							  soap,
							  callback);
	trans->payload = payload;

	g_free(contact);
	g_free(hdr);
}

/**
 * delta_num != NULL: use user sip: URI as from, include deltanum and increment it
 * delta_num == NULL; use sip: URI generated from domain name as from
 */
static void sip_soap_request_full(struct sipe_core_private *sipe_private,
				  const gchar *method,
				  const gchar *request,
				  const gchar *additional,
				  guint *deltanum,
				  SoapTransCallback callback,
				  struct transaction_payload *payload)
{
	gchar *from = deltanum ?
		sip_uri_self(sipe_private) :
		sip_uri_from_name(sipe_private->public.sip_domain);
	gchar *delta = deltanum ?
		g_strdup_printf("<m:deltaNum>%d</m:deltaNum>", (*deltanum)++) :
		g_strdup("");
	gchar *soap = g_strdup_printf("<s:Envelope"
				      " xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\""
				      " xmlns:m=\"http://schemas.microsoft.com/winrtc/2002/11/sip\""
				      ">"
				        "<s:Body>"
				          "<m:%s>"
				            "%s"
				            "%s"
				          "</m:%s>"
				          "%s"
				         "</s:Body>"
				      "</s:Envelope>",
				      method,
				      request,
				      delta,
				      method,
				      additional ? additional : "");
	sip_soap_raw_request_cb(sipe_private, from, soap, callback, payload);
	g_free(soap);
	g_free(delta);
	g_free(from);
}

void sip_soap_request_cb(struct sipe_core_private *sipe_private,
			 const gchar *method,
			 const gchar *request,
			 SoapTransCallback callback,
			 struct transaction_payload *payload)
{
	sip_soap_request_full(sipe_private,
			      method,
			      request,
			      NULL,
			      &sipe_private->deltanum_contacts,
			      callback,
			      payload);
}

void sip_soap_request(struct sipe_core_private *sipe_private,
		      const gchar *method,
		      const gchar *request)
{
	sip_soap_request_cb(sipe_private,
			    method,
			    request,
			    NULL,
			    NULL);
}

/* This is the only user of deltanum_acl */
void sip_soap_ocs2005_setacl(struct sipe_core_private *sipe_private,
			     const gchar *who,
			     gboolean allow)
{
	gchar *request = g_strdup_printf("<m:type>USER</m:type>"
					 "<m:mask>%s</m:mask>"
					 "<m:rights>%s</m:rights>",
					 who,
					 allow ? "AA" : "BD");
	sip_soap_request_full(sipe_private,
			      "setACE",
			      request,
			      NULL,
			      &sipe_private->deltanum_acl,
			      NULL,
			      NULL);
	g_free(request);
}

/**
 * This request is special:
 * a) it is send from domain URI and not the users
 * b) it has XML nodes outside the [MS-PRES] method node
 * c) doesn't use deltaNum
 */
void sip_soap_directory_search(struct sipe_core_private *sipe_private,
			       guint max,
			       const gchar *rows,
			       SoapTransCallback callback,
			       struct transaction_payload *payload)
{
	gchar *request = g_strdup_printf("<m:filter m:href=\"#searchArray\"/>"
					 "<m:maxResults>%d</m:maxResults>",
					 max);
	gchar *additional = g_strdup_printf("<m:Array m:id=\"searchArray\">"
					      "%s"
					    "</m:Array>",
					    rows);
	sip_soap_request_full(sipe_private,
			      "directorySearch",
			      request,
			      additional,
			      NULL,
			      callback,
			      payload);
	g_free(additional);
	g_free(request);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
