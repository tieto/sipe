/**
 * @file sip-soap.h
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
 */

/* Forward declarations */
struct sipmsg;
struct sipe_core_private;
struct transaction;
struct transaction_payload;

/* Must be the same as sip-transport.h/TransCallback */
typedef gboolean (*SoapTransCallback) (struct sipe_core_private *,
				       struct sipmsg *,
				       struct transaction *);

/**
 * Send raw SOAP request with callback
 *
 * @param sipe_private SIPE core private data
 * @param from         URI to use for SIP transport
 * @param soap         SOAP XML string
 * @param callback     callback function (may be @c NULL)
 * @param payload      callback data     (may be @c NULL)
 */
void sip_soap_raw_request_cb(struct sipe_core_private *sipe_private,
			     const gchar *from,
			     const gchar *soap,
			     SoapTransCallback callback,
			     struct transaction_payload *payload);

/**
 * Send [MS-SIP] SOAP request with callback
 *
 * @param sipe_private SIPE core private data
 * @param method       [MS-PRES] method
 * @param request      [MS-PRES] request data
 * @param callback     callback function (may be @c NULL)
 * @param payload      callback data     (may be @c NULL)
 */
void sip_soap_request_cb(struct sipe_core_private *sipe_private,
			 const gchar *method,
			 const gchar *request,
			 SoapTransCallback callback,
			 struct transaction_payload *payload);

/**
 * Send [MS-SIP] SOAP request
 *
 * @param sipe_private SIPE core private data
 * @param method       [MS-PRES] method
 * @param request      [MS-PRES] request data
 */
void sip_soap_request(struct sipe_core_private *sipe_private,
		      const gchar *method,
		      const gchar *request);

/**
 * Send [MS-SIP] setACE (set ACL for contact) SOAP request (OCS2005)
 *
 * @param sipe_private SIPE core private data
 * @param who          sip: URI of the contact
 * @param allow        allow or deny
 */
void sip_soap_ocs2005_setacl(struct sipe_core_private *sipe_private,
			     const gchar *who,
			     gboolean allow);

/**
 * Send [MS-PRES] directorySearch SOAP request (OCS2007 and older)
 *
 * @param sipe_private SIPE core private data
 * @param max          maximum number of results to return
 * @param rows         XML m:row nodes to add to request
 * @param callback     callback function
 * @param payload      callback data     (may be @c NULL)
 */
void sip_soap_directory_search(struct sipe_core_private *sipe_private,
			       guint max,
			       const gchar *rows,
			       SoapTransCallback callback,
			       struct transaction_payload *payload);

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
