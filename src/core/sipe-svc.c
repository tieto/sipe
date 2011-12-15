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

#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "sipe-common.h"
#include "http-conn.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-svc.h"
#include "sipe-tls.h"
#include "sipe-utils.h"
#include "sipe-xml.h"
#include "uuid.h"

/* forward declaration */
struct svc_request;
typedef void (svc_callback)(struct svc_request *data,
			    const gchar *raw,
			    sipe_xml *xml);

struct svc_request {
	struct sipe_core_private *sipe_private;
	svc_callback *internal_cb;
	sipe_svc_callback *cb;
	gpointer *cb_data;
	HttpConn *conn;
	HttpConnAuth auth;
	gchar *uri;
	gchar *soap_action;
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
		(*data->cb)(data->sipe_private, NULL, NULL, NULL, data->cb_data);
	g_free(data->soap_action);
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
		(*data->internal_cb)(data, body, xml);
		sipe_xml_free(xml);
	} else {
		/* Internal callback: failed */
		(*data->internal_cb)(data, NULL, NULL);
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
				       const gchar *soap_action,
				       const gchar *body,
				       svc_callback *internal_callback,
				       sipe_svc_callback *callback,
				       gpointer callback_data)
{
	struct svc_request *data = g_new0(struct svc_request, 1);
	gboolean ret = FALSE;

	data->sipe_private = sipe_private;
	data->uri          = g_strdup(uri);

	if (soap_action)
		data->soap_action = g_strdup_printf("SOAPAction: \"%s\"\r\n",
						    soap_action);

	/* re-use SIP credentials */
	data->auth.domain   = sipe_private->authdomain;
	data->auth.user     = sipe_private->authuser ? sipe_private->authuser : sipe_private->username;
	data->auth.password = sipe_private->password;

	data->conn = http_conn_create(SIPE_CORE_PUBLIC,
				      NULL, /* HttpSession */
				      method,
				      HTTP_CONN_SSL,
				      HTTP_CONN_NO_REDIRECT,
				      uri,
				      body,
				      content_type,
				      data->soap_action,
				      &data->auth,
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
				      const gchar *additional_ns,
				      const gchar *soap_action,
				      const gchar *wsse_security,
				      const gchar *soap_body,
				      svc_callback *internal_callback,
				      sipe_svc_callback *callback,
				      gpointer callback_data)
{
	/* Only generate SOAP header if we have a security token */
	gchar *soap_header = wsse_security ?
		g_strdup_printf("<soap:Header>"
				" <wsa:To>%s</wsa:To>"
				" <wsa:ReplyTo>"
				"  <wsa:Address>http://www.w3.org/2005/08/addressing/anonymous</wsa:Address>"
				" </wsa:ReplyTo>"
				" <wsa:Action>%s</wsa:Action>"
				" <wsse:Security>%s</wsse:Security>"
				"</soap:Header>",
				uri,
				soap_action,
				wsse_security) :
		g_strdup("");
	gchar *body = g_strdup_printf("<?xml version=\"1.0\"?>\r\n"
				      "<soap:Envelope %s"
				      " xmlns:auth=\"http://schemas.xmlsoap.org/ws/2006/12/authorization\""
				      " xmlns:wsa=\"http://www.w3.org/2005/08/addressing\""
				      " xmlns:wsp=\"http://schemas.xmlsoap.org/ws/2004/09/policy\""
				      " xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\""
				      " xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\""
				      " >"
				      "%s"
				      " <soap:Body>%s</soap:Body>"
				      "</soap:Envelope>",
				      additional_ns,
				      soap_header,
				      soap_body);

	gboolean ret = sipe_svc_https_request(sipe_private,
					      HTTP_CONN_POST,
					      uri,
					      "text/xml",
					      soap_action,
					      body,
					      internal_callback,
					      callback,
					      callback_data);
	g_free(soap_header);
	g_free(body);

	return(ret);
}

static gboolean new_soap_req(struct sipe_core_private *sipe_private,
			     const gchar *uri,
			     const gchar *soap_action,
			     const gchar *wsse_security,
			     const gchar *soap_body,
			     svc_callback *internal_callback,
			     sipe_svc_callback *callback,
			     gpointer callback_data)
{
	return(sipe_svc_wsdl_request(sipe_private,
				     uri,
				     "xmlns:saml=\"urn:oasis:names:tc:SAML:1.0:assertion\" "
				     "xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" "
				     "xmlns:wst=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\"",
				     soap_action,
				     wsse_security,
				     soap_body,
				     internal_callback,
				     callback,
				     callback_data));
}

static void sipe_svc_wsdl_response(struct svc_request *data,
				   const gchar *raw,
				   sipe_xml *xml)
{
	if (xml) {
		/* Callback: success */
		(*data->cb)(data->sipe_private, data->uri, raw, xml, data->cb_data);
	} else {
		/* Callback: failed */
		(*data->cb)(data->sipe_private, data->uri, NULL, NULL, data->cb_data);
	}
}

gboolean sipe_svc_get_and_publish_cert(struct sipe_core_private *sipe_private,
				       const gchar *uri,
				       const gchar *wsse_security,
				       const gchar *certreq,
				       sipe_svc_callback *callback,
				       gpointer callback_data)
{
	struct sipe_tls_random id;
	gchar *id_base64;
	gchar *id_uuid;
	gchar *uuid = get_uuid(sipe_private);
	gchar *soap_body;
	gboolean ret;

	/* random request ID */
	sipe_tls_fill_random(&id, 256);
	id_base64 = g_base64_encode(id.buffer, id.length);
	sipe_tls_free_random(&id);
	id_uuid = generateUUIDfromEPID(id_base64);
	g_free(id_base64);

	soap_body = g_strdup_printf("<GetAndPublishCert"
				    " xmlns=\"http://schemas.microsoft.com/OCS/AuthWebServices/\""
				    " xmlns:wst=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512/\""
				    " xmlns:wstep=\"http://schemas.microsoft.com/windows/pki/2009/01/enrollment\""
				    " DeviceId=\"{%s}\""
				    " Entity=\"%s\""
				    ">"
				    " <wst:RequestSecurityToken>"
				    "  <wst:TokenType>http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3</wst:TokenType>"
				    "  <wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>"
				    "  <wsse:BinarySecurityToken"
				    "   ValueType=\"http://schemas.microsoft.com/OCS/AuthWebServices.xsd#PKCS10\""
				    "   EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#Base64Binary\""
				    "  >\r\n%s</wsse:BinarySecurityToken>"
				    "  <wstep:RequestID>%s</wstep:RequestID>"
				    " </wst:RequestSecurityToken>"
				    "</GetAndPublishCert>",
				    uuid,
				    sipe_private->username,
				    certreq,
				    id_uuid);
	g_free(id_uuid);
	g_free(uuid);

	ret = new_soap_req(sipe_private,
			   uri,
			   "http://schemas.microsoft.com/OCS/AuthWebServices/GetAndPublishCert",
			   wsse_security,
			   soap_body,
			   sipe_svc_wsdl_response,
			   callback,
			   callback_data);
	g_free(soap_body);

	return(ret);
}

gboolean sipe_svc_ab_entry_request(struct sipe_core_private *sipe_private,
				   const gchar *uri,
				   const gchar *wsse_security,
				   const gchar *search,
				   guint entries,
				   guint max_returns,
				   sipe_svc_callback *callback,
				   gpointer callback_data)
{
	gboolean ret;
	gchar *soap_body = g_strdup_printf("<SearchAbEntry"
					   " xmlns=\"DistributionListExpander\""
					   " xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""
					   " xmlns:soapenc=\"http://schemas.xmlsoap.org/soap/encoding/\""
					   ">"
					   " <AbEntryRequest>"
					   "  <ChangeSearch xmlns:q1=\"DistributionListExpander\" soapenc:arrayType=\"q1:AbEntryRequest.ChangeSearchQuery[%d]\">"
					   "   %s"
					   "  </ChangeSearch>"
					   "  <Metadata>"
					   "   <FromDialPad>false</FromDialPad>"
					   "   <MaxResultNum>%d</MaxResultNum>"
					   "   <ReturnList>displayName,msRTCSIP-PrimaryUserAddress,title,telephoneNumber,homePhone,mobile,otherTelephone,mail,company,country</ReturnList>"
					   "  </Metadata>"
					   " </AbEntryRequest>"
					   "</SearchAbEntry>",
					   entries,
					   search,
					   max_returns);

	ret = new_soap_req(sipe_private,
			   uri,
			   "DistributionListExpander/IAddressBook/SearchAbEntry",
			   wsse_security,
			   soap_body,
			   sipe_svc_wsdl_response,
			   callback,
			   callback_data);
	g_free(soap_body);

	return(ret);
}

/*
 * This functions encodes what the Microsoft Lync client does for
 * Office365 accounts. It will most definitely fail for internal Lync
 * installation that use TLS-DSK instead of NTLM.
 *
 * But for those anonymous authentication should already have succeeded.
 * I guess we'll have to see what happens in real life...
 */
gboolean sipe_svc_webticket_lmc(struct sipe_core_private *sipe_private,
				const gchar *service_uri,
				sipe_svc_callback *callback,
				gpointer callback_data)
{
	/* login.microsoftonline.com seems only to accept cleartext passwords :/ */
	gchar *security = g_strdup_printf("<wsse:UsernameToken>"
					  " <wsse:Username>%s</wsse:Username>"
					  " <wsse:Password>%s</wsse:Password>"
					  "</wsse:UsernameToken>",
					  sipe_private->username,
					  sipe_private->password);

	gchar *soap_body = g_strdup_printf("<ps:RequestMultipleSecurityTokens>"
					   " <wst:RequestSecurityToken>"
					   "  <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>"
					   "  <wsp:AppliesTo>"
					   "   <wsa:EndpointReference>"
					   "    <wsa:Address>%s</wsa:Address>"
					   "   </wsa:EndpointReference>"
					   "  </wsp:AppliesTo>"
					   " </wst:RequestSecurityToken>"
					   "</ps:RequestMultipleSecurityTokens>",
					   service_uri);

	gboolean ret = sipe_svc_wsdl_request(sipe_private,
					     "https://login.microsoftonline.com:443/RST2.srf",
					     "xmlns:ps=\"http://schemas.microsoft.com/Passport/SoapServices/PPCRL\" "
					     "xmlns:soap=\"http://www.w3.org/2003/05/soap-envelope\" "
					     "xmlns:wst=\"http://schemas.xmlsoap.org/ws/2005/02/trust\"",
					     "http://schemas.xmlsoap.org/ws/2005/02/trust/RST/Issue",
					     security,
					     soap_body,
					     sipe_svc_wsdl_response,
					     callback,
					     callback_data);
	g_free(soap_body);
	g_free(security);

	return(ret);
}

gboolean sipe_svc_webticket(struct sipe_core_private *sipe_private,
			    const gchar *uri,
			    const gchar *wsse_security,
			    const gchar *service_uri,
			    const struct sipe_tls_random *entropy,
			    sipe_svc_callback *callback,
			    gpointer callback_data)
{
	gchar *uuid = get_uuid(sipe_private);
	gchar *security = NULL;
	gchar *secret = g_base64_encode(entropy->buffer, entropy->length);
	gchar *soap_body = g_strdup_printf("<wst:RequestSecurityToken Context=\"%s\">"
					   " <wst:TokenType>http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1</wst:TokenType>"
					   " <wst:RequestType>http://schemas.xmlsoap.org/ws/2005/02/trust/Issue</wst:RequestType>"
					   " <wsp:AppliesTo>"
					   "  <wsa:EndpointReference>"
					   "   <wsa:Address>%s</wsa:Address>"
					   "  </wsa:EndpointReference>"
					   " </wsp:AppliesTo>"
					   " <wst:Claims Dialect=\"urn:component:Microsoft.Rtc.WebAuthentication.2010:authclaims\">"
					   "  <auth:ClaimType Uri=\"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/uri\" Optional=\"false\">"
					   "   <auth:Value>sip:%s</auth:Value>"
					   "  </auth:ClaimType>"
					   " </wst:Claims>"
					   " <wst:Entropy>"
					   "  <wst:BinarySecret>%s</wst:BinarySecret>"
					   " </wst:Entropy>"
					   " <wst:KeyType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/SymmetricKey</wst:KeyType>"
					   "</wst:RequestSecurityToken>",
					   uuid,
					   service_uri,
					   sipe_private->username,
					   secret);

	gboolean ret = new_soap_req(sipe_private,
				    uri,
				    "http://docs.oasis-open.org/ws-sx/ws-trust/200512/RST/Issue",
				    wsse_security,
				    soap_body,
				    sipe_svc_wsdl_response,
				    callback,
				    callback_data);
	g_free(soap_body);
	g_free(secret);
	g_free(security);
	g_free(uuid);

	return(ret);
}

static void sipe_svc_metadata_response(struct svc_request *data,
				       const gchar *raw,
				       sipe_xml *xml)
{
	if (xml) {
		/* Callback: success */
		(*data->cb)(data->sipe_private, data->uri, raw, xml, data->cb_data);
	} else {
		/* Callback: failed */
		(*data->cb)(data->sipe_private, data->uri, NULL, NULL, data->cb_data);
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
					      NULL,
					      NULL,
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
