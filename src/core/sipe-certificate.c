/**
 * @file sipe-certificate.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include <glib.h>

#include "sipe-common.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-certificate.h"
#include "sipe-cert-crypto.h"
#include "sipe-digest.h"
#include "sipe-nls.h"
#include "sipe-svc.h"
#include "sipe-tls.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

struct sipe_certificate {
	GHashTable *certificates;
	struct sipe_cert_crypto *backend;
};

void sipe_certificate_free(struct sipe_core_private *sipe_private)
{
	struct sipe_certificate *sc = sipe_private->certificate;

	if (sc) {
		g_hash_table_destroy(sc->certificates);
		sipe_cert_crypto_free(sc->backend);
		g_free(sc);
	}
}

static gboolean sipe_certificate_init(struct sipe_core_private *sipe_private)
{
	struct sipe_certificate *sc;
	struct sipe_cert_crypto *ssc;

	if (sipe_private->certificate)
		return(TRUE);

	ssc = sipe_cert_crypto_init();
	if (!ssc) {
		SIPE_DEBUG_ERROR_NOFORMAT("sipe_certificate_init: crypto backend init FAILED!");
		return(FALSE);
	}

	sc = g_new0(struct sipe_certificate, 1);
	sc->certificates = g_hash_table_new_full(g_str_hash, g_str_equal,
						 g_free,
						 sipe_cert_crypto_destroy);
	sc->backend = ssc;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_certificate_init: DONE");

	sipe_private->certificate = sc;
	return(TRUE);
}

static gchar *create_certreq(struct sipe_core_private *sipe_private,
			     const gchar *subject)
{
	gchar *base64;

	if (!sipe_certificate_init(sipe_private))
		return(NULL);

	SIPE_DEBUG_INFO_NOFORMAT("create_req: generating new certificate request");

	base64 = sipe_cert_crypto_request(sipe_private->certificate->backend,
					  subject);
	if (base64) {
		GString *format = g_string_new(NULL);
		gsize count     = strlen(base64);
		const gchar *p  = base64;

		/* Base64 needs to be formated correctly */
#define CERTREQ_BASE64_LINE_LENGTH 76
		while (count > 0) {
			gsize chunk = count > CERTREQ_BASE64_LINE_LENGTH ?
				CERTREQ_BASE64_LINE_LENGTH : count;
			g_string_append_len(format, p, chunk);
			if (chunk == CERTREQ_BASE64_LINE_LENGTH)
				g_string_append(format, "\r\n");
			count -= chunk;
			p     += chunk;
		}

		/* swap Base64 buffers */
		g_free(base64);
		base64 = format->str;
		g_string_free(format, FALSE);
	}

	return(base64);
}

static void add_certificate(struct sipe_core_private *sipe_private,
			    const gchar *target,
			    gpointer certificate)
{
	struct sipe_certificate *sc = sipe_private->certificate;
	g_hash_table_insert(sc->certificates, g_strdup(target), certificate);
}

gpointer sipe_certificate_tls_dsk_find(struct sipe_core_private *sipe_private,
				       const gchar *target)
{
	struct sipe_certificate *sc = sipe_private->certificate;
	gpointer certificate;

	if (!target || !sc)
		return(NULL);

	certificate = g_hash_table_lookup(sc->certificates, target);

	/* Let's make sure the certificate is still valid for another hour */
	if (!sipe_cert_crypto_valid(certificate, 60 * 60)) {
		SIPE_DEBUG_ERROR("sipe_certificate_tls_dsk_find: certificate for '%s' is invalid",
				 target);
		return(NULL);
	}

	return(certificate);
}

struct certificate_callback_data {
	gchar *target;
	gchar *webticket_negotiate_uri;
	gchar *webticket_fedbearer_uri;
	gchar *certprov_uri;

	gboolean tried_fedbearer;
	gboolean webticket_for_certprov;

	struct sipe_tls_random entropy;
};

static void callback_data_free(struct certificate_callback_data *ccd)
{
	if (ccd) {
		g_free(ccd->target);
		g_free(ccd->webticket_negotiate_uri);
		g_free(ccd->webticket_fedbearer_uri);
		g_free(ccd->certprov_uri);
		sipe_tls_free_random(&ccd->entropy);
		g_free(ccd);
	}
}

static void certificate_failure(struct sipe_core_private *sipe_private,
				const gchar *format,
				const gchar *parameter)
{
	gchar *tmp = g_strdup_printf(format, parameter);
	sipe_backend_connection_error(SIPE_CORE_PUBLIC,
				      SIPE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
				      tmp);
	g_free(tmp);
}

static void get_and_publish_cert(struct sipe_core_private *sipe_private,
				 const gchar *uri,
				 SIPE_UNUSED_PARAMETER const gchar *raw,
				 sipe_xml *soap_body,
				 gpointer callback_data)
{
	struct certificate_callback_data *ccd = callback_data;
	gboolean success = (uri == NULL); /* abort case */

	if (soap_body) {
		gchar *cert_base64 = sipe_xml_data(sipe_xml_child(soap_body,
								  "Body/GetAndPublishCertResponse/RequestSecurityTokenResponse/RequestedSecurityToken/BinarySecurityToken"));

		SIPE_DEBUG_INFO("get_and_publish_cert: received valid SOAP message from service %s",
				uri);

		if (cert_base64) {
			gpointer opaque = sipe_cert_crypto_decode(sipe_private->certificate->backend,
								  cert_base64);

			SIPE_DEBUG_INFO_NOFORMAT("get_and_publish_cert: found certificate");

			if (opaque) {
				add_certificate(sipe_private,
						ccd->target,
						opaque);
				SIPE_DEBUG_INFO("get_and_publish_cert: certificate for target '%s' added",
						ccd->target);

				/* Let's try this again... */
				sip_transport_authentication_completed(sipe_private);
				success = TRUE;
			}

			g_free(cert_base64);
		}

	}

	if (!success) {
		certificate_failure(sipe_private,
				    _("Certificate request to %s failed"),
				    uri);
	}

	callback_data_free(ccd);
}

static gchar *extract_raw_xml_attribute(const gchar *xml,
					const gchar *name)
{
	gchar *attr_start = g_strdup_printf("%s=\"", name);
	gchar *data       = NULL;
	const gchar *start = strstr(xml, attr_start);

	if (start) {
		const gchar *value = start + strlen(attr_start);
		const gchar *end = strchr(value, '"');
		if (end) {
			data = g_strndup(value, end - value);
		}
	}

	g_free(attr_start);
	return(data);
}

static gchar *extract_raw_xml(const gchar *xml,
			      const gchar *tag,
			      gboolean include_tag)
{
	gchar *tag_start = g_strdup_printf("<%s", tag);
	gchar *tag_end   = g_strdup_printf("</%s>", tag);
	gchar *data      = NULL;
	const gchar *start = strstr(xml, tag_start);

	if (start) {
		const gchar *end = strstr(start + strlen(tag_start), tag_end);
		if (end) {
			if (include_tag) {
				data = g_strndup(start, end + strlen(tag_end) - start);
			} else {
				const gchar *tmp = strchr(start + strlen(tag_start), '>') + 1;
				data = g_strndup(tmp, end - tmp);
			}
		}
	}

	g_free(tag_end);
	g_free(tag_start);
	return(data);
}

static gchar *generate_timestamp(const gchar *raw,
				 const gchar *lifetime_tag)
{
	gchar *lifetime = extract_raw_xml(raw, lifetime_tag, FALSE);
	gchar *timestamp = NULL;
	if (lifetime)
		timestamp = g_strdup_printf("<wsu:Timestamp xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"timestamp\">%s</wsu:Timestamp>",
					    lifetime);
	g_free(lifetime);
	return(timestamp);
}

static gchar *generate_fedbearer_wsse(const gchar *raw)
{
	gchar *timestamp = generate_timestamp(raw, "wst:Lifetime");
	gchar *keydata   = extract_raw_xml(raw, "EncryptedData", TRUE);
	gchar *wsse_security = NULL;

	if (timestamp && keydata) {
		SIPE_DEBUG_INFO_NOFORMAT("generate_fedbearer_wsse: found timestamp & keydata");
		wsse_security = g_strconcat(timestamp, keydata, NULL);
	}

	g_free(keydata);
	g_free(timestamp);
	return(wsse_security);
}

static gchar *generate_sha1_proof_wsse(const gchar *raw,
				       struct sipe_tls_random *entropy)
{
	gchar *timestamp = generate_timestamp(raw, "Lifetime");
	gchar *keydata   = extract_raw_xml(raw, "saml:Assertion", TRUE);
	gchar *wsse_security = NULL;

	if (timestamp && keydata) {
		gchar *assertionID = extract_raw_xml_attribute(keydata,
							       "AssertionID");

		/*
		 * WS-Trust 1.3
		 *
		 * http://docs.oasis-open.org/ws-sx/ws-trust/200512/CK/PSHA1:
		 *
		 * "The key is computed using P_SHA1() from the TLS sepcification to generate
		 *  a bit stream using entropy from both sides. The exact form is:
		 *
		 *       key = P_SHA1(Entropy_REQ, Entropy_RES)"
		 */
		gchar *entropy_res_base64 = extract_raw_xml(raw, "BinarySecret", FALSE);
		gsize entropy_res_length;
		guchar *entropy_response = g_base64_decode(entropy_res_base64,
							   &entropy_res_length);
		guchar *key = sipe_tls_p_sha1(entropy->buffer,
					      entropy->length,
					      entropy_response,
					      entropy_res_length,
					      entropy->length);
		g_free(entropy_response);
		g_free(entropy_res_base64);

		SIPE_DEBUG_INFO_NOFORMAT("generate_sha1_proof_wsse: found timestamp & keydata");

		if (assertionID && key) {
			/* same as SIPE_DIGEST_HMAC_SHA1_LENGTH */
			guchar digest[SIPE_DIGEST_SHA1_LENGTH];
			gchar *base64;
			gchar *signed_info;
			gchar *canon;

			SIPE_DEBUG_INFO_NOFORMAT("generate_sha1_proof_wsse: found assertionID and successfully computed the key");

			/* Digest over reference element (#timestamp -> wsu:Timestamp) */
			sipe_digest_sha1((guchar *) timestamp,
					 strlen(timestamp),
					 digest);
			base64 = g_base64_encode(digest,
						 SIPE_DIGEST_SHA1_LENGTH);

			/* XML-Sig: SignedInfo for reference element */
			signed_info = g_strdup_printf("<SignedInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
						      "<CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
						      "<SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#hmac-sha1\"/>"
						      "<Reference URI=\"#timestamp\">"
						      "<Transforms>"
						      "<Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>"
						      "</Transforms>"
						      "<DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>"
						      "<DigestValue>%s</DigestValue>"
						      "</Reference>"
						      "</SignedInfo>",
						      base64);
			g_free(base64);

			/* XML-Sig: SignedInfo in canonical form */
			canon = sipe_xml_exc_c14n(signed_info);
			g_free(signed_info);

			if (canon) {
				gchar *signature;

				/* calculate signature */
				sipe_digest_hmac_sha1(key, entropy->length,
						      (guchar *)canon,
						      strlen(canon),
						      digest);
				base64 = g_base64_encode(digest,
							 SIPE_DIGEST_HMAC_SHA1_LENGTH);

				/* XML-Sig: Signature from SignedInfo + Key */
				signature = g_strdup_printf("<Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">"
							    " %s"
							    " <SignatureValue>%s</SignatureValue>"
							    " <KeyInfo>"
							    "  <wsse:SecurityTokenReference wsse:TokenType=\"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.1#SAMLV1.1\">"
							    "   <wsse:KeyIdentifier ValueType=\"http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID\">%s</wsse:KeyIdentifier>"
							    "  </wsse:SecurityTokenReference>"
							    " </KeyInfo>"
							    "</Signature>",
							    canon,
							    base64,
							    assertionID);
				g_free(base64);
				g_free(canon);

				wsse_security = g_strconcat(timestamp,
							    keydata,
							    signature,
							    NULL);
				g_free(signature);
			}

		}

		g_free(key);
		g_free(assertionID);
	}

	g_free(keydata);
	g_free(timestamp);
	return(wsse_security);
}

static void webticket_token(struct sipe_core_private *sipe_private,
			    const gchar *uri,
			    const gchar *raw,
			    sipe_xml *soap_body,
			    gpointer callback_data)
{
	struct certificate_callback_data *ccd = callback_data;
	gboolean success = (uri == NULL); /* abort case */

	if (soap_body) {
		/* WebTicket for Certificate Provisioning Service */
		if (ccd->webticket_for_certprov) {
			gchar *wsse_security = generate_sha1_proof_wsse(raw,
									&ccd->entropy);

			if (wsse_security) {
				gchar *certreq_base64 = create_certreq(sipe_private,
								       sipe_private->username);

				SIPE_DEBUG_INFO("webticket_token: received valid SOAP message from service %s",
						uri);

				if (certreq_base64) {

					SIPE_DEBUG_INFO_NOFORMAT("webticket_token: created certificate request");

					success = sipe_svc_get_and_publish_cert(sipe_private,
										ccd->certprov_uri,
										wsse_security,
										certreq_base64,
										get_and_publish_cert,
										ccd);
					if (success) {
						/* callback data passed down the line */
						ccd = NULL;
					}
					g_free(certreq_base64);
				}
				g_free(wsse_security);
			}

		/* WebTicket for federated authentication */
		} else {
			gchar *wsse_security = generate_fedbearer_wsse(raw);

			if (wsse_security) {

				SIPE_DEBUG_INFO("webticket_token: received valid SOAP message from service %s",
						uri);

				success = sipe_svc_webticket(sipe_private,
							     ccd->webticket_fedbearer_uri,
							     wsse_security,
							     ccd->certprov_uri,
							     &ccd->entropy,
							     webticket_token,
							     ccd);
				ccd->webticket_for_certprov = TRUE;

				if (success) {
					/* callback data passed down the line */
					ccd = NULL;
				}
				g_free(wsse_security);
			}
		}

	} else if (uri) {
		/* Retry with federated authentication? */
		success = ccd->webticket_fedbearer_uri && !ccd->tried_fedbearer;
		if (success) {
			SIPE_DEBUG_INFO("webticket_token: anonymous authentication to service %s failed, retrying with federated authentication",
					uri);

			ccd->tried_fedbearer = TRUE;
			success = sipe_svc_webticket_lmc(sipe_private,
							 ccd->webticket_fedbearer_uri,
							 webticket_token,
							 ccd);
			ccd->webticket_for_certprov = FALSE;

			if (success) {
				/* callback data passed down the line */
				ccd = NULL;
			}
		}
	}

	if (!success) {
		certificate_failure(sipe_private,
				    _("Web ticket request to %s failed"),
				    uri);
	}

	callback_data_free(ccd);
}

static void webticket_metadata(struct sipe_core_private *sipe_private,
			       const gchar *uri,
			       SIPE_UNUSED_PARAMETER const gchar *raw,
			       sipe_xml *metadata,
			       gpointer callback_data)
{
	struct certificate_callback_data *ccd = callback_data;

	if (metadata) {
		const sipe_xml *node;

		SIPE_DEBUG_INFO("webticket_metadata: metadata for service %s retrieved successfully",
				uri);

		/* Authentication ports accepted by WebTicket Service */
		for (node = sipe_xml_child(metadata, "service/port");
		     node;
		     node = sipe_xml_twin(node)) {
			const gchar *auth_uri = sipe_xml_attribute(sipe_xml_child(node,
										  "address"),
								   "location");

			if (auth_uri) {
				if (sipe_strcase_equal(sipe_xml_attribute(node, "name"),
						       "WebTicketServiceWinNegotiate")) {
					SIPE_DEBUG_INFO("webticket_metadata: WebTicket Windows Negotiate Auth URI %s", auth_uri);
					g_free(ccd->webticket_negotiate_uri);
					ccd->webticket_negotiate_uri = g_strdup(auth_uri);
				} else if (sipe_strcase_equal(sipe_xml_attribute(node, "name"),
							      "WsFedBearer")) {
					SIPE_DEBUG_INFO("webticket_metadata: WebTicket FedBearer Auth URI %s", auth_uri);
					g_free(ccd->webticket_fedbearer_uri);
					ccd->webticket_fedbearer_uri = g_strdup(auth_uri);
				}
			}
		}

		if (ccd->webticket_negotiate_uri || ccd->webticket_fedbearer_uri) {
			gboolean success;

			/* Entropy: 256 random bits */
			if (!ccd->entropy.buffer)
				sipe_tls_fill_random(&ccd->entropy, 256);

			if (ccd->webticket_negotiate_uri) {
				/* Try Negotiate authentication first */

				success = sipe_svc_webticket(sipe_private,
							     ccd->webticket_negotiate_uri,
							     NULL,
							     ccd->certprov_uri,
							     &ccd->entropy,
							     webticket_token,
							     ccd);
				ccd->webticket_for_certprov = TRUE;
			} else {
				ccd->tried_fedbearer = TRUE;
				success = sipe_svc_webticket_lmc(sipe_private,
								 ccd->webticket_fedbearer_uri,
								 webticket_token,
								 ccd);
				ccd->webticket_for_certprov = FALSE;
			}

			if (success) {
				/* callback data passed down the line */
				ccd = NULL;
			} else {
				certificate_failure(sipe_private,
						    _("Can't request security token from %s"),
						    ccd->webticket_negotiate_uri ? ccd->webticket_negotiate_uri : ccd->webticket_fedbearer_uri);
			}

		} else {
			certificate_failure(sipe_private,
					    _("Can't find the authentication port for TLS-DSK web ticket URI %s"),
					    uri);
		}

	} else if (uri) {
		certificate_failure(sipe_private,
				    _("Can't retrieve metadata for TLS-DSK web ticket URI %s"),
				    uri);
	}

	callback_data_free(ccd);
}

static void certprov_metadata(struct sipe_core_private *sipe_private,
			      const gchar *uri,
			      SIPE_UNUSED_PARAMETER const gchar *raw,
			      sipe_xml *metadata,
			      gpointer callback_data)
{
	struct certificate_callback_data *ccd = callback_data;

	if (metadata) {
		const sipe_xml *node;
		gchar *ticket_uri = NULL;

		SIPE_DEBUG_INFO("certprov_metadata: metadata for service %s retrieved successfully",
				uri);

		/* WebTicket policies accepted by Certificate Provisioning Service */
		for (node = sipe_xml_child(metadata, "Policy");
		     node;
		     node = sipe_xml_twin(node)) {
			if (sipe_strcase_equal(sipe_xml_attribute(node, "Id"),
					       "CertProvisioningServiceWebTicketProof_SHA1_policy")) {

				SIPE_DEBUG_INFO_NOFORMAT("certprov_metadata: WebTicket policy found");

				ticket_uri = sipe_xml_data(sipe_xml_child(node,
									  "ExactlyOne/All/EndorsingSupportingTokens/Policy/IssuedToken/Issuer/Address"));
				if (ticket_uri) {
					SIPE_DEBUG_INFO("certprov_metadata: WebTicket URI %s", ticket_uri);
				} else {
					certificate_failure(sipe_private,
							    _("Can't find the web ticket URI for TLS-DSK certificate provisioning URI %s"),
							    uri);
				}
				break;
			}
		}

		if (ticket_uri) {

			/* Authentication ports accepted by Certificate Provisioning Service */
			for (node = sipe_xml_child(metadata, "service/port");
			     node;
			     node = sipe_xml_twin(node)) {
				if (sipe_strcase_equal(sipe_xml_attribute(node, "name"),
						       "CertProvisioningServiceWebTicketProof_SHA1")) {
					const gchar *auth_uri;

					SIPE_DEBUG_INFO_NOFORMAT("certprov_metadata: authentication port found");

					auth_uri = sipe_xml_attribute(sipe_xml_child(node,
										     "address"),
								      "location");
					if (auth_uri) {
						SIPE_DEBUG_INFO("certprov_metadata: CertProv Auth URI %s", auth_uri);

						if (sipe_svc_metadata(sipe_private,
								      ticket_uri,
								      webticket_metadata,
								      ccd)) {
							/* Remember for later */
							ccd->certprov_uri = g_strdup(auth_uri);

							/* callback data passed down the line */
							ccd = NULL;
						} else {
							certificate_failure(sipe_private,
									    _("Can't request metadata from %s"),
									    ticket_uri);
						}
					}
					break;
				}
			}

			g_free(ticket_uri);

			if (!node) {
				certificate_failure(sipe_private,
						    _("Can't find the authentication port for TLS-DSK certificate provisioning URI %s"),
						    uri);
			}

		} else {
			certificate_failure(sipe_private,
					    _("Can't find the web ticket policy for TLS-DSK certificate provisioning URI %s"),
					    uri);
		}

	} else if (uri) {
		certificate_failure(sipe_private,
				    _("Can't retrieve metadata for TLS-DSK certificate provisioning URI %s"),
				    uri);
	}

	callback_data_free(ccd);
}

gboolean sipe_certificate_tls_dsk_generate(struct sipe_core_private *sipe_private,
					   const gchar *target,
					   const gchar *uri)
{
	struct certificate_callback_data *ccd = g_new0(struct certificate_callback_data, 1);
	gboolean ret;

	ccd->target   = g_strdup(target);

	ret = sipe_svc_metadata(sipe_private, uri, certprov_metadata, ccd);
	if (!ret)
		callback_data_free(ccd);

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
