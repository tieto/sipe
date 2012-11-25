/**
 * @file sipe-webticket.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-12 SIPE Project <http://sipe.sourceforge.net/>
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
 *   - [MS-OCAUTHWS]: http://msdn.microsoft.com/en-us/library/ff595592.aspx
 *   - MS Tech-Ed Europe 2010 "UNC310: Microsoft Lync 2010 Technology Explained"
 *     http://ecn.channel9.msdn.com/o9/te/Europe/2010/pptx/unc310.pptx
 */

#include <string.h>
#include <time.h>

#include <glib.h>

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-digest.h"
#include "sipe-svc.h"
#include "sipe-tls.h"
#include "sipe-webticket.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

struct webticket_queued_data {
	sipe_webticket_callback *callback;
	gpointer callback_data;
};

struct webticket_callback_data {
	gchar *service_uri;
	const gchar *service_port;
	gchar *service_auth_uri;

	gchar *webticket_negotiate_uri;
	gchar *webticket_fedbearer_uri;

	gboolean tried_fedbearer;
	gboolean webticket_for_federation;
	gboolean webticket_for_service;
	gboolean requires_signing;

	struct sipe_tls_random entropy;

	sipe_webticket_callback *callback;
	gpointer callback_data;

	struct sipe_svc_session *session;

	GSList *queued;
};

struct webticket_token {
	gchar *auth_uri;
	gchar *token;
	time_t expires;
};

struct sipe_webticket {
	GHashTable *cache;
	GHashTable *pending;
};

void sipe_webticket_free(struct sipe_core_private *sipe_private)
{
	struct sipe_webticket *webticket = sipe_private->webticket;
	if (!webticket)
		return;

	if (webticket->pending)
		g_hash_table_destroy(webticket->pending);
	if (webticket->cache)
		g_hash_table_destroy(webticket->cache);
	g_free(webticket);
	sipe_private->webticket = NULL;
}

static void free_token(gpointer data)
{
	struct webticket_token *wt = data;
	g_free(wt->auth_uri);
	g_free(wt->token);
	g_free(wt);
}

static void sipe_webticket_init(struct sipe_core_private *sipe_private)
{
	struct sipe_webticket *webticket;

	if (sipe_private->webticket)
		return;

	sipe_private->webticket = webticket = g_new0(struct sipe_webticket, 1);

	webticket->cache   = g_hash_table_new_full(g_str_hash,
						   g_str_equal,
						   g_free,
						   free_token);
	webticket->pending = g_hash_table_new(g_str_hash,
					      g_str_equal);
}

/* takes ownership of "token" */
static void cache_token(struct sipe_core_private *sipe_private,
			const gchar *service_uri,
			const gchar *auth_uri,
			gchar *token,
			time_t expires)
{
	struct webticket_token *wt = g_new0(struct webticket_token, 1);
	wt->auth_uri = g_strdup(auth_uri);
	wt->token    = token;
	wt->expires  = expires;
	g_hash_table_insert(sipe_private->webticket->cache,
			    g_strdup(service_uri),
			    wt);
}

static const struct webticket_token *cache_hit(struct sipe_core_private *sipe_private,
					       const gchar *service_uri)
{
	const struct webticket_token *wt;

	sipe_webticket_init(sipe_private);

	/* make sure a cached Web Ticket is still valid for 60 seconds */
	wt = g_hash_table_lookup(sipe_private->webticket->cache,
				 service_uri);
	if (wt && (wt->expires < time(NULL) + 60)) {
		SIPE_DEBUG_INFO("cache_hit: cached token for URI %s has expired",
				service_uri);
		wt = NULL;
	}

	return(wt);
}

/* frees just the main request data, when this is called "queued" is cleared */
static void callback_data_free(struct webticket_callback_data *wcd)
{
	if (wcd) {
		sipe_tls_free_random(&wcd->entropy);
		g_free(wcd->webticket_negotiate_uri);
		g_free(wcd->webticket_fedbearer_uri);
		g_free(wcd->service_auth_uri);
		g_free(wcd->service_uri);
		g_free(wcd);
	}
}

static void queue_request(struct webticket_callback_data *wcd,
			  sipe_webticket_callback *callback,
			  gpointer callback_data)
{
	struct webticket_queued_data *wqd = g_new0(struct webticket_queued_data, 1);

	wqd->callback      = callback;
	wqd->callback_data = callback_data;

	wcd->queued = g_slist_prepend(wcd->queued, wqd);
}

static void callback_execute(struct sipe_core_private *sipe_private,
			     struct webticket_callback_data *wcd,
			     const gchar *auth_uri,
			     const gchar *wsse_security,
			     const gchar *failure_msg)
{
	GSList *entry = wcd->queued;

	/* complete main request */
	wcd->callback(sipe_private,
		      wcd->service_uri,
		      auth_uri,
		      wsse_security,
		      failure_msg,
		      wcd->callback_data);

	/* complete queued requests */
	while (entry) {
		struct webticket_queued_data *wqd = entry->data;

		SIPE_DEBUG_INFO("callback_execute: completing queue request URI %s (Auth URI %s)",
				wcd->service_uri, auth_uri);
		wqd->callback(sipe_private,
			      wcd->service_uri,
			      auth_uri,
			      wsse_security,
			      failure_msg,
			      wqd->callback_data);

		g_free(wqd);
		entry = entry->next;
	}
	g_slist_free(wcd->queued);

	/* drop request from pending hash */
	g_hash_table_remove(sipe_private->webticket->pending,
			    wcd->service_uri);
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

static gchar *generate_timestamp(const gchar *raw,
				 const gchar *lifetime_tag)
{
	gchar *lifetime = sipe_xml_extract_raw(raw, lifetime_tag, FALSE);
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
	gchar *keydata   = sipe_xml_extract_raw(raw, "EncryptedData", TRUE);
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
				       struct sipe_tls_random *entropy,
				       time_t *expires)
{
	gchar *timestamp = generate_timestamp(raw, "Lifetime");
	gchar *keydata   = sipe_xml_extract_raw(raw, "saml:Assertion", TRUE);
	gchar *wsse_security = NULL;

	if (timestamp && keydata) {
		gchar *expires_string = sipe_xml_extract_raw(timestamp,
							     "Expires",
							     FALSE);

		if (entropy) {
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
			gchar *entropy_res_base64 = sipe_xml_extract_raw(raw, "BinarySecret", FALSE);
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
		} else {
			/* token doesn't require signature */
			SIPE_DEBUG_INFO_NOFORMAT("generate_sha1_proof_wsse: found timestamp & keydata, no signing required");
			wsse_security = g_strconcat(timestamp,
						    keydata,
						    NULL);
		}

		*expires = 0;
		if (expires_string) {
			*expires = sipe_utils_str_to_time(expires_string);
			g_free(expires_string);
		}
	}

	g_free(keydata);
	g_free(timestamp);
	return(wsse_security);
}

static gboolean initiate_fedbearer(struct sipe_core_private *sipe_private,
				   struct webticket_callback_data *wcd);
static void webticket_token(struct sipe_core_private *sipe_private,
			    const gchar *uri,
			    const gchar *raw,
			    sipe_xml *soap_body,
			    gpointer callback_data)
{
	struct webticket_callback_data *wcd = callback_data;
	gboolean failed = TRUE;

	if (soap_body) {
		/* WebTicket for Web Service */
		if (wcd->webticket_for_service) {
			time_t expires;
			gchar *wsse_security = generate_sha1_proof_wsse(raw,
									wcd->requires_signing ? &wcd->entropy : NULL,
									&expires);

			if (wsse_security) {
				/* cache takes ownership of wsse_security */
				cache_token(sipe_private,
					    wcd->service_uri,
					    wcd->service_auth_uri,
					    wsse_security,
					    expires);
				callback_execute(sipe_private,
						 wcd,
						 wcd->service_auth_uri,
						 wsse_security,
						 NULL);
				failed = FALSE;
			}

		/* WebTicket from ADFS for federared authentication */
		} else if (wcd->webticket_for_federation) {
			time_t expires;
			gchar *wsse_security = generate_sha1_proof_wsse(raw,
									NULL,
									&expires);

			if (wsse_security) {

				SIPE_DEBUG_INFO("webticket_token: received valid SOAP message from ADFS %s",
						uri);

				if (sipe_svc_webticket_lmc_federated(sipe_private,
								     wcd->session,
								     wsse_security,
								     wcd->webticket_fedbearer_uri,
								     webticket_token,
								     wcd)) {
					wcd->webticket_for_service = TRUE;

					/* callback data passed down the line */
					wcd = NULL;
				}
				g_free(wsse_security);
			}

		/* WebTicket for federated authentication */
		} else {
			gchar *wsse_security = generate_fedbearer_wsse(raw);

			if (wsse_security) {

				SIPE_DEBUG_INFO("webticket_token: received valid SOAP message from service %s",
						uri);

				if (sipe_svc_webticket(sipe_private,
						       wcd->session,
						       wcd->webticket_fedbearer_uri,
						       wsse_security,
						       wcd->service_auth_uri,
						       &wcd->entropy,
						       webticket_token,
						       wcd)) {
					wcd->webticket_for_service = TRUE;

					/* callback data passed down the line */
					wcd = NULL;
				}
				g_free(wsse_security);
			}
		}

	} else if (uri) {
		/* Retry with federated authentication? */
		if (wcd->webticket_fedbearer_uri && !wcd->tried_fedbearer) {
			SIPE_DEBUG_INFO("webticket_token: anonymous authentication to service %s failed, retrying with federated authentication",
					uri);

			if (initiate_fedbearer(sipe_private, wcd)) {
				/* callback data passed down the line */
				wcd = NULL;
			}
		}
	}

	if (wcd) {
		if (failed) {
			gchar *failure_msg = NULL;

			if (soap_body) {
				failure_msg = sipe_xml_data(sipe_xml_child(soap_body,
									   "Body/Fault/Detail/error/internalerror/text"));
				/* XML data can end in &#x000D;&#x000A; */
				g_strstrip(failure_msg);
			}

			callback_execute(sipe_private,
					 wcd,
					 uri,
					 NULL,
					 failure_msg);
			g_free(failure_msg);
		}
		callback_data_free(wcd);
	}
}

static void realminfo(struct sipe_core_private *sipe_private,
		      const gchar *uri,
		      SIPE_UNUSED_PARAMETER const gchar *raw,
		      sipe_xml *realminfo,
		      gpointer callback_data)
{
	struct webticket_callback_data *wcd = callback_data;
	gboolean failed = FALSE;

	if (realminfo) {
		/* detect ADFS setup. See also:
		 *
		 *   http://en.wikipedia.org/wiki/Active_Directory_Federation_Services
		 *
		 * NOTE: this is based on observed behaviour.
		 *       It is unkown if this is documented somewhere...
		 */
		gchar *sts_auth_url = sipe_xml_data(sipe_xml_child(realminfo,
								   "STSAuthURL"));

		SIPE_DEBUG_INFO("realminfo: data for user %s retrieved successfully",
				sipe_private->username);

		if (sts_auth_url) {

			SIPE_DEBUG_INFO("realminfo: ADFS setup detected: %s",
					sts_auth_url);

			if (sipe_svc_webticket_adfs(sipe_private,
						    wcd->session,
						    sts_auth_url,
						    webticket_token,
						    wcd)) {
				wcd->webticket_for_federation = TRUE;

				/* callback data passed down the line */
				wcd = NULL;
			} else
				failed = TRUE;

			g_free(sts_auth_url);
		}
	}

	/* don't fail if we didn't receive valid RealmInfo XML data */
	if (wcd && !failed) {

		SIPE_DEBUG_INFO_NOFORMAT("realminfo: no RealmInfo found or no ADFS setup detected - try direct login");

		if (sipe_svc_webticket_lmc(sipe_private,
					   wcd->session,
					   wcd->webticket_fedbearer_uri,
					   webticket_token,
					   wcd)) {
			/* callback data passed down the line */
			wcd = NULL;
		}
	}

	if (wcd) {
		callback_execute(sipe_private,
				 wcd,
				 uri,
				 NULL,
				 NULL);
		callback_data_free(wcd);
	}
}

static gboolean initiate_fedbearer(struct sipe_core_private *sipe_private,
				   struct webticket_callback_data *wcd)
{
	gboolean success = sipe_svc_realminfo(sipe_private,
					      wcd->session,
					      realminfo,
					      wcd);
	wcd->tried_fedbearer          = TRUE;
	wcd->webticket_for_federation = FALSE;
	wcd->webticket_for_service    = FALSE;

	return(success);
}

static void webticket_metadata(struct sipe_core_private *sipe_private,
			       const gchar *uri,
			       SIPE_UNUSED_PARAMETER const gchar *raw,
			       sipe_xml *metadata,
			       gpointer callback_data)
{
	struct webticket_callback_data *wcd = callback_data;

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
					g_free(wcd->webticket_negotiate_uri);
					wcd->webticket_negotiate_uri = g_strdup(auth_uri);
				} else if (sipe_strcase_equal(sipe_xml_attribute(node, "name"),
							      "WsFedBearer")) {
					SIPE_DEBUG_INFO("webticket_metadata: WebTicket FedBearer Auth URI %s", auth_uri);
					g_free(wcd->webticket_fedbearer_uri);
					wcd->webticket_fedbearer_uri = g_strdup(auth_uri);
				}
			}
		}

		if (wcd->webticket_negotiate_uri || wcd->webticket_fedbearer_uri) {
			gboolean success;

			/* Entropy: 256 random bits */
			if (!wcd->entropy.buffer)
				sipe_tls_fill_random(&wcd->entropy, 256);

			if (wcd->webticket_negotiate_uri) {
				/* Try Negotiate authentication first */

				success = sipe_svc_webticket(sipe_private,
							     wcd->session,
							     wcd->webticket_negotiate_uri,
							     NULL,
							     wcd->service_auth_uri,
							     &wcd->entropy,
							     webticket_token,
							     wcd);
				wcd->webticket_for_service = TRUE;
			} else {
				success = initiate_fedbearer(sipe_private,
							     wcd);
			}

			if (success) {
				/* callback data passed down the line */
				wcd = NULL;
			}
		}
	}

	if (wcd) {
		callback_execute(sipe_private,
				 wcd,
				 uri,
				 NULL,
				 NULL);
		callback_data_free(wcd);
	}
}

static void service_metadata(struct sipe_core_private *sipe_private,
			     const gchar *uri,
			     SIPE_UNUSED_PARAMETER const gchar *raw,
			     sipe_xml *metadata,
			     gpointer callback_data)
{
	struct webticket_callback_data *wcd = callback_data;

	if (metadata) {
		const sipe_xml *node;
		gchar *policy = g_strdup_printf("%s_policy", wcd->service_port);
		gchar *ticket_uri = NULL;

		SIPE_DEBUG_INFO("webservice_metadata: metadata for service %s retrieved successfully",
				uri);

		/* WebTicket policies accepted by Web Service */
		for (node = sipe_xml_child(metadata, "Policy");
		     node;
		     node = sipe_xml_twin(node)) {
			if (sipe_strcase_equal(sipe_xml_attribute(node, "Id"),
					       policy)) {

				SIPE_DEBUG_INFO_NOFORMAT("webservice_metadata: WebTicket policy found");

				ticket_uri = sipe_xml_data(sipe_xml_child(node,
									  "ExactlyOne/All/EndorsingSupportingTokens/Policy/IssuedToken/Issuer/Address"));
				if (ticket_uri) {
					/* this token type requires signing */
					wcd->requires_signing = TRUE;
				} else {
					/* try alternative token type */
					ticket_uri = sipe_xml_data(sipe_xml_child(node,
										  "ExactlyOne/All/SignedSupportingTokens/Policy/IssuedToken/Issuer/Address"));
				}
				if (ticket_uri) {
					SIPE_DEBUG_INFO("webservice_metadata: WebTicket URI %s", ticket_uri);
				}
				break;
			}
		}
		g_free(policy);

		if (ticket_uri) {

			/* Authentication ports accepted by Web Service */
			for (node = sipe_xml_child(metadata, "service/port");
			     node;
			     node = sipe_xml_twin(node)) {
				if (sipe_strcase_equal(sipe_xml_attribute(node, "name"),
						       wcd->service_port)) {
					const gchar *auth_uri;

					SIPE_DEBUG_INFO_NOFORMAT("webservice_metadata: authentication port found");

					auth_uri = sipe_xml_attribute(sipe_xml_child(node,
										     "address"),
								      "location");
					if (auth_uri) {
						SIPE_DEBUG_INFO("webservice_metadata: Auth URI %s", auth_uri);

						if (sipe_svc_metadata(sipe_private,
								      wcd->session,
								      ticket_uri,
								      webticket_metadata,
								      wcd)) {
							/* Remember for later */
							wcd->service_auth_uri = g_strdup(auth_uri);

							/* callback data passed down the line */
							wcd = NULL;
						}
					}
					break;
				}
			}
			g_free(ticket_uri);
		}
	}

	if (wcd) {
		callback_execute(sipe_private,
				 wcd,
				 uri,
				 NULL,
				 NULL);
		callback_data_free(wcd);
	}
}

gboolean sipe_webticket_request(struct sipe_core_private *sipe_private,
				struct sipe_svc_session *session,
				const gchar *base_uri,
				const gchar *port_name,
				sipe_webticket_callback *callback,
				gpointer callback_data)
{
	const struct webticket_token *wt = cache_hit(sipe_private, base_uri);
	gboolean ret;

	/* cache hit for this URI? */
	if (wt) {
		SIPE_DEBUG_INFO("sipe_webticket_request: using cached token for URI %s (Auth URI %s)",
				base_uri, wt->auth_uri);
		callback(sipe_private,
			 base_uri,
			 wt->auth_uri,
			 wt->token,
			 NULL,
			 callback_data);
		ret = TRUE;
	} else {
		GHashTable *pending = sipe_private->webticket->pending;
		struct webticket_callback_data *wcd = g_hash_table_lookup(pending,
									  base_uri);

		/* is there already a pending request for this URI? */
		if (wcd) {
			SIPE_DEBUG_INFO("sipe_webticket_request: pending request found for URI %s - queueing",
					base_uri);
			queue_request(wcd, callback, callback_data);
			ret = TRUE;
		} else {
			wcd = g_new0(struct webticket_callback_data, 1);

			ret = sipe_svc_metadata(sipe_private,
						session,
						base_uri,
						service_metadata,
						wcd);

			if (ret) {
				wcd->service_uri   = g_strdup(base_uri);
				wcd->service_port  = port_name;
				wcd->callback      = callback;
				wcd->callback_data = callback_data;
				wcd->session       = session;
				g_hash_table_insert(pending,
						    wcd->service_uri, /* borrowed */
						    wcd);             /* borrowed */
			} else {
				g_free(wcd);
			}
		}
	}

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
