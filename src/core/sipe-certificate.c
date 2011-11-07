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

#include <glib.h>

#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-certificate.h"
#include "sipe-nls.h"
#include "sipe-svc.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

struct certificate_callback_data {
	gchar *target;
	gchar *authuser;
	gchar *webticket_anon_uri;
	gchar *webticket_fedbearer_uri;
	gchar *certprov_uri;

	gboolean tried_fedbearer;

	struct sipe_svc_random entropy;
};

static void callback_data_free(struct certificate_callback_data *ccd)
{
	if (ccd) {
		g_free(ccd->target);
		g_free(ccd->authuser);
		g_free(ccd->webticket_anon_uri);
		g_free(ccd->webticket_fedbearer_uri);
		g_free(ccd->certprov_uri);
		sipe_svc_free_random(&ccd->entropy);
		g_free(ccd);
	}
}

gpointer sipe_certificate_tls_dsk_find(struct sipe_core_private *sipe_private,
				       const gchar *target)
{
	if (!target)
		return(NULL);

	/* temporary */
	(void)sipe_private;

	return(NULL);
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

static void webticket_token(struct sipe_core_private *sipe_private,
			    const gchar *uri,
			    sipe_xml *soap_body,
			    gpointer callback_data)
{
	struct certificate_callback_data *ccd = callback_data;

	if (soap_body) {
		SIPE_DEBUG_INFO("webticket_token: received valid SOAP message from service %s",
				uri);

		/* TBD.... */

	} else if (uri) {
		/* Retry with federated authentication? */
		gboolean tmp = !ccd->webticket_fedbearer_uri || ccd->tried_fedbearer;
		if (!tmp) {
			SIPE_DEBUG_INFO("webticket_token: anonymous authentication to service %s failed, retrying with federated authentication",
					uri);

			ccd->tried_fedbearer = TRUE;
			tmp = sipe_svc_webticket_lmc(sipe_private,
						     ccd->authuser,
						     ccd->webticket_fedbearer_uri,
						     webticket_token,
						     ccd);
			if (tmp) {
				/* callback data passed down the line */
				ccd = NULL;
			}
		}
		if (!tmp) {
			certificate_failure(sipe_private,
					    _("Web ticket request to %s failed"),
					    uri);
		}
	}

	callback_data_free(ccd);
}

static void webticket_metadata(struct sipe_core_private *sipe_private,
			       const gchar *uri,
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
						       "WebTicketServiceAnon")) {
					SIPE_DEBUG_INFO("webticket_metadata: WebTicket Anon Auth URI %s", auth_uri);
					g_free(ccd->webticket_anon_uri);
					ccd->webticket_anon_uri = g_strdup(auth_uri);
				} else if (sipe_strcase_equal(sipe_xml_attribute(node, "name"),
							      "WsFedBearer")) {
					SIPE_DEBUG_INFO("webticket_metadata: WebTicket Anon Auth URI %s", auth_uri);
					g_free(ccd->webticket_fedbearer_uri);
					ccd->webticket_fedbearer_uri = g_strdup(auth_uri);
				}
			}
		}

		if (ccd->webticket_anon_uri || ccd->webticket_fedbearer_uri) {
			gboolean success;

			if (ccd->webticket_anon_uri) {
				/* Try anonymous authentication first */
				/* Entropy: 256 random bits */
				sipe_svc_fill_random(&ccd->entropy, 256);

				success = sipe_svc_webticket(sipe_private,
							     ccd->webticket_anon_uri,
							     ccd->authuser,
							     ccd->certprov_uri,
							     &ccd->entropy,
							     webticket_token,
							     ccd);
			} else {
				ccd->tried_fedbearer = TRUE;
				success = sipe_svc_webticket_lmc(sipe_private,
								 ccd->authuser,
								 ccd->webticket_fedbearer_uri,
								 webticket_token,
								 ccd);
			}

			if (success) {
				/* callback data passed down the line */
				ccd = NULL;
			} else {
				certificate_failure(sipe_private,
						    _("Can't request security token from %s"),
						    ccd->webticket_anon_uri ? ccd->webticket_anon_uri : ccd->webticket_fedbearer_uri);
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
							    _("Can't find the WebTicket URI for TLS-DSK certificate provisioning URI %s"),
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
					    _("Can't find the WebTicket Policy for TLS-DSK certificate provisioning URI %s"),
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
					   const gchar *authuser,
					   const gchar *uri)
{
	struct certificate_callback_data *ccd = g_new0(struct certificate_callback_data, 1);
	gboolean ret;

	ccd->target   = g_strdup(target);
	ccd->authuser = g_strdup(authuser);

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
