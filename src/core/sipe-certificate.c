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
};

static void callback_data_free(struct certificate_callback_data *ccd)
{
	if (ccd) {
		g_free(ccd->target);
		g_free(ccd->authuser);
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

static void certprov_metadata(struct sipe_core_private *sipe_private,
			      const gchar *uri,
			      sipe_xml *metadata,
			      gpointer callback_data)
{
	struct certificate_callback_data *ccd = callback_data;

	if (metadata) {
		const sipe_xml *node;

		SIPE_DEBUG_INFO("certprov_metadata: metadata for service %s retrieved successfully",
				uri);

		/* WebTicket policies accepted by Certificate Provisiong Service */
		for (node = sipe_xml_child(metadata, "Policy");
		     node;
		     node = sipe_xml_twin(node)) {
			if (sipe_strcase_equal(sipe_xml_attribute(node, "Id"),
					       "CertProvisioningServiceWebTicketProof_SHA1_policy")) {
				gchar *ticket_uri;

				SIPE_DEBUG_INFO_NOFORMAT("certprov_metadata: WebTicket policy found");

				ticket_uri = sipe_xml_data(sipe_xml_child(node,
									  "ExactlyOne/All/EndorsingSupportingTokens/Policy/IssuedToken/Issuer/Address"));
				if (ticket_uri) {
					SIPE_DEBUG_INFO("certprov_metadata: WebTicket URI %s", ticket_uri);

					/* TBD.... */

					g_free(ticket_uri);
				} else {
					gchar *tmp = g_strdup_printf(_("Can't find the WebTicket URI for TLS-DSK certificate provisioning URI %s"),
								     uri);
					sipe_backend_connection_error(SIPE_CORE_PUBLIC,
								      SIPE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
								      tmp);
					g_free(tmp);
					SIPE_DEBUG_ERROR_NOFORMAT("certprov_metadata: no WebTicket URI found");
				}
				break;
			}
		}

	} else if (uri) {
		gchar *tmp = g_strdup_printf(_("Can't retrieve metadata for TLS-DSK certificate provisioning URI %s"),
					     uri);
		sipe_backend_connection_error(SIPE_CORE_PUBLIC,
					      SIPE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
					      tmp);
		g_free(tmp);
		SIPE_DEBUG_ERROR("certprov_metadata: metadata failure for service %s",
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
