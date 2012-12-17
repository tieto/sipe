/**
 * @file sipe-certificate.c
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
#include "sipe-nls.h"
#include "sipe-svc.h"
#include "sipe-webticket.h"
#include "sipe-xml.h"

struct sipe_certificate {
	GHashTable *certificates;
	struct sipe_cert_crypto *backend;
};

struct certificate_callback_data {
	gchar *target;
	struct sipe_svc_session *session;
};

static void callback_data_free(struct certificate_callback_data *ccd)
{
	if (ccd) {
		sipe_svc_session_close(ccd->session);
		g_free(ccd->target);
		g_free(ccd);
	}
}

void sipe_certificate_free(struct sipe_core_private *sipe_private)
{
	struct sipe_certificate *sc = sipe_private->certificate;

	if (sc) {
		g_hash_table_destroy(sc->certificates);
		sipe_cert_crypto_free(sc->backend);
		g_free(sc);
	}
}

gboolean sipe_certificate_init(struct sipe_core_private *sipe_private)
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

static void certificate_failure(struct sipe_core_private *sipe_private,
				const gchar *format,
				const gchar *parameter,
				const gchar *failure_info)
{
	gchar *tmp = g_strdup_printf(format, parameter);
	if (failure_info) {
		gchar *tmp2 = g_strdup_printf("%s\n(%s)", tmp, failure_info);
		g_free(tmp);
		tmp = tmp2;
	}
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
				    uri,
				    NULL);
	}

	callback_data_free(ccd);
}

static void certprov_webticket(struct sipe_core_private *sipe_private,
			       const gchar *base_uri,
			       const gchar *auth_uri,
			       const gchar *wsse_security,
			       const gchar *failure_msg,
			       gpointer callback_data)
{
	struct certificate_callback_data *ccd = callback_data;

	if (wsse_security) {
		/* Got a Web Ticket for Certificate Provisioning Service */
		gchar *certreq_base64 = create_certreq(sipe_private,
						       sipe_private->username);

		SIPE_DEBUG_INFO("certprov_webticket: got ticket for %s",
				base_uri);

		if (certreq_base64) {

			SIPE_DEBUG_INFO_NOFORMAT("certprov_webticket: created certificate request");

			if (sipe_svc_get_and_publish_cert(sipe_private,
							  ccd->session,
							  auth_uri,
							  wsse_security,
							  certreq_base64,
							  get_and_publish_cert,
							  ccd))
				/* callback data passed down the line */
				ccd = NULL;

			g_free(certreq_base64);
		}

	        if (ccd) {
			certificate_failure(sipe_private,
					    _("Certificate request to %s failed"),
					    base_uri,
					    NULL);
		}

	} else if (auth_uri) {
		certificate_failure(sipe_private,
				    _("Web ticket request to %s failed"),
				    base_uri,
				    failure_msg);
	}

	if (ccd)
		callback_data_free(ccd);
}

gboolean sipe_certificate_tls_dsk_generate(struct sipe_core_private *sipe_private,
					   const gchar *target,
					   const gchar *uri)
{
	struct certificate_callback_data *ccd = g_new0(struct certificate_callback_data, 1);
	gboolean ret;

	ccd->session = sipe_svc_session_start();

	ret = sipe_webticket_request(sipe_private,
				     ccd->session,
				     uri,
				     "CertProvisioningServiceWebTicketProof_SHA1",
				     certprov_webticket,
				     ccd);
	if (ret) {
		ccd->target = g_strdup(target);

	} else {
		callback_data_free(ccd);
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
