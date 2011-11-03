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
#include "sipe-xml.h"

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
	if (metadata) {
		SIPE_DEBUG_INFO("certprov_metadata: metadata for service %s retrieved successfully",
				uri);
		(void)sipe_private;
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
	g_free(callback_data);
}

gboolean sipe_certificate_tls_dsk_generate(struct sipe_core_private *sipe_private,
					   const gchar *target,
					   const gchar *uri)
{
	gchar *data = g_strdup(target);
	gboolean ret = sipe_svc_metadata(sipe_private, uri,
					 certprov_metadata, data);
	if (!ret) g_free(data);
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
