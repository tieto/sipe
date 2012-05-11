/**
 * @file purple-dnsquery.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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

#include "glib.h"

#include "dnssrv.h"

#include "sipe-backend.h"
#include "sipe-core.h"

#include "purple-private.h"

static void dns_srv_response(PurpleSrvResponse *resp,
			     int results,
			     gpointer data)
{
	struct sipe_backend_private *purple_private = data;

	/* data no longer needed and free'd by libpurple */
	purple_private->dns_query = NULL;

	/* find the host to connect to */
	if (results) {
		sipe_core_dns_resolved(purple_private->public,
				       resp->hostname,
				       resp->port);
		g_free(resp);
	} else {
		sipe_core_dns_resolve_failure(purple_private->public);
	}
}

void sipe_backend_dns_query(struct sipe_core_public *sipe_public,
			    const gchar *protocol,
			    const gchar *transport,
			    const gchar *domain)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;

	/* Try to resolve next service */
	purple_private->dns_query = purple_srv_resolve(protocol,
						       transport,
						       domain,
						       dns_srv_response,
						       purple_private);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
