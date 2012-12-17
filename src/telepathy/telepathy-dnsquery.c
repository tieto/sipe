/**
 * @file telepathy-dnsquery.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2012 SIPE Project <http://sipe.sourceforge.net/>
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

#include <glib.h>
#include <gio/gio.h>

#include "sipe-backend.h"
#include "sipe-common.h"

struct sipe_dns_query {
	sipe_dns_resolved_cb  callback;
	gpointer	      extradata;
	guint                 port;
	GCancellable         *cancel;
};

static void dns_srv_response(GObject *resolver,
			     GAsyncResult *result,
			     gpointer data)
{
	GError *error  = NULL;
	GList *targets = g_resolver_lookup_service_finish(G_RESOLVER(resolver),
							  result,
							  &error);
	struct sipe_dns_query *query = data;

	if (targets) {
		GSrvTarget *target = targets->data;
		query->callback(query->extradata,
				g_srv_target_get_hostname(target),
				g_srv_target_get_port(target));
		g_resolver_free_targets(targets);
	} else {
		SIPE_DEBUG_INFO("dns_srv_response: failed: %s",
				error ? error->message : "UNKNOWN");
		g_error_free(error);
		if (query->callback)
			query->callback(query->extradata, NULL, 0);
	}
	g_object_unref(query->cancel);
	g_free(query);
}

struct sipe_dns_query *sipe_backend_dns_query_srv(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
						  const gchar *protocol,
						  const gchar *transport,
						  const gchar *domain,
						  sipe_dns_resolved_cb callback,
						  gpointer data)
{
	struct sipe_dns_query *query = g_new0(struct sipe_dns_query, 1);
	GResolver *resolver          = g_resolver_get_default();

	SIPE_DEBUG_INFO("sipe_backend_dns_query_srv: %s/%s/%s",
			protocol, transport, domain);

	query->callback  = callback;
	query->extradata = data;
	query->cancel    = g_cancellable_new();
	g_resolver_lookup_service_async(resolver,
					protocol, transport, domain,
					query->cancel,
					dns_srv_response,
					query);

	g_object_unref(resolver);
	return(query);
}

static void dns_a_response(GObject *resolver,
			   GAsyncResult *result,
			   gpointer data)
{
	GError *error    = NULL;
	GList *addresses = g_resolver_lookup_by_name_finish(G_RESOLVER(resolver),
							    result,
							    &error);
	struct sipe_dns_query *query = data;

	if (addresses) {
		GInetAddress *address  = addresses->data;
		gchar        *ipstr    = g_inet_address_to_string(address);
		query->callback(query->extradata, ipstr, query->port);
		g_free(ipstr);
		g_resolver_free_addresses(addresses);
	} else {
		SIPE_DEBUG_INFO("dns_a_response: failed: %s",
				error ? error->message : "UNKNOWN");
		g_error_free(error);
		if (query->callback)
			query->callback(query->extradata, NULL, 0);
	}
	g_object_unref(query->cancel);
	g_free(query);
}

struct sipe_dns_query *sipe_backend_dns_query_a(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
						const gchar *hostname,
						guint port,
						sipe_dns_resolved_cb callback,
						gpointer data)
{
	struct sipe_dns_query *query = g_new0(struct sipe_dns_query, 1);
	GResolver *resolver          = g_resolver_get_default();

	SIPE_DEBUG_INFO("sipe_backend_dns_query_a: %s", hostname);

	query->callback  = callback;
	query->extradata = data;
	query->port      = port;
	query->cancel    = g_cancellable_new();
	g_resolver_lookup_by_name_async(resolver,
					hostname,
					query->cancel,
					dns_a_response,
					query);

	g_object_unref(resolver);
	return(query);
}

void sipe_backend_dns_query_cancel(struct sipe_dns_query *query)
{
	/* callback is invalid now, do no longer call! */
	query->callback = NULL;
	g_cancellable_cancel(query->cancel);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
