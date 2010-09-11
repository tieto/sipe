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

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#endif

#include "glib.h"

#include "dnsquery.h"
#include "dnssrv.h"

#include "sipe-backend.h"

struct sipe_dns_query {
	enum {
		A,
		SRV
	} type;
	sipe_dns_resolved_cb  callback;
	gpointer	      extradata;
	gpointer	      purple_query_data;
};

static void dns_a_response(GSList *hosts,
			   struct sipe_dns_query *query,
			   const char *error_message)
{
	char ipstr[INET6_ADDRSTRLEN];
	struct sockaddr *addr;
	const void *addrdata;
	int port;

	if (error_message || !g_slist_next(hosts)) {
		query->callback(query->extradata, NULL, 0);
		g_slist_free(hosts);
		return;
	}

	addr = g_slist_next(hosts)->data;
	if (addr->sa_family == AF_INET6) {
		addrdata = &((struct sockaddr_in6 *) addr)->sin6_addr;
		port = ((struct sockaddr_in6 *) addr)->sin6_port;
	} else {
		addrdata = &((struct sockaddr_in *) addr)->sin_addr;
		port = ((struct sockaddr_in *) addr)->sin_port;
	}

	inet_ntop(addr->sa_family, addrdata, ipstr, sizeof (ipstr));

	query->callback(query->extradata, ipstr, port);

	for (; hosts; hosts = g_slist_delete_link(hosts, hosts)) {
		// Free the addrlen, no data in this link
		hosts = g_slist_delete_link(hosts, hosts);
		// Free the address
		g_free(hosts->data);
	}

	g_free(query);
}

struct sipe_dns_query *sipe_backend_dns_query_a(const gchar *hostname,
						int port,
						sipe_dns_resolved_cb callback,
						gpointer data)
{
	struct sipe_dns_query *query = g_new(struct sipe_dns_query, 1);
	query->type = A;
	query->callback = callback;
	query->extradata = data;
	query->purple_query_data = purple_dnsquery_a(hostname,
						     port,
						     (PurpleDnsQueryConnectFunction) dns_a_response,
						     query);

	return query;
}


static void dns_srv_response(PurpleSrvResponse *resp,
			     int results,
			     struct sipe_dns_query *query)
{
	if (results)
		query->callback(query->extradata, resp->hostname, resp->port);
	else
		query->callback(query->extradata, NULL, 0);

	g_free(query);
	g_free(resp);
}

struct sipe_dns_query *sipe_backend_dns_query_srv(const gchar *protocol,
						  const gchar *transport,
						  const gchar *domain,
						  sipe_dns_resolved_cb callback,
						  gpointer data)
{
	struct sipe_dns_query *query = g_new(struct sipe_dns_query, 1);
	query->type = SRV;
	query->callback = callback;
	query->extradata = data;
	query->purple_query_data = purple_srv_resolve(protocol,
						      transport,
						      domain,
						      (PurpleSrvCallback) dns_srv_response,
						      query);

	return query;
}

void sipe_backend_dns_query_cancel(struct sipe_dns_query *query)
{
	switch (query->type) {
		case A:
			purple_dnsquery_destroy(query->purple_query_data);
			break;
		case SRV:
			purple_srv_cancel(query->purple_query_data);
			break;
	}

	g_free(query);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
