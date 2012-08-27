/**
 * @file miranda-dnsquery.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-12 SIPE Project <http://sipe.sourceforge.net/>
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

#include <windows.h>
#include <win2k.h>
#include <stdio.h>
#include <windns.h>

#include <glib.h>

#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "m_utils.h"

#include "sipe-backend.h"
#include "miranda-private.h"

typedef DNS_STATUS (WINAPI *DNSQUERYA)(IN PCSTR pszName, IN WORD wType, IN DWORD Options, IN PIP4_ARRAY aipServers OPTIONAL, IN OUT PDNS_RECORD *ppQueryResults OPTIONAL, IN OUT PVOID *pReserved OPTIONAL);
typedef void (WINAPI *DNSFREELIST)(IN OUT PDNS_RECORD pRecordList, IN DNS_FREE_TYPE FreeType);

typedef struct srv_reply_t {
        char *host;
        int port;
} srv_reply;

static srv_reply* srv_lookup(WORD wType,
			     const gchar* service,
			     const gchar* protocol,
			     const gchar* domain )
{
	srv_reply *res = NULL;
	HINSTANCE hDnsapi = LoadLibraryA( "dnsapi.dll" );
	DNSQUERYA pDnsQuery;
	DNSFREELIST pDnsRecordListFree;
	gchar temp[256];
	DNS_RECORD *results = NULL;
	DNS_STATUS status;

	if ( hDnsapi == NULL )
		return res;

	pDnsQuery = (DNSQUERYA)GetProcAddress(hDnsapi, "DnsQuery_A");
	pDnsRecordListFree = (DNSFREELIST)GetProcAddress(hDnsapi, "DnsRecordListFree");
	if ( pDnsQuery == NULL ) {
		//dnsapi.dll is not the needed dnsapi ;)
		FreeLibrary( hDnsapi );
		return res;
	}

	mir_snprintf( temp, SIZEOF(temp), "_%s._%s.%s", service, protocol, domain );

	status = pDnsQuery(temp, DNS_TYPE_SRV, DNS_QUERY_STANDARD, NULL, &results, NULL);
	if (FAILED(status)||!results || results[0].Data.Srv.pNameTarget == 0||results[0].wType != DNS_TYPE_SRV) {
		FreeLibrary(hDnsapi);
		return res;
	}

	res = g_new0(srv_reply,1);
	res->host = g_strdup((const gchar*)results[0].Data.Srv.pNameTarget);
	res->port = (int)results[0].Data.Srv.wPort;

	pDnsRecordListFree(results, DnsFreeRecordList);
	FreeLibrary(hDnsapi);
	return res;
}


struct sipe_dns_query *sipe_backend_dns_query_a(struct sipe_core_public *sipe_public,
						const gchar *hostname,
						guint port,
						sipe_dns_resolved_cb callback,
						gpointer data)
{
	srv_reply* sr = srv_lookup( DNS_TYPE_A, "protocol", "transport", "domain" );
	SIPE_DEBUG_INFO("Type A lookup for host <%s> port <%d>", hostname, port);

	if (sr) {
		callback( data, sr->host, sr->port);

		g_free(sr->host);
		g_free(sr);
	} else {
		callback( data, NULL, 0);
	}

	return NULL;
}

struct sipe_dns_query *sipe_backend_dns_query_srv(struct sipe_core_public *sipe_public,
						  const gchar *protocol,
						  const gchar *transport,
						  const gchar *domain,
						  sipe_dns_resolved_cb callback,
						  gpointer data)
{
	srv_reply* sr = srv_lookup( DNS_TYPE_SRV, protocol, transport, domain );

	SIPE_DEBUG_INFO("Type SRV lookup for proto <%s> transport <%s> domain <%s>",
			protocol, transport, domain);

	if (sr) {
		callback( data, sr->host, sr->port);

		g_free(sr->host);
		g_free(sr);
	} else {
		callback( data, NULL, 0);
	}

	return NULL;
}

void sipe_backend_dns_query_cancel(struct sipe_dns_query *query)
{
	_NIF();
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
