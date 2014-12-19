/**
 * @file miranda-search.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-2014 SIPE Project <http://sipe.sourceforge.net/>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <windows.h>
#include <glib.h>
#include <stdio.h>

#include "miranda-version.h"
#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "m_system.h"
#include "m_utils.h"

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-nls.h"

#include "miranda-private.h"
#include "miranda-resource.h"

struct sipe_backend_search_results {
	int dummy;
};

void sipe_backend_search_failed(struct sipe_core_public *sipe_public,
				SIPE_UNUSED_PARAMETER struct sipe_backend_search_token *token,
				const gchar *msg)
{
	sipe_miranda_SendBroadcast(sipe_public->backend_private, NULL, ACKTYPE_SEARCH, ACKRESULT_FAILED, (HANDLE)1, 0);
	sipe_backend_notify_error(sipe_public, msg, NULL);
}

struct sipe_backend_search_results *sipe_backend_search_results_start(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
								      SIPE_UNUSED_PARAMETER struct sipe_backend_search_token *token)
{
	return g_new0(struct sipe_backend_search_results, 1);
}

void sipe_backend_search_results_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				     struct sipe_backend_search_results *results,
				     const gchar *uri,
				     const gchar *name,
				     const gchar *company,
				     const gchar *country,
				     const gchar *email)
{
	SIPPROTO *pr = sipe_public->backend_private;
	PROTOSEARCHRESULT psr = { 0 };
	HANDLE hProcess = (HANDLE)1; /* g_hash_table_lookup(opts, "searchid"); */
	gchar **nameparts;

	psr.cbSize = sizeof(psr);
	psr.id = (PROTOCHAR*)uri;
	nameparts = g_strsplit_set(name, ",", 2);
	psr.nick = (FNAMECHAR*)name;
	psr.firstName = (PROTOCHAR*)(nameparts[1] ? nameparts[1] : NULL);
	psr.lastName = (PROTOCHAR*)nameparts[0];
	psr.email = (PROTOCHAR*)email;

	sipe_miranda_SendBroadcast(pr, NULL, ACKTYPE_SEARCH, ACKRESULT_DATA, hProcess, (LPARAM) & psr);
	g_strfreev(nameparts);
}

void sipe_backend_search_results_finalize(struct sipe_core_public *sipe_public,
					  struct sipe_backend_search_results *results,
					  const gchar *description,
					  gboolean more)
{
	SIPPROTO *pr = sipe_public->backend_private;
	HANDLE hProcess = (HANDLE)1; /* g_hash_table_lookup(opts, "searchid"); */

	sipe_miranda_SendBroadcast(pr, NULL, ACKTYPE_SEARCH, ACKRESULT_SUCCESS, hProcess, 0);

	g_free(results);
}

HANDLE sipe_miranda_SearchByEmail( SIPPROTO *pr, const PROTOCHAR* email )
{
	char *mail;

	SIPE_DEBUG_INFO("SearchByEmail: email <%S>", email);
	if (!pr->sip) return NULL;

	mail = mir_t2a(email);

	LOCK;
	sipe_core_buddy_search(pr->sip, NULL, NULL, NULL, mail, NULL, NULL, NULL);
	UNLOCK;

	mir_free(mail);

	return (HANDLE)1;
}

HANDLE sipe_miranda_SearchByName( SIPPROTO *pr, const PROTOCHAR* nick, const PROTOCHAR* firstName, const PROTOCHAR* lastName)
{
	char *given_name;
	char *surname;
	SIPE_DEBUG_INFO("SearchByName: nick <%S> firstname <%S> lastname <%S>", nick, firstName, lastName);
	if (!pr->sip) return NULL;

	given_name = mir_t2a(firstName);
	surname = mir_t2a(lastName);

	LOCK;
	sipe_core_buddy_search(pr->sip, NULL, given_name, surname, NULL, NULL, NULL, NULL);
	UNLOCK;

	mir_free(given_name);
	mir_free(surname);

	return (HANDLE)1;
}

HWND sipe_miranda_SearchAdvanced( SIPPROTO *pr, HWND owner )
{
	char buf[512];
	GHashTable *query = g_hash_table_new_full(NULL,NULL,NULL,g_free);
	GString *msg;

	if (!pr->sip) return NULL;
	msg = g_string_new("SearchAdvanced: ");

	GetDlgItemTextA(owner, IDC_SEARCH_FN, buf, sizeof(buf));
	if (strlen(buf))
	{
		g_string_append_printf(msg, "firstname <%s> ", buf);
		g_hash_table_insert(query, "givenName", g_strdup(buf));
	}

	GetDlgItemTextA(owner, IDC_SEARCH_LN, buf, sizeof(buf));
	if (strlen(buf))
	{
		g_string_append_printf(msg, "lastname <%s> ", buf);
		g_hash_table_insert(query, "sn", g_strdup(buf));
	}

	GetDlgItemTextA(owner, IDC_SEARCH_COMPANY, buf, sizeof(buf));
	if (strlen(buf))
	{
		g_string_append_printf(msg, "company <%s> ", buf);
		g_hash_table_insert(query, "company", g_strdup(buf));
	}

	GetDlgItemTextA(owner, IDC_SEARCH_COUNTRY, buf, sizeof(buf));
	if (strlen(buf))
	{
		g_string_append_printf(msg, "country <%s> ", buf);
		g_hash_table_insert(query, "c", g_strdup(buf));
	}

	SIPE_DEBUG_INFO_NOFORMAT(msg->str);
	g_string_free(msg, TRUE);

	LOCK;
	sipe_backend_search_failed(pr->sip, NULL, "Not implemented");

/*	ret = (HANDLE)sipe_core_buddy_search( pr->sip, NULL, query, sipsimple_search_contact_cb, pr); */
	UNLOCK;

	return (HANDLE)1;

}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
