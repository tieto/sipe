/**
 * @file miranda-chat.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2013 SIPE Project <http://sipe.sourceforge.net/>
 * Copyright (C) 2009 pier11 <pier11@operamail.com>
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
 */

#include <windows.h>
#include <stdio.h>

#include <glib.h>

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-nls.h"

#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "m_chat.h"
#include "m_utils.h"
#include "m_system.h"

#include "miranda-private.h"

void sipe_backend_chat_session_destroy(SIPE_UNUSED_PARAMETER struct sipe_backend_chat_session *session)
{
	/* Nothing to do here */
}

void sipe_backend_chat_add(struct sipe_backend_chat_session *backend_session,
			   const gchar *uri,
			   gboolean is_new)
{
	SIPPROTO *pr = backend_session->pr;
	struct sipe_core_public *sipe_public = pr->sip;
	gchar *self = sipe_miranda_uri_self(pr);
	GCDEST gcd = {0};
	GCEVENT gce = {0};
	int retval;
	HANDLE hContact = sipe_backend_buddy_find( sipe_public, uri, NULL );
	gchar *nick = sipe_miranda_getContactString(pr, hContact, "Nick");

	SIPE_DEBUG_INFO("sipe_backend_chat_add: Adding user <%s> to chat <%s>", uri, backend_session->conv);

	gcd.pszModule = pr->proto.m_szModuleName;
	gcd.pszID = backend_session->conv;
	gcd.iType = GC_EVENT_JOIN;

	gce.cbSize = sizeof(gce);
	gce.pDest = &gcd;
	gce.pszNick = nick;
	gce.pszUID = uri;
	gce.pszStatus = "Normal";
	gce.bIsMe = !strcmp(self, uri);

	g_free(self);
	retval = CallService( MS_GC_EVENT, 0, (LPARAM)&gce );
	if (retval) {
		SIPE_DEBUG_WARNING("sipe_backend_chat_add: Failed to add user to chat: <%d>", retval);
	}
	mir_free(nick);
}

void sipe_backend_chat_close(struct sipe_backend_chat_session *backend_session)
{
	SIPPROTO *pr;
	GCEVENT gce = {0};
	GCDEST gcd = {0};
	struct sipe_chat_session *session;

	if (!backend_session)
	{
		SIPE_DEBUG_WARNING_NOFORMAT("Attempted to close NULL backend_session");
		return;
	}

	pr = backend_session->pr;

	gce.cbSize = sizeof(gce);
	gce.pDest = &gcd;

	gcd.pszModule = pr->proto.m_szModuleName;
	gcd.pszID = backend_session->conv;
	gcd.iType = GC_EVENT_CONTROL;

	session = (struct sipe_chat_session*)CallServiceSync( MS_GC_EVENT, SESSION_TERMINATE, (LPARAM)&gce );
}

struct sipe_backend_chat_session *sipe_backend_chat_create(struct sipe_core_public *sipe_public,
							   struct sipe_chat_session *session,
							   const gchar *title,
							   const gchar *nick)
{
	SIPPROTO *pr = sipe_public->backend_private;
	GCSESSION gs;
	GCDEST gcd = {0};
	GCEVENT gce = {0};
	gchar *id = g_strdup(title); /* FIXME: Generate ID */
	struct sipe_backend_chat_session *conv = g_new0(struct sipe_backend_chat_session,1);

	gs.cbSize = sizeof(gs);
	gs.iType = GCW_CHATROOM;
	gs.pszModule = pr->proto.m_szModuleName;
	gs.pszName = title;
	gs.pszID = id;
	gs.pszStatusbarText = NULL;
	gs.dwFlags = 0;
	gs.dwItemData = (DWORD)session;

	if (CallServiceSync( MS_GC_NEWSESSION, 0, (LPARAM)&gs ))
	{
		SIPE_DEBUG_ERROR("Failed to create chat session <%d> <%s>", id, title);
	}

	gcd.pszModule = pr->proto.m_szModuleName;
	gcd.pszID = id;

	gce.cbSize = sizeof(gce);
	gce.pDest = &gcd;

	gcd.iType = GC_EVENT_ADDGROUP;
	gce.pszStatus = "Normal";
	if (CallService( MS_GC_EVENT, 0, (LPARAM)&gce ))
	{
		SIPE_DEBUG_WARNING_NOFORMAT("Failed to add normal status to chat session");
	}

	gce.pszStatus = "Presenter";
	if (CallService( MS_GC_EVENT, 0, (LPARAM)&gce ))
	{
		SIPE_DEBUG_WARNING_NOFORMAT("Failed to add presenter status to chat session");
	}


	gcd.iType = GC_EVENT_CONTROL;

	if (CallServiceSync( MS_GC_EVENT, SESSION_INITDONE, (LPARAM)&gce ))
	{
		SIPE_DEBUG_WARNING_NOFORMAT("Failed to initdone chat session");
	}
	if (CallServiceSync( MS_GC_EVENT, SESSION_ONLINE, (LPARAM)&gce ))
	{
		SIPE_DEBUG_ERROR_NOFORMAT("Failed to set chat session online");
	}

	conv->conv = id;
	conv->pr = pr;

	return conv;
}

gboolean sipe_backend_chat_find(struct sipe_backend_chat_session *backend_session,
				const gchar *uri)
{
	SIPPROTO *pr = backend_session->pr;
	GC_INFO gci = {0};
	gchar *context;
	const gchar *user;

	gci.Flags = BYID | USERS;
	gci.pszID = mir_a2t(backend_session->conv);
	gci.pszModule = pr->proto.m_szModuleName;

	if(CallServiceSync( MS_GC_GETINFO, 0, (LPARAM)&gci )) {
		SIPE_DEBUG_ERROR_NOFORMAT("Failed to get chat user list");
		return FALSE;
	}

	if (!gci.pszUsers)
		return FALSE;

	user = strtok_s(gci.pszUsers, " ", &context);
	while (user)
	{
		SIPE_DEBUG_INFO("sipe_backend_chat_find: Found user <%s>", user);
		if (!strcmp(uri, user)) {
			mir_free(gci.pszUsers);
			return TRUE;
		}
		user = strtok_s(NULL, " ", &context);
	}

	mir_free(gci.pszUsers);
	return FALSE;
}

gboolean sipe_backend_chat_is_operator(struct sipe_backend_chat_session *backend_session,
				       const gchar *uri)
{
	_NIF();
	return TRUE;
}

void sipe_backend_chat_message(struct sipe_core_public *sipe_public,
			       struct sipe_backend_chat_session *backend_session,
			       const gchar *from,
			       time_t when,
			       const gchar *html)
{
	SIPPROTO *pr = backend_session->pr;
	gchar *self = sipe_miranda_uri_self(pr);
	gchar *msg;
	GCDEST gcd = {0};
	GCEVENT gce = {0};
	HANDLE hContact = sipe_backend_buddy_find( sipe_public, from, NULL );
	gchar *nick = sipe_miranda_getContactString(pr, hContact, "Nick");

	gcd.pszModule = pr->proto.m_szModuleName;
	gcd.pszID = backend_session->conv;
	gcd.iType = GC_EVENT_MESSAGE;

	msg = sipe_miranda_eliminate_html(html, strlen(html));

	gce.cbSize = sizeof(gce);
	gce.pDest = &gcd;
	gce.pszNick = nick;
	gce.pszUID = from;
	gce.pszText = msg;
	gce.bIsMe = !strcmp(self, from);
//	gce.time = mtime; // FIXME: Generate timestamp
	g_free(self);

	CallService( MS_GC_EVENT, 0, (LPARAM)&gce );
	mir_free(nick);
	mir_free(msg);
}

void sipe_backend_chat_operator(struct sipe_backend_chat_session *backend_session,
				const gchar *uri)
{
	SIPPROTO *pr;
	GCEVENT gce = {0};
	GCDEST gcd = {0};
	HANDLE hContact;
	gchar *nick;
	struct sipe_core_public *sipe_public;

	if (!backend_session)
	{
		SIPE_DEBUG_WARNING_NOFORMAT("Attempted to set operator on NULL backend_session");
		return;
	}

	pr = backend_session->pr;
	sipe_public = pr->sip;

	hContact = sipe_backend_buddy_find( sipe_public, uri, NULL );
	nick = sipe_miranda_getContactString(pr, hContact, "Nick");

	gce.cbSize = sizeof(gce);
	gce.pDest = &gcd;
	gce.pszNick = nick;
	gce.pszUID = uri;
	gce.pszText = "Presenter";
	gce.pszStatus = "Presenter";

	gcd.pszModule = pr->proto.m_szModuleName;
	gcd.pszID = backend_session->conv;
	gcd.iType = GC_EVENT_ADDSTATUS;

	if (CallServiceSync( MS_GC_EVENT, 0, (LPARAM)&gce ))
	{
		SIPE_DEBUG_WARNING_NOFORMAT("Failed to set presenter status");
	}
	mir_free(nick);
}

void sipe_backend_chat_rejoin(struct sipe_core_public *sipe_public,
			      struct sipe_backend_chat_session *backend_session,
			      const gchar *nick,
			      const gchar *title)
{
	_NIF();
}

/**
 * Connection re-established: tell core what chats need to be rejoined
 */
void sipe_backend_chat_rejoin_all(struct sipe_core_public *sipe_public)
{
	_NIF();
}

void sipe_backend_chat_remove(struct sipe_backend_chat_session *backend_session,
			      const gchar *uri)
{
	SIPPROTO *pr = backend_session->pr;
	struct sipe_core_public *sipe_public = pr->sip;
	gchar *self = sipe_miranda_uri_self(pr);
	GCDEST gcd = {0};
	GCEVENT gce = {0};
	HANDLE hContact = sipe_backend_buddy_find( sipe_public, uri, NULL );
	gchar *nick = sipe_miranda_getContactString(pr, hContact, "Nick");

	SIPE_DEBUG_INFO("sipe_backend_chat_remove: Removing user <%s> from chat <%s>", uri, backend_session->conv);

	gcd.pszModule = pr->proto.m_szModuleName;
	gcd.pszID = backend_session->conv;
	gcd.iType = GC_EVENT_PART;

	gce.cbSize = sizeof(gce);
	gce.pDest = &gcd;
	gce.pszNick = nick;
	gce.pszUID = uri;
	gce.pszStatus = 0;
	gce.bIsMe = !strcmp(self, uri);

	g_free(self);
	CallService( MS_GC_EVENT, 0, (LPARAM)&gce );
	mir_free(nick);
}

void sipe_backend_chat_show(struct sipe_backend_chat_session *backend_session)
{
	_NIF();
}

void sipe_backend_chat_topic(struct sipe_backend_chat_session *backend_session,
			      const gchar *topic)
{
	SIPPROTO *pr = backend_session->pr;
	GCDEST gcd = {0};
	GCEVENT gce = {0};

	SIPE_DEBUG_INFO("sipe_backend_chat_topic: conv <%s> topic <%s>", backend_session->conv, topic);

	gcd.pszModule = pr->proto.m_szModuleName;
	gcd.pszID = backend_session->conv;
	gcd.iType = GC_EVENT_TOPIC;

	gce.cbSize = sizeof(gce);
	gce.pDest = &gcd;
	gce.pszNick = NULL;
	gce.pszUID = NULL;
	gce.pszText = topic;

	CallService( MS_GC_EVENT, 0, (LPARAM)&gce );
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
