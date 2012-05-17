/**
 * @file miranda-groupchat.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-11 SIPE Project <http://sipe.sourceforge.net/>
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
#include <stdio.h>

#include <glib.h>

#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "m_chat.h"

#include "sipe-backend.h"
#include "sipe-core.h"
#include "miranda-private.h"

void sipe_backend_groupchat_room_add(struct sipe_core_public *sipe_public,
				     const gchar *uri,
				     const gchar *name,
				     const gchar *description,
				     guint users,
				     guint32 flags)
{
	SIPPROTO *pr = sipe_public->backend_private;
	GCSESSION gs;
	GCEVENT gce = {0};
	GCDEST gcd = {0};

	gs.cbSize = sizeof(gs);
	gs.iType = GCW_CHATROOM;
	gs.pszModule = pr->proto.m_szModuleName;
	gs.pszName = name;
	gs.pszID = uri;
	gs.pszStatusbarText = description;
	gs.dwFlags = 0;
	gs.dwItemData = 0;

	if (CallServiceSync( MS_GC_NEWSESSION, 0, (LPARAM)&gs ))
	{
		SIPE_DEBUG_ERROR("sipe_backend_groupchat_room_add: Failed to create chat session <%d> <%s>", uri, name);
	}

	gcd.pszModule = pr->proto.m_szModuleName;
	gcd.pszID = uri;

	gce.cbSize = sizeof(gce);
	gce.pDest = &gcd;

	gcd.iType = GC_EVENT_CONTROL;
	
	if (CallService( MS_GC_EVENT, 0, (LPARAM)&gce ))
	{
		SIPE_DEBUG_WARNING_NOFORMAT("sipe_backend_groupchat_room_add: Failed to add normal status to chat session");
	}

	gce.pszStatus = "Presenter";
	if (CallService( MS_GC_EVENT, 0, (LPARAM)&gce ))
	{
		SIPE_DEBUG_WARNING_NOFORMAT("sipe_backend_groupchat_room_add: Failed to add presenter status to chat session");
	}


	gcd.iType = GC_EVENT_CONTROL;

	if (CallServiceSync( MS_GC_EVENT, SESSION_INITDONE, (LPARAM)&gce ))
	{
		SIPE_DEBUG_WARNING_NOFORMAT("sipe_backend_groupchat_room_add: Failed to initdone chat session");
	}
	if (CallServiceSync( MS_GC_EVENT, SESSION_ONLINE, (LPARAM)&gce ))
	{
		SIPE_DEBUG_ERROR_NOFORMAT("sipe_backend_groupchat_room_add: Failed to set chat session online\n");
	}

}

void sipe_backend_groupchat_room_terminate(struct sipe_core_public *sipe_public)
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
