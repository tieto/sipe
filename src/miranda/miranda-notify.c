/**
 * @file miranda-notify.c
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

#include <windows.h>
#include <stdio.h>

#include <glib.h>

#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "m_chat.h"
#include "m_database.h"

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "miranda-private.h"

static void notify_message(struct sipe_core_public *sipe_public,
			   struct sipe_backend_chat_session *backend_session,
			   const gchar *who,
			   const gchar *message,
			   int eventtype,
			   const gchar *prefix
			   )
{
        SIPPROTO *pr = sipe_public->backend_private;

	if (backend_session)
	{
		GCDEST gcd = {0};
		GCEVENT gce = {0};
		gchar *msg;

		gcd.pszModule = pr->proto.m_szModuleName;
		gcd.pszID = backend_session->conv;
		gcd.iType = GC_EVENT_INFORMATION;

		msg = mir_alloc(strlen(message)+strlen(prefix)+1);
		mir_snprintf(msg, strlen(message)+strlen(prefix)+1, "%s%s", prefix, message);

		gce.cbSize = sizeof(gce);
		gce.pDest = &gcd;
		gce.pszText = msg;
//	gce.time = mtime; // FIXME: Generate timestamp

		CallService( MS_GC_EVENT, 0, (LPARAM)&gce );
		mir_free(msg);

	} else {
		HANDLE hContact = sipe_backend_buddy_find( sipe_public, who, NULL );
		if (hContact)
		{
			sipe_miranda_AddEvent(pr, hContact, eventtype, time(NULL), DBEF_UTF, strlen(message), (PBYTE)message);
		}
	}

}

void sipe_backend_notify_message_error(struct sipe_core_public *sipe_public,
				       struct sipe_backend_chat_session *backend_session,
				       const gchar *who,
				       const gchar *message)
{
	notify_message(sipe_public, backend_session, who, message, SIPE_EVENTTYPE_ERROR_NOTIFY, "Error: ");
}

void sipe_backend_notify_message_info(struct sipe_core_public *sipe_public,
				      struct sipe_backend_chat_session *backend_session,
				      const gchar *who,
				      const gchar *message)
{
	notify_message(sipe_public, backend_session, who, message, SIPE_EVENTTYPE_INFO_NOTIFY, "Info: ");
}

void sipe_backend_notify_error(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
			       const gchar *title,
			       const gchar *msg)
{
	sipe_miranda_msgbox(msg, title);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
