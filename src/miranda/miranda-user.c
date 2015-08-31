/**
 * @file miranda-user.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2015 SIPE Project <http://sipe.sourceforge.net/>
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

#include "miranda-version.h"
#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "m_database.h"

#include "sipe-backend.h"
#include "sipe-core.h"
#include "miranda-private.h"

void sipe_backend_user_feedback_typing(struct sipe_core_public *sipe_public,
				       const gchar *from)
{
	HANDLE hContact = sipe_backend_buddy_find( sipe_public, from, NULL );

	if (!hContact)
		return;

	CallService(MS_PROTO_CONTACTISTYPING, (WPARAM)hContact, (LPARAM)6);
}

void sipe_backend_user_feedback_typing_stop(struct sipe_core_public *sipe_public,
					    const gchar *from)
{
	HANDLE hContact = sipe_backend_buddy_find( sipe_public, from, NULL );

	if (!hContact)
		return;

	CallService(MS_PROTO_CONTACTISTYPING, (WPARAM)hContact, (LPARAM)0);
}

void sipe_backend_user_ask(struct sipe_core_public *sipe_public,
			   const gchar *message,
			   const gchar *accept_label,
			   const gchar *decline_label,
			   gpointer key)
{
	_NIF();
}

void sipe_backend_user_close_ask(gpointer key)
{
	_NIF();
}

int sipe_miranda_SetAwayMsg(SIPPROTO *pr,
	       int m_iStatus,
	       const PROTOCHAR* msg)
{
	const gchar *note = TCHAR2CHAR(msg);

	SIPE_DEBUG_INFO("SetAwayMsg: status <%x> msg <%ls>", m_iStatus, msg);
	sipe_miranda_setString(pr, "note", note);
	LOCK;
	if (pr->state == SIPE_MIRANDA_CONNECTED)
		sipe_core_status_set(pr->sip, FALSE, MirandaStatusToSipe(pr->proto.m_iStatus), note);
	UNLOCK;
	return 0;
}

int sipe_miranda_UserIsTyping( SIPPROTO *pr, HANDLE hContact, int type )
{
	SIPE_DEBUG_INFO("type <%x>", type);
	if (hContact)
	{
		DBVARIANT dbv;
		char *name;

		if ( !DBGetContactSettingString( hContact, pr->proto.m_szModuleName, SIP_UNIQUEID, &dbv )) {
			name = g_strdup(dbv.pszVal);
			DBFreeVariant(&dbv);
		} else {
			return 1;
		}

		switch (type) {
			case PROTOTYPE_SELFTYPING_ON:
				LOCK;
				sipe_core_user_feedback_typing(pr->sip, name, TRUE);
				UNLOCK;
				g_free(name);
				return 0;

			case PROTOTYPE_SELFTYPING_OFF:
				/* Not supported anymore? */
				LOCK;
				sipe_core_user_feedback_typing(pr->sip, name, FALSE);
				UNLOCK;
				g_free(name);
				return 0;
		}

		g_free(name);
	}

	return 1;
}


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
