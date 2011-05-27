/**
 * @file miranda-user.c
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

#include <windows.h>
#include <stdio.h>
#include <glib.h>

#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"

#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
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
	if (pr->sip)
		sipe_core_set_status(pr->sip, note, MirandaStatusToSipe(pr->proto.m_iStatus));
	return 0;
}


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
