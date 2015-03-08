/**
 * @file miranda-status.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-2015 SIPE Project <http://sipe.sourceforge.net/>
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
#include <glib.h>

#include "miranda-version.h"
#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "m_system.h"

#include "sipe-backend.h"
#include "sipe-core.h"
#include "miranda-private.h"

guint sipe_backend_status(struct sipe_core_public *sipe_public)
{
	SIPPROTO* pr = sipe_public->backend_private;
	return MirandaStatusToSipe(pr->proto.m_iStatus);
}

int sipe_miranda_SetStatus( SIPPROTO *pr, int iNewStatus )
{
	int oldStatus;
	if (!pr->m_hServerNetlibUser) return 0;
	if (pr->proto.m_iDesiredStatus == iNewStatus) return 0;

	oldStatus = pr->proto.m_iStatus;
	pr->proto.m_iDesiredStatus = iNewStatus;

	SIPE_DEBUG_INFO("SetStatus: newstatus <%x>", iNewStatus);

	if (iNewStatus == ID_STATUS_OFFLINE) {
		pr->disconnecting = TRUE;
		sipe_miranda_connection_destroy(pr);
		pr->valid = FALSE;
		pr->disconnecting = FALSE;
	} else {
		if (pr->proto.m_iStatus == ID_STATUS_OFFLINE) {
			pr->valid = TRUE;
			pr->state = SIPE_MIRANDA_CONNECTING;
			pr->proto.m_iStatus = ID_STATUS_CONNECTING;
			sipe_miranda_SendBroadcast(pr, NULL, ACKTYPE_STATUS, ACKRESULT_SUCCESS, (HANDLE)oldStatus, pr->proto.m_iStatus);
			sipe_miranda_login(pr);
		} else if (pr->state == SIPE_MIRANDA_CONNECTED) {
			pr->proto.m_iStatus = pr->proto.m_iDesiredStatus;
			sipe_miranda_SendBroadcast(pr, NULL, ACKTYPE_STATUS, ACKRESULT_SUCCESS, (HANDLE)oldStatus, pr->proto.m_iStatus);
			LOCK;
			if (pr->proto.m_iStatus != ID_STATUS_OFFLINE) {
				gchar *note = sipe_miranda_getString(pr, "note");
				sipe_core_status_set(pr->sip, TRUE, MirandaStatusToSipe(iNewStatus), note);
				mir_free(note);
			}
			UNLOCK;
		}
	}


/*
//Will send an ack with:
//type=ACKTYPE_STATUS, result=ACKRESULT_SUCCESS, hProcess=(HANDLE)previousMode, lParam=newMode
//when the change completes. This ack is sent for all changes, not just ones
//caused by calling this function.
//Note that newMode can be ID_STATUS_CONNECTING<=newMode<ID_STATUS_CONNECTING+
//MAX_CONNECT_RETRIES to signify that it's connecting and it's the nth retry.
//Protocols are initially always in offline mode.
//Non-network-level protocol modules do not have the concept of a status and
//should leave this service unimplemented
//If a protocol doesn't support the specific status mode, it should pick the
*/

	return 0;
}

gboolean sipe_backend_status_changed(struct sipe_core_public *sipe_public,
				     guint activity,
				     const gchar *message)
{
	SIPPROTO *pr = sipe_public->backend_private;
	int iNewStatus = SipeStatusToMiranda(activity);
	if (!pr->m_hServerNetlibUser) return FALSE;
	if (pr->proto.m_iDesiredStatus == iNewStatus) return FALSE;
	return(TRUE);
}

void sipe_backend_status_and_note(struct sipe_core_public *sipe_public,
				  guint activity,
				  const gchar *message)
{
	sipe_miranda_SetStatus(sipe_public->backend_private, SipeStatusToMiranda(activity));
}
