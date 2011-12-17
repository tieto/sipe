/**
 * @file miranda-connection.c
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

#include "sipe-backend.h"
#include "sipe-core.h"

#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "miranda-private.h"

void sipe_miranda_connection_destroy(SIPPROTO *pr)
{
	int oldStatus;

	SIPE_DEBUG_INFO("valid <%d> state <%d>", pr->valid, pr->state);
	if (!pr->valid) return;

	set_buddies_offline(pr);
	sipe_miranda_close(pr);
	pr->state = SIPE_MIRANDA_DISCONNECTED;
	pr->valid = FALSE;

	oldStatus = pr->proto.m_iStatus;
	pr->proto.m_iDesiredStatus = ID_STATUS_OFFLINE;
	pr->proto.m_iStatus = pr->proto.m_iDesiredStatus;
	sipe_miranda_SendBroadcast(pr, NULL, ACKTYPE_STATUS, ACKRESULT_SUCCESS, (HANDLE)oldStatus, pr->proto.m_iStatus);
}

static void disconnect_cb(SIPPROTO *pr)
{
	SIPE_DEBUG_INFO_NOFORMAT("");
	if (!pr->valid) return;
	if (pr->state == SIPE_MIRANDA_DISCONNECTED) return;
	pr->disconnecting = TRUE;
	sipe_miranda_connection_destroy(pr);
	pr->valid = FALSE;
	pr->disconnecting = FALSE;
	pr->disconnect_timeout = NULL;
}

void sipe_miranda_connection_error_reason(SIPPROTO *pr, sipe_connection_error error, const gchar *msg)
{
	if (!pr->disconnect_timeout)
	{
		SIPE_DEBUG_INFO("valid <%d> state <%d> error <%d> message <%s>", pr->valid, pr->state, error, msg);
		pr->disconnect_timeout = sipe_miranda_schedule_mseconds(disconnect_cb, 1000, pr);
	}
}

void sipe_backend_connection_completed(struct sipe_core_public *sipe_public)
{
	SIPPROTO *pr = sipe_public->backend_private;
	int oldStatus = pr->proto.m_iStatus;
	pr->state = SIPE_MIRANDA_CONNECTED;
	pr->proto.m_iStatus = pr->proto.m_iDesiredStatus;
	sipe_miranda_SendBroadcast(pr, NULL, ACKTYPE_STATUS, ACKRESULT_SUCCESS, (HANDLE)oldStatus, pr->proto.m_iStatus);
}

void sipe_backend_connection_error(struct sipe_core_public *sipe_public,
				   sipe_connection_error error,
				   const gchar *msg)
{
	SIPE_DEBUG_INFO("reason <%d> message <%s>", error, msg);
	sipe_miranda_connection_error_reason(sipe_public->backend_private, error, msg);
}

gboolean sipe_backend_connection_is_disconnecting(struct sipe_core_public *sipe_public)
{
	SIPPROTO *pr = sipe_public->backend_private;
	return (pr->disconnecting);
}

gboolean sipe_backend_connection_is_valid(struct sipe_core_public *sipe_public)
{
	SIPPROTO *pr = sipe_public->backend_private;
	return (pr->state == SIPE_MIRANDA_CONNECTED);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
