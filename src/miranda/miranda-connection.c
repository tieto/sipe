/**
 * @file miranda-connection.c
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

#include "sipe-backend.h"
#include "sipe-core.h"

#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "miranda-private.h"

void sipe_backend_connection_completed(struct sipe_core_public *sipe_public)
{
	SIPPROTO *pr = sipe_public->backend_private;
	_NIF();
}

void sipe_backend_connection_error(struct sipe_core_public *sipe_public,
				   sipe_connection_error error,
				   const gchar *msg)
{
	SIPPROTO *pr = sipe_public->backend_private;

	int oldStatus = pr->proto.m_iStatus;

	pr->proto.m_iDesiredStatus = ID_STATUS_OFFLINE;
	pr->proto.m_iStatus = pr->proto.m_iDesiredStatus;
	SendBroadcast(pr, NULL, ACKTYPE_STATUS, ACKRESULT_SUCCESS, (HANDLE)oldStatus, pr->proto.m_iStatus);
	/* TODO: Bring up a dialog box */
}

gboolean sipe_backend_connection_is_disconnecting(struct sipe_core_public *sipe_public)
{
	SIPPROTO *pr = sipe_public->backend_private;
	_NIF();
	return FALSE;
}

gboolean sipe_backend_connection_is_valid(struct sipe_core_public *sipe_public)
{
	SIPPROTO *pr = sipe_public->backend_private;
	_NIF();
	return TRUE;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
