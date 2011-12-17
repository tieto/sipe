/**
 * @file miranda-schedule.c
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

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"

#include "newpluginapi.h"
#include "m_system.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "miranda-private.h"

struct time_entry {
	gpointer core_data;
	guint timeout;
	HANDLE sem;
	gboolean cancelled;
	SIPPROTO *pr;
	void (*callback)(gpointer);

	/* Private. For locking only */
	HANDLE hDoneEvent;
};

static void __stdcall
timeout_cb_async(void *data)
{
	struct time_entry *entry = (struct time_entry*)data;
        SIPPROTO *pr = entry->pr;

	if (entry->cancelled == TRUE)
	{
		SIPE_DEBUG_INFO("Entry <%08x> already cancelled. Not calling timeout function", entry);
	} else {
		SIPE_DEBUG_INFO("Calling timeout function for entry <%08x>", entry);
		LOCK;
		entry->callback(entry->core_data);
		UNLOCK;
	}
	SetEvent(entry->hDoneEvent);
}

static unsigned __stdcall timeoutfunc(void* data)
{
	struct time_entry *entry = (struct time_entry*)data;
	DWORD ret;
        SIPPROTO *pr = entry->pr;

	SIPE_DEBUG_INFO("timeout start; <%08x> timeout is <%d>", entry, entry->timeout);

	entry->sem = CreateSemaphore(NULL, 0, 100, NULL);

	ret = WaitForSingleObjectEx( entry->sem, entry->timeout, FALSE);
	if (entry->cancelled == TRUE)
	{
		SIPE_DEBUG_INFO("<%08x> Timeout cancelled by caller", entry);
	}
	else if (ret == WAIT_TIMEOUT)
	{
		SIPE_DEBUG_INFO("<%08x> about to run", entry);
		if (entry->cancelled == TRUE)
		{
			SIPE_DEBUG_INFO("<%08x> Timeout cancelled by caller in the nick of time", entry);
		}
		else
		{
			entry->hDoneEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
			CallFunctionAsync(timeout_cb_async, entry);
			WaitForSingleObject(entry->hDoneEvent, INFINITE);
			CloseHandle(entry->hDoneEvent);
		}
		SIPE_DEBUG_INFO("<%08x> exiting", entry);
	}
	else
	{
		SIPE_DEBUG_INFO("<%08x> Something unexpected happened: <%d>", entry, ret);
	}

	CloseHandle(entry->sem);
	g_free(entry);
	return 0;

}

gpointer sipe_miranda_schedule_mseconds(void (*callback)(gpointer),
					guint timeout,
					gpointer data)
{
	struct time_entry *entry;

	entry = g_new0(struct time_entry,1);
	entry->timeout = timeout;
	entry->core_data = data;
	entry->cancelled = FALSE;
	entry->pr = data; /* FIXME: Assumes data = SIPPROTO * */
	entry->callback = callback;

	SIPE_DEBUG_INFO("Scheduling timeout in <%u>ms for entry <%08x>", timeout, entry);
	CloseHandle((HANDLE) mir_forkthreadex( timeoutfunc, entry, 65536, NULL ));

	return entry;
}

gpointer sipe_backend_schedule_mseconds(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					guint timeout,
					gpointer data)
{
	struct time_entry *entry;

	entry = g_new0(struct time_entry,1);
	entry->timeout = timeout;
	entry->core_data = data;
	entry->cancelled = FALSE;
	entry->pr = sipe_public->backend_private;
	entry->callback = sipe_core_schedule_execute;

	CloseHandle((HANDLE) mir_forkthreadex( timeoutfunc, entry, 65536, NULL ));

	return entry;
}

gpointer sipe_backend_schedule_seconds(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				       guint timeout,
				       gpointer data)
{
	return sipe_backend_schedule_mseconds( sipe_public, timeout*1000, data);
}

void sipe_backend_schedule_cancel(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				  gpointer data)
{
	struct time_entry *entry = (struct time_entry*) data;

	if (entry && entry->sem)
	{
		SIPE_DEBUG_INFO("Cancelling timeout <%08x>", entry);
		entry->cancelled = TRUE;
		ReleaseSemaphore(entry->sem, 1, NULL);
	}

}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
