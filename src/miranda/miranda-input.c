/**
 * @file miranda-input.c
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

#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_protoint.h"
#include "m_netlib.h"
#include "miranda-private.h"

#define ENTRY_SIG 0x88442211

static NETLIBSELECTEX m_select = {0};
static GHashTable *m_readhash = NULL;
static GHashTable *m_writehash = NULL;
static GList *m_entries = NULL;

typedef struct sipe_miranda_sel_entry
{
	int sig;
	HANDLE fd;
	sipe_miranda_input_function func;
	gpointer user_data;
	gboolean async;

	/* Private. For locking only */
	HANDLE hDoneEvent;
	gint source;
	sipe_miranda_input_condition cond;
};

static void __stdcall
input_cb_async(void *data)
{
	struct sipe_miranda_sel_entry *entry = (struct sipe_miranda_sel_entry*)data;
	if (entry->fd == NULL)
	{
		SIPE_DEBUG_INFO("[IE:%08x] Entry already removed. Not calling read/write function", entry);
	} else {
		SIPE_DEBUG_INFO("[IE:%08x] Calling real read/write function", entry);
		entry->func(entry->user_data, entry->source, entry->cond);
	}
	SetEvent(entry->hDoneEvent);
}

static unsigned __stdcall
inputloop(void* data)
{
	int cnt;
	struct sipe_miranda_sel_entry *entry;
	INT_PTR lstRes;

	m_select.cbSize = sizeof(m_select);
	m_select.dwTimeout = 6000;

	while( m_select.hReadConns[0] || m_select.hWriteConns[0])
	{
		int rc=0;
		int wc=0;
		for ( rc=0 ; m_select.hReadConns[rc] ; rc++ );
		for ( wc=0 ; m_select.hWriteConns[wc] ; wc++ );

		SIPE_DEBUG_INFO("About to run select on <%d> read and <%d> write", rc, wc);
		lstRes = CallService(MS_NETLIB_SELECTEX, 0, (LPARAM)&m_select);

		if (lstRes < 0)
		{
			SIPE_DEBUG_INFO_NOFORMAT("Connection failed while waiting.");
			break;
		}
		else if (lstRes == 0)
		{
			SIPE_DEBUG_INFO_NOFORMAT("Select Timeout.");
		}
		else
		{
			SIPE_DEBUG_INFO_NOFORMAT("Back from select");

			for ( cnt=0 ; m_select.hReadConns[cnt] ; cnt++ )
			{
				DWORD wr;
				if (!m_select.hReadStatus[cnt]) continue;
				SIPE_DEBUG_INFO("FD at position <%d> ready to read.", cnt);
				entry = (struct sipe_miranda_sel_entry*)g_hash_table_lookup(m_readhash, (gconstpointer)m_select.hReadConns[cnt]);
				if (!entry)
				{
					SIPE_DEBUG_INFO_NOFORMAT("ERROR: no read handler found.");
					continue;
				}
				SIPE_DEBUG_INFO("[IE:%08x] About to call read function.", entry);
				entry->source = (gint)m_select.hReadConns[cnt];
				entry->cond = SIPE_MIRANDA_INPUT_READ;
				entry->hDoneEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
				if (entry->async)
				{
					CallFunctionAsync(input_cb_async, entry);
					wr = WaitForSingleObject(entry->hDoneEvent, INFINITE);
				} else {
					input_cb_async(entry);
				}
				CloseHandle(entry->hDoneEvent);
				SIPE_DEBUG_INFO("[IE:%08x] read function returned.", entry);
			}

			for ( cnt=0 ; m_select.hWriteConns[cnt] ; cnt++ )
			{
				if (!m_select.hWriteStatus[cnt]) continue;
				SIPE_DEBUG_INFO("FD at position <%d> ready to write.", cnt);
				entry = (struct sipe_miranda_sel_entry*)g_hash_table_lookup(m_writehash, (gconstpointer)m_select.hWriteConns[cnt]);
				if (!entry)
				{
					SIPE_DEBUG_INFO_NOFORMAT("ERROR: no write handler found.");
					continue;
				}
				SIPE_DEBUG_INFO("[IE:%08x] About to call write function.", entry);
				entry->source = (gint)m_select.hWriteConns[cnt];
				entry->cond = SIPE_MIRANDA_INPUT_WRITE;
				entry->hDoneEvent = CreateEvent(NULL, FALSE, FALSE, NULL);
				if (entry->async)
				{
					CallFunctionAsync(input_cb_async, entry);
					WaitForSingleObject(entry->hDoneEvent, INFINITE);
				} else {
					input_cb_async(entry);
				}
				CloseHandle(entry->hDoneEvent);
				SIPE_DEBUG_INFO("[IE:%08x] write function returned.", entry);
			}
		}

		/* Free all removed entries */
		while (m_entries) g_list_delete_link(m_entries, g_list_last(m_entries));
	}

	return 0;
}

struct sipe_miranda_sel_entry*
sipe_miranda_input_add(HANDLE fd, sipe_miranda_input_condition cond, sipe_miranda_input_function func, gpointer user_data)
{
	int rcnt = 0;
	int wcnt = 0;
	struct sipe_miranda_sel_entry *entry;

	if (!m_readhash)
		m_readhash = g_hash_table_new(NULL, NULL);

	if (!m_writehash)
		m_writehash = g_hash_table_new(NULL, NULL);

	if ((cond != SIPE_MIRANDA_INPUT_READ) && (cond != SIPE_MIRANDA_INPUT_WRITE))
	{
		SIPE_DEBUG_INFO("Invalid input condition <%d> cond.", cond);
		return 0;
	}

	entry = g_new0(struct sipe_miranda_sel_entry,1);
	entry->sig = ENTRY_SIG;
	entry->func = func;
	entry->user_data = user_data;
	entry->fd = fd;
	entry->async = FALSE;

	if (cond == SIPE_MIRANDA_INPUT_READ)
	{
		for ( wcnt=0 ; m_select.hWriteConns[wcnt] ; wcnt++ );
		for ( rcnt=0 ; m_select.hReadConns[rcnt] && m_select.hReadConns[rcnt]!=(HANDLE)fd ; rcnt++ );
		g_hash_table_replace( m_readhash, (gpointer)fd, entry );
		m_select.hReadStatus[rcnt] = FALSE;
		m_select.hReadConns[rcnt] = (HANDLE)fd;
	}
	else if (cond == SIPE_MIRANDA_INPUT_WRITE)
	{
		for ( rcnt=0 ; m_select.hReadConns[rcnt] ; rcnt++ );
		for ( wcnt=0 ; m_select.hWriteConns[wcnt] && m_select.hWriteConns[wcnt]!=(HANDLE)fd ; wcnt++ );
		g_hash_table_replace( m_writehash, (gpointer)fd, entry );
		m_select.hWriteStatus[rcnt] = FALSE;
		m_select.hWriteConns[rcnt] = (HANDLE)fd;
	}

	if (!(rcnt+wcnt))
		CloseHandle((HANDLE) mir_forkthreadex( inputloop, NULL, 8192, NULL ));

	SIPE_DEBUG_INFO_NOFORMAT("Added input handler.");
	return entry;
}

gboolean
sipe_miranda_input_remove(struct sipe_miranda_sel_entry *entry)
{
	int cnt;

	if (!entry)
	{
		SIPE_DEBUG_INFO_NOFORMAT("Not a valid entry. NULL.");
		return FALSE;
	}

	if (entry->sig != ENTRY_SIG)
	{
		SIPE_DEBUG_INFO("Not a valid entry. Sig is <%08x>.", entry->sig);
		return FALSE;
	}

	if (g_hash_table_lookup(m_readhash, (gconstpointer)entry->fd) == entry)
	{
		for ( cnt=0 ; m_select.hReadConns[cnt] && m_select.hReadConns[cnt]!=(HANDLE)entry->fd ; cnt++ );
		for ( ; m_select.hReadConns[cnt] ; cnt++ ) m_select.hReadConns[cnt] = m_select.hReadConns[cnt+1];
		g_hash_table_remove(m_readhash, (gconstpointer)entry->fd);
	}

	if (g_hash_table_lookup(m_writehash, (gconstpointer)entry->fd) == entry)
	{
		for ( cnt=0 ; m_select.hWriteConns[cnt] && m_select.hWriteConns[cnt]!=(HANDLE)entry->fd ; cnt++ );
		for ( ; m_select.hWriteConns[cnt] ; cnt++ ) m_select.hWriteConns[cnt] = m_select.hWriteConns[cnt+1];
		g_hash_table_remove(m_writehash, (gconstpointer)entry->fd);
	}

	/* Set fd to NULL so we won't try to call the callback if we're
	   currently waiting to get back to the main thread */
	entry->fd = NULL;

	/* Add it to the list of entries that can be freed after the next select
	 * loop in the thread that's handling the actual select
	 */
	g_list_append( m_entries, entry );

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
