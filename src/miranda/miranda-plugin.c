/**
 * @file miranda-plugin.c
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
#include <glib.h>

#include "sipe-common.h"

#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-nls.h"

#include "newpluginapi.h"
#include "m_protosvc.h"
#include "m_system.h"

/* Sipe core activity <-> Miranda status mapping */
static const gchar * const activity_to_miranda[SIPE_ACTIVITY_NUM_TYPES] = {
	/* SIPE_ACTIVITY_UNSET       */ "unset",
	/* SIPE_ACTIVITY_ONLINE      */ "online",
	/* SIPE_ACTIVITY_INACTIVE    */ "idle",
	/* SIPE_ACTIVITY_BUSY        */ "busy",
	/* SIPE_ACTIVITY_BUSYIDLE    */ "busyidle",
	/* SIPE_ACTIVITY_DND         */ "do-not-disturb",
	/* SIPE_ACTIVITY_BRB         */ "be-right-back",
	/* SIPE_ACTIVITY_AWAY        */ "away",
	/* SIPE_ACTIVITY_LUNCH       */ "out-to-lunch",
	/* SIPE_ACTIVITY_OFFLINE     */ "offline", 
	/* SIPE_ACTIVITY_ON_PHONE    */ "on-the-phone",
	/* SIPE_ACTIVITY_IN_CONF     */ "in-a-conference",
	/* SIPE_ACTIVITY_IN_MEETING  */ "in-a-meeting",
	/* SIPE_ACTIVITY_OOF         */ "out-of-office",
	/* SIPE_ACTIVITY_URGENT_ONLY */ "urgent-interruptions-only",
};
GHashTable *miranda_to_activity = NULL;
#define MIRANDA_STATUS_TO_ACTIVITY(x) \
	GPOINTER_TO_UINT(g_hash_table_lookup(miranda_to_activity, (x)))

static void sipe_miranda_activity_init(void)
{
	sipe_activity index = SIPE_ACTIVITY_UNSET;
	miranda_to_activity = g_hash_table_new(g_str_hash, g_str_equal);
	while (index < SIPE_ACTIVITY_NUM_TYPES) {
		g_hash_table_insert(miranda_to_activity,
				    (gpointer) activity_to_miranda[index],
				    GUINT_TO_POINTER(index));
		index++;
	}
}

gchar *sipe_backend_version(void)
{
	char version[200];

	if (CallService(MS_SYSTEM_GETVERSIONTEXT, sizeof(version), (LPARAM)version)) {
		strcpy(version, "Unknown");
	}

	return g_strdup_printf("Miranda %s SipSimple " __DATE__ " " __TIME__, version );
}

static void sipe_miranda_activity_destroy(void)
{
	g_hash_table_destroy(miranda_to_activity);
	miranda_to_activity = NULL;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
