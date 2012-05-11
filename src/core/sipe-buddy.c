/**
 * @file sipe-buddy.c
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

#include <glib.h>

#include "sipe-buddy.h"
#include "sipe-core.h"
#include "sipe-core-private.h"

gchar *sipe_core_buddy_status(struct sipe_core_public *sipe_public,
			      const gchar *name,
			      const sipe_activity activity,
			      const gchar *status_text)
{
	struct sipe_buddy *sbuddy;
	const char *activity_str;

	if (!sipe_public) return NULL; /* happens on pidgin exit */

	sbuddy = g_hash_table_lookup(SIPE_CORE_PRIVATE->buddies, name);
	if (!sbuddy) return NULL;

	activity_str = sbuddy->activity ? sbuddy->activity :
		(activity == SIPE_ACTIVITY_BUSY) || (activity == SIPE_ACTIVITY_BRB) ?
		status_text : NULL;

	if (activity_str && sbuddy->note) {
		return g_strdup_printf("%s - <i>%s</i>", activity_str, sbuddy->note);
	} else if (activity_str) {
		return g_strdup(activity_str);
	} else if (sbuddy->note) {
		return g_strdup_printf("<i>%s</i>", sbuddy->note);
	} else {
		return NULL;
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
