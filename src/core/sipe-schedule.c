/**
 * @file sipe-schedule.c
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

#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-schedule.h"

struct sipe_schedule {
	/**
	 * Name of action.
	 * Format is <Event>[<Data>...]
	 * Example:  <presence><sip:user@domain.com> or <registration>
	 */
	gchar *name;
	struct sipe_core_private *sipe_private;
	gpointer backend_private;
	gpointer payload;
	sipe_schedule_action action;
	GDestroyNotify destroy;
};

static void sipe_schedule_deallocate(struct sipe_schedule *schedule)
{
	if (schedule->destroy) (*schedule->destroy)(schedule->payload);
	g_free(schedule->name);
	g_free(schedule);
}

void sipe_core_schedule_execute(gpointer data)
{
	struct sipe_schedule *expired = data;
	struct sipe_core_private *sipe_private = expired->sipe_private;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_core_schedule_execute: executing");
	sipe_private->timeouts = g_slist_remove(sipe_private->timeouts, expired);
	SIPE_DEBUG_INFO("sipe_core_schedule_execute timeouts count %d after removal",
			g_slist_length(sipe_private->timeouts));

	(*expired->action)(sipe_private, expired->payload);
	sipe_schedule_deallocate(expired);
}

static struct sipe_schedule *sipe_schedule_allocate(struct sipe_core_private *sipe_private,
						    const gchar *name,
						    gpointer payload,
						    sipe_schedule_action action,
						    GDestroyNotify destroy)
{
	struct sipe_schedule *new;

	/* Make sure each action only exists once */
	sipe_schedule_cancel(sipe_private, name);

	new = g_new0(struct sipe_schedule, 1);
	new->name = g_strdup(name);
	new->sipe_private = sipe_private;
	new->payload = payload;
	new->action = action;
	new->destroy = destroy;
	sipe_private->timeouts = g_slist_append(sipe_private->timeouts, new);
	SIPE_DEBUG_INFO("sipe_schedule_allocate timeouts count %d after addition",
			g_slist_length(sipe_private->timeouts));
	return(new);
}

void sipe_schedule_seconds(struct sipe_core_private *sipe_private,
			   const gchar *name,
			   gpointer payload,
			   guint seconds,
			   sipe_schedule_action action,
			   GDestroyNotify destroy)
{
	struct sipe_schedule *new = sipe_schedule_allocate(sipe_private,
							   name,
							   payload,
							   action,
							   destroy);
	SIPE_DEBUG_INFO("scheduling action %s timeout %d seconds",
			name, seconds);
	new->backend_private = sipe_backend_schedule_seconds(SIPE_CORE_PUBLIC,
							     seconds,
							     new);
}

void sipe_schedule_mseconds(struct sipe_core_private *sipe_private,
			    const gchar *name,
			    gpointer payload,
			    guint milliseconds,
			    sipe_schedule_action action,
			    GDestroyNotify destroy)
{
	struct sipe_schedule *new = sipe_schedule_allocate(sipe_private,
							   name,
							   payload,
							   action,
							   destroy);
	SIPE_DEBUG_INFO("scheduling action %s timeout %d milliseconds",
			name, milliseconds);
	new->backend_private = sipe_backend_schedule_mseconds(SIPE_CORE_PUBLIC,
							      milliseconds,
							      new);
}

void sipe_schedule_cancel(struct sipe_core_private *sipe_private,
			  const gchar *name)
{
	GSList *entry;

	if (!sipe_private->timeouts || !name) return;

	entry = sipe_private->timeouts;
	while (entry) {
		struct sipe_schedule *schedule = entry->data;
		if (sipe_strequal(schedule->name, name)) {
			GSList *to_delete = entry;
			entry = entry->next;
			sipe_private->timeouts = g_slist_delete_link(sipe_private->timeouts,
								     to_delete);
			SIPE_DEBUG_INFO("sipe_schedule_cancel: action name=%s", name);
			sipe_backend_schedule_cancel(SIPE_CORE_PUBLIC,
						     schedule->backend_private);
			sipe_schedule_deallocate(schedule);
		} else {
			entry = entry->next;
		}
	}
}

void sipe_schedule_cancel_all(struct sipe_core_private *sipe_private)
{
	if (sipe_private->timeouts) {
		GSList *entry;
		while ((entry = sipe_private->timeouts) != NULL)
			sipe_schedule_cancel(sipe_private,
					     ((struct sipe_schedule *)entry->data)->name);
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
