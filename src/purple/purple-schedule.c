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

#include "eventloop.h"

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"

struct purple_schedule {
	gpointer core_data;
	guint timeout_handler;
};

static gboolean purple_timeout_execute(gpointer data)
{
	gpointer core_data = ((struct purple_schedule *) data)->core_data;
	g_free(data);
 	sipe_core_schedule_execute(core_data);
	return(FALSE);
}

gpointer sipe_backend_schedule_seconds(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				       guint timeout,
				       gpointer data)
{
	struct purple_schedule *schedule = g_malloc(sizeof(struct purple_schedule));
	schedule->core_data = data;
	schedule->timeout_handler = purple_timeout_add_seconds(timeout,
							       purple_timeout_execute,
							       schedule);
	return(schedule);
}

gpointer sipe_backend_schedule_mseconds(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					guint timeout,
					gpointer data)
{
	struct purple_schedule *schedule = g_malloc(sizeof(struct purple_schedule));
	schedule->core_data = data;
	schedule->timeout_handler = purple_timeout_add(timeout,
						       purple_timeout_execute,
						       schedule);
	return(schedule);
}

void sipe_backend_schedule_cancel(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				  gpointer data)
{
	struct purple_schedule *schedule = data;
	purple_timeout_remove(schedule->timeout_handler);
	g_free(schedule);
}
	
/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
