/**
 * @file telepathy-schedule.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2012 SIPE Project <http://sipe.sourceforge.net/>
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
#include "sipe-common.h"
#include "sipe-core.h"

static gboolean timeout_execute(gpointer data)
{
	sipe_core_schedule_execute(data);
	return(FALSE);
}

gpointer sipe_backend_schedule_seconds(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				       guint timeout,
				       gpointer data)
{
	return(GUINT_TO_POINTER(g_timeout_add_seconds(timeout, timeout_execute, data)));
}

gpointer sipe_backend_schedule_mseconds(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					guint timeout,
					gpointer data)
{
	return(GUINT_TO_POINTER(g_timeout_add(timeout, timeout_execute, data)));
}

void sipe_backend_schedule_cancel(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				  gpointer data)
{
	g_source_remove(GPOINTER_TO_UINT(data));
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
