/**
 * @file sipe-schedule.h
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

/* Forward declarations */
struct sipe_core_private;

typedef void (*sipe_schedule_action)(struct sipe_core_private *sipe_private,
				     gpointer data);

/**
  * Do schedule action for execution in the future.
  * Non repetitive execution.
  *
  * @param sipe_core_private
  * @param name of action (will be copied)
  * @param timeout in seconds or milliseconds
  * @param action  callback function
  * @param destroy payload destroy function
  * @param payload callback data (can be NULL, otherwise caller must allocate memory)
  */
void sipe_schedule_seconds(struct sipe_core_private *sipe_private,
			   const gchar *name,
			   gpointer payload,
			   guint seconds,
			   sipe_schedule_action action,
			   GDestroyNotify destroy);
void sipe_schedule_mseconds(struct sipe_core_private *sipe_private,
			    const gchar *name,
			    gpointer payload,
			    guint milliseconds,
			    sipe_schedule_action action,
			    GDestroyNotify destroy);
void sipe_schedule_cancel(struct sipe_core_private *sipe_private,
			  const gchar *name);
void sipe_schedule_cancel_all(struct sipe_core_private *sipe_private);

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
