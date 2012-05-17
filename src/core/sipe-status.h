/**
 * @file sipe-status.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011 SIPE Project <http://sipe.sourceforge.net/>
 *
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

/* called by sipe-core.c during plugin initialization/destruction */
void sipe_status_init(void);
void sipe_status_shutdown(void);

/* type == SIPE_ACTIVITY_xxx (see sipe-core.h) */
const gchar *sipe_status_activity_to_token(guint type);
guint sipe_status_token_to_activity(const gchar *token);

void sipe_status_set_token(struct sipe_core_private *sipe_private,
			   const gchar *status_id);
void sipe_status_set_activity(struct sipe_core_private *sipe_private,
			      guint activity);
void sipe_status_and_note(struct sipe_core_private *sipe_private,
			  const gchar *status_id);
void sipe_status_update(struct sipe_core_private *sipe_private,
			gpointer unused);
gboolean sipe_status_changed_by_user(struct sipe_core_private *sipe_private);

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
