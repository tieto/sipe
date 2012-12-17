/**
 * @file sipe-ocs2007.h
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
struct sipmsg;
struct sipe_container;
struct sipe_core_private;

/**
 * Member is directly placed to access level container.
 * For example SIP URI of user is in the container.
 */
#define SIPE_OCS2007_INDENT_MARKED_FMT		"* %s"

/**
 * OCS2007 status ID, availability & activity
 */
guint sipe_ocs2007_availability_from_status(const gchar *sipe_status_id,
					    const gchar **activity_token);
const gchar *sipe_ocs2007_status_from_legacy_availability(guint availability,
							  const gchar *activity);
const gchar *sipe_ocs2007_legacy_activity_description(guint availability);
gboolean sipe_ocs2007_status_is_busy(const gchar *status_id);
gboolean sipe_ocs2007_availability_is_away(guint availability);

/**
 * Publish status (OCS2007+)
 */
void sipe_ocs2007_presence_publish(struct sipe_core_private *sipe_private,
				   gpointer unused);
void sipe_ocs2007_free(struct sipe_core_private *sipe_private);
void sipe_ocs2007_category_publish(struct sipe_core_private *sipe_private);
void sipe_ocs2007_phone_state_publish(struct sipe_core_private *sipe_private);
void sipe_ocs2007_reset_status(struct sipe_core_private *sipe_private);
void sipe_ocs2007_process_roaming_self(struct sipe_core_private *sipe_private,
				       struct sipmsg *msg);

/**
 * OCS2007 Access Levels
 */
const gchar *sipe_ocs2007_access_level_name(guint id);
int sipe_ocs2007_find_access_level(struct sipe_core_private *sipe_private,
				   const gchar *type,
				   const gchar *value,
				   gboolean *is_group_access);
void sipe_ocs2007_change_access_level(struct sipe_core_private *sipe_private,
				      const int container_id,
				      const gchar *type,
				      const gchar *value);

/* buddy menu */
struct sipe_backend_buddy_menu *sipe_ocs2007_access_control_menu(struct sipe_core_private *sipe_private,
								 const gchar *buddy_name);

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
