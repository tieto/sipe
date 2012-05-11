/**
 * @file sipe-ocs2005.h
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
struct _sipe_xml;
struct sipe_core_private;

/**
 * OCS2005 status ID, availability & activity
 */
const gchar *sipe_ocs2005_status_from_activity_availability(guint activity,
							    guint availablity);
const gchar *sipe_ocs2005_activity_description(guint activity);

/**
 * Publish status (OCS2005)
 */
void sipe_ocs2005_presence_publish(struct sipe_core_private *sipe_private,
				   gboolean do_publish_calendar);
void sipe_ocs2005_reset_status(struct sipe_core_private *sipe_private);
void sipe_ocs2005_user_info_has_updated(struct sipe_core_private *sipe_private,
					const struct _sipe_xml *xn_userinfo);
void sipe_ocs2005_apply_calendar_status(struct sipe_core_private *sipe_private,
					struct sipe_buddy *sbuddy,
					const char *status_id);
void sipe_ocs2005_schedule_status_update(struct sipe_core_private *sipe_private,
					 time_t calculate_from);

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
