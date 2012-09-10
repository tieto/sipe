/**
 * @file sipe-buddy.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-12 SIPE Project <http://sipe.sourceforge.net/>
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
struct sipe_cal_working_hours;

struct sipe_buddy {
	gchar *name;
	gchar *activity;
	gchar *meeting_subject;
	gchar *meeting_location;
	/* Sipe internal format for Note is HTML.
	 * All incoming plain text should be html-escaped
	 * for example by g_markup_escape_text()
	 */
	gchar *note;
	gboolean is_oof_note;
	time_t note_since;

	/* Calendar related fields */
	gchar *cal_start_time;
	int cal_granularity;
	gchar *cal_free_busy_base64;
	gchar *cal_free_busy;
	time_t cal_free_busy_published;
	/* for 2005 systems */
	int user_avail;
	time_t user_avail_since;
	time_t activity_since;
	const char *last_non_cal_status_id;
	gchar *last_non_cal_activity;

	struct sipe_cal_working_hours *cal_working_hours;

	gchar *device_name;
	GSList *groups;
	 /** flag to control sending 'context' element in 2007 subscriptions */
	gboolean just_added;
};

/**
 * Creates @c sipe_buddy structure for a new buddy and adds it into the buddy
 * list of given account. If buddy is already in the list, its existing
 * structure is returned.
 *
 * @param sipe_private SIPE core data
 * @param uri          SIP URI of a buddy
 *
 * @return @c sipe_buddy structure
 */
struct sipe_buddy *sipe_buddy_add(struct sipe_core_private *sipe_private,
				  const gchar *uri);

/**
 * Cancels buddy subscriptions and then deletes the buddy
 *
 * @param sipe_private SIPE core data
 * @param buddy        @c sipe_buddy structure to remove
 */
void sipe_buddy_remove(struct sipe_core_private *sipe_private,
		       struct sipe_buddy *buddy);

/**
 * Free all buddy information
 *
 * @param sipe_private SIPE core data
 */
void sipe_buddy_free_all(struct sipe_core_private *sipe_private);

/**
 * Tries to retrieve a real user's name associated with given SIP URI.
 *
 * Result must be g_free'd after use.
 *
 * @param sipe_private SIPE core data
 * @param with         a SIP URI
 *
 * @return Name of the user if the URI is found in buddy list, otherwise @c NULL
 */
gchar *sipe_buddy_get_alias(struct sipe_core_private *sipe_private,
			    const gchar *with);

/**
 * Update the value of a buddy property with given SIP URI
 *
 * @param sipe_private   SIPE core data
 * @param uri            a SIP URI
 * @param propkey        property id (see sipe-backend.h)
 * @param property_value new value for the property
 */
void sipe_buddy_update_property(struct sipe_core_private *sipe_private,
				const gchar *uri,
				sipe_buddy_info_fields propkey,
				gchar *property_value);

/**
 * Triggers a download of all buddy photos that were changed on the server.
 *
 * @param sipe_private SIPE core data
 */
void sipe_buddy_refresh_photos(struct sipe_core_private *sipe_private);
