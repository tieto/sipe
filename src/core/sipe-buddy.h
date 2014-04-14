/**
 * @file sipe-buddy.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2013 SIPE Project <http://sipe.sourceforge.net/>
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
struct sipe_cal_working_hours;
struct sipe_core_private;
struct sipe_group;

struct sipe_buddy {
	gchar *name;
	gchar *exchange_key;
	gchar *change_key;
	gchar *activity;
	gchar *meeting_subject;
	gchar *meeting_location;
	/* Sipe internal format for Note is HTML.
	 * All incoming plain text should be html-escaped
	 * for example by g_markup_escape_text()
	 */
	gchar *note;
	gboolean is_oof_note;
	gboolean is_mobile;
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
	gboolean is_obsolete;
};

/**
 * Adds UCS Exchange/Change keys to a @c sipe_buddy structure
 *
 * @param sipe_private SIPE core data
 * @param buddy        sipe_buddy data structure
 * @param exchange_key Exchange key (may be @c NULL)
 * @param change_key   Change key (may be @c NULL)
 */
void sipe_buddy_add_keys(struct sipe_core_private *sipe_private,
			 struct sipe_buddy *buddy,
			 const gchar *exchange_key,
			 const gchar *change_key);

/**
 * Creates @c sipe_buddy structure for a new buddy and adds it into the buddy
 * list of given account. If buddy is already in the list, its existing
 * structure is returned.
 *
 * @param sipe_private SIPE core data
 * @param uri          SIP URI of a buddy
 * @param exchange_key Exchange key (may be @c NULL)
 * @param change_key   Change key (may be @c NULL)
 *
 * @return @c sipe_buddy structure
 */
struct sipe_buddy *sipe_buddy_add(struct sipe_core_private *sipe_private,
				  const gchar *uri,
				  const gchar *exchange_key,
				  const gchar *change_key);

/**
 * Add buddy to a group.
 *
 * @param sipe_private SIPE core data
 * @param buddy        sipe_buddy data structure
 * @param group        sipe_group data structure
 * @param alias        alias for the buddy in that group (may be @c NULL)
 */
void sipe_buddy_add_to_group(struct sipe_core_private *sipe_private,
			     struct sipe_buddy *buddy,
			     struct sipe_group *group,
			     const gchar *alias);

/**
 * Insert a group to buddy group list
 *
 * @param buddy        sipe_buddy data structure
 * @param group        sipe_group data structure
 */
void sipe_buddy_insert_group(struct sipe_buddy *buddy,
			     struct sipe_group *group);

/**
 * Update group list for a buddy
 *
 * @param sipe_private SIPE core data
 * @param buddy        sipe_buddy data structure
 * @param group        list with new sipe_group data structures
 */
void sipe_buddy_update_groups(struct sipe_core_private *sipe_private,
			      struct sipe_buddy *buddy,
			      GSList *new_groups);

/**
 * Returns string of group IDs the buddy belongs to, e.g. "2 4 7 8"
 *
 * @param buddy sipe_buddy data structure
 *
 * @result group string. Must be @c g_free()'d after use.
 */
gchar *sipe_buddy_groups_string(struct sipe_buddy *buddy);

/**
 * Remove entries from local buddy list that do not have corresponding entries
 * in the ones in the contact list sent by the server
 *
 * @param sipe_private SIPE core data
 */
void sipe_buddy_cleanup_local_list(struct sipe_core_private *sipe_private);

/**
 * Prepare buddy list for an update
 *
 * @param sipe_private SIPE core data
 */
void sipe_buddy_update_start(struct sipe_core_private *sipe_private);

/**
 * Finish buddy list update. This will remove obsolete buddies.
 *
 * @param sipe_private SIPE core data
 */
void sipe_buddy_update_finish(struct sipe_core_private *sipe_private);

/**
 * Find buddy by URI
 *
 * @param sipe_private SIPE core data
 * @param uri          SIP URI of a buddy
 *
 * @return @c sipe_buddy structure
 */
struct sipe_buddy *sipe_buddy_find_by_uri(struct sipe_core_private *sipe_private,
					  const gchar *uri);

/**
 * Find buddy by Exchange Key
 *
 * @param sipe_private SIPE core data
 * @param uri          Exchange Key of a buddy
 *
 * @return @c sipe_buddy structure
 */
struct sipe_buddy *sipe_buddy_find_by_exchange_key(struct sipe_core_private *sipe_private,
						   const gchar *exchange_key);

/**
 * Iterate buddy list
 *
 * @param sipe_private SIPE core data
 * @param callback          function to call on each buddy
 * @param callback_data     user data for the callback
 */
void sipe_buddy_foreach(struct sipe_core_private *sipe_private,
			GHFunc callback,
			gpointer callback_data);

/**
 * Cancels buddy subscriptions and then deletes the buddy
 *
 * @param sipe_private SIPE core data
 * @param buddy        @c sipe_buddy structure to remove
 */
void sipe_buddy_remove(struct sipe_core_private *sipe_private,
		       struct sipe_buddy *buddy);

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

/**
 * Number of buddies
 *
 * @param sipe_private SIPE core data
 */
guint sipe_buddy_count(struct sipe_core_private *sipe_private);

/**
 * Initialize buddy data
 *
 * @param sipe_private SIPE core data
 */
void sipe_buddy_init(struct sipe_core_private *sipe_private);

/**
 * Free buddy data
 *
 * @param sipe_private SIPE core data
 */
void sipe_buddy_free(struct sipe_core_private *sipe_private);
