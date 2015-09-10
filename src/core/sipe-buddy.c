/**
 * @file sipe-buddy.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2017 SIPE Project <http://sipe.sourceforge.net/>
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
 *
 * GetUserPhoto operation
 *  <http://msdn.microsoft.com/en-us/library/office/jj900502.aspx>
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <glib.h>

#include "sipe-common.h"
#include "sipmsg.h"
#include "sip-csta.h"
#include "sip-soap.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-buddy.h"
#include "sipe-cal.h"
#include "sipe-chat.h"
#include "sipe-conf.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-appshare.h"
#include "sipe-digest.h"
#include "sipe-group.h"
#include "sipe-http.h"
#include "sipe-im.h"
#include "sipe-media.h"
#include "sipe-nls.h"
#include "sipe-ocs2005.h"
#include "sipe-ocs2007.h"
#include "sipe-schedule.h"
#include "sipe-session.h"
#include "sipe-status.h"
#include "sipe-subscriptions.h"
#include "sipe-svc.h"
#include "sipe-ucs.h"
#include "sipe-utils.h"
#include "sipe-webticket.h"
#include "sipe-xml.h"

struct sipe_buddies {
	GHashTable *uri;
	GHashTable *exchange_key;

	/* Pending photo download HTTP requests */
	GSList *pending_photo_requests;
};

struct buddy_group_data {
	const struct sipe_group *group;
	gboolean is_obsolete;
};

struct photo_response_data {
	gchar *who;
	gchar *photo_hash;
	struct sipe_http_request *request;
};

static void buddy_fetch_photo(struct sipe_core_private *sipe_private,
			      const gchar *uri);
static void photo_response_data_free(struct photo_response_data *data);

void sipe_buddy_add_keys(struct sipe_core_private *sipe_private,
			 struct sipe_buddy *buddy,
			 const gchar *exchange_key,
			 const gchar *change_key)
{
	if (exchange_key) {
		buddy->exchange_key = g_strdup(exchange_key);
		g_hash_table_insert(sipe_private->buddies->exchange_key,
				    buddy->exchange_key,
				    buddy);
	}
	if (change_key)
		buddy->change_key = g_strdup(change_key);
}

struct sipe_buddy *sipe_buddy_add(struct sipe_core_private *sipe_private,
				  const gchar *uri,
				  const gchar *exchange_key,
				  const gchar *change_key)
{
	/* Buddy name must be lower case as we use purple_normalize_nocase() to compare */
	gchar *normalized_uri = g_ascii_strdown(uri, -1);
	struct sipe_buddy *buddy = sipe_buddy_find_by_uri(sipe_private,
							  normalized_uri);

	if (!buddy) {
		buddy = g_new0(struct sipe_buddy, 1);
		buddy->name = normalized_uri;
		g_hash_table_insert(sipe_private->buddies->uri,
				    buddy->name,
				    buddy);

		sipe_buddy_add_keys(sipe_private,
				    buddy,
				    exchange_key,
				    change_key);

		SIPE_DEBUG_INFO("sipe_buddy_add: Added buddy %s", normalized_uri);

		if (SIPE_CORE_PRIVATE_FLAG_IS(SUBSCRIBED_BUDDIES)) {
			buddy->just_added = TRUE;
			sipe_subscribe_presence_single_cb(sipe_private,
							  buddy->name);
		}

		buddy_fetch_photo(sipe_private, normalized_uri);

		normalized_uri = NULL; /* buddy takes ownership */
	} else {
		SIPE_DEBUG_INFO("sipe_buddy_add: Buddy %s already exists", normalized_uri);
		buddy->is_obsolete = FALSE;
	}
	g_free(normalized_uri);

	return(buddy);
}

static gboolean is_buddy_in_group(struct sipe_buddy *buddy,
				  const gchar *name)
{
	if (buddy) {
		GSList *entry = buddy->groups;

		while (entry) {
			struct buddy_group_data *bgd = entry->data;
			if (sipe_strequal(bgd->group->name, name)) {
				bgd->is_obsolete = FALSE;
				return(TRUE);
			}
			entry = entry->next;
		}
	}

	return(FALSE);
}

void sipe_buddy_add_to_group(struct sipe_core_private *sipe_private,
			     struct sipe_buddy *buddy,
			     struct sipe_group *group,
			     const gchar *alias)
{
	const gchar *uri = buddy->name;
	const gchar *group_name = group->name;
	sipe_backend_buddy bb = sipe_backend_buddy_find(SIPE_CORE_PUBLIC,
							uri,
							group_name);

	if (!bb) {
		bb = sipe_backend_buddy_add(SIPE_CORE_PUBLIC,
					    uri,
					    alias,
					    group_name);
		SIPE_DEBUG_INFO("sipe_buddy_add_to_group: created backend buddy '%s' with alias '%s'",
				uri, alias ? alias : "<NONE>");
	}


	if (!is_empty(alias)) {
		gchar *old_alias = sipe_backend_buddy_get_alias(SIPE_CORE_PUBLIC,
								bb);

		if (sipe_strcase_equal(sipe_get_no_sip_uri(uri),
				       old_alias)) {
			sipe_backend_buddy_set_alias(SIPE_CORE_PUBLIC,
						     bb,
						     alias);
			SIPE_DEBUG_INFO("sipe_buddy_add_to_group: replaced alias for buddy '%s': old '%s' new '%s'",
					uri, old_alias, alias);
		}
		g_free(old_alias);
	}

	if (!is_buddy_in_group(buddy, group_name)) {
		sipe_buddy_insert_group(buddy, group);
		SIPE_DEBUG_INFO("sipe_buddy_add_to_group: added buddy %s to group %s",
				uri, group_name);
	}
}

static gint buddy_group_compare(gconstpointer a, gconstpointer b)
{
	return(((const struct buddy_group_data *)a)->group->id -
	       ((const struct buddy_group_data *)b)->group->id);
}

void sipe_buddy_insert_group(struct sipe_buddy *buddy,
			     struct sipe_group *group)
{
	struct buddy_group_data *bgd = g_new0(struct buddy_group_data, 1);

	bgd->group = group;

	buddy->groups = sipe_utils_slist_insert_unique_sorted(buddy->groups,
							      bgd,
							      buddy_group_compare,
							      NULL);
}

static void buddy_group_free(gpointer data)
{
	g_free(data);
}

static void buddy_group_remove(struct sipe_buddy *buddy,
			       struct buddy_group_data *bgd)
{
	buddy->groups = g_slist_remove(buddy->groups, bgd);
	buddy_group_free(bgd);
}

static void sipe_buddy_remove_group(struct sipe_buddy *buddy,
				    const struct sipe_group *group)
{
	GSList *entry = buddy->groups;
	struct buddy_group_data *bgd = NULL;

	while (entry) {
		bgd = entry->data;
		if (bgd->group == group)
			break;
		entry = entry->next;
	}

	buddy_group_remove(buddy, bgd);
}

void sipe_buddy_update_groups(struct sipe_core_private *sipe_private,
			      struct sipe_buddy *buddy,
			      GSList *new_groups)
{
	const gchar *uri = buddy->name;
	GSList *entry = buddy->groups;

	while (entry) {
		struct buddy_group_data *bgd = entry->data;
		const struct sipe_group *group = bgd->group;

		/* next buddy group */
		entry = entry->next;

		/* old group NOT found in new list? */
		if (g_slist_find(new_groups, group) == NULL) {
			sipe_backend_buddy oldb = sipe_backend_buddy_find(SIPE_CORE_PUBLIC,
									  uri,
									  group->name);
			SIPE_DEBUG_INFO("sipe_buddy_update_groups: removing buddy %s from group '%s'",
					uri, group->name);
			/* this should never be NULL */
			if (oldb)
				sipe_backend_buddy_remove(SIPE_CORE_PUBLIC,
							  oldb);
			buddy_group_remove(buddy, bgd);
		}
	}
}

gchar *sipe_buddy_groups_string(struct sipe_buddy *buddy)
{
	guint i = 0;
	gchar *string;
	/* creating array from GList, converting guint to gchar * */
	gchar **ids_arr = g_new(gchar *, g_slist_length(buddy->groups) + 1);
	GSList *entry = buddy->groups;

	if (!ids_arr)
		return(NULL);

	while (entry) {
		const struct sipe_group *group = ((struct buddy_group_data *) entry->data)->group;
		ids_arr[i] = g_strdup_printf("%u", group->id);
		entry = entry->next;
		i++;
	}
	ids_arr[i] = NULL;

	string = g_strjoinv(" ", ids_arr);
	g_strfreev(ids_arr);

	return(string);
}

void sipe_buddy_cleanup_local_list(struct sipe_core_private *sipe_private)
{
	GSList *buddies = sipe_backend_buddy_find_all(SIPE_CORE_PUBLIC,
						      NULL,
						      NULL);
	GSList *entry = buddies;

	SIPE_DEBUG_INFO("sipe_buddy_cleanup_local_list: overall %d backend buddies (including clones)",
			g_slist_length(buddies));
	SIPE_DEBUG_INFO("sipe_buddy_cleanup_local_list: %d sipe buddies (unique)",
			sipe_buddy_count(sipe_private));
	while (entry) {
		sipe_backend_buddy bb = entry->data;
		gchar *bname = sipe_backend_buddy_get_name(SIPE_CORE_PUBLIC,
							   bb);
		gchar *gname = sipe_backend_buddy_get_group_name(SIPE_CORE_PUBLIC,
								 bb);
		struct sipe_buddy *buddy = sipe_buddy_find_by_uri(sipe_private,
								  bname);

		if (!is_buddy_in_group(buddy, gname)) {
			SIPE_DEBUG_INFO("sipe_buddy_cleanup_local_list: REMOVING '%s' from local group '%s', as buddy is not in that group on remote contact list",
					bname, gname);
			sipe_backend_buddy_remove(SIPE_CORE_PUBLIC, bb);
		}

		g_free(gname);
		g_free(bname);

		entry = entry->next;
	}

	g_slist_free(buddies);
}

struct sipe_buddy *sipe_buddy_find_by_uri(struct sipe_core_private *sipe_private,
					  const gchar *uri)
{
	if (!uri) return(NULL);
	return(g_hash_table_lookup(sipe_private->buddies->uri, uri));
}

struct sipe_buddy *sipe_buddy_find_by_exchange_key(struct sipe_core_private *sipe_private,
						   const gchar *exchange_key)
{
	return(g_hash_table_lookup(sipe_private->buddies->exchange_key,
				   exchange_key));
}

void sipe_buddy_foreach(struct sipe_core_private *sipe_private,
			GHFunc callback,
			gpointer callback_data)
{
	g_hash_table_foreach(sipe_private->buddies->uri,
			     callback,
			     callback_data);
}

static void buddy_free(struct sipe_buddy *buddy)
{
#ifndef _WIN32
	 /*
	  * We are calling g_hash_table_foreach_steal(). That means that no
	  * key/value deallocation functions are called. Therefore the glib
	  * hash code does not touch the key (buddy->name) or value (buddy)
	  * of the to-be-deleted hash node at all. It follows that we
	  *
	  *   - MUST free the memory for the key ourselves and
	  *   - ARE allowed to do it in this function
	  *
	  * Conclusion: glib must be broken on the Windows platform if sipe
	  *             crashes with SIGTRAP when closing. You'll have to live
	  *             with the memory leak until this is fixed.
	  */
	g_free(buddy->name);
#endif
	g_free(buddy->exchange_key);
	g_free(buddy->change_key);
	g_free(buddy->activity);
	g_free(buddy->meeting_subject);
	g_free(buddy->meeting_location);
	g_free(buddy->note);

	g_free(buddy->cal_start_time);
	g_free(buddy->cal_free_busy_base64);
	g_free(buddy->cal_free_busy);
	g_free(buddy->last_non_cal_activity);

	sipe_cal_free_working_hours(buddy->cal_working_hours);

	g_free(buddy->device_name);
	sipe_utils_slist_free_full(buddy->groups, buddy_group_free);
	g_free(buddy);
}

static gboolean buddy_free_cb(SIPE_UNUSED_PARAMETER gpointer key,
			      gpointer buddy,
			      SIPE_UNUSED_PARAMETER gpointer user_data)
{
	buddy_free(buddy);
	/* We must return TRUE as the key/value have already been deleted */
	return(TRUE);
}

void sipe_buddy_free(struct sipe_core_private *sipe_private)
{
	struct sipe_buddies *buddies = sipe_private->buddies;

	g_hash_table_foreach_steal(buddies->uri,
				   buddy_free_cb,
				   NULL);

	/* core is being deallocated, remove all its pending photo requests */
	while (buddies->pending_photo_requests) {
		struct photo_response_data *data =
			buddies->pending_photo_requests->data;
		buddies->pending_photo_requests =
			g_slist_remove(buddies->pending_photo_requests, data);
		photo_response_data_free(data);
	}

	g_hash_table_destroy(buddies->uri);
	g_hash_table_destroy(buddies->exchange_key);
	g_free(buddies);
	sipe_private->buddies = NULL;
}

static void buddy_set_obsolete_flag(SIPE_UNUSED_PARAMETER gpointer key,
				    gpointer value,
				    SIPE_UNUSED_PARAMETER gpointer user_data)
{
	struct sipe_buddy *buddy = value;
	GSList *entry = buddy->groups;

	buddy->is_obsolete = TRUE;
	while (entry) {
		((struct buddy_group_data *) entry->data)->is_obsolete = TRUE;
		entry = entry->next;
	}
}

void sipe_buddy_update_start(struct sipe_core_private *sipe_private)
{
	g_hash_table_foreach(sipe_private->buddies->uri,
			     buddy_set_obsolete_flag,
			     NULL);
}

static gboolean buddy_check_obsolete_flag(SIPE_UNUSED_PARAMETER gpointer key,
					  gpointer value,
					  gpointer user_data)
{
	struct sipe_core_private *sipe_private = user_data;
	struct sipe_buddy *buddy = value;
	const gchar *uri = buddy->name;

	if (buddy->is_obsolete) {
		/* all backend buddies in different groups */
		GSList *buddies = sipe_backend_buddy_find_all(SIPE_CORE_PUBLIC,
							      uri,
							      NULL);
		GSList *entry = buddies;

		SIPE_DEBUG_INFO("buddy_check_obsolete_flag: REMOVING %d backend buddies for '%s'",
				g_slist_length(buddies),
				uri);

		while (entry) {
			sipe_backend_buddy_remove(SIPE_CORE_PUBLIC,
						  entry->data);
			entry = entry->next;
		}
		g_slist_free(buddies);

		buddy_free(buddy);
		/* return TRUE as the key/value have already been deleted */
		return(TRUE);

	} else {
		GSList *entry = buddy->groups;

		while (entry) {
			struct buddy_group_data *bgd = entry->data;

			/* next buddy group */
			entry = entry->next;

			if (bgd->is_obsolete) {
				const struct sipe_group *group = bgd->group;
				sipe_backend_buddy oldb = sipe_backend_buddy_find(SIPE_CORE_PUBLIC,
										  uri,
										  group->name);
				SIPE_DEBUG_INFO("buddy_check_obsolete_flag: removing buddy '%s' from group '%s'",
						uri, group->name);
				/* this should never be NULL */
				if (oldb)
					sipe_backend_buddy_remove(SIPE_CORE_PUBLIC,
								  oldb);
				buddy_group_remove(buddy, bgd);
			}
		}
		return(FALSE);
	}
}

void sipe_buddy_update_finish(struct sipe_core_private *sipe_private)
{
	g_hash_table_foreach_remove(sipe_private->buddies->uri,
				    buddy_check_obsolete_flag,
				    sipe_private);
}

gchar *sipe_core_buddy_status(struct sipe_core_public *sipe_public,
			      const gchar *uri,
			      guint activity,
			      const gchar *status_text)
{
	struct sipe_buddy *sbuddy;
	GString *status;

	if (!sipe_public) return NULL; /* happens on pidgin exit */

	sbuddy = sipe_buddy_find_by_uri(SIPE_CORE_PRIVATE, uri);
	if (!sbuddy) return NULL;

	status = g_string_new(sbuddy->activity ? sbuddy->activity :
			      (activity == SIPE_ACTIVITY_BUSY) || (activity == SIPE_ACTIVITY_BRB) ?
			      status_text : NULL);

	if (sbuddy->is_mobile) {
		if (status->len)
			g_string_append(status, " - ");
		g_string_append(status, _("Mobile"));
	}

	if (sbuddy->note) {
		if (status->len)
			g_string_append(status, " - ");
		g_string_append(status, sbuddy->note);
	}

	/* return NULL instead of empty status text */
	return(g_string_free(status, status->len ? FALSE : TRUE));
}

gchar *sipe_buddy_get_alias(struct sipe_core_private *sipe_private,
			    const gchar *with)
{
	sipe_backend_buddy pbuddy;
	gchar *alias = NULL;
	if ((pbuddy = sipe_backend_buddy_find(SIPE_CORE_PUBLIC, with, NULL))) {
		alias = sipe_backend_buddy_get_alias(SIPE_CORE_PUBLIC, pbuddy);
	}
	return alias;
}

void sipe_core_buddy_group(struct sipe_core_public *sipe_public,
			   const gchar *who,
			   const gchar *old_group_name,
			   const gchar *new_group_name)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_buddy *buddy = sipe_buddy_find_by_uri(sipe_private,
							  who);
	struct sipe_group *old_group = NULL;
	struct sipe_group *new_group;
	struct sipe_ucs_transaction *ucs_trans = NULL;

	SIPE_DEBUG_INFO("sipe_core_buddy_group: buddy '%s' old group '%s' new group '%s'",
			who ? who : "",
			old_group_name ? old_group_name : "<UNDEFINED>",
			new_group_name ? new_group_name : "<UNDEFINED>");

	if (!buddy)
		/* buddy not in roaming list */
		return;

	old_group = sipe_group_find_by_name(sipe_private, old_group_name);
	if (old_group) {
		sipe_buddy_remove_group(buddy, old_group);
		SIPE_DEBUG_INFO("sipe_core_buddy_group: buddy '%s' removed from old group '%s'",
				who, old_group_name);
	}

	new_group = sipe_group_find_by_name(sipe_private, new_group_name);
	if (new_group) {
		sipe_buddy_insert_group(buddy, new_group);
		SIPE_DEBUG_INFO("sipe_core_buddy_group: buddy '%s' added to new group '%s'",
				who, new_group_name);
	}

	if (sipe_ucs_is_migrated(sipe_private)) {

		/* UCS handling */
		ucs_trans = sipe_ucs_transaction(sipe_private);

		if (new_group) {
			/*
			 * 1. new buddy added to existing group
			 * 2. existing buddy moved from old to existing group
			 */
			sipe_ucs_group_add_buddy(sipe_private,
						 ucs_trans,
						 new_group,
						 buddy,
						 buddy->name);
			if (old_group)
				sipe_ucs_group_remove_buddy(sipe_private,
							    ucs_trans,
							    old_group,
							    buddy);

		} else if (old_group) {
			/*
			 * 3. existing buddy removed from one of its groups
			 * 4. existing buddy removed from last group
			 */
			sipe_ucs_group_remove_buddy(sipe_private,
						    ucs_trans,
						    old_group,
						    buddy);
			if (g_slist_length(buddy->groups) < 1)
				sipe_buddy_remove(sipe_private,
						  buddy);
				/* buddy no longer valid */
		}

	/* non-UCS handling */
	} else if (new_group)
		sipe_group_update_buddy(sipe_private, buddy);

	/* 5. buddy added to new group */
	if (!new_group)
		sipe_group_create(sipe_private,
				  ucs_trans,
				  new_group_name,
				  who);
}

void sipe_core_buddy_add(struct sipe_core_public *sipe_public,
			 const gchar *uri,
			 const gchar *group_name)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;

	if (!sipe_buddy_find_by_uri(sipe_private, uri))
		sipe_buddy_add(sipe_private,
			       uri,
			       NULL,
			       NULL);
	else
		SIPE_DEBUG_INFO("sipe_core_buddy_add: buddy %s already in internal list",
				uri);

	sipe_core_buddy_group(sipe_public,
			      uri,
			      NULL,
			      group_name);
}

void sipe_buddy_remove(struct sipe_core_private *sipe_private,
		       struct sipe_buddy *buddy)
{
	struct sipe_buddies *buddies = sipe_private->buddies;
	const gchar *uri = buddy->name;
	GSList *entry = buddy->groups;
	gchar *action_name = sipe_utils_presence_key(uri);

	sipe_schedule_cancel(sipe_private, action_name);
	g_free(action_name);

	/* If the buddy still has groups, we need to delete backend buddies */
	while (entry) {
		const struct sipe_group *group = ((struct buddy_group_data *) entry->data)->group;
		sipe_backend_buddy oldb = sipe_backend_buddy_find(SIPE_CORE_PUBLIC,
								  uri,
								  group->name);
		/* this should never be NULL */
		if (oldb)
			sipe_backend_buddy_remove(SIPE_CORE_PUBLIC, oldb);

		entry = entry->next;
	}

	g_hash_table_remove(buddies->uri, uri);
	if (buddy->exchange_key)
		g_hash_table_remove(buddies->exchange_key,
				    buddy->exchange_key);

	buddy_free(buddy);
}

/**
 * Unassociates buddy from group first.
 * Then see if no groups left, removes buddy completely.
 * Otherwise updates buddy groups on server.
 */
void sipe_core_buddy_remove(struct sipe_core_public *sipe_public,
			    const gchar *uri,
			    const gchar *group_name)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_buddy *buddy = sipe_buddy_find_by_uri(sipe_private,
							  uri);
	struct sipe_group *group = NULL;

	if (!buddy) return;

	if (group_name) {
		group = sipe_group_find_by_name(sipe_private, group_name);
		if (group) {
			sipe_buddy_remove_group(buddy, group);
			SIPE_DEBUG_INFO("sipe_core_buddy_remove: buddy '%s' removed from group '%s'",
					uri, group->name);
		}
	}

	if (g_slist_length(buddy->groups) < 1) {

		if (sipe_ucs_is_migrated(sipe_private)) {
			sipe_ucs_group_remove_buddy(sipe_private,
						    NULL,
						    group,
						    buddy);
		} else {
			gchar *request = g_strdup_printf("<m:URI>%s</m:URI>",
							 buddy->name);
			sip_soap_request(sipe_private,
					 "deleteContact",
					 request);
			g_free(request);
		}

		sipe_buddy_remove(sipe_private, buddy);
	} else {
		if (sipe_ucs_is_migrated(sipe_private)) {
			sipe_ucs_group_remove_buddy(sipe_private,
						    NULL,
						    group,
						    buddy);
		} else
			/* updates groups on server */
			sipe_group_update_buddy(sipe_private, buddy);
	}
}

void sipe_core_buddy_got_status(struct sipe_core_public *sipe_public,
				const gchar *uri,
				guint activity)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_buddy *sbuddy = sipe_buddy_find_by_uri(sipe_private,
							   uri);

	if (!sbuddy) return;

	/* Check if on 2005 system contact's calendar,
	 * then set/preserve it.
	 */
	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		sipe_backend_buddy_set_status(sipe_public, uri, activity);
	} else {
		sipe_ocs2005_apply_calendar_status(sipe_private,
						   sbuddy,
						   sipe_status_activity_to_token(activity));
	}
}

void sipe_core_buddy_tooltip_info(struct sipe_core_public *sipe_public,
				  const gchar *uri,
				  const gchar *status_name,
				  gboolean is_online,
				  struct sipe_backend_buddy_tooltip *tooltip)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	gchar *note = NULL;
	gboolean is_oof_note = FALSE;
	const gchar *activity = NULL;
	gchar *calendar = NULL;
	const gchar *meeting_subject = NULL;
	const gchar *meeting_location = NULL;
	gchar *access_text = NULL;

#define SIPE_ADD_BUDDY_INFO(l, t) \
	{ \
		gchar *tmp = g_markup_escape_text((t), -1); \
		sipe_backend_buddy_tooltip_add(sipe_public, tooltip, (l), tmp); \
		g_free(tmp); \
	}
#define SIPE_ADD_BUDDY_INFO_NOESCAPE(l, t) \
	sipe_backend_buddy_tooltip_add(sipe_public, tooltip, (l), (t))

	if (sipe_public) { /* happens on pidgin exit */
		struct sipe_buddy *sbuddy = sipe_buddy_find_by_uri(sipe_private,
								   uri);
		if (sbuddy) {
			note = sbuddy->note;
			is_oof_note = sbuddy->is_oof_note;
			activity = sbuddy->activity;
			calendar = sipe_cal_get_description(sbuddy);
			meeting_subject = sbuddy->meeting_subject;
			meeting_location = sbuddy->meeting_location;
		}
		if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
			gboolean is_group_access = FALSE;
			const int container_id = sipe_ocs2007_find_access_level(sipe_private,
										"user",
										sipe_get_no_sip_uri(uri),
										&is_group_access);
			const char *access_level = sipe_ocs2007_access_level_name(container_id);
			access_text = is_group_access ?
				g_strdup(access_level) :
				g_strdup_printf(SIPE_OCS2007_INDENT_MARKED_FMT,
						access_level);
		}
	}

	if (is_online) {
		const gchar *status_str = activity ? activity : status_name;

		SIPE_ADD_BUDDY_INFO(_("Status"), status_str);
	}
	if (is_online && !is_empty(calendar)) {
		SIPE_ADD_BUDDY_INFO(_("Calendar"), calendar);
	}
	g_free(calendar);
	if (!is_empty(meeting_location)) {
		SIPE_DEBUG_INFO("sipe_tooltip_text: %s meeting location: '%s'", uri, meeting_location);
		SIPE_ADD_BUDDY_INFO(_("Meeting in"), meeting_location);
	}
	if (!is_empty(meeting_subject)) {
		SIPE_DEBUG_INFO("sipe_tooltip_text: %s meeting subject: '%s'", uri, meeting_subject);
		SIPE_ADD_BUDDY_INFO(_("Meeting about"), meeting_subject);
	}
	if (note) {
		gchar *note_italics = g_strdup_printf("<i>%s</i>", note);
		SIPE_DEBUG_INFO("sipe_tooltip_text: %s note: '%s'", uri, note);
		SIPE_ADD_BUDDY_INFO_NOESCAPE(is_oof_note ? _("Out of office note") : _("Note"),
					     note_italics);
		g_free(note_italics);
	}
	if (access_text) {
		SIPE_ADD_BUDDY_INFO(_("Access level"), access_text);
		g_free(access_text);
	}
}

void sipe_buddy_update_property(struct sipe_core_private *sipe_private,
				const char *uri,
				sipe_buddy_info_fields propkey,
				char *property_value)
{
	GSList *buddies, *entry;

	if (property_value)
		property_value = g_strstrip(property_value);

	entry = buddies = sipe_backend_buddy_find_all(SIPE_CORE_PUBLIC, uri, NULL); /* all buddies in different groups */
	while (entry) {
		gchar *prop_str;
		sipe_backend_buddy p_buddy = entry->data;

		/* for Display Name */
		if (propkey == SIPE_BUDDY_INFO_DISPLAY_NAME) {
			gchar *alias;
			alias = sipe_backend_buddy_get_alias(SIPE_CORE_PUBLIC, p_buddy);
			if (property_value && sipe_is_bad_alias(uri, alias)) {
				SIPE_DEBUG_INFO("Replacing alias for %s with %s", uri, property_value);
				sipe_backend_buddy_set_alias(SIPE_CORE_PUBLIC, p_buddy, property_value);
			}
			g_free(alias);

			alias = sipe_backend_buddy_get_server_alias(SIPE_CORE_PUBLIC, p_buddy);
			if (!is_empty(property_value) &&
			   (!sipe_strequal(property_value, alias) || is_empty(alias)) )
			{
				SIPE_DEBUG_INFO("Replacing service alias for %s with %s", uri, property_value);
				sipe_backend_buddy_set_server_alias(SIPE_CORE_PUBLIC, p_buddy, property_value);
			}
			g_free(alias);
		}
		/* for other properties */
		else {
			if (!is_empty(property_value)) {
				prop_str = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC, p_buddy, propkey);
				if (!prop_str || !sipe_strcase_equal(prop_str, property_value)) {
					sipe_backend_buddy_set_string(SIPE_CORE_PUBLIC, p_buddy, propkey, property_value);
				}
				g_free(prop_str);
			}
		}

		entry = entry->next;
	}
	g_slist_free(buddies);
}


struct ms_dlx_data;
struct ms_dlx_data {
	GSList *search_rows;
	gchar  *other;
	guint   max_returns;
	sipe_svc_callback *callback;
	struct sipe_svc_session *session;
	gchar *wsse_security;
	struct sipe_backend_search_token *token;
	/* must call ms_dlx_free() */
	void (*failed_callback)(struct sipe_core_private *sipe_private,
				struct ms_dlx_data *mdd);
};

static void free_search_rows(GSList *search_rows)
{
	sipe_utils_slist_free_full(search_rows, g_free);
}

static void ms_dlx_free(struct ms_dlx_data *mdd)
{
	free_search_rows(mdd->search_rows);
	sipe_svc_session_close(mdd->session);
	g_free(mdd->other);
	g_free(mdd->wsse_security);
	g_free(mdd);
}

#define SIPE_SOAP_SEARCH_ROW "<m:row m:attrib=\"%s\" m:value=\"%s\"/>"
#define DLX_SEARCH_ITEM							\
	"<AbEntryRequest.ChangeSearchQuery>"				\
	" <SearchOn>%s</SearchOn>"					\
	" <Value>%s</Value>"						\
	"</AbEntryRequest.ChangeSearchQuery>"

static gchar * prepare_buddy_search_query(GSList *query_rows, gboolean use_dlx) {
	gchar **attrs = g_new(gchar *, (g_slist_length(query_rows) / 2) + 1);
	guint i = 0;
	gchar *query = NULL;

	while (query_rows) {
		gchar *attr;
		gchar *value;
		gchar *tmp = NULL;

		attr = query_rows->data;
		query_rows = g_slist_next(query_rows);
		value = query_rows->data;
		query_rows = g_slist_next(query_rows);

		if (!value)
			break;

		/*
		 * Special value for SIP ID
		 *
		 * Active Directory seems only to be able to search for
		 * SIP URIs. Make sure search string starts with "sip:".
		 */
		if (!attr) {
			attr = "msRTCSIP-PrimaryUserAddress";
			if (!use_dlx)
				value = tmp = sip_uri(value);
		}

		attrs[i++] = g_markup_printf_escaped(use_dlx ? DLX_SEARCH_ITEM : SIPE_SOAP_SEARCH_ROW,
						     attr, value);
		g_free(tmp);
	}
	attrs[i] = NULL;

	if (i) {
		query = g_strjoinv(NULL, attrs);
		SIPE_DEBUG_INFO("prepare_buddy_search_query: rows:\n%s",
				query ? query : "");
	}

	g_strfreev(attrs);

	return query;
}

static void ms_dlx_webticket(struct sipe_core_private *sipe_private,
			     const gchar *base_uri,
			     const gchar *auth_uri,
			     const gchar *wsse_security,
			     SIPE_UNUSED_PARAMETER const gchar *failure_msg,
			     gpointer callback_data)
{
	struct ms_dlx_data *mdd = callback_data;

	if (wsse_security) {
		guint length = g_slist_length(mdd->search_rows);
		gchar *search;

		SIPE_DEBUG_INFO("ms_dlx_webticket: got ticket for %s",
				base_uri);

		if (length > 0) {
			/* complex search */
			gchar *query = prepare_buddy_search_query(mdd->search_rows, TRUE);
			search = g_strdup_printf("<ChangeSearch xmlns:q1=\"DistributionListExpander\" soapenc:arrayType=\"q1:AbEntryRequest.ChangeSearchQuery[%d]\">"
						 " %s"
						 "</ChangeSearch>",
						 length / 2,
						 query);
			g_free(query);
		} else {
			/* simple search */
			search = g_strdup_printf("<BasicSearch>"
						 " <SearchList>c,company,displayName,givenName,mail,mailNickname,msRTCSIP-PrimaryUserAddress,sn</SearchList>"
						 " <Value>%s</Value>"
						 " <Verb>BeginsWith</Verb>"
						 "</BasicSearch>",
						 mdd->other);
		}

		if (sipe_svc_ab_entry_request(sipe_private,
					      mdd->session,
					      auth_uri,
					      wsse_security,
					      search,
					      mdd->max_returns,
					      mdd->callback,
					      mdd)) {

			/* keep webticket security token for potential further use */
			g_free(mdd->wsse_security);
			mdd->wsse_security = g_strdup(wsse_security);

			/* callback data passed down the line */
			mdd = NULL;
		}
		g_free(search);

	} else {
		/* no ticket: this will show the minmum information */
		SIPE_DEBUG_ERROR("ms_dlx_webticket: no web ticket for %s",
				 base_uri);
	}

	if (mdd)
		mdd->failed_callback(sipe_private, mdd);
}

static void ms_dlx_webticket_request(struct sipe_core_private *sipe_private,
				     struct ms_dlx_data *mdd)
{
	if (!sipe_webticket_request_with_port(sipe_private,
					      mdd->session,
					      sipe_private->dlx_uri,
					      "AddressBookWebTicketBearer",
					      ms_dlx_webticket,
					      mdd)) {
		SIPE_DEBUG_ERROR("ms_dlx_webticket_request: couldn't request webticket for %s",
				 sipe_private->dlx_uri);
		mdd->failed_callback(sipe_private, mdd);
	}
}

void sipe_buddy_search_contacts_finalize(struct sipe_core_private *sipe_private,
					 struct sipe_backend_search_results *results,
					 guint match_count,
					 gboolean more)
{
	gchar *secondary = g_strdup_printf(
		dngettext(PACKAGE_NAME,
			  "Found %d contact%s:",
			  "Found %d contacts%s:", match_count),
		match_count, more ? _(" (more matched your query)") : "");

	sipe_backend_search_results_finalize(SIPE_CORE_PUBLIC,
					     results,
					     secondary,
					     more);
	g_free(secondary);
}

static void search_ab_entry_response(struct sipe_core_private *sipe_private,
				     const gchar *uri,
				     SIPE_UNUSED_PARAMETER const gchar *raw,
				     sipe_xml *soap_body,
				     gpointer callback_data)
{
	struct ms_dlx_data *mdd = callback_data;

	if (soap_body) {
		const sipe_xml *node;
		struct sipe_backend_search_results *results;
		GHashTable *found;

		SIPE_DEBUG_INFO("search_ab_entry_response: received valid SOAP message from service %s",
				uri);

		/* any matches? */
		node = sipe_xml_child(soap_body, "Body/SearchAbEntryResponse/SearchAbEntryResult/Items/AbEntry");
		if (!node) {
			/* try again with simple search, if possible */
			if (mdd->other && mdd->search_rows) {
				SIPE_DEBUG_INFO_NOFORMAT("search_ab_entry_response: no matches, retrying with simple search");

				/* throw away original search query */
				free_search_rows(mdd->search_rows);
				mdd->search_rows = NULL;

				ms_dlx_webticket_request(sipe_private, mdd);

				/* callback data passed down the line */
				return;

			} else {
				SIPE_DEBUG_ERROR_NOFORMAT("search_ab_entry_response: no matches");

				sipe_backend_search_failed(SIPE_CORE_PUBLIC,
							   mdd->token,
							   _("No contacts found"));
				ms_dlx_free(mdd);
				return;
			}
		}

		/* OK, we found something - show the results to the user */
		results = sipe_backend_search_results_start(SIPE_CORE_PUBLIC,
							    mdd->token);
		if (!results) {
			SIPE_DEBUG_ERROR_NOFORMAT("search_ab_entry_response: Unable to display the search results.");
			sipe_backend_search_failed(SIPE_CORE_PUBLIC,
						   mdd->token,
						   _("Unable to display the search results"));
			ms_dlx_free(mdd);
			return;
		}

		/* SearchAbEntryResult can contain duplicates */
		found = g_hash_table_new_full(g_str_hash, g_str_equal,
					      g_free, NULL);

		for (/* initialized above */ ; node; node = sipe_xml_twin(node)) {
			const sipe_xml *attrs;
			gchar *sip_uri     = NULL;
			gchar *displayname = NULL;
			gchar *company     = NULL;
			gchar *country     = NULL;
			gchar *email       = NULL;

			for (attrs = sipe_xml_child(node, "Attributes/Attribute");
			     attrs;
			     attrs = sipe_xml_twin(attrs)) {
				gchar *name  = sipe_xml_data(sipe_xml_child(attrs,
									    "Name"));
				gchar *value = sipe_xml_data(sipe_xml_child(attrs,
									    "Value"));

				if (!is_empty(value)) {
					if (sipe_strcase_equal(name, "msrtcsip-primaryuseraddress")) {
						g_free(sip_uri);
					        sip_uri = value;
						value = NULL;
					} else if (sipe_strcase_equal(name, "displayname")) {
						g_free(displayname);
						displayname = value;
						value = NULL;
					} else if (sipe_strcase_equal(name, "mail")) {
						g_free(email);
						email = value;
						value = NULL;
					} else if (sipe_strcase_equal(name, "company")) {
						g_free(company);
						company = value;
						value = NULL;
					} else if (sipe_strcase_equal(name, "country")) {
						g_free(country);
						country = value;
						value = NULL;
					}
				}

				g_free(value);
				g_free(name);
			}

			if (sip_uri && !g_hash_table_lookup(found, sip_uri)) {
				gchar **uri_parts = g_strsplit(sip_uri, ":", 2);
				sipe_backend_search_results_add(SIPE_CORE_PUBLIC,
								results,
								uri_parts[1],
								displayname,
								company,
								country,
								email);
				g_strfreev(uri_parts);

				g_hash_table_insert(found, sip_uri, (gpointer) TRUE);
				sip_uri = NULL;
			}

			g_free(email);
			g_free(country);
			g_free(company);
			g_free(displayname);
			g_free(sip_uri);
		}

		sipe_buddy_search_contacts_finalize(sipe_private, results,
						    g_hash_table_size(found),
						    FALSE);
		g_hash_table_destroy(found);
		ms_dlx_free(mdd);

	} else {
		mdd->failed_callback(sipe_private, mdd);
	}
}

static gboolean process_search_contact_response(struct sipe_core_private *sipe_private,
						struct sipmsg *msg,
						struct transaction *trans)
{
	struct sipe_backend_search_token *token = trans->payload->data;
	struct sipe_backend_search_results *results;
	sipe_xml *searchResults;
	const sipe_xml *mrow;
	guint match_count = 0;
	gboolean more = FALSE;

	/* valid response? */
	if (msg->response != 200) {
		SIPE_DEBUG_ERROR("process_search_contact_response: request failed (%d)",
				 msg->response);
		sipe_backend_search_failed(SIPE_CORE_PUBLIC,
					   token,
					   _("Contact search failed"));
		return(FALSE);
	}

	SIPE_DEBUG_INFO("process_search_contact_response: body:\n%s", msg->body ? msg->body : "");

	/* valid XML? */
	searchResults = sipe_xml_parse(msg->body, msg->bodylen);
	if (!searchResults) {
		SIPE_DEBUG_INFO_NOFORMAT("process_search_contact_response: no parseable searchResults");
		sipe_backend_search_failed(SIPE_CORE_PUBLIC,
					   token,
					   _("Contact search failed"));
		return(FALSE);
	}

	/* any matches? */
	mrow = sipe_xml_child(searchResults, "Body/Array/row");
	if (!mrow) {
		SIPE_DEBUG_ERROR_NOFORMAT("process_search_contact_response: no matches");
		sipe_backend_search_failed(SIPE_CORE_PUBLIC,
					   token,
					   _("No contacts found"));

		sipe_xml_free(searchResults);
		return(FALSE);
	}

	/* OK, we found something - show the results to the user */
	results = sipe_backend_search_results_start(SIPE_CORE_PUBLIC,
						    trans->payload->data);
	if (!results) {
		SIPE_DEBUG_ERROR_NOFORMAT("process_search_contact_response: Unable to display the search results.");
		sipe_backend_search_failed(SIPE_CORE_PUBLIC,
					   token,
					   _("Unable to display the search results"));

		sipe_xml_free(searchResults);
		return FALSE;
	}

	for (/* initialized above */ ; mrow; mrow = sipe_xml_twin(mrow)) {
		gchar **uri_parts = g_strsplit(sipe_xml_attribute(mrow, "uri"), ":", 2);
		sipe_backend_search_results_add(SIPE_CORE_PUBLIC,
						results,
						uri_parts[1],
						sipe_xml_attribute(mrow, "displayName"),
						sipe_xml_attribute(mrow, "company"),
						sipe_xml_attribute(mrow, "country"),
						sipe_xml_attribute(mrow, "email"));
		g_strfreev(uri_parts);
		match_count++;
	}

	if ((mrow = sipe_xml_child(searchResults, "Body/directorySearch/moreAvailable")) != NULL) {
		char *data = sipe_xml_data(mrow);
		more = (g_ascii_strcasecmp(data, "true") == 0);
		g_free(data);
	}

	sipe_buddy_search_contacts_finalize(sipe_private, results, match_count, more);
	sipe_xml_free(searchResults);

	return(TRUE);
}

static void search_soap_request(struct sipe_core_private *sipe_private,
				GDestroyNotify destroy,
				void *data,
				guint max,
				SoapTransCallback callback,
				GSList *search_rows)
{
	gchar *query = prepare_buddy_search_query(search_rows, FALSE);
	struct transaction_payload *payload = g_new0(struct transaction_payload, 1);

	payload->destroy = destroy;
	payload->data    = data;

	sip_soap_directory_search(sipe_private,
				  max,
				  query,
				  callback,
				  payload);
	g_free(query);
}

static void search_ab_entry_failed(struct sipe_core_private *sipe_private,
				   struct ms_dlx_data *mdd)
{
	/* error using [MS-DLX] server, retry using Active Directory */
	if (mdd->search_rows)
		search_soap_request(sipe_private,
				    NULL,
				    mdd->token,
				    100,
				    process_search_contact_response,
				    mdd->search_rows);
	ms_dlx_free(mdd);
}

void sipe_core_buddy_search(struct sipe_core_public *sipe_public,
			    struct sipe_backend_search_token *token,
			    const gchar *given_name,
			    const gchar *surname,
			    const gchar *email,
			    const gchar *sipid,
			    const gchar *company,
			    const gchar *country)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;

	/* Lync 2013 or newer: use UCS if contacts are migrated */
	if (SIPE_CORE_PRIVATE_FLAG_IS(LYNC2013) &&
	    sipe_ucs_is_migrated(sipe_private)) {

		sipe_ucs_search(sipe_private,
				token,
				given_name,
				surname,
				email,
				sipid,
				company,
				country);

	} else {
		GSList *query_rows  = NULL;
		guint count         = 0;
		const gchar *simple = NULL;

#define ADD_QUERY_ROW(attr, val)                                                 \
		if (val) {                                                       \
			query_rows = g_slist_append(query_rows, g_strdup(attr)); \
			query_rows = g_slist_append(query_rows, g_strdup(val));  \
			simple = val;                                            \
			count++;                                                 \
		}

		ADD_QUERY_ROW("givenName", given_name);
		ADD_QUERY_ROW("sn",        surname);
		ADD_QUERY_ROW("mail",      email);
		/* prepare_buddy_search_query() interprets NULL as SIP ID */
		ADD_QUERY_ROW(NULL,        sipid);
		ADD_QUERY_ROW("company",   company);
		ADD_QUERY_ROW("c",         country);

		if (query_rows) {
			if (sipe_private->dlx_uri != NULL) {
				struct ms_dlx_data *mdd = g_new0(struct ms_dlx_data, 1);

				mdd->search_rows     = query_rows;
				/* user entered only one search string, remember that one */
				if (count == 1)
					mdd->other   = g_strdup(simple);
				mdd->max_returns     = 100;
				mdd->callback        = search_ab_entry_response;
				mdd->failed_callback = search_ab_entry_failed;
				mdd->session         = sipe_svc_session_start();
				mdd->token           = token;

				ms_dlx_webticket_request(sipe_private, mdd);

			} else {
				/* no [MS-DLX] server, use Active Directory search instead */
				search_soap_request(sipe_private,
						    NULL,
						    token,
						    100,
						    process_search_contact_response,
						    query_rows);
				free_search_rows(query_rows);
			}
		} else
			sipe_backend_search_failed(sipe_public,
						   token,
						   _("Invalid contact search query"));
	}
}

static void get_info_finalize(struct sipe_core_private *sipe_private,
			      struct sipe_backend_buddy_info *info,
			      const gchar *uri,
			      const gchar *server_alias,
			      const gchar *email)
{
	sipe_backend_buddy bbuddy;
	struct sipe_buddy *sbuddy;
	gchar *alias;
	gchar *value;

	if (!info) {
		info = sipe_backend_buddy_info_start(SIPE_CORE_PUBLIC);
	} else {
		sipe_backend_buddy_info_break(SIPE_CORE_PUBLIC, info);
	}
	if (!info)
		return;

	bbuddy = sipe_backend_buddy_find(SIPE_CORE_PUBLIC, uri, NULL);

	if (is_empty(server_alias)) {
		value = sipe_backend_buddy_get_server_alias(SIPE_CORE_PUBLIC,
							    bbuddy);
		if (value) {
			sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
						    info,
						    SIPE_BUDDY_INFO_DISPLAY_NAME,
						    value);
		}
	} else {
		value = g_strdup(server_alias);
	}

	/* present alias if it differs from server alias */
	alias = sipe_backend_buddy_get_local_alias(SIPE_CORE_PUBLIC, bbuddy);
	if (alias && !sipe_strequal(alias, value))
	{
		sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
					     info,
					     SIPE_BUDDY_INFO_ALIAS,
					     alias);
	}
	g_free(alias);
	g_free(value);

	if (is_empty(email)) {
		value = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC,
						      bbuddy,
						      SIPE_BUDDY_INFO_EMAIL);
		if (value) {
			sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
						    info,
						    SIPE_BUDDY_INFO_EMAIL,
						    value);
			g_free(value);
		}
	}

	value = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC,
					      bbuddy,
					      SIPE_BUDDY_INFO_SITE);
	if (value) {
		sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
					    info,
					    SIPE_BUDDY_INFO_SITE,
					    value);
		g_free(value);
	}

	sbuddy = sipe_buddy_find_by_uri(sipe_private, uri);
	if (sbuddy && sbuddy->device_name) {
		sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
					    info,
					    SIPE_BUDDY_INFO_DEVICE,
					    sbuddy->device_name);
	}

	sipe_backend_buddy_info_finalize(SIPE_CORE_PUBLIC, info, uri);
}


static void get_info_ab_entry_response(struct sipe_core_private *sipe_private,
				       const gchar *uri,
				       SIPE_UNUSED_PARAMETER const gchar *raw,
				       sipe_xml *soap_body,
				       gpointer callback_data)
{
	struct ms_dlx_data *mdd = callback_data;
	struct sipe_backend_buddy_info *info = NULL;
	gchar *server_alias = NULL;
	gchar *email        = NULL;

	if (soap_body) {
		const sipe_xml *node;

		SIPE_DEBUG_INFO("get_info_ab_entry_response: received valid SOAP message from service %s",
				uri);

		info = sipe_backend_buddy_info_start(SIPE_CORE_PUBLIC);

		for (node = sipe_xml_child(soap_body, "Body/SearchAbEntryResponse/SearchAbEntryResult/Items/AbEntry/Attributes/Attribute");
		     node;
		     node = sipe_xml_twin(node)) {
			gchar *name  = sipe_xml_data(sipe_xml_child(node,
								    "Name"));
			gchar *value = sipe_xml_data(sipe_xml_child(node,
								    "Value"));
			const sipe_xml *values = sipe_xml_child(node,
								"Values");

			/* Single value entries */
			if (!is_empty(value)) {

				if (sipe_strcase_equal(name, "displayname")) {
					g_free(server_alias);
					server_alias = value;
					value = NULL;
					sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
								    info,
								    SIPE_BUDDY_INFO_DISPLAY_NAME,
								    server_alias);
				} else if (sipe_strcase_equal(name, "mail")) {
					g_free(email);
					email = value;
					value = NULL;
					sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
								    info,
								    SIPE_BUDDY_INFO_EMAIL,
								    email);
				} else if (sipe_strcase_equal(name, "title")) {
					sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
								    info,
								    SIPE_BUDDY_INFO_JOB_TITLE,
								    value);
				} else if (sipe_strcase_equal(name, "company")) {
					sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
								    info,
								    SIPE_BUDDY_INFO_COMPANY,
								    value);
				} else if (sipe_strcase_equal(name, "country")) {
					sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
								    info,
								    SIPE_BUDDY_INFO_COUNTRY,
								    value);
				}

			} else if (values) {
				gchar *first = sipe_xml_data(sipe_xml_child(values,
									    "string"));

				if (sipe_strcase_equal(name, "telephonenumber")) {
					sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
								    info,
								    SIPE_BUDDY_INFO_WORK_PHONE,
								    first);
				}

				g_free(first);
			}

			g_free(value);
			g_free(name);
		}
	}

	/* this will show the minmum information */
	get_info_finalize(sipe_private,
			  info,
			  mdd->other,
			  server_alias,
			  email);

	g_free(email);
	g_free(server_alias);
	ms_dlx_free(mdd);
}

static gboolean process_get_info_response(struct sipe_core_private *sipe_private,
					  struct sipmsg *msg,
					  struct transaction *trans)
{
	const gchar *uri = trans->payload->data;
	struct sipe_backend_buddy_info *info = NULL;
	gchar *server_alias = NULL;
	gchar *email        = NULL;

	SIPE_DEBUG_INFO("Fetching %s's user info for %s",
			uri, sipe_private->username);

	if (msg->response != 200) {
		SIPE_DEBUG_INFO("process_get_info_response: SERVICE response is %d", msg->response);
	} else {
		sipe_xml *searchResults;
		const sipe_xml *mrow;

		SIPE_DEBUG_INFO("process_get_info_response: body:\n%s",
				msg->body ? msg->body : "");

		searchResults = sipe_xml_parse(msg->body, msg->bodylen);
		if (!searchResults) {

			SIPE_DEBUG_INFO_NOFORMAT("process_get_info_response: no parseable searchResults");

		} else if ((mrow = sipe_xml_child(searchResults, "Body/Array/row"))) {
			const gchar *value;
			gchar *phone_number;

			info = sipe_backend_buddy_info_start(SIPE_CORE_PUBLIC);

			server_alias = g_strdup(sipe_xml_attribute(mrow, "displayName"));
			email = g_strdup(sipe_xml_attribute(mrow, "email"));
			phone_number = g_strdup(sipe_xml_attribute(mrow, "phone"));

			/*
			 * For 2007 system we will take this from ContactCard -
			 * it has cleaner tel: URIs at least
			 */
			if (!SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
				char *tel_uri = sip_to_tel_uri(phone_number);
				/* trims its parameters, so call first */
				sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_DISPLAY_NAME, server_alias);
				sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_EMAIL, email);
				sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_WORK_PHONE, tel_uri);
				sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_WORK_PHONE_DISPLAY, phone_number);
				g_free(tel_uri);

				sipe_backend_buddy_refresh_properties(SIPE_CORE_PUBLIC,
								      uri);
			}

			if (!is_empty(server_alias)) {
				sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
							     info,
							     SIPE_BUDDY_INFO_DISPLAY_NAME,
							     server_alias);
			}
			if ((value = sipe_xml_attribute(mrow, "title")) && strlen(value) > 0) {
				sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
							     info,
							     SIPE_BUDDY_INFO_JOB_TITLE,
							     value);
			}
			if ((value = sipe_xml_attribute(mrow, "office")) && strlen(value) > 0) {
				sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
							     info,
							     SIPE_BUDDY_INFO_OFFICE,
							     value);
			}
			if (!is_empty(phone_number)) {
				sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
							     info,
							     SIPE_BUDDY_INFO_WORK_PHONE,
							     phone_number);
			}
			g_free(phone_number);
			if ((value = sipe_xml_attribute(mrow, "company")) && strlen(value) > 0) {
				sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
							     info,
							     SIPE_BUDDY_INFO_COMPANY,
							     value);
			}
			if ((value = sipe_xml_attribute(mrow, "city")) && strlen(value) > 0) {
				sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
							     info,
							     SIPE_BUDDY_INFO_CITY,
							     value);
			}
			if ((value = sipe_xml_attribute(mrow, "state")) && strlen(value) > 0) {
				sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
							     info,
							     SIPE_BUDDY_INFO_STATE,
							     value);
			}
			if ((value = sipe_xml_attribute(mrow, "country")) && strlen(value) > 0) {
				sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
							     info,
							     SIPE_BUDDY_INFO_COUNTRY,
							     value);
			}
			if (!is_empty(email)) {
				sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
							     info,
							     SIPE_BUDDY_INFO_EMAIL,
							     email);
			}
		}
		sipe_xml_free(searchResults);
	}

	/* this will show the minmum information */
	get_info_finalize(sipe_private,
			  info,
			  uri,
			  server_alias,
			  email);

	g_free(server_alias);
	g_free(email);

	return TRUE;
}

static void get_info_ab_entry_failed(struct sipe_core_private *sipe_private,
				     struct ms_dlx_data *mdd)
{
	/* error using [MS-DLX] server, retry using Active Directory */
	search_soap_request(sipe_private,
			    g_free,
			    mdd->other,
			    1,
			    process_get_info_response,
			    mdd->search_rows);
	mdd->other = NULL;
	ms_dlx_free(mdd);
}

static GSList *search_rows_for_uri(const gchar *uri)
{
	/* prepare_buddy_search_query() interprets NULL as SIP ID */
	GSList *l = g_slist_append(NULL, NULL);
	return(g_slist_append(l, g_strdup(uri)));
}

void sipe_core_buddy_get_info(struct sipe_core_public *sipe_public,
			      const gchar *who)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	GSList *search_rows = search_rows_for_uri(who);

	if (sipe_private->dlx_uri) {
		struct ms_dlx_data *mdd = g_new0(struct ms_dlx_data, 1);

		mdd->search_rows     = search_rows;
		mdd->other           = g_strdup(who);
		mdd->max_returns     = 1;
		mdd->callback        = get_info_ab_entry_response;
		mdd->failed_callback = get_info_ab_entry_failed;
		mdd->session         = sipe_svc_session_start();

		ms_dlx_webticket_request(sipe_private, mdd);

	} else {
		/* no [MS-DLX] server, use Active Directory search instead */
		search_soap_request(sipe_private,
				    g_free,
				    g_strdup(who),
				    1,
				    process_get_info_response,
				    search_rows);
		free_search_rows(search_rows);
	}
}

static void photo_response_data_free(struct photo_response_data *data)
{
	g_free(data->who);
	g_free(data->photo_hash);
	if (data->request) {
		sipe_http_request_cancel(data->request);
	}
	g_free(data);
}

static void photo_response_data_remove(struct sipe_core_private *sipe_private,
				       struct photo_response_data *data)
{
	data->request = NULL;
	sipe_private->buddies->pending_photo_requests =
		g_slist_remove(sipe_private->buddies->pending_photo_requests, data);
	photo_response_data_free(data);
}

static void process_buddy_photo_response(struct sipe_core_private *sipe_private,
					 guint status,
					 GSList *headers,
					 const char *body,
					 gpointer data)
{
	struct photo_response_data *rdata = (struct photo_response_data *) data;

	if (status == SIPE_HTTP_STATUS_OK) {
		const gchar *len_str = sipe_utils_nameval_find(headers,
							       "Content-Length");
		if (len_str) {
			gsize photo_size = atoi(len_str);
			gpointer photo = g_new(char, photo_size);

			if (photo) {
				memcpy(photo, body, photo_size);

				sipe_backend_buddy_set_photo(SIPE_CORE_PUBLIC,
							     rdata->who,
							     photo,
							     photo_size,
							     rdata->photo_hash);
			}
		}
	}

	photo_response_data_remove(sipe_private, rdata);
}

static void process_get_user_photo_response(struct sipe_core_private *sipe_private,
					    guint status,
					    SIPE_UNUSED_PARAMETER GSList *headers,
					    const gchar *body,
					    gpointer data)
{
	struct photo_response_data *rdata = (struct photo_response_data *) data;

	if ((status == SIPE_HTTP_STATUS_OK) && body) {
		sipe_xml *xml = sipe_xml_parse(body, strlen(body));
		const sipe_xml *node = sipe_xml_child(xml,
						      "Body/GetUserPhotoResponse/PictureData");

		if (node) {
			gchar *base64;
			gsize photo_size;
			guchar *photo;

			/* decode photo data */
			base64 = sipe_xml_data(node);
			photo = g_base64_decode(base64, &photo_size);
			g_free(base64);

			/* EWS doesn't provide a hash -> calculate SHA-1 digest */
			if (!rdata->photo_hash) {
				guchar digest[SIPE_DIGEST_SHA1_LENGTH];
				sipe_digest_sha1(photo, photo_size, digest);

				/* rdata takes ownership of digest string */
				rdata->photo_hash = buff_to_hex_str(digest,
								    SIPE_DIGEST_SHA1_LENGTH);
			}

			/* backend frees "photo" */
			sipe_backend_buddy_set_photo(SIPE_CORE_PUBLIC,
						     rdata->who,
						     photo,
						     photo_size,
						     rdata->photo_hash);
		}

		sipe_xml_free(xml);
	}

	photo_response_data_remove(sipe_private, rdata);
}

static gchar *create_x_ms_webticket_header(const gchar *wsse_security)
{
	gchar *assertion = sipe_xml_extract_raw(wsse_security, "Assertion", TRUE);
	gchar *wsse_security_base64;
	gchar *x_ms_webticket_header;

	if (!assertion) {
		return NULL;
	}

	wsse_security_base64 = g_base64_encode((const guchar *)assertion,
			strlen(assertion));
	x_ms_webticket_header = g_strdup_printf("X-MS-WebTicket: opaque=%s\r\n",
			wsse_security_base64);

	g_free(assertion);
	g_free(wsse_security_base64);

	return x_ms_webticket_header;
}

/* see also sipe_ucs_http_request() */
static struct sipe_http_request *get_user_photo_request(struct sipe_core_private *sipe_private,
							struct photo_response_data *data,
							const gchar *ews_url,
							const gchar *email)
{
	gchar *soap = g_strdup_printf("<?xml version=\"1.0\"?>\r\n"
				      "<soap:Envelope"
				      " xmlns:m=\"http://schemas.microsoft.com/exchange/services/2006/messages\""
				      " xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\""
				      " xmlns:t=\"http://schemas.microsoft.com/exchange/services/2006/types\""
				      " >"
				      " <soap:Header>"
				      "  <t:RequestServerVersion Version=\"Exchange2013\" />"
				      " </soap:Header>"
				      " <soap:Body>"
				      "  <m:GetUserPhoto>"
				      "   <m:Email>%s</m:Email>"
				      "   <m:SizeRequested>HR48x48</m:SizeRequested>"
				      "  </m:GetUserPhoto>"
				      " </soap:Body>"
				      "</soap:Envelope>",
				      email);
	struct sipe_http_request *request = sipe_http_request_post(sipe_private,
								   ews_url,
								   NULL,
								   soap,
								   "text/xml; charset=UTF-8",
								   process_get_user_photo_response,
								   data);
	g_free(soap);

	if (request) {
		sipe_core_email_authentication(sipe_private,
					       request);
		sipe_http_request_allow_redirect(request);
	} else {
		SIPE_DEBUG_ERROR_NOFORMAT("get_user_photo_request: failed to create HTTP connection");
	}

	return(request);
}

static void photo_response_data_finalize(struct sipe_core_private *sipe_private,
					 struct photo_response_data *data,
					 const gchar *uri,
					 const gchar *photo_hash)
{
	if (data->request) {
		data->who        = g_strdup(uri);
		data->photo_hash = g_strdup(photo_hash);

		sipe_private->buddies->pending_photo_requests =
			g_slist_append(sipe_private->buddies->pending_photo_requests, data);
		sipe_http_request_ready(data->request);
	} else {
		photo_response_data_free(data);
	}
}

void sipe_buddy_update_photo(struct sipe_core_private *sipe_private,
			     const gchar *uri,
			     const gchar *photo_hash,
			     const gchar *photo_url,
			     const gchar *headers)
{
	const gchar *photo_hash_old =
		sipe_backend_buddy_get_photo_hash(SIPE_CORE_PUBLIC, uri);

	if (!sipe_strequal(photo_hash, photo_hash_old)) {
		struct photo_response_data *data = g_new0(struct photo_response_data, 1);

		SIPE_DEBUG_INFO("sipe_buddy_update_photo: who '%s' url '%s' hash '%s'",
				uri, photo_url, photo_hash);

		/* Photo URL is embedded XML? */
		if (g_str_has_prefix(photo_url, "<") &&
		    g_str_has_suffix(photo_url, ">")) {
			/* add dummy root to embedded XML string */
			gchar *tmp = g_strdup_printf("<r>%s</r>", photo_url);
			sipe_xml *xml = sipe_xml_parse(tmp, strlen(tmp));
			g_free(tmp);

			if (xml) {
				gchar *ews_url = sipe_xml_data(sipe_xml_child(xml, "ewsUrl"));
				gchar *email = sipe_xml_data(sipe_xml_child(xml, "primarySMTP"));

				if (!is_empty(ews_url) && !is_empty(email)) {
					/*
					 * Workaround for missing Office 365 buddy icons
					 *
					 * (All?) Office 365 contact cards have the following
					 * XML embedded as the photo URI XML node text:
					 *
					 *    <ewsUrl>https://outlook.office365.com/EWS/Exchange.asmx/WSSecurity</ewsUrl>
					 *    <primarySMTP>user@company.com</primarySMTP>
					 *
					 * The simple HTTP request by get_user_photo_request()
					 * is rejected with 401. But the response contains
					 *
					 *    WWW-Authenticate: Basic Realm=""
					 *
					 * to which the HTTP transport answers with a retry
					 * using Basic authentication. That in turn is rejected
					 * with 500 and thus the buddy icon retrieval fails.
					 *
					 * As a quick workaround strip the trailing "/WSSecurity"
					 * from the URL. The HTTP request for the buddy icon
					 * retrieval will work with this stripped URL.
					 *
					 * @TODO: this is probably not the correct approach.
					 *        get_user_photo_request() should be updated
					 *        to support also a webticket request.
					 */
					gchar *tmp = g_strrstr(ews_url, "/WSSecurity");
					if (tmp)
						*tmp = '\0';

					data->request = get_user_photo_request(sipe_private,
									       data,
									       ews_url,
									       email);
				}

				g_free(email);
				g_free(ews_url);
				sipe_xml_free(xml);
			}
		} else {
			data->request = sipe_http_request_get(sipe_private,
							      photo_url,
							      headers,
							      process_buddy_photo_response,
							      data);
		}

		photo_response_data_finalize(sipe_private,
					     data,
					     uri,
					     photo_hash);
	}
}

static void get_photo_ab_entry_response(struct sipe_core_private *sipe_private,
					const gchar *uri,
					SIPE_UNUSED_PARAMETER const gchar *raw,
					sipe_xml *soap_body,
					gpointer callback_data)
{
	struct ms_dlx_data *mdd = callback_data;
	gchar *photo_rel_path = NULL;
	gchar *photo_hash = NULL;

	if (soap_body) {
		const sipe_xml *node;

		SIPE_DEBUG_INFO("get_photo_ab_entry_response: received valid SOAP message from service %s",
				uri);

		for (node = sipe_xml_child(soap_body, "Body/SearchAbEntryResponse/SearchAbEntryResult/Items/AbEntry/Attributes/Attribute");
		     node;
		     node = sipe_xml_twin(node)) {
			gchar *name  = sipe_xml_data(sipe_xml_child(node, "Name"));
			gchar *value = sipe_xml_data(sipe_xml_child(node, "Value"));

			if (!is_empty(value)) {
				if (sipe_strcase_equal(name, "PhotoRelPath")) {
					g_free(photo_rel_path);
					photo_rel_path = value;
					value = NULL;
				} else if (sipe_strcase_equal(name, "PhotoHash")) {
					g_free(photo_hash);
					photo_hash = value;
					value = NULL;
				}
			}

			g_free(value);
			g_free(name);
		}
	}

	if (sipe_private->addressbook_uri && photo_rel_path && photo_hash) {
		gchar *photo_url = g_strdup_printf("%s/%s",
				sipe_private->addressbook_uri, photo_rel_path);
		gchar *x_ms_webticket_header = create_x_ms_webticket_header(mdd->wsse_security);

		sipe_buddy_update_photo(sipe_private,
					mdd->other,
					photo_hash,
					photo_url,
					x_ms_webticket_header);

		g_free(x_ms_webticket_header);
		g_free(photo_url);
	}

	g_free(photo_rel_path);
	g_free(photo_hash);
	ms_dlx_free(mdd);
}

static void get_photo_ab_entry_failed(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private,
				      struct ms_dlx_data *mdd)
{
	ms_dlx_free(mdd);
}

static void buddy_fetch_photo(struct sipe_core_private *sipe_private,
			      const gchar *uri)
{
        if (sipe_backend_uses_photo()) {

		/* Lync 2013 or newer: use UCS if contacts are migrated */
		if (SIPE_CORE_PRIVATE_FLAG_IS(LYNC2013) &&
		    sipe_ucs_is_migrated(sipe_private)) {
			struct photo_response_data *data = g_new0(struct photo_response_data, 1);

			data->request = get_user_photo_request(sipe_private,
							       data,
							       sipe_ucs_ews_url(sipe_private),
							       sipe_get_no_sip_uri(uri));
			photo_response_data_finalize(sipe_private,
						     data,
						     uri,
						     /* there is no hash */
						     NULL);

		/* Lync 2010: use [MS-DLX] */
		} else if (sipe_private->dlx_uri         &&
			   sipe_private->addressbook_uri) {
			struct ms_dlx_data *mdd = g_new0(struct ms_dlx_data, 1);

			mdd->search_rows     = search_rows_for_uri(uri);
			mdd->other           = g_strdup(uri);
			mdd->max_returns     = 1;
			mdd->callback        = get_photo_ab_entry_response;
			mdd->failed_callback = get_photo_ab_entry_failed;
			mdd->session         = sipe_svc_session_start();

			ms_dlx_webticket_request(sipe_private, mdd);
		}
	}
}

static void buddy_refresh_photos_cb(gpointer uri,
				    SIPE_UNUSED_PARAMETER gpointer value,
				    gpointer sipe_private)
{
	buddy_fetch_photo(sipe_private, uri);
}

void sipe_buddy_refresh_photos(struct sipe_core_private *sipe_private)
{
	g_hash_table_foreach(sipe_private->buddies->uri,
			     buddy_refresh_photos_cb,
			     sipe_private);
}

/* Buddy menu callbacks*/

void sipe_core_buddy_new_chat(struct sipe_core_public *sipe_public,
			      const gchar *who)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;

	/* 2007+ conference */
	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		sipe_conf_add(sipe_private, who);

	/* 2005- multiparty chat */
	} else {
		gchar *self = sip_uri_self(sipe_private);
		struct sip_session *session;

		session = sipe_session_add_chat(sipe_private,
						NULL,
						TRUE,
						self);
		session->chat_session->backend = sipe_backend_chat_create(SIPE_CORE_PUBLIC,
									  session->chat_session,
									  session->chat_session->title,
									  self);
		g_free(self);

		sipe_im_invite(sipe_private, session, who,
			       NULL, NULL, NULL, FALSE);
	}
}

void sipe_core_buddy_send_email(struct sipe_core_public *sipe_public,
				const gchar *who)
{
	sipe_backend_buddy buddy = sipe_backend_buddy_find(sipe_public,
							   who,
							   NULL);
	gchar *email = sipe_backend_buddy_get_string(sipe_public,
						     buddy,
						     SIPE_BUDDY_INFO_EMAIL);

	if (email) {
		gchar *command_line = g_strdup_printf(
#ifdef _WIN32
			"cmd /c start"
#else
			"xdg-email"
#endif
			" mailto:%s", email);
		g_free(email);

		SIPE_DEBUG_INFO("sipe_core_buddy_send_email: going to call email client: %s",
				command_line);
		g_spawn_command_line_async(command_line, NULL);
		g_free(command_line);

	} else {
		SIPE_DEBUG_INFO("sipe_core_buddy_send_email: no email address stored for buddy=%s",
				who);
	}
}

/* Buddy menu */

static struct sipe_backend_buddy_menu *buddy_menu_phone(struct sipe_core_public *sipe_public,
							struct sipe_backend_buddy_menu *menu,
							sipe_backend_buddy buddy,
							sipe_buddy_info_fields id_phone,
							sipe_buddy_info_fields id_display,
							const gchar *type)
{
	gchar *phone = sipe_backend_buddy_get_string(sipe_public,
						     buddy,
						     id_phone);
	if (phone) {
		gchar *display = sipe_backend_buddy_get_string(sipe_public,
							       buddy,
							       id_display);
		gchar *tmp   = NULL;
		gchar *label = g_strdup_printf("%s %s",
					       type,
					       display ? display :
					       (tmp = sip_tel_uri_denormalize(phone)));
		menu = sipe_backend_buddy_menu_add(sipe_public,
						   menu,
						   label,
						   SIPE_BUDDY_MENU_MAKE_CALL,
						   phone);
		g_free(tmp);
		g_free(label);
		g_free(display);
		g_free(phone);
	}

	return(menu);
}

#ifdef HAVE_RDP_SERVER
static struct sipe_backend_buddy_menu *buddy_menu_share_desktop(struct sipe_core_public *sipe_public,
								struct sipe_backend_buddy_menu *menu,
								const gchar *buddy_name)
{
	struct sipe_media_call *call;

	call = sipe_media_call_find(SIPE_CORE_PRIVATE, buddy_name);
	if (call && sipe_appshare_get_role(call) == SIPE_APPSHARE_ROLE_PRESENTER) {
		/* We're already presenting to this buddy. */
		return menu;
	}

	return sipe_backend_buddy_menu_add(sipe_public,
					   menu,
					   _("Share my desktop"),
					   SIPE_BUDDY_MENU_SHARE_DESKTOP,
					   NULL);
}
#endif // HAVE_RDP_SERVER

struct sipe_backend_buddy_menu *sipe_core_buddy_create_menu(struct sipe_core_public *sipe_public,
							    const gchar *buddy_name,
							    struct sipe_backend_buddy_menu *menu)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	sipe_backend_buddy buddy = sipe_backend_buddy_find(sipe_public,
							   buddy_name,
							   NULL);
	gchar *self = sip_uri_self(sipe_private);

 	SIPE_SESSION_FOREACH {
		if (!sipe_strcase_equal(self, buddy_name) && session->chat_session)
		{
			struct sipe_chat_session *chat_session = session->chat_session;
			gboolean is_conf = (chat_session->type == SIPE_CHAT_TYPE_CONFERENCE);

			if (sipe_backend_chat_find(chat_session->backend, buddy_name))
			{
				gboolean conf_op = sipe_backend_chat_is_operator(chat_session->backend, self);

				if (is_conf &&
				    /* Not conf OP */
				    !sipe_backend_chat_is_operator(chat_session->backend, buddy_name) &&
				    /* We are a conf OP */
				    conf_op) {
					gchar *label = g_strdup_printf(_("Make leader of '%s'"),
								       chat_session->title);
					menu = sipe_backend_buddy_menu_add(sipe_public,
									   menu,
									   label,
									   SIPE_BUDDY_MENU_MAKE_CHAT_LEADER,
									   chat_session);
					g_free(label);
				}

				if (is_conf &&
				    /* We are a conf OP */
				    conf_op) {
					gchar *label = g_strdup_printf(_("Remove from '%s'"),
								       chat_session->title);
					menu = sipe_backend_buddy_menu_add(sipe_public,
									   menu,
									   label,
									   SIPE_BUDDY_MENU_REMOVE_FROM_CHAT,
									   chat_session);
					g_free(label);
				}
			}
			else
			{
				if (!is_conf ||
				    (is_conf && !session->locked)) {
					gchar *label = g_strdup_printf(_("Invite to '%s'"),
								       chat_session->title);
					menu = sipe_backend_buddy_menu_add(sipe_public,
									 menu,
									 label,
									 SIPE_BUDDY_MENU_INVITE_TO_CHAT,
									 chat_session);
					g_free(label);
				}
			}
		}
	} SIPE_SESSION_FOREACH_END;
	g_free(self);

	menu = sipe_backend_buddy_menu_add(sipe_public,
					   menu,
					   _("New chat"),
					   SIPE_BUDDY_MENU_NEW_CHAT,
					   NULL);

	/* add buddy's phone numbers if we have call control */
	if (sip_csta_is_idle(sipe_private)) {

		/* work phone */
		menu = buddy_menu_phone(sipe_public,
					menu,
					buddy,
					SIPE_BUDDY_INFO_WORK_PHONE,
					SIPE_BUDDY_INFO_WORK_PHONE_DISPLAY,
					_("Work"));
		/* mobile phone */
		menu = buddy_menu_phone(sipe_public,
					menu,
					buddy,
					SIPE_BUDDY_INFO_MOBILE_PHONE,
					SIPE_BUDDY_INFO_MOBILE_PHONE_DISPLAY,
					_("Mobile"));

		/* home phone */
		menu = buddy_menu_phone(sipe_public,
					menu,
					buddy,
					SIPE_BUDDY_INFO_HOME_PHONE,
					SIPE_BUDDY_INFO_HOME_PHONE_DISPLAY,
					_("Home"));

		/* other phone */
		menu = buddy_menu_phone(sipe_public,
					menu,
					buddy,
					SIPE_BUDDY_INFO_OTHER_PHONE,
					SIPE_BUDDY_INFO_OTHER_PHONE_DISPLAY,
					_("Other"));

		/* custom1 phone */
		menu = buddy_menu_phone(sipe_public,
					menu,
					buddy,
					SIPE_BUDDY_INFO_CUSTOM1_PHONE,
					SIPE_BUDDY_INFO_CUSTOM1_PHONE_DISPLAY,
					_("Custom1"));
	}

	{
		gchar *email = sipe_backend_buddy_get_string(sipe_public,
							     buddy,
							     SIPE_BUDDY_INFO_EMAIL);
		if (email) {
			menu = sipe_backend_buddy_menu_add(sipe_public,
							   menu,
							   _("Send email..."),
							   SIPE_BUDDY_MENU_SEND_EMAIL,
							   NULL);
			g_free(email);
		}
	}

#ifdef HAVE_RDP_SERVER
	menu = buddy_menu_share_desktop(sipe_public, menu, buddy_name);
#endif // HAVE_RDP_SERVER

	/* access level control */
	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007))
		menu = sipe_backend_buddy_sub_menu_add(sipe_public,
						       menu,
						       _("Access level"),
						       sipe_ocs2007_access_control_menu(sipe_private,
											buddy_name));

	return(menu);
}

guint sipe_buddy_count(struct sipe_core_private *sipe_private)
{
	return(g_hash_table_size(sipe_private->buddies->uri));
}

static guint sipe_ht_hash_nick(const char *nick)
{
	char *lc = g_utf8_strdown(nick, -1);
	guint bucket = g_str_hash(lc);
	g_free(lc);

	return bucket;
}

static gboolean sipe_ht_equals_nick(const char *nick1, const char *nick2)
{
	char *nick1_norm = NULL;
	char *nick2_norm = NULL;
	gboolean equal;

	if (nick1 == NULL && nick2 == NULL) return TRUE;
	if (nick1 == NULL || nick2 == NULL    ||
	    !g_utf8_validate(nick1, -1, NULL) ||
	    !g_utf8_validate(nick2, -1, NULL)) return FALSE;

	nick1_norm = g_utf8_casefold(nick1, -1);
	nick2_norm = g_utf8_casefold(nick2, -1);
	equal = g_utf8_collate(nick1_norm, nick2_norm) == 0;
	g_free(nick2_norm);
	g_free(nick1_norm);

	return equal;
}

void sipe_buddy_init(struct sipe_core_private *sipe_private)
{
	struct sipe_buddies *buddies = g_new0(struct sipe_buddies, 1);
	buddies->uri          = g_hash_table_new((GHashFunc)  sipe_ht_hash_nick,
						 (GEqualFunc) sipe_ht_equals_nick);
	buddies->exchange_key = g_hash_table_new(g_str_hash,
						 g_str_equal);
	sipe_private->buddies = buddies;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
