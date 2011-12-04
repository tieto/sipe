/**
 * @file sipe-buddy.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-11 SIPE Project <http://sipe.sourceforge.net/>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>

#include <glib.h>

#include "sipe-common.h"
#include "http-conn.h" /* sipe-cal.h requires this */
#include "sipmsg.h"
#include "sip-soap.h"
#include "sipe-backend.h"
#include "sipe-buddy.h"
#include "sipe-cal.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-group.h"
#include "sipe-nls.h"
#include "sipe-ocs2007.h"
#include "sipe-schedule.h"
#include "sipe-subscriptions.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

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
	g_slist_free(buddy->groups);
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

void sipe_buddy_free_all(struct sipe_core_private *sipe_private)
{
	g_hash_table_foreach_steal(sipe_private->buddies,
				   buddy_free_cb,
				   NULL);
}

gchar *sipe_core_buddy_status(struct sipe_core_public *sipe_public,
			      const gchar *name,
			      const sipe_activity activity,
			      const gchar *status_text)
{
	struct sipe_buddy *sbuddy;
	const char *activity_str;

	if (!sipe_public) return NULL; /* happens on pidgin exit */

	sbuddy = g_hash_table_lookup(SIPE_CORE_PRIVATE->buddies, name);
	if (!sbuddy) return NULL;

	activity_str = sbuddy->activity ? sbuddy->activity :
		(activity == SIPE_ACTIVITY_BUSY) || (activity == SIPE_ACTIVITY_BRB) ?
		status_text : NULL;

	if (activity_str && sbuddy->note) {
		return g_strdup_printf("%s - <i>%s</i>", activity_str, sbuddy->note);
	} else if (activity_str) {
		return g_strdup(activity_str);
	} else if (sbuddy->note) {
		return g_strdup_printf("<i>%s</i>", sbuddy->note);
	} else {
		return NULL;
	}
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
	struct sipe_buddy * buddy = g_hash_table_lookup(SIPE_CORE_PRIVATE->buddies, who);
	struct sipe_group * old_group = NULL;
	struct sipe_group * new_group;

	SIPE_DEBUG_INFO("sipe_core_buddy_group: who:%s old_group_name:%s new_group_name:%s",
			who ? who : "", old_group_name ? old_group_name : "", new_group_name ? new_group_name : "");

	if(!buddy) { // buddy not in roaming list
		return;
	}

	if (old_group_name) {
		old_group = sipe_group_find_by_name(SIPE_CORE_PRIVATE, old_group_name);
	}
	new_group = sipe_group_find_by_name(SIPE_CORE_PRIVATE, new_group_name);

	if (old_group) {
		buddy->groups = g_slist_remove(buddy->groups, old_group);
		SIPE_DEBUG_INFO("sipe_core_buddy_group: buddy %s removed from old group %s", who, old_group_name);
	}

	if (!new_group) {
		sipe_group_create(SIPE_CORE_PRIVATE, new_group_name, who);
	} else {
		buddy->groups = slist_insert_unique_sorted(buddy->groups, new_group, (GCompareFunc)sipe_group_compare);
		sipe_core_group_set_user(sipe_public, who);
	}
}

void sipe_core_buddy_add(struct sipe_core_public *sipe_public,
			 const gchar *name,
			 const gchar *group_name)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;

	if (!g_hash_table_lookup(sipe_private->buddies, name)) {
		struct sipe_buddy *b = g_new0(struct sipe_buddy, 1);

		SIPE_DEBUG_INFO("sipe_core_buddy_add: %s", name);

		b->name = g_strdup(name);
		b->just_added = TRUE;
		g_hash_table_insert(sipe_private->buddies, b->name, b);

		/* @TODO should go to callback */
		sipe_subscribe_presence_single(sipe_private, b->name);

	} else {
		SIPE_DEBUG_INFO("sipe_core_buddy_add: buddy %s already in internal list",
				name);
	}

	sipe_core_buddy_group(SIPE_CORE_PUBLIC,
			      name,
			      NULL,
			      group_name);
}

/**
 * Unassociates buddy from group first.
 * Then see if no groups left, removes buddy completely.
 * Otherwise updates buddy groups on server.
 */
void sipe_core_buddy_remove(struct sipe_core_public *sipe_public,
			    const gchar *name,
			    const gchar *group_name)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_buddy *b = g_hash_table_lookup(sipe_private->buddies,
						   name);

	if (!b) return;

	if (group_name) {
		struct sipe_group *g = sipe_group_find_by_name(sipe_private,
							       group_name);
		if (g) {
			b->groups = g_slist_remove(b->groups, g);
			SIPE_DEBUG_INFO("sipe_core_buddy_remove: buddy %s removed from group %s",
					name, g->name);
		}
	}

	if (g_slist_length(b->groups) < 1) {
		gchar *action_name = sipe_utils_presence_key(name);
		sipe_schedule_cancel(sipe_private, action_name);
		g_free(action_name);

		g_hash_table_remove(sipe_private->buddies, name);

		if (b->name) {
			gchar *request = g_strdup_printf("<m:URI>%s</m:URI>",
							 b->name);
			sip_soap_request(sipe_private,
					 "deleteContact",
					 request);
			g_free(request);
		}

		buddy_free(b);
	} else {
		/* updates groups on server */
		sipe_core_group_set_user(SIPE_CORE_PUBLIC, b->name);
	}

}

GSList *sipe_core_buddy_info(struct sipe_core_public *sipe_public,
			     const gchar *name,
			     const gchar *status_name,
			     gboolean is_online)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	gchar *note = NULL;
	gboolean is_oof_note = FALSE;
	const gchar *activity = NULL;
	gchar *calendar = NULL;
	const gchar *meeting_subject = NULL;
	const gchar *meeting_location = NULL;
	gchar *access_text = NULL;
	GSList *info = NULL;

#define SIPE_ADD_BUDDY_INFO_COMMON(l, t) \
	{ \
		struct sipe_buddy_info *sbi = g_malloc(sizeof(struct sipe_buddy_info)); \
		sbi->label = (l); \
		sbi->text = (t); \
		info = g_slist_append(info, sbi); \
	}
#define SIPE_ADD_BUDDY_INFO(l, t)          SIPE_ADD_BUDDY_INFO_COMMON((l), g_markup_escape_text((t), -1))
#define SIPE_ADD_BUDDY_INFO_NOESCAPE(l, t) SIPE_ADD_BUDDY_INFO_COMMON((l), (t))

	if (sipe_public) { //happens on pidgin exit
		struct sipe_buddy *sbuddy = g_hash_table_lookup(sipe_private->buddies, name);
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
			const int container_id = sipe_ocs2007_find_access_level(sipe_private, "user", sipe_get_no_sip_uri(name), &is_group_access);
			const char *access_level = sipe_ocs2007_access_level_name(container_id);
			access_text = is_group_access ?
				g_strdup(access_level) :
				g_strdup_printf(SIPE_OCS2007_INDENT_MARKED_FMT,
						access_level);
		}
	}

	if (is_online)
	{
		const gchar *status_str = activity ? activity : status_name;

		SIPE_ADD_BUDDY_INFO(_("Status"), status_str);
	}
	if (is_online && !is_empty(calendar))
	{
		SIPE_ADD_BUDDY_INFO(_("Calendar"), calendar);
	}
	g_free(calendar);
	if (!is_empty(meeting_location))
	{
		SIPE_DEBUG_INFO("sipe_tooltip_text: %s meeting location: '%s'", name, meeting_location);
		SIPE_ADD_BUDDY_INFO(_("Meeting in"), meeting_location);
	}
	if (!is_empty(meeting_subject))
	{
		SIPE_DEBUG_INFO("sipe_tooltip_text: %s meeting subject: '%s'", name, meeting_subject);
		SIPE_ADD_BUDDY_INFO(_("Meeting about"), meeting_subject);
	}
	if (note)
	{
		SIPE_DEBUG_INFO("sipe_tooltip_text: %s note: '%s'", name, note);
		SIPE_ADD_BUDDY_INFO_NOESCAPE(is_oof_note ? _("Out of office note") : _("Note"),
					     g_strdup_printf("<i>%s</i>", note));
	}
	if (access_text) {
		SIPE_ADD_BUDDY_INFO(_("Access level"), access_text);
		g_free(access_text);
	}

	return(info);
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
		gchar *server_alias;
		gchar *alias;
		sipe_backend_buddy p_buddy = entry->data;

		/* for Display Name */
		if (propkey == SIPE_BUDDY_INFO_DISPLAY_NAME) {
			alias = sipe_backend_buddy_get_alias(SIPE_CORE_PUBLIC, p_buddy);
			if (property_value && sipe_is_bad_alias(uri, alias)) {
				SIPE_DEBUG_INFO("Replacing alias for %s with %s", uri, property_value);
				sipe_backend_buddy_set_alias(SIPE_CORE_PUBLIC, p_buddy, property_value);
			}
			g_free(alias);

			server_alias = sipe_backend_buddy_get_server_alias(SIPE_CORE_PUBLIC, p_buddy);
			if (!is_empty(property_value) &&
			   (!sipe_strequal(property_value, server_alias) || is_empty(server_alias)) )
			{
				SIPE_DEBUG_INFO("Replacing service alias for %s with %s", uri, property_value);
				sipe_backend_buddy_set_server_alias(SIPE_CORE_PUBLIC, p_buddy, property_value);
			}
			g_free(server_alias);
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

static gboolean process_search_contact_response(struct sipe_core_private *sipe_private,
						struct sipmsg *msg,
						SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	struct sipe_backend_search_results *results;
	sipe_xml *searchResults;
	const sipe_xml *mrow;
	guint match_count = 0;
	gboolean more = FALSE;
	gchar *secondary;

	/* valid response? */
	if (msg->response != 200) {
		SIPE_DEBUG_ERROR("process_search_contact_response: request failed (%d)",
				 msg->response);
		sipe_backend_notify_error(SIPE_CORE_PUBLIC,
					  _("Contact search failed"),
					  NULL);
		return(FALSE);
	}

	SIPE_DEBUG_INFO("process_search_contact_response: body:\n%s", msg->body ? msg->body : "");

	/* valid XML? */
	searchResults = sipe_xml_parse(msg->body, msg->bodylen);
	if (!searchResults) {
		SIPE_DEBUG_INFO_NOFORMAT("process_search_contact_response: no parseable searchResults");
		sipe_backend_notify_error(SIPE_CORE_PUBLIC,
					  _("Contact search failed"),
					  NULL);
		return(FALSE);
	}

	/* any matches? */
	mrow = sipe_xml_child(searchResults, "Body/Array/row");
	if (!mrow) {
		SIPE_DEBUG_ERROR_NOFORMAT("process_search_contact_response: no matches");
		sipe_backend_notify_error(SIPE_CORE_PUBLIC,
					  _("No contacts found"),
					  NULL);

		sipe_xml_free(searchResults);
		return(FALSE);
	}

	/* OK, we found something - show the results to the user */
	results = sipe_backend_search_results_start(SIPE_CORE_PUBLIC);
	if (!results) {
		SIPE_DEBUG_ERROR_NOFORMAT("process_search_contact_response: Unable to display the search results.");
		sipe_backend_notify_error(SIPE_CORE_PUBLIC,
					  _("Unable to display the search results"),
					  NULL);

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
		more = (g_strcasecmp(data, "true") == 0);
		g_free(data);
	}

	secondary = g_strdup_printf(
		dngettext(PACKAGE_NAME,
			  "Found %d contact%s:",
			  "Found %d contacts%s:", match_count),
		match_count, more ? _(" (more matched your query)") : "");

	sipe_backend_search_results_finalize(SIPE_CORE_PUBLIC,
					     results,
					     secondary);
	g_free(secondary);
	sipe_xml_free(searchResults);

	return(TRUE);
}

#define SIPE_SOAP_SEARCH_ROW "<m:row m:attrib=\"%s\" m:value=\"%s\"/>"

void sipe_core_buddy_search(struct sipe_core_public *sipe_public,
			    const gchar *given_name,
			    const gchar *surname,
			    const gchar *company,
			    const gchar *country)
{
	gchar **attrs = g_new(gchar *, 5);
	guint i = 0;

	if (!attrs) return;

#define ADD_QUERY_ROW(a, v) \
	if (v) attrs[i++] = g_markup_printf_escaped(SIPE_SOAP_SEARCH_ROW, a, v)

	ADD_QUERY_ROW("givenName", given_name);
	ADD_QUERY_ROW("sn",        surname);
	ADD_QUERY_ROW("company",   company);
	ADD_QUERY_ROW("c",         country);

	if (i) {
		gchar *query;

		attrs[i] = NULL;
		query = g_strjoinv(NULL, attrs);
		SIPE_DEBUG_INFO("sipe_core_buddy_search: rows:\n%s",
				query ? query : "");
		sip_soap_directory_search(SIPE_CORE_PRIVATE,
					  100,
					  query,
					  process_search_contact_response,
					  NULL);
		g_free(query);
	}

	g_strfreev(attrs);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
