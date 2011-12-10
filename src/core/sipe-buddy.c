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
#include "sipe-group.h"
#include "sipe-im.h"
#include "sipe-nls.h"
#include "sipe-ocs2005.h"
#include "sipe-ocs2007.h"
#include "sipe-schedule.h"
#include "sipe-session.h"
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
			      const gchar *uri,
			      guint activity,
			      const gchar *status_text)
{
	struct sipe_buddy *sbuddy;
	const char *activity_str;

	if (!sipe_public) return NULL; /* happens on pidgin exit */

	sbuddy = g_hash_table_lookup(SIPE_CORE_PRIVATE->buddies, uri);
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
			 const gchar *uri,
			 const gchar *group_name)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;

	if (!g_hash_table_lookup(sipe_private->buddies, uri)) {
		struct sipe_buddy *b = g_new0(struct sipe_buddy, 1);

		SIPE_DEBUG_INFO("sipe_core_buddy_add: %s", uri);

		b->name = g_strdup(uri);
		b->just_added = TRUE;
		g_hash_table_insert(sipe_private->buddies, b->name, b);

		/* @TODO should go to callback */
		sipe_subscribe_presence_single(sipe_private, b->name);

	} else {
		SIPE_DEBUG_INFO("sipe_core_buddy_add: buddy %s already in internal list",
				uri);
	}

	sipe_core_buddy_group(sipe_public,
			      uri,
			      NULL,
			      group_name);
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
	struct sipe_buddy *b = g_hash_table_lookup(sipe_private->buddies,
						   uri);

	if (!b) return;

	if (group_name) {
		struct sipe_group *g = sipe_group_find_by_name(sipe_private,
							       group_name);
		if (g) {
			b->groups = g_slist_remove(b->groups, g);
			SIPE_DEBUG_INFO("sipe_core_buddy_remove: buddy %s removed from group %s",
					uri, g->name);
		}
	}

	if (g_slist_length(b->groups) < 1) {
		gchar *action_name = sipe_utils_presence_key(uri);
		sipe_schedule_cancel(sipe_private, action_name);
		g_free(action_name);

		g_hash_table_remove(sipe_private->buddies, uri);

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
		sipe_core_group_set_user(sipe_public, b->name);
	}

}

void sipe_core_buddy_got_status(struct sipe_core_public *sipe_public,
				const gchar *uri,
				const gchar *status_id)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_buddy *sbuddy = g_hash_table_lookup(sipe_private->buddies,
							uri);

	if (!sbuddy) return;

	/* Check if on 2005 system contact's calendar,
	 * then set/preserve it.
	 */
	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		sipe_backend_buddy_set_status(sipe_public, uri, status_id);
	} else {
		sipe_ocs2005_apply_calendar_status(sipe_private,
						   sbuddy,
						   status_id);
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
		struct sipe_buddy *sbuddy = g_hash_table_lookup(sipe_private->buddies, uri);
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
		SIPE_DEBUG_INFO("sipe_tooltip_text: %s note: '%s'", uri, note);
		SIPE_ADD_BUDDY_INFO_NOESCAPE(is_oof_note ? _("Out of office note") : _("Note"),
					     g_strdup_printf("<i>%s</i>", note));
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
					     secondary,
					     more);
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

static gboolean process_options_response(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private,
					 struct sipmsg *msg,
					 SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	if (msg->response != 200) {
		SIPE_DEBUG_INFO("process_options_response: OPTIONS response is %d",
				msg->response);
		return(FALSE);
	} else {
		SIPE_DEBUG_INFO("process_options_response: body:\n%s",
				msg->body ? msg->body : "");
		return(TRUE);
	}
}

/* Asks UA/proxy about its capabilities */
static void sipe_options_request(struct sipe_core_private *sipe_private,
				 const char *who)
{
	gchar *to = sip_uri(who);
	gchar *contact = get_contact(sipe_private);
	gchar *request = g_strdup_printf("Accept: application/sdp\r\n"
					 "Contact: %s\r\n",
					 contact);
	g_free(contact);

	sip_transport_request(sipe_private,
			      "OPTIONS",
			      to,
			      to,
			      request,
			      NULL,
			      NULL,
			      process_options_response);

	g_free(to);
	g_free(request);
}

static gboolean process_get_info_response(struct sipe_core_private *sipe_private,
					  struct sipmsg *msg,
					  struct transaction *trans)
{
	const gchar *uri = trans->payload->data;
	sipe_backend_buddy bbuddy;
	struct sipe_backend_buddy_info *info;
	struct sipe_buddy *sbuddy;
	gchar *alias        = NULL;
	gchar *device_name  = NULL;
	gchar *server_alias = NULL;
	gchar *phone_number = NULL;
	gchar *email        = NULL;
	gchar *site;

	SIPE_DEBUG_INFO("Fetching %s's user info for %s",
			uri, sipe_private->username);

	info = sipe_backend_buddy_info_start(SIPE_CORE_PUBLIC);
	if (!info) return(FALSE);

	bbuddy = sipe_backend_buddy_find(SIPE_CORE_PUBLIC, uri, NULL);
	alias = sipe_backend_buddy_get_local_alias(SIPE_CORE_PUBLIC, bbuddy);

	/* will query buddy UA's capabilities and send answer to log */
	if (sipe_backend_debug_enabled())
		sipe_options_request(sipe_private, uri);

	sbuddy = g_hash_table_lookup(sipe_private->buddies, uri);
	if (sbuddy) {
		device_name = sbuddy->device_name ? g_strdup(sbuddy->device_name) : NULL;
	}

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
			}

			if (server_alias && strlen(server_alias) > 0) {
				sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
							     info,
							     _("Display name"),
							     server_alias);
			}
			if ((value = sipe_xml_attribute(mrow, "title")) && strlen(value) > 0) {
				sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
							     info,
							     _("Job title"),
							     value);
			}
			if ((value = sipe_xml_attribute(mrow, "office")) && strlen(value) > 0) {
				sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
							     info,
							     _("Office"),
							     value);
			}
			if (phone_number && strlen(phone_number) > 0) {
				sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
							     info,
							     _("Business phone"),
							     phone_number);
			}
			if ((value = sipe_xml_attribute(mrow, "company")) && strlen(value) > 0) {
				sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
							     info,
							     _("Company"),
							     value);
			}
			if ((value = sipe_xml_attribute(mrow, "city")) && strlen(value) > 0) {
				sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
							     info,
							     _("City"),
							     value);
			}
			if ((value = sipe_xml_attribute(mrow, "state")) && strlen(value) > 0) {
				sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
							     info,
							     _("State"),
							     value);
			}
			if ((value = sipe_xml_attribute(mrow, "country")) && strlen(value) > 0) {
				sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
							     info,
							     _("Country"),
							     value);
			}
			if (email && strlen(email) > 0) {
				sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
							     info,
							     _("Email address"),
							     email);
			}

		}
		sipe_xml_free(searchResults);
	}

	sipe_backend_buddy_info_break(SIPE_CORE_PUBLIC, info);

	if (is_empty(server_alias)) {
		g_free(server_alias);
		server_alias = sipe_backend_buddy_get_server_alias(SIPE_CORE_PUBLIC,
								   bbuddy);
		if (server_alias) {
			sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
						     info,
						     _("Display name"),
						     server_alias);
		}
	}

	/* present alias if it differs from server alias */
	if (alias && !sipe_strequal(alias, server_alias))
	{
		sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
					     info,
					     _("Alias"),
					     alias);
	}

	if (is_empty(email)) {
		g_free(email);
		email = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC,
						      bbuddy,
						      SIPE_BUDDY_INFO_EMAIL);
		if (email) {
			sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
						     info,
						     _("Email address"),
						     email);
		}
	}

	site = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC,
					     bbuddy,
					     SIPE_BUDDY_INFO_SITE);
	if (site) {
		sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
					     info,
					     _("Site"),
					     site);
		g_free(site);
	}

	if (device_name) {
		sipe_backend_buddy_info_add(SIPE_CORE_PUBLIC,
					     info,
					     _("Device"),
					     device_name);
	}

	sipe_backend_buddy_info_finalize(SIPE_CORE_PUBLIC, info, uri);

	g_free(phone_number);
	g_free(server_alias);
	g_free(email);
	g_free(device_name);
	g_free(alias);

	return TRUE;
}

/**
 * AD search first, LDAP based
 */
void sipe_core_buddy_get_info(struct sipe_core_public *sipe_public,
			      const gchar *who)
{
	char *row = g_markup_printf_escaped(SIPE_SOAP_SEARCH_ROW,
					    "msRTCSIP-PrimaryUserAddress",
					    who);
	struct transaction_payload *payload = g_new0(struct transaction_payload, 1);

	SIPE_DEBUG_INFO("sipe_core_buddy_get_info: row: %s", row ? row : "");

	payload->destroy = g_free;
	payload->data = g_strdup(who);

	sip_soap_directory_search(SIPE_CORE_PRIVATE,
				  1,
				  row,
				  process_get_info_response,
				  payload);
	g_free(row);
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

	/*--------------------- START WIP ------------------------------*/

	return(menu);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
