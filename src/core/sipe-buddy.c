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
#include "sipmsg.h"
#include "sip-soap.h"
#include "sipe-backend.h"
#include "sipe-buddy.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-group.h"
#include "sipe-nls.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

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
