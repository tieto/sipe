/**
 * @file purple-search.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-2015 SIPE Project <http://sipe.sourceforge.net/>
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

#include <glib.h>

#include "notify.h"
#include "request.h"

#include "version.h"
#if PURPLE_VERSION_CHECK(3,0,0)
#include "conversations.h"
#endif

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-nls.h"

#include "purple-private.h"

void sipe_backend_search_failed(struct sipe_core_public *sipe_public,
				SIPE_UNUSED_PARAMETER struct sipe_backend_search_token *token,
				const gchar *msg)
{
	sipe_backend_notify_error(sipe_public, msg, NULL);
}

struct sipe_backend_search_results *sipe_backend_search_results_start(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
								      SIPE_UNUSED_PARAMETER struct sipe_backend_search_token *token)
{
	PurpleNotifySearchResults *results = purple_notify_searchresults_new();

	if (results) {
		PurpleNotifySearchColumn *column;
		column = purple_notify_searchresults_column_new(_("User name"));
		purple_notify_searchresults_column_add(results, column);

		column = purple_notify_searchresults_column_new(_("Name"));
		purple_notify_searchresults_column_add(results, column);

		column = purple_notify_searchresults_column_new(_("Company"));
		purple_notify_searchresults_column_add(results, column);

		column = purple_notify_searchresults_column_new(_("Country"));
		purple_notify_searchresults_column_add(results, column);

		column = purple_notify_searchresults_column_new(_("Email"));
		purple_notify_searchresults_column_add(results, column);
	}

	return((struct sipe_backend_search_results *)results);
}

void sipe_backend_search_results_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				     struct sipe_backend_search_results *results,
				     const gchar *uri,
				     const gchar *name,
				     const gchar *company,
				     const gchar *country,
				     const gchar *email)
{
		GList *row = NULL;
		row = g_list_append(row, g_strdup(uri));
		row = g_list_append(row, g_strdup(name));
		row = g_list_append(row, g_strdup(company));
		row = g_list_append(row, g_strdup(country));
		row = g_list_append(row, g_strdup(email));
		purple_notify_searchresults_row_add((PurpleNotifySearchResults *) results,
						    row);
}

static void searchresults_im_buddy(PurpleConnection *gc,
				   GList *row,
				   SIPE_UNUSED_PARAMETER void *user_data)
{
	PurpleAccount *acct = purple_connection_get_account(gc);
	gchar *id = sip_uri_from_name(g_list_nth_data(row, 0));

#if PURPLE_VERSION_CHECK(3,0,0)
	PurpleIMConversation *conv = purple_conversations_find_im_with_account(id,
									       acct);

	if (conv == NULL)
		conv = purple_im_conversation_new(acct, id);
#else
	PurpleConversation *conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM,
									 id,
									 acct);
	if (conv == NULL)
		conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, acct, id);
#endif

	g_free(id);
	purple_conversation_present((PurpleConversation *) conv);
}

static void searchresults_add_buddy(PurpleConnection *gc,
				    GList *row,
				    SIPE_UNUSED_PARAMETER void *user_data)
{
	purple_blist_request_add_buddy(purple_connection_get_account(gc),
				       g_list_nth_data(row, 0),
				       _("Other Contacts"),
				       g_list_nth_data(row, 1));
}


void sipe_backend_search_results_finalize(struct sipe_core_public *sipe_public,
					  struct sipe_backend_search_results *results,
					  const gchar *description,
					  SIPE_UNUSED_PARAMETER gboolean more)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleNotifySearchResults *r = (PurpleNotifySearchResults *) results;

	purple_notify_searchresults_button_add(r,
					       PURPLE_NOTIFY_BUTTON_IM,
					       searchresults_im_buddy);
	purple_notify_searchresults_button_add(r,
					       PURPLE_NOTIFY_BUTTON_ADD,
					       searchresults_add_buddy);
	purple_notify_searchresults(purple_private->gc,
				    NULL,
				    NULL,
				    description,
				    r,
				    NULL,
				    NULL);

}

static void sipe_purple_find_contact_cb(PurpleConnection *gc,
					PurpleRequestFields *fields)
{
	GList *entries = purple_request_field_group_get_fields(purple_request_fields_get_groups(fields)->data);
	const gchar *given_name = NULL;
	const gchar *surname    = NULL;
	const gchar *email      = NULL;
	const gchar *sipid      = NULL;
	const gchar *company    = NULL;
	const gchar *country    = NULL;

	while (entries) {
		PurpleRequestField *field = entries->data;
		const char *id = purple_request_field_get_id(field);
		const char *value = purple_request_field_string_get_value(field);

		SIPE_DEBUG_INFO("sipe_purple_find_contact_cb: %s = '%s'", id, value ? value : "");

		if (value && strlen(value)) {
			if (strcmp(id, "given") == 0) {
				given_name = value;
			} else if (strcmp(id, "surname") == 0) {
				surname = value;
			} else if (strcmp(id, "email") == 0) {
				email = value;
			} else if (strcmp(id, "sipid") == 0) {
				sipid = value;
			} else if (strcmp(id, "company") == 0) {
				company = value;
			} else if (strcmp(id, "country") == 0) {
				country = value;
			}
		}

		entries = g_list_next(entries);
	};

	sipe_core_buddy_search(PURPLE_GC_TO_SIPE_CORE_PUBLIC,
			       NULL,
			       given_name,
			       surname,
			       email,
			       sipid,
			       company,
			       country);
}

#if PURPLE_VERSION_CHECK(3,0,0)
void sipe_purple_show_find_contact(PurpleProtocolAction *action)
{
	PurpleConnection *gc = action->connection;
#else
void sipe_purple_show_find_contact(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
#endif
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);

	field = purple_request_field_string_new("given", _("First name"), NULL, FALSE);
	purple_request_field_group_add_field(group, field);
	field = purple_request_field_string_new("surname", _("Last name"), NULL, FALSE);
	purple_request_field_group_add_field(group, field);
	field = purple_request_field_string_new("email", _("Email"), NULL, FALSE);
	purple_request_field_group_add_field(group, field);
	field = purple_request_field_string_new("sipid", _("SIP ID"), NULL, FALSE);
	purple_request_field_group_add_field(group, field);
	field = purple_request_field_string_new("company", _("Company"), NULL, FALSE);
	purple_request_field_group_add_field(group, field);
	field = purple_request_field_string_new("country", _("Country"), NULL, FALSE);
	purple_request_field_group_add_field(group, field);

	purple_request_fields(gc,
			      _("Search"),
			      _("Search for a contact"),
			      _("Enter the information for the person you wish to find. Empty fields will be ignored."),
			      fields,
			      _("_Search"), G_CALLBACK(sipe_purple_find_contact_cb),
			      _("_Cancel"), NULL,
#if PURPLE_VERSION_CHECK(3,0,0)
			      purple_request_cpar_from_connection(gc),
#else
			      purple_connection_get_account(gc), NULL, NULL,
#endif
			      gc);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
