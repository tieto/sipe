/**
 * @file purple-search.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011 SIPE Project <http://sipe.sourceforge.net/>
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

#include <glib.h>

#include "notify.h"

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-nls.h"

#include "purple-private.h"

struct sipe_backend_search_results *sipe_backend_search_results_start(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public)
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
	PurpleConversation *conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM,
									 id,
									 acct);
	if (conv == NULL)
		conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, acct, id);
	g_free(id);
	purple_conversation_present(conv);
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

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
