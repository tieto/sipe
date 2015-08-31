/**
 * @file purple-status.c
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

#include <glib.h>

#include "account.h"
#include "savedstatuses.h"

#include "sipe-backend.h"
#include "sipe-core.h"

#include "purple-private.h"

guint sipe_backend_status(struct sipe_core_public *sipe_public)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleStatus *status = purple_account_get_active_status(purple_private->account);
	if (!status) return(SIPE_ACTIVITY_UNSET);
	return(sipe_purple_token_to_activity(purple_status_get_id(status)));
}

gboolean sipe_backend_status_changed(struct sipe_core_public *sipe_public,
				     guint activity,
				     const gchar *message)
{
	gboolean result = FALSE;

	if ((activity == SIPE_ACTIVITY_AWAY) && purple_savedstatus_is_idleaway()) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_backend_status_changed: user is already idle-away");
	} else {
		struct sipe_backend_private *purple_private = sipe_public->backend_private;
		PurpleStatus *status = purple_account_get_active_status(purple_private->account);
		const gchar *status_id = sipe_purple_activity_to_token(activity);

		result = !(g_str_equal(status_id, purple_status_get_id(status)) &&
			   sipe_strequal(message,
					 purple_status_get_attr_string(status,
								       SIPE_PURPLE_STATUS_ATTR_ID_MESSAGE)));
	}

	return(result);
}

/**
 * This method motivates Purple's Host (e.g. Pidgin) to update its UI
 * by using standard Purple's means of signals and saved statuses.
 *
 * Thus all UI elements get updated: Status Button with Note, docklet.
 * This is ablolutely important as both our status and note can come
 * inbound (roaming) or be updated programmatically (e.g. based on our
 * calendar data).
 */
void sipe_backend_status_and_note(struct sipe_core_public *sipe_public,
				  guint activity,
				  const gchar *message)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleAccount *account = purple_private->account;
	const gchar *status_id = sipe_purple_activity_to_token(activity);
	PurpleSavedStatus *saved_status;
	const PurpleStatusType *acct_status_type =
		purple_status_type_find_with_id(purple_account_get_status_types(account),
						status_id);
	PurpleStatusPrimitive primitive = purple_status_type_get_primitive(acct_status_type);

	/* code adapted from: pidgin/gtkstatusbox.c */
	saved_status = purple_savedstatus_find_transient_by_type_and_message(primitive, message);
	if (saved_status) {
		purple_savedstatus_set_substatus(saved_status, account, acct_status_type, message);
	} else {
		/* This type+message is unique then create a new transient saved status */
		GList *entry;
		GList *active_accts = purple_accounts_get_all_active();

		SIPE_DEBUG_INFO("sipe_backend_status_and_note: creating new saved status %s '%s'",
				status_id, message ? message : "(null)");

		saved_status = purple_savedstatus_new(NULL, primitive);
		purple_savedstatus_set_message(saved_status, message);

		for (entry = active_accts; entry != NULL; entry = entry->next)
			purple_savedstatus_set_substatus(saved_status,
							 (PurpleAccount *) entry->data,
							 acct_status_type,
							 message);
		g_list_free(active_accts);
	}

	/* Set the status for each account */
	purple_private->status_changed_by_core = TRUE;
	purple_savedstatus_activate(saved_status);
}

/**
 * Work around broken libpurple idle notification
 *
 * (1) user changes the status
 *      sipe_purple_set_status()
 *      -> user changed state
 *
 * (2) client detects that user is idle
 *      sipe_purple_set_status()      [sometimes omitted?!?!?]
 *      sipe_purple_set_idle( != 0 )
 *      -> machine changed state
 *
 * (3) client detects that user is no longer idle
 *      sipe_purple_set_idle(0)
 *      sipe_purple_set_status()
 *      -> user changed state
 *
 * (4) core sends a status change
 *      sipe_backend_status_and_note()
 *      purple_savedstatus_activate()
 *      sipe_purple_set_status()
 *      -> status change must be ignored
 *
 * Cases (1) and (2) can only be differentiated by deferring the update.
 */
static void sipe_purple_status_deferred_update(struct sipe_backend_private *purple_private,
					       gboolean changed_by_user)
{
	gchar *note = purple_private->deferred_status_note;

	purple_private->deferred_status_note    = NULL;
	purple_private->deferred_status_timeout = 0;

	sipe_core_status_set(purple_private->public,
			     changed_by_user,
			     purple_private->deferred_status_activity,
			     note);
	g_free(note);
}

static gboolean sipe_purple_status_timeout(gpointer data)
{
	/* timeout expired -> no idle indication -> state changed by user */
	sipe_purple_status_deferred_update(data, TRUE);
	return(FALSE);
}

void sipe_purple_set_status(PurpleAccount *account,
			    PurpleStatus *status)
{
	if (purple_account_get_connection(account) &&
	    purple_status_is_active(status)) {
		struct sipe_core_public *sipe_public = PURPLE_ACCOUNT_TO_SIPE_CORE_PUBLIC;
		struct sipe_backend_private *purple_private = sipe_public->backend_private;
		const gchar *status_id = purple_status_get_id(status);
		guint activity = sipe_purple_token_to_activity(status_id);
		const gchar *note = purple_status_get_attr_string(status,
								  SIPE_PURPLE_STATUS_ATTR_ID_MESSAGE);

		SIPE_DEBUG_INFO("sipe_purple_set_status[CB]: '%s'",
				status_id);

		if (purple_private->status_changed_by_core) {
			SIPE_DEBUG_INFO_NOFORMAT("sipe_purple_set_status[CB]: triggered by core - ignoring");

		} else if (purple_private->user_is_not_idle) {
			sipe_core_status_set(sipe_public,
					     TRUE,
					     activity,
					     note);

		} else {
			if (purple_private->deferred_status_timeout)
				purple_timeout_remove(purple_private->deferred_status_timeout);
			g_free(purple_private->deferred_status_note);

			SIPE_DEBUG_INFO_NOFORMAT("sipe_purple_set_status[CB]: defer status update");

			purple_private->deferred_status_note     = g_strdup(note);
			purple_private->deferred_status_activity = activity;
			purple_private->deferred_status_timeout  = purple_timeout_add_seconds(1,
											      sipe_purple_status_timeout,
											      purple_private);
		}

		/* reset flags */
		purple_private->status_changed_by_core = FALSE;
		purple_private->user_is_not_idle       = FALSE;
	}
}

void sipe_purple_set_idle(PurpleConnection *gc,
			  int interval)
{
	if (gc) {
		struct sipe_core_public *sipe_public = PURPLE_GC_TO_SIPE_CORE_PUBLIC;
		struct sipe_backend_private *purple_private = sipe_public->backend_private;

		purple_private->user_is_not_idle = interval == 0;

		SIPE_DEBUG_INFO("sipe_purple_set_idle[CB]: user is %sidle",
				purple_private->user_is_not_idle ? "not " : "");

		if (!purple_private->user_is_not_idle) {
			/* timeout not expired -> state changed by machine */
			if (purple_private->deferred_status_timeout)
				purple_timeout_remove(purple_private->deferred_status_timeout);
			sipe_purple_status_deferred_update(purple_private, FALSE);
		}
	}
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
