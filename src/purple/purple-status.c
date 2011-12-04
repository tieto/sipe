/**
 * @file purple-status.c
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

#include <glib.h>

#include "account.h"
#include "savedstatuses.h"

#include "sipe-backend.h"
#include "sipe-core.h"

#include "purple-private.h"

/* Status attributes */
#define PURPLE_STATUS_ATTR_ID_MESSAGE "message"

/**
 * This method motivates Purple's Host (e.g. Pidgin) to update its UI
 * by using standard Purple's means of signals and saved statuses.
 *
 * Thus all UI elements get updated: Status Button with Note, docklet.
 * This is ablolutely important as both our status and note can come
 * inbound (roaming) or be updated programmatically (e.g. based on our
 * calendar data).
 */
gboolean sipe_backend_status_and_note(struct sipe_core_public *sipe_public,
				      const gchar *status_id,
				      const gchar *message)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleAccount *account = purple_private->account;
	PurpleStatus *status = purple_account_get_active_status(account);
	gboolean changed = TRUE;

	if (g_str_equal(status_id, purple_status_get_id(status)) &&
	    sipe_strequal(message,
			  purple_status_get_attr_string(status,
							PURPLE_STATUS_ATTR_ID_MESSAGE)))
	{
		changed = FALSE;
	}

	if (purple_savedstatus_is_idleaway()) {
		changed = FALSE;
	}

	if (changed) {
		PurpleSavedStatus *saved_status;
		const PurpleStatusType *acct_status_type =
			purple_status_type_find_with_id(account->status_types, status_id);
		PurpleStatusPrimitive primitive = purple_status_type_get_primitive(acct_status_type);

		saved_status = purple_savedstatus_find_transient_by_type_and_message(primitive, message);
		if (saved_status) {
			purple_savedstatus_set_substatus(saved_status, account, acct_status_type, message);
		}

		/* If this type+message is unique then create a new transient saved status
		 * Ref: gtkstatusbox.c
		 */
		if (!saved_status) {
			GList *tmp;
			GList *active_accts = purple_accounts_get_all_active();

			saved_status = purple_savedstatus_new(NULL, primitive);
			purple_savedstatus_set_message(saved_status, message);

			for (tmp = active_accts; tmp != NULL; tmp = tmp->next) {
				purple_savedstatus_set_substatus(saved_status,
					(PurpleAccount *)tmp->data, acct_status_type, message);
			}
			g_list_free(active_accts);
		}

		/* Set the status for each account */
		purple_savedstatus_activate(saved_status);
	}

	return(changed);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
