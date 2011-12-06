/**
 * @file sipe-status.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011 SIPE Project <http://sipe.sourceforge.net/>
 *
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

#include <time.h>

#include <glib.h>

#include "http-conn.h" /* sipe-cal.h requires this */
#include "sipe-backend.h"
#include "sipe-cal.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-ocs2005.h"
#include "sipe-ocs2007.h"
#include "sipe-schedule.h"
#include "sipe-status.h"
#include "sipe-utils.h"
#define _SIPE_NEED_ACTIVITIES
#include "sipe.h"

#define SIPE_IDLE_SET_DELAY 1 /* seconds */

void sipe_core_reset_status(struct sipe_core_public *sipe_public)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007))
		sipe_ocs2007_reset_status(sipe_private);
	else
		sipe_ocs2005_reset_status(sipe_private);
}

void sipe_status_and_note(struct sipe_core_private *sipe_private,
			  const gchar *status_id)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

	if (!status_id)
		status_id = sip->status;

	SIPE_DEBUG_INFO("sipe_status_and_note: switch to '%s' for the account", status_id);

	if (sipe_backend_status_and_note(SIPE_CORE_PUBLIC,
					 status_id,
					 sip->note)) {
		/* status has changed */
		sipe_activity activity = sipe_activity_from_token(status_id);

		sip->do_not_publish[activity] = time(NULL);
		SIPE_DEBUG_INFO("sipe_status_and_note: do_not_publish[%s]=%d [now]",
				status_id,
				(int) sip->do_not_publish[activity]);
	}
}

void sipe_core_status_set(struct sipe_core_public *sipe_public,
			  const gchar *status_id,
			  const gchar *note)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

	if (sip) {
		gchar *action_name;
		gchar *tmp;
		time_t now = time(NULL);
		sipe_activity activity = sipe_activity_from_token(status_id);
		gboolean do_not_publish = ((now - sip->do_not_publish[activity]) <= 2);

		/* when other point of presence clears note, but we are keeping
		 * state if OOF note.
		 */
		if (do_not_publish && !note && sip->cal && sip->cal->oof_note) {
			SIPE_DEBUG_INFO_NOFORMAT("sipe_core_status_set: enabling publication as OOF note keepers.");
			do_not_publish = FALSE;
		}

		SIPE_DEBUG_INFO("sipe_core_status_set: was: sip->do_not_publish[%s]=%d [?] now(time)=%d",
				status_id, (int)sip->do_not_publish[activity], (int)now);

		sip->do_not_publish[activity] = 0;
		SIPE_DEBUG_INFO("sipe_core_status_set: set: sip->do_not_publish[%s]=%d [0]",
				status_id, (int)sip->do_not_publish[activity]);

		if (do_not_publish) {
			SIPE_DEBUG_INFO_NOFORMAT("sipe_core_status_set: publication was switched off, exiting.");
			return;
		}

		sipe_set_status(sipe_private, status_id);

		/* hack to escape apostrof before comparison */
		tmp = note ? sipe_utils_str_replace(note, "'", "&apos;") : NULL;

		/* this will preserve OOF flag as well */
		if (!sipe_strequal(tmp, sip->note)) {
			sip->is_oof_note = FALSE;
			g_free(sip->note);
			sip->note = g_strdup(note);
			sip->note_since = time(NULL);
		}
		g_free(tmp);

		/* schedule 2 sec to capture idle flag */
		action_name = g_strdup("<+set-status>");
		sipe_schedule_seconds(sipe_private,
				      action_name,
				      NULL,
				      SIPE_IDLE_SET_DELAY,
				      send_presence_status,
				      NULL);
		g_free(action_name);
	}
}

/**
 * Whether user manually changed status or
 * it was changed automatically due to user
 * became inactive/active again
 */
gboolean sipe_status_changed_by_user(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	gboolean res;
	time_t now = time(NULL);

	SIPE_DEBUG_INFO("sipe_status_changed_by_user: sip->idle_switch : %s",
			asctime(localtime(&(sip->idle_switch))));
	SIPE_DEBUG_INFO("sipe_status_changed_by_user: now              : %s",
			asctime(localtime(&now)));

	res = ((now - SIPE_IDLE_SET_DELAY * 2) >= sip->idle_switch);

	SIPE_DEBUG_INFO("sipe_status_changed_by_user: res  = %s",
			res ? "USER" : "MACHINE");
	return res;
}

void sipe_core_status_idle(struct sipe_core_public *sipe_public)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

	if (sip) {
		sip->idle_switch = time(NULL);
		SIPE_DEBUG_INFO("sipe_core_status_idle: sip->idle_switch : %s",
				asctime(localtime(&(sip->idle_switch))));
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
