/**
 * @file sipe-status.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-12 SIPE Project <http://sipe.sourceforge.net/>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>

#include <glib.h>

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-cal.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-nls.h"
#include "sipe-ocs2005.h"
#include "sipe-ocs2007.h"
#include "sipe-schedule.h"
#include "sipe-status.h"
#include "sipe-utils.h"

#define SIPE_IDLE_SET_DELAY 1 /* seconds */

static struct
{
	const gchar *status_id;
	const gchar *desc;
} const sipe_activity_map[SIPE_ACTIVITY_NUM_TYPES] = {
/*
 * This has nothing to do with Availability numbers, like 3500 (online).
 * Just a mapping of Communicator Activities to tokens/translations
 */
/* @TODO: NULL means "default translation from Pidgin"?
 *        What about other backends?                    */
/* SIPE_ACTIVITY_UNSET       */ { "unset",                     NULL                            },
/* SIPE_ACTIVITY_AVAILABLE   */ { "available",                 NULL                            },
/* SIPE_ACTIVITY_ONLINE      */ { "online",                    NULL                            },
/* SIPE_ACTIVITY_INACTIVE    */ { "idle",                      N_("Inactive")                  },
/* SIPE_ACTIVITY_BUSY        */ { "busy",                      N_("Busy")                      },
/* SIPE_ACTIVITY_BUSYIDLE    */ { "busyidle",                  N_("Busy-Idle")                 },
/* SIPE_ACTIVITY_DND         */ { "do-not-disturb",            NULL                            },
/* SIPE_ACTIVITY_BRB         */ { "be-right-back",             N_("Be right back")             },
/* SIPE_ACTIVITY_AWAY        */ { "away",                      NULL                            },
/* SIPE_ACTIVITY_LUNCH       */ { "out-to-lunch",              N_("Out to lunch")              },
/* SIPE_ACTIVITY_INVISIBLE   */ { "invisible",                 NULL                            },
/* SIPE_ACTIVITY_OFFLINE     */ { "offline",                   NULL                            },
/* SIPE_ACTIVITY_ON_PHONE    */ { "on-the-phone",              N_("In a call")                 },
/* SIPE_ACTIVITY_IN_CONF     */ { "in-a-conference",           N_("In a conference")           },
/* SIPE_ACTIVITY_IN_MEETING  */ { "in-a-meeting",              N_("In a meeting")              },
/* SIPE_ACTIVITY_OOF         */ { "out-of-office",             N_("Out of office")             },
/* SIPE_ACTIVITY_URGENT_ONLY */ { "urgent-interruptions-only", N_("Urgent interruptions only") },
};

static GHashTable *token_map;

void sipe_status_init(void)
{
	guint index;

	token_map = g_hash_table_new(g_str_hash, g_str_equal);
	for (index = SIPE_ACTIVITY_UNSET;
	     index < SIPE_ACTIVITY_NUM_TYPES;
	     index++) {
		g_hash_table_insert(token_map,
				    (gchar *) sipe_activity_map[index].status_id,
				    GUINT_TO_POINTER(index));
	}
}

void sipe_status_shutdown(void)
{
	g_hash_table_destroy(token_map);
}

/* type == SIPE_ACTIVITY_xxx (see sipe-core.h) */
const gchar *sipe_status_activity_to_token(guint type)
{
	return(sipe_activity_map[type].status_id);
}

guint sipe_status_token_to_activity(const gchar *token)
{
	if (!token) return(SIPE_ACTIVITY_UNSET);
	return(GPOINTER_TO_UINT(g_hash_table_lookup(token_map, token)));
}

const gchar *sipe_core_activity_description(guint type)
{
	return(gettext(sipe_activity_map[type].desc));
}

void sipe_status_set_token(struct sipe_core_private *sipe_private,
			   const gchar *status_id)
{
	g_free(sipe_private->status);
	sipe_private->status = g_strdup(status_id);
}

void sipe_status_set_activity(struct sipe_core_private *sipe_private,
			      guint activity)
{
	sipe_status_set_token(sipe_private,
			      sipe_status_activity_to_token(activity));
}

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
	guint activity;

	if (!status_id)
		status_id = sipe_private->status;

	SIPE_DEBUG_INFO("sipe_status_and_note: switch to '%s' for the account", status_id);

	activity = sipe_status_token_to_activity(status_id);
	if (sipe_backend_status_changed(SIPE_CORE_PUBLIC,
					activity,
					sipe_private->note)) {
		/* status has changed */
		sipe_private->do_not_publish[activity] = time(NULL);
		SIPE_DEBUG_INFO("sipe_status_and_note: do_not_publish[%s]=%d [now]",
				status_id,
				(int) sipe_private->do_not_publish[activity]);

		/* update backend status */
		sipe_backend_status_and_note(SIPE_CORE_PUBLIC,
					     activity,
					     sipe_private->note);
	}
}

void sipe_status_update(struct sipe_core_private *sipe_private,
			SIPE_UNUSED_PARAMETER gpointer unused)
{
	guint activity = sipe_backend_status(SIPE_CORE_PUBLIC);

	if (activity == SIPE_ACTIVITY_UNSET) return;

	SIPE_DEBUG_INFO("sipe_status_update: status: %s (%s)",
			sipe_status_activity_to_token(activity),
			sipe_status_changed_by_user(sipe_private) ? "USER" : "MACHINE");

	sipe_cal_presence_publish(sipe_private, FALSE);
}

void sipe_core_status_set(struct sipe_core_public *sipe_public,
			  guint activity,
			  const gchar *note)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	gchar *action_name;
	gchar *tmp;
	time_t now = time(NULL);
	const gchar *status_id = sipe_status_activity_to_token(activity);
	gboolean do_not_publish = ((now - sipe_private->do_not_publish[activity]) <= 2);

	/* when other point of presence clears note, but we are keeping
	 * state if OOF note.
	 */
	if (do_not_publish &&
	    !note &&
	    sipe_private->calendar &&
	    sipe_private->calendar->oof_note) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_core_status_set: enabling publication as OOF note keepers.");
		do_not_publish = FALSE;
	}

	SIPE_DEBUG_INFO("sipe_core_status_set: was: sipe_private->do_not_publish[%s]=%d [?] now(time)=%d",
			status_id, (int)sipe_private->do_not_publish[activity], (int)now);

	sipe_private->do_not_publish[activity] = 0;
	SIPE_DEBUG_INFO("sipe_core_status_set: set: sipe_private->do_not_publish[%s]=%d [0]",
			status_id, (int)sipe_private->do_not_publish[activity]);

	if (do_not_publish) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_core_status_set: publication was switched off, exiting.");
		return;
	}

	sipe_status_set_token(sipe_private, status_id);

	/* hack to escape apostrof before comparison */
	tmp = note ? sipe_utils_str_replace(note, "'", "&apos;") : NULL;

	/* this will preserve OOF flag as well */
	if (!sipe_strequal(tmp, sipe_private->note)) {
		SIPE_CORE_PRIVATE_FLAG_UNSET(OOF_NOTE);
		g_free(sipe_private->note);
		sipe_private->note = g_strdup(note);
		sipe_private->note_since = time(NULL);
	}
	g_free(tmp);

	/* schedule 2 sec to capture idle flag */
	action_name = g_strdup("<+set-status>");
	sipe_schedule_seconds(sipe_private,
			      action_name,
			      NULL,
			      SIPE_IDLE_SET_DELAY,
			      sipe_status_update,
			      NULL);
	g_free(action_name);
}

/**
 * Whether user manually changed status or
 * it was changed automatically due to user
 * became inactive/active again
 */
gboolean sipe_status_changed_by_user(struct sipe_core_private *sipe_private)
{
	gboolean res;
	time_t now = time(NULL);

	SIPE_DEBUG_INFO("sipe_status_changed_by_user: sipe_private->idle_switch : %s",
			asctime(localtime(&(sipe_private->idle_switch))));
	SIPE_DEBUG_INFO("sipe_status_changed_by_user: now              : %s",
			asctime(localtime(&now)));

	res = ((now - SIPE_IDLE_SET_DELAY * 2) >= sipe_private->idle_switch);

	SIPE_DEBUG_INFO("sipe_status_changed_by_user: res  = %s",
			res ? "USER" : "MACHINE");
	return res;
}

void sipe_core_status_idle(struct sipe_core_public *sipe_public)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;

	sipe_private->idle_switch = time(NULL);
	SIPE_DEBUG_INFO("sipe_core_status_idle: sipe_private->idle_switch : %s",
			asctime(localtime(&(sipe_private->idle_switch))));
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
