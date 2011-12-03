/**
 * @file sipe.c
 *
 *****************************************************************************
 *** !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ***
 ***                                                                       ***
 ***                       THIS MODULE IS DEPECRATED                       ***
 ***                                                                       ***
 ***                DO NOT ADD ANY NEW CODE TO THIS MODULE                 ***
 ***                                                                       ***
 *** !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ***
 *****************************************************************************
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-11 SIPE Project <http://sipe.sourceforge.net/>
 * Copyright (C) 2010 pier11 <pier11@operamail.com>
 * Copyright (C) 2009 Anibal Avelar <debianmx@gmail.com>
 * Copyright (C) 2009 pier11 <pier11@operamail.com>
 * Copyright (C) 2008 Novell, Inc., Anibal Avelar <debianmx@gmail.com>
 * Copyright (C) 2007 Anibal Avelar <debianmx@gmail.com>
 * Copyright (C) 2005 Thomas Butter <butter@uni-mannheim.de>
 *
 * ***
 * Thanks to Google's Summer of Code Program and the helpful mentors
 * ***
 *
 * Session-based SIP MESSAGE documentation:
 *   http://tools.ietf.org/html/draft-ietf-simple-im-session-00
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
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>

#include <libintl.h>

#include "sipe-common.h"

#include "account.h"
#include "blist.h"
#include "connection.h"
#include "conversation.h"
#include "ft.h"
#include "notify.h"
#include "plugin.h"
#include "privacy.h"
#include "request.h"
#include "savedstatuses.h"
#include "version.h"

#include "core-depurple.h" /* Temporary for the core de-purple transition */

#include "http-conn.h"
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
#include "sipe-dialog.h"
#include "sipe-groupchat.h"
#include "sipe-im.h"
#include "sipe-nls.h"
#include "sipe-ocs2005.h"
#include "sipe-ocs2007.h"
#include "sipe-schedule.h"
#include "sipe-session.h"
#include "sipe-subscriptions.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

#define _SIPE_NEED_ACTIVITIES /* ugly hack :-( */
#include "sipe.h"

#define SIPE_IDLE_SET_DELAY		1	/* 1 sec */

/* Status identifiers (see also: sipe_status_types()) */
#define SIPE_STATUS_ID_UNKNOWN     purple_primitive_get_id_from_type(PURPLE_STATUS_UNSET)     /* Unset (primitive) */
#define SIPE_STATUS_ID_OFFLINE     purple_primitive_get_id_from_type(PURPLE_STATUS_OFFLINE)   /* Offline (primitive) */
#define SIPE_STATUS_ID_AVAILABLE   purple_primitive_get_id_from_type(PURPLE_STATUS_AVAILABLE) /* Online */
/*      PURPLE_STATUS_UNAVAILABLE: */
#define SIPE_STATUS_ID_BUSY        "busy"                                                     /* Busy */
#define SIPE_STATUS_ID_BUSYIDLE    "busyidle"                                                 /* BusyIdle */
#define SIPE_STATUS_ID_DND         "do-not-disturb"                                           /* Do Not Disturb */
#define SIPE_STATUS_ID_IN_MEETING  "in-a-meeting"                                             /* In a meeting */
#define SIPE_STATUS_ID_IN_CONF     "in-a-conference"                                          /* In a conference */
#define SIPE_STATUS_ID_ON_PHONE    "on-the-phone"                                             /* On the phone */
#define SIPE_STATUS_ID_INVISIBLE   purple_primitive_get_id_from_type(PURPLE_STATUS_INVISIBLE) /* Appear Offline */
/*      PURPLE_STATUS_AWAY: */
#define SIPE_STATUS_ID_IDLE        "idle"                                                     /* Idle/Inactive */
#define SIPE_STATUS_ID_BRB         "be-right-back"                                            /* Be Right Back */
#define SIPE_STATUS_ID_AWAY        purple_primitive_get_id_from_type(PURPLE_STATUS_AWAY)      /* Away (primitive) */
/** Reuters status (user settable) */
#define SIPE_STATUS_ID_LUNCH       "out-to-lunch"                                             /* Out To Lunch */
/* ???  PURPLE_STATUS_EXTENDED_AWAY */
/* ???  PURPLE_STATUS_MOBILE */
/* ???  PURPLE_STATUS_TUNE */

/* Status attributes (see also sipe_status_types() */
#define SIPE_STATUS_ATTR_ID_MESSAGE  "message"

static struct sipe_activity_map_struct
{
	sipe_activity type;
	const char *token;
	const char *desc;
	const char *status_id;

} const sipe_activity_map[] =
{
/* This has nothing to do with Availability numbers, like 3500 (online).
 * Just a mapping of Communicator Activities to Purple statuses to be able display them in Pidgin.
 */
	{ SIPE_ACTIVITY_UNSET,		"unset",			NULL				, NULL				},
	{ SIPE_ACTIVITY_ONLINE,		"online",			NULL				, NULL				},
	{ SIPE_ACTIVITY_INACTIVE,	SIPE_STATUS_ID_IDLE,		N_("Inactive")			, NULL				},
	{ SIPE_ACTIVITY_BUSY,		SIPE_STATUS_ID_BUSY,		N_("Busy")			, SIPE_STATUS_ID_BUSY		},
	{ SIPE_ACTIVITY_BUSYIDLE,	SIPE_STATUS_ID_BUSYIDLE,	N_("Busy-Idle")			, NULL				},
	{ SIPE_ACTIVITY_DND,		SIPE_STATUS_ID_DND,		NULL				, SIPE_STATUS_ID_DND		},
	{ SIPE_ACTIVITY_BRB,		SIPE_STATUS_ID_BRB,		N_("Be right back")		, SIPE_STATUS_ID_BRB		},
	{ SIPE_ACTIVITY_AWAY,		"away",				NULL				, NULL				},
	{ SIPE_ACTIVITY_LUNCH,		SIPE_STATUS_ID_LUNCH,		N_("Out to lunch")		, NULL				},
	{ SIPE_ACTIVITY_OFFLINE,	"offline",			NULL				, NULL				},
	{ SIPE_ACTIVITY_ON_PHONE,	SIPE_STATUS_ID_ON_PHONE,	N_("In a call")			, NULL				},
	{ SIPE_ACTIVITY_IN_CONF,	SIPE_STATUS_ID_IN_CONF,		N_("In a conference")		, NULL				},
	{ SIPE_ACTIVITY_IN_MEETING,	SIPE_STATUS_ID_IN_MEETING,	N_("In a meeting")		, NULL				},
	{ SIPE_ACTIVITY_OOF,		"out-of-office",		N_("Out of office")		, NULL				},
	{ SIPE_ACTIVITY_URGENT_ONLY,	"urgent-interruptions-only",	N_("Urgent interruptions only")	, NULL				}
};
/** @param x is sipe_activity */
#define SIPE_ACTIVITY_I18N(x) gettext(sipe_activity_map[x].desc)

const gchar *sipe_activity_to_token(sipe_activity type)
{
	return(sipe_activity_map[type].token);
}

const gchar *sipe_activity_description(sipe_activity type)
{
	return(SIPE_ACTIVITY_I18N(type));
}

void sipe_set_unknown_status(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

	g_free(sip->status);
	sip->status = g_strdup(SIPE_STATUS_ID_UNKNOWN);
}

void sipe_set_initial_status(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

	g_free(sip->status);
	sip->status = g_strdup(SIPE_STATUS_ID_AVAILABLE); /* our initial state */
}

void sipe_set_invisible_status(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

	g_free(sip->status);
	sip->status = g_strdup(SIPE_STATUS_ID_INVISIBLE);
}

static sipe_activity
sipe_get_activity_by_token(const char *token)
{
	int i;

	for (i = 0; i < SIPE_ACTIVITY_NUM_TYPES; i++)
	{
		if (sipe_strequal(token, sipe_activity_to_token(i)))
			return sipe_activity_map[i].type;
	}

	return sipe_activity_map[0].type;
}

const gchar *sipe_activity_description_from_token(const gchar *token)
{
	if (!token) return NULL;

	return sipe_activity_description(sipe_get_activity_by_token(token));
}

void
sipe_apply_calendar_status(struct sipe_core_private *sipe_private,
			   struct sipe_buddy *sbuddy,
			   const char *status_id)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	time_t cal_avail_since;
	int cal_status = sipe_cal_get_status(sbuddy, time(NULL), &cal_avail_since);
	int avail;
	gchar *self_uri;

	if (!sbuddy) return;

	if (cal_status < SIPE_CAL_NO_DATA) {
		SIPE_DEBUG_INFO("sipe_apply_calendar_status: cal_status      : %d for %s", cal_status, sbuddy->name);
		SIPE_DEBUG_INFO("sipe_apply_calendar_status: cal_avail_since : %s", asctime(localtime(&cal_avail_since)));
	}

	/* scheduled Cal update call */
	if (!status_id) {
		status_id = sbuddy->last_non_cal_status_id;
		g_free(sbuddy->activity);
		sbuddy->activity = g_strdup(sbuddy->last_non_cal_activity);
	}

	if (!status_id) {
		SIPE_DEBUG_INFO("sipe_apply_calendar_status: status_id is NULL for %s, exiting.",
				sbuddy->name ? sbuddy->name : "" );
		return;
	}

	/* adjust to calendar status */
	if (cal_status != SIPE_CAL_NO_DATA) {
		SIPE_DEBUG_INFO("sipe_apply_calendar_status: user_avail_since: %s", asctime(localtime(&sbuddy->user_avail_since)));

		if (cal_status == SIPE_CAL_BUSY
		    && cal_avail_since > sbuddy->user_avail_since
		    && 6500 >= sipe_get_availability_by_status(status_id, NULL))
		{
			status_id = SIPE_STATUS_ID_BUSY;
			g_free(sbuddy->activity);
			sbuddy->activity = g_strdup(sipe_activity_description(SIPE_ACTIVITY_IN_MEETING));
		}
		avail = sipe_get_availability_by_status(status_id, NULL);

		SIPE_DEBUG_INFO("sipe_apply_calendar_status: activity_since  : %s", asctime(localtime(&sbuddy->activity_since)));
		if (cal_avail_since > sbuddy->activity_since) {
			if (cal_status == SIPE_CAL_OOF
			    && avail >= 15000) /* 12000 in 2007 */
			{
				g_free(sbuddy->activity);
				sbuddy->activity = g_strdup(sipe_activity_description(SIPE_ACTIVITY_OOF));
			}
		}
	}

	/* then set status_id actually */
	SIPE_DEBUG_INFO("sipe_apply_calendar_status: to %s for %s", status_id, sbuddy->name ? sbuddy->name : "" );
	sipe_backend_buddy_set_status(SIPE_CORE_PUBLIC, sbuddy->name, status_id);

	/* set our account state to the one in roaming (including calendar info) */
	self_uri = sip_uri_self(sipe_private);
	if (sip->initial_state_published && sipe_strcase_equal(sbuddy->name, self_uri)) {
		if (sipe_strequal(status_id, SIPE_STATUS_ID_OFFLINE)) {
			status_id = g_strdup(SIPE_STATUS_ID_INVISIBLE); /* not not let offline status switch us off */
		}

		SIPE_DEBUG_INFO("sipe_apply_calendar_status: switch to '%s' for the account", sip->status);
		sipe_backend_account_status_and_note(sipe_private, status_id);
	}
	g_free(self_uri);
}

void
sipe_core_buddy_got_status(struct sipe_core_public *sipe_public,
			   const gchar* uri,
			   const gchar *status_id)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_buddy *sbuddy = g_hash_table_lookup(sipe_private->buddies, uri);

	if (!sbuddy) return;

	/* Check if on 2005 system contact's calendar,
	 * then set/preserve it.
	 */
	if (!SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		sipe_apply_calendar_status(sipe_private, sbuddy, status_id);
	} else {
		sipe_backend_buddy_set_status(sipe_public, uri, status_id);
	}
}

void sipe_set_status(PurpleAccount *account, PurpleStatus *status)
{
	SIPE_DEBUG_INFO("sipe_set_status: status=%s", purple_status_get_id(status));

	if (!purple_status_is_active(status))
		return;

	if (account->gc) {
		struct sipe_core_private *sipe_private = PURPLE_ACCOUNT_TO_SIPE_CORE_PRIVATE;
		struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

		if (sip) {
			gchar *action_name;
			gchar *tmp;
			time_t now = time(NULL);
			const char *status_id = purple_status_get_id(status);
			const char *note = purple_status_get_attr_string(status, SIPE_STATUS_ATTR_ID_MESSAGE);
			sipe_activity activity = sipe_get_activity_by_token(status_id);
			gboolean do_not_publish = ((now - sip->do_not_publish[activity]) <= 2);

			/* when other point of presence clears note, but we are keeping
			 * state if OOF note.
			 */
			if (do_not_publish && !note && sip->cal && sip->cal->oof_note) {
				SIPE_DEBUG_INFO_NOFORMAT("sipe_set_status: enabling publication as OOF note keepers.");
				do_not_publish = FALSE;
			}

			SIPE_DEBUG_INFO("sipe_set_status: was: sip->do_not_publish[%s]=%d [?] now(time)=%d",
					status_id, (int)sip->do_not_publish[activity], (int)now);

			sip->do_not_publish[activity] = 0;
			SIPE_DEBUG_INFO("sipe_set_status: set: sip->do_not_publish[%s]=%d [0]",
					status_id, (int)sip->do_not_publish[activity]);

			if (do_not_publish)
			{
				SIPE_DEBUG_INFO_NOFORMAT("sipe_set_status: publication was switched off, exiting.");
				return;
			}

			g_free(sip->status);
			sip->status = g_strdup(status_id);

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
			action_name = g_strdup_printf("<%s>", "+set-status");
			sipe_schedule_seconds(sipe_private,
					      action_name,
					      NULL,
					      SIPE_IDLE_SET_DELAY,
					      send_presence_status,
					      NULL);
			g_free(action_name);
		}
	}
}

void
sipe_set_idle(PurpleConnection * gc,
	      int interval)
{
	SIPE_DEBUG_INFO("sipe_set_idle: interval=%d", interval);

	if (gc) {
		struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;
		struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

		if (sip) {
			sip->idle_switch = time(NULL);
			SIPE_DEBUG_INFO("sipe_set_idle: sip->idle_switch : %s", asctime(localtime(&(sip->idle_switch))));
		}
	}
}

const gchar *sipe_get_buddy_status(struct sipe_core_private *sipe_private,
				   const gchar *uri)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	PurpleBuddy *pbuddy = purple_find_buddy((PurpleAccount *)sip->account, uri);
	const PurplePresence *presence = purple_buddy_get_presence(pbuddy);
	const PurpleStatus *pstatus = purple_presence_get_active_status(presence);
	return(purple_status_get_id(pstatus));
}

void sipe_buddy_status_from_activity(struct sipe_core_private *sipe_private,
				     const gchar *uri,
				     const gchar *activity,
				     gboolean is_online)
{
	if (is_online) {
		const gchar *status_id = NULL;
		if (activity) {
			if (sipe_strequal(activity, sipe_activity_to_token(SIPE_ACTIVITY_BUSY))) {
				status_id = SIPE_STATUS_ID_BUSY;
			} else if (sipe_strequal(activity, sipe_activity_to_token(SIPE_ACTIVITY_AWAY))) {
				status_id = SIPE_STATUS_ID_AWAY;
			}
		}

		if (!status_id) {
			status_id = SIPE_STATUS_ID_AVAILABLE;
		}

		SIPE_DEBUG_INFO("sipe_buddy_status_from_activity: status_id(%s)", status_id);
		sipe_core_buddy_got_status(SIPE_CORE_PUBLIC, uri, status_id);
	} else {
		sipe_core_buddy_got_status(SIPE_CORE_PUBLIC, uri, SIPE_STATUS_ID_OFFLINE);
	}
}

void sipe_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
	SIPE_DEBUG_INFO("sipe_add_buddy[CB]: buddy:%s group:%s", buddy ? buddy->name : "", group ? group->name : "");

	/* libpurple can call us with undefined buddy or group */
	if (buddy && group) {
		struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;

		/* Buddy name must be lower case as we use purple_normalize_nocase() to compare */
		gchar *buddy_name = g_ascii_strdown(buddy->name, -1);
		purple_blist_rename_buddy(buddy, buddy_name);
		g_free(buddy_name);

		/* Prepend sip: if needed */
		if (!g_str_has_prefix(buddy->name, "sip:")) {
			gchar *buf = sip_uri_from_name(buddy->name);
			purple_blist_rename_buddy(buddy, buf);
			g_free(buf);
		}

		if (!g_hash_table_lookup(sipe_private->buddies, buddy->name)) {
			struct sipe_buddy *b = g_new0(struct sipe_buddy, 1);
			SIPE_DEBUG_INFO("sipe_add_buddy: adding %s", buddy->name);
			b->name = g_strdup(buddy->name);
			b->just_added = TRUE;
			g_hash_table_insert(sipe_private->buddies, b->name, b);
			/* @TODO should go to callback */
			sipe_subscribe_presence_single(sipe_private,
						       b->name);
		} else {
			SIPE_DEBUG_INFO("sipe_add_buddy: buddy %s already in internal list", buddy->name);
		}

		sipe_core_buddy_group(PURPLE_GC_TO_SIPE_CORE_PUBLIC, buddy->name, NULL, group->name);
	}
}

/**
 * Tries to figure out user first and last name
 * based on Display Name and email properties.
 *
 * Allocates memory - must be g_free()'d
 *
 * Examples to parse:
 *  First Last
 *  First Last - Company Name
 *  Last, First
 *  Last, First M.
 *  Last, First (C)(STP) (Company)
 *  first.last@company.com		(preprocessed as "first last")
 *  first.last.company.com@reuters.net	(preprocessed as "first last company com")
 *
 * Unusable examples:
 *  user@company.com			(preprocessed as "user")
 *  first.m.last@company.com		(preprocessed as "first m last")
 *  user.company.com@reuters.net	(preprocessed as "user company com")
 */
static void
sipe_get_first_last_names(struct sipe_core_private *sipe_private,
			  const char *uri,
			  char **first_name,
			  char **last_name)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	sipe_backend_buddy p_buddy;
	char *display_name;
	gchar *email;
	const char *first, *last;
	char *tmp;
	char **parts;
	gboolean has_comma = FALSE;

	if (!sip || !uri) return;

	p_buddy = sipe_backend_buddy_find(SIPE_CORE_PUBLIC, uri, NULL);

	if (!p_buddy) return;

	display_name = sipe_backend_buddy_get_alias(SIPE_CORE_PUBLIC, p_buddy);
	email = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC, p_buddy, SIPE_BUDDY_INFO_EMAIL);

	if (!display_name && !email) return;

	/* if no display name, make "first last anything_else" out of email */
	if (email && !display_name) {
		display_name = g_strndup(email, strstr(email, "@") - email);
		display_name = sipe_utils_str_replace((tmp = display_name), ".", " ");
		g_free(tmp);
	}

	if (display_name) {
		has_comma = (strstr(display_name, ",") != NULL);
		display_name = sipe_utils_str_replace((tmp = display_name), ", ", " ");
		g_free(tmp);
		display_name = sipe_utils_str_replace((tmp = display_name), ",", " ");
		g_free(tmp);
	}

	parts = g_strsplit(display_name, " ", 0);

	if (!parts[0] || !parts[1]) {
		g_free(email);
		g_free(display_name);
		g_strfreev(parts);
		return;
	}

	if (has_comma) {
		last  = parts[0];
		first = parts[1];
	} else {
		first = parts[0];
		last  = parts[1];
	}

	if (first_name) {
		*first_name = g_strstrip(g_strdup(first));
	}

	if (last_name) {
		*last_name = g_strstrip(g_strdup(last));
	}

	g_free(email);
	g_free(display_name);
	g_strfreev(parts);
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
void sipe_backend_account_status_and_note(struct sipe_core_private *sipe_private,
					  const gchar *status_id)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	PurpleAccount *account = sip->account;
	PurpleStatus *status = purple_account_get_active_status(account);
	const gchar *message = sip->note;
	time_t *do_not_publish = sip->do_not_publish;
	gboolean changed = TRUE;

	if (g_str_equal(status_id, purple_status_get_id(status)) &&
	    sipe_strequal(message, purple_status_get_attr_string(status, SIPE_STATUS_ATTR_ID_MESSAGE)))
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
		sipe_activity activity = sipe_get_activity_by_token(status_id);

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

		do_not_publish[activity] = time(NULL);
		SIPE_DEBUG_INFO("sipe_set_purple_account_status_and_note: do_not_publish[%s]=%d [now]",
				status_id, (int)do_not_publish[activity]);

		/* Set the status for each account */
		purple_savedstatus_activate(saved_status);
	}
}

/* IM Session (INVITE and MESSAGE methods) */

static gboolean
process_options_response(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private,
			 struct sipmsg *msg,
			 SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	gboolean ret = TRUE;

	if (msg->response != 200) {
		SIPE_DEBUG_INFO("process_options_response: OPTIONS response is %d", msg->response);
		return FALSE;
	}

	SIPE_DEBUG_INFO("process_options_response: body:\n%s", msg->body ? msg->body : "");

	return ret;
}

/**
 * Asks UA/proxy about its capabilities.
 */
static void sipe_options_request(struct sipe_core_private *sipe_private,
				 const char *who)
{
	gchar *to = sip_uri(who);
	gchar *contact = get_contact(sipe_private);
	gchar *request = g_strdup_printf(
		"Accept: application/sdp\r\n"
		"Contact: %s\r\n", contact);
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

void
sipe_convo_closed(PurpleConnection * gc, const char *who)
{
	struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;

	SIPE_DEBUG_INFO("conversation with %s closed", who);
	sipe_session_close(sipe_private,
			   sipe_session_find_im(sipe_private, who));
}

/**
 * Returns 2005-style activity and Availability.
 *
 * @param status Sipe statis id.
 */
void sipe_get_act_avail_by_status_2005(const char *status,
				       int *activity,
				       int *availability)
{
	int avail = 300; /* online */
	int act = 400;  /* Available */

	if (sipe_strequal(status, SIPE_STATUS_ID_AWAY)) {
		act = 100;
	//} else if (sipe_strequal(status, SIPE_STATUS_ID_LUNCH)) {
	//	act = 150;
	} else if (sipe_strequal(status, SIPE_STATUS_ID_BRB)) {
		act = 300;
	} else if (sipe_strequal(status, SIPE_STATUS_ID_AVAILABLE)) {
		act = 400;
	//} else if (sipe_strequal(status, SIPE_STATUS_ID_ON_PHONE)) {
	//	act = 500;
	} else if (sipe_strequal(status, SIPE_STATUS_ID_BUSY) ||
		   sipe_strequal(status, SIPE_STATUS_ID_DND)) {
		act = 600;
	} else if (sipe_strequal(status, SIPE_STATUS_ID_INVISIBLE) ||
		   sipe_strequal(status, SIPE_STATUS_ID_OFFLINE)) {
		avail = 0; /* offline */
		act = 100;
	} else {
		act = 400; /* Available */
	}

	if (activity) *activity = act;
	if (availability) *availability = avail;
}

/**
 * [MS-SIP] 2.2.1
 *
 * @param activity	2005 aggregated activity.    Ex.: 600
 * @param availablity	2005 aggregated availablity. Ex.: 300
 */
const gchar *
sipe_get_status_by_act_avail_2005(const int activity,
				  const int availablity,
				  char **activity_desc)
{
	const char *status_id = NULL;
	const char *act = NULL;

	if (activity < 150) {
		status_id = SIPE_STATUS_ID_AWAY;
	} else if (activity < 200) {
		//status_id = SIPE_STATUS_ID_LUNCH;
		status_id = SIPE_STATUS_ID_AWAY;
		act = sipe_activity_description(SIPE_ACTIVITY_LUNCH);
	} else if (activity < 300) {
		//status_id = SIPE_STATUS_ID_IDLE;
		status_id = SIPE_STATUS_ID_AWAY;
		act = sipe_activity_description(SIPE_ACTIVITY_INACTIVE);
	} else if (activity < 400) {
		status_id = SIPE_STATUS_ID_BRB;
	} else if (activity < 500) {
		status_id = SIPE_STATUS_ID_AVAILABLE;
	} else if (activity < 600) {
		//status_id = SIPE_STATUS_ID_ON_PHONE;
		status_id = SIPE_STATUS_ID_BUSY;
		act = sipe_activity_description(SIPE_ACTIVITY_ON_PHONE);
	} else if (activity < 700) {
		status_id = SIPE_STATUS_ID_BUSY;
	} else if (activity < 800) {
		status_id = SIPE_STATUS_ID_AWAY;
	} else {
		status_id = SIPE_STATUS_ID_AVAILABLE;
	}

	if (availablity < 100)
		status_id = SIPE_STATUS_ID_OFFLINE;

	if (activity_desc && act) {
		g_free(*activity_desc);
		*activity_desc = g_strdup(act);
	}

	return status_id;
}

/**
 * [MS-PRES] Table 3: Conversion of legacyInterop elements and attributes to MSRTC elements and attributes.
 */
const gchar *
sipe_get_status_by_availability(int avail,
				gchar **activity_desc)
{
	const char *status;
	const char *act = NULL;

	if (avail < 3000) {
		status = SIPE_STATUS_ID_OFFLINE;
	} else if (avail < 4500) {
		status = SIPE_STATUS_ID_AVAILABLE;
	} else if (avail < 6000) {
		//status = SIPE_STATUS_ID_IDLE;
		status = SIPE_STATUS_ID_AVAILABLE;
		act = sipe_activity_description(SIPE_ACTIVITY_INACTIVE);
	} else if (avail < 7500) {
		status = SIPE_STATUS_ID_BUSY;
	} else if (avail < 9000) {
		//status = SIPE_STATUS_ID_BUSYIDLE;
		status = SIPE_STATUS_ID_BUSY;
		act = sipe_activity_description(SIPE_ACTIVITY_BUSYIDLE);
	} else if (avail < 12000) {
		status = SIPE_STATUS_ID_DND;
	} else if (avail < 15000) {
		status = SIPE_STATUS_ID_BRB;
	} else if (avail < 18000) {
		status = SIPE_STATUS_ID_AWAY;
	} else {
		status = SIPE_STATUS_ID_OFFLINE;
	}

	if (activity_desc && act) {
		g_free(*activity_desc);
		*activity_desc = g_strdup(act);
	}

	return status;
}

/**
 * Returns 2007-style availability value
 *
 * @param sipe_status_id (in)
 * @param activity_token (out)	Must be g_free()'d after use if consumed.
 */
int
sipe_get_availability_by_status(const char* sipe_status_id, char** activity_token)
{
	int availability;
	sipe_activity activity = SIPE_ACTIVITY_UNSET;

	if (sipe_strequal(sipe_status_id, SIPE_STATUS_ID_AWAY)) {
		availability = 15500;
		if (!activity_token || !(*activity_token))	{
			activity = SIPE_ACTIVITY_AWAY;
		}
	} else if (sipe_strequal(sipe_status_id, SIPE_STATUS_ID_BRB)) {
		availability = 12500;
		activity = SIPE_ACTIVITY_BRB;
	} else if (sipe_strequal(sipe_status_id, SIPE_STATUS_ID_DND)) {
		availability =  9500;
		activity = SIPE_ACTIVITY_DND;
	} else if (sipe_strequal(sipe_status_id, SIPE_STATUS_ID_BUSY)) {
		availability =  6500;
		if (!activity_token || !(*activity_token))	{
			activity = SIPE_ACTIVITY_BUSY;
		}
	} else if (sipe_strequal(sipe_status_id, SIPE_STATUS_ID_AVAILABLE)) {
		availability =  3500;
		activity = SIPE_ACTIVITY_ONLINE;
	} else if (sipe_strequal(sipe_status_id, SIPE_STATUS_ID_UNKNOWN)) {
		availability =     0;
	} else {
		// Offline or invisible
		availability = 18500;
		activity = SIPE_ACTIVITY_OFFLINE;
	}

	if (activity_token) {
		*activity_token = g_strdup(sipe_activity_to_token(activity));
	}
	return availability;
}

/**
 * Whether user manually changed status or
 * it was changed automatically due to user
 * became inactive/active again
 */
gboolean
sipe_is_user_state(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	gboolean res;
	time_t now = time(NULL);

	SIPE_DEBUG_INFO("sipe_is_user_state: sip->idle_switch : %s", asctime(localtime(&(sip->idle_switch))));
	SIPE_DEBUG_INFO("sipe_is_user_state: now              : %s", asctime(localtime(&now)));

	res = ((now - SIPE_IDLE_SET_DELAY * 2) >= sip->idle_switch);

	SIPE_DEBUG_INFO("sipe_is_user_state: res  = %s", res ? "USER" : "MACHINE");
	return res;
}

gboolean sipe_is_user_available(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	return(sipe_strequal(sip->status, SIPE_STATUS_ID_AVAILABLE));
}

void send_presence_status(struct sipe_core_private *sipe_private,
			  SIPE_UNUSED_PARAMETER gpointer unused)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	PurpleStatus * status = purple_account_get_active_status(sip->account);

	if (!status) return;

	SIPE_DEBUG_INFO("send_presence_status: status: %s (%s)",
			purple_status_get_id(status) ? purple_status_get_id(status) : "",
			sipe_is_user_state(sipe_private) ? "USER" : "MACHINE");

	sipe_cal_presence_publish(sipe_private, FALSE);
}

/* temporary function */
void sipe_purple_setup(struct sipe_core_public *sipe_public,
		       PurpleConnection *gc)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA;
	sip->gc = gc;
	sip->account = purple_connection_get_account(gc);
}

static void
sipe_blist_menu_free_containers(struct sipe_core_private *sipe_private);

void sipe_connection_cleanup(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

	g_free(sipe_private->epid);
	sipe_private->epid = NULL;

	sip_transport_disconnect(sipe_private);

	sipe_schedule_cancel_all(sipe_private);

	if (sip->allow_events) {
		GSList *entry = sip->allow_events;
		while (entry) {
			g_free(entry->data);
			entry = entry->next;
		}
	}
	g_slist_free(sip->allow_events);

	sipe_ocs2007_free(sipe_private);

	/* libpurple memory leak workaround */
	sipe_blist_menu_free_containers(sipe_private);

	if (sipe_private->contact)
		g_free(sipe_private->contact);
	sipe_private->contact = NULL;
	if (sip->regcallid)
		g_free(sip->regcallid);
	sip->regcallid = NULL;

	if (sipe_private->focus_factory_uri)
		g_free(sipe_private->focus_factory_uri);
	sipe_private->focus_factory_uri = NULL;

	if (sip->cal) {
		sipe_cal_calendar_free(sip->cal);
	}
	sip->cal = NULL;

	sipe_groupchat_free(sipe_private);
}

void sipe_core_reset_status(struct sipe_core_public *sipe_public)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007))
		sipe_ocs2007_reset_status(sipe_private);
	else
		sipe_ocs2005_reset_status(sipe_private);
}

/** for Access levels menu */
#define INDENT_FMT			"  %s"

/** Member is indirectly belong to access level container.
 *  For example 'sameEnterprise' is in the container and user
 *  belongs to that same enterprise.
 */
#define INDENT_MARKED_INHERITED_FMT	"= %s"

static PurpleBuddy *
purple_blist_add_buddy_clone(PurpleGroup * group, PurpleBuddy * buddy)
{
	struct sipe_core_private *sipe_private = PURPLE_BUDDY_TO_SIPE_CORE_PRIVATE;
	PurpleBuddy *clone;
	gchar *server_alias, *email;
	const PurpleStatus *status = purple_presence_get_active_status(purple_buddy_get_presence(buddy));

	clone = sipe_backend_buddy_add(SIPE_CORE_PUBLIC,
				       buddy->name,
				       buddy->alias,
				       group->name);

	server_alias = sipe_backend_buddy_get_server_alias(SIPE_CORE_PUBLIC,
							   buddy);
	if (server_alias) {
		sipe_backend_buddy_set_server_alias(SIPE_CORE_PUBLIC,
						    clone,
						    server_alias);
		g_free(server_alias);
	}

	email = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC,
					      buddy,
					      SIPE_BUDDY_INFO_EMAIL);
	if (email) {
		sipe_backend_buddy_set_string(SIPE_CORE_PUBLIC,
					      clone,
					      SIPE_BUDDY_INFO_EMAIL,
					      email);
		g_free(email);
	}

	purple_presence_set_status_active(purple_buddy_get_presence(clone),
					  purple_status_get_id(status),
					  TRUE);
	/* for UI to update */
	sipe_backend_buddy_set_status(SIPE_CORE_PUBLIC,
				      buddy->name,
				      purple_status_get_id(status));

	return clone;
}

static void
sipe_buddy_menu_copy_to_cb(PurpleBlistNode *node, const char *group_name)
{
	PurpleBuddy *buddy, *b;
	PurpleConnection *gc;
	PurpleGroup * group = purple_find_group(group_name);

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy *)node;

	SIPE_DEBUG_INFO("sipe_buddy_menu_copy_to_cb: copying %s to %s", buddy->name, group_name);
	gc = purple_account_get_connection(buddy->account);

	b = purple_find_buddy_in_group(buddy->account, buddy->name, group);
	if (!b){
		b = purple_blist_add_buddy_clone(group, buddy);
	}

	sipe_add_buddy(gc, b, group);
}

static void
sipe_buddy_menu_chat_new_cb(PurpleBuddy *buddy)
{
	struct sipe_core_private *sipe_private = PURPLE_BUDDY_TO_SIPE_CORE_PRIVATE;

	SIPE_DEBUG_INFO("sipe_buddy_menu_chat_new_cb: buddy->name=%s", buddy->name);

	/* 2007+ conference */
	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007))
	{
		sipe_conf_add(sipe_private, buddy->name);
	}
	else /* 2005- multiparty chat */
	{
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

		sipe_im_invite(sipe_private, session, buddy->name, NULL, NULL, NULL, FALSE);
	}
}

/**
 * For 2007+ conference only.
 */
static void
sipe_buddy_menu_chat_make_leader_cb(PurpleBuddy *buddy,
				    struct sipe_chat_session *chat_session)
{
	struct sipe_core_private *sipe_private = PURPLE_BUDDY_TO_SIPE_CORE_PRIVATE;
	struct sip_session *session;

	SIPE_DEBUG_INFO("sipe_buddy_menu_chat_make_leader_cb: buddy->name=%s", buddy->name);
	SIPE_DEBUG_INFO("sipe_buddy_menu_chat_make_leader_cb: chat_title=%s", chat_session->title);

	session = sipe_session_find_chat(sipe_private, chat_session);

	sipe_conf_modify_user_role(sipe_private, session, buddy->name);
}

/**
 * For 2007+ conference only.
 */
static void
sipe_buddy_menu_chat_remove_cb(PurpleBuddy *buddy,
			       struct sipe_chat_session *chat_session)
{
	struct sipe_core_private *sipe_private = PURPLE_BUDDY_TO_SIPE_CORE_PRIVATE;
	struct sip_session *session;

	SIPE_DEBUG_INFO("sipe_buddy_menu_chat_remove_cb: buddy->name=%s", buddy->name);
	SIPE_DEBUG_INFO("sipe_buddy_menu_chat_remove_cb: chat_title=%s", chat_session->title);

	session = sipe_session_find_chat(sipe_private, chat_session);

	sipe_conf_delete_user(sipe_private, session, buddy->name);
}

static void
sipe_buddy_menu_chat_invite_cb(PurpleBuddy *buddy,
			       struct sipe_chat_session *chat_session)
{
	struct sipe_core_private *sipe_private = PURPLE_BUDDY_TO_SIPE_CORE_PRIVATE;

	SIPE_DEBUG_INFO("sipe_buddy_menu_chat_invite_cb: buddy->name=%s", buddy->name);
	SIPE_DEBUG_INFO("sipe_buddy_menu_chat_invite_cb: chat_title=%s", chat_session->title);

	sipe_core_chat_invite(SIPE_CORE_PUBLIC, chat_session, buddy->name);
}

static void
sipe_buddy_menu_make_call_cb(PurpleBuddy *buddy, const char *phone)
{
	struct sipe_core_private *sipe_private = PURPLE_BUDDY_TO_SIPE_CORE_PRIVATE;

	SIPE_DEBUG_INFO("sipe_buddy_menu_make_call_cb: buddy->name=%s", buddy->name);
	if (phone) {
		char *tel_uri = sip_to_tel_uri(phone);

		SIPE_DEBUG_INFO("sipe_buddy_menu_make_call_cb: going to call number: %s", tel_uri ? tel_uri : "");
		sip_csta_make_call(sipe_private, tel_uri);

		g_free(tel_uri);
	}
}

static void
sipe_buddy_menu_access_level_help_cb(PurpleBuddy *buddy)
{
	/** Translators: replace with URL to localized page
	 * If it doesn't exist copy the original URL */
	purple_notify_uri(buddy->account->gc, _("https://sourceforge.net/apps/mediawiki/sipe/index.php?title=Access_Levels"));
}

static void
sipe_buddy_menu_send_email_cb(PurpleBuddy *buddy)
{
	struct sipe_core_private *sipe_private = PURPLE_BUDDY_TO_SIPE_CORE_PRIVATE;
	gchar *email;
	SIPE_DEBUG_INFO("sipe_buddy_menu_send_email_cb: buddy->name=%s", buddy->name);

	email = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC,
					      buddy,
					      SIPE_BUDDY_INFO_EMAIL);
	if (email)
	{
		char *command_line = g_strdup_printf(
#ifdef _WIN32
			"cmd /c start"
#else
			"xdg-email"
#endif
			" mailto:%s", email);
		SIPE_DEBUG_INFO("sipe_buddy_menu_send_email_cb: going to call email client: %s", command_line);

		g_free(email);
		g_spawn_command_line_async(command_line, NULL);
		g_free(command_line);
	}
	else
	{
		SIPE_DEBUG_INFO("sipe_buddy_menu_send_email_cb: no email address stored for buddy=%s", buddy->name);
	}
}

static void
sipe_buddy_menu_access_level_cb(PurpleBuddy *buddy,
				struct sipe_container *container)
{
	struct sipe_core_private *sipe_private = PURPLE_BUDDY_TO_SIPE_CORE_PRIVATE;
	sipe_ocs2007_change_access_level_from_container(sipe_private,
							container);
}

static GList *
sipe_get_access_control_menu(struct sipe_core_private *sipe_private,
			     const char* uri);

/*
 * A menu which appear when right-clicking on buddy in contact list.
 */
GList *
sipe_buddy_menu(PurpleBuddy *buddy)
{
	PurpleBlistNode *g_node;
	PurpleGroup *gr_parent;
	PurpleMenuAction *act;
	GList *menu = NULL;
	GList *menu_groups = NULL;
	struct sipe_core_private *sipe_private = PURPLE_BUDDY_TO_SIPE_CORE_PRIVATE;
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	gchar *email;
	gchar *self = sip_uri_self(sipe_private);

	SIPE_SESSION_FOREACH {
		if (!sipe_strcase_equal(self, buddy->name) && session->chat_session)
		{
			struct sipe_chat_session *chat_session = session->chat_session;
			gboolean is_conf = (chat_session->type == SIPE_CHAT_TYPE_CONFERENCE);

			if (sipe_backend_chat_find(chat_session->backend, buddy->name))
			{
				gboolean conf_op = sipe_backend_chat_is_operator(chat_session->backend, self);

				if (is_conf
				    && !sipe_backend_chat_is_operator(chat_session->backend, buddy->name) /* Not conf OP */
				    &&  conf_op)                                                          /* We are a conf OP */
				{
					gchar *label = g_strdup_printf(_("Make leader of '%s'"),
								       chat_session->title);
					act = purple_menu_action_new(label,
								     PURPLE_CALLBACK(sipe_buddy_menu_chat_make_leader_cb),
								     chat_session, NULL);
					g_free(label);
					menu = g_list_prepend(menu, act);
				}

				if (is_conf
				    && conf_op) /* We are a conf OP */
				{
					gchar *label = g_strdup_printf(_("Remove from '%s'"),
								       chat_session->title);
					act = purple_menu_action_new(label,
								     PURPLE_CALLBACK(sipe_buddy_menu_chat_remove_cb),
								     chat_session, NULL);
					g_free(label);
					menu = g_list_prepend(menu, act);
				}
			}
			else
			{
				if (!is_conf
				    || (is_conf && !session->locked))
				{
					gchar *label = g_strdup_printf(_("Invite to '%s'"),
								       chat_session->title);
					act = purple_menu_action_new(label,
								     PURPLE_CALLBACK(sipe_buddy_menu_chat_invite_cb),
								     chat_session, NULL);
					g_free(label);
					menu = g_list_prepend(menu, act);
				}
			}
		}
	} SIPE_SESSION_FOREACH_END;

	act = purple_menu_action_new(_("New chat"),
				     PURPLE_CALLBACK(sipe_buddy_menu_chat_new_cb),
				     NULL, NULL);
	menu = g_list_prepend(menu, act);

	if (sip->csta && !sip->csta->line_status) {
		gchar *phone;
		gchar *phone_disp_str;
		gchar *tmp = NULL;
		/* work phone */
		phone = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC,
						      buddy,
						      SIPE_BUDDY_INFO_WORK_PHONE);
		phone_disp_str = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC,
							       buddy,
							       SIPE_BUDDY_INFO_WORK_PHONE_DISPLAY);
		if (phone) {
			gchar *label = g_strdup_printf(_("Work %s"),
				phone_disp_str ? phone_disp_str : (tmp = sip_tel_uri_denormalize(phone)));
			act = purple_menu_action_new(label, PURPLE_CALLBACK(sipe_buddy_menu_make_call_cb), (gpointer) phone, NULL);
			g_free(tmp);
			tmp = NULL;
			g_free(label);
			menu = g_list_prepend(menu, act);
			g_free(phone);
		}
		g_free(phone_disp_str);

		/* mobile phone */
		phone = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC,
						      buddy,
						      SIPE_BUDDY_INFO_MOBILE_PHONE);
		phone_disp_str = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC,
							       buddy,
							       SIPE_BUDDY_INFO_MOBILE_PHONE_DISPLAY);
		if (phone) {
			gchar *label = g_strdup_printf(_("Mobile %s"),
				phone_disp_str ? phone_disp_str : (tmp = sip_tel_uri_denormalize(phone)));
			act = purple_menu_action_new(label, PURPLE_CALLBACK(sipe_buddy_menu_make_call_cb), (gpointer) phone, NULL);
			g_free(tmp);
			tmp = NULL;
			g_free(label);
			menu = g_list_prepend(menu, act);
			g_free(phone);
		}
		g_free(phone_disp_str);

		/* home phone */
		phone = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC,
						      buddy,
						      SIPE_BUDDY_INFO_HOME_PHONE);
		phone_disp_str = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC,
							       buddy,
							       SIPE_BUDDY_INFO_HOME_PHONE_DISPLAY);
		if (phone) {
			gchar *label = g_strdup_printf(_("Home %s"),
				phone_disp_str ? phone_disp_str : (tmp = sip_tel_uri_denormalize(phone)));
			act = purple_menu_action_new(label, PURPLE_CALLBACK(sipe_buddy_menu_make_call_cb), (gpointer) phone, NULL);
			g_free(tmp);
			tmp = NULL;
			g_free(label);
			menu = g_list_prepend(menu, act);
			g_free(phone);
		}
		g_free(phone_disp_str);

		/* other phone */
		phone = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC,
						      buddy,
						      SIPE_BUDDY_INFO_OTHER_PHONE);
		phone_disp_str = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC,
							       buddy,
							       SIPE_BUDDY_INFO_OTHER_PHONE_DISPLAY);
		if (phone) {
			gchar *label = g_strdup_printf(_("Other %s"),
				phone_disp_str ? phone_disp_str : (tmp = sip_tel_uri_denormalize(phone)));
			act = purple_menu_action_new(label, PURPLE_CALLBACK(sipe_buddy_menu_make_call_cb), (gpointer) phone, NULL);
			g_free(tmp);
			tmp = NULL;
			g_free(label);
			menu = g_list_prepend(menu, act);
			g_free(phone);
		}
		g_free(phone_disp_str);

		/* custom1 phone */
		phone = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC,
						      buddy,
						      SIPE_BUDDY_INFO_CUSTOM1_PHONE);
		phone_disp_str = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC,
							       buddy,
							       SIPE_BUDDY_INFO_CUSTOM1_PHONE_DISPLAY);
		if (phone) {
			gchar *label = g_strdup_printf(_("Custom1 %s"),
				phone_disp_str ? phone_disp_str : (tmp = sip_tel_uri_denormalize(phone)));
			act = purple_menu_action_new(label, PURPLE_CALLBACK(sipe_buddy_menu_make_call_cb), (gpointer) phone, NULL);
			g_free(tmp);
			tmp = NULL;
			g_free(label);
			menu = g_list_prepend(menu, act);
			g_free(phone);
		}
		g_free(phone_disp_str);
	}

	email = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC,
					      buddy,
					      SIPE_BUDDY_INFO_EMAIL);
	if (email) {
		act = purple_menu_action_new(_("Send email..."),
					     PURPLE_CALLBACK(sipe_buddy_menu_send_email_cb),
					     NULL, NULL);
		menu = g_list_prepend(menu, act);
		g_free(email);
	}

	/* Access Level */
	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		GList *menu_access_levels = sipe_get_access_control_menu(sipe_private, buddy->name);

		act = purple_menu_action_new(_("Access level"),
					     NULL,
					     NULL, menu_access_levels);
		menu = g_list_prepend(menu, act);
	}

	/* Copy to */
	gr_parent = purple_buddy_get_group(buddy);
	for (g_node = purple_blist_get_root(); g_node; g_node = g_node->next) {
		PurpleGroup *group;

		if (g_node->type != PURPLE_BLIST_GROUP_NODE)
			continue;

		group = (PurpleGroup *)g_node;
		if (group == gr_parent)
			continue;

		if (purple_find_buddy_in_group(buddy->account, buddy->name, group))
			continue;

		act = purple_menu_action_new(purple_group_get_name(group),
							   PURPLE_CALLBACK(sipe_buddy_menu_copy_to_cb),
							   group->name, NULL);
		menu_groups = g_list_prepend(menu_groups, act);
	}
	/* Coverity complains about RESOURCE_LEAK here - no idea how to fix it */
	menu_groups = g_list_reverse(menu_groups);

	act = purple_menu_action_new(_("Copy to"),
				     NULL,
				     NULL, menu_groups);
	menu = g_list_prepend(menu, act);

	menu = g_list_reverse(menu);

	g_free(self);
	return menu;
}

static void
sipe_ask_access_domain_cb(PurpleConnection *gc, PurpleRequestFields *fields)
{
	struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;
	const char *domain = purple_request_fields_get_string(fields, "access_domain");
	guint index = purple_request_fields_get_choice(fields, "container_id");
	sipe_ocs2007_change_access_level_for_domain(sipe_private,
						    domain,
						    index);
}

static void
sipe_ask_access_domain(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	PurpleAccount *account = sip->account;
	PurpleConnection *gc = sip->gc;
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *g;
	PurpleRequestField *f;

	fields = purple_request_fields_new();

	g = purple_request_field_group_new(NULL);
	f = purple_request_field_string_new("access_domain", _("Domain"), "partner-company.com", FALSE);
	purple_request_field_set_required(f, TRUE);
	purple_request_field_group_add_field(g, f);

	f = purple_request_field_choice_new("container_id", _("Access level"), 0);
	purple_request_field_choice_add(f, _("Personal")); /* index 0 */
	purple_request_field_choice_add(f, _("Team"));
	purple_request_field_choice_add(f, _("Company"));
	purple_request_field_choice_add(f, _("Public"));
	purple_request_field_choice_add(f, _("Blocked")); /* index 4 */
	purple_request_field_choice_set_default_value(f, 3); /* index */
	purple_request_field_set_required(f, TRUE);
	purple_request_field_group_add_field(g, f);

	purple_request_fields_add_group(fields, g);

	purple_request_fields(gc, _("Add new domain"),
			      _("Add new domain"), NULL, fields,
			      _("Add"), G_CALLBACK(sipe_ask_access_domain_cb),
			      _("Cancel"), NULL,
			      account, NULL, NULL, gc);
}

static void
sipe_buddy_menu_access_level_add_domain_cb(PurpleBuddy *buddy)
{
	sipe_ask_access_domain(PURPLE_BUDDY_TO_SIPE_CORE_PRIVATE);
}

/*
 * Workaround for missing libpurple API to release resources allocated
 * during blist_node_menu() callback. See also:
 *
 *   <http://developer.pidgin.im/ticket/12597>
 *
 * We remember all memory blocks in a list and deallocate them when
 *
 *   - the next time we enter the callback, or
 *   - the account is disconnected
 *
 * That means that after the buddy menu has been closed we have unused
 * resources but at least we don't leak them anymore...
 */
static void
sipe_blist_menu_free_containers(struct sipe_core_private *sipe_private)
{
	GSList *entry = sipe_private->blist_menu_containers;
	while (entry) {
		sipe_ocs2007_free_container(entry->data);
		entry = entry->next;
	}
	g_slist_free(sipe_private->blist_menu_containers);
	sipe_private->blist_menu_containers = NULL;
}

static void
sipe_blist_menu_remember_container(struct sipe_core_private *sipe_private,
				   struct sipe_container *container)
{
	sipe_private->blist_menu_containers = g_slist_prepend(sipe_private->blist_menu_containers,
							      container);
}

static GList *
sipe_get_access_levels_menu(struct sipe_core_private *sipe_private,
			    const char* member_type,
			    const char* member_value,
			    const gboolean extra_menu)
{
	GList *menu_access_levels = NULL;
	unsigned int i;
	char *menu_name;
	PurpleMenuAction *act;
	struct sipe_container *container;
	gboolean is_group_access = FALSE;
	int container_id = sipe_ocs2007_find_access_level(sipe_private,
							  member_type,
							  member_value,
							  &is_group_access);
	guint container_max = sipe_ocs2007_containers();

	for (i = 1; i <= container_max; i++) {
		/* to put Blocked level last in menu list.
		 * Blocked should remaim in the first place in the containers[] array.
		 */
		unsigned int j = (i == container_max) ? 0 : i;
		int container_j = sipe_ocs2007_container_id(j);
		const gchar *acc_level_name = sipe_ocs2007_access_level_name(container_j);

		container = sipe_ocs2007_create_container(j,
							  member_type,
							  member_value,
							  FALSE);

		/* libpurple memory leak workaround */
		sipe_blist_menu_remember_container(sipe_private, container);

		/* current container/access level */
		if (container_j == container_id) {
			menu_name = is_group_access ?
				g_strdup_printf(INDENT_MARKED_INHERITED_FMT, acc_level_name) :
				g_strdup_printf(SIPE_OCS2007_INDENT_MARKED_FMT, acc_level_name);
		} else {
			menu_name = g_strdup_printf(INDENT_FMT, acc_level_name);
		}

		act = purple_menu_action_new(menu_name,
					     PURPLE_CALLBACK(sipe_buddy_menu_access_level_cb),
					     container, NULL);
		g_free(menu_name);
		menu_access_levels = g_list_prepend(menu_access_levels, act);
	}

	if (extra_menu && (container_id >= 0)) {
		/* separator */
		act = purple_menu_action_new("  --------------", NULL, NULL, NULL);
		menu_access_levels = g_list_prepend(menu_access_levels, act);

		if (!is_group_access) {
			container = sipe_ocs2007_create_container(0,
								  member_type,
								  member_value,
								  TRUE);

			/* libpurple memory leak workaround */
			sipe_blist_menu_remember_container(sipe_private, container);

			/* Translators: remove (clear) previously assigned access level */
			menu_name = g_strdup_printf(INDENT_FMT, _("Unspecify"));
			act = purple_menu_action_new(menu_name,
						     PURPLE_CALLBACK(sipe_buddy_menu_access_level_cb),
						     container, NULL);
			g_free(menu_name);
			menu_access_levels = g_list_prepend(menu_access_levels, act);
		}
	}

	menu_access_levels = g_list_reverse(menu_access_levels);
	return menu_access_levels;
}

static GList *
sipe_get_access_groups_menu(struct sipe_core_private *sipe_private)
{
	GList *menu_access_groups = NULL;
	PurpleMenuAction *act;
	GSList *access_domains;
	GSList *entry;

	act = purple_menu_action_new(_("People in my company"),
				     NULL,
				     NULL, sipe_get_access_levels_menu(sipe_private, "sameEnterprise", NULL, FALSE));
	menu_access_groups = g_list_prepend(menu_access_groups, act);

	/* this is original name, don't edit */
	act = purple_menu_action_new(_("People in domains connected with my company"),
				     NULL,
				     NULL, sipe_get_access_levels_menu(sipe_private, "federated", NULL, FALSE));
	menu_access_groups = g_list_prepend(menu_access_groups, act);

	act = purple_menu_action_new(_("People in public domains"),
				     NULL,
				     NULL, sipe_get_access_levels_menu(sipe_private, "publicCloud", NULL, TRUE));
	menu_access_groups = g_list_prepend(menu_access_groups, act);

	access_domains = sipe_ocs2007_get_access_domains(sipe_private);
	entry = access_domains;
	while (entry) {
		gchar *domain    = entry->data;
		gchar *menu_name = g_strdup_printf(_("People at %s"), domain);

		/* takes over ownership of entry->data (= domain) */
		act = purple_menu_action_new(menu_name,
					     NULL,
					     NULL, sipe_get_access_levels_menu(sipe_private, "domain", domain, TRUE));
		menu_access_groups = g_list_prepend(menu_access_groups, act);
		g_free(menu_name);

		entry = entry->next;
	}
	g_slist_free(access_domains);

	/* separator */
	/*			      People in domains connected with my company		 */
	act = purple_menu_action_new("-------------------------------------------", NULL, NULL, NULL);
	menu_access_groups = g_list_prepend(menu_access_groups, act);

	act = purple_menu_action_new(_("Add new domain..."),
				     PURPLE_CALLBACK(sipe_buddy_menu_access_level_add_domain_cb),
				     NULL, NULL);
	menu_access_groups = g_list_prepend(menu_access_groups, act);

	menu_access_groups = g_list_reverse(menu_access_groups);

	return menu_access_groups;
}

static GList *
sipe_get_access_control_menu(struct sipe_core_private *sipe_private,
			     const char* uri)
{
	GList *menu_access_levels = NULL;
	GList *menu_access_groups = NULL;
	char *menu_name;
	PurpleMenuAction *act;

	/* libpurple memory leak workaround */
	sipe_blist_menu_free_containers(sipe_private);

	menu_access_levels = sipe_get_access_levels_menu(sipe_private, "user", sipe_get_no_sip_uri(uri), TRUE);

	menu_access_groups = sipe_get_access_groups_menu(sipe_private);

	menu_name = g_strdup_printf(INDENT_FMT, _("Access groups"));
	act = purple_menu_action_new(menu_name,
				     NULL,
				     NULL, menu_access_groups);
	g_free(menu_name);
	menu_access_levels = g_list_append(menu_access_levels, act);

	menu_name = g_strdup_printf(INDENT_FMT, _("Online help..."));
	act = purple_menu_action_new(menu_name,
				     PURPLE_CALLBACK(sipe_buddy_menu_access_level_help_cb),
				     NULL, NULL);
	g_free(menu_name);
	menu_access_levels = g_list_append(menu_access_levels, act);

	return menu_access_levels;
}

static gboolean
process_get_info_response(struct sipe_core_private *sipe_private,
			  struct sipmsg *msg, struct transaction *trans)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	char *uri = trans->payload->data;

	PurpleNotifyUserInfo *info;
	PurpleBuddy *pbuddy = NULL;
	struct sipe_buddy *sbuddy;
	const char *alias = NULL;
	char *device_name = NULL;
	char *server_alias = NULL;
	char *phone_number = NULL;
	char *email = NULL;
	char *site;
	char *first_name = NULL;
	char *last_name = NULL;

	if (!sip) return FALSE;

	SIPE_DEBUG_INFO("Fetching %s's user info for %s", uri, sipe_private->username);

	pbuddy = purple_find_buddy((PurpleAccount *)sip->account, uri);
	alias = purple_buddy_get_local_alias(pbuddy);

	//will query buddy UA's capabilities and send answer to log
	sipe_options_request(sipe_private, uri);

	sbuddy = g_hash_table_lookup(sipe_private->buddies, uri);
	if (sbuddy) {
		device_name = sbuddy->device_name ? g_strdup(sbuddy->device_name) : NULL;
	}

	info = purple_notify_user_info_new();

	if (msg->response != 200) {
		SIPE_DEBUG_INFO("process_get_info_response: SERVICE response is %d", msg->response);
	} else {
		sipe_xml *searchResults;
		const sipe_xml *mrow;

		SIPE_DEBUG_INFO("process_get_info_response: body:\n%s", msg->body ? msg->body : "");
		searchResults = sipe_xml_parse(msg->body, msg->bodylen);
		if (!searchResults) {
			SIPE_DEBUG_INFO_NOFORMAT("process_get_info_response: no parseable searchResults");
		} else if ((mrow = sipe_xml_child(searchResults, "Body/Array/row"))) {
			const char *value;
			server_alias = g_strdup(sipe_xml_attribute(mrow, "displayName"));
			email = g_strdup(sipe_xml_attribute(mrow, "email"));
			phone_number = g_strdup(sipe_xml_attribute(mrow, "phone"));

			/* For 2007 system we will take this from ContactCard -
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

#if PURPLE_VERSION_CHECK(3,0,0)
#define PURPLE_NOTIFY_USER_INFO_ADD_PAIR purple_notify_user_info_add_pair_html
#else
#define PURPLE_NOTIFY_USER_INFO_ADD_PAIR purple_notify_user_info_add_pair
#endif

			if (server_alias && strlen(server_alias) > 0) {
				PURPLE_NOTIFY_USER_INFO_ADD_PAIR(info, _("Display name"), server_alias);
			}
			if ((value = sipe_xml_attribute(mrow, "title")) && strlen(value) > 0) {
				PURPLE_NOTIFY_USER_INFO_ADD_PAIR(info, _("Job title"), value);
			}
			if ((value = sipe_xml_attribute(mrow, "office")) && strlen(value) > 0) {
				PURPLE_NOTIFY_USER_INFO_ADD_PAIR(info, _("Office"), value);
			}
			if (phone_number && strlen(phone_number) > 0) {
				PURPLE_NOTIFY_USER_INFO_ADD_PAIR(info, _("Business phone"), phone_number);
			}
			if ((value = sipe_xml_attribute(mrow, "company")) && strlen(value) > 0) {
				PURPLE_NOTIFY_USER_INFO_ADD_PAIR(info, _("Company"), value);
			}
			if ((value = sipe_xml_attribute(mrow, "city")) && strlen(value) > 0) {
				PURPLE_NOTIFY_USER_INFO_ADD_PAIR(info, _("City"), value);
			}
			if ((value = sipe_xml_attribute(mrow, "state")) && strlen(value) > 0) {
				PURPLE_NOTIFY_USER_INFO_ADD_PAIR(info, _("State"), value);
			}
			if ((value = sipe_xml_attribute(mrow, "country")) && strlen(value) > 0) {
				PURPLE_NOTIFY_USER_INFO_ADD_PAIR(info, _("Country"), value);
			}
			if (email && strlen(email) > 0) {
				PURPLE_NOTIFY_USER_INFO_ADD_PAIR(info, _("Email address"), email);
			}

		}
		sipe_xml_free(searchResults);
	}

	purple_notify_user_info_add_section_break(info);

	if (is_empty(server_alias)) {
		g_free(server_alias);
		server_alias = sipe_backend_buddy_get_server_alias(SIPE_CORE_PUBLIC,
								   pbuddy);
		if (server_alias) {
			PURPLE_NOTIFY_USER_INFO_ADD_PAIR(info, _("Display name"), server_alias);
		}
	}

	/* present alias if it differs from server alias */
	if (alias && !sipe_strequal(alias, server_alias))
	{
		PURPLE_NOTIFY_USER_INFO_ADD_PAIR(info, _("Alias"), alias);
	}

	if (is_empty(email)) {
		g_free(email);
		email = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC,
						      pbuddy,
						      SIPE_BUDDY_INFO_EMAIL);
		if (email) {
			PURPLE_NOTIFY_USER_INFO_ADD_PAIR(info, _("Email address"), email);
		}
	}

	site = sipe_backend_buddy_get_string(SIPE_CORE_PUBLIC,
					     pbuddy,
					     SIPE_BUDDY_INFO_SITE);
	if (site) {
		PURPLE_NOTIFY_USER_INFO_ADD_PAIR(info, _("Site"), site);
		g_free(site);
	}

	sipe_get_first_last_names(sipe_private, uri, &first_name, &last_name);
	if (first_name && last_name) {
		char *link = g_strconcat("http://www.linkedin.com/pub/dir/", first_name, "/", last_name, NULL);

		PURPLE_NOTIFY_USER_INFO_ADD_PAIR(info, _("Find on LinkedIn"), link);
		g_free(link);
	}
	g_free(first_name);
	g_free(last_name);

	if (device_name) {
		PURPLE_NOTIFY_USER_INFO_ADD_PAIR(info, _("Device"), device_name);
	}

	/* show a buddy's user info in a nice dialog box */
	purple_notify_userinfo(sip->gc,   /* connection the buddy info came through */
			       uri,       /* buddy's URI */
			       info,      /* body */
			       NULL,      /* callback called when dialog closed */
			       NULL);     /* userdata for callback */

	g_free(phone_number);
	g_free(server_alias);
	g_free(email);
	g_free(device_name);

	return TRUE;
}

#define SIPE_SOAP_SEARCH_ROW "<m:row m:attrib=\"%s\" m:value=\"%s\"/>"

/**
 * AD search first, LDAP based
 */
void sipe_get_info(PurpleConnection *gc, const char *username)
{
	struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;
	char *row = g_markup_printf_escaped(SIPE_SOAP_SEARCH_ROW, "msRTCSIP-PrimaryUserAddress", username);
	struct transaction_payload *payload = g_new0(struct transaction_payload, 1);

	payload->destroy = g_free;
	payload->data = g_strdup(username);

	SIPE_DEBUG_INFO("sipe_get_info: row: %s", row ? row : "");
	sip_soap_directory_search(sipe_private,
				  1,
				  row,
				  process_get_info_response,
				  payload);
	g_free(row);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
