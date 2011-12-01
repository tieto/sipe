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
#include "sipe-group.h"
#include "sipe-dialog.h"
#include "sipe-ews.h"
#include "sipe-groupchat.h"
#include "sipe-im.h"
#include "sipe-nls.h"
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
		if (sipe_strequal(token, sipe_activity_map[i].token))
			return sipe_activity_map[i].type;
	}

	return sipe_activity_map[0].type;
}

static const char *
sipe_get_activity_desc_by_token(const char *token)
{
	if (!token) return NULL;

	return SIPE_ACTIVITY_I18N(sipe_get_activity_by_token(token));
}

/**
 * Returns pointer to URI without sip: prefix if any
 *
 * @param sip_uri SIP URI possibly with sip: prefix. Example: sip:first.last@hq.company.com
 * @return pointer to URL without sip: prefix. Coresponding example: first.last@hq.company.com
 *
 * Doesn't allocate memory
 */
const gchar *
sipe_get_no_sip_uri(const gchar *sip_uri)
{
	const char *prefix = "sip:";
	if (!sip_uri) return NULL;

	if (g_str_has_prefix(sip_uri, prefix)) {
		return (sip_uri+strlen(prefix));
	} else {
		return sip_uri;
	}
}

void
sipe_core_contact_allow_deny (struct sipe_core_public *sipe_public,
			      const gchar * who, gboolean allow)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;

	if (allow) {
		SIPE_DEBUG_INFO("Authorizing contact %s", who);
	} else {
		SIPE_DEBUG_INFO("Blocking contact %s", who);
	}

	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		sipe_ocs2007_change_access_level(sipe_private,
						 (allow ? -1 : 32000),
						 "user",
						 sipe_get_no_sip_uri(who));
	} else {
		sip_soap_ocs2005_setacl(sipe_private, who, allow);
	}
}

static void
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
			sbuddy->activity = g_strdup(SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_IN_MEETING));
		}
		avail = sipe_get_availability_by_status(status_id, NULL);

		SIPE_DEBUG_INFO("sipe_apply_calendar_status: activity_since  : %s", asctime(localtime(&sbuddy->activity_since)));
		if (cal_avail_since > sbuddy->activity_since) {
			if (cal_status == SIPE_CAL_OOF
			    && avail >= 15000) /* 12000 in 2007 */
			{
				g_free(sbuddy->activity);
				sbuddy->activity = g_strdup(SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_OOF));
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

static void
update_calendar_status_cb(SIPE_UNUSED_PARAMETER char *name,
			  struct sipe_buddy *sbuddy,
			  struct sipe_core_private *sipe_private)
{
	sipe_apply_calendar_status(sipe_private, sbuddy, NULL);
}

/**
 * Updates contact's status
 * based on their calendar information.
 *
 * Applicability: 2005 systems
 */
static void
update_calendar_status(struct sipe_core_private *sipe_private,
	               SIPE_UNUSED_PARAMETER void *unused)
{
	SIPE_DEBUG_INFO_NOFORMAT("update_calendar_status() started.");
	g_hash_table_foreach(sipe_private->buddies, (GHFunc)update_calendar_status_cb, sipe_private);

	/* repeat scheduling */
	sipe_sched_calendar_status_update(sipe_private, time(NULL) + 3*60 /* 3 min */);
}

/**
 * Schedules process of contacts' status update
 * based on their calendar information.
 * Should be scheduled to the beginning of every
 * 15 min interval, like:
 * 13:00, 13:15, 13:30, 13:45, etc.
 *
 * Applicability: 2005 systems
 */
void
sipe_sched_calendar_status_update(struct sipe_core_private *sipe_private,
				  time_t calculate_from)
{
	int interval = 15*60;
	/** start of the beginning of closest 15 min interval. */
	time_t next_start = ((time_t)((int)((int)calculate_from)/interval + 1)*interval);

	SIPE_DEBUG_INFO("sipe_sched_calendar_status_update: calculate_from time: %s",
			asctime(localtime(&calculate_from)));
	SIPE_DEBUG_INFO("sipe_sched_calendar_status_update: next start time    : %s",
			asctime(localtime(&next_start)));

	sipe_schedule_seconds(sipe_private,
			      "<+2005-cal-status>",
			      NULL,
			      next_start - time(NULL),
			      update_calendar_status,
			      NULL);
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

static void sipe_free_buddy(struct sipe_buddy *buddy)
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

/**
  * Unassociates buddy from group first.
  * Then see if no groups left, removes buddy completely.
  * Otherwise updates buddy groups on server.
  */
void sipe_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
	struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;
	struct sipe_buddy *b;
	struct sipe_group *g = NULL;

	SIPE_DEBUG_INFO("sipe_remove_buddy[CB]: buddy:%s group:%s", buddy ? buddy->name : "", group ? group->name : "");
	if (!buddy) return;

	b = g_hash_table_lookup(sipe_private->buddies, buddy->name);
	if (!b) return;

	if (group) {
		g = sipe_group_find_by_name(sipe_private, group->name);
	}

	if (g) {
		b->groups = g_slist_remove(b->groups, g);
		SIPE_DEBUG_INFO("buddy %s removed from group %s", buddy->name, g->name);
	}

	if (g_slist_length(b->groups) < 1) {
		gchar *action_name = sipe_utils_presence_key(buddy->name);
		sipe_schedule_cancel(sipe_private, action_name);
		g_free(action_name);

		g_hash_table_remove(sipe_private->buddies, buddy->name);

		if (b->name) {
			gchar *request = g_strdup_printf("<m:URI>%s</m:URI>",
							 b->name);
			sip_soap_request(sipe_private,
					 "deleteContact",
					 request);
			g_free(request);
		}

		sipe_free_buddy(b);
	} else {
		//updates groups on server
		sipe_core_group_set_user(SIPE_CORE_PUBLIC, b->name);
	}

}

/** Property names to store in blist.xml */
#define ALIAS_PROP			"alias"
#define EMAIL_PROP			"email"
#define PHONE_PROP			"phone"
#define PHONE_DISPLAY_PROP		"phone-display"
#define PHONE_MOBILE_PROP		"phone-mobile"
#define PHONE_MOBILE_DISPLAY_PROP	"phone-mobile-display"
#define PHONE_HOME_PROP			"phone-home"
#define PHONE_HOME_DISPLAY_PROP		"phone-home-display"
#define PHONE_OTHER_PROP		"phone-other"
#define PHONE_OTHER_DISPLAY_PROP	"phone-other-display"
#define PHONE_CUSTOM1_PROP		"phone-custom1"
#define PHONE_CUSTOM1_DISPLAY_PROP	"phone-custom1-display"
#define SITE_PROP			"site"
#define COMPANY_PROP			"company"
#define DEPARTMENT_PROP			"department"
#define TITLE_PROP			"title"
#define OFFICE_PROP			"office"
/** implies work address */
#define ADDRESS_STREET_PROP		"address-street"
#define ADDRESS_CITY_PROP		"address-city"
#define ADDRESS_STATE_PROP		"address-state"
#define ADDRESS_ZIPCODE_PROP		"address-zipcode"
#define ADDRESS_COUNTRYCODE_PROP	"address-country-code"

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
 * Update user information
 *
 * @param uri             buddy SIP URI with 'sip:' prefix whose info we want to change.
 * @param property_name
 * @param property_value  may be modified to strip white space
 */
void sipe_update_user_info(struct sipe_core_private *sipe_private,
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

/**
 * Update user phone
 * Suitable for both 2005 and 2007 systems.
 *
 * @param uri                   buddy SIP URI with 'sip:' prefix whose info we want to change.
 * @param phone_type
 * @param phone                 may be modified to strip white space
 * @param phone_display_string  may be modified to strip white space
 */
static void
sipe_update_user_phone(struct sipe_core_private *sipe_private,
		       const gchar *uri,
		       const gchar *phone_type,
		       gchar *phone,
		       gchar *phone_display_string)
{
	sipe_buddy_info_fields phone_node = SIPE_BUDDY_INFO_WORK_PHONE; /* work phone by default */
	sipe_buddy_info_fields phone_display_node = SIPE_BUDDY_INFO_WORK_PHONE_DISPLAY; /* work phone by default */

	if(!phone || strlen(phone) == 0) return;

	if ((sipe_strequal(phone_type, "mobile") ||  sipe_strequal(phone_type, "cell"))) {
		phone_node = SIPE_BUDDY_INFO_MOBILE_PHONE;
		phone_display_node = SIPE_BUDDY_INFO_MOBILE_PHONE_DISPLAY;
	} else if (sipe_strequal(phone_type, "home")) {
		phone_node = SIPE_BUDDY_INFO_HOME_PHONE;
		phone_display_node = SIPE_BUDDY_INFO_HOME_PHONE_DISPLAY;
	} else if (sipe_strequal(phone_type, "other")) {
		phone_node = SIPE_BUDDY_INFO_OTHER_PHONE;
		phone_display_node = SIPE_BUDDY_INFO_OTHER_PHONE_DISPLAY;
	} else if (sipe_strequal(phone_type, "custom1")) {
		phone_node = SIPE_BUDDY_INFO_CUSTOM1_PHONE;
		phone_display_node = SIPE_BUDDY_INFO_CUSTOM1_PHONE_DISPLAY;
	}

	sipe_update_user_info(sipe_private, uri, phone_node, phone);
	if (phone_display_string) {
		sipe_update_user_info(sipe_private, uri, phone_display_node, phone_display_string);
	}
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
static void
sipe_get_act_avail_by_status_2005(const char *status,
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
static const char *
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
		act = SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_LUNCH);
	} else if (activity < 300) {
		//status_id = SIPE_STATUS_ID_IDLE;
		status_id = SIPE_STATUS_ID_AWAY;
		act = SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_INACTIVE);
	} else if (activity < 400) {
		status_id = SIPE_STATUS_ID_BRB;
	} else if (activity < 500) {
		status_id = SIPE_STATUS_ID_AVAILABLE;
	} else if (activity < 600) {
		//status_id = SIPE_STATUS_ID_ON_PHONE;
		status_id = SIPE_STATUS_ID_BUSY;
		act = SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_ON_PHONE);
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
		act = SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_INACTIVE);
	} else if (avail < 7500) {
		status = SIPE_STATUS_ID_BUSY;
	} else if (avail < 9000) {
		//status = SIPE_STATUS_ID_BUSYIDLE;
		status = SIPE_STATUS_ID_BUSY;
		act = SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_BUSYIDLE);
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
		*activity_token = g_strdup(sipe_activity_map[activity].token);
	}
	return availability;
}

void process_incoming_notify_rlmi(struct sipe_core_private *sipe_private,
				  const gchar *data,
				  unsigned len)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	const char *uri;
	sipe_xml *xn_categories;
	const sipe_xml *xn_category;
	const char *status = NULL;
	gboolean do_update_status = FALSE;
	gboolean has_note_cleaned = FALSE;
	gboolean has_free_busy_cleaned = FALSE;

	xn_categories = sipe_xml_parse(data, len);
	uri = sipe_xml_attribute(xn_categories, "uri"); /* with 'sip:' prefix */

	for (xn_category = sipe_xml_child(xn_categories, "category");
		 xn_category ;
		 xn_category = sipe_xml_twin(xn_category) )
	{
		const sipe_xml *xn_node;
		const char *tmp;
		const char *attrVar = sipe_xml_attribute(xn_category, "name");
		time_t publish_time = (tmp = sipe_xml_attribute(xn_category, "publishTime")) ?
			sipe_utils_str_to_time(tmp) : 0;

		/* contactCard */
		if (sipe_strequal(attrVar, "contactCard"))
		{
			const sipe_xml *card = sipe_xml_child(xn_category, "contactCard");

			if (card) {
				const sipe_xml *node;
				/* identity - Display Name and email */
				node = sipe_xml_child(card, "identity");
				if (node) {
					char* display_name = sipe_xml_data(
						sipe_xml_child(node, "name/displayName"));
					char* email = sipe_xml_data(
						sipe_xml_child(node, "email"));

					sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_DISPLAY_NAME, display_name);
					sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_EMAIL, email);

					g_free(display_name);
					g_free(email);
				}
				/* company */
				node = sipe_xml_child(card, "company");
				if (node) {
					char* company = sipe_xml_data(node);
					sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_COMPANY, company);
					g_free(company);
				}
				/* department */
				node = sipe_xml_child(card, "department");
				if (node) {
					char* department = sipe_xml_data(node);
					sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_DEPARTMENT, department);
					g_free(department);
				}
				/* title */
				node = sipe_xml_child(card, "title");
				if (node) {
					char* title = sipe_xml_data(node);
					sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_JOB_TITLE, title);
					g_free(title);
				}
				/* office */
				node = sipe_xml_child(card, "office");
				if (node) {
					char* office = sipe_xml_data(node);
					sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_OFFICE, office);
					g_free(office);
				}
				/* site (url) */
				node = sipe_xml_child(card, "url");
				if (node) {
					char* site = sipe_xml_data(node);
					sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_SITE, site);
					g_free(site);
				}
				/* phone */
				for (node = sipe_xml_child(card, "phone");
				     node;
				     node = sipe_xml_twin(node))
				{
					const char *phone_type = sipe_xml_attribute(node, "type");
					char* phone = sipe_xml_data(sipe_xml_child(node, "uri"));
					char* phone_display_string = sipe_xml_data(sipe_xml_child(node, "displayString"));

					sipe_update_user_phone(sipe_private, uri, phone_type, phone, phone_display_string);

					g_free(phone);
					g_free(phone_display_string);
				}
				/* address */
				for (node = sipe_xml_child(card, "address");
				     node;
				     node = sipe_xml_twin(node))
				{
					if (sipe_strequal(sipe_xml_attribute(node, "type"), "work")) {
						char* street = sipe_xml_data(sipe_xml_child(node, "street"));
						char* city = sipe_xml_data(sipe_xml_child(node, "city"));
						char* state = sipe_xml_data(sipe_xml_child(node, "state"));
						char* zipcode = sipe_xml_data(sipe_xml_child(node, "zipcode"));
						char* country_code = sipe_xml_data(sipe_xml_child(node, "countryCode"));

						sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_STREET, street);
						sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_CITY, city);
						sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_STATE, state);
						sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_ZIPCODE, zipcode);
						sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_COUNTRY, country_code);

						g_free(street);
						g_free(city);
						g_free(state);
						g_free(zipcode);
						g_free(country_code);

						break;
					}
				}
			}
		}
		/* note */
		else if (sipe_strequal(attrVar, "note"))
		{
			if (uri) {
				struct sipe_buddy *sbuddy = g_hash_table_lookup(sipe_private->buddies, uri);

				if (!has_note_cleaned) {
					has_note_cleaned = TRUE;

					g_free(sbuddy->note);
					sbuddy->note = NULL;
					sbuddy->is_oof_note = FALSE;
					sbuddy->note_since = publish_time;

					do_update_status = TRUE;
				}
				if (sbuddy && (publish_time >= sbuddy->note_since)) {
					/* clean up in case no 'note' element is supplied
					 * which indicate note removal in client
					 */
					g_free(sbuddy->note);
					sbuddy->note = NULL;
					sbuddy->is_oof_note = FALSE;
					sbuddy->note_since = publish_time;

					xn_node = sipe_xml_child(xn_category, "note/body");
					if (xn_node) {
						char *tmp;
						sbuddy->note = g_markup_escape_text((tmp = sipe_xml_data(xn_node)), -1);
						g_free(tmp);
						sbuddy->is_oof_note = sipe_strequal(sipe_xml_attribute(xn_node, "type"), "OOF");
						sbuddy->note_since = publish_time;

						SIPE_DEBUG_INFO("process_incoming_notify_rlmi: uri(%s), note(%s)",
								uri, sbuddy->note ? sbuddy->note : "");
					}
					/* to trigger UI refresh in case no status info is supplied in this update */
					do_update_status = TRUE;
				}
			}
		}
		/* state */
		else if(sipe_strequal(attrVar, "state"))
		{
			char *tmp;
			int availability;
			const sipe_xml *xn_availability;
			const sipe_xml *xn_activity;
			const sipe_xml *xn_meeting_subject;
			const sipe_xml *xn_meeting_location;
			struct sipe_buddy *sbuddy = uri ? g_hash_table_lookup(sipe_private->buddies, uri) : NULL;

			xn_node = sipe_xml_child(xn_category, "state");
			if (!xn_node) continue;
			xn_availability = sipe_xml_child(xn_node, "availability");
			if (!xn_availability) continue;
			xn_activity = sipe_xml_child(xn_node, "activity");
			xn_meeting_subject = sipe_xml_child(xn_node, "meetingSubject");
			xn_meeting_location = sipe_xml_child(xn_node, "meetingLocation");

			tmp = sipe_xml_data(xn_availability);
			availability = atoi(tmp);
			g_free(tmp);

			/* activity, meeting_subject, meeting_location */
			if (sbuddy) {
				char *tmp = NULL;

				/* activity */
				g_free(sbuddy->activity);
				sbuddy->activity = NULL;
				if (xn_activity) {
					const char *token = sipe_xml_attribute(xn_activity, "token");
					const sipe_xml *xn_custom = sipe_xml_child(xn_activity, "custom");

					/* from token */
					if (!is_empty(token)) {
						sbuddy->activity = g_strdup(sipe_get_activity_desc_by_token(token));
					}
					/* from custom element */
					if (xn_custom) {
						char *custom = sipe_xml_data(xn_custom);

						if (!is_empty(custom)) {
							sbuddy->activity = custom;
							custom = NULL;
						}
						g_free(custom);
					}
				}
				/* meeting_subject */
				g_free(sbuddy->meeting_subject);
				sbuddy->meeting_subject = NULL;
				if (xn_meeting_subject) {
					char *meeting_subject = sipe_xml_data(xn_meeting_subject);

					if (!is_empty(meeting_subject)) {
						sbuddy->meeting_subject = meeting_subject;
						meeting_subject = NULL;
					}
					g_free(meeting_subject);
				}
				/* meeting_location */
				g_free(sbuddy->meeting_location);
				sbuddy->meeting_location = NULL;
				if (xn_meeting_location) {
					char *meeting_location = sipe_xml_data(xn_meeting_location);

					if (!is_empty(meeting_location)) {
						sbuddy->meeting_location = meeting_location;
						meeting_location = NULL;
					}
					g_free(meeting_location);
				}

				status = sipe_get_status_by_availability(availability, &tmp);
				if (sbuddy->activity && tmp) {
					char *tmp2 = sbuddy->activity;

					sbuddy->activity = g_strdup_printf("%s, %s", sbuddy->activity, tmp);
					g_free(tmp);
					g_free(tmp2);
				} else if (tmp) {
					sbuddy->activity = tmp;
				}
			}

			do_update_status = TRUE;
		}
		/* calendarData */
		else if(sipe_strequal(attrVar, "calendarData"))
		{
			struct sipe_buddy *sbuddy = uri ? g_hash_table_lookup(sipe_private->buddies, uri) : NULL;
			const sipe_xml *xn_free_busy = sipe_xml_child(xn_category, "calendarData/freeBusy");
			const sipe_xml *xn_working_hours = sipe_xml_child(xn_category, "calendarData/WorkingHours");

			if (sbuddy && xn_free_busy) {
				if (!has_free_busy_cleaned) {
					has_free_busy_cleaned = TRUE;

					g_free(sbuddy->cal_start_time);
					sbuddy->cal_start_time = NULL;

					g_free(sbuddy->cal_free_busy_base64);
					sbuddy->cal_free_busy_base64 = NULL;

					g_free(sbuddy->cal_free_busy);
					sbuddy->cal_free_busy = NULL;

					sbuddy->cal_free_busy_published = publish_time;
				}

				if (publish_time >= sbuddy->cal_free_busy_published) {
					g_free(sbuddy->cal_start_time);
					sbuddy->cal_start_time = g_strdup(sipe_xml_attribute(xn_free_busy, "startTime"));

					sbuddy->cal_granularity = sipe_strcase_equal(sipe_xml_attribute(xn_free_busy, "granularity"), "PT15M") ?
						15 : 0;

					g_free(sbuddy->cal_free_busy_base64);
					sbuddy->cal_free_busy_base64 = sipe_xml_data(xn_free_busy);

					g_free(sbuddy->cal_free_busy);
					sbuddy->cal_free_busy = NULL;

					sbuddy->cal_free_busy_published = publish_time;

					SIPE_DEBUG_INFO("process_incoming_notify_rlmi: startTime=%s granularity=%d cal_free_busy_base64=\n%s", sbuddy->cal_start_time, sbuddy->cal_granularity, sbuddy->cal_free_busy_base64);
				}
			}

			if (sbuddy && xn_working_hours) {
				sipe_cal_parse_working_hours(xn_working_hours, sbuddy);
			}
		}
	}

	if (do_update_status) {
		if (!status) { /* no status category in this update, using contact's current status */
			PurpleBuddy *pbuddy = purple_find_buddy((PurpleAccount *)sip->account, uri);
			const PurplePresence *presence = purple_buddy_get_presence(pbuddy);
			const PurpleStatus *pstatus = purple_presence_get_active_status(presence);
			status = purple_status_get_id(pstatus);
		}

		SIPE_DEBUG_INFO("process_incoming_notify_rlmi: %s", status);
		sipe_core_buddy_got_status(SIPE_CORE_PUBLIC, uri, status);
	}

	sipe_xml_free(xn_categories);
}

void process_incoming_notify_pidf(struct sipe_core_private *sipe_private,
				  const gchar *data,
				  unsigned len)
{
	gchar *uri;
	gchar *getbasic;
	gchar *activity = NULL;
	sipe_xml *pidf;
	const sipe_xml *basicstatus = NULL, *tuple, *status;
	gboolean isonline = FALSE;
	const sipe_xml *display_name_node;

	pidf = sipe_xml_parse(data, len);
	if (!pidf) {
		SIPE_DEBUG_INFO("process_incoming_notify_pidf: no parseable pidf:%s", data);
		return;
	}

	if ((tuple = sipe_xml_child(pidf, "tuple")))
	{
		if ((status = sipe_xml_child(tuple, "status"))) {
			basicstatus = sipe_xml_child(status, "basic");
		}
	}

	if (!basicstatus) {
		SIPE_DEBUG_INFO_NOFORMAT("process_incoming_notify_pidf: no basic found");
		sipe_xml_free(pidf);
		return;
	}

	getbasic = sipe_xml_data(basicstatus);
	if (!getbasic) {
		SIPE_DEBUG_INFO_NOFORMAT("process_incoming_notify_pidf: no basic data found");
		sipe_xml_free(pidf);
		return;
	}

	SIPE_DEBUG_INFO("process_incoming_notify_pidf: basic-status(%s)", getbasic);
	if (strstr(getbasic, "open")) {
		isonline = TRUE;
	}
	g_free(getbasic);

	uri = sip_uri(sipe_xml_attribute(pidf, "entity")); /* with 'sip:' prefix */ /* AOL comes without the prefix */

	display_name_node = sipe_xml_child(pidf, "display-name");
	if (display_name_node) {
		char * display_name = sipe_xml_data(display_name_node);

		sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_DISPLAY_NAME, display_name);
		g_free(display_name);
	}

	if ((tuple = sipe_xml_child(pidf, "tuple"))) {
		if ((status = sipe_xml_child(tuple, "status"))) {
			if ((basicstatus = sipe_xml_child(status, "activities"))) {
				if ((basicstatus = sipe_xml_child(basicstatus, "activity"))) {
					activity = sipe_xml_data(basicstatus);
					SIPE_DEBUG_INFO("process_incoming_notify_pidf: activity(%s)", activity);
				}
			}
		}
	}

	if (isonline) {
		const gchar * status_id = NULL;
		if (activity) {
			if (sipe_strequal(activity, sipe_activity_map[SIPE_ACTIVITY_BUSY].token)) {
				status_id = SIPE_STATUS_ID_BUSY;
			} else if (sipe_strequal(activity, sipe_activity_map[SIPE_ACTIVITY_AWAY].token)) {
				status_id = SIPE_STATUS_ID_AWAY;
			}
		}

		if (!status_id) {
			status_id = SIPE_STATUS_ID_AVAILABLE;
		}

		SIPE_DEBUG_INFO("process_incoming_notify_pidf: status_id(%s)", status_id);
		sipe_core_buddy_got_status(SIPE_CORE_PUBLIC, uri, status_id);
	} else {
		sipe_core_buddy_got_status(SIPE_CORE_PUBLIC, uri, SIPE_STATUS_ID_OFFLINE);
	}

	g_free(activity);
	g_free(uri);
	sipe_xml_free(pidf);
}

/** 2005 */
static void
sipe_user_info_has_updated(struct sipe_core_private *sipe_private,
			   const sipe_xml *xn_userinfo)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	const sipe_xml *xn_states;

	g_free(sip->user_states);
	sip->user_states = NULL;
	if ((xn_states = sipe_xml_child(xn_userinfo, "states")) != NULL) {
		gchar *orig = sip->user_states = sipe_xml_stringify(xn_states);

		/* this is a hack-around to remove added newline after inner element,
		 * state in this case, where it shouldn't be.
		 * After several use of sipe_xml_stringify, amount of added newlines
		 * grows significantly.
		 */
		if (orig) {
			gchar c, *stripped = orig;
			while ((c = *orig++)) {
				if ((c != '\n') /* && (c != '\r') */) {
					*stripped++ = c;
				}
			}
			*stripped = '\0';
		}
	}

	/* Publish initial state if not yet.
	 * Assuming this happens on initial responce to self subscription
	 * so we've already updated our UserInfo.
	 */
	if (!sip->initial_state_published) {
		send_presence_soap(sipe_private, FALSE);
		/* dalayed run */
		sipe_cal_delayed_calendar_update(sipe_private);
	}
}

void process_incoming_notify_msrtc(struct sipe_core_private *sipe_private,
				   const gchar *data,
				   unsigned len)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	char *activity = NULL;
	const char *epid;
	const char *status_id = NULL;
	const char *name;
	char *uri;
	char *self_uri = sip_uri_self(sipe_private);
	int avl;
	int act;
	const char *device_name = NULL;
	const char *cal_start_time = NULL;
	const char *cal_granularity = NULL;
	char *cal_free_busy_base64 = NULL;
	struct sipe_buddy *sbuddy;
	const sipe_xml *node;
	sipe_xml *xn_presentity;
	const sipe_xml *xn_availability;
	const sipe_xml *xn_activity;
	const sipe_xml *xn_display_name;
	const sipe_xml *xn_email;
	const sipe_xml *xn_phone_number;
	const sipe_xml *xn_userinfo;
	const sipe_xml *xn_note;
	const sipe_xml *xn_oof;
	const sipe_xml *xn_state;
	const sipe_xml *xn_contact;
	char *note;
	int user_avail;
	const char *user_avail_nil;
	int res_avail;
	time_t user_avail_since = 0;
	time_t activity_since = 0;

	/* fix for Reuters environment on Linux */
	if (data && strstr(data, "encoding=\"utf-16\"")) {
		char *tmp_data;
		tmp_data = replace(data, "encoding=\"utf-16\"", "encoding=\"utf-8\"");
		xn_presentity = sipe_xml_parse(tmp_data, strlen(tmp_data));
		g_free(tmp_data);
	} else {
		xn_presentity = sipe_xml_parse(data, len);
	}

	xn_availability = sipe_xml_child(xn_presentity, "availability");
	xn_activity = sipe_xml_child(xn_presentity, "activity");
	xn_display_name = sipe_xml_child(xn_presentity, "displayName");
	xn_email = sipe_xml_child(xn_presentity, "email");
	xn_phone_number = sipe_xml_child(xn_presentity, "phoneNumber");
	xn_userinfo = sipe_xml_child(xn_presentity, "userInfo");
	xn_oof = xn_userinfo ? sipe_xml_child(xn_userinfo, "oof") : NULL;
	xn_state = xn_userinfo ? sipe_xml_child(xn_userinfo, "states/state"): NULL;
	user_avail = xn_state ? sipe_xml_int_attribute(xn_state, "avail", 0) : 0;
	user_avail_since = xn_state ? sipe_utils_str_to_time(sipe_xml_attribute(xn_state, "since")) : 0;
	user_avail_nil = xn_state ? sipe_xml_attribute(xn_state, "nil") : NULL;
	xn_contact = xn_userinfo ? sipe_xml_child(xn_userinfo, "contact") : NULL;
	xn_note = xn_userinfo ? sipe_xml_child(xn_userinfo, "note") : NULL;
	note = xn_note ? sipe_xml_data(xn_note) : NULL;

	if (sipe_strequal(user_avail_nil, "true")) {	/* null-ed */
		user_avail = 0;
		user_avail_since = 0;
	}

	name = sipe_xml_attribute(xn_presentity, "uri"); /* without 'sip:' prefix */
	uri = sip_uri_from_name(name);
	avl = sipe_xml_int_attribute(xn_availability, "aggregate", 0);
	epid = sipe_xml_attribute(xn_availability, "epid");
	act = sipe_xml_int_attribute(xn_activity, "aggregate", 0);

	status_id = sipe_get_status_by_act_avail_2005(act, avl, &activity);
	res_avail = sipe_get_availability_by_status(status_id, NULL);
	if (user_avail > res_avail) {
		res_avail = user_avail;
		status_id = sipe_get_status_by_availability(user_avail, NULL);
	}

	if (xn_display_name) {
		char *display_name = g_strdup(sipe_xml_attribute(xn_display_name, "displayName"));
		char *email        = xn_email ? g_strdup(sipe_xml_attribute(xn_email, "email")) : NULL;
		char *phone_label  = xn_phone_number ? g_strdup(sipe_xml_attribute(xn_phone_number, "label")) : NULL;
		char *phone_number = xn_phone_number ? g_strdup(sipe_xml_attribute(xn_phone_number, "number")) : NULL;
		char *tel_uri      = sip_to_tel_uri(phone_number);

		sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_DISPLAY_NAME, display_name);
		sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_EMAIL, email);
		sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_WORK_PHONE, tel_uri);
		sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_WORK_PHONE_DISPLAY, !is_empty(phone_label) ? phone_label : phone_number);

		g_free(tel_uri);
		g_free(phone_label);
		g_free(phone_number);
		g_free(email);
		g_free(display_name);
	}

	if (xn_contact) {
		/* tel */
		for (node = sipe_xml_child(xn_contact, "tel"); node; node = sipe_xml_twin(node))
		{
			/* Ex.: <tel type="work">tel:+3222220000</tel> */
			const char *phone_type = sipe_xml_attribute(node, "type");
			char* phone = sipe_xml_data(node);

			sipe_update_user_phone(sipe_private, uri, phone_type, phone, NULL);

			g_free(phone);
		}
	}

	/* devicePresence */
	for (node = sipe_xml_child(xn_presentity, "devices/devicePresence"); node; node = sipe_xml_twin(node)) {
		const sipe_xml *xn_device_name;
		const sipe_xml *xn_calendar_info;
		const sipe_xml *xn_state;
		char *state;

		/* deviceName */
		if (sipe_strequal(sipe_xml_attribute(node, "epid"), epid)) {
			xn_device_name = sipe_xml_child(node, "deviceName");
			device_name = xn_device_name ? sipe_xml_attribute(xn_device_name, "name") : NULL;
		}

		/* calendarInfo */
		xn_calendar_info = sipe_xml_child(node, "calendarInfo");
		if (xn_calendar_info) {
			const char *cal_start_time_tmp = sipe_xml_attribute(xn_calendar_info, "startTime");

			if (cal_start_time) {
				time_t cal_start_time_t     = sipe_utils_str_to_time(cal_start_time);
				time_t cal_start_time_t_tmp = sipe_utils_str_to_time(cal_start_time_tmp);

				if (cal_start_time_t_tmp > cal_start_time_t) {
					cal_start_time = cal_start_time_tmp;
					cal_granularity = sipe_xml_attribute(xn_calendar_info, "granularity");
					g_free(cal_free_busy_base64);
					cal_free_busy_base64 = sipe_xml_data(xn_calendar_info);

					SIPE_DEBUG_INFO("process_incoming_notify_msrtc: startTime=%s granularity=%s cal_free_busy_base64=\n%s", cal_start_time, cal_granularity, cal_free_busy_base64);
				}
			} else {
				cal_start_time = cal_start_time_tmp;
				cal_granularity = sipe_xml_attribute(xn_calendar_info, "granularity");
				g_free(cal_free_busy_base64);
				cal_free_busy_base64 = sipe_xml_data(xn_calendar_info);

				SIPE_DEBUG_INFO("process_incoming_notify_msrtc: startTime=%s granularity=%s cal_free_busy_base64=\n%s", cal_start_time, cal_granularity, cal_free_busy_base64);
			}
		}

		/* state */
		xn_state = sipe_xml_child(node, "states/state");
		if (xn_state) {
			int dev_avail = sipe_xml_int_attribute(xn_state, "avail", 0);
			time_t dev_avail_since = sipe_utils_str_to_time(sipe_xml_attribute(xn_state, "since"));

			state = sipe_xml_data(xn_state);
			if (dev_avail_since > user_avail_since &&
			    dev_avail >= res_avail)
			{
				res_avail = dev_avail;
				if (!is_empty(state))
				{
					if (sipe_strequal(state, sipe_activity_map[SIPE_ACTIVITY_ON_PHONE].token)) {
						g_free(activity);
						activity = g_strdup(SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_ON_PHONE));
					} else if (sipe_strequal(state, "presenting")) {
						g_free(activity);
						activity = g_strdup(SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_IN_CONF));
					} else {
						activity = state;
						state = NULL;
					}
					activity_since = dev_avail_since;
				}
				status_id = sipe_get_status_by_availability(res_avail, &activity);
			}
			g_free(state);
		}
	}

	/* oof */
	if (xn_oof && res_avail >= 15000) { /* 12000 in 2007 */
		g_free(activity);
		activity = g_strdup(SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_OOF));
		activity_since = 0;
	}

	sbuddy = g_hash_table_lookup(sipe_private->buddies, uri);
	if (sbuddy)
	{
		g_free(sbuddy->activity);
		sbuddy->activity = activity;
		activity = NULL;

		sbuddy->activity_since = activity_since;

		sbuddy->user_avail = user_avail;
		sbuddy->user_avail_since = user_avail_since;

		g_free(sbuddy->note);
		sbuddy->note = NULL;
		if (!is_empty(note)) { sbuddy->note = g_markup_escape_text(note, -1); }

		sbuddy->is_oof_note = (xn_oof != NULL);

		g_free(sbuddy->device_name);
		sbuddy->device_name = NULL;
		if (!is_empty(device_name)) { sbuddy->device_name = g_strdup(device_name); }

		if (!is_empty(cal_free_busy_base64)) {
			g_free(sbuddy->cal_start_time);
			sbuddy->cal_start_time = g_strdup(cal_start_time);

			sbuddy->cal_granularity = sipe_strcase_equal(cal_granularity, "PT15M") ? 15 : 0;

			g_free(sbuddy->cal_free_busy_base64);
			sbuddy->cal_free_busy_base64 = cal_free_busy_base64;
			cal_free_busy_base64 = NULL;

			g_free(sbuddy->cal_free_busy);
			sbuddy->cal_free_busy = NULL;
		}

		sbuddy->last_non_cal_status_id = status_id;
		g_free(sbuddy->last_non_cal_activity);
		sbuddy->last_non_cal_activity = g_strdup(sbuddy->activity);

		if (sipe_strcase_equal(sbuddy->name, self_uri)) {
			if (!sipe_strequal(sbuddy->note, sip->note)) /* not same */
			{
				sip->is_oof_note = sbuddy->is_oof_note;

				g_free(sip->note);
				sip->note = g_strdup(sbuddy->note);

				sip->note_since = time(NULL);
			}

			g_free(sip->status);
			sip->status = g_strdup(sbuddy->last_non_cal_status_id);
		}
	}
	g_free(cal_free_busy_base64);
	g_free(activity);

	SIPE_DEBUG_INFO("process_incoming_notify_msrtc: status(%s)", status_id);
	sipe_core_buddy_got_status(SIPE_CORE_PUBLIC, uri, status_id);

	if (!SIPE_CORE_PRIVATE_FLAG_IS(OCS2007) && sipe_strcase_equal(self_uri, uri)) {
		sipe_user_info_has_updated(sipe_private, xn_userinfo);
	}

	g_free(note);
	sipe_xml_free(xn_presentity);
	g_free(uri);
	g_free(self_uri);
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

/**
 * OCS2005 presence XML messages
 *
 * Calendar publication entry
 *
 * @param legacy_dn		(%s) Ex.: /o=EXCHANGE/ou=BTUK02/cn=Recipients/cn=AHHBTT
 * @param fb_start_time_str	(%s) Ex.: 2009-12-06T17:15:00Z
 * @param free_busy_base64	(%s) Ex.: AAAAAAAAAAAAAAAAA......
 */
#define SIPE_SOAP_SET_PRESENCE_CALENDAR \
"<calendarInfo xmlns=\"http://schemas.microsoft.com/2002/09/sip/presence\" mailboxId=\"%s\" startTime=\"%s\" granularity=\"PT15M\">%s</calendarInfo>"

/**
 * Note publication entry
 *
 * @param note	(%s) Ex.: Working from home
 */
#define SIPE_SOAP_SET_PRESENCE_NOTE_XML  "<note>%s</note>"

/**
 * Note's OOF publication entry
 */
#define SIPE_SOAP_SET_PRESENCE_OOF_XML  "<oof></oof>"

/**
 * States publication entry for User State
 *
 * @param avail			(%d) Availability 2007-style. Ex.: 9500
 * @param since_time_str	(%s) Ex.: 2010-01-13T10:30:05Z
 * @param device_id		(%s) epid. Ex.: 4c77e6ec72
 * @param activity_token	(%s) Ex.: do-not-disturb
 */
#define SIPE_SOAP_SET_PRESENCE_STATES \
          "<states>"\
            "<state avail=\"%d\" since=\"%s\" validWith=\"any-device\" deviceId=\"%s\" set=\"manual\" xsi:type=\"userState\">%s</state>"\
          "</states>"

/**
 * Presentity publication entry.
 *
 * @param uri			(%s) SIP URI without 'sip:' prefix. Ex.: fox@atlanta.local
 * @param aggr_availability	(%d) Ex.: 300
 * @param aggr_activity		(%d) Ex.: 600
 * @param host_name		(%s) Uppercased. Ex.: ATLANTA
 * @param note_xml_str		(%s) XML string as SIPE_SOAP_SET_PRESENCE_NOTE_XML
 * @param oof_xml_str		(%s) XML string as SIPE_SOAP_SET_PRESENCE_OOF_XML
 * @param states_xml_str	(%s) XML string as SIPE_SOAP_SET_PRESENCE_STATES
 * @param calendar_info_xml_str	(%s) XML string as SIPE_SOAP_SET_PRESENCE_CALENDAR
 * @param device_id		(%s) epid. Ex.: 4c77e6ec72
 * @param since_time_str	(%s) Ex.: 2010-01-13T10:30:05Z
 * @param since_time_str	(%s) Ex.: 2010-01-13T10:30:05Z
 * @param user_input		(%s) active, idle
 */
#define SIPE_SOAP_SET_PRESENCE \
	"<s:Envelope" \
        " xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\"" \
	" xmlns:m=\"http://schemas.microsoft.com/winrtc/2002/11/sip\"" \
	">" \
	"<s:Body>" \
	"<m:setPresence>" \
	"<m:presentity xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" m:uri=\"sip:%s\">"\
	"<m:availability m:aggregate=\"%d\"/>"\
	"<m:activity m:aggregate=\"%d\"/>"\
	"<deviceName xmlns=\"http://schemas.microsoft.com/2002/09/sip/presence\" name=\"%s\"/>"\
	"<rtc:devicedata xmlns:rtc=\"http://schemas.microsoft.com/winrtc/2002/11/sip\" namespace=\"rtcService\">"\
	"<![CDATA[<caps><renders_gif/><renders_isf/></caps>]]></rtc:devicedata>"\
	"<userInfo xmlns=\"http://schemas.microsoft.com/2002/09/sip/presence\">"\
	"%s%s" \
	"%s" \
        "</userInfo>"\
	"%s" \
	"<device xmlns=\"http://schemas.microsoft.com/2002/09/sip/presence\" deviceId=\"%s\" since=\"%s\" >"\
		"<userInput since=\"%s\" >%s</userInput>"\
	"</device>"\
	"</m:presentity>" \
	"</m:setPresence>"\
	"</s:Body>" \
	"</s:Envelope>"

static void
send_presence_soap0(struct sipe_core_private *sipe_private,
		    gboolean do_publish_calendar,
		    gboolean do_reset_status)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	struct sipe_calendar* cal = sip->cal;
	int availability = 0;
	int activity = 0;
	gchar *body;
	gchar *tmp;
	gchar *tmp2 = NULL;
	gchar *res_note = NULL;
	gchar *res_oof = NULL;
	const gchar *note_pub = NULL;
	gchar *states = NULL;
	gchar *calendar_data = NULL;
	gchar *epid = get_epid(sipe_private);
	gchar *from = sip_uri_self(sipe_private);
	time_t now = time(NULL);
	gchar *since_time_str = sipe_utils_time_to_str(now);
	const gchar *oof_note = cal ? sipe_ews_get_oof_note(cal) : NULL;
	const char *user_input;
	gboolean pub_oof = cal && oof_note && (!sip->note || cal->updated > sip->note_since);

	if (oof_note && sip->note) {
		SIPE_DEBUG_INFO("cal->oof_start  : %s", asctime(localtime(&(cal->oof_start))));
		SIPE_DEBUG_INFO("sip->note_since : %s", asctime(localtime(&(sip->note_since))));
	}

	SIPE_DEBUG_INFO("sip->note  : %s", sip->note ? sip->note : "");

	if (!sip->initial_state_published ||
	    do_reset_status)
		sipe_set_initial_status(sipe_private);

	sipe_get_act_avail_by_status_2005(sip->status, &activity, &availability);

	/* Note */
	if (pub_oof) {
		note_pub = oof_note;
		res_oof = SIPE_SOAP_SET_PRESENCE_OOF_XML;
		cal->published = TRUE;
	} else if (sip->note) {
		if (sip->is_oof_note && !oof_note) { /* stale OOF note, as it's not present in cal already */
			g_free(sip->note);
			sip->note = NULL;
			sip->is_oof_note = FALSE;
			sip->note_since = 0;
		} else {
			note_pub = sip->note;
			res_oof = sip->is_oof_note ? SIPE_SOAP_SET_PRESENCE_OOF_XML : "";
		}
	}

	if (note_pub)
	{
		/* to protocol internal plain text format */
		tmp = sipe_backend_markup_strip_html(note_pub);
		res_note = g_markup_printf_escaped(SIPE_SOAP_SET_PRESENCE_NOTE_XML, tmp);
		g_free(tmp);
	}

	/* User State */
	if (!do_reset_status) {
		if (sipe_is_user_state(sipe_private) && !do_publish_calendar && sip->initial_state_published)
		{
			gchar *activity_token = NULL;
			int avail_2007 = sipe_get_availability_by_status(sip->status, &activity_token);

			states = g_strdup_printf(SIPE_SOAP_SET_PRESENCE_STATES,
						avail_2007,
						since_time_str,
						epid,
						activity_token);
			g_free(activity_token);
		}
		else /* preserve existing publication */
		{
			if (sip->user_states) {
				states = g_strdup(sip->user_states);
			}
		}
	} else {
		/* do nothing - then User state will be erased */
	}
	sip->initial_state_published = TRUE;

	/* CalendarInfo */
	if (cal && (!is_empty(cal->legacy_dn) || !is_empty(cal->email)) && cal->fb_start && !is_empty(cal->free_busy))
	{
		char *fb_start_str = sipe_utils_time_to_str(cal->fb_start);
		char *free_busy_base64 = sipe_cal_get_freebusy_base64(cal->free_busy);
		calendar_data = g_strdup_printf(SIPE_SOAP_SET_PRESENCE_CALENDAR,
						!is_empty(cal->legacy_dn) ? cal->legacy_dn : cal->email,
						fb_start_str,
						free_busy_base64);
		g_free(fb_start_str);
		g_free(free_busy_base64);
	}

	user_input = (sipe_is_user_state(sipe_private) ||
		      sipe_strequal(sip->status, SIPE_STATUS_ID_AVAILABLE)) ?
		"active" : "idle";

	/* forming resulting XML */
	body = g_strdup_printf(SIPE_SOAP_SET_PRESENCE,
			       sipe_private->username,
			       availability,
			       activity,
			       (tmp = g_ascii_strup(g_get_host_name(), -1)),
			       res_note ? res_note : "",
			       res_oof ? res_oof : "",
			       states ? states : "",
			       calendar_data ? calendar_data : "",
			       epid,
			       since_time_str,
			       since_time_str,
			       user_input);
	g_free(tmp);
	g_free(tmp2);
	g_free(res_note);
	g_free(states);
	g_free(calendar_data);
	g_free(since_time_str);
	g_free(epid);

	sip_soap_raw_request_cb(sipe_private, from, body, NULL, NULL);

	g_free(body);
}

void
send_presence_soap(struct sipe_core_private *sipe_private,
		   gboolean do_publish_calendar)
{
	return send_presence_soap0(sipe_private, do_publish_calendar, FALSE);
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

static guint sipe_ht_hash_nick(const char *nick)
{
	char *lc = g_utf8_strdown(nick, -1);
	guint bucket = g_str_hash(lc);
	g_free(lc);

	return bucket;
}

static gboolean sipe_ht_equals_nick(const char *nick1, const char *nick2)
{
	char *nick1_norm = NULL;
	char *nick2_norm = NULL;
	gboolean equal;

	if (nick1 == NULL && nick2 == NULL) return TRUE;
	if (nick1 == NULL || nick2 == NULL    ||
	    !g_utf8_validate(nick1, -1, NULL) ||
	    !g_utf8_validate(nick2, -1, NULL)) return FALSE;

	nick1_norm = g_utf8_casefold(nick1, -1);
	nick2_norm = g_utf8_casefold(nick2, -1);
	equal = g_utf8_collate(nick1_norm, nick2_norm) == 0;
	g_free(nick2_norm);
	g_free(nick1_norm);

	return equal;
}

/* temporary function */
void sipe_purple_setup(struct sipe_core_public *sipe_public,
		       PurpleConnection *gc)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA;
	sip->gc = gc;
	sip->account = purple_connection_get_account(gc);
}

struct sipe_core_public *sipe_core_allocate(const gchar *signin_name,
					    const gchar *login_domain,
					    const gchar *login_account,
					    const gchar *password,
					    const gchar *email,
					    const gchar *email_url,
					    const gchar **errmsg)
{
	struct sipe_core_private *sipe_private;
	struct sipe_account_data *sip;
	gchar **user_domain;

	SIPE_DEBUG_INFO("sipe_core_allocate: signin_name '%s'", signin_name);

	/* ensure that sign-in name doesn't contain invalid characters */
	if (strpbrk(signin_name, "\t\v\r\n") != NULL) {
		*errmsg = _("SIP Exchange user name contains invalid characters");
		return NULL;
	}

	/* ensure that sign-in name format is name@domain */
	if (!strchr(signin_name, '@') ||
	    g_str_has_prefix(signin_name, "@") ||
	    g_str_has_suffix(signin_name, "@")) {
		*errmsg = _("User name should be a valid SIP URI\nExample: user@company.com");
		return NULL;
	}

	/* ensure that email format is name@domain (if provided) */
	if (!is_empty(email) &&
	    (!strchr(email, '@') ||
	     g_str_has_prefix(email, "@") ||
	     g_str_has_suffix(email, "@")))
	{
		*errmsg = _("Email address should be valid if provided\nExample: user@company.com");
		return NULL;
	}

	/* ensure that user name doesn't contain spaces */
	user_domain = g_strsplit(signin_name, "@", 2);
	SIPE_DEBUG_INFO("sipe_core_allocate: user '%s' domain '%s'", user_domain[0], user_domain[1]);
	if (strchr(user_domain[0], ' ') != NULL) {
		g_strfreev(user_domain);
		*errmsg = _("SIP Exchange user name contains whitespace");
		return NULL;
	}

	/* ensure that email_url is in proper format if enabled (if provided).
	 * Example (Exchange): https://server.company.com/EWS/Exchange.asmx
	 * Example (Domino)  : https://[domino_server]/[mail_database_name].nsf
	 */
	if (!is_empty(email_url)) {
		char *tmp = g_ascii_strdown(email_url, -1);
		if (!g_str_has_prefix(tmp, "https://"))
		{
			g_free(tmp);
			g_strfreev(user_domain);
			*errmsg = _("Email services URL should be valid if provided\n"
				    "Example: https://exchange.corp.com/EWS/Exchange.asmx\n"
				    "Example: https://domino.corp.com/maildatabase.nsf");
			return NULL;
		}
		g_free(tmp);
	}

	sipe_private = g_new0(struct sipe_core_private, 1);
	sipe_private->temporary = sip = g_new0(struct sipe_account_data, 1);
	sip->subscribed_buddies = FALSE;
	sip->initial_state_published = FALSE;
	sipe_private->username   = g_strdup(signin_name);
	sip->email      = is_empty(email)         ? g_strdup(signin_name) : g_strdup(email);
	sip->authdomain = is_empty(login_domain)  ? NULL                  : g_strdup(login_domain);
	sip->authuser   = is_empty(login_account) ? NULL                  : g_strdup(login_account);
	sip->password   = g_strdup(password);
	sipe_private->public.sip_name   = g_strdup(user_domain[0]);
	sipe_private->public.sip_domain = g_strdup(user_domain[1]);
	g_strfreev(user_domain);

	sipe_private->buddies = g_hash_table_new((GHashFunc)sipe_ht_hash_nick, (GEqualFunc)sipe_ht_equals_nick);
	sip->our_publications = g_hash_table_new_full(g_str_hash, g_str_equal,
						      g_free, (GDestroyNotify)g_hash_table_destroy);
	sipe_subscriptions_init(sipe_private);
	sip->status = g_strdup(SIPE_STATUS_ID_UNKNOWN);

	return((struct sipe_core_public *)sipe_private);
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

/**
  * A callback for g_hash_table_foreach_remove
  */
static gboolean sipe_buddy_remove(SIPE_UNUSED_PARAMETER gpointer key, gpointer buddy,
				  SIPE_UNUSED_PARAMETER gpointer user_data)
{
	sipe_free_buddy((struct sipe_buddy *) buddy);

	/* We must return TRUE as the key/value have already been deleted */
	return(TRUE);
}

void sipe_buddy_free_all(struct sipe_core_private *sipe_private)
{
	g_hash_table_foreach_steal(sipe_private->buddies, sipe_buddy_remove, NULL);
}

static void sipe_searchresults_im_buddy(PurpleConnection *gc, GList *row,
					SIPE_UNUSED_PARAMETER void *user_data)
{
	PurpleAccount *acct = purple_connection_get_account(gc);
	char *id = sip_uri_from_name((gchar *)g_list_nth_data(row, 0));
	PurpleConversation *conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, id, acct);
	if (conv == NULL)
		conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, acct, id);
	purple_conversation_present(conv);
	g_free(id);
}

static void sipe_searchresults_add_buddy(PurpleConnection *gc, GList *row,
					 SIPE_UNUSED_PARAMETER void *user_data)
{

	purple_blist_request_add_buddy(purple_connection_get_account(gc),
								 g_list_nth_data(row, 0), _("Other Contacts"), g_list_nth_data(row, 1));
}

static gboolean process_search_contact_response(struct sipe_core_private *sipe_private,
						struct sipmsg *msg,
						SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	PurpleNotifySearchResults *results;
	PurpleNotifySearchColumn *column;
	sipe_xml *searchResults;
	const sipe_xml *mrow;
	int match_count = 0;
	gboolean more = FALSE;
	gchar *secondary;

	/* valid response? */
	if (msg->response != 200) {
		SIPE_DEBUG_ERROR("process_search_contact_response: request failed (%d)",
				 msg->response);
		purple_notify_error(sip->gc, NULL,
				    _("Contact search failed"),
				    NULL);
		return(FALSE);
	}

	SIPE_DEBUG_INFO("process_search_contact_response: body:\n%s", msg->body ? msg->body : "");

	/* valid XML? */
	searchResults = sipe_xml_parse(msg->body, msg->bodylen);
	if (!searchResults) {
		SIPE_DEBUG_INFO_NOFORMAT("process_search_contact_response: no parseable searchResults");
		purple_notify_error(sip->gc, NULL,
				    _("Contact search failed"),
				    NULL);
		return FALSE;
	}

	/* any matches? */
	mrow = sipe_xml_child(searchResults, "Body/Array/row");
	if (!mrow) {
		SIPE_DEBUG_ERROR_NOFORMAT("process_search_contact_response: no matches");
		purple_notify_error(sip->gc, NULL,
				    _("No contacts found"),
				    NULL);

		sipe_xml_free(searchResults);
		return(FALSE);
	}

	/* OK, we found something - show the results to the user */
	results = purple_notify_searchresults_new();
	if (!results) {
		SIPE_DEBUG_ERROR_NOFORMAT("process_search_contact_response: Unable to display the search results.");
		purple_notify_error(sip->gc, NULL, _("Unable to display the search results"), NULL);

		sipe_xml_free(searchResults);
		return FALSE;
	}

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

	for (/* initialized above */ ; mrow; mrow = sipe_xml_twin(mrow)) {
		GList *row = NULL;

		gchar **uri_parts = g_strsplit(sipe_xml_attribute(mrow, "uri"), ":", 2);
		row = g_list_append(row, g_strdup(uri_parts[1]));
		g_strfreev(uri_parts);

		row = g_list_append(row, g_strdup(sipe_xml_attribute(mrow, "displayName")));
		row = g_list_append(row, g_strdup(sipe_xml_attribute(mrow, "company")));
		row = g_list_append(row, g_strdup(sipe_xml_attribute(mrow, "country")));
		row = g_list_append(row, g_strdup(sipe_xml_attribute(mrow, "email")));

		purple_notify_searchresults_row_add(results, row);
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

	purple_notify_searchresults_button_add(results, PURPLE_NOTIFY_BUTTON_IM, sipe_searchresults_im_buddy);
	purple_notify_searchresults_button_add(results, PURPLE_NOTIFY_BUTTON_ADD, sipe_searchresults_add_buddy);
	purple_notify_searchresults(sip->gc, NULL, NULL, secondary, results, NULL, NULL);

	g_free(secondary);
	sipe_xml_free(searchResults);
	return TRUE;
}

#define SIPE_SOAP_SEARCH_ROW "<m:row m:attrib=\"%s\" m:value=\"%s\"/>"

void sipe_search_contact_with_cb(PurpleConnection *gc, PurpleRequestFields *fields)
{
	GList *entries = purple_request_field_group_get_fields(purple_request_fields_get_groups(fields)->data);
	gchar **attrs = g_new(gchar *, g_list_length(entries) + 1);
	unsigned i = 0;

	if (!attrs) return;

	do {
		PurpleRequestField *field = entries->data;
		const char *id = purple_request_field_get_id(field);
		const char *value = purple_request_field_string_get_value(field);

		SIPE_DEBUG_INFO("sipe_search_contact_with_cb: %s = '%s'", id, value ? value : "");

		if (value != NULL) attrs[i++] = g_markup_printf_escaped(SIPE_SOAP_SEARCH_ROW, id, value);
	} while ((entries = g_list_next(entries)) != NULL);
	attrs[i] = NULL;

	if (i > 0) {
		struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;
		gchar *query = g_strjoinv(NULL, attrs);
		SIPE_DEBUG_INFO("sipe_search_contact_with_cb: rows:\n%s", query ? query : "");
		sip_soap_directory_search(sipe_private,
					  100,
					  query,
					  process_search_contact_response,
					  NULL);
		g_free(query);
	}

	g_strfreev(attrs);
}

void sipe_core_reset_status(struct sipe_core_public *sipe_public)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007))
		sipe_ocs2007_reset_status(sipe_private);
	else
		send_presence_soap0(sipe_private, FALSE, TRUE);
}

/** for Access levels menu */
#define INDENT_FMT			"  %s"

/** Member is directly placed to access level container.
 *  For example SIP URI of user is in the container.
 */
#define INDENT_MARKED_FMT		"* %s"

/** Member is indirectly belong to access level container.
 *  For example 'sameEnterprise' is in the container and user
 *  belongs to that same enterprise.
 */
#define INDENT_MARKED_INHERITED_FMT	"= %s"

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
				g_strdup_printf(INDENT_MARKED_FMT, access_level);
		}
	}

	//Layout
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

static PurpleBuddy *
purple_blist_add_buddy_clone(PurpleGroup * group, PurpleBuddy * buddy)
{
	PurpleBuddy *clone;
	const gchar *server_alias, *email;
	const PurpleStatus *status = purple_presence_get_active_status(purple_buddy_get_presence(buddy));

	clone = purple_buddy_new(buddy->account, buddy->name, buddy->alias);

	purple_blist_add_buddy(clone, NULL, group, NULL);

	server_alias = purple_buddy_get_server_alias(buddy);
	if (server_alias) {
		purple_blist_server_alias_buddy(clone, server_alias);
	}

	email = purple_blist_node_get_string(&buddy->node, EMAIL_PROP);
	if (email) {
		purple_blist_node_set_string(&clone->node, EMAIL_PROP, email);
	}

	purple_presence_set_status_active(purple_buddy_get_presence(clone), purple_status_get_id(status), TRUE);
	//for UI to update;
	purple_prpl_got_user_status(clone->account, clone->name, purple_status_get_id(status), NULL);
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
	const gchar *email;
	SIPE_DEBUG_INFO("sipe_buddy_menu_send_email_cb: buddy->name=%s", buddy->name);

	email = purple_blist_node_get_string(&buddy->node, EMAIL_PROP);
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
	const char *email;
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
		const char *phone;
		const char *phone_disp_str;
		gchar *tmp = NULL;
		/* work phone */
		phone = purple_blist_node_get_string(&buddy->node, PHONE_PROP);
		phone_disp_str = purple_blist_node_get_string(&buddy->node, PHONE_DISPLAY_PROP);
		if (phone) {
			gchar *label = g_strdup_printf(_("Work %s"),
				phone_disp_str ? phone_disp_str : (tmp = sip_tel_uri_denormalize(phone)));
			act = purple_menu_action_new(label, PURPLE_CALLBACK(sipe_buddy_menu_make_call_cb), (gpointer) phone, NULL);
			g_free(tmp);
			tmp = NULL;
			g_free(label);
			menu = g_list_prepend(menu, act);
		}

		/* mobile phone */
		phone = purple_blist_node_get_string(&buddy->node, PHONE_MOBILE_PROP);
		phone_disp_str = purple_blist_node_get_string(&buddy->node, PHONE_MOBILE_DISPLAY_PROP);
		if (phone) {
			gchar *label = g_strdup_printf(_("Mobile %s"),
				phone_disp_str ? phone_disp_str : (tmp = sip_tel_uri_denormalize(phone)));
			act = purple_menu_action_new(label, PURPLE_CALLBACK(sipe_buddy_menu_make_call_cb), (gpointer) phone, NULL);
			g_free(tmp);
			tmp = NULL;
			g_free(label);
			menu = g_list_prepend(menu, act);
		}

		/* home phone */
		phone = purple_blist_node_get_string(&buddy->node, PHONE_HOME_PROP);
		phone_disp_str = purple_blist_node_get_string(&buddy->node, PHONE_HOME_DISPLAY_PROP);
		if (phone) {
			gchar *label = g_strdup_printf(_("Home %s"),
				phone_disp_str ? phone_disp_str : (tmp = sip_tel_uri_denormalize(phone)));
			act = purple_menu_action_new(label, PURPLE_CALLBACK(sipe_buddy_menu_make_call_cb), (gpointer) phone, NULL);
			g_free(tmp);
			tmp = NULL;
			g_free(label);
			menu = g_list_prepend(menu, act);
		}

		/* other phone */
		phone = purple_blist_node_get_string(&buddy->node, PHONE_OTHER_PROP);
		phone_disp_str = purple_blist_node_get_string(&buddy->node, PHONE_OTHER_DISPLAY_PROP);
		if (phone) {
			gchar *label = g_strdup_printf(_("Other %s"),
				phone_disp_str ? phone_disp_str : (tmp = sip_tel_uri_denormalize(phone)));
			act = purple_menu_action_new(label, PURPLE_CALLBACK(sipe_buddy_menu_make_call_cb), (gpointer) phone, NULL);
			g_free(tmp);
			tmp = NULL;
			g_free(label);
			menu = g_list_prepend(menu, act);
		}

		/* custom1 phone */
		phone = purple_blist_node_get_string(&buddy->node, PHONE_CUSTOM1_PROP);
		phone_disp_str = purple_blist_node_get_string(&buddy->node, PHONE_CUSTOM1_DISPLAY_PROP);
		if (phone) {
			gchar *label = g_strdup_printf(_("Custom1 %s"),
				phone_disp_str ? phone_disp_str : (tmp = sip_tel_uri_denormalize(phone)));
			act = purple_menu_action_new(label, PURPLE_CALLBACK(sipe_buddy_menu_make_call_cb), (gpointer) phone, NULL);
			g_free(tmp);
			tmp = NULL;
			g_free(label);
			menu = g_list_prepend(menu, act);
		}
	}

	email = purple_blist_node_get_string(&buddy->node, EMAIL_PROP);
	if (email) {
		act = purple_menu_action_new(_("Send email..."),
					     PURPLE_CALLBACK(sipe_buddy_menu_send_email_cb),
					     NULL, NULL);
		menu = g_list_prepend(menu, act);
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
				g_strdup_printf(INDENT_MARKED_FMT, acc_level_name);
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
	const char *site;
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
				sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_DISPLAY_NAME, server_alias);
				sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_EMAIL, email);
				sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_WORK_PHONE, tel_uri);
				sipe_update_user_info(sipe_private, uri, SIPE_BUDDY_INFO_WORK_PHONE_DISPLAY, phone_number);
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
		server_alias = g_strdup(purple_buddy_get_server_alias(pbuddy));
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
		email = g_strdup(purple_blist_node_get_string(&pbuddy->node, EMAIL_PROP));
		if (email) {
			PURPLE_NOTIFY_USER_INFO_ADD_PAIR(info, _("Email address"), email);
		}
	}

	site = purple_blist_node_get_string(&pbuddy->node, SITE_PROP);
	if (site) {
		PURPLE_NOTIFY_USER_INFO_ADD_PAIR(info, _("Site"), site);
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
