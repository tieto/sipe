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

#include "core-depurple.h" /* Temporary for the core de-purple transition */

#include "http-conn.h"
#include "sipmsg.h"
#include "sip-csta.h"
#include "sip-soap.h"
#include "sipe-backend.h"
#include "sipe-buddy.h"
#include "sipe-cal.h"
#include "sipe-chat.h"
#include "sipe-conf.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-dialog.h"
#include "sipe-im.h"
#include "sipe-nls.h"
#include "sipe-ocs2007.h"
#include "sipe-session.h"
#include "sipe-status.h"
#include "sipe-utils.h"

#define _SIPE_NEED_ACTIVITIES /* ugly hack :-( */
#include "sipe.h"

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
} const sipe_activity_map[] =
{
/* This has nothing to do with Availability numbers, like 3500 (online).
 * Just a mapping of Communicator Activities to Purple statuses to be able display them in Pidgin.
 */
	{ SIPE_ACTIVITY_UNSET,		"unset",			NULL				},
	{ SIPE_ACTIVITY_ONLINE,		"online",			NULL				},
	{ SIPE_ACTIVITY_INACTIVE,	SIPE_STATUS_ID_IDLE,		N_("Inactive")			},
	{ SIPE_ACTIVITY_BUSY,		SIPE_STATUS_ID_BUSY,		N_("Busy")			},
	{ SIPE_ACTIVITY_BUSYIDLE,	SIPE_STATUS_ID_BUSYIDLE,	N_("Busy-Idle")			},
	{ SIPE_ACTIVITY_DND,		SIPE_STATUS_ID_DND,		NULL				},
	{ SIPE_ACTIVITY_BRB,		SIPE_STATUS_ID_BRB,		N_("Be right back")		},
	{ SIPE_ACTIVITY_AWAY,		"away",				NULL				},
	{ SIPE_ACTIVITY_LUNCH,		SIPE_STATUS_ID_LUNCH,		N_("Out to lunch")		},
	{ SIPE_ACTIVITY_OFFLINE,	"offline",			NULL				},
	{ SIPE_ACTIVITY_ON_PHONE,	SIPE_STATUS_ID_ON_PHONE,	N_("In a call")			},
	{ SIPE_ACTIVITY_IN_CONF,	SIPE_STATUS_ID_IN_CONF,		N_("In a conference")		},
	{ SIPE_ACTIVITY_IN_MEETING,	SIPE_STATUS_ID_IN_MEETING,	N_("In a meeting")		},
	{ SIPE_ACTIVITY_OOF,		"out-of-office",		N_("Out of office")		},
	{ SIPE_ACTIVITY_URGENT_ONLY,	"urgent-interruptions-only",	N_("Urgent interruptions only")	}
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

void sipe_set_status(struct sipe_core_private *sipe_private,
		     const gchar *status_id)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	g_free(sip->status);
	sip->status = g_strdup(status_id);
}

void sipe_set_unknown_status(struct sipe_core_private *sipe_private)
{
	sipe_set_status(sipe_private, SIPE_STATUS_ID_UNKNOWN);
}

void sipe_set_initial_status(struct sipe_core_private *sipe_private)
{
	sipe_set_status(sipe_private, SIPE_STATUS_ID_AVAILABLE);
}

void sipe_set_invisible_status(struct sipe_core_private *sipe_private)
{
	sipe_set_status(sipe_private, SIPE_STATUS_ID_INVISIBLE);
}

sipe_activity sipe_activity_from_token(const gchar *token)
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

	return sipe_activity_description(sipe_activity_from_token(token));
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

/**
 * 2005-style Activity and Availability.
 *
 * [MS-SIP] 2.2.1
 *
 * @param activity	2005 aggregated activity.    Ex.: 600
 * @param availablity	2005 aggregated availablity. Ex.: 300
 *
 * The values define the starting point of a range
 */
#define SIPE_OCS2005_ACTIVITY_UNKNOWN       0
#define SIPE_OCS2005_ACTIVITY_AWAY        100
#define SIPE_OCS2005_ACTIVITY_LUNCH       150
#define SIPE_OCS2005_ACTIVITY_IDLE        200
#define SIPE_OCS2005_ACTIVITY_BRB         300
#define SIPE_OCS2005_ACTIVITY_AVAILABLE   400 /* user is active */
#define SIPE_OCS2005_ACTIVITY_ON_PHONE    500 /* user is participating in a communcation session */
#define SIPE_OCS2005_ACTIVITY_BUSY        600
#define SIPE_OCS2005_ACTIVITY_AWAY2       700
#define SIPE_OCS2005_ACTIVITY_AVAILABLE2  800

#define SIPE_OCS2005_AVAILABILITY_OFFLINE   0
#define SIPE_OCS2005_AVAILABILITY_MAYBE   100
#define SIPE_OCS2005_AVAILABILITY_ONLINE  300
guint sipe_ocs2005_activity_from_status(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	const gchar *status = sip->status;

	if (sipe_strequal(status, SIPE_STATUS_ID_AWAY)) {
		return(SIPE_OCS2005_ACTIVITY_AWAY);
	/*} else if (sipe_strequal(status, SIPE_STATUS_ID_LUNCH)) {
		return(SIPE_OCS2005_ACTIVITY_LUNCH); */
	} else if (sipe_strequal(status, SIPE_STATUS_ID_BRB)) {
		return(SIPE_OCS2005_ACTIVITY_BRB);
	} else if (sipe_strequal(status, SIPE_STATUS_ID_AVAILABLE)) {
		return(SIPE_OCS2005_ACTIVITY_AVAILABLE);
	/*} else if (sipe_strequal(status, SIPE_STATUS_ID_ON_PHONE)) {
		return(SIPE_OCS2005_ACTIVITY_ON_PHONE); */
	} else if (sipe_strequal(status, SIPE_STATUS_ID_BUSY) ||
		   sipe_strequal(status, SIPE_STATUS_ID_DND)) {
		return(SIPE_OCS2005_ACTIVITY_BUSY);
	} else if (sipe_strequal(status, SIPE_STATUS_ID_INVISIBLE) ||
		   sipe_strequal(status, SIPE_STATUS_ID_OFFLINE)) {
		return(SIPE_OCS2005_ACTIVITY_AWAY);
	} else {
		return(SIPE_OCS2005_ACTIVITY_AVAILABLE);
	}
}

guint sipe_ocs2005_availability_from_status(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	const gchar *status = sip->status;

	if (sipe_strequal(status, SIPE_STATUS_ID_INVISIBLE) ||
	    sipe_strequal(status, SIPE_STATUS_ID_OFFLINE))
		return(SIPE_OCS2005_AVAILABILITY_OFFLINE);
	else
		return(SIPE_OCS2005_AVAILABILITY_ONLINE);
}

const gchar *sipe_ocs2005_status_from_activity_availability(guint activity,
							    guint availability)
{
	if (availability < SIPE_OCS2005_AVAILABILITY_MAYBE) {
		return(SIPE_STATUS_ID_OFFLINE);
	} else if (activity < SIPE_OCS2005_ACTIVITY_LUNCH) {
		return(SIPE_STATUS_ID_AWAY);
	} else if (activity < SIPE_OCS2005_ACTIVITY_IDLE) {
		//return(SIPE_STATUS_ID_LUNCH);
		return(SIPE_STATUS_ID_AWAY);
	} else if (activity < SIPE_OCS2005_ACTIVITY_BRB) {
		//return(SIPE_STATUS_ID_IDLE);
		return(SIPE_STATUS_ID_AWAY);
	} else if (activity < SIPE_OCS2005_ACTIVITY_AVAILABLE) {
		return(SIPE_STATUS_ID_BRB);
	} else if (activity < SIPE_OCS2005_ACTIVITY_ON_PHONE) {
		return(SIPE_STATUS_ID_AVAILABLE);
	} else if (activity < SIPE_OCS2005_ACTIVITY_BUSY) {
		//return(SIPE_STATUS_ID_ON_PHONE);
		return(SIPE_STATUS_ID_BUSY);
	} else if (activity < SIPE_OCS2005_ACTIVITY_AWAY2) {
		return(SIPE_STATUS_ID_BUSY);
	} else if (activity < SIPE_OCS2005_ACTIVITY_AVAILABLE2) {
		return(SIPE_STATUS_ID_AWAY);
	} else {
		return(SIPE_STATUS_ID_AVAILABLE);
	}
}

const gchar *sipe_ocs2005_activity_description(guint activity)
{
	if ((activity >= SIPE_OCS2005_ACTIVITY_LUNCH) &&
	    (activity <  SIPE_OCS2005_ACTIVITY_IDLE)) {
		return(sipe_activity_description(SIPE_ACTIVITY_LUNCH));
	} else if ((activity >= SIPE_OCS2005_ACTIVITY_IDLE) &&
		   (activity <  SIPE_OCS2005_ACTIVITY_BRB)) {
		return(sipe_activity_description(SIPE_ACTIVITY_INACTIVE));
	} else if ((activity >= SIPE_OCS2005_ACTIVITY_ON_PHONE) &&
		   (activity <  SIPE_OCS2005_ACTIVITY_BUSY)) {
		return(sipe_activity_description(SIPE_ACTIVITY_ON_PHONE));
	} else {
		return(NULL);
	}
}

/**
 * 2007-style Activity and Availability.
 *
 * [MS-PRES] 3.7.5.5
 *
 * Conversion of legacyInterop elements and attributes to MSRTC elements and attributes.
 *
 * The values define the starting point of a range
 */
#define SIPE_OCS2007_LEGACY_AVAILIBILITY_ONLINE    3000
#define SIPE_OCS2007_LEGACY_AVAILIBILITY_AWAY      4500
#define SIPE_OCS2007_LEGACY_AVAILIBILITY_ON_PHONE  6000
#define SIPE_OCS2007_LEGACY_AVAILIBILITY_BUSY      7500
#define SIPE_OCS2007_LEGACY_AVAILIBILITY_DND       9000 /* do not disturb */
#define SIPE_OCS2007_LEGACY_AVAILIBILITY_BRB      12000 /* be right back */
#define SIPE_OCS2007_LEGACY_AVAILIBILITY_AWAY2    15000
#define SIPE_OCS2007_LEGACY_AVAILIBILITY_OFFLINE  18000
const gchar *sipe_ocs2007_status_from_legacy_availability(guint availability)
{
	if (availability < SIPE_OCS2007_LEGACY_AVAILIBILITY_ONLINE) {
		return(SIPE_STATUS_ID_OFFLINE);
	} else if (availability < SIPE_OCS2007_LEGACY_AVAILIBILITY_AWAY) {
		return(SIPE_STATUS_ID_AVAILABLE);
	} else if (availability < SIPE_OCS2007_LEGACY_AVAILIBILITY_ON_PHONE) {
		//return(SIPE_STATUS_ID_IDLE);
		return(SIPE_STATUS_ID_AVAILABLE);
	} else if (availability < SIPE_OCS2007_LEGACY_AVAILIBILITY_BUSY) {
		return(SIPE_STATUS_ID_BUSY);
	} else if (availability < SIPE_OCS2007_LEGACY_AVAILIBILITY_DND) {
		//return(SIPE_STATUS_ID_BUSYIDLE);
		return(SIPE_STATUS_ID_BUSY);
	} else if (availability < SIPE_OCS2007_LEGACY_AVAILIBILITY_BRB) {
		return(SIPE_STATUS_ID_DND);
	} else if (availability < SIPE_OCS2007_LEGACY_AVAILIBILITY_AWAY2) {
		return(SIPE_STATUS_ID_BRB);
	} else if (availability < SIPE_OCS2007_LEGACY_AVAILIBILITY_OFFLINE) {
		return(SIPE_STATUS_ID_AWAY);
	} else {
		return(SIPE_STATUS_ID_OFFLINE);
	}
}

const gchar *sipe_ocs2007_legacy_activity_description(guint availability)
{
	if ((availability >= SIPE_OCS2007_LEGACY_AVAILIBILITY_AWAY) &&
	    (availability <  SIPE_OCS2007_LEGACY_AVAILIBILITY_ON_PHONE)) {
		return(sipe_activity_description(SIPE_ACTIVITY_INACTIVE));
	} else if ((availability >= SIPE_OCS2007_LEGACY_AVAILIBILITY_BUSY) &&
		   (availability <  SIPE_OCS2007_LEGACY_AVAILIBILITY_DND)) {
		return(sipe_activity_description(SIPE_ACTIVITY_BUSYIDLE));
	} else {
		return(NULL);
	}
}

/**
 * @param sipe_status_id (in)
 * @param activity_token (out) [only sipe-ocs2005.c/send_presence_soap()
 *                              requests this token]
 */
#define SIPE_OCS2007_AVAILABILITY_UNKNOWN     0
#define SIPE_OCS2007_AVAILABILITY_ONLINE   3500
#define SIPE_OCS2007_AVAILABILITY_BUSY     6500
#define SIPE_OCS2007_AVAILABILITY_DND      9500 /* do not disturb */
#define SIPE_OCS2007_AVAILABILITY_BRB     12500 /* be right back */
#define SIPE_OCS2007_AVAILABILITY_AWAY    15500
#define SIPE_OCS2007_AVAILABILITY_OFFLINE 18500
guint sipe_ocs2007_availability_from_status(const gchar *sipe_status_id,
					    const gchar **activity_token)
{
	guint availability;
	sipe_activity activity;

	if (sipe_strequal(sipe_status_id, SIPE_STATUS_ID_AWAY)) {
		availability = SIPE_OCS2007_AVAILABILITY_AWAY;
		activity     = SIPE_ACTIVITY_AWAY;
	} else if (sipe_strequal(sipe_status_id, SIPE_STATUS_ID_BRB)) {
		availability = SIPE_OCS2007_AVAILABILITY_BRB;
		activity     = SIPE_ACTIVITY_BRB;
	} else if (sipe_strequal(sipe_status_id, SIPE_STATUS_ID_DND)) {
		availability = SIPE_OCS2007_AVAILABILITY_DND;
		activity     = SIPE_ACTIVITY_DND;
	} else if (sipe_strequal(sipe_status_id, SIPE_STATUS_ID_BUSY)) {
		availability = SIPE_OCS2007_AVAILABILITY_BUSY;
		activity     = SIPE_ACTIVITY_BUSY;
	} else if (sipe_strequal(sipe_status_id, SIPE_STATUS_ID_AVAILABLE)) {
		availability = SIPE_OCS2007_AVAILABILITY_ONLINE;
		activity     = SIPE_ACTIVITY_ONLINE;
	} else if (sipe_strequal(sipe_status_id, SIPE_STATUS_ID_UNKNOWN)) {
		availability = SIPE_OCS2007_AVAILABILITY_UNKNOWN;
		activity     = SIPE_ACTIVITY_UNSET;
	} else {
		/* Offline or invisible */
		availability = SIPE_OCS2007_AVAILABILITY_OFFLINE;
		activity     = SIPE_ACTIVITY_OFFLINE;
	}

	if (activity_token) {
		*activity_token = sipe_activity_to_token(activity);
	}

	return(availability);
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
			sipe_status_changed_by_user(sipe_private) ? "USER" : "MACHINE");

	sipe_cal_presence_publish(sipe_private, FALSE);
}

void sipe_apply_calendar_status(struct sipe_core_private *sipe_private,
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
		    && SIPE_OCS2007_AVAILABILITY_BUSY >= sipe_ocs2007_availability_from_status(status_id, NULL))
		{
			status_id = SIPE_STATUS_ID_BUSY;
			g_free(sbuddy->activity);
			sbuddy->activity = g_strdup(sipe_activity_description(SIPE_ACTIVITY_IN_MEETING));
		}
		avail = sipe_ocs2007_availability_from_status(status_id, NULL);

		SIPE_DEBUG_INFO("sipe_apply_calendar_status: activity_since  : %s", asctime(localtime(&sbuddy->activity_since)));
		if (cal_avail_since > sbuddy->activity_since) {
			if (cal_status == SIPE_CAL_OOF
			    && avail >= SIPE_OCS2007_LEGACY_AVAILIBILITY_AWAY2) /* 12000 in 2007 */
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
			/* do not let offline status switch us off */
			status_id = SIPE_STATUS_ID_INVISIBLE;
		}

		sipe_status_and_note(sipe_private, status_id);
	}
	g_free(self_uri);
}

/* temporary function */
void sipe_purple_setup(struct sipe_core_public *sipe_public,
		       PurpleConnection *gc)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA;
	sip->gc = gc;
	sip->account = purple_connection_get_account(gc);
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
	PurpleGroup * group = purple_find_group(group_name);

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy *)node;

	SIPE_DEBUG_INFO("sipe_buddy_menu_copy_to_cb: copying %s to %s",
			buddy->name, group_name);

	b = purple_find_buddy_in_group(buddy->account, buddy->name, group);
	if (!b)
		b = purple_blist_add_buddy_clone(group, buddy);

	if (b && group) {
		PurpleConnection *gc = purple_account_get_connection(b->account);

		sipe_core_buddy_add(PURPLE_GC_TO_SIPE_CORE_PUBLIC,
				    b->name,
				    group->name);
	}
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
void sipe_blist_menu_free_containers(struct sipe_core_private *sipe_private)
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

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
