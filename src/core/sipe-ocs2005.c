/**
 * @file sipe-ocs2005.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-2013 SIPE Project <http://sipe.sourceforge.net/>
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
 *
 *
 * OCS2005 specific code
 *
 */

#include <time.h>

#include <glib.h>

#include "sipe-common.h"
#include "sip-soap.h"
#include "sipe-backend.h"
#include "sipe-buddy.h"
#include "sipe-cal.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-ews.h"
#include "sipe-ocs2005.h"
#include "sipe-ocs2007.h"
#include "sipe-schedule.h"
#include "sipe-status.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

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
static guint sipe_ocs2005_activity_from_status(struct sipe_core_private *sipe_private)
{
	const gchar *status = sipe_private->status;

	if (sipe_strequal(status, sipe_status_activity_to_token(SIPE_ACTIVITY_AWAY))) {
		return(SIPE_OCS2005_ACTIVITY_AWAY);
	/*} else if (sipe_strequal(status, sipe_status_activity_to_token(SIPE_ACTIVITY_LUNCH))) {
		return(SIPE_OCS2005_ACTIVITY_LUNCH); */
	} else if (sipe_strequal(status, sipe_status_activity_to_token(SIPE_ACTIVITY_BRB))) {
		return(SIPE_OCS2005_ACTIVITY_BRB);
	} else if (sipe_strequal(status, sipe_status_activity_to_token(SIPE_ACTIVITY_AVAILABLE))) {
		return(SIPE_OCS2005_ACTIVITY_AVAILABLE);
	/*} else if (sipe_strequal(status, sipe_status_activity_to_token(SIPE_ACTIVITY_ON_PHONE))) {
		return(SIPE_OCS2005_ACTIVITY_ON_PHONE); */
	} else if (sipe_strequal(status, sipe_status_activity_to_token(SIPE_ACTIVITY_BUSY)) ||
		   sipe_strequal(status, sipe_status_activity_to_token(SIPE_ACTIVITY_DND))) {
		return(SIPE_OCS2005_ACTIVITY_BUSY);
	} else if (sipe_strequal(status, sipe_status_activity_to_token(SIPE_ACTIVITY_INVISIBLE)) ||
		   sipe_strequal(status, sipe_status_activity_to_token(SIPE_ACTIVITY_OFFLINE))) {
		return(SIPE_OCS2005_ACTIVITY_AWAY);
	} else {
		return(SIPE_OCS2005_ACTIVITY_AVAILABLE);
	}
}

static guint sipe_ocs2005_availability_from_status(struct sipe_core_private *sipe_private)
{
	const gchar *status = sipe_private->status;

	if (sipe_strequal(status, sipe_status_activity_to_token(SIPE_ACTIVITY_INVISIBLE)) ||
	    sipe_strequal(status, sipe_status_activity_to_token(SIPE_ACTIVITY_OFFLINE)))
		return(SIPE_OCS2005_AVAILABILITY_OFFLINE);
	else
		return(SIPE_OCS2005_AVAILABILITY_ONLINE);
}

const gchar *sipe_ocs2005_status_from_activity_availability(guint activity,
							    guint availability)
{
	guint type;

	if (availability < SIPE_OCS2005_AVAILABILITY_MAYBE) {
		type = SIPE_ACTIVITY_OFFLINE;
	} else if (activity < SIPE_OCS2005_ACTIVITY_LUNCH) {
		type = SIPE_ACTIVITY_AWAY;
	} else if (activity < SIPE_OCS2005_ACTIVITY_IDLE) {
		//type = SIPE_ACTIVITY_LUNCH;
		type = SIPE_ACTIVITY_AWAY;
	} else if (activity < SIPE_OCS2005_ACTIVITY_BRB) {
		//type = SIPE_ACTIVITY_IDLE;
		type = SIPE_ACTIVITY_AWAY;
	} else if (activity < SIPE_OCS2005_ACTIVITY_AVAILABLE) {
		type = SIPE_ACTIVITY_BRB;
	} else if (activity < SIPE_OCS2005_ACTIVITY_ON_PHONE) {
		type = SIPE_ACTIVITY_AVAILABLE;
	} else if (activity < SIPE_OCS2005_ACTIVITY_BUSY) {
		//type = SIPE_ACTIVITY_ON_PHONE;
		type = SIPE_ACTIVITY_BUSY;
	} else if (activity < SIPE_OCS2005_ACTIVITY_AWAY2) {
		type = SIPE_ACTIVITY_BUSY;
	} else if (activity < SIPE_OCS2005_ACTIVITY_AVAILABLE2) {
		type = SIPE_ACTIVITY_AWAY;
	} else {
		type = SIPE_ACTIVITY_AVAILABLE;
	}

	return(sipe_status_activity_to_token(type));
}

const gchar *sipe_ocs2005_activity_description(guint activity)
{
	if ((activity >= SIPE_OCS2005_ACTIVITY_LUNCH) &&
	    (activity <  SIPE_OCS2005_ACTIVITY_IDLE)) {
		return(sipe_core_activity_description(SIPE_ACTIVITY_LUNCH));
	} else if ((activity >= SIPE_OCS2005_ACTIVITY_IDLE) &&
		   (activity <  SIPE_OCS2005_ACTIVITY_BRB)) {
		return(sipe_core_activity_description(SIPE_ACTIVITY_INACTIVE));
	} else if ((activity >= SIPE_OCS2005_ACTIVITY_ON_PHONE) &&
		   (activity <  SIPE_OCS2005_ACTIVITY_BUSY)) {
		return(sipe_core_activity_description(SIPE_ACTIVITY_ON_PHONE));
	} else {
		return(NULL);
	}
}

void sipe_ocs2005_user_info_has_updated(struct sipe_core_private *sipe_private,
					const sipe_xml *xn_userinfo)
{
	const sipe_xml *xn_states;

	g_free(sipe_private->ocs2005_user_states);
	sipe_private->ocs2005_user_states = NULL;
	if ((xn_states = sipe_xml_child(xn_userinfo, "states")) != NULL) {
		gchar *orig = sipe_private->ocs2005_user_states = sipe_xml_stringify(xn_states);

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
	if (!SIPE_CORE_PRIVATE_FLAG_IS(INITIAL_PUBLISH)) {
		sipe_ocs2005_presence_publish(sipe_private, FALSE);
		/* dalayed run */
		sipe_cal_delayed_calendar_update(sipe_private);
	}
}

static gboolean sipe_is_user_available(struct sipe_core_private *sipe_private)
{
	return(sipe_strequal(sipe_private->status,
			     sipe_status_activity_to_token(SIPE_ACTIVITY_AVAILABLE)));
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

static void send_presence_soap(struct sipe_core_private *sipe_private,
			       gboolean do_publish_calendar,
			       gboolean do_reset_status)
{
	struct sipe_calendar* cal = sipe_private->calendar;
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
	gboolean pub_oof = cal && oof_note && (!sipe_private->note || cal->updated > sipe_private->note_since);

	if (oof_note && sipe_private->note) {
		SIPE_DEBUG_INFO("cal->oof_start           : %s", asctime(localtime(&(cal->oof_start))));
		SIPE_DEBUG_INFO("sipe_private->note_since : %s", asctime(localtime(&(sipe_private->note_since))));
	}

	SIPE_DEBUG_INFO("sipe_private->note  : %s", sipe_private->note ? sipe_private->note : "");

	if (!SIPE_CORE_PRIVATE_FLAG_IS(INITIAL_PUBLISH) ||
	    do_reset_status)
		sipe_status_set_activity(sipe_private, SIPE_ACTIVITY_AVAILABLE);

	/* Note */
	if (pub_oof) {
		note_pub = oof_note;
		res_oof = SIPE_SOAP_SET_PRESENCE_OOF_XML;
		cal->published = TRUE;
	} else if (sipe_private->note) {
		if (SIPE_CORE_PRIVATE_FLAG_IS(OOF_NOTE) &&
		    !oof_note) { /* stale OOF note, as it's not present in cal already */
			g_free(sipe_private->note);
			sipe_private->note = NULL;
			SIPE_CORE_PRIVATE_FLAG_UNSET(OOF_NOTE);
			sipe_private->note_since = 0;
		} else {
			note_pub = sipe_private->note;
			res_oof = SIPE_CORE_PRIVATE_FLAG_IS(OOF_NOTE) ? SIPE_SOAP_SET_PRESENCE_OOF_XML : "";
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
		if (sipe_status_changed_by_user(sipe_private) &&
		    !do_publish_calendar &&
		    SIPE_CORE_PRIVATE_FLAG_IS(INITIAL_PUBLISH)) {
			const gchar *activity_token;
			int avail_2007 = sipe_ocs2007_availability_from_status(sipe_private->status,
									       &activity_token);

			states = g_strdup_printf(SIPE_SOAP_SET_PRESENCE_STATES,
						avail_2007,
						since_time_str,
						epid,
						activity_token);
		}
		else /* preserve existing publication */
		{
			if (sipe_private->ocs2005_user_states) {
				states = g_strdup(sipe_private->ocs2005_user_states);
			}
		}
	} else {
		/* do nothing - then User state will be erased */
	}
	SIPE_CORE_PRIVATE_FLAG_SET(INITIAL_PUBLISH);

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

	user_input = (sipe_status_changed_by_user(sipe_private) ||
		      sipe_is_user_available(sipe_private)) ?
		"active" : "idle";

	/* generate XML */
	body = g_strdup_printf(SIPE_SOAP_SET_PRESENCE,
			       sipe_private->username,
			       sipe_ocs2005_availability_from_status(sipe_private),
			       sipe_ocs2005_activity_from_status(sipe_private),
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

void sipe_ocs2005_presence_publish(struct sipe_core_private *sipe_private,
				   gboolean do_publish_calendar)
{
	send_presence_soap(sipe_private, do_publish_calendar, FALSE);
}

void sipe_ocs2005_reset_status(struct sipe_core_private *sipe_private)
{
	send_presence_soap(sipe_private, FALSE, TRUE);
}

void sipe_ocs2005_apply_calendar_status(struct sipe_core_private *sipe_private,
					struct sipe_buddy *sbuddy,
					const char *status_id)
{
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

		if ((cal_status == SIPE_CAL_BUSY) &&
		    (cal_avail_since > sbuddy->user_avail_since) &&
		    sipe_ocs2007_status_is_busy(status_id)) {
			status_id = sipe_status_activity_to_token(SIPE_ACTIVITY_BUSY);
			g_free(sbuddy->activity);
			sbuddy->activity = g_strdup(sipe_core_activity_description(SIPE_ACTIVITY_IN_MEETING));
		}
		avail = sipe_ocs2007_availability_from_status(status_id, NULL);

		SIPE_DEBUG_INFO("sipe_apply_calendar_status: activity_since  : %s", asctime(localtime(&sbuddy->activity_since)));
		if (cal_avail_since > sbuddy->activity_since) {
			if ((cal_status == SIPE_CAL_OOF) &&
			    sipe_ocs2007_availability_is_away(avail)) {
				g_free(sbuddy->activity);
				sbuddy->activity = g_strdup(sipe_core_activity_description(SIPE_ACTIVITY_OOF));
			}
		}
	}

	/* then set status_id actually */
	SIPE_DEBUG_INFO("sipe_apply_calendar_status: to %s for %s", status_id, sbuddy->name ? sbuddy->name : "" );
	sipe_backend_buddy_set_status(SIPE_CORE_PUBLIC, sbuddy->name,
				      sipe_status_token_to_activity(status_id));

	/* set our account state to the one in roaming (including calendar info) */
	self_uri = sip_uri_self(sipe_private);
	if (SIPE_CORE_PRIVATE_FLAG_IS(INITIAL_PUBLISH) &&
	    sipe_strcase_equal(sbuddy->name, self_uri)) {
		if (sipe_strequal(status_id, sipe_status_activity_to_token(SIPE_ACTIVITY_OFFLINE))) {
			/* do not let offline status switch us off */
			status_id = sipe_status_activity_to_token(SIPE_ACTIVITY_INVISIBLE);
		}

		sipe_status_and_note(sipe_private, status_id);
	}
	g_free(self_uri);
}

static void update_calendar_status_cb(SIPE_UNUSED_PARAMETER char *name,
				      struct sipe_buddy *sbuddy,
				      struct sipe_core_private *sipe_private)
{
	sipe_ocs2005_apply_calendar_status(sipe_private, sbuddy, NULL);
}

/**
 * Updates contact's status
 * based on their calendar information.
 */
static void update_calendar_status(struct sipe_core_private *sipe_private,
				   SIPE_UNUSED_PARAMETER void *unused)
{
	SIPE_DEBUG_INFO_NOFORMAT("update_calendar_status() started.");
	sipe_buddy_foreach(sipe_private,
			   (GHFunc) update_calendar_status_cb,
			   sipe_private);

	/* repeat scheduling */
	sipe_ocs2005_schedule_status_update(sipe_private,
					    time(NULL) + 3 * 60 /* 3 min */);
}

/**
 * Schedules process of contacts' status update
 * based on their calendar information.
 * Should be scheduled to the beginning of every
 * 15 min interval, like:
 * 13:00, 13:15, 13:30, 13:45, etc.
 */
void sipe_ocs2005_schedule_status_update(struct sipe_core_private *sipe_private,
					 time_t calculate_from)
{
#define SCHEDULE_INTERVAL 15 * 60 /* 15 min */

	/* start of the beginning of closest 15 min interval. */
	time_t next_start = (calculate_from / SCHEDULE_INTERVAL + 1) * SCHEDULE_INTERVAL;

	SIPE_DEBUG_INFO("sipe_ocs2005_schedule_status_update: calculate_from time: %s",
			asctime(localtime(&calculate_from)));
	SIPE_DEBUG_INFO("sipe_ocs2005_schedule_status_update: next start time    : %s",
			asctime(localtime(&next_start)));

	sipe_schedule_seconds(sipe_private,
			      "<+2005-cal-status>",
			      NULL,
			      next_start - time(NULL),
			      update_calendar_status,
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
