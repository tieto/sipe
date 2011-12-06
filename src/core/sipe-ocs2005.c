/**
 * @file sipe-ocs2005.c
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
 *
 *
 * OCS2005 specific code
 *
 */

#include <time.h>

#include <glib.h>

#include "sipe-common.h"
#include "http-conn.h" /* sipe-cal.h requires this */
#include "sip-soap.h"
#include "sipe-backend.h"
#include "sipe-cal.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-ews.h"
#include "sipe-ocs2005.h"
#include "sipe-schedule.h"
#include "sipe-status.h"
#include "sipe-utils.h"
#include "sipe-xml.h"
#include "sipe.h"

void sipe_ocs2005_user_info_has_updated(struct sipe_core_private *sipe_private,
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
		sipe_ocs2005_presence_publish(sipe_private, FALSE);
		/* dalayed run */
		sipe_cal_delayed_calendar_update(sipe_private);
	}
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
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	struct sipe_calendar* cal = sip->cal;
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
		if (sipe_status_changed_by_user(sipe_private) && !do_publish_calendar && sip->initial_state_published)
		{
			const gchar *activity_token;
			int avail_2007 = sipe_ocs2007_availability_from_status(sip->status,
									       &activity_token);

			states = g_strdup_printf(SIPE_SOAP_SET_PRESENCE_STATES,
						avail_2007,
						since_time_str,
						epid,
						activity_token);
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
	return send_presence_soap(sipe_private, do_publish_calendar, FALSE);
}

void sipe_ocs2005_reset_status(struct sipe_core_private *sipe_private)
{
	return send_presence_soap(sipe_private, FALSE, TRUE);
}

static void update_calendar_status_cb(SIPE_UNUSED_PARAMETER char *name,
				      struct sipe_buddy *sbuddy,
				      struct sipe_core_private *sipe_private)
{
	sipe_apply_calendar_status(sipe_private, sbuddy, NULL);
}

/**
 * Updates contact's status
 * based on their calendar information.
 */
static void update_calendar_status(struct sipe_core_private *sipe_private,
				   SIPE_UNUSED_PARAMETER void *unused)
{
	SIPE_DEBUG_INFO_NOFORMAT("update_calendar_status() started.");
	g_hash_table_foreach(sipe_private->buddies,
			     (GHFunc)update_calendar_status_cb,
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
