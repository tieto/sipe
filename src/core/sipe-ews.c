/**
 * @file sipe-ews.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2013 SIPE Project <http://sipe.sourceforge.net/>
 * Copyright (C) 2010, 2009 pier11 <pier11@operamail.com>
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

/**
For communication with Exchange 2007/2010 Web Server/Web Services:

1) Autodiscover (HTTPS POST request). With redirect support. XML content.
1.1) DNS SRV record _autodiscover._tcp.<domain> may also be resolved.
2) Availability Web service (SOAP = HTTPS POST + XML) call.
3) Out of Office (OOF) Web Service (SOAP = HTTPS POST + XML) call.
4) Web server authentication required - NTLM and/or Negotiate (Kerberos).

Note: ews - EWS stands for Exchange Web Services.

It will be able to retrieve our Calendar information (FreeBusy, WorkingHours,
Meetings Subject and Location, Is_Meeting) as well as our Out of Office (OOF) note
from Exchange Web Services for subsequent publishing.

Ref. for more implementation details:
http://sourceforge.net/projects/sipe/forums/forum/688535/topic/3403462

Similar functionality for Lotus Notes/Domino, iCalendar/CalDAV/Google would
be great to implement too.
*/

#include <string.h>
#include <time.h>

#include <glib.h>

#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-cal.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-ews.h"
#include "sipe-ews-autodiscover.h"
#include "sipe-http.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

/**
 * GetUserOofSettingsRequest SOAP request to Exchange Web Services
 * to obtain our Out-of-office (OOF) information.
 * @param email (%s) Ex.: alice@cosmo.local
 */
#define SIPE_EWS_USER_OOF_SETTINGS_REQUEST \
"<?xml version=\"1.0\" encoding=\"utf-8\"?>"\
"<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">"\
  "<soap:Body>"\
    "<GetUserOofSettingsRequest xmlns=\"http://schemas.microsoft.com/exchange/services/2006/messages\">"\
      "<Mailbox xmlns=\"http://schemas.microsoft.com/exchange/services/2006/types\">"\
        "<Address>%s</Address>"\
      "</Mailbox>"\
    "</GetUserOofSettingsRequest>"\
  "</soap:Body>"\
"</soap:Envelope>"

/**
 * GetUserAvailabilityRequest SOAP request to Exchange Web Services
 * to obtain our Availability (FreeBusy, WorkingHours, Meetings) information.
 * @param email      (%s) Ex.: alice@cosmo.local
 * @param start_time (%s) Ex.: 2009-12-06T00:00:00
 * @param end_time   (%s) Ex.: 2009-12-09T23:59:59
 */
#define SIPE_EWS_USER_AVAILABILITY_REQUEST \
"<?xml version=\"1.0\" encoding=\"utf-8\"?>"\
"<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\""\
              " xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\""\
              " xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\""\
              " xmlns:t=\"http://schemas.microsoft.com/exchange/services/2006/types\">"\
  "<soap:Body>"\
    "<GetUserAvailabilityRequest xmlns=\"http://schemas.microsoft.com/exchange/services/2006/messages\""\
                " xmlns:t=\"http://schemas.microsoft.com/exchange/services/2006/types\">"\
      "<t:TimeZone xmlns=\"http://schemas.microsoft.com/exchange/services/2006/types\">"\
        "<Bias>0</Bias>"\
        "<StandardTime>"\
          "<Bias>0</Bias>"\
          "<Time>00:00:00</Time>"\
          "<DayOrder>0</DayOrder>"\
          "<Month>0</Month>"\
          "<DayOfWeek>Sunday</DayOfWeek>"\
        "</StandardTime>"\
        "<DaylightTime>"\
          "<Bias>0</Bias>"\
          "<Time>00:00:00</Time>"\
          "<DayOrder>0</DayOrder>"\
          "<Month>0</Month>"\
          "<DayOfWeek>Sunday</DayOfWeek>"\
        "</DaylightTime>"\
      "</t:TimeZone>"\
      "<MailboxDataArray>"\
        "<t:MailboxData>"\
          "<t:Email>"\
            "<t:Address>%s</t:Address>"\
          "</t:Email>"\
          "<t:AttendeeType>Required</t:AttendeeType>"\
          "<t:ExcludeConflicts>false</t:ExcludeConflicts>"\
        "</t:MailboxData>"\
      "</MailboxDataArray>"\
      "<t:FreeBusyViewOptions>"\
        "<t:TimeWindow>"\
          "<t:StartTime>%s</t:StartTime>"\
          "<t:EndTime>%s</t:EndTime>"\
        "</t:TimeWindow>"\
        "<t:MergedFreeBusyIntervalInMinutes>15</t:MergedFreeBusyIntervalInMinutes>"\
        "<t:RequestedView>DetailedMerged</t:RequestedView>"\
      "</t:FreeBusyViewOptions>"\
    "</GetUserAvailabilityRequest>"\
  "</soap:Body>"\
"</soap:Envelope>"

#define SIPE_EWS_STATE_NONE			 0
#define SIPE_EWS_STATE_IDLE			 1
#define SIPE_EWS_STATE_AVAILABILITY_SUCCESS	 2
#define SIPE_EWS_STATE_AVAILABILITY_FAILURE	-2
#define SIPE_EWS_STATE_OOF_SUCCESS		 3
#define SIPE_EWS_STATE_OOF_FAILURE		-3

char *
sipe_ews_get_oof_note(struct sipe_calendar *cal)
{
	time_t now = time(NULL);

	if (!cal || !cal->oof_state) return NULL;

	if (sipe_strequal(cal->oof_state, "Enabled") ||
	    (sipe_strequal(cal->oof_state, "Scheduled") && now >= cal->oof_start && now <= cal->oof_end))
	{
		return cal->oof_note;
	}
	else
	{
		return NULL;
	}
}

static void
sipe_ews_run_state_machine(struct sipe_calendar *cal);

static void sipe_ews_process_avail_response(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private,
					    guint status,
					    SIPE_UNUSED_PARAMETER GSList *headers,
					    const gchar *body,
					    gpointer data)
{
	struct sipe_calendar *cal = data;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_ews_process_avail_response: cb started.");

	cal->request = NULL;

	if ((status == SIPE_HTTP_STATUS_OK) && body) {
		const sipe_xml *node;
		const sipe_xml *resp;
		/** ref: [MS-OXWAVLS] */
		sipe_xml *xml = sipe_xml_parse(body, strlen(body));
		/*
Envelope/Body/GetUserAvailabilityResponse/FreeBusyResponseArray/FreeBusyResponse/ResponseMessage@ResponseClass="Success"
Envelope/Body/GetUserAvailabilityResponse/FreeBusyResponseArray/FreeBusyResponse/FreeBusyView/MergedFreeBusy
Envelope/Body/GetUserAvailabilityResponse/FreeBusyResponseArray/FreeBusyResponse/FreeBusyView/CalendarEventArray/CalendarEvent
Envelope/Body/GetUserAvailabilityResponse/FreeBusyResponseArray/FreeBusyResponse/FreeBusyView/WorkingHours
		 */
		resp = sipe_xml_child(xml, "Body/GetUserAvailabilityResponse/FreeBusyResponseArray/FreeBusyResponse");
		if (!resp) return; /* rather soap:Fault */
		if (!sipe_strequal(sipe_xml_attribute(sipe_xml_child(resp, "ResponseMessage"), "ResponseClass"), "Success")) {
			return; /* Error response */
		}

		/* MergedFreeBusy */
		g_free(cal->free_busy);
		cal->free_busy = sipe_xml_data(sipe_xml_child(resp, "FreeBusyView/MergedFreeBusy"));

		/* WorkingHours */
		node = sipe_xml_child(resp, "FreeBusyView/WorkingHours");
		g_free(cal->working_hours_xml_str);
		cal->working_hours_xml_str = sipe_xml_stringify(node);
		SIPE_DEBUG_INFO("sipe_ews_process_avail_response: cal->working_hours_xml_str:\n%s",
				cal->working_hours_xml_str ? cal->working_hours_xml_str : "");

		sipe_cal_events_free(cal->cal_events);
		cal->cal_events = NULL;
		/* CalendarEvents */
		for (node = sipe_xml_child(resp, "FreeBusyView/CalendarEventArray/CalendarEvent");
		     node;
		     node = sipe_xml_twin(node))
		{
			char *tmp;
/*
      <CalendarEvent>
	<StartTime>2009-12-07T13:30:00</StartTime>
	<EndTime>2009-12-07T14:30:00</EndTime>
	<BusyType>Busy</BusyType>
	<CalendarEventDetails>
	  <ID>0000000...</ID>
	  <Subject>Lunch</Subject>
	  <Location>Cafe</Location>
	  <IsMeeting>false</IsMeeting>
	  <IsRecurring>true</IsRecurring>
	  <IsException>false</IsException>
	  <IsReminderSet>true</IsReminderSet>
	  <IsPrivate>false</IsPrivate>
	</CalendarEventDetails>
      </CalendarEvent>
*/
			struct sipe_cal_event *cal_event = g_new0(struct sipe_cal_event, 1);
			cal->cal_events = g_slist_append(cal->cal_events, cal_event);

			tmp = sipe_xml_data(sipe_xml_child(node, "StartTime"));
			cal_event->start_time = sipe_utils_str_to_time(tmp);
			g_free(tmp);

			tmp = sipe_xml_data(sipe_xml_child(node, "EndTime"));
			cal_event->end_time = sipe_utils_str_to_time(tmp);
			g_free(tmp);

			tmp = sipe_xml_data(sipe_xml_child(node, "BusyType"));
			if (sipe_strequal("Free", tmp)) {
				cal_event->cal_status = SIPE_CAL_FREE;
			} else if (sipe_strequal("Tentative", tmp)) {
				cal_event->cal_status = SIPE_CAL_TENTATIVE;
			} else if (sipe_strequal("Busy", tmp)) {
				cal_event->cal_status = SIPE_CAL_BUSY;
			} else if (sipe_strequal("OOF", tmp)) {
				cal_event->cal_status = SIPE_CAL_OOF;
			} else {
				cal_event->cal_status = SIPE_CAL_NO_DATA;
			}
			g_free(tmp);

			cal_event->subject = sipe_xml_data(sipe_xml_child(node, "CalendarEventDetails/Subject"));
			cal_event->location = sipe_xml_data(sipe_xml_child(node, "CalendarEventDetails/Location"));

			tmp = sipe_xml_data(sipe_xml_child(node, "CalendarEventDetails/IsMeeting"));
			cal_event->is_meeting = tmp ? sipe_strequal(tmp, "true") : TRUE;
			g_free(tmp);
		}

		sipe_xml_free(xml);

		cal->state = SIPE_EWS_STATE_AVAILABILITY_SUCCESS;
		sipe_ews_run_state_machine(cal);

	} else {
		cal->state = SIPE_EWS_STATE_AVAILABILITY_FAILURE;
		sipe_ews_run_state_machine(cal);
	}
}

static void sipe_ews_process_oof_response(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private,
					  guint status,
					  SIPE_UNUSED_PARAMETER GSList *headers,
					  const gchar *body,
					  gpointer data)
{
	struct sipe_calendar *cal = data;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_ews_process_oof_response: cb started.");

	cal->request = NULL;

	if ((status == SIPE_HTTP_STATUS_OK) && body) {
		char *old_note;
		const sipe_xml *resp;
		const sipe_xml *xn_duration;
		/** ref: [MS-OXWOOF] */
		sipe_xml *xml = sipe_xml_parse(body, strlen(body));
		/* Envelope/Body/GetUserOofSettingsResponse/ResponseMessage@ResponseClass="Success"
		 * Envelope/Body/GetUserOofSettingsResponse/OofSettings/OofState=Enabled
		 * Envelope/Body/GetUserOofSettingsResponse/OofSettings/Duration/StartTime
		 * Envelope/Body/GetUserOofSettingsResponse/OofSettings/Duration/EndTime
		 * Envelope/Body/GetUserOofSettingsResponse/OofSettings/InternalReply/Message
		 */
		resp = sipe_xml_child(xml, "Body/GetUserOofSettingsResponse");
		if (!resp) return; /* rather soap:Fault */
		if (!sipe_strequal(sipe_xml_attribute(sipe_xml_child(resp, "ResponseMessage"), "ResponseClass"), "Success")) {
			return; /* Error response */
		}

		g_free(cal->oof_state);
		cal->oof_state = sipe_xml_data(sipe_xml_child(resp, "OofSettings/OofState"));

		old_note = cal->oof_note;
		cal->oof_note = NULL;
		if (!sipe_strequal(cal->oof_state, "Disabled")) {
			char *tmp = sipe_xml_data(
				sipe_xml_child(resp, "OofSettings/InternalReply/Message"));
			char *html;

			/* UTF-8 encoded BOM (0xEF 0xBB 0xBF) as a signature to mark the beginning of a UTF-8 file */
			if (g_str_has_prefix(tmp, "\xEF\xBB\xBF")) {
				html = g_strdup(tmp+3);
			} else {
				html = g_strdup(tmp);
			}
			g_free(tmp);
			tmp = g_strstrip(sipe_backend_markup_strip_html(html));
			g_free(html);
			cal->oof_note = g_markup_escape_text(tmp, -1);
			g_free(tmp);
		}

		if (sipe_strequal(cal->oof_state, "Scheduled")
		    && (xn_duration = sipe_xml_child(resp, "OofSettings/Duration")))
		{
			char *tmp = sipe_xml_data(sipe_xml_child(xn_duration, "StartTime"));
			cal->oof_start = sipe_utils_str_to_time(tmp);
			g_free(tmp);

			tmp = sipe_xml_data(sipe_xml_child(xn_duration, "EndTime"));
			cal->oof_end = sipe_utils_str_to_time(tmp);
			g_free(tmp);
		}

		if (!sipe_strequal(old_note, cal->oof_note)) { /* oof note changed */
			cal->updated = time(NULL);
			cal->published = FALSE;
		}
		g_free(old_note);

		sipe_xml_free(xml);

		cal->state = SIPE_EWS_STATE_OOF_SUCCESS;
		sipe_ews_run_state_machine(cal);

	} else {
		cal->state = SIPE_EWS_STATE_OOF_FAILURE;
		sipe_ews_run_state_machine(cal);
	}
}

static void sipe_ews_send_http_request(struct sipe_calendar *cal)
{
	if (cal->request) {
		sipe_core_email_authentication(cal->sipe_private,
					       cal->request);
		sipe_http_request_allow_redirect(cal->request);
		sipe_http_request_ready(cal->request);
	}
}

static void sipe_ews_do_avail_request(struct sipe_calendar *cal)
{
	if (cal->as_url) {
		char *body;
		time_t end;
		time_t now = time(NULL);
		char *start_str;
		char *end_str;
		struct tm *now_tm;

		SIPE_DEBUG_INFO_NOFORMAT("sipe_ews_do_avail_request: going Availability req.");

		now_tm = gmtime(&now);
		/* start -1 day, 00:00:00 */
		now_tm->tm_sec = 0;
		now_tm->tm_min = 0;
		now_tm->tm_hour = 0;
		cal->fb_start = sipe_mktime_tz(now_tm, "UTC");
		cal->fb_start -= 24*60*60;
		/* end = start + 4 days - 1 sec */
		end = cal->fb_start + SIPE_FREE_BUSY_PERIOD_SEC - 1;

		start_str = sipe_utils_time_to_str(cal->fb_start);
		end_str = sipe_utils_time_to_str(end);

		body = g_strdup_printf(SIPE_EWS_USER_AVAILABILITY_REQUEST, cal->email, start_str, end_str);
		cal->request = sipe_http_request_post(cal->sipe_private,
						      cal->as_url,
						      NULL,
						      body,
						      "text/xml; charset=UTF-8",
						      sipe_ews_process_avail_response,
						      cal);
		g_free(body);
		g_free(start_str);
		g_free(end_str);

		sipe_ews_send_http_request(cal);
	}
}

static void sipe_ews_do_oof_request(struct sipe_calendar *cal)
{
	if (cal->oof_url) {
		char *body;

		SIPE_DEBUG_INFO_NOFORMAT("sipe_ews_do_oof_request: going OOF req.");

		body = g_strdup_printf(SIPE_EWS_USER_OOF_SETTINGS_REQUEST, cal->email);
		cal->request = sipe_http_request_post(cal->sipe_private,
						      cal->as_url,
						      NULL,
						      body,
						      "text/xml; charset=UTF-8",
						      sipe_ews_process_oof_response,
						      cal);
		g_free(body);

		sipe_ews_send_http_request(cal);
	}
}

static void
sipe_ews_run_state_machine(struct sipe_calendar *cal)
{
	switch (cal->state) {
	case SIPE_EWS_STATE_AVAILABILITY_FAILURE:
	case SIPE_EWS_STATE_OOF_FAILURE:
		cal->is_ews_disabled = TRUE;
		break;
	case SIPE_EWS_STATE_IDLE:
		sipe_ews_do_avail_request(cal);
		break;
	case SIPE_EWS_STATE_AVAILABILITY_SUCCESS:
		sipe_ews_do_oof_request(cal);
		break;
	case SIPE_EWS_STATE_OOF_SUCCESS:
		{
			struct sipe_core_private *sipe_private = cal->sipe_private;

			cal->state = SIPE_EWS_STATE_IDLE;
			cal->is_updated = TRUE;
			sipe_cal_presence_publish(sipe_private, TRUE);
		}
		break;
	}
}

static void sipe_calendar_ews_autodiscover_cb(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private,
					      const struct sipe_ews_autodiscover_data *ews_data,
					      gpointer callback_data)
{
	struct sipe_calendar *cal = callback_data;

	if (ews_data) {
		cal->as_url    = g_strdup(ews_data->as_url);
		cal->legacy_dn = g_strdup(ews_data->legacy_dn);
		cal->oab_url   = g_strdup(ews_data->oab_url);
		cal->oof_url   = g_strdup(ews_data->oof_url);
		cal->state     = SIPE_EWS_STATE_IDLE;
		sipe_ews_run_state_machine(cal);
	} else {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_calendar_ews_autodiscover_cb: EWS disabled");
		cal->is_ews_disabled = TRUE;
	}
}

void sipe_ews_update_calendar(struct sipe_core_private *sipe_private)
{
	//char *autodisc_srv = g_strdup_printf("_autodiscover._tcp.%s", maildomain);
	struct sipe_calendar *cal;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_ews_update_calendar: started.");

	sipe_cal_calendar_init(sipe_private);
	cal = sipe_private->calendar;

	if (cal->is_ews_disabled) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_ews_update_calendar: disabled, exiting.");
	} else if (!cal->as_url && !cal->ews_autodiscover_triggered) {
		cal->ews_autodiscover_triggered = TRUE;
		sipe_ews_autodiscover_start(sipe_private,
					    sipe_calendar_ews_autodiscover_cb,
					    cal);
	} else {
		sipe_ews_run_state_machine(cal);
		SIPE_DEBUG_INFO_NOFORMAT("sipe_ews_update_calendar: finished.");
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
