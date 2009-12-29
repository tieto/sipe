/**
 * @file sipe-ews.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009 pier11 <pier11@operamail.com>
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

#include "debug.h"
#include "xmlnode.h"

#include "sipe.h"
/* for xmlnode_get_descendant */
#include "sipe-utils.h"

#include "http-conn.h"
#include "sipe-ews.h"
#include "sipe-cal.h"


/**
 * Autodiscover request for Exchange Web Services
 * @param email (%s) Ex.: alice@cosmo.local
 */
#define SIPE_EWS_AUTODISCOVER_REQUEST \
"<?xml version=\"1.0\"?>"\
"<Autodiscover xmlns=\"http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006\">"\
  "<Request>"\
    "<EMailAddress>%s</EMailAddress>"\
    "<AcceptableResponseSchema>"\
      "http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a"\
    "</AcceptableResponseSchema>"\
  "</Request>"\
"</Autodiscover>"

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

#define SIPE_EWS_STATE_NONE			0
#define SIPE_EWS_STATE_AUTODISCOVER_SUCCESS	1
#define SIPE_EWS_STATE_AVAILABILITY_SUCCESS	2
#define SIPE_EWS_STATE_OOF_SUCCESS		3

struct sipe_ews {
	int state;
	char *email;
	HttpConnAuth *auth;
	PurpleAccount *account;

	char *as_url;
	char *oof_url;
	char *oab_url;
	
	char *oof_note;
	
	time_t fb_start;
	/* hex form */
	char *free_busy;
	char *working_hours_xml_str;
	GSList *cal_events;
};

static void
sipe_ews_cal_events_free(GSList *cal_events)
{
	GSList *entry = cal_events;
	
	if (!cal_events) return;
	
	while (entry) {
		struct sipe_cal_event *cal_event = entry->data;
		sipe_cal_event_free(cal_event);
		entry = entry->next;
	}

	g_slist_free(cal_events);
}

/* plug in later
static void
sipe_ews_free(struct sipe_ews* ews)
{
	g_free(ews->email);
	g_free(ews->auth);
	g_free(ews->as_url);
	g_free(ews->oof_url);
	g_free(ews->oab_url);
	g_free(ews->oof_note);
	g_free(ews->free_busy);
	g_free(ews->working_hours_xml_str);
	
	sipe_ews_cal_events_free(ews->cal_events);
	
	g_free(ews);
}
*/

static void
sipe_ews_run_state_machine(struct sipe_ews *ews);

static void
sipe_ews_process_avail_response(int return_code,
				const char *body,
				void *data)
{
	struct sipe_ews *ews = data;
	
	purple_debug_info("sipe", "sipe_ews_process_avail_response: cb started.\n");

	if (return_code == 200 && body) {
		xmlnode *node;
		xmlnode *resp;
		/** ref: [MS-OXWAVLS] */
		xmlnode *xml = xmlnode_from_str(body, strlen(body));
		/* Envelope/Body/GetUserAvailabilityResponse/FreeBusyResponseArray/FreeBusyResponse/ResponseMessage@ResponseClass="Success"
Envelope/Body/GetUserAvailabilityResponse/FreeBusyResponseArray/FreeBusyResponse/FreeBusyView/MergedFreeBusy
Envelope/Body/GetUserAvailabilityResponse/FreeBusyResponseArray/FreeBusyResponse/FreeBusyView/CalendarEventArray/CalendarEvent
Envelope/Body/GetUserAvailabilityResponse/FreeBusyResponseArray/FreeBusyResponse/FreeBusyView/WorkingHours
		 */
		resp = xmlnode_get_descendant(xml, "Envelope", "Body", "GetUserAvailabilityResponse", "FreeBusyResponseArray", "FreeBusyResponse", NULL);
		if (!resp) return; /* rather soap:Fault */
		if (strcmp(xmlnode_get_attrib(xmlnode_get_child(resp, "ResponseMessage"), "ResponseClass"), "Success")) {
			return; /* Error response */
		}

		/* MergedFreeBusy */
		g_free(ews->free_busy);
		ews->free_busy = xmlnode_get_data(xmlnode_get_descendant(resp, "FreeBusyView", "MergedFreeBusy", NULL));

		/* WorkingHours */
		node = xmlnode_get_descendant(resp, "FreeBusyView", "WorkingHours", NULL);
		ews->working_hours_xml_str = xmlnode_to_str(node, NULL);	

		sipe_ews_cal_events_free(ews->cal_events);
		ews->cal_events = NULL;
		/* CalendarEvents */
		for (node = xmlnode_get_descendant(resp, "FreeBusyView", "CalendarEventArray", "CalendarEvent", NULL);
		     node;
		     node = xmlnode_get_next_twin(node))
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
			ews->cal_events = g_slist_append(ews->cal_events, cal_event);

			tmp = xmlnode_get_data(xmlnode_get_child(resp, "StartTime"));
			cal_event->start_time = purple_str_to_time(tmp, FALSE, NULL, NULL, NULL);
			g_free(tmp);

			tmp = xmlnode_get_data(xmlnode_get_child(resp, "EndTime"));
			cal_event->end_time = purple_str_to_time(tmp, FALSE, NULL, NULL, NULL);
			g_free(tmp);

			tmp = xmlnode_get_data(xmlnode_get_child(resp, "BusyType"));
			if (!strcmp("Free", tmp)) {
				cal_event->cal_status = SIPE_CAL_FREE;
			} else if (!strcmp("Tentative", tmp)) {
				cal_event->cal_status = SIPE_CAL_TENTATIVE;
			} else if (!strcmp("Busy", tmp)) {
				cal_event->cal_status = SIPE_CAL_BUSY;
			} else if (!strcmp("OOF", tmp)) {
				cal_event->cal_status = SIPE_CAL_OOF;
			} else {
				cal_event->cal_status = SIPE_CAL_NO_DATA;
			}
			g_free(tmp);
			
			cal_event->subject = xmlnode_get_data(xmlnode_get_descendant(resp, "CalendarEventDetails", "Subject", NULL));
			cal_event->location = xmlnode_get_data(xmlnode_get_descendant(resp, "CalendarEventDetails", "Location", NULL));
			
			tmp = xmlnode_get_data(xmlnode_get_descendant(resp, "CalendarEventDetails", "IsMeeting", NULL));
			cal_event->is_meeting = !strcmp(tmp, "true");
			g_free(tmp);
		}

		xmlnode_free(xml);
		
		ews->state = SIPE_EWS_STATE_AVAILABILITY_SUCCESS;
		sipe_ews_run_state_machine(ews);
	}
}

static void
sipe_ews_process_oof_response(int return_code,
			      const char *body,
			      void *data)
{
	struct sipe_ews *ews = data;
	
	purple_debug_info("sipe", "sipe_ews_process_oof_response: cb started.\n");

	if (return_code == 200 && body) {
		char *state;
		xmlnode *resp;
		/** ref: [MS-OXWOOF] */
		xmlnode *xml = xmlnode_from_str(body, strlen(body));
		/* Envelope/Body/GetUserOofSettingsResponse/ResponseMessage@ResponseClass="Success"
		 * Envelope/Body/GetUserOofSettingsResponse/OofSettings/OofState=Enabled
		 * Envelope/Body/GetUserOofSettingsResponse/OofSettings/InternalReply/Message
		 */
		resp = xmlnode_get_descendant(xml, "Envelope", "Body", "GetUserOofSettingsResponse", NULL);
		if (!resp) return; /* rather soap:Fault */
		if (strcmp(xmlnode_get_attrib(xmlnode_get_child(resp, "ResponseMessage"), "ResponseClass"), "Success")) {
			return; /* Error response */
		}

		g_free(ews->oof_note);
		state = xmlnode_get_data(xmlnode_get_descendant(resp, "OofSettings", "OofState", NULL));
		if (!strcmp(state, "Enabled")) {
			char *tmp = xmlnode_get_data(xmlnode_get_descendant(resp, "OofSettings", "InternalReply", "Message", NULL));
			char *html = purple_unescape_html(tmp);
			
			g_free(tmp);
			ews->oof_note = purple_markup_strip_html(html);
			g_free(tmp);
		}
		g_free(state);

		xmlnode_free(xml);
		
		ews->state = SIPE_EWS_STATE_OOF_SUCCESS;
		sipe_ews_run_state_machine(ews);
	}
}

static void
sipe_ews_process_autodiscover(int return_code,
			      const char *body,
			      void *data)
{
	struct sipe_ews *ews = data;
	
	purple_debug_info("sipe", "sipe_ews_process_autodiscover: cb started.\n");

	if (return_code == 200 && body) {
		xmlnode *node;
		/** ref: [MS-OXDSCLI] */
		xmlnode *xml = xmlnode_from_str(body, strlen(body));

		/* Protocols */
		for (node = xmlnode_get_descendant(xml, "Response", "Account", "Protocol", NULL);
		     node;
		     node = xmlnode_get_next_twin(node))
		{
			char *type = xmlnode_get_data(xmlnode_get_child(node, "Type"));
			if (!strcmp("EXCH", type)) {
				ews->as_url  = xmlnode_get_data(xmlnode_get_child(node, "ASUrl"));
				ews->oof_url = xmlnode_get_data(xmlnode_get_child(node, "OOFUrl"));
				ews->oab_url = xmlnode_get_data(xmlnode_get_child(node, "OABUrl"));

				purple_debug_info("sipe", "sipe_ews_process_autodiscover:as_url %s\n",
					ews->as_url ? ews->as_url : "");
				purple_debug_info("sipe", "sipe_ews_process_autodiscover:oof_url %s\n",
					ews->oof_url ? ews->oof_url : "");
				purple_debug_info("sipe", "sipe_ews_process_autodiscover:oab_url %s\n",
					ews->oab_url ? ews->oab_url : "");

				g_free(type);
				break;
			} else {
				g_free(type);
				continue;
			}
		}

		xmlnode_free(xml);

		ews->state = SIPE_EWS_STATE_AUTODISCOVER_SUCCESS;
		sipe_ews_run_state_machine(ews);
	}
}

static void
sipe_ews_do_autodiscover(struct sipe_ews *ews,
			 const char* autodiscover_url)
{
	char *body;
	HttpConn *http_conn;

	purple_debug_info("sipe", "sipe_ews_initialize: going autodiscover url=%s\n", autodiscover_url ? autodiscover_url : "");

	body = g_strdup_printf(SIPE_EWS_AUTODISCOVER_REQUEST, ews->email);	
	http_conn = http_conn_create(
				 ews->account,
				 HTTP_CONN_SSL,
				 autodiscover_url,
				 body,
				 "text/xml",
				 ews->auth,
				 (HttpConnCallback)sipe_ews_process_autodiscover,
				 ews);	
	g_free(body);
}

static void
sipe_ews_do_avail_request(struct sipe_ews *ews)
{
	if (ews->as_url) {
		char *body;
		HttpConn *http_conn;
		time_t end;
		time_t now = time(NULL);
		char *start_str;
		char *end_str;
		struct tm *now_tm;
		const char *pattern = "%Y-%m-%dT%H:%M:%SZ";
		
		purple_debug_info("sipe", "sipe_ews_initialize: going Availability req.\n");

		now_tm = gmtime(&now);
		/* start -1 day, 00:00:00 */
		now_tm->tm_sec = 0;
		now_tm->tm_min = 0;
		now_tm->tm_hour = 0;
		ews->fb_start = sipe_mktime_tz(now_tm, "UTC");
		ews->fb_start -= 24*60*60;
		/* end = start + 4 days - 1 sec */
		end = ews->fb_start + 4*(24*60*60) - 1;

		start_str = g_strdup(purple_utf8_strftime(pattern, gmtime(&ews->fb_start)));
		end_str = g_strdup(purple_utf8_strftime(pattern, gmtime(&end)));

		body = g_strdup_printf(SIPE_EWS_USER_AVAILABILITY_REQUEST, ews->email, start_str, end_str);	
		http_conn = http_conn_create(
					 ews->account,
					 HTTP_CONN_SSL,
					 ews->as_url,
					 body,
					 "text/xml; charset=UTF-8",
					 ews->auth,
					 (HttpConnCallback)sipe_ews_process_avail_response,
					 ews);
		g_free(body);
		g_free(start_str);
		g_free(end_str);
	}
}

static void
sipe_ews_do_oof_request(struct sipe_ews *ews)
{
	if (ews->oof_url) {
		char *body;
		HttpConn *http_conn;

		purple_debug_info("sipe", "sipe_ews_initialize: going OOF req.\n");
	
		body = g_strdup_printf(SIPE_EWS_USER_OOF_SETTINGS_REQUEST, ews->email);	
		http_conn = http_conn_create(
					 ews->account,
					 HTTP_CONN_SSL,
					 ews->oof_url,
					 body,
					 "text/xml; charset=UTF-8",
					 ews->auth,
					 (HttpConnCallback)sipe_ews_process_oof_response,
					 ews);
		g_free(body);
	}
}

static void
sipe_ews_run_state_machine(struct sipe_ews *ews)
{
	switch (ews->state) {
		case SIPE_EWS_STATE_NONE:
			{
				char *maildomain = strstr(ews->email, "@") + 1;
				char *autodisc_1_url = g_strdup_printf("https://Autodiscover.%s/Autodiscover/Autodiscover.xml", maildomain);
				char *autodisc_2_url = g_strdup_printf("https://%s/Autodiscover/Autodiscover.xml", maildomain);
			
				sipe_ews_do_autodiscover(ews, autodisc_1_url);
				sipe_ews_do_autodiscover(ews, autodisc_2_url);
				
				g_free(autodisc_1_url);
				g_free(autodisc_2_url);
				break;
			}
		case SIPE_EWS_STATE_AUTODISCOVER_SUCCESS:
			sipe_ews_do_avail_request(ews);
			break;
		case SIPE_EWS_STATE_AVAILABILITY_SUCCESS:
			sipe_ews_do_oof_request(ews);
			break;
		case SIPE_EWS_STATE_OOF_SUCCESS:
			
			break;
	}
}

void
sipe_ews_initialize(struct sipe_account_data *sip)
{
	struct sipe_ews *ews = g_new0(struct sipe_ews, 1);

	ews->account = sip->account;
	/* or take the values from acc config (later) */
	ews->email = g_strdup("alice@cosmo.local");//sip->username;
	//char *autodisc_srv = g_strdup_printf("_autodiscover._tcp.%s", maildomain);
	
	purple_debug_info("sipe", "sipe_ews_initialize: started.\n");

	ews->auth = g_new0(HttpConnAuth, 1);
	ews->auth->domain = sip->authdomain;
	ews->auth->user = sip->authuser;
	ews->auth->password = sip->password;
	
	sipe_ews_run_state_machine(ews);
	
	//sipe_ews_free(ews);
	purple_debug_info("sipe", "sipe_ews_initialize: finished.\n");
}



/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
