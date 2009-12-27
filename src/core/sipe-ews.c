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

#include "sipe.h"
#include "http-conn.h"
#include "sipe-ews.h"


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


struct sipe_ews {
	int state;
};

static void
sipe_ews_process_oof_response(int return_code,
			      const char *body)
{
	
}

void
sipe_ews_initialize(struct sipe_account_data *sip)
{
	char *body;
	HttpConn *http_conn;
	HttpConnAuth *auth;
	
	//if (!sip->ews) {
		//sip->ews = g_new0(struct sipe_ews, 1);
	//}

	body = g_strdup_printf(SIPE_EWS_USER_OOF_SETTINGS_REQUEST, "alice@cosmo.local");
					   
	auth = g_new0(HttpConnAuth, 1);	
	auth->domain = sip->authdomain;
	auth->user = sip->authuser;
	auth->password = sip->password;
	
	http_conn = http_conn_create(
				 sip->account,
				 HTTP_CONN_SSL,
				 "cosmo-ocs-r2.cosmo.local",
				 443,
				 "/EWS/Exchange.asmx", /* or https://cosmo-ocs-r2.cosmo.local/EWS/Exchange.asmx */
				 body,
				 "text/xml; charset=UTF-8",
				 auth,
				 (HttpConnCallback)sipe_ews_process_oof_response);	
	g_free(body);
}



/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
