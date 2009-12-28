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
	char *as_url;
	char *oof_url;
	char *oab_url;
	
	char *oof_note;
};

static void
sipe_ews_free(struct sipe_ews* ews)
{
	g_free(ews->as_url);
	g_free(ews->oof_url);
	g_free(ews->oab_url);
	g_free(ews->oof_note);
	g_free(ews);
}

static void
sipe_ews_process_oof_response(int return_code,
			      const char *body,
			      void *data)
{
	struct sipe_ews *ews = data;

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
	}
}

static void
sipe_ews_process_autodiscover(int return_code,
			      const char *body,
			      void *data)
{
	struct sipe_ews *ews = data;

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
	}
}

/** 
 * Extracts host, port and relative url
 * Ex. url: https://machine.domain.Contoso.com/EWS/Exchange.asmx
 *
 * Allocates memory, must be g_free'd.
 */
static void
sipe_ews_parse_url(const char *url,
		   char **host,
		   int *port,
		   char **rel_url)
{
	char **parts = g_strsplit(url, "://", 2);
	char *no_proto = parts[1] ? g_strdup(parts[1]) : g_strdup(parts[0]);
	int port_tmp = !strcmp(parts[0], "https") ? 443 : 80;
	char *tmp;
	char *host_port;

	g_strfreev(parts);
	tmp = strstr(no_proto, "/");
	if (tmp && rel_url) *rel_url = g_strdup(tmp);
	host_port = tmp ? g_strndup(no_proto, tmp - no_proto) : g_strdup(no_proto);
	g_free(no_proto);	
	
	parts = g_strsplit(host_port, ":", 2);
	*host = g_strdup(parts[0]);
	*port = parts[1] ? atoi(parts[1]) : port_tmp;
	g_strfreev(parts);

	g_free(host_port);	
}

void
sipe_ews_initialize(struct sipe_account_data *sip)
{
	char *body;
	HttpConn *http_conn;
	HttpConnAuth *auth;
	/* or take the values from acc config (later) */
	char *email = sip->username;
	char *maildomain = sip->sipdomain;
	char *autodisc_srv = g_strdup_printf("_autodiscover._tcp.%s", maildomain);
	char *autodisc_url = "/Autodiscover/Autodiscover.xml";
	char *autodisc_1_host = g_strdup_printf("Autodiscover.%s", maildomain);
	char *autodisc_2_host = g_strdup(maildomain);
	struct sipe_ews *ews = g_new0(struct sipe_ews, 1);

	auth = g_new0(HttpConnAuth, 1);	
	auth->domain = sip->authdomain;
	auth->user = sip->authuser;
	auth->password = sip->password;

	if (!ews->as_url) {
		body = g_strdup_printf(SIPE_EWS_AUTODISCOVER_REQUEST, email);	
		http_conn = http_conn_create(
					 sip->account,
					 HTTP_CONN_SSL,
					 autodisc_1_host,
					 443, /* https */
					 autodisc_url,
					 body,
					 "text/xml",
					 auth,
					 (HttpConnCallback)sipe_ews_process_autodiscover,
					 ews);	
		g_free(body);
		//close/free conn
	}


	if (ews->oof_url) {
		char *host;
		int port;
		char *url;
		
		sipe_ews_parse_url(ews->oof_url, &host, &port, &url);

		body = g_strdup_printf(SIPE_EWS_USER_OOF_SETTINGS_REQUEST, email);	
		http_conn = http_conn_create(
					 sip->account,
					 HTTP_CONN_SSL,
					 host,
					 port,
					 url,
					 body,
					 "text/xml; charset=UTF-8",
					 auth,
					 (HttpConnCallback)sipe_ews_process_oof_response,
					 ews);
		g_free(host);
		g_free(url);
		g_free(body);
	}
	
	g_free(autodisc_srv);
	g_free(autodisc_1_host);
	g_free(autodisc_2_host);
	
	sipe_ews_free(ews);
}



/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
