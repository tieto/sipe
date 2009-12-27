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
 * GetUserOofSettingsRequest request to Exchange Web Services
 * to obtain our Out-of-office (OOF) information.
 * @param email (%s) Ex.: Alice@cosmo.local
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
