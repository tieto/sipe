/**
 * @file sip-csta.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009 pier11 <pier11@operamail.com>
 *
 * Implements Remote Call Control (RCC) feature for
 * integration with legacy enterprise PBX (wired telephony) systems.
 * Should be applicable to 2005 and 2007(R2) systems.
 * Inderlying XML protocol CSTA is defined in ECMA-323.
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

#include <glib.h>
#include <stdlib.h>
#include <string.h>
#include "debug.h"

#include "sipe.h"
#include "sipe-dialog.h"
#include "sip-csta.h"
#include "sipe-utils.h"

/**
 * Sends CSTA RequestSystemStatus request to SIP/CSTA Gateway.
 * @param line_uri (%s) Ex.: tel:73124;phone-context=dialstring;partition=BE_BRS_INT
 */
#define SIP_SEND_CSTA_REQUEST_SYSTEM_STATUS \
"<?xml version=\"1.0\"?>"\
"<RequestSystemStatus xmlns=\"http://www.ecma-international.org/standards/ecma-323/csta/ed3\">"\
    "<extensions>"\
        "<privateData>"\
            "<private>"\
                "<lcs:line xmlns:lcs=\"http://schemas.microsoft.com/Lcs/2005/04/RCCExtension\">%s</lcs:line>"\
            "</private>"\
        "</privateData>"\
    "</extensions>"\
"</RequestSystemStatus>"

/**
 * Sends CSTA start monitor request to SIP/CSTA Gateway.
 * @param line_uri (%s) Ex.: tel:73124;phone-context=dialstring;partition=BE_BRS_INT
 */
#define SIP_SEND_CSTA_MONITOR_START \
"<?xml version=\"1.0\"?>"\
"<MonitorStart xmlns=\"http://www.ecma-international.org/standards/ecma-323/csta/ed3\">"\
    "<monitorObject>"\
        "<deviceObject>%s</deviceObject>"\
    "</monitorObject>"\
"</MonitorStart>"

/**
 * Sends CSTA make call request to SIP/CSTA Gateway.
 * @param line_uri (%s) Ex.: tel:73124;phone-context=dialstring;partition=BE_BRS_INT
 * @param calling_number (%s) Ex.: tel:+3222220220
 */
#define SIP_SEND_CSTA_MAKE_CALL \
"<?xml version=\"1.0\"?>"\
"<MakeCall xmlns=\"http://www.ecma-international.org/standards/ecma-323/csta/ed3\">"\
    "<callingDevice>%s</callingDevice>"\
    "<calledDirectoryNumber>%s</calledDirectoryNumber>"\
    "<autoOriginate>doNotPrompt</autoOriginate>"\
"</MakeCall>"


static void
sip_csta_initialize(struct sipe_account_data *sip,
		    const gchar *line_uri,
		    const gchar *server)
{
	if(!sip->csta) {
		sip->csta = g_new0(struct sip_csta, 1);
		sip->csta->line_uri = g_strdup(line_uri);
		sip->csta->gateway_uri = g_strdup(server);
	} else {
		purple_debug_info("sipe", "sip_csta_initialize: sip->csta is already instantiated, exiting.\n");
	}
}

/** a callback */
static gboolean
process_invite_csta_gateway_response(struct sipe_account_data *sip,
				     struct sipmsg *msg,
				     SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	if (!sip->csta) {
		purple_debug_info("sipe", "process_invite_csta_gateway_response: sip->csta is not initializzed, exiting\n");
		return FALSE;
	}

	if (!sip->csta->dialog) {
		purple_debug_info("sipe", "process_invite_csta_gateway_response: GSTA dialog is NULL, exiting\n");
		return FALSE;
	}

	sipe_dialog_parse(sip->csta->dialog, msg, TRUE);

	if (msg->response >= 200) {
		/* send ACK to CSTA */
		sip->csta->dialog->cseq = 0;
		send_sip_request(sip->gc, "ACK", sip->csta->dialog->with, sip->csta->dialog->with, NULL, NULL, sip->csta->dialog, NULL);
		sip->csta->dialog->outgoing_invite = NULL;
		sip->csta->dialog->is_established = TRUE;
	}

	if (msg->response >= 400) {
		purple_debug_info("sipe", "process_invite_csta_gateway_response: INVITE response is not 200. Failed to join CSTA.\n");
		/* @TODO notify user of failure to join CSTA */
		return FALSE;
	}
	else if (msg->response == 200) {
		xmlnode *xml = xmlnode_from_str(msg->body, msg->bodylen);
		g_free(sip->csta->gateway_status);
		sip->csta->gateway_status = xmlnode_get_data(xmlnode_get_child(xml, "systemStatus"));
		purple_debug_info("sipe", "process_invite_csta_gateway_response: gateway_status=%s\n",
				  sip->csta->gateway_status ? sip->csta->gateway_status : "");
		if (!g_ascii_strcasecmp(sip->csta->gateway_status, "normal")) {
			//sip_csta_monitor_start(sip);
		} else {
			purple_debug_info("sipe", "process_invite_csta_gateway_response: ERRIR: CSTA status is %s, won't continue.\n",
					  sip->csta->gateway_status);
			/* @TODO notify user of failure to join CSTA */
		}
		xmlnode_free(xml);
	}

	return TRUE;
}

/** Creates long living dialog with SIP/CSTA Gateway */
/*  should be re-entrant as require to sent re-invites every 10 min to refresh */
static void
sipe_invite_csta_gateway(struct sipe_account_data *sip)
{
	gchar *hdr;
	gchar *contact;
	gchar *body;

	if (!sip->csta) {
		purple_debug_info("sipe", "sipe_invite_csta_gateway: sip->csta is uninitialized, exiting\n");
		return;
	}

	if(!sip->csta->dialog) {
		sip->csta->dialog = g_new0(struct sip_dialog, 1);
		sip->csta->dialog->callid = gencallid();
		sip->csta->dialog->with = g_strdup(sip->csta->gateway_uri);
	}
	if (!(sip->csta->dialog->ourtag)) {
		sip->csta->dialog->ourtag = gentag();
	}

	contact = get_contact(sip);
	hdr = g_strdup_printf(
		"Contact: %s\r\n"
		"Content-Disposition: signal;handling=required\r\n"
		"Content-Type: application/csta+xml\r\n",
		contact);
	g_free(contact);

	body = g_strdup_printf(
		SIP_SEND_CSTA_REQUEST_SYSTEM_STATUS,
		sip->csta->line_uri);

	sip->csta->dialog->outgoing_invite = send_sip_request(sip->gc,
							      "INVITE",
							      sip->csta->dialog->with,
							      sip->csta->dialog->with,
							      hdr,
							      body,
							      sip->csta->dialog,
							      process_invite_csta_gateway_response);
	g_free(body);
	g_free(hdr);
}

void
sip_csta_open(struct sipe_account_data *sip,
	      const gchar *line_uri,
	      const gchar *server)
{
	sip_csta_initialize(sip, line_uri, server);
	sipe_invite_csta_gateway(sip);
}

static void
sip_csta_free(struct sip_csta *csta)
{
	if (!csta) return;
	
	g_free(csta->line_uri);
	g_free(csta->gateway_uri);
	
	sipe_dialog_free(csta->dialog);
	
	g_free(csta->gateway_status);
	g_free(csta->line_status);
	g_free(csta->called_uri);
	
	g_free(csta);
}

void
sip_csta_close(struct sipe_account_data *sip)
{
	/* @TODO stop monitor */
	
	if (sip->csta && sip->csta->dialog) {
		/* send BYE to CSTA */
		send_sip_request(sip->gc,
				 "BYE",
				 sip->csta->dialog->with,
				 sip->csta->dialog->with,
				 NULL,
				 NULL,
				 sip->csta->dialog,
				 NULL);
	}
	
	sip_csta_free(sip->csta);
}



/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
