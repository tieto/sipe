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


#define ORIGINATED_CSTA_STATUS   "originated"
#define DELIVERED_CSTA_STATUS    "delivered"
#define ESTABLISHED_CSTA_STATUS  "established"


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
 * Sends CSTA GetCSTAFeatures request to SIP/CSTA Gateway.
 * @param line_uri (%s) Ex.: tel:73124;phone-context=dialstring;partition=BE_BRS_INT
 */
#define SIP_SEND_CSTA_GET_CSTA_FEATURES \
"<?xml version=\"1.0\"?>"\
"<GetCSTAFeatures xmlns=\"http://www.ecma-international.org/standards/ecma-323/csta/ed3\">"\
	"<extensions>"\
		"<privateData>"\
			"<private>"\
				"<lcs:line xmlns:lcs=\"http://schemas.microsoft.com/Lcs/2005/04/RCCExtension\">%s</lcs:line>"\
			"</private>"\
		"</privateData>"\
	"</extensions>"\
"</GetCSTAFeatures>"

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
 * Sends CSTA stop monitor request to SIP/CSTA Gateway.
 * @param monitor_cross_ref_id (%s) Ex.: 99fda87c
 */
#define SIP_SEND_CSTA_MONITOR_STOP \
"<?xml version=\"1.0\"?>"\
"<MonitorStop xmlns=\"http://www.ecma-international.org/standards/ecma-323/csta/ed3\">"\
	"<monitorCrossRefID>%s</monitorCrossRefID>"\
"</MonitorStop>"

/**
 * Sends CSTA make call request to SIP/CSTA Gateway.
 * @param line_uri (%s) Ex.: tel:73124;phone-context=dialstring;partition=BE_BRS_INT
 * @param to_tel_uri (%s) Ex.: tel:+3222220220
 */
#define SIP_SEND_CSTA_MAKE_CALL \
"<?xml version=\"1.0\"?>"\
"<MakeCall xmlns=\"http://www.ecma-international.org/standards/ecma-323/csta/ed3\">"\
    "<callingDevice>%s</callingDevice>"\
    "<calledDirectoryNumber>%s</calledDirectoryNumber>"\
    "<autoOriginate>doNotPrompt</autoOriginate>"\
"</MakeCall>"

/**
 * Sends CSTA ClearConnection request to SIP/CSTA Gateway.
 * @param call_id   (%s)  Ex.: 0_99f261b4
 * @param device_id (%s)  Same as in OriginatedEvent, DeliveredEvent notifications.
 *                        Ex.: tel:73124;phone-context=dialstring
 */
#define SIP_SEND_CSTA_CLEAR_CONNECTION \
"<?xml version=\"1.0\"?>"\
"<ClearConnection xmlns=\"http://www.ecma-international.org/standards/ecma-323/csta/ed3\">"\
	"<connectionToBeCleared>"\
		"<callID>%s</callID>"\
		"<deviceID>%s</deviceID>"\
	"</connectionToBeCleared>"\
"</ClearConnection>"


gchar *
sip_to_tel_uri(const gchar *phone)
{
	if (!phone || strlen(phone) == 0) return NULL;

	if (g_str_has_prefix(phone, "tel:")) {
		return g_strdup(phone);
	} else {
		gchar *tel_uri = g_malloc(strlen(phone) + 4);
		gchar *dest_p = g_stpcpy(tel_uri, "tel:");
		for (; *phone; phone++) {
			if (*phone == ' ') continue;
			if (*phone == '(') continue;
			if (*phone == ')') continue;
			if (*phone == '-') continue;
			*dest_p++ = *phone;
		}
		*dest_p = '\0';
		return tel_uri;
	}
}

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

/** get CSTA feautures's callback */
static gboolean
process_csta_get_features_response(SIPE_UNUSED_PARAMETER struct sipe_account_data *sip,
				   struct sipmsg *msg,
				   SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	if (msg->response >= 400) {
		purple_debug_info("sipe", "process_csta_get_features_response: Get CSTA features response is not 200. Failed to get features.\n");
		/* @TODO notify user of failure to get CSTA features */
		return FALSE;
	}
	else if (msg->response == 200) {
		purple_debug_info("sipe", "process_csta_get_features_response:\n%s\n", msg->body ? msg->body : "");
	}

	return TRUE;
}

/** get CSTA feautures */
static void
sip_csta_get_features(struct sipe_account_data *sip)
{
	gchar *hdr;
	gchar *body;

	if (!sip->csta || !sip->csta->dialog || !sip->csta->dialog->is_established) {
		purple_debug_info("sipe", "sip_csta_get_features: no dialog with CSTA, exiting.\n");
		return;
	}

	hdr = g_strdup(
		"Content-Disposition: signal;handling=required\r\n"
		"Content-Type: application/csta+xml\r\n");

	body = g_strdup_printf(
		SIP_SEND_CSTA_GET_CSTA_FEATURES,
		sip->csta->line_uri);

	send_sip_request(sip->gc,
			 "INFO",
			 sip->csta->dialog->with,
			 sip->csta->dialog->with,
			 hdr,
			 body,
			 sip->csta->dialog,
			 process_csta_get_features_response);
	g_free(body);
	g_free(hdr);
}

/** Monitor Start's callback */
static gboolean
process_csta_monitor_start_response(struct sipe_account_data *sip,
				    struct sipmsg *msg,
				    SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	purple_debug_info("sipe", "process_csta_monitor_start_response:\n%s\n", msg->body ? msg->body : "");

	if (!sip->csta) {
		purple_debug_info("sipe", "process_csta_monitor_start_response: sip->csta is not initializzed, exiting\n");
		return FALSE;
	}

	if (msg->response >= 400) {
		purple_debug_info("sipe", "process_csta_monitor_start_response: Monitor Start response is not 200. Failed to start monitor.\n");
		/* @TODO notify user of failure to start monitor */
		return FALSE;
	}
	else if (msg->response == 200) {
		xmlnode *xml = xmlnode_from_str(msg->body, msg->bodylen);
		g_free(sip->csta->monitor_cross_ref_id);
		sip->csta->monitor_cross_ref_id = xmlnode_get_data(xmlnode_get_child(xml, "monitorCrossRefID"));
		purple_debug_info("sipe", "process_csta_monitor_start_response: monitor_cross_ref_id=%s\n",
				  sip->csta->monitor_cross_ref_id ? sip->csta->monitor_cross_ref_id : "");
		xmlnode_free(xml);
	}

	return TRUE;
}

/** Monitor Start */
static void
sip_csta_monitor_start(struct sipe_account_data *sip)
{
	gchar *hdr;
	gchar *body;

	if (!sip->csta || !sip->csta->dialog || !sip->csta->dialog->is_established) {
		purple_debug_info("sipe", "sip_csta_monitor_start: no dialog with CSTA, exiting.\n");
		return;
	}

	hdr = g_strdup(
		"Content-Disposition: signal;handling=required\r\n"
		"Content-Type: application/csta+xml\r\n");

	body = g_strdup_printf(
		SIP_SEND_CSTA_MONITOR_START,
		sip->csta->line_uri);

	send_sip_request(sip->gc,
			 "INFO",
			 sip->csta->dialog->with,
			 sip->csta->dialog->with,
			 hdr,
			 body,
			 sip->csta->dialog,
			 process_csta_monitor_start_response);
	g_free(body);
	g_free(hdr);
}

/** Monitor Stop */
static void
sip_csta_monitor_stop(struct sipe_account_data *sip)
{
	gchar *hdr;
	gchar *body;

	if (!sip->csta || !sip->csta->dialog || !sip->csta->dialog->is_established) {
		purple_debug_info("sipe", "sip_csta_monitor_stop: no dialog with CSTA, exiting.\n");
		return;
	}

	hdr = g_strdup(
		"Content-Disposition: signal;handling=required\r\n"
		"Content-Type: application/csta+xml\r\n");

	body = g_strdup_printf(
		SIP_SEND_CSTA_MONITOR_STOP,
		sip->csta->monitor_cross_ref_id);

	send_sip_request(sip->gc,
			 "INFO",
			 sip->csta->dialog->with,
			 sip->csta->dialog->with,
			 hdr,
			 body,
			 sip->csta->dialog,
			 NULL);
	g_free(body);
	g_free(hdr);
}

/** a callback */
static gboolean
process_invite_csta_gateway_response(struct sipe_account_data *sip,
				     struct sipmsg *msg,
				     SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	purple_debug_info("sipe", "process_invite_csta_gateway_response:\n%s\n", msg->body ? msg->body : "");

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
			sip_csta_get_features(sip);
			sip_csta_monitor_start(sip);
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
	g_free(csta->monitor_cross_ref_id);
	g_free(csta->line_status);
	g_free(csta->to_tel_uri);
	g_free(csta->call_id);
	g_free(csta->device_id);

	g_free(csta);
}

void
sip_csta_close(struct sipe_account_data *sip)
{
	if (sip->csta) {
		sip_csta_monitor_stop(sip);
	}

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



/** Make Call's callback */
static gboolean
process_csta_make_call_response(struct sipe_account_data *sip,
				struct sipmsg *msg,
				SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	purple_debug_info("sipe", "process_csta_make_call_response:\n%s\n", msg->body ? msg->body : "");

	if (!sip->csta) {
		purple_debug_info("sipe", "process_csta_make_call_response: sip->csta is not initializzed, exiting\n");
		return FALSE;
	}

	if (msg->response >= 400) {
		purple_debug_info("sipe", "process_csta_make_call_response: Make Call response is not 200. Failed to make call.\n");
		/* @TODO notify user of failure to make call */
		return FALSE;
	}
	else if (msg->response == 200) {
		xmlnode *xml;
		xmlnode *xn_calling_device;
		gchar *device_id;

		purple_debug_info("sipe", "process_csta_make_call_response: SUCCESS\n");

		xml = xmlnode_from_str(msg->body, msg->bodylen);
		xn_calling_device = xmlnode_get_child(xml, "callingDevice");
		device_id = xmlnode_get_data(xmlnode_get_child(xn_calling_device, "deviceID"));
		if (!strcmp(sip->csta->line_uri, device_id)) {
			g_free(sip->csta->call_id);
			sip->csta->call_id = xmlnode_get_data(xmlnode_get_child(xn_calling_device, "callID"));
			purple_debug_info("sipe", "process_csta_make_call_response: call_id=%s\n", sip->csta->call_id ? sip->csta->call_id : "");
		}
		g_free(device_id);
		xmlnode_free(xml);
	}

	return TRUE;
}

/** Make Call */
void
sip_csta_make_call(struct sipe_account_data *sip,
		   const gchar* to_tel_uri)
{
	gchar *hdr;
	gchar *body;

	if (!to_tel_uri) {
		purple_debug_info("sipe", "sip_csta_make_call: no tel URI parameter provided, exiting.\n");
		return;
	}

	if (!sip->csta || !sip->csta->dialog || !sip->csta->dialog->is_established) {
		purple_debug_info("sipe", "sip_csta_make_call: no dialog with CSTA, exiting.\n");
		return;
	}

	g_free(sip->csta->to_tel_uri);
	sip->csta->to_tel_uri = g_strdup(to_tel_uri);

	hdr = g_strdup(
		"Content-Disposition: signal;handling=required\r\n"
		"Content-Type: application/csta+xml\r\n");

	body = g_strdup_printf(
		SIP_SEND_CSTA_MAKE_CALL,
		sip->csta->line_uri,
		sip->csta->to_tel_uri);

	send_sip_request(sip->gc,
			 "INFO",
			 sip->csta->dialog->with,
			 sip->csta->dialog->with,
			 hdr,
			 body,
			 sip->csta->dialog,
			 process_csta_make_call_response);
	g_free(body);
	g_free(hdr);
}

void
process_incoming_info_csta(struct sipe_account_data *sip,
			   struct sipmsg *msg)
{
	xmlnode *xml = xmlnode_from_str(msg->body, msg->bodylen);	
	gchar *monitor_cross_ref_id = xmlnode_get_data(xmlnode_get_child(xml, "monitorCrossRefID"));
	
	if(!sip->csta || (monitor_cross_ref_id 
			  && sip->csta->monitor_cross_ref_id
			  && strcmp(monitor_cross_ref_id, sip->csta->monitor_cross_ref_id)))
	{
		purple_debug_info("sipe", "process_incoming_info_csta: monitorCrossRefID (%s) does not match, exiting\n",
				   monitor_cross_ref_id ? monitor_cross_ref_id : "");
		return;
	}
	
	if (!strcmp(xml->name, "OriginatedEvent"))
	{
		gchar *device_id;
		gchar *call_id = xmlnode_get_data(xmlnode_get_descendant(xml, "originatedConnection", "callID", NULL));
		if (call_id && sip->csta->call_id && strcmp(call_id, sip->csta->call_id)) {
			purple_debug_info("sipe", "process_incoming_info_csta: callID (%s) does not match, exiting\n",
				   call_id ? call_id : "");
			return;
		}
		
		/* save deviceID */
		device_id = xmlnode_get_data(xmlnode_get_descendant(xml, "originatedConnection", "deviceID", NULL));
		purple_debug_info("sipe", "process_incoming_info_csta: device_id=(%s)\n", device_id ? device_id : "");
		if (device_id) {
			g_free(sip->csta->device_id);
			sip->csta->device_id = g_strdup(device_id);
		}
		g_free(device_id);
		
		/* set line status */
		g_free(sip->csta->line_status);
		sip->csta->line_status = g_strdup(ORIGINATED_CSTA_STATUS);
		
		g_free(call_id);
	}
	else if (!strcmp(xml->name, "DeliveredEvent"))
	{
		gchar *device_id;
		gchar *call_id = xmlnode_get_data(xmlnode_get_descendant(xml, "connection", "callID", NULL));
		if (call_id && sip->csta->call_id && strcmp(call_id, sip->csta->call_id)) {
			purple_debug_info("sipe", "process_incoming_info_csta: callID (%s) does not match, exiting\n",
				   call_id ? call_id : "");
			return;
		}
		
		/* save deviceID */
		device_id = xmlnode_get_data(xmlnode_get_descendant(xml, "connection", "deviceID", NULL));
		purple_debug_info("sipe", "process_incoming_info_csta: device_id=(%s)\n", device_id ? device_id : "");
		if (device_id) {
			g_free(sip->csta->device_id);
			sip->csta->device_id = g_strdup(device_id);
		}
		g_free(device_id);
		
		/* set line status */
		g_free(sip->csta->line_status);
		sip->csta->line_status = g_strdup(DELIVERED_CSTA_STATUS);
		
		g_free(call_id);	
	}
	else if (!strcmp(xml->name, "EstablishedEvent"))
	{
		gchar *device_id;
		gchar *call_id = xmlnode_get_data(xmlnode_get_descendant(xml, "establishedConnection", "callID", NULL));
		if (call_id && sip->csta->call_id && strcmp(call_id, sip->csta->call_id)) {
			purple_debug_info("sipe", "process_incoming_info_csta: callID (%s) does not match, exiting\n",
				   call_id ? call_id : "");
			return;
		}		
		
		/* save deviceID */
		device_id = xmlnode_get_data(xmlnode_get_descendant(xml, "establishedConnection", "deviceID", NULL));
		purple_debug_info("sipe", "process_incoming_info_csta: device_id=(%s)\n", device_id ? device_id : "");
		if (device_id) {
			g_free(sip->csta->device_id);
			sip->csta->device_id = g_strdup(device_id);
		}
		g_free(device_id);
		
		/* set line status */
		g_free(sip->csta->line_status);
		sip->csta->line_status = g_strdup(ESTABLISHED_CSTA_STATUS);
		
		g_free(call_id);	
	}	
	else if (!strcmp(xml->name, "ConnectionClearedEvent"))
	{
		gchar *call_id = xmlnode_get_data(xmlnode_get_descendant(xml, "droppedConnection", "callID", NULL));
		if (call_id && sip->csta->call_id && strcmp(call_id, sip->csta->call_id)) {
			purple_debug_info("sipe", "process_incoming_info_csta: callID (%s) does not match, exiting\n",
				   call_id ? call_id : "");
			return;
		}
		
		/* clear line status */
		g_free(sip->csta->line_status);

		g_free(call_id);
	}
	g_free(monitor_cross_ref_id);
	xmlnode_free(xml);
}



/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
