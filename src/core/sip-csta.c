/**
 * @file sip-csta.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <glib.h>

#include "sipe-common.h"
#include "sipmsg.h"
#include "sip-csta.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-dialog.h"
#include "sipe-schedule.h"
#include "sipe-utils.h"
#include "sipe-xml.h"
#include "sipe.h"

#define ORIGINATED_CSTA_STATUS          "originated"
#define DELIVERED_CSTA_STATUS           "delivered"
#define ESTABLISHED_CSTA_STATUS         "established"


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


static gchar *
sip_to_tel_uri0(const gchar *phone)
{
	if (!phone || strlen(phone) == 0) return NULL;

	if (g_str_has_prefix(phone, "tel:")) {
		return g_strdup(phone);
	} else {
		gchar *tel_uri = g_malloc(strlen(phone) + 4 + 1);
		gchar *dest_p = g_stpcpy(tel_uri, "tel:");
		for (; *phone; phone++) {
			if (*phone == ' ') continue;
			if (*phone == '(') continue;
			if (*phone == ')') continue;
			if (*phone == '-') continue;
			if (*phone == '.') continue;
			*dest_p++ = *phone;
		}
		*dest_p = '\0';
		return tel_uri;
	}
}

gchar *
sip_to_tel_uri(const gchar *phone)
{
	gchar *res = sip_to_tel_uri0(phone);
	gchar *v;
	/* strips everything starting with 'v:' if any */
	if (res && (v = strstr(res, "v:"))) {
		gchar *tmp = res;

		res = g_strndup(res, v - res);
		g_free(tmp);
		return res;
	}
	return res;
}

gchar *
sip_tel_uri_denormalize(const gchar *tel_uri)
{
	if (!tel_uri) return NULL;

	if (g_str_has_prefix(tel_uri, "tel:")) {
		return g_strdup(tel_uri + 4);
	} else {
		return g_strdup(tel_uri);
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
		SIPE_DEBUG_INFO_NOFORMAT("sip_csta_initialize: sip->csta is already instantiated, exiting.");
	}
}

/** get CSTA feautures's callback */
static gboolean
process_csta_get_features_response(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private,
				   struct sipmsg *msg,
				   SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	if (msg->response >= 400) {
		SIPE_DEBUG_INFO_NOFORMAT("process_csta_get_features_response: Get CSTA features response is not 200. Failed to get features.");
		/* @TODO notify user of failure to get CSTA features */
		return FALSE;
	}
	else if (msg->response == 200) {
		SIPE_DEBUG_INFO("process_csta_get_features_response:\n%s", msg->body ? msg->body : "");
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
		SIPE_DEBUG_INFO_NOFORMAT("sip_csta_get_features: no dialog with CSTA, exiting.");
		return;
	}

	hdr = g_strdup(
		"Content-Disposition: signal;handling=required\r\n"
		"Content-Type: application/csta+xml\r\n");

	body = g_strdup_printf(
		SIP_SEND_CSTA_GET_CSTA_FEATURES,
		sip->csta->line_uri);

	send_sip_request(SIP_TO_CORE_PRIVATE,
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
process_csta_monitor_start_response(struct sipe_core_private *sipe_private,
				    struct sipmsg *msg,
				    SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

	SIPE_DEBUG_INFO("process_csta_monitor_start_response:\n%s", msg->body ? msg->body : "");

	if (!sip->csta) {
		SIPE_DEBUG_INFO_NOFORMAT("process_csta_monitor_start_response: sip->csta is not initializzed, exiting");
		return FALSE;
	}

	if (msg->response >= 400) {
		SIPE_DEBUG_INFO_NOFORMAT("process_csta_monitor_start_response: Monitor Start response is not 200. Failed to start monitor.");
		/* @TODO notify user of failure to start monitor */
		return FALSE;
	}
	else if (msg->response == 200) {
		sipe_xml *xml = sipe_xml_parse(msg->body, msg->bodylen);
		g_free(sip->csta->monitor_cross_ref_id);
		sip->csta->monitor_cross_ref_id = sipe_xml_data(sipe_xml_child(xml, "monitorCrossRefID"));
		SIPE_DEBUG_INFO("process_csta_monitor_start_response: monitor_cross_ref_id=%s",
				sip->csta->monitor_cross_ref_id ? sip->csta->monitor_cross_ref_id : "");
		sipe_xml_free(xml);
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
		SIPE_DEBUG_INFO_NOFORMAT("sip_csta_monitor_start: no dialog with CSTA, exiting.");
		return;
	}

	hdr = g_strdup(
		"Content-Disposition: signal;handling=required\r\n"
		"Content-Type: application/csta+xml\r\n");

	body = g_strdup_printf(
		SIP_SEND_CSTA_MONITOR_START,
		sip->csta->line_uri);

	send_sip_request(SIP_TO_CORE_PRIVATE,
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
		SIPE_DEBUG_INFO_NOFORMAT("sip_csta_monitor_stop: no dialog with CSTA, exiting.");
		return;
	}

	if (!sip->csta->monitor_cross_ref_id) {
		SIPE_DEBUG_INFO_NOFORMAT("sip_csta_monitor_stop: no monitor_cross_ref_id, exiting.");
		return;
	}

	hdr = g_strdup(
		"Content-Disposition: signal;handling=required\r\n"
		"Content-Type: application/csta+xml\r\n");

	body = g_strdup_printf(
		SIP_SEND_CSTA_MONITOR_STOP,
		sip->csta->monitor_cross_ref_id);

	send_sip_request(SIP_TO_CORE_PRIVATE,
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

static void
sipe_invite_csta_gateway(struct sipe_core_private *sipe_private,
			 gpointer unused);

/** a callback */
static gboolean
process_invite_csta_gateway_response(struct sipe_core_private *sipe_private,
				     struct sipmsg *msg,
				     SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

	SIPE_DEBUG_INFO("process_invite_csta_gateway_response:\n%s", msg->body ? msg->body : "");

	if (!sip->csta) {
		SIPE_DEBUG_INFO_NOFORMAT("process_invite_csta_gateway_response: sip->csta is not initializzed, exiting");
		return FALSE;
	}

	if (!sip->csta->dialog) {
		SIPE_DEBUG_INFO_NOFORMAT("process_invite_csta_gateway_response: GSTA dialog is NULL, exiting");
		return FALSE;
	}

	sipe_dialog_parse(sip->csta->dialog, msg, TRUE);

	if (msg->response >= 200) {
		/* send ACK to CSTA */
		sip->csta->dialog->cseq = 0;
		send_sip_request(sipe_private, "ACK", sip->csta->dialog->with, sip->csta->dialog->with, NULL, NULL, sip->csta->dialog, NULL);
		sip->csta->dialog->outgoing_invite = NULL;
		sip->csta->dialog->is_established = TRUE;
	}

	if (msg->response >= 400) {
		SIPE_DEBUG_INFO_NOFORMAT("process_invite_csta_gateway_response: INVITE response is not 200. Failed to join CSTA.");
		/* @TODO notify user of failure to join CSTA */
		return FALSE;
	}
	else if (msg->response == 200) {
		sipe_xml *xml = sipe_xml_parse(msg->body, msg->bodylen);

		g_free(sip->csta->gateway_status);
		sip->csta->gateway_status = sipe_xml_data(sipe_xml_child(xml, "systemStatus"));
		SIPE_DEBUG_INFO("process_invite_csta_gateway_response: gateway_status=%s",
				sip->csta->gateway_status ? sip->csta->gateway_status : "");
		if (sipe_strcase_equal(sip->csta->gateway_status, "normal")) {
			if (!sip->csta->monitor_cross_ref_id) {
				sip_csta_get_features(sip);
				sip_csta_monitor_start(sip);
			}
		} else {
			SIPE_DEBUG_INFO("process_invite_csta_gateway_response: ERROR: CSTA status is %s, won't continue.",
					sip->csta->gateway_status);
			/* @TODO notify user of failure to join CSTA */
		}
		sipe_xml_free(xml);

		/* schedule re-invite. RFC4028 */
		if (sip->csta->dialog->expires) {
			sipe_schedule_seconds(sipe_private,
					      "<+csta>",
					      NULL,
					      sip->csta->dialog->expires - 60, /* 1 minute earlier */
					      sipe_invite_csta_gateway,
					      NULL);
		}
	}

	return TRUE;
}

/** Creates long living dialog with SIP/CSTA Gateway */
/*  should be re-entrant as require to sent re-invites every 10 min to refresh */
static void
sipe_invite_csta_gateway(struct sipe_core_private *sipe_private,
			 SIPE_UNUSED_PARAMETER gpointer unused)
{
	struct sipe_account_data *sip = sipe_private->temporary;
	gchar *hdr;
	gchar *contact;
	gchar *body;

	if (!sip->csta) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_invite_csta_gateway: sip->csta is uninitialized, exiting");
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
		"Supported: timer\r\n"
		"Content-Disposition: signal;handling=required\r\n"
		"Content-Type: application/csta+xml\r\n",
		contact);
	g_free(contact);

	body = g_strdup_printf(
		SIP_SEND_CSTA_REQUEST_SYSTEM_STATUS,
		sip->csta->line_uri);

	sip->csta->dialog->outgoing_invite = send_sip_request(SIP_TO_CORE_PRIVATE,
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
	sipe_invite_csta_gateway(SIP_TO_CORE_PRIVATE, NULL);
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
		send_sip_request(SIP_TO_CORE_PRIVATE,
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
process_csta_make_call_response(struct sipe_core_private *sipe_private,
				struct sipmsg *msg,
				SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

	SIPE_DEBUG_INFO("process_csta_make_call_response:\n%s", msg->body ? msg->body : "");

	if (!sip->csta) {
		SIPE_DEBUG_INFO_NOFORMAT("process_csta_make_call_response: sip->csta is not initializzed, exiting");
		return FALSE;
	}

	if (msg->response >= 400) {
		SIPE_DEBUG_INFO_NOFORMAT("process_csta_make_call_response: Make Call response is not 200. Failed to make call.");
		/* @TODO notify user of failure to make call */
		return FALSE;
	}
	else if (msg->response == 200) {
		sipe_xml *xml;
		const sipe_xml *xn_calling_device;
		gchar *device_id;

		SIPE_DEBUG_INFO_NOFORMAT("process_csta_make_call_response: SUCCESS");

		xml = sipe_xml_parse(msg->body, msg->bodylen);
		xn_calling_device = sipe_xml_child(xml, "callingDevice");
		device_id = sipe_xml_data(sipe_xml_child(xn_calling_device, "deviceID"));
		if (sipe_strequal(sip->csta->line_uri, device_id)) {
			g_free(sip->csta->call_id);
			sip->csta->call_id = sipe_xml_data(sipe_xml_child(xn_calling_device, "callID"));
			SIPE_DEBUG_INFO("process_csta_make_call_response: call_id=%s", sip->csta->call_id ? sip->csta->call_id : "");
		}
		g_free(device_id);
		sipe_xml_free(xml);
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
		SIPE_DEBUG_INFO_NOFORMAT("sip_csta_make_call: no tel URI parameter provided, exiting.");
		return;
	}

	if (!sip->csta || !sip->csta->dialog || !sip->csta->dialog->is_established) {
		SIPE_DEBUG_INFO_NOFORMAT("sip_csta_make_call: no dialog with CSTA, exiting.");
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

	send_sip_request(SIP_TO_CORE_PRIVATE,
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

static void
sip_csta_update_id_and_status(struct sip_csta *csta,
			      const sipe_xml *node,
			      const char *status)
{
	gchar *call_id = sipe_xml_data(sipe_xml_child(node, "callID"));

	if (!sipe_strequal(call_id, csta->call_id)) {
		SIPE_DEBUG_INFO("sipe_csta_update_id_and_status: callID (%s) does not match", call_id);
	}
	else
	{
		/* free old line status */
		g_free(csta->line_status);
		csta->line_status = NULL;

		if (status)
		{
			/* save deviceID */
			gchar *device_id = sipe_xml_data(sipe_xml_child(node, "deviceID"));
			SIPE_DEBUG_INFO("sipe_csta_update_id_and_status: device_id=(%s)", device_id ? device_id : "");
			if (device_id) {
				g_free(csta->device_id);
				csta->device_id = device_id;
			}

			/* set new line status */
			csta->line_status = g_strdup(status);
		}
		else
		{
			/* clean up cleared connection */
			g_free(csta->to_tel_uri);
			csta->to_tel_uri = NULL;
			g_free(csta->call_id);
			csta->call_id = NULL;
			g_free(csta->device_id);
			csta->device_id = NULL;
		}
	}

	g_free(call_id);
}

void
process_incoming_info_csta(struct sipe_account_data *sip,
			   struct sipmsg *msg)
{
	gchar *monitor_cross_ref_id;
	sipe_xml *xml = sipe_xml_parse(msg->body, msg->bodylen);

	if (!xml) return;

	monitor_cross_ref_id = sipe_xml_data(sipe_xml_child(xml, "monitorCrossRefID"));

	if(!sip->csta || !sipe_strequal(monitor_cross_ref_id, sip->csta->monitor_cross_ref_id))
	{
		SIPE_DEBUG_INFO("process_incoming_info_csta: monitorCrossRefID (%s) does not match, exiting",
				monitor_cross_ref_id ? monitor_cross_ref_id : "");
	}
	else
	{
		if (sipe_strequal(sipe_xml_name(xml), "OriginatedEvent"))
		{
			sip_csta_update_id_and_status(sip->csta,
						      sipe_xml_child(xml, "originatedConnection"),
						      ORIGINATED_CSTA_STATUS);
		}
		else if (sipe_strequal(sipe_xml_name(xml), "DeliveredEvent"))
		{
			sip_csta_update_id_and_status(sip->csta,
						      sipe_xml_child(xml, "connection"),
						      DELIVERED_CSTA_STATUS);
		}
		else if (sipe_strequal(sipe_xml_name(xml), "EstablishedEvent"))
		{
			sip_csta_update_id_and_status(sip->csta,
						      sipe_xml_child(xml, "establishedConnection"),
						      ESTABLISHED_CSTA_STATUS);
		}
		else if (sipe_strequal(sipe_xml_name(xml), "ConnectionClearedEvent"))
		{
			sip_csta_update_id_and_status(sip->csta,
						      sipe_xml_child(xml, "droppedConnection"),
						      NULL);
		}
	}

	g_free(monitor_cross_ref_id);
	sipe_xml_free(xml);
}



/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
