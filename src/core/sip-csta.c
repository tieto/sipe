/**
 * @file sip-csta.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-11 SIPE Project <http://sipe.sourceforge.net/>
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

#define ORIGINATED_CSTA_STATUS          "originated"
#define DELIVERED_CSTA_STATUS           "delivered"
#define ESTABLISHED_CSTA_STATUS         "established"

/**
 * Data model for interaction with SIP/CSTA Gateway
 */
struct sip_csta {
	gchar *line_uri;
	/** SIP/CSTA Gateway's SIP URI */
	gchar *gateway_uri;
	/** dialog with SIP/CSTA Gateway */
	struct sip_dialog *dialog;

	gchar *gateway_status;
	gchar *monitor_cross_ref_id;

	gchar *line_status;
	/** destination tel: URI */
	gchar *to_tel_uri;
	gchar *call_id;
	/* our device ID as reported by SIP/CSTA gateway */
	gchar *device_id;
};

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
sip_csta_initialize(struct sipe_core_private *sipe_private,
		    const gchar *line_uri,
		    const gchar *server)
{
	if(!sipe_private->csta) {
		sipe_private->csta = g_new0(struct sip_csta, 1);
		sipe_private->csta->line_uri = g_strdup(line_uri);
		sipe_private->csta->gateway_uri = g_strdup(server);
	} else {
		SIPE_DEBUG_INFO_NOFORMAT("sip_csta_initialize: sipe_private->csta is already instantiated, exiting.");
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
sip_csta_get_features(struct sipe_core_private *sipe_private)
{
	gchar *hdr;
	gchar *body;

	if (!sipe_private->csta || !sipe_private->csta->dialog || !sipe_private->csta->dialog->is_established) {
		SIPE_DEBUG_INFO_NOFORMAT("sip_csta_get_features: no dialog with CSTA, exiting.");
		return;
	}

	hdr = g_strdup(
		"Content-Disposition: signal;handling=required\r\n"
		"Content-Type: application/csta+xml\r\n");

	body = g_strdup_printf(
		SIP_SEND_CSTA_GET_CSTA_FEATURES,
		sipe_private->csta->line_uri);

	sip_transport_info(sipe_private,
			   hdr,
			   body,
			   sipe_private->csta->dialog,
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
	SIPE_DEBUG_INFO("process_csta_monitor_start_response:\n%s", msg->body ? msg->body : "");

	if (!sipe_private->csta) {
		SIPE_DEBUG_INFO_NOFORMAT("process_csta_monitor_start_response: sipe_private->csta is not initializzed, exiting");
		return FALSE;
	}

	if (msg->response >= 400) {
		SIPE_DEBUG_INFO_NOFORMAT("process_csta_monitor_start_response: Monitor Start response is not 200. Failed to start monitor.");
		/* @TODO notify user of failure to start monitor */
		return FALSE;
	}
	else if (msg->response == 200) {
		sipe_xml *xml = sipe_xml_parse(msg->body, msg->bodylen);
		g_free(sipe_private->csta->monitor_cross_ref_id);
		sipe_private->csta->monitor_cross_ref_id = sipe_xml_data(sipe_xml_child(xml, "monitorCrossRefID"));
		SIPE_DEBUG_INFO("process_csta_monitor_start_response: monitor_cross_ref_id=%s",
				sipe_private->csta->monitor_cross_ref_id ? sipe_private->csta->monitor_cross_ref_id : "");
		sipe_xml_free(xml);
	}

	return TRUE;
}

/** Monitor Start */
static void
sip_csta_monitor_start(struct sipe_core_private *sipe_private)
{
	gchar *hdr;
	gchar *body;

	if (!sipe_private->csta || !sipe_private->csta->dialog || !sipe_private->csta->dialog->is_established) {
		SIPE_DEBUG_INFO_NOFORMAT("sip_csta_monitor_start: no dialog with CSTA, exiting.");
		return;
	}

	hdr = g_strdup(
		"Content-Disposition: signal;handling=required\r\n"
		"Content-Type: application/csta+xml\r\n");

	body = g_strdup_printf(
		SIP_SEND_CSTA_MONITOR_START,
		sipe_private->csta->line_uri);

	sip_transport_info(sipe_private,
			   hdr,
			   body,
			   sipe_private->csta->dialog,
			   process_csta_monitor_start_response);
	g_free(body);
	g_free(hdr);
}

/** Monitor Stop */
static void
sip_csta_monitor_stop(struct sipe_core_private *sipe_private)
{
	gchar *hdr;
	gchar *body;

	if (!sipe_private->csta || !sipe_private->csta->dialog || !sipe_private->csta->dialog->is_established) {
		SIPE_DEBUG_INFO_NOFORMAT("sip_csta_monitor_stop: no dialog with CSTA, exiting.");
		return;
	}

	if (!sipe_private->csta->monitor_cross_ref_id) {
		SIPE_DEBUG_INFO_NOFORMAT("sip_csta_monitor_stop: no monitor_cross_ref_id, exiting.");
		return;
	}

	hdr = g_strdup(
		"Content-Disposition: signal;handling=required\r\n"
		"Content-Type: application/csta+xml\r\n");

	body = g_strdup_printf(
		SIP_SEND_CSTA_MONITOR_STOP,
		sipe_private->csta->monitor_cross_ref_id);

	sip_transport_info(sipe_private,
			   hdr,
			   body,
			   sipe_private->csta->dialog,
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
	SIPE_DEBUG_INFO("process_invite_csta_gateway_response:\n%s", msg->body ? msg->body : "");

	if (!sipe_private->csta) {
		SIPE_DEBUG_INFO_NOFORMAT("process_invite_csta_gateway_response: sipe_private->csta is not initializzed, exiting");
		return FALSE;
	}

	if (!sipe_private->csta->dialog) {
		SIPE_DEBUG_INFO_NOFORMAT("process_invite_csta_gateway_response: GSTA dialog is NULL, exiting");
		return FALSE;
	}

	sipe_dialog_parse(sipe_private->csta->dialog, msg, TRUE);

	if (msg->response >= 200) {
		/* send ACK to CSTA */
		sipe_private->csta->dialog->cseq = 0;
		sip_transport_ack(sipe_private, sipe_private->csta->dialog);
		sipe_private->csta->dialog->outgoing_invite = NULL;
		sipe_private->csta->dialog->is_established = TRUE;
	}

	if (msg->response >= 400) {
		SIPE_DEBUG_INFO_NOFORMAT("process_invite_csta_gateway_response: INVITE response is not 200. Failed to join CSTA.");
		/* @TODO notify user of failure to join CSTA */
		return FALSE;
	}
	else if (msg->response == 200) {
		sipe_xml *xml = sipe_xml_parse(msg->body, msg->bodylen);

		g_free(sipe_private->csta->gateway_status);
		sipe_private->csta->gateway_status = sipe_xml_data(sipe_xml_child(xml, "systemStatus"));
		SIPE_DEBUG_INFO("process_invite_csta_gateway_response: gateway_status=%s",
				sipe_private->csta->gateway_status ? sipe_private->csta->gateway_status : "");
		if (sipe_strcase_equal(sipe_private->csta->gateway_status, "normal")) {
			if (!sipe_private->csta->monitor_cross_ref_id) {
				sip_csta_get_features(sipe_private);
				sip_csta_monitor_start(sipe_private);
			}
		} else {
			SIPE_DEBUG_INFO("process_invite_csta_gateway_response: ERROR: CSTA status is %s, won't continue.",
					sipe_private->csta->gateway_status);
			/* @TODO notify user of failure to join CSTA */
		}
		sipe_xml_free(xml);

		/* schedule re-invite. RFC4028 */
		if (sipe_private->csta->dialog->expires) {
			sipe_schedule_seconds(sipe_private,
					      "<+csta>",
					      NULL,
					      sipe_private->csta->dialog->expires - 60, /* 1 minute earlier */
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
	gchar *hdr;
	gchar *contact;
	gchar *body;

	if (!sipe_private->csta) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_invite_csta_gateway: sipe_private->csta is uninitialized, exiting");
		return;
	}

	if(!sipe_private->csta->dialog) {
		sipe_private->csta->dialog = g_new0(struct sip_dialog, 1);
		sipe_private->csta->dialog->callid = gencallid();
		sipe_private->csta->dialog->with = g_strdup(sipe_private->csta->gateway_uri);
	}
	if (!(sipe_private->csta->dialog->ourtag)) {
		sipe_private->csta->dialog->ourtag = gentag();
	}

	contact = get_contact(sipe_private);
	hdr = g_strdup_printf(
		"Contact: %s\r\n"
		"Supported: timer\r\n"
		"Content-Disposition: signal;handling=required\r\n"
		"Content-Type: application/csta+xml\r\n",
		contact);
	g_free(contact);

	body = g_strdup_printf(
		SIP_SEND_CSTA_REQUEST_SYSTEM_STATUS,
		sipe_private->csta->line_uri);

	sipe_private->csta->dialog->outgoing_invite =
		sip_transport_invite(sipe_private,
				     hdr,
				     body,
				     sipe_private->csta->dialog,
				     process_invite_csta_gateway_response);
	g_free(body);
	g_free(hdr);
}

void
sip_csta_open(struct sipe_core_private *sipe_private,
	      const gchar *line_uri,
	      const gchar *server)
{
	sip_csta_initialize(sipe_private, line_uri, server);
	sipe_invite_csta_gateway(sipe_private, NULL);
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
sip_csta_close(struct sipe_core_private *sipe_private)
{
	if (sipe_private->csta) {
		sip_csta_monitor_stop(sipe_private);
	}

	if (sipe_private->csta && sipe_private->csta->dialog) {
		/* send BYE to CSTA */
		sip_transport_bye(sipe_private, sipe_private->csta->dialog);
	}

	sip_csta_free(sipe_private->csta);
}



/** Make Call's callback */
static gboolean
process_csta_make_call_response(struct sipe_core_private *sipe_private,
				struct sipmsg *msg,
				SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	SIPE_DEBUG_INFO("process_csta_make_call_response:\n%s", msg->body ? msg->body : "");

	if (!sipe_private->csta) {
		SIPE_DEBUG_INFO_NOFORMAT("process_csta_make_call_response: sipe_private->csta is not initializzed, exiting");
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
		if (sipe_strequal(sipe_private->csta->line_uri, device_id)) {
			g_free(sipe_private->csta->call_id);
			sipe_private->csta->call_id = sipe_xml_data(sipe_xml_child(xn_calling_device, "callID"));
			SIPE_DEBUG_INFO("process_csta_make_call_response: call_id=%s", sipe_private->csta->call_id ? sipe_private->csta->call_id : "");
		}
		g_free(device_id);
		sipe_xml_free(xml);
	}

	return TRUE;
}

/** Make Call */
static void sip_csta_make_call(struct sipe_core_private *sipe_private,
			       const gchar* to_tel_uri)
{
	gchar *hdr;
	gchar *body;

	if (!to_tel_uri) {
		SIPE_DEBUG_INFO_NOFORMAT("sip_csta_make_call: no tel URI parameter provided, exiting.");
		return;
	}

	if (!sipe_private->csta || !sipe_private->csta->dialog || !sipe_private->csta->dialog->is_established) {
		SIPE_DEBUG_INFO_NOFORMAT("sip_csta_make_call: no dialog with CSTA, exiting.");
		return;
	}

	g_free(sipe_private->csta->to_tel_uri);
	sipe_private->csta->to_tel_uri = g_strdup(to_tel_uri);

	hdr = g_strdup(
		"Content-Disposition: signal;handling=required\r\n"
		"Content-Type: application/csta+xml\r\n");

	body = g_strdup_printf(
		SIP_SEND_CSTA_MAKE_CALL,
		sipe_private->csta->line_uri,
		sipe_private->csta->to_tel_uri);

	sip_transport_info(sipe_private,
			   hdr,
			   body,
			   sipe_private->csta->dialog,
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
process_incoming_info_csta(struct sipe_core_private *sipe_private,
			   struct sipmsg *msg)
{
	gchar *monitor_cross_ref_id;
	sipe_xml *xml = sipe_xml_parse(msg->body, msg->bodylen);

	if (!xml) return;

	monitor_cross_ref_id = sipe_xml_data(sipe_xml_child(xml, "monitorCrossRefID"));

	if(!sipe_private->csta || !sipe_strequal(monitor_cross_ref_id, sipe_private->csta->monitor_cross_ref_id))
	{
		SIPE_DEBUG_INFO("process_incoming_info_csta: monitorCrossRefID (%s) does not match, exiting",
				monitor_cross_ref_id ? monitor_cross_ref_id : "");
	}
	else
	{
		if (sipe_strequal(sipe_xml_name(xml), "OriginatedEvent"))
		{
			sip_csta_update_id_and_status(sipe_private->csta,
						      sipe_xml_child(xml, "originatedConnection"),
						      ORIGINATED_CSTA_STATUS);
		}
		else if (sipe_strequal(sipe_xml_name(xml), "DeliveredEvent"))
		{
			sip_csta_update_id_and_status(sipe_private->csta,
						      sipe_xml_child(xml, "connection"),
						      DELIVERED_CSTA_STATUS);
		}
		else if (sipe_strequal(sipe_xml_name(xml), "EstablishedEvent"))
		{
			sip_csta_update_id_and_status(sipe_private->csta,
						      sipe_xml_child(xml, "establishedConnection"),
						      ESTABLISHED_CSTA_STATUS);
		}
		else if (sipe_strequal(sipe_xml_name(xml), "ConnectionClearedEvent"))
		{
			sip_csta_update_id_and_status(sipe_private->csta,
						      sipe_xml_child(xml, "droppedConnection"),
						      NULL);
		}
	}

	g_free(monitor_cross_ref_id);
	sipe_xml_free(xml);
}

gboolean sip_csta_is_idle(struct sipe_core_private *sipe_private)
{
	return(sipe_private->csta && !sipe_private->csta->line_status);
}

void sipe_core_buddy_make_call(struct sipe_core_public *sipe_public,
			       const gchar *phone)
{
	if (phone) {
		gchar *tel_uri = sip_to_tel_uri(phone);

		SIPE_DEBUG_INFO("sipe_core_buddy_make_call: calling number: %s",
				tel_uri ? tel_uri : "");
		sip_csta_make_call(SIPE_CORE_PRIVATE, tel_uri);

		g_free(tel_uri);
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
