/**
 * @file sipe-subscriptions.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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

#include <glib.h>

#include "sipe-common.h"
#include "sipmsg.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-dialog.h"
#include "sipe-utils.h"
#include "sipe.h"

gboolean process_subscribe_response(struct sipe_core_private *sipe_private,
				    struct sipmsg *msg,
				    struct transaction *trans)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	gchar *with = parse_from(sipmsg_find_header(msg, "To"));
	const gchar *event = sipmsg_find_header(msg, "Event");
	gchar *key;

	/* The case with 2005 Public IM Connectivity (PIC) - no Event header */
	if (!event) {
		struct sipmsg *request_msg = trans->msg;
		event = sipmsg_find_header(request_msg, "Event");
	}

	key = sipe_utils_subscription_key(event, with);

	/* 200 OK; 481 Call Leg Does Not Exist */
	if (key && (msg->response == 200 || msg->response == 481)) {
		if (g_hash_table_lookup(sip->subscriptions, key)) {
			g_hash_table_remove(sip->subscriptions, key);
			SIPE_DEBUG_INFO("process_subscribe_response: subscription dialog removed for: %s", key);
		}
	}

	/* create/store subscription dialog if not yet */
	if (msg->response == 200) {
		const gchar *callid = sipmsg_find_header(msg, "Call-ID");
		gchar *cseq = sipmsg_find_part_of_header(sipmsg_find_header(msg, "CSeq"), NULL, " ", NULL);

		if (key) {
			struct sip_subscription *subscription = g_new0(struct sip_subscription, 1);
			g_hash_table_insert(sip->subscriptions, g_strdup(key), subscription);

			subscription->dialog.callid = g_strdup(callid);
			subscription->dialog.cseq = atoi(cseq);
			subscription->dialog.with = g_strdup(with);
			subscription->event = g_strdup(event);
			sipe_dialog_parse(&subscription->dialog, msg, TRUE);

			SIPE_DEBUG_INFO("process_subscribe_response: subscription dialog added for: %s", key);
		}

		g_free(cseq);
	}

	g_free(key);
	g_free(with);

	if (sipmsg_find_header(msg, "ms-piggyback-cseq"))
	{
		process_incoming_notify(sipe_private, msg, FALSE, FALSE);
	}
	return TRUE;
}

/**
 * common subscription code
 */
static void subscribe(struct sipe_core_private *sipe_private,
		      const gchar *event,
		      const gchar *accept,
		      const gchar *addheaders,
		      const gchar *body,
		      struct sip_dialog *dialog)
{
	gchar *to = sip_uri_self(sipe_private);
	gchar *contact = get_contact(sipe_private);
	gchar *hdr = g_strdup_printf(
		"Event: %s\r\n"
		"Accept: %s\r\n"
		"Supported: com.microsoft.autoextend\r\n"
		"Supported: ms-benotify\r\n"
		"Proxy-Require: ms-benotify\r\n"
		"Supported: ms-piggyback-first-notify\r\n"
		"%s"
		"Contact: %s\r\n",
		event,
		accept,
		addheaders ? addheaders : "",
		contact);
	g_free(contact);

	sip_transport_subscribe(sipe_private,
				to,
				hdr,
				body,
				dialog,
				process_subscribe_response);

	g_free(hdr);
	g_free(to);
}

void sipe_subscribe_presence_wpending(struct sipe_core_private *sipe_private,
				      SIPE_UNUSED_PARAMETER void *unused)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	gchar *key = sipe_utils_subscription_key("presence.wpending", NULL);
	struct sip_dialog *dialog = (struct sip_dialog *)g_hash_table_lookup(sip->subscriptions, key);

	SIPE_DEBUG_INFO("sipe_subscribe_presence_wpending: subscription dialog for: %s is %s", key, dialog ? "Not NULL" : "NULL");
	g_free(key);

	subscribe(sipe_private,
		  "presence.wpending",
		  "text/xml+msrtc.wpending",
		  NULL,
		  NULL,
		  dialog);
}

/**
 * Subscribe roaming ACL
 */
void sipe_subscribe_roaming_acl(struct sipe_core_private *sipe_private)
{
	subscribe(sipe_private,
		  "vnd-microsoft-roaming-ACL",
		  "application/vnd-microsoft-roaming-acls+xml",
		  NULL,
		  NULL,
		  NULL);
}

/**
 * Subscribe roaming contacts
 */
void sipe_subscribe_roaming_contacts(struct sipe_core_private *sipe_private)
{
	subscribe(sipe_private,
		  "vnd-microsoft-roaming-contacts",
		  "application/vnd-microsoft-roaming-contacts+xml",
		  NULL,
		  NULL,
		  NULL);
}

/**
 *  OCS 2005 version
 */
void sipe_subscribe_roaming_provisioning(struct sipe_core_private *sipe_private)
{
	subscribe(sipe_private,
		  "vnd-microsoft-provisioning",
		  "application/vnd-microsoft-roaming-provisioning+xml",
		  "Expires: 0\r\n",
		  NULL,
		  NULL);
}

/**
 * Subscription for provisioning information to help with initial 
 * configuration. This subscription is a one-time query (denoted by the
 * Expires header, which asks for 0 seconds for the subscription lifetime).
 * This subscription asks for server configuration, meeting policies, and
 * policy settings that Communicator must enforce.
 *
 * @TODO: for what do we need this information?
 */
void sipe_subscribe_roaming_provisioning_v2(struct sipe_core_private *sipe_private)
{
	subscribe(sipe_private,
		  "vnd-microsoft-provisioning-v2",
		  "application/vnd-microsoft-roaming-provisioning-v2+xml",
		  "Expires: 0\r\n"
		  "Content-Type: application/vnd-microsoft-roaming-provisioning-v2+xml\r\n",
		  "<provisioningGroupList xmlns=\"http://schemas.microsoft.com/2006/09/sip/provisioninggrouplist\">"
		  "<provisioningGroup name=\"ServerConfiguration\"/><provisioningGroup name=\"meetingPolicy\"/>"
		  "<provisioningGroup name=\"ucPolicy\"/>"
		  "</provisioningGroupList>",
		  NULL);
}

/**
 * To request for presence information about the user, access level settings
 * that have already been configured by the user to control who has access to
 * what information, and the list of contacts who currently have outstanding
 * subscriptions.
 *
 * We wait for (BE)NOTIFY messages with some info change (categories,
 * containers, subscribers)
 */
void sipe_subscribe_roaming_self(struct sipe_core_private *sipe_private)
{
	subscribe(sipe_private,
		  "vnd-microsoft-roaming-self",
		  "application/vnd-microsoft-roaming-self+xml",
		  "Content-Type: application/vnd-microsoft-roaming-self+xml\r\n",
		  "<roamingList xmlns=\"http://schemas.microsoft.com/2006/09/sip/roaming-self\">"
		  "<roaming type=\"categories\"/>"
		  "<roaming type=\"containers\"/>"
		  "<roaming type=\"subscribers\"/></roamingList>",
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
