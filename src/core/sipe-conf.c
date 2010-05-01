/**
 * @file sipe-conf.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <glib.h>

#include "conversation.h"

#include "sipe-common.h"
#include "sipmsg.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-chat.h"
#include "sipe-conf.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-dialog.h"
#include "sipe-nls.h"
#include "sipe-session.h"
#include "sipe-utils.h"
#include "sipe-xml.h"
#include "sipe.h"

/**
 * Add Conference request to FocusFactory.
 * @param focus_factory_uri (%s) Ex.: sip:bob7@boston.local;gruu;opaque=app:conf:focusfactory
 * @param from		    (%s) Ex.: sip:bob7@boston.local
 * @param request_id	    (%d) Ex.: 1094520
 * @param conference_id	    (%s) Ex.: 8386E6AEAAA41E4AA6627BA76D43B6D1
 * @param expiry_time	    (%s) Ex.: 2009-07-13T17:57:09Z , Default duration: 7 hours
 */
#define SIPE_SEND_CONF_ADD \
"<?xml version=\"1.0\"?>"\
"<request xmlns=\"urn:ietf:params:xml:ns:cccp\" "\
	"xmlns:mscp=\"http://schemas.microsoft.com/rtc/2005/08/cccpextensions\" "\
	"C3PVersion=\"1\" "\
	"to=\"%s\" "\
	"from=\"%s\" "\
	"requestId=\"%d\">"\
	"<addConference>"\
		"<ci:conference-info xmlns:ci=\"urn:ietf:params:xml:ns:conference-info\" entity=\"\" xmlns:msci=\"http://schemas.microsoft.com/rtc/2005/08/confinfoextensions\">"\
			"<ci:conference-description>"\
				"<ci:subject/>"\
				"<msci:conference-id>%s</msci:conference-id>"\
				"<msci:expiry-time>%s</msci:expiry-time>"\
				"<msci:admission-policy>openAuthenticated</msci:admission-policy>"\
			"</ci:conference-description>"\
			"<msci:conference-view>"\
				"<msci:entity-view entity=\"chat\"/>"\
			"</msci:conference-view>"\
		"</ci:conference-info>"\
	"</addConference>"\
"</request>"

/**
 * AddUser request to Focus.
 * Params:
 * focus_URI, from, request_id, focus_URI, from, endpoint_GUID
 */
#define SIPE_SEND_CONF_ADD_USER \
"<?xml version=\"1.0\"?>"\
"<request xmlns=\"urn:ietf:params:xml:ns:cccp\" xmlns:mscp=\"http://schemas.microsoft.com/rtc/2005/08/cccpextensions\" "\
	"C3PVersion=\"1\" "\
	"to=\"%s\" "\
	"from=\"%s\" "\
	"requestId=\"%d\">"\
	"<addUser>"\
		"<conferenceKeys confEntity=\"%s\"/>"\
		"<ci:user xmlns:ci=\"urn:ietf:params:xml:ns:conference-info\" entity=\"%s\">"\
			"<ci:roles>"\
				"<ci:entry>attendee</ci:entry>"\
			"</ci:roles>"\
			"<ci:endpoint entity=\"{%s}\" xmlns:msci=\"http://schemas.microsoft.com/rtc/2005/08/confinfoextensions\"/>"\
		"</ci:user>"\
	"</addUser>"\
"</request>"

/**
 * ModifyUserRoles request to Focus. Makes user a leader.
 * @param focus_uri (%s)
 * @param from (%s)
 * @param request_id (%d)
 * @param focus_uri (%s)
 * @param who (%s)
 */
#define SIPE_SEND_CONF_MODIFY_USER_ROLES \
"<?xml version=\"1.0\"?>"\
"<request xmlns=\"urn:ietf:params:xml:ns:cccp\" xmlns:mscp=\"http://schemas.microsoft.com/rtc/2005/08/cccpextensions\" "\
	"C3PVersion=\"1\" "\
	"to=\"%s\" "\
	"from=\"%s\" "\
	"requestId=\"%d\">"\
	"<modifyUserRoles>"\
		"<userKeys confEntity=\"%s\" userEntity=\"%s\"/>"\
		"<user-roles xmlns=\"urn:ietf:params:xml:ns:conference-info\">"\
			"<entry>presenter</entry>"\
		"</user-roles>"\
	"</modifyUserRoles>"\
"</request>"

/**
 * ModifyConferenceLock request to Focus. Locks/unlocks conference.
 * @param focus_uri (%s)
 * @param from (%s)
 * @param request_id (%d)
 * @param focus_uri (%s)
 * @param locked (%s) "true" or "false" values applicable
 */
#define SIPE_SEND_CONF_MODIFY_CONF_LOCK \
"<?xml version=\"1.0\"?>"\
"<request xmlns=\"urn:ietf:params:xml:ns:cccp\" xmlns:mscp=\"http://schemas.microsoft.com/rtc/2005/08/cccpextensions\" "\
	"C3PVersion=\"1\" "\
	"to=\"%s\" "\
	"from=\"%s\" "\
	"requestId=\"%d\">"\
	"<modifyConferenceLock>"\
		"<conferenceKeys confEntity=\"%s\"/>"\
		"<locked>%s</locked>"\
	"</modifyConferenceLock>"\
"</request>"

/**
 * ModifyConferenceLock request to Focus. Locks/unlocks conference.
 * @param focus_uri (%s)
 * @param from (%s)
 * @param request_id (%d)
 * @param focus_uri (%s)
 * @param who (%s)
 */
#define SIPE_SEND_CONF_DELETE_USER \
"<?xml version=\"1.0\"?>"\
"<request xmlns=\"urn:ietf:params:xml:ns:cccp\" xmlns:mscp=\"http://schemas.microsoft.com/rtc/2005/08/cccpextensions\" "\
	"C3PVersion=\"1\" "\
	"to=\"%s\" "\
	"from=\"%s\" "\
	"requestId=\"%d\">"\
	"<deleteUser>"\
		"<userKeys confEntity=\"%s\" userEntity=\"%s\"/>"\
	"</deleteUser>"\
"</request>"

/**
 * Invite counterparty to join conference.
 * @param focus_uri (%s)
 * @param subject (%s) of conference
 */
#define SIPE_SEND_CONF_INVITE \
"<Conferencing version=\"2.0\">"\
	"<focus-uri>%s</focus-uri>"\
	"<subject>%s</subject>"\
	"<im available=\"true\">"\
		"<first-im/>"\
	"</im>"\
"</Conferencing>"

/**
 * Generates random GUID.
 * This method is borrowed from pidgin's msnutils.c
 */
static char *
rand_guid()
{
	return g_strdup_printf("%4X%4X-%4X-%4X-%4X-%4X%4X%4X",
			rand() % 0xAAFF + 0x1111,
			rand() % 0xAAFF + 0x1111,
			rand() % 0xAAFF + 0x1111,
			rand() % 0xAAFF + 0x1111,
			rand() % 0xAAFF + 0x1111,
			rand() % 0xAAFF + 0x1111,
			rand() % 0xAAFF + 0x1111,
			rand() % 0xAAFF + 0x1111);
}

/**
 * @param expires not respected if set to negative value (E.g. -1)
 */
static void
sipe_subscribe_conference(struct sipe_account_data *sip,
			  struct sip_session *session,
			  const int expires)
{
	gchar *expires_hdr = (expires >= 0) ? g_strdup_printf("Expires: %d\r\n", expires) : g_strdup("");
	gchar *contact = get_contact(sip);
	gchar *hdr = g_strdup_printf(
		"Event: conference\r\n"
		"%s"
		"Accept: application/conference-info+xml\r\n"
		"Supported: com.microsoft.autoextend\r\n"
		"Supported: ms-benotify\r\n"
		"Proxy-Require: ms-benotify\r\n"
		"Supported: ms-piggyback-first-notify\r\n"
		"Contact: %s\r\n",
		expires_hdr,
		contact);
	g_free(expires_hdr);
	g_free(contact);

	send_sip_request(SIP_TO_CORE_PRIVATE,
			 "SUBSCRIBE",
			 session->focus_uri,
			 session->focus_uri,
			 hdr,
			 "",
			 NULL,
			 process_subscribe_response);
	g_free(hdr);
}

/** Invite us to the focus callback */
static gboolean
process_invite_conf_focus_response(struct sipe_core_private *sipe_private,
				   struct sipmsg *msg,
				   SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	struct sip_session *session = NULL;
	char *focus_uri = parse_from(sipmsg_find_header(msg, "To"));

	session = sipe_session_find_conference(sip, focus_uri);

	if (!session) {
		SIPE_DEBUG_INFO("process_invite_conf_focus_response: unable to find conf session with focus=%s", focus_uri);
		g_free(focus_uri);
		return FALSE;
	}

	if (!session->focus_dialog) {
		SIPE_DEBUG_INFO_NOFORMAT("process_invite_conf_focus_response: session's focus_dialog is NULL");
		g_free(focus_uri);
		return FALSE;
	}

	sipe_dialog_parse(session->focus_dialog, msg, TRUE);

	if (msg->response >= 200) {
		/* send ACK to focus */
		session->focus_dialog->cseq = 0;
		send_sip_request(sipe_private, "ACK", session->focus_dialog->with, session->focus_dialog->with, NULL, NULL, session->focus_dialog, NULL);
		session->focus_dialog->outgoing_invite = NULL;
		session->focus_dialog->is_established = TRUE;
	}

	if (msg->response >= 400) {
		SIPE_DEBUG_INFO_NOFORMAT("process_invite_conf_focus_response: INVITE response is not 200. Failed to join focus.");
		/* @TODO notify user of failure to join focus */
		sipe_session_remove(sip, session);
		g_free(focus_uri);
		return FALSE;
	} else if (msg->response == 200) {
		sipe_xml *xn_response = sipe_xml_parse(msg->body, msg->bodylen);
		const gchar *code = sipe_xml_attribute(xn_response, "code");
		if (sipe_strequal(code, "success")) {
			/* subscribe to focus */
			sipe_subscribe_conference(sip, session, -1);
		}
		sipe_xml_free(xn_response);
	}

	g_free(focus_uri);
	return TRUE;
}

/** Invite us to the focus */
void
sipe_invite_conf_focus(struct sipe_account_data *sip,
		       struct sip_session *session)
{
	gchar *hdr;
	gchar *contact;
	gchar *body;
	gchar *self;

	if (session->focus_dialog && session->focus_dialog->is_established) {
		SIPE_DEBUG_INFO("session with %s already has a dialog open", session->focus_uri);
		return;
	}

	if(!session->focus_dialog) {
		session->focus_dialog = g_new0(struct sip_dialog, 1);
		session->focus_dialog->callid = gencallid();
		session->focus_dialog->with = g_strdup(session->focus_uri);
		session->focus_dialog->endpoint_GUID = rand_guid();
	}
	if (!(session->focus_dialog->ourtag)) {
		session->focus_dialog->ourtag = gentag();
	}

	contact = get_contact(sip);
	hdr = g_strdup_printf(
		"Supported: ms-sender\r\n"
		"Contact: %s\r\n"
		"Content-Type: application/cccp+xml\r\n",
		contact);
	g_free(contact);

	/* @TODO put request_id to queue to further compare with incoming one */
	/* focus_URI, from, request_id, focus_URI, from, endpoint_GUID */
	self = sip_uri_self(sip);
	body = g_strdup_printf(
		SIPE_SEND_CONF_ADD_USER,
		session->focus_dialog->with,
		self,
		session->request_id++,
		session->focus_dialog->with,
		self,
		session->focus_dialog->endpoint_GUID);
	g_free(self);

	session->focus_dialog->outgoing_invite = send_sip_request(SIP_TO_CORE_PRIVATE,
								  "INVITE",
								  session->focus_dialog->with,
								  session->focus_dialog->with,
								  hdr,
								  body,
								  session->focus_dialog,
								  process_invite_conf_focus_response);
	g_free(body);
	g_free(hdr);
}

/** Modify User Role */
void
sipe_conf_modify_user_role(struct sipe_account_data *sip,
			   struct sip_session *session,
			   const gchar* who)
{
	gchar *hdr;
	gchar *body;
	gchar *self;

	if (!session->focus_dialog || !session->focus_dialog->is_established) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_conf_modify_user_role: no dialog with focus, exiting.");
		return;
	}

	hdr = g_strdup(
		"Content-Type: application/cccp+xml\r\n");

	/* @TODO put request_id to queue to further compare with incoming one */
	self = sip_uri_self(sip);
	body = g_strdup_printf(
		SIPE_SEND_CONF_MODIFY_USER_ROLES,
		session->focus_dialog->with,
		self,
		session->request_id++,
		session->focus_dialog->with,
		who);
	g_free(self);

	send_sip_request(SIP_TO_CORE_PRIVATE,
			 "INFO",
			 session->focus_dialog->with,
			 session->focus_dialog->with,
			 hdr,
			 body,
			 session->focus_dialog,
			 NULL);
	g_free(body);
	g_free(hdr);
}

/** Modify Conference Lock */
void
sipe_conf_modify_conference_lock(struct sipe_account_data *sip,
				 struct sip_session *session,
				 const gboolean locked)
{
	gchar *hdr;
	gchar *body;
	gchar *self;

	if (!session->focus_dialog || !session->focus_dialog->is_established) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_conf_modify_conference_lock: no dialog with focus, exiting.");
		return;
	}

	hdr = g_strdup(
		"Content-Type: application/cccp+xml\r\n");

	/* @TODO put request_id to queue to further compare with incoming one */
	self = sip_uri_self(sip);
	body = g_strdup_printf(
		SIPE_SEND_CONF_MODIFY_CONF_LOCK,
		session->focus_dialog->with,
		self,
		session->request_id++,
		session->focus_dialog->with,
		locked ? "true" : "false");
	g_free(self);

	send_sip_request(SIP_TO_CORE_PRIVATE,
			 "INFO",
			 session->focus_dialog->with,
			 session->focus_dialog->with,
			 hdr,
			 body,
			 session->focus_dialog,
			 NULL);
	g_free(body);
	g_free(hdr);
}

/** Modify Delete User */
void
sipe_conf_delete_user(struct sipe_account_data *sip,
		      struct sip_session *session,
		      const gchar* who)
{
	gchar *hdr;
	gchar *body;
	gchar *self;

	if (!session->focus_dialog || !session->focus_dialog->is_established) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_conf_delete_user: no dialog with focus, exiting.");
		return;
	}

	hdr = g_strdup(
		"Content-Type: application/cccp+xml\r\n");

	/* @TODO put request_id to queue to further compare with incoming one */
	self = sip_uri_self(sip);
	body = g_strdup_printf(
		SIPE_SEND_CONF_DELETE_USER,
		session->focus_dialog->with,
		self,
		session->request_id++,
		session->focus_dialog->with,
		who);
	g_free(self);

	send_sip_request(SIP_TO_CORE_PRIVATE,
			 "INFO",
			 session->focus_dialog->with,
			 session->focus_dialog->with,
			 hdr,
			 body,
			 session->focus_dialog,
			 NULL);
	g_free(body);
	g_free(hdr);
}

/** Invite counterparty to join conference callback */
static gboolean
process_invite_conf_response(struct sipe_core_private *sipe_private,
			     struct sipmsg *msg,
			     SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	struct sip_dialog *dialog = g_new0(struct sip_dialog, 1);

	dialog->callid = g_strdup(sipmsg_find_header(msg, "Call-ID"));
	dialog->cseq = parse_cseq(sipmsg_find_header(msg, "CSeq"));
	dialog->with = parse_from(sipmsg_find_header(msg, "To"));
	sipe_dialog_parse(dialog, msg, TRUE);

	if (msg->response >= 200) {
		/* send ACK to counterparty */
		dialog->cseq--;
		send_sip_request(sipe_private, "ACK", dialog->with, dialog->with, NULL, NULL, dialog, NULL);
		dialog->outgoing_invite = NULL;
		dialog->is_established = TRUE;
	}

	if (msg->response >= 400) {
		SIPE_DEBUG_INFO("process_invite_conf_response: INVITE response is not 200. Failed to invite %s.", dialog->with);
		/* @TODO notify user of failure to invite counterparty */
		sipe_dialog_free(dialog);
		return FALSE;
	}

	if (msg->response >= 200) {
		struct sip_session *session = sipe_session_find_im(sip, dialog->with);
		struct sip_dialog *im_dialog = sipe_dialog_find(session, dialog->with);

		/* close IM session to counterparty */
		if (im_dialog) {
			send_sip_request(sipe_private, "BYE", im_dialog->with, im_dialog->with, NULL, NULL, im_dialog, NULL);
			sipe_dialog_remove(session, dialog->with);
		}
	}

	sipe_dialog_free(dialog);
	return TRUE;
}

/**
 * Invites counterparty to join conference.
 */
void
sipe_invite_conf(struct sipe_account_data *sip,
		 struct sip_session *session,
		 const gchar* who)
{
	gchar *hdr;
	gchar *contact;
	gchar *body;
	struct sip_dialog *dialog = NULL;

	/* It will be short lived special dialog.
	 * Will not be stored in session.
	 */
	dialog = g_new0(struct sip_dialog, 1);
	dialog->callid = gencallid();
	dialog->with = g_strdup(who);
	dialog->ourtag = gentag();

	contact = get_contact(sip);
	hdr = g_strdup_printf(
		"Supported: ms-sender\r\n"
		"Contact: %s\r\n"
		"Content-Type: application/ms-conf-invite+xml\r\n",
		contact);
	g_free(contact);

	body = g_strdup_printf(
		SIPE_SEND_CONF_INVITE,
		session->focus_uri,
		session->subject ? session->subject : ""
		);

	send_sip_request( SIP_TO_CORE_PRIVATE,
			  "INVITE",
			  dialog->with,
			  dialog->with,
			  hdr,
			  body,
			  dialog,
			  process_invite_conf_response);

	sipe_dialog_free(dialog);
	g_free(body);
	g_free(hdr);
}

/** Create conference callback */
static gboolean
process_conf_add_response(struct sipe_core_private *sipe_private,
			  struct sipmsg *msg,
			  struct transaction *trans)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	
	if (msg->response >= 400) {
		SIPE_DEBUG_INFO_NOFORMAT("process_conf_add_response: SERVICE response is not 200. Failed to create conference.");
		/* @TODO notify user of failure to create conference */
		return FALSE;
	}
	if (msg->response == 200) {
		sipe_xml *xn_response = sipe_xml_parse(msg->body, msg->bodylen);
		if (sipe_strequal("success", sipe_xml_attribute(xn_response, "code")))
		{
			gchar *who = trans->payload->data;
			struct sip_session *session;
			const sipe_xml *xn_conference_info = sipe_xml_child(xn_response, "addConference/conference-info");

			session = sipe_session_add_chat(sip);
			session->is_multiparty = FALSE;
			session->focus_uri = g_strdup(sipe_xml_attribute(xn_conference_info, "entity"));
			SIPE_DEBUG_INFO("process_conf_add_response: session->focus_uri=%s",
					session->focus_uri ? session->focus_uri : "");

			session->pending_invite_queue = slist_insert_unique_sorted(
				session->pending_invite_queue, g_strdup(who), (GCompareFunc)strcmp);

			/* add self to conf */
			sipe_invite_conf_focus(sip, session);
		}
		sipe_xml_free(xn_response);
	}

	return TRUE;
}

/**
 * Creates conference.
 */
void
sipe_conf_add(struct sipe_account_data *sip,
	      const gchar* who)
{
	gchar *hdr;
	gchar *conference_id;
	gchar *contact;
	gchar *body;
	gchar *self;
	struct transaction *trans;
	struct sip_dialog *dialog = NULL;
	time_t expiry = time(NULL) + 7*60*60; /* 7 hours */
	char *expiry_time;
	struct transaction_payload *payload;

	contact = get_contact(sip);
	hdr = g_strdup_printf(
		"Supported: ms-sender\r\n"
		"Contact: %s\r\n"
		"Content-Type: application/cccp+xml\r\n",
		contact);
	g_free(contact);

	expiry_time = sipe_utils_time_to_str(expiry);
	self = sip_uri_self(sip);
	conference_id = genconfid();
	body = g_strdup_printf(
		SIPE_SEND_CONF_ADD,
		sip->focus_factory_uri,
		self,
		rand(),
		conference_id,
		expiry_time);
	g_free(self);
	g_free(conference_id);
	g_free(expiry_time);

	trans = send_sip_request( SIP_TO_CORE_PRIVATE,
				  "SERVICE",
				  sip->focus_factory_uri,
				  sip->focus_factory_uri,
				  hdr,
				  body,
				  NULL,
				  process_conf_add_response);

	payload = g_new0(struct transaction_payload, 1);
	payload->destroy = g_free;
	payload->data = g_strdup(who);
	trans->payload = payload;

	sipe_dialog_free(dialog);
	g_free(body);
	g_free(hdr);
}

void
process_incoming_invite_conf(struct sipe_account_data *sip,
			     struct sipmsg *msg)
{
	struct sip_session *session = NULL;
	struct sip_dialog *dialog = NULL;
	sipe_xml *xn_conferencing = sipe_xml_parse(msg->body, msg->bodylen);
	const sipe_xml *xn_focus_uri = sipe_xml_child(xn_conferencing, "focus-uri");
	char *focus_uri = sipe_xml_data(xn_focus_uri);
	gchar *newTag = gentag();
	const gchar *oldHeader = sipmsg_find_header(msg, "To");
	gchar *newHeader;

	sipe_xml_free(xn_conferencing);

	/* send OK */
	SIPE_DEBUG_INFO("We have received invitation to Conference. Focus URI=%s", focus_uri);

	newHeader = g_strdup_printf("%s;tag=%s", oldHeader, newTag);
	sipmsg_remove_header_now(msg, "To");
	sipmsg_add_header_now(msg, "To", newHeader);
	g_free(newHeader);

	/* temporary dialog with invitor */
	/* take data before 'msg' will be modified by send_sip_response */
	dialog = g_new0(struct sip_dialog, 1);
	dialog->callid = g_strdup(sipmsg_find_header(msg, "Call-ID"));
	dialog->cseq = parse_cseq(sipmsg_find_header(msg, "CSeq"));
	dialog->with = parse_from(sipmsg_find_header(msg, "From"));
	sipe_dialog_parse(dialog, msg, FALSE);

	send_sip_response(SIP_TO_CORE_PRIVATE, msg, 200, "OK", NULL);

	session = sipe_session_add_chat(sip);
	session->focus_uri = focus_uri;
	session->is_multiparty = FALSE;

	/* send BYE to invitor */
	send_sip_request(SIP_TO_CORE_PRIVATE, "BYE", dialog->with, dialog->with, NULL, NULL, dialog, NULL);
	sipe_dialog_free(dialog);

	/* add self to conf */
	sipe_invite_conf_focus(sip, session);
}

void
sipe_process_conference(struct sipe_account_data *sip,
			struct sipmsg *msg)
{
	sipe_xml *xn_conference_info;
	const sipe_xml *node;
	const sipe_xml *xn_subject;
	const gchar *focus_uri;
	struct sip_session *session;
	gboolean just_joined = FALSE;

	if (msg->response != 0 && msg->response != 200) return;

	if (msg->bodylen == 0 || msg->body == NULL || !sipe_strequal(sipmsg_find_header(msg, "Event"), "conference")) return;

	xn_conference_info = sipe_xml_parse(msg->body, msg->bodylen);
	if (!xn_conference_info) return;

	focus_uri = sipe_xml_attribute(xn_conference_info, "entity");
	session = sipe_session_find_conference(sip, focus_uri);

	if (!session) {
		SIPE_DEBUG_INFO("sipe_process_conference: unable to find conf session with focus=%s", focus_uri);
		return;
	}

	if (session->focus_uri && !session->conv) {
		gchar *chat_title = sipe_chat_get_name(session->focus_uri);
		gchar *self = sip_uri_self(sip);
		/* can't be find by chat id as it won't survive acc reinstantation */
		PurpleConversation *conv = NULL;

		if (chat_title) {
			conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
								     chat_title,
								     sip->account);
		}
		/* to be able to rejoin existing chat/window */
		if (conv && !purple_conv_chat_has_left(PURPLE_CONV_CHAT(conv))) {
			PURPLE_CONV_CHAT(conv)->left = TRUE;
		}
		/* create prpl chat */
		session->conv = serv_got_joined_chat(sip->gc, session->chat_id, chat_title);
		session->chat_title = chat_title;
		purple_conv_chat_set_nick(PURPLE_CONV_CHAT(session->conv), self);
		just_joined = TRUE;
		/* @TODO ask for full state (re-subscribe) if it was a partial one -
		 * this is to obtain full list of conference participants.
		 */
		 g_free(self);
	}

	/* subject */
	if ((xn_subject = sipe_xml_child(xn_conference_info, "conference-description/subject"))) {
		g_free(session->subject);
		session->subject = sipe_xml_data(xn_subject);
		purple_conv_chat_set_topic(PURPLE_CONV_CHAT(session->conv), NULL, session->subject);
		SIPE_DEBUG_INFO("sipe_process_conference: subject=%s", session->subject ? session->subject : "");
	}

	/* IM MCU URI */
	if (!session->im_mcu_uri) {
		for (node = sipe_xml_child(xn_conference_info, "conference-description/conf-uris/entry");
		     node;
		     node = sipe_xml_twin(node))
		{
			gchar *purpose = sipe_xml_data(sipe_xml_child(node, "purpose"));

			if (sipe_strequal("chat", purpose)) {
				g_free(purpose);
				session->im_mcu_uri = sipe_xml_data(sipe_xml_child(node, "uri"));
				SIPE_DEBUG_INFO("sipe_process_conference: im_mcu_uri=%s", session->im_mcu_uri);
				break;
			}
			g_free(purpose);
		}
	}

	/* users */
	for (node = sipe_xml_child(xn_conference_info, "users/user"); node; node = sipe_xml_twin(node)) {
		const gchar *user_uri = sipe_xml_attribute(node, "entity");
		const gchar *state = sipe_xml_attribute(node, "state");
		gchar *role  = sipe_xml_data(sipe_xml_child(node, "roles/entry"));
		PurpleConvChatBuddyFlags flags = PURPLE_CBFLAGS_NONE;
		PurpleConvChat *chat = PURPLE_CONV_CHAT(session->conv);
		gboolean is_in_im_mcu = FALSE;
		gchar *self = sip_uri_self(sip);

		if (sipe_strequal(role, "presenter")) {
			flags |= PURPLE_CBFLAGS_OP;
		}

		if (sipe_strequal("deleted", state)) {
			if (purple_conv_chat_find_user(chat, user_uri)) {
				purple_conv_chat_remove_user(chat, user_uri, NULL /* reason */);
			}
		} else {
			/* endpoints */
			const sipe_xml *endpoint;
			for (endpoint = sipe_xml_child(node, "endpoint"); endpoint; endpoint = sipe_xml_twin(endpoint)) {
				if (sipe_strequal("chat", sipe_xml_attribute(endpoint, "session-type"))) {
					gchar *status = sipe_xml_data(sipe_xml_child(endpoint, "status"));
					if (sipe_strequal("connected", status)) {
						is_in_im_mcu = TRUE;
						if (!purple_conv_chat_find_user(chat, user_uri)) {
							purple_conv_chat_add_user(chat, user_uri, NULL, flags,
										  !just_joined && g_strcasecmp(user_uri, self));
						} else {
							purple_conv_chat_user_set_flags(chat, user_uri, flags);
						}
					}
					g_free(status);
					break;
				}
			}
			if (!is_in_im_mcu) {
				if (purple_conv_chat_find_user(chat, user_uri)) {
					purple_conv_chat_remove_user(chat, user_uri, NULL /* reason */);
				}
			}
		}
		g_free(role);
		g_free(self);
	}

	/* entity-view, locked */
	for (node = sipe_xml_child(xn_conference_info, "conference-view/entity-view");
	     node;
	     node = sipe_xml_twin(node)) {

		const sipe_xml *xn_type = sipe_xml_child(node, "entity-state/media/entry/type");
		gchar *tmp = NULL;
		if (xn_type && sipe_strequal("chat", (tmp = sipe_xml_data(xn_type)))) {
			const sipe_xml *xn_locked = sipe_xml_child(node, "entity-state/locked");
			if (xn_locked) {
				gchar *locked = sipe_xml_data(xn_locked);
				gboolean prev_locked = session->locked;
				session->locked = sipe_strequal(locked, "true");
				if (prev_locked && !session->locked) {
					sipe_present_info(sip, session,
						_("This conference is no longer locked. Additional participants can now join."));
				}
				if (!prev_locked && session->locked) {
					sipe_present_info(sip, session,
						_("This conference is locked. Nobody else can join the conference while it is locked."));
				}

				SIPE_DEBUG_INFO("sipe_process_conference: session->locked=%s",
						session->locked ? "TRUE" : "FALSE");
				g_free(locked);
			}
		}
		g_free(tmp);
	}
	sipe_xml_free(xn_conference_info);

	if (session->im_mcu_uri) {
		struct sip_dialog *dialog = sipe_dialog_find(session, session->im_mcu_uri);
		if (!dialog) {
			dialog = sipe_dialog_add(session);

			dialog->callid = g_strdup(session->callid);
			dialog->with = g_strdup(session->im_mcu_uri);

			/* send INVITE to IM MCU */
			sipe_invite(sip, session, dialog->with, NULL, NULL, NULL, FALSE);
		}
	}

	sipe_process_pending_invite_queue(sip, session);
}

void
sipe_conf_immcu_closed(struct sipe_account_data *sip,
		       struct sip_session *session)
{
	sipe_present_info(sip, session,
			  _("You have been disconnected from this conference."));
	purple_conv_chat_clear_users(PURPLE_CONV_CHAT(session->conv));
}

void
conf_session_close(struct sipe_account_data *sip,
		   struct sip_session *session)
{
	if (session) {
		/* unsubscribe from focus */
		sipe_subscribe_conference(sip, session, 0);

		if (session->focus_dialog) {
			/* send BYE to focus */
			send_sip_request(SIP_TO_CORE_PRIVATE,
					 "BYE",
					 session->focus_dialog->with,
					 session->focus_dialog->with,
					 NULL,
					 NULL,
					 session->focus_dialog,
					 NULL);
		}
	}
}

void
sipe_process_imdn(struct sipe_account_data *sip,
		  struct sipmsg *msg)
{
	gchar *with = parse_from(sipmsg_find_header(msg, "From"));
	const gchar *call_id = sipmsg_find_header(msg, "Call-ID");
	static struct sip_session *session;
	sipe_xml *xn_imdn;
	const sipe_xml *node;
	gchar *message_id;
	gchar *message;

	session = sipe_session_find_chat_by_callid(sip, call_id);
	if (!session) {
		session = sipe_session_find_im(sip, with);
	}
	if (!session) {
		SIPE_DEBUG_INFO("sipe_process_imdn: unable to find conf session with call_id=%s", call_id);
		g_free(with);
		return;
	}

	xn_imdn = sipe_xml_parse(msg->body, msg->bodylen);
	message_id = sipe_xml_data(sipe_xml_child(xn_imdn, "message-id"));

	message = g_hash_table_lookup(session->conf_unconfirmed_messages, message_id);

	/* recipient */
	for (node = sipe_xml_child(xn_imdn, "recipient"); node; node = sipe_xml_twin(node)) {
		gchar *tmp = parse_from(sipe_xml_attribute(node, "uri"));
		gchar *uri = parse_from(tmp);
		sipe_present_message_undelivered_err(sip, session, -1, -1, uri, message);
		g_free(tmp);
		g_free(uri);
	}

	sipe_xml_free(xn_imdn);

	g_hash_table_remove(session->conf_unconfirmed_messages, message_id);
	SIPE_DEBUG_INFO("sipe_process_imdn: removed message %s from conf_unconfirmed_messages(count=%d)",
			message_id, g_hash_table_size(session->conf_unconfirmed_messages));
	g_free(message_id);
	g_free(with);
}


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
