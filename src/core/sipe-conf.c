/**
 * @file sipe-conf.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2014 SIPE Project <http://sipe.sourceforge.net/>
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
 * Documentation references:
 *
 * Microsoft DevNet: [MS-CONFIM]: Centralized Conference Control Protocol:
 *                                Instant Messaging Extensions
 *  <http://msdn.microsoft.com/en-us/library/cc431500%28v=office.12%29.aspx>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <glib.h>

#include "sipe-common.h"
#include "sipmsg.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-buddy.h"
#include "sipe-chat.h"
#include "sipe-conf.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-dialog.h"
#include "sipe-im.h"
#include "sipe-nls.h"
#include "sipe-session.h"
#include "sipe-subscriptions.h"
#include "sipe-user.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

#ifdef HAVE_VV
#define ENTITY_VIEW_AUDIO_VIDEO "<msci:entity-view entity=\"audio-video\"/>"
#else
#define ENTITY_VIEW_AUDIO_VIDEO
#endif

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
				ENTITY_VIEW_AUDIO_VIDEO \
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

/** Invite us to the focus callback */
static gboolean
process_invite_conf_focus_response(struct sipe_core_private *sipe_private,
				   struct sipmsg *msg,
				   SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	struct sip_session *session = NULL;
	char *focus_uri = parse_from(sipmsg_find_header(msg, "To"));

	session = sipe_session_find_conference(sipe_private, focus_uri);

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
		sip_transport_ack(sipe_private, session->focus_dialog);
		session->focus_dialog->outgoing_invite = NULL;
		session->focus_dialog->is_established = TRUE;
	}

	if (msg->response >= 400) {
		gchar *reason = sipmsg_get_ms_diagnostics_reason(msg);

		SIPE_DEBUG_INFO_NOFORMAT("process_invite_conf_focus_response: INVITE response is not 200. Failed to join focus.");
		sipe_backend_notify_error(SIPE_CORE_PUBLIC,
					  _("Failed to join the conference"),
					  reason ? reason : _("no reason given"));
		g_free(reason);

		sipe_session_remove(sipe_private, session);
		g_free(focus_uri);
		return FALSE;
	} else if (msg->response == 200) {
		sipe_xml *xn_response = sipe_xml_parse(msg->body, msg->bodylen);
		const gchar *code = sipe_xml_attribute(xn_response, "code");
		if (sipe_strequal(code, "success")) {
			/* subscribe to focus */
			sipe_subscribe_conference(sipe_private,
						  session->chat_session->id,
						  FALSE);
#ifdef HAVE_VV
			if (session->is_call)
				sipe_core_media_connect_conference(SIPE_CORE_PUBLIC,
								   session->chat_session);
#endif
		}
		sipe_xml_free(xn_response);
	}

	g_free(focus_uri);
	return TRUE;
}

static gchar *
parse_ocs_focus_uri(const gchar *uri)
{
	const gchar *confkey;
	size_t uri_len;

	if (!uri)
		return NULL;

	// URI can have this prefix if it was typed in by the user
	if (g_str_has_prefix(uri, "meet:") || g_str_has_prefix(uri, "conf:")) {
		uri += 5;
	}

	uri_len = strlen(uri);

	if (!uri || !g_str_has_prefix(uri, "sip:") ||
		uri_len == 4 || g_strstr_len(uri, -1, "%")) {
		return NULL;
	}

	confkey = g_strstr_len(uri, -1, "?");
	if (confkey) {
		/* TODO: Investigate how conf-key field should be used,
		 * ignoring for now */
		uri_len = confkey - uri;
	}

	return g_strndup(uri, uri_len);
}

static gchar *
parse_lync_join_url(const gchar *uri)
{
	gchar *focus_uri = NULL;
	gchar **parts;
	int parts_count = 0;

	if (!uri)
		return NULL;

	if (g_str_has_prefix(uri, "https://")) {
		uri += 8;
	} else if (g_str_has_prefix(uri, "http://")) {
		uri += 7;
	}

	parts = g_strsplit(uri, "/", 0);

	for (parts_count = 0; parts[parts_count]; ++parts_count);
	if (parts_count >= 3) {
		const gchar *conference_id   = parts[parts_count - 1];
		const gchar *organizer_alias = parts[parts_count - 2];

		gchar **domain_parts = g_strsplit(parts[0], ".", 2);

		/* we need to drop the first sub-domain from the URL */
		if (domain_parts[0] && domain_parts[1]) {
			focus_uri = g_strdup_printf("sip:%s@%s;gruu;opaque=app:conf:focus:id:%s",
						    organizer_alias,
						    domain_parts[1],
						    conference_id);
		}

		g_strfreev(domain_parts);
	}

	g_strfreev(parts);

	return focus_uri;
}

struct sip_session *
sipe_core_conf_create(struct sipe_core_public *sipe_public,
		      const gchar *uri)
{
	gchar *uri_ue = sipe_utils_uri_unescape(uri);
	gchar *focus_uri;
	struct sip_session *session = NULL;

	SIPE_DEBUG_INFO("sipe_core_conf_create: URI '%s' unescaped '%s'",
			uri    ? uri    : "<UNDEFINED>",
			uri_ue ? uri_ue : "<UNDEFINED>");

	focus_uri = parse_ocs_focus_uri(uri_ue);
	if (!focus_uri) {
		focus_uri = parse_lync_join_url(uri_ue);
	}

	if (focus_uri) {
		session = sipe_conf_create(SIPE_CORE_PRIVATE, NULL, focus_uri);
		g_free(focus_uri);
	} else {
		gchar *error = g_strdup_printf(_("\"%s\" is not a valid conference URI"),
					       uri ? uri : "");
		sipe_backend_notify_error(sipe_public,
					  _("Failed to join the conference"),
					  error);
		g_free(error);
	}

	g_free(uri_ue);

	return session;
}

/** Create new session with Focus URI */
struct sip_session *
sipe_conf_create(struct sipe_core_private *sipe_private,
		 struct sipe_chat_session *chat_session,
		 const gchar *focus_uri)
{
	gchar *hdr;
	gchar *contact;
	gchar *body;
	gchar *self;
	struct sip_session *session = sipe_session_add_chat(sipe_private,
							    chat_session,
							    FALSE,
							    focus_uri);

	session->focus_dialog = g_new0(struct sip_dialog, 1);
	session->focus_dialog->callid = gencallid();
	session->focus_dialog->with = g_strdup(session->chat_session->id);
	session->focus_dialog->endpoint_GUID = rand_guid();
	session->focus_dialog->ourtag = gentag();

	contact = get_contact(sipe_private);
	hdr = g_strdup_printf(
		"Supported: ms-sender\r\n"
		"Contact: %s\r\n"
		"Content-Type: application/cccp+xml\r\n",
		contact);
	g_free(contact);

	/* @TODO put request_id to queue to further compare with incoming one */
	/* focus_URI, from, request_id, focus_URI, from, endpoint_GUID */
	self = sip_uri_self(sipe_private);
	body = g_strdup_printf(
		SIPE_SEND_CONF_ADD_USER,
		session->focus_dialog->with,
		self,
		session->request_id++,
		session->focus_dialog->with,
		self,
		session->focus_dialog->endpoint_GUID);

	session->focus_dialog->outgoing_invite =
		sip_transport_invite(sipe_private,
				     hdr,
				     body,
				     session->focus_dialog,
				     process_invite_conf_focus_response);
	g_free(body);
	g_free(hdr);

	/* Rejoin existing session? */
	if (chat_session) {
		SIPE_DEBUG_INFO("sipe_conf_create: rejoin '%s' (%s)",
				chat_session->title,
				chat_session->id);
		sipe_backend_chat_rejoin(SIPE_CORE_PUBLIC,
					 chat_session->backend,
					 self,
					 chat_session->title);
	}
	g_free(self);

	return(session);
}

/** Modify User Role */
void
sipe_conf_modify_user_role(struct sipe_core_private *sipe_private,
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
	self = sip_uri_self(sipe_private);
	body = g_strdup_printf(
		SIPE_SEND_CONF_MODIFY_USER_ROLES,
		session->focus_dialog->with,
		self,
		session->request_id++,
		session->focus_dialog->with,
		who);
	g_free(self);

	sip_transport_info(sipe_private,
			   hdr,
			   body,
			   session->focus_dialog,
			   NULL);
	g_free(body);
	g_free(hdr);
}

/**
 * Check conference lock status
 */
sipe_chat_lock_status sipe_core_chat_lock_status(struct sipe_core_public *sipe_public,
						 struct sipe_chat_session *chat_session)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	sipe_chat_lock_status status = SIPE_CHAT_LOCK_STATUS_NOT_ALLOWED;

	if (chat_session &&
	    (chat_session->type == SIPE_CHAT_TYPE_CONFERENCE)) {
		struct sip_session *session = sipe_session_find_chat(sipe_private,
								     chat_session);
		if (session) {
			gchar *self = sip_uri_self(sipe_private);

			/* Only operators are allowed to change the lock status */
			if (sipe_backend_chat_is_operator(chat_session->backend, self)) {
				status = session->locked ?
					SIPE_CHAT_LOCK_STATUS_LOCKED :
					SIPE_CHAT_LOCK_STATUS_UNLOCKED;
			}

			g_free(self);
		}
	}

	return(status);
}

/**
 * Modify Conference Lock
 * Sends request to Focus.
 * INFO method is a carrier of application/cccp+xml
 */
void
sipe_core_chat_modify_lock(struct sipe_core_public *sipe_public,
			   struct sipe_chat_session *chat_session,
			   const gboolean locked)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	gchar *hdr;
	gchar *body;
	gchar *self;

	struct sip_session *session = sipe_session_find_chat(sipe_private,
							     chat_session);

	if (!session) return;
	if (!session->focus_dialog || !session->focus_dialog->is_established) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_conf_modify_conference_lock: no dialog with focus, exiting.");
		return;
	}

	hdr = g_strdup(
		"Content-Type: application/cccp+xml\r\n");

	/* @TODO put request_id to queue to further compare with incoming one */
	self = sip_uri_self(sipe_private);
	body = g_strdup_printf(
		SIPE_SEND_CONF_MODIFY_CONF_LOCK,
		session->focus_dialog->with,
		self,
		session->request_id++,
		session->focus_dialog->with,
		locked ? "true" : "false");
	g_free(self);

	sip_transport_info(sipe_private,
			   hdr,
			   body,
			   session->focus_dialog,
			   NULL);
	g_free(body);
	g_free(hdr);
}

/** Modify Delete User */
void
sipe_conf_delete_user(struct sipe_core_private *sipe_private,
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
	self = sip_uri_self(sipe_private);
	body = g_strdup_printf(
		SIPE_SEND_CONF_DELETE_USER,
		session->focus_dialog->with,
		self,
		session->request_id++,
		session->focus_dialog->with,
		who);
	g_free(self);

	sip_transport_info(sipe_private,
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
	struct sip_dialog *dialog = g_new0(struct sip_dialog, 1);

	dialog->callid = g_strdup(sipmsg_find_header(msg, "Call-ID"));
	dialog->cseq = sipmsg_parse_cseq(msg);
	dialog->with = parse_from(sipmsg_find_header(msg, "To"));
	sipe_dialog_parse(dialog, msg, TRUE);

	if (msg->response >= 200) {
		/* send ACK to counterparty */
		dialog->cseq--;
		sip_transport_ack(sipe_private, dialog);
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
		struct sip_session *session = sipe_session_find_im(sipe_private, dialog->with);
		struct sip_dialog *im_dialog = sipe_dialog_find(session, dialog->with);

		/* close IM session to counterparty */
		if (im_dialog) {
			sip_transport_bye(sipe_private, im_dialog);
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
sipe_invite_conf(struct sipe_core_private *sipe_private,
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

	contact = get_contact(sipe_private);
	hdr = g_strdup_printf(
		"Supported: ms-sender\r\n"
		"Contact: %s\r\n"
		"Content-Type: application/ms-conf-invite+xml\r\n",
		contact);
	g_free(contact);

	body = g_strdup_printf(
		SIPE_SEND_CONF_INVITE,
		session->chat_session->id,
		session->subject ? session->subject : ""
		);

	sip_transport_invite(sipe_private,
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
			const sipe_xml *xn_conference_info = sipe_xml_child(xn_response, "addConference/conference-info");
			struct sip_session *session = sipe_conf_create(sipe_private,
								       NULL,
								       sipe_xml_attribute(xn_conference_info,
											  "entity"));

			SIPE_DEBUG_INFO("process_conf_add_response: session->focus_uri=%s",
					session->chat_session->id);

			session->pending_invite_queue = sipe_utils_slist_insert_unique_sorted(session->pending_invite_queue,
											      g_strdup(who),
											      (GCompareFunc)strcmp,
											      g_free);
		}
		sipe_xml_free(xn_response);
	}

	return TRUE;
}

/**
 * Creates conference.
 */
void
sipe_conf_add(struct sipe_core_private *sipe_private,
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

	contact = get_contact(sipe_private);
	hdr = g_strdup_printf(
		"Supported: ms-sender\r\n"
		"Contact: %s\r\n"
		"Content-Type: application/cccp+xml\r\n",
		contact);
	g_free(contact);

	expiry_time = sipe_utils_time_to_str(expiry);
	self = sip_uri_self(sipe_private);
	conference_id = genconfid();
	body = g_strdup_printf(
		SIPE_SEND_CONF_ADD,
		sipe_private->focus_factory_uri,
		self,
		rand(),
		conference_id,
		expiry_time);
	g_free(self);
	g_free(conference_id);
	g_free(expiry_time);

	trans = sip_transport_service(sipe_private,
				      sipe_private->focus_factory_uri,
				      hdr,
				      body,
				      process_conf_add_response);

	payload = g_new0(struct transaction_payload, 1);
	payload->destroy = g_free;
	payload->data = g_strdup(who);
	trans->payload = payload;

	sipe_dialog_free(dialog);
	g_free(body);
	g_free(hdr);
}

static void
accept_incoming_invite_conf(struct sipe_core_private *sipe_private,
			    gchar *focus_uri,
			    gboolean audio,
			    struct sipmsg *msg)
{
	struct sip_session *session;
	gchar *newTag = gentag();
	const gchar *oldHeader = sipmsg_find_header(msg, "To");
	gchar *newHeader;

	newHeader = g_strdup_printf("%s;tag=%s", oldHeader, newTag);
	g_free(newTag);
	sipmsg_remove_header_now(msg, "To");
	sipmsg_add_header_now(msg, "To", newHeader);
	g_free(newHeader);

	/* acknowledge invite */
	sip_transport_response(sipe_private, msg, 200, "OK", NULL);

	/* add self to conf */
	session = sipe_conf_create(sipe_private, NULL, focus_uri);
	session->is_call = audio;
}

struct conf_accept_ctx {
	gchar *focus_uri;
	struct sipmsg *msg;
	struct sipe_user_ask_ctx *ask_ctx;
};

static void
conf_accept_ctx_free(struct conf_accept_ctx *ctx)
{
	g_return_if_fail(ctx != NULL);

	sipmsg_free(ctx->msg);
	g_free(ctx->focus_uri);
	g_free(ctx);
}

static void
conf_accept_cb(struct sipe_core_private *sipe_private, struct conf_accept_ctx *ctx)
{
	sipe_private->sessions_to_accept =
			g_slist_remove(sipe_private->sessions_to_accept, ctx);

	accept_incoming_invite_conf(sipe_private, ctx->focus_uri, TRUE, ctx->msg);
	conf_accept_ctx_free(ctx);
}

static void
conf_decline_cb(struct sipe_core_private *sipe_private, struct conf_accept_ctx *ctx)
{
	sipe_private->sessions_to_accept =
			g_slist_remove(sipe_private->sessions_to_accept, ctx);

	sip_transport_response(sipe_private,
			       ctx->msg,
			       603, "Decline", NULL);

	conf_accept_ctx_free(ctx);
}

void
sipe_conf_cancel_unaccepted(struct sipe_core_private *sipe_private,
			    struct sipmsg *msg)
{
	const gchar *callid1 = msg ? sipmsg_find_header(msg, "Call-ID") : NULL;
	GSList *it = sipe_private->sessions_to_accept;
	while (it) {
		struct conf_accept_ctx *ctx = it->data;
		const gchar *callid2 = NULL;

		if (msg && ctx->msg)
			callid2 = sipmsg_find_header(ctx->msg, "Call-ID");

		if (sipe_strequal(callid1, callid2)) {
			GSList *tmp;

			if (ctx->msg)
				sip_transport_response(sipe_private, ctx->msg,
						       487, "Request Terminated", NULL);

			if (msg)
				sip_transport_response(sipe_private, msg, 200, "OK", NULL);

			sipe_user_close_ask(ctx->ask_ctx);
			conf_accept_ctx_free(ctx);

			tmp = it;
			it = it->next;

			sipe_private->sessions_to_accept =
				g_slist_delete_link(sipe_private->sessions_to_accept, tmp);

			if (callid1)
				break;
		} else
			it = it->next;
	}
}

static void
ask_accept_voice_conference(struct sipe_core_private *sipe_private,
			    const gchar *focus_uri,
			    struct sipmsg *msg,
			    SipeUserAskCb accept_cb,
			    SipeUserAskCb decline_cb)
{
	gchar **parts;
	gchar *alias;
	gchar *ask_msg;
	const gchar *novv_note;
	struct conf_accept_ctx *ctx;

#ifdef HAVE_VV
	novv_note = "";
#else
	novv_note = _("\n\nAs this client was not compiled with voice call "
		      "support, if you accept, you will be able to contact "
		      "the other participants only via IM session.");
#endif

	parts = g_strsplit(focus_uri, ";", 2);
	alias = sipe_buddy_get_alias(sipe_private, parts[0]);

	ask_msg = g_strdup_printf(_("%s wants to invite you "
				  "to the conference call%s"),
				  alias ? alias : parts[0], novv_note);

	g_free(alias);
	g_strfreev(parts);

	ctx = g_new0(struct conf_accept_ctx, 1);
	sipe_private->sessions_to_accept =
			g_slist_append(sipe_private->sessions_to_accept, ctx);

	ctx->focus_uri = g_strdup(focus_uri);
	ctx->msg = msg ? sipmsg_copy(msg) : NULL;
	ctx->ask_ctx = sipe_user_ask(sipe_private, ask_msg,
				     _("Accept"), accept_cb,
				     _("Decline"), decline_cb,
				     ctx);

	g_free(ask_msg);
}

void
process_incoming_invite_conf(struct sipe_core_private *sipe_private,
			     struct sipmsg *msg)
{
	sipe_xml *xn_conferencing = sipe_xml_parse(msg->body, msg->bodylen);
	const sipe_xml *xn_focus_uri = sipe_xml_child(xn_conferencing, "focus-uri");
	const sipe_xml *xn_audio = sipe_xml_child(xn_conferencing, "audio");
	gchar *focus_uri = sipe_xml_data(xn_focus_uri);
	gboolean audio = sipe_strequal(sipe_xml_attribute(xn_audio, "available"), "true");

	sipe_xml_free(xn_conferencing);

	SIPE_DEBUG_INFO("We have received invitation to Conference. Focus URI=%s", focus_uri);

	if (audio) {
		sip_transport_response(sipe_private, msg, 180, "Ringing", NULL);
		ask_accept_voice_conference(sipe_private, focus_uri, msg,
					    (SipeUserAskCb) conf_accept_cb,
					    (SipeUserAskCb) conf_decline_cb);

	} else {
		accept_incoming_invite_conf(sipe_private, focus_uri, FALSE, msg);
	}

	g_free(focus_uri);
}

#ifdef HAVE_VV

static void
call_accept_cb(struct sipe_core_private *sipe_private, struct conf_accept_ctx *ctx)
{
	struct sip_session *session;
	session = sipe_session_find_conference(sipe_private, ctx->focus_uri);

	sipe_private->sessions_to_accept =
			g_slist_remove(sipe_private->sessions_to_accept, ctx);

	if (session) {
		sipe_core_media_connect_conference(SIPE_CORE_PUBLIC,
						   session->chat_session);
	}

	conf_accept_ctx_free(ctx);
}

static void
call_decline_cb(struct sipe_core_private *sipe_private, struct conf_accept_ctx *ctx)
{
	sipe_private->sessions_to_accept =
			g_slist_remove(sipe_private->sessions_to_accept, ctx);

	conf_accept_ctx_free(ctx);
}

#endif // HAVE_VV

void
sipe_process_conference(struct sipe_core_private *sipe_private,
			struct sipmsg *msg)
{
	sipe_xml *xn_conference_info;
	const sipe_xml *node;
	const sipe_xml *xn_subject;
	const gchar *focus_uri;
	struct sip_session *session;
	gboolean just_joined = FALSE;
#ifdef HAVE_VV
	gboolean audio_was_added = FALSE;
#endif

	if (msg->response != 0 && msg->response != 200) return;

	if (msg->bodylen == 0 || msg->body == NULL || !sipe_strequal(sipmsg_find_header(msg, "Event"), "conference")) return;

	xn_conference_info = sipe_xml_parse(msg->body, msg->bodylen);
	if (!xn_conference_info) return;

	focus_uri = sipe_xml_attribute(xn_conference_info, "entity");
	session = sipe_session_find_conference(sipe_private, focus_uri);

	if (!session) {
		SIPE_DEBUG_INFO("sipe_process_conference: unable to find conf session with focus=%s", focus_uri);
		return;
	}

	if (!session->chat_session->backend) {
		gchar *self = sip_uri_self(sipe_private);

		/* create chat */
		session->chat_session->backend = sipe_backend_chat_create(SIPE_CORE_PUBLIC,
									  session->chat_session,
									  session->chat_session->title,
									  self);
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
		sipe_backend_chat_topic(session->chat_session->backend, session->subject);
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
		gchar *role = sipe_xml_data(sipe_xml_child(node, "roles/entry"));
		gboolean is_operator = sipe_strequal(role, "presenter");
		gboolean is_in_im_mcu = FALSE;
		gchar *self = sip_uri_self(sipe_private);

		if (sipe_strequal("deleted", state)) {
			if (sipe_backend_chat_find(session->chat_session->backend, user_uri)) {
				sipe_backend_chat_remove(session->chat_session->backend,
							 user_uri);
			}
		} else {
			/* endpoints */
			const sipe_xml *endpoint;
			for (endpoint = sipe_xml_child(node, "endpoint"); endpoint; endpoint = sipe_xml_twin(endpoint)) {
				const gchar *session_type;
				gchar *status = sipe_xml_data(sipe_xml_child(endpoint, "status"));
				gboolean connected = sipe_strequal("connected", status);
				g_free(status);

				if (!connected)
					continue;

				session_type = sipe_xml_attribute(endpoint, "session-type");

				if (sipe_strequal("chat", session_type)) {
					is_in_im_mcu = TRUE;
					if (!sipe_backend_chat_find(session->chat_session->backend, user_uri)) {
						sipe_backend_chat_add(session->chat_session->backend,
								      user_uri,
								      !just_joined && g_ascii_strcasecmp(user_uri, self));
					}
					if (is_operator) {
						sipe_backend_chat_operator(session->chat_session->backend,
									   user_uri);
					}
				} else if (sipe_strequal("audio-video", session_type)) {
#ifdef HAVE_VV
					if (!session->is_call)
						audio_was_added = TRUE;
#endif
				}
			}
			if (!is_in_im_mcu) {
				if (sipe_backend_chat_find(session->chat_session->backend, user_uri)) {
					sipe_backend_chat_remove(session->chat_session->backend,
								 user_uri);
				}
			}
		}
		g_free(role);
		g_free(self);
	}

#ifdef HAVE_VV
	if (audio_was_added) {
		session->is_call = TRUE;
		ask_accept_voice_conference(sipe_private, focus_uri, NULL,
					    (SipeUserAskCb) call_accept_cb,
					    (SipeUserAskCb) call_decline_cb);
	}
#endif

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
					sipe_user_present_info(sipe_private, session,
							       _("This conference is no longer locked. Additional participants can now join."));
				}
				if (!prev_locked && session->locked) {
					sipe_user_present_info(sipe_private, session,
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
			sipe_im_invite(sipe_private, session, dialog->with, NULL, NULL, NULL, FALSE);
		}
	}

	sipe_process_pending_invite_queue(sipe_private, session);
}

void
sipe_conf_immcu_closed(struct sipe_core_private *sipe_private,
		       struct sip_session *session)
{
	sipe_user_present_info(sipe_private, session,
			       _("You have been disconnected from this conference."));
	sipe_backend_chat_close(session->chat_session->backend);
}

void
conf_session_close(struct sipe_core_private *sipe_private,
		   struct sip_session *session)
{
	if (session) {
		/* unsubscribe from focus */
		sipe_subscribe_conference(sipe_private,
					  session->chat_session->id, TRUE);

		if (session->focus_dialog) {
			/* send BYE to focus */
			sip_transport_bye(sipe_private, session->focus_dialog);
		}
	}
}

void
sipe_process_imdn(struct sipe_core_private *sipe_private,
		  struct sipmsg *msg)
{
	gchar *with = parse_from(sipmsg_find_header(msg, "From"));
	const gchar *callid = sipmsg_find_header(msg, "Call-ID");
	static struct sip_session *session;
	sipe_xml *xn_imdn;
	const sipe_xml *node;
	gchar *message_id;
	gchar *message;

	session = sipe_session_find_chat_or_im(sipe_private, callid, with);
	if (!session) {
		SIPE_DEBUG_INFO("sipe_process_imdn: unable to find conf session with callid=%s", callid);
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
		gchar *status = sipe_xml_data(sipe_xml_child(node, "status"));
		guint error = status ? g_ascii_strtoull(status, NULL, 10) : 0;
		/* default to error if missing or conversion failed */
		if ((error == 0) || (error >= 300))
			sipe_user_present_message_undelivered(sipe_private,
							      session,
							      error,
							      -1,
							      uri,
							      message);
		g_free(status);
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

void sipe_core_conf_make_leader(struct sipe_core_public *sipe_public,
				gpointer parameter,
				const gchar *buddy_name)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_chat_session *chat_session = parameter;
	struct sip_session *session;

	SIPE_DEBUG_INFO("sipe_core_conf_make_leader: chat_title=%s",
			chat_session->title);

	session = sipe_session_find_chat(sipe_private, chat_session);
	sipe_conf_modify_user_role(sipe_private, session, buddy_name);
}

void sipe_core_conf_remove_from(struct sipe_core_public *sipe_public,
				gpointer parameter,
				const gchar *buddy_name)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_chat_session *chat_session = parameter;
	struct sip_session *session;

	SIPE_DEBUG_INFO("sipe_core_conf_remove_from: chat_title=%s",
			chat_session->title);

	session = sipe_session_find_chat(sipe_private, chat_session);
	sipe_conf_delete_user(sipe_private, session, buddy_name);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
