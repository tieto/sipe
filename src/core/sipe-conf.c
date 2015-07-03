/**
 * @file sipe-conf.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2016 SIPE Project <http://sipe.sourceforge.net/>
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
#include "sipe-http.h"
#include "sipe-im.h"
#include "sipe-nls.h"
#include "sipe-session.h"
#include "sipe-subscriptions.h"
#include "sipe-user.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

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

static gboolean
sipe_conf_check_for_lync_url(struct sipe_core_private *sipe_private,
			     gchar *uri);

static struct transaction *
cccp_request(struct sipe_core_private *sipe_private, const gchar *method,
	     const gchar *with, struct sip_dialog *dialog,
	     TransCallback callback, const gchar *body, ...)
{
	gchar *headers;
	gchar *request;
	gchar *request_body;

	gchar *self = sip_uri_self(sipe_private);

	va_list args;

	struct transaction *trans;

	headers = g_strdup_printf(
		"Supported: ms-sender\r\n"
		"Contact: %s\r\n"
		"Content-Type: application/cccp+xml\r\n",
		sipe_private->contact);

	/* TODO: put request_id to queue to further compare with incoming one */
	request = g_strdup_printf(
		"<?xml version=\"1.0\"?>"
		"<request xmlns=\"urn:ietf:params:xml:ns:cccp\" "
		"xmlns:mscp=\"http://schemas.microsoft.com/rtc/2005/08/cccpextensions\" "
			"C3PVersion=\"1\" "
			"to=\"%s\" "
			"from=\"%s\" "
			"requestId=\"%d\">"
			"%s"
		"</request>",
		with,
		self,
		sipe_private->cccp_request_id++,
		body);
	g_free(self);

	va_start(args, body);
	request_body = g_strdup_vprintf(request, args);
	va_end(args);

	g_free(request);

	trans = sip_transport_request(sipe_private,
				      method,
				      with,
				      with,
				      headers,
				      request_body,
				      dialog,
				      callback);

	g_free(headers);
	g_free(request_body);

	return trans;
}

static gboolean
process_conf_get_capabilities(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private,
			      struct sipmsg *msg,
			      SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	if (msg->response >= 400) {
		SIPE_DEBUG_INFO_NOFORMAT("process_conf_get_capabilities: "
				"getConferencingCapabilities failed.");
		return FALSE;
	}
	if (msg->response == 200) {
		sipe_xml *xn_response = sipe_xml_parse(msg->body, msg->bodylen);
		const sipe_xml *node;
		gchar *default_region;

		if (!sipe_strequal("success", sipe_xml_attribute(xn_response, "code"))) {
			return TRUE;
		}

		node = sipe_xml_child(xn_response, "getConferencingCapabilities/mcu-types/mcuType");
		for (;node; node = sipe_xml_twin(node)) {
			sipe_private->conf_mcu_types =
					g_slist_append(sipe_private->conf_mcu_types,
						       sipe_xml_data(node));
		}

		g_hash_table_remove_all(sipe_private->access_numbers);
		node = sipe_xml_child(xn_response, "getConferencingCapabilities/pstn-bridging/access-numbers/region");
		for (;node; node = sipe_xml_twin(node)) {
			gchar *name = g_strdup(sipe_xml_attribute(node, "name"));
			gchar *number = sipe_xml_data(sipe_xml_child(node, "access-number/number"));
			if (name && number) {
				g_hash_table_insert(sipe_private->access_numbers, name, number);
			}
		}

		node = sipe_xml_child(xn_response, "getConferencingCapabilities/pstn-bridging/access-numbers/default-region");
		default_region = sipe_xml_data(node);
		if (default_region) {
			sipe_private->default_access_number =
					g_hash_table_lookup(sipe_private->access_numbers, default_region);
		}
		g_free(default_region);

		sipe_xml_free(xn_response);
	}

	return TRUE;
}

void
sipe_conf_get_capabilities(struct sipe_core_private *sipe_private)
{
	cccp_request(sipe_private, "SERVICE",
		     sipe_private->focus_factory_uri,
		     NULL,
		     process_conf_get_capabilities,
		     "<getConferencingCapabilities />");
}

gboolean
sipe_conf_supports_mcu_type(struct sipe_core_private *sipe_private,
			    const gchar *type)
{
	return g_slist_find_custom(sipe_private->conf_mcu_types, type,
				   sipe_strcompare) != NULL;
}

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
extract_uri_from_html(const gchar *body,
		      const gchar *prefix,
		      guint prefix_skip_chars)
{
	gchar *uri = NULL;
	const gchar *start = g_strstr_len(body, -1, prefix);

	if (start) {
		const gchar *end;

		start += prefix_skip_chars;
		end = strchr(start, '"');

		if (end) {
			gchar *html = g_strndup(start, end - start);

			/* decode HTML entities */
			gchar *html_unescaped = sipe_backend_markup_strip_html(html);
			g_free(html);

			if (!is_empty(html_unescaped)) {
				uri = sipe_utils_uri_unescape(html_unescaped);
			}

			g_free(html_unescaped);
		}
	}

	return uri;
}

static void sipe_conf_lync_url_cb(struct sipe_core_private *sipe_private,
				  guint status,
				  SIPE_UNUSED_PARAMETER GSList *headers,
				  const gchar *body,
				  gpointer callback_data)
{
	gchar *uri = callback_data;

	if (status != (guint) SIPE_HTTP_STATUS_ABORTED) {
		gchar *focus_uri = NULL;

		if (body) {
			/*
			 * Extract focus URI from HTML, e.g.
			 *
			 *  <a ... href="conf&#58;sip&#58;...ABCDEF&#37;3Frequired..." ... >
			 */
			gchar *uri = extract_uri_from_html(body, "href=\"conf", 6);
			focus_uri = parse_ocs_focus_uri(uri);
			g_free(uri);
		}

		if (focus_uri) {
			SIPE_DEBUG_INFO("sipe_conf_lync_url_cb: found focus URI"
					" '%s'", focus_uri);

			sipe_conf_create(sipe_private, NULL, focus_uri);
			g_free(focus_uri);
		} else {
			/*
			 * If present, domainOwnerJoinLauncherUrl redirects to
			 * a page from where we still may extract the focus URI.
			 */
			gchar *launcher_url;
			static const gchar launcher_url_prefix[] =
					"var domainOwnerJoinLauncherUrl = \"";

			SIPE_DEBUG_INFO("sipe_conf_lync_url_cb: no focus URI "
					"found from URL '%s'", uri);

			launcher_url = extract_uri_from_html(body,
							     launcher_url_prefix,
							     sizeof (launcher_url_prefix) - 1);

			if (launcher_url &&
			    sipe_conf_check_for_lync_url(sipe_private, launcher_url)) {
				SIPE_DEBUG_INFO("sipe_conf_lync_url_cb: retrying with URL '%s'",
						launcher_url);
				/* Ownership taken by sipe_conf_check_for_lync_url() */
				launcher_url = NULL;
			} else {
				gchar *error;

				error = g_strdup_printf(_("Can't find a conference URI on this page:\n\n%s"),
							uri);

				sipe_backend_notify_error(SIPE_CORE_PUBLIC,
							  _("Failed to join the conference"),
							  error);
				g_free(error);
			}

			g_free(launcher_url);
		}
	}

	g_free(uri);
}

static gboolean sipe_conf_check_for_lync_url(struct sipe_core_private *sipe_private,
					     gchar *uri)
{
	if (!(g_str_has_prefix(uri, "https://") ||
	      g_str_has_prefix(uri, "http://")))
		return(FALSE);

	/* URL points to a HTML page with the conference focus URI */
	return(sipe_http_request_get(sipe_private,
				     uri,
				     NULL,
				     sipe_conf_lync_url_cb,
				     uri)
	       != NULL);
}

static void sipe_conf_uri_error(struct sipe_core_private *sipe_private,
				const gchar *uri)
{
	gchar *error = g_strdup_printf(_("\"%s\" is not a valid conference URI"),
				       uri ? uri : "");
	sipe_backend_notify_error(SIPE_CORE_PUBLIC,
				  _("Failed to join the conference"),
				  error);
	g_free(error);
}

void sipe_core_conf_create(struct sipe_core_public *sipe_public,
			   const gchar *uri,
			   const gchar *organizer,
			   const gchar *meeting_id)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;

	/* SIP URI or HTTP URL */
	if (uri) {
		gchar *uri_ue = sipe_utils_uri_unescape(uri);

		SIPE_DEBUG_INFO("sipe_core_conf_create: URI '%s' unescaped '%s'",
				uri,
				uri_ue ? uri_ue : "<UNDEFINED>");

		/* takes ownership of "uri_ue" if successful */
		if (!sipe_conf_check_for_lync_url(sipe_private, uri_ue)) {
			gchar *focus_uri = parse_ocs_focus_uri(uri_ue);

			if (focus_uri) {
				sipe_conf_create(sipe_private, NULL, focus_uri);
				g_free(focus_uri);
			} else
				sipe_conf_uri_error(sipe_private, uri);

			g_free(uri_ue);
		}

	/* Organizer email and meeting ID */
	} else if (organizer && meeting_id) {
		gchar *tmp = g_strdup_printf("sip:%s;gruu;opaque=app:conf:focus:id:%s",
					     organizer, meeting_id);
		gchar *focus_uri = parse_ocs_focus_uri(tmp);

		SIPE_DEBUG_INFO("sipe_core_conf_create: organizer '%s' meeting ID '%s'",
				organizer,
				meeting_id);

		if (focus_uri) {
			sipe_conf_create(sipe_private, NULL, focus_uri);
			g_free(focus_uri);
		} else
			sipe_conf_uri_error(sipe_private, tmp);
		g_free(tmp);

	} else {
		sipe_backend_notify_error(SIPE_CORE_PUBLIC,
					  _("Failed to join the conference"),
					  _("Incomplete conference information provided"));
	}
}

/** Create new session with Focus URI */
struct sip_session *
sipe_conf_create(struct sipe_core_private *sipe_private,
		 struct sipe_chat_session *chat_session,
		 const gchar *focus_uri)
{
	/* addUser request to the focus.
	 *
	 * focus_URI, from, endpoint_GUID
	 */
	static const gchar CCCP_ADD_USER[] =
		"<addUser>"
			"<conferenceKeys confEntity=\"%s\"/>"
			"<ci:user xmlns:ci=\"urn:ietf:params:xml:ns:conference-info\" entity=\"%s\">"
				"<ci:roles>"
					"<ci:entry>attendee</ci:entry>"
				"</ci:roles>"
				"<ci:endpoint entity=\"{%s}\" "
					      "xmlns:msci=\"http://schemas.microsoft.com/rtc/2005/08/confinfoextensions\"/>"
			"</ci:user>"
		"</addUser>";

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

	self = sip_uri_self(sipe_private);
	session->focus_dialog->outgoing_invite =
		cccp_request(sipe_private, "INVITE",
			     session->focus_dialog->with, session->focus_dialog,
			     process_invite_conf_focus_response,
			     CCCP_ADD_USER,
			     session->focus_dialog->with, self,
			     session->focus_dialog->endpoint_GUID);

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
	/* modifyUserRoles request to the focus. Makes user a leader.
	 *
	 * focus_uri (%s)
	 * who (%s)
	 */
	static const gchar CCCP_MODIFY_USER_ROLES[] =
		"<modifyUserRoles>"
			"<userKeys confEntity=\"%s\" userEntity=\"%s\"/>"
			"<user-roles xmlns=\"urn:ietf:params:xml:ns:conference-info\">"
				"<entry>presenter</entry>"
			"</user-roles>"
		"</modifyUserRoles>";

	if (!session->focus_dialog || !session->focus_dialog->is_established) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_conf_modify_user_role: no dialog with focus, exiting.");
		return;
	}

	cccp_request(sipe_private, "INFO", session->focus_dialog->with,
		     session->focus_dialog, NULL,
		     CCCP_MODIFY_USER_ROLES,
		     session->focus_dialog->with, who);
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
	/* modifyConferenceLock request to the focus. Locks/unlocks conference.
	 *
	 * focus_uri (%s)
	 * locked (%s) "true" or "false" values applicable
	 */
	static const gchar CCCP_MODIFY_CONFERENCE_LOCK[] =
		"<modifyConferenceLock>"
			"<conferenceKeys confEntity=\"%s\"/>"
			"<locked>%s</locked>"
		"</modifyConferenceLock>";

	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;

	struct sip_session *session = sipe_session_find_chat(sipe_private,
							     chat_session);

	if (!session) return;
	if (!session->focus_dialog || !session->focus_dialog->is_established) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_conf_modify_conference_lock: no dialog with focus, exiting.");
		return;
	}

	cccp_request(sipe_private, "INFO", session->focus_dialog->with,
		     session->focus_dialog, NULL,
		     CCCP_MODIFY_CONFERENCE_LOCK,
		     session->focus_dialog->with,
		     locked ? "true" : "false");
}

/** Modify Delete User */
void
sipe_conf_delete_user(struct sipe_core_private *sipe_private,
		      struct sip_session *session,
		      const gchar* who)
{
	/* deleteUser request to the focus. Removes a user from the conference.
	 *
	 * focus_uri (%s)
	 * who (%s)
	 */
	static const gchar CCCP_DELETE_USER[] =
		"<deleteUser>"
			"<userKeys confEntity=\"%s\" userEntity=\"%s\"/>"
		"</deleteUser>";

	if (!session->focus_dialog || !session->focus_dialog->is_established) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_conf_delete_user: no dialog with focus, exiting.");
		return;
	}

	cccp_request(sipe_private, "INFO", session->focus_dialog->with,
		     session->focus_dialog, NULL,
		     CCCP_DELETE_USER,
		     session->focus_dialog->with, who);
}

void
sipe_conf_announce_audio_mute_state(struct sipe_core_private *sipe_private,
				    struct sip_session *session,
				    gboolean is_muted)
{
	// See [MS-CONFAV] 3.2.5.4 and 4.3
	static const gchar CCCP_MODIFY_ENDPOINT_MEDIA[] =
		"<modifyEndpointMedia mscp:mcuUri=\"%s\""
		" xmlns:mscp=\"http://schemas.microsoft.com/rtc/2005/08/cccpextensions\">"
			"<mediaKeys confEntity=\"%s\" userEntity=\"%s\""
			" endpointEntity=\"%s\" mediaId=\"%d\"/>"
			"<ci:media"
			" xmlns:ci=\"urn:ietf:params:xml:ns:conference-info\" id=\"%d\">"
				"<ci:type>audio</ci:type>"
				"<ci:status>%s</ci:status>"
				"<media-ingress-filter"
				" xmlns=\"http://schemas.microsoft.com/rtc/2005/08/confinfoextensions\">"
					"%s"
				"</media-ingress-filter>"
			"</ci:media>"
		"</modifyEndpointMedia>";

	gchar *mcu_uri = sipe_conf_build_uri(session->focus_dialog->with,
					     "audio-video");
	gchar *self = sip_uri_self(sipe_private);

	cccp_request(sipe_private, "INFO", session->focus_dialog->with,
		     session->focus_dialog, NULL,
		     CCCP_MODIFY_ENDPOINT_MEDIA,
		     mcu_uri, session->focus_dialog->with, self,
		     session->audio_video_entity,
		     session->audio_media_id, session->audio_media_id,
		     is_muted ? "recvonly" : "sendrecv",
		     is_muted ? "block" : "unblock");

	g_free(mcu_uri);
	g_free(self);
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
	gchar *conference_id;
	struct transaction *trans;
	time_t expiry = time(NULL) + 7*60*60; /* 7 hours */
	char *expiry_time;

	/* addConference request to the focus factory.
	 *
	 * conference_id	(%s) Ex.: 8386E6AEAAA41E4AA6627BA76D43B6D1
	 * expiry_time		(%s) Ex.: 2009-07-13T17:57:09Z
	 * conference_view	(%s) Ex.: <msci:entity-view entity="chat"/>
	 */
	static const gchar CCCP_ADD_CONFERENCE[] =
		"<addConference>"
			"<ci:conference-info xmlns:ci=\"urn:ietf:params:xml:ns:conference-info\" "
					     "entity=\"\" "
					     "xmlns:msci=\"http://schemas.microsoft.com/rtc/2005/08/confinfoextensions\">"
				"<ci:conference-description>"
					"<ci:subject/>"
					"<msci:conference-id>%s</msci:conference-id>"
					"<msci:expiry-time>%s</msci:expiry-time>"
					"<msci:admission-policy>openAuthenticated</msci:admission-policy>"
				"</ci:conference-description>"
				"<msci:conference-view>%s</msci:conference-view>"
			"</ci:conference-info>"
		"</addConference>";

	static const gchar *DESIRED_MCU_TYPES[] = {
		"chat",
#ifdef HAVE_VV
		"audio-video",
#endif
		NULL
	};

	GString *conference_view = g_string_new("");
	const gchar **type;

	for (type = DESIRED_MCU_TYPES; *type; ++type ) {
		if (sipe_conf_supports_mcu_type(sipe_private, *type)) {
			g_string_append(conference_view, "<msci:entity-view entity=\"");
			g_string_append(conference_view, *type);
			g_string_append(conference_view, "\"/>");
		}
	}

	expiry_time = sipe_utils_time_to_str(expiry);
	conference_id = genconfid();
	trans = cccp_request(sipe_private, "SERVICE", sipe_private->focus_factory_uri,
			     NULL, process_conf_add_response,
			     CCCP_ADD_CONFERENCE,
			     conference_id, expiry_time, conference_view->str);
	g_free(conference_id);
	g_free(expiry_time);
	g_string_free(conference_view, TRUE);

	if (trans) {
		struct transaction_payload *payload = g_new0(struct transaction_payload, 1);

		payload->destroy = g_free;
		payload->data = g_strdup(who);
		trans->payload = payload;
	}
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

struct conf_accept_ctx *ctx;

typedef void (* ConfAcceptCb)(struct sipe_core_private *sipe_private,
			      struct conf_accept_ctx *ctx);

struct conf_accept_ctx {
	gchar *focus_uri;
	struct sipmsg *msg;
	struct sipe_user_ask_ctx *ask_ctx;

	ConfAcceptCb accept_cb;
	ConfAcceptCb decline_cb;

	gpointer user_data;
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
	accept_incoming_invite_conf(sipe_private, ctx->focus_uri, TRUE, ctx->msg);
}

static void
conf_decline_cb(struct sipe_core_private *sipe_private, struct conf_accept_ctx *ctx)
{
	sip_transport_response(sipe_private,
			       ctx->msg,
			       603, "Decline", NULL);
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
accept_invitation_cb(struct sipe_core_private *sipe_private, gpointer data)
{
	struct conf_accept_ctx *ctx = data;

	sipe_private->sessions_to_accept =
			g_slist_remove(sipe_private->sessions_to_accept, ctx);

	if (ctx->accept_cb) {
		ctx->accept_cb(sipe_private, ctx);
	}

	conf_accept_ctx_free(ctx);
}

static void
decline_invitation_cb(struct sipe_core_private *sipe_private, gpointer data)
{
	struct conf_accept_ctx *ctx = data;

	sipe_private->sessions_to_accept =
			g_slist_remove(sipe_private->sessions_to_accept, ctx);

	if (ctx->decline_cb) {
		ctx->decline_cb(sipe_private, ctx);
	}

	conf_accept_ctx_free(ctx);
}

static void
ask_accept_invitation(struct sipe_core_private *sipe_private,
		      const gchar *focus_uri,
		      const gchar *question_text,
		      struct sipmsg *msg,
		      ConfAcceptCb accept_cb,
		      ConfAcceptCb decline_cb,
		      gpointer user_data)
{
	gchar **parts;
	gchar *alias;
	gchar *question;
	struct conf_accept_ctx *ctx;

	parts = g_strsplit(focus_uri, ";", 2);
	alias = sipe_buddy_get_alias(sipe_private, parts[0]);

	question = g_strdup_printf(_("%s %s"),
				   alias ? alias : parts[0], question_text);

	g_free(alias);
	g_strfreev(parts);

	ctx = g_new0(struct conf_accept_ctx, 1);
	sipe_private->sessions_to_accept =
			g_slist_append(sipe_private->sessions_to_accept, ctx);

	ctx->focus_uri = g_strdup(focus_uri);
	ctx->msg = msg ? sipmsg_copy(msg) : NULL;
	ctx->accept_cb = accept_cb;
	ctx->decline_cb = decline_cb;
	ctx->user_data = user_data;
	ctx->ask_ctx = sipe_user_ask(sipe_private, question,
				     _("Accept"), accept_invitation_cb,
				     _("Decline"), decline_invitation_cb,
				     ctx);

	g_free(question);
}

static void
ask_accept_voice_conference(struct sipe_core_private *sipe_private,
			    const gchar *focus_uri,
			    struct sipmsg *msg,
			    ConfAcceptCb accept_cb,
			    ConfAcceptCb decline_cb)
{
	gchar *question;
	const gchar *novv_note;

#ifdef HAVE_VV
	novv_note = "";
#else
	novv_note = _("\n\nAs this client was not compiled with voice call "
		      "support, if you accept, you will be able to contact "
		      "the other participants only via IM session.");
#endif

	question = g_strdup_printf(_("wants to invite you "
				     "to a conference call%s"), novv_note);

	ask_accept_invitation(sipe_private, focus_uri, question, msg,
			      accept_cb, decline_cb, NULL);

	g_free(question);
}

static void
presentation_accepted_cb(struct sipe_core_private *sipe_private,
			 struct conf_accept_ctx *ctx)
{
	struct sipe_chat_session *chat_session = ctx->user_data;

	sipe_core_connect_applicationsharing(SIPE_CORE_PUBLIC, chat_session);
}

static void
ask_accept_conf_presentation(struct sipe_core_private *sipe_private,
			     const gchar *focus_uri,
			     struct sipe_chat_session *chat_session)
{
	ask_accept_invitation(sipe_private, focus_uri,
			      _("wants to start presenting"), NULL,
			      presentation_accepted_cb, NULL,
			      chat_session);
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
					    conf_accept_cb,
					    conf_decline_cb);

	} else {
		accept_incoming_invite_conf(sipe_private, focus_uri, FALSE, msg);
	}

	g_free(focus_uri);
}

#ifdef HAVE_VV

static void
process_conference_av_endpoint(const sipe_xml *endpoint,
			       const gchar *user_uri,
			       const gchar *self_uri,
			       struct sip_session *session)
{
	const sipe_xml *media;
	const gchar *new_entity;

	if (!sipe_strequal(user_uri, self_uri)) {
		/* We are interested only in our own endpoint data. */
		return;
	}

	new_entity = sipe_xml_attribute(endpoint, "entity");
	if (!sipe_strequal(session->audio_video_entity, new_entity)) {
		g_free(session->audio_video_entity);
		session->audio_video_entity = g_strdup(new_entity);
	}

	session->audio_media_id = 0;

	media = sipe_xml_child(endpoint, "media");
	for (; media; media = sipe_xml_twin(media)) {
		gchar *type = sipe_xml_data(sipe_xml_child(media, "type"));

		if (sipe_strequal(type, "audio")) {
			session->audio_media_id =
					sipe_xml_int_attribute(media, "id", 0);
		}

		g_free(type);

		if (session->audio_media_id != 0) {
			break;
		}
	}
}

static void
call_accept_cb(struct sipe_core_private *sipe_private, struct conf_accept_ctx *ctx)
{
	struct sip_session *session;
	session = sipe_session_find_conference(sipe_private, ctx->focus_uri);

	if (session) {
		sipe_core_media_connect_conference(SIPE_CORE_PUBLIC,
						   session->chat_session);
	}
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
	gboolean audio_was_added = FALSE;
	gboolean presentation_was_added = FALSE;

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

	/* organizer */
	if (!session->chat_session->organizer) {
		node = sipe_xml_child(xn_conference_info, "conference-description/organizer/display-name");
		if (node) {
			session->chat_session->organizer = sipe_xml_data(node);
		}
	}

	/* join URL */
	if (!session->chat_session->join_url) {
		node = sipe_xml_child(xn_conference_info, "conference-description/join-url");
		if (node) {
			session->chat_session->join_url = sipe_xml_data(node);
		}
	}

	/* dial-in conference id */
	if (!session->chat_session->dial_in_conf_id) {
		node = sipe_xml_child(xn_conference_info, "conference-description/pstn-access/id");
		if (node) {
			session->chat_session->dial_in_conf_id = sipe_xml_data(node);
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
					process_conference_av_endpoint(endpoint,
								       user_uri,
								       self,
								       session);
#endif
				} else if (sipe_strequal("applicationsharing", session_type)) {
					if (!session->presentation_callid) {
						gchar *media_state =
								sipe_xml_data(sipe_xml_child(endpoint, "media/media-state"));
						gchar *status = sipe_xml_data(sipe_xml_child(endpoint, "media/status"));
						if (sipe_strequal(media_state, "connected") &&
						    sipe_strequal(status, "sendonly")) {
							presentation_was_added = TRUE;
						}
						g_free(media_state);
						g_free(status);
					}
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
					    call_accept_cb,
					    NULL);
	}
	if (presentation_was_added) {
		ask_accept_conf_presentation(sipe_private, focus_uri, session->chat_session);
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

gchar *
sipe_conf_build_uri(const gchar *focus_uri, const gchar *session_type)
{
	gchar **parts = g_strsplit(focus_uri, ":focus:", 2);
	gchar *result = NULL;

	if (g_strv_length(parts) == 2) {
		result = g_strconcat(parts[0], ":", session_type, ":", parts[1],
				     NULL);
	}

	g_strfreev(parts);
	return result;
}

static gchar *
access_numbers_info(struct sipe_core_public *sipe_public)
{
	GString *result = g_string_new("");

#if GLIB_CHECK_VERSION(2,16,0)
	GList *keys = g_hash_table_get_keys(SIPE_CORE_PRIVATE->access_numbers);
	keys = g_list_sort(keys, (GCompareFunc)g_strcmp0);

	for (; keys; keys = g_list_delete_link(keys, keys)) {
		gchar *value;
		value = g_hash_table_lookup(SIPE_CORE_PRIVATE->access_numbers,
					    keys->data);

		g_string_append(result, keys->data);
		g_string_append(result, "&nbsp;&nbsp;&nbsp;&nbsp;");
		g_string_append(result, value);
		g_string_append(result, "<br/>");
	}
#else
	(void)sipe_public; /* keep compiler happy */
#endif

	return g_string_free(result, FALSE);
}

gchar *
sipe_core_conf_entry_info(struct sipe_core_public *sipe_public,
			  struct sipe_chat_session *chat_session)
{
	gchar *access_info = access_numbers_info(sipe_public);
	gchar *result = g_strdup_printf(
			"<b><font size=\"+1\">%s</font></b><br/>"
			"<b>%s:</b> %s<br/>"
			"<b>%s:</b> %s<br/>"
			"<br/>"
			"<b>%s:</b><br/>"
			"%s<br/>"
			"<br/>"
			"<b>%s:</b> %s<br/>"
			"<br/>"
			"<b><font size=\"+1\">%s</font></b><br/>"
			"%s",
			_("Dial-in info"),
			_("Number"),
			SIPE_CORE_PRIVATE->default_access_number ? SIPE_CORE_PRIVATE->default_access_number : "",
			_("Conference ID"),
			chat_session->dial_in_conf_id ? chat_session->dial_in_conf_id : "",
			_("Meeting link"),
			chat_session->join_url ? chat_session->join_url : "",
			_("Organizer"),
			chat_session->organizer ? chat_session->organizer : "",
			_("Alternative dial-in numbers"),
			access_info);

	g_free(access_info);

	return result;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
