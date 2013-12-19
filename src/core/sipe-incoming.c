/**
 * @file sipe-incoming.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2013 SIPE Project <http://sipe.sourceforge.net/>
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

#include <glib.h>

#include "sipe-common.h"
#include "sipmsg.h"
#include "sip-csta.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-chat.h"
#include "sipe-conf.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-dialog.h"
#include "sipe-ft.h"
#include "sipe-groupchat.h"
#include "sipe-im.h"
#include "sipe-incoming.h"
#include "sipe-media.h"
#include "sipe-mime.h"
#include "sipe-nls.h"
#include "sipe-schedule.h"
#include "sipe-session.h"
#include "sipe-user.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

void process_incoming_bye(struct sipe_core_private *sipe_private,
			  struct sipmsg *msg)
{
	const gchar *callid = sipmsg_find_header(msg, "Call-ID");
	gchar *from = parse_from(sipmsg_find_header(msg, "From"));
	struct sip_session *session;
	struct sip_dialog *dialog;

#ifdef HAVE_VV
	if (is_media_session_msg(sipe_private->media_call, msg)) {
		// BYE ends a media call
		sipe_media_hangup(sipe_private->media_call);
	}
#endif

	/* collect dialog identification
	 * we need callid, ourtag and theirtag to unambiguously identify dialog
	 */
	/* take data before 'msg' will be modified by sip_transport_response */
	dialog = g_new0(struct sip_dialog, 1);
	dialog->callid = g_strdup(callid);
	dialog->cseq = sipmsg_parse_cseq(msg);
	dialog->with = g_strdup(from);
	sipe_dialog_parse(dialog, msg, FALSE);

	sip_transport_response(sipe_private, msg, 200, "OK", NULL);

	session = sipe_session_find_chat_or_im(sipe_private, callid, from);
	if (!session) {
		SIPE_DEBUG_INFO_NOFORMAT("process_incoming_bye: couldn't find session. Ignoring");
		sipe_dialog_free(dialog);
		g_free(from);
		return;
	}

	SIPE_DEBUG_INFO("process_incoming_bye: session found (chat ID %s)",
			(session->chat_session && session->chat_session->id) ?
			session->chat_session->id : "<NO CHAT>");

	if (session->chat_session &&
	    (session->chat_session->type == SIPE_CHAT_TYPE_MULTIPARTY) &&
	    session->chat_session->id &&
	    !g_ascii_strcasecmp(from, session->chat_session->id))
		sipe_chat_set_roster_manager(session, NULL);

	sipe_im_cancel_unconfirmed(sipe_private, session, callid, from);

	/* This what BYE is essentially for - terminating dialog */
	sipe_dialog_remove_3(session, dialog);
	sipe_dialog_free(dialog);
	if (session->chat_session) {
		if ((session->chat_session->type == SIPE_CHAT_TYPE_CONFERENCE) &&
		    !g_ascii_strcasecmp(from, session->im_mcu_uri)) {
			SIPE_DEBUG_INFO("process_incoming_bye: disconnected from conference %s",
					session->im_mcu_uri);
			sipe_conf_immcu_closed(sipe_private, session);
		} else if (session->chat_session->type == SIPE_CHAT_TYPE_MULTIPARTY) {
			SIPE_DEBUG_INFO_NOFORMAT("process_incoming_bye: disconnected from multiparty chat");
			sipe_backend_chat_remove(session->chat_session->backend,
						 from);
		}
	}

	g_free(from);
}

void process_incoming_cancel(struct sipe_core_private *sipe_private,
			     struct sipmsg *msg)
{
	const gchar *callid;

#ifdef HAVE_VV
	if (is_media_session_msg(sipe_private->media_call, msg)) {
		process_incoming_cancel_call(sipe_private, msg);
		return;
	}
#endif
	callid = sipmsg_find_header(msg, "Call-ID");

	if (!sipe_session_find_chat_by_callid(sipe_private, callid))
		sipe_conf_cancel_unaccepted(sipe_private, msg);
}

void process_incoming_info(struct sipe_core_private *sipe_private,
			   struct sipmsg *msg)
{
	const gchar *contenttype = sipmsg_find_header(msg, "Content-Type");
	const gchar *callid = sipmsg_find_header(msg, "Call-ID");
	gchar *from;
	struct sip_session *session;

	SIPE_DEBUG_INFO_NOFORMAT("process_incoming_info");

	/* Call Control protocol */
	if (g_str_has_prefix(contenttype, "application/csta+xml"))
	{
		process_incoming_info_csta(sipe_private, msg);
		return;
	}
	else if (g_str_has_prefix(contenttype, "application/xml+conversationinfo"))
	{
		process_incoming_info_conversation(sipe_private, msg);
		return;
	}

	from = parse_from(sipmsg_find_header(msg, "From"));
	session = sipe_session_find_chat_or_im(sipe_private, callid, from);
	if (!session) {
		g_free(from);
		return;
	}

	/* Group Chat uses text/plain */
	if (session->is_groupchat) {
		process_incoming_info_groupchat(sipe_private, msg, session);
		g_free(from);
		return;
	}

	if (g_str_has_prefix(contenttype, "application/x-ms-mim"))
	{
		sipe_xml *xn_action           = sipe_xml_parse(msg->body, msg->bodylen);
		const sipe_xml *xn_request_rm = sipe_xml_child(xn_action, "RequestRM");
		const sipe_xml *xn_set_rm     = sipe_xml_child(xn_action, "SetRM");

		sipmsg_add_header(msg, "Content-Type", "application/x-ms-mim");

		if (xn_request_rm) {
			//const char *rm = sipe_xml_attribute(xn_request_rm, "uri");
			int bid = sipe_xml_int_attribute(xn_request_rm, "bid", 0);
			gchar *body = g_strdup_printf(
				"<?xml version=\"1.0\"?>\r\n"
				"<action xmlns=\"http://schemas.microsoft.com/sip/multiparty/\">"
				"<RequestRMResponse uri=\"sip:%s\" allow=\"%s\"/></action>\r\n",
				sipe_private->username,
				session->bid < bid ? "true" : "false");
			sip_transport_response(sipe_private, msg, 200, "OK", body);
			g_free(body);
		} else if (xn_set_rm) {
			gchar *body;

			sipe_chat_set_roster_manager(session,
						     sipe_xml_attribute(xn_set_rm, "uri"));

			body = g_strdup_printf(
				"<?xml version=\"1.0\"?>\r\n"
				"<action xmlns=\"http://schemas.microsoft.com/sip/multiparty/\">"
				"<SetRMResponse uri=\"sip:%s\"/></action>\r\n",
				sipe_private->username);
			sip_transport_response(sipe_private, msg, 200, "OK", body);
			g_free(body);
		}
		sipe_xml_free(xn_action);

	}
	else
	{
		/* looks like purple lacks typing notification for chat */
		if (!session->chat_session) {
			sipe_xml *xn_keyboard_activity  = sipe_xml_parse(msg->body, msg->bodylen);
			const char *status = sipe_xml_attribute(sipe_xml_child(xn_keyboard_activity, "status"),
								"status");
			if (sipe_strequal(status, "type")) {
				sipe_backend_user_feedback_typing(SIPE_CORE_PUBLIC,
								  from);
			} else if (sipe_strequal(status, "idle")) {
				sipe_backend_user_feedback_typing_stop(SIPE_CORE_PUBLIC,
								       from);
			}
			sipe_xml_free(xn_keyboard_activity);
		}

		sip_transport_response(sipe_private, msg, 200, "OK", NULL);
	}
	g_free(from);
}

static gboolean sipe_process_incoming_x_msmsgsinvite(struct sipe_core_private *sipe_private,
						     struct sip_dialog *dialog,
						     GSList *parsed_body)
{
	gboolean found = FALSE;

	if (parsed_body) {
		const gchar *invitation_command = sipe_utils_nameval_find(parsed_body, "Invitation-Command");

		if (sipe_strequal(invitation_command, "INVITE")) {
			sipe_ft_incoming_transfer(sipe_private, dialog, parsed_body);
			found = TRUE;
		} else if (sipe_strequal(invitation_command, "CANCEL")) {
			sipe_ft_incoming_cancel(dialog, parsed_body);
			found = TRUE;
		} else if (sipe_strequal(invitation_command, "ACCEPT")) {
			sipe_ft_incoming_accept(dialog, parsed_body);
			found = TRUE;
		}
	}
	return found;
}

#ifdef HAVE_VV
static void sipe_invite_mime_cb(gpointer user_data, const GSList *fields,
				const gchar *body, gsize length)
{
	const gchar *type = sipe_utils_nameval_find(fields, "Content-Type");
	const gchar *cd = sipe_utils_nameval_find(fields, "Content-Disposition");

	if (!g_str_has_prefix(type, "application/sdp"))
		return;

	if (!cd || !strstr(cd, "ms-proxy-2007fallback")) {
		struct sipmsg *msg = user_data;
		const gchar* msg_ct = sipmsg_find_header(msg, "Content-Type");

		if (g_str_has_prefix(msg_ct, "application/sdp")) {
			/* We have already found suitable alternative and set message's body
			 * and Content-Type accordingly */
			return;
		}

		sipmsg_remove_header_now(msg, "Content-Type");
		sipmsg_add_header_now(msg, "Content-Type", type);

		/* Replace message body with chosen alternative, so we can continue to
		 * process it as a normal single part message. */
		g_free(msg->body);
		msg->body = g_strndup(body, length);
		msg->bodylen = length;
	}
}
#endif

static void sipe_invite_mime_mixed_cb(gpointer user_data, const GSList *fields,
	SIPE_UNUSED_PARAMETER const gchar *body, SIPE_UNUSED_PARAMETER gsize length)
{
	const gchar *ctype = sipe_utils_nameval_find(fields, "Content-Type");

	/* Lync 2010 file transfer */
	if (g_str_has_prefix(ctype, "application/ms-filetransfer+xml")) {
		struct sipmsg *msg = user_data;

		sipmsg_remove_header_now(msg, "Content-Type");
		sipmsg_add_header_now(msg, "Content-Type", ctype);

		/* Right now, we do not care about the message body, only detect new
		 * file transfer protocol from Content-Type and reply with
		 * 488 Not Acceptable Here to force the old MSOC behavior.
		 *
		 * TODO: Extend sipmsg so that it supports multipart messages, as to
		 * implement the new protocol, we need access to both parts of the
		 * message for further processing. */
	}
}

static void send_invite_response(struct sipe_core_private *sipe_private,
				 struct sipmsg *msg)
{
	gchar *body = g_strdup_printf(
		"v=0\r\n"
		"o=- 0 0 IN IP4 %s\r\n"
		"s=session\r\n"
		"c=IN IP4 %s\r\n"
		"t=0 0\r\n"
		"m=%s %d sip sip:%s\r\n"
		"a=accept-types:" SDP_ACCEPT_TYPES "\r\n",
		sipe_backend_network_ip_address(SIPE_CORE_PUBLIC),
		sipe_backend_network_ip_address(SIPE_CORE_PUBLIC),
		SIPE_CORE_PRIVATE_FLAG_IS(OCS2007) ? "message" : "x-ms-message",
		sip_transport_port(sipe_private),
		sipe_private->username);
	sipmsg_add_header(msg, "Content-Type", "application/sdp");
	sip_transport_response(sipe_private, msg, 200, "OK", body);
	g_free(body);
}

struct sipe_delayed_invite {
	gchar *action;
	struct sipmsg *msg;
};

static void delayed_invite_destroy(gpointer data)
{
	struct sipe_delayed_invite *delayed_invite = data;
	sipmsg_free(delayed_invite->msg);
	g_free(delayed_invite->action);
	g_free(delayed_invite);
}

static void delayed_invite_timeout(struct sipe_core_private *sipe_private,
				   gpointer data)
{
	struct sipe_delayed_invite *delayed_invite = data;
	send_invite_response(sipe_private, delayed_invite->msg);
}

static void delayed_invite_response(struct sipe_core_private *sipe_private,
				    struct sipmsg *msg,
				    const gchar *callid)
{
	struct sipe_delayed_invite *delayed_invite = g_new0(struct sipe_delayed_invite, 1);

	delayed_invite->action = g_strdup_printf("<delayed-invite-%s>", callid);
	delayed_invite->msg    = sipmsg_copy(msg);
	sipe_schedule_seconds(sipe_private,
			      delayed_invite->action,
			      delayed_invite,
			      10,
			      delayed_invite_timeout,
			      delayed_invite_destroy);
}

void sipe_incoming_cancel_delayed_invite(struct sipe_core_private *sipe_private,
					 struct sip_dialog *dialog)
{
	struct sipe_delayed_invite *delayed_invite = dialog->delayed_invite;
	dialog->delayed_invite = NULL;
	send_invite_response(sipe_private, delayed_invite->msg);
	sipe_schedule_cancel(sipe_private, delayed_invite->action);
}

void process_incoming_invite(struct sipe_core_private *sipe_private,
			     struct sipmsg *msg)
{
	gchar *newTag;
	const gchar *oldHeader;
	gchar *newHeader;
	gboolean is_multiparty = FALSE;
	gboolean was_multiparty = TRUE;
	gboolean just_joined = FALSE;
	gchar *from;
	const gchar *callid         = sipmsg_find_header(msg, "Call-ID");
	const gchar *roster_manager = sipmsg_find_header(msg, "Roster-Manager");
	const gchar *end_points_hdr = sipmsg_find_header(msg, "EndPoints");
	const gchar *trig_invite    = sipmsg_find_header(msg, "TriggeredInvite");
	const gchar *content_type   = sipmsg_find_header(msg, "Content-Type");
	const gchar *subject        = sipmsg_find_header(msg, "Subject");
	GSList *end_points = NULL;
	struct sip_session *session;
	struct sip_dialog *dialog;
	const gchar *ms_text_format;
	gboolean dont_delay = FALSE;

#ifdef HAVE_VV
	if (g_str_has_prefix(content_type, "multipart/alternative")) {
		sipe_mime_parts_foreach(content_type, msg->body, sipe_invite_mime_cb, msg);
		/* Reload Content-Type to get type of the selected message part */
		content_type = sipmsg_find_header(msg, "Content-Type");
	}
#endif

	if (g_str_has_prefix(content_type, "multipart/mixed")) {
		sipe_mime_parts_foreach(content_type, msg->body, sipe_invite_mime_mixed_cb, msg);
		/* Reload Content-Type to get type of the selected message part */
		content_type = sipmsg_find_header(msg, "Content-Type");
	}

	/* Lync 2010 file transfer */
	if (g_str_has_prefix(content_type, "application/ms-filetransfer+xml")) {
		sip_transport_response(sipe_private, msg, 488, "Not Acceptable Here", NULL);
		return;
	}

	/* Invitation to join conference */
	if (g_str_has_prefix(content_type, "application/ms-conf-invite+xml")) {
		process_incoming_invite_conf(sipe_private, msg);
		return;
	}

#ifdef HAVE_VV
	/* Invitation to audio call */
	if (msg->body && strstr(msg->body, "m=audio")) {
		process_incoming_invite_call(sipe_private, msg);
		return;
	}
#endif

	/* Only accept text invitations */
	if (msg->body && !(strstr(msg->body, "m=message") || strstr(msg->body, "m=x-ms-message"))) {
		sip_transport_response(sipe_private, msg, 501, "Not implemented", NULL);
		return;
	}

	// TODO There *must* be a better way to clean up the To header to add a tag...
	SIPE_DEBUG_INFO_NOFORMAT("Adding a Tag to the To Header on Invite Request...");
	oldHeader = sipmsg_find_header(msg, "To");
	newTag = gentag();
	newHeader = g_strdup_printf("%s;tag=%s", oldHeader, newTag);
	g_free(newTag);
	sipmsg_remove_header_now(msg, "To");
	sipmsg_add_header_now(msg, "To", newHeader);
	g_free(newHeader);

	if (end_points_hdr) {
		end_points = sipmsg_parse_endpoints_header(end_points_hdr);

		if (g_slist_length(end_points) > 2) {
			is_multiparty = TRUE;
		}
	}
	if (trig_invite && !g_ascii_strcasecmp(trig_invite, "TRUE")) {
		is_multiparty = TRUE;
	}

	/* Multiparty session */
	session = sipe_session_find_chat_by_callid(sipe_private, callid);
	if (is_multiparty) {

		if (session) {
			if (session->chat_session) {
				/* Update roster manager for existing multiparty session */
				if (roster_manager)
					sipe_chat_set_roster_manager(session, roster_manager);

			} else {
				gchar *chat_title = sipe_chat_get_name();

				/* Convert IM session to multiparty session */
				g_free(session->with);
				session->with = NULL;
				was_multiparty = FALSE;
				session->chat_session = sipe_chat_create_session(SIPE_CHAT_TYPE_MULTIPARTY,
										 roster_manager,
										 chat_title);

				g_free(chat_title);
			}
		} else {
			/* New multiparty session */
			session = sipe_session_add_chat(sipe_private,
							NULL,
							TRUE,
							roster_manager);
		}

		/* Create chat */
		if (!session->chat_session->backend) {
			gchar *self = sip_uri_self(sipe_private);
			session->chat_session->backend = sipe_backend_chat_create(SIPE_CORE_PUBLIC,
										  session->chat_session,
										  session->chat_session->title,
										  self);
			g_free(self);
		}
	}

	/* IM session */
	from = parse_from(sipmsg_find_header(msg, "From"));
	if (!session)
		session = sipe_session_find_or_add_im(sipe_private, from);

	/* session is now initialized */
	g_free(session->callid);
	session->callid = g_strdup(callid);

	if (is_multiparty && end_points) {
		gchar *to = parse_from(sipmsg_find_header(msg, "To"));
		GSList *entry = end_points;
		while (entry) {
			struct sipendpoint *end_point = entry->data;
			entry = entry->next;

			if (!g_ascii_strcasecmp(from, end_point->contact) ||
			    !g_ascii_strcasecmp(to,   end_point->contact))
				continue;

			dialog = sipe_dialog_find(session, end_point->contact);
			if (dialog) {
				g_free(dialog->theirepid);
				dialog->theirepid = end_point->epid;
				end_point->epid = NULL;
			} else {
				dialog = sipe_dialog_add(session);

				dialog->callid = g_strdup(session->callid);
				dialog->with = end_point->contact;
				end_point->contact = NULL;
				dialog->theirepid = end_point->epid;
				end_point->epid = NULL;

				just_joined = TRUE;

				/* send triggered INVITE */
				sipe_im_invite(sipe_private, session, dialog->with, NULL, NULL, NULL, TRUE);
			}
		}
		g_free(to);
	}

	if (end_points) {
		GSList *entry = end_points;
		while (entry) {
			struct sipendpoint *end_point = entry->data;
			entry = entry->next;
			g_free(end_point->contact);
			g_free(end_point->epid);
			g_free(end_point);
		}
		g_slist_free(end_points);
	}

	dialog = sipe_dialog_find(session, from);
	if (dialog) {
		sipe_im_cancel_dangling(sipe_private, session, dialog, from,
					sipe_im_reenqueue_unconfirmed);
		/* dialog is no longer valid */
	} else {
		just_joined = TRUE;
	}

	dialog = sipe_dialog_add(session);
	dialog->with = g_strdup(from);
	dialog->callid = g_strdup(session->callid);
	dialog->is_established = TRUE;
	sipe_dialog_parse(dialog, msg, FALSE);

	if (is_multiparty && !was_multiparty) {
		/* add current IM counterparty to chat */
		sipe_backend_chat_add(session->chat_session->backend,
				      sipe_dialog_first(session)->with,
				      FALSE);
	}

	/* add inviting party to chat */
	if (just_joined && session->chat_session) {
		sipe_backend_chat_add(session->chat_session->backend,
				      from,
				      TRUE);
	}

	if (!is_multiparty && subject)
		sipe_im_topic(sipe_private, session, subject);

	/* ms-text-format: text/plain; charset=UTF-8;msgr=WAAtAE0...DIADQAKAA0ACgA;ms-body=SGk= */

	/* This used only in 2005 official client, not 2007 or Reuters.
	   Disabled for most cases as interfering with audit of messages which only is applied to regular MESSAGEs.
	   Only enabled for 2005 multiparty chats as otherwise the first message got lost completely.
	*/
	/* also enabled for 2005 file transfer. Didn't work otherwise. */
	ms_text_format = sipmsg_find_header(msg, "ms-text-format");
	if (is_multiparty ||
	    (ms_text_format && g_str_has_prefix(ms_text_format, "text/x-msmsgsinvite")) )
	{
		if (ms_text_format) {
			if (g_str_has_prefix(ms_text_format, "text/x-msmsgsinvite"))
			{
				dont_delay = TRUE;
			}
			else if (g_str_has_prefix(ms_text_format, "text/plain") || g_str_has_prefix(ms_text_format, "text/html"))
			{
				/* please do not optimize logic inside as this code may be re-enabled for other cases */
				gchar *html = get_html_message(ms_text_format, NULL);
				if (html) {
					if (is_multiparty) {
						sipe_backend_chat_message(SIPE_CORE_PUBLIC,
									  session->chat_session->backend,
									  from,
									  0,
									  html);
					} else {
						sipe_backend_im_message(SIPE_CORE_PUBLIC,
									from,
									html);
					}
					g_free(html);
					sipmsg_add_header(msg, "Supported", "ms-text-format"); /* accepts received message */
					dont_delay = TRUE;
				}
			}
		}
	}

	g_free(from);

	sipmsg_add_header(msg, "Supported", "com.microsoft.rtc-multiparty");

	if (dont_delay || !SIPE_CORE_PRIVATE_FLAG_IS(MPOP)) {
		send_invite_response(sipe_private, msg);
	} else {
		delayed_invite_response(sipe_private, msg, session->callid);
	}
}

void process_incoming_message(struct sipe_core_private *sipe_private,
			      struct sipmsg *msg)
{
	gchar *from;
	const gchar *contenttype;
	gboolean found = FALSE;

	from = parse_from(sipmsg_find_header(msg, "From"));

	if (!from) return;

	SIPE_DEBUG_INFO("got message from %s: %s", from, msg->body);

	contenttype = sipmsg_find_header(msg, "Content-Type");
	if (g_str_has_prefix(contenttype, "text/plain")
	    || g_str_has_prefix(contenttype, "text/html")
	    || g_str_has_prefix(contenttype, "multipart/related")
	    || g_str_has_prefix(contenttype, "multipart/alternative"))
	{
		const gchar *callid = sipmsg_find_header(msg, "Call-ID");
		gchar *html = get_html_message(contenttype, msg->body);

		struct sip_session *session = sipe_session_find_chat_or_im(sipe_private,
									   callid,
									   from);
		if (session && session->chat_session) {
			if (session->chat_session->type == SIPE_CHAT_TYPE_CONFERENCE) { /* a conference */
				gchar *tmp = parse_from(sipmsg_find_header(msg, "Ms-Sender"));
				gchar *sender = parse_from(tmp);
				g_free(tmp);
				sipe_backend_chat_message(SIPE_CORE_PUBLIC,
							  session->chat_session->backend,
							  sender,
							  0,
							  html);
				g_free(sender);
			} else { /* a multiparty chat */
				sipe_backend_chat_message(SIPE_CORE_PUBLIC,
							  session->chat_session->backend,
							  from,
							  0,
							  html);
			}
		} else {
			sipe_backend_im_message(SIPE_CORE_PUBLIC,
						from,
						html);
		}
		g_free(html);
		sip_transport_response(sipe_private, msg, 200, "OK", NULL);
		found = TRUE;

	} else if (g_str_has_prefix(contenttype, "application/im-iscomposing+xml")) {
		sipe_xml *isc = sipe_xml_parse(msg->body, msg->bodylen);
		const sipe_xml *state;
		gchar *statedata;

		if (!isc) {
			SIPE_DEBUG_INFO_NOFORMAT("process_incoming_message: can not parse iscomposing");
			g_free(from);
			return;
		}

		state = sipe_xml_child(isc, "state");

		if (!state) {
			SIPE_DEBUG_INFO_NOFORMAT("process_incoming_message: no state found");
			sipe_xml_free(isc);
			g_free(from);
			return;
		}

		statedata = sipe_xml_data(state);
		if (statedata) {
			if (strstr(statedata, "active")) {
				sipe_backend_user_feedback_typing(SIPE_CORE_PUBLIC,
								  from);
			} else {
				sipe_backend_user_feedback_typing_stop(SIPE_CORE_PUBLIC,
								       from);
			}
			g_free(statedata);
		}
		sipe_xml_free(isc);
		sip_transport_response(sipe_private, msg, 200, "OK", NULL);
		found = TRUE;
	} else if (g_str_has_prefix(contenttype, "text/x-msmsgsinvite")) {
		const gchar *callid = sipmsg_find_header(msg, "Call-ID");
		struct sip_session *session = sipe_session_find_chat_or_im(sipe_private,
									   callid,
									   from);
		if (session) {
			struct sip_dialog *dialog = sipe_dialog_find(session, from);
			GSList *body = sipe_ft_parse_msg_body(msg->body);
			found = sipe_process_incoming_x_msmsgsinvite(sipe_private, dialog, body);
			sipe_utils_nameval_free(body);
			if (found) {
				sip_transport_response(sipe_private, msg, 200, "OK", NULL);
			}
		} else {
			sip_transport_response(sipe_private, msg, 481,
					       "Call Leg/Transaction Does Not Exist", NULL);
			found = TRUE;
		}
	}
	if (!found) {
		const gchar *callid = sipmsg_find_header(msg, "Call-ID");
		struct sip_session *session = sipe_session_find_chat_or_im(sipe_private,
									   callid,
									   from);
		if (session) {
			gchar *errmsg = g_strdup_printf(_("Received a message with unrecognized contents from %s"),
							from);
			sipe_user_present_error(sipe_private, session, errmsg);
			g_free(errmsg);
		}

		SIPE_DEBUG_INFO("got unknown mime-type '%s'", contenttype);
		sip_transport_response(sipe_private, msg, 415, "Unsupported media type", NULL);
	}
	g_free(from);
}

void process_incoming_options(struct sipe_core_private *sipe_private,
			      struct sipmsg *msg)
{
	gchar *body;

	sipmsg_add_header(msg, "Allow", "INVITE, MESSAGE, INFO, SUBSCRIBE, OPTIONS, BYE, CANCEL, NOTIFY, ACK, REFER, BENOTIFY");
	sipmsg_add_header(msg, "Content-Type", "application/sdp");

	body = g_strdup_printf(
		"v=0\r\n"
		"o=- 0 0 IN IP4 0.0.0.0\r\n"
		"s=session\r\n"
		"c=IN IP4 0.0.0.0\r\n"
		"t=0 0\r\n"
		"m=%s %d sip sip:%s\r\n"
		"a=accept-types:" SDP_ACCEPT_TYPES "\r\n",
		SIPE_CORE_PRIVATE_FLAG_IS(OCS2007) ? "message" : "x-ms-message",
		sip_transport_port(sipe_private),
		sipe_private->username);
	sip_transport_response(sipe_private, msg, 200, "OK", body);
	g_free(body);
}

void process_incoming_refer(struct sipe_core_private *sipe_private,
			    struct sipmsg *msg)
{
	gchar *self = sip_uri_self(sipe_private);
	const gchar *callid = sipmsg_find_header(msg, "Call-ID");
	gchar *from = parse_from(sipmsg_find_header(msg, "From"));
	gchar *refer_to = parse_from(sipmsg_find_header(msg, "Refer-to"));
	gchar *referred_by = g_strdup(sipmsg_find_header(msg, "Referred-By"));
	struct sip_session *session;
	struct sip_dialog *dialog;

	session = sipe_session_find_chat_by_callid(sipe_private, callid);
	dialog = sipe_dialog_find(session, from);

	if (!session || !dialog || !session->chat_session ||
	    (session->chat_session->type != SIPE_CHAT_TYPE_MULTIPARTY) ||
	    !session->chat_session->id ||
	    !sipe_strcase_equal(session->chat_session->id, self)) {
		sip_transport_response(sipe_private, msg, 500, "Server Internal Error", NULL);
	} else {
		sip_transport_response(sipe_private, msg, 202, "Accepted", NULL);

		sipe_im_invite(sipe_private, session, refer_to, NULL, NULL, referred_by, FALSE);
	}

	g_free(self);
	g_free(from);
	g_free(refer_to);
	g_free(referred_by);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
