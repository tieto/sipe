/**
 * @file sipe-im.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-2013 SIPE Project <http://sipe.sourceforge.net/>
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
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-buddy.h"
#include "sipe-chat.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-dialog.h"
#include "sipe-ft.h"
#include "sipe-groupchat.h"
#include "sipe-im.h"
#include "sipe-incoming.h"
#include "sipe-nls.h"
#include "sipe-session.h"
#include "sipe-user.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

/*
 * Hash key template for unconfirmed messages
 *
 *                                             Call-ID      Recipient URI (or empty)
 *                                               |               |
 *                                               |  SIP method   |    CSeq
 *                                               |     |         |     |             */
#define UNCONFIRMED_KEY_TEMPLATE(method, cseq) "<%s><" method "><%s><" cseq

/* key must be g_free()'d */
static gchar *get_unconfirmed_message_key(const gchar *callid,
					  unsigned int cseq,
					  const gchar *with)
{
	return(g_strdup_printf(UNCONFIRMED_KEY_TEMPLATE("%s", "%d>"),
			       callid,
			       with ? "MESSAGE" : "INVITE",
			       with ? with : "",
			       cseq));
}

static void insert_unconfirmed_message(struct sip_session *session,
				       struct sip_dialog *dialog,
				       const gchar *with,
				       const gchar *body,
				       const gchar *content_type)
{
	gchar *key = get_unconfirmed_message_key(dialog->callid, dialog->cseq + 1, with);
	struct queued_message *message = g_new0(struct queued_message, 1);

	message->body = g_strdup(body);
	if (content_type != NULL)
		message->content_type = g_strdup(content_type);
	message->cseq = dialog->cseq + 1;

	g_hash_table_insert(session->unconfirmed_messages, key, message);
	SIPE_DEBUG_INFO("insert_unconfirmed_message: added %s to list (count=%d)",
			key, g_hash_table_size(session->unconfirmed_messages));
}

static gboolean remove_unconfirmed_message(struct sip_session *session,
					   const gchar *key)
{
	gboolean found = g_hash_table_remove(session->unconfirmed_messages, key);
	if (found) {
		SIPE_DEBUG_INFO("remove_unconfirmed_message: removed %s from list (count=%d)",
				key, g_hash_table_size(session->unconfirmed_messages));
	} else {
		SIPE_DEBUG_INFO("remove_unconfirmed_message: key %s not found",
				key);
	}
	return(found);
}

static void sipe_refer_notify(struct sipe_core_private *sipe_private,
			      struct sip_session *session,
			      const gchar *who,
			      int status,
			      const gchar *desc)
{
	gchar *hdr;
	gchar *body;
	struct sip_dialog *dialog = sipe_dialog_find(session, who);

	hdr = g_strdup_printf(
		"Event: refer\r\n"
		"Subscription-State: %s\r\n"
		"Content-Type: message/sipfrag\r\n",
		status >= 200 ? "terminated" : "active");

	body = g_strdup_printf(
		"SIP/2.0 %d %s\r\n",
		status, desc);

	sip_transport_request(sipe_private,
			      "NOTIFY",
			      who,
			      who,
			      hdr,
			      body,
			      dialog,
			      NULL);

	g_free(hdr);
	g_free(body);
}

static gboolean process_invite_response(struct sipe_core_private *sipe_private,
					struct sipmsg *msg,
					struct transaction *trans)
{
	gchar *with = parse_from(sipmsg_find_header(msg, "To"));
	struct sip_session *session;
	struct sip_dialog *dialog;
	gchar *key;
	struct queued_message *message;
	struct sipmsg *request_msg = trans->msg;

	const gchar *callid = sipmsg_find_header(msg, "Call-ID");
	gchar *referred_by;

	session = sipe_session_find_chat_or_im(sipe_private, callid, with);
	if (!session) {
		SIPE_DEBUG_INFO_NOFORMAT("process_invite_response: unable to find IM session");
		g_free(with);
		return FALSE;
	}

	dialog = sipe_dialog_find(session, with);
	if (!dialog) {
		SIPE_DEBUG_INFO_NOFORMAT("process_invite_response: session outgoing dialog is NULL");
		g_free(with);
		return FALSE;
	}

	sipe_dialog_parse(dialog, msg, TRUE);

	key = get_unconfirmed_message_key(dialog->callid, sipmsg_parse_cseq(msg), NULL);
	message = g_hash_table_lookup(session->unconfirmed_messages, key);

	if (msg->response != 200) {
		gchar *alias = sipe_buddy_get_alias(sipe_private, with);
		int warning = sipmsg_parse_warning(msg, NULL);

		SIPE_DEBUG_INFO_NOFORMAT("process_invite_response: INVITE response not 200");

		/* cancel file transfer as rejected by server */
		if (msg->response == 606 &&	/* Not acceptable all. */
		    warning == 309 &&		/* Message contents not allowed by policy */
		    message && g_str_has_prefix(message->content_type, "text/x-msmsgsinvite"))
		{
			GSList *parsed_body = sipe_ft_parse_msg_body(message->body);
			sipe_ft_incoming_cancel(dialog, parsed_body);
			sipe_utils_nameval_free(parsed_body);
		}

		if (message) {
			/* generate error for each unprocessed message */
			GSList *entry = session->outgoing_message_queue;
			while (entry) {
				struct queued_message *queued = entry->data;
				sipe_user_present_message_undelivered(sipe_private, session, msg->response, warning, alias ? alias : with, queued->body);
				entry = sipe_session_dequeue_message(session);
			}
		} else {
			/* generate one error and remove all unprocessed messages */
			gchar *tmp_msg = g_strdup_printf(_("Failed to invite %s"), alias ? alias : with);
			sipe_user_present_error(sipe_private, session, tmp_msg);
			g_free(tmp_msg);
			while (sipe_session_dequeue_message(session));
		}
		g_free(alias);

		remove_unconfirmed_message(session, key);
		/* message is no longer valid */
		g_free(key);

		sipe_dialog_remove(session, with);
		g_free(with);

		if (session->is_groupchat) {
			sipe_groupchat_invite_failed(sipe_private, session);
			/* session is no longer valid */
		}

		return FALSE;
	}

	dialog->cseq = 0;
	sip_transport_ack(sipe_private, dialog);
	dialog->outgoing_invite = NULL;
	dialog->is_established = TRUE;

	referred_by = parse_from(sipmsg_find_header(request_msg, "Referred-By"));
	if (referred_by) {
		sipe_refer_notify(sipe_private, session, referred_by, 200, "OK");
		g_free(referred_by);
	}

	/* add user to chat if it is a multiparty session */
	if (session->chat_session &&
	    (session->chat_session->type == SIPE_CHAT_TYPE_MULTIPARTY)) {
		sipe_backend_chat_add(session->chat_session->backend,
				      with,
				      TRUE);
	}

	if (session->is_groupchat) {
		sipe_groupchat_invite_response(sipe_private, dialog, msg);
	}

	if(g_slist_find_custom(dialog->supported, "ms-text-format", (GCompareFunc)g_ascii_strcasecmp)) {
		SIPE_DEBUG_INFO_NOFORMAT("process_invite_response: remote system accepted message in INVITE");
		sipe_session_dequeue_message(session);
	}

	sipe_im_process_queue(sipe_private, session);

	remove_unconfirmed_message(session, key);

	g_free(key);
	g_free(with);
	return TRUE;
}

/* EndPoints: "alice alisson" <sip:alice@atlanta.local>, <sip:bob@atlanta.local>;epid=ebca82d94d, <sip:carol@atlanta.local> */
static gchar *get_end_points(struct sipe_core_private *sipe_private,
			     struct sip_session *session)
{
	gchar *res;

	if (session == NULL) {
		return NULL;
	}

	res = g_strdup_printf("<sip:%s>", sipe_private->username);

	SIPE_DIALOG_FOREACH {
		gchar *tmp = res;
		res = g_strdup_printf("%s, <%s>", res, dialog->with);
		g_free(tmp);

		if (dialog->theirepid) {
			tmp = res;
			res = g_strdup_printf("%s;epid=%s", res, dialog->theirepid);
			g_free(tmp);
		}
	} SIPE_DIALOG_FOREACH_END;

	return res;
}

void
sipe_im_invite(struct sipe_core_private *sipe_private,
	       struct sip_session *session,
	       const gchar *who,
	       const gchar *msg_body,
	       const gchar *content_type,
	       const gchar *referred_by,
	       const gboolean is_triggered)
{
	gchar *hdr;
	gchar *to;
	gchar *contact;
	gchar *body;
	gchar *self;
	char  *ms_text_format = NULL;
	char  *ms_conversation_id = NULL;
	gchar *roster_manager;
	gchar *end_points;
	gchar *referred_by_str;
	gboolean is_multiparty =
		session->chat_session &&
		(session->chat_session->type == SIPE_CHAT_TYPE_MULTIPARTY);
	struct sip_dialog *dialog = sipe_dialog_find(session, who);

	if (dialog && dialog->is_established) {
		SIPE_DEBUG_INFO("session with %s already has a dialog open", who);
		return;
	}

	if (!dialog) {
		dialog = sipe_dialog_add(session);
		dialog->callid = session->callid ? g_strdup(session->callid) : gencallid();
		dialog->with = g_strdup(who);
	}

	if (!(dialog->ourtag)) {
		dialog->ourtag = gentag();
	}

	to = sip_uri(who);

	if (msg_body) {
		char *msgtext = NULL;
		char *base64_msg;
		const gchar *msgr = "";
		gchar *tmp = NULL;

		if (!g_str_has_prefix(content_type, "text/x-msmsgsinvite")) {
			char *msgformat;
			gchar *msgr_value;

			sipe_parse_html(msg_body, &msgformat, &msgtext);
			SIPE_DEBUG_INFO("sipe_invite: msgformat=%s", msgformat);

			msgr_value = sipmsg_get_msgr_string(msgformat);
			g_free(msgformat);
			if (msgr_value) {
				msgr = tmp = g_strdup_printf(";msgr=%s", msgr_value);
				g_free(msgr_value);
			}

			/* When Sipe reconnects after a crash, we are not able
			 * to send messages to contacts with which we had open
			 * conversations when the crash occured. Server sends
			 * error response with reason="This client has an IM
			 * session with the same conversation ID"
			 *
			 * Setting random Ms-Conversation-ID prevents this problem
			 * so we can continue the conversation. */
			ms_conversation_id = g_strdup_printf("Ms-Conversation-ID: %u\r\n",
							     rand() % 1000000000);
		} else {
			msgtext = g_strdup(msg_body);
		}

		base64_msg = g_base64_encode((guchar*) msgtext, strlen(msgtext));
		ms_text_format = g_strdup_printf("ms-text-format: %s; charset=UTF-8%s;ms-body=%s\r\n",
						 content_type ? content_type : "text/plain",
						 msgr,
						 base64_msg);
		g_free(msgtext);
		g_free(tmp);
		g_free(base64_msg);

		insert_unconfirmed_message(session, dialog, NULL,
					   msg_body, content_type);
	}

	contact = get_contact(sipe_private);
	end_points = get_end_points(sipe_private, session);
	self = sip_uri_self(sipe_private);
	roster_manager = g_strdup_printf(
		"Roster-Manager: %s\r\n"
		"EndPoints: %s\r\n",
		self,
		end_points);
	referred_by_str = referred_by ?
		g_strdup_printf(
			"Referred-By: %s\r\n",
			referred_by)
		: g_strdup("");
	hdr = g_strdup_printf(
		"Supported: ms-sender\r\n"
		"%s"
		"%s"
		"%s"
		"%s"
		"Contact: %s\r\n%s"
		"%s"
		"Content-Type: application/sdp\r\n",
		is_multiparty && sipe_strcase_equal(session->chat_session->id, self) ? roster_manager : "",
		referred_by_str,
		is_triggered ? "TriggeredInvite: TRUE\r\n" : "",
		is_triggered || is_multiparty ? "Require: com.microsoft.rtc-multiparty\r\n" : "",
		contact,
		ms_text_format ? ms_text_format : "",
		ms_conversation_id ? ms_conversation_id : "");
	g_free(ms_text_format);
	g_free(ms_conversation_id);
	g_free(self);

	body = g_strdup_printf(
		"v=0\r\n"
		"o=- 0 0 IN IP4 %s\r\n"
		"s=session\r\n"
		"c=IN IP4 %s\r\n"
		"t=0 0\r\n"
		"m=%s %d sip null\r\n"
		"a=accept-types:" SDP_ACCEPT_TYPES "\r\n",
		sipe_backend_network_ip_address(SIPE_CORE_PUBLIC),
		sipe_backend_network_ip_address(SIPE_CORE_PUBLIC),
		SIPE_CORE_PRIVATE_FLAG_IS(OCS2007) ? "message" : "x-ms-message",
		sip_transport_port(sipe_private));

	dialog->outgoing_invite = sip_transport_request(sipe_private,
							"INVITE",
							to,
							to,
							hdr,
							body,
							dialog,
							process_invite_response);

	g_free(to);
	g_free(roster_manager);
	g_free(end_points);
	g_free(referred_by_str);
	g_free(body);
	g_free(hdr);
	g_free(contact);
}

static gboolean
process_message_response(struct sipe_core_private *sipe_private,
			 struct sipmsg *msg,
			 SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	gboolean ret = TRUE;
	gchar *with = parse_from(sipmsg_find_header(msg, "To"));
	const gchar *callid = sipmsg_find_header(msg, "Call-ID");
	struct sip_session *session = sipe_session_find_chat_or_im(sipe_private, callid, with);
	struct sip_dialog *dialog;
	gchar *key;
	struct queued_message *message;

	if (!session) {
		SIPE_DEBUG_INFO_NOFORMAT("process_message_response: unable to find IM session");
		g_free(with);
		return FALSE;
	}

	dialog = sipe_dialog_find(session, with);
	if (!dialog) {
		SIPE_DEBUG_INFO_NOFORMAT("process_message_response: session outgoing dialog is NULL");
		g_free(with);
		return FALSE;
	}

	key = get_unconfirmed_message_key(sipmsg_find_header(msg, "Call-ID"), sipmsg_parse_cseq(msg), with);
	message = g_hash_table_lookup(session->unconfirmed_messages, key);

	if (msg->response >= 400) {
		int warning = sipmsg_parse_warning(msg, NULL);

		SIPE_DEBUG_INFO_NOFORMAT("process_message_response: MESSAGE response >= 400");

		/* cancel file transfer as rejected by server */
		if (msg->response == 606 &&	/* Not acceptable all. */
		    warning == 309 &&		/* Message contents not allowed by policy */
		    message && g_str_has_prefix(message->content_type, "text/x-msmsgsinvite"))
		{
			GSList *parsed_body = sipe_ft_parse_msg_body(msg->body);
			sipe_ft_incoming_cancel(dialog, parsed_body);
			sipe_utils_nameval_free(parsed_body);
		}

		/* drop dangling IM sessions: assume that BYE from remote never reached us */
		if (msg->response == 408 || /* Request timeout */
		    msg->response == 480 || /* Temporarily Unavailable */
		    msg->response == 481) { /* Call/Transaction Does Not Exist */
			sipe_im_cancel_dangling(sipe_private, session, dialog, with,
						sipe_im_cancel_unconfirmed);
			/* dialog is no longer valid */
		} else {
			gchar *alias = sipe_buddy_get_alias(sipe_private, with);
			sipe_user_present_message_undelivered(sipe_private, session,
							      msg->response, warning,
							      alias ? alias : with,
							      message ? message->body : NULL);
			remove_unconfirmed_message(session, key);
			/* message is no longer valid */
			g_free(alias);
		}

		ret = FALSE;
	} else {
		const gchar *message_id = sipmsg_find_header(msg, "Message-Id");
		if (message_id) {
			g_hash_table_insert(session->conf_unconfirmed_messages, g_strdup(message_id), g_strdup(message->body));
			SIPE_DEBUG_INFO("process_message_response: added message with id %s to conf_unconfirmed_messages(count=%d)",
					message_id, g_hash_table_size(session->conf_unconfirmed_messages));
		}
		remove_unconfirmed_message(session, key);
	}

	g_free(key);
	g_free(with);

	if (ret) sipe_im_process_queue(sipe_private, session);
	return ret;
}

#ifndef ENABLE_OCS2005_MESSAGE_HACK
/*
 * Hack to circumvent problems reported in the bug report
 *
 *        #3267073 - False "could not be delivered" errors
 *
 * The logs provided by the reporters indicate that OCS2005 clients DO NOT
 * acknowledge our SIP MESSAGEs. Therefore the message timeout is triggered
 * and messages are reported to the user as not delivered.
 *
 * Either this is a bug in the OCS2005 client or we do something wrong in our
 * SIP MESSAGEs. This hack removes the message timeout and is provided for
 * users who need to communicate with a still existing OCS2005 user base.
 *
 * Do not enable it by default!
 */
static gboolean
process_message_timeout(struct sipe_core_private *sipe_private,
			struct sipmsg *msg,
			SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	gchar *with = parse_from(sipmsg_find_header(msg, "To"));
	const gchar *callid = sipmsg_find_header(msg, "Call-ID");
	struct sip_session *session = sipe_session_find_chat_or_im(sipe_private, callid, with);
	gchar *key;
	gboolean found;

	if (!session) {
		SIPE_DEBUG_INFO_NOFORMAT("process_message_timeout: unable to find IM session");
		g_free(with);
		return TRUE;
	}

	/* Remove timed-out message from unconfirmed list */
	key = get_unconfirmed_message_key(sipmsg_find_header(msg, "Call-ID"), sipmsg_parse_cseq(msg), with);
	found = remove_unconfirmed_message(session, key);
	g_free(key);

	if (found) {
		gchar *alias = sipe_buddy_get_alias(sipe_private, with);
		sipe_user_present_message_undelivered(sipe_private, session, -1, -1,
						      alias ? alias : with,
						      msg->body);
		g_free(alias);
	}

	g_free(with);
	return TRUE;
}
#endif

static void sipe_im_send_message(struct sipe_core_private *sipe_private,
				 struct sip_dialog *dialog,
				 const gchar *msg_body,
				 const gchar *content_type)
{
	gchar *hdr;
	gchar *tmp;
	char *msgtext = NULL;
	const gchar *msgr = "";
	gchar *tmp2 = NULL;

	if (content_type == NULL)
		content_type = "text/plain";

	if (!g_str_has_prefix(content_type, "text/x-msmsgsinvite")) {
		char *msgformat;
		gchar *msgr_value;

		sipe_parse_html(msg_body, &msgformat, &msgtext);
		SIPE_DEBUG_INFO("sipe_send_message: msgformat=%s", msgformat);

		msgr_value = sipmsg_get_msgr_string(msgformat);
		g_free(msgformat);
		if (msgr_value) {
			msgr = tmp2 = g_strdup_printf(";msgr=%s", msgr_value);
			g_free(msgr_value);
		}
	} else {
		msgtext = g_strdup(msg_body);
	}

	tmp = get_contact(sipe_private);
	//hdr = g_strdup("Content-Type: text/plain; charset=UTF-8\r\n");
	//hdr = g_strdup("Content-Type: text/rtf\r\n");
	//hdr = g_strdup("Content-Type: text/plain; charset=UTF-8;msgr=WAAtAE0ATQBTAC....AoADQA\r\nSupported: timer\r\n");

	hdr = g_strdup_printf("Contact: %s\r\nContent-Type: %s; charset=UTF-8%s\r\n", tmp, content_type, msgr);
	g_free(tmp);
	g_free(tmp2);

#ifdef ENABLE_OCS2005_MESSAGE_HACK
	sip_transport_request(
#else
	sip_transport_request_timeout(
#endif
				      sipe_private,
				      "MESSAGE",
				      dialog->with,
				      dialog->with,
				      hdr,
				      msgtext,
				      dialog,
				      process_message_response
#ifndef ENABLE_OCS2005_MESSAGE_HACK
				      ,
				      60,
				      process_message_timeout
#endif
				     );
	g_free(msgtext);
	g_free(hdr);
}

void sipe_im_process_queue(struct sipe_core_private *sipe_private,
			   struct sip_session *session)
{
	GSList *entry2 = session->outgoing_message_queue;
	while (entry2) {
		struct queued_message *msg = entry2->data;

		/* for multiparty chat or conference */
		if (session->chat_session) {
			gchar *who = sip_uri_self(sipe_private);
			sipe_backend_chat_message(SIPE_CORE_PUBLIC,
						  session->chat_session->backend,
						  who,
						  0,
						  msg->body);
			g_free(who);
		}

		SIPE_DIALOG_FOREACH {
			if (dialog->outgoing_invite) continue; /* do not send messages as INVITE is not responded. */

			insert_unconfirmed_message(session, dialog, dialog->with,
						   msg->body, msg->content_type);

			sipe_im_send_message(sipe_private, dialog, msg->body, msg->content_type);
		} SIPE_DIALOG_FOREACH_END;

		entry2 = sipe_session_dequeue_message(session);
	}
}

struct unconfirmed_callback_data {
	const gchar *prefix;
	GSList *list;
};

struct unconfirmed_message {
	const gchar *key;
	const struct queued_message *msg;
};

static gint compare_cseq(gconstpointer a,
			 gconstpointer b)
{
	return(((struct unconfirmed_message *) a)->msg->cseq -
	       ((struct unconfirmed_message *) b)->msg->cseq);
}

static void unconfirmed_message_callback(gpointer key,
					 gpointer value,
					 gpointer user_data)
{
	const gchar *message_key = key;
	struct unconfirmed_callback_data *data = user_data;

	SIPE_DEBUG_INFO("unconfirmed_message_callback: key %s", message_key);

	/* Put messages with the same prefix on a list sorted by CSeq */
	if (g_str_has_prefix(message_key, data->prefix)) {
		struct unconfirmed_message *msg = g_malloc(sizeof(struct unconfirmed_message));
		msg->key = message_key;
		msg->msg = value;
		data->list = g_slist_insert_sorted(data->list, msg,
						   compare_cseq);
	}
}

static void foreach_unconfirmed_message(struct sipe_core_private *sipe_private,
					struct sip_session *session,
					const gchar *callid,
					const gchar *with,
					unconfirmed_callback callback,
					const gchar *callback_data)
{
	gchar *prefix = g_strdup_printf(UNCONFIRMED_KEY_TEMPLATE("MESSAGE", ""),
					callid, with);
	struct unconfirmed_callback_data data = { prefix, NULL };

	SIPE_DEBUG_INFO("foreach_unconfirmed_message: prefix %s", prefix);

	/* Generate list of matching unconfirmed messages */
	g_hash_table_foreach(session->unconfirmed_messages,
			     unconfirmed_message_callback,
			     &data);
	g_free(prefix);

	/* Process list unconfirmed messages */
	if (data.list) {
		GSList *entry;

		while ((entry = data.list) != NULL) {
			struct unconfirmed_message *unconfirmed = entry->data;
			data.list = g_slist_remove(data.list, unconfirmed);

			SIPE_DEBUG_INFO("foreach_unconfirmed_message: %s", unconfirmed->key);
			(*callback)(sipe_private, session, unconfirmed->msg->body, callback_data);

			g_hash_table_remove(session->unconfirmed_messages, unconfirmed->key);
			g_free(unconfirmed);
		}
	}
}

static void cancel_callback(struct sipe_core_private *sipe_private,
			    struct sip_session *session,
			    const gchar *body,
			    const gchar *with)
{
	sipe_user_present_message_undelivered(sipe_private, session,
					      -1, -1, with, body);
}

void sipe_im_cancel_unconfirmed(struct sipe_core_private *sipe_private,
				struct sip_session *session,
				const gchar *callid,
				const gchar *with)
{
	gchar *alias = sipe_buddy_get_alias(sipe_private, with);

	SIPE_DEBUG_INFO("sipe_im_cancel_unconfirmed: with %s callid '%s'",
			with, callid);

	foreach_unconfirmed_message(sipe_private, session, callid, with,
				    cancel_callback, alias ? alias : with);
	g_free(alias);
}

static void reenqueue_callback(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private,
			       struct sip_session *session,
			       const gchar *body,
			       SIPE_UNUSED_PARAMETER const gchar *with)
{
	sipe_session_enqueue_message(session, body, NULL);
}

void sipe_im_reenqueue_unconfirmed(struct sipe_core_private *sipe_private,
				   struct sip_session *session,
				   const gchar *callid,
				   const gchar *with)
{
	/* Remember original list, start with an empty list  */
	GSList *first = session->outgoing_message_queue;
	session->outgoing_message_queue = NULL;

	SIPE_DEBUG_INFO("sipe_im_reenqueue_unconfirmed: with %s callid '%s'",
			with, callid);

	/* Enqueue unconfirmed messages */
	foreach_unconfirmed_message(sipe_private, session, callid, with,
				    reenqueue_callback, NULL);

	/* Append or restore original list */
	if (session->outgoing_message_queue) {
		GSList *last = g_slist_last(session->outgoing_message_queue);
		last->next = first;
	} else {
		session->outgoing_message_queue = first;
	}
}

void sipe_core_im_send(struct sipe_core_public *sipe_public,
		       const gchar *who,
		       const gchar *what)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sip_session *session;
	struct sip_dialog *dialog;
	gchar *uri = sip_uri(who);

	SIPE_DEBUG_INFO("sipe_core_im_send: '%s'", what);

	session = sipe_session_find_or_add_im(sipe_private, uri);
	dialog = sipe_dialog_find(session, uri);

	/* Queue the message */
	sipe_session_enqueue_message(session, what, NULL);

	if (dialog && !dialog->outgoing_invite) {
                if (dialog->delayed_invite)
			sipe_incoming_cancel_delayed_invite(sipe_private,
							    dialog);
		sipe_im_process_queue(sipe_private, session);
	} else if (!dialog || !dialog->outgoing_invite) {
		/* Need to send the INVITE to get the outgoing dialog setup */
		sipe_im_invite(sipe_private, session, uri, what, NULL, NULL, FALSE);
	}

	g_free(uri);
}

void sipe_core_im_close(struct sipe_core_public *sipe_public,
			const gchar *who)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;

	SIPE_DEBUG_INFO("sipe_core_im_close: conversation with %s closed", who);
	sipe_session_close(sipe_private,
			   sipe_session_find_im(sipe_private, who));
}

void sipe_im_cancel_dangling(struct sipe_core_private *sipe_private,
			     struct sip_session *session,
			     struct sip_dialog *dialog,
			     const gchar *with,
			     unconfirmed_callback callback)
{
	SIPE_DEBUG_INFO_NOFORMAT("sipe_im_cancel_dangling: assuming dangling IM session, dropping it.");
	sip_transport_bye(sipe_private, dialog);

	(*callback)(sipe_private, session, dialog->callid, with);

	/* We might not get a valid reply to our BYE,
	   so make sure the dialog is removed for sure. */
	sipe_dialog_remove(session, with);
	/* dialog is no longer valid */
}

void sipe_im_topic(struct sipe_core_private *sipe_private,
		   struct sip_session *session,
		   const gchar *topic)
{
	g_free(session->subject);
	session->subject = g_strdup(topic);
	sipe_backend_im_topic(SIPE_CORE_PUBLIC, session->with, topic);
}

void process_incoming_info_conversation(struct sipe_core_private *sipe_private,
					struct sipmsg *msg)
{
	sipe_xml *xml = sipe_xml_parse(msg->body, msg->bodylen);
	const gchar *from = NULL;
	gchar *subject = NULL;


	if (!xml)
		return;

	if (sipe_strequal(sipe_xml_name(xml), "ConversationInfo")) {
		const sipe_xml *node = sipe_xml_child(xml, "From");
		if (node)
			from = sipe_xml_attribute(node, "uri");

		node = sipe_xml_child(xml, "Subject");
		if (node)
			subject = sipe_xml_data(node);
	}

	if (from && subject) {
		struct sip_session *session;
		session = sipe_session_find_im(sipe_private, from);

		if (session)
			sipe_im_topic(sipe_private, session, subject);
	}

	g_free(subject);
	sipe_xml_free(xml);

	sip_transport_response(sipe_private, msg, 200, "OK", NULL);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
