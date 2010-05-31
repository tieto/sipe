/**
 * @file sipe-chat.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009-10 SIPE Project <http://sipe.sourceforge.net/>
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
#include <time.h>

#include <glib.h>

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
#include "sipe-schedule.h"
#include "sipe-session.h"
#include "sipe-utils.h"
#include "sipe-xml.h"
#include "sipe.h"

void sipe_core_chat_create(struct sipe_core_public *sipe_public, int id,
			   const char *name)
{
	struct sip_session *session = sipe_session_find_chat_by_id(SIPE_CORE_PRIVATE,
								   id);

	if (session) {
		gchar *uri = sip_uri(name);
		sipe_invite_to_chat(SIPE_CORE_PRIVATE, session, uri);
		g_free(uri);
	}
}

/** See below. Same as chat_names but swapped key with values */
static GHashTable *chat_names_inverse = NULL;

gchar *
sipe_chat_get_name(const gchar *proto_chat_id)
{
	/**
	 * A non-volatile mapping of protocol's chat identification
	 * to purple's chat-name. The latter is very important to
	 * find/rejoin chat.
	 *
	 * @key for 2007 conference this is (gchar *) Focus URI
	 *      for 2005 multiparty chat this is (gchar *) Call-Id of the conversation.
	 * @value a purple chat name.
	 */
	static GHashTable *chat_names = NULL;

	/**
	 * A non-volatile chat counter.
	 * Should survive protocol reload.
	 */
	static int chat_seq = 0;

	char *chat_name = NULL;

	if (!chat_names) {
		chat_names = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	}
	if (!chat_names_inverse) {
		chat_names_inverse = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	}

	if (proto_chat_id) {
		chat_name = g_hash_table_lookup(chat_names, proto_chat_id);
		SIPE_DEBUG_INFO("sipe_chat_get_name: lookup results: %s", chat_name ? chat_name : "NULL");
	}
	if (!chat_name) {
		chat_name = g_strdup_printf(_("Chat #%d"), ++chat_seq);
		g_hash_table_insert(chat_names, g_strdup(proto_chat_id), chat_name);
		g_hash_table_insert(chat_names_inverse,  chat_name, g_strdup(proto_chat_id));
		SIPE_DEBUG_INFO("sipe_chat_get_name: added new: %s", chat_name);
	}

	return g_strdup(chat_name);
}

const gchar *
sipe_chat_find_name(const gchar *chat_name)
{
	if (!chat_names_inverse) return NULL;
	return(g_hash_table_lookup(chat_names_inverse, chat_name));
}

static void
sipe_refer(struct sipe_core_private *sipe_private,
	   struct sip_session *session,
	   const gchar *who)
{
	gchar *hdr;
	gchar *contact;
	gchar *epid = get_epid(sipe_private);
	struct sip_dialog *dialog = sipe_dialog_find(session,
						     session->roster_manager);
	const char *ourtag = dialog && dialog->ourtag ? dialog->ourtag : NULL;

	contact = get_contact(sipe_private);
	hdr = g_strdup_printf(
		"Contact: %s\r\n"
		"Refer-to: <%s>\r\n"
		"Referred-By: <sip:%s>%s%s;epid=%s\r\n"
		"Require: com.microsoft.rtc-multiparty\r\n",
		contact,
		who,
		sipe_private->username,
		ourtag ? ";tag=" : "",
		ourtag ? ourtag : "",
		epid);
	g_free(epid);

	sip_transport_request(sipe_private,
			      "REFER",
			      session->roster_manager,
			      session->roster_manager,
			      hdr,
			      NULL,
			      dialog,
			      NULL);

	g_free(hdr);
	g_free(contact);
}

static gboolean
sipe_is_election_finished(struct sip_session *session)
{
	gboolean res = TRUE;

	SIPE_DIALOG_FOREACH {
		if (dialog->election_vote == 0) {
			res = FALSE;
			break;
		}
	} SIPE_DIALOG_FOREACH_END;

	if (res) {
		session->is_voting_in_progress = FALSE;
	}
	return res;
}

static gboolean
process_info_response(struct sipe_core_private *sipe_private,
		      struct sipmsg *msg,
		      struct transaction *trans);

static void
sipe_send_election_set_rm(struct sipe_core_private *sipe_private,
			  struct sip_dialog *dialog)
{
	const gchar *hdr = "Content-Type: application/x-ms-mim\r\n";

	gchar *body = g_strdup_printf(
		"<?xml version=\"1.0\"?>\r\n"
		"<action xmlns=\"http://schemas.microsoft.com/sip/multiparty/\">"
		"<SetRM uri=\"sip:%s\"/></action>\r\n",
		sipe_private->username);

	sip_transport_info(sipe_private,
			   hdr,
			   body,
			   dialog,
			   process_info_response);

	g_free(body);
}

void
sipe_process_pending_invite_queue(struct sipe_core_private *sipe_private,
				  struct sip_session *session)
{
	gchar *invitee;
	GSList *entry = session->pending_invite_queue;

	while (entry) {
		invitee = entry->data;
		sipe_invite_to_chat(sipe_private, session, invitee);
		entry = session->pending_invite_queue = g_slist_remove(session->pending_invite_queue, invitee);
		g_free(invitee);
	}
}

static void
sipe_election_result(struct sipe_core_private *sipe_private,
		     void *sess)
{
	struct sip_session *session = (struct sip_session *)sess;
	gchar *rival;
	gboolean has_won = TRUE;

	if (session->roster_manager) {
		SIPE_DEBUG_INFO(
			"sipe_election_result: RM has already been elected in the meantime. It is %s",
			session->roster_manager);
		return;
	}

	session->is_voting_in_progress = FALSE;

	SIPE_DIALOG_FOREACH {
		if (dialog->election_vote < 0) {
			has_won = FALSE;
			rival = dialog->with;
			break;
		}
	} SIPE_DIALOG_FOREACH_END;

	if (has_won) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_election_result: we have won RM election!");

		session->roster_manager = sip_uri_self(sipe_private);

		SIPE_DIALOG_FOREACH {
			/* send SetRM to each chat participant*/
			sipe_send_election_set_rm(sipe_private, dialog);
		} SIPE_DIALOG_FOREACH_END;
	} else {
		SIPE_DEBUG_INFO("sipe_election_result: we loose RM election to %s", rival);
	}
	session->bid = 0;

	sipe_process_pending_invite_queue(sipe_private, session);
}

static gboolean
process_info_response(struct sipe_core_private *sipe_private,
		      struct sipmsg *msg,
		      SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	const gchar *contenttype = sipmsg_find_header(msg, "Content-Type");
	const gchar *callid = sipmsg_find_header(msg, "Call-ID");
	struct sip_dialog *dialog;
	struct sip_session *session;

	session = sipe_session_find_chat_by_callid(sipe_private, callid);
	if (!session) {
		SIPE_DEBUG_INFO("process_info_response: failed find dialog for callid %s, exiting.", callid);
		return FALSE;
	}

	if (msg->response == 200 && g_str_has_prefix(contenttype, "application/x-ms-mim")) {
		sipe_xml *xn_action                    = sipe_xml_parse(msg->body, msg->bodylen);
		const sipe_xml *xn_request_rm_response = sipe_xml_child(xn_action, "RequestRMResponse");
		const sipe_xml *xn_set_rm_response     = sipe_xml_child(xn_action, "SetRMResponse");

		if (xn_request_rm_response) {
			const char *with = sipe_xml_attribute(xn_request_rm_response, "uri");
			const char *allow = sipe_xml_attribute(xn_request_rm_response, "allow");

			dialog = sipe_dialog_find(session, with);
			if (!dialog) {
				SIPE_DEBUG_INFO("process_info_response: failed find dialog for %s, exiting.", with);
				sipe_xml_free(xn_action);
				return FALSE;
			}

			if (allow && !g_strcasecmp(allow, "true")) {
				SIPE_DEBUG_INFO("process_info_response: %s has voted PRO", with);
				dialog->election_vote = 1;
			} else if (allow && !g_strcasecmp(allow, "false")) {
				SIPE_DEBUG_INFO("process_info_response: %s has voted CONTRA", with);
				dialog->election_vote = -1;
			}

			if (sipe_is_election_finished(session)) {
				sipe_election_result(sipe_private,
						     session);
			}

		} else if (xn_set_rm_response) {

		}
		sipe_xml_free(xn_action);

	}

	return TRUE;
}

static void
sipe_send_election_request_rm(struct sipe_core_private *sipe_private,
			      struct sip_dialog *dialog,
			      int bid)
{
	const gchar *hdr = "Content-Type: application/x-ms-mim\r\n";

	gchar *body = g_strdup_printf(
		"<?xml version=\"1.0\"?>\r\n"
		"<action xmlns=\"http://schemas.microsoft.com/sip/multiparty/\">"
		"<RequestRM uri=\"sip:%s\" bid=\"%d\"/></action>\r\n",
		sipe_private->username, bid);

	sip_transport_info(sipe_private,
			   hdr,
			   body,
			   dialog,
			   process_info_response);

	g_free(body);
}

static void
sipe_election_start(struct sipe_core_private *sipe_private,
		    struct sip_session *session)
{
	if (session->is_voting_in_progress) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_election_start: other election is in progress, exiting.");
		return;
	} else {
		session->is_voting_in_progress = TRUE;
	}
	session->bid = rand();

	SIPE_DEBUG_INFO("sipe_election_start: RM election has initiated. Our bid=%d", session->bid);

	SIPE_DIALOG_FOREACH {
		/* reset election_vote for each chat participant */
		dialog->election_vote = 0;

		/* send RequestRM to each chat participant*/
		sipe_send_election_request_rm(sipe_private, dialog, session->bid);
	} SIPE_DIALOG_FOREACH_END;

	sipe_schedule_seconds(sipe_private,
			      "<+election-result>",
			      session,
			      15,
			      sipe_election_result,
			      NULL);
}

void
sipe_invite_to_chat(struct sipe_core_private *sipe_private,
		    struct sip_session *session,
		    const gchar *who)
{
	/* a conference */
	if (session->focus_uri)
	{
		sipe_invite_conf(sipe_private, session, who);
	}
	else /* a multi-party chat */
	{
		gchar *self = sip_uri_self(sipe_private);
		if (session->roster_manager) {
			if (sipe_strcase_equal(session->roster_manager, self)) {
				sipe_invite(sipe_private, session, who, NULL, NULL, NULL, FALSE);
			} else {
				sipe_refer(sipe_private, session, who);
			}
		} else {
			SIPE_DEBUG_INFO_NOFORMAT("sipe_buddy_menu_chat_invite: no RM available");

			session->pending_invite_queue = slist_insert_unique_sorted(
				session->pending_invite_queue, g_strdup(who), (GCompareFunc)strcmp);

			sipe_election_start(sipe_private, session);
		}
		g_free(self);
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
