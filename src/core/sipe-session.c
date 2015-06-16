/**
 * @file sipe-session.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009-2013 SIPE Project <http://sipe.sourceforge.net/>
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

#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-chat.h"
#include "sipe-conf.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-dialog.h"
#include "sipe-session.h"
#include "sipe-utils.h"

static void
sipe_free_queued_message(struct queued_message *message)
{
	g_free(message->body);
	g_free(message->content_type);
	g_free(message);
}

struct sip_session *
sipe_session_add_chat(struct sipe_core_private *sipe_private,
		      struct sipe_chat_session *chat_session,
		      gboolean multiparty,
		      const gchar *id)
{
	struct sip_session *session = g_new0(struct sip_session, 1);
	session->callid = gencallid();
	if (chat_session) {
		session->chat_session = chat_session;
	} else {
		gchar *chat_title = sipe_chat_get_name();
		session->chat_session = sipe_chat_create_session(multiparty ?
								 SIPE_CHAT_TYPE_MULTIPARTY :
								 SIPE_CHAT_TYPE_CONFERENCE,
								 id,
								 chat_title);
		g_free(chat_title);
	}
	session->unconfirmed_messages = g_hash_table_new_full(
		g_str_hash, g_str_equal, g_free, (GDestroyNotify)sipe_free_queued_message);
	session->conf_unconfirmed_messages = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	sipe_private->sessions = g_slist_append(sipe_private->sessions, session);
	return session;
}

#ifdef HAVE_VV

struct sip_session *
sipe_session_add_call(struct sipe_core_private *sipe_private,
		      const gchar *who)
{
	struct sip_session *session = g_new0(struct sip_session, 1);
	SIPE_DEBUG_INFO("sipe_session_add_call: new session for %s", who);
	session->with = g_strdup(who);
	session->unconfirmed_messages = g_hash_table_new_full(
		g_str_hash, g_str_equal, g_free, (GDestroyNotify)sipe_free_queued_message);
	session->is_call = TRUE;
	sipe_private->sessions = g_slist_append(sipe_private->sessions, session);
	return session;
}

#endif

struct sip_session *
sipe_session_find_chat(struct sipe_core_private *sipe_private,
		       struct sipe_chat_session *chat_session)
{
	if (sipe_private == NULL || chat_session == NULL) {
		return NULL;
	}

	SIPE_SESSION_FOREACH {
		if (session->chat_session == chat_session) {
			return session;
		}
	} SIPE_SESSION_FOREACH_END;
	return NULL;

}

struct sip_session *
sipe_session_find_chat_by_callid(struct sipe_core_private *sipe_private,
				 const gchar *callid)
{
	if (sipe_private == NULL || callid == NULL) {
		return NULL;
	}

	SIPE_SESSION_FOREACH {
		if (session->callid &&
		    sipe_strcase_equal(callid, session->callid)) {
			return session;
		}
	} SIPE_SESSION_FOREACH_END;
	return NULL;
}

struct sip_session *
sipe_session_find_conference(struct sipe_core_private *sipe_private,
			     const gchar *focus_uri)
{
	if (sipe_private == NULL || focus_uri == NULL) {
		return NULL;
	}

	SIPE_SESSION_FOREACH {
		if (session->chat_session &&
		    (session->chat_session->type == SIPE_CHAT_TYPE_CONFERENCE) &&
		    sipe_strcase_equal(focus_uri, session->chat_session->id)) {
			return session;
		}
	} SIPE_SESSION_FOREACH_END;
	return NULL;
}

struct sip_session *
sipe_session_find_im(struct sipe_core_private *sipe_private,
		     const gchar *who)
{
	if (sipe_private == NULL || who == NULL) {
		return NULL;
	}

	SIPE_SESSION_FOREACH {
		if (!session->is_call &&
		    session->with && sipe_strcase_equal(who, session->with)) {
			return session;
		}
	} SIPE_SESSION_FOREACH_END;
	return NULL;
}

struct sip_session *
sipe_session_find_or_add_im(struct sipe_core_private *sipe_private,
			    const gchar *who)
{
	struct sip_session *session = sipe_session_find_im(sipe_private, who);
	if (!session) {
		SIPE_DEBUG_INFO("sipe_session_find_or_add_im: new session for %s", who);
		session = g_new0(struct sip_session, 1);
		session->with = g_strdup(who);
		session->unconfirmed_messages = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free, (GDestroyNotify)sipe_free_queued_message);
		sipe_private->sessions = g_slist_append(sipe_private->sessions, session);
	}
	return session;
}

struct sip_session *
sipe_session_find_chat_or_im(struct sipe_core_private *sipe_private,
			     const gchar *callid,
			     const gchar *who)
{
	struct sip_session *session = sipe_session_find_chat_by_callid(sipe_private,
								       callid);
	if (!session) {
		session = sipe_session_find_im(sipe_private, who);
	}
	return session;
}

void
sipe_session_remove(struct sipe_core_private *sipe_private,
		    struct sip_session *session)
{
	sipe_private->sessions = g_slist_remove(sipe_private->sessions, session);

	sipe_dialog_remove_all(session);
	sipe_dialog_free(session->focus_dialog);

	while (sipe_session_dequeue_message(session));

	sipe_utils_slist_free_full(session->pending_invite_queue, g_free);

	g_hash_table_destroy(session->unconfirmed_messages);
	if (session->conf_unconfirmed_messages)
		g_hash_table_destroy(session->conf_unconfirmed_messages);

	g_free(session->with);
	g_free(session->callid);
	g_free(session->im_mcu_uri);
	g_free(session->subject);
	g_free(session);
}

void
sipe_session_close(struct sipe_core_private *sipe_private,
		   struct sip_session *session)
{
	if (session) {
		if (session->chat_session &&
		    (session->chat_session->type == SIPE_CHAT_TYPE_CONFERENCE)) {
			sipe_conf_immcu_closed(sipe_private, session);
			conf_session_close(sipe_private, session);
		}

		SIPE_DIALOG_FOREACH {
			/* @TODO slow down BYE message sending rate */
			/* @see single subscription code */
			sip_transport_bye(sipe_private, dialog);
		} SIPE_DIALOG_FOREACH_END;

		sipe_session_remove(sipe_private, session);
	}
}

void
sipe_session_enqueue_message(struct sip_session *session,
			     const gchar *body, const gchar *content_type)
{
	struct queued_message *msg = g_new0(struct queued_message,1);
	msg->body = g_strdup(body);
	if (content_type != NULL)
		msg->content_type = g_strdup(content_type);

	session->outgoing_message_queue = g_slist_append(session->outgoing_message_queue, msg);
}

GSList *
sipe_session_dequeue_message(struct sip_session *session)
{
	struct queued_message *msg;

	if (session->outgoing_message_queue == NULL)
		return NULL;

	msg = session->outgoing_message_queue->data;
	session->outgoing_message_queue = g_slist_remove(session->outgoing_message_queue, msg);
	g_free(msg->body);
	g_free(msg->content_type);
	g_free(msg);

	return session->outgoing_message_queue;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
