/**
 * @file sipe-session.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
 * Copyright (C) 2009 SIPE Project <http://sipe.sourceforge.net/>
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

#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-dialog.h"
#include "sipe-session.h"
#include "sipe-utils.h"
#include "sipe.h"

void
sipe_free_queued_message(struct queued_message *message)
{
	g_free(message->body);
	g_free(message->content_type);
	g_free(message);
}

struct sip_session *
sipe_session_add_chat(struct sipe_account_data *sip)
{
	struct sip_session *session = g_new0(struct sip_session, 1);
	session->callid = gencallid();
	session->is_multiparty = TRUE;
	session->chat_id = rand();
	session->unconfirmed_messages = g_hash_table_new_full(
		g_str_hash, g_str_equal, g_free, (GDestroyNotify)sipe_free_queued_message);
	session->conf_unconfirmed_messages = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	sip->sessions = g_slist_append(sip->sessions, session);
	return session;
}

struct sip_session *
sipe_session_find_or_add_chat_by_callid(struct sipe_account_data *sip,
					const gchar *callid)
{
	struct sip_session *session = sipe_session_find_chat_by_callid(sip, callid);
	if (!session) {
		SIPE_DEBUG_INFO("sipe_session_find_or_add_chat_by_callid: new session for %s", callid);
		session = sipe_session_add_chat(sip);
		session->callid = g_strdup(callid);
	}
	return session;
}

struct sip_session *
sipe_session_find_chat_by_callid(struct sipe_account_data *sip,
				 const gchar *callid)
{
	if (sip == NULL || callid == NULL) {
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
sipe_session_find_chat_by_id(struct sipe_account_data *sip,
			     int id)
{
	if (sip == NULL) {
		return NULL;
	}

	SIPE_SESSION_FOREACH {
		if (id == session->chat_id) {
			return session;
		}
	} SIPE_SESSION_FOREACH_END;
	return NULL;
}

struct sip_session *
sipe_session_find_chat_by_title(struct sipe_account_data *sip,
			        const gchar *name)
{
	if (sip == NULL || name == NULL) {
		return NULL;
	}

	SIPE_SESSION_FOREACH {
		if (session->chat_title &&
		    !g_strcasecmp(name, session->chat_title)) {
			return session;
		}
	} SIPE_SESSION_FOREACH_END;
	return NULL;
}

struct sip_session *
sipe_session_find_conference(struct sipe_account_data *sip,
			     const gchar *focus_uri)
{
	if (sip == NULL || focus_uri == NULL) {
		return NULL;
	}

	SIPE_SESSION_FOREACH {
		if (session->focus_uri &&
		    sipe_strcase_equal(focus_uri, session->focus_uri)) {
			return session;
		}
	} SIPE_SESSION_FOREACH_END;
	return NULL;
}

struct sip_session *
sipe_session_find_im(struct sipe_account_data *sip, const gchar *who)
{
	if (sip == NULL || who == NULL) {
		return NULL;
	}

	SIPE_SESSION_FOREACH {
		if (session->with && sipe_strcase_equal(who, session->with)) {
			return session;
		}
	} SIPE_SESSION_FOREACH_END;
	return NULL;
}

struct sip_session *
sipe_session_find_or_add_im(struct sipe_account_data *sip,
			    const gchar *who)
{
	struct sip_session *session = sipe_session_find_im(sip, who);
	if (!session) {
		SIPE_DEBUG_INFO("sipe_session_find_or_add_im: new session for %s", who);
		session = g_new0(struct sip_session, 1);
		session->is_multiparty = FALSE;
		session->with = g_strdup(who);
		session->unconfirmed_messages = g_hash_table_new_full(
			g_str_hash, g_str_equal, g_free, (GDestroyNotify)sipe_free_queued_message);
		sip->sessions = g_slist_append(sip->sessions, session);
	}
	return session;
}

void
sipe_session_remove(struct sipe_account_data *sip, struct sip_session *session)
{
	GSList *entry;

	sip->sessions = g_slist_remove(sip->sessions, session);

	sipe_dialog_remove_all(session);
	sipe_dialog_free(session->focus_dialog);

	entry = session->outgoing_message_queue;
	while (entry) {
		struct queued_message *msg = entry->data;
		g_free(msg->body);
		g_free(msg->content_type);
		g_free(msg);
		entry = entry->next;
	}
	g_slist_free(session->outgoing_message_queue);

	entry = session->pending_invite_queue;
	while (entry) {
		g_free(entry->data);
		entry = entry->next;
	}
	g_slist_free(session->pending_invite_queue);

	g_hash_table_destroy(session->unconfirmed_messages);
	g_hash_table_destroy(session->conf_unconfirmed_messages);

	g_free(session->with);
	g_free(session->chat_title);
	g_free(session->callid);
	g_free(session->roster_manager);
	g_free(session->focus_uri);
	g_free(session->im_mcu_uri);
	g_free(session->subject);
	g_free(session);
}

void
sipe_session_remove_all(struct sipe_account_data *sip)
{
	GSList *entry;
	while ((entry = sip->sessions) != NULL) {
		sipe_session_remove(sip, entry->data);
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
