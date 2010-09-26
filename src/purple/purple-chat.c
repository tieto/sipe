/**
 * @file purple-chat.c
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

#include <time.h>

#include <glib.h>

#include "conversation.h"
#include "server.h"

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"

#define _PurpleMessageFlags PurpleMessageFlags
#include "purple-private.h"

/* @TODO: remove after API rework! */
#include "request.h"
#include "core-depurple.h"

/**
 * Mapping between chat sessions in SIPE core and libpurple backend
 *
 * PurpleAccount
 *    This data structure is created when the user creates the account or at
 *    startup. It lives as long as the account exists, i.e. until the user
 *    deletes it or shutdown.
 *
 *    Value does not change when connection is dropped & re-created.
 *    HAS: gc (PurpleConnection *)
 *
 * PurpleConversation / PurpleConvChat (sub-type)
 *    This data structure is created by serv_got_join_chat(). It lives as long
 *    as the user doesn't leave the chat or until shutdown.
 *    
 *    Value does not change when connection is dropped & re-created.
 *    HAS: account (PurpleAccount *)
 *    HAS: chat ID (int), must be unique
 *    HAS: name (char *), must be unique
 *    HAS: data (GHashTable *)
 *
 * PurpleConnection
 *    This data structure is created when the connection to the service is
 *    set up. It lives as long as the connection stays open, the user disables
 *    the account or until shutdown.
 *
 *    Value *DOES NOT* survive a connection drop & re-creation.
 *    ASSOCIATED TO: account
 *
 * SIPE -> libpurple API
 *    add user:    purple_conv_chat_add_user(conv, ...)
 *    create:      serv_got_joined_chat(gc, chat ID, name)
 *    find user:   purple_conv_chat_find_user(conv, ...)
 *    message:     serv_got_chat_in(gc, chat ID, ...)
 *    remove user: purple_conv_chat_remove_user(conv, ...)
 *    topic:       purple_conv_chat_set_topic(conv, ...)
 *
 * libpurple -> SIPE API
 *    join_chat(gc, params (GHashTable *))
 *      request to join a channel (again)                 [only Group Chat]
 *      SIPE must call serv_got_joined_chat() on join response
 *
 *    reject_chat(gc, params (GHashTable *))                NOT IMPLEMENTED
 *    get_chat_name(params (GHashTable *))                  NOT IMPLEMENTED
 *
 *    chat_invite(gc, chat ID,...)
 *      invite a user to a join a chat
 *
 *    chat_leave(gc, chat ID)
 *      request to leave a channel, also called on conversation destroy
 *      SIPE must call serv_got_chat_left() immediately!
 *
 *    chat_whisper(gc, chat ID, ...)                        NOT IMPLEMENTED
 *
 *    chat_send(gc, chat ID, ...)
 *      send a message to the channel
 *
 *    set_chat_topic(gc, chat ID, ...)                      NOT IMPLEMENTED
 *      set channel topic                           [@TODO: for Group Chat]
 *
 *
 * struct sipe_chat_session [@TODO: TO BE IMPLEMENTED]
 *    Same life span as PurpleConversation
 *    Pointer stored under key "sipe" in PurpleConversation->data
 *    Contains information private to core to identify chat session on server
 *
 *    If connection is closed and THEN the conversation, then libpurple will
 *    not call chat_leave() and this will be a dangling data structure! Core
 *    must take care to release them at unload.
 *
 *    HAS: backend_session (gpointer) -> PurpleConversation
 *
 * struct sipe_backend_private [@TODO: TO BE IMPLEMENTED]
 *
 *    HAS: rejoin_chats (GList *)
 *         created on login() for existing chats
 *         initiate re-join calls to core (sipe_backend_chat_rejoin_all)
 *         remove chats when joined (sipe_backend_chat_create)
 */

#define SIPE_PURPLE_KEY_CHAT_SESSION "sipe"

#define BACKEND_SESSION_TO_PURPLE_CONV_CHAT(s) \
	(PURPLE_CONV_CHAT(((PurpleConversation *)s)))

#if 0
static struct sipe_chat_session* sipe_purple_chat_find(struct sipe_backend_private *purple_private,
						       int id)
{
	PurpleConversation *conv = purple_find_chat(purple_private->gc, id);

	if (!conv) {
		SIPE_DEBUG_ERROR("sipe_purple_chat_find: can't find chat with ID %d?!?",
				 id);
		return NULL;
	}

	return purple_conversation_get_data(conv,
					    SIPE_PURPLE_KEY_CHAT_SESSION);
}
#endif

void sipe_purple_chat_invite(PurpleConnection *gc, int id,
			     SIPE_UNUSED_PARAMETER const char *message,
			     const char *name)
{
	sipe_core_chat_create(PURPLE_GC_TO_SIPE_CORE_PUBLIC, id, name);
}

void sipe_purple_chat_leave(PurpleConnection *gc, int id)
{
	sipe_chat_leave(gc, id);
}

int sipe_purple_chat_send(PurpleConnection *gc,
			  int id,
			  const char *what,
			  PurpleMessageFlags flags)
{
	return sipe_chat_send(gc, id, what, flags);
}

void sipe_backend_chat_session_destroy(SIPE_UNUSED_PARAMETER struct sipe_backend_chat_session *session)
{
	/* Nothing to do here */
}

void sipe_backend_chat_add(struct sipe_backend_session *backend_session,
			   const gchar *uri,
			   gboolean is_new)
{
	purple_conv_chat_add_user(BACKEND_SESSION_TO_PURPLE_CONV_CHAT(backend_session),
				  uri, NULL, PURPLE_CBFLAGS_NONE, is_new);
}

void sipe_backend_chat_close(struct sipe_backend_session *backend_session)
{
	purple_conv_chat_clear_users(BACKEND_SESSION_TO_PURPLE_CONV_CHAT(backend_session));
}

struct sipe_backend_session *sipe_backend_chat_create(struct sipe_core_public *sipe_public,
						      guint id,
						      const gchar *title,
						      const gchar *nick,
						      gboolean rejoin)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleConversation *conv = NULL;

	if (rejoin) {
		/* can't be find by chat id as it won't survive acc reinstantation */
		if (title) {
			conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
								     title,
								     purple_private->account);
		}
		/* to be able to rejoin existing chat/window */
		if (conv && !purple_conv_chat_has_left(PURPLE_CONV_CHAT(conv))) {
			PURPLE_CONV_CHAT(conv)->left = TRUE;
		}
	}

	/* create prpl chat */
	conv = serv_got_joined_chat(purple_private->gc,
				    id,
				    title);
	purple_conv_chat_set_nick(PURPLE_CONV_CHAT(conv), nick);

	/* @TODO: incomplete */
	purple_conversation_set_data(conv, SIPE_PURPLE_KEY_CHAT_SESSION, NULL);

	return((struct sipe_backend_session *) conv);
}

gboolean sipe_backend_chat_find(struct sipe_backend_session *backend_session,
			    const gchar *uri)
{
	return purple_conv_chat_find_user(BACKEND_SESSION_TO_PURPLE_CONV_CHAT(backend_session),
					  uri);
}

gboolean sipe_backend_chat_is_operator(struct sipe_backend_session *backend_session,
				       const gchar *uri)
{
	return (purple_conv_chat_user_get_flags(BACKEND_SESSION_TO_PURPLE_CONV_CHAT(backend_session),
						uri) & PURPLE_CBFLAGS_OP)
		== PURPLE_CBFLAGS_OP;
}

void sipe_backend_chat_message(struct sipe_core_public *sipe_public,
			       guint id,
			       const gchar *from,
			       const gchar *html)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	serv_got_chat_in(purple_private->gc,
			 id,
			 from,
			 PURPLE_MESSAGE_RECV,
			 html,
			 time(NULL));
}
						      
void sipe_backend_chat_operator(struct sipe_backend_session *backend_session,
				const gchar *uri)
{
	purple_conv_chat_user_set_flags(BACKEND_SESSION_TO_PURPLE_CONV_CHAT(backend_session),
					uri,
					PURPLE_CBFLAGS_NONE | PURPLE_CBFLAGS_OP);
}

/**
 * Allows to send typed messages from chat window again after
 * account reinstantiation.
 *
 * @TODO: is this really necessary? No other purple protocol plugin
 *        seems to have this kind of code...
 */
void sipe_backend_chat_rejoin_all(struct sipe_core_public *sipe_public)
	
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	GList *entry = purple_get_chats();

	while (entry) {
		PurpleConversation *conv = entry->data;
		if ((purple_conversation_get_gc(conv) == purple_private->gc) &&
		    purple_conv_chat_has_left(PURPLE_CONV_CHAT(conv))) {
			PURPLE_CONV_CHAT(conv)->left = FALSE;
			purple_conversation_update(conv,
						   PURPLE_CONV_UPDATE_CHATLEFT);
		}
		entry = entry->next;
	}
}

void sipe_backend_chat_remove(struct sipe_backend_session *backend_session,
			      const gchar *uri)
{
	purple_conv_chat_remove_user(BACKEND_SESSION_TO_PURPLE_CONV_CHAT(backend_session),
				     uri,
				     NULL /* reason */);
}

void sipe_backend_chat_topic(struct sipe_backend_session *backend_session,
			      const gchar *topic)
{
	purple_conv_chat_set_topic(BACKEND_SESSION_TO_PURPLE_CONV_CHAT(backend_session),
				   NULL,
				   topic);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
