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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>
#include <errno.h>

#include <glib.h>

#include "blist.h"
#include "conversation.h"
#include "server.h"

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-nls.h"

#define _PurpleMessageFlags PurpleMessageFlags
#include "purple-private.h"

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
 * struct sipe_chat_session
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
 * struct sipe_backend_private
 *
 *    HAS: rejoin_chats (GList *)
 *         created on login() for existing chats
 *         initiate re-join calls to core (sipe_backend_chat_rejoin_all)
 */

#define SIPE_PURPLE_KEY_CHAT_SESSION "sipe"

#define BACKEND_SESSION_TO_PURPLE_CONV_CHAT(s) \
	(PURPLE_CONV_CHAT(((PurpleConversation *)s)))

#define PURPLE_CONV_TO_SIPE_CORE_PUBLIC ((struct sipe_core_public *) conv->account->gc->proto_data)

static struct sipe_chat_session *sipe_purple_chat_get_session(PurpleConversation *conv)
{
	return purple_conversation_get_data(conv,
					    SIPE_PURPLE_KEY_CHAT_SESSION);
}

static struct sipe_chat_session *sipe_purple_chat_find(PurpleConnection *gc,
						       int id)
{
	PurpleConversation *conv = purple_find_chat(gc, id);

	if (!conv) {
		SIPE_DEBUG_ERROR("sipe_purple_chat_find: can't find chat with ID %d?!?",
				 id);
		return NULL;
	}

	return sipe_purple_chat_get_session(conv);
}

void sipe_purple_chat_setup_rejoin(struct sipe_backend_private *purple_private)
{
	GList *entry = purple_get_chats();

	while (entry) {
		PurpleConversation *conv = entry->data;
		if (purple_conversation_get_gc(conv) == purple_private->gc)
			purple_private->rejoin_chats = g_list_prepend(purple_private->rejoin_chats,
								      sipe_purple_chat_get_session(conv));
		entry = entry->next;
	}
}

void sipe_purple_chat_destroy_rejoin(struct sipe_backend_private *purple_private)
{
	g_list_free(purple_private->rejoin_chats);
	purple_private->rejoin_chats = NULL;
}

void sipe_purple_chat_invite(PurpleConnection *gc, int id,
			     SIPE_UNUSED_PARAMETER const char *message,
			     const char *name)
{
	struct sipe_chat_session *session = sipe_purple_chat_find(gc, id);
	if (!session) return;

	sipe_core_chat_invite(PURPLE_GC_TO_SIPE_CORE_PUBLIC, session, name);
}

void sipe_purple_chat_leave(PurpleConnection *gc, int id)
{
	struct sipe_chat_session *session = sipe_purple_chat_find(gc, id);
	if (!session) return;

	sipe_core_chat_leave(PURPLE_GC_TO_SIPE_CORE_PUBLIC, session);
}

int sipe_purple_chat_send(PurpleConnection *gc,
			  int id,
			  const char *what,
			  SIPE_UNUSED_PARAMETER PurpleMessageFlags flags)
{
	struct sipe_chat_session *session = sipe_purple_chat_find(gc, id);
	if (!session) return -ENOTCONN;
	sipe_core_chat_send(PURPLE_GC_TO_SIPE_CORE_PUBLIC, session, what);
	return 1;
}

static void sipe_purple_chat_menu_unlock_cb(SIPE_UNUSED_PARAMETER PurpleChat *chat,
					    PurpleConversation *conv)
{
	struct sipe_core_public *sipe_public = PURPLE_CONV_TO_SIPE_CORE_PUBLIC;
	struct sipe_chat_session *chat_session = sipe_purple_chat_get_session(conv);
	SIPE_DEBUG_INFO("sipe_purple_chat_menu_lock_cb: %p %p", conv, chat_session);
	sipe_core_chat_modify_lock(sipe_public, chat_session, FALSE);
}

static void sipe_purple_chat_menu_lock_cb(SIPE_UNUSED_PARAMETER PurpleChat *chat,
					  PurpleConversation *conv)
{
	struct sipe_core_public *sipe_public = PURPLE_CONV_TO_SIPE_CORE_PUBLIC;
	struct sipe_chat_session *chat_session = sipe_purple_chat_get_session(conv);
	SIPE_DEBUG_INFO("sipe_purple_chat_menu_lock_cb: %p %p", conv, chat_session);
	sipe_core_chat_modify_lock(sipe_public, chat_session, TRUE);
}

GList *
sipe_purple_chat_menu(PurpleChat *chat)
{
	PurpleConversation *conv = g_hash_table_lookup(chat->components,
						       SIPE_PURPLE_COMPONENT_KEY_CONVERSATION);
	GList *menu = NULL;

	if (conv) {
		PurpleMenuAction *act = NULL;

		SIPE_DEBUG_INFO("sipe_purple_chat_menu: %p", conv);

		switch (sipe_core_chat_lock_status(PURPLE_CONV_TO_SIPE_CORE_PUBLIC,
						   sipe_purple_chat_get_session(conv))) {
		case SIPE_CHAT_LOCK_STATUS_UNLOCKED:
			act = purple_menu_action_new(_("Lock"),
						     PURPLE_CALLBACK(sipe_purple_chat_menu_lock_cb),
						     conv, NULL);
			break;
		case SIPE_CHAT_LOCK_STATUS_LOCKED:
			act = purple_menu_action_new(_("Unlock"),
						     PURPLE_CALLBACK(sipe_purple_chat_menu_unlock_cb),
						     conv, NULL);
			break;
		default:
			/* Not allowed */
			break;
		}

		if (act)
			menu = g_list_prepend(menu, act);

	}

	return menu;
}

void sipe_backend_chat_session_destroy(SIPE_UNUSED_PARAMETER struct sipe_backend_chat_session *session)
{
	/* Nothing to do here */
}

void sipe_backend_chat_add(struct sipe_backend_chat_session *backend_session,
			   const gchar *uri,
			   gboolean is_new)
{
	purple_conv_chat_add_user(BACKEND_SESSION_TO_PURPLE_CONV_CHAT(backend_session),
				  uri, NULL, PURPLE_CBFLAGS_NONE, is_new);
}

void sipe_backend_chat_close(struct sipe_backend_chat_session *backend_session)
{
	purple_conv_chat_clear_users(BACKEND_SESSION_TO_PURPLE_CONV_CHAT(backend_session));
}

static int sipe_purple_chat_id(PurpleConnection *gc)
{
	/**
	 * A non-volatile ID counter.
	 * Should survive connection drop & reconnect.
	 */
	static int chat_id = 0;

	/* Find next free ID */
	do {
		if (++chat_id < 0) chat_id = 0;
	} while (purple_find_chat(gc, chat_id) != NULL)
;
	return chat_id;
}

struct sipe_backend_chat_session *sipe_backend_chat_create(struct sipe_core_public *sipe_public,
							   struct sipe_chat_session *session,
							   const gchar *title,
							   const gchar *nick)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleConversation *conv = serv_got_joined_chat(purple_private->gc,
							sipe_purple_chat_id(purple_private->gc),
							title);
	purple_conversation_set_data(conv,
				     SIPE_PURPLE_KEY_CHAT_SESSION,
				     session);
	purple_conv_chat_set_nick(PURPLE_CONV_CHAT(conv), nick);
	return((struct sipe_backend_chat_session *) conv);
}

gboolean sipe_backend_chat_find(struct sipe_backend_chat_session *backend_session,
			    const gchar *uri)
{
	return purple_conv_chat_find_user(BACKEND_SESSION_TO_PURPLE_CONV_CHAT(backend_session),
					  uri);
}

gboolean sipe_backend_chat_is_operator(struct sipe_backend_chat_session *backend_session,
				       const gchar *uri)
{
	return (purple_conv_chat_user_get_flags(BACKEND_SESSION_TO_PURPLE_CONV_CHAT(backend_session),
						uri) & PURPLE_CBFLAGS_OP)
		== PURPLE_CBFLAGS_OP;
}

void sipe_backend_chat_message(struct sipe_core_public *sipe_public,
			       struct sipe_backend_chat_session *backend_session,
			       const gchar *from,
			       const gchar *html)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	serv_got_chat_in(purple_private->gc,
			 purple_conv_chat_get_id(BACKEND_SESSION_TO_PURPLE_CONV_CHAT(backend_session)),
			 from,
			 PURPLE_MESSAGE_RECV,
			 html,
			 time(NULL));
}

void sipe_backend_chat_operator(struct sipe_backend_chat_session *backend_session,
				const gchar *uri)
{
	purple_conv_chat_user_set_flags(BACKEND_SESSION_TO_PURPLE_CONV_CHAT(backend_session),
					uri,
					PURPLE_CBFLAGS_NONE | PURPLE_CBFLAGS_OP);
}

void sipe_backend_chat_rejoin(struct sipe_core_public *sipe_public,
			      struct sipe_backend_chat_session *backend_session,
			      const gchar *nick,
			      const gchar *title)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleConvChat *chat = BACKEND_SESSION_TO_PURPLE_CONV_CHAT(backend_session);
	PurpleConversation *new;

	/**
	 * As the chat is marked as "left", serv_got_joined_chat() will
	 * do a "rejoin cleanup" and return the same conversation.
	 */
	new = serv_got_joined_chat(purple_private->gc,
				   purple_conv_chat_get_id(chat),
				   title);
	SIPE_DEBUG_INFO("sipe_backend_chat_rejoin: old %p (%p) == new %p (%p)",
			backend_session, chat,
			new, PURPLE_CONV_CHAT(new));
	purple_conv_chat_set_nick(chat, nick);
}

/**
 * Connection re-established: tell core what chats need to be rejoined
 */
void sipe_backend_chat_rejoin_all(struct sipe_core_public *sipe_public)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	GList *entry = purple_private->rejoin_chats;

	while (entry) {
		sipe_core_chat_rejoin(sipe_public, entry->data);
		entry = entry->next;
	}
	sipe_purple_chat_destroy_rejoin(purple_private);
}

void sipe_backend_chat_remove(struct sipe_backend_chat_session *backend_session,
			      const gchar *uri)
{
	purple_conv_chat_remove_user(BACKEND_SESSION_TO_PURPLE_CONV_CHAT(backend_session),
				     uri,
				     NULL /* reason */);
}

void sipe_backend_chat_show(struct sipe_backend_chat_session *backend_session)
{
	/* Bring existing purple chat to the front */
	/* @TODO: This seems to the trick, but is it the correct way? */
	purple_conversation_update((PurpleConversation *) backend_session,
				   PURPLE_CONV_UPDATE_TOPIC);
}

void sipe_backend_chat_topic(struct sipe_backend_chat_session *backend_session,
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
