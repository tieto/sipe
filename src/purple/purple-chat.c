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

#include "sipe-backend.h"
#include "sipe-core.h"

#include "purple-private.h"

#define BACKEND_SESSION_TO_PURPLE_CONV_CHAT(s) \
	(PURPLE_CONV_CHAT(((PurpleConversation *)s)))

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
						      int id,
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
			       int id,
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
