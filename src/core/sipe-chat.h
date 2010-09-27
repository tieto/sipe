/**
 * @file sipe-chat.h
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

/* Forward declarations */
struct sipe_core_private;
struct sip_session;
struct sipe_backend_chat_session;

struct sipe_chat_session {
	struct sipe_backend_chat_session *backend;
	struct sip_session *session;
	gchar *id;
	gchar *title;
	gboolean is_groupchat;
};

/**
 * Create a new chat session
 *
 * @param session
 */
struct sipe_chat_session *
sipe_chat_create_session(const gchar *id, const gchar *title);

/**
 * Remove a chat session
 *
 * @param session
 */
void
sipe_chat_remove_session(struct sipe_chat_session *session);

/**
 * Release resources on unload
 */
void
sipe_chat_destroy(void);

/**
 * Returns purple's chat name for provided chat identification in protocol.
 * Stores newly created chat title if not yet exist.
 *
 * @param proto_chat_id for 2007 conference this is (gchar *) Focus URI,
 *                      for 2005 multiparty chat this is (gchar *) Call-Id of the conversation.
 *
 * @return chat name. Must be g_free()'d after use
 */
gchar *
sipe_chat_get_name(const gchar *proto_chat_id);

/**
 * Returns protocol id for provided purple's chat name
 *
 * @param chat_name chat name
 *
 * @return protocol id
 */
const gchar *
sipe_chat_find_name(const gchar *chat_name);

/**
 * 
 *
 * @param sipe_private SIPE core private data
 * @param session SIPE session for chat
 */
void
sipe_process_pending_invite_queue(struct sipe_core_private *sipe_private,
				  struct sip_session *session);

/**
 * Invite @who to chat
 *
 * @param sipe_private SIPE core private data
 * @param session SIPE session for chat
 * @param who URI whom to invite to chat.
 */
void
sipe_invite_to_chat(struct sipe_core_private *sipe_private,
		    struct sip_session *session,
		    const gchar *who);
