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

enum sipe_chat_type {
	SIPE_CHAT_TYPE_UNKNOWN = 0,
	SIPE_CHAT_TYPE_MULTIPARTY,
	SIPE_CHAT_TYPE_CONFERENCE,
	SIPE_CHAT_TYPE_GROUPCHAT
};

struct sipe_chat_session {
	struct sipe_backend_chat_session *backend;

	/*
	 * Chat identifier (must be unique per account)
	 *
	 * 2007 Group chat:      channel URI
	 * 2007 Conference:      focus URI
	 * 2005 multiparty chat: roster manager SIP URI
	 */
	gchar *id;

	/* Human readable chat identifier (can have duplicates) */
	gchar *title;

	enum sipe_chat_type type;
};

/**
 * Create a new chat session
 *
 * @param session
 */
struct sipe_chat_session *
sipe_chat_create_session(enum sipe_chat_type type,
			 const gchar *id, const gchar *title);

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
 * Generate a name for a new private chat.
 *
 * @return chat name. Must be g_free()'d after use
 */
gchar *
sipe_chat_get_name(void);

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
 * Set roster manager URI for a multiparty chat
 *
 * @param session SIPE session for chat
 * @param roster_manager New roster manager URI or NULL
 */
void sipe_chat_set_roster_manager(struct sip_session *session,
				  const gchar *roster_manager);
