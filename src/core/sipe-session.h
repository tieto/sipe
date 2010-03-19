/**
 * @file sipe-sesion.h
 *
 * pidgin-sipe
 *
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

/*
 * Interface dependencies:
 *
 * <glib.h>
 */

/* Forward declarations */
struct sipe_account_data;
struct _PurpleConversation;

/* Helper macros to iterate over session list in a SIP account */
#define SIPE_SESSION_FOREACH {                             \
	GSList *entry = sip->sessions;                    \
	while (entry) {                                    \
		struct sip_session *session = entry->data; \
		entry = entry->next;
#define SIPE_SESSION_FOREACH_END }}

/** Correspond to multi-party conversation */
struct sip_session {
	gchar *with; /* For IM sessions only (not multi-party) . A URI.*/
	/** key is user (URI) */
	GSList *dialogs;
	/** Link to purple chat or IM */
	struct _PurpleConversation *conv;
	GSList *outgoing_message_queue;
	/** Key is <Call-ID><CSeq><METHOD><To> */
	GHashTable *unconfirmed_messages;
	
	/*
	 * Multiparty conversation related fields
	 */
	gboolean is_multiparty;
	/** purple chat id */
	int chat_id;
	/** purple indexes chats by names */
	//gchar *chat_name;
	/** Human readable chat name */
	gchar *chat_title;
	/** Call-Id identifying the conversation */
	gchar *callid; /* For multiparty conversations */
	/** Roster Manager URI */
	gchar *roster_manager;
	int bid;
	gboolean is_voting_in_progress;
	GSList *pending_invite_queue;
	
	/*
	 * Conference related fields
	 */
	gchar *focus_uri;
	gchar *im_mcu_uri;
	gchar *subject;
	gboolean locked;
	guint request_id;
	struct sip_dialog *focus_dialog;
	/** Key is Message-Id */
	GHashTable *conf_unconfirmed_messages;
};

/**
 * An item in outgoing message queue.
 *
 * Messages are put in the queue until a response to initial INVITE is received
 * from remote dialog participant.
 */
struct queued_message {
	/** Body of the message. */
	gchar *body;
	/**
	 * Content type of message body, e.g. text/plain for chat messages,
	 * text/x-msmsgsinvite for filetransfer initialization. Setting this to NULL
	 * means default value text/plain.
	 */
	gchar *content_type;
};

/** Frees queued_message
 */
void
sipe_free_queued_message(struct queued_message *message);

/**
 * Add a new chat session
 *
 * @param sip (in) SIP account data. May be NULL
 *
 * @return pointer to new session
 */
struct sip_session *
sipe_session_add_chat(struct sipe_account_data *sip);

/**
 * Find chat session by Call ID
 *
 * @param sip (in) SIP account data. May be NULL
 * @param callid (in) Call ID. May be NULL
 *
 * @return pointer to session or NULL
 */
struct sip_session *
sipe_session_find_chat_by_callid(struct sipe_account_data *sip,
				 const gchar *callid);

/**
 * Find or add new chat session by Call ID
 *
 * @param sip (in) SIP account data
 * @param callid (in) Call ID
 *
 * @return pointer to session
 */
struct sip_session *
sipe_session_find_or_add_chat_by_callid(struct sipe_account_data *sip,
					const gchar *callid);

/**
 * Find chat session by ID
 *
 * @param sip (in) SIP account data. May be NULL
 * @param id (in) Chat ID
 *
 * @return pointer to session or NULL
 */
struct sip_session * 
sipe_session_find_chat_by_id(struct sipe_account_data *sip, int id);

/**
 * Find chat session by name
 *
 * @param sip (in) SIP account data. May be NULL
 * @param name (in) Chat name. May be NULL
 *
 * @return pointer to session or NULL
 */
struct sip_session * 
sipe_session_find_chat_by_title(struct sipe_account_data *sip,
			        const gchar *name);

/**
 * Find Conference session
 *
 * @param sip (in) SIP account data. May be NULL
 * @param focus_uri (in) URI of conference focus. May be NULL
 *
 * @return pointer to session or NULL
 */
struct sip_session *
sipe_session_find_conference(struct sipe_account_data *sip,
			     const gchar *focus_uri);

/**
 * Find IM session
 *
 * @param sip (in) SIP account data. May be NULL
 * @param who (in) remote partner. May be NULL
 *
 * @return pointer to session or NULL
 */
struct sip_session *
sipe_session_find_im(struct sipe_account_data *sip, const gchar *who);

/**
 * Find or add new IM session
 *
 * @param sip (in) SIP account data
 * @param who (in) remote partner
 *
 * @return pointer to session
 */
struct sip_session *
sipe_session_find_or_add_im(struct sipe_account_data *sip,
			    const gchar *who);

/**
 * Remove a session from a SIP account
 *
 * @param sip (in) SIP account data
 * @param session (in) pointer to session
 */
void
sipe_session_remove(struct sipe_account_data *sip,
		    struct sip_session *session);

/**
 * Remove all sessions from a SIP account
 *
 * @param sip (in) SIP account data
 */
void
sipe_session_remove_all(struct sipe_account_data *sip);

/**
 * Add a message to outgoing queue.
 *
 * @param session (in) SIP session
 * @param body (in) message to send
 * @param content_type (in) content type of the message body
 */
void
sipe_session_enqueue_message(struct sip_session *session,
			     const gchar *body, const gchar *content_type);

/**
 * Removes and deallocates the first item in outgoing message queue.
 *
 * @param session (in) SIP session
 *
 * @return pointer to new message queue head
 */
GSList *
sipe_session_dequeue_message(struct sip_session *session);
