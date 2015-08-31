/**
 * @file purple-private.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2015 SIPE Project <http://sipe.sourceforge.net/>
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

#include "version.h"

/* Forward declarations */
struct sipe_chat_session;
struct sipe_core_public;
struct _PurpleAccount;
struct _PurpleBuddy;
struct _PurpleChat;
struct _PurpleConnection;
struct _PurpleConversation;
struct _PurpleGroup;
struct _PurpleMessage;
struct _PurplePluginAction;
struct _PurpleRoomlist;
struct _PurpleStatus;
struct _PurpleXfer;

#ifndef _PurpleMessageFlags
#define _PurpleMessageFlags int
#endif

struct sipe_backend_private {
	struct sipe_core_public *public;
	struct _PurpleConnection *gc;
	struct _PurpleAccount *account;
	struct _PurpleRoomlist *roomlist;
	/* see sipe_backend_chat_create() */
	struct sipe_chat_session *adium_chat_session;
	GHashTable *roomlist_map; /* name -> uri */
	GList *rejoin_chats;
	GSList *transports;
	GSList *dns_queries;

	/* work around broken libpurple idle notification */
	gchar *deferred_status_note;
	guint  deferred_status_activity;
	guint  deferred_status_timeout;

	/* flags */
	gboolean status_changed_by_core; /* status changed by core */
	gboolean user_is_not_idle;       /* user came back online */
};

struct sipe_backend_fd {
	int fd;
};

/* Status attributes */
#define SIPE_PURPLE_STATUS_ATTR_ID_MESSAGE "message"

const gchar *sipe_purple_activity_to_token(guint type);
guint sipe_purple_token_to_activity(const gchar *token);

/* DNS queries */
void sipe_purple_dns_query_cancel_all(struct sipe_backend_private *purple_private);

/**
 * Initiates outgoing file transfer, sending @c file to remote peer identified
 * by @c who.
 *
 * @param gc   a PurpleConnection
 * @param who  string identifying receiver of the file
 * @param file local file system path of the file to send
 */
void sipe_purple_ft_send_file(struct _PurpleConnection *gc,
			      const char *who,
			      const char *file);

/**
 * Creates new PurpleXfer structure representing a file transfer.
 *
 * @param gc  a PurpleConnection
 * @param who remote participant in the file transfer session
 */
struct _PurpleXfer *sipe_purple_ft_new_xfer(struct _PurpleConnection *gc,
					    const char *who);

/* libpurple chat callbacks */
#define SIPE_PURPLE_COMPONENT_KEY_CONVERSATION "_conv"

struct sipe_chat_session *sipe_purple_chat_get_session(struct _PurpleConversation *conv);
void sipe_purple_chat_setup_rejoin(struct sipe_backend_private *purple_private);
void sipe_purple_chat_destroy_rejoin(struct sipe_backend_private *purple_private);
void sipe_purple_chat_invite(struct _PurpleConnection *gc,
			     int id,
			     const char *message,
			     const char *name);
void sipe_purple_chat_leave(struct _PurpleConnection *gc, int id);
int sipe_purple_chat_send(struct _PurpleConnection *gc,
			  int id,
#if PURPLE_VERSION_CHECK(3,0,0)
			  struct _PurpleMessage *msg);
#else
			  const char *what,
			  _PurpleMessageFlags flags);
#endif
GList *sipe_purple_chat_menu(struct _PurpleChat *chat);

/* libpurple chat room callbacks */
GList *sipe_purple_chat_info(struct _PurpleConnection *gc);
GHashTable *sipe_purple_chat_info_defaults(struct _PurpleConnection *gc,
					   const char *chat_name);
void sipe_purple_chat_join(struct _PurpleConnection *gc, GHashTable *data);
struct _PurpleRoomlist *sipe_purple_roomlist_get_list(struct _PurpleConnection *gc);
void sipe_purple_roomlist_cancel(struct _PurpleRoomlist *list);

/* libpurple buddy callbacks */
#ifdef PURPLE_VERSION_CHECK
void sipe_purple_add_buddy(struct _PurpleConnection *gc,
			   struct _PurpleBuddy *buddy,
			   struct _PurpleGroup *group
#if PURPLE_VERSION_CHECK(3,0,0)
			   , const gchar *message
#endif
);
#endif
void sipe_purple_remove_buddy(struct _PurpleConnection *gc,
			      struct _PurpleBuddy *buddy,
			      struct _PurpleGroup *group);
void sipe_purple_group_buddy(struct _PurpleConnection *gc,
			     const char *who,
			     const char *old_group_name,
			     const char *new_group_name);
GList *sipe_purple_buddy_menu(struct _PurpleBuddy *buddy);

/* libpurple search callbacks */
void sipe_purple_show_find_contact(struct _PurplePluginAction *action);

/* libpurple status callbacks */
void sipe_purple_set_status(struct _PurpleAccount *account,
			    struct _PurpleStatus *status);
void sipe_purple_set_idle(struct _PurpleConnection *gc,
			  int interval);

/* media */
void capture_pipeline(const gchar *label);

/* transport */
void sipe_purple_transport_close_all(struct sipe_backend_private *purple_private);

/* Convenience macros */
#if PURPLE_VERSION_CHECK(2,6,0) || PURPLE_VERSION_CHECK(3,0,0)
#define PURPLE_ACCOUNT_TO_SIPE_CORE_PUBLIC ((struct sipe_core_public *) purple_connection_get_protocol_data(purple_account_get_connection(account)))
#define PURPLE_BUDDY_TO_SIPE_CORE_PUBLIC   ((struct sipe_core_public *) purple_connection_get_protocol_data(purple_account_get_connection(purple_buddy_get_account(buddy))))
#define PURPLE_GC_TO_SIPE_CORE_PUBLIC      ((struct sipe_core_public *) purple_connection_get_protocol_data(gc))
#else
#define PURPLE_ACCOUNT_TO_SIPE_CORE_PUBLIC ((struct sipe_core_public *) purple_account_get_connection(account)->proto_data)
#define PURPLE_BUDDY_TO_SIPE_CORE_PUBLIC   ((struct sipe_core_public *) purple_account_get_connection(purple_buddy_get_account(buddy))->proto_data)
#define PURPLE_GC_TO_SIPE_CORE_PUBLIC      ((struct sipe_core_public *) gc->proto_data)
#endif

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
