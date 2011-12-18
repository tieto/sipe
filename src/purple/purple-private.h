/**
 * @file purple-private.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-11 SIPE Project <http://sipe.sourceforge.net/>
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
struct sipe_core_public;
struct _PurpleAccount;
struct _PurpleBuddy;
struct _PurpleChat;
struct _PurpleConnection;
struct _PurpleGroup;
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
	GHashTable *roomlist_map; /* name -> uri */
	GList *rejoin_chats;
	time_t last_keepalive;
};

struct sipe_backend_fd {
	int fd;
};

/* Status attributes */
#define SIPE_PURPLE_STATUS_ATTR_ID_MESSAGE "message"

const gchar *sipe_purple_activity_to_token(guint type);
guint sipe_purple_token_to_activity(const gchar *token);

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

void sipe_purple_chat_setup_rejoin(struct sipe_backend_private *purple_private);
void sipe_purple_chat_destroy_rejoin(struct sipe_backend_private *purple_private);
void sipe_purple_chat_invite(struct _PurpleConnection *gc,
			     int id,
			     const char *message,
			     const char *name);
void sipe_purple_chat_leave(struct _PurpleConnection *gc, int id);
int sipe_purple_chat_send(struct _PurpleConnection *gc,
			  int id,
			  const char *what,
			  _PurpleMessageFlags flags);
GList *sipe_purple_chat_menu(struct _PurpleChat *chat);

/* libpurple chat room callbacks */
GList *sipe_purple_chat_info(struct _PurpleConnection *gc);
GHashTable *sipe_purple_chat_info_defaults(struct _PurpleConnection *gc,
					   const char *chat_name);
void sipe_purple_chat_join(struct _PurpleConnection *gc, GHashTable *data);
struct _PurpleRoomlist *sipe_purple_roomlist_get_list(struct _PurpleConnection *gc);
void sipe_purple_roomlist_cancel(struct _PurpleRoomlist *list);

/* libpurple buddy callbacks */
void sipe_purple_add_buddy(struct _PurpleConnection *gc,
			   struct _PurpleBuddy *buddy,
			   struct _PurpleGroup *group);
void sipe_purple_remove_buddy(struct _PurpleConnection *gc,
			      struct _PurpleBuddy *buddy,
			      struct _PurpleGroup *group);
void sipe_purple_group_buddy(struct _PurpleConnection *gc,
			     const char *who,
			     const char *old_group_name,
			     const char *new_group_name);
GList *sipe_purple_buddy_menu(struct _PurpleBuddy *buddy);

/* libpurple status callbacks */
void sipe_purple_set_status(struct _PurpleAccount *account,
			    struct _PurpleStatus *status);
void sipe_purple_set_idle(struct _PurpleConnection *gc,
			  int interval);

/* Convenience macros */
#define PURPLE_ACCOUNT_TO_SIPE_CORE_PUBLIC ((struct sipe_core_public *) account->gc->proto_data)
#define PURPLE_BUDDY_TO_SIPE_CORE_PUBLIC   ((struct sipe_core_public *) buddy->account->gc->proto_data)
#define PURPLE_GC_TO_SIPE_CORE_PUBLIC      ((struct sipe_core_public *) gc->proto_data)

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
