/**
 * @file purple-private.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2017 SIPE Project <http://sipe.sourceforge.net/>
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

#define SIPE_PURPLE_PLUGIN_ID "prpl-sipe"
#define SIPE_PURPLE_PLUGIN_NAME "Office Communicator"

#define SIPE_PURPLE_PLUGIN_SUMMARY \
	"Microsoft Office Communicator Protocol Plugin"

#define SIPE_PURPLE_PLUGIN_DESCRIPTION \
	"A plugin for the extended SIP/SIMPLE protocol used by " \
	"Microsoft Live/Office Communications/Lync Server (LCS2005/OCS2007+)"

#define SIPE_PURPLE_PLUGIN_AUTHORS \
	"Stefan Becker <chemobejk@gmail.com>, " \
	"Jakub Adam <jakub.adam@ktknet.cz>, " \
	"Anibal Avelar <avelar@gmail.com> (retired), " \
	"pier11 <pier11@operamail.com> (retired), " \
	"Gabriel Burt <gburt@novell.com> (retired)"

#define SIPE_PURPLE_PROTOCOL_OPTIONS OPT_PROTO_CHAT_TOPIC | OPT_PROTO_PASSWORD_OPTIONAL

#if PURPLE_VERSION_CHECK(3,0,0)
#include "conversationtypes.h" /* PurpleIMTypingState */
#include "plugins.h"           /* PurplePlugin */
#else
#include "conversation.h"      /* PurpleTypingState */
#include "plugin.h"            /* PurplePlugin */
#define PurpleIMTypingState PurpleTypingState
#define _PurpleProtocolAction _PurplePluginAction
#endif

/* Forward declarations */
struct sipe_chat_session;
struct sipe_core_public;
struct _PurpleAccount;
struct _PurpleBlistNode;
struct _PurpleBuddy;
struct _PurpleChat;
struct _PurpleConnection;
struct _PurpleConversation;
struct _PurpleGroup;
struct _PurpleMessage;
struct _PurpleNotifyUserInfo;
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
void sipe_purple_show_find_contact(struct _PurpleProtocolAction *action);

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
#define PURPLE_ACCOUNT_TO_SIPE_CORE_PUBLIC ((struct sipe_core_public *) purple_connection_get_protocol_data(purple_account_get_connection(account)))
#define PURPLE_BUDDY_TO_SIPE_CORE_PUBLIC   ((struct sipe_core_public *) purple_connection_get_protocol_data(purple_account_get_connection(purple_buddy_get_account(buddy))))
#define PURPLE_GC_TO_SIPE_CORE_PUBLIC      ((struct sipe_core_public *) purple_connection_get_protocol_data(gc))

/* Protocol common functions */

gboolean sipe_purple_plugin_load(PurplePlugin *plugin);
gboolean sipe_purple_plugin_unload(PurplePlugin *plugin);

gpointer sipe_purple_user_split(void);
GList *sipe_purple_account_options(void);

void sipe_purple_republish_calendar(struct _PurpleAccount *account);
void sipe_purple_reset_status(struct _PurpleAccount *account);

GList *sipe_purple_actions(void);
gchar *sipe_purple_status_text(struct _PurpleBuddy *buddy);
void sipe_purple_tooltip_text(struct _PurpleBuddy *buddy,
			      struct _PurpleNotifyUserInfo *user_info,
			      gboolean full);
GList *sipe_purple_blist_node_menu(struct _PurpleBlistNode *node);
void sipe_purple_convo_closed(struct _PurpleConnection *gc, const char *who);
GHashTable *sipe_purple_get_account_text_table(struct _PurpleAccount *account);

void sipe_purple_login(struct _PurpleAccount *account);
void sipe_purple_close(struct _PurpleConnection *gc);
GList *sipe_purple_status_types(struct _PurpleAccount *account);
const char *sipe_purple_list_icon(struct _PurpleAccount *account,
				  struct _PurpleBuddy *buddy);

void sipe_purple_get_info(struct _PurpleConnection *gc, const char *who);
void sipe_purple_alias_buddy(struct _PurpleConnection *gc, const char *name,
			     const char *alias);
void sipe_purple_group_rename(struct _PurpleConnection *gc, const char *old_name,
			      struct _PurpleGroup *group, GList *moved_buddies);
void sipe_purple_group_remove(struct _PurpleConnection *gc,
			      struct _PurpleGroup *group);

unsigned int sipe_purple_send_typing(struct _PurpleConnection *gc,
				     const char *who, PurpleIMTypingState state);

void sipe_purple_add_permit(struct _PurpleConnection *gc, const char *name);
void sipe_purple_add_deny(struct _PurpleConnection *gc, const char *name);

gboolean sipe_purple_initiate_media(struct _PurpleAccount *account,
				    const char *who,
				    PurpleMediaSessionType type);
PurpleMediaCaps sipe_purple_get_media_caps(struct _PurpleAccount *account,
					   const char *who);

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
