/**
 * @file purple-groupchat.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include "sipe-common.h"

#include "conversation.h"
#include "roomlist.h"

#include "version.h"
#if PURPLE_VERSION_CHECK(3,0,0)
#include "conversations.h"
#else
#define purple_roomlist_get_account(r) r->account
#endif

#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-nls.h"

#include "purple-private.h"

GList *sipe_purple_chat_info(SIPE_UNUSED_PARAMETER PurpleConnection *gc)
{
	GList *m = NULL;

#if PURPLE_VERSION_CHECK(3,0,0)
	PurpleProtocolChatEntry *pce = g_new0(PurpleProtocolChatEntry, 1);
#else
	struct proto_chat_entry *pce = g_new0(struct proto_chat_entry, 1);
#endif
	pce->label = _("_URI:");
	pce->identifier = "uri";
	pce->required = TRUE;
	m = g_list_append(m, pce);

	return m;
}

/**
 * This callback is called for two reasons:
 *
 *  a) generate the defaults for the "Add chat..." dialog initiated from the
 *     roomlist (applies only to group chat)
 *  b) generate the components for the creation of a PurpleChat object
 *
 */
GHashTable *sipe_purple_chat_info_defaults(PurpleConnection *gc,
					   const char *chat_name)
{
	GHashTable *defaults = g_hash_table_new(g_str_hash, g_str_equal);

	if (chat_name != NULL) {
		struct sipe_core_public *sipe_public = PURPLE_GC_TO_SIPE_CORE_PUBLIC;
		struct sipe_backend_private *purple_private = sipe_public->backend_private;
		GHashTable *uri_map = purple_private->roomlist_map;
		const gchar *uri = uri_map != NULL ?
			g_hash_table_lookup(uri_map, chat_name) :
			NULL;
#if PURPLE_VERSION_CHECK(3,0,0)
		PurpleChatConversation *conv = purple_conversations_find_chat_with_account(
#else
		PurpleConversation *conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_CHAT,
#endif
										 chat_name,
										 purple_private->account);
		/* Group Chat rooms have a valid URI */
		if (uri) {
			g_hash_table_insert(defaults, "uri", (gpointer)uri);
		}

		/**
		 * Remember the PurpleConversation
		 *
		 * libpurple API is so brain-dead that we don't receive this
		 * information when it is known and we need it. Make our life
		 * easier by remembering it here for later lookup....
		 */
		if (conv) {
			g_hash_table_insert(defaults,
					    SIPE_PURPLE_COMPONENT_KEY_CONVERSATION,
					    conv);
		}
	}

	return defaults;
}

void sipe_purple_chat_join(PurpleConnection *gc, GHashTable *data)
{
	struct sipe_core_public *sipe_public = PURPLE_GC_TO_SIPE_CORE_PUBLIC;
	const gchar *uri = g_hash_table_lookup(data, "uri");

	if (uri) {
		SIPE_DEBUG_INFO("sipe_purple_chat_join: uri '%s'", uri);
		sipe_core_groupchat_join(sipe_public, uri);
	}
}

static void clear_roomlist(struct sipe_backend_private *purple_private)
{
#if PURPLE_VERSION_CHECK(3,0,0)
	g_object_unref(purple_private->roomlist);
#else
	purple_roomlist_unref(purple_private->roomlist);
#endif
	purple_private->roomlist = NULL;
}

PurpleRoomlist *sipe_purple_roomlist_get_list(PurpleConnection *gc)
{
	struct sipe_core_public *sipe_public = PURPLE_GC_TO_SIPE_CORE_PUBLIC;
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleAccount *account = purple_private->account;
	PurpleRoomlist *roomlist;
	GList *fields = NULL;
	PurpleRoomlistField *f;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_purple_roomlist_get_list");

	if (purple_private->roomlist)
		clear_roomlist(purple_private);
	if (purple_private->roomlist_map)
		g_hash_table_destroy(purple_private->roomlist_map);

	purple_private->roomlist = roomlist = purple_roomlist_new(account);
	purple_private->roomlist_map = g_hash_table_new_full(g_str_hash,
							     g_str_equal,
							     g_free, g_free);

	/* The order needs to be kept in-sync with sipe_backend_groupchat_room_add() */
	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING,
				      "", "uri", TRUE);
	fields = g_list_append(fields, f);
	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_INT,
				      _("Users"), "users", FALSE);
	fields = g_list_append(fields, f);
	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_BOOL,
				      _("Invite"), "invite", FALSE);
	fields = g_list_append(fields, f);
	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_BOOL,
				      _("Private"), "private", FALSE);
	fields = g_list_append(fields, f);
	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_BOOL,
				      _("Log"), "logged", FALSE);
	fields = g_list_append(fields, f);
	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING,
				      _("Description"), "description", FALSE);
	fields = g_list_append(fields, f);

	purple_roomlist_set_fields(roomlist, fields);
	purple_roomlist_set_in_progress(roomlist, TRUE);

	if (!sipe_core_groupchat_query_rooms(sipe_public)) {
		sipe_purple_roomlist_cancel(roomlist);
		roomlist = NULL;
	}

	return roomlist;
}

void sipe_purple_roomlist_cancel(PurpleRoomlist *roomlist)
{
	PurpleAccount *account = purple_roomlist_get_account(roomlist);
	struct sipe_core_public *sipe_public = PURPLE_ACCOUNT_TO_SIPE_CORE_PUBLIC;
	struct sipe_backend_private *purple_private = sipe_public->backend_private;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_purple_roomlist_cancel");

	purple_roomlist_set_in_progress(roomlist, FALSE);

	if (purple_private->roomlist == roomlist)
		clear_roomlist(purple_private);
}

void sipe_backend_groupchat_room_add(struct sipe_core_public *sipe_public,
				     const gchar *uri,
				     const gchar *name,
				     const gchar *description,
				     guint users,
				     guint32 flags)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleRoomlist *roomlist = purple_private->roomlist;
	if (roomlist) {
		PurpleRoomlistRoom *room = purple_roomlist_room_new(PURPLE_ROOMLIST_ROOMTYPE_ROOM,
								    name, NULL);

		/* The order needs to be kept in-sync with sipe_roomlist_get_list() */
		purple_roomlist_room_add_field(roomlist, room,
					       uri);
		purple_roomlist_room_add_field(roomlist, room,
					       GUINT_TO_POINTER(users));
		purple_roomlist_room_add_field(roomlist, room,
					       GUINT_TO_POINTER(flags & SIPE_GROUPCHAT_ROOM_INVITE));
		purple_roomlist_room_add_field(roomlist, room,
					       GUINT_TO_POINTER(flags & SIPE_GROUPCHAT_ROOM_PRIVATE));
		purple_roomlist_room_add_field(roomlist, room,
					       GUINT_TO_POINTER(flags & SIPE_GROUPCHAT_ROOM_LOGGED));
		purple_roomlist_room_add_field(roomlist, room,
					       description);

		/* libpurple API only gives us the channel name */
		g_hash_table_insert(purple_private->roomlist_map,
				    g_strdup(name), g_strdup(uri));

		purple_roomlist_room_add(roomlist, room);
	}
}

void sipe_backend_groupchat_room_terminate(struct sipe_core_public *sipe_public)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleRoomlist *roomlist = purple_private->roomlist;
	if (roomlist) {
		purple_roomlist_set_in_progress(roomlist, FALSE);
		clear_roomlist(purple_private);
	}
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
