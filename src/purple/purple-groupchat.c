/**
 * @file purple-groupchat.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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

#include "roomlist.h"

#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-nls.h"

#include "purple-private.h"

GList *sipe_chat_info(SIPE_UNUSED_PARAMETER PurpleConnection *gc)
{
	GList *m = NULL;
	struct proto_chat_entry *pce;

	pce = g_new0(struct proto_chat_entry, 1);
	pce->label = _("_URI:");
	pce->identifier = "uri";
	pce->required = TRUE;
	m = g_list_append(m, pce);

	return m;
}

void sipe_join_chat(PurpleConnection *gc, GHashTable *data)
{
	(void)gc;
	(void)data;
	SIPE_DEBUG_INFO_NOFORMAT("sipe_join_chat");
}

PurpleRoomlist *sipe_roomlist_get_list(PurpleConnection *gc)
{
	struct sipe_core_public *sipe_public = PURPLE_GC_TO_SIPE_CORE_PUBLIC;
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleAccount *account = purple_private->account;
	PurpleRoomlist *roomlist;
	GList *fields = NULL;
	PurpleRoomlistField *f;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_roomlist_get_list");

	if (purple_private->roomlist)
		purple_roomlist_unref(purple_private->roomlist);

	purple_private->roomlist = roomlist = purple_roomlist_new(account);

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
		sipe_roomlist_cancel(roomlist);
		roomlist = NULL;
	}

	return roomlist;
}

void sipe_roomlist_cancel(PurpleRoomlist *roomlist)
{
	PurpleAccount *account = roomlist->account;
	struct sipe_core_public *sipe_public = PURPLE_ACCOUNT_TO_SIPE_CORE_PUBLIC;
	struct sipe_backend_private *purple_private = sipe_public->backend_private;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_roomlist_get_cancel");

	purple_roomlist_set_in_progress(roomlist, FALSE);

	if (purple_private->roomlist == roomlist) {
		purple_private->roomlist = NULL;
		purple_roomlist_unref(roomlist);
	}
}

void sipe_backend_groupchat_room_add(struct sipe_core_public *sipe_public,
				     const gchar *uri,
				     const gchar *name,
				     const gchar *description,
				     guint users,
				     guint32 flags)
{
	PurpleRoomlist *roomlist = sipe_public->backend_private->roomlist;
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

		purple_roomlist_room_add(roomlist, room);
	}
}

void sipe_backend_groupchat_room_terminate(struct sipe_core_public *sipe_public)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleRoomlist *roomlist = purple_private->roomlist;
	if (roomlist) {
		purple_roomlist_set_in_progress(roomlist, FALSE);
		purple_roomlist_unref(roomlist);
		purple_private->roomlist = NULL;
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
