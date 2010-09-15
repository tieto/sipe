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

	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING,
				      "", "uri", TRUE);
	fields = g_list_append(fields, f);
	f = purple_roomlist_field_new(PURPLE_ROOMLIST_FIELD_STRING,
				      _("Description"), "description", FALSE);
	fields = g_list_append(fields, f);

	purple_roomlist_set_fields(roomlist, fields);
	purple_roomlist_set_in_progress(roomlist, TRUE);

	/* TBA: sipe_core_groupchat_get_roomlist(....) */

	return roomlist;
}

void sipe_roomlist_cancel(PurpleRoomlist *list)
{
	PurpleAccount *account = list->account;
	struct sipe_core_public *sipe_public = PURPLE_ACCOUNT_TO_SIPE_CORE_PUBLIC;
	struct sipe_backend_private *purple_private = sipe_public->backend_private;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_roomlist_get_cancel");

	purple_roomlist_set_in_progress(list, FALSE);

	if (purple_private->roomlist == list) {
		purple_private->roomlist = NULL;
		purple_roomlist_unref(list);
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
