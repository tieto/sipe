/**
 * @file core-depurple.h
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

/*
 * This is a temporary file for the core de-purple transition period
 */
struct sipe_core_public;

void sipe_search_contact_with_cb(PurpleConnection *gc,
				 PurpleRequestFields *fields);
GList *sipe_buddy_menu(PurpleBuddy *buddy);
GList *sipe_chat_menu(PurpleChat *chat);
void sipe_purple_setup(struct sipe_core_public *sipe_public,
		       PurpleConnection *gc);
int sipe_im_send(PurpleConnection *gc, const char *who, const char *what,
		 PurpleMessageFlags flags);
void sipe_get_info(PurpleConnection *gc, const char *username);
void sipe_set_status(PurpleAccount *account, PurpleStatus *status);
void sipe_set_idle(PurpleConnection *gc, int interval);
void sipe_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy,
		    PurpleGroup *group);
void sipe_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy,
		       PurpleGroup *group);
void sipe_chat_leave(PurpleConnection *gc, int id);
int sipe_chat_send(PurpleConnection *gc, int id, const char *what,
		   PurpleMessageFlags flags);
void sipe_group_buddy(PurpleConnection *gc, const char *who,
		      const char *old_group_name,
		      const char *new_group_name);
void sipe_rename_group(PurpleConnection *gc, const char *old_name,
		       PurpleGroup *group, GList *moved_buddies);
void sipe_convo_closed(PurpleConnection *gc, const char *who);
void sipe_remove_group(PurpleConnection *gc, PurpleGroup *group);

/* Convenience macros */
#define PURPLE_ACCOUNT_TO_SIPE_CORE_PRIVATE ((struct sipe_core_private *)account->gc->proto_data)
#define PURPLE_BUDDY_TO_SIPE_CORE_PRIVATE   ((struct sipe_core_private *)buddy->account->gc->proto_data)
#define PURPLE_CHAT_TO_SIPE_CORE_PRIVATE    ((struct sipe_core_private *)chat->account->gc->proto_data)
#define PURPLE_GC_TO_SIPE_CORE_PRIVATE      ((struct sipe_core_private *)gc->proto_data)
