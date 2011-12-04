/**
 * @file core-depurple.h
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

/*
 * This is a temporary file for the core de-purple transition period
 */
struct sipe_core_public;

GList *sipe_buddy_menu(PurpleBuddy *buddy);
void sipe_purple_setup(struct sipe_core_public *sipe_public,
		       PurpleConnection *gc);
void sipe_get_info(PurpleConnection *gc, const char *username);
void sipe_convo_closed(PurpleConnection *gc, const char *who);

/* Convenience macros */
#define PURPLE_ACCOUNT_TO_SIPE_CORE_PRIVATE ((struct sipe_core_private *)account->gc->proto_data)
#define PURPLE_BUDDY_TO_SIPE_CORE_PRIVATE   ((struct sipe_core_private *)buddy->account->gc->proto_data)
#define PURPLE_GC_TO_SIPE_CORE_PRIVATE      ((struct sipe_core_private *)gc->proto_data)
#define PURPLE_GC_TO_SIPE_CORE_PUBLIC       ((struct sipe_core_public *) gc->proto_data)

