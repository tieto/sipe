/**
 * @file purple-private.h
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

/* Forward declarations */
struct sipe_core_public;
struct _PurpleAccount;
struct _PurpleConnection;
struct _PurpleRoomlist;
struct _PurpleSrvQueryData;
struct _PurpleXfer;

struct sipe_backend_private {
	struct sipe_core_public *public;
	struct _PurpleConnection *gc;
	struct _PurpleAccount *account;
	struct _PurpleSrvQueryData *dns_query;
	time_t last_keepalive;
};

/**
 * Initiates outgoing file transfer, sending @c file to remote peer identified
 * by @c who.
 *
 * @param gc   a PurpleConnection
 * @param who  string identifying receiver of the file
 * @param file local file system path of the file to send
 */
void sipe_ft_send_file(struct _PurpleConnection *gc,
		       const char *who,
		       const char *file);

/**
 * Creates new PurpleXfer structure representing a file transfer.
 *
 * @param gc  a PurpleConnection
 * @param who remote participant in the file transfer session
 */
struct _PurpleXfer *sipe_ft_new_xfer(struct _PurpleConnection *gc,
				     const char *who);

/* libpurple chat room callbacks */
GList *sipe_chat_info(struct _PurpleConnection *gc);
void sipe_join_chat(struct _PurpleConnection *gc, GHashTable *data);
struct _PurpleRoomlist *sipe_roomlist_get_list(struct _PurpleConnection *gc);
void sipe_roomlist_cancel(struct _PurpleRoomlist *list);

/* Convenience macros */
#define PURPLE_ACCOUNT_TO_SIPE_CORE_PUBLIC ((struct sipe_core_public *) account->gc->proto_data)
#define PURPLE_GC_TO_SIPE_CORE_PUBLIC      ((struct sipe_core_public *) gc->proto_data)

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
