/**
 * @file sipe-chat.h
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

/**
 * Returns purple's chat name for provided chat identification in protocol.
 * Stores newly created chat title if not yet exist.
 *
 * @param proto_chat_id for 2007 conference this is (gchar *) Focus URI,
 *                      for 2005 multiparty chat this is (gchar *) Call-Id of the conversation.
 *
 * @return chat name. Must be g_free()'d after use
 */
gchar *
sipe_chat_get_name(const gchar *proto_chat_id);

/**
 * Returns protocol id for provided purple's chat name
 *
 * @param chat_name chat name
 *
 * @return protocol id
 */
const gchar *
sipe_chat_find_name(const gchar *chat_name);
