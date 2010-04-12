/**
 * @file sipe-chat.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>

#include <glib.h>

#include "sipe-backend.h"
#include "sipe-chat.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-nls.h"
#include "sipe-session.h"
#include "sipe-utils.h"
#include "sipe.h"

void sipe_core_chat_create(struct sipe_core_public *sipe_public, int id,
			   const char *name)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA;
	struct sip_session *session = sipe_session_find_chat_by_id(sip, id);

	if (session) {
		gchar *uri = sip_uri(name);
		sipe_invite_to_chat(sip, session, uri);
		g_free(uri);
	}
}

/** See below. Same as chat_names but swapped key with values */
static GHashTable *chat_names_inverse = NULL;

gchar *
sipe_chat_get_name(const gchar *proto_chat_id)
{
	/**
	 * A non-volatile mapping of protocol's chat identification
	 * to purple's chat-name. The latter is very important to
	 * find/rejoin chat.
	 *
	 * @key for 2007 conference this is (gchar *) Focus URI
	 *      for 2005 multiparty chat this is (gchar *) Call-Id of the conversation.
	 * @value a purple chat name.
	 */
	static GHashTable *chat_names = NULL;

	/**
	 * A non-volatile chat counter.
	 * Should survive protocol reload.
	 */
	static int chat_seq = 0;

	char *chat_name = NULL;

	if (!chat_names) {
		chat_names = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	}
	if (!chat_names_inverse) {
		chat_names_inverse = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	}

	if (proto_chat_id) {
		chat_name = g_hash_table_lookup(chat_names, proto_chat_id);
		SIPE_DEBUG_INFO("sipe_chat_get_name: lookup results: %s", chat_name ? chat_name : "NULL");
	}
	if (!chat_name) {
		chat_name = g_strdup_printf(_("Chat #%d"), ++chat_seq);
		g_hash_table_insert(chat_names, g_strdup(proto_chat_id), chat_name);
		g_hash_table_insert(chat_names_inverse,  chat_name, g_strdup(proto_chat_id));
		SIPE_DEBUG_INFO("sipe_chat_get_name: added new: %s", chat_name);
	}

	return g_strdup(chat_name);
}

const gchar *
sipe_chat_find_name(const gchar *chat_name)
{
	if (!chat_names_inverse) return NULL;
	return(g_hash_table_lookup(chat_names_inverse, chat_name));
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
