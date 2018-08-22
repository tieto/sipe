/**
 * @file purple-plugin.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include "sipe-common.h"

/* Flag needed for correct version of PURPLE_INIT_PLUGIN() */
#ifndef PURPLE_PLUGINS
#define PURPLE_PLUGINS
#endif

/* for LOCALEDIR
 * as it's determined on runtime, as Pidgin installation can be anywhere.
 */
#ifdef _WIN32
#include "win32/win32dep.h"
#endif

#include "accountopt.h"
#include "prpl.h"

#include "sipe-core.h"

#define _PurpleMessageFlags PurpleMessageFlags
#include "purple-private.h"

static int sipe_purple_send_im(PurpleConnection *gc,
			       const char *who,
			       const char *what,
			       SIPE_UNUSED_PARAMETER PurpleMessageFlags flags)
{
	sipe_core_im_send(PURPLE_GC_TO_SIPE_CORE_PUBLIC, who, what);
	return 1;
}

/*
 * Simplistic source upward compatibility path for newer libpurple APIs
 *
 * Usually we compile with -Werror=missing-field-initializers if GCC supports
 * it. But that means that the compilation of this structure can fail if the
 * newer API has added additional plugin callbacks. For the benefit of the
 * user we downgrade it to a warning here.
 *
 * Diagnostic #pragma was added in GCC 4.2.0
 * Diagnostic push/pop was added in GCC 4.6.0
 */
#ifdef __GNUC__
#if ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 2)) || (__GNUC__ >= 5)
#if ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 6)) || (__GNUC__ >= 5)
#pragma GCC diagnostic push
#endif
#pragma GCC diagnostic warning "-Wmissing-field-initializers"
#endif
#endif
static PurplePluginProtocolInfo sipe_prpl_info =
{
	SIPE_PURPLE_PROTOCOL_OPTIONS,
	NULL,					/* user_splits */
	NULL,					/* protocol_options */
	NO_BUDDY_ICONS,				/* icon_spec */
	sipe_purple_list_icon,			/* list_icon */
	NULL,					/* list_emblems */
	sipe_purple_status_text,		/* status_text */
	sipe_purple_tooltip_text,		/* tooltip_text */	// add custom info to contact tooltip
	sipe_purple_status_types,		/* away_states */
	sipe_purple_blist_node_menu,		/* blist_node_menu */
	sipe_purple_chat_info,			/* chat_info */
	sipe_purple_chat_info_defaults,		/* chat_info_defaults */
	sipe_purple_login,			/* login */
	sipe_purple_close,			/* close */
	sipe_purple_send_im,			/* send_im */
	NULL,					/* set_info */		// TODO maybe
	sipe_purple_send_typing,		/* send_typing */
	sipe_purple_get_info,			/* get_info */
	sipe_purple_set_status,			/* set_status */
	sipe_purple_set_idle,			/* set_idle */
	NULL,					/* change_passwd */
	sipe_purple_add_buddy,			/* add_buddy */
	NULL,					/* add_buddies */
	sipe_purple_remove_buddy,		/* remove_buddy */
	NULL,					/* remove_buddies */
	sipe_purple_add_permit,			/* add_permit */
	sipe_purple_add_deny,			/* add_deny */
	sipe_purple_add_deny,			/* rem_permit */
	sipe_purple_add_permit,			/* rem_deny */
	NULL,					/* set_permit_deny */
	sipe_purple_chat_join,			/* join_chat */
	NULL,					/* reject_chat */
	NULL,					/* get_chat_name */
	sipe_purple_chat_invite,		/* chat_invite */
	sipe_purple_chat_leave,			/* chat_leave */
	NULL,					/* chat_whisper */
	sipe_purple_chat_send,			/* chat_send */
	NULL,					/* keepalive */
	NULL,					/* register_user */
	NULL,					/* get_cb_info */	// deprecated
	NULL,					/* get_cb_away */	// deprecated
	sipe_purple_alias_buddy,		/* alias_buddy */
	sipe_purple_group_buddy,		/* group_buddy */
	sipe_purple_group_rename,		/* rename_group */
	NULL,					/* buddy_free */
	sipe_purple_convo_closed,		/* convo_closed */
	purple_normalize_nocase,		/* normalize */
	NULL,					/* set_buddy_icon */
	sipe_purple_group_remove,		/* remove_group */
	NULL,					/* get_cb_real_name */	// TODO?
	NULL,					/* set_chat_topic */
	NULL,					/* find_blist_chat */
	sipe_purple_roomlist_get_list,		/* roomlist_get_list */
	sipe_purple_roomlist_cancel,		/* roomlist_cancel */
	NULL,					/* roomlist_expand_category */
	NULL,					/* can_receive_file */
	sipe_purple_ft_send_file,		/* send_file */
	NULL,					/* new_xfer */
	NULL,					/* offline_message */
	NULL,					/* whiteboard_prpl_ops */
	NULL,					/* send_raw */
	NULL,					/* roomlist_room_serialize */
	NULL,					/* unregister_user */
	NULL,					/* send_attention */
	NULL,					/* get_attention_types */
	sizeof(PurplePluginProtocolInfo),       /* struct_size */
	sipe_purple_get_account_text_table,	/* get_account_text_table */
#ifdef HAVE_VV
	sipe_purple_initiate_media,		/* initiate_media */
	sipe_purple_get_media_caps,		/* get_media_caps */
#else
	NULL,					/* initiate_media */
	NULL,					/* get_media_caps */
#endif
	NULL,					/* get_moods */
	NULL,					/* set_public_alias */
	NULL,					/* get_public_alias */
#if PURPLE_VERSION_CHECK(2,8,0)
	NULL,					/* add_buddy_with_invite */
	NULL,					/* add_buddies_with_invite */
#endif
#if PURPLE_VERSION_CHECK(2,14,0)
	NULL,					/* get_cb_alias */
#endif
};
#ifdef __GNUC__
#if ((__GNUC__ == 4) && (__GNUC_MINOR__ >= 6)) || (__GNUC__ >= 5)
#pragma GCC diagnostic pop
#endif
#endif
/* Original GCC error checking restored from here on... (see above) */

/* PurplePluginInfo function calls & data structure */
static void sipe_purple_plugin_destroy(SIPE_UNUSED_PARAMETER PurplePlugin *plugin)
{
	GList *entry;

	sipe_core_destroy();

	entry = sipe_prpl_info.protocol_options;
	while (entry) {
		purple_account_option_destroy(entry->data);
		entry = g_list_delete_link(entry, entry);
	}
	sipe_prpl_info.protocol_options = NULL;

	entry = sipe_prpl_info.user_splits;
	while (entry) {
		purple_account_user_split_destroy(entry->data);
		entry = g_list_delete_link(entry, entry);
	}
	sipe_prpl_info.user_splits = NULL;
}

static GList *purple_actions(SIPE_UNUSED_PARAMETER PurplePlugin *plugin,
			     SIPE_UNUSED_PARAMETER gpointer context)
{
	return sipe_purple_actions();
}

static PurplePluginInfo sipe_purple_info = {
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_PROTOCOL,                           /**< type           */
	NULL,                                             /**< ui_requirement */
	0,                                                /**< flags          */
	NULL,                                             /**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,                          /**< priority       */
	SIPE_PURPLE_PLUGIN_ID,                            /**< id             */
	SIPE_PURPLE_PLUGIN_NAME,                          /**< name           */
	PACKAGE_VERSION,                                  /**< version        */
	SIPE_PURPLE_PLUGIN_SUMMARY,                       /**< summary        */
	SIPE_PURPLE_PLUGIN_DESCRIPTION,                   /**< description    */
	SIPE_PURPLE_PLUGIN_AUTHORS,                       /**< authors        */
	PACKAGE_URL,                                      /**< homepage       */
	sipe_purple_plugin_load,                          /**< load           */
	sipe_purple_plugin_unload,                        /**< unload         */
	sipe_purple_plugin_destroy,                       /**< destroy        */
	NULL,                                             /**< ui_info        */
	&sipe_prpl_info,                                  /**< extra_info     */
	NULL,
	purple_actions,
	NULL,
	NULL,
	NULL,
	NULL
};

static void sipe_purple_init_plugin(PurplePlugin *plugin)
{
	/* This needs to be called first */
	sipe_core_init(LOCALEDIR);

	purple_plugin_register(plugin);

	sipe_prpl_info.user_splits = g_list_append(sipe_prpl_info.user_splits,
						   sipe_purple_user_split());

	sipe_prpl_info.protocol_options = sipe_purple_account_options();
}

/* This macro makes the code a purple plugin */
PURPLE_INIT_PLUGIN(sipe, sipe_purple_init_plugin, sipe_purple_info);

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
