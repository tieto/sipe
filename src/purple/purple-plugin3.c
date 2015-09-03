/**
 * @file purple-plugin3.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2015 SIPE Project <http://sipe.sourceforge.net/>
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
#include <gmodule.h>

/* Flag needed for correct version of PURPLE_INIT_PLUGIN() */
#ifndef PURPLE_PLUGINS
#define PURPLE_PLUGINS
#endif

#include "protocol.h"

#include "purple-private.h"
#include "sipe-common.h"
#include "sipe-core.h"

#define SIPE_TYPE_PROTOCOL (sipe_protocol_get_type())

typedef struct _SipeProtocol {
	PurpleProtocol parent;
} SipeProtocol;

typedef struct _NullProtocolClass {
	PurpleProtocolClass parent_class;
} SipeProtocolClass;

G_MODULE_EXPORT GType sipe_protocol_get_type(void);

static void
sipe_protocol_class_init(PurpleProtocolClass *klass)
{
	klass->login = sipe_purple_login;
	klass->close = sipe_purple_close;
	klass->status_types = sipe_purple_status_types;
	klass->list_icon = sipe_purple_list_icon;
}

static void
sipe_protocol_init(PurpleProtocol *protocol)
{
	sipe_core_init(LOCALEDIR);

	protocol->id = SIPE_PURPLE_PLUGIN_ID;
	protocol->name = SIPE_PURPLE_PLUGIN_NAME;
	protocol->options = SIPE_PURPLE_PROTOCOL_OPTIONS;
	protocol->user_splits = g_list_append(NULL, sipe_purple_user_split());
	protocol->account_options = sipe_purple_account_options();
}

static GList *
get_actions(SIPE_UNUSED_PARAMETER PurpleConnection *gc)
{
	return sipe_purple_actions();
}

static void
sipe_protocol_client_iface_init(PurpleProtocolClientIface *client_iface)
{
	client_iface->get_actions = get_actions;
	client_iface->status_text = sipe_purple_status_text;
	client_iface->tooltip_text = sipe_purple_tooltip_text;
	client_iface->blist_node_menu = sipe_purple_blist_node_menu;
	client_iface->convo_closed = sipe_purple_convo_closed;
	client_iface->normalize = purple_normalize_nocase;
	client_iface->get_account_text_table = sipe_purple_get_account_text_table;
}

static void
sipe_protocol_server_iface_init(PurpleProtocolServerIface *server_iface)
{
	server_iface->get_info = sipe_purple_get_info;
	server_iface->set_status = sipe_purple_set_status;
	server_iface->set_idle = sipe_purple_set_idle;
	server_iface->add_buddy = sipe_purple_add_buddy;
	server_iface->remove_buddy = sipe_purple_remove_buddy;
	server_iface->alias_buddy = sipe_purple_alias_buddy;
	server_iface->group_buddy = sipe_purple_group_buddy;
	server_iface->rename_group = sipe_purple_group_rename;
	server_iface->remove_group = sipe_purple_group_remove;
}

static int
send_im(PurpleConnection *gc, PurpleMessage *msg)
{
	sipe_core_im_send(PURPLE_GC_TO_SIPE_CORE_PUBLIC,
			  purple_message_get_recipient(msg),
			  purple_message_get_contents(msg));
	return 1;
}

static void
sipe_protocol_im_iface_init(PurpleProtocolIMIface *im_iface)
{
	im_iface->send = send_im;
	im_iface->send_typing = sipe_purple_send_typing;
}

static void
sipe_protocol_chat_iface_init(PurpleProtocolChatIface *chat_iface)
{
	chat_iface->info = sipe_purple_chat_info;
	chat_iface->info_defaults = sipe_purple_chat_info_defaults;
	chat_iface->join = sipe_purple_chat_join;
	chat_iface->invite = sipe_purple_chat_invite;
	chat_iface->leave = sipe_purple_chat_leave;
	chat_iface->send = sipe_purple_chat_send;
}

static void
sipe_protocol_privacy_iface_init(PurpleProtocolPrivacyIface *privacy_iface)
{
	privacy_iface->add_permit = sipe_purple_add_permit;
	privacy_iface->add_deny = sipe_purple_add_deny;
	privacy_iface->rem_permit = sipe_purple_add_deny;
	privacy_iface->rem_deny = sipe_purple_add_permit;
}

static void
sipe_protocol_xfer_iface_init(PurpleProtocolXferIface *xfer_iface)
{
	xfer_iface->send = sipe_purple_ft_send_file;
	xfer_iface->new_xfer = sipe_purple_ft_new_xfer;
}

static void
sipe_protocol_roomlist_iface_init(PurpleProtocolRoomlistIface *roomlist_iface)
{
	roomlist_iface->get_list = sipe_purple_roomlist_get_list;
	roomlist_iface->cancel = sipe_purple_roomlist_cancel;
}

static void
sipe_protocol_media_iface_init(PurpleProtocolMediaIface *media_iface)
{
	media_iface->initiate_session = sipe_purple_initiate_media;
	media_iface->get_caps = sipe_purple_get_media_caps;
}

PURPLE_DEFINE_TYPE_EXTENDED(
	SipeProtocol, sipe_protocol, PURPLE_TYPE_PROTOCOL, 0,

	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CLIENT_IFACE,
					  sipe_protocol_client_iface_init)
	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_SERVER_IFACE,
					  sipe_protocol_server_iface_init)
	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_IM_IFACE,
					  sipe_protocol_im_iface_init)
	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_CHAT_IFACE,
					  sipe_protocol_chat_iface_init)
	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_PRIVACY_IFACE,
					  sipe_protocol_privacy_iface_init)
	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_XFER_IFACE,
					  sipe_protocol_xfer_iface_init)
	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_ROOMLIST_IFACE,
					  sipe_protocol_roomlist_iface_init)
	PURPLE_IMPLEMENT_INTERFACE_STATIC(PURPLE_TYPE_PROTOCOL_MEDIA_IFACE,
					  sipe_protocol_media_iface_init)
)

static PurplePluginInfo *
plugin_query(SIPE_UNUSED_PARAMETER GError **error)
{
	gchar ** authors = g_strsplit(SIPE_PURPLE_PLUGIN_AUTHORS, ", ", -1);
	PurplePluginInfo *info = purple_plugin_info_new(
			"id", SIPE_PURPLE_PLUGIN_ID,
			"name", SIPE_PURPLE_PLUGIN_NAME,
			"version", PACKAGE_VERSION,
			"category", "Protocol",
			"summary", SIPE_PURPLE_PLUGIN_SUMMARY,
			"description", SIPE_PURPLE_PLUGIN_DESCRIPTION,
			"authors", authors,
			"website", PACKAGE_URL,
			"abi-version", PURPLE_ABI_VERSION,
			"flags", PURPLE_PLUGIN_INFO_FLAGS_AUTO_LOAD,
			NULL);

	g_strfreev(authors);

	return info;
}

static PurpleProtocol *sipe_protocol = NULL;

static gboolean
plugin_load(PurplePlugin *plugin, GError **error)
{
	sipe_protocol_register_type(plugin);

	sipe_protocol = purple_protocols_add(SIPE_TYPE_PROTOCOL, error);
	if (!sipe_protocol) {
		return FALSE;
	}

	if (!sipe_purple_plugin_load(plugin)) {
		return FALSE;
	}

	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin, GError **error)
{
	sipe_purple_plugin_unload(plugin);

	if (!purple_protocols_remove(sipe_protocol, error)) {
		return FALSE;
	}

	return TRUE;
}

PURPLE_PLUGIN_INIT(sipe, plugin_query, plugin_load, plugin_unload);

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
