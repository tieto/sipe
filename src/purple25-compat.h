/**
 * @file purple25-compat.h Compatibility definitions for use with purple < 2.5.x.
 * @ingroup core
 */

/* purple
 *
 * Purple is the legal property of its developers, whose names are too numerous
 * to list here.  Please refer to the COPYRIGHT file distributed with this
 * source distribution.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02111-1301  USA
 */

/* This file is provided to satisfy purple-2.5 plugins dependencies using
 * purple 2.4 headers and libraries. This currently satisfies the needs
 * of pidgin-sipe >= 1.6.1 for Debian 5.0 (Lenny) or Ubuntu 8.04 LTS (Hardy).
 *
 * We make use of the fact that from 2.4 to 2.5
 *
 *   - enum PurpleConnectionFlags has ony been extended by on element
 *   - struct _PurplePluginProtocolInfo has been extended, but all used
 *     fields from 2.4 remained unchanged.
 *
 * A pidgin-2.4 loading our plugin will just ignore the purple-2.5 enhancements,
 * a lated version of pidgin will find and use them just as if the plugin had
 * been built with purple 2.5.
 */

#ifndef _PURPLE25_COMPAT_H_
#define _PURPLE25_COMPAT_H_

#include "prpl.h"

/**
 * Extends PurpleConnectionFlags from libpurple/connection.h
 */

typedef enum
{
        PURPLE_CONNECTION_ALLOW_CUSTOM_SMILEY = 0x0100 /**< Connection supports sending and receiving custom smileys */

} Purple25CompatConnectionFlags;

/**
 * Extends PurplePluginProtocolInfo from libpurple/prpl.h
 */

typedef struct _Purple25CompatPluginProtocolInfo Purple25CompatPluginProtocolInfo;

/**
 * A  purple-2.5.x compatible protocol plugin information structure.
 *
 * Every protocol plugin initializes this structure. It is the gateway
 * between purple and the protocol plugin.  Many of these callbacks can be
 * NULL.  If a callback must be implemented, it has a comment indicating so.
 */
struct _Purple25CompatPluginProtocolInfo
{
	PurpleProtocolOptions options;  /**< Protocol options.          */

	GList *user_splits;      /**< A GList of PurpleAccountUserSplit */
	GList *protocol_options; /**< A GList of PurpleAccountOption    */

	PurpleBuddyIconSpec icon_spec; /**< The icon spec. */

	/**
	 * Returns the base icon name for the given buddy and account.
	 * If buddy is NULL and the account is non-NULL, it will return the 
	 * name to use for the account's icon. If both are NULL, it will
	 * return the name to use for the protocol's icon.
	 *
	 * This must be implemented.
	 */
	const char *(*list_icon)(PurpleAccount *account, PurpleBuddy *buddy);

	/**
	 * Fills the four char**'s with string identifiers for "emblems"
	 * that the UI will interpret and display as relevant
	 */
	const char *(*list_emblem)(PurpleBuddy *buddy);

	/**
	 * Gets a short string representing this buddy's status.  This will
	 * be shown on the buddy list.
	 */
	char *(*status_text)(PurpleBuddy *buddy);

	/**
	 * Allows the prpl to add text to a buddy's tooltip.
	 */
	void (*tooltip_text)(PurpleBuddy *buddy, PurpleNotifyUserInfo *user_info, gboolean full);

	/**
	 * Returns a list of #PurpleStatusType which exist for this account;
	 * this must be implemented, and must add at least the offline and
	 * online states.
	 */
	GList *(*status_types)(PurpleAccount *account);

	/**
	 * Returns a list of #PurpleMenuAction structs, which represent extra
	 * actions to be shown in (for example) the right-click menu for @a
	 * node.
	 */
	GList *(*blist_node_menu)(PurpleBlistNode *node);
	GList *(*chat_info)(PurpleConnection *);
	GHashTable *(*chat_info_defaults)(PurpleConnection *, const char *chat_name);

	/* All the server-related functions */

	/** This must be implemented. */
	void (*login)(PurpleAccount *);

	/** This must be implemented. */
	void (*close)(PurpleConnection *);

	/**
	 * This PRPL function should return a positive value on success.
	 * If the message is too big to be sent, return -E2BIG.  If
	 * the account is not connected, return -ENOTCONN.  If the
	 * PRPL is unable to send the message for another reason, return
	 * some other negative value.  You can use one of the valid
	 * errno values, or just big something.  If the message should
	 * not be echoed to the conversation window, return 0.
	 */
	int  (*send_im)(PurpleConnection *, const char *who,
					const char *message,
					PurpleMessageFlags flags);

	void (*set_info)(PurpleConnection *, const char *info);

	/**
	 * @return If this protocol requires the PURPLE_TYPING message to
	 *         be sent repeatedly to signify that the user is still
	 *         typing, then the PRPL should return the number of
	 *         seconds to wait before sending a subsequent notification.
	 *         Otherwise the PRPL should return 0.
	 */
	unsigned int (*send_typing)(PurpleConnection *, const char *name, PurpleTypingState state);

	/**
	 * Should arrange for purple_notify_userinfo() to be called with
	 * @a who's user info.
	 */
	void (*get_info)(PurpleConnection *, const char *who);
	void (*set_status)(PurpleAccount *account, PurpleStatus *status);

	void (*set_idle)(PurpleConnection *, int idletime);
	void (*change_passwd)(PurpleConnection *, const char *old_pass,
						  const char *new_pass);
	void (*add_buddy)(PurpleConnection *, PurpleBuddy *buddy, PurpleGroup *group);
	void (*add_buddies)(PurpleConnection *, GList *buddies, GList *groups);
	void (*remove_buddy)(PurpleConnection *, PurpleBuddy *buddy, PurpleGroup *group);
	void (*remove_buddies)(PurpleConnection *, GList *buddies, GList *groups);
	void (*add_permit)(PurpleConnection *, const char *name);
	void (*add_deny)(PurpleConnection *, const char *name);
	void (*rem_permit)(PurpleConnection *, const char *name);
	void (*rem_deny)(PurpleConnection *, const char *name);
	void (*set_permit_deny)(PurpleConnection *);
	void (*join_chat)(PurpleConnection *, GHashTable *components);
	void (*reject_chat)(PurpleConnection *, GHashTable *components);
	char *(*get_chat_name)(GHashTable *components);
	void (*chat_invite)(PurpleConnection *, int id,
						const char *message, const char *who);
	void (*chat_leave)(PurpleConnection *, int id);
	void (*chat_whisper)(PurpleConnection *, int id,
						 const char *who, const char *message);
	int  (*chat_send)(PurpleConnection *, int id, const char *message, PurpleMessageFlags flags);

	/** If implemented, this will be called regularly for this prpl's
	 *  active connections.  You'd want to do this if you need to repeatedly
	 *  send some kind of keepalive packet to the server to avoid being
	 *  disconnected.  ("Regularly" is defined by
	 *  <code>KEEPALIVE_INTERVAL</code> in <tt>libpurple/connection.c</tt>.)
	 */
	void (*keepalive)(PurpleConnection *);

	/** new user registration */
	void (*register_user)(PurpleAccount *);

	/**
	 * @deprecated Use #PurplePluginProtocolInfo.get_info instead.
	 */
	void (*get_cb_info)(PurpleConnection *, int, const char *who);
	/**
	 * @deprecated Use #PurplePluginProtocolInfo.get_cb_real_name and
	 *             #PurplePluginProtocolInfo.status_text instead.
	 */
	void (*get_cb_away)(PurpleConnection *, int, const char *who);

	/** save/store buddy's alias on server list/roster */
	void (*alias_buddy)(PurpleConnection *, const char *who,
						const char *alias);

	/** change a buddy's group on a server list/roster */
	void (*group_buddy)(PurpleConnection *, const char *who,
						const char *old_group, const char *new_group);

	/** rename a group on a server list/roster */
	void (*rename_group)(PurpleConnection *, const char *old_name,
						 PurpleGroup *group, GList *moved_buddies);

	void (*buddy_free)(PurpleBuddy *);

	void (*convo_closed)(PurpleConnection *, const char *who);

	/**
	 *  Convert the username @a who to its canonical form.  (For example,
	 *  AIM treats "fOo BaR" and "foobar" as the same user; this function
	 *  should return the same normalized string for both of those.)
	 */
	const char *(*normalize)(const PurpleAccount *, const char *who);

	/**
	 * Set the buddy icon for the given connection to @a img.  The prpl
	 * does NOT own a reference to @a img; if it needs one, it must
	 * #purple_imgstore_ref(@a img) itself.
	 */
	void (*set_buddy_icon)(PurpleConnection *, PurpleStoredImage *img);

	void (*remove_group)(PurpleConnection *gc, PurpleGroup *group);

	/** Gets the real name of a participant in a chat.  For example, on
	 *  XMPP this turns a chat room nick <tt>foo</tt> into
	 *  <tt>room\@server/foo</tt>
	 *  @param gc  the connection on which the room is.
	 *  @param id  the ID of the chat room.
	 *  @param who the nickname of the chat participant.
	 *  @return    the real name of the participant.  This string must be
	 *             freed by the caller.
	 */
	char *(*get_cb_real_name)(PurpleConnection *gc, int id, const char *who);

	void (*set_chat_topic)(PurpleConnection *gc, int id, const char *topic);

	PurpleChat *(*find_blist_chat)(PurpleAccount *account, const char *name);

	/* room listing prpl callbacks */
	PurpleRoomlist *(*roomlist_get_list)(PurpleConnection *gc);
	void (*roomlist_cancel)(PurpleRoomlist *list);
	void (*roomlist_expand_category)(PurpleRoomlist *list, PurpleRoomlistRoom *category);

	/* file transfer callbacks */
	gboolean (*can_receive_file)(PurpleConnection *, const char *who);
	void (*send_file)(PurpleConnection *, const char *who, const char *filename);
	PurpleXfer *(*new_xfer)(PurpleConnection *, const char *who);

	/** Checks whether offline messages to @a buddy are supported.
	 *  @return @c TRUE if @a buddy can be sent messages while they are
	 *          offline, or @c FALSE if not.
	 */
	gboolean (*offline_message)(const PurpleBuddy *buddy);

	PurpleWhiteboardPrplOps *whiteboard_prpl_ops;

	/** For use in plugins that may understand the underlying protocol */
	int (*send_raw)(PurpleConnection *gc, const char *buf, int len);

	/* room list serialize */
	char *(*roomlist_room_serialize)(PurpleRoomlistRoom *room);

	/** Remove the user from the server.  The account can either be
	 * connected or disconnected. After the removal is finished, the
	 * connection will stay open and has to be closed!
	 */
	/* This is here rather than next to register_user for API compatibility
	 * reasons.
	 */
	void (*unregister_user)(PurpleAccount *, PurpleAccountUnregistrationCb cb, void *user_data);
	
	/* Attention API for sending & receiving zaps/nudges/buzzes etc. */
	gboolean (*send_attention)(PurpleConnection *gc, const char *username, guint type);
	GList *(*get_attention_types)(PurpleAccount *acct);

	/**
	 * The size of the PurplePluginProtocolInfo. This should always be sizeof(PurplePluginProtocolInfo).
	 * This allows adding more functions to this struct without requiring a major version bump.
	 */
	unsigned long struct_size;

	/* NOTE:
	 * If more functions are added, they should accessed using the following syntax:
	 *
	 *		if (PURPLE_PROTOCOL_PLUGIN_HAS_FUNC(prpl, new_function))
	 *			prpl->new_function(...);
	 *
	 * instead of
	 *
	 *		if (prpl->new_function != NULL)
	 *			prpl->new_function(...);
	 *
	 * The PURPLE_PROTOCOL_PLUGIN_HAS_FUNC macro can be used for the older member
	 * functions (e.g. login, send_im etc.) too.
	 */

	/** This allows protocols to specify additional strings to be used for
	 * various purposes.  The idea is to stuff a bunch of strings in this hash
	 * table instead of expanding the struct for every addition.  This hash
	 * table is allocated every call and MUST be unrefed by the caller.
	 *
	 * @param account The account to specify.  This can be NULL.
	 * @return The protocol's string hash table. The hash table should be
	 *         destroyed by the caller when it's no longer needed.
	 */
	GHashTable *(*get_account_text_table)(PurpleAccount *account);
};

#endif /* _PURPLE25_COMPAT_H_ */
