/**
 * @file purple-plugin-common.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2015 SIPE Project <http://sipe.sourceforge.net/>
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
#include <string.h>

#include "sipe-common.h"

#include "account.h"
#include "accountopt.h"
#include "core.h"
#include "notify.h"
#include "request.h"
#include "version.h"

/* Backward compatibility when compiling against 2.4.x API */
#if !PURPLE_VERSION_CHECK(2,5,0) && !PURPLE_VERSION_CHECK(3,0,0)
#define PURPLE_CONNECTION_ALLOW_CUSTOM_SMILEY 0x0100
#endif

#if PURPLE_VERSION_CHECK(3,0,0)
#define PURPLE_TYPE_STRING G_TYPE_STRING
#define SIPE_PURPLE_ACTION_TO_CONNECTION              action->connection
#else
#include "blist.h"
#define PURPLE_CONNECTION_FLAG_ALLOW_CUSTOM_SMILEY    PURPLE_CONNECTION_ALLOW_CUSTOM_SMILEY
#define PURPLE_CONNECTION_FLAG_FORMATTING_WBFO        PURPLE_CONNECTION_FORMATTING_WBFO
#define PURPLE_CONNECTION_FLAG_HTML                   PURPLE_CONNECTION_HTML
#define PURPLE_CONNECTION_FLAG_NO_BGCOLOR             PURPLE_CONNECTION_NO_BGCOLOR
#define PURPLE_CONNECTION_FLAG_NO_FONTSIZE            PURPLE_CONNECTION_NO_FONTSIZE
#define PURPLE_CONNECTION_FLAG_NO_URLDESC             PURPLE_CONNECTION_NO_URLDESC
#define PURPLE_IS_BUDDY(n)                            PURPLE_BLIST_NODE_IS_BUDDY(n)
#define PURPLE_IS_CHAT(n)                             PURPLE_BLIST_NODE_IS_CHAT(n)
#define PURPLE_IM_TYPING                              PURPLE_TYPING
#define PURPLE_IM_NOT_TYPING                          PURPLE_NOT_TYPING
#define purple_account_option_string_set_masked(o, f) purple_account_option_set_masked(o, f)
#define purple_connection_error(g, e, m)              purple_connection_error_reason(g, e, m)
#define purple_connection_get_flags(gc)               0
#define purple_connection_set_protocol_data(gc, p)    gc->proto_data = p
#define purple_connection_set_flags(gc, f)            gc->flags |= f
#define purple_protocol_action_new(l, c)              purple_plugin_action_new(l, c)
#define PurpleProtocolAction                          PurplePluginAction
#define SIPE_PURPLE_ACTION_TO_CONNECTION              action->context
#endif

#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-nls.h"

#include "purple-private.h"

/*
 * NOTE: this flag means two things:
 *
 *  - is Single Sign-On supported, and
 *  - is Kerberos supported
 */
#if defined(HAVE_GSSAPI_GSSAPI_H) || defined(HAVE_SSPI)
#define PURPLE_SIPE_SSO_AND_KERBEROS 1
#else
#define PURPLE_SIPE_SSO_AND_KERBEROS 0
#endif

/*
 * SIPE core activity <-> Purple status mapping
 *
 * NOTE: this needs to be kept in sync with sipe_purple_status_types()
 */
static const gchar * const activity_to_purple_map[SIPE_ACTIVITY_NUM_TYPES] = {
/* SIPE_ACTIVITY_UNSET       */ "unset",     /* == purple_primitive_get_id_from_type(PURPLE_STATUS_UNSET) */
/* SIPE_ACTIVITY_AVAILABLE   */ "available", /* == purple_primitive_get_id_from_type(PURPLE_STATUS_AVAILABLE) */
/* SIPE_ACTIVITY_ONLINE      */ "online",
/* SIPE_ACTIVITY_INACTIVE    */ "idle",
/* SIPE_ACTIVITY_BUSY        */ "busy",
/* SIPE_ACTIVITY_BUSYIDLE    */ "busyidle",
/* SIPE_ACTIVITY_DND         */ "do-not-disturb",
/* SIPE_ACTIVITY_BRB         */ "be-right-back",
/* SIPE_ACTIVITY_AWAY        */ "away",      /* == purple_primitive_get_id_from_type(PURPLE_STATUS_AWAY) */
/* SIPE_ACTIVITY_LUNCH       */ "out-to-lunch",
/* SIPE_ACTIVITY_INVISIBLE   */ "invisible", /* == purple_primitive_get_id_from_type(PURPLE_STATUS_INVISIBLE) */
/* SIPE_ACTIVITY_OFFLINE     */ "offline",   /* == purple_primitive_get_id_from_type(PURPLE_STATUS_OFFLINE) */
/* SIPE_ACTIVITY_ON_PHONE    */ "on-the-phone",
/* SIPE_ACTIVITY_IN_CONF     */ "in-a-conference",
/* SIPE_ACTIVITY_IN_MEETING  */ "in-a-meeting",
/* SIPE_ACTIVITY_OOF         */ "out-of-office",
/* SIPE_ACTIVITY_URGENT_ONLY */ "urgent-interruptions-only",
/* SIPE_ACTIVITY_IN_PRES     */ "presenting",
/* SIPE_ACTIVIY_NUM_TYPES -> compare to sipe_purple_status_types() */
};

GHashTable *purple_token_map;

static void sipe_purple_activity_init(void)
{
	guint index;

	purple_token_map = g_hash_table_new(g_str_hash, g_str_equal);
	for (index = SIPE_ACTIVITY_UNSET;
	     index < SIPE_ACTIVITY_NUM_TYPES;
	     index++) {
		g_hash_table_insert(purple_token_map,
				    (gchar *) activity_to_purple_map[index],
				    GUINT_TO_POINTER(index));
	}
}

static void sipe_purple_activity_shutdown(void)
{
	g_hash_table_destroy(purple_token_map);
}

const gchar *sipe_purple_activity_to_token(guint type)
{
	return(activity_to_purple_map[type]);
}

guint sipe_purple_token_to_activity(const gchar *token)
{
	return(GPOINTER_TO_UINT(g_hash_table_lookup(purple_token_map, token)));
}

gchar *sipe_backend_version(void)
{
	return(g_strdup_printf("Purple/%s", purple_core_get_version()));
}

const char *sipe_purple_list_icon(SIPE_UNUSED_PARAMETER PurpleAccount *a,
				  SIPE_UNUSED_PARAMETER PurpleBuddy *b)
{
	return "sipe";
}

gchar *sipe_purple_status_text(PurpleBuddy *buddy)
{
	const PurpleStatus *status = purple_presence_get_active_status(purple_buddy_get_presence(buddy));
	return sipe_core_buddy_status(PURPLE_BUDDY_TO_SIPE_CORE_PUBLIC,
				      purple_buddy_get_name(buddy),
				      sipe_purple_token_to_activity(purple_status_get_id(status)),
				      purple_status_get_name(status));
}

void sipe_purple_tooltip_text(PurpleBuddy *buddy,
			      PurpleNotifyUserInfo *user_info,
			      SIPE_UNUSED_PARAMETER gboolean full)
{
	const PurplePresence *presence = purple_buddy_get_presence(buddy);
	sipe_core_buddy_tooltip_info(PURPLE_BUDDY_TO_SIPE_CORE_PUBLIC,
				     purple_buddy_get_name(buddy),
				     purple_status_get_name(purple_presence_get_active_status(presence)),
				     purple_presence_is_online(presence),
				     (struct sipe_backend_buddy_tooltip *) user_info);
}

GList *sipe_purple_status_types(SIPE_UNUSED_PARAMETER PurpleAccount *acc)
{
	PurpleStatusType *type;
	GList *types = NULL;

	/* Macro to reduce code repetition
	   Translators: noun */
#define SIPE_ADD_STATUS(prim,activity,user) type = purple_status_type_new_with_attrs( \
		prim, \
		sipe_purple_activity_to_token(activity), \
		sipe_core_activity_description(activity), \
		TRUE, user, FALSE,          \
		SIPE_PURPLE_STATUS_ATTR_ID_MESSAGE, _("Message"), purple_value_new(PURPLE_TYPE_STRING), \
		NULL);                      \
	types = g_list_append(types, type);

	/*
	 * NOTE: needs to be kept in sync with activity_to_purple_map[],
	 *       i.e. for each SIPE_ACTIVITY_xxx value there must be an
	 *       entry on this list.
	 *
	 * NOTE: the following code is sorted by purple primitive type not
	 *       by SIPE_ACTIVITY_xxx value.
	 */

	/*  1: Unset - special case: no entry needed */

	/*
	 * Status list entries for primitive type AVAILABLE
	 *
	 *  2: Available */
	SIPE_ADD_STATUS(PURPLE_STATUS_AVAILABLE,
			SIPE_ACTIVITY_AVAILABLE,
			TRUE);

	/*  3: Online */
	SIPE_ADD_STATUS(PURPLE_STATUS_AVAILABLE,
			SIPE_ACTIVITY_ONLINE,
			FALSE);

	/*  4: Inactive (Idle) */
	SIPE_ADD_STATUS(PURPLE_STATUS_AVAILABLE,
			SIPE_ACTIVITY_INACTIVE,
			FALSE);

	/*
	 * Status list entries for primitive type UNAVAILABLE
	 *
	 *  5: Busy */
	SIPE_ADD_STATUS(PURPLE_STATUS_UNAVAILABLE,
			SIPE_ACTIVITY_BUSY,
			TRUE);

	/*  6: Busy-Idle */
	SIPE_ADD_STATUS(PURPLE_STATUS_UNAVAILABLE,
			SIPE_ACTIVITY_BUSYIDLE,
			FALSE);

	/*  7: Do Not Disturb */
	SIPE_ADD_STATUS(PURPLE_STATUS_UNAVAILABLE,
			SIPE_ACTIVITY_DND,
			TRUE);

	/*  8: In a call */
	SIPE_ADD_STATUS(PURPLE_STATUS_UNAVAILABLE,
			SIPE_ACTIVITY_ON_PHONE,
			FALSE);

	/*  9: In a conference call */
	SIPE_ADD_STATUS(PURPLE_STATUS_UNAVAILABLE,
			SIPE_ACTIVITY_IN_CONF,
			FALSE);

	/* 10: In a meeting */
	SIPE_ADD_STATUS(PURPLE_STATUS_UNAVAILABLE,
			SIPE_ACTIVITY_IN_MEETING,
			FALSE);

	/* 11: Urgent interruptions only */
	SIPE_ADD_STATUS(PURPLE_STATUS_UNAVAILABLE,
			SIPE_ACTIVITY_URGENT_ONLY,
			FALSE);

	/* Presenting */
	SIPE_ADD_STATUS(PURPLE_STATUS_UNAVAILABLE,
			SIPE_ACTIVITY_IN_PRES,
			FALSE);

	/*
	 * Status list entries for primitive type AWAY
	 *
	 * 12: Away - special case: needs to go first in the list as purple
	 *            picks the first status with primitive type AWAY for idle
	 */
	SIPE_ADD_STATUS(PURPLE_STATUS_AWAY,
			SIPE_ACTIVITY_AWAY,
			TRUE);

	/* 13: Be Right Back */
	SIPE_ADD_STATUS(PURPLE_STATUS_AWAY,
			SIPE_ACTIVITY_BRB,
			TRUE);

	/* 14: Out to lunch */
	SIPE_ADD_STATUS(PURPLE_STATUS_AWAY,
			SIPE_ACTIVITY_LUNCH,
			FALSE);

	/*
	 * Status list entries for primitive type EXTENDED_AWAY
	 *
	 * 15: Out of office */
	SIPE_ADD_STATUS(PURPLE_STATUS_EXTENDED_AWAY,
			SIPE_ACTIVITY_OOF,
			FALSE);

	/*
	 * Status list entries for primitive type INVISIBLE
	 *
	 * 16: Appear Offline */
	SIPE_ADD_STATUS(PURPLE_STATUS_INVISIBLE,
			SIPE_ACTIVITY_INVISIBLE,
			TRUE);

	/*
	 * Status list entries for primitive type OFFLINE
	 *
	 * NOTE: this is always the last entry. Compare the number
	 *       with the comment in activity_to_purple_map[].
	 *
	 * 17: Offline - special case: no message text */
	type = purple_status_type_new(PURPLE_STATUS_OFFLINE,
				      NULL,
				      NULL,
				      TRUE);
	types = g_list_append(types, type);

	return types;
}

GList *sipe_purple_blist_node_menu(PurpleBlistNode *node)
{
	if (PURPLE_IS_BUDDY(node))
	{
		return sipe_purple_buddy_menu((PurpleBuddy *) node);
	} else
	if (PURPLE_IS_CHAT(node))
	{
		return sipe_purple_chat_menu((PurpleChat *)node);
	} else {
		return NULL;
	}
}

static guint get_authentication_type(PurpleAccount *account)
{
	const gchar *auth = purple_account_get_string(account, "authentication", "ntlm");

	/* map option list to type - default is automatic */
	guint authentication_type = SIPE_AUTHENTICATION_TYPE_AUTOMATIC;
	if (sipe_strequal(auth, "ntlm")) {
		authentication_type = SIPE_AUTHENTICATION_TYPE_NTLM;
	} else
#if PURPLE_SIPE_SSO_AND_KERBEROS
	if (sipe_strequal(auth, "krb5")) {
		authentication_type = SIPE_AUTHENTICATION_TYPE_KERBEROS;
	} else
#endif
	if (sipe_strequal(auth, "tls-dsk")) {
		authentication_type = SIPE_AUTHENTICATION_TYPE_TLS_DSK;
	}

	return(authentication_type);
}

static gboolean get_sso_flag(PurpleAccount *account)
{
#if PURPLE_SIPE_SSO_AND_KERBEROS
	/*
	 * NOTE: the default must be *OFF*, i.e. it is up to the user to tell
	 *       SIPE that it is OK to use Single Sign-On or not.
	 */
	return(purple_account_get_bool(account, "sso", FALSE));
#else
	(void) account; /* keep compiler happy */
	return(FALSE);
#endif
}

static gboolean get_dont_publish_flag(PurpleAccount *account)
{
	/* default is to publish calendar information */
	return(purple_account_get_bool(account, "dont-publish", FALSE));
}

static void connect_to_core(PurpleConnection *gc,
			    PurpleAccount *account,
			    const gchar *password)
{
	const gchar *username  = purple_account_get_username(account);
	const gchar *email     = purple_account_get_string(account, "email", NULL);
	const gchar *email_url = purple_account_get_string(account, "email_url", NULL);
	const gchar *transport = purple_account_get_string(account, "transport", "auto");
	struct sipe_core_public *sipe_public;
	gchar **username_split;
	const gchar *errmsg;
	guint transport_type;
	struct sipe_backend_private *purple_private;

	/* username format: <username>,[<optional login>] */
	SIPE_DEBUG_INFO("sipe_purple_login: username '%s'", username);
	username_split = g_strsplit(username, ",", 2);

	sipe_public = sipe_core_allocate(username_split[0],
					 get_sso_flag(account),
					 username_split[1],
					 password,
					 email,
					 email_url,
					 &errmsg);
	g_strfreev(username_split);

	if (!sipe_public) {
		purple_connection_error(gc,
					PURPLE_CONNECTION_ERROR_INVALID_USERNAME,
					errmsg);
		return;
	}

	sipe_public->backend_private = purple_private = g_new0(struct sipe_backend_private, 1);
	purple_private->public = sipe_public;
	purple_private->gc = gc;
	purple_private->account = account;

	sipe_purple_chat_setup_rejoin(purple_private);

	SIPE_CORE_FLAG_UNSET(DONT_PUBLISH);
	if (get_dont_publish_flag(account))
		SIPE_CORE_FLAG_SET(DONT_PUBLISH);

	purple_connection_set_protocol_data(gc, sipe_public);
	purple_connection_set_flags(gc,
				    purple_connection_get_flags(gc) |
				    PURPLE_CONNECTION_FLAG_HTML |
				    PURPLE_CONNECTION_FLAG_FORMATTING_WBFO |
				    PURPLE_CONNECTION_FLAG_NO_BGCOLOR |
				    PURPLE_CONNECTION_FLAG_NO_FONTSIZE |
				    PURPLE_CONNECTION_FLAG_NO_URLDESC |
				    PURPLE_CONNECTION_FLAG_ALLOW_CUSTOM_SMILEY);
	purple_connection_set_display_name(gc, sipe_public->sip_name);
	purple_connection_update_progress(gc, _("Connecting"), 1, 2);

	username_split = g_strsplit(purple_account_get_string(account, "server", ""), ":", 2);
	if (sipe_strequal(transport, "auto")) {
		transport_type = (username_split[0] == NULL) ?
			SIPE_TRANSPORT_AUTO : SIPE_TRANSPORT_TLS;
	} else if (sipe_strequal(transport, "tls")) {
		transport_type = SIPE_TRANSPORT_TLS;
	} else {
		transport_type = SIPE_TRANSPORT_TCP;
	}
	sipe_core_transport_sip_connect(sipe_public,
					transport_type,
					get_authentication_type(account),
					username_split[0],
					username_split[0] ? username_split[1] : NULL);
	g_strfreev(username_split);
}

static void password_required_cb(PurpleConnection *gc,
				 SIPE_UNUSED_PARAMETER PurpleRequestFields *fields)
{
#if !PURPLE_VERSION_CHECK(3,0,0)
	if (!PURPLE_CONNECTION_IS_VALID(gc)) {
		return;
	}
#endif

	purple_connection_error(gc,
				PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
				_("Password required"));
}

static void password_ok_cb(PurpleConnection *gc,
			   PurpleRequestFields *fields)
{
	const gchar *password;

#if !PURPLE_VERSION_CHECK(3,0,0)
	if (!PURPLE_CONNECTION_IS_VALID(gc)) {
		return;
	}
#endif

	password = purple_request_fields_get_string(fields, "password");

	if (password && strlen(password)) {
		PurpleAccount *account = purple_connection_get_account(gc);

		if (purple_request_fields_get_bool(fields, "remember"))
			purple_account_set_remember_password(account, TRUE);
		purple_account_set_password(account, password
#if PURPLE_VERSION_CHECK(3,0,0)
					    , NULL, NULL
#endif
					   );

		/* Now we have a password and we can connect */
		connect_to_core(gc, account, password);

	} else
		/* reject an empty password */
		password_required_cb(gc, fields);
}

void sipe_purple_login(PurpleAccount *account)
{
	PurpleConnection *gc = purple_account_get_connection(account);
	const gchar *password = purple_connection_get_password(gc);

	/* Password required? */
	if (sipe_core_transport_sip_requires_password(get_authentication_type(account),
						      get_sso_flag(account)) &&
	    (!password || !strlen(password)))
		/* No password set - request one from user */
		purple_account_request_password(account,
						G_CALLBACK(password_ok_cb),
						G_CALLBACK(password_required_cb),
						gc);
	else
		/* No password required or saved password - connect now */
		connect_to_core(gc, account, password);

}

void sipe_purple_close(PurpleConnection *gc)
{
	struct sipe_core_public *sipe_public = PURPLE_GC_TO_SIPE_CORE_PUBLIC;

	if (sipe_public) {
		struct sipe_backend_private *purple_private = sipe_public->backend_private;

		sipe_core_deallocate(sipe_public);

		/* anything left after that must be in pending state... */
		sipe_purple_dns_query_cancel_all(purple_private);
		sipe_purple_transport_close_all(purple_private);

		if (purple_private->roomlist_map)
			g_hash_table_destroy(purple_private->roomlist_map);
		sipe_purple_chat_destroy_rejoin(purple_private);

		if (purple_private->deferred_status_timeout)
			purple_timeout_remove(purple_private->deferred_status_timeout);
		g_free(purple_private->deferred_status_note);

		g_free(purple_private);
		purple_connection_set_protocol_data(gc, NULL);
	}
}

unsigned int sipe_purple_send_typing(PurpleConnection *gc,
				     const char *who,
				     PurpleIMTypingState state)
{
	gboolean typing = (state == PURPLE_IM_TYPING);

	/* only enable this debug output while testing
	   SIPE_DEBUG_INFO("sipe_purple_send_typing: '%s' state %d", who, state); */

	/*
	 * libpurple calls this function with PURPLE_NOT_TYPING *after*
	 * calling sipe_purple_send_im() with the message. This causes
	 * SIPE core to send out two SIP messages to the same dialog in
	 * short succession without waiting for the response to the first
	 * one. Some servers then reject the first one with
	 *
	 *    SIP/2.0 500 Stale CSeq Value
	 *
	 * which triggers a "message not delivered" error for the user.
	 *
	 * Work around this by filtering out PURPLE_NOT_TYPING events.
	 */
	if (state != PURPLE_IM_NOT_TYPING)
		sipe_core_user_feedback_typing(PURPLE_GC_TO_SIPE_CORE_PUBLIC,
					       who,
					       typing);

	/* tell libpurple to send typing indications every 4 seconds */
	return(typing ? 4 : 0);
}

void sipe_purple_get_info(PurpleConnection *gc, const char *who)
{
	sipe_core_buddy_get_info(PURPLE_GC_TO_SIPE_CORE_PUBLIC,
				 who);
}

void sipe_purple_add_permit(PurpleConnection *gc, const char *name)
{
	sipe_core_contact_allow_deny(PURPLE_GC_TO_SIPE_CORE_PUBLIC, name, TRUE);
}

void sipe_purple_add_deny(PurpleConnection *gc, const char *name)
{
	sipe_core_contact_allow_deny(PURPLE_GC_TO_SIPE_CORE_PUBLIC, name, FALSE);
}

void sipe_purple_alias_buddy(PurpleConnection *gc, const char *name,
			     const char *alias)
{
	sipe_core_group_set_alias(PURPLE_GC_TO_SIPE_CORE_PUBLIC, name, alias);
}

void sipe_purple_group_rename(PurpleConnection *gc, const char *old_name,
			      PurpleGroup *group,
			      SIPE_UNUSED_PARAMETER GList *moved_buddies)
{
	sipe_core_group_rename(PURPLE_GC_TO_SIPE_CORE_PUBLIC,
			       old_name,
			       purple_group_get_name(group));
}

void sipe_purple_convo_closed(PurpleConnection *gc, const char *who)
{
	sipe_core_im_close(PURPLE_GC_TO_SIPE_CORE_PUBLIC, who);
}

void sipe_purple_group_remove(PurpleConnection *gc, PurpleGroup *group)
{
	sipe_core_group_remove(PURPLE_GC_TO_SIPE_CORE_PUBLIC,
			       purple_group_get_name(group));
}

#if PURPLE_VERSION_CHECK(2,5,0) || PURPLE_VERSION_CHECK(3,0,0)
GHashTable *
sipe_purple_get_account_text_table(SIPE_UNUSED_PARAMETER PurpleAccount *account)
{
	GHashTable *table;
	table = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(table, "login_label", (gpointer)_("user@company.com"));
	return table;
}

#if PURPLE_VERSION_CHECK(2,6,0) || PURPLE_VERSION_CHECK(3,0,0)
#ifdef HAVE_VV

static void
sipe_purple_sigusr1_handler(SIPE_UNUSED_PARAMETER int signum)
{
	capture_pipeline("PURPLE_SIPE_PIPELINE");
}

gboolean sipe_purple_initiate_media(PurpleAccount *account, const char *who,
				    SIPE_UNUSED_PARAMETER PurpleMediaSessionType type)
{
	sipe_core_media_initiate_call(PURPLE_ACCOUNT_TO_SIPE_CORE_PUBLIC,
				      who,
				      (type & PURPLE_MEDIA_VIDEO));
	return TRUE;
}

PurpleMediaCaps sipe_purple_get_media_caps(SIPE_UNUSED_PARAMETER PurpleAccount *account,
					   SIPE_UNUSED_PARAMETER const char *who)
{
	return   PURPLE_MEDIA_CAPS_AUDIO
	       | PURPLE_MEDIA_CAPS_AUDIO_VIDEO
	       | PURPLE_MEDIA_CAPS_MODIFY_SESSION;
}
#endif
#endif
#endif

/* PurplePluginInfo function calls & data structure */
gboolean sipe_purple_plugin_load(SIPE_UNUSED_PARAMETER PurplePlugin *plugin)
{
#ifdef HAVE_VV
	struct sigaction action;
	memset(&action, 0, sizeof (action));
	action.sa_handler = sipe_purple_sigusr1_handler;
	sigaction(SIGUSR1, &action, NULL);
#endif

	sipe_purple_activity_init();

	return TRUE;
}

gboolean sipe_purple_plugin_unload(SIPE_UNUSED_PARAMETER PurplePlugin *plugin)
{
#ifdef HAVE_VV
	struct sigaction action;
	memset(&action, 0, sizeof (action));
	action.sa_handler = SIG_DFL;
	sigaction(SIGUSR1, &action, NULL);
#endif

	sipe_purple_activity_shutdown();

	return TRUE;
}

static void sipe_purple_show_about_plugin(PurpleProtocolAction *action)
{
	gchar *tmp = sipe_core_about();
	purple_notify_formatted(SIPE_PURPLE_ACTION_TO_CONNECTION,
				NULL, " ", NULL, tmp, NULL, NULL);
	g_free(tmp);
}

static void sipe_purple_join_conference_cb(PurpleConnection *gc,
					   PurpleRequestFields *fields)
{
	GList *entries = purple_request_field_group_get_fields(purple_request_fields_get_groups(fields)->data);

	if (entries) {
		const gchar *location = purple_request_fields_get_string(fields,
									 "meetingLocation");
		const gchar *organizer = purple_request_fields_get_string(fields,
									  "meetingOrganizer");
		const gchar *meeting_id = purple_request_fields_get_string(fields,
									   "meetingID");
		sipe_core_conf_create(PURPLE_GC_TO_SIPE_CORE_PUBLIC,
				      location,
				      organizer,
				      meeting_id);
	}
}

#ifdef HAVE_VV

static void sipe_purple_phone_call_cb(PurpleConnection *gc,
				      PurpleRequestFields *fields)
{
	GList *entries = purple_request_field_group_get_fields(purple_request_fields_get_groups(fields)->data);

	if (entries)
		sipe_core_media_phone_call(PURPLE_GC_TO_SIPE_CORE_PUBLIC,
					   purple_request_fields_get_string(fields,
									    "phoneNumber"));
}

static void sipe_purple_phone_call(PurpleProtocolAction *action)
{
	PurpleConnection *gc = SIPE_PURPLE_ACTION_TO_CONNECTION;
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);

	field = purple_request_field_string_new("phoneNumber", _("Phone number"), NULL, FALSE);
	purple_request_field_group_add_field(group, field);

	purple_request_fields(gc,
			      _("Call a phone number"),
			      _("Call a phone number"),
			      NULL,
			      fields,
			      _("_Call"), G_CALLBACK(sipe_purple_phone_call_cb),
			      _("_Cancel"), NULL,
#if PURPLE_VERSION_CHECK(3,0,0)
			      purple_request_cpar_from_connection(gc),
#else
			      purple_connection_get_account(gc), NULL, NULL,
#endif
			      gc);
}

static void sipe_purple_test_call(PurpleProtocolAction *action)
{
	PurpleConnection *gc = SIPE_PURPLE_ACTION_TO_CONNECTION;
	sipe_core_media_test_call(PURPLE_GC_TO_SIPE_CORE_PUBLIC);
}
#endif

static void sipe_purple_show_join_conference(PurpleProtocolAction *action)
{
	PurpleConnection *gc = SIPE_PURPLE_ACTION_TO_CONNECTION;
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);

	field = purple_request_field_string_new("meetingLocation", _("Meeting location"), NULL, FALSE);
	purple_request_field_group_add_field(group, field);
	field = purple_request_field_label_new("separator", _("Alternatively"));
	purple_request_field_group_add_field(group, field);
	field = purple_request_field_string_new("meetingOrganizer", _("Organizer email"), NULL, FALSE);
	purple_request_field_group_add_field(group, field);
	field = purple_request_field_string_new("meetingID", _("Meeting ID"), NULL, FALSE);
	purple_request_field_group_add_field(group, field);

	purple_request_fields(gc,
			      _("Join conference"),
			      _("Join scheduled conference"),
			      _("Enter meeting location string you received in the invitation.\n"
				"\n"
				"Valid location will be something like\n"
				"meet:sip:someone@company.com;gruu;opaque=app:conf:focus:id:abcdef1234\n"
				"conf:sip:someone@company.com;gruu;opaque=app:conf:focus:id:abcdef1234\n"
				"or\n"
				"https://meet.company.com/someone/abcdef1234"),
			      fields,
			      _("_Join"), G_CALLBACK(sipe_purple_join_conference_cb),
			      _("_Cancel"), NULL,
#if PURPLE_VERSION_CHECK(3,0,0)
			      purple_request_cpar_from_connection(gc),
#else
			      purple_connection_get_account(gc), NULL, NULL,
#endif
			      gc);
}

static void sipe_purple_republish_calendar(PurpleProtocolAction *action)
{
	PurpleConnection *gc = SIPE_PURPLE_ACTION_TO_CONNECTION;
	PurpleAccount *account = purple_connection_get_account(gc);

	if (get_dont_publish_flag(account)) {
		sipe_backend_notify_error(PURPLE_GC_TO_SIPE_CORE_PUBLIC,
					  _("Publishing of calendar information has been disabled"),
					  NULL);
	} else {
		sipe_core_update_calendar(PURPLE_GC_TO_SIPE_CORE_PUBLIC);
	}
}

static void sipe_purple_reset_status(PurpleProtocolAction *action)
{
	PurpleConnection *gc = SIPE_PURPLE_ACTION_TO_CONNECTION;
	PurpleAccount *account = purple_connection_get_account(gc);

	if (get_dont_publish_flag(account)) {
		sipe_backend_notify_error(PURPLE_GC_TO_SIPE_CORE_PUBLIC,
					  _("Publishing of calendar information has been disabled"),
					  NULL);
	} else {
		sipe_core_reset_status(PURPLE_GC_TO_SIPE_CORE_PUBLIC);
	}
}

GList *sipe_purple_actions()
{
	GList *menu = NULL;
	PurpleProtocolAction *act;

	act = purple_protocol_action_new(_("About SIPE plugin..."), sipe_purple_show_about_plugin);
	menu = g_list_prepend(menu, act);

	act = purple_protocol_action_new(_("Contact search..."), sipe_purple_show_find_contact);
	menu = g_list_prepend(menu, act);

#ifdef HAVE_VV
	act = purple_protocol_action_new(_("Call a phone number..."), sipe_purple_phone_call);
	menu = g_list_prepend(menu, act);

	act = purple_protocol_action_new(_("Test call"), sipe_purple_test_call);
	menu = g_list_prepend(menu, act);
#endif

	act = purple_protocol_action_new(_("Join scheduled conference..."), sipe_purple_show_join_conference);
	menu = g_list_prepend(menu, act);

	act = purple_protocol_action_new(_("Republish Calendar"), sipe_purple_republish_calendar);
	menu = g_list_prepend(menu, act);

	act = purple_protocol_action_new(_("Reset status"), sipe_purple_reset_status);
	menu = g_list_prepend(menu, act);

	return g_list_reverse(menu);
}

GList * sipe_purple_account_options()
{
	PurpleAccountOption *option;
	GList *options = NULL;

	/**
	 * When adding new string settings please make sure to keep these
	 * in sync:
	 *
	 *     api/sipe-backend.h
	 *     purple-settings.c:setting_name[]
	 */
	option = purple_account_option_string_new(_("Server[:Port]\n(leave empty for auto-discovery)"), "server", "");
	options = g_list_append(options, option);

	option = purple_account_option_list_new(_("Connection type"), "transport", NULL);
	purple_account_option_add_list_item(option, _("Auto"), "auto");
	purple_account_option_add_list_item(option, _("SSL/TLS"), "tls");
	purple_account_option_add_list_item(option, _("TCP"), "tcp");
	options = g_list_append(options, option);

	/*option = purple_account_option_bool_new(_("Publish status (note: everyone may watch you)"), "doservice", TRUE);
	sipe_prpl_info.protocol_options = g_list_append(sipe_prpl_info.protocol_options, option);*/

	option = purple_account_option_string_new(_("User Agent"), "useragent", "");
	options = g_list_append(options, option);

	option = purple_account_option_list_new(_("Authentication scheme"), "authentication", NULL);
	purple_account_option_add_list_item(option, _("Auto"), "auto");
	purple_account_option_add_list_item(option, _("NTLM"), "ntlm");
#if PURPLE_SIPE_SSO_AND_KERBEROS
	purple_account_option_add_list_item(option, _("Kerberos"), "krb5");
#endif
	purple_account_option_add_list_item(option, _("TLS-DSK"), "tls-dsk");
	options = g_list_append(options, option);

#if PURPLE_SIPE_SSO_AND_KERBEROS
	/*
	 * When the user selects Single Sign-On then SIPE will ignore the
	 * settings for "login name" and "password". Instead it will use the
	 * default credentials provided by the OS.
	 *
	 * NOTE: the default must be *OFF*, i.e. it is up to the user to tell
	 *       SIPE that it is OK to use Single Sign-On or not.
	 *
	 * Configurations that are known to support Single Sign-On:
	 *
	 *  - Windows, host joined to domain, SIPE with SSPI: NTLM
	 *  - Windows, host joined to domain, SIPE with SSPI: Kerberos
	 *  - SIPE with libkrb5, valid TGT in cache (kinit):  Kerberos
	 */
	option = purple_account_option_bool_new(_("Use Single Sign-On"), "sso", FALSE);
	options = g_list_append(options, option);
#endif

	/** Example (Exchange): https://server.company.com/EWS/Exchange.asmx
	 *  Example (Domino)  : https://[domino_server]/[mail_database_name].nsf
	 */
	option = purple_account_option_bool_new(_("Don't publish my calendar information"), "dont-publish", FALSE);
	options = g_list_append(options, option);

	option = purple_account_option_string_new(_("Email services URL\n(leave empty for auto-discovery)"), "email_url", "");
	options = g_list_append(options, option);

	option = purple_account_option_string_new(_("Email address\n(if different from Username)"), "email", "");
	options = g_list_append(options, option);

	/** Example (Exchange): DOMAIN\user  or  user@company.com
	 *  Example (Domino)  : email_address
	 */
	option = purple_account_option_string_new(_("Email login\n(if different from Login)"), "email_login", "");
	options = g_list_append(options, option);

	option = purple_account_option_string_new(_("Email password\n(if different from Password)"), "email_password", "");
	purple_account_option_string_set_masked(option, TRUE);
	options = g_list_append(options, option);

	/** Example (federated domain): company.com      (i.e. ocschat@company.com)
	 *  Example (non-default user): user@company.com
	 */
	option = purple_account_option_string_new(_("Group Chat Proxy\n   company.com  or  user@company.com\n(leave empty to determine from Username)"), "groupchat_user", "");
	options = g_list_append(options, option);

#ifdef HAVE_SRTP
	option = purple_account_option_list_new(_("Media encryption"), "encryption-policy", NULL);
	purple_account_option_add_list_item(option, _("Obey server policy"), "obey-server");
	purple_account_option_add_list_item(option, _("Always"), "required");
	purple_account_option_add_list_item(option, _("Optional"), "optional");
	purple_account_option_add_list_item(option, _("Disabled"), "disabled");
	options = g_list_append(options, option);
#endif

	return options;
}

gpointer sipe_purple_user_split()
{
	PurpleAccountUserSplit *split =
			purple_account_user_split_new(_("Login\n   user  or  DOMAIN\\user  or\n   user@company.com"), NULL, ',');
	purple_account_user_split_set_reverse(split, FALSE);

	return split;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
