/**
 * @file purple-buddy.c
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

#include "notify.h"
#include "request.h"

#include "version.h"
#if PURPLE_VERSION_CHECK(3,0,0)
#include "account.h"
#include "buddylist.h"
#else
#include "blist.h"
#include "privacy.h"
#define purple_account_privacy_check(a, n)             purple_privacy_check(a, n)
#define purple_account_privacy_deny_add(a, n, l)       purple_privacy_deny_add(a, n, l)
#define purple_account_privacy_deny_remove(a, n, l)    purple_privacy_deny_remove(a, n, l)
#define purple_blist_find_buddies(a, n)                purple_find_buddies(a, n)
#define purple_blist_find_buddy(a, n)                  purple_find_buddy(a, n)
#define purple_blist_find_buddy_in_group(a, n, g)      purple_find_buddy_in_group(a, n, g)
#define purple_blist_find_group(n)                     purple_find_group(n)
#define purple_buddy_set_local_alias(b, n)             purple_blist_alias_buddy(b, n)
#define purple_buddy_set_server_alias(b, n)            purple_blist_server_alias_buddy(b, n)
#define purple_buddy_set_name(b, n)                    purple_blist_rename_buddy(b, n)
#define purple_group_set_name(g, n)                    purple_blist_rename_group(g, n)
#define purple_notify_user_info_add_pair_html(i, k, v) purple_notify_user_info_add_pair(i, k, v)
#define purple_protocol_got_user_status                purple_prpl_got_user_status
#define PURPLE_IS_BUDDY(b)                             PURPLE_BLIST_NODE_IS_BUDDY(b)
#define PURPLE_IS_GROUP(b)                             PURPLE_BLIST_NODE_IS_GROUP(b)
#endif

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-nls.h"

#include "purple-private.h"

static const struct {
	const gchar *property;    /* property name to store in blist.xml */
	const gchar *description; /* label for "Get Info" dialog */
} buddy_info_map[] = {
/* SIPE_BUDDY_INFO_DISPLAY_NAME          */ { "alias",                 N_("Display name")   },
/* SIPE_BUDDY_INFO_JOB_TITLE             */ { "title",                 N_("Job title")      },
/* SIPE_BUDDY_INFO_CITY                  */ { "address-city",          N_("City")           },
/* SIPE_BUDDY_INFO_STATE                 */ { "address-state",         N_("State")          },
/* SIPE_BUDDY_INFO_OFFICE                */ { "office",                N_("Office")         },
/* SIPE_BUDDY_INFO_DEPARTMENT            */ { "department",            NULL                 },
/* SIPE_BUDDY_INFO_COUNTRY               */ { "address-country-code",  N_("Country")        },
/* SIPE_BUDDY_INFO_WORK_PHONE            */ { "phone",                 N_("Business phone") },
/* SIPE_BUDDY_INFO_WORK_PHONE_DISPLAY    */ { "phone-display",         NULL                 },
/* SIPE_BUDDY_INFO_COMPANY               */ { "company",               N_("Company")        },
/* SIPE_BUDDY_INFO_EMAIL                 */ { "email",                 N_("Email address")  },
/* SIPE_BUDDY_INFO_SITE                  */ { "site",                  N_("Site")           },
/* SIPE_BUDDY_INFO_ZIPCODE               */ { "address-zipcode",       NULL                 },
/* SIPE_BUDDY_INFO_STREET                */ { "address-street",        NULL                 },
/* SIPE_BUDDY_INFO_MOBILE_PHONE          */ { "phone-mobile",          NULL                 },
/* SIPE_BUDDY_INFO_MOBILE_PHONE_DISPLAY  */ { "phone-mobile-display",  NULL                 },
/* SIPE_BUDDY_INFO_HOME_PHONE            */ { "phone-home",            NULL                 },
/* SIPE_BUDDY_INFO_HOME_PHONE_DISPLAY    */ { "phone-home-display",    NULL                 },
/* SIPE_BUDDY_INFO_OTHER_PHONE           */ { "phone-other",           NULL                 },
/* SIPE_BUDDY_INFO_OTHER_PHONE_DISPLAY   */ { "phone-other-display",   NULL                 },
/* SIPE_BUDDY_INFO_CUSTOM1_PHONE         */ { "phone-custom1",         NULL                 },
/* SIPE_BUDDY_INFO_CUSTOM1_PHONE_DISPLAY */ { "phone-custom1-display", NULL                 },
/* SIPE_BUDDY_INFO_ALIAS                 */ { NULL,                    N_("Alias")          },
/* SIPE_BUDDY_INFO_DEVICE                */ { NULL,                    N_("Device")         },
};

#define buddy_info_property(i)    buddy_info_map[i].property
#define buddy_info_description(i) gettext(buddy_info_map[i].description)

sipe_backend_buddy sipe_backend_buddy_find(struct sipe_core_public *sipe_public,
					   const gchar *buddy_name,
					   const gchar *group_name)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleGroup *purple_group;

	if (group_name)
	{
		purple_group = purple_blist_find_group(group_name);
		if (!purple_group)
			return NULL;

		return purple_blist_find_buddy_in_group(purple_private->account,
							buddy_name,
							purple_group);
	} else {
		return purple_blist_find_buddy(purple_private->account,
					       buddy_name);
	}
}

GSList* sipe_backend_buddy_find_all(struct sipe_core_public *sipe_public,
				    const gchar *buddy_name,
				    const gchar *group_name)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;

	if (group_name)
	{
		SIPE_DEBUG_ERROR_NOFORMAT("Finding all buddies in a group not supported on purple");
		return NULL;
	}

	return purple_blist_find_buddies(purple_private->account, buddy_name);
}

gchar* sipe_backend_buddy_get_name(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				   const sipe_backend_buddy who)
{
	return g_strdup(purple_buddy_get_name((PurpleBuddy *) who));
}

gchar* sipe_backend_buddy_get_alias(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				    const sipe_backend_buddy who)
{
	return g_strdup(purple_buddy_get_alias(who));
}

gchar* sipe_backend_buddy_get_server_alias(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					   const sipe_backend_buddy who)
{
	return g_strdup(purple_buddy_get_server_alias(who));
}

gchar *sipe_backend_buddy_get_local_alias(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					  const sipe_backend_buddy who)
{
	return g_strdup(
#if PURPLE_VERSION_CHECK(2,6,0)
		purple_buddy_get_local_buddy_alias(who)
#else
		purple_buddy_get_local_alias(who)
#endif
		);
}

gchar* sipe_backend_buddy_get_group_name(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					 const sipe_backend_buddy who)
{
	return g_strdup(purple_group_get_name(purple_buddy_get_group((PurpleBuddy*)who)));
}

guint sipe_backend_buddy_get_status(struct sipe_core_public *sipe_public,
				    const gchar *uri)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleBuddy *pbuddy = purple_blist_find_buddy(purple_private->account, uri);
	const PurplePresence *presence = purple_buddy_get_presence(pbuddy);
	const PurpleStatus *pstatus = purple_presence_get_active_status(presence);
	return(sipe_purple_token_to_activity(purple_status_get_id(pstatus)));
}

void sipe_backend_buddy_set_alias(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				  const sipe_backend_buddy who,
				  const gchar *alias)
{
	purple_buddy_set_local_alias(who, alias);
}

void sipe_backend_buddy_set_server_alias(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					 const sipe_backend_buddy who,
					 const gchar *alias)
{
	purple_buddy_set_server_alias(who, alias);
}

gchar* sipe_backend_buddy_get_string(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				     sipe_backend_buddy buddy,
				     const sipe_buddy_info_fields key)
{
	PurpleBuddy *b = (PurpleBuddy*) buddy;
	return g_strdup(purple_blist_node_get_string(&b->node, buddy_info_property(key)));
}

void sipe_backend_buddy_set_string(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				   sipe_backend_buddy buddy,
				   const sipe_buddy_info_fields key,
				   const gchar *val)
{
	PurpleBuddy *b = (PurpleBuddy*) buddy;
	purple_blist_node_set_string(&b->node, buddy_info_property(key), val);
}

void sipe_backend_buddy_refresh_properties(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					   SIPE_UNUSED_PARAMETER const gchar *uri)
{
	/* nothing to do here: already taken care of by libpurple */
}

void sipe_backend_buddy_list_processing_start(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public)
{
}

void sipe_backend_buddy_list_processing_finish(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public)
{
}

sipe_backend_buddy sipe_backend_buddy_add(struct sipe_core_public *sipe_public,
					  const gchar *name,
					  const gchar *alias,
					  const gchar *groupname)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleBuddy *b;
	PurpleGroup *purple_group = purple_blist_find_group(groupname);

	if (!purple_group)
		return NULL;

	b = purple_buddy_new(purple_private->account, name, alias);
	purple_blist_add_buddy(b, NULL, purple_group, NULL);
	return b;
}

void sipe_backend_buddy_remove(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
			       const sipe_backend_buddy who)
{
	purple_blist_remove_buddy(who);
}

void sipe_backend_buddy_request_authorization(struct sipe_core_public *sipe_public,
					      const gchar *who,
					      const gchar *alias,
					      gboolean on_list,
					      sipe_backend_buddy_request_authorization_cb auth_cb,
					      sipe_backend_buddy_request_authorization_cb deny_cb,
					      gpointer data)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;

	purple_account_request_authorization(
		purple_private->account,
		who,
		_("you"), /* id */
		alias,
		NULL, /* message */
		on_list,
		(PurpleAccountRequestAuthorizationCb) auth_cb,
		(PurpleAccountRequestAuthorizationCb) deny_cb,
		data);

}

void sipe_backend_buddy_request_add(struct sipe_core_public *sipe_public,
				    const gchar *who,
				    const gchar *alias)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;

	purple_account_request_add(purple_private->account,
				   who,
				   _("you"),
				   alias,
				   NULL);

}

gboolean sipe_backend_buddy_is_blocked(struct sipe_core_public *sipe_public,
				       const gchar *who)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;

	return(!purple_account_privacy_check(purple_private->account, who));
}

void sipe_backend_buddy_set_blocked_status(struct sipe_core_public *sipe_public,
				      const gchar *who,
				      gboolean blocked)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;

	if (blocked) {
		purple_account_privacy_deny_add(purple_private->account, who, TRUE);
	} else {
		purple_account_privacy_deny_remove(purple_private->account, who, TRUE);
	}

	/* stupid workaround to make pidgin re-render screen to reflect our changes */
	SIPE_DEBUG_INFO_NOFORMAT("sipe_backend_buddy_set_blocked_status: forcefully refreshing screen.");
	sipe_core_buddy_got_status(sipe_public,
				   who,
				   sipe_backend_buddy_get_status(sipe_public,
								 who));
}

void sipe_backend_buddy_set_status(struct sipe_core_public *sipe_public,
				   const gchar *who,
				   guint activity)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleBuddy *buddy = NULL;
	PurpleStatus *status = NULL;
	gchar *tmp = NULL;

	buddy = purple_blist_find_buddy(purple_private->account, who);
	if (buddy)
		status = purple_presence_get_active_status(purple_buddy_get_presence(buddy));

	if (status)
		tmp = sipe_core_buddy_status(PURPLE_BUDDY_TO_SIPE_CORE_PUBLIC,
					     purple_buddy_get_name(buddy),
					     sipe_purple_token_to_activity(purple_status_get_id(status)),
					     purple_status_get_name(status));

	if (tmp) {
		purple_protocol_got_user_status(purple_private->account, who,
						sipe_purple_activity_to_token(activity),
						SIPE_PURPLE_STATUS_ATTR_ID_MESSAGE, tmp,
						NULL);
		g_free(tmp);
	} else
		purple_protocol_got_user_status(purple_private->account, who,
						sipe_purple_activity_to_token(activity),
						NULL);
}

gboolean sipe_backend_uses_photo(void)
{
	return TRUE;
}

void sipe_backend_buddy_set_photo(struct sipe_core_public *sipe_public,
				  const gchar *who,
				  gpointer photo_data,
				  gsize data_len,
				  const gchar *photo_hash)
{
	PurpleAccount *account = sipe_public->backend_private->account;

	purple_buddy_icons_set_for_user(account, who, photo_data,
					data_len, photo_hash);
}

const gchar *sipe_backend_buddy_get_photo_hash(struct sipe_core_public *sipe_public,
					       const gchar *who)
{
	PurpleAccount *account = sipe_public->backend_private->account;
	const gchar *result = NULL;

	PurpleBuddyIcon *icon = purple_buddy_icons_find(account, who);
	if (icon) {
		result = purple_buddy_icon_get_checksum(icon);
		purple_buddy_icon_unref(icon);
	}

	return result;
}

gboolean sipe_backend_buddy_group_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				      const gchar *group_name)
{
	PurpleGroup * purple_group = purple_blist_find_group(group_name);
	if (!purple_group) {
		purple_group = purple_group_new(group_name);
		purple_blist_add_group(purple_group, NULL);
	}

	return (purple_group != NULL);
}

gboolean sipe_backend_buddy_group_rename(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					 const gchar *old_name,
					 const gchar *new_name)
{
	PurpleGroup *purple_group = purple_blist_find_group(old_name);
	if (purple_group)
		purple_group_set_name(purple_group, new_name);
	return(purple_group != NULL);
}

void sipe_backend_buddy_group_remove(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				     const gchar *group_name)
{
	PurpleGroup *purple_group = purple_blist_find_group(group_name);
	if (purple_group)
		purple_blist_remove_group(purple_group);
}

struct sipe_backend_buddy_info *sipe_backend_buddy_info_start(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public)
{
	return((struct sipe_backend_buddy_info *)purple_notify_user_info_new());
}

void sipe_backend_buddy_info_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				 struct sipe_backend_buddy_info *info,
				 sipe_buddy_info_fields key,
				 const gchar *value)
{
	if (info) {
		purple_notify_user_info_add_pair_html((PurpleNotifyUserInfo *) info,
						      buddy_info_description(key),
						      value);
	}
}

void sipe_backend_buddy_info_break(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				   struct sipe_backend_buddy_info *info)
{
	purple_notify_user_info_add_section_break((PurpleNotifyUserInfo *) info);
}

void sipe_backend_buddy_info_finalize(struct sipe_core_public *sipe_public,
				      struct sipe_backend_buddy_info *info,
				      const gchar *uri)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;

	/* show a buddy's user info in a nice dialog box */
	purple_notify_userinfo(purple_private->gc,
			       uri,       /* buddy's URI */
			       (PurpleNotifyUserInfo *) info,
			       NULL,      /* callback called when dialog closed */
			       NULL);     /* userdata for callback */
}

void sipe_backend_buddy_tooltip_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				    struct sipe_backend_buddy_tooltip *tooltip,
				    const gchar *description,
				    const gchar *value)
{
	purple_notify_user_info_add_pair_html((PurpleNotifyUserInfo *) tooltip,
					      description,
					      value);
}

void sipe_purple_add_buddy(PurpleConnection *gc,
			   PurpleBuddy *buddy,
			   PurpleGroup *group
#if PURPLE_VERSION_CHECK(3,0,0)
			   , SIPE_UNUSED_PARAMETER const gchar *message
#endif
	)
{
	SIPE_DEBUG_INFO("sipe_purple_add_buddy[CB]: buddy:%s group:%s",
			buddy ? purple_buddy_get_name(buddy) : "",
			group ? purple_group_get_name(group) : "");

	/* libpurple can call us with undefined buddy or group */
	if (buddy && group) {
		/*
		 * Buddy name must be lower case as we use
		 * purple_normalize_nocase() to compare
		 */
		gchar *buddy_name = g_ascii_strdown(purple_buddy_get_name(buddy), -1);
		gchar *uri        = sip_uri_if_valid(buddy_name);
		g_free(buddy_name);

		if (uri) {
			purple_buddy_set_name(buddy, uri);
			g_free(uri);

			sipe_core_buddy_add(PURPLE_GC_TO_SIPE_CORE_PUBLIC,
					    purple_buddy_get_name(buddy),
					    purple_group_get_name(group));
		} else {
			SIPE_DEBUG_ERROR_NOFORMAT("sipe_purple_add_buddy[CB]: buddy name is invalid for URI");
			purple_blist_remove_buddy(buddy);
			purple_notify_error(gc, NULL,
					    _("User name should be a valid SIP URI\nExample: user@company.com"),
					    NULL
#if PURPLE_VERSION_CHECK(3,0,0)
					    , NULL
#endif
					    );
		}
	}
}

void sipe_purple_remove_buddy(PurpleConnection *gc,
			      PurpleBuddy *buddy,
			      PurpleGroup *group)
{
	SIPE_DEBUG_INFO("sipe_purple_remove_buddy[CB]: buddy: '%s' group: '%s'",
			buddy ? purple_buddy_get_name(buddy) : "",
			group ? purple_group_get_name(group) : "");
	if (!buddy) return;

	sipe_core_buddy_remove(PURPLE_GC_TO_SIPE_CORE_PUBLIC,
			       purple_buddy_get_name(buddy),
			       group ? purple_group_get_name(group) : NULL);
}

void sipe_purple_group_buddy(PurpleConnection *gc,
			     const char *who,
			     const char *old_group_name,
			     const char *new_group_name)
{
	sipe_core_buddy_group(PURPLE_GC_TO_SIPE_CORE_PUBLIC, who, old_group_name, new_group_name);
}

/* Buddy Menu Handling */

static void sipe_purple_buddy_make_chat_leader_cb(PurpleBuddy *buddy,
						  gpointer parameter)
{
	SIPE_DEBUG_INFO("sipe_purple_buddy_make_chat_leader_cb: name '%s'",
			purple_buddy_get_name(buddy));
	sipe_core_conf_make_leader(PURPLE_BUDDY_TO_SIPE_CORE_PUBLIC,
				   parameter,
				   purple_buddy_get_name(buddy));
}

static void sipe_purple_buddy_remove_from_chat_cb(PurpleBuddy *buddy,
						  gpointer parameter)
{
	SIPE_DEBUG_INFO("sipe_purple_buddy_remove_from_chat_cb: name '%s'",
			purple_buddy_get_name(buddy));
	sipe_core_conf_remove_from(PURPLE_BUDDY_TO_SIPE_CORE_PUBLIC,
				   parameter,
				   purple_buddy_get_name(buddy));
}

static void sipe_purple_buddy_invite_to_chat_cb(PurpleBuddy *buddy,
						gpointer parameter)
{
	SIPE_DEBUG_INFO("sipe_purple_buddy_invite_to_chat_cb: name '%s'",
			purple_buddy_get_name(buddy));
	sipe_core_chat_invite(PURPLE_BUDDY_TO_SIPE_CORE_PUBLIC,
			      parameter,
			      purple_buddy_get_name(buddy));
}

static void sipe_purple_buddy_new_chat_cb(PurpleBuddy *buddy,
					  SIPE_UNUSED_PARAMETER gpointer parameter)
{
	SIPE_DEBUG_INFO("sipe_purple_buddy_new_chat_cb: name '%s'",
			purple_buddy_get_name(buddy));
	sipe_core_buddy_new_chat(PURPLE_BUDDY_TO_SIPE_CORE_PUBLIC,
				 purple_buddy_get_name(buddy));
}

static void sipe_purple_buddy_make_call_cb(PurpleBuddy *buddy,
					   gpointer parameter)
{
	SIPE_DEBUG_INFO("sipe_purple_buddy_make_call_cb: name '%s'",
			purple_buddy_get_name(buddy));
	sipe_core_buddy_make_call(PURPLE_BUDDY_TO_SIPE_CORE_PUBLIC,
				  parameter);
}

static void sipe_purple_buddy_send_email_cb(PurpleBuddy *buddy,
					    SIPE_UNUSED_PARAMETER gpointer parameter)
{
	SIPE_DEBUG_INFO("sipe_purple_buddy_send_email_cb: name '%s'",
			purple_buddy_get_name(buddy));
	sipe_core_buddy_send_email(PURPLE_BUDDY_TO_SIPE_CORE_PUBLIC,
				   purple_buddy_get_name(buddy));
}

static void sipe_purple_buddy_access_level_help_cb(PurpleBuddy *buddy,
						   SIPE_UNUSED_PARAMETER gpointer parameter)
{
	/**
	 * Translators: replace with URL to localized page
	 * If it doesn't exist copy the original URL
	 */
	purple_notify_uri(purple_account_get_connection(purple_buddy_get_account(buddy)),
			  _("https://sourceforge.net/apps/mediawiki/sipe/index.php?title=Access_Levels"));
}

static void sipe_purple_buddy_change_access_level_cb(PurpleBuddy *buddy,
						     gpointer parameter)
{
	sipe_core_change_access_level_from_container(PURPLE_BUDDY_TO_SIPE_CORE_PUBLIC,
						     parameter);
}

static void sipe_purple_ask_access_domain_cb(PurpleConnection *gc,
					     PurpleRequestFields *fields)
{
	const gchar *domain = purple_request_fields_get_string(fields, "access_domain");
	guint index         =
#if PURPLE_VERSION_CHECK(3,0,0)
		GPOINTER_TO_UINT(
#endif
			purple_request_fields_get_choice(fields, "container_id")
#if PURPLE_VERSION_CHECK(3,0,0)
				)
#endif
		;

	sipe_core_change_access_level_for_domain(PURPLE_GC_TO_SIPE_CORE_PUBLIC,
						 domain,
						 index);
}

static void sipe_purple_buddy_add_new_domain_cb(PurpleBuddy *buddy,
						SIPE_UNUSED_PARAMETER gpointer parameter)
{
	PurpleAccount *account = purple_buddy_get_account(buddy);
	PurpleConnection *gc = purple_account_get_connection(account);
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *g;
	PurpleRequestField *f;

	fields = purple_request_fields_new();

	g = purple_request_field_group_new(NULL);
	f = purple_request_field_string_new("access_domain",
					    _("Domain"),
					    "partner-company.com",
					    FALSE);
	purple_request_field_set_required(f, TRUE);
	purple_request_field_group_add_field(g, f);

	f = purple_request_field_choice_new("container_id",
					    _("Access level"),
					    0);
#if PURPLE_VERSION_CHECK(3,0,0)
	purple_request_field_choice_add(f, _("Personal"), GUINT_TO_POINTER(0));
	purple_request_field_choice_add(f, _("Team"),     GUINT_TO_POINTER(1));
	purple_request_field_choice_add(f, _("Company"),  GUINT_TO_POINTER(2));
	purple_request_field_choice_add(f, _("Public"),   GUINT_TO_POINTER(3));
	purple_request_field_choice_add(f, _("Blocked"),  GUINT_TO_POINTER(4));
	purple_request_field_choice_set_default_value(f,  GUINT_TO_POINTER(3));
#else
	purple_request_field_choice_add(f, _("Personal")); /* index 0 */
	purple_request_field_choice_add(f, _("Team"));
	purple_request_field_choice_add(f, _("Company"));
	purple_request_field_choice_add(f, _("Public"));
	purple_request_field_choice_add(f, _("Blocked")); /* index 4 */
	purple_request_field_choice_set_default_value(f, 3); /* index */
#endif
	purple_request_field_set_required(f, TRUE);
	purple_request_field_group_add_field(g, f);

	purple_request_fields_add_group(fields, g);

	purple_request_fields(gc, _("Add new domain"),
			      _("Add new domain"), NULL, fields,
			      _("Add"), G_CALLBACK(sipe_purple_ask_access_domain_cb),
			      _("Cancel"), NULL,
#if PURPLE_VERSION_CHECK(3,0,0)
			      purple_request_cpar_from_account(account),
#else
			      account, NULL, NULL,
#endif
			      gc);
}

static void sipe_purple_buddy_share_application_cb(PurpleBuddy *buddy,
						   SIPE_UNUSED_PARAMETER gpointer parameter)
{
	SIPE_DEBUG_INFO("sipe_purple_buddy_share_application_cb: name '%s'",
			purple_buddy_get_name(buddy));

	sipe_core_share_application(PURPLE_BUDDY_TO_SIPE_CORE_PUBLIC,
				    purple_buddy_get_name(buddy));
}

typedef void (*buddy_menu_callback)(PurpleBuddy *buddy,
				    gpointer parameter);
static const buddy_menu_callback callback_map[SIPE_BUDDY_MENU_TYPES] = {
/* SIPE_BUDDY_MENU_MAKE_CHAT_LEADER    */ sipe_purple_buddy_make_chat_leader_cb,
/* SIPE_BUDDY_MENU_REMOVE_FROM_CHAT    */ sipe_purple_buddy_remove_from_chat_cb,
/* SIPE_BUDDY_MENU_INVITE_TO_CHAT      */ sipe_purple_buddy_invite_to_chat_cb,
/* SIPE_BUDDY_MENU_NEW_CHAT            */ sipe_purple_buddy_new_chat_cb,
/* SIPE_BUDDY_MENU_MAKE_CALL           */ sipe_purple_buddy_make_call_cb,
/* SIPE_BUDDY_MENU_SEND_EMAIL          */ sipe_purple_buddy_send_email_cb,
/* SIPE_BUDDY_MENU_ACCESS_LEVEL_HELP   */ sipe_purple_buddy_access_level_help_cb,
/* SIPE_BUDDY_MENU_CHANGE_ACCESS_LEVEL */ sipe_purple_buddy_change_access_level_cb,
/* SIPE_BUDDY_MENU_ADD_NEW_DOMAIN      */ sipe_purple_buddy_add_new_domain_cb,
/* SIPE_BUDDY_MENU_SHARE_APPLICATION   */ sipe_purple_buddy_share_application_cb,
};

struct sipe_backend_buddy_menu *sipe_backend_buddy_menu_start(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public)
{
	return(NULL);
}

struct sipe_backend_buddy_menu *sipe_backend_buddy_menu_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
							    struct sipe_backend_buddy_menu *menu,
							    const gchar *label,
							    enum sipe_buddy_menu_type type,
							    gpointer parameter)
{
	return((struct sipe_backend_buddy_menu *)
	       g_list_prepend((GList *) menu,
			      purple_menu_action_new(label,
						     PURPLE_CALLBACK(callback_map[type]),
						     parameter, NULL)));
}

struct sipe_backend_buddy_menu *sipe_backend_buddy_menu_separator(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
								  struct sipe_backend_buddy_menu *menu,
								  const gchar *label)
{
	return((struct sipe_backend_buddy_menu *)
	       g_list_prepend((GList *) menu,
			      purple_menu_action_new(label, NULL, NULL, NULL)));
}

struct sipe_backend_buddy_menu *sipe_backend_buddy_sub_menu_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
								struct sipe_backend_buddy_menu *menu,
								const gchar *label,
								struct sipe_backend_buddy_menu *sub)
{
	return((struct sipe_backend_buddy_menu *)
	       g_list_prepend((GList *) menu,
			      purple_menu_action_new(label,
						     NULL,
						     NULL,
						     g_list_reverse((GList *) sub))));
}

static void sipe_purple_buddy_copy_to_cb(PurpleBlistNode *node,
					 const gchar *group_name)
{
	struct sipe_core_public *sipe_public;
	PurpleBuddy *buddy = (PurpleBuddy *)node;
	PurpleGroup *group;
	PurpleBuddy *clone;

	g_return_if_fail(PURPLE_IS_BUDDY(node));

	sipe_public = PURPLE_BUDDY_TO_SIPE_CORE_PUBLIC;
	group       = purple_blist_find_group(group_name);

	SIPE_DEBUG_INFO("sipe_purple_buddy_copy_to_cb: copying %s to %s",
			purple_buddy_get_name(buddy), group_name);

	clone = purple_blist_find_buddy_in_group(purple_buddy_get_account(buddy),
						 purple_buddy_get_name(buddy),
						 group);
	if (!clone) {
		clone = sipe_backend_buddy_add(sipe_public,
					       purple_buddy_get_name(buddy),
#if PURPLE_VERSION_CHECK(3,0,0)
					       purple_buddy_get_local_alias(buddy),
#else
					       buddy->alias,
#endif
					       purple_group_get_name(group));
		if (clone) {
			const gchar *tmp;
			const gchar *key;
			const PurpleStatus *status = purple_presence_get_active_status(purple_buddy_get_presence(buddy));

			tmp = purple_buddy_get_server_alias(buddy);
			if (tmp) purple_buddy_set_server_alias(clone, tmp);

			key = buddy_info_property(SIPE_BUDDY_INFO_EMAIL);
			tmp = purple_blist_node_get_string(&buddy->node, key);
			if (tmp) purple_blist_node_set_string(&clone->node,
							      key,
							      tmp);

			tmp = purple_status_get_id(status);
			purple_presence_set_status_active(purple_buddy_get_presence(clone),
							  tmp,
							  TRUE);

			/* update UI */
			purple_protocol_got_user_status(purple_buddy_get_account(clone),
							purple_buddy_get_name(clone),
							tmp,
							SIPE_PURPLE_STATUS_ATTR_ID_MESSAGE, tmp,
							NULL);
		}
	}

	if (clone && group)
		sipe_core_buddy_add(sipe_public,
				    purple_buddy_get_name(clone),
				    purple_group_get_name(group));
}

static GList *sipe_purple_copy_to_menu(GList *menu,
				       PurpleBuddy *buddy)
{
	GList *menu_groups = NULL;
	PurpleGroup *gr_parent = purple_buddy_get_group(buddy);
	PurpleBlistNode *g_node;

	for (g_node = purple_blist_get_root(); g_node; g_node = g_node->next) {
		PurpleGroup *group = (PurpleGroup *)g_node;
		PurpleMenuAction *act;

		if ((!PURPLE_IS_GROUP(g_node)) ||
		    (group == gr_parent)       ||
		    purple_blist_find_buddy_in_group(purple_buddy_get_account(buddy),
						     purple_buddy_get_name(buddy),
						     group))
			continue;

		act = purple_menu_action_new(purple_group_get_name(group),
					     PURPLE_CALLBACK(sipe_purple_buddy_copy_to_cb),
					     (gpointer) purple_group_get_name(group),
					     NULL);
		menu_groups = g_list_prepend(menu_groups, act);
	}

	if (menu_groups)
		menu = g_list_prepend(menu,
				      purple_menu_action_new(_("Copy to"),
							     NULL,
							     NULL,
							     g_list_reverse(menu_groups)));

	return(menu);
}

GList *sipe_purple_buddy_menu(PurpleBuddy *buddy)
{
	struct sipe_core_public *sipe_public = PURPLE_BUDDY_TO_SIPE_CORE_PUBLIC;
	GList *menu = (GList *) sipe_core_buddy_create_menu(sipe_public,
							    purple_buddy_get_name(buddy),
							    NULL);
	menu = sipe_purple_copy_to_menu(menu, buddy);
	return(g_list_reverse(menu));
}


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
