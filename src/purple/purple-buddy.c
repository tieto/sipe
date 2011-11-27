/**
 * @file purple-buddy.c
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include "purple-private.h"

#include "blist.h"
#include "privacy.h"

#include "sipe-common.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-nls.h"

static GHashTable *info_to_property_table = NULL;

/** Property names to store in blist.xml */
#define ALIAS_PROP			"alias"
#define EMAIL_PROP			"email"
#define PHONE_PROP			"phone"
#define PHONE_DISPLAY_PROP		"phone-display"
#define PHONE_MOBILE_PROP		"phone-mobile"
#define PHONE_MOBILE_DISPLAY_PROP	"phone-mobile-display"
#define PHONE_HOME_PROP			"phone-home"
#define PHONE_HOME_DISPLAY_PROP		"phone-home-display"
#define PHONE_OTHER_PROP		"phone-other"
#define PHONE_OTHER_DISPLAY_PROP	"phone-other-display"
#define PHONE_CUSTOM1_PROP		"phone-custom1"
#define PHONE_CUSTOM1_DISPLAY_PROP	"phone-custom1-display"
#define SITE_PROP			"site"
#define COMPANY_PROP			"company"
#define DEPARTMENT_PROP			"department"
#define TITLE_PROP			"title"
#define OFFICE_PROP			"office"
/** implies work address */
#define ADDRESS_STREET_PROP		"address-street"
#define ADDRESS_CITY_PROP		"address-city"
#define ADDRESS_STATE_PROP		"address-state"
#define ADDRESS_ZIPCODE_PROP		"address-zipcode"
#define ADDRESS_COUNTRYCODE_PROP	"address-country-code"

#define ADD_PROP(key,value) g_hash_table_insert(info_to_property_table, (gpointer)key, value)

static void
init_property_hash(void)
{
	info_to_property_table = g_hash_table_new(NULL, NULL);

	ADD_PROP(SIPE_BUDDY_INFO_DISPLAY_NAME         , ALIAS_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_EMAIL                , EMAIL_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_WORK_PHONE           , PHONE_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_WORK_PHONE_DISPLAY   , PHONE_DISPLAY_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_SITE                 , SITE_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_COMPANY              , COMPANY_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_DEPARTMENT           , DEPARTMENT_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_JOB_TITLE            , TITLE_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_OFFICE               , OFFICE_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_STREET               , ADDRESS_STREET_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_CITY                 , ADDRESS_CITY_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_STATE                , ADDRESS_STATE_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_ZIPCODE              , ADDRESS_ZIPCODE_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_COUNTRY              , ADDRESS_COUNTRYCODE_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_MOBILE_PHONE         , PHONE_MOBILE_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_MOBILE_PHONE_DISPLAY , PHONE_MOBILE_DISPLAY_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_HOME_PHONE           , PHONE_HOME_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_HOME_PHONE_DISPLAY   , PHONE_HOME_DISPLAY_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_OTHER_PHONE          , PHONE_OTHER_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_OTHER_PHONE_DISPLAY  , PHONE_OTHER_DISPLAY_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_CUSTOM1_PHONE        , PHONE_CUSTOM1_PROP);
	ADD_PROP(SIPE_BUDDY_INFO_CUSTOM1_PHONE_DISPLAY, PHONE_CUSTOM1_DISPLAY_PROP);
}

static gchar *
sipe_buddy_info_to_purple_property(sipe_buddy_info_fields info)
{
	if (!info_to_property_table)
		init_property_hash();
	return g_hash_table_lookup(info_to_property_table, (gpointer)info);
}

sipe_backend_buddy sipe_backend_buddy_find(struct sipe_core_public *sipe_public,
					   const gchar *buddy_name,
					   const gchar *group_name)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleGroup *purple_group;

	if (group_name)
	{
		purple_group = purple_find_group(group_name);
		if (!purple_group)
			return NULL;

		return purple_find_buddy_in_group(purple_private->account,
						  buddy_name,
						  purple_group);
	} else {
		return purple_find_buddy(purple_private->account,
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

	return purple_find_buddies(purple_private->account, buddy_name);
}

gchar* sipe_backend_buddy_get_name(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				   const sipe_backend_buddy who)
{
	return g_strdup(((PurpleBuddy*)who)->name);
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

gchar* sipe_backend_buddy_get_group_name(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					 const sipe_backend_buddy who)
{
	return g_strdup(purple_buddy_get_group((PurpleBuddy*)who)->name);
}

void sipe_backend_buddy_set_alias(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				  const sipe_backend_buddy who,
				  const gchar *alias)
{
	purple_blist_alias_buddy(who, alias);
}

void sipe_backend_buddy_set_server_alias(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					 const sipe_backend_buddy who,
					 const gchar *alias)
{
	purple_blist_server_alias_buddy(who, alias);
}

gchar* sipe_backend_buddy_get_string(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				     sipe_backend_buddy buddy,
				     const sipe_buddy_info_fields key)
{
	PurpleBuddy *b = (PurpleBuddy*) buddy;
	return g_strdup(purple_blist_node_get_string(&b->node, sipe_buddy_info_to_purple_property(key)));
}

void sipe_backend_buddy_set_string(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				   sipe_backend_buddy buddy,
				   const sipe_buddy_info_fields key,
				   const gchar *val)
{
	PurpleBuddy *b = (PurpleBuddy*) buddy;
	purple_blist_node_set_string(&b->node, sipe_buddy_info_to_purple_property(key), val);
}

sipe_backend_buddy sipe_backend_buddy_add(struct sipe_core_public *sipe_public,
					  const gchar *name,
					  const gchar *alias,
					  const gchar *groupname)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;
	PurpleBuddy *b;
	PurpleGroup *purple_group = purple_find_group(groupname);

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
		auth_cb,
		deny_cb,
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

	return !purple_privacy_check(purple_private->account, who);
}

void sipe_backend_buddy_set_blocked_status(struct sipe_core_public *sipe_public,
				      const gchar *who,
				      gboolean blocked)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;

	if (blocked) {
		purple_privacy_deny_add(purple_private->account, who, TRUE);
	} else {
		purple_privacy_deny_remove(purple_private->account, who, TRUE);
	}

	/* stupid workaround to make pidgin re-render screen to reflect our changes */
	{
		PurpleBuddy *pbuddy = purple_find_buddy(purple_private->account, who);
		const PurplePresence *presence = purple_buddy_get_presence(pbuddy);
		const PurpleStatus *pstatus = purple_presence_get_active_status(presence);

		SIPE_DEBUG_INFO_NOFORMAT("sipe_backend_buddy_set_blocked_status: forcefully refreshing screen.");
		sipe_core_buddy_got_status(sipe_public, who, purple_status_get_id(pstatus));
	}

}

void sipe_backend_buddy_set_status(struct sipe_core_public *sipe_public,
				   const gchar *who,
				   const gchar *status_id)
{
	struct sipe_backend_private *purple_private = sipe_public->backend_private;

	purple_prpl_got_user_status(purple_private->account, who, status_id, NULL);
}

gboolean sipe_backend_buddy_group_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				      const gchar *group_name)
{
	PurpleGroup * purple_group = purple_find_group(group_name);
	if (!purple_group) {
		purple_group = purple_group_new(group_name);
		purple_blist_add_group(purple_group, NULL);
	}

	return (purple_group != NULL);
}

void sipe_purple_group_buddy(PurpleConnection *gc,
			     const char *who,
			     const char *old_group_name,
			     const char *new_group_name)
{
	sipe_core_buddy_group(PURPLE_GC_TO_SIPE_CORE_PUBLIC, who, old_group_name, new_group_name);
}


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
