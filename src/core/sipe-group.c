/**
 * @file sipe-group.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-2013 SIPE Project <http://sipe.sourceforge.net/>
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

#include "sipmsg.h"
#include "sip-soap.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-buddy.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-group.h"
#include "sipe-nls.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

struct sipe_groups {
	GSList *list;
};

struct group_user_context {
	gchar *group_name;
	gchar *user_name;
};

static void
sipe_group_context_destroy(gpointer data)
{
	struct group_user_context *ctx = data;
	g_free(ctx->group_name);
	g_free(ctx->user_name);
	g_free(ctx);
}

static gboolean
process_add_group_response(struct sipe_core_private *sipe_private,
			   struct sipmsg *msg,
			   struct transaction *trans)
{
	if (msg->response == 200) {
		struct sipe_group *group;
		struct group_user_context *ctx = trans->payload->data;
		sipe_xml *xml;
		const sipe_xml *node;
		char *group_id;
		struct sipe_buddy *buddy;

		xml = sipe_xml_parse(msg->body, msg->bodylen);
		if (!xml) {
			return FALSE;
		}

		node = sipe_xml_child(xml, "Body/addGroup/groupID");
		if (!node) {
			sipe_xml_free(xml);
			return FALSE;
		}

		group_id = sipe_xml_data(node);
		if (!group_id) {
			sipe_xml_free(xml);
			return FALSE;
		}

		group = g_new0(struct sipe_group, 1);
		group->id = (int)g_ascii_strtod(group_id, NULL);
		g_free(group_id);
		group->name = g_strdup(ctx->group_name);

		sipe_group_add(sipe_private, group);

		if (ctx->user_name) {
			buddy = sipe_buddy_find_by_uri(sipe_private,
						       ctx->user_name);
			if (buddy) {
				buddy->groups = sipe_utils_slist_insert_unique_sorted(buddy->groups,
										      group,
										      (GCompareFunc)sipe_group_compare,
										      NULL);
				sipe_group_update_buddy(sipe_private, buddy);
			}
		}

		sipe_xml_free(xml);
		return TRUE;
	}
	return FALSE;
}

int
sipe_group_compare(struct sipe_group *group1, struct sipe_group *group2) {
	return group1->id - group2->id;
}

struct sipe_group*
sipe_group_find_by_id(struct sipe_core_private *sipe_private,
		      int id)
{
	struct sipe_group *group;
	GSList *entry;

	if (!sipe_private)
		return NULL;

	entry = sipe_private->groups->list;
	while (entry) {
		group = entry->data;
		if (group->id == id) {
			return group;
		}
		entry = entry->next;
	}
	return NULL;
}

struct sipe_group*
sipe_group_find_by_name(struct sipe_core_private *sipe_private,
			const gchar * name)
{
	struct sipe_group *group;
	GSList *entry;

	if (!sipe_private || !name)
		return NULL;

	entry = sipe_private->groups->list;
	while (entry) {
		group = entry->data;
		if (sipe_strequal(group->name, name)) {
			return group;
		}
		entry = entry->next;
	}
	return NULL;
}

void
sipe_group_create(struct sipe_core_private *sipe_private,
		  const gchar *name,
		  const gchar *who)
{
	struct transaction_payload *payload = g_new0(struct transaction_payload, 1);
	struct group_user_context *ctx = g_new0(struct group_user_context, 1);
	const gchar *soap_name = sipe_strequal(name, _("Other Contacts")) ? "~" : name;
	gchar *request;
	ctx->group_name = g_strdup(name);
	ctx->user_name = g_strdup(who);
	payload->destroy = sipe_group_context_destroy;
	payload->data = ctx;

	/* soap_name can contain restricted characters */
	request = g_markup_printf_escaped("<m:name>%s</m:name>"
					  "<m:externalURI />",
					  soap_name);
	sip_soap_request_cb(sipe_private,
			    "addGroup",
			    request,
			    process_add_group_response,
			    payload);
	g_free(request);
}

gboolean sipe_group_rename(struct sipe_core_private *sipe_private,
			   struct sipe_group *group,
			   const gchar *name)
{
	gboolean renamed = sipe_backend_buddy_group_rename(SIPE_CORE_PUBLIC,
							   group->name,
							   name);
	if (renamed) {
		g_free(group->name);
		group->name = g_strdup(name);
	}
	return(renamed);
}

void
sipe_group_add(struct sipe_core_private *sipe_private,
	       struct sipe_group * group)
{
	if (sipe_backend_buddy_group_add(SIPE_CORE_PUBLIC,group->name))
	{
		SIPE_DEBUG_INFO("added group %s (id %d)", group->name, group->id);
		sipe_private->groups->list = g_slist_append(sipe_private->groups->list,
							    group);
	}
	else
	{
		SIPE_DEBUG_INFO("did not add group %s", group->name ? group->name : "");
	}
}

static void group_free(struct sipe_core_private *sipe_private,
		       struct sipe_group *group)
{
	sipe_private->groups->list = g_slist_remove(sipe_private->groups->list,
						    group);
	g_free(group->name);
	g_free(group);
}

void sipe_group_remove(struct sipe_core_private *sipe_private,
		       struct sipe_group *group)
{
	if (group) {
		SIPE_DEBUG_INFO("removing group %s (id %d)", group->name, group->id);
		sipe_backend_buddy_group_remove(SIPE_CORE_PUBLIC, group->name);
		group_free(sipe_private, group);
	}
}

void
sipe_core_group_rename(struct sipe_core_public *sipe_public,
		       const gchar *old_name,
		       const gchar *new_name)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_group *s_group = sipe_group_find_by_name(sipe_private, old_name);

	if (s_group) {
		gchar *request;
		SIPE_DEBUG_INFO("Renaming group %s to %s", old_name, new_name);
		/* new_name can contain restricted characters */
		request = g_markup_printf_escaped("<m:groupID>%d</m:groupID>"
						  "<m:name>%s</m:name>"
						  "<m:externalURI />",
						  s_group->id, new_name);
		sip_soap_request(sipe_private,
				 "modifyGroup",
				 request);
		g_free(request);

		g_free(s_group->name);
		s_group->name = g_strdup(new_name);
	} else {
		SIPE_DEBUG_INFO("Cannot find group %s to rename", old_name);
	}
}

void
sipe_core_group_remove(struct sipe_core_public *sipe_public,
		       const gchar *name)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_group *s_group = sipe_group_find_by_name(sipe_private, name);

	if (s_group) {
		gchar *request;
		SIPE_DEBUG_INFO("Deleting group %s", name);
		request = g_strdup_printf("<m:groupID>%d</m:groupID>",
					  s_group->id);
		sip_soap_request(sipe_private,
				 "deleteGroup",
				 request);
		g_free(request);

		group_free(sipe_private, s_group);
	} else {
		SIPE_DEBUG_INFO("Cannot find group %s to delete", name);
	}
}

/**
 * Returns string like "2 4 7 8" - group ids buddy belong to.
 */
static gchar *sipe_get_buddy_groups_string(struct sipe_buddy *buddy)
{
	int i = 0;
	gchar *res;
	//creating array from GList, converting int to gchar*
	gchar **ids_arr = g_new(gchar *, g_slist_length(buddy->groups) + 1);
	GSList *entry = buddy->groups;

	if (!ids_arr) return NULL;

	while (entry) {
		struct sipe_group * group = entry->data;
		ids_arr[i] = g_strdup_printf("%d", group->id);
		entry = entry->next;
		i++;
	}
	ids_arr[i] = NULL;
	res = g_strjoinv(" ", ids_arr);
	g_strfreev(ids_arr);
	return res;
}

/**
 * Sends buddy update to server
 */
static void send_buddy_update(struct sipe_core_private *sipe_private,
			      struct sipe_buddy *buddy,
			      const gchar *alias)
{
	gchar *groups = sipe_get_buddy_groups_string(buddy);

	if (groups) {
		gchar *request;
		SIPE_DEBUG_INFO("Saving buddy %s with alias '%s' and groups '%s'",
				buddy->name, alias, groups);

		/* alias can contain restricted characters */
		request = g_markup_printf_escaped("<m:displayName>%s</m:displayName>"
						  "<m:groups>%s</m:groups>"
						  "<m:subscribed>true</m:subscribed>"
						  "<m:URI>%s</m:URI>"
						  "<m:externalURI />",
						  alias, groups, buddy->name);
		g_free(groups);

		sip_soap_request(sipe_private,
				 "setContact",
				 request);
		g_free(request);
	}
}

/* indicates that buddy information on the server needs updating */
void sipe_group_update_buddy(struct sipe_core_private *sipe_private,
			     struct sipe_buddy *buddy)
{
	if (buddy) {
		sipe_backend_buddy backend_buddy = sipe_backend_buddy_find(SIPE_CORE_PUBLIC,
									   buddy->name,
									   NULL);
		if (backend_buddy) {
			gchar *alias = sipe_backend_buddy_get_alias(SIPE_CORE_PUBLIC,
								    backend_buddy);
			send_buddy_update(sipe_private, buddy, alias);
			g_free(alias);
		}
	}
}

void sipe_core_group_set_alias(struct sipe_core_public *sipe_public,
			       const gchar *who,
			       const gchar *alias)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_buddy *buddy = sipe_buddy_find_by_uri(sipe_private,
							  who);

	if (buddy)
		send_buddy_update(sipe_private, buddy, alias);
}

struct sipe_group *sipe_group_first(struct sipe_core_private *sipe_private)
{
	return(sipe_private->groups->list ? sipe_private->groups->list->data : NULL);
}

guint sipe_group_count(struct sipe_core_private *sipe_private)
{
	return(g_slist_length(sipe_private->groups->list));
}

void sipe_group_init(struct sipe_core_private *sipe_private)
{
	sipe_private->groups = g_new0(struct sipe_groups, 1);
}

void sipe_group_free(struct sipe_core_private *sipe_private)
{
	GSList *entry;

	while ((entry = sipe_private->groups->list) != NULL)
		group_free(sipe_private, entry->data);

	g_free(sipe_private->groups);
	sipe_private->groups = NULL;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
