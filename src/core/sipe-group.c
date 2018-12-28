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
#include "sipe-ucs.h"
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

		group = sipe_group_add(sipe_private,
				       ctx->group_name,
				       NULL,
				       NULL,
				       g_ascii_strtoull(group_id, NULL, 10));
		g_free(group_id);

		if (group) {
			struct sipe_buddy *buddy = sipe_buddy_find_by_uri(sipe_private,
									  ctx->user_name);
			if (buddy) {
				sipe_buddy_insert_group(buddy, group);
				sipe_group_update_buddy(sipe_private, buddy);
			}
		}

		sipe_xml_free(xml);
		return TRUE;
	}
	return FALSE;
}

struct sipe_group*
sipe_group_find_by_id(struct sipe_core_private *sipe_private,
		      guint id)
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
		  struct sipe_ucs_transaction *trans,
		  const gchar *name,
		  const gchar *who)
{
	/* "trans" is always set for UCS code paths, otherwise NULL */
	if (trans) {
		sipe_ucs_group_create(sipe_private,
				      trans,
				      name,
				      who);
	} else {
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

struct sipe_group *sipe_group_add(struct sipe_core_private *sipe_private,
				  const gchar *name,
				  const gchar *exchange_key,
				  const gchar *change_key,
				  guint id)
{
	struct sipe_group *group = NULL;

	if (!is_empty(name)) {
		group = sipe_group_find_by_name(sipe_private, name);

		if (!group &&
		    sipe_backend_buddy_group_add(SIPE_CORE_PUBLIC, name)) {

			group       = g_new0(struct sipe_group, 1);
			group->name = g_strdup(name);
			group->id   = id;

			if (exchange_key)
				group->exchange_key = g_strdup(exchange_key);
			if (change_key)
				group->change_key = g_strdup(change_key);

			sipe_private->groups->list = g_slist_append(sipe_private->groups->list,
								    group);

			SIPE_DEBUG_INFO("sipe_group_add: created backend group '%s' with id %d",
					group->name, group->id);
		} else {
			SIPE_DEBUG_INFO("sipe_group_add: backend group '%s' already exists",
					name ? name : "");
			if (group)
				group->is_obsolete = FALSE;
		}
	}

	return(group);
}

static void group_free(struct sipe_core_private *sipe_private,
		       struct sipe_group *group)
{
	sipe_private->groups->list = g_slist_remove(sipe_private->groups->list,
						    group);
	g_free(group->name);
	g_free(group->exchange_key);
	g_free(group->change_key);
	g_free(group);
}

void sipe_group_remove(struct sipe_core_private *sipe_private,
		       struct sipe_group *group)
{
	if (group) {
		SIPE_DEBUG_INFO("sipe_group_remove: %s (id %d)", group->name, group->id);
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
		SIPE_DEBUG_INFO("sipe_core_group_rename: from '%s' to '%s'", old_name, new_name);

		if (sipe_ucs_is_migrated(sipe_private)) {
			sipe_ucs_group_rename(sipe_private,
					      s_group,
					      new_name);
		} else {
			/* new_name can contain restricted characters */
			gchar *request = g_markup_printf_escaped("<m:groupID>%d</m:groupID>"
								 "<m:name>%s</m:name>"
								 "<m:externalURI />",
								 s_group->id,
								 new_name);
			sip_soap_request(sipe_private,
					 "modifyGroup",
					 request);
			g_free(request);
		}

		g_free(s_group->name);
		s_group->name = g_strdup(new_name);
	} else {
		SIPE_DEBUG_INFO("sipe_core_group_rename: cannot find group '%s'", old_name);
	}
}

void
sipe_core_group_remove(struct sipe_core_public *sipe_public,
		       const gchar *name)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_group *s_group = sipe_group_find_by_name(sipe_private, name);

	if (s_group) {

		/* ignore backend events while deleting obsoleted groups */
		if (!s_group->is_obsolete) {
			SIPE_DEBUG_INFO("sipe_core_group_remove: delete '%s'", name);

			if (sipe_ucs_is_migrated(sipe_private)) {
				sipe_ucs_group_remove(sipe_private,
						      s_group);
			} else {
				gchar *request = g_strdup_printf("<m:groupID>%d</m:groupID>",
								 s_group->id);
				sip_soap_request(sipe_private,
						 "deleteGroup",
						 request);
				g_free(request);
			}

			group_free(sipe_private, s_group);
		}
	} else {
		SIPE_DEBUG_INFO("sipe_core_group_remove: cannot find group '%s'", name);
	}
}

/**
 * Sends buddy update to server
 *
 * NOTE: must not be called when contact list has been migrated to UCS
 */
static void send_buddy_update(struct sipe_core_private *sipe_private,
			      struct sipe_buddy *buddy,
			      const gchar *alias)
{
	gchar *groups = sipe_buddy_groups_string(buddy);

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
						  alias ? alias : "",
						  groups,
						  buddy->name);
		g_free(groups);

		sip_soap_request(sipe_private,
				 "setContact",
				 request);
		g_free(request);
	}
}

/**
 * indicates that buddy information on the server needs updating
 *
 * NOTE: must not be called when contact list has been migrated to UCS
 */
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

/**
 * @param alias new alias (may be @c NULL)
 */
void sipe_core_group_set_alias(struct sipe_core_public *sipe_public,
			       const gchar *who,
			       const gchar *alias)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;

	/* UCS does not support setting of display name/alias */
	if (sipe_ucs_is_migrated(sipe_private))
		SIPE_DEBUG_INFO("sipe_core_group_set_alias: not supported for UCS (uri '%s' alias '%s')",
				who, alias ? alias : "<UNDEFINED>");
	else {
		struct sipe_buddy *buddy = sipe_buddy_find_by_uri(sipe_private,
								  who);

		if (buddy)
			send_buddy_update(sipe_private, buddy, alias);
	}
}

void sipe_group_update_start(struct sipe_core_private *sipe_private)
{
	GSList *entry = sipe_private->groups->list;

	while (entry) {
		((struct sipe_group *) entry->data)->is_obsolete = TRUE;
		entry = entry->next;
	}
}

void sipe_group_update_finish(struct sipe_core_private *sipe_private)
{
	GSList *entry = sipe_private->groups->list;

	while (entry) {
		struct sipe_group *group = entry->data;

		/* next group entry */
		entry = entry->next;

		if (group->is_obsolete)
			sipe_group_remove(sipe_private, group);
	}
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
