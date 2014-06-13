/**
 * @file sipe-ucs.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2013-2014 SIPE Project <http://sipe.sourceforge.net/>
 *
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
 *
 *
 * Implementation for Unified Contact Store [MS-OXWSCOS]
 *  <http://msdn.microsoft.com/en-us/library/jj194130.aspx>
 */

#include <string.h>

#include <glib.h>
#include <time.h>

#include "sipe-backend.h"
#include "sipe-buddy.h"
#include "sipe-common.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-digest.h"
#include "sipe-ews-autodiscover.h"
#include "sipe-group.h"
#include "sipe-http.h"
#include "sipe-subscriptions.h"
#include "sipe-ucs.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

struct sipe_ucs_transaction {
	GSList *pending_requests;
};

typedef void (ucs_callback)(struct sipe_core_private *sipe_private,
			    struct sipe_ucs_transaction *trans,
			    const sipe_xml *body,
			    gpointer callback_data);

struct ucs_request {
	gchar *body;
	ucs_callback *cb;
	gpointer cb_data;
	struct sipe_ucs_transaction *transaction;
	struct sipe_http_request *request;
};

struct sipe_ucs {
	struct ucs_request *active_request;
	GSList *transactions;
	GSList *default_transaction;
	gchar *ews_url;
	time_t last_response;
	guint group_id;
	gboolean migrated;
	gboolean shutting_down;
};

static void sipe_ucs_request_free(struct sipe_core_private *sipe_private,
				  struct ucs_request *data)
{
	struct sipe_ucs *ucs = sipe_private->ucs;
	struct sipe_ucs_transaction *trans = data->transaction;

	/* remove request from transaction */
	trans->pending_requests = g_slist_remove(trans->pending_requests,
						 data);
	sipe_private->ucs->active_request = NULL;

	/* remove completed transactions (except default transaction) */
	if (!trans->pending_requests &&
	    (trans != ucs->default_transaction->data)) {
		ucs->transactions = g_slist_remove(ucs->transactions,
						   trans);
		g_free(trans);
	}

	if (data->request)
		sipe_http_request_cancel(data->request);
	if (data->cb)
		/* Callback: aborted */
		(*data->cb)(sipe_private, NULL, NULL, data->cb_data);
	g_free(data->body);
	g_free(data);
}

static void sipe_ucs_next_request(struct sipe_core_private *sipe_private);
static void sipe_ucs_http_response(struct sipe_core_private *sipe_private,
				   guint status,
				   SIPE_UNUSED_PARAMETER GSList *headers,
				   const gchar *body,
				   gpointer callback_data)
{
	struct ucs_request *data = callback_data;

	SIPE_DEBUG_INFO("sipe_ucs_http_response: code %d", status);
	data->request = NULL;

	if ((status == SIPE_HTTP_STATUS_OK) && body) {
		sipe_xml *xml = sipe_xml_parse(body, strlen(body));
		const sipe_xml *soap_body = sipe_xml_child(xml, "Body");
		/* Callback: success */
		(*data->cb)(sipe_private,
			    data->transaction,
			    soap_body,
			    data->cb_data);
		sipe_xml_free(xml);
	} else {
		/* Callback: failed */
		(*data->cb)(sipe_private, NULL, NULL, data->cb_data);
	}

	/* already been called */
	data->cb = NULL;

	sipe_ucs_request_free(sipe_private, data);
	sipe_ucs_next_request(sipe_private);
}

static void sipe_ucs_next_request(struct sipe_core_private *sipe_private)
{
	struct sipe_ucs *ucs = sipe_private->ucs;
	struct sipe_ucs_transaction *trans;

	if (ucs->active_request || ucs->shutting_down || !ucs->ews_url)
		return;

	trans = ucs->transactions->data;
	while (trans->pending_requests) {
		struct ucs_request *data = trans->pending_requests->data;
		gchar *soap = g_strdup_printf("<?xml version=\"1.0\"?>\r\n"
					      "<soap:Envelope"
					      " xmlns:m=\"http://schemas.microsoft.com/exchange/services/2006/messages\""
					      " xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\""
					      " xmlns:t=\"http://schemas.microsoft.com/exchange/services/2006/types\""
					      " >"
					      " <soap:Header>"
					      "  <t:RequestServerVersion Version=\"Exchange2013\" />"
					      " </soap:Header>"
					      " <soap:Body>"
					      "  %s"
					      " </soap:Body>"
					      "</soap:Envelope>",
					      data->body);
		struct sipe_http_request *request = sipe_http_request_post(sipe_private,
									   ucs->ews_url,
									   NULL,
									   soap,
									   "text/xml; charset=UTF-8",
									   sipe_ucs_http_response,
									   data);
		g_free(soap);

		if (request) {
			g_free(data->body);
			data->body    = NULL;
			data->request = request;

			ucs->active_request = data;

			sipe_core_email_authentication(sipe_private,
						       request);
			sipe_http_request_allow_redirect(request);
			sipe_http_request_ready(request);

			break;
		} else {
			SIPE_DEBUG_ERROR_NOFORMAT("sipe_ucs_next_request: failed to create HTTP connection");
			sipe_ucs_request_free(sipe_private, data);
		}
	}
}

static gboolean sipe_ucs_http_request(struct sipe_core_private *sipe_private,
				      struct sipe_ucs_transaction *trans,
				      gchar *body,  /* takes ownership */
				      ucs_callback *callback,
				      gpointer callback_data)
{
	struct sipe_ucs *ucs = sipe_private->ucs;

	if (!ucs || ucs->shutting_down) {
		SIPE_DEBUG_ERROR("sipe_ucs_http_request: new UCS request during shutdown: THIS SHOULD NOT HAPPEN! Debugging information:\n"
				 "Body:   %s\n",
				 body ? body : "<EMPTY>");
		g_free(body);
		return(FALSE);

	} else {
		struct ucs_request *data = g_new0(struct ucs_request, 1);

		data->cb      = callback;
		data->cb_data = callback_data;
		data->body    = body;

		if (!trans)
			trans = ucs->default_transaction->data;
		data->transaction = trans;
		trans->pending_requests = g_slist_append(trans->pending_requests,
							 data);

		sipe_ucs_next_request(sipe_private);
		return(TRUE);
	}
}

struct sipe_ucs_transaction *sipe_ucs_transaction(struct sipe_core_private *sipe_private)
{
	struct sipe_ucs *ucs = sipe_private->ucs;
	struct sipe_ucs_transaction *trans;

	if (!ucs)
		return(NULL);

	/* always insert new transactions before default transaction */
	trans = g_new0(struct sipe_ucs_transaction, 1);
	ucs->transactions = g_slist_insert_before(ucs->transactions,
						  ucs->default_transaction,
						  trans);

	return(trans);
}

static void sipe_ucs_get_user_photo_response(struct sipe_core_private *sipe_private,
					     SIPE_UNUSED_PARAMETER struct sipe_ucs_transaction *trans,
					     const sipe_xml *body,
					     gpointer callback_data)
{
	gchar *uri = callback_data;
	const sipe_xml *node = sipe_xml_child(body,
					      "GetUserPhotoResponse/PictureData");

	if (node) {
		gchar *base64;
		gsize photo_size;
		guchar *photo;
		guchar digest[SIPE_DIGEST_SHA1_LENGTH];
		gchar *digest_string;

		/* decode photo data */
		base64 = sipe_xml_data(node);
		photo = g_base64_decode(base64, &photo_size);
		g_free(base64);

		/* EWS doesn't provide a hash -> calculate SHA-1 digest */
		sipe_digest_sha1(photo, photo_size, digest);
		digest_string = buff_to_hex_str(digest,
						SIPE_DIGEST_SHA1_LENGTH);

		/* backend frees "photo" */
		sipe_backend_buddy_set_photo(SIPE_CORE_PUBLIC,
					     uri,
					     photo,
					     photo_size,
					     digest_string);
		g_free(digest_string);
	}

	g_free(uri);
}

void sipe_ucs_get_photo(struct sipe_core_private *sipe_private,
			const gchar *uri)
{
	gchar *payload = g_strdup(uri);
	gchar *body = g_strdup_printf("<m:GetUserPhoto>"
				      " <m:Email>%s</m:Email>"
				      " <m:SizeRequested>HR48x48</m:SizeRequested>"
				      "</m:GetUserPhoto>",
				      sipe_get_no_sip_uri(uri));

	if (!sipe_ucs_http_request(sipe_private,
				   NULL,
				   body,
				   sipe_ucs_get_user_photo_response,
				   payload))
		g_free(payload);
}

static void sipe_ucs_ignore_response(struct sipe_core_private *sipe_private,
				     SIPE_UNUSED_PARAMETER struct sipe_ucs_transaction *trans,
				     SIPE_UNUSED_PARAMETER const sipe_xml *body,
				     SIPE_UNUSED_PARAMETER gpointer callback_data)
{
	SIPE_DEBUG_INFO_NOFORMAT("sipe_ucs_ignore_response: done");
	sipe_private->ucs->last_response = time(NULL);
}

static void ucs_extract_keys(const sipe_xml *persona_node,
			     const gchar **key,
			     const gchar **change)
{
	const sipe_xml *attr_node;

	/*
	 * extract Exchange key - play the guessing game :-(
	 *
	 * We can't use the "DisplayName" node, because the text is localized.
	 *
	 * Assume that IsQuickContact == "true" and IsHidden == "false" means
	 * this Attribution node contains the information for the Lync contact.
	 */
	for (attr_node = sipe_xml_child(persona_node,
					"Attributions/Attribution");
	     attr_node;
	     attr_node = sipe_xml_twin(attr_node)) {
		const sipe_xml *id_node = sipe_xml_child(attr_node,
							 "SourceId");
		gchar *hidden = sipe_xml_data(sipe_xml_child(attr_node,
							     "IsHidden"));
		gchar *quick = sipe_xml_data(sipe_xml_child(attr_node,
							    "IsQuickContact"));
		if (id_node &&
		    sipe_strcase_equal(hidden, "false") &&
		    sipe_strcase_equal(quick,  "true")) {
			*key = sipe_xml_attribute(id_node, "Id");
			*change = sipe_xml_attribute(id_node, "ChangeKey");
			g_free(quick);
			g_free(hidden);
			break;
		}
		g_free(quick);
		g_free(hidden);
	}
}

static void sipe_ucs_add_new_im_contact_to_group_response(struct sipe_core_private *sipe_private,
							  SIPE_UNUSED_PARAMETER struct sipe_ucs_transaction *trans,
							  const sipe_xml *body,
							  gpointer callback_data)
{
	gchar *who = callback_data;
	struct sipe_buddy *buddy = sipe_buddy_find_by_uri(sipe_private, who);
	const sipe_xml *persona_node = sipe_xml_child(body,
						      "AddNewImContactToGroupResponse/Persona");

	sipe_private->ucs->last_response = time(NULL);

	if (persona_node                  &&
	    buddy                         &&
	    is_empty(buddy->exchange_key) &&
	    is_empty(buddy->change_key)) {
		const gchar *key = NULL;
		const gchar *change = NULL;

		ucs_extract_keys(persona_node, &key, &change);

		if (!is_empty(key) && !is_empty(change)) {

			sipe_buddy_add_keys(sipe_private,
					    buddy,
					    key,
					    change);

			SIPE_DEBUG_INFO("sipe_ucs_add_new_im_contact_to_group_response: persona URI '%s' key '%s' change '%s'",
					buddy->name, key, change);
		}
	}

	g_free(who);
}

void sipe_ucs_group_add_buddy(struct sipe_core_private *sipe_private,
			      struct sipe_ucs_transaction *trans,
			      struct sipe_group *group,
			      struct sipe_buddy *buddy,
			      const gchar *who)
{
	/* existing or new buddy? */
	if (buddy && buddy->exchange_key) {
		gchar *body = g_strdup_printf("<m:AddImContactToGroup>"
					      " <m:ContactId Id=\"%s\" ChangeKey=\"%s\"/>"
					      " <m:GroupId Id=\"%s\" ChangeKey=\"%s\"/>"
					      "</m:AddImContactToGroup>",
					      buddy->exchange_key,
					      buddy->change_key,
					      group->exchange_key,
					      group->change_key);

		sipe_ucs_http_request(sipe_private,
				      trans,
				      body,
				      sipe_ucs_ignore_response,
				      NULL);
	} else {
		gchar *payload = g_strdup(who);
		gchar *body = g_strdup_printf("<m:AddNewImContactToGroup>"
					      " <m:ImAddress>%s</m:ImAddress>"
					      " <m:GroupId Id=\"%s\" ChangeKey=\"%s\"/>"
					      "</m:AddNewImContactToGroup>",
					      sipe_get_no_sip_uri(who),
					      group->exchange_key,
					      group->change_key);

		if (!sipe_ucs_http_request(sipe_private,
					   trans,
					   body,
					   sipe_ucs_add_new_im_contact_to_group_response,
					   payload))
			g_free(payload);
	}
}

void sipe_ucs_group_remove_buddy(struct sipe_core_private *sipe_private,
				 struct sipe_ucs_transaction *trans,
				 struct sipe_group *group,
				 struct sipe_buddy *buddy)
{
	if (group) {
		/*
		 * If a contact is removed from last group, it will also be
		 * removed from contact list completely. The documentation has
		 * a RemoveContactFromImList operation, but that doesn't seem
		 * to work at all, i.e. it is always rejected by the server.
		 */
		gchar *body = g_strdup_printf("<m:RemoveImContactFromGroup>"
					      " <m:ContactId Id=\"%s\" ChangeKey=\"%s\"/>"
					      " <m:GroupId Id=\"%s\" ChangeKey=\"%s\"/>"
					      "</m:RemoveImContactFromGroup>",
					      buddy->exchange_key,
					      buddy->change_key,
					      group->exchange_key,
					      group->change_key);

		sipe_ucs_http_request(sipe_private,
				      trans,
				      body,
				      sipe_ucs_ignore_response,
				      NULL);
	}
}

static struct sipe_group *ucs_create_group(struct sipe_core_private *sipe_private,
					   const sipe_xml *group_node)
{
	const sipe_xml *id_node = sipe_xml_child(group_node,
						 "ExchangeStoreId");
	const gchar *key = sipe_xml_attribute(id_node, "Id");
	const gchar *change = sipe_xml_attribute(id_node, "ChangeKey");
	struct sipe_group *group = NULL;

	if (!(is_empty(key) || is_empty(change))) {
		gchar *name = sipe_xml_data(sipe_xml_child(group_node,
							   "DisplayName"));
		group = sipe_group_add(sipe_private,
				       name,
				       key,
				       change,
				       /* sipe_group must have unique ID */
				       ++sipe_private->ucs->group_id);
		g_free(name);
	}

	return(group);
}

static void sipe_ucs_add_im_group_response(struct sipe_core_private *sipe_private,
					   struct sipe_ucs_transaction *trans,
					   const sipe_xml *body,
					   gpointer callback_data)
{
	gchar *who = callback_data;
	const sipe_xml *group_node = sipe_xml_child(body,
						    "AddImGroupResponse/ImGroup");
	struct sipe_group *group = ucs_create_group(sipe_private, group_node);

	sipe_private->ucs->last_response = time(NULL);

	if (group) {
		struct sipe_buddy *buddy = sipe_buddy_find_by_uri(sipe_private,
								  who);

		if (buddy)
			sipe_buddy_insert_group(buddy, group);

		sipe_ucs_group_add_buddy(sipe_private,
					 trans,
					 group,
					 buddy,
					 who);
	}

	g_free(who);
}

void sipe_ucs_group_create(struct sipe_core_private *sipe_private,
			   struct sipe_ucs_transaction *trans,
			   const gchar *name,
			   const gchar *who)
{
	gchar *payload = g_strdup(who);
	/* new_name can contain restricted characters */
	gchar *body = g_markup_printf_escaped("<m:AddImGroup>"
					      " <m:DisplayName>%s</m:DisplayName>"
					      "</m:AddImGroup>",
					      name);

	if (!sipe_ucs_http_request(sipe_private,
				   trans,
				   body,
				   sipe_ucs_add_im_group_response,
				   payload))
		g_free(payload);
}

void sipe_ucs_group_rename(struct sipe_core_private *sipe_private,
			   struct sipe_group *group,
			   const gchar *new_name)
{
	/* new_name can contain restricted characters */
	gchar *body = g_markup_printf_escaped("<m:SetImGroup>"
					      " <m:GroupId Id=\"%s\" ChangeKey=\"%s\"/>"
					      " <m:NewDisplayName>%s</m:NewDisplayName>"
					      "</m:SetImGroup>",
					      group->exchange_key,
					      group->change_key,
					      new_name);

	sipe_ucs_http_request(sipe_private,
			      NULL,
			      body,
			      sipe_ucs_ignore_response,
			      NULL);
}

void sipe_ucs_group_remove(struct sipe_core_private *sipe_private,
			   struct sipe_group *group)
{
	gchar *body = g_strdup_printf("<m:RemoveImGroup>"
				      " <m:GroupId Id=\"%s\" ChangeKey=\"%s\"/>"
				      "</m:RemoveImGroup>",
				      group->exchange_key,
				      group->change_key);

	sipe_ucs_http_request(sipe_private,
			      NULL,
			      body,
			      sipe_ucs_ignore_response,
			      NULL);
}

static void sipe_ucs_get_im_item_list_response(struct sipe_core_private *sipe_private,
					       SIPE_UNUSED_PARAMETER struct sipe_ucs_transaction *trans,
					       const sipe_xml *body,
					       SIPE_UNUSED_PARAMETER gpointer callback_data)
{
	const sipe_xml *node = sipe_xml_child(body,
					      "GetImItemListResponse/ImItemList");

	if (node) {
		const sipe_xml *persona_node;
		const sipe_xml *group_node;
		GHashTable *uri_to_alias = g_hash_table_new_full(g_str_hash,
								 g_str_equal,
								 NULL,
								 g_free);

		/* Start processing contact list */
		if (SIPE_CORE_PRIVATE_FLAG_IS(SUBSCRIBED_BUDDIES)) {
			sipe_group_update_start(sipe_private);
			sipe_buddy_update_start(sipe_private);
		} else
			sipe_backend_buddy_list_processing_start(SIPE_CORE_PUBLIC);

		for (persona_node = sipe_xml_child(node, "Personas/Persona");
		     persona_node;
		     persona_node = sipe_xml_twin(persona_node)) {
			gchar *address = sipe_xml_data(sipe_xml_child(persona_node,
								      "ImAddress"));
			const gchar *key = NULL;
			const gchar *change = NULL;

			ucs_extract_keys(persona_node, &key, &change);

			if (!(is_empty(address) || is_empty(key) || is_empty(change))) {
				gchar *alias = sipe_xml_data(sipe_xml_child(persona_node,
									    "DisplayName"));
				/*
				 * it seems to be undefined if ImAddress node
				 * contains "sip:" prefix or not...
				 */
				gchar *uri = sip_uri(address);
				struct sipe_buddy *buddy = sipe_buddy_add(sipe_private,
									  uri,
									  key,
									  change);
				g_free(uri);

				/* hash table takes ownership of alias */
				g_hash_table_insert(uri_to_alias,
						    buddy->name,
						    alias);

				SIPE_DEBUG_INFO("sipe_ucs_get_im_item_list_response: persona URI '%s' key '%s' change '%s'",
						buddy->name, key, change);
			}
			g_free(address);
		}

		for (group_node = sipe_xml_child(node, "Groups/ImGroup");
		     group_node;
		     group_node = sipe_xml_twin(group_node)) {
			struct sipe_group *group = ucs_create_group(sipe_private,
								    group_node);

			if (group) {
				const sipe_xml *member_node;

				for (member_node = sipe_xml_child(group_node,
								  "MemberCorrelationKey/ItemId");
				     member_node;
				     member_node = sipe_xml_twin(member_node)) {
					struct sipe_buddy *buddy = sipe_buddy_find_by_exchange_key(sipe_private,
												   sipe_xml_attribute(member_node,
														      "Id"));
					if (buddy)
						sipe_buddy_add_to_group(sipe_private,
									buddy,
									group,
									g_hash_table_lookup(uri_to_alias,
											    buddy->name));
				}
			}
		}

		g_hash_table_destroy(uri_to_alias);

		/* Finished processing contact list */
		if (SIPE_CORE_PRIVATE_FLAG_IS(SUBSCRIBED_BUDDIES)) {
			sipe_buddy_update_finish(sipe_private);
			sipe_group_update_finish(sipe_private);
		} else {
			sipe_buddy_cleanup_local_list(sipe_private);
			sipe_backend_buddy_list_processing_finish(SIPE_CORE_PUBLIC);
			sipe_subscribe_presence_initial(sipe_private);
		}
	}
}

static void ucs_get_im_item_list(struct sipe_core_private *sipe_private)
{
	if (sipe_private->ucs->migrated)
		sipe_ucs_http_request(sipe_private,
				      /* prioritize over pending default requests */
				      sipe_ucs_transaction(sipe_private),
				      g_strdup("<m:GetImItemList/>"),
				      sipe_ucs_get_im_item_list_response,
				      NULL);
}

static void ucs_set_ews_url(struct sipe_core_private *sipe_private,
		      const gchar *ews_url)
{
	struct sipe_ucs *ucs = sipe_private->ucs;

	SIPE_DEBUG_INFO("ucs_set_ews_url: '%s'", ews_url);
	ucs->ews_url = g_strdup(ews_url);

	/* this will trigger sending of the first deferred request */
	ucs_get_im_item_list(sipe_private);
}

static void ucs_ews_autodiscover_cb(struct sipe_core_private *sipe_private,
				    const struct sipe_ews_autodiscover_data *ews_data,
				    SIPE_UNUSED_PARAMETER gpointer callback_data)
{
	struct sipe_ucs *ucs = sipe_private->ucs;
	const gchar *ews_url;

	if (!ucs || !ews_data)
		return;

	ews_url = ews_data->ews_url;
	if (is_empty(ews_url)) {
		SIPE_DEBUG_ERROR_NOFORMAT("ucs_ews_autodiscover_cb: can't detect EWS URL, contact list operations will not work!");
		return;
	}

	ucs_set_ews_url(sipe_private, ews_url);
}

gboolean sipe_ucs_is_migrated(struct sipe_core_private *sipe_private)
{
	return(sipe_private->ucs ? sipe_private->ucs->migrated : FALSE);
}

void sipe_ucs_init(struct sipe_core_private *sipe_private,
		   gboolean migrated)
{
	struct sipe_ucs *ucs;
	const gchar *ews_url;

	if (sipe_private->ucs) {
		struct sipe_ucs *ucs = sipe_private->ucs;

		/*
		 * contact list update trigger -> request list again
		 *
		 * If the trigger arrives less than 10 seconds after our
		 * last UCS response, then ignore it, because it is caused
		 * by our own changes to the contact list.
		 */
		if (SIPE_CORE_PRIVATE_FLAG_IS(SUBSCRIBED_BUDDIES)) {
			if ((time(NULL) - ucs->last_response) >= 10)
				ucs_get_im_item_list(sipe_private);
			else
				SIPE_DEBUG_INFO_NOFORMAT("sipe_ucs_init: ignoring this contact list update - triggered by our last change");
		}

		ucs->last_response = 0;
		return;
	}

	sipe_private->ucs = ucs = g_new0(struct sipe_ucs, 1);
	ucs->migrated           = migrated;

	/* create default transaction */
	sipe_ucs_transaction(sipe_private);
	ucs->default_transaction = ucs->transactions;

	/* user specified a service URL? */
	ews_url = sipe_backend_setting(SIPE_CORE_PUBLIC, SIPE_SETTING_EMAIL_URL);
	if (is_empty(ews_url))
		sipe_ews_autodiscover_start(sipe_private,
					    ucs_ews_autodiscover_cb,
					    NULL);
	else
		ucs_set_ews_url(sipe_private, ews_url);
}

void sipe_ucs_free(struct sipe_core_private *sipe_private)
{
	struct sipe_ucs *ucs = sipe_private->ucs;
	GSList *entry;

	if (!ucs)
		return;

	/* UCS stack is shutting down: reject all new requests */
	ucs->shutting_down = TRUE;

	entry = ucs->transactions;
	while (entry) {
		struct sipe_ucs_transaction *trans = entry->data;
		GSList *entry2 = trans->pending_requests;

		/* transactions get deleted by sipe_ucs_request_free() */
		entry = entry->next;

		while (entry2) {
			struct ucs_request *request = entry2->data;

			/* transactions get deleted by sipe_ucs_request_free() */
			entry2 = entry2->next;

			sipe_ucs_request_free(sipe_private, request);
		}

	}
	/* only default transaction is left... */
	sipe_utils_slist_free_full(ucs->transactions, g_free);

	g_free(ucs->ews_url);
	g_free(ucs);
	sipe_private->ucs = NULL;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
