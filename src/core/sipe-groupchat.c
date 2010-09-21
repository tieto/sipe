/**
 * @file sipe-groupchat.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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

/**
 * This module implements the OCS2007R2 Group Chat functionality
 *
 * Documentation references:
 *
 *  Microsoft TechNet: Key Protocols and Windows Services Used by Group Chat
 *   <http://technet.microsoft.com/en-us/library/ee323484%28office.13%29.aspx>
 *  Microsoft TechNet: Group Chat Call Flows
 *   <http://technet.microsoft.com/en-us/library/ee323524%28office.13%29.aspx>
 *  Microsoft Office Communications Server 2007 R2 Technical Reference Guide
 *   <http://go.microsoft.com/fwlink/?LinkID=159649>
 *  XML XCCOS message specification
 *   <???> (searches on the internet currently reveal nothing)
 *
 *
 * @TODO:
 *
 *   -.cmd:getserverinfo
 *       <sib domain="<DOMAIN>" infoType="123" />
 *     rpl:getservinfo
 *       <sib infoType="123"
 *          serverTime="2010-09-14T14:26:17.6206356Z"
 *          searchLimit="999"
 *          messageSizeLimit="512"
 *          storySizeLimit="4096"
 *          rootUri="ma-cat://<DOMAIN>/<GUID>"
 *          dbVersion="3ea3a5a8-ef36-46cf-898f-7a5133931d63"
 *       />
 *
 *     is there any information in there we would need/use?
 *
 *   - cmd:getpref/rpl:getpref/cmd:setpref/rpl:setpref
 *     probably useless, as libpurple stores configuration locally
 *
 *     can store base64 encoded "free text" in key/value fashion
 *       <cmd id="cmd:getpref" seqid="x">
 *         <data>
 *           <pref label="kedzie.GroupChannels"
 *             seqid="71"
 *             createdefault="true" />
 *         </data>
 *       </cmd>
 *       <cmd id="cmd:setpref" seqid="x">
 *         <data>
 *           <pref label="kedzie.GroupChannels"
 *             seqid="71"
 *             createdefault="false"
 *             content="<BASE64 text>" />
 *         </data>
 *       </cmd>
 *
 *     use this to sync chats in buddy list on multiple clients?
 *
 *   - cmd:bccontext
 *     send after cmd:join to trigger rpl:bccontext
 *
 *   - rpl:bccontext
 *     according to available documentation delivers channel history, etc.
 *     [no log file examples]
 *     can we add the history to the window when we open the window, or would
 *     that confuse users that use history based on client log?
 *
 *   - cmd:getinv
 *       <inv inviteId="1" domain="<DOMAIN>" />
 *     rpl:getinv
 *       ???
 *
 *     according to documentation should provide list of outstanding invites.
 *     [no log file examples]
 *     should we automatically join those channels or ask user to join/add?
 *
 *   - chatserver_command_message()
 *     needs to support multiple <chatgrp> nodes?
 *     [no log file examples]
 *
 *   - create/delete chat rooms
 *     [no log file examples]
 *     are these related to this functionality?
 *
 *     <cmd id="cmd:nodespermcreatechild" seqid="1">
 *       <data />
 *     </cmd>
 *     <rpl id="rpl:nodespermcreatechild" seqid="1">
 *       <commandid seqid="1" envid="xxx" />
 *       <resp code="200">SUCCESS_OK</resp>
 *       <data />
 *     </rpl>
 *
 *   - file transfer (uses HTTPS PUT/GET via a filestore server)
 *     [no log file examples]
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "sipe-common.h"
#include "sipmsg.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-dialog.h"
#include "sipe-groupchat.h"
#include "sipe-nls.h"
#include "sipe-schedule.h"
#include "sipe-session.h"
#include "sipe-utils.h"
#include "sipe-xml.h"
#include "sipe.h"

#define GROUPCHAT_RETRY_TIMEOUT 5*60 /* seconds */

/**
 * aib node - magic numbers?
 *
 * Example:
 * <aib key="3984" value="0,1,2,3,4,5,7,9,10,12,13,14,15,16,17" />
 * <aib key="12276" value="6,8,11" />
 *
 * "value" corresponds to the "id" attribute in uib nodes.
 *
 * @TODO: Confirm "guessed" meaning of the magic numbers:
 *        3984  = normal users
 *        12276 = channel operators
 */
#define GROUPCHAT_AIB_KEY_USER    "3984"
#define GROUPCHAT_AIB_KEY_CHANOP "12276"

struct sipe_groupchat {
	struct sip_session *session;
	gchar *domain;
	GSList *join_queue;
	GHashTable *id_to_room;
	GHashTable *uri_to_room;
	GHashTable *msgs;
	guint envid;
	gboolean connected;
};

struct sipe_groupchat_room {
	struct sipe_backend_session *backend_session;
	gchar *uri;
	gchar *title;
	int id;
};

struct sipe_groupchat_msg {
	GHashTable *container;
	struct sipe_groupchat_room *room;
	gchar *content;
	gchar *xccos;
	guint envid;
};

/* GDestroyNotify */
static void sipe_groupchat_room_free(gpointer data) {
	struct sipe_groupchat_room *room = data;
	g_free(room->title);
	g_free(room->uri);
	g_free(room);
}

/* GDestroyNotify */
static void sipe_groupchat_msg_free(gpointer data) {
	struct sipe_groupchat_msg *msg = data;
	g_free(msg->content);
	g_free(msg->xccos);
	g_free(msg);
}

/* GDestroyNotify */
static void sipe_groupchat_msg_remove(gpointer data) {
	struct sipe_groupchat_msg *msg = data;
	g_hash_table_remove(msg->container, &msg->envid);
}

static void sipe_groupchat_allocate(struct sipe_core_private *sipe_private)
{
	struct sipe_groupchat *groupchat = g_new0(struct sipe_groupchat, 1);

	groupchat->id_to_room = g_hash_table_new_full(g_int_hash, g_int_equal,
						      NULL,
						      sipe_groupchat_room_free);
	groupchat->uri_to_room = g_hash_table_new(g_str_hash, g_str_equal);
	groupchat->msgs  = g_hash_table_new_full(g_int_hash, g_int_equal,
						 NULL,
						 sipe_groupchat_msg_free);
	groupchat->envid = rand();
	groupchat->connected = FALSE;
	sipe_private->groupchat = groupchat;
}

static void sipe_groupchat_free_join_queue(struct sipe_groupchat *groupchat)
{
	GSList *entry = groupchat->join_queue;
	while (entry) {
		g_free(entry->data);
		entry = entry->next;
	}
	g_slist_free(groupchat->join_queue);
	groupchat->join_queue = NULL;
}

void sipe_groupchat_free(struct sipe_core_private *sipe_private)
{
	struct sipe_groupchat *groupchat = sipe_private->groupchat;
	if (groupchat) {
		sipe_groupchat_free_join_queue(groupchat);
		g_hash_table_destroy(groupchat->msgs);
		g_hash_table_destroy(groupchat->uri_to_room);
		g_hash_table_destroy(groupchat->id_to_room);
		g_free(groupchat->domain);
		g_free(groupchat);
		sipe_private->groupchat = NULL;
	}
}

static struct sipe_groupchat_msg *generate_xccos_message(struct sipe_groupchat *groupchat,
							 const gchar *content)
{
	struct sipe_groupchat_msg *msg = g_new0(struct sipe_groupchat_msg, 1);

	msg->container = groupchat->msgs;
	msg->envid     = groupchat->envid++;
	msg->xccos     = g_strdup_printf("<xccos ver=\"1\" envid=\"%u\" xmlns=\"urn:parlano:xml:ns:xccos\">"
					 "%s"
					 "</xccos>",
					 msg->envid,
					 content);

	g_hash_table_insert(groupchat->msgs, &msg->envid, msg);

	return(msg);
}

/**
 * Create short-lived dialog with ocschat@<domain> (or user specified value)
 * This initiates the Group Chat feature
 */
void sipe_groupchat_init(struct sipe_core_private *sipe_private)
{
	const gchar *setting = sipe_backend_setting(SIPE_CORE_PUBLIC,
						    SIPE_SETTING_GROUPCHAT_USER);
	gboolean user_set = !is_empty(setting);
	gchar **parts = g_strsplit(user_set ? setting : sipe_private->username,
				   "@", 2);
	gboolean domain_found = !is_empty(parts[1]);
	const gchar *user = "ocschat";
	const gchar *domain = parts[domain_found ? 1 : 0];
	gchar *chat_uri;
	struct sip_session *session;
	struct sipe_groupchat *groupchat;

	/* User specified valid 'user@company.com' */
	if (user_set && domain_found && !is_empty(parts[0]))
		user = parts[0];

	SIPE_DEBUG_INFO("sipe_groupchat_init: username '%s' setting '%s' split '%s'/'%s' GC user %s@%s",
			sipe_private->username, setting, parts[0], parts[1],
			user, domain);

	if (!sipe_private->groupchat)
		sipe_groupchat_allocate(sipe_private);
	groupchat = sipe_private->groupchat;

	chat_uri = g_strdup_printf("sip:%s@%s", user, domain);
	session = sipe_session_find_or_add_im(sipe_private,
					      chat_uri);
	session->is_groupchat = TRUE;
	sipe_invite(sipe_private, session, chat_uri,
		    NULL, NULL, NULL, FALSE);

	g_free(groupchat->domain);
	groupchat->domain = g_strdup(domain);

	g_free(chat_uri);
	g_strfreev(parts);
}

/* sipe_schedule_action */
static void groupchat_init_retry_cb(struct sipe_core_private *sipe_private,
				    SIPE_UNUSED_PARAMETER gpointer data)
{
	sipe_groupchat_init(sipe_private);
}

static void groupchat_init_retry(struct sipe_core_private *sipe_private)
{
	struct sipe_groupchat *groupchat = sipe_private->groupchat;

	SIPE_DEBUG_INFO_NOFORMAT("groupchat_init_retry: trying again later...");

	groupchat->session = NULL;
	groupchat->connected = FALSE;

	sipe_schedule_seconds(sipe_private,
			      "<+grouchat-retry>",
			      NULL,
			      GROUPCHAT_RETRY_TIMEOUT,
			      groupchat_init_retry_cb,
			      NULL);
}

void sipe_groupchat_invite_failed(struct sipe_core_private *sipe_private,
				  struct sip_session *session)
{
	struct sipe_groupchat *groupchat = sipe_private->groupchat;
	const gchar *setting = sipe_backend_setting(SIPE_CORE_PUBLIC,
						    SIPE_SETTING_GROUPCHAT_USER);

	if (groupchat->session) {
		/* response to group chat server invite */
		SIPE_DEBUG_ERROR_NOFORMAT("can't connect to group chat server!");
	} else {
		/* response to initial invite */
		SIPE_DEBUG_INFO_NOFORMAT("no group chat server found.");
	}

	sipe_session_close(sipe_private, session);
	groupchat_init_retry(sipe_private);

	if (setting) {
		gchar *msg = g_strdup_printf(_("Group Chat Proxy setting is incorrect:\n\n\t%s\n\nPlease update your Account."),
					     setting);
		sipe_backend_notify_error(_("Couldn't find Group Chat server!"), msg);
		g_free(msg);
	}
}

static gchar *generate_chanid_node(const gchar *uri, guint key)
{
	/* ma-chan://<domain>/<value> */
	gchar **parts = g_strsplit(uri, "/", 4);
	gchar *chanid = NULL;

	if (parts[2] && parts[3]) {
		chanid = g_strdup_printf("<chanid key=\"%d\" domain=\"%s\" value=\"%s\"/>",
					 key, parts[2], parts[3]);
	} else {
		SIPE_DEBUG_ERROR("generate_chanid_node: mal-formed URI '%s'",
				 uri);
	}
	g_strfreev(parts);

	return chanid;
}

static struct sipe_groupchat_msg *chatserver_command(struct sipe_core_private *sipe_private,
						     const gchar *cmd);

void sipe_groupchat_invite_response(struct sipe_core_private *sipe_private,
				    struct sip_dialog *dialog)
{
	struct sipe_groupchat *groupchat = sipe_private->groupchat;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_groupchat_invite_response");

	if (!groupchat->session) {
		/* response to initial invite */
		struct sipe_groupchat_msg *msg = generate_xccos_message(groupchat,
									"<cmd id=\"cmd:requri\" seqid=\"1\"><data/></cmd>");
		sip_transport_info(sipe_private,
				   "Content-Type: text/plain\r\n",
				   msg->xccos,
				   dialog,
				   NULL);
		sipe_groupchat_msg_remove(msg);

	} else {
		/* response to group chat server invite */
		gchar *invcmd;

		SIPE_DEBUG_INFO_NOFORMAT("connection to group chat server established.");

		groupchat->connected = TRUE;

		/* Any queued joins? */
		if (groupchat->join_queue) {
			GString *cmd = g_string_new("<cmd id=\"cmd:bjoin\" seqid=\"1\">"
						    "<data>");
			GSList *entry;
			guint i = 0;

			/* We used g_slist_prepend() to create the list */
			groupchat->join_queue = entry = g_slist_reverse(groupchat->join_queue);
			while (entry) {
				gchar *chanid = generate_chanid_node(entry->data, i++);
				g_string_append(cmd, chanid);
				g_free(chanid);
				entry = entry->next;
			}
			sipe_groupchat_free_join_queue(groupchat);

			g_string_append(cmd, "</data></cmd>");
			chatserver_command(sipe_private, cmd->str);
			g_string_free(cmd, TRUE);
		}

		/* Request outstanding invites from server */
		invcmd = g_strdup_printf("<cmd id=\"cmd:getinv\" seqid=\"1\">"
					 "<data>"
					 "<inv inviteId=\"1\" domain=\"%s\"/>"
					 "</data>"
					 "</cmd>", groupchat->domain);
		chatserver_command(sipe_private, invcmd);
		g_free(invcmd);
	}
}

/* TransCallback */
static gboolean chatserver_command_response(struct sipe_core_private *sipe_private,
					    struct sipmsg *msg,
					    struct transaction *trans)
{
	if (msg->response != 200) {
		struct sipe_groupchat_msg *gmsg = trans->payload->data;
		struct sipe_groupchat_room *room = gmsg->room;

		SIPE_DEBUG_INFO("chatserver_command_response: failure %d", msg->response);

		if (room) {
			gchar *label  = g_strdup_printf(_("This message was not delivered to chat room '%s'"),
							room->title);
			gchar *errmsg = g_strdup_printf("%s:\n<font color=\"#888888\"></b>%s<b></font>",
							label, gmsg->content);
			g_free(label);
			sipe_backend_notify_message_error(SIPE_CORE_PUBLIC,
							  room->backend_session,
							  NULL,
							  errmsg);
			g_free(errmsg);
		}
	}
	return TRUE;
}

static struct sipe_groupchat_msg *chatserver_command(struct sipe_core_private *sipe_private,
						     const gchar *cmd)
{
	struct sipe_groupchat *groupchat = sipe_private->groupchat;
	struct sipe_groupchat_msg *msg = generate_xccos_message(groupchat, cmd);

	struct sip_dialog *dialog = sipe_dialog_find(groupchat->session,
						     groupchat->session->with);

	struct transaction_payload *payload = g_new0(struct transaction_payload, 1);
	struct transaction *trans = sip_transport_info(sipe_private,
						       "Content-Type: text/plain\r\n",
						       msg->xccos,
						       dialog,
						       chatserver_command_response);

	payload->destroy = sipe_groupchat_msg_remove;
	payload->data    = msg;
	trans->payload   = payload;

	return(msg);
}

static void chatserver_response_uri(struct sipe_core_private *sipe_private,
				    struct sip_session *session,
				    SIPE_UNUSED_PARAMETER guint result,
				    SIPE_UNUSED_PARAMETER const gchar *message,
				    const sipe_xml *xml)
{
		const sipe_xml *uib = sipe_xml_child(xml, "uib");
		const gchar *uri = sipe_xml_attribute(uib, "uri");

		/* drop connection to ocschat@<domain> again */
		sipe_session_close(sipe_private, session);

		if (uri) {
			struct sipe_groupchat *groupchat = sipe_private->groupchat;

			SIPE_DEBUG_INFO("chatserver_response_uri: '%s'", uri);

			groupchat->session = session = sipe_session_find_or_add_im(sipe_private,
										   uri);

			session->is_groupchat = TRUE;
			sipe_invite(sipe_private, session, uri, NULL, NULL, NULL, FALSE);
		} else {
			SIPE_DEBUG_WARNING_NOFORMAT("process_incoming_info_groupchat: no server URI found!");
			groupchat_init_retry(sipe_private);
		}
}

static void chatserver_response_channel_search(struct sipe_core_private *sipe_private,
					       SIPE_UNUSED_PARAMETER struct sip_session *session,
					       guint result,
					       const gchar *message,
					       const sipe_xml *xml)
{
	struct sipe_core_public *sipe_public = SIPE_CORE_PUBLIC;

	if (result != 200) {
		sipe_backend_notify_error(_("Error retrieving room list"),
					  message);
	} else {
		const sipe_xml *chanib;

		for (chanib = sipe_xml_child(xml, "chanib");
		     chanib;
		     chanib = sipe_xml_twin(chanib)) {
			const gchar *name = sipe_xml_attribute(chanib, "name");
			const gchar *desc = sipe_xml_attribute(chanib, "description");
			const gchar *uri  = sipe_xml_attribute(chanib, "uri");
			const sipe_xml *node;
			guint user_count = 0;
			guint32 flags = 0;

			/* information */
			for (node = sipe_xml_child(chanib, "info");
			     node;
			     node = sipe_xml_twin(node)) {
				const gchar *id = sipe_xml_attribute(node, "id");
				gchar *data;

				if (!id) continue;

				data = sipe_xml_data(node);
				if (data) {
					if        (sipe_strcase_equal(id, "urn:parlano:ma:info:ucnt")) {
						user_count = g_ascii_strtoll(data, NULL, 10);
					} else if (sipe_strcase_equal(id, "urn:parlano:ma:info:visibilty")) {
						if (sipe_strcase_equal(data, "private")) {
							flags |= SIPE_GROUPCHAT_ROOM_PRIVATE;
						}
					}
					g_free(data);
				}
			}

			/* properties */
			for (node = sipe_xml_child(chanib, "prop");
			     node;
			     node = sipe_xml_twin(node)) {
				const gchar *id = sipe_xml_attribute(node, "id");
				gchar *data;

				if (!id) continue;

				data = sipe_xml_data(node);
				if (data) {
					gboolean value = sipe_strcase_equal(data, "true");
					g_free(data);

					if (value) {
						guint32 add = 0;
						if        (sipe_strcase_equal(id, "urn:parlano:ma:prop:filepost")) {
							add = SIPE_GROUPCHAT_ROOM_FILEPOST;
						} else if (sipe_strcase_equal(id, "urn:parlano:ma:prop:invite")) {
							add = SIPE_GROUPCHAT_ROOM_INVITE;
						} else if (sipe_strcase_equal(id, "urn:parlano:ma:prop:logged")) {
							add = SIPE_GROUPCHAT_ROOM_LOGGED;
						}
						flags |= add;
					}
				}
			}

			SIPE_DEBUG_INFO("group chat channel '%s': '%s' (%s) with %u users, flags 0x%x",
					name, desc, uri, user_count, flags);
			sipe_backend_groupchat_room_add(sipe_public,
							uri, name, desc,
							user_count, flags);
		}
	}

	sipe_backend_groupchat_room_terminate(sipe_public);
}

static gboolean is_chanop(const sipe_xml *aib)
{
	return sipe_strequal(sipe_xml_attribute(aib, "key"),
			     GROUPCHAT_AIB_KEY_CHANOP);
}

static void add_user(struct sipe_groupchat_room *room,
		     const gchar *uri,
		     gboolean new, gboolean chanop)
{
	SIPE_DEBUG_INFO("add_user: %s%s%s to room %s (%s)",
			new ? "new " : "",
			chanop ? "chanop " : "",
			uri,
			room->title, room->uri);
	sipe_backend_chat_add(room->backend_session, uri, new);
	if (chanop)
		sipe_backend_chat_operator(room->backend_session, uri);
}

static void chatserver_response_join(struct sipe_core_private *sipe_private,
				     SIPE_UNUSED_PARAMETER struct sip_session *session,
				     guint result,
				     const gchar *message,
				     const sipe_xml *xml)
{
	if (result != 200) {
		sipe_backend_notify_error(_("Error joining chat room"),
					  message);
	} else {
		const sipe_xml *node;
		GHashTable *user_ids = g_hash_table_new(g_str_hash, g_str_equal);

		/* Extract user IDs & URIs and generate ID -> URI map */
		for (node = sipe_xml_child(xml, "uib");
		     node;
		     node = sipe_xml_twin(node)) {
			const gchar *id  = sipe_xml_attribute(node, "id");
			const gchar *uri = sipe_xml_attribute(node, "uri");
			if (id && uri)
				g_hash_table_insert(user_ids,
						    (gpointer) id,
						    (gpointer) uri);
		}

		/* Process channel data */
		for (node = sipe_xml_child(xml, "chanib");
		     node;
		     node = sipe_xml_twin(node)) {
			struct sipe_groupchat *groupchat = sipe_private->groupchat;
			struct sipe_groupchat_room *room = g_new0(struct sipe_groupchat_room, 1);
			gchar *self = sip_uri_self(sipe_private);
			const sipe_xml *aib;
			const gchar *attr;
			int id;

			/* @TODO: collision-free IDs for sipe-(groupchat|incoming|session).c */
			/* Find next free ID */
			do {
				id = rand();
			} while (g_hash_table_lookup(groupchat->id_to_room, &id));

			attr = sipe_xml_attribute(node, "name");
			room->title = g_strdup(attr ? attr : "");
			room->uri   = g_strdup(sipe_xml_attribute(node, "uri"));
			room->id    = id;

			SIPE_DEBUG_INFO("joined room '%s' (%s id %d)",
					room->title,
					room->uri, id);

			room->backend_session = sipe_backend_chat_create(SIPE_CORE_PUBLIC,
									 id,
									 room->title,
									 self,
									 FALSE);
			g_free(self);

			/* Don't use "id" here! Key must be in non-volatile memory. */
			g_hash_table_insert(groupchat->id_to_room,  &room->id, room);
			g_hash_table_insert(groupchat->uri_to_room, room->uri, room);

			attr = sipe_xml_attribute(node, "topic");
			if (attr) {
				sipe_backend_chat_topic(room->backend_session,
							attr);
			}

			/* Process user map for channel */
			for (aib = sipe_xml_child(node, "aib");
			     aib;
			     aib = sipe_xml_twin(aib)) {
				const gchar *value = sipe_xml_attribute(aib, "value");
				gboolean chanop = is_chanop(aib);
				gchar **ids = g_strsplit(value, ",", 0);

				if (ids) {
					gchar **uid = ids;

					while (*uid) {
						const gchar *uri = g_hash_table_lookup(user_ids,
										       *uid);
						if (uri)
							add_user(room, uri, FALSE, chanop);
						uid++;
					}

					g_strfreev(ids);
				}
			}
		}

		g_hash_table_destroy(user_ids);
	}
}

static void chatserver_response_part(struct sipe_core_private *sipe_private,
				     SIPE_UNUSED_PARAMETER struct sip_session *session,
				     guint result,
				     const gchar *message,
				     const sipe_xml *xml)
{
	if (result != 200) {
		SIPE_DEBUG_WARNING("chatserver_response_part: failed with %d: %s. Dropping room",
				   result, message);
	} else {
		struct sipe_groupchat *groupchat = sipe_private->groupchat;
		const gchar *uri = sipe_xml_attribute(sipe_xml_child(xml, "chanib"),
						      "uri");
		struct sipe_groupchat_room *room;

		if (uri &&
		    (room = g_hash_table_lookup(groupchat->uri_to_room, uri))) {

			SIPE_DEBUG_INFO("leaving room '%s' (%s id %d)",
					room->title, room->uri, room->id);

			/* The order is important here! The last _remove calls the
			   value_destroy_func callback and releases the room */
			g_hash_table_remove(groupchat->uri_to_room, uri);
			g_hash_table_remove(groupchat->id_to_room,  &room->id);

		} else {
			SIPE_DEBUG_WARNING("chatserver_response_part: unknown chat room uri '%s'",
					   uri ? uri : "");
		}
	}
}

static void chatserver_notice_join(struct sipe_core_private *sipe_private,
				   SIPE_UNUSED_PARAMETER struct sip_session *session,
				   SIPE_UNUSED_PARAMETER guint result,
				   SIPE_UNUSED_PARAMETER const gchar *message,
				   const sipe_xml *xml)
{
	struct sipe_groupchat *groupchat = sipe_private->groupchat;
	const sipe_xml *uib;

	for (uib = sipe_xml_child(xml, "uib");
	     uib;
	     uib = sipe_xml_twin(uib)) {
		const gchar *uri = sipe_xml_attribute(uib, "uri");

		if (uri) {
			const sipe_xml *aib;

			for (aib = sipe_xml_child(uib, "aib");
			     aib;
			     aib = sipe_xml_twin(aib)) {
				const gchar *domain = sipe_xml_attribute(aib, "domain");
				const gchar *path   = sipe_xml_attribute(aib, "value");

				if (domain && path) {
					gchar *room_uri = g_strdup_printf("ma-chan://%s/%s",
									  domain, path);
					struct sipe_groupchat_room *room = g_hash_table_lookup(groupchat->uri_to_room,
											       room_uri);
					if (room)
						add_user(room, uri, TRUE, is_chanop(aib));

					g_free(room_uri);
				}
			}
		}
	}
}

static void chatserver_notice_part(struct sipe_core_private *sipe_private,
				   SIPE_UNUSED_PARAMETER struct sip_session *session,
				   SIPE_UNUSED_PARAMETER guint result,
				   SIPE_UNUSED_PARAMETER const gchar *message,
				   const sipe_xml *xml)
{
	struct sipe_groupchat *groupchat = sipe_private->groupchat;
	const sipe_xml *chanib;

	for (chanib = sipe_xml_child(xml, "chanib");
	     chanib;
	     chanib = sipe_xml_twin(chanib)) {
		const gchar *room_uri = sipe_xml_attribute(chanib, "uri");

		if (room_uri) {
			struct sipe_groupchat_room *room = g_hash_table_lookup(groupchat->uri_to_room,
									       room_uri);

			if (room) {
				const sipe_xml *uib;

				for (uib = sipe_xml_child(chanib, "uib");
				     uib;
				     uib = sipe_xml_twin(uib)) {
					const gchar *uri = sipe_xml_attribute(uib, "uri");

					if (uri) {
						SIPE_DEBUG_INFO("remove_user: %s from room %s (%s)",
								uri,
								room->title, room->uri);
						sipe_backend_chat_remove(room->backend_session,
									 uri);
					}
				}
			}
		}
	}
}

static const struct response {
	const gchar *key;
	void (* const handler)(struct sipe_core_private *,
			       struct sip_session *,
			       guint result, const gchar *,
			       const sipe_xml *xml);
} response_table[] = {
	{ "rpl:requri",   chatserver_response_uri },
	{ "rpl:chansrch", chatserver_response_channel_search },
	{ "rpl:join",     chatserver_response_join },
	{ "rpl:bjoin",    chatserver_response_join },
	{ "rpl:part",     chatserver_response_part },
	{ "ntc:join",     chatserver_notice_join },
	{ "ntc:bjoin",    chatserver_notice_join },
	{ "ntc:part",     chatserver_notice_part },
	{ NULL, NULL }
};

/* Handles rpl:XXX & ntc:YYY */
static void chatserver_response(struct sipe_core_private *sipe_private,
				const sipe_xml *reply,
				struct sip_session *session)
{
	do {
		const sipe_xml *resp, *data;
		const gchar *id;
		gchar *message;
		guint result = 500;
		const struct response *r;

		id = sipe_xml_attribute(reply, "id");
		if (!id) {
			SIPE_DEBUG_INFO_NOFORMAT("chatserver_response: no reply ID found!");
			continue;
		}

		resp = sipe_xml_child(reply, "resp");
		if (resp) {
			result = sipe_xml_int_attribute(resp, "code", 500);
			message = sipe_xml_data(resp);
		} else {
			message = g_strdup("");
		}

		data = sipe_xml_child(reply, "data");

		SIPE_DEBUG_INFO("chatserver_response: '%s' result (%d) %s",
				id, result, message ? message : "");

		for (r = response_table; r->key; r++) {
			if (sipe_strcase_equal(id, r->key)) {
				(*r->handler)(sipe_private, session, result, message, data);
				break;
			}
		}
		if (!r->key) {
			SIPE_DEBUG_INFO_NOFORMAT("chatserver_response: ignoring unknown response");
		}

		g_free(message);
	} while ((reply = sipe_xml_twin(reply)) != NULL);
}

static void chatserver_grpchat_message(struct sipe_core_private *sipe_private,
				       const sipe_xml *chatgrp)
{
	struct sipe_groupchat *groupchat = sipe_private->groupchat;
	const gchar *uri = sipe_xml_attribute(chatgrp, "chanUri");
	const gchar *from = sipe_xml_attribute(chatgrp, "author");
	gchar *text = sipe_xml_data(sipe_xml_child(chatgrp, "chat"));
	struct sipe_groupchat_room *room;
	gchar *escaped;

	if (!uri || !from) {
		SIPE_DEBUG_INFO("chatserver_grpchat_message: message '%s' received without chat room URI or author!",
				text ? text : "");
		g_free(text);
		return;
	}

	room = g_hash_table_lookup(groupchat->uri_to_room, uri); 
	if (!room) {
		SIPE_DEBUG_INFO("chatserver_grpchat_message: message '%s' from '%s' received from unknown chat room '%s'!",
				text ? text : "", from, uri);
		g_free(text);
		return;
	}

	/* libxml2 decodes all entities, but the backend expects HTML */
	escaped = g_markup_escape_text(text, -1);
	g_free(text);
	sipe_backend_chat_message(SIPE_CORE_PUBLIC, room->id, from, escaped);
	g_free(escaped);
}

void process_incoming_info_groupchat(struct sipe_core_private *sipe_private,
				     struct sipmsg *msg,
				     struct sip_session *session)
{
	sipe_xml *xml = sipe_xml_parse(msg->body, msg->bodylen);
	const sipe_xml *node;

	/* @TODO: is this always correct?*/
	sip_transport_response(sipe_private, msg, 200, "OK", NULL);

	if (!xml) return;

	if        (((node = sipe_xml_child(xml, "rpl")) != NULL) ||
		   ((node = sipe_xml_child(xml, "ntc")) != NULL)) {
		chatserver_response(sipe_private, node, session);
	} else if ((node = sipe_xml_child(xml, "grpchat")) != NULL) {
		chatserver_grpchat_message(sipe_private, node);
	} else {
		SIPE_DEBUG_INFO_NOFORMAT("process_incoming_info_groupchat: ignoring unknown response");
	}

	sipe_xml_free(xml);
}

gboolean sipe_groupchat_send(struct sipe_core_private *sipe_private,
			     int id, const gchar *what)
{
	struct sipe_groupchat *groupchat = sipe_private->groupchat;
	struct sipe_groupchat_room *room;
	gchar *cmd, *self, *timestamp;
	struct sipe_groupchat_msg *msg;

	if (!groupchat)
		return FALSE;

	room = g_hash_table_lookup(groupchat->id_to_room, &id);
	if (!room)
		return FALSE;

	SIPE_DEBUG_INFO("sipe_groupchat_send: (%s id %d) %s",
			room->uri, id, what);

	self = sip_uri_self(sipe_private);
	timestamp = sipe_utils_time_to_str(time(NULL));

	/**
	 * 'what' is already XML-escaped, e.g.
	 *
	 *    " -> &quot;
	 *    > -> &gt;
	 *    < -> &lt;
	 *    & -> &amp;
	 *
	 * No need to escape them here.
	 */
	cmd = g_strdup_printf("<grpchat id=\"grpchat\" seqid=\"1\" chanUri=\"%s\" author=\"%s\" ts=\"%s\">"
			      "<chat>%s</chat>"
			      "</grpchat>",
			      room->uri, self, timestamp, what);
	g_free(timestamp);
	g_free(self);
	msg = chatserver_command(sipe_private, cmd);
	g_free(cmd);

	msg->room    = room;
	msg->content = g_strdup(what);

	return TRUE;
}

gboolean sipe_groupchat_leave(struct sipe_core_private *sipe_private,
			     int id)
{
	struct sipe_groupchat *groupchat = sipe_private->groupchat;
	struct sipe_groupchat_room *room;
	gchar *cmd;

	if (!groupchat)
		return FALSE;

	room = g_hash_table_lookup(groupchat->id_to_room, &id);
	if (!room)
		return FALSE;

	SIPE_DEBUG_INFO("sipe_groupchat_leave: %s id %d", room->uri, id);

	cmd = g_strdup_printf("<cmd id=\"cmd:part\" seqid=\"1\">"
			      "<data>"
			      "<chanib uri=\"%s\"/>"
			      "</data>"
			      "</cmd>", room->uri);
	chatserver_command(sipe_private, cmd);
	g_free(cmd);

	return TRUE;
}

gboolean sipe_core_groupchat_query_rooms(struct sipe_core_public *sipe_public)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_groupchat *groupchat = sipe_private->groupchat;

	if (!groupchat || !groupchat->connected)
		return FALSE;

	chatserver_command(sipe_private,
			   "<cmd id=\"cmd:chansrch\" seqid=\"1\">"
			   "<data>"
			   "<qib qtype=\"BYNAME\" criteria=\"\" extended=\"false\"/>"
			   "</data>"
			   "</cmd>");

	return TRUE;
}

void sipe_core_groupchat_join(struct sipe_core_public *sipe_public,
			      const gchar *uri)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_groupchat *groupchat = sipe_private->groupchat;

	if (!g_str_has_prefix(uri, "ma-chan://"))
		return;

	if (!groupchat) {
		/* This happens when a user has set auto-join on a channel */
		sipe_groupchat_allocate(sipe_private);
		groupchat = sipe_private->groupchat;
	}

	if (groupchat->connected) {
		/* Send it out directly */
		gchar *chanid = generate_chanid_node(uri, 0);
		if (chanid) {
			gchar *cmd = g_strdup_printf("<cmd id=\"cmd:join\" seqid=\"1\">"
						     "<data>%s</data>"
						     "</cmd>",
						     chanid);
			chatserver_command(sipe_private, cmd);
			g_free(cmd);
			g_free(chanid);
		}
	} else {
		/* Add it to the queue but avoid duplicates */
		if (!g_slist_find_custom(groupchat->join_queue, uri,
					 (GCompareFunc) g_strcmp0)) {
			SIPE_DEBUG_INFO_NOFORMAT("sipe_core_groupchat_join: URI queued");
			groupchat->join_queue = g_slist_prepend(groupchat->join_queue,
								g_strdup(uri));
		}
	}
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
