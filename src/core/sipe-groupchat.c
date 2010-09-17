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
#include "sipe-session.h"
#include "sipe-utils.h"
#include "sipe-xml.h"
#include "sipe.h"

struct sipe_groupchat {
	struct sip_session *session;
	GHashTable *id_to_room;
	GHashTable *uri_to_room;
	GHashTable *msgs;
	guint envid;
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

static struct sipe_groupchat *sipe_groupchat_allocate(struct sipe_core_private *sipe_private)
{
	struct sipe_groupchat *groupchat = sipe_private->groupchat;

	if (groupchat) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_groupchat_allocate: called twice. Exiting.");
		return NULL;
	}

	groupchat = g_new0(struct sipe_groupchat, 1);
	groupchat->id_to_room = g_hash_table_new_full(g_int_hash, g_int_equal,
						      NULL,
						      sipe_groupchat_room_free);
	groupchat->uri_to_room = g_hash_table_new(g_str_hash, g_str_equal);
	groupchat->msgs  = g_hash_table_new_full(g_int_hash, g_int_equal,
						 NULL,
						 sipe_groupchat_msg_free);
	groupchat->envid = rand();
	sipe_private->groupchat = groupchat;

	return(groupchat);
}

void sipe_groupchat_free(struct sipe_core_private *sipe_private)
{
	struct sipe_groupchat *groupchat = sipe_private->groupchat;
	if (groupchat) {
		g_hash_table_destroy(groupchat->msgs);
		g_hash_table_destroy(groupchat->uri_to_room);
		g_hash_table_destroy(groupchat->id_to_room);
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
 * Create short-lived dialog with ocschat@<domain>
 * This initiates Group Chat feature
 */
void sipe_groupchat_init(struct sipe_core_private *sipe_private)
{
	struct sipe_groupchat *groupchat = sipe_groupchat_allocate(sipe_private);

	if (groupchat) {
		const gchar *setting = sipe_backend_setting(SIPE_CORE_PUBLIC,
							    SIPE_SETTING_GROUPCHAT_USER);
		gchar **parts = g_strsplit(is_empty(setting) ?
					   sipe_private->username : setting,
					   "@", 2);
		const gchar *user = "ocschat";
		const gchar *domain = parts[is_empty(parts[1]) ? 0 : 1];

		SIPE_DEBUG_INFO("sipe_groupchat_init: user '%s' setting '%s' split '%s' '%s'",
				sipe_private->username, setting,
				parts[0] ? parts[0] : "",
				parts[1] ? parts[1] : "");

		/* Did the user specify a valid user@company.com? */
		if (!is_empty(setting) && !is_empty(parts[1])) {
			/* special case '@company.com' */
			if (!is_empty(parts[0]))
				user = parts[0];
			domain = parts[1];
		}

		SIPE_DEBUG_INFO("sipe_groupchat_init: using '%s' '%s'",
				user ? user : "",
				domain ? domain: "");

		if (!is_empty(user) && !is_empty(domain)) {
			gchar *addr = g_strdup_printf("%s@%s", user, domain);
			gchar *chat_uri = sip_uri_from_name(addr);
			struct sip_session *session = sipe_session_find_or_add_im(sipe_private,
										  chat_uri);
			session->is_groupchat = TRUE;
			sipe_invite(sipe_private, session, chat_uri,
				    NULL, NULL, NULL, FALSE);

			g_free(chat_uri);
			g_free(addr);
		} else {
			sipe_groupchat_free(sipe_private);
		}

		g_strfreev(parts);
	}
}

void sipe_groupchat_invite_failed(struct sipe_core_private *sipe_private,
				  struct sip_session *session)
{
	struct sipe_groupchat *groupchat = sipe_private->groupchat;

	if (!groupchat->session) {
		/* response to initial invite */
		SIPE_DEBUG_INFO_NOFORMAT("no group chat server found.");
		sipe_session_close(sipe_private, session);
		sipe_groupchat_free(sipe_private);
	} else {
		/* response to group chat server invite */
		SIPE_DEBUG_ERROR_NOFORMAT("can't connect to group chat server!");
		sipe_session_close(sipe_private, session);
		sipe_groupchat_free(sipe_private);
	}
}

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
		SIPE_DEBUG_INFO_NOFORMAT("connection to group chat server established.");
		/* TBA */
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
			sipe_groupchat_free(sipe_private);
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
		struct sipe_groupchat *groupchat = sipe_private->groupchat;
		struct sipe_groupchat_room *room = g_new0(struct sipe_groupchat_room, 1);
		const sipe_xml *chanib = sipe_xml_child(xml, "chanib");
		const gchar *title = sipe_xml_attribute(chanib, "name");
		const gchar *topic = sipe_xml_attribute(chanib, "topic");
		gchar *self = sip_uri_self(sipe_private);
		const sipe_xml *uib;
		int id;

		/* @TODO: collision-free IDs for sipe-(groupchat|incoming|session).c */
		/* Find next free ID */
		do {
			id = rand();
		} while (g_hash_table_lookup(groupchat->id_to_room, &id));

		room->uri   = g_strdup(sipe_xml_attribute(chanib, "uri"));
		room->title = g_strdup(title ? title : "");
		room->id    = id;

		SIPE_DEBUG_INFO("joined room '%s' '%s' (%s id %d)",
				room->title,
				topic ? topic : "",
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

		if (topic) {
			sipe_backend_chat_topic(room->backend_session, topic);
		}

		for (uib = sipe_xml_child(xml, "uib");
		     uib;
		     uib = sipe_xml_twin(uib)) {
			const gchar *uri = sipe_xml_attribute(uib, "uri");
			if (uri)
				sipe_backend_chat_add(room->backend_session,
						      uri, FALSE);
		}
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
	{ "rpl:part",     chatserver_response_part },
	{ NULL, NULL }
};

static void chatserver_command_reply(struct sipe_core_private *sipe_private,
				     const sipe_xml *reply,
				     struct sip_session *session)
{
	const sipe_xml *resp, *data;
	const gchar *id;
	gchar *message;
	guint result = 500;
	const struct response *r;

	id = sipe_xml_attribute(reply, "id");
	if (!id) {
		SIPE_DEBUG_INFO_NOFORMAT("chatserver_command_reply: no reply ID found!");
		return;
	}

	resp = sipe_xml_child(reply, "resp");
	if (resp) {
		result = sipe_xml_int_attribute(resp, "code", 500);
		message = sipe_xml_data(resp);
	} else {
		message = g_strdup("");
	}

	data = sipe_xml_child(reply, "data");

	SIPE_DEBUG_INFO("chatserver_command_reply: '%s' result (%d) %s",
			id, result, message ? message : "");

	for (r = response_table; r->key; r++) {
		if (sipe_strcase_equal(id, r->key)) {
			(*r->handler)(sipe_private, session, result, message, data);
			break;
		}
	}
	if (!r->key) {
		SIPE_DEBUG_INFO_NOFORMAT("chatserver_command_reply: ignoring unknown response");
	}

	g_free(message);
}

static void chatserver_chatgrp_message(struct sipe_core_private *sipe_private,
				       const sipe_xml *chatgrp)
{
	struct sipe_groupchat *groupchat = sipe_private->groupchat;
	const gchar *uri = sipe_xml_attribute(chatgrp, "chanUri");
	const gchar *from = sipe_xml_attribute(chatgrp, "author");
	gchar *text = sipe_xml_data(sipe_xml_child(chatgrp, "chat"));
	struct sipe_groupchat_room *room;

	if (!uri || !from) {
		SIPE_DEBUG_INFO("chatserver_chatgrp_message: message '%s' received without chat room URI or author!",
				text ? text : "");
		g_free(text);
		return;
	}

	room = g_hash_table_lookup(groupchat->uri_to_room, uri); 
	if (!room) {
		SIPE_DEBUG_INFO("chatserver_chatgrp_message: message '%s' from '%s' received from unknown chat room '%s'!",
				text ? text : "", from, uri);
		g_free(text);
		return;
	}

	/* @TODO: do we need to unescape 'text'? */
	sipe_backend_chat_message(SIPE_CORE_PUBLIC, room->id, from, text);

	g_free(text);
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

	if        ((node = sipe_xml_child(xml, "rpl")) != NULL) {
		chatserver_command_reply(sipe_private, node, session);
	} else if ((node = sipe_xml_child(xml, "grpchat")) != NULL) {
		chatserver_chatgrp_message(sipe_private, node);
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
	gchar *cmd;
	gchar *self;
	struct sipe_groupchat_msg *msg;

	if (!groupchat)
		return FALSE;

	room = g_hash_table_lookup(groupchat->id_to_room, &id);
	if (!room)
		return FALSE;

	SIPE_DEBUG_INFO("sipe_groupchat_send: (%s id %d) %s",
			room->uri, id, what);

	self = sip_uri_self(sipe_private);
	/* @TODO: 'what' needs escaping! */
	cmd = g_strdup_printf("<grpchat id=\"grpchat\" seqid=\"1\" chanUri=\"%s\" author=\"%s\">"
			      "<chat>%s</chat>"
			      "</grpchat>",
			      room->uri, self, what);
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

	if (!sipe_private->groupchat)
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
	gchar **parts;

	if (!sipe_private->groupchat ||
	    !g_str_has_prefix(uri, "ma-chan://"))
		return;

	/* ma-chan://<domain>/<value> */
	parts = g_strsplit(uri, "/", 4);
	if (parts[2] && parts[3]) {
		gchar *cmd = g_strdup_printf("<cmd id=\"cmd:join\" seqid=\"1\">"
					     "<data>"
					     "<chanid key=\"0\" domain=\"%s\" value=\"%s\"/>"
					     "</data>"
					     "</cmd>",
					     parts[2], parts[3]);
		chatserver_command(sipe_private, cmd);
		g_free(cmd);
	} else {
		SIPE_DEBUG_ERROR("sipe_core_groupchat_join: mal-formed URI '%s'",
				 uri);
	}
	g_strfreev(parts);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
