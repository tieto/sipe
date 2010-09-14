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

#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "sipmsg.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-groupchat.h"
#include "sipe-session.h"
#include "sipe-utils.h"
#include "sipe-xml.h"
#include "sipe.h"

struct sipe_groupchat {
	struct sip_session *session;
	guint32 envid;
};

static struct sipe_groupchat *sipe_groupchat_allocate(struct sipe_core_private *sipe_private)
{
	struct sipe_groupchat *groupchat = sipe_private->groupchat;

	if (groupchat) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_groupchat_allocate: called twice. Exiting.");
		return NULL;
	}

	groupchat = g_new0(struct sipe_groupchat, 1);
	groupchat->envid = rand();
	sipe_private->groupchat = groupchat;

	return(groupchat);
}

void sipe_groupchat_free(struct sipe_core_private *sipe_private)
{
	struct sipe_groupchat *groupchat = sipe_private->groupchat;
	if (groupchat) {
		g_free(groupchat);
		sipe_private->groupchat = NULL;
	}
}

static gchar *generate_xccos_message(struct sipe_groupchat *groupchat,
				     const gchar *content)
{
	return g_strdup_printf("<xccos ver=\"1\" envid=\"%u\" xmlns=\"urn:parlano:xml:ns:xccos\">\r\n"
			       "%s\r\n"
			       "</xccos>",
			       groupchat->envid++,
			       content);
}

/**
 * Create short-lived dialog with ocschat@<domain>
 * This initiates Group Chat feature
 */
static void sipe_invite_ocschat(struct sipe_core_private *sipe_private)
{
	struct sipe_groupchat *groupchat = sipe_groupchat_allocate(sipe_private);

	if (groupchat) {
		gchar *domain = strchr(sipe_private->username, '@');

		SIPE_DEBUG_INFO("sipe_invite_ocschat: user %s", sipe_private->username);

		if (domain) {
			gchar *chat_uri = g_strdup_printf("sip:ocschat%s", domain);
			struct sip_session *session = sipe_session_find_or_add_im(sipe_private,
										  chat_uri);
			SIPE_DEBUG_INFO("sipe_invite_ocschat: domain %s", domain);

			session->is_groupchat = TRUE;
			sipe_invite(sipe_private, session, chat_uri,
				    NULL, NULL, NULL, FALSE);

			g_free(chat_uri);
		} else {
			sipe_groupchat_free(sipe_private);
		}
	}
}

void sipe_groupchat_init(struct sipe_core_private *sipe_private)
{
	sipe_invite_ocschat(sipe_private);
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
	}
}

void sipe_groupchat_invite_response(struct sipe_core_private *sipe_private,
				    struct sip_dialog *dialog)
{
	struct sipe_groupchat *groupchat = sipe_private->groupchat;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_groupchat_server_init");

	if (!groupchat->session) {
		/* response to initial invite */
		gchar *xccosmsg = generate_xccos_message(sipe_private->groupchat,
							 "<cmd id=\"cmd:requri\" seqid=\"1\"><data/></cmd>");
		sip_transport_info(sipe_private,
				   "Content-Type: text/plain\r\n",
				   xccosmsg,
				   dialog,
				   NULL);
		g_free(xccosmsg);

	
	} else {
		/* response to group chat server invite */
		/* TBA */
	}
}

static void chatserver_connect(struct sipe_core_private *sipe_private,
			       const gchar *uri)
{
	struct sipe_groupchat *groupchat = sipe_private->groupchat;
	struct sip_session *session = sipe_session_find_or_add_im(sipe_private,
								  uri);

	SIPE_DEBUG_INFO("chatserver_connect: uri '%s'", uri);
	groupchat->session = session;

	session->is_groupchat = TRUE;
	sipe_invite(sipe_private, session, uri, NULL, NULL, NULL, FALSE);
}

void process_incoming_info_groupchat(struct sipe_core_private *sipe_private,
				     struct sipmsg *msg,
				     struct sip_session *session)
{
	sipe_xml *xml = sipe_xml_parse(msg->body, msg->bodylen);
	const sipe_xml *reply;
	const gchar *id;

	/* @TODO: is this always correct?*/ 
	sip_transport_response(sipe_private, msg, 200, "OK", NULL);

	if (!xml) return;

	reply = sipe_xml_child(xml, "rpl");
	if (!reply) {
		SIPE_DEBUG_INFO_NOFORMAT("process_incoming_info_groupchat: no reply node found!");
		sipe_xml_free(xml);
		return;
	}

	id = sipe_xml_attribute(reply, "id");
	if (!id) {
		SIPE_DEBUG_INFO_NOFORMAT("process_incoming_info_groupchat: no reply ID found!");
		sipe_xml_free(xml);
		return;
	}

	SIPE_DEBUG_INFO("process_incoming_info_groupchat: reply '%s'", id);

	if (sipe_strcase_equal(id, "rpl:requri")) {
		const sipe_xml *uib = sipe_xml_child(reply, "data/uib");
		const char *chatserver_uri = sipe_xml_attribute(uib, "uri");

		/* drop connection to ocschat@<domain> again */
		sipe_session_close(sipe_private, session);

		if (chatserver_uri) {
			chatserver_connect(sipe_private, chatserver_uri);
		} else {
			SIPE_DEBUG_WARNING_NOFORMAT("process_incoming_info_groupchat: no server URI found!");
			sipe_groupchat_free(sipe_private);
		}

	} else {
		SIPE_DEBUG_INFO_NOFORMAT("process_incoming_info_groupchat: ignoring unknown response");
	}

	sipe_xml_free(xml);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
