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

#include <string.h>

#include <glib.h>

#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-groupchat.h"
#include "sipe-session.h"
#include "sipe.h"

struct sipe_groupchat {
	int dummy;
};

static struct sipe_groupchat *sipe_groupchat_allocate(struct sipe_core_private *sipe_private)
{
	struct sipe_groupchat *groupchat = sipe_private->groupchat;

	if (groupchat) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_groupchat_allocate: called twice. Exiting.");
		return NULL;
	}

	groupchat = g_new0(struct sipe_groupchat, 1);
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

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
