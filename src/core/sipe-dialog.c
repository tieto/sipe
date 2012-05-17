/**
 * @file sipe-dialog.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009-11 SIPE Project <http://sipe.sourceforge.net/>
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

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <glib.h>

#include "sipe-core.h"
#include "sipe-common.h"
#include "sipmsg.h"
#include "sipe-backend.h"
#include "sipe-dialog.h"
#include "sipe-session.h"
#include "sipe-utils.h"

void sipe_dialog_free(struct sip_dialog *dialog)
{
	GSList *entry;
	void *data;

	if (!dialog) return;

	g_free(dialog->with);
	g_free(dialog->endpoint_GUID);
	entry = dialog->routes;
	while (entry) {
		data = entry->data;
		entry = g_slist_remove(entry, data);
		g_free(data);
	}
	entry = dialog->supported;
	while (entry) {
		data = entry->data;
		entry = g_slist_remove(entry, data);
		g_free(data);
	}

	while (dialog->filetransfers) {
		struct sipe_file_transfer *ft = dialog->filetransfers->data;
		sipe_core_ft_deallocate(ft);
	}

	g_free(dialog->callid);
	g_free(dialog->ourtag);
	g_free(dialog->theirtag);
	g_free(dialog->theirepid);
	g_free(dialog->request);

	g_free(dialog);
}

struct sip_dialog *sipe_dialog_add(struct sip_session *session)
{
	struct sip_dialog *dialog = g_new0(struct sip_dialog, 1);
	session->dialogs = g_slist_append(session->dialogs, dialog);
	return(dialog);
}

static struct sip_dialog *
sipe_dialog_find_3(struct sip_session *session,
		   struct sip_dialog *dialog_in)
{
	if (session && dialog_in) {
		SIPE_DIALOG_FOREACH {
			if (	dialog_in->callid &&
				dialog_in->ourtag &&
				dialog_in->theirtag &&

				dialog->callid &&
				dialog->ourtag &&
				dialog->theirtag &&

				sipe_strcase_equal(dialog_in->callid, dialog->callid) &&
				sipe_strcase_equal(dialog_in->ourtag, dialog->ourtag) &&
				sipe_strcase_equal(dialog_in->theirtag, dialog->theirtag))
			{
				SIPE_DEBUG_INFO("sipe_dialog_find_3 who='%s'",
						dialog->with ? dialog->with : "");
				return dialog;
			}
		} SIPE_DIALOG_FOREACH_END;
	}
	return NULL;
}

struct sip_dialog *sipe_dialog_find(struct sip_session *session,
				    const gchar *who)
{
	if (session && who) {
		SIPE_DIALOG_FOREACH {
			if (dialog->with && sipe_strcase_equal(who, dialog->with)) {
				SIPE_DEBUG_INFO("sipe_dialog_find who='%s'", who);
				return dialog;
			}
		} SIPE_DIALOG_FOREACH_END;
	}
	return NULL;
}

void sipe_dialog_remove(struct sip_session *session, const gchar *who)
{
	struct sip_dialog *dialog = sipe_dialog_find(session, who);
	if (dialog) {
		SIPE_DEBUG_INFO("sipe_dialog_remove who='%s' with='%s'", who, dialog->with ? dialog->with : "");
		session->dialogs = g_slist_remove(session->dialogs, dialog);
		sipe_dialog_free(dialog);
	}
}

void
sipe_dialog_remove_3(struct sip_session *session,
		     struct sip_dialog *dialog_in)
{
	struct sip_dialog *dialog = sipe_dialog_find_3(session, dialog_in);
	if (dialog) {
		SIPE_DEBUG_INFO("sipe_dialog_remove_3 with='%s'",
				dialog->with ? dialog->with : "");
		session->dialogs = g_slist_remove(session->dialogs, dialog);
		sipe_dialog_free(dialog);
	}
}

void sipe_dialog_remove_all(struct sip_session *session)
{
	GSList *entry = session->dialogs;
	while (entry) {
		struct sip_dialog *dialog = entry->data;
		entry = g_slist_remove(entry, dialog);
		sipe_dialog_free(dialog);
	}
}

static void sipe_dialog_parse_routes(struct sip_dialog *dialog,
				     const struct sipmsg *msg,
				     gboolean outgoing)
{
        GSList *hdr = msg->headers;
	gchar *contact = sipmsg_find_part_of_header(sipmsg_find_header(msg, "Contact"), "<", ">", NULL);

	/* Remove old routes */
	while (dialog->routes) {
		void *data = dialog->routes->data;
		dialog->routes = g_slist_remove(dialog->routes, data);
		g_free(data);
	}
	g_free(dialog->request);
        dialog->request = NULL;

        while (hdr) {
                struct sipnameval *elem = hdr->data;
                if (sipe_strcase_equal(elem->name, "Record-Route")) {
			gchar **parts = g_strsplit(elem->value, ",", 0);
			gchar **part = parts;

			while (*part) {
				SIPE_DEBUG_INFO("sipe_dialog_parse_routes: route %s", *part);
				dialog->routes = g_slist_append(dialog->routes,
								g_strdup(*part));
				part++;
			}
			g_strfreev(parts);
                }
                hdr = g_slist_next(hdr);
        }
        if (outgoing) {
		dialog->routes = g_slist_reverse(dialog->routes);
        }

        if (contact) {
		dialog->request = contact;
	}

	/* logic for strict router only - RFC3261 - 12.2.1.1 */
	/* @TODO: proper check for presence of 'lr' PARAMETER in URI */
	if (dialog->routes && !strstr(dialog->routes->data, ";lr")) {
		gchar *route = dialog->routes->data;
		dialog->request = sipmsg_find_part_of_header(route, "<", ">", NULL);
		SIPE_DEBUG_INFO("sipe_dialog_parse_routes: strict route, contact %s", dialog->request);
		dialog->routes = g_slist_remove(dialog->routes, route);
		g_free(route);
		if (contact) {
			dialog->routes = g_slist_append(dialog->routes,
							g_strdup_printf("<%s>", contact));
			g_free(contact);
		}
	}
}

static void
sipe_get_supported_header(const struct sipmsg *msg,
			  struct sip_dialog *dialog,
			  SIPE_UNUSED_PARAMETER gboolean outgoing)
{
	GSList *hdr = msg->headers;
	struct sipnameval *elem;
	while(hdr)
	{
		elem = hdr->data;
		if (sipe_strcase_equal(elem->name, "Supported")
			&& !g_slist_find_custom(dialog->supported, elem->value, (GCompareFunc)g_ascii_strcasecmp))
		{
			dialog->supported = g_slist_append(dialog->supported, g_strdup(elem->value));

		}
		hdr = g_slist_next(hdr);
	}
}

static gchar *find_tag(const gchar *hdr)
{
	gchar * tag = sipmsg_find_part_of_header (hdr, "tag=", ";", NULL);
	if (!tag) {
		// In case it's at the end and there's no trailing ;
		tag = sipmsg_find_part_of_header (hdr, "tag=", NULL, NULL);
	}
	return tag;
}

void sipe_dialog_parse(struct sip_dialog *dialog,
		       const struct sipmsg *msg,
		       gboolean outgoing)
{
	gchar *us = outgoing ? "From" : "To";
	gchar *them = outgoing ? "To" : "From";
	const gchar *session_expires_header;

	g_free(dialog->ourtag);
	g_free(dialog->theirtag);

	dialog->ourtag = find_tag(sipmsg_find_header(msg, us));
	dialog->theirtag = find_tag(sipmsg_find_header(msg, them));
	if (!dialog->theirepid) {
		dialog->theirepid = sipmsg_find_part_of_header(sipmsg_find_header(msg, them), "epid=", ";", NULL);
		if (!dialog->theirepid) {
			dialog->theirepid = sipmsg_find_part_of_header(sipmsg_find_header(msg, them), "epid=", NULL, NULL);
		}
	}

	// Catch a tag on the end of the To Header and get rid of it.
	if (dialog->theirepid && strstr(dialog->theirepid, "tag=")) {
		dialog->theirepid = strtok(dialog->theirepid, ";");
	}

	if ((session_expires_header = sipmsg_find_header(msg, "Session-Expires"))) {
		dialog->expires = atoi(session_expires_header);
	}

	sipe_dialog_parse_routes(dialog, msg, outgoing);
	sipe_get_supported_header(msg, dialog, outgoing);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
