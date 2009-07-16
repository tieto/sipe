/**
 * @file sipe-dialog.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2009 SIPE Project <http://sipe.sourceforge.net/>
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

#include <string.h>
#include <glib.h>

#include "debug.h"

#ifdef _WIN32
#include "internal.h"
#endif

#include "sipe.h"
#include "sipe-dialog.h"
#include "sipe-session.h"
#include "sipmsg.h"

void sipe_dialog_free(struct sip_dialog *dialog)
{
	GSList *entry;

	if (!dialog) return;

	g_free(dialog->with);
	g_free(dialog->endpoint_GUID);
	entry = dialog->routes;
	while (entry) {
		g_free(entry->data);
		entry = g_slist_remove(entry, entry->data);
	}
	entry = dialog->supported;
	while (entry) {
		g_free(entry->data);
		entry = g_slist_remove(entry, entry->data);
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

struct sip_dialog *sipe_dialog_find(struct sip_session *session,
				    const gchar *who)
{
	if (session && who) {
		SIPE_DIALOG_FOREACH {
			if (dialog->with && !strcmp(who, dialog->with)) {
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
		session->dialogs = g_slist_remove(session->dialogs, dialog);
		sipe_dialog_free(dialog);
	}
}

void sipe_dialog_remove_all(struct sip_session *session)
{
	GSList *entry = session->dialogs;
	while (entry) {
		sipe_dialog_free(entry->data);
		entry = g_slist_remove(entry, entry->data);
	}
}

static void sipe_get_route_header(const struct sipmsg *msg,
				  struct sip_dialog *dialog,
				  gboolean outgoing)
{
        GSList *hdr = msg->headers;
        gchar *contact;

        while (hdr) {
                struct siphdrelement *elem = hdr->data;
                if(!g_ascii_strcasecmp(elem->name, "Record-Route")) {
			gchar **parts = g_strsplit(elem->value, ",", 0);
			gchar **part = parts;

			while (*part) {
				gchar *route = sipmsg_find_part_of_header(*part, "<", ">", NULL);
				purple_debug_info("sipe", "sipe_get_route_header: route %s \n", route);
				dialog->routes = g_slist_append(dialog->routes, route);
				part++;
			}

			g_strfreev(parts);
                }
                hdr = g_slist_next(hdr);
        }

        if (outgoing) {
		dialog->routes = g_slist_reverse(dialog->routes);
        }

        if (dialog->routes) {
		dialog->request = dialog->routes->data;
		dialog->routes = g_slist_remove(dialog->routes, dialog->routes->data);
        }

        contact = sipmsg_find_part_of_header(sipmsg_find_header(msg, "Contact"), "<", ">", NULL);
        if (contact) {
		dialog->routes = g_slist_append(dialog->routes, contact);
	}
}

static void
sipe_get_supported_header(const struct sipmsg *msg,
			  struct sip_dialog *dialog,
			  gboolean outgoing)
{
	GSList *hdr = msg->headers;
	struct siphdrelement *elem;
	while(hdr)
	{
		elem = hdr->data;
		if(!g_ascii_strcasecmp(elem->name, "Supported")
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

	sipe_get_route_header(msg, dialog, outgoing);
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
