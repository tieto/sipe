/**
 * @file sipe-notify.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011 SIPE Project <http://sipe.sourceforge.net/>
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
 * Process incoming SIP NOTIFY/BENOTIFY messages
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
#include "sip-csta.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-buddy.h"
#include "sipe-conf.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-group.h"
#include "sipe-media.h"
#include "sipe-mime.h"
#include "sipe-nls.h"
#include "sipe-notify.h"
#include "sipe-ocs2007.h"
#include "sipe-schedule.h"
#include "sipe-subscriptions.h"
#include "sipe-utils.h"
#include "sipe-xml.h"
#include "sipe.h"

/* OCS2005 */
static void sipe_process_provisioning(struct sipe_core_private *sipe_private,
				      struct sipmsg *msg)
{
	sipe_xml *xn_provision;
	const sipe_xml *node;

	xn_provision = sipe_xml_parse(msg->body, msg->bodylen);
	if ((node = sipe_xml_child(xn_provision, "user"))) {
		SIPE_DEBUG_INFO("sipe_process_provisioning: uri=%s", sipe_xml_attribute(node, "uri"));
		if ((node = sipe_xml_child(node, "line"))) {
			const gchar *line_uri = sipe_xml_attribute(node, "uri");
			const gchar *server = sipe_xml_attribute(node, "server");
			SIPE_DEBUG_INFO("sipe_process_provisioning: line_uri=%s server=%s", line_uri, server);
			sip_csta_open(sipe_private, line_uri, server);
		}
	}
	sipe_xml_free(xn_provision);
}

/* OCS2007+ */
static void sipe_process_provisioning_v2(struct sipe_core_private *sipe_private,
					 struct sipmsg *msg)
{
	sipe_xml *xn_provision_group_list;
	const sipe_xml *node;

	xn_provision_group_list = sipe_xml_parse(msg->body, msg->bodylen);

	/* provisionGroup */
	for (node = sipe_xml_child(xn_provision_group_list, "provisionGroup"); node; node = sipe_xml_twin(node)) {
		if (sipe_strequal("ServerConfiguration", sipe_xml_attribute(node, "name"))) {
			g_free(sipe_private->focus_factory_uri);
			sipe_private->focus_factory_uri = sipe_xml_data(sipe_xml_child(node, "focusFactoryUri"));
			SIPE_DEBUG_INFO("sipe_process_provisioning_v2: sipe_private->focus_factory_uri=%s",
					sipe_private->focus_factory_uri ? sipe_private->focus_factory_uri : "");

#ifdef HAVE_VV
			g_free(sipe_private->mras_uri);
			sipe_private->mras_uri = g_strstrip(sipe_xml_data(sipe_xml_child(node, "mrasUri")));
			SIPE_DEBUG_INFO("sipe_process_provisioning_v2: sipe_private->mras_uri=%s",
					sipe_private->mras_uri ? sipe_private->mras_uri : "");

			if (sipe_private->mras_uri)
					sipe_media_get_av_edge_credentials(sipe_private);
#endif
			break;
		}
	}
	sipe_xml_free(xn_provision_group_list);
}

static void process_incoming_notify_rlmi_resub(struct sipe_core_private *sipe_private,
					       const gchar *data, unsigned len)
{
	sipe_xml *xn_list;
	const sipe_xml *xn_resource;
	GHashTable *servers = g_hash_table_new_full(g_str_hash, g_str_equal,
						    g_free, NULL);
	GSList *server;
	gchar *host;

	xn_list = sipe_xml_parse(data, len);

        for (xn_resource = sipe_xml_child(xn_list, "resource");
	     xn_resource;
	     xn_resource = sipe_xml_twin(xn_resource) )
	{
		const char *uri, *state;
		const sipe_xml *xn_instance;

		xn_instance = sipe_xml_child(xn_resource, "instance");
                if (!xn_instance) continue;

                uri = sipe_xml_attribute(xn_resource, "uri");
                state = sipe_xml_attribute(xn_instance, "state");
                SIPE_DEBUG_INFO("process_incoming_notify_rlmi_resub: uri(%s),state(%s)", uri, state);

                if (strstr(state, "resubscribe")) {
			const char *poolFqdn = sipe_xml_attribute(xn_instance, "poolFqdn");

			if (poolFqdn) { //[MS-PRES] Section 3.4.5.1.3 Processing Details
				gchar *user = g_strdup(uri);
				host = g_strdup(poolFqdn);
				server = g_hash_table_lookup(servers, host);
				server = g_slist_append(server, user);
				g_hash_table_insert(servers, host, server);
			} else {
				sipe_subscribe_presence_single(sipe_private,
							       (void *) uri);
			}
                }
	}

	/* Send out any deferred poolFqdn subscriptions */
	g_hash_table_foreach(servers, (GHFunc) sipe_subscribe_poolfqdn_resource_uri, sipe_private);
	g_hash_table_destroy(servers);

	sipe_xml_free(xn_list);
}

static void sipe_presence_mime_cb(gpointer user_data, /* sipe_core_private */
				  const GSList *fields,
				  const gchar *body,
				  gsize length)
{
	const gchar *type = sipe_utils_nameval_find(fields, "Content-Type");

	if (strstr(type,"application/rlmi+xml")) {
		process_incoming_notify_rlmi_resub(user_data, body, length);
	} else if (strstr(type, "text/xml+msrtc.pidf")) {
		process_incoming_notify_msrtc(user_data, body, length);
	} else {
		process_incoming_notify_rlmi(user_data, body, length);
	}
}

static void sipe_process_presence(struct sipe_core_private *sipe_private,
				  struct sipmsg *msg)
{
	const char *ctype = sipmsg_find_header(msg, "Content-Type");

	SIPE_DEBUG_INFO("sipe_process_presence: Content-Type: %s", ctype ? ctype : "");

	if (ctype &&
	    (strstr(ctype, "application/rlmi+xml") ||
	     strstr(ctype, "application/msrtc-event-categories+xml")))
	{
		if (strstr(ctype, "multipart"))
		{
			sipe_mime_parts_foreach(ctype, msg->body, sipe_presence_mime_cb, sipe_private);
		}
		else if(strstr(ctype, "application/msrtc-event-categories+xml") )
		{
			process_incoming_notify_rlmi(sipe_private, msg->body, msg->bodylen);
		}
		else if(strstr(ctype, "application/rlmi+xml"))
		{
			process_incoming_notify_rlmi_resub(sipe_private, msg->body, msg->bodylen);
		}
	}
	else if(ctype && strstr(ctype, "text/xml+msrtc.pidf"))
	{
		process_incoming_notify_msrtc(sipe_private, msg->body, msg->bodylen);
	}
	else
	{
		process_incoming_notify_pidf(sipe_private, msg->body, msg->bodylen);
	}
}

/**
 * Fires on deregistration event initiated by server.
 * [MS-SIPREGE] SIP extension.
 *
 *	OCS2007 Example
 *
 *	Content-Type: text/registration-event
 *	subscription-state: terminated;expires=0
 *	ms-diagnostics-public: 4141;reason="User disabled"
 *
 *	deregistered;event=rejected
 */
static void sipe_process_registration_notify(struct sipe_core_private *sipe_private,
					     struct sipmsg *msg)
{
	const gchar *contenttype = sipmsg_find_header(msg, "Content-Type");
	gchar *event = NULL;
	gchar *reason = NULL;
	gchar *warning;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_process_registration_notify: deregistration received.");

	if (!g_ascii_strncasecmp(contenttype, "text/registration-event", 23)) {
		event = sipmsg_find_part_of_header(msg->body, "event=", NULL, NULL);
		//@TODO have proper parameter extraction _by_name_ func, case insesitive.
		event = event ? event : sipmsg_find_part_of_header(msg->body, "event=", ";", NULL);
	} else {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_process_registration_notify: unknown content type, exiting.");
		return;
	}

	reason = sipmsg_get_ms_diagnostics_reason(msg);
	reason = reason ? reason : sipmsg_get_ms_diagnostics_public_reason(msg);
	if (!reason) { // for LCS2005
		if (event && sipe_strcase_equal(event, "unregistered")) {
			//reason = g_strdup(_("User logged out")); // [MS-OCER]
			reason = g_strdup(_("you are already signed in at another location"));
		} else if (event && sipe_strcase_equal(event, "rejected")) {
			reason = g_strdup(_("user disabled")); // [MS-OCER]
		} else if (event && sipe_strcase_equal(event, "deactivated")) {
			reason = g_strdup(_("user moved")); // [MS-OCER]
		}
	}
	g_free(event);
	warning = g_strdup_printf(_("You have been rejected by the server: %s"), reason ? reason : _("no reason given"));
	g_free(reason);

	sipe_backend_connection_error(SIPE_CORE_PUBLIC,
				      SIPE_CONNECTION_ERROR_INVALID_USERNAME,
				      warning);
	g_free(warning);

}

/**
  * Removes entries from local buddy list
  * that does not correspond ones in the roaming contact list.
  */
static void sipe_cleanup_local_blist(struct sipe_core_private *sipe_private)
{
	GSList *buddies = sipe_backend_buddy_find_all(SIPE_CORE_PUBLIC,
						      NULL, NULL);
	GSList *entry = buddies;
	struct sipe_buddy *buddy;
	sipe_backend_buddy b;
	gchar *bname;
	gchar *gname;

	SIPE_DEBUG_INFO("sipe_cleanup_local_blist: overall %d backend buddies (including clones)", g_slist_length(buddies));
	SIPE_DEBUG_INFO("sipe_cleanup_local_blist: %d sipe buddies (unique)", g_hash_table_size(sipe_private->buddies));
	while (entry) {
		b = entry->data;
		gname = sipe_backend_buddy_get_group_name(SIPE_CORE_PUBLIC, b);
		bname = sipe_backend_buddy_get_name(SIPE_CORE_PUBLIC, b);
		buddy = g_hash_table_lookup(sipe_private->buddies, bname);
		if(buddy) {
			gboolean in_sipe_groups = FALSE;
			GSList *entry2 = buddy->groups;
			while (entry2) {
				struct sipe_group *group = entry2->data;
				if (sipe_strequal(group->name, gname)) {
					in_sipe_groups = TRUE;
					break;
				}
				entry2 = entry2->next;
			}
			if(!in_sipe_groups) {
				SIPE_DEBUG_INFO("*** REMOVING %s from blist group: %s as not having this group in roaming list", bname, gname);
				sipe_backend_buddy_remove(SIPE_CORE_PUBLIC, b);
			}
		} else {
				SIPE_DEBUG_INFO("*** REMOVING %s from blist group: %s as this buddy not in roaming list", bname, gname);
				sipe_backend_buddy_remove(SIPE_CORE_PUBLIC, b);
		}
		g_free(bname);
		g_free(gname);
		entry = entry->next;
	}
	g_slist_free(buddies);
}

/**
  * A callback for g_hash_table_foreach
  */
static void sipe_buddy_subscribe_cb(char *buddy_name,
				    SIPE_UNUSED_PARAMETER struct sipe_buddy *buddy,
				    struct sipe_core_private *sipe_private)
{
	gchar *action_name = sipe_utils_presence_key(buddy_name);
	/* g_hash_table_size() can never return 0, otherwise this function wouldn't be called :-) */
	guint time_range = (g_hash_table_size(sipe_private->buddies) * 1000) / 25; /* time interval for 25 requests per sec. In msec. */
	guint timeout = ((guint) rand()) / (RAND_MAX / time_range) + 1; /* random period within the range but never 0! */

	sipe_schedule_mseconds(sipe_private,
			       action_name,
			       g_strdup(buddy_name),
			       timeout,
			       sipe_subscribe_presence_single,
			       g_free);
	g_free(action_name);
}

static gboolean sipe_process_roaming_contacts(struct sipe_core_private *sipe_private,
					      struct sipmsg *msg)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	int len = msg->bodylen;

	const gchar *tmp = sipmsg_find_header(msg, "Event");
	const sipe_xml *item;
	sipe_xml *isc;
	guint delta;
	const sipe_xml *group_node;
	if (!g_str_has_prefix(tmp, "vnd-microsoft-roaming-contacts")) {
		return FALSE;
	}

	/* Convert the contact from XML to backend Buddies */
	isc = sipe_xml_parse(msg->body, len);
	if (!isc) {
		return FALSE;
	}

	/* [MS-SIP]: deltaNum MUST be non-zero */
	delta = sipe_xml_int_attribute(isc, "deltaNum", 0);
	if (delta) {
		sipe_private->deltanum_contacts = delta;
	}

	if (sipe_strequal(sipe_xml_name(isc), "contactList")) {

		/* Parse groups */
		for (group_node = sipe_xml_child(isc, "group"); group_node; group_node = sipe_xml_twin(group_node)) {
			struct sipe_group * group = g_new0(struct sipe_group, 1);
			const char *name = sipe_xml_attribute(group_node, "name");

			if (g_str_has_prefix(name, "~")) {
				name = _("Other Contacts");
			}
			group->name = g_strdup(name);
			group->id = (int)g_ascii_strtod(sipe_xml_attribute(group_node, "id"), NULL);

			sipe_group_add(sipe_private, group);
		}

		// Make sure we have at least one group
		if (g_slist_length(sipe_private->groups) == 0) {
			sipe_group_create(sipe_private, _("Other Contacts"), NULL);
		}

		/* Parse contacts */
		for (item = sipe_xml_child(isc, "contact"); item; item = sipe_xml_twin(item)) {
			const gchar *uri = sipe_xml_attribute(item, "uri");
			const gchar *name = sipe_xml_attribute(item, "name");
			gchar *buddy_name;
			struct sipe_buddy *buddy = NULL;
			gchar *tmp;
			gchar **item_groups;
			int i = 0;

			/* Buddy name must be lower case as we use purple_normalize_nocase() to compare */
			tmp = sip_uri_from_name(uri);
			buddy_name = g_ascii_strdown(tmp, -1);
			g_free(tmp);

			/* assign to group Other Contacts if nothing else received */
			tmp = g_strdup(sipe_xml_attribute(item, "groups"));
			if(is_empty(tmp)) {
				struct sipe_group *group = sipe_group_find_by_name(sipe_private, _("Other Contacts"));
				g_free(tmp);
				tmp = group ? g_strdup_printf("%d", group->id) : g_strdup("1");
			}
			item_groups = g_strsplit(tmp, " ", 0);
			g_free(tmp);

			while (item_groups[i]) {
				struct sipe_group *group = sipe_group_find_by_id(sipe_private, g_ascii_strtod(item_groups[i], NULL));

				// If couldn't find the right group for this contact, just put them in the first group we have
				if (group == NULL && g_slist_length(sipe_private->groups) > 0) {
					group = sipe_private->groups->data;
				}

				if (group != NULL) {
					gchar *b_alias;
					sipe_backend_buddy b = sipe_backend_buddy_find(SIPE_CORE_PUBLIC, buddy_name, group->name);
					if (!b){
						b = sipe_backend_buddy_add(SIPE_CORE_PUBLIC, buddy_name, uri, group->name);
						SIPE_DEBUG_INFO("Created new buddy %s with alias %s", buddy_name, uri);
					}

					b_alias = sipe_backend_buddy_get_alias(SIPE_CORE_PUBLIC, b);
					if (sipe_strcase_equal(uri, b_alias)) {
						if (name != NULL && strlen(name) != 0) {
							sipe_backend_buddy_set_alias(SIPE_CORE_PUBLIC, b, name);

							SIPE_DEBUG_INFO("Replaced buddy %s alias with %s", buddy_name, name);
						}
					}
					g_free(b_alias);

					if (!buddy) {
						buddy = g_new0(struct sipe_buddy, 1);
						buddy->name = sipe_backend_buddy_get_name(SIPE_CORE_PUBLIC, b);
						g_hash_table_insert(sipe_private->buddies, buddy->name, buddy);

						SIPE_DEBUG_INFO("Added SIPE buddy %s", buddy->name);
					}

					buddy->groups = slist_insert_unique_sorted(buddy->groups, group, (GCompareFunc)sipe_group_compare);

					SIPE_DEBUG_INFO("Added buddy %s to group %s", buddy->name, group->name);
				} else {
					SIPE_DEBUG_INFO("No group found for contact %s!  Unable to add to buddy list",
							name);
				}

				i++;
			} // while, contact groups
			g_strfreev(item_groups);
			g_free(buddy_name);

		} // for, contacts

		sipe_cleanup_local_blist(sipe_private);

		/* Add self-contact if not there yet. 2005 systems. */
		/* This will resemble subscription to roaming_self in 2007 systems */
		if (!SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
			gchar *self_uri = sip_uri_self(sipe_private);
			struct sipe_buddy *buddy = g_hash_table_lookup(sipe_private->buddies, self_uri);

			if (!buddy) {
				buddy = g_new0(struct sipe_buddy, 1);
				buddy->name = g_strdup(self_uri);
				g_hash_table_insert(sipe_private->buddies, buddy->name, buddy);
			}
			g_free(self_uri);
		}
	}
	sipe_xml_free(isc);

	/* subscribe to buddies */
	if (!sip->subscribed_buddies) { //do it once, then count Expire field to schedule resubscribe.
		if (sip->batched_support) {
			sipe_subscribe_presence_batched(sipe_private);
		} else {
			g_hash_table_foreach(sipe_private->buddies,
					     (GHFunc)sipe_buddy_subscribe_cb,
					     sipe_private);
		}
		sip->subscribed_buddies = TRUE;
	}
	/* for 2005 systems schedule contacts' status update
	 * based on their calendar information
	 */
	if (!SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		sipe_sched_calendar_status_update(sipe_private, time(NULL));
	}

	return 0;
}

static void sipe_process_roaming_acl(struct sipe_core_private *sipe_private,
				     struct sipmsg *msg)
{
	guint delta;
	sipe_xml *xml;

	xml = sipe_xml_parse(msg->body, msg->bodylen);
	if (!xml)
		return;

	/* [MS-SIP]: deltaNum MUST be non-zero */
	delta = sipe_xml_int_attribute(xml, "deltaNum", 0);
	if (delta) {
		sipe_private->deltanum_acl = delta;
	}

	sipe_xml_free(xml);
}

struct sipe_auth_job {
	gchar *who;
	struct sipe_core_private *sipe_private;
};

static void sipe_auth_user_cb(gpointer data)
{
	struct sipe_auth_job *job = (struct sipe_auth_job *) data;
	if (!job) return;

	sipe_core_contact_allow_deny((struct sipe_core_public *)job->sipe_private,
				     job->who,
				     TRUE);
	g_free(job);
}

static void sipe_deny_user_cb(gpointer data)
{
	struct sipe_auth_job *job = (struct sipe_auth_job *) data;
	if (!job) return;

	sipe_core_contact_allow_deny((struct sipe_core_public *)job->sipe_private,
				     job->who,
				     FALSE);
	g_free(job);
}

/* OCS2005- */
static void sipe_process_presence_wpending (struct sipe_core_private *sipe_private,
					    struct sipmsg * msg)
{
	sipe_xml *watchers;
	const sipe_xml *watcher;
	// Ensure it's either not a response (eg it's a BENOTIFY) or that it's a 200 OK response
	if (msg->response != 0 && msg->response != 200) return;

	if (msg->bodylen == 0 || msg->body == NULL || sipe_strequal(sipmsg_find_header(msg, "Event"), "msrtc.wpending")) return;

	watchers = sipe_xml_parse(msg->body, msg->bodylen);
	if (!watchers) return;

	for (watcher = sipe_xml_child(watchers, "watcher"); watcher; watcher = sipe_xml_twin(watcher)) {
		gchar * remote_user = g_strdup(sipe_xml_attribute(watcher, "uri"));
		gchar * alias = g_strdup(sipe_xml_attribute(watcher, "displayName"));
		gboolean on_list = g_hash_table_lookup(sipe_private->buddies, remote_user) != NULL;

		// TODO pull out optional displayName to pass as alias
		if (remote_user) {
			struct sipe_auth_job * job = g_new0(struct sipe_auth_job, 1);
			job->who = remote_user;
			job->sipe_private = sipe_private;
			sipe_backend_buddy_request_authorization(SIPE_CORE_PUBLIC,
								 remote_user,
								 alias,
								 on_list,
								 sipe_auth_user_cb,
								 sipe_deny_user_cb,
								 (gpointer)job);
		}
	}


	sipe_xml_free(watchers);
	return;
}

static void sipe_presence_timeout_mime_cb(gpointer user_data,
					  SIPE_UNUSED_PARAMETER const GSList *fields,
					  const gchar *body,
					  gsize length)
{
	GSList **buddies = user_data;
	sipe_xml *xml = sipe_xml_parse(body, length);

	if (xml && !sipe_strequal(sipe_xml_name(xml), "list")) {
		const gchar *uri = sipe_xml_attribute(xml, "uri");
		const sipe_xml *xn_category;

		/**
		 * automaton: presence is never expected to change
		 *
		 * see: http://msdn.microsoft.com/en-us/library/ee354295(office.13).aspx
		 */
		for (xn_category = sipe_xml_child(xml, "category");
		     xn_category;
		     xn_category = sipe_xml_twin(xn_category)) {
			if (sipe_strequal(sipe_xml_attribute(xn_category, "name"),
					  "contactCard")) {
				const sipe_xml *node = sipe_xml_child(xn_category, "contactCard/automaton");
				if (node) {
					char *boolean = sipe_xml_data(node);
					if (sipe_strequal(boolean, "true")) {
						SIPE_DEBUG_INFO("sipe_process_presence_timeout: %s is an automaton: - not subscribing to presence updates",
								uri);
						uri = NULL;
					}
					g_free(boolean);
				}
				break;
			}
		}

		if (uri) {
			*buddies = g_slist_append(*buddies, sip_uri(uri));
		}
	}

	sipe_xml_free(xml);
}

static void sipe_process_presence_timeout(struct sipe_core_private *sipe_private,
					  struct sipmsg *msg,
					  const gchar *who,
					  int timeout)
{
	const char *ctype = sipmsg_find_header(msg, "Content-Type");
	gchar *action_name = sipe_utils_presence_key(who);

	SIPE_DEBUG_INFO("sipe_process_presence_timeout: Content-Type: %s", ctype ? ctype : "");

	if (ctype &&
	    strstr(ctype, "multipart") &&
	    (strstr(ctype, "application/rlmi+xml") ||
	     strstr(ctype, "application/msrtc-event-categories+xml"))) {
		GSList *buddies = NULL;

		sipe_mime_parts_foreach(ctype, msg->body, sipe_presence_timeout_mime_cb, &buddies);

		if (buddies)
			sipe_subscribe_presence_batched_schedule(sipe_private,
								 action_name,
								 who,
								 buddies,
								 timeout);

	} else {
		sipe_schedule_seconds(sipe_private,
				      action_name,
				      g_strdup(who),
				      timeout,
				      sipe_subscribe_presence_single,
				      g_free);
		SIPE_DEBUG_INFO("Resubscription single contact with batched support(%s) in %d", who, timeout);
	}
	g_free(action_name);
}

/**
 * Dispatcher for all incoming subscription information
 * whether it comes from NOTIFY, BENOTIFY requests or
 * piggy-backed to subscription's OK responce.
 *
 * @param request whether initiated from BE/NOTIFY request or OK-response message.
 * @param benotify whether initiated from NOTIFY or BENOTIFY request.
 */
void process_incoming_notify(struct sipe_core_private *sipe_private,
			     struct sipmsg *msg,
			     gboolean request, gboolean benotify)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	const gchar *content_type = sipmsg_find_header(msg, "Content-Type");
	const gchar *event = sipmsg_find_header(msg, "Event");
	const gchar *subscription_state = sipmsg_find_header(msg, "subscription-state");

	SIPE_DEBUG_INFO("process_incoming_notify: subscription_state: %s", subscription_state ? subscription_state : "");

	/* implicit subscriptions */
	if (content_type && g_str_has_prefix(content_type, "application/ms-imdn+xml")) {
		sipe_process_imdn(sipe_private, msg);
	}

	if (event) {
		/* for one off subscriptions (send with Expire: 0) */
		if (sipe_strcase_equal(event, "vnd-microsoft-provisioning-v2"))
		{
			sipe_process_provisioning_v2(sipe_private, msg);
		}
		else if (sipe_strcase_equal(event, "vnd-microsoft-provisioning"))
		{
			sipe_process_provisioning(sipe_private, msg);
		}
		else if (sipe_strcase_equal(event, "presence"))
		{
			sipe_process_presence(sipe_private, msg);
		}
		else if (sipe_strcase_equal(event, "registration-notify"))
		{
			sipe_process_registration_notify(sipe_private, msg);
		}

		if (!subscription_state || strstr(subscription_state, "active"))
		{
			if (sipe_strcase_equal(event, "vnd-microsoft-roaming-contacts"))
			{
				sipe_process_roaming_contacts(sipe_private, msg);
			}
			else if (sipe_strcase_equal(event, "vnd-microsoft-roaming-self"))
			{
				sipe_ocs2007_process_roaming_self(sipe_private, msg);
			}
			else if (sipe_strcase_equal(event, "vnd-microsoft-roaming-ACL"))
			{
				sipe_process_roaming_acl(sipe_private, msg);
			}
			else if (sipe_strcase_equal(event, "presence.wpending"))
			{
				sipe_process_presence_wpending(sipe_private, msg);
			}
			else if (sipe_strcase_equal(event, "conference"))
			{
				sipe_process_conference(sipe_private, msg);
			}
		}
	}

	/* The server sends status 'terminated' */
	if (subscription_state && strstr(subscription_state, "terminated") ) {
		gchar *who = parse_from(sipmsg_find_header(msg, request ? "From" : "To"));
		gchar *key = sipe_utils_subscription_key(event, who);

		SIPE_DEBUG_INFO("process_incoming_notify: server says that subscription to %s was terminated.",  who);
		g_free(who);

		sipe_subscriptions_remove(sipe_private, key);
		g_free(key);
	}

	if (!request && event) {
		const gchar *expires_header = sipmsg_find_header(msg, "Expires");
		int timeout = expires_header ? strtol(expires_header, NULL, 10) : 0;
		SIPE_DEBUG_INFO("process_incoming_notify: subscription expires:%d", timeout);

		if (timeout) {
			/* 2 min ahead of expiration */
			timeout = (timeout - 120) > 120 ? (timeout - 120) : timeout;

			if (sipe_strcase_equal(event, "presence.wpending") &&
			    g_slist_find_custom(sip->allow_events, "presence.wpending", (GCompareFunc)g_ascii_strcasecmp))
			{
				gchar *action_name = g_strdup_printf("<%s>", "presence.wpending");
				sipe_schedule_seconds(sipe_private,
						      action_name,
						      NULL,
						      timeout,
						      sipe_subscribe_presence_wpending,
						      NULL);
				g_free(action_name);
			}
			else if (sipe_strcase_equal(event, "presence") &&
				 g_slist_find_custom(sip->allow_events, "presence", (GCompareFunc)g_ascii_strcasecmp))
			{
				gchar *who = parse_from(sipmsg_find_header(msg, "To"));
				gchar *action_name = sipe_utils_presence_key(who);

				if (sip->batched_support) {
					sipe_process_presence_timeout(sipe_private, msg, who, timeout);
				}
				else {
					sipe_schedule_seconds(sipe_private,
							      action_name,
							      g_strdup(who),
							      timeout,
							      sipe_subscribe_presence_single,
							      g_free);
					SIPE_DEBUG_INFO("Resubscription single contact (%s) in %d", who, timeout);
				}
				g_free(action_name);
				g_free(who);
			}
		}
	}

	/* The client responses on received a NOTIFY message */
	if (request && !benotify)
	{
		sip_transport_response(sipe_private, msg, 200, "OK", NULL);
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
