/**
 * @file sipe-subscriptions.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2013 SIPE Project <http://sipe.sourceforge.net/>
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

#include <glib.h>

#include "sipe-common.h"
#include "sipmsg.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-buddy.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-dialog.h"
#include "sipe-mime.h"
#include "sipe-notify.h"
#include "sipe-schedule.h"
#include "sipe-subscriptions.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

/* RFC3265 subscription */
struct sip_subscription {
	struct sip_dialog dialog;
	gchar *event;
	GSList *buddies; /* batched subscriptions */
};

static void sipe_subscription_free(struct sip_subscription *subscription)
{

	if (!subscription) return;

	g_free(subscription->event);
	sipe_utils_slist_free_full(subscription->buddies, g_free);

	/* NOTE: use cast to prevent BAD_FREE warning from Coverity */
	sipe_dialog_free((struct sip_dialog *) subscription);
}

void sipe_subscriptions_init(struct sipe_core_private *sipe_private)
{
	sipe_private->subscriptions = g_hash_table_new_full(g_str_hash,
							    g_str_equal,
							    g_free,
							    (GDestroyNotify)sipe_subscription_free);
}

static void sipe_unsubscribe_cb(SIPE_UNUSED_PARAMETER gpointer key,
				gpointer value, gpointer user_data)
{
	struct sip_subscription *subscription = value;
	struct sip_dialog *dialog = &subscription->dialog;
	struct sipe_core_private *sipe_private = user_data;
	gchar *contact = get_contact(sipe_private);
	gchar *hdr = g_strdup_printf(
		"Event: %s\r\n"
		"Expires: 0\r\n"
		"Contact: %s\r\n", subscription->event, contact);
	g_free(contact);

	/* Rate limit to max. 25 requests per seconds */
	g_usleep(1000000 / 25);

	sip_transport_subscribe(sipe_private,
				dialog->with,
				hdr,
				NULL,
				dialog,
				NULL);

	g_free(hdr);
}

void sipe_subscriptions_unsubscribe(struct sipe_core_private *sipe_private)
{
	/* unsubscribe all */
	g_hash_table_foreach(sipe_private->subscriptions,
			     sipe_unsubscribe_cb,
			     sipe_private);

}

void sipe_subscriptions_destroy(struct sipe_core_private *sipe_private)
{
	g_hash_table_destroy(sipe_private->subscriptions);
}

static void sipe_subscription_remove(struct sipe_core_private *sipe_private,
				     const gchar *key)
{
	if (g_hash_table_lookup(sipe_private->subscriptions, key)) {
		g_hash_table_remove(sipe_private->subscriptions, key);
		SIPE_DEBUG_INFO("sipe_subscription_remove: %s", key);
	}
}

/**
 * Generate subscription key
 *
 * @param event event name   (must not by @c NULL)
 * @param uri   presence URI (ignored if @c event != "presence")
 *
 * @return key string. Must be g_free()'d after use.
 */
static gchar *sipe_subscription_key(const gchar *event,
				    const gchar *uri)
{
	if (!g_ascii_strcasecmp(event, "presence"))
		/* Subscription is identified by <presence><uri> key */
		return(sipe_utils_presence_key(uri));
	else
		/* Subscription is identified by <event> key */
		return(g_strdup_printf("<%s>", event));
}

static struct sip_dialog *sipe_subscribe_dialog(struct sipe_core_private *sipe_private,
						const gchar *key)
{
	struct sip_dialog *dialog = g_hash_table_lookup(sipe_private->subscriptions,
							key);
	SIPE_DEBUG_INFO("sipe_subscribe_dialog: dialog for '%s' is %s", key, dialog ? "not NULL" : "NULL");
	return(dialog);
}

static void sipe_subscription_expiration(struct sipe_core_private *sipe_private,
					 struct sipmsg *msg,
					 const gchar *event);
static gboolean process_subscribe_response(struct sipe_core_private *sipe_private,
					   struct sipmsg *msg,
					   struct transaction *trans)
{
	gchar *with = parse_from(sipmsg_find_header(msg, "To"));
	const gchar *event = sipmsg_find_header(msg, "Event");

	/* The case with 2005 Public IM Connectivity (PIC) - no Event header */
	if (!event) {
		struct sipmsg *request_msg = trans->msg;
		event = sipmsg_find_header(request_msg, "Event");
	}

	if (event) {
		const gchar *subscription_state = sipmsg_find_header(msg, "subscription-state");
		gboolean terminated = subscription_state && strstr(subscription_state, "terminated");
		gchar *key = sipe_subscription_key(event, with);

		/*
		 * @TODO: does the server send this only for one-off
		 *        subscriptions, i.e. the ones which anyway
		 *        have "Expires: 0"?
		 */
		if (terminated)
			SIPE_DEBUG_INFO("process_subscribe_response: subscription '%s' to '%s' was terminated",
					event, with);

		/* 481 Call Leg Does Not Exist */
		if ((msg->response == 481) || terminated) {
			sipe_subscription_remove(sipe_private, key);

		/* create/store subscription dialog if not yet */
		} else if (msg->response == 200) {
			struct sip_dialog *dialog = sipe_subscribe_dialog(sipe_private, key);

			if (!dialog) {
				struct sip_subscription *subscription = g_new0(struct sip_subscription, 1);

				SIPE_DEBUG_INFO("process_subscribe_response: subscription dialog added for event '%s'",
						key);

				g_hash_table_insert(sipe_private->subscriptions,
						    key,
						    subscription);
				key = NULL; /* table takes ownership of key */

				subscription->dialog.callid = g_strdup(sipmsg_find_header(msg, "Call-ID"));
				subscription->dialog.cseq   = sipmsg_parse_cseq(msg);
				subscription->dialog.with   = g_strdup(with);
				subscription->event         = g_strdup(event);

				dialog = &subscription->dialog;
			}

			sipe_dialog_parse(dialog, msg, TRUE);

			sipe_subscription_expiration(sipe_private, msg, event);
		}
		g_free(key);
	}
	g_free(with);

	if (sipmsg_find_header(msg, "ms-piggyback-cseq"))
		process_incoming_notify(sipe_private, msg);

	return(TRUE);
}

/**
 * common subscription code
 */
static void sipe_subscribe(struct sipe_core_private *sipe_private,
			   const gchar *uri,
			   const gchar *event,
			   const gchar *accept,
			   const gchar *addheaders,
			   const gchar *body,
			   struct sip_dialog *dialog)
{
	gchar *contact = get_contact(sipe_private);
	gchar *hdr = g_strdup_printf(
		"Event: %s\r\n"
		"Accept: %s\r\n"
		"Supported: com.microsoft.autoextend\r\n"
		"Supported: ms-benotify\r\n"
		"Proxy-Require: ms-benotify\r\n"
		"Supported: ms-piggyback-first-notify\r\n"
		"%s"
		"Contact: %s\r\n",
		event,
		accept,
		addheaders ? addheaders : "",
		contact);
	g_free(contact);

	sip_transport_subscribe(sipe_private,
				uri,
				hdr,
				body,
				dialog,
				process_subscribe_response);
	g_free(hdr);
}

/**
 * common subscription code for self-subscriptions
 */
static void sipe_subscribe_self(struct sipe_core_private *sipe_private,
				const gchar *event,
				const gchar *accept,
				const gchar *addheaders,
				const gchar *body)
{
	gchar *self = sip_uri_self(sipe_private);
	gchar *key = sipe_subscription_key(event, self);
	struct sip_dialog *dialog = sipe_subscribe_dialog(sipe_private, key);

	sipe_subscribe(sipe_private,
		       self,
		       event,
		       accept,
		       addheaders,
		       body,
		       dialog);
	g_free(key);
	g_free(self);
}

static void sipe_subscribe_presence_wpending(struct sipe_core_private *sipe_private,
					     SIPE_UNUSED_PARAMETER void *unused)
{
	sipe_subscribe_self(sipe_private,
			    "presence.wpending",
			    "text/xml+msrtc.wpending",
			    NULL,
			    NULL);
}

/**
 * Subscribe roaming ACL
 */
static void sipe_subscribe_roaming_acl(struct sipe_core_private *sipe_private,
				       SIPE_UNUSED_PARAMETER void *unused)
{
	sipe_subscribe_self(sipe_private,
			    "vnd-microsoft-roaming-ACL",
			    "application/vnd-microsoft-roaming-acls+xml",
			    NULL,
			    NULL);
}

/**
 * Subscribe roaming contacts
 */
static void sipe_subscribe_roaming_contacts(struct sipe_core_private *sipe_private,
					    SIPE_UNUSED_PARAMETER void *unused)
{
	sipe_subscribe_self(sipe_private,
			    "vnd-microsoft-roaming-contacts",
			    "application/vnd-microsoft-roaming-contacts+xml",
			    NULL,
			    NULL);
}

/**
 *  OCS 2005 version
 */
static void sipe_subscribe_roaming_provisioning(struct sipe_core_private *sipe_private,
						SIPE_UNUSED_PARAMETER void *unused)
{
	sipe_subscribe_self(sipe_private,
			    "vnd-microsoft-provisioning",
			    "application/vnd-microsoft-roaming-provisioning+xml",
			    "Expires: 0\r\n",
			    NULL);
}

/**
 * Subscription for provisioning information to help with initial
 * configuration. This subscription is a one-time query (denoted by the
 * Expires header, which asks for 0 seconds for the subscription lifetime).
 * This subscription asks for server configuration, meeting policies, and
 * policy settings that Communicator must enforce.
 */
static void sipe_subscribe_roaming_provisioning_v2(struct sipe_core_private *sipe_private,
						   SIPE_UNUSED_PARAMETER void *unused)
{
	sipe_subscribe_self(sipe_private,
			    "vnd-microsoft-provisioning-v2",
			    "application/vnd-microsoft-roaming-provisioning-v2+xml",
			    "Expires: 0\r\n"
			    "Content-Type: application/vnd-microsoft-roaming-provisioning-v2+xml\r\n",
			    "<provisioningGroupList xmlns=\"http://schemas.microsoft.com/2006/09/sip/provisioninggrouplist\">"
			    " <provisioningGroup name=\"ServerConfiguration\"/>"
			    " <provisioningGroup name=\"meetingPolicy\"/>"
			    " <provisioningGroup name=\"persistentChatConfiguration\"/>"
			    " <provisioningGroup name=\"ucPolicy\"/>"
			    "</provisioningGroupList>");
}

/**
 * To request for presence information about the user, access level settings
 * that have already been configured by the user to control who has access to
 * what information, and the list of contacts who currently have outstanding
 * subscriptions.
 *
 * We wait for (BE)NOTIFY messages with some info change (categories,
 * containers, subscribers)
 */
static void sipe_subscribe_roaming_self(struct sipe_core_private *sipe_private,
					SIPE_UNUSED_PARAMETER void *unused)
{
	sipe_subscribe_self(sipe_private,
			    "vnd-microsoft-roaming-self",
			    "application/vnd-microsoft-roaming-self+xml",
			    "Content-Type: application/vnd-microsoft-roaming-self+xml\r\n",
			    "<roamingList xmlns=\"http://schemas.microsoft.com/2006/09/sip/roaming-self\">"
			    "<roaming type=\"categories\"/>"
			    "<roaming type=\"containers\"/>"
			    "<roaming type=\"subscribers\"/></roamingList>");
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

static void sipe_subscribe_presence_batched_schedule(struct sipe_core_private *sipe_private,
						     const gchar *action_name,
						     const gchar *who,
						     GSList *buddies,
						     int timeout);
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
				      sipe_subscribe_presence_single_cb,
				      g_free);
		SIPE_DEBUG_INFO("Resubscription single contact with batched support(%s) in %d seconds", who, timeout);
	}
	g_free(action_name);
}

/**
 * @param expires not respected if set to negative value (E.g. -1)
 */
void sipe_subscribe_conference(struct sipe_core_private *sipe_private,
			       const gchar *id,
			       gboolean expires)
{
	sipe_subscribe(sipe_private,
		       id,
		       "conference",
		       "application/conference-info+xml",
		       expires ? "Expires: 0\r\n" : NULL,
		       NULL,
		       NULL);
}

/**
 * code for presence subscription
 */
static void sipe_subscribe_presence_buddy(struct sipe_core_private *sipe_private,
					  const gchar *uri,
					  const gchar *request,
					  const gchar *body)
{
	gchar *key = sipe_utils_presence_key(uri);

	sip_transport_subscribe(sipe_private,
				uri,
				request,
				body,
				sipe_subscribe_dialog(sipe_private, key),
				process_subscribe_response);

	g_free(key);
}

/**
 * if to == NULL: initial single subscription
 *   OCS2005: send to URI
 *   OCS2007: send to self URI
 *
 * if to != NULL:
 * Single Category SUBSCRIBE [MS-PRES] ; To send when the server returns a 200 OK message with state="resubscribe" in response.
 * The user sends a single SUBSCRIBE request to the subscribed contact.
 * The To-URI and the URI listed in the resource list MUST be the same for a single category SUBSCRIBE request.
 *
 */
void sipe_subscribe_presence_single(struct sipe_core_private *sipe_private,
				    const gchar *uri,
				    const gchar *to)
{
	gchar *self = NULL;
	gchar *contact = get_contact(sipe_private);
	gchar *request;
	gchar *content = NULL;
	const gchar *additional = "";
	const gchar *content_type = "";
	struct sipe_buddy *sbuddy = sipe_buddy_find_by_uri(sipe_private,
							   uri);

	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		content_type = "Content-Type: application/msrtc-adrl-categorylist+xml\r\n";
		content = g_strdup_printf("<batchSub xmlns=\"http://schemas.microsoft.com/2006/01/sip/batch-subscribe\" uri=\"sip:%s\" name=\"\">\n"
					  "<action name=\"subscribe\" id=\"63792024\"><adhocList>\n"
					  "<resource uri=\"%s\"%s\n"
					  "</adhocList>\n"
					  "<categoryList xmlns=\"http://schemas.microsoft.com/2006/09/sip/categorylist\">\n"
					  "<category name=\"calendarData\"/>\n"
					  "<category name=\"contactCard\"/>\n"
					  "<category name=\"note\"/>\n"
					  "<category name=\"state\"/>\n"
					  "</categoryList>\n"
					  "</action>\n"
					  "</batchSub>",
					  sipe_private->username,
					  uri,
					  sbuddy && sbuddy->just_added ? "><context/></resource>" : "/>");
		if (!to) {
			additional = "Require: adhoclist, categoryList\r\n" \
				     "Supported: eventlist\r\n";
			to = self = sip_uri_self(sipe_private);
		}

	} else {
		additional = "Supported: com.microsoft.autoextend\r\n";
		if (!to)
			to = uri;
	}

	if (sbuddy)
		sbuddy->just_added = FALSE;

	request = g_strdup_printf("Accept: application/msrtc-event-categories+xml, text/xml+msrtc.pidf, application/xpidf+xml, application/pidf+xml, application/rlmi+xml, multipart/related\r\n"
				  "Supported: ms-piggyback-first-notify\r\n"
				  "%s%sSupported: ms-benotify\r\n"
				  "Proxy-Require: ms-benotify\r\n"
				  "Event: presence\r\n"
				  "Contact: %s\r\n",
				  additional,
				  content_type,
				  contact);
	g_free(contact);

	sipe_subscribe_presence_buddy(sipe_private, to, request, content);

	g_free(content);
	g_free(self);
	g_free(request);
}

void sipe_subscribe_presence_single_cb(struct sipe_core_private *sipe_private,
				       gpointer uri)
{
	sipe_subscribe_presence_single(sipe_private, uri, NULL);
}


/**
 *   Support for Batch Category SUBSCRIBE [MS-PRES] - msrtc-event-categories+xml  OCS 2007
 *   Support for Batch Category SUBSCRIBE [MS-SIP] - adrl+xml LCS 2005
 *   The user sends an initial batched category SUBSCRIBE request against all contacts on his roaming list in only a request
 *   A batch category SUBSCRIBE request MUST have the same To-URI and From-URI.
 *   This header will be send only if adhoclist there is a "Supported: adhoclist" in REGISTER answer else will be send a Single Category SUBSCRIBE
 */
static void sipe_subscribe_presence_batched_to(struct sipe_core_private *sipe_private,
					       gchar *resources_uri,
					       const gchar *to)
{
	gchar *contact = get_contact(sipe_private);
	gchar *request;
	gchar *content;
	const gchar *require = "";
	const gchar *accept = "";
	const gchar *autoextend = "";
	const gchar *content_type;

	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		require = ", categoryList";
		accept = ", application/msrtc-event-categories+xml, application/xpidf+xml, application/pidf+xml";
                content_type = "application/msrtc-adrl-categorylist+xml";
                content = g_strdup_printf("<batchSub xmlns=\"http://schemas.microsoft.com/2006/01/sip/batch-subscribe\" uri=\"sip:%s\" name=\"\">\n"
					  "<action name=\"subscribe\" id=\"63792024\">\n"
					  "<adhocList>\n%s</adhocList>\n"
					  "<categoryList xmlns=\"http://schemas.microsoft.com/2006/09/sip/categorylist\">\n"
					  "<category name=\"calendarData\"/>\n"
					  "<category name=\"contactCard\"/>\n"
					  "<category name=\"note\"/>\n"
					  "<category name=\"state\"/>\n"
					  "</categoryList>\n"
					  "</action>\n"
					  "</batchSub>",
					  sipe_private->username,
					  resources_uri);
	} else {
                autoextend =  "Supported: com.microsoft.autoextend\r\n";
		content_type = "application/adrl+xml";
        	content = g_strdup_printf("<adhoclist xmlns=\"urn:ietf:params:xml:ns:adrl\" uri=\"sip:%s\" name=\"sip:%s\">\n"
					  "<create xmlns=\"\">\n%s</create>\n"
					  "</adhoclist>\n",
					  sipe_private->username,
					  sipe_private->username,
					  resources_uri);
	}
	g_free(resources_uri);

	request = g_strdup_printf("Require: adhoclist%s\r\n"
				  "Supported: eventlist\r\n"
				  "Accept:  application/rlmi+xml, multipart/related, text/xml+msrtc.pidf%s\r\n"
				  "Supported: ms-piggyback-first-notify\r\n"
				  "%sSupported: ms-benotify\r\n"
				  "Proxy-Require: ms-benotify\r\n"
				  "Event: presence\r\n"
				  "Content-Type: %s\r\n"
				  "Contact: %s\r\n",
				  require,
				  accept,
				  autoextend,
				  content_type,
				  contact);
	g_free(contact);

	sipe_subscribe_presence_buddy(sipe_private, to, request, content);

	g_free(content);
	g_free(request);
}

struct presence_batched_routed {
	gchar  *host;
	const GSList *buddies; /* points to subscription->buddies */
};

static void sipe_subscribe_presence_batched_routed_free(gpointer payload)
{
	struct presence_batched_routed *data = payload;
	g_free(data->host);
	g_free(payload);
}

static void sipe_subscribe_presence_batched_routed(struct sipe_core_private *sipe_private,
						   gpointer payload)
{
	struct presence_batched_routed *data = payload;
	const GSList *buddies = data->buddies;
	gchar *resources_uri = g_strdup("");
	while (buddies) {
		gchar *tmp = resources_uri;
		resources_uri = g_strdup_printf("%s<resource uri=\"%s\"/>\n", tmp, (char *) buddies->data);
		g_free(tmp);
		buddies = buddies->next;
	}
	sipe_subscribe_presence_batched_to(sipe_private,
					   resources_uri,
					   data->host);
}

static void sipe_subscribe_presence_batched_schedule(struct sipe_core_private *sipe_private,
						     const gchar *action_name,
						     const gchar *who,
						     GSList *buddies,
						     int timeout)
{
	struct sip_subscription *subscription = g_hash_table_lookup(sipe_private->subscriptions,
								    action_name);
	struct presence_batched_routed *payload = g_malloc(sizeof(struct presence_batched_routed));

	if (subscription->buddies) {
		/* merge old and new list */
		GSList *entry = buddies;
		while (entry) {
			subscription->buddies = sipe_utils_slist_insert_unique_sorted(subscription->buddies,
										      g_strdup(entry->data),
										      (GCompareFunc) g_ascii_strcasecmp,
										      g_free);
			entry = entry->next;
		}
		sipe_utils_slist_free_full(buddies, g_free);
	} else {
		/* no list yet, simply take ownership of whole list */
		subscription->buddies = buddies;
	}

	payload->host    = g_strdup(who);
	payload->buddies = subscription->buddies;
	sipe_schedule_seconds(sipe_private,
			      action_name,
			      payload,
			      timeout,
			      sipe_subscribe_presence_batched_routed,
			      sipe_subscribe_presence_batched_routed_free);
	SIPE_DEBUG_INFO("Resubscription multiple contacts with batched support & route(%s) in %d", who, timeout);
}

static void sipe_subscribe_resource_uri_with_context(const gchar *name,
						     gpointer value,
						     gchar **resources_uri)
{
	struct sipe_buddy *sbuddy = (struct sipe_buddy *)value;
	gchar *context = sbuddy && sbuddy->just_added ? "><context/></resource>" : "/>";
	gchar *tmp = *resources_uri;

	/* should be enough to include context one time */
	if (sbuddy)
		sbuddy->just_added = FALSE;

	*resources_uri = g_strdup_printf("%s<resource uri=\"%s\"%s\n", tmp, name, context);
	g_free(tmp);
}

static void sipe_subscribe_resource_uri(const char *name,
					SIPE_UNUSED_PARAMETER gpointer value,
					gchar **resources_uri)
{
	gchar *tmp = *resources_uri;
        *resources_uri = g_strdup_printf("%s<resource uri=\"%s\"/>\n", tmp, name);
	g_free(tmp);
}

/**
  * A callback for g_hash_table_foreach
  */
static void schedule_buddy_resubscription_cb(char *buddy_name,
					     SIPE_UNUSED_PARAMETER struct sipe_buddy *buddy,
					     struct sipe_core_private *sipe_private)
{
	guint time_range = (sipe_buddy_count(sipe_private) * 1000) / 25; /* time interval for 25 requests per sec. In msec. */

	/*
	 * g_hash_table_size() can never return 0, otherwise this function
	 * wouldn't be called :-) But to keep Coverity happy...
	 */
	if (time_range) {
		gchar *action_name = sipe_utils_presence_key(buddy_name);
		guint timeout = ((guint) rand()) / (RAND_MAX / time_range) + 1; /* random period within the range but never 0! */

		sipe_schedule_mseconds(sipe_private,
				       action_name,
				       g_strdup(buddy_name),
				       timeout,
				       sipe_subscribe_presence_single_cb,
				       g_free);
		g_free(action_name);
	}
}

void sipe_subscribe_presence_initial(struct sipe_core_private *sipe_private)
{
	/*
	 * Subscribe to buddies, but only do it once.
	 * We'll resubsribe to them based on the Expire field values.
	 */
	if (!SIPE_CORE_PRIVATE_FLAG_IS(SUBSCRIBED_BUDDIES)) {

		if (SIPE_CORE_PRIVATE_FLAG_IS(BATCHED_SUPPORT)) {
			gchar *to = sip_uri_self(sipe_private);
			gchar *resources_uri = g_strdup("");
			if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
				sipe_buddy_foreach(sipe_private,
						   (GHFunc) sipe_subscribe_resource_uri_with_context,
						   &resources_uri);
			} else {
				sipe_buddy_foreach(sipe_private,
						   (GHFunc) sipe_subscribe_resource_uri,
						   &resources_uri);
			}
			sipe_subscribe_presence_batched_to(sipe_private, resources_uri, to);
			g_free(to);

		} else {
			sipe_buddy_foreach(sipe_private,
					   (GHFunc) schedule_buddy_resubscription_cb,
					   sipe_private);
		}

		SIPE_CORE_PRIVATE_FLAG_SET(SUBSCRIBED_BUDDIES);
	}
}

void sipe_subscribe_poolfqdn_resource_uri(const char *host,
					  GSList *server,
					  struct sipe_core_private *sipe_private)
{
	struct presence_batched_routed *payload = g_malloc(sizeof(struct presence_batched_routed));
	SIPE_DEBUG_INFO("process_incoming_notify_rlmi_resub: pool(%s)", host);
	payload->host    = g_strdup(host);
	payload->buddies = server;
	sipe_subscribe_presence_batched_routed(sipe_private,
					       payload);
	sipe_subscribe_presence_batched_routed_free(payload);
	sipe_utils_slist_free_full(server, g_free);
}


/*
 * subscription expiration handling
 */
struct event_subscription_data {
	const gchar *event;
	sipe_schedule_action callback;
	guint flags;
};

#define EVENT_OCS2005 0x00000001
#define EVENT_OCS2007 0x00000002

static const struct event_subscription_data events_table[] =
{
	/*
	 * For 2007+ it does not make sence to subscribe to:
	 *
	 *   presence.wpending
	 *   vnd-microsoft-roaming-ACL
	 *   vnd-microsoft-provisioning (not v2)
	 *
	 * These are only needed as backward compatibility for older clients
	 *
	 * For 2005- we publish our initial statuses only after we received
	 * our existing UserInfo data in response to self subscription.
	 * Only in this case we won't override existing UserInfo data
	 * set earlier or by other client on our behalf.
	 *
	 * For 2007+ we publish our initial statuses and calendar data only
	 * after we received our existing publications in roaming_self.
	 * Only in this case we know versions of current publications made
	 * on our behalf.
	 */
	{ "presence.wpending",              sipe_subscribe_presence_wpending,
		  EVENT_OCS2005                 },
	{ "vnd-microsoft-roaming-ACL",      sipe_subscribe_roaming_acl,
		  EVENT_OCS2005                 },
	{ "vnd-microsoft-roaming-contacts", sipe_subscribe_roaming_contacts,
		  EVENT_OCS2005 | EVENT_OCS2007 },
	{ "vnd-microsoft-provisioning",     sipe_subscribe_roaming_provisioning,
		  EVENT_OCS2005                 },
	{ "vnd-microsoft-provisioning-v2",  sipe_subscribe_roaming_provisioning_v2,
		  EVENT_OCS2007                 },
	{ "vnd-microsoft-roaming-self",     sipe_subscribe_roaming_self,
		  EVENT_OCS2007                 },
	{ NULL, NULL, 0 }
};

static void sipe_subscription_expiration(struct sipe_core_private *sipe_private,
					 struct sipmsg *msg,
					 const gchar *event)
{
	const gchar *expires_header = sipmsg_find_header(msg, "Expires");
	guint timeout = expires_header ? strtol(expires_header, NULL, 10) : 0;

	if (timeout) {
		/* 2 min ahead of expiration */
		if (timeout > 240) timeout -= 120;

		if (sipe_strcase_equal(event, "presence")) {
			gchar *who = parse_from(sipmsg_find_header(msg, "To"));

			if (SIPE_CORE_PRIVATE_FLAG_IS(BATCHED_SUPPORT)) {
				sipe_process_presence_timeout(sipe_private, msg, who, timeout);
			} else {
				gchar *action_name = sipe_utils_presence_key(who);
				sipe_schedule_seconds(sipe_private,
						      action_name,
						      g_strdup(who),
						      timeout,
						      sipe_subscribe_presence_single_cb,
						      g_free);
				g_free(action_name);
				SIPE_DEBUG_INFO("Resubscription single contact '%s' in %d seconds", who, timeout);
			}
			g_free(who);

		} else {
			const struct event_subscription_data *esd;

			for (esd = events_table; esd->event; esd++) {
				if (sipe_strcase_equal(event, esd->event)) {
					gchar *action_name = g_strdup_printf("<%s>", event);
					sipe_schedule_seconds(sipe_private,
							      action_name,
							      NULL,
							      timeout,
							      esd->callback,
							      NULL);
					g_free(action_name);
					SIPE_DEBUG_INFO("Resubscription to event '%s' in %d seconds", event, timeout);
					break;
				}
			}
		}
	}
}

/*
 * Initial event subscription
 */
void sipe_subscription_self_events(struct sipe_core_private *sipe_private)
{
	const guint mask = SIPE_CORE_PRIVATE_FLAG_IS(OCS2007) ? EVENT_OCS2007 : EVENT_OCS2005;
	const struct event_subscription_data *esd;

	/* subscribe to those events which are selected for
	 * this version and are allowed by the server */
	for (esd = events_table; esd->event; esd++)
		if ((esd->flags & mask) &&
		    (g_slist_find_custom(sipe_private->allowed_events,
					 esd->event,
					 (GCompareFunc) g_ascii_strcasecmp) != NULL))
			(*esd->callback)(sipe_private, NULL);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
