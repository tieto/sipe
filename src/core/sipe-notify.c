/**
 * @file sipe-notify.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-2013 SIPE Project <http://sipe.sourceforge.net/>
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

#include "sipmsg.h"
#include "sip-csta.h"
#include "sip-soap.h"
#include "sipe-backend.h"
#include "sipe-buddy.h"
#include "sipe-cal.h"
#include "sipe-conf.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-group.h"
#include "sipe-groupchat.h"
#include "sipe-media.h"
#include "sipe-mime.h"
#include "sipe-nls.h"
#include "sipe-notify.h"
#include "sipe-ocs2005.h"
#include "sipe-ocs2007.h"
#include "sipe-status.h"
#include "sipe-subscriptions.h"
#include "sipe-ucs.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

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
	for (node = sipe_xml_child(xn_provision_group_list, "provisionGroup");
	     node;
	     node = sipe_xml_twin(node)) {
		const gchar *node_name = sipe_xml_attribute(node, "name");

		/* ServerConfiguration */
		if (sipe_strequal("ServerConfiguration", node_name)) {
			const gchar *dlx_uri_str = SIPE_CORE_PRIVATE_FLAG_IS(REMOTE_USER) ?
					"dlxExternalUrl" : "dlxInternalUrl";
			const gchar *addressbook_uri_str = SIPE_CORE_PRIVATE_FLAG_IS(REMOTE_USER) ?
					"absExternalServerUrl" : "absInternalServerUrl";

			g_free(sipe_private->focus_factory_uri);
			sipe_private->focus_factory_uri = sipe_xml_data(sipe_xml_child(node, "focusFactoryUri"));
			SIPE_DEBUG_INFO("sipe_process_provisioning_v2: sipe_private->focus_factory_uri=%s",
					sipe_private->focus_factory_uri ? sipe_private->focus_factory_uri : "");

			g_free(sipe_private->dlx_uri);
			sipe_private->dlx_uri = sipe_xml_data(sipe_xml_child(node, dlx_uri_str));
			SIPE_DEBUG_INFO("sipe_process_provisioning_v2: sipe_private->dlx_uri=%s",
					sipe_private->dlx_uri ? sipe_private->dlx_uri : "");

			g_free(sipe_private->addressbook_uri);
			sipe_private->addressbook_uri = sipe_xml_data(sipe_xml_child(node, addressbook_uri_str));
			SIPE_DEBUG_INFO("sipe_process_provisioning_v2: sipe_private->addressbook_uri=%s",
					sipe_private->addressbook_uri ? sipe_private->addressbook_uri : "");

#ifdef HAVE_VV
			g_free(sipe_private->test_call_bot_uri);
			sipe_private->test_call_bot_uri = sipe_xml_data(sipe_xml_child(node, "botSipUriForTestCall"));
			SIPE_DEBUG_INFO("sipe_process_provisioning_v2: sipe_private->test_call_bot_uri=%s",
					sipe_private->test_call_bot_uri ? sipe_private->test_call_bot_uri : "");

			g_free(sipe_private->mras_uri);
			sipe_private->mras_uri = g_strstrip(sipe_xml_data(sipe_xml_child(node, "mrasUri")));
			SIPE_DEBUG_INFO("sipe_process_provisioning_v2: sipe_private->mras_uri=%s",
					sipe_private->mras_uri ? sipe_private->mras_uri : "");

			if (sipe_private->mras_uri)
					sipe_media_get_av_edge_credentials(sipe_private);
#endif

		/* persistentChatConfiguration */
		} else if (sipe_strequal("persistentChatConfiguration", node_name)) {
			const sipe_xml *property;
			gboolean enabled = FALSE;
			gchar *uri = NULL;

			for (property = sipe_xml_child(node, "propertyEntryList/property");
			     property;
			     property = sipe_xml_twin(property)) {
				const gchar *name = sipe_xml_attribute(property, "name");
				gchar *value = sipe_xml_data(property);

				if (sipe_strequal(name, "EnablePersistentChat")) {
					enabled = sipe_strequal(value, "true");

				} else if (sipe_strequal(name, "DefaultPersistentChatPoolUri")) {
					g_free(uri);
					uri = value;
					value = NULL;
				}
				g_free(value);
			}

			if (enabled) {
				g_free(sipe_private->persistentChatPool_uri);
				sipe_private->persistentChatPool_uri = g_strdup(sipe_get_no_sip_uri(uri));
				SIPE_DEBUG_INFO("sipe_process_provisioning_v2: sipe_private->persistentChatPool_uri=%s",
						sipe_private->persistentChatPool_uri ? sipe_private->persistentChatPool_uri : "");
			}
			g_free(uri);
		}

	}
	sipe_xml_free(xn_provision_group_list);

	if (sipe_private->dlx_uri && sipe_private->addressbook_uri) {
		/* Some buddies might have been added before we received this
		 * provisioning notify with DLX and addressbook URIs. Now we can
		 * trigger an update of their photos. */
		sipe_buddy_refresh_photos(sipe_private);
	}

	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007))
		/* persistentChatPool_uri has been set at this point */
		sipe_groupchat_init(sipe_private);
}

static void process_incoming_notify_rlmi_resub(struct sipe_core_private *sipe_private,
					       const gchar *data, unsigned len)
{
	sipe_xml *xn_list;
	const sipe_xml *xn_resource;
	GHashTable *servers = g_hash_table_new_full(g_str_hash, g_str_equal,
						    g_free, NULL);

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
				gchar *user    = g_strdup(uri);
				gchar *host    = g_strdup(poolFqdn);
				GSList *server = g_hash_table_lookup(servers,
								     host);
				server = g_slist_append(server, user);
				g_hash_table_insert(servers, host, server);
			} else {
				sipe_subscribe_presence_single(sipe_private,
							       uri,
							       uri);
			}
                }
	}

	/* Send out any deferred poolFqdn subscriptions */
	g_hash_table_foreach(servers, (GHFunc) sipe_subscribe_poolfqdn_resource_uri, sipe_private);
	g_hash_table_destroy(servers);

	sipe_xml_free(xn_list);
}

/**
 * Update user phone
 * Suitable for both 2005 and 2007 systems.
 *
 * @param uri                   buddy SIP URI with 'sip:' prefix whose info we want to change.
 * @param phone_type
 * @param phone                 may be modified to strip white space
 * @param phone_display_string  may be modified to strip white space
 */
static void
sipe_update_user_phone(struct sipe_core_private *sipe_private,
		       const gchar *uri,
		       const gchar *phone_type,
		       gchar *phone,
		       gchar *phone_display_string)
{
	sipe_buddy_info_fields phone_node = SIPE_BUDDY_INFO_WORK_PHONE; /* work phone by default */
	sipe_buddy_info_fields phone_display_node = SIPE_BUDDY_INFO_WORK_PHONE_DISPLAY; /* work phone by default */

	if(!phone || strlen(phone) == 0) return;

	if ((sipe_strequal(phone_type, "mobile") ||  sipe_strequal(phone_type, "cell"))) {
		phone_node = SIPE_BUDDY_INFO_MOBILE_PHONE;
		phone_display_node = SIPE_BUDDY_INFO_MOBILE_PHONE_DISPLAY;
	} else if (sipe_strequal(phone_type, "home")) {
		phone_node = SIPE_BUDDY_INFO_HOME_PHONE;
		phone_display_node = SIPE_BUDDY_INFO_HOME_PHONE_DISPLAY;
	} else if (sipe_strequal(phone_type, "other")) {
		phone_node = SIPE_BUDDY_INFO_OTHER_PHONE;
		phone_display_node = SIPE_BUDDY_INFO_OTHER_PHONE_DISPLAY;
	} else if (sipe_strequal(phone_type, "custom1")) {
		phone_node = SIPE_BUDDY_INFO_CUSTOM1_PHONE;
		phone_display_node = SIPE_BUDDY_INFO_CUSTOM1_PHONE_DISPLAY;
	}

	sipe_buddy_update_property(sipe_private, uri, phone_node, phone);
	if (phone_display_string) {
		sipe_buddy_update_property(sipe_private, uri, phone_display_node, phone_display_string);
	}
}

static void process_incoming_notify_msrtc(struct sipe_core_private *sipe_private,
					  const gchar *data,
					  unsigned len)
{
	char *activity = NULL;
	const char *epid;
	const char *status_id = NULL;
	const char *name;
	char *uri;
	char *self_uri = sip_uri_self(sipe_private);
	int avl;
	int act;
	const char *device_name = NULL;
	const char *cal_start_time = NULL;
	const char *cal_granularity = NULL;
	char *cal_free_busy_base64 = NULL;
	struct sipe_buddy *sbuddy;
	const sipe_xml *node;
	sipe_xml *xn_presentity;
	const sipe_xml *xn_availability;
	const sipe_xml *xn_activity;
	const sipe_xml *xn_display_name;
	const sipe_xml *xn_email;
	const sipe_xml *xn_phone_number;
	const sipe_xml *xn_userinfo;
	const sipe_xml *xn_note;
	const sipe_xml *xn_oof;
	const sipe_xml *xn_state;
	const sipe_xml *xn_contact;
	char *note;
	int user_avail;
	const char *user_avail_nil;
	int res_avail;
	time_t user_avail_since = 0;
	time_t activity_since = 0;

	/* fix for Reuters environment on Linux */
	if (data && strstr(data, "encoding=\"utf-16\"")) {
		char *tmp_data;
		tmp_data = sipe_utils_str_replace(data, "encoding=\"utf-16\"", "encoding=\"utf-8\"");
		xn_presentity = sipe_xml_parse(tmp_data, strlen(tmp_data));
		g_free(tmp_data);
	} else {
		xn_presentity = sipe_xml_parse(data, len);
	}

	xn_availability = sipe_xml_child(xn_presentity, "availability");
	xn_activity = sipe_xml_child(xn_presentity, "activity");
	xn_display_name = sipe_xml_child(xn_presentity, "displayName");
	xn_email = sipe_xml_child(xn_presentity, "email");
	xn_phone_number = sipe_xml_child(xn_presentity, "phoneNumber");
	xn_userinfo = sipe_xml_child(xn_presentity, "userInfo");
	xn_oof = xn_userinfo ? sipe_xml_child(xn_userinfo, "oof") : NULL;
	xn_state = xn_userinfo ? sipe_xml_child(xn_userinfo, "states/state"): NULL;
	user_avail = xn_state ? sipe_xml_int_attribute(xn_state, "avail", 0) : 0;
	user_avail_since = xn_state ? sipe_utils_str_to_time(sipe_xml_attribute(xn_state, "since")) : 0;
	user_avail_nil = xn_state ? sipe_xml_attribute(xn_state, "nil") : NULL;
	xn_contact = xn_userinfo ? sipe_xml_child(xn_userinfo, "contact") : NULL;
	xn_note = xn_userinfo ? sipe_xml_child(xn_userinfo, "note") : NULL;
	note = xn_note ? sipe_xml_data(xn_note) : NULL;

	if (sipe_strequal(user_avail_nil, "true")) {	/* null-ed */
		user_avail = 0;
		user_avail_since = 0;
	}

	name = sipe_xml_attribute(xn_presentity, "uri"); /* without 'sip:' prefix */
	uri = sip_uri_from_name(name);
	avl = sipe_xml_int_attribute(xn_availability, "aggregate", 0);
	epid = sipe_xml_attribute(xn_availability, "epid");
	act = sipe_xml_int_attribute(xn_activity, "aggregate", 0);

	status_id = sipe_ocs2005_status_from_activity_availability(act, avl);
	activity = g_strdup(sipe_ocs2005_activity_description(act));
	res_avail = sipe_ocs2007_availability_from_status(status_id, NULL);
	if (user_avail > res_avail) {
		res_avail = user_avail;
		status_id = sipe_ocs2007_status_from_legacy_availability(user_avail, NULL);
	}

	if (xn_display_name) {
		char *display_name = g_strdup(sipe_xml_attribute(xn_display_name, "displayName"));
		char *email        = xn_email ? g_strdup(sipe_xml_attribute(xn_email, "email")) : NULL;
		char *phone_label  = xn_phone_number ? g_strdup(sipe_xml_attribute(xn_phone_number, "label")) : NULL;
		char *phone_number = xn_phone_number ? g_strdup(sipe_xml_attribute(xn_phone_number, "number")) : NULL;
		char *tel_uri      = sip_to_tel_uri(phone_number);

		sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_DISPLAY_NAME, display_name);
		sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_EMAIL, email);
		sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_WORK_PHONE, tel_uri);
		sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_WORK_PHONE_DISPLAY, !is_empty(phone_label) ? phone_label : phone_number);

		g_free(tel_uri);
		g_free(phone_label);
		g_free(phone_number);
		g_free(email);
		g_free(display_name);
	}

	if (xn_contact) {
		/* tel */
		for (node = sipe_xml_child(xn_contact, "tel"); node; node = sipe_xml_twin(node))
		{
			/* Ex.: <tel type="work">tel:+3222220000</tel> */
			const char *phone_type = sipe_xml_attribute(node, "type");
			char* phone = sipe_xml_data(node);

			sipe_update_user_phone(sipe_private, uri, phone_type, phone, NULL);

			g_free(phone);
		}
	}

	if (xn_display_name || xn_contact)
		sipe_backend_buddy_refresh_properties(SIPE_CORE_PUBLIC, uri);

	/* devicePresence */
	for (node = sipe_xml_child(xn_presentity, "devices/devicePresence"); node; node = sipe_xml_twin(node)) {
		const sipe_xml *xn_device_name;
		const sipe_xml *xn_calendar_info;
		const sipe_xml *xn_state;
		char *state;

		/* deviceName */
		if (sipe_strequal(sipe_xml_attribute(node, "epid"), epid)) {
			xn_device_name = sipe_xml_child(node, "deviceName");
			device_name = xn_device_name ? sipe_xml_attribute(xn_device_name, "name") : NULL;
		}

		/* calendarInfo */
		xn_calendar_info = sipe_xml_child(node, "calendarInfo");
		if (xn_calendar_info) {
			const char *cal_start_time_tmp = sipe_xml_attribute(xn_calendar_info, "startTime");

			if (cal_start_time) {
				time_t cal_start_time_t     = sipe_utils_str_to_time(cal_start_time);
				time_t cal_start_time_t_tmp = sipe_utils_str_to_time(cal_start_time_tmp);

				if (cal_start_time_t_tmp > cal_start_time_t) {
					cal_start_time = cal_start_time_tmp;
					cal_granularity = sipe_xml_attribute(xn_calendar_info, "granularity");
					g_free(cal_free_busy_base64);
					cal_free_busy_base64 = sipe_xml_data(xn_calendar_info);

					SIPE_DEBUG_INFO("process_incoming_notify_msrtc: startTime=%s granularity=%s cal_free_busy_base64=\n%s", cal_start_time, cal_granularity, cal_free_busy_base64);
				}
			} else {
				cal_start_time = cal_start_time_tmp;
				cal_granularity = sipe_xml_attribute(xn_calendar_info, "granularity");
				g_free(cal_free_busy_base64);
				cal_free_busy_base64 = sipe_xml_data(xn_calendar_info);

				SIPE_DEBUG_INFO("process_incoming_notify_msrtc: startTime=%s granularity=%s cal_free_busy_base64=\n%s", cal_start_time, cal_granularity, cal_free_busy_base64);
			}
		}

		/* state */
		xn_state = sipe_xml_child(node, "states/state");
		if (xn_state) {
			int dev_avail = sipe_xml_int_attribute(xn_state, "avail", 0);
			time_t dev_avail_since = sipe_utils_str_to_time(sipe_xml_attribute(xn_state, "since"));

			state = sipe_xml_data(xn_state);
			if (dev_avail_since > user_avail_since &&
			    dev_avail >= res_avail)
			{
				const gchar *new_desc;
				res_avail = dev_avail;
				if (!is_empty(state)) {
					if (sipe_strequal(state, sipe_status_activity_to_token(SIPE_ACTIVITY_ON_PHONE))) {
						g_free(activity);
						activity = g_strdup(sipe_core_activity_description(SIPE_ACTIVITY_ON_PHONE));
					} else if (sipe_strequal(state, "presenting")) {
						g_free(activity);
						activity = g_strdup(sipe_core_activity_description(SIPE_ACTIVITY_IN_CONF));
					} else {
						activity = state;
						state = NULL;
					}
					activity_since = dev_avail_since;
				}
				status_id = sipe_ocs2007_status_from_legacy_availability(res_avail, NULL);
				new_desc  = sipe_ocs2007_legacy_activity_description(res_avail);
				if (new_desc) {
					g_free(activity);
					activity = g_strdup(new_desc);
				}
			}
			g_free(state);
		}
	}

	/* oof */
	if (xn_oof && res_avail >= 15000) { /* 12000 in 2007 */
		g_free(activity);
		activity = g_strdup(sipe_core_activity_description(SIPE_ACTIVITY_OOF));
		activity_since = 0;
	}

	sbuddy = sipe_buddy_find_by_uri(sipe_private, uri);
	if (sbuddy)
	{
		g_free(sbuddy->activity);
		sbuddy->activity = activity;
		activity = NULL;

		sbuddy->activity_since = activity_since;

		sbuddy->user_avail = user_avail;
		sbuddy->user_avail_since = user_avail_since;

		g_free(sbuddy->note);
		sbuddy->note = NULL;
		if (!is_empty(note)) { sbuddy->note = g_markup_escape_text(note, -1); }

		sbuddy->is_oof_note = (xn_oof != NULL);

		g_free(sbuddy->device_name);
		sbuddy->device_name = NULL;
		if (!is_empty(device_name)) { sbuddy->device_name = g_strdup(device_name); }

		if (!is_empty(cal_free_busy_base64)) {
			g_free(sbuddy->cal_start_time);
			sbuddy->cal_start_time = g_strdup(cal_start_time);

			sbuddy->cal_granularity = sipe_strcase_equal(cal_granularity, "PT15M") ? 15 : 0;

			g_free(sbuddy->cal_free_busy_base64);
			sbuddy->cal_free_busy_base64 = cal_free_busy_base64;
			cal_free_busy_base64 = NULL;

			g_free(sbuddy->cal_free_busy);
			sbuddy->cal_free_busy = NULL;
		}

		sbuddy->last_non_cal_status_id = status_id;
		g_free(sbuddy->last_non_cal_activity);
		sbuddy->last_non_cal_activity = g_strdup(sbuddy->activity);

		if (sipe_strcase_equal(sbuddy->name, self_uri)) {
			if (!sipe_strequal(sbuddy->note, sipe_private->note)) /* not same */
			{
				if (sbuddy->is_oof_note)
					SIPE_CORE_PRIVATE_FLAG_SET(OOF_NOTE);
				else
					SIPE_CORE_PRIVATE_FLAG_UNSET(OOF_NOTE);

				g_free(sipe_private->note);
				sipe_private->note = g_strdup(sbuddy->note);

				sipe_private->note_since = time(NULL);
			}

			sipe_status_set_token(sipe_private,
					      sbuddy->last_non_cal_status_id);
		}
	}
	g_free(cal_free_busy_base64);
	g_free(activity);

	SIPE_DEBUG_INFO("process_incoming_notify_msrtc: status(%s)", status_id);
	sipe_core_buddy_got_status(SIPE_CORE_PUBLIC, uri,
				   sipe_status_token_to_activity(status_id));

	if (!SIPE_CORE_PRIVATE_FLAG_IS(OCS2007) && sipe_strcase_equal(self_uri, uri)) {
		sipe_ocs2005_user_info_has_updated(sipe_private, xn_userinfo);
	}

	g_free(note);
	sipe_xml_free(xn_presentity);
	g_free(uri);
	g_free(self_uri);
}

static void process_incoming_notify_rlmi(struct sipe_core_private *sipe_private,
					 const gchar *data,
					 unsigned len)
{
	const char *uri;
	struct sipe_buddy *sbuddy = NULL;
	sipe_xml *xn_categories;
	const sipe_xml *xn_category;
	const char *status = NULL;
	gboolean do_update_status = FALSE;
	gboolean has_note_cleaned = FALSE;
	gboolean has_free_busy_cleaned = FALSE;

	xn_categories = sipe_xml_parse(data, len);
	uri = sipe_xml_attribute(xn_categories, "uri"); /* with 'sip:' prefix */
	if (uri) {
		sbuddy = sipe_buddy_find_by_uri(sipe_private, uri);
	}

	if (!sbuddy) {
		/* Got presence of a buddy not in our contact list, ignore. */
		sipe_xml_free(xn_categories);
		return;
	}

	for (xn_category = sipe_xml_child(xn_categories, "category");
		 xn_category ;
		 xn_category = sipe_xml_twin(xn_category) )
	{
		const sipe_xml *xn_node;
		const char *tmp;
		const char *attrVar = sipe_xml_attribute(xn_category, "name");
		time_t publish_time = (tmp = sipe_xml_attribute(xn_category, "publishTime")) ?
			sipe_utils_str_to_time(tmp) : 0;

		/* contactCard */
		if (sipe_strequal(attrVar, "contactCard"))
		{
			const sipe_xml *card = sipe_xml_child(xn_category, "contactCard");

			if (card) {
				const sipe_xml *node;
				/* identity - Display Name and email */
				node = sipe_xml_child(card, "identity");
				if (node) {
					char* display_name = sipe_xml_data(
						sipe_xml_child(node, "name/displayName"));
					char* email = sipe_xml_data(
						sipe_xml_child(node, "email"));

					sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_DISPLAY_NAME, display_name);
					sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_EMAIL, email);

					g_free(display_name);
					g_free(email);
				}
				/* company */
				node = sipe_xml_child(card, "company");
				if (node) {
					char* company = sipe_xml_data(node);
					sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_COMPANY, company);
					g_free(company);
				}
				/* department */
				node = sipe_xml_child(card, "department");
				if (node) {
					char* department = sipe_xml_data(node);
					sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_DEPARTMENT, department);
					g_free(department);
				}
				/* title */
				node = sipe_xml_child(card, "title");
				if (node) {
					char* title = sipe_xml_data(node);
					sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_JOB_TITLE, title);
					g_free(title);
				}
				/* office */
				node = sipe_xml_child(card, "office");
				if (node) {
					char* office = sipe_xml_data(node);
					sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_OFFICE, office);
					g_free(office);
				}
				/* site (url) */
				node = sipe_xml_child(card, "url");
				if (node) {
					char* site = sipe_xml_data(node);
					sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_SITE, site);
					g_free(site);
				}
				/* phone */
				for (node = sipe_xml_child(card, "phone");
				     node;
				     node = sipe_xml_twin(node))
				{
					const char *phone_type = sipe_xml_attribute(node, "type");
					char* phone = sipe_xml_data(sipe_xml_child(node, "uri"));
					char* phone_display_string = sipe_xml_data(sipe_xml_child(node, "displayString"));

					sipe_update_user_phone(sipe_private, uri, phone_type, phone, phone_display_string);

					g_free(phone);
					g_free(phone_display_string);
				}
				/* address */
				for (node = sipe_xml_child(card, "address");
				     node;
				     node = sipe_xml_twin(node))
				{
					if (sipe_strequal(sipe_xml_attribute(node, "type"), "work")) {
						char* street = sipe_xml_data(sipe_xml_child(node, "street"));
						char* city = sipe_xml_data(sipe_xml_child(node, "city"));
						char* state = sipe_xml_data(sipe_xml_child(node, "state"));
						char* zipcode = sipe_xml_data(sipe_xml_child(node, "zipcode"));
						char* country_code = sipe_xml_data(sipe_xml_child(node, "countryCode"));

						sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_STREET, street);
						sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_CITY, city);
						sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_STATE, state);
						sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_ZIPCODE, zipcode);
						sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_COUNTRY, country_code);

						g_free(street);
						g_free(city);
						g_free(state);
						g_free(zipcode);
						g_free(country_code);

						break;
					}
				}
			}
		}
		/* note */
		else if (sipe_strequal(attrVar, "note"))
		{
			if (!has_note_cleaned) {
				has_note_cleaned = TRUE;

				g_free(sbuddy->note);
				sbuddy->note = NULL;
				sbuddy->is_oof_note = FALSE;
				sbuddy->note_since = publish_time;

				do_update_status = TRUE;
			}
			if (publish_time >= sbuddy->note_since) {
				/* clean up in case no 'note' element is supplied
				 * which indicate note removal in client
				 */
				g_free(sbuddy->note);
				sbuddy->note = NULL;
				sbuddy->is_oof_note = FALSE;
				sbuddy->note_since = publish_time;

				xn_node = sipe_xml_child(xn_category, "note/body");
				if (xn_node) {
					char *tmp;
					sbuddy->note = g_markup_escape_text((tmp = sipe_xml_data(xn_node)), -1);
					g_free(tmp);
					sbuddy->is_oof_note = sipe_strequal(sipe_xml_attribute(xn_node, "type"), "OOF");
					sbuddy->note_since = publish_time;

					SIPE_DEBUG_INFO("process_incoming_notify_rlmi: uri(%s), note(%s)",
							uri, sbuddy->note ? sbuddy->note : "");
				}
				/* to trigger UI refresh in case no status info is supplied in this update */
				do_update_status = TRUE;
			}
		}
		/* state */
		else if(sipe_strequal(attrVar, "state"))
		{
			char *tmp;
			int availability;
			const sipe_xml *xn_availability;
			const sipe_xml *xn_activity;
			const sipe_xml *xn_device;
			const sipe_xml *xn_meeting_subject;
			const sipe_xml *xn_meeting_location;
			const gchar *legacy_activity;

			xn_node = sipe_xml_child(xn_category, "state");
			if (!xn_node) continue;
			xn_availability = sipe_xml_child(xn_node, "availability");
			if (!xn_availability) continue;
			xn_activity = sipe_xml_child(xn_node, "activity");
			xn_meeting_subject = sipe_xml_child(xn_node, "meetingSubject");
			xn_meeting_location = sipe_xml_child(xn_node, "meetingLocation");

			tmp = sipe_xml_data(xn_availability);
			availability = atoi(tmp);
			g_free(tmp);

			sbuddy->is_mobile = FALSE;
			xn_device = sipe_xml_child(xn_node, "device");
			if (xn_device) {
				tmp = sipe_xml_data(xn_device);
				sbuddy->is_mobile = !g_ascii_strcasecmp(tmp, "Mobile");
				g_free(tmp);
			}

			/* activity */
			g_free(sbuddy->activity);
			sbuddy->activity = NULL;
			if (xn_activity) {
				const char *token = sipe_xml_attribute(xn_activity, "token");
				const sipe_xml *xn_custom = sipe_xml_child(xn_activity, "custom");

				/* from token */
				if (!is_empty(token)) {
					sbuddy->activity = g_strdup(sipe_core_activity_description(sipe_status_token_to_activity(token)));
				}
				/* from custom element */
				if (xn_custom) {
					char *custom = sipe_xml_data(xn_custom);

					if (!is_empty(custom)) {
						g_free(sbuddy->activity);
						sbuddy->activity = custom;
						custom = NULL;
					}
					g_free(custom);
				}
			}
			/* meeting_subject */
			g_free(sbuddy->meeting_subject);
			sbuddy->meeting_subject = NULL;
			if (xn_meeting_subject) {
				char *meeting_subject = sipe_xml_data(xn_meeting_subject);

				if (!is_empty(meeting_subject)) {
					sbuddy->meeting_subject = meeting_subject;
					meeting_subject = NULL;
				}
				g_free(meeting_subject);
			}
			/* meeting_location */
			g_free(sbuddy->meeting_location);
			sbuddy->meeting_location = NULL;
			if (xn_meeting_location) {
				char *meeting_location = sipe_xml_data(xn_meeting_location);

				if (!is_empty(meeting_location)) {
					sbuddy->meeting_location = meeting_location;
					meeting_location = NULL;
				}
				g_free(meeting_location);
			}

			status = sipe_ocs2007_status_from_legacy_availability(availability, NULL);
			legacy_activity = sipe_ocs2007_legacy_activity_description(availability);
			if (sbuddy->activity && legacy_activity) {
				gchar *tmp2 = sbuddy->activity;

				sbuddy->activity = g_strdup_printf("%s, %s", sbuddy->activity, legacy_activity);
				g_free(tmp2);
			} else if (legacy_activity) {
				sbuddy->activity = g_strdup(legacy_activity);
			}

			do_update_status = TRUE;
		}
		/* calendarData */
		else if(sipe_strequal(attrVar, "calendarData"))
		{
			const sipe_xml *xn_free_busy = sipe_xml_child(xn_category, "calendarData/freeBusy");
			const sipe_xml *xn_working_hours = sipe_xml_child(xn_category, "calendarData/WorkingHours");

			if (xn_free_busy) {
				if (!has_free_busy_cleaned) {
					has_free_busy_cleaned = TRUE;

					g_free(sbuddy->cal_start_time);
					sbuddy->cal_start_time = NULL;

					g_free(sbuddy->cal_free_busy_base64);
					sbuddy->cal_free_busy_base64 = NULL;

					g_free(sbuddy->cal_free_busy);
					sbuddy->cal_free_busy = NULL;

					sbuddy->cal_free_busy_published = publish_time;
				}

				if (publish_time >= sbuddy->cal_free_busy_published) {
					g_free(sbuddy->cal_start_time);
					sbuddy->cal_start_time = g_strdup(sipe_xml_attribute(xn_free_busy, "startTime"));

					sbuddy->cal_granularity = sipe_strcase_equal(sipe_xml_attribute(xn_free_busy, "granularity"), "PT15M") ?
						15 : 0;

					g_free(sbuddy->cal_free_busy_base64);
					sbuddy->cal_free_busy_base64 = sipe_xml_data(xn_free_busy);

					g_free(sbuddy->cal_free_busy);
					sbuddy->cal_free_busy = NULL;

					sbuddy->cal_free_busy_published = publish_time;

					SIPE_DEBUG_INFO("process_incoming_notify_rlmi: startTime=%s granularity=%d cal_free_busy_base64=\n%s", sbuddy->cal_start_time, sbuddy->cal_granularity, sbuddy->cal_free_busy_base64);
				}
			}

			if (xn_working_hours) {
				sipe_cal_parse_working_hours(xn_working_hours, sbuddy);
			}
		}
	}

	if (do_update_status) {
		guint activity;

		if (status) {
			SIPE_DEBUG_INFO("process_incoming_notify_rlmi: %s", status);
			activity = sipe_status_token_to_activity(status);
		} else {
			/* no status category in this update,
			   using contact's current status */
			activity = sipe_backend_buddy_get_status(SIPE_CORE_PUBLIC,
								 uri);
		}

		sipe_core_buddy_got_status(SIPE_CORE_PUBLIC, uri, activity);
	}

	sipe_backend_buddy_refresh_properties(SIPE_CORE_PUBLIC, uri);

	sipe_xml_free(xn_categories);
}

static void sipe_buddy_status_from_activity(struct sipe_core_private *sipe_private,
					    const gchar *uri,
					    const gchar *activity,
					    gboolean is_online)
{
	if (is_online) {
		const gchar *status_id = NULL;
		if (activity) {
			if (sipe_strequal(activity,
					  sipe_status_activity_to_token(SIPE_ACTIVITY_BUSY))) {
				status_id = sipe_status_activity_to_token(SIPE_ACTIVITY_BUSY);
			} else if (sipe_strequal(activity,
						 sipe_status_activity_to_token(SIPE_ACTIVITY_AWAY))) {
				status_id = sipe_status_activity_to_token(SIPE_ACTIVITY_AWAY);
			}
		}

		if (!status_id) {
			status_id = sipe_status_activity_to_token(SIPE_ACTIVITY_AVAILABLE);
		}

		SIPE_DEBUG_INFO("sipe_buddy_status_from_activity: status_id(%s)", status_id);
		sipe_core_buddy_got_status(SIPE_CORE_PUBLIC, uri,
					   sipe_status_token_to_activity(status_id));
	} else {
		sipe_core_buddy_got_status(SIPE_CORE_PUBLIC, uri,
					   SIPE_ACTIVITY_OFFLINE);
	}
}

static void process_incoming_notify_pidf(struct sipe_core_private *sipe_private,
					 const gchar *data,
					 unsigned len)
{
	gchar *uri;
	gchar *getbasic;
	gchar *activity = NULL;
	sipe_xml *pidf;
	const sipe_xml *basicstatus = NULL, *tuple, *status;
	gboolean isonline = FALSE;
	const sipe_xml *display_name_node;

	pidf = sipe_xml_parse(data, len);
	if (!pidf) {
		SIPE_DEBUG_INFO("process_incoming_notify_pidf: no parseable pidf:%s", data);
		return;
	}

	if ((tuple = sipe_xml_child(pidf, "tuple")))
	{
		if ((status = sipe_xml_child(tuple, "status"))) {
			basicstatus = sipe_xml_child(status, "basic");
		}
	}

	if (!basicstatus) {
		SIPE_DEBUG_INFO_NOFORMAT("process_incoming_notify_pidf: no basic found");
		sipe_xml_free(pidf);
		return;
	}

	getbasic = sipe_xml_data(basicstatus);
	if (!getbasic) {
		SIPE_DEBUG_INFO_NOFORMAT("process_incoming_notify_pidf: no basic data found");
		sipe_xml_free(pidf);
		return;
	}

	SIPE_DEBUG_INFO("process_incoming_notify_pidf: basic-status(%s)", getbasic);
	if (strstr(getbasic, "open")) {
		isonline = TRUE;
	}
	g_free(getbasic);

	uri = sip_uri(sipe_xml_attribute(pidf, "entity")); /* with 'sip:' prefix */ /* AOL comes without the prefix */

	display_name_node = sipe_xml_child(pidf, "display-name");
	if (display_name_node) {
		char * display_name = sipe_xml_data(display_name_node);

		sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_DISPLAY_NAME, display_name);
		g_free(display_name);

		sipe_backend_buddy_refresh_properties(SIPE_CORE_PUBLIC, uri);
	}

	if ((tuple = sipe_xml_child(pidf, "tuple"))) {
		if ((status = sipe_xml_child(tuple, "status"))) {
			if ((basicstatus = sipe_xml_child(status, "activities"))) {
				if ((basicstatus = sipe_xml_child(basicstatus, "activity"))) {
					activity = sipe_xml_data(basicstatus);
					SIPE_DEBUG_INFO("process_incoming_notify_pidf: activity(%s)", activity);
				}
			}
		}
	}

	sipe_buddy_status_from_activity(sipe_private,
					uri,
					activity,
					isonline);

	g_free(activity);
	g_free(uri);
	sipe_xml_free(pidf);
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

/* Replace "~" with localized version of "Other Contacts" */
static const gchar *get_group_name(const sipe_xml *node)
{
	const gchar *name = sipe_xml_attribute(node, "name");
	return(g_str_has_prefix(name, "~") ? _("Other Contacts") : name);
}

static void add_new_group(struct sipe_core_private *sipe_private,
			  const sipe_xml *node)
{
	sipe_group_add(sipe_private,
		       get_group_name(node),
		       NULL,
		       NULL,
		       sipe_xml_int_attribute(node, "id", 0));
}

static void add_new_buddy(struct sipe_core_private *sipe_private,
			  const sipe_xml *node,
			  const gchar *uri)
{
	const gchar *name = sipe_xml_attribute(node, "name");
	struct sipe_buddy *buddy = NULL;
	gchar *tmp;
	gchar **item_groups;
	int i = 0;

	/* assign to group Other Contacts if nothing else received */
	tmp = g_strdup(sipe_xml_attribute(node, "groups"));
	if (is_empty(tmp)) {
		struct sipe_group *group = sipe_group_find_by_name(sipe_private,
								   _("Other Contacts"));
		g_free(tmp);
		tmp = group ? g_strdup_printf("%d", group->id) : g_strdup("1");
	}
	item_groups = g_strsplit(tmp, " ", 0);
	g_free(tmp);

	while (item_groups[i]) {
		struct sipe_group *group = sipe_group_find_by_id(sipe_private,
								 g_ascii_strtod(item_groups[i],
										NULL));

		/* If couldn't find the right group for this contact, */
		/* then just put it in the first group we have	      */
		if (!group)
			group = sipe_group_first(sipe_private);

		if (group) {
			if (!buddy)
				buddy = sipe_buddy_add(sipe_private,
						       uri,
						       NULL,
						       NULL);

			sipe_buddy_add_to_group(sipe_private,
						buddy,
						group,
						name);
		} else {
			SIPE_DEBUG_INFO("No group found for contact %s!  Unable to add to buddy list",
					name);
		}

		i++;
	}

	g_strfreev(item_groups);
}

static gboolean sipe_process_roaming_contacts(struct sipe_core_private *sipe_private,
					      struct sipmsg *msg)
{
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

	/*
	 * Process whole buddy list
	 *
	 *  - Only sent once
	 *    * up to Lync 2010
	 *    * Lync 2013 (and later) with buddy list not migrated
	 *
	 *  - Lync 2013 with buddy list migrated to Unified Contact Store (UCS)
	 *    * Notify piggy-backed on SUBSCRIBE response with empty list
	 *    * NOTIFY send by server with standard list (ignored by us)
	 */
	if (sipe_strequal(sipe_xml_name(isc), "contactList")) {
		const gchar *ucsmode = sipe_xml_attribute(isc, "ucsmode");

		SIPE_CORE_PRIVATE_FLAG_UNSET(LYNC2013);
		if (ucsmode) {
			gboolean migrated = sipe_strcase_equal(ucsmode,
							       "migrated");
			SIPE_CORE_PRIVATE_FLAG_SET(LYNC2013);
			SIPE_DEBUG_INFO_NOFORMAT("contact list contains 'ucsmode' attribute (indicates Lync 2013+)");

			if (migrated)
				SIPE_DEBUG_INFO_NOFORMAT("contact list has been migrated to Unified Contact Store (UCS)");
			sipe_ucs_init(sipe_private, migrated);
		}

		if (!sipe_ucs_is_migrated(sipe_private)) {
			/* Start processing contact list */
			sipe_backend_buddy_list_processing_start(SIPE_CORE_PUBLIC);

			/* Parse groups */
			for (group_node = sipe_xml_child(isc, "group"); group_node; group_node = sipe_xml_twin(group_node))
				add_new_group(sipe_private, group_node);

			/* Make sure we have at least one group */
			if (sipe_group_count(sipe_private) == 0) {
				sipe_group_create(sipe_private,
						  NULL,
						  _("Other Contacts"),
						  NULL);
			}

			/* Parse contacts */
			for (item = sipe_xml_child(isc, "contact"); item; item = sipe_xml_twin(item)) {
				const gchar *name = sipe_xml_attribute(item, "uri");
				gchar *uri        = sip_uri_from_name(name);
				add_new_buddy(sipe_private, item, uri);
				g_free(uri);
			}

			sipe_buddy_cleanup_local_list(sipe_private);

			/* Add self-contact if not there yet. 2005 systems. */
			/* This will resemble subscription to roaming_self in 2007 systems */
			if (!SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
				gchar *self_uri = sip_uri_self(sipe_private);
				sipe_buddy_add(sipe_private,
					       self_uri,
					       NULL,
					       NULL);
				g_free(self_uri);
			}

			/* Finished processing contact list */
			sipe_backend_buddy_list_processing_finish(SIPE_CORE_PUBLIC);
		}

	/* Process buddy list updates */
	} else if (sipe_strequal(sipe_xml_name(isc), "contactDelta")) {

		/* Process new groups */
		for (group_node = sipe_xml_child(isc, "addedGroup"); group_node; group_node = sipe_xml_twin(group_node))
			add_new_group(sipe_private, group_node);

		/* Process modified groups */
		for (group_node = sipe_xml_child(isc, "modifiedGroup"); group_node; group_node = sipe_xml_twin(group_node)) {
			struct sipe_group *group = sipe_group_find_by_id(sipe_private,
									 (int)g_ascii_strtod(sipe_xml_attribute(group_node, "id"),
											     NULL));
			if (group) {
				const gchar *name = get_group_name(group_node);

				if (!(is_empty(name) ||
				      sipe_strequal(group->name, name)) &&
				    sipe_group_rename(sipe_private,
						      group,
						      name))
					SIPE_DEBUG_INFO("Replaced group %d name with %s", group->id, name);
			}
		}

		/* Process new buddies */
		for (item = sipe_xml_child(isc, "addedContact"); item; item = sipe_xml_twin(item)) {
			add_new_buddy(sipe_private,
				      item,
				      sipe_xml_attribute(item, "uri"));
		}

		/* Process modified buddies */
		for (item = sipe_xml_child(isc, "modifiedContact"); item; item = sipe_xml_twin(item)) {
			const gchar *uri = sipe_xml_attribute(item, "uri");
			struct sipe_buddy *buddy = sipe_buddy_find_by_uri(sipe_private,
									  uri);

			if (buddy) {
				gchar **item_groups = g_strsplit(sipe_xml_attribute(item,
										    "groups"),
								 " ", 0);

				/* this should be defined. Otherwise we would get "deletedContact" */
				if (item_groups) {
					const gchar *name = sipe_xml_attribute(item, "name");
					gboolean empty_name = is_empty(name);
					GSList *found = NULL;
					int i = 0;

					while (item_groups[i]) {
						struct sipe_group *group = sipe_group_find_by_id(sipe_private,
												 g_ascii_strtod(item_groups[i],
														NULL));
						/* ignore unkown groups */
						if (group) {
							sipe_backend_buddy b = sipe_backend_buddy_find(SIPE_CORE_PUBLIC,
												       uri,
												       group->name);

							/* add group to found list */
							found = g_slist_prepend(found, group);

							if (b) {
								/* new alias? */
								gchar *b_alias = sipe_backend_buddy_get_alias(SIPE_CORE_PUBLIC,
													      b);

								if (!(empty_name ||
								      sipe_strequal(b_alias, name))) {
									sipe_backend_buddy_set_alias(SIPE_CORE_PUBLIC,
												     b,
												     name);
									SIPE_DEBUG_INFO("Replaced for buddy %s in group '%s' old alias '%s' with '%s'",
											uri, group->name, b_alias, name);
								}
								g_free(b_alias);

							} else {
								const gchar *alias = empty_name ? uri : name;
								/* buddy was not in this group */
								sipe_backend_buddy_add(SIPE_CORE_PUBLIC,
										       uri,
										       alias,
										       group->name);
								sipe_buddy_insert_group(buddy, group);
								SIPE_DEBUG_INFO("Added buddy %s (alias '%s' to group '%s'",
										uri, alias, group->name);
							}
						}

						/* next group */
						i++;
					}
					g_strfreev(item_groups);

 					/* removed from groups? */
					sipe_buddy_update_groups(sipe_private,
								 buddy,
								 found);
					g_slist_free(found);
				}
			}
		}

		/* Process deleted buddies */
		for (item = sipe_xml_child(isc, "deletedContact"); item; item = sipe_xml_twin(item)) {
			const gchar *uri = sipe_xml_attribute(item, "uri");
			struct sipe_buddy *buddy = sipe_buddy_find_by_uri(sipe_private,
									  uri);

			if (buddy) {
				SIPE_DEBUG_INFO("Removing buddy %s", uri);
				sipe_buddy_remove(sipe_private, buddy);
			}
		}

		/* Process deleted groups
		 *
		 * NOTE: all buddies will already have been removed from the
		 *       group prior to this. The log shows that OCS actually
		 *       sends two separate updates when you delete a group:
		 *
		 *         - first one with "modifiedContact" removing buddies
		 *           from the group, leaving it empty, and
		 *
		 *         - then one with "deletedGroup" removing the group
		 */
		for (group_node = sipe_xml_child(isc, "deletedGroup"); group_node; group_node = sipe_xml_twin(group_node))
			sipe_group_remove(sipe_private,
					  sipe_group_find_by_id(sipe_private,
								(int)g_ascii_strtod(sipe_xml_attribute(group_node, "id"),
										    NULL)));

	}
	sipe_xml_free(isc);

	/* Subscribe to buddies, if contact list not migrated to UCS */
	if (!sipe_ucs_is_migrated(sipe_private))
		sipe_subscribe_presence_initial(sipe_private);

	/* for 2005 systems schedule contacts' status update
	 * based on their calendar information
	 */
	if (!SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		sipe_ocs2005_schedule_status_update(sipe_private, time(NULL));
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

void sipe_core_contact_allow_deny(struct sipe_core_public *sipe_public,
				  const gchar* who,
				  gboolean allow)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;

	if (allow) {
		SIPE_DEBUG_INFO("sipe_core_contact_allow_deny: authorizing contact %s", who);
	} else {
		SIPE_DEBUG_INFO("sipe_core_contact_allow_deny: blocking contact %s", who);
	}

	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		sipe_ocs2007_change_access_level(sipe_private,
						 (allow ? -1 : 32000),
						 "user",
						 sipe_get_no_sip_uri(who));
	} else {
		sip_soap_ocs2005_setacl(sipe_private, who, allow);
	}
}


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
		gboolean on_list = sipe_buddy_find_by_uri(sipe_private, remote_user) != NULL;

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

/**
 * Dispatcher for all incoming subscription information
 * whether it comes from NOTIFY, BENOTIFY requests or
 * piggy-backed to subscription's OK responce.
 */
void process_incoming_notify(struct sipe_core_private *sipe_private,
			     struct sipmsg *msg)
{
	const gchar *content_type = sipmsg_find_header(msg, "Content-Type");
	const gchar *event = sipmsg_find_header(msg, "Event");
	const gchar *subscription_state = sipmsg_find_header(msg, "subscription-state");

	SIPE_DEBUG_INFO("process_incoming_notify: subscription_state: %s", subscription_state ? subscription_state : "");

	/* implicit subscriptions */
	if (content_type && g_str_has_prefix(content_type, "application/ms-imdn+xml")) {
		sipe_process_imdn(sipe_private, msg);

	/* event subscriptions */
	} else if (event) {

		/* One-off subscriptions - sent with "Expires: 0" */
		if (sipe_strcase_equal(event, "vnd-microsoft-provisioning-v2")) {
			sipe_process_provisioning_v2(sipe_private, msg);
		} else if (sipe_strcase_equal(event, "vnd-microsoft-provisioning")) {
			sipe_process_provisioning(sipe_private, msg);
		} else if (sipe_strcase_equal(event, "presence")) {
			sipe_process_presence(sipe_private, msg);
		} else if (sipe_strcase_equal(event, "registration-notify")) {
			sipe_process_registration_notify(sipe_private, msg);

		/* Subscriptions with timeout */
		} else if (!subscription_state || strstr(subscription_state, "active")) {
			if (sipe_strcase_equal(event, "vnd-microsoft-roaming-contacts")) {
				sipe_process_roaming_contacts(sipe_private, msg);
			} else if (sipe_strcase_equal(event, "vnd-microsoft-roaming-self")) {
				sipe_ocs2007_process_roaming_self(sipe_private, msg);
			} else if (sipe_strcase_equal(event, "vnd-microsoft-roaming-ACL")) {
				sipe_process_roaming_acl(sipe_private, msg);
			} else if (sipe_strcase_equal(event, "presence.wpending")) {
				sipe_process_presence_wpending(sipe_private, msg);
			} else if (sipe_strcase_equal(event, "conference")) {
				sipe_process_conference(sipe_private, msg);
			}
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
