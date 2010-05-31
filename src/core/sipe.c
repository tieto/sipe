/**
 * @file sipe.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
 * Copyright (C) 2010 pier11 <pier11@operamail.com>
 * Copyright (C) 2009 Anibal Avelar <debianmx@gmail.com>
 * Copyright (C) 2009 pier11 <pier11@operamail.com>
 * Copyright (C) 2008 Novell, Inc., Anibal Avelar <debianmx@gmail.com>
 * Copyright (C) 2007 Anibal Avelar <debianmx@gmail.com>
 * Copyright (C) 2005 Thomas Butter <butter@uni-mannheim.de>
 *
 * ***
 * Thanks to Google's Summer of Code Program and the helpful mentors
 * ***
 *
 * Session-based SIP MESSAGE documentation:
 *   http://tools.ietf.org/html/draft-ietf-simple-im-session-00
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <glib.h>

#include "sipe-common.h"

#include "account.h"
#include "blist.h"
#include "connection.h"
#include "conversation.h"
#include "ft.h"
#include "notify.h"
#include "plugin.h"
#include "privacy.h"
#include "request.h"
#include "savedstatuses.h"

#include "core-depurple.h" /* Temporary for the core de-purple transition */

#include "http-conn.h"
#include "sipmsg.h"
#include "sip-csta.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-buddy.h"
#include "sipe-cal.h"
#include "sipe-chat.h"
#include "sipe-conf.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-dialog.h"
#include "sipe-ews.h"
#include "sipe-domino.h"
#include "sipe-ft.h"
#include "sipe-mime.h"
#include "sipe-nls.h"
#include "sipe-schedule.h"
#include "sipe-session.h"
#include "sipe-subscriptions.h"
#include "sipe-media.h"
#include "sipe-utils.h"
#include "sipe-xml.h"
#include "uuid.h"
#include "sipe.h"

#define SIPE_IDLE_SET_DELAY		1	/* 1 sec */

#define UPDATE_CALENDAR_DELAY		1*60	/* 1 min */
#define UPDATE_CALENDAR_INTERVAL	30*60	/* 30 min */

/* Status identifiers (see also: sipe_status_types()) */
#define SIPE_STATUS_ID_UNKNOWN     purple_primitive_get_id_from_type(PURPLE_STATUS_UNSET)     /* Unset (primitive) */
#define SIPE_STATUS_ID_OFFLINE     purple_primitive_get_id_from_type(PURPLE_STATUS_OFFLINE)   /* Offline (primitive) */
#define SIPE_STATUS_ID_AVAILABLE   purple_primitive_get_id_from_type(PURPLE_STATUS_AVAILABLE) /* Online */
/*      PURPLE_STATUS_UNAVAILABLE: */
#define SIPE_STATUS_ID_BUSY        "busy"                                                     /* Busy */
#define SIPE_STATUS_ID_BUSYIDLE    "busyidle"                                                 /* BusyIdle */
#define SIPE_STATUS_ID_DND         "do-not-disturb"                                           /* Do Not Disturb */
#define SIPE_STATUS_ID_IN_MEETING  "in-a-meeting"                                             /* In a meeting */
#define SIPE_STATUS_ID_IN_CONF     "in-a-conference"                                          /* In a conference */
#define SIPE_STATUS_ID_ON_PHONE    "on-the-phone"                                             /* On the phone */
#define SIPE_STATUS_ID_INVISIBLE   purple_primitive_get_id_from_type(PURPLE_STATUS_INVISIBLE) /* Appear Offline */
/*      PURPLE_STATUS_AWAY: */
#define SIPE_STATUS_ID_IDLE        "idle"                                                     /* Idle/Inactive */
#define SIPE_STATUS_ID_BRB         "be-right-back"                                            /* Be Right Back */
#define SIPE_STATUS_ID_AWAY        purple_primitive_get_id_from_type(PURPLE_STATUS_AWAY)      /* Away (primitive) */
/** Reuters status (user settable) */
#define SIPE_STATUS_ID_LUNCH       "out-to-lunch"                                             /* Out To Lunch */
/* ???  PURPLE_STATUS_EXTENDED_AWAY */
/* ???  PURPLE_STATUS_MOBILE */
/* ???  PURPLE_STATUS_TUNE */

/* Status attributes (see also sipe_status_types() */
#define SIPE_STATUS_ATTR_ID_MESSAGE  "message"

#ifdef HAVE_GMIME
/* pls. don't add multipart/related - it's not used in IM modality */
#define SDP_ACCEPT_TYPES  "text/plain text/html image/gif multipart/alternative application/im-iscomposing+xml application/ms-imdn+xml text/x-msmsgsinvite"
#else
/* this is a rediculous hack as Pidgin's MIME implementastion doesn't support (or have bug) in multipart/alternative */
/* OCS/OC won't use multipart/related so we don't advertase it */
#define SDP_ACCEPT_TYPES  "text/plain text/html image/gif application/im-iscomposing+xml application/ms-imdn+xml text/x-msmsgsinvite"
#endif

static struct sipe_activity_map_struct
{
	sipe_activity type;
	const char *token;
	const char *desc;
	const char *status_id;

} const sipe_activity_map[] =
{
/* This has nothing to do with Availability numbers, like 3500 (online).
 * Just a mapping of Communicator Activities to Purple statuses to be able display them in Pidgin.
 */
	{ SIPE_ACTIVITY_UNSET,		"unset",			NULL				, NULL				},
	{ SIPE_ACTIVITY_ONLINE,		"online",			NULL				, NULL				},
	{ SIPE_ACTIVITY_INACTIVE,	SIPE_STATUS_ID_IDLE,		N_("Inactive")			, NULL				},
	{ SIPE_ACTIVITY_BUSY,		SIPE_STATUS_ID_BUSY,		N_("Busy")			, SIPE_STATUS_ID_BUSY		},
	{ SIPE_ACTIVITY_BUSYIDLE,	SIPE_STATUS_ID_BUSYIDLE,	N_("Busy-Idle")			, NULL				},
	{ SIPE_ACTIVITY_DND,		SIPE_STATUS_ID_DND,		NULL				, SIPE_STATUS_ID_DND		},
	{ SIPE_ACTIVITY_BRB,		SIPE_STATUS_ID_BRB,		N_("Be right back")		, SIPE_STATUS_ID_BRB		},
	{ SIPE_ACTIVITY_AWAY,		"away",				NULL				, NULL				},
	{ SIPE_ACTIVITY_LUNCH,		SIPE_STATUS_ID_LUNCH,		N_("Out to lunch")		, NULL				},
	{ SIPE_ACTIVITY_OFFLINE,	"offline",			NULL				, NULL				},
	{ SIPE_ACTIVITY_ON_PHONE,	SIPE_STATUS_ID_ON_PHONE,	N_("In a call")			, NULL				},
	{ SIPE_ACTIVITY_IN_CONF,	SIPE_STATUS_ID_IN_CONF,		N_("In a conference")		, NULL				},
	{ SIPE_ACTIVITY_IN_MEETING,	SIPE_STATUS_ID_IN_MEETING,	N_("In a meeting")		, NULL				},
	{ SIPE_ACTIVITY_OOF,		"out-of-office",		N_("Out of office")		, NULL				},
	{ SIPE_ACTIVITY_URGENT_ONLY,	"urgent-interruptions-only",	N_("Urgent interruptions only")	, NULL				}
};
/** @param x is sipe_activity */
#define SIPE_ACTIVITY_I18N(x) gettext(sipe_activity_map[x].desc)

static sipe_activity
sipe_get_activity_by_token(const char *token)
{
	int i;

	for (i = 0; i < SIPE_ACTIVITY_NUM_TYPES; i++)
	{
		if (sipe_strequal(token, sipe_activity_map[i].token))
			return sipe_activity_map[i].type;
	}

	return sipe_activity_map[0].type;
}

static const char *
sipe_get_activity_desc_by_token(const char *token)
{
	if (!token) return NULL;

	return SIPE_ACTIVITY_I18N(sipe_get_activity_by_token(token));
}

static void send_presence_status(struct sipe_core_private *sipe_private,
				 void *unused);

/**
 * @param from0	from URI (with 'sip:' prefix). Will be filled with self-URI if NULL passed.
 */
static void
send_soap_request_with_cb(struct sipe_core_private *sipe_private,
			  gchar *from0,
			  gchar *body,
			  TransCallback callback,
			  struct transaction_payload *payload)
{
	gchar *from = from0 ? g_strdup(from0) : sip_uri_self(sipe_private);
	gchar *contact = get_contact(sipe_private);
	gchar *hdr = g_strdup_printf("Contact: %s\r\n"
	                             "Content-Type: application/SOAP+xml\r\n",contact);

	struct transaction *trans = sip_transport_service(sipe_private,
							  from,
							  hdr,
							  body,
							  callback);
	trans->payload = payload;

	g_free(from);
	g_free(contact);
	g_free(hdr);
}

static void send_soap_request(struct sipe_core_private *sipe_private,
			      gchar *body)
{
	send_soap_request_with_cb(sipe_private, NULL, body, NULL, NULL);
}

/**
 * Returns pointer to URI without sip: prefix if any
 *
 * @param sip_uri SIP URI possibly with sip: prefix. Example: sip:first.last@hq.company.com
 * @return pointer to URL without sip: prefix. Coresponding example: first.last@hq.company.com
 *
 * Doesn't allocate memory
 */
static const char *
sipe_get_no_sip_uri(const char *sip_uri)
{
	const char *prefix = "sip:";
	if (!sip_uri) return NULL;

	if (g_str_has_prefix(sip_uri, prefix)) {
		return (sip_uri+strlen(prefix));
	} else {
		return sip_uri;
	}
}

static void
sipe_contact_set_acl (struct sipe_core_private *sipe_private,
		      const gchar *who,
		      gchar *rights)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	gchar * body = g_strdup_printf(SIPE_SOAP_ALLOW_DENY, who, rights, sip->acl_delta++);
	send_soap_request(sipe_private, body);
	g_free(body);
}

static void
sipe_change_access_level(struct sipe_core_private *sipe_private,
			 const int container_id,
			 const gchar *type,
			 const gchar *value);

void
sipe_core_contact_allow_deny (struct sipe_core_public *sipe_public,
			      const gchar * who, gboolean allow)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;

	if (allow) {
		SIPE_DEBUG_INFO("Authorizing contact %s", who);
	} else {
		SIPE_DEBUG_INFO("Blocking contact %s", who);
	}

	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		sipe_change_access_level(sipe_private, (allow ? -1 : 32000), "user", sipe_get_no_sip_uri(who));
	} else {
		sipe_contact_set_acl(sipe_private, who, allow ? "AA" : "BD");
	}
}

static
void sipe_auth_user_cb(void * data)
{
	struct sipe_auth_job * job = (struct sipe_auth_job *) data;
	if (!job) return;

	sipe_core_contact_allow_deny((struct sipe_core_public *)job->sipe_private, job->who, TRUE);
	g_free(job);
}

static
void sipe_deny_user_cb(void * data)
{
	struct sipe_auth_job * job = (struct sipe_auth_job *) data;
	if (!job) return;

	sipe_core_contact_allow_deny((struct sipe_core_public *)job->sipe_private, job->who, FALSE);
	g_free(job);
}

/** @applicable: 2005-
 */
static void
sipe_process_presence_wpending (struct sipe_core_private *sipe_private,
				struct sipmsg * msg)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
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
			purple_account_request_authorization(
				sip->account,
				remote_user,
				_("you"), /* id */
				alias,
				NULL, /* message */
				on_list,
				sipe_auth_user_cb,
				sipe_deny_user_cb,
				(void *) job);
		}
	}


	sipe_xml_free(watchers);
	return;
}

static void
sipe_group_add(struct sipe_core_private *sipe_private,
	       struct sipe_group * group)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	PurpleGroup * purple_group = purple_find_group(group->name);
	if (!purple_group) {
		purple_group = purple_group_new(group->name);
		purple_blist_add_group(purple_group, NULL);
	}

	if (purple_group) {
		group->purple_group = purple_group;
		sip->groups = g_slist_append(sip->groups, group);
		SIPE_DEBUG_INFO("added group %s (id %d)", group->name, group->id);
	} else {
		SIPE_DEBUG_INFO("did not add group %s", group->name ? group->name : "");
	}
}

static struct sipe_group *sipe_group_find_by_id(struct sipe_core_private *sipe_private,
						int id)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	struct sipe_group *group;
	GSList *entry;
	if (sip == NULL) {
		return NULL;
	}

	entry = sip->groups;
	while (entry) {
		group = entry->data;
		if (group->id == id) {
			return group;
		}
		entry = entry->next;
	}
	return NULL;
}

static struct sipe_group *sipe_group_find_by_name(struct sipe_core_private *sipe_private,
						  const gchar * name)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	struct sipe_group *group;
	GSList *entry;
	if (!sip || !name) {
		return NULL;
	}

	entry = sip->groups;
	while (entry) {
		group = entry->data;
		if (sipe_strequal(group->name, name)) {
			return group;
		}
		entry = entry->next;
	}
	return NULL;
}

static void
sipe_group_rename(struct sipe_core_private *sipe_private,
		  struct sipe_group *group,
		  gchar *name)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	gchar *body;
	SIPE_DEBUG_INFO("Renaming group %s to %s", group->name, name);
	body = g_markup_printf_escaped(SIPE_SOAP_MOD_GROUP, group->id, name, sip->contacts_delta++);
	send_soap_request(sipe_private, body);
	g_free(body);
	g_free(group->name);
	group->name = g_strdup(name);
}

/**
 * Only appends if no such value already stored.
 * Like Set in Java.
 */
GSList * slist_insert_unique_sorted(GSList *list, gpointer data, GCompareFunc func) {
	GSList * res = list;
	if (!g_slist_find_custom(list, data, func)) {
		res = g_slist_insert_sorted(list, data, func);
	}
	return res;
}

static int
sipe_group_compare(struct sipe_group *group1, struct sipe_group *group2) {
	return group1->id - group2->id;
}

/**
 * Returns string like "2 4 7 8" - group ids buddy belong to.
 */
static gchar *
sipe_get_buddy_groups_string (struct sipe_buddy *buddy) {
	int i = 0;
	gchar *res;
	//creating array from GList, converting int to gchar*
	gchar **ids_arr = g_new(gchar *, g_slist_length(buddy->groups) + 1);
	GSList *entry = buddy->groups;

	if (!ids_arr) return NULL;

	while (entry) {
		struct sipe_group * group = entry->data;
		ids_arr[i] = g_strdup_printf("%d", group->id);
		entry = entry->next;
		i++;
	}
	ids_arr[i] = NULL;
	res = g_strjoinv(" ", ids_arr);
	g_strfreev(ids_arr);
	return res;
}

/**
  * Sends buddy update to server
  */
void
sipe_core_group_set_user(struct sipe_core_public *sipe_public, const gchar * who)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA;
	struct sipe_buddy *buddy = g_hash_table_lookup(SIPE_CORE_PRIVATE->buddies, who);
	PurpleBuddy *purple_buddy = purple_find_buddy (sip->account, who);

	if (buddy && purple_buddy) {
		const char *alias = purple_buddy_get_alias(purple_buddy);
		gchar *groups = sipe_get_buddy_groups_string(buddy);
		if (groups) {
			gchar *body;
			SIPE_DEBUG_INFO("Saving buddy %s with alias %s and groups %s", who, alias, groups);

			body = g_markup_printf_escaped(SIPE_SOAP_SET_CONTACT,
						       alias, groups, "true", buddy->name, sip->contacts_delta++
				);
			send_soap_request(SIPE_CORE_PRIVATE, body);
			g_free(groups);
			g_free(body);
		}
	}
}

static gboolean process_add_group_response(struct sipe_core_private *sipe_private,
					   struct sipmsg *msg,
					   struct transaction *trans)
{
	if (msg->response == 200) {
		struct sipe_group *group;
		struct group_user_context *ctx = trans->payload->data;
		sipe_xml *xml;
		const sipe_xml *node;
		char *group_id;
		struct sipe_buddy *buddy;

		xml = sipe_xml_parse(msg->body, msg->bodylen);
		if (!xml) {
			return FALSE;
		}

		node = sipe_xml_child(xml, "Body/addGroup/groupID");
		if (!node) {
			sipe_xml_free(xml);
			return FALSE;
		}

		group_id = sipe_xml_data(node);
		if (!group_id) {
			sipe_xml_free(xml);
			return FALSE;
		}

		group = g_new0(struct sipe_group, 1);
		group->id = (int)g_ascii_strtod(group_id, NULL);
		g_free(group_id);
		group->name = g_strdup(ctx->group_name);

		sipe_group_add(sipe_private, group);

		buddy = g_hash_table_lookup(sipe_private->buddies, ctx->user_name);
		if (buddy) {
			buddy->groups = slist_insert_unique_sorted(buddy->groups, group, (GCompareFunc)sipe_group_compare);
		}

		sipe_core_group_set_user(SIPE_CORE_PUBLIC, ctx->user_name);

		sipe_xml_free(xml);
		return TRUE;
	}
	return FALSE;
}

static void sipe_group_context_destroy(gpointer data)
{
	struct group_user_context *ctx = data;
	g_free(ctx->group_name);
	g_free(ctx->user_name);
	g_free(ctx);
}

static void sipe_group_create (struct sipe_core_private *sipe_private,
			       const gchar *name, const gchar * who)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;	
	struct transaction_payload *payload = g_new0(struct transaction_payload, 1);
	struct group_user_context *ctx = g_new0(struct group_user_context, 1);
	gchar *body;
	ctx->group_name = g_strdup(name);
	ctx->user_name = g_strdup(who);
	payload->destroy = sipe_group_context_destroy;
	payload->data = ctx;

	body = g_markup_printf_escaped(SIPE_SOAP_ADD_GROUP, name, sip->contacts_delta++);
	send_soap_request_with_cb(sipe_private, NULL, body, process_add_group_response, payload);
	g_free(body);
}

static void
sipe_sched_calendar_status_update(struct sipe_core_private *sipe_private,
				  time_t calculate_from);

static int
sipe_get_availability_by_status(const char* sipe_status_id, char** activity_token);

static const char*
sipe_get_status_by_availability(int avail,
				char** activity);

static void
sipe_set_purple_account_status_and_note(const PurpleAccount *account,
					const char *status_id,
					const char *message,
					time_t do_not_publish[]);

static void
sipe_apply_calendar_status(struct sipe_core_private *sipe_private,
			   struct sipe_buddy *sbuddy,
			   const char *status_id)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	time_t cal_avail_since;
	int cal_status = sipe_cal_get_status(sbuddy, time(NULL), &cal_avail_since);
	int avail;
	gchar *self_uri;

	if (!sbuddy) return;

	if (cal_status < SIPE_CAL_NO_DATA) {
		SIPE_DEBUG_INFO("sipe_apply_calendar_status: cal_status      : %d for %s", cal_status, sbuddy->name);
		SIPE_DEBUG_INFO("sipe_apply_calendar_status: cal_avail_since : %s", asctime(localtime(&cal_avail_since)));
	}

	/* scheduled Cal update call */
	if (!status_id) {
		status_id = sbuddy->last_non_cal_status_id;
		g_free(sbuddy->activity);
		sbuddy->activity = g_strdup(sbuddy->last_non_cal_activity);
	}

	if (!status_id) {
		SIPE_DEBUG_INFO("sipe_apply_calendar_status: status_id is NULL for %s, exiting.",
				sbuddy->name ? sbuddy->name : "" );
		return;
	}

	/* adjust to calendar status */
	if (cal_status != SIPE_CAL_NO_DATA) {
		SIPE_DEBUG_INFO("sipe_apply_calendar_status: user_avail_since: %s", asctime(localtime(&sbuddy->user_avail_since)));

		if (cal_status == SIPE_CAL_BUSY
		    && cal_avail_since > sbuddy->user_avail_since
		    && 6500 >= sipe_get_availability_by_status(status_id, NULL))
		{
			status_id = SIPE_STATUS_ID_BUSY;
			g_free(sbuddy->activity);
			sbuddy->activity = g_strdup(SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_IN_MEETING));
		}
		avail = sipe_get_availability_by_status(status_id, NULL);

		SIPE_DEBUG_INFO("sipe_apply_calendar_status: activity_since  : %s", asctime(localtime(&sbuddy->activity_since)));
		if (cal_avail_since > sbuddy->activity_since) {
			if (cal_status == SIPE_CAL_OOF
			    && avail >= 15000) /* 12000 in 2007 */
			{
				g_free(sbuddy->activity);
				sbuddy->activity = g_strdup(SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_OOF));
			}
		}
	}

	/* then set status_id actually */
	SIPE_DEBUG_INFO("sipe_apply_calendar_status: to %s for %s", status_id, sbuddy->name ? sbuddy->name : "" );
	purple_prpl_got_user_status(sip->account, sbuddy->name, status_id, NULL);

	/* set our account state to the one in roaming (including calendar info) */
	self_uri = sip_uri_self(sipe_private);
	if (sip->initial_state_published && sipe_strcase_equal(sbuddy->name, self_uri)) {
		if (sipe_strequal(status_id, SIPE_STATUS_ID_OFFLINE)) {
			status_id = g_strdup(SIPE_STATUS_ID_INVISIBLE); /* not not let offline status switch us off */
		}

		SIPE_DEBUG_INFO("sipe_apply_calendar_status: switch to '%s' for the account", sip->status);
		sipe_set_purple_account_status_and_note(sip->account, status_id, sip->note, sip->do_not_publish);
	}
	g_free(self_uri);
}

static void
sipe_got_user_status(struct sipe_core_private *sipe_private,
		     const char* uri,
		     const char *status_id)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	struct sipe_buddy *sbuddy = g_hash_table_lookup(sipe_private->buddies, uri);

	if (!sbuddy) return;

	/* Check if on 2005 system contact's calendar,
	 * then set/preserve it.
	 */
	if (!SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		sipe_apply_calendar_status(sipe_private, sbuddy, status_id);
	} else {
		purple_prpl_got_user_status(sip->account, uri, status_id, NULL);
	}
}

static void
update_calendar_status_cb(SIPE_UNUSED_PARAMETER char *name,
			  struct sipe_buddy *sbuddy,
			  struct sipe_core_private *sipe_private)
{
	sipe_apply_calendar_status(sipe_private, sbuddy, NULL);
}

/**
 * Updates contact's status
 * based on their calendar information.
 *
 * Applicability: 2005 systems
 */
static void
update_calendar_status(struct sipe_core_private *sipe_private,
	               SIPE_UNUSED_PARAMETER void *unused)
{
	SIPE_DEBUG_INFO_NOFORMAT("update_calendar_status() started.");
	g_hash_table_foreach(sipe_private->buddies, (GHFunc)update_calendar_status_cb, sipe_private);

	/* repeat scheduling */
	sipe_sched_calendar_status_update(sipe_private, time(NULL) + 3*60 /* 3 min */);
}

/**
 * Schedules process of contacts' status update
 * based on their calendar information.
 * Should be scheduled to the beginning of every
 * 15 min interval, like:
 * 13:00, 13:15, 13:30, 13:45, etc.
 *
 * Applicability: 2005 systems
 */
static void
sipe_sched_calendar_status_update(struct sipe_core_private *sipe_private,
				  time_t calculate_from)
{
	int interval = 15*60;
	/** start of the beginning of closest 15 min interval. */
	time_t next_start = ((time_t)((int)((int)calculate_from)/interval + 1)*interval);

	SIPE_DEBUG_INFO("sipe_sched_calendar_status_update: calculate_from time: %s",
			asctime(localtime(&calculate_from)));
	SIPE_DEBUG_INFO("sipe_sched_calendar_status_update: next start time    : %s",
			asctime(localtime(&next_start)));

	sipe_schedule_seconds(sipe_private,
			      "<+2005-cal-status>",
			      NULL,
			      next_start - time(NULL),
			      update_calendar_status,
			      NULL);
}

/**
 * Schedules process of self status publish
 * based on own calendar information.
 * Should be scheduled to the beginning of every
 * 15 min interval, like:
 * 13:00, 13:15, 13:30, 13:45, etc.
 *
 * Applicability: 2007+ systems
 */
static void
sipe_sched_calendar_status_self_publish(struct sipe_core_private *sipe_private,
					time_t calculate_from)
{
	int interval = 5*60;
	/** start of the beginning of closest 5 min interval. */
	time_t next_start = ((time_t)((int)((int)calculate_from)/interval + 1)*interval);

	SIPE_DEBUG_INFO("sipe_sched_calendar_status_self_publish: calculate_from time: %s",
			asctime(localtime(&calculate_from)));
	SIPE_DEBUG_INFO("sipe_sched_calendar_status_self_publish: next start time    : %s",
			asctime(localtime(&next_start)));

	sipe_schedule_seconds(sipe_private,
			      "<+2007-cal-status>",
			      NULL,
			      next_start - time(NULL),
			      publish_calendar_status_self,
			      NULL);
}

static void sipe_subscribe_resource_uri(const char *name,
					SIPE_UNUSED_PARAMETER gpointer value,
					gchar **resources_uri)
{
	gchar *tmp = *resources_uri;
        *resources_uri = g_strdup_printf("%s<resource uri=\"%s\"/>\n", tmp, name);
	g_free(tmp);
}

static void sipe_subscribe_resource_uri_with_context(const char *name, gpointer value, gchar **resources_uri)
{
	struct sipe_buddy *sbuddy = (struct sipe_buddy *)value;
	gchar *context = sbuddy && sbuddy->just_added ? "><context/></resource>" : "/>";
	gchar *tmp = *resources_uri;

	if (sbuddy) sbuddy->just_added = FALSE; /* should be enought to include context one time */

	*resources_uri = g_strdup_printf("%s<resource uri=\"%s\"%s\n", tmp, name, context);
	g_free(tmp);
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
					       gchar *to)
{
	gchar *contact = get_contact(sipe_private);
	gchar *request;
	gchar *content;
	gchar *require = "";
	gchar *accept = "";
        gchar *autoextend = "";
	gchar *content_type;

	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		require = ", categoryList";
		accept = ", application/msrtc-event-categories+xml, application/xpidf+xml, application/pidf+xml";
                content_type = "application/msrtc-adrl-categorylist+xml";
                content = g_strdup_printf(
					  "<batchSub xmlns=\"http://schemas.microsoft.com/2006/01/sip/batch-subscribe\" uri=\"sip:%s\" name=\"\">\n"
					  "<action name=\"subscribe\" id=\"63792024\">\n"
					  "<adhocList>\n%s</adhocList>\n"
					  "<categoryList xmlns=\"http://schemas.microsoft.com/2006/09/sip/categorylist\">\n"
					  "<category name=\"calendarData\"/>\n"
					  "<category name=\"contactCard\"/>\n"
					  "<category name=\"note\"/>\n"
					  "<category name=\"state\"/>\n"
					  "</categoryList>\n"
					  "</action>\n"
					  "</batchSub>", sipe_private->username, resources_uri);
	} else {
                autoextend =  "Supported: com.microsoft.autoextend\r\n";
		content_type = "application/adrl+xml";
        	content = g_strdup_printf(
					  "<adhoclist xmlns=\"urn:ietf:params:xml:ns:adrl\" uri=\"sip:%s\" name=\"sip:%s\">\n"
					  "<create xmlns=\"\">\n%s</create>\n"
					  "</adhoclist>\n", sipe_private->username,  sipe_private->username, resources_uri);
	}
	g_free(resources_uri);

	request = g_strdup_printf(
				  "Require: adhoclist%s\r\n"
				  "Supported: eventlist\r\n"
				  "Accept:  application/rlmi+xml, multipart/related, text/xml+msrtc.pidf%s\r\n"
				  "Supported: ms-piggyback-first-notify\r\n"
				  "%sSupported: ms-benotify\r\n"
				  "Proxy-Require: ms-benotify\r\n"
				  "Event: presence\r\n"
				  "Content-Type: %s\r\n"
				  "Contact: %s\r\n", require, accept, autoextend, content_type, contact);
	g_free(contact);

	sipe_subscribe_presence_buddy(sipe_private, to, request, content);

	g_free(content);
	g_free(to);
	g_free(request);
}

static void sipe_subscribe_presence_batched(struct sipe_core_private *sipe_private,
					    SIPE_UNUSED_PARAMETER void *unused)
{
	gchar *to = sip_uri_self(sipe_private);
	gchar *resources_uri = g_strdup("");
	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		g_hash_table_foreach(sipe_private->buddies, (GHFunc) sipe_subscribe_resource_uri_with_context , &resources_uri);
	} else {
                g_hash_table_foreach(sipe_private->buddies, (GHFunc) sipe_subscribe_resource_uri, &resources_uri);

	}
	sipe_subscribe_presence_batched_to(sipe_private, resources_uri, to);
}

struct presence_batched_routed {
	gchar  *host;
	GSList *buddies;
};

static void sipe_subscribe_presence_batched_routed_free(void *payload)
{
	struct presence_batched_routed *data = payload;
	GSList *buddies = data->buddies;
	while (buddies) {
		g_free(buddies->data);
		buddies = buddies->next;
	}
	g_slist_free(data->buddies);
	g_free(data->host);
	g_free(payload);
}

static void sipe_subscribe_presence_batched_routed(struct sipe_core_private *sipe_private,
						   void *payload)
{
	struct presence_batched_routed *data = payload;
	GSList *buddies = data->buddies;
	gchar *resources_uri = g_strdup("");
	while (buddies) {
		gchar *tmp = resources_uri;
		resources_uri = g_strdup_printf("%s<resource uri=\"%s\"/>\n", tmp, (char *) buddies->data);
		g_free(tmp);
		buddies = buddies->next;
	}
	sipe_subscribe_presence_batched_to(sipe_private, resources_uri,
					   g_strdup(data->host));
}

/**
  * Single Category SUBSCRIBE [MS-PRES] ; To send when the server returns a 200 OK message with state="resubscribe" in response.
  * The user sends a single SUBSCRIBE request to the subscribed contact.
  * The To-URI and the URI listed in the resource list MUST be the same for a single category SUBSCRIBE request.
  *
  */

static void sipe_subscribe_presence_single(struct sipe_core_private *sipe_private,
					   void *buddy_name)
{
	gchar *to = sip_uri((char *)buddy_name);
	gchar *tmp = get_contact(sipe_private);
	gchar *request;
	gchar *content = NULL;
        gchar *autoextend = "";
	gchar *content_type = "";
	struct sipe_buddy *sbuddy = g_hash_table_lookup(sipe_private->buddies, to);
	gchar *context = sbuddy && sbuddy->just_added ? "><context/></resource>" : "/>";

	if (sbuddy) sbuddy->just_added = FALSE;

	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		content_type = "Content-Type: application/msrtc-adrl-categorylist+xml\r\n";
	} else {
		autoextend = "Supported: com.microsoft.autoextend\r\n";
	}

	request = g_strdup_printf(
		"Accept: application/msrtc-event-categories+xml, text/xml+msrtc.pidf, application/xpidf+xml, application/pidf+xml, application/rlmi+xml, multipart/related\r\n"
		"Supported: ms-piggyback-first-notify\r\n"
		"%s%sSupported: ms-benotify\r\n"
		"Proxy-Require: ms-benotify\r\n"
		"Event: presence\r\n"
		"Contact: %s\r\n", autoextend, content_type, tmp);

	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		content = g_strdup_printf(
			"<batchSub xmlns=\"http://schemas.microsoft.com/2006/01/sip/batch-subscribe\" uri=\"sip:%s\" name=\"\">\n"
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
			"</batchSub>", sipe_private->username, to, context);
	}

	g_free(tmp);

	sipe_subscribe_presence_buddy(sipe_private, to, request, content);

	g_free(content);
	g_free(to);
	g_free(request);
}

void sipe_set_status(PurpleAccount *account, PurpleStatus *status)
{
	SIPE_DEBUG_INFO("sipe_set_status: status=%s", purple_status_get_id(status));

	if (!purple_status_is_active(status))
		return;

	if (account->gc) {
		struct sipe_core_private *sipe_private = PURPLE_ACCOUNT_TO_SIPE_CORE_PRIVATE;
		struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

		if (sip) {
			gchar *action_name;
			gchar *tmp;
			time_t now = time(NULL);
			const char *status_id = purple_status_get_id(status);
			const char *note = purple_status_get_attr_string(status, SIPE_STATUS_ATTR_ID_MESSAGE);
			sipe_activity activity = sipe_get_activity_by_token(status_id);
			gboolean do_not_publish = ((now - sip->do_not_publish[activity]) <= 2);

			/* when other point of presence clears note, but we are keeping
			 * state if OOF note.
			 */
			if (do_not_publish && !note && sip->cal && sip->cal->oof_note) {
				SIPE_DEBUG_INFO_NOFORMAT("sipe_set_status: enabling publication as OOF note keepers.");
				do_not_publish = FALSE;
			}

			SIPE_DEBUG_INFO("sipe_set_status: was: sip->do_not_publish[%s]=%d [?] now(time)=%d",
					status_id, (int)sip->do_not_publish[activity], (int)now);

			sip->do_not_publish[activity] = 0;
			SIPE_DEBUG_INFO("sipe_set_status: set: sip->do_not_publish[%s]=%d [0]",
					status_id, (int)sip->do_not_publish[activity]);

			if (do_not_publish)
			{
				SIPE_DEBUG_INFO_NOFORMAT("sipe_set_status: publication was switched off, exiting.");
				return;
			}

			g_free(sip->status);
			sip->status = g_strdup(status_id);

			/* hack to escape apostrof before comparison */
			tmp = note ? sipe_utils_str_replace(note, "'", "&apos;") : NULL;

			/* this will preserve OOF flag as well */
			if (!sipe_strequal(tmp, sip->note)) {
				sip->is_oof_note = FALSE;
				g_free(sip->note);
				sip->note = g_strdup(note);
				sip->note_since = time(NULL);
			}
			g_free(tmp);

			/* schedule 2 sec to capture idle flag */
			action_name = g_strdup_printf("<%s>", "+set-status");
			sipe_schedule_seconds(sipe_private,
					      action_name,
					      NULL,
					      SIPE_IDLE_SET_DELAY,
					      send_presence_status,
					      NULL);
			g_free(action_name);
		}
	}
}

void
sipe_set_idle(PurpleConnection * gc,
	      int interval)
{
	SIPE_DEBUG_INFO("sipe_set_idle: interval=%d", interval);

	if (gc) {
		struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;
		struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

		if (sip) {
			sip->idle_switch = time(NULL);
			SIPE_DEBUG_INFO("sipe_set_idle: sip->idle_switch : %s", asctime(localtime(&(sip->idle_switch))));
		}
	}
}

void
sipe_group_buddy(PurpleConnection *gc,
		 const char *who,
		 const char *old_group_name,
		 const char *new_group_name)
{
	struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;
	struct sipe_buddy * buddy = g_hash_table_lookup(sipe_private->buddies, who);
	struct sipe_group * old_group = NULL;
	struct sipe_group * new_group;

	SIPE_DEBUG_INFO("sipe_group_buddy[CB]: who:%s old_group_name:%s new_group_name:%s",
			who ? who : "", old_group_name ? old_group_name : "", new_group_name ? new_group_name : "");

	if(!buddy) { // buddy not in roaming list
		return;
	}

	if (old_group_name) {
		old_group = sipe_group_find_by_name(sipe_private, old_group_name);
	}
	new_group = sipe_group_find_by_name(sipe_private, new_group_name);

	if (old_group) {
		buddy->groups = g_slist_remove(buddy->groups, old_group);
		SIPE_DEBUG_INFO("buddy %s removed from old group %s", who, old_group_name);
	}

	if (!new_group) {
 		sipe_group_create(sipe_private, new_group_name, who);
 	} else {
		buddy->groups = slist_insert_unique_sorted(buddy->groups, new_group, (GCompareFunc)sipe_group_compare);
		sipe_core_group_set_user(SIPE_CORE_PUBLIC, who);
 	}
}

void sipe_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
	SIPE_DEBUG_INFO("sipe_add_buddy[CB]: buddy:%s group:%s", buddy ? buddy->name : "", group ? group->name : "");

	/* libpurple can call us with undefined buddy or group */
	if (buddy && group) {
		struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;

		/* Buddy name must be lower case as we use purple_normalize_nocase() to compare */
		gchar *buddy_name = g_ascii_strdown(buddy->name, -1);
		purple_blist_rename_buddy(buddy, buddy_name);
		g_free(buddy_name);

		/* Prepend sip: if needed */
		if (!g_str_has_prefix(buddy->name, "sip:")) {
			gchar *buf = sip_uri_from_name(buddy->name);
			purple_blist_rename_buddy(buddy, buf);
			g_free(buf);
		}

		if (!g_hash_table_lookup(sipe_private->buddies, buddy->name)) {
			struct sipe_buddy *b = g_new0(struct sipe_buddy, 1);
			SIPE_DEBUG_INFO("sipe_add_buddy: adding %s", buddy->name);
			b->name = g_strdup(buddy->name);
			b->just_added = TRUE;
			g_hash_table_insert(sipe_private->buddies, b->name, b);
			sipe_group_buddy(gc, b->name, NULL, group->name);
			/* @TODO should go to callback */
			sipe_subscribe_presence_single(sipe_private,
						       b->name);
		} else {
			SIPE_DEBUG_INFO("sipe_add_buddy: buddy %s already in internal list", buddy->name);
		}
	}
}

static void sipe_free_buddy(struct sipe_buddy *buddy)
{
#ifndef _WIN32
	 /*
	  * We are calling g_hash_table_foreach_steal(). That means that no
	  * key/value deallocation functions are called. Therefore the glib
	  * hash code does not touch the key (buddy->name) or value (buddy)
	  * of the to-be-deleted hash node at all. It follows that we
	  *
	  *   - MUST free the memory for the key ourselves and
	  *   - ARE allowed to do it in this function
	  *
	  * Conclusion: glib must be broken on the Windows platform if sipe
	  *             crashes with SIGTRAP when closing. You'll have to live
	  *             with the memory leak until this is fixed.
	  */
	g_free(buddy->name);
#endif
	g_free(buddy->activity);
	g_free(buddy->meeting_subject);
	g_free(buddy->meeting_location);
	g_free(buddy->note);

	g_free(buddy->cal_start_time);
	g_free(buddy->cal_free_busy_base64);
	g_free(buddy->cal_free_busy);
	g_free(buddy->last_non_cal_activity);

	sipe_cal_free_working_hours(buddy->cal_working_hours);

	g_free(buddy->device_name);
	g_slist_free(buddy->groups);
	g_free(buddy);
}

/**
  * Unassociates buddy from group first.
  * Then see if no groups left, removes buddy completely.
  * Otherwise updates buddy groups on server.
  */
void sipe_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
	struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;
	struct sipe_buddy *b;
	struct sipe_group *g = NULL;

	SIPE_DEBUG_INFO("sipe_remove_buddy[CB]: buddy:%s group:%s", buddy ? buddy->name : "", group ? group->name : "");
	if (!buddy) return;

	b = g_hash_table_lookup(sipe_private->buddies, buddy->name);
	if (!b) return;

	if (group) {
		g = sipe_group_find_by_name(sipe_private, group->name);
	}

	if (g) {
		b->groups = g_slist_remove(b->groups, g);
		SIPE_DEBUG_INFO("buddy %s removed from group %s", buddy->name, g->name);
	}

	if (g_slist_length(b->groups) < 1) {
		gchar *action_name = sipe_utils_presence_key(buddy->name);
		sipe_schedule_cancel(sipe_private, action_name);
		g_free(action_name);

		g_hash_table_remove(sipe_private->buddies, buddy->name);

		if (b->name) {
			struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
			gchar * body = g_strdup_printf(SIPE_SOAP_DEL_CONTACT, b->name, sip->contacts_delta++);
			send_soap_request(sipe_private, body);
			g_free(body);
		}

		sipe_free_buddy(b);
	} else {
		//updates groups on server
		sipe_core_group_set_user(SIPE_CORE_PUBLIC, b->name);
	}

}

void
sipe_rename_group(PurpleConnection *gc,
		  const char *old_name,
		  PurpleGroup *group,
		  SIPE_UNUSED_PARAMETER GList *moved_buddies)
{
	struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;
	struct sipe_group * s_group = sipe_group_find_by_name(sipe_private, old_name);
	if (s_group) {
		sipe_group_rename(sipe_private, s_group, group->name);
	} else {
		SIPE_DEBUG_INFO("Cannot find group %s to rename", old_name);
	}
}

void
sipe_remove_group(PurpleConnection *gc, PurpleGroup *group)
{
	struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;
	struct sipe_group * s_group = sipe_group_find_by_name(sipe_private, group->name);
	if (s_group) {
		struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
		gchar *body;
		SIPE_DEBUG_INFO("Deleting group %s", group->name);
		body = g_strdup_printf(SIPE_SOAP_DEL_GROUP, s_group->id, sip->contacts_delta++);
		send_soap_request(sipe_private, body);
		g_free(body);

		sip->groups = g_slist_remove(sip->groups, s_group);
		g_free(s_group->name);
		g_free(s_group);
	} else {
		SIPE_DEBUG_INFO("Cannot find group %s to delete", group->name);
	}
}

/**
  * A callback for g_hash_table_foreach
  */
static void
sipe_buddy_subscribe_cb(char *buddy_name,
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

/**
  * Removes entries from purple buddy list
  * that does not correspond ones in the roaming contact list.
  */
static void sipe_cleanup_local_blist(struct sipe_core_private *sipe_private) {
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	GSList *buddies = purple_find_buddies(sip->account, NULL);
	GSList *entry = buddies;
	struct sipe_buddy *buddy;
	PurpleBuddy *b;
	PurpleGroup *g;

	SIPE_DEBUG_INFO("sipe_cleanup_local_blist: overall %d Purple buddies (including clones)", g_slist_length(buddies));
	SIPE_DEBUG_INFO("sipe_cleanup_local_blist: %d sipe buddies (unique)", g_hash_table_size(sipe_private->buddies));
	while (entry) {
		b = entry->data;
		g = purple_buddy_get_group(b);
		buddy = g_hash_table_lookup(sipe_private->buddies, b->name);
		if(buddy) {
			gboolean in_sipe_groups = FALSE;
			GSList *entry2 = buddy->groups;
			while (entry2) {
				struct sipe_group *group = entry2->data;
				if (sipe_strequal(group->name, g->name)) {
					in_sipe_groups = TRUE;
					break;
				}
				entry2 = entry2->next;
			}
			if(!in_sipe_groups) {
				SIPE_DEBUG_INFO("*** REMOVING %s from Purple group: %s as not having this group in roaming list", b->name, g->name);
				purple_blist_remove_buddy(b);
			}
		} else {
				SIPE_DEBUG_INFO("*** REMOVING %s from Purple group: %s as this buddy not in roaming list", b->name, g->name);
				purple_blist_remove_buddy(b);
		}
		entry = entry->next;
	}
	g_slist_free(buddies);
}

static int
sipe_find_access_level(struct sipe_core_private *sipe_private,
		       const gchar *type,
		       const gchar *value,
		       gboolean *is_group_access);

static void
sipe_refresh_blocked_status_cb(char *buddy_name,
			       SIPE_UNUSED_PARAMETER struct sipe_buddy *buddy,
			       struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	int container_id = sipe_find_access_level(sipe_private, "user", buddy_name, NULL);
	gboolean blocked = (container_id == 32000);
	gboolean blocked_in_blist = !purple_privacy_check(sip->account, buddy_name);

	/* SIPE_DEBUG_INFO("sipe_refresh_blocked_status_cb: buddy_name=%s, blocked=%s, blocked_in_blist=%s",
		buddy_name, blocked ? "T" : "F", blocked_in_blist ? "T" : "F"); */

	if (blocked != blocked_in_blist) {
		if (blocked) {
			purple_privacy_deny_add(sip->account, buddy_name, TRUE);
		} else {
			purple_privacy_deny_remove(sip->account, buddy_name, TRUE);
		}

		/* stupid workaround to make pidgin re-render screen to reflect our changes */
		{
			PurpleBuddy *pbuddy = purple_find_buddy(sip->account, buddy_name);
			const PurplePresence *presence = purple_buddy_get_presence(pbuddy);
			const PurpleStatus *pstatus = purple_presence_get_active_status(presence);

			SIPE_DEBUG_INFO_NOFORMAT("sipe_refresh_blocked_status_cb: forcefully refreshing screen.");
			sipe_got_user_status(sipe_private, buddy_name, purple_status_get_id(pstatus));
		}

	}
}

static void
sipe_refresh_blocked_status(struct sipe_core_private *sipe_private)
{
	g_hash_table_foreach(sipe_private->buddies,
			     (GHFunc) sipe_refresh_blocked_status_cb,
			     sipe_private);
}

static gboolean sipe_process_roaming_contacts(struct sipe_core_private *sipe_private,
					      struct sipmsg *msg)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	int len = msg->bodylen;

	const gchar *tmp = sipmsg_find_header(msg, "Event");
	const sipe_xml *item;
	sipe_xml *isc;
	const gchar *contacts_delta;
	const sipe_xml *group_node;
	if (!g_str_has_prefix(tmp, "vnd-microsoft-roaming-contacts")) {
		return FALSE;
	}

	/* Convert the contact from XML to Purple Buddies */
	isc = sipe_xml_parse(msg->body, len);
	if (!isc) {
		return FALSE;
	}

	contacts_delta = sipe_xml_attribute(isc, "deltaNum");
	if (contacts_delta) {
		sip->contacts_delta = (int)g_ascii_strtod(contacts_delta, NULL);
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
		if (g_slist_length(sip->groups) == 0) {
			struct sipe_group * group = g_new0(struct sipe_group, 1);
			PurpleGroup *purple_group;
			group->name = g_strdup(_("Other Contacts"));
			group->id = 1;
			purple_group = purple_group_new(group->name);
			purple_blist_add_group(purple_group, NULL);
			sip->groups = g_slist_append(sip->groups, group);
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
				if (group == NULL && g_slist_length(sip->groups) > 0) {
					group = sip->groups->data;
				}

				if (group != NULL) {
					PurpleBuddy *b = purple_find_buddy_in_group(sip->account, buddy_name, group->purple_group);
					if (!b){
						b = purple_buddy_new(sip->account, buddy_name, uri);
						purple_blist_add_buddy(b, NULL, group->purple_group, NULL);

						SIPE_DEBUG_INFO("Created new buddy %s with alias %s", buddy_name, uri);
					}

					if (sipe_strcase_equal(uri, purple_buddy_get_alias(b))) {
						if (name != NULL && strlen(name) != 0) {
							purple_blist_alias_buddy(b, name);

							SIPE_DEBUG_INFO("Replaced buddy %s alias with %s", buddy_name, name);
						}
					}

					if (!buddy) {
						buddy = g_new0(struct sipe_buddy, 1);
						buddy->name = g_strdup(b->name);
						g_hash_table_insert(sipe_private->buddies, buddy->name, buddy);
					}

					buddy->groups = slist_insert_unique_sorted(buddy->groups, group, (GCompareFunc)sipe_group_compare);

					SIPE_DEBUG_INFO("Added buddy %s to group %s", b->name, group->name);
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
			sipe_subscribe_presence_batched(sipe_private, NULL);
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

/**
 * Fires on deregistration event initiated by server.
 * [MS-SIPREGE] SIP extension.
 */
//
//	2007 Example
//
//	Content-Type: text/registration-event
//	subscription-state: terminated;expires=0
//	ms-diagnostics-public: 4141;reason="User disabled"
//
//	deregistered;event=rejected
//
static void sipe_process_registration_notify(struct sipe_core_private *sipe_private,
					     struct sipmsg *msg)
{
	const gchar *contenttype = sipmsg_find_header(msg, "Content-Type");
	gchar *event = NULL;
	gchar *reason = NULL;
	const gchar *diagnostics = sipmsg_find_header(msg, "ms-diagnostics");
	gchar *warning;

	diagnostics = diagnostics ? diagnostics : sipmsg_find_header(msg, "ms-diagnostics-public");
	SIPE_DEBUG_INFO_NOFORMAT("sipe_process_registration_notify: deregistration received.");

	if (!g_ascii_strncasecmp(contenttype, "text/registration-event", 23)) {
		event = sipmsg_find_part_of_header(msg->body, "event=", NULL, NULL);
		//@TODO have proper parameter extraction _by_name_ func, case insesitive.
		event = event ? event : sipmsg_find_part_of_header(msg->body, "event=", ";", NULL);
	} else {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_process_registration_notify: unknown content type, exiting.");
		return;
	}

	if (diagnostics != NULL) {
		reason = sipmsg_find_part_of_header(diagnostics, "reason=\"", "\"", NULL);
	} else { // for LCS2005
		int error_id = 0;
		if (event && sipe_strcase_equal(event, "unregistered")) {
			error_id = 4140; // [MS-SIPREGE]
			//reason = g_strdup(_("User logged out")); // [MS-OCER]
			reason = g_strdup(_("you are already signed in at another location"));
		} else if (event && sipe_strcase_equal(event, "rejected")) {
			error_id = 4141;
			reason = g_strdup(_("user disabled")); // [MS-OCER]
		} else if (event && sipe_strcase_equal(event, "deactivated")) {
			error_id = 4142;
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
			break;
		}
	}
	sipe_xml_free(xn_provision_group_list);
}

/** for 2005 system */
static void
sipe_process_provisioning(struct sipe_core_private *sipe_private,
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

static void sipe_process_roaming_acl(struct sipe_core_private *sipe_private,
				     struct sipmsg *msg)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	const gchar *contacts_delta;
	sipe_xml *xml;

	xml = sipe_xml_parse(msg->body, msg->bodylen);
	if (!xml)
	{
		return;
	}

	contacts_delta = sipe_xml_attribute(xml, "deltaNum");
	if (contacts_delta)
	{
		sip->acl_delta = (int)g_ascii_strtod(contacts_delta, NULL);
	}

	sipe_xml_free(xml);
}

static void
free_container_member(struct sipe_container_member *member)
{
	if (!member) return;

	g_free(member->type);
	g_free(member->value);
	g_free(member);
}

static void
free_container(struct sipe_container *container)
{
	GSList *entry;

	if (!container) return;

	entry = container->members;
	while (entry) {
		void *data = entry->data;
		entry = g_slist_remove(entry, data);
		free_container_member((struct sipe_container_member *)data);
	}
	g_free(container);
}

static void
sipe_send_container_members_prepare(const guint container_id,
				    const guint container_version,
				    const gchar *action,
				    const gchar *type,
				    const gchar *value,
				    char **container_xmls)
{
	gchar *value_str = value ? g_strdup_printf(" value=\"%s\"", value) : g_strdup("");
	gchar *body;

	if (!container_xmls) return;

	body = g_strdup_printf(
		"<container id=\"%d\" version=\"%d\"><member action=\"%s\" type=\"%s\"%s/></container>",
		container_id,
		container_version,
		action,
		type,
		value_str);
	g_free(value_str);

	if ((*container_xmls) == NULL) {
		*container_xmls = body;
	} else {
		char *tmp = *container_xmls;

		*container_xmls = g_strconcat(*container_xmls, body, NULL);
		g_free(tmp);
		g_free(body);
	}
}

static void
sipe_send_set_container_members(struct sipe_core_private *sipe_private,
				char *container_xmls)
{
	gchar *self;
	gchar *contact;
	gchar *hdr;
	gchar *body;

	if (!container_xmls) return;

	self = sip_uri_self(sipe_private);
	body = g_strdup_printf(
		"<setContainerMembers xmlns=\"http://schemas.microsoft.com/2006/09/sip/container-management\">"
		"%s"
		"</setContainerMembers>",
		container_xmls);

	contact = get_contact(sipe_private);
	hdr = g_strdup_printf("Contact: %s\r\n"
			      "Content-Type: application/msrtc-setcontainermembers+xml\r\n", contact);
	g_free(contact);

	sip_transport_service(sipe_private,
			      self,
			      hdr,
			      body,
			      NULL);

	g_free(hdr);
	g_free(body);
	g_free(self);
}

/**
 * Finds locally stored MS-PRES container member
 */
static struct sipe_container_member *
sipe_find_container_member(struct sipe_container *container,
			   const gchar *type,
			   const gchar *value)
{
	struct sipe_container_member *member;
	GSList *entry;

	if (container == NULL || type == NULL) {
		return NULL;
	}

	entry = container->members;
	while (entry) {
		member = entry->data;
		if (sipe_strcase_equal(member->type, type) &&
		    sipe_strcase_equal(member->value, value))
		{
			return member;
		}
		entry = entry->next;
	}
	return NULL;
}

/**
 * Finds locally stored MS-PRES container by id
 */
static struct sipe_container *
sipe_find_container(struct sipe_core_private *sipe_private,
		    guint id)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	struct sipe_container *container;
	GSList *entry;

	if (sip == NULL) {
		return NULL;
	}

	entry = sip->containers;
	while (entry) {
		container = entry->data;
		if (id == container->id) {
			return container;
		}
		entry = entry->next;
	}
	return NULL;
}

static GSList *
sipe_get_access_domains(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	struct sipe_container *container;
	struct sipe_container_member *member;
	GSList *entry;
	GSList *entry2;
	GSList *res = NULL;

	if (!sip) return NULL;

	entry = sip->containers;
	while (entry) {
		container = entry->data;

		entry2 = container->members;
		while (entry2) {
			member = entry2->data;
			if (sipe_strcase_equal(member->type, "domain"))
			{
				res = slist_insert_unique_sorted(res, g_strdup(member->value), (GCompareFunc)g_ascii_strcasecmp);
			}
			entry2 = entry2->next;
		}
		entry = entry->next;
	}
	return res;
}

/**
 * Returns pointer to domain part in provided Email URL
 *
 * @param email an email URL. Example: first.last@hq.company.com
 * @return pointer to domain part of email URL. Coresponding example: hq.company.com
 *
 * Doesn't allocate memory
 */
static const char *
sipe_get_domain(const char *email)
{
	char *tmp;

	if (!email) return NULL;

	tmp = strstr(email, "@");

	if (tmp && ((tmp+1) < (email + strlen(email)))) {
		return tmp+1;
	} else {
		return NULL;
	}
}


/* @TODO: replace with binary search for faster access? */
/** source: http://support.microsoft.com/kb/897567 */
static const char * const public_domains [] = {
	"aol.com", "icq.com", "love.com", "mac.com", "br.live.com",
	"hotmail.co.il", "hotmail.co.jp", "hotmail.co.th", "hotmail.co.uk",
	"hotmail.com", "hotmail.com.ar", "hotmail.com.tr", "hotmail.es",
	"hotmail.de", "hotmail.fr", "hotmail.it", "live.at", "live.be",
	"live.ca", "live.cl", "live.cn", "live.co.in", "live.co.kr",
	"live.co.uk", "live.co.za", "live.com", "live.com.ar", "live.com.au",
	"live.com.co", "live.com.mx", "live.com.my", "live.com.pe",
	"live.com.ph", "live.com.pk", "live.com.pt", "live.com.sg",
	"live.com.ve", "live.de", "live.dk", "live.fr", "live.hk", "live.ie",
	"live.in", "live.it", "live.jp", "live.nl", "live.no", "live.ph",
	"live.ru", "live.se", "livemail.com.br", "livemail.tw",
	"messengeruser.com", "msn.com", "passport.com", "sympatico.ca",
	"tw.live.com", "webtv.net", "windowslive.com", "windowslive.es",
	"yahoo.com",
	NULL};

static gboolean
sipe_is_public_domain(const char *domain)
{
	int i = 0;
	while (public_domains[i]) {
		if (sipe_strcase_equal(public_domains[i], domain)) {
			return TRUE;
		}
		i++;
	}
	return FALSE;
}

/**
 * Access Levels
 * 32000 - Blocked
 * 400   - Personal
 * 300   - Team
 * 200   - Company
 * 100   - Public
 */
static const char *
sipe_get_access_level_name(int container_id)
{
	switch(container_id) {
		case 32000: return _("Blocked");
		case 400:   return _("Personal");
		case 300:   return _("Team");
		case 200:   return _("Company");
		case 100:   return _("Public");
	}
	return _("Unknown");
}

static const guint containers[] = {32000, 400, 300, 200, 100};
#define CONTAINERS_LEN (sizeof(containers) / sizeof(guint))


static int
sipe_find_member_access_level(struct sipe_core_private *sipe_private,
			      const gchar *type,
			      const gchar *value)
{
	unsigned int i = 0;
	const gchar *value_mod = value;

	if (!type) return -1;

	if (sipe_strequal("user", type)) {
		value_mod = sipe_get_no_sip_uri(value);
	}

	for (i = 0; i < CONTAINERS_LEN; i++) {
		struct sipe_container_member *member;
		struct sipe_container *container = sipe_find_container(sipe_private, containers[i]);
		if (!container) continue;

		member = sipe_find_container_member(container, type, value_mod);
		if (member) return containers[i];
	}

	return -1;
}

/** Member type: user, domain, sameEnterprise, federated, publicCloud; everyone */
static int
sipe_find_access_level(struct sipe_core_private *sipe_private,
		       const gchar *type,
		       const gchar *value,
		       gboolean *is_group_access)
{
	int container_id = -1;

	if (sipe_strequal("user", type)) {
		const char *domain;
		const char *no_sip_uri = sipe_get_no_sip_uri(value);

		container_id = sipe_find_member_access_level(sipe_private, "user", no_sip_uri);
		if (container_id >= 0) {
			if (is_group_access) *is_group_access = FALSE;
			return container_id;
		}

		domain = sipe_get_domain(no_sip_uri);
		container_id = sipe_find_member_access_level(sipe_private, "domain", domain);
		if (container_id >= 0)  {
			if (is_group_access) *is_group_access = TRUE;
			return container_id;
		}

		container_id = sipe_find_member_access_level(sipe_private, "sameEnterprise", NULL);
		if ((container_id >= 0) && sipe_strcase_equal(sipe_private->public.sip_domain, domain)) {
			if (is_group_access) *is_group_access = TRUE;
			return container_id;
		}

		container_id = sipe_find_member_access_level(sipe_private, "publicCloud", NULL);
		if ((container_id >= 0) && sipe_is_public_domain(domain)) {
			if (is_group_access) *is_group_access = TRUE;
			return container_id;
		}

		container_id = sipe_find_member_access_level(sipe_private, "everyone", NULL);
		if ((container_id >= 0)) {
			if (is_group_access) *is_group_access = TRUE;
			return container_id;
		}
	} else {
		container_id = sipe_find_member_access_level(sipe_private, type, value);
		if (is_group_access) *is_group_access = FALSE;
	}

	return container_id;
}

/**
  * @param container_id	a new access level. If -1 then current access level
  * 			is just removed (I.e. the member is removed from all containers).
  * @param type		a type of member. E.g. "user", "sameEnterprise", etc.
  * @param value	a value for member. E.g. SIP URI for "user" member type.
  */
static void
sipe_change_access_level(struct sipe_core_private *sipe_private,
			 const int container_id,
			 const gchar *type,
			 const gchar *value)
{
	unsigned int i;
	int current_container_id = -1;
	char *container_xmls = NULL;

	/* for each container: find/delete */
	for (i = 0; i < CONTAINERS_LEN; i++) {
		struct sipe_container_member *member;
		struct sipe_container *container = sipe_find_container(sipe_private, containers[i]);

		if (!container) continue;

		member = sipe_find_container_member(container, type, value);
		if (member) {
			current_container_id = containers[i];
			/* delete/publish current access level */
			if (container_id < 0 || container_id != current_container_id) {
				sipe_send_container_members_prepare(current_container_id, container->version, "remove", type, value, &container_xmls);
				/* remove member from our cache, to be able to recalculate AL below */
				container->members = g_slist_remove(container->members, member);
				current_container_id = -1;
			}
		}
	}

	/* recalculate AL below */
	current_container_id = sipe_find_access_level(sipe_private, type, value, NULL);

	/* assign/publish new access level */
	if (container_id != current_container_id && container_id >= 0) {
		struct sipe_container *container = sipe_find_container(sipe_private, container_id);
		guint version = container ? container->version : 0;

		sipe_send_container_members_prepare(container_id, version, "add", type, value, &container_xmls);
	}

	if (container_xmls) {
		sipe_send_set_container_members(sipe_private, container_xmls);
	}
	g_free(container_xmls);
}

static void
free_publication(struct sipe_publication *publication)
{
	g_free(publication->category);
	g_free(publication->cal_event_hash);
	g_free(publication->note);

	g_free(publication->working_hours_xml_str);
	g_free(publication->fb_start_str);
	g_free(publication->free_busy_base64);

	g_free(publication);
}

/* key is <category><instance><container> */
static gboolean
sipe_is_our_publication(struct sipe_core_private *sipe_private,
			const gchar *key)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;	
	GSList *entry;

	/* filling keys for our publications if not yet cached */
	if (!sip->our_publication_keys) {
		guint device_instance 	= sipe_get_pub_instance(sipe_private, SIPE_PUB_DEVICE);
		guint machine_instance 	= sipe_get_pub_instance(sipe_private, SIPE_PUB_STATE_MACHINE);
		guint user_instance 	= sipe_get_pub_instance(sipe_private, SIPE_PUB_STATE_USER);
		guint calendar_instance	= sipe_get_pub_instance(sipe_private, SIPE_PUB_STATE_CALENDAR);
		guint cal_oof_instance	= sipe_get_pub_instance(sipe_private, SIPE_PUB_STATE_CALENDAR_OOF);
		guint cal_data_instance = sipe_get_pub_instance(sipe_private, SIPE_PUB_CALENDAR_DATA);
		guint note_oof_instance = sipe_get_pub_instance(sipe_private, SIPE_PUB_NOTE_OOF);

		SIPE_DEBUG_INFO_NOFORMAT("* Our Publication Instances *");
		SIPE_DEBUG_INFO("\tDevice               : %u\t0x%08X", device_instance, device_instance);
		SIPE_DEBUG_INFO("\tMachine State        : %u\t0x%08X", machine_instance, machine_instance);
		SIPE_DEBUG_INFO("\tUser Stare           : %u\t0x%08X", user_instance, user_instance);
		SIPE_DEBUG_INFO("\tCalendar State       : %u\t0x%08X", calendar_instance, calendar_instance);
		SIPE_DEBUG_INFO("\tCalendar OOF State   : %u\t0x%08X", cal_oof_instance, cal_oof_instance);
		SIPE_DEBUG_INFO("\tCalendar FreeBusy    : %u\t0x%08X", cal_data_instance, cal_data_instance);
		SIPE_DEBUG_INFO("\tOOF Note             : %u\t0x%08X", note_oof_instance, note_oof_instance);
		SIPE_DEBUG_INFO("\tNote                 : %u", 0);
		SIPE_DEBUG_INFO("\tCalendar WorkingHours: %u", 0);

		/* device */
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "device", device_instance, 2));

		/* state:machineState */
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "state", machine_instance, 2));
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "state", machine_instance, 3));

		/* state:userState */
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "state", user_instance, 2));
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "state", user_instance, 3));

		/* state:calendarState */
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "state", calendar_instance, 2));
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "state", calendar_instance, 3));

		/* state:calendarState OOF */
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "state", cal_oof_instance, 2));
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "state", cal_oof_instance, 3));

		/* note */
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "note", 0, 200));
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "note", 0, 300));
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "note", 0, 400));

		/* note OOF */
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "note", note_oof_instance, 200));
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "note", note_oof_instance, 300));
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "note", note_oof_instance, 400));

		/* calendarData:WorkingHours */
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 1));
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 100));
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 200));
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 300));
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 400));
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 32000));

		/* calendarData:FreeBusy */
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 1));
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 100));
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 200));
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 300));
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 400));
		sip->our_publication_keys = g_slist_append(sip->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 32000));

		//SIPE_DEBUG_INFO("sipe_is_our_publication: sip->our_publication_keys length=%d",
		//	  sip->our_publication_keys ? (int) g_slist_length(sip->our_publication_keys) : -1);
	}

	//SIPE_DEBUG_INFO("sipe_is_our_publication: key=%s", key);

	entry = sip->our_publication_keys;
	while (entry) {
		//SIPE_DEBUG_INFO("   sipe_is_our_publication: entry->data=%s", entry->data);
		if (sipe_strequal(entry->data, key)) {
			return TRUE;
		}
		entry = entry->next;
	}
	return FALSE;
}

/** Property names to store in blist.xml */
#define ALIAS_PROP			"alias"
#define EMAIL_PROP			"email"
#define PHONE_PROP			"phone"
#define PHONE_DISPLAY_PROP		"phone-display"
#define PHONE_MOBILE_PROP		"phone-mobile"
#define PHONE_MOBILE_DISPLAY_PROP	"phone-mobile-display"
#define PHONE_HOME_PROP			"phone-home"
#define PHONE_HOME_DISPLAY_PROP		"phone-home-display"
#define PHONE_OTHER_PROP		"phone-other"
#define PHONE_OTHER_DISPLAY_PROP	"phone-other-display"
#define PHONE_CUSTOM1_PROP		"phone-custom1"
#define PHONE_CUSTOM1_DISPLAY_PROP	"phone-custom1-display"
#define SITE_PROP			"site"
#define COMPANY_PROP			"company"
#define DEPARTMENT_PROP			"department"
#define TITLE_PROP			"title"
#define OFFICE_PROP			"office"
/** implies work address */
#define ADDRESS_STREET_PROP		"address-street"
#define ADDRESS_CITY_PROP		"address-city"
#define ADDRESS_STATE_PROP		"address-state"
#define ADDRESS_ZIPCODE_PROP		"address-zipcode"
#define ADDRESS_COUNTRYCODE_PROP	"address-country-code"

/**
 * Tries to figure out user first and last name
 * based on Display Name and email properties.
 *
 * Allocates memory - must be g_free()'d
 *
 * Examples to parse:
 *  First Last
 *  First Last - Company Name
 *  Last, First
 *  Last, First M.
 *  Last, First (C)(STP) (Company)
 *  first.last@company.com		(preprocessed as "first last")
 *  first.last.company.com@reuters.net	(preprocessed as "first last company com")
 *
 * Unusable examples:
 *  user@company.com			(preprocessed as "user")
 *  first.m.last@company.com		(preprocessed as "first m last")
 *  user.company.com@reuters.net	(preprocessed as "user company com")
 */
static void
sipe_get_first_last_names(struct sipe_core_private *sipe_private,
			  const char *uri,
			  char **first_name,
			  char **last_name)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	PurpleBuddy *p_buddy;
	char *display_name;
	const char *email;
	const char *first, *last;
	char *tmp;
	char **parts;
	gboolean has_comma = FALSE;

	if (!sip || !uri) return;

	p_buddy = purple_find_buddy(sip->account, uri);

	if (!p_buddy) return;

	display_name = g_strdup(purple_buddy_get_alias(p_buddy));
	email = purple_blist_node_get_string(&p_buddy->node, EMAIL_PROP);

	if (!display_name && !email) return;

	/* if no display name, make "first last anything_else" out of email */
	if (email && !display_name) {
		display_name = g_strndup(email, strstr(email, "@") - email);
		display_name = sipe_utils_str_replace((tmp = display_name), ".", " ");
		g_free(tmp);
	}

	if (display_name) {
		has_comma = (strstr(display_name, ",") != NULL);
		display_name = sipe_utils_str_replace((tmp = display_name), ", ", " ");
		g_free(tmp);
		display_name = sipe_utils_str_replace((tmp = display_name), ",", " ");
		g_free(tmp);
	}

	parts = g_strsplit(display_name, " ", 0);

	if (!parts[0] || !parts[1]) {
		g_free(display_name);
		g_strfreev(parts);
		return;
	}

	if (has_comma) {
		last  = parts[0];
		first = parts[1];
	} else {
		first = parts[0];
		last  = parts[1];
	}

	if (first_name) {
		*first_name = g_strstrip(g_strdup(first));
	}

	if (last_name) {
		*last_name = g_strstrip(g_strdup(last));
	}

	g_free(display_name);
	g_strfreev(parts);
}

/**
 * Update user information
 *
 * @param uri             buddy SIP URI with 'sip:' prefix whose info we want to change.
 * @param property_name
 * @param property_value  may be modified to strip white space
 */
static void
sipe_update_user_info(struct sipe_core_private *sipe_private,
		      const char *uri,
		      const char *property_name,
		      char *property_value)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	GSList *buddies, *entry;

	if (!property_name || strlen(property_name) == 0) return;

	if (property_value)
		property_value = g_strstrip(property_value);

	entry = buddies = purple_find_buddies(sip->account, uri); /* all buddies in different groups */
	while (entry) {
		const char *prop_str;
		const char *server_alias;
		PurpleBuddy *p_buddy = entry->data;

		/* for Display Name */
		if (sipe_strequal(property_name, ALIAS_PROP)) {
			if (property_value && sipe_is_bad_alias(uri, purple_buddy_get_alias(p_buddy))) {
				SIPE_DEBUG_INFO("Replacing alias for %s with %s", uri, property_value);
				purple_blist_alias_buddy(p_buddy, property_value);
			}

			server_alias = purple_buddy_get_server_alias(p_buddy);
			if (!is_empty(property_value) &&
			   (!sipe_strequal(property_value, server_alias) || is_empty(server_alias)) )
			{
				purple_blist_server_alias_buddy(p_buddy, property_value);
			}
		}
		/* for other properties */
		else {
			if (!is_empty(property_value)) {
				prop_str = purple_blist_node_get_string(&p_buddy->node, property_name);
				if (!prop_str || !sipe_strcase_equal(prop_str, property_value)) {
					purple_blist_node_set_string(&p_buddy->node, property_name, property_value);
				}
			}
		}

		entry = entry->next;
	}
	g_slist_free(buddies);
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
		       const char *uri,
		       const gchar *phone_type,
		       gchar *phone,
		       gchar *phone_display_string)
{
	const char *phone_node = PHONE_PROP; /* work phone by default */
	const char *phone_display_node = PHONE_DISPLAY_PROP; /* work phone by default */

	if(!phone || strlen(phone) == 0) return;

	if ((sipe_strequal(phone_type, "mobile") ||  sipe_strequal(phone_type, "cell"))) {
		phone_node = PHONE_MOBILE_PROP;
		phone_display_node = PHONE_MOBILE_DISPLAY_PROP;
	} else if (sipe_strequal(phone_type, "home")) {
		phone_node = PHONE_HOME_PROP;
		phone_display_node = PHONE_HOME_DISPLAY_PROP;
	} else if (sipe_strequal(phone_type, "other")) {
		phone_node = PHONE_OTHER_PROP;
		phone_display_node = PHONE_OTHER_DISPLAY_PROP;
	} else if (sipe_strequal(phone_type, "custom1")) {
		phone_node = PHONE_CUSTOM1_PROP;
		phone_display_node = PHONE_CUSTOM1_DISPLAY_PROP;
	}

	sipe_update_user_info(sipe_private, uri, phone_node, phone);
	if (phone_display_string) {
		sipe_update_user_info(sipe_private, uri, phone_display_node, phone_display_string);
	}
}

void
sipe_core_update_calendar(struct sipe_core_public *sipe_public)
{
	SIPE_DEBUG_INFO_NOFORMAT("sipe_core_update_calendar: started.");

	/* Do in parallel.
	 * If failed, the branch will be disabled for subsequent calls.
	 * Can't rely that user turned the functionality on in account settings.
	 */
	sipe_ews_update_calendar(SIPE_CORE_PRIVATE);
	sipe_domino_update_calendar(SIPE_CORE_PRIVATE);

	/* schedule repeat */
	sipe_schedule_seconds(SIPE_CORE_PRIVATE,
			      "<+update-calendar>",
			      NULL,
			      UPDATE_CALENDAR_INTERVAL,
			      (sipe_schedule_action)sipe_core_update_calendar,
			      NULL);

	SIPE_DEBUG_INFO_NOFORMAT("sipe_core_update_calendar: finished.");
}

/**
 * This method motivates Purple's Host (e.g. Pidgin) to update its UI
 * by using standard Purple's means of signals and saved statuses.
 *
 * Thus all UI elements get updated: Status Button with Note, docklet.
 * This is ablolutely important as both our status and note can come
 * inbound (roaming) or be updated programmatically (e.g. based on our
 * calendar data).
 */
static void
sipe_set_purple_account_status_and_note(const PurpleAccount *account,
					const char *status_id,
					const char *message,
					time_t do_not_publish[])
{
	PurpleStatus *status = purple_account_get_active_status(account);
	gboolean changed = TRUE;

	if (g_str_equal(status_id, purple_status_get_id(status)) &&
	    sipe_strequal(message, purple_status_get_attr_string(status, SIPE_STATUS_ATTR_ID_MESSAGE)))
	{
		changed = FALSE;
	}

	if (purple_savedstatus_is_idleaway()) {
		changed = FALSE;
	}

	if (changed) {
		PurpleSavedStatus *saved_status;
		const PurpleStatusType *acct_status_type =
			purple_status_type_find_with_id(account->status_types, status_id);
		PurpleStatusPrimitive primitive = purple_status_type_get_primitive(acct_status_type);
		sipe_activity activity = sipe_get_activity_by_token(status_id);

		saved_status = purple_savedstatus_find_transient_by_type_and_message(primitive, message);
		if (saved_status) {
			purple_savedstatus_set_substatus(saved_status, account, acct_status_type, message);
		}

		/* If this type+message is unique then create a new transient saved status
		 * Ref: gtkstatusbox.c
		 */
		if (!saved_status) {
			GList *tmp;
			GList *active_accts = purple_accounts_get_all_active();

			saved_status = purple_savedstatus_new(NULL, primitive);
			purple_savedstatus_set_message(saved_status, message);

			for (tmp = active_accts; tmp != NULL; tmp = tmp->next) {
				purple_savedstatus_set_substatus(saved_status,
					(PurpleAccount *)tmp->data, acct_status_type, message);
			}
			g_list_free(active_accts);
		}

		do_not_publish[activity] = time(NULL);
		SIPE_DEBUG_INFO("sipe_set_purple_account_status_and_note: do_not_publish[%s]=%d [now]",
				status_id, (int)do_not_publish[activity]);

		/* Set the status for each account */
		purple_savedstatus_activate(saved_status);
	}
}

struct hash_table_delete_payload {
	GHashTable *hash_table;
	guint container;
};

static void
sipe_remove_category_container_publications_cb(const char *name,
					       struct sipe_publication *publication,
					       struct hash_table_delete_payload *payload)
{
	if (publication->container == payload->container) {
		g_hash_table_remove(payload->hash_table, name);
	}
}
static void
sipe_remove_category_container_publications(GHashTable *our_publications,
					    const char *category,
					    guint container)
{
	struct hash_table_delete_payload payload;
	payload.hash_table = g_hash_table_lookup(our_publications, category);

	if (!payload.hash_table) return;

	payload.container = container;
	g_hash_table_foreach(payload.hash_table, (GHFunc)sipe_remove_category_container_publications_cb, &payload);
}

static void
send_publish_category_initial(struct sipe_core_private *sipe_private);

/**
  *   When we receive some self (BE) NOTIFY with a new subscriber
  *   we sends a setSubscribers request to him [SIP-PRES] 4.8
  *
  */
static void sipe_process_roaming_self(struct sipe_core_private *sipe_private,
				      struct sipmsg *msg)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	gchar *contact;
	gchar *to;
	sipe_xml *xml;
	const sipe_xml *node;
	const sipe_xml *node2;
        char *display_name = NULL;
        char *uri;
	GSList *category_names = NULL;
	int aggreg_avail = 0;
	gboolean do_update_status = FALSE;
	gboolean has_note_cleaned = FALSE;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_process_roaming_self");

	xml = sipe_xml_parse(msg->body, msg->bodylen);
	if (!xml) return;

	contact = get_contact(sipe_private);
	to = sip_uri_self(sipe_private);


	/* categories */
	/* set list of categories participating in this XML */
	for (node = sipe_xml_child(xml, "categories/category"); node; node = sipe_xml_twin(node)) {
		const gchar *name = sipe_xml_attribute(node, "name");
		category_names = slist_insert_unique_sorted(category_names, (gchar *)name, (GCompareFunc)strcmp);
	}
	SIPE_DEBUG_INFO("sipe_process_roaming_self: category_names length=%d",
			category_names ? (int) g_slist_length(category_names) : -1);
	/* drop category information */
	if (category_names) {
		GSList *entry = category_names;
		while (entry) {
			GHashTable *cat_publications;
			const gchar *category = entry->data;
			entry = entry->next;
			SIPE_DEBUG_INFO("sipe_process_roaming_self: dropping category: %s", category);
			cat_publications = g_hash_table_lookup(sip->our_publications, category);
			if (cat_publications) {
				g_hash_table_remove(sip->our_publications, category);
				SIPE_DEBUG_INFO("sipe_process_roaming_self: dropped category: %s", category);
			}
		}
	}
	g_slist_free(category_names);
	/* filling our categories reflected in roaming data */
	for (node = sipe_xml_child(xml, "categories/category"); node; node = sipe_xml_twin(node)) {
		const char *tmp;
		const gchar *name = sipe_xml_attribute(node, "name");
		guint container = sipe_xml_int_attribute(node, "container", -1);
		guint instance  = sipe_xml_int_attribute(node, "instance", -1);
		guint version   = sipe_xml_int_attribute(node, "version", 0);
		time_t publish_time = (tmp = sipe_xml_attribute(node, "publishTime")) ?
			sipe_utils_str_to_time(tmp) : 0;
		gchar *key;
		GHashTable *cat_publications = g_hash_table_lookup(sip->our_publications, name);

		/* Ex. clear note: <category name="note"/> */
		if (container == (guint)-1) {
			g_free(sip->note);
			sip->note = NULL;
			do_update_status = TRUE;
			continue;
		}

		/* Ex. clear note: <category name="note" container="200"/> */
		if (instance == (guint)-1) {
			if (container == 200) {
				g_free(sip->note);
				sip->note = NULL;
				do_update_status = TRUE;
			}
			SIPE_DEBUG_INFO("sipe_process_roaming_self: removing publications for: %s/%u", name, container);
			sipe_remove_category_container_publications(
				sip->our_publications, name, container);
			continue;
		}

		/* key is <category><instance><container> */
		key = g_strdup_printf("<%s><%u><%u>", name, instance, container);
		SIPE_DEBUG_INFO("sipe_process_roaming_self: key=%s version=%d", key, version);

		/* capture all userState publication for later clean up if required */
		if (sipe_strequal(name, "state") && (container == 2 || container == 3)) {
			const sipe_xml *xn_state = sipe_xml_child(node, "state");

			if (xn_state && sipe_strequal(sipe_xml_attribute(xn_state, "type"), "userState")) {
				struct sipe_publication *publication = g_new0(struct sipe_publication, 1);
				publication->category  = g_strdup(name);
				publication->instance  = instance;
				publication->container = container;
				publication->version   = version;

				if (!sip->user_state_publications) {
					sip->user_state_publications = g_hash_table_new_full(
									g_str_hash, g_str_equal,
									g_free,	(GDestroyNotify)free_publication);
				}
				g_hash_table_insert(sip->user_state_publications, g_strdup(key), publication);
				SIPE_DEBUG_INFO("sipe_process_roaming_self: added to user_state_publications key=%s version=%d",
						key, version);
			}
		}

		if (sipe_is_our_publication(sipe_private, key)) {
			struct sipe_publication *publication = g_new0(struct sipe_publication, 1);

			publication->category = g_strdup(name);
			publication->instance  = instance;
			publication->container = container;
			publication->version   = version;

			/* filling publication->availability */
			if (sipe_strequal(name, "state")) {
				const sipe_xml *xn_state = sipe_xml_child(node, "state");
				const sipe_xml *xn_avail = sipe_xml_child(xn_state, "availability");

				if (xn_avail) {
					gchar *avail_str = sipe_xml_data(xn_avail);
					if (avail_str) {
						publication->availability = atoi(avail_str);
					}
					g_free(avail_str);
				}
				/* for calendarState */
				if (xn_state && sipe_strequal(sipe_xml_attribute(xn_state, "type"), "calendarState")) {
					const sipe_xml *xn_activity = sipe_xml_child(xn_state, "activity");
					struct sipe_cal_event *event = g_new0(struct sipe_cal_event, 1);

					event->start_time = sipe_utils_str_to_time(sipe_xml_attribute(xn_state, "startTime"));
					if (xn_activity) {
						if (sipe_strequal(sipe_xml_attribute(xn_activity, "token"),
							    sipe_activity_map[SIPE_ACTIVITY_IN_MEETING].token))
						{
							event->is_meeting = TRUE;
						}
					}
					event->subject = sipe_xml_data(sipe_xml_child(xn_state, "meetingSubject"));
					event->location = sipe_xml_data(sipe_xml_child(xn_state, "meetingLocation"));

					publication->cal_event_hash = sipe_cal_event_hash(event);
					SIPE_DEBUG_INFO("sipe_process_roaming_self: hash=%s",
							publication->cal_event_hash);
					sipe_cal_event_free(event);
				}
			}
			/* filling publication->note */
			if (sipe_strequal(name, "note")) {
				const sipe_xml *xn_body = sipe_xml_child(node, "note/body");

				if (!has_note_cleaned) {
					has_note_cleaned = TRUE;

					g_free(sip->note);
					sip->note = NULL;
					sip->note_since = publish_time;

					do_update_status = TRUE;
				}

				g_free(publication->note);
				publication->note = NULL;
				if (xn_body) {
					char *tmp;

					publication->note = g_markup_escape_text((tmp = sipe_xml_data(xn_body)), -1);
					g_free(tmp);
					if (publish_time >= sip->note_since) {
						g_free(sip->note);
						sip->note = g_strdup(publication->note);
						sip->note_since = publish_time;
						sip->is_oof_note = sipe_strequal(sipe_xml_attribute(xn_body, "type"), "OOF");

						do_update_status = TRUE;
					}
				}
			}

			/* filling publication->fb_start_str, free_busy_base64, working_hours_xml_str */
			if (sipe_strequal(name, "calendarData") && (publication->container == 300)) {
				const sipe_xml *xn_free_busy = sipe_xml_child(node, "calendarData/freeBusy");
				const sipe_xml *xn_working_hours = sipe_xml_child(node, "calendarData/WorkingHours");
				if (xn_free_busy) {
					publication->fb_start_str = g_strdup(sipe_xml_attribute(xn_free_busy, "startTime"));
					publication->free_busy_base64 = sipe_xml_data(xn_free_busy);
				}
				if (xn_working_hours) {
					publication->working_hours_xml_str = sipe_xml_stringify(xn_working_hours);
				}
			}

			if (!cat_publications) {
				cat_publications = g_hash_table_new_full(
							g_str_hash, g_str_equal,
							g_free,	(GDestroyNotify)free_publication);
				g_hash_table_insert(sip->our_publications, g_strdup(name), cat_publications);
				SIPE_DEBUG_INFO("sipe_process_roaming_self: added GHashTable cat=%s", name);
			}
			g_hash_table_insert(cat_publications, g_strdup(key), publication);
			SIPE_DEBUG_INFO("sipe_process_roaming_self: added key=%s version=%d", key, version);
		}
		g_free(key);

		/* aggregateState (not an our publication) from 2-nd container */
		if (sipe_strequal(name, "state") && container == 2) {
			const sipe_xml *xn_state = sipe_xml_child(node, "state");

			if (xn_state && sipe_strequal(sipe_xml_attribute(xn_state, "type"), "aggregateState")) {
				const sipe_xml *xn_avail = sipe_xml_child(xn_state, "availability");

				if (xn_avail) {
					gchar *avail_str = sipe_xml_data(xn_avail);
					if (avail_str) {
						aggreg_avail = atoi(avail_str);
					}
					g_free(avail_str);
				}

				do_update_status = TRUE;
			}
		}

		/* userProperties published by server from AD */
		if (!sip->csta && sipe_strequal(name, "userProperties")) {
			const sipe_xml *line;
			/* line, for Remote Call Control (RCC) */
			for (line = sipe_xml_child(node, "userProperties/lines/line"); line; line = sipe_xml_twin(line)) {
				const gchar *line_server = sipe_xml_attribute(line, "lineServer");
				const gchar *line_type = sipe_xml_attribute(line, "lineType");
				gchar *line_uri;

				if (!line_server || !(sipe_strequal(line_type, "Rcc") || sipe_strequal(line_type, "Dual"))) continue;

				line_uri = sipe_xml_data(line);
				if (line_uri) {
					SIPE_DEBUG_INFO("sipe_process_roaming_self: line_uri=%s server=%s", line_uri, line_server);
					sip_csta_open(sipe_private, line_uri, line_server);
				}
				g_free(line_uri);

				break;
			}
		}
	}
	SIPE_DEBUG_INFO("sipe_process_roaming_self: sip->our_publications size=%d",
			sip->our_publications ? (int) g_hash_table_size(sip->our_publications) : -1);

	/* containers */
	for (node = sipe_xml_child(xml, "containers/container"); node; node = sipe_xml_twin(node)) {
		guint id = sipe_xml_int_attribute(node, "id", 0);
		struct sipe_container *container = sipe_find_container(sipe_private, id);

		if (container) {
			sip->containers = g_slist_remove(sip->containers, container);
			SIPE_DEBUG_INFO("sipe_process_roaming_self: removed existing container id=%d v%d", container->id, container->version);
			free_container(container);
		}
		container = g_new0(struct sipe_container, 1);
		container->id = id;
		container->version = sipe_xml_int_attribute(node, "version", 0);
		sip->containers = g_slist_append(sip->containers, container);
		SIPE_DEBUG_INFO("sipe_process_roaming_self: added container id=%d v%d", container->id, container->version);

		for (node2 = sipe_xml_child(node, "member"); node2; node2 = sipe_xml_twin(node2)) {
			struct sipe_container_member *member = g_new0(struct sipe_container_member, 1);
			member->type = g_strdup(sipe_xml_attribute(node2, "type"));
			member->value = g_strdup(sipe_xml_attribute(node2, "value"));
			container->members = g_slist_append(container->members, member);
			SIPE_DEBUG_INFO("sipe_process_roaming_self: added container member type=%s value=%s",
					member->type, member->value ? member->value : "");
		}
	}

	SIPE_DEBUG_INFO("sipe_process_roaming_self: sip->access_level_set=%s", sip->access_level_set ? "TRUE" : "FALSE");
	if (!sip->access_level_set && sipe_xml_child(xml, "containers")) {
		char *container_xmls = NULL;
		int sameEnterpriseAL = sipe_find_access_level(sipe_private, "sameEnterprise", NULL, NULL);
		int federatedAL      = sipe_find_access_level(sipe_private, "federated", NULL, NULL);

		SIPE_DEBUG_INFO("sipe_process_roaming_self: sameEnterpriseAL=%d", sameEnterpriseAL);
		SIPE_DEBUG_INFO("sipe_process_roaming_self: federatedAL=%d", federatedAL);
		/* initial set-up to let counterparties see your status */
		if (sameEnterpriseAL < 0) {
			struct sipe_container *container = sipe_find_container(sipe_private, 200);
			guint version = container ? container->version : 0;
			sipe_send_container_members_prepare(200, version, "add", "sameEnterprise", NULL, &container_xmls);
		}
		if (federatedAL < 0) {
			struct sipe_container *container = sipe_find_container(sipe_private, 100);
			guint version = container ? container->version : 0;
			sipe_send_container_members_prepare(100, version, "add", "federated", NULL, &container_xmls);
		}
		sip->access_level_set = TRUE;

		if (container_xmls) {
			sipe_send_set_container_members(sipe_private, container_xmls);
		}
		g_free(container_xmls);
	}

	/* Refresh contacts' blocked status */
	sipe_refresh_blocked_status(sipe_private);

	/* subscribers */
	for (node = sipe_xml_child(xml, "subscribers/subscriber"); node; node = sipe_xml_twin(node)) {
		const char *user;
		const char *acknowledged;
		gchar *hdr;
		gchar *body;

		user = sipe_xml_attribute(node, "user"); /* without 'sip:' prefix */
		if (!user) continue;
		SIPE_DEBUG_INFO("sipe_process_roaming_self: user %s", user);
		display_name = g_strdup(sipe_xml_attribute(node, "displayName"));
		uri = sip_uri_from_name(user);

		sipe_update_user_info(sipe_private, uri, ALIAS_PROP, display_name);

	        acknowledged= sipe_xml_attribute(node, "acknowledged");
		if(sipe_strcase_equal(acknowledged,"false")){
                        SIPE_DEBUG_INFO("sipe_process_roaming_self: user added you %s", user);
			if (!purple_find_buddy(sip->account, uri)) {
				purple_account_request_add(sip->account, uri, _("you"), display_name, NULL);
			}

		        hdr = g_strdup_printf(
				      "Contact: %s\r\n"
				      "Content-Type: application/msrtc-presence-setsubscriber+xml\r\n", contact);

		        body = g_strdup_printf(
				       "<setSubscribers xmlns=\"http://schemas.microsoft.com/2006/09/sip/presence-subscribers\">"
				       "<subscriber user=\"%s\" acknowledged=\"true\"/>"
				       "</setSubscribers>", user);

		        sip_transport_service(sipe_private,
					      to,
					      hdr,
					      body,
					      NULL);
		        g_free(body);
		        g_free(hdr);
                }
		g_free(display_name);
		g_free(uri);
	}

	g_free(contact);
	sipe_xml_free(xml);

	/* Publish initial state if not yet.
	 * Assuming this happens on initial responce to subscription to roaming-self
	 * so we've already updated our roaming data in full.
	 * Only for 2007+
	 */
	if (!sip->initial_state_published) {
		send_publish_category_initial(sipe_private);
		sip->initial_state_published = TRUE;
		/* dalayed run */
		sipe_schedule_seconds(sipe_private,
				      "<+update-calendar>",
				      NULL,
				      UPDATE_CALENDAR_DELAY,
				      (sipe_schedule_action)sipe_core_update_calendar,
				      NULL);
		do_update_status = FALSE;
	} else if (aggreg_avail) {

		g_free(sip->status);
		if (aggreg_avail && aggreg_avail < 18000) { /* not offline */
			sip->status = g_strdup(sipe_get_status_by_availability(aggreg_avail, NULL));
		} else {
			sip->status = g_strdup(SIPE_STATUS_ID_INVISIBLE); /* not not let offline status switch us off */
		}
	}

	if (do_update_status) {
		SIPE_DEBUG_INFO("sipe_process_roaming_self: switch to '%s' for the account", sip->status);
		sipe_set_purple_account_status_and_note(sip->account, sip->status, sip->note, sip->do_not_publish);
	}

	g_free(to);
}

/* IM Session (INVITE and MESSAGE methods) */

/* EndPoints: "alice alisson" <sip:alice@atlanta.local>, <sip:bob@atlanta.local>;epid=ebca82d94d, <sip:carol@atlanta.local> */
static gchar *
get_end_points (struct sipe_core_private *sipe_private,
		struct sip_session *session)
{
	gchar *res;

	if (session == NULL) {
		return NULL;
	}

	res = g_strdup_printf("<sip:%s>", sipe_private->username);

	SIPE_DIALOG_FOREACH {
		gchar *tmp = res;
		res = g_strdup_printf("%s, <%s>", res, dialog->with);
		g_free(tmp);

		if (dialog->theirepid) {
			tmp = res;
			res = g_strdup_printf("%s;epid=%s", res, dialog->theirepid);
			g_free(tmp);
		}
	} SIPE_DIALOG_FOREACH_END;

	return res;
}

static gboolean
process_options_response(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private,
			 struct sipmsg *msg,
			 SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	gboolean ret = TRUE;

	if (msg->response != 200) {
		SIPE_DEBUG_INFO("process_options_response: OPTIONS response is %d", msg->response);
		return FALSE;
	}

	SIPE_DEBUG_INFO("process_options_response: body:\n%s", msg->body ? msg->body : "");

	return ret;
}

/**
 * Asks UA/proxy about its capabilities.
 */
static void sipe_options_request(struct sipe_core_private *sipe_private,
				 const char *who)
{
	gchar *to = sip_uri(who);
	gchar *contact = get_contact(sipe_private);
	gchar *request = g_strdup_printf(
		"Accept: application/sdp\r\n"
		"Contact: %s\r\n", contact);
	g_free(contact);

	sip_transport_request(sipe_private,
			      "OPTIONS",
			      to,
			      to,
			      request,
			      NULL,
			      NULL,
			      process_options_response);

	g_free(to);
	g_free(request);
}

static void
sipe_notify_user(struct sipe_core_private *sipe_private,
		 struct sip_session *session,
		 PurpleMessageFlags flags,
		 const gchar *message)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	PurpleConversation *conv;

	if (!session->backend_session) {
		conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_ANY, session->with, sip->account);
	} else {
		/* TEMPORARY HACK!! */
		conv = (PurpleConversation *) session->backend_session;
	}
	purple_conversation_write(conv, NULL, message, flags, time(NULL));
}

void
sipe_present_info(struct sipe_core_private *sipe_private,
		 struct sip_session *session,
		 const gchar *message)
{
	sipe_notify_user(sipe_private, session, PURPLE_MESSAGE_SYSTEM, message);
}

static void
sipe_present_err(struct sipe_core_private *sipe_private,
		 struct sip_session *session,
		 const gchar *message)
{
	sipe_notify_user(sipe_private, session, PURPLE_MESSAGE_ERROR, message);
}

void
sipe_present_message_undelivered_err(struct sipe_core_private *sipe_private,
				     struct sip_session *session,
				     int sip_error,
				     int sip_warning,
				     const gchar *who,
				     const gchar *message)
{
	char *msg, *msg_tmp, *msg_tmp2;
	const char *label;

	msg_tmp = message ? sipe_backend_markup_strip_html(message) : NULL;
	msg = msg_tmp ? g_strdup_printf("<font color=\"#888888\"></b>%s<b></font>", msg_tmp) : NULL;
	g_free(msg_tmp);
	/* Service unavailable; Server Internal Error; Server Time-out */
	if (sip_error == 606 && sip_warning == 309) { /* Not acceptable all. */ /* Message contents not allowed by policy */
		label = _("Your message or invitation was not delivered, possibly because it contains a hyperlink or other content that the system administrator has blocked.");
		g_free(msg);
		msg = NULL;
	} else if (sip_error == 503 || sip_error == 500 || sip_error == 504) {
		label = _("This message was not delivered to %s because the service is not available");
	} else if (sip_error == 486) { /* Busy Here */
		label = _("This message was not delivered to %s because one or more recipients do not want to be disturbed");
	} else if (sip_error == 415) { /* Unsupported media type */
		label = _("This message was not delivered to %s because one or more recipients don't support this type of message");
	} else {
		label = _("This message was not delivered to %s because one or more recipients are offline");
	}

	msg_tmp = g_strdup_printf( "%s%s\n%s" ,
			msg_tmp2 = g_strdup_printf(label, who ? who : ""),
			msg ? ":" : "",
			msg ? msg : "");
	sipe_present_err(sipe_private, session, msg_tmp);
	g_free(msg_tmp2);
	g_free(msg_tmp);
	g_free(msg);
}


static gboolean
process_message_response(struct sipe_core_private *sipe_private,
			 struct sipmsg *msg,
			 SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	gboolean ret = TRUE;
	gchar *with = parse_from(sipmsg_find_header(msg, "To"));
	struct sip_session *session = sipe_session_find_im(sipe_private, with);
	struct sip_dialog *dialog;
	gchar *cseq;
	char *key;
	struct queued_message *message;

	if (!session) {
		SIPE_DEBUG_INFO_NOFORMAT("process_message_response: unable to find IM session");
		g_free(with);
		return FALSE;
	}

	dialog = sipe_dialog_find(session, with);
	if (!dialog) {
		SIPE_DEBUG_INFO_NOFORMAT("process_message_response: session outgoing dialog is NULL");
		g_free(with);
		return FALSE;
	}

	cseq = sipmsg_find_part_of_header(sipmsg_find_header(msg, "CSeq"), NULL, " ", NULL);
	key = g_strdup_printf("<%s><%d><MESSAGE><%s>", sipmsg_find_header(msg, "Call-ID"), atoi(cseq), with);
	g_free(cseq);
	message = g_hash_table_lookup(session->unconfirmed_messages, key);

	if (msg->response >= 400) {
		PurpleBuddy *pbuddy;
		const char *alias = with;
		const char *warn_hdr = sipmsg_find_header(msg, "Warning");
		int warning = -1;

		SIPE_DEBUG_INFO_NOFORMAT("process_message_response: MESSAGE response >= 400");

		if (warn_hdr) {
			gchar **parts = g_strsplit(warn_hdr, " ", 2);
			if (parts[0]) {
				warning = atoi(parts[0]);
			}
			g_strfreev(parts);
		}

		/* cancel file transfer as rejected by server */
		if (msg->response == 606 &&	/* Not acceptable all. */
		    warning == 309 &&		/* Message contents not allowed by policy */
		    message && g_str_has_prefix(message->content_type, "text/x-msmsgsinvite"))
		{
			GSList *parsed_body = sipe_ft_parse_msg_body(msg->body);
			sipe_ft_incoming_cancel(dialog, parsed_body);
			sipe_utils_nameval_free(parsed_body);
		}

		if ((pbuddy = purple_find_buddy(sip->account, with))) {
			alias = purple_buddy_get_alias(pbuddy);
		}

		sipe_present_message_undelivered_err(sipe_private, session, msg->response, warning, alias, (message ? message->body : NULL));

		/* drop dangling IM sessions: assume that BYE from remote never reached us */
		if (msg->response == 408 || /* Request timeout */
		    msg->response == 480 || /* Temporarily Unavailable */
		    msg->response == 481) { /* Call/Transaction Does Not Exist */
			SIPE_DEBUG_INFO_NOFORMAT("process_message_response: assuming dangling IM session, dropping it.");
			sip_transport_bye(sipe_private, dialog);
		}

		ret = FALSE;
	} else {
		const gchar *message_id = sipmsg_find_header(msg, "Message-Id");
		if (message_id) {
			g_hash_table_insert(session->conf_unconfirmed_messages, g_strdup(message_id), g_strdup(message->body));
			SIPE_DEBUG_INFO("process_message_response: added message with id %s to conf_unconfirmed_messages(count=%d)",
					message_id, g_hash_table_size(session->conf_unconfirmed_messages));
		}

		g_hash_table_remove(session->unconfirmed_messages, key);
		SIPE_DEBUG_INFO("process_message_response: removed message %s from unconfirmed_messages(count=%d)",
				key, g_hash_table_size(session->unconfirmed_messages));
	}

	g_free(key);
	g_free(with);

	if (ret) sipe_im_process_queue(sipe_private, session);
	return ret;
}

static void sipe_send_message(struct sipe_core_private *sipe_private,
			      struct sip_dialog *dialog,
			      const char *msg, const char *content_type)
{
	gchar *hdr;
	gchar *tmp;
	char *msgtext = NULL;
	const gchar *msgr = "";
	gchar *tmp2 = NULL;

	if (!g_str_has_prefix(content_type, "text/x-msmsgsinvite")) {
		char *msgformat;
		gchar *msgr_value;

		sipe_parse_html(msg, &msgformat, &msgtext);
		SIPE_DEBUG_INFO("sipe_send_message: msgformat=%s", msgformat);

		msgr_value = sipmsg_get_msgr_string(msgformat);
		g_free(msgformat);
		if (msgr_value) {
			msgr = tmp2 = g_strdup_printf(";msgr=%s", msgr_value);
			g_free(msgr_value);
		}
	} else {
		msgtext = g_strdup(msg);
	}

	tmp = get_contact(sipe_private);
	//hdr = g_strdup("Content-Type: text/plain; charset=UTF-8\r\n");
	//hdr = g_strdup("Content-Type: text/rtf\r\n");
	//hdr = g_strdup("Content-Type: text/plain; charset=UTF-8;msgr=WAAtAE0ATQBTAC....AoADQA\r\nSupported: timer\r\n");
	if (content_type == NULL)
		content_type = "text/plain";

	hdr = g_strdup_printf("Contact: %s\r\nContent-Type: %s; charset=UTF-8%s\r\n", tmp, content_type, msgr);
	g_free(tmp);
	g_free(tmp2);

	sip_transport_request(sipe_private,
			      "MESSAGE",
			      dialog->with,
			      dialog->with,
			      hdr,
			      msgtext,
			      dialog,
			      process_message_response);
	g_free(msgtext);
	g_free(hdr);
}


void
sipe_im_process_queue (struct sipe_core_private *sipe_private,
		       struct sip_session * session)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	GSList *entry2 = session->outgoing_message_queue;
	while (entry2) {
		struct queued_message *msg = entry2->data;

		/* for multiparty chat or conference */
		if (session->is_multiparty || session->focus_uri) {
			gchar *who = sip_uri_self(sipe_private);
			serv_got_chat_in(sip->gc, session->chat_id, who,
				PURPLE_MESSAGE_SEND, msg->body, time(NULL));
			g_free(who);
		}

		SIPE_DIALOG_FOREACH {
			char *key;
			struct queued_message *message;

			if (dialog->outgoing_invite) continue; /* do not send messages as INVITE is not responded. */

			message = g_new0(struct queued_message,1);
			message->body = g_strdup(msg->body);
			if (msg->content_type != NULL)
				message->content_type = g_strdup(msg->content_type);

			key = g_strdup_printf("<%s><%d><MESSAGE><%s>", dialog->callid, (dialog->cseq) + 1, dialog->with);
			g_hash_table_insert(session->unconfirmed_messages, g_strdup(key), message);
			SIPE_DEBUG_INFO("sipe_im_process_queue: added message %s to unconfirmed_messages(count=%d)",
					key, g_hash_table_size(session->unconfirmed_messages));
			g_free(key);

			sipe_send_message(sipe_private, dialog, msg->body, msg->content_type);
		} SIPE_DIALOG_FOREACH_END;

		entry2 = sipe_session_dequeue_message(session);
	}
}

static void
sipe_refer_notify(struct sipe_core_private *sipe_private,
		  struct sip_session *session,
		  const gchar *who,
		  int status,
		  const gchar *desc)
{
	gchar *hdr;
	gchar *body;
	struct sip_dialog *dialog = sipe_dialog_find(session, who);

	hdr = g_strdup_printf(
		"Event: refer\r\n"
		"Subscription-State: %s\r\n"
		"Content-Type: message/sipfrag\r\n",
		status >= 200 ? "terminated" : "active");

	body = g_strdup_printf(
		"SIP/2.0 %d %s\r\n",
		status, desc);

	sip_transport_request(sipe_private,
			      "NOTIFY",
			      who,
			      who,
			      hdr,
			      body,
			      dialog,
			      NULL);

	g_free(hdr);
	g_free(body);
}

static gboolean
process_invite_response(struct sipe_core_private *sipe_private,
			struct sipmsg *msg, struct transaction *trans)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	gchar *with = parse_from(sipmsg_find_header(msg, "To"));
	struct sip_session *session;
	struct sip_dialog *dialog;
	char *cseq;
	char *key;
	struct queued_message *message;
	struct sipmsg *request_msg = trans->msg;

	const gchar *callid = sipmsg_find_header(msg, "Call-ID");
	gchar *referred_by;

	session = sipe_session_find_chat_or_im(sipe_private, callid, with);
	if (!session) {
		SIPE_DEBUG_INFO_NOFORMAT("process_invite_response: unable to find IM session");
		g_free(with);
		return FALSE;
	}

	dialog = sipe_dialog_find(session, with);
	if (!dialog) {
		SIPE_DEBUG_INFO_NOFORMAT("process_invite_response: session outgoing dialog is NULL");
		g_free(with);
		return FALSE;
	}

	sipe_dialog_parse(dialog, msg, TRUE);

	cseq = sipmsg_find_part_of_header(sipmsg_find_header(msg, "CSeq"), NULL, " ", NULL);
	key = g_strdup_printf("<%s><%d><INVITE>", dialog->callid, atoi(cseq));
	g_free(cseq);
	message = g_hash_table_lookup(session->unconfirmed_messages, key);

	if (msg->response != 200) {
		PurpleBuddy *pbuddy;
		const char *alias = with;
		const char *warn_hdr = sipmsg_find_header(msg, "Warning");
		int warning = -1;

		SIPE_DEBUG_INFO_NOFORMAT("process_invite_response: INVITE response not 200");

		if (warn_hdr) {
			gchar **parts = g_strsplit(warn_hdr, " ", 2);
			if (parts[0]) {
				warning = atoi(parts[0]);
			}
			g_strfreev(parts);
		}

		/* cancel file transfer as rejected by server */
		if (msg->response == 606 &&	/* Not acceptable all. */
		    warning == 309 &&		/* Message contents not allowed by policy */
		    message && g_str_has_prefix(message->content_type, "text/x-msmsgsinvite"))
		{
			GSList *parsed_body = sipe_ft_parse_msg_body(message->body);
			sipe_ft_incoming_cancel(dialog, parsed_body);
			sipe_utils_nameval_free(parsed_body);
		}

		if ((pbuddy = purple_find_buddy(sip->account, with))) {
			alias = purple_buddy_get_alias(pbuddy);
		}

		if (message) {
			sipe_present_message_undelivered_err(sipe_private, session, msg->response, warning, alias, message->body);
		} else {
			gchar *tmp_msg = g_strdup_printf(_("Failed to invite %s"), alias);
			sipe_present_err(sipe_private, session, tmp_msg);
			g_free(tmp_msg);
		}

		sipe_dialog_remove(session, with);

		g_free(key);
		g_free(with);
		return FALSE;
	}

	dialog->cseq = 0;
	sip_transport_ack(sipe_private, dialog);
	dialog->outgoing_invite = NULL;
	dialog->is_established = TRUE;

	referred_by = parse_from(sipmsg_find_header(request_msg, "Referred-By"));
	if (referred_by) {
		sipe_refer_notify(sipe_private, session, referred_by, 200, "OK");
		g_free(referred_by);
	}

	/* add user to chat if it is a multiparty session */
	if (session->is_multiparty) {
		sipe_backend_chat_add(session->backend_session,
				      with,
				      TRUE);
	}

	if(g_slist_find_custom(dialog->supported, "ms-text-format", (GCompareFunc)g_ascii_strcasecmp)) {
		SIPE_DEBUG_INFO_NOFORMAT("process_invite_response: remote system accepted message in INVITE");
		sipe_session_dequeue_message(session);
	}

	sipe_im_process_queue(sipe_private, session);

	g_hash_table_remove(session->unconfirmed_messages, key);
	SIPE_DEBUG_INFO("process_invite_response: removed message %s from unconfirmed_messages(count=%d)",
			key, g_hash_table_size(session->unconfirmed_messages));

	g_free(key);
	g_free(with);
	return TRUE;
}


void
sipe_invite(struct sipe_core_private *sipe_private,
	    struct sip_session *session,
	    const gchar *who,
	    const gchar *msg_body,
	    const gchar *msg_content_type,
	    const gchar *referred_by,
	    const gboolean is_triggered)
{
	gchar *hdr;
	gchar *to;
	gchar *contact;
	gchar *body;
	gchar *self;
	char  *ms_text_format = NULL;
	gchar *roster_manager;
	gchar *end_points;
	gchar *referred_by_str;
	struct sip_dialog *dialog = sipe_dialog_find(session, who);

	if (dialog && dialog->is_established) {
		SIPE_DEBUG_INFO("session with %s already has a dialog open", who);
		return;
	}

	if (!dialog) {
		dialog = sipe_dialog_add(session);
		dialog->callid = session->callid ? g_strdup(session->callid) : gencallid();
		dialog->with = g_strdup(who);
	}

	if (!(dialog->ourtag)) {
		dialog->ourtag = gentag();
	}

	to = sip_uri(who);

	if (msg_body) {
		char *msgtext = NULL;
		char *base64_msg;
		const gchar *msgr = "";
		char *key;
		struct queued_message *message;
		gchar *tmp = NULL;

		if (!g_str_has_prefix(msg_content_type, "text/x-msmsgsinvite")) {
			char *msgformat;
			gchar *msgr_value;

			sipe_parse_html(msg_body, &msgformat, &msgtext);
			SIPE_DEBUG_INFO("sipe_invite: msgformat=%s", msgformat);

			msgr_value = sipmsg_get_msgr_string(msgformat);
			g_free(msgformat);
			if (msgr_value) {
				msgr = tmp = g_strdup_printf(";msgr=%s", msgr_value);
				g_free(msgr_value);
			}
		} else {
			msgtext = g_strdup(msg_body);
		}

		base64_msg = g_base64_encode((guchar*) msgtext, strlen(msgtext));
		ms_text_format = g_strdup_printf(SIPE_INVITE_TEXT,
						 msg_content_type ? msg_content_type : "text/plain",
						 msgr,
						 base64_msg);
		g_free(msgtext);
		g_free(tmp);
		g_free(base64_msg);

		message = g_new0(struct queued_message,1);
		message->body = g_strdup(msg_body);
		if (msg_content_type != NULL)
			message->content_type = g_strdup(msg_content_type);

		key = g_strdup_printf("<%s><%d><INVITE>", dialog->callid, (dialog->cseq) + 1);
		g_hash_table_insert(session->unconfirmed_messages, g_strdup(key), message);
		SIPE_DEBUG_INFO("sipe_invite: added message %s to unconfirmed_messages(count=%d)",
				key, g_hash_table_size(session->unconfirmed_messages));
		g_free(key);
	}

	contact = get_contact(sipe_private);
	end_points = get_end_points(sipe_private, session);
	self = sip_uri_self(sipe_private);
	roster_manager = g_strdup_printf(
		"Roster-Manager: %s\r\n"
		"EndPoints: %s\r\n",
		self,
		end_points);
	referred_by_str = referred_by ?
		g_strdup_printf(
			"Referred-By: %s\r\n",
			referred_by)
		: g_strdup("");
	hdr = g_strdup_printf(
		"Supported: ms-sender\r\n"
		"%s"
		"%s"
		"%s"
		"%s"
		"Contact: %s\r\n%s"
		"Content-Type: application/sdp\r\n",
		sipe_strcase_equal(session->roster_manager, self) ? roster_manager : "",
		referred_by_str,
		is_triggered ? "TriggeredInvite: TRUE\r\n" : "",
		is_triggered || session->is_multiparty ? "Require: com.microsoft.rtc-multiparty\r\n" : "",
		contact,
		ms_text_format ? ms_text_format : "");
	g_free(ms_text_format);
	g_free(self);

	body = g_strdup_printf(
		"v=0\r\n"
		"o=- 0 0 IN IP4 %s\r\n"
		"s=session\r\n"
		"c=IN IP4 %s\r\n"
		"t=0 0\r\n"
		"m=%s %d sip null\r\n"
		"a=accept-types:" SDP_ACCEPT_TYPES "\r\n",
		sipe_backend_network_ip_address(),
		sipe_backend_network_ip_address(),
		SIPE_CORE_PRIVATE_FLAG_IS(OCS2007) ? "message" : "x-ms-message",
		sip_transport_port(sipe_private));

	dialog->outgoing_invite = sip_transport_request(sipe_private,
							"INVITE",
							to,
							to,
							hdr,
							body,
							dialog,
							process_invite_response);

	g_free(to);
	g_free(roster_manager);
	g_free(end_points);
	g_free(referred_by_str);
	g_free(body);
	g_free(hdr);
	g_free(contact);
}

static void
sipe_session_close(struct sipe_core_private *sipe_private,
		   struct sip_session * session)
{
	if (session && session->focus_uri) {
		sipe_conf_immcu_closed(sipe_private, session);
		conf_session_close(sipe_private, session);
	}

	if (session) {
		SIPE_DIALOG_FOREACH {
			/* @TODO slow down BYE message sending rate */
			/* @see single subscription code */
			sip_transport_bye(sipe_private, dialog);
		} SIPE_DIALOG_FOREACH_END;

		sipe_session_remove(sipe_private, session);
	}
}

static void
sipe_session_close_all(struct sipe_core_private *sipe_private)
{
	GSList *entry;
	while ((entry = sipe_private->sessions) != NULL) {
		sipe_session_close(sipe_private, entry->data);
	}
}

void
sipe_convo_closed(PurpleConnection * gc, const char *who)
{
	struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;

	SIPE_DEBUG_INFO("conversation with %s closed", who);
	sipe_session_close(sipe_private,
			   sipe_session_find_im(sipe_private, who));
}

void
sipe_chat_leave (PurpleConnection *gc, int id)
{
	struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;
	struct sip_session *session = sipe_session_find_chat_by_id(sipe_private,
								   id);

	sipe_session_close(sipe_private, session);
}

int sipe_im_send(PurpleConnection *gc, const char *who, const char *what,
		 SIPE_UNUSED_PARAMETER PurpleMessageFlags flags)
{
	struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;
	struct sip_session *session;
	struct sip_dialog *dialog;
	gchar *uri = sip_uri(who);

	SIPE_DEBUG_INFO("sipe_im_send what='%s'", what);

	session = sipe_session_find_or_add_im(sipe_private, uri);
	dialog = sipe_dialog_find(session, uri);

	// Queue the message
	sipe_session_enqueue_message(session, what, NULL);

	if (dialog && !dialog->outgoing_invite) {
		sipe_im_process_queue(sipe_private, session);
	} else if (!dialog || !dialog->outgoing_invite) {
		// Need to send the INVITE to get the outgoing dialog setup
		sipe_invite(sipe_private, session, uri, what, NULL, NULL, FALSE);
	}

	g_free(uri);
	return 1;
}

int sipe_chat_send(PurpleConnection *gc, int id, const char *what,
		   SIPE_UNUSED_PARAMETER PurpleMessageFlags flags)
{
	struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	struct sip_session *session;

	SIPE_DEBUG_INFO("sipe_chat_send what='%s'", what);

	session = sipe_session_find_chat_by_id(sipe_private, id);

	// Queue the message
	if (session && session->dialogs) {
		sipe_session_enqueue_message(session,what,NULL);
		sipe_im_process_queue(sipe_private, session);
	} else if (sip) {
		gchar *chat_name = purple_find_chat(sip->gc, id)->name;
		const gchar *proto_chat_id = sipe_chat_find_name(chat_name);

		SIPE_DEBUG_INFO("sipe_chat_send: chat_name='%s'", chat_name ? chat_name : "NULL");
		SIPE_DEBUG_INFO("sipe_chat_send: proto_chat_id='%s'", proto_chat_id ? proto_chat_id : "NULL");

		if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
			struct sip_session *session = sipe_session_add_chat(sipe_private);

			session->is_multiparty = FALSE;
			session->focus_uri = g_strdup(proto_chat_id);
			sipe_session_enqueue_message(session, what, NULL);
			sipe_invite_conf_focus(sipe_private, session);
		}
	}

	return 1;
}

/* End IM Session (INVITE and MESSAGE methods) */
void process_incoming_info(struct sipe_core_private *sipe_private,
			   struct sipmsg *msg)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	const gchar *contenttype = sipmsg_find_header(msg, "Content-Type");
	const gchar *callid = sipmsg_find_header(msg, "Call-ID");
	gchar *from;
	struct sip_session *session;

	SIPE_DEBUG_INFO("process_incoming_info: \n%s", msg->body ? msg->body : "");

	/* Call Control protocol */
	if (g_str_has_prefix(contenttype, "application/csta+xml"))
	{
		process_incoming_info_csta(sipe_private, msg);
		return;
	}

	from = parse_from(sipmsg_find_header(msg, "From"));
	session = sipe_session_find_chat_or_im(sipe_private, callid, from);
	if (!session) {
		g_free(from);
		return;
	}

	if (g_str_has_prefix(contenttype, "application/x-ms-mim"))
	{
		sipe_xml *xn_action           = sipe_xml_parse(msg->body, msg->bodylen);
		const sipe_xml *xn_request_rm = sipe_xml_child(xn_action, "RequestRM");
		const sipe_xml *xn_set_rm     = sipe_xml_child(xn_action, "SetRM");

		sipmsg_add_header(msg, "Content-Type", "application/x-ms-mim");

		if (xn_request_rm) {
			//const char *rm = sipe_xml_attribute(xn_request_rm, "uri");
			int bid = sipe_xml_int_attribute(xn_request_rm, "bid", 0);
			gchar *body = g_strdup_printf(
				"<?xml version=\"1.0\"?>\r\n"
				"<action xmlns=\"http://schemas.microsoft.com/sip/multiparty/\">"
				"<RequestRMResponse uri=\"sip:%s\" allow=\"%s\"/></action>\r\n",
				sipe_private->username,
				session->bid < bid ? "true" : "false");
			sip_transport_response(sipe_private, msg, 200, "OK", body);
			g_free(body);
		} else if (xn_set_rm) {
			gchar *body;
			const char *rm = sipe_xml_attribute(xn_set_rm, "uri");
			g_free(session->roster_manager);
			session->roster_manager = g_strdup(rm);

			body = g_strdup_printf(
				"<?xml version=\"1.0\"?>\r\n"
				"<action xmlns=\"http://schemas.microsoft.com/sip/multiparty/\">"
				"<SetRMResponse uri=\"sip:%s\"/></action>\r\n",
				sipe_private->username);
			sip_transport_response(sipe_private, msg, 200, "OK", body);
			g_free(body);
		}
		sipe_xml_free(xn_action);

	}
	else
	{
		/* looks like purple lacks typing notification for chat */
		if (!session->is_multiparty && !session->focus_uri) {
			sipe_xml *xn_keyboard_activity  = sipe_xml_parse(msg->body, msg->bodylen);
			const char *status = sipe_xml_attribute(sipe_xml_child(xn_keyboard_activity, "status"),
								"status");
			if (sipe_strequal(status, "type")) {
				serv_got_typing(sip->gc, from, SIPE_TYPING_RECV_TIMEOUT, PURPLE_TYPING);
			} else if (sipe_strequal(status, "idle")) {
				serv_got_typing_stopped(sip->gc, from);
			}
			sipe_xml_free(xn_keyboard_activity);
		}

		sip_transport_response(sipe_private, msg, 200, "OK", NULL);
	}
	g_free(from);
}

void process_incoming_cancel(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private,
			     SIPE_UNUSED_PARAMETER struct sipmsg *msg)
{
#if HAVE_VV
	struct sipe_media_call_private *call_private = sipe_private->media_call;
	const gchar *callid = sipmsg_find_header(msg, "Call-ID");
	if (call_private &&
	    sipe_strequal(sipe_media_get_callid(call_private), callid)) {
		struct sip_session *session = sipe_session_find_chat_by_callid(sipe_private,
									       callid);
		sipe_media_hangup(sipe_private);
		if (session) {
			gchar *from = parse_from(sipmsg_find_header(msg, "From"));
			sipe_dialog_remove(session, from);
			g_free(from);

			sipe_session_close(sipe_private, session);
		}
	}
#endif
}

void process_incoming_bye(struct sipe_core_private *sipe_private,
			  struct sipmsg *msg)
{
	const gchar *callid = sipmsg_find_header(msg, "Call-ID");
	gchar *from = parse_from(sipmsg_find_header(msg, "From"));
	struct sip_session *session;
	struct sip_dialog *dialog;

#if HAVE_VV
	{
		struct sipe_media_call_private *call_private = sipe_private->media_call;
		if (call_private &&
		    sipe_strequal(sipe_media_get_callid(call_private), callid)) {
			// BYE ends a media call
			sipe_media_hangup(sipe_private);
		}
	}
#endif

	/* collect dialog identification
	 * we need callid, ourtag and theirtag to unambiguously identify dialog
	 */
	/* take data before 'msg' will be modified by sip_transport_response */
	dialog = g_new0(struct sip_dialog, 1);
	dialog->callid = g_strdup(callid);
	dialog->cseq = parse_cseq(sipmsg_find_header(msg, "CSeq"));
	dialog->with = g_strdup(from);
	sipe_dialog_parse(dialog, msg, FALSE);

	sip_transport_response(sipe_private, msg, 200, "OK", NULL);

	session = sipe_session_find_chat_or_im(sipe_private, callid, from);
	if (!session) {
		sipe_dialog_free(dialog);
		g_free(from);
		return;
	}

	if (session->roster_manager && !g_strcasecmp(from, session->roster_manager)) {
		g_free(session->roster_manager);
		session->roster_manager = NULL;
	}

	/* This what BYE is essentially for - terminating dialog */
	sipe_dialog_remove_3(session, dialog);
	sipe_dialog_free(dialog);
	if (session->focus_uri && !g_strcasecmp(from, session->im_mcu_uri)) {
		sipe_conf_immcu_closed(sipe_private, session);
	} else if (session->is_multiparty) {
		sipe_backend_chat_remove(session->backend_session,
					 from);
	}

	g_free(from);
}

void process_incoming_refer(struct sipe_core_private *sipe_private,
			    struct sipmsg *msg)
{
	gchar *self = sip_uri_self(sipe_private);
	const gchar *callid = sipmsg_find_header(msg, "Call-ID");
	gchar *from = parse_from(sipmsg_find_header(msg, "From"));
	gchar *refer_to = parse_from(sipmsg_find_header(msg, "Refer-to"));
	gchar *referred_by = g_strdup(sipmsg_find_header(msg, "Referred-By"));
	struct sip_session *session;
	struct sip_dialog *dialog;

	session = sipe_session_find_chat_by_callid(sipe_private, callid);
	dialog = sipe_dialog_find(session, from);

	if (!session || !dialog || !session->roster_manager || !sipe_strcase_equal(session->roster_manager, self)) {
		sip_transport_response(sipe_private, msg, 500, "Server Internal Error", NULL);
	} else {
		sip_transport_response(sipe_private, msg, 202, "Accepted", NULL);

		sipe_invite(sipe_private, session, refer_to, NULL, NULL, referred_by, FALSE);
	}

	g_free(self);
	g_free(from);
	g_free(refer_to);
	g_free(referred_by);
}

unsigned int
sipe_send_typing(PurpleConnection *gc, const char *who, PurpleTypingState state)
{
	struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;
	struct sip_session *session;
	struct sip_dialog *dialog;

	if (state == PURPLE_NOT_TYPING)
		return 0;

	session = sipe_session_find_im(sipe_private, who);
	dialog = sipe_dialog_find(session, who);

	if (session && dialog && dialog->is_established) {
		sip_transport_info(sipe_private,
				   "Content-Type: application/xml\r\n",
				   SIPE_SEND_TYPING,
				   dialog,
				   NULL);
	}
	return SIPE_TYPING_SEND_TIMEOUT;
}

static gboolean
sipe_process_incoming_x_msmsgsinvite(struct sipe_core_private *sipe_private,
				     struct sip_dialog *dialog,
				     GSList *parsed_body)
{
	gboolean found = FALSE;

	if (parsed_body) {
		const gchar *invitation_command = sipe_utils_nameval_find(parsed_body, "Invitation-Command");

		if (sipe_strequal(invitation_command, "INVITE")) {
			sipe_ft_incoming_transfer(sipe_private, dialog, parsed_body);
			found = TRUE;
		} else if (sipe_strequal(invitation_command, "CANCEL")) {
			sipe_ft_incoming_cancel(dialog, parsed_body);
			found = TRUE;
		} else if (sipe_strequal(invitation_command, "ACCEPT")) {
			sipe_ft_incoming_accept(dialog, parsed_body);
			found = TRUE;
		}
	}
	return found;
}

void process_incoming_message(struct sipe_core_private *sipe_private,
			      struct sipmsg *msg)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	gchar *from;
	const gchar *contenttype;
	gboolean found = FALSE;

	from = parse_from(sipmsg_find_header(msg, "From"));

	if (!from) return;

	SIPE_DEBUG_INFO("got message from %s: %s", from, msg->body);

	contenttype = sipmsg_find_header(msg, "Content-Type");
	if (g_str_has_prefix(contenttype, "text/plain")
	    || g_str_has_prefix(contenttype, "text/html")
	    || g_str_has_prefix(contenttype, "multipart/related")
	    || g_str_has_prefix(contenttype, "multipart/alternative"))
	{
		const gchar *callid = sipmsg_find_header(msg, "Call-ID");
		gchar *html = get_html_message(contenttype, msg->body);

		struct sip_session *session = sipe_session_find_chat_or_im(sipe_private,
									   callid,
									   from);
		if (session && session->focus_uri) { /* a conference */
			gchar *tmp = parse_from(sipmsg_find_header(msg, "Ms-Sender"));
			gchar *sender = parse_from(tmp);
			g_free(tmp);
			serv_got_chat_in(sip->gc, session->chat_id, sender,
				PURPLE_MESSAGE_RECV, html, time(NULL));
			g_free(sender);
		} else if (session && session->is_multiparty) { /* a multiparty chat */
			serv_got_chat_in(sip->gc, session->chat_id, from,
				PURPLE_MESSAGE_RECV, html, time(NULL));
		} else {
			serv_got_im(sip->gc, from, html, 0, time(NULL));
		}
		g_free(html);
		sip_transport_response(sipe_private, msg, 200, "OK", NULL);
		found = TRUE;

	} else if (g_str_has_prefix(contenttype, "application/im-iscomposing+xml")) {
		sipe_xml *isc = sipe_xml_parse(msg->body, msg->bodylen);
		const sipe_xml *state;
		gchar *statedata;

		if (!isc) {
			SIPE_DEBUG_INFO_NOFORMAT("process_incoming_message: can not parse iscomposing");
			g_free(from);
			return;
		}

		state = sipe_xml_child(isc, "state");

		if (!state) {
			SIPE_DEBUG_INFO_NOFORMAT("process_incoming_message: no state found");
			sipe_xml_free(isc);
			g_free(from);
			return;
		}

		statedata = sipe_xml_data(state);
		if (statedata) {
			if (strstr(statedata, "active")) serv_got_typing(sip->gc, from, 0, PURPLE_TYPING);
			else serv_got_typing_stopped(sip->gc, from);

			g_free(statedata);
		}
		sipe_xml_free(isc);
		sip_transport_response(sipe_private, msg, 200, "OK", NULL);
		found = TRUE;
	} else if (g_str_has_prefix(contenttype, "text/x-msmsgsinvite")) {
		const gchar *callid = sipmsg_find_header(msg, "Call-ID");
		struct sip_session *session = sipe_session_find_chat_or_im(sipe_private,
									   callid,
									   from);
		struct sip_dialog *dialog = sipe_dialog_find(session, from);
		GSList *body = sipe_ft_parse_msg_body(msg->body);
		found = sipe_process_incoming_x_msmsgsinvite(sipe_private, dialog, body);
		sipe_utils_nameval_free(body);
		if (found) {
			sip_transport_response(sipe_private, msg, 200, "OK", NULL);
		}
	}
	if (!found) {
		const gchar *callid = sipmsg_find_header(msg, "Call-ID");
		struct sip_session *session = sipe_session_find_chat_or_im(sipe_private,
									   callid,
									   from);
		if (session) {
			gchar *errmsg = g_strdup_printf(_("Received a message with unrecognized contents from %s"),
							from);
			sipe_present_err(sipe_private, session, errmsg);
			g_free(errmsg);
		}

		SIPE_DEBUG_INFO("got unknown mime-type '%s'", contenttype);
		sip_transport_response(sipe_private, msg, 415, "Unsupported media type", NULL);
	}
	g_free(from);
}

#ifdef HAVE_VV
static void sipe_invite_mime_cb(gpointer user_data, const GSList *fields,
								const gchar *body, SIPE_UNUSED_PARAMETER gsize length)
{
	const gchar *type = sipe_utils_nameval_find(fields, "Content-Type");
	const gchar *cd = sipe_utils_nameval_find(fields, "Content-Disposition");

	if (!g_str_has_prefix(type, "application/sdp"))
		return;

	if (cd && !strstr(cd, "ms-proxy-2007fallback")) {
		struct sipmsg *msg = user_data;
		const gchar* msg_ct = sipmsg_find_header(msg, "Content-Type");

		if (g_str_has_prefix(msg_ct, "application/sdp")) {
			/* We have already found suitable alternative and set message's body
			 * and Content-Type accordingly */
			return;
		}

		sipmsg_remove_header_now(msg, "Content-Type");
		sipmsg_add_header_now(msg, "Content-Type", type);

		/* Replace message body with chosen alternative, so we can continue to
		 * process it as a normal single part message. */
		g_free(msg->body);
		msg->body = g_strndup(body, length);
	}
}
#endif

void process_incoming_invite(struct sipe_core_private *sipe_private,
			     struct sipmsg *msg)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	gchar *body;
	gchar *newTag;
	const gchar *oldHeader;
	gchar *newHeader;
	gboolean is_multiparty = FALSE;
	gboolean is_triggered = FALSE;
	gboolean was_multiparty = TRUE;
	gboolean just_joined = FALSE;
	gchar *from;
	const gchar *callid         = sipmsg_find_header(msg, "Call-ID");
	const gchar *roster_manager = sipmsg_find_header(msg, "Roster-Manager");
	const gchar *end_points_hdr = sipmsg_find_header(msg, "EndPoints");
	const gchar *trig_invite    = sipmsg_find_header(msg, "TriggeredInvite");
	const gchar *content_type   = sipmsg_find_header(msg, "Content-Type");
	GSList *end_points = NULL;
	char *tmp = NULL;
	struct sip_session *session;
	const gchar *ms_text_format;

	SIPE_DEBUG_INFO("process_incoming_invite: body:\n%s!", msg->body ? tmp = fix_newlines(msg->body) : "");
	g_free(tmp);

#ifdef HAVE_VV
	if (g_str_has_prefix(content_type, "multipart/alternative")) {
		sipe_mime_parts_foreach(content_type, msg->body, sipe_invite_mime_cb, msg);
	}
#endif

	/* Invitation to join conference */
	if (g_str_has_prefix(content_type, "application/ms-conf-invite+xml")) {
		process_incoming_invite_conf(sipe_private, msg);
		return;
	}

#ifdef HAVE_VV
	/* Invitation to audio call */
	if (msg->body && strstr(msg->body, "m=audio")) {
		sipe_media_incoming_invite(sipe_private, msg);
		return;
	}
#endif

	/* Only accept text invitations */
	if (msg->body && !(strstr(msg->body, "m=message") || strstr(msg->body, "m=x-ms-message"))) {
		sip_transport_response(sipe_private, msg, 501, "Not implemented", NULL);
		return;
	}

	// TODO There *must* be a better way to clean up the To header to add a tag...
	SIPE_DEBUG_INFO_NOFORMAT("Adding a Tag to the To Header on Invite Request...");
	oldHeader = sipmsg_find_header(msg, "To");
	newTag = gentag();
	newHeader = g_strdup_printf("%s;tag=%s", oldHeader, newTag);
	sipmsg_remove_header_now(msg, "To");
	sipmsg_add_header_now(msg, "To", newHeader);
	g_free(newHeader);

	if (end_points_hdr) {
		end_points = sipmsg_parse_endpoints_header(end_points_hdr);

		if (g_slist_length(end_points) > 2) {
			is_multiparty = TRUE;
		}
	}
	if (trig_invite && !g_strcasecmp(trig_invite, "TRUE")) {
		is_triggered = TRUE;
		is_multiparty = TRUE;
	}

	session = sipe_session_find_chat_by_callid(sipe_private, callid);
	/* Convert to multiparty */
	if (session && is_multiparty && !session->is_multiparty) {
		g_free(session->with);
		session->with = NULL;
		was_multiparty = FALSE;
		session->is_multiparty = TRUE;
		session->chat_id = rand();
	}

	if (!session && is_multiparty) {
		session = sipe_session_find_or_add_chat_by_callid(sipe_private,
								  callid);
	}
	/* IM session */
	from = parse_from(sipmsg_find_header(msg, "From"));
	if (!session) {
		session = sipe_session_find_or_add_im(sipe_private, from);
	}

	if (session) {
		g_free(session->callid);
		session->callid = g_strdup(callid);

		session->is_multiparty = is_multiparty;
		if (roster_manager) {
			session->roster_manager = g_strdup(roster_manager);
		}
	}

	if (is_multiparty && end_points) {
		gchar *to = parse_from(sipmsg_find_header(msg, "To"));
		GSList *entry = end_points;
		while (entry) {
			struct sip_dialog *dialog;
			struct sipendpoint *end_point = entry->data;
			entry = entry->next;

			if (!g_strcasecmp(from, end_point->contact) ||
			    !g_strcasecmp(to,   end_point->contact))
				continue;

			dialog = sipe_dialog_find(session, end_point->contact);
			if (dialog) {
				g_free(dialog->theirepid);
				dialog->theirepid = end_point->epid;
				end_point->epid = NULL;
			} else {
				dialog = sipe_dialog_add(session);

				dialog->callid = g_strdup(session->callid);
				dialog->with = end_point->contact;
				end_point->contact = NULL;
				dialog->theirepid = end_point->epid;
				end_point->epid = NULL;

				just_joined = TRUE;

				/* send triggered INVITE */
				sipe_invite(sipe_private, session, dialog->with, NULL, NULL, NULL, TRUE);
			}
		}
		g_free(to);
	}

	if (end_points) {
		GSList *entry = end_points;
		while (entry) {
			struct sipendpoint *end_point = entry->data;
			entry = entry->next;
			g_free(end_point->contact);
			g_free(end_point->epid);
			g_free(end_point);
		}
		g_slist_free(end_points);
	}

	if (session) {
		struct sip_dialog *dialog = sipe_dialog_find(session, from);
		if (dialog) {
			SIPE_DEBUG_INFO_NOFORMAT("process_incoming_invite, session already has dialog!");
			sipe_dialog_parse_routes(dialog, msg, FALSE);
		} else {
			dialog = sipe_dialog_add(session);

			dialog->callid = g_strdup(session->callid);
			dialog->with = g_strdup(from);
			sipe_dialog_parse(dialog, msg, FALSE);

			if (!dialog->ourtag) {
				dialog->ourtag = newTag;
				newTag = NULL;
			}

			just_joined = TRUE;
		}
	} else {
		SIPE_DEBUG_INFO_NOFORMAT("process_incoming_invite, failed to find or create IM session");
	}
	g_free(newTag);

	if (is_multiparty && !session->backend_session) {
		gchar *chat_title = sipe_chat_get_name(callid);
		gchar *self = sip_uri_self(sipe_private);
		/* create chat */
		session->backend_session = sipe_backend_chat_create(SIPE_CORE_PUBLIC,
								    session->chat_id,
								    chat_title, 
								    self,
								    FALSE);
		session->chat_title = g_strdup(chat_title);
		/* add self */
		sipe_backend_chat_add(session->backend_session,
				      self,
				      FALSE);
		g_free(chat_title);
		g_free(self);
	}

	if (is_multiparty && !was_multiparty) {
		/* add current IM counterparty to chat */
		sipe_backend_chat_add(session->backend_session,
				      sipe_dialog_first(session)->with,
				      FALSE);
	}

	/* add inviting party to chat */
	if (just_joined && session->backend_session) {
		sipe_backend_chat_add(session->backend_session,
				      from,
				      TRUE);
	}

	/* ms-text-format: text/plain; charset=UTF-8;msgr=WAAtAE0...DIADQAKAA0ACgA;ms-body=SGk= */

	/* This used only in 2005 official client, not 2007 or Reuters.
	   Disabled for most cases as interfering with audit of messages which only is applied to regular MESSAGEs.
	   Only enabled for 2005 multiparty chats as otherwise the first message got lost completely.
	*/
	/* also enabled for 2005 file transfer. Didn't work otherwise. */
	ms_text_format = sipmsg_find_header(msg, "ms-text-format");
	if (is_multiparty ||
	    (ms_text_format && g_str_has_prefix(ms_text_format, "text/x-msmsgsinvite")) )
	{
		if (ms_text_format) {
			if (g_str_has_prefix(ms_text_format, "text/x-msmsgsinvite"))
			{
				gchar *tmp = sipmsg_find_part_of_header(ms_text_format, "ms-body=", NULL, NULL);
				if (tmp) {
					gsize len;
					struct sip_dialog *dialog = sipe_dialog_find(session, from);
					gchar *body = (gchar *) g_base64_decode(tmp, &len);

					GSList *parsed_body = sipe_ft_parse_msg_body(body);

					sipe_process_incoming_x_msmsgsinvite(sipe_private, dialog, parsed_body);
					sipe_utils_nameval_free(parsed_body);
					sipmsg_add_header(msg, "Supported", "ms-text-format"); /* accepts received message */
				}
				g_free(tmp);
			}
			else if (g_str_has_prefix(ms_text_format, "text/plain") || g_str_has_prefix(ms_text_format, "text/html"))
			{
				/* please do not optimize logic inside as this code may be re-enabled for other cases */
				gchar *html = get_html_message(ms_text_format, NULL);
				if (html) {
					if (is_multiparty) {
						serv_got_chat_in(sip->gc, session->chat_id, from,
							PURPLE_MESSAGE_RECV, html, time(NULL));
					} else {
						serv_got_im(sip->gc, from, html, 0, time(NULL));
					}
					g_free(html);
					sipmsg_add_header(msg, "Supported", "ms-text-format"); /* accepts received message */
				}
			}
		}
	}

	g_free(from);

	sipmsg_add_header(msg, "Supported", "com.microsoft.rtc-multiparty");
	sipmsg_add_header(msg, "User-Agent", sip_transport_user_agent(sipe_private));
	sipmsg_add_header(msg, "Content-Type", "application/sdp");

	body = g_strdup_printf(
		"v=0\r\n"
		"o=- 0 0 IN IP4 %s\r\n"
		"s=session\r\n"
		"c=IN IP4 %s\r\n"
		"t=0 0\r\n"
		"m=%s %d sip sip:%s\r\n"
		"a=accept-types:" SDP_ACCEPT_TYPES "\r\n",
		sipe_backend_network_ip_address(),
		sipe_backend_network_ip_address(),
		SIPE_CORE_PRIVATE_FLAG_IS(OCS2007) ? "message" : "x-ms-message",
		sip_transport_port(sipe_private),
		sipe_private->username);
	sip_transport_response(sipe_private, msg, 200, "OK", body);
	g_free(body);
}

void process_incoming_options(struct sipe_core_private *sipe_private,
			      struct sipmsg *msg)
{
	gchar *body;

	sipmsg_add_header(msg, "Allow", "INVITE, MESSAGE, INFO, SUBSCRIBE, OPTIONS, BYE, CANCEL, NOTIFY, ACK, REFER, BENOTIFY");
	sipmsg_add_header(msg, "User-Agent", sip_transport_user_agent(sipe_private));
	sipmsg_add_header(msg, "Content-Type", "application/sdp");

	body = g_strdup_printf(
		"v=0\r\n"
		"o=- 0 0 IN IP4 0.0.0.0\r\n"
		"s=session\r\n"
		"c=IN IP4 0.0.0.0\r\n"
		"t=0 0\r\n"
		"m=%s %d sip sip:%s\r\n"
		"a=accept-types:" SDP_ACCEPT_TYPES "\r\n",
		SIPE_CORE_PRIVATE_FLAG_IS(OCS2007) ? "message" : "x-ms-message",
		sip_transport_port(sipe_private),
		sipe_private->username);
	sip_transport_response(sipe_private, msg, 200, "OK", body);
	g_free(body);
}

/**
 * Returns 2005-style activity and Availability.
 *
 * @param status Sipe statis id.
 */
static void
sipe_get_act_avail_by_status_2005(const char *status,
				  int *activity,
				  int *availability)
{
	int avail = 300; /* online */
	int act = 400;  /* Available */

	if (sipe_strequal(status, SIPE_STATUS_ID_AWAY)) {
		act = 100;
	//} else if (sipe_strequal(status, SIPE_STATUS_ID_LUNCH)) {
	//	act = 150;
	} else if (sipe_strequal(status, SIPE_STATUS_ID_BRB)) {
		act = 300;
	} else if (sipe_strequal(status, SIPE_STATUS_ID_AVAILABLE)) {
		act = 400;
	//} else if (sipe_strequal(status, SIPE_STATUS_ID_ON_PHONE)) {
	//	act = 500;
	} else if (sipe_strequal(status, SIPE_STATUS_ID_BUSY) ||
		   sipe_strequal(status, SIPE_STATUS_ID_DND)) {
		act = 600;
	} else if (sipe_strequal(status, SIPE_STATUS_ID_INVISIBLE) ||
		   sipe_strequal(status, SIPE_STATUS_ID_OFFLINE)) {
		avail = 0; /* offline */
		act = 100;
	} else {
		act = 400; /* Available */
	}

	if (activity) *activity = act;
	if (availability) *availability = avail;
}

/**
 * [MS-SIP] 2.2.1
 *
 * @param activity	2005 aggregated activity.    Ex.: 600
 * @param availablity	2005 aggregated availablity. Ex.: 300
 */
static const char *
sipe_get_status_by_act_avail_2005(const int activity,
				  const int availablity,
				  char **activity_desc)
{
	const char *status_id = NULL;
	const char *act = NULL;

	if (activity < 150) {
		status_id = SIPE_STATUS_ID_AWAY;
	} else if (activity < 200) {
		//status_id = SIPE_STATUS_ID_LUNCH;
		status_id = SIPE_STATUS_ID_AWAY;
		act = SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_LUNCH);
	} else if (activity < 300) {
		//status_id = SIPE_STATUS_ID_IDLE;
		status_id = SIPE_STATUS_ID_AWAY;
		act = SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_INACTIVE);
	} else if (activity < 400) {
		status_id = SIPE_STATUS_ID_BRB;
	} else if (activity < 500) {
		status_id = SIPE_STATUS_ID_AVAILABLE;
	} else if (activity < 600) {
		//status_id = SIPE_STATUS_ID_ON_PHONE;
		status_id = SIPE_STATUS_ID_BUSY;
		act = SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_ON_PHONE);
	} else if (activity < 700) {
		status_id = SIPE_STATUS_ID_BUSY;
	} else if (activity < 800) {
		status_id = SIPE_STATUS_ID_AWAY;
	} else {
		status_id = SIPE_STATUS_ID_AVAILABLE;
	}

	if (availablity < 100)
		status_id = SIPE_STATUS_ID_OFFLINE;

	if (activity_desc && act) {
		g_free(*activity_desc);
		*activity_desc = g_strdup(act);
	}

	return status_id;
}

/**
 * [MS-PRES] Table 3: Conversion of legacyInterop elements and attributes to MSRTC elements and attributes.
 */
static const char*
sipe_get_status_by_availability(int avail,
				char** activity_desc)
{
	const char *status;
	const char *act = NULL;

	if (avail < 3000) {
		status = SIPE_STATUS_ID_OFFLINE;
	} else if (avail < 4500) {
		status = SIPE_STATUS_ID_AVAILABLE;
	} else if (avail < 6000) {
		//status = SIPE_STATUS_ID_IDLE;
		status = SIPE_STATUS_ID_AVAILABLE;
		act = SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_INACTIVE);
	} else if (avail < 7500) {
		status = SIPE_STATUS_ID_BUSY;
	} else if (avail < 9000) {
		//status = SIPE_STATUS_ID_BUSYIDLE;
		status = SIPE_STATUS_ID_BUSY;
		act = SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_BUSYIDLE);
	} else if (avail < 12000) {
		status = SIPE_STATUS_ID_DND;
	} else if (avail < 15000) {
		status = SIPE_STATUS_ID_BRB;
	} else if (avail < 18000) {
		status = SIPE_STATUS_ID_AWAY;
	} else {
		status = SIPE_STATUS_ID_OFFLINE;
	}

	if (activity_desc && act) {
		g_free(*activity_desc);
		*activity_desc = g_strdup(act);
	}

	return status;
}

/**
 * Returns 2007-style availability value
 *
 * @param sipe_status_id (in)
 * @param activity_token (out)	Must be g_free()'d after use if consumed.
 */
static int
sipe_get_availability_by_status(const char* sipe_status_id, char** activity_token)
{
	int availability;
	sipe_activity activity = SIPE_ACTIVITY_UNSET;

	if (sipe_strequal(sipe_status_id, SIPE_STATUS_ID_AWAY)) {
		availability = 15500;
		if (!activity_token || !(*activity_token))	{
			activity = SIPE_ACTIVITY_AWAY;
		}
	} else if (sipe_strequal(sipe_status_id, SIPE_STATUS_ID_BRB)) {
		availability = 12500;
		activity = SIPE_ACTIVITY_BRB;
	} else if (sipe_strequal(sipe_status_id, SIPE_STATUS_ID_DND)) {
		availability =  9500;
		activity = SIPE_ACTIVITY_DND;
	} else if (sipe_strequal(sipe_status_id, SIPE_STATUS_ID_BUSY)) {
		availability =  6500;
		if (!activity_token || !(*activity_token))	{
			activity = SIPE_ACTIVITY_BUSY;
		}
	} else if (sipe_strequal(sipe_status_id, SIPE_STATUS_ID_AVAILABLE)) {
		availability =  3500;
		activity = SIPE_ACTIVITY_ONLINE;
	} else if (sipe_strequal(sipe_status_id, SIPE_STATUS_ID_UNKNOWN)) {
		availability =     0;
	} else {
		// Offline or invisible
		availability = 18500;
		activity = SIPE_ACTIVITY_OFFLINE;
	}

	if (activity_token) {
		*activity_token = g_strdup(sipe_activity_map[activity].token);
	}
	return availability;
}

static void process_incoming_notify_rlmi(struct sipe_core_private *sipe_private,
					 const gchar *data, unsigned len)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	const char *uri;
	sipe_xml *xn_categories;
	const sipe_xml *xn_category;
	const char *status = NULL;
	gboolean do_update_status = FALSE;
	gboolean has_note_cleaned = FALSE;
	gboolean has_free_busy_cleaned = FALSE;

	xn_categories = sipe_xml_parse(data, len);
	uri = sipe_xml_attribute(xn_categories, "uri"); /* with 'sip:' prefix */

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

					sipe_update_user_info(sipe_private, uri, ALIAS_PROP, display_name);
					sipe_update_user_info(sipe_private, uri, EMAIL_PROP, email);

					g_free(display_name);
					g_free(email);
				}
				/* company */
				node = sipe_xml_child(card, "company");
				if (node) {
					char* company = sipe_xml_data(node);
					sipe_update_user_info(sipe_private, uri, COMPANY_PROP, company);
					g_free(company);
				}
				/* department */
				node = sipe_xml_child(card, "department");
				if (node) {
					char* department = sipe_xml_data(node);
					sipe_update_user_info(sipe_private, uri, DEPARTMENT_PROP, department);
					g_free(department);
				}
				/* title */
				node = sipe_xml_child(card, "title");
				if (node) {
					char* title = sipe_xml_data(node);
					sipe_update_user_info(sipe_private, uri, TITLE_PROP, title);
					g_free(title);
				}
				/* office */
				node = sipe_xml_child(card, "office");
				if (node) {
					char* office = sipe_xml_data(node);
					sipe_update_user_info(sipe_private, uri, OFFICE_PROP, office);
					g_free(office);
				}
				/* site (url) */
				node = sipe_xml_child(card, "url");
				if (node) {
					char* site = sipe_xml_data(node);
					sipe_update_user_info(sipe_private, uri, SITE_PROP, site);
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

						sipe_update_user_info(sipe_private, uri, ADDRESS_STREET_PROP, street);
						sipe_update_user_info(sipe_private, uri, ADDRESS_CITY_PROP, city);
						sipe_update_user_info(sipe_private, uri, ADDRESS_STATE_PROP, state);
						sipe_update_user_info(sipe_private, uri, ADDRESS_ZIPCODE_PROP, zipcode);
						sipe_update_user_info(sipe_private, uri, ADDRESS_COUNTRYCODE_PROP, country_code);

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
			if (uri) {
				struct sipe_buddy *sbuddy = g_hash_table_lookup(sipe_private->buddies, uri);

				if (!has_note_cleaned) {
					has_note_cleaned = TRUE;

					g_free(sbuddy->note);
					sbuddy->note = NULL;
					sbuddy->is_oof_note = FALSE;
					sbuddy->note_since = publish_time;

					do_update_status = TRUE;
				}
				if (sbuddy && (publish_time >= sbuddy->note_since)) {
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
		}
		/* state */
		else if(sipe_strequal(attrVar, "state"))
		{
			char *tmp;
			int availability;
			const sipe_xml *xn_availability;
			const sipe_xml *xn_activity;
			const sipe_xml *xn_meeting_subject;
			const sipe_xml *xn_meeting_location;
			struct sipe_buddy *sbuddy = uri ? g_hash_table_lookup(sipe_private->buddies, uri) : NULL;

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

			/* activity, meeting_subject, meeting_location */
			if (sbuddy) {
				char *tmp = NULL;

				/* activity */
				g_free(sbuddy->activity);
				sbuddy->activity = NULL;
				if (xn_activity) {
					const char *token = sipe_xml_attribute(xn_activity, "token");
					const sipe_xml *xn_custom = sipe_xml_child(xn_activity, "custom");

					/* from token */
					if (!is_empty(token)) {
						sbuddy->activity = g_strdup(sipe_get_activity_desc_by_token(token));
					}
					/* from custom element */
					if (xn_custom) {
						char *custom = sipe_xml_data(xn_custom);

						if (!is_empty(custom)) {
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

				status = sipe_get_status_by_availability(availability, &tmp);
				if (sbuddy->activity && tmp) {
					char *tmp2 = sbuddy->activity;

					sbuddy->activity = g_strdup_printf("%s, %s", sbuddy->activity, tmp);
					g_free(tmp);
					g_free(tmp2);
				} else if (tmp) {
					sbuddy->activity = tmp;
				}
			}

			do_update_status = TRUE;
		}
		/* calendarData */
		else if(sipe_strequal(attrVar, "calendarData"))
		{
			struct sipe_buddy *sbuddy = uri ? g_hash_table_lookup(sipe_private->buddies, uri) : NULL;
			const sipe_xml *xn_free_busy = sipe_xml_child(xn_category, "calendarData/freeBusy");
			const sipe_xml *xn_working_hours = sipe_xml_child(xn_category, "calendarData/WorkingHours");

			if (sbuddy && xn_free_busy) {
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

			if (sbuddy && xn_working_hours) {
				sipe_cal_parse_working_hours(xn_working_hours, sbuddy);
			}
		}
	}

	if (do_update_status) {
		if (!status) { /* no status category in this update, using contact's current status */
			PurpleBuddy *pbuddy = purple_find_buddy((PurpleAccount *)sip->account, uri);
			const PurplePresence *presence = purple_buddy_get_presence(pbuddy);
			const PurpleStatus *pstatus = purple_presence_get_active_status(presence);
			status = purple_status_get_id(pstatus);
		}

		SIPE_DEBUG_INFO("process_incoming_notify_rlmi: %s", status);
		sipe_got_user_status(sipe_private, uri, status);
	}

	sipe_xml_free(xn_categories);
}

static void sipe_subscribe_poolfqdn_resource_uri(const char *host,
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

static void process_incoming_notify_pidf(struct sipe_core_private *sipe_private,
					 const gchar *data, unsigned len)
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

		sipe_update_user_info(sipe_private, uri, ALIAS_PROP, display_name);
		g_free(display_name);
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

	if (isonline) {
		const gchar * status_id = NULL;
		if (activity) {
			if (sipe_strequal(activity, sipe_activity_map[SIPE_ACTIVITY_BUSY].token)) {
				status_id = SIPE_STATUS_ID_BUSY;
			} else if (sipe_strequal(activity, sipe_activity_map[SIPE_ACTIVITY_AWAY].token)) {
				status_id = SIPE_STATUS_ID_AWAY;
			}
		}

		if (!status_id) {
			status_id = SIPE_STATUS_ID_AVAILABLE;
		}

		SIPE_DEBUG_INFO("process_incoming_notify_pidf: status_id(%s)", status_id);
		sipe_got_user_status(sipe_private, uri, status_id);
	} else {
		sipe_got_user_status(sipe_private, uri, SIPE_STATUS_ID_OFFLINE);
	}

	g_free(activity);
	g_free(uri);
	sipe_xml_free(pidf);
}

/** 2005 */
static void
sipe_user_info_has_updated(struct sipe_core_private *sipe_private,
			   const sipe_xml *xn_userinfo)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	const sipe_xml *xn_states;

	g_free(sip->user_states);
	sip->user_states = NULL;
	if ((xn_states = sipe_xml_child(xn_userinfo, "states")) != NULL) {
		gchar *orig = sip->user_states = sipe_xml_stringify(xn_states);

		/* this is a hack-around to remove added newline after inner element,
		 * state in this case, where it shouldn't be.
		 * After several use of sipe_xml_stringify, amount of added newlines
		 * grows significantly.
		 */
		if (orig) {
			gchar c, *stripped = orig;
			while ((c = *orig++)) {
				if ((c != '\n') /* && (c != '\r') */) {
					*stripped++ = c;
				}
			}
			*stripped = '\0';
		}
	}

	/* Publish initial state if not yet.
	 * Assuming this happens on initial responce to self subscription
	 * so we've already updated our UserInfo.
	 */
	if (!sip->initial_state_published) {
		send_presence_soap(sipe_private, FALSE);
		/* dalayed run */
		sipe_schedule_seconds(sipe_private,
				      "<+update-calendar>",
				      NULL,
				      UPDATE_CALENDAR_DELAY,
				      (sipe_schedule_action) sipe_core_update_calendar,
				      NULL);
	}
}

static void process_incoming_notify_msrtc(struct sipe_core_private *sipe_private,
					  const gchar *data, unsigned len)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
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
	char *free_activity;
	int user_avail;
	const char *user_avail_nil;
	int res_avail;
	time_t user_avail_since = 0;
	time_t activity_since = 0;

	/* fix for Reuters environment on Linux */
	if (data && strstr(data, "encoding=\"utf-16\"")) {
		char *tmp_data;
		tmp_data = replace(data, "encoding=\"utf-16\"", "encoding=\"utf-8\"");
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

	free_activity = NULL;

	name = sipe_xml_attribute(xn_presentity, "uri"); /* without 'sip:' prefix */
	uri = sip_uri_from_name(name);
	avl = sipe_xml_int_attribute(xn_availability, "aggregate", 0);
	epid = sipe_xml_attribute(xn_availability, "epid");
	act = sipe_xml_int_attribute(xn_activity, "aggregate", 0);

	status_id = sipe_get_status_by_act_avail_2005(act, avl, &activity);
	res_avail = sipe_get_availability_by_status(status_id, NULL);
	if (user_avail > res_avail) {
		res_avail = user_avail;
		status_id = sipe_get_status_by_availability(user_avail, NULL);
	}

	if (xn_display_name) {
		char *display_name = g_strdup(sipe_xml_attribute(xn_display_name, "displayName"));
		char *email        = xn_email ? g_strdup(sipe_xml_attribute(xn_email, "email")) : NULL;
		char *phone_label  = xn_phone_number ? g_strdup(sipe_xml_attribute(xn_phone_number, "label")) : NULL;
		char *phone_number = xn_phone_number ? g_strdup(sipe_xml_attribute(xn_phone_number, "number")) : NULL;
		char *tel_uri      = sip_to_tel_uri(phone_number);

		sipe_update_user_info(sipe_private, uri, ALIAS_PROP, display_name);
		sipe_update_user_info(sipe_private, uri, EMAIL_PROP, email);
		sipe_update_user_info(sipe_private, uri, PHONE_PROP, tel_uri);
		sipe_update_user_info(sipe_private, uri, PHONE_DISPLAY_PROP, !is_empty(phone_label) ? phone_label : phone_number);

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
				res_avail = dev_avail;
				if (!is_empty(state))
				{
					if (sipe_strequal(state, sipe_activity_map[SIPE_ACTIVITY_ON_PHONE].token)) {
						g_free(activity);
						activity = g_strdup(SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_ON_PHONE));
					} else if (sipe_strequal(state, "presenting")) {
						g_free(activity);
						activity = g_strdup(SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_IN_CONF));
					} else {
						activity = state;
						state = NULL;
					}
					activity_since = dev_avail_since;
				}
				status_id = sipe_get_status_by_availability(res_avail, &activity);
			}
			g_free(state);
		}
	}

	/* oof */
	if (xn_oof && res_avail >= 15000) { /* 12000 in 2007 */
		g_free(activity);
		activity = g_strdup(SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_OOF));
		activity_since = 0;
	}

	sbuddy = g_hash_table_lookup(sipe_private->buddies, uri);
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
			if (!sipe_strequal(sbuddy->note, sip->note)) /* not same */
			{
				sip->is_oof_note = sbuddy->is_oof_note;

				g_free(sip->note);
				sip->note = g_strdup(sbuddy->note);

				sip->note_since = time(NULL);
			}

			g_free(sip->status);
			sip->status = g_strdup(sbuddy->last_non_cal_status_id);
		}
	}
	g_free(cal_free_busy_base64);
	g_free(activity);

	SIPE_DEBUG_INFO("process_incoming_notify_msrtc: status(%s)", status_id);
	sipe_got_user_status(sipe_private, uri, status_id);

	if (!SIPE_CORE_PRIVATE_FLAG_IS(OCS2007) && sipe_strcase_equal(self_uri, uri)) {
		sipe_user_info_has_updated(sipe_private, xn_userinfo);
	}

	g_free(note);
	sipe_xml_free(xn_presentity);
	g_free(uri);
	g_free(self_uri);
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
					  struct sipmsg *msg, gchar *who,
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

		if (buddies) {
			struct presence_batched_routed *payload = g_malloc(sizeof(struct presence_batched_routed));
			payload->host    = g_strdup(who);
			payload->buddies = buddies;
			sipe_schedule_seconds(sipe_private,
					      action_name,
					      payload,
					      timeout,
					      sipe_subscribe_presence_batched_routed,
					      sipe_subscribe_presence_batched_routed_free);
			SIPE_DEBUG_INFO("Resubscription multiple contacts with batched support & route(%s) in %d", who, timeout);
		}

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
	char *tmp;

	SIPE_DEBUG_INFO("process_incoming_notify: Event: %s\n\n%s",
			event ? event : "",
			tmp = fix_newlines(msg->body));
	g_free(tmp);
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
				sipe_process_roaming_self(sipe_private, msg);
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

/**
 * Whether user manually changed status or
 * it was changed automatically due to user
 * became inactive/active again
 */
static gboolean
sipe_is_user_state(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	gboolean res;
	time_t now = time(NULL);

	SIPE_DEBUG_INFO("sipe_is_user_state: sip->idle_switch : %s", asctime(localtime(&(sip->idle_switch))));
	SIPE_DEBUG_INFO("sipe_is_user_state: now              : %s", asctime(localtime(&now)));

	res = ((now - SIPE_IDLE_SET_DELAY * 2) >= sip->idle_switch);

	SIPE_DEBUG_INFO("sipe_is_user_state: res  = %s", res ? "USER" : "MACHINE");
	return res;
}

static void
send_presence_soap0(struct sipe_core_private *sipe_private,
		    gboolean do_publish_calendar,
		    gboolean do_reset_status)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	struct sipe_calendar* cal = sip->cal;
	int availability = 0;
	int activity = 0;
	gchar *body;
	gchar *tmp;
	gchar *tmp2 = NULL;
	gchar *res_note = NULL;
	gchar *res_oof = NULL;
	const gchar *note_pub = NULL;
	gchar *states = NULL;
	gchar *calendar_data = NULL;
	gchar *epid = get_epid(sipe_private);
	time_t now = time(NULL);
	gchar *since_time_str = sipe_utils_time_to_str(now);
	const gchar *oof_note = cal ? sipe_ews_get_oof_note(cal) : NULL;
	const char *user_input;
	gboolean pub_oof = cal && oof_note && (!sip->note || cal->updated > sip->note_since);

	if (oof_note && sip->note) {
		SIPE_DEBUG_INFO("cal->oof_start  : %s", asctime(localtime(&(cal->oof_start))));
		SIPE_DEBUG_INFO("sip->note_since : %s", asctime(localtime(&(sip->note_since))));
	}

	SIPE_DEBUG_INFO("sip->note  : %s", sip->note ? sip->note : "");

	if (!sip->initial_state_published ||
	    do_reset_status)
	{
		g_free(sip->status);
		sip->status = g_strdup(SIPE_STATUS_ID_AVAILABLE);
	}

	sipe_get_act_avail_by_status_2005(sip->status, &activity, &availability);

	/* Note */
	if (pub_oof) {
		note_pub = oof_note;
		res_oof = SIPE_SOAP_SET_PRESENCE_OOF_XML;
		cal->published = TRUE;
	} else if (sip->note) {
		if (sip->is_oof_note && !oof_note) { /* stale OOF note, as it's not present in cal already */
			g_free(sip->note);
			sip->note = NULL;
			sip->is_oof_note = FALSE;
			sip->note_since = 0;
		} else {
			note_pub = sip->note;
			res_oof = sip->is_oof_note ? SIPE_SOAP_SET_PRESENCE_OOF_XML : "";
		}
	}

	if (note_pub)
	{
		/* to protocol internal plain text format */
		tmp = sipe_backend_markup_strip_html(note_pub);
		res_note = g_markup_printf_escaped(SIPE_SOAP_SET_PRESENCE_NOTE_XML, tmp);
		g_free(tmp);
	}

	/* User State */
	if (!do_reset_status) {
		if (sipe_is_user_state(sipe_private) && !do_publish_calendar && sip->initial_state_published)
		{
			gchar *activity_token = NULL;
			int avail_2007 = sipe_get_availability_by_status(sip->status, &activity_token);

			states = g_strdup_printf(SIPE_SOAP_SET_PRESENCE_STATES,
						avail_2007,
						since_time_str,
						epid,
						activity_token);
			g_free(activity_token);
		}
		else /* preserve existing publication */
		{
			if (sip->user_states) {
				states = g_strdup(sip->user_states);
			}
		}
	} else {
		/* do nothing - then User state will be erased */
	}
	sip->initial_state_published = TRUE;

	/* CalendarInfo */
	if (cal && (!is_empty(cal->legacy_dn) || !is_empty(cal->email)) && cal->fb_start && !is_empty(cal->free_busy))
	{
		char *fb_start_str = sipe_utils_time_to_str(cal->fb_start);
		char *free_busy_base64 = sipe_cal_get_freebusy_base64(cal->free_busy);
		calendar_data = g_strdup_printf(SIPE_SOAP_SET_PRESENCE_CALENDAR,
						!is_empty(cal->legacy_dn) ? cal->legacy_dn : cal->email,
						fb_start_str,
						free_busy_base64);
		g_free(fb_start_str);
		g_free(free_busy_base64);
	}

	user_input = !sipe_is_user_state(sipe_private) && sip->status != SIPE_STATUS_ID_AVAILABLE ? "idle" : "active";

	/* forming resulting XML */
	body = g_strdup_printf(SIPE_SOAP_SET_PRESENCE,
			       sipe_private->username,
			       availability,
			       activity,
			       (tmp = g_ascii_strup(g_get_host_name(), -1)),
			       res_note ? res_note : "",
			       res_oof ? res_oof : "",
			       states ? states : "",
			       calendar_data ? calendar_data : "",
			       epid,
			       since_time_str,
			       since_time_str,
			       user_input);
	g_free(tmp);
	g_free(tmp2);
	g_free(res_note);
	g_free(states);
	g_free(calendar_data);

	send_soap_request(sipe_private, body);

	g_free(body);
	g_free(since_time_str);
	g_free(epid);
}

void
send_presence_soap(struct sipe_core_private *sipe_private,
		   gboolean do_publish_calendar)
{
	return send_presence_soap0(sipe_private, do_publish_calendar, FALSE);
}


static gboolean
process_send_presence_category_publish_response(struct sipe_core_private *sipe_private,
						struct sipmsg *msg,
						struct transaction *trans)
{
	const gchar *contenttype = sipmsg_find_header(msg, "Content-Type");

	if (msg->response == 409 && g_str_has_prefix(contenttype, "application/msrtc-fault+xml")) {
		sipe_xml *xml;
		const sipe_xml *node;
		gchar *fault_code;
		GHashTable *faults;
		int index_our;
		gboolean has_device_publication = FALSE;

		xml = sipe_xml_parse(msg->body, msg->bodylen);

		/* test if version mismatch fault */
		fault_code = sipe_xml_data(sipe_xml_child(xml, "Faultcode"));
		if (!sipe_strequal(fault_code, "Client.BadCall.WrongDelta")) {
			SIPE_DEBUG_INFO("process_send_presence_category_publish_response: unsupported fault code:%s returning.", fault_code);
			g_free(fault_code);
			sipe_xml_free(xml);
			return TRUE;
		}
		g_free(fault_code);

		/* accumulating information about faulty versions */
		faults = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
		for (node = sipe_xml_child(xml, "details/operation");
		     node;
		     node = sipe_xml_twin(node))
		{
			const gchar *index = sipe_xml_attribute(node, "index");
			const gchar *curVersion = sipe_xml_attribute(node, "curVersion");

			g_hash_table_insert(faults, g_strdup(index), g_strdup(curVersion));
			SIPE_DEBUG_INFO("fault added: index:%s curVersion:%s", index, curVersion);
		}
		sipe_xml_free(xml);

		/* here we are parsing own request to figure out what publication
		 * referensed here only by index went wrong
		 */
		xml = sipe_xml_parse(trans->msg->body, trans->msg->bodylen);

		/* publication */
		for (node = sipe_xml_child(xml, "publications/publication"),
		     index_our = 1; /* starts with 1 - our first publication */
		     node;
		     node = sipe_xml_twin(node), index_our++)
		{
			gchar *idx = g_strdup_printf("%d", index_our);
			const gchar *curVersion = g_hash_table_lookup(faults, idx);
			const gchar *categoryName = sipe_xml_attribute(node, "categoryName");
			g_free(idx);

			if (sipe_strequal("device", categoryName)) {
				has_device_publication = TRUE;
			}

			if (curVersion) { /* fault exist on this index */
				struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
				const gchar *container = sipe_xml_attribute(node, "container");
				const gchar *instance = sipe_xml_attribute(node, "instance");
				/* key is <category><instance><container> */
				gchar *key = g_strdup_printf("<%s><%s><%s>", categoryName, instance, container);
				GHashTable *category = g_hash_table_lookup(sip->our_publications, categoryName);

				if (category) {
					struct sipe_publication *publication =
						g_hash_table_lookup(category, key);

					SIPE_DEBUG_INFO("key is %s", key);

					if (publication) {
						SIPE_DEBUG_INFO("Updating %s with version %s. Was %d before.",
								key, curVersion, publication->version);
						/* updating publication's version to the correct one */
						publication->version = atoi(curVersion);
					}
				} else {
					/* We somehow lost this category from our publications... */
					struct sipe_publication *publication = g_new0(struct sipe_publication, 1);
					publication->category  = g_strdup(categoryName);
					publication->instance  = atoi(instance);
					publication->container = atoi(container);
					publication->version   = atoi(curVersion);
					category = g_hash_table_new_full(g_str_hash, g_str_equal,
									 g_free, (GDestroyNotify)free_publication);
					g_hash_table_insert(category, g_strdup(key), publication);
					g_hash_table_insert(sip->our_publications, g_strdup(categoryName), category);
					SIPE_DEBUG_INFO("added lost category '%s' key '%s'", categoryName, key);
				}
				g_free(key);
			}
		}
		sipe_xml_free(xml);
		g_hash_table_destroy(faults);

		/* rebublishing with right versions */
		if (has_device_publication) {
			send_publish_category_initial(sipe_private);
		} else {
			send_presence_status(sipe_private, NULL);
		}
	}
	return TRUE;
}

/**
 * Returns 'device' XML part for publication.
 * Must be g_free'd after use.
 */
static gchar *
sipe_publish_get_category_device(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	gchar *uri;
	gchar *doc;
	gchar *epid = get_epid(sipe_private);
	gchar *uuid = generateUUIDfromEPID(epid);
	guint device_instance = sipe_get_pub_instance(sipe_private, SIPE_PUB_DEVICE);
	/* key is <category><instance><container> */
	gchar *key = g_strdup_printf("<%s><%u><%u>", "device", device_instance, 2);
	struct sipe_publication *publication =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "device"), key);

	g_free(key);
	g_free(epid);

	uri = sip_uri_self(sipe_private);
	doc = g_strdup_printf(SIPE_PUB_XML_DEVICE,
		device_instance,
		publication ? publication->version : 0,
		uuid,
		uri,
		"00:00:00+01:00", /* @TODO make timezone real*/
		g_get_host_name()
	);

	g_free(uri);
	g_free(uuid);

	return doc;
}

/**
 * A service method - use
 * - send_publish_get_category_state_machine and
 * - send_publish_get_category_state_user instead.
 * Must be g_free'd after use.
 */
static gchar *
sipe_publish_get_category_state(struct sipe_core_private *sipe_private,
				gboolean is_user_state)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	int availability = sipe_get_availability_by_status(sip->status, NULL);
	guint instance = is_user_state ? sipe_get_pub_instance(sipe_private, SIPE_PUB_STATE_USER) :
					 sipe_get_pub_instance(sipe_private, SIPE_PUB_STATE_MACHINE);
	/* key is <category><instance><container> */
	gchar *key_2 = g_strdup_printf("<%s><%u><%u>", "state", instance, 2);
	gchar *key_3 = g_strdup_printf("<%s><%u><%u>", "state", instance, 3);
	struct sipe_publication *publication_2 =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "state"), key_2);
	struct sipe_publication *publication_3 =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "state"), key_3);

	g_free(key_2);
	g_free(key_3);

	if (publication_2 && (publication_2->availability == availability))
	{
		SIPE_DEBUG_INFO_NOFORMAT("sipe_publish_get_category_state: state has NOT changed. Exiting.");
		return NULL; /* nothing to update */
	}

	return g_strdup_printf( is_user_state ? SIPE_PUB_XML_STATE_USER : SIPE_PUB_XML_STATE_MACHINE,
				instance,
				publication_2 ? publication_2->version : 0,
				availability,
				instance,
				publication_3 ? publication_3->version : 0,
				availability);
}

/**
 * Only Busy and OOF calendar event are published.
 * Different instances are used for that.
 *
 * Must be g_free'd after use.
 */
static gchar *
sipe_publish_get_category_state_calendar(struct sipe_core_private *sipe_private,
					 struct sipe_cal_event *event,
					 const char *uri,
					 int cal_satus)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	gchar *start_time_str;
	int availability = 0;
	gchar *res;
	gchar *tmp = NULL;
	guint instance = (cal_satus == SIPE_CAL_OOF) ?
		sipe_get_pub_instance(sipe_private, SIPE_PUB_STATE_CALENDAR_OOF) :
		sipe_get_pub_instance(sipe_private, SIPE_PUB_STATE_CALENDAR);

	/* key is <category><instance><container> */
	gchar *key_2 = g_strdup_printf("<%s><%u><%u>", "state", instance, 2);
	gchar *key_3 = g_strdup_printf("<%s><%u><%u>", "state", instance, 3);
	struct sipe_publication *publication_2 =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "state"), key_2);
	struct sipe_publication *publication_3 =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "state"), key_3);

	g_free(key_2);
	g_free(key_3);

	if (!publication_3 && !event) { /* was nothing, have nothing, exiting */
		SIPE_DEBUG_INFO("sipe_publish_get_category_state_calendar: "
				"Exiting as no publication and no event for cal_satus:%d", cal_satus);
		return NULL;
	}

	if (event &&
	    publication_3 &&
	    (publication_3->availability == availability) &&
	    sipe_strequal(publication_3->cal_event_hash, (tmp = sipe_cal_event_hash(event))))
	{
		g_free(tmp);
		SIPE_DEBUG_INFO("sipe_publish_get_category_state_calendar: "
				"cal state has NOT changed for cal_satus:%d. Exiting.", cal_satus);
		return NULL; /* nothing to update */
	}
	g_free(tmp);

	if (event &&
	    (event->cal_status == SIPE_CAL_BUSY ||
	     event->cal_status == SIPE_CAL_OOF))
	{
		gchar *availability_xml_str = NULL;
		gchar *activity_xml_str = NULL;

		if (event->cal_status == SIPE_CAL_BUSY) {
			availability_xml_str = g_strdup_printf(SIPE_PUB_XML_STATE_CALENDAR_AVAIL, 6500);
		}

		if (event->cal_status == SIPE_CAL_BUSY && event->is_meeting) {
			activity_xml_str = g_strdup_printf(SIPE_PUB_XML_STATE_CALENDAR_ACTIVITY,
							   sipe_activity_map[SIPE_ACTIVITY_IN_MEETING].token,
							   "minAvailability=\"6500\"",
							   "maxAvailability=\"8999\"");
		} else if (event->cal_status == SIPE_CAL_OOF) {
			activity_xml_str = g_strdup_printf(SIPE_PUB_XML_STATE_CALENDAR_ACTIVITY,
							   sipe_activity_map[SIPE_ACTIVITY_OOF].token,
							   "minAvailability=\"12000\"",
							   "");
		}
		start_time_str = sipe_utils_time_to_str(event->start_time);

		res = g_strdup_printf(SIPE_PUB_XML_STATE_CALENDAR,
					instance,
					publication_2 ? publication_2->version : 0,
					uri,
					start_time_str,
					availability_xml_str ? availability_xml_str : "",
					activity_xml_str ? activity_xml_str : "",
					event->subject ? event->subject : "",
					event->location ? event->location : "",

					instance,
					publication_3 ? publication_3->version : 0,
					uri,
					start_time_str,
					availability_xml_str ? availability_xml_str : "",
					activity_xml_str ? activity_xml_str : "",
					event->subject ? event->subject : "",
					event->location ? event->location : ""
					);
		g_free(start_time_str);
		g_free(availability_xml_str);
		g_free(activity_xml_str);

	}
	else /* including !event, SIPE_CAL_FREE, SIPE_CAL_TENTATIVE */
	{
		res = g_strdup_printf(SIPE_PUB_XML_STATE_CALENDAR_CLEAR,
					instance,
					publication_2 ? publication_2->version : 0,

					instance,
					publication_3 ? publication_3->version : 0
					);
	}

	return res;
}

/**
 * Returns 'machineState' XML part for publication.
 * Must be g_free'd after use.
 */
static gchar *
sipe_publish_get_category_state_machine(struct sipe_core_private *sipe_private)
{
	return sipe_publish_get_category_state(sipe_private, FALSE);
}

/**
 * Returns 'userState' XML part for publication.
 * Must be g_free'd after use.
 */
static gchar *
sipe_publish_get_category_state_user(struct sipe_core_private *sipe_private)
{
	return sipe_publish_get_category_state(sipe_private, TRUE);
}

/**
 * Returns 'note' XML part for publication.
 * Must be g_free'd after use.
 *
 * Protocol format for Note is plain text.
 *
 * @param note a note in Sipe internal HTML format
 * @param note_type either personal or OOF
 */
static gchar *
sipe_publish_get_category_note(struct sipe_core_private *sipe_private,
			       const char *note, /* html */
			       const char *note_type,
			       time_t note_start,
			       time_t note_end)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	guint instance = sipe_strequal("OOF", note_type) ? sipe_get_pub_instance(sipe_private, SIPE_PUB_NOTE_OOF) : 0;
	/* key is <category><instance><container> */
	gchar *key_note_200 = g_strdup_printf("<%s><%u><%u>", "note", instance, 200);
	gchar *key_note_300 = g_strdup_printf("<%s><%u><%u>", "note", instance, 300);
	gchar *key_note_400 = g_strdup_printf("<%s><%u><%u>", "note", instance, 400);

	struct sipe_publication *publication_note_200 =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "note"), key_note_200);
	struct sipe_publication *publication_note_300 =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "note"), key_note_300);
	struct sipe_publication *publication_note_400 =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "note"), key_note_400);

	char *tmp = note ? sipe_backend_markup_strip_html(note) : NULL;
	char *n1 = tmp ? g_markup_escape_text(tmp, -1) : NULL;
	const char *n2 = publication_note_200 ? publication_note_200->note : NULL;
	char *res, *tmp1, *tmp2, *tmp3;
	char *start_time_attr;
	char *end_time_attr;

	g_free(tmp);
	tmp = NULL;
	g_free(key_note_200);
	g_free(key_note_300);
	g_free(key_note_400);

	/* we even need to republish empty note */
	if (sipe_strequal(n1, n2))
	{
		SIPE_DEBUG_INFO_NOFORMAT("sipe_publish_get_category_note: note has NOT changed. Exiting.");
		g_free(n1);
		return NULL; /* nothing to update */
	}

	start_time_attr = note_start ? g_strdup_printf(" startTime=\"%s\"", (tmp = sipe_utils_time_to_str(note_start))) : NULL;
	g_free(tmp);
	tmp = NULL;
	end_time_attr = note_end ? g_strdup_printf(" endTime=\"%s\"", (tmp = sipe_utils_time_to_str(note_end))) : NULL;
	g_free(tmp);

	if (n1) {
		tmp1 = g_strdup_printf(SIPE_PUB_XML_NOTE,
				       instance,
				       200,
				       publication_note_200 ? publication_note_200->version : 0,
				       note_type,
				       start_time_attr ? start_time_attr : "",
				       end_time_attr ? end_time_attr : "",
				       n1);

		tmp2 = g_strdup_printf(SIPE_PUB_XML_NOTE,
				       instance,
				       300,
				       publication_note_300 ? publication_note_300->version : 0,
				       note_type,
				       start_time_attr ? start_time_attr : "",
				       end_time_attr ? end_time_attr : "",
				       n1);

		tmp3 = g_strdup_printf(SIPE_PUB_XML_NOTE,
				       instance,
				       400,
				       publication_note_400 ? publication_note_400->version : 0,
				       note_type,
				       start_time_attr ? start_time_attr : "",
				       end_time_attr ? end_time_attr : "",
				       n1);
	} else {
		tmp1 = g_strdup_printf( SIPE_PUB_XML_PUBLICATION_CLEAR,
					"note",
					instance,
					200,
					publication_note_200 ? publication_note_200->version : 0,
					"static");
		tmp2 = g_strdup_printf( SIPE_PUB_XML_PUBLICATION_CLEAR,
					"note",
					instance,
					300,
					publication_note_200 ? publication_note_200->version : 0,
					"static");
		tmp3 = g_strdup_printf( SIPE_PUB_XML_PUBLICATION_CLEAR,
					"note",
					instance,
					400,
					publication_note_200 ? publication_note_200->version : 0,
					"static");
	}
	res =  g_strconcat(tmp1, tmp2, tmp3, NULL);

	g_free(start_time_attr);
	g_free(end_time_attr);
	g_free(tmp1);
	g_free(tmp2);
	g_free(tmp3);
	g_free(n1);

	return res;
}

/**
 * Returns 'calendarData' XML part with WorkingHours for publication.
 * Must be g_free'd after use.
 */
static gchar *
sipe_publish_get_category_cal_working_hours(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	struct sipe_calendar* cal = sip->cal;

	/* key is <category><instance><container> */
	gchar *key_cal_1     = g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 1);
	gchar *key_cal_100   = g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 100);
	gchar *key_cal_200   = g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 200);
	gchar *key_cal_300   = g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 300);
	gchar *key_cal_400   = g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 400);
	gchar *key_cal_32000 = g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 32000);

	struct sipe_publication *publication_cal_1 =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "calendarData"), key_cal_1);
	struct sipe_publication *publication_cal_100 =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "calendarData"), key_cal_100);
	struct sipe_publication *publication_cal_200 =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "calendarData"), key_cal_200);
	struct sipe_publication *publication_cal_300 =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "calendarData"), key_cal_300);
	struct sipe_publication *publication_cal_400 =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "calendarData"), key_cal_400);
	struct sipe_publication *publication_cal_32000 =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "calendarData"), key_cal_32000);

	const char *n1 = cal ? cal->working_hours_xml_str : NULL;
	const char *n2 = publication_cal_300 ? publication_cal_300->working_hours_xml_str : NULL;

	g_free(key_cal_1);
	g_free(key_cal_100);
	g_free(key_cal_200);
	g_free(key_cal_300);
	g_free(key_cal_400);
	g_free(key_cal_32000);

	if (!cal || is_empty(cal->email) || is_empty(cal->working_hours_xml_str)) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_publish_get_category_cal_working_hours: no data to publish, exiting");
		return NULL;
	}

	if (sipe_strequal(n1, n2))
	{
		SIPE_DEBUG_INFO_NOFORMAT("sipe_publish_get_category_cal_working_hours: WorkingHours has NOT changed. Exiting.");
		return NULL; /* nothing to update */
	}

	return g_strdup_printf(SIPE_PUB_XML_WORKING_HOURS,
				/* 1 */
				publication_cal_1 ? publication_cal_1->version : 0,
				cal->email,
				cal->working_hours_xml_str,
				/* 100 - Public */
				publication_cal_100 ? publication_cal_100->version : 0,
				/* 200 - Company */
				publication_cal_200 ? publication_cal_200->version : 0,
				cal->email,
				cal->working_hours_xml_str,
				/* 300 - Team */
				publication_cal_300 ? publication_cal_300->version : 0,
				cal->email,
				cal->working_hours_xml_str,
				/* 400 - Personal */
				publication_cal_400 ? publication_cal_400->version : 0,
				cal->email,
				cal->working_hours_xml_str,
				/* 32000 - Blocked */
				publication_cal_32000 ? publication_cal_32000->version : 0
			      );
}

/**
 * Returns 'calendarData' XML part with FreeBusy for publication.
 * Must be g_free'd after use.
 */
static gchar *
sipe_publish_get_category_cal_free_busy(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	struct sipe_calendar* cal = sip->cal;
	guint cal_data_instance = sipe_get_pub_instance(sipe_private, SIPE_PUB_CALENDAR_DATA);
	char *fb_start_str;
	char *free_busy_base64;
	const char *st;
	const char *fb;
	char *res;

	/* key is <category><instance><container> */
	gchar *key_cal_1     = g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 1);
	gchar *key_cal_100   = g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 100);
	gchar *key_cal_200   = g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 200);
	gchar *key_cal_300   = g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 300);
	gchar *key_cal_400   = g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 400);
	gchar *key_cal_32000 = g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 32000);

	struct sipe_publication *publication_cal_1 =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "calendarData"), key_cal_1);
	struct sipe_publication *publication_cal_100 =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "calendarData"), key_cal_100);
	struct sipe_publication *publication_cal_200 =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "calendarData"), key_cal_200);
	struct sipe_publication *publication_cal_300 =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "calendarData"), key_cal_300);
	struct sipe_publication *publication_cal_400 =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "calendarData"), key_cal_400);
	struct sipe_publication *publication_cal_32000 =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "calendarData"), key_cal_32000);

	g_free(key_cal_1);
	g_free(key_cal_100);
	g_free(key_cal_200);
	g_free(key_cal_300);
	g_free(key_cal_400);
	g_free(key_cal_32000);

	if (!cal || is_empty(cal->email) || !cal->fb_start || is_empty(cal->free_busy)) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_publish_get_category_cal_free_busy: no data to publish, exiting");
		return NULL;
	}

	fb_start_str = sipe_utils_time_to_str(cal->fb_start);
	free_busy_base64 = sipe_cal_get_freebusy_base64(cal->free_busy);

	st = publication_cal_300 ? publication_cal_300->fb_start_str : NULL;
	fb = publication_cal_300 ? publication_cal_300->free_busy_base64 : NULL;

	/* we will rebuplish the same data to refresh publication time,
	 * so if data from multiple sources, most recent will be choosen
	 */
	//if (sipe_strequal(st, fb_start_str) && sipe_strequal(fb, free_busy_base64))
	//{
	//	SIPE_DEBUG_INFO_NOFORMAT("sipe_publish_get_category_cal_free_busy: FreeBusy has NOT changed. Exiting.");
	//	g_free(fb_start_str);
	//	g_free(free_busy_base64);
	//	return NULL; /* nothing to update */
	//}

	res = g_strdup_printf(SIPE_PUB_XML_FREE_BUSY,
				/* 1 */
				cal_data_instance,
				publication_cal_1 ? publication_cal_1->version : 0,
				/* 100 - Public */
				cal_data_instance,
				publication_cal_100 ? publication_cal_100->version : 0,
				/* 200 - Company */
				cal_data_instance,
				publication_cal_200 ? publication_cal_200->version : 0,
				cal->email,
				fb_start_str,
				free_busy_base64,
				/* 300 - Team */
				cal_data_instance,
				publication_cal_300 ? publication_cal_300->version : 0,
				cal->email,
				fb_start_str,
				free_busy_base64,
				/* 400 - Personal */
				cal_data_instance,
				publication_cal_400 ? publication_cal_400->version : 0,
				cal->email,
				fb_start_str,
				free_busy_base64,
				/* 32000 - Blocked */
				cal_data_instance,
				publication_cal_32000 ? publication_cal_32000->version : 0
			     );

	g_free(fb_start_str);
	g_free(free_busy_base64);
	return res;
}

static void send_presence_publish(struct sipe_core_private *sipe_private,
				  const char *publications)
{
	gchar *uri;
	gchar *doc;
	gchar *tmp;
	gchar *hdr;

	uri = sip_uri_self(sipe_private);
	doc = g_strdup_printf(SIPE_SEND_PRESENCE,
		uri,
		publications);

	tmp = get_contact(sipe_private);
	hdr = g_strdup_printf("Contact: %s\r\n"
		"Content-Type: application/msrtc-category-publish+xml\r\n", tmp);

	sip_transport_service(sipe_private,
			      uri,
			      hdr,
			      doc,
			      process_send_presence_category_publish_response);

	g_free(tmp);
	g_free(hdr);
	g_free(uri);
	g_free(doc);
}

static void
send_publish_category_initial(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	gchar *pub_device   = sipe_publish_get_category_device(sipe_private);
	gchar *pub_machine;
	gchar *publications;

	g_free(sip->status);
	sip->status = g_strdup(SIPE_STATUS_ID_AVAILABLE); /* our initial state */

	pub_machine  = sipe_publish_get_category_state_machine(sipe_private);
	publications = g_strdup_printf("%s%s",
				       pub_device,
				       pub_machine ? pub_machine : "");
	g_free(pub_device);
	g_free(pub_machine);

	send_presence_publish(sipe_private, publications);
	g_free(publications);
}

static void
send_presence_category_publish(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	gchar *pub_state = sipe_is_user_state(sipe_private) ?
				sipe_publish_get_category_state_user(sipe_private) :
				sipe_publish_get_category_state_machine(sipe_private);
	gchar *pub_note = sipe_publish_get_category_note(sipe_private,
							 sip->note,
							 sip->is_oof_note ? "OOF" : "personal",
							 0,
							 0);
	gchar *publications;

	if (!pub_state && !pub_note) {
		SIPE_DEBUG_INFO_NOFORMAT("send_presence_category_publish: nothing has changed. Exiting.");
		return;
	}

	publications = g_strdup_printf("%s%s",
				       pub_state ? pub_state : "",
				       pub_note ? pub_note : "");

	g_free(pub_state);
	g_free(pub_note);

	send_presence_publish(sipe_private, publications);
	g_free(publications);
}

/**
 * Publishes self status
 * based on own calendar information.
 *
 * For 2007+
 */
void
publish_calendar_status_self(struct sipe_core_private *sipe_private,
			     SIPE_UNUSED_PARAMETER void *unused)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	struct sipe_cal_event* event = NULL;
	gchar *pub_cal_working_hours = NULL;
	gchar *pub_cal_free_busy = NULL;
	gchar *pub_calendar = NULL;
	gchar *pub_calendar2 = NULL;
	gchar *pub_oof_note = NULL;
	const gchar *oof_note;
	time_t oof_start = 0;
	time_t oof_end = 0;

	if (!sip->cal) {
		SIPE_DEBUG_INFO_NOFORMAT("publish_calendar_status_self() no calendar data.");
		return;
	}

	SIPE_DEBUG_INFO_NOFORMAT("publish_calendar_status_self() started.");
	if (sip->cal->cal_events) {
		event = sipe_cal_get_event(sip->cal->cal_events, time(NULL));
	}

	if (!event) {
		SIPE_DEBUG_INFO_NOFORMAT("publish_calendar_status_self: current event is NULL");
	} else {
		char *desc = sipe_cal_event_describe(event);
		SIPE_DEBUG_INFO("publish_calendar_status_self: current event is:\n%s", desc ? desc : "");
		g_free(desc);
	}

	/* Logic
	if OOF
		OOF publish, Busy clean
	ilse if Busy
		OOF clean, Busy publish
	else
		OOF clean, Busy clean
	*/
	if (event && event->cal_status == SIPE_CAL_OOF) {
		pub_calendar  = sipe_publish_get_category_state_calendar(sipe_private, event, sip->cal->email, SIPE_CAL_OOF);
		pub_calendar2 = sipe_publish_get_category_state_calendar(sipe_private, NULL,  sip->cal->email, SIPE_CAL_BUSY);
	} else if (event && event->cal_status == SIPE_CAL_BUSY) {
		pub_calendar  = sipe_publish_get_category_state_calendar(sipe_private, NULL,  sip->cal->email, SIPE_CAL_OOF);
		pub_calendar2 = sipe_publish_get_category_state_calendar(sipe_private, event, sip->cal->email, SIPE_CAL_BUSY);
	} else {
		pub_calendar  = sipe_publish_get_category_state_calendar(sipe_private, NULL,  sip->cal->email, SIPE_CAL_OOF);
		pub_calendar2 = sipe_publish_get_category_state_calendar(sipe_private, NULL,  sip->cal->email, SIPE_CAL_BUSY);
	}

	oof_note = sipe_ews_get_oof_note(sip->cal);
	if (sipe_strequal("Scheduled", sip->cal->oof_state)) {
		oof_start = sip->cal->oof_start;
		oof_end = sip->cal->oof_end;
	}
	pub_oof_note = sipe_publish_get_category_note(sipe_private, oof_note, "OOF", oof_start, oof_end);

	pub_cal_working_hours = sipe_publish_get_category_cal_working_hours(sipe_private);
	pub_cal_free_busy = sipe_publish_get_category_cal_free_busy(sipe_private);

	if (!pub_cal_working_hours && !pub_cal_free_busy && !pub_calendar && !pub_calendar2 && !pub_oof_note) {
		SIPE_DEBUG_INFO_NOFORMAT("publish_calendar_status_self: nothing has changed.");
	} else {
		gchar *publications = g_strdup_printf("%s%s%s%s%s",
				       pub_cal_working_hours ? pub_cal_working_hours : "",
				       pub_cal_free_busy ? pub_cal_free_busy : "",
				       pub_calendar ? pub_calendar : "",
				       pub_calendar2 ? pub_calendar2 : "",
				       pub_oof_note ? pub_oof_note : "");

		send_presence_publish(sipe_private, publications);
		g_free(publications);
	}

	g_free(pub_cal_working_hours);
	g_free(pub_cal_free_busy);
	g_free(pub_calendar);
	g_free(pub_calendar2);
	g_free(pub_oof_note);

	/* repeat scheduling */
	sipe_sched_calendar_status_self_publish(sipe_private, time(NULL));
}

static void send_presence_status(struct sipe_core_private *sipe_private,
				 SIPE_UNUSED_PARAMETER void *unused)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	PurpleStatus * status = purple_account_get_active_status(sip->account);

	if (!status) return;

	SIPE_DEBUG_INFO("send_presence_status: status: %s (%s)",
			purple_status_get_id(status) ? purple_status_get_id(status) : "",
			sipe_is_user_state(sipe_private) ? "USER" : "MACHINE");

        if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		send_presence_category_publish(sipe_private);
	} else {
		send_presence_soap(sipe_private, FALSE);
	}
}

static guint sipe_ht_hash_nick(const char *nick)
{
	char *lc = g_utf8_strdown(nick, -1);
	guint bucket = g_str_hash(lc);
	g_free(lc);

	return bucket;
}

static gboolean sipe_ht_equals_nick(const char *nick1, const char *nick2)
{
	char *nick1_norm = NULL;
	char *nick2_norm = NULL;
	gboolean equal;

	if (nick1 == NULL && nick2 == NULL) return TRUE;
	if (nick1 == NULL || nick2 == NULL    ||
	    !g_utf8_validate(nick1, -1, NULL) ||
	    !g_utf8_validate(nick2, -1, NULL)) return FALSE;

	nick1_norm = g_utf8_casefold(nick1, -1);
	nick2_norm = g_utf8_casefold(nick2, -1);
	equal = g_utf8_collate(nick2_norm, nick2_norm) == 0;
	g_free(nick2_norm);
	g_free(nick1_norm);

	return equal;
}

/* temporary function */
void sipe_purple_setup(struct sipe_core_public *sipe_public,
		       PurpleConnection *gc)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA;
	sip->gc = gc;
	sip->account = purple_connection_get_account(gc);
}

struct sipe_core_public *sipe_core_allocate(const gchar *signin_name,
					    const gchar *login_domain,
					    const gchar *login_account,
					    const gchar *password,
					    const gchar *email,
					    const gchar *email_url,
					    const gchar **errmsg)
{
	struct sipe_core_private *sipe_private;
	struct sipe_account_data *sip;
	gchar **user_domain;

	SIPE_DEBUG_INFO("sipe_core_allocate: signin_name '%s'", signin_name);

	/* ensure that sign-in name doesn't contain invalid characters */
	if (strpbrk(signin_name, "\t\v\r\n") != NULL) {
		*errmsg = _("SIP Exchange user name contains invalid characters");
		return NULL;
	}

	/* ensure that sign-in name format is name@domain */
	if (!strchr(signin_name, '@') ||
	    g_str_has_prefix(signin_name, "@") ||
	    g_str_has_suffix(signin_name, "@")) {
		*errmsg = _("User name should be a valid SIP URI\nExample: user@company.com");
		return NULL;
	}

	/* ensure that email format is name@domain (if provided) */
	if (!is_empty(email) &&
	    (!strchr(email, '@') ||
	     g_str_has_prefix(email, "@") ||
	     g_str_has_suffix(email, "@")))
	{
		*errmsg = _("Email address should be valid if provided\nExample: user@company.com");
		return NULL;
	}

	/* ensure that user name doesn't contain spaces */
	user_domain = g_strsplit(signin_name, "@", 2);
	SIPE_DEBUG_INFO("sipe_core_allocate: user '%s' domain '%s'", user_domain[0], user_domain[1]);
	if (strchr(user_domain[0], ' ') != NULL) {
		g_strfreev(user_domain);
		*errmsg = _("SIP Exchange user name contains whitespace");
		return NULL;
	}
	
	/* ensure that email_url is in proper format if enabled (if provided).
	 * Example (Exchange): https://server.company.com/EWS/Exchange.asmx
	 * Example (Domino)  : https://[domino_server]/[mail_database_name].nsf
	 */
	if (!is_empty(email_url)) {
		char *tmp = g_ascii_strdown(email_url, -1);
		if (!g_str_has_prefix(tmp, "https://"))
		{
			g_free(tmp);
			g_strfreev(user_domain);
			*errmsg = _("Email services URL should be valid if provided\n"
				    "Example: https://exchange.corp.com/EWS/Exchange.asmx\n"
				    "Example: https://domino.corp.com/maildatabase.nsf");
			return NULL;
		}
		g_free(tmp);
	}

	sipe_private = g_new0(struct sipe_core_private, 1);
	sipe_private->temporary = sip = g_new0(struct sipe_account_data, 1);
	sip->subscribed_buddies = FALSE;
	sip->initial_state_published = FALSE;
	sipe_private->username   = g_strdup(signin_name);
	sip->email      = is_empty(email)         ? g_strdup(signin_name) : g_strdup(email);
	sip->authdomain = is_empty(login_domain)  ? NULL                  : g_strdup(login_domain);
	sip->authuser   = is_empty(login_account) ? NULL                  : g_strdup(login_account);
	sip->password   = g_strdup(password);
	sipe_private->public.sip_name   = g_strdup(user_domain[0]);
	sipe_private->public.sip_domain = g_strdup(user_domain[1]);
	g_strfreev(user_domain);

	sipe_private->buddies = g_hash_table_new((GHashFunc)sipe_ht_hash_nick, (GEqualFunc)sipe_ht_equals_nick);
	sip->our_publications = g_hash_table_new_full(g_str_hash, g_str_equal,
						      g_free, (GDestroyNotify)g_hash_table_destroy);
	sipe_subscriptions_init(sipe_private);
	sip->status = g_strdup(SIPE_STATUS_ID_UNKNOWN);

	return((struct sipe_core_public *)sipe_private);
}

void sipe_connection_cleanup(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

	g_free(sipe_private->epid);
	sipe_private->epid = NULL;

	sip_transport_disconnect(sipe_private);

	sipe_schedule_cancel_all(sipe_private);

	if (sip->allow_events) {
		GSList *entry = sip->allow_events;
		while (entry) {
			g_free(entry->data);
			entry = entry->next;
		}
	}
	g_slist_free(sip->allow_events);

	if (sip->containers) {
		GSList *entry = sip->containers;
		while (entry) {
			free_container((struct sipe_container *)entry->data);
			entry = entry->next;
		}
	}
	g_slist_free(sip->containers);

	if (sipe_private->contact)
		g_free(sipe_private->contact);
	sipe_private->contact = NULL;
	if (sip->regcallid)
		g_free(sip->regcallid);
	sip->regcallid = NULL;

	if (sipe_private->focus_factory_uri)
		g_free(sipe_private->focus_factory_uri);
	sipe_private->focus_factory_uri = NULL;

	if (sip->cal) {
		sipe_cal_calendar_free(sip->cal);
	}
	sip->cal = NULL;
}

/**
  * A callback for g_hash_table_foreach_remove
  */
static gboolean sipe_buddy_remove(SIPE_UNUSED_PARAMETER gpointer key, gpointer buddy,
				  SIPE_UNUSED_PARAMETER gpointer user_data)
{
	sipe_free_buddy((struct sipe_buddy *) buddy);

	/* We must return TRUE as the key/value have already been deleted */
	return(TRUE);
}

void sipe_core_deallocate(struct sipe_core_public *sipe_public)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

	/* leave all conversations */
	sipe_session_close_all(sipe_private);
	sipe_session_remove_all(sipe_private);

	if (sip->csta) {
		sip_csta_close(sipe_private);
	}

	if (PURPLE_CONNECTION_IS_CONNECTED(sip->gc)) {
		sipe_subscriptions_unsubscribe(sipe_private);
		sip_transport_deregister(sipe_private);
	}

	sipe_connection_cleanup(sipe_private);
	g_free(sipe_private->public.sip_name);
	g_free(sipe_private->public.sip_domain);
	g_free(sipe_private->username);
	g_free(sip->email);
	g_free(sip->password);
	g_free(sip->authdomain);
	g_free(sip->authuser);
	g_free(sip->status);
	g_free(sip->note);
	g_free(sip->user_states);

	g_hash_table_foreach_steal(sipe_private->buddies, sipe_buddy_remove, NULL);
	g_hash_table_destroy(sipe_private->buddies);
	g_hash_table_destroy(sip->our_publications);
	g_hash_table_destroy(sip->user_state_publications);
	sipe_subscriptions_destroy(sipe_private);

	if (sip->groups) {
		GSList *entry = sip->groups;
		while (entry) {
			struct sipe_group *group = entry->data;
			g_free(group->name);
			g_free(group);
			entry = entry->next;
		}
	}
	g_slist_free(sip->groups);

	if (sip->our_publication_keys) {
		GSList *entry = sip->our_publication_keys;
		while (entry) {
			g_free(entry->data);
			entry = entry->next;
		}
	}
	g_slist_free(sip->our_publication_keys);

	g_free(sip);
	g_free(sipe_private);
}

static void sipe_searchresults_im_buddy(PurpleConnection *gc, GList *row,
					SIPE_UNUSED_PARAMETER void *user_data)
{
	PurpleAccount *acct = purple_connection_get_account(gc);
	char *id = sip_uri_from_name((gchar *)g_list_nth_data(row, 0));
	PurpleConversation *conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, id, acct);
	if (conv == NULL)
		conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, acct, id);
	purple_conversation_present(conv);
	g_free(id);
}

static void sipe_searchresults_add_buddy(PurpleConnection *gc, GList *row,
					 SIPE_UNUSED_PARAMETER void *user_data)
{

	purple_blist_request_add_buddy(purple_connection_get_account(gc),
								 g_list_nth_data(row, 0), _("Other Contacts"), g_list_nth_data(row, 1));
}

static gboolean process_search_contact_response(struct sipe_core_private *sipe_private,
						struct sipmsg *msg,
						SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	PurpleNotifySearchResults *results;
	PurpleNotifySearchColumn *column;
	sipe_xml *searchResults;
	const sipe_xml *mrow;
	int match_count = 0;
	gboolean more = FALSE;
	gchar *secondary;

	SIPE_DEBUG_INFO("process_search_contact_response: body:\n%s", msg->body ? msg->body : "");

	searchResults = sipe_xml_parse(msg->body, msg->bodylen);
	if (!searchResults) {
		SIPE_DEBUG_INFO_NOFORMAT("process_search_contact_response: no parseable searchResults");
		return FALSE;
	}

	results = purple_notify_searchresults_new();

	if (results == NULL) {
		SIPE_DEBUG_ERROR_NOFORMAT("purple_parse_searchreply: Unable to display the search results.");
		purple_notify_error(sip->gc, NULL, _("Unable to display the search results"), NULL);

		sipe_xml_free(searchResults);
		return FALSE;
	}

	column = purple_notify_searchresults_column_new(_("User name"));
	purple_notify_searchresults_column_add(results, column);

	column = purple_notify_searchresults_column_new(_("Name"));
	purple_notify_searchresults_column_add(results, column);

	column = purple_notify_searchresults_column_new(_("Company"));
	purple_notify_searchresults_column_add(results, column);

	column = purple_notify_searchresults_column_new(_("Country"));
	purple_notify_searchresults_column_add(results, column);

	column = purple_notify_searchresults_column_new(_("Email"));
	purple_notify_searchresults_column_add(results, column);

	for (mrow =  sipe_xml_child(searchResults, "Body/Array/row"); mrow; mrow = sipe_xml_twin(mrow)) {
		GList *row = NULL;

		gchar **uri_parts = g_strsplit(sipe_xml_attribute(mrow, "uri"), ":", 2);
		row = g_list_append(row, g_strdup(uri_parts[1]));
		g_strfreev(uri_parts);

		row = g_list_append(row, g_strdup(sipe_xml_attribute(mrow, "displayName")));
		row = g_list_append(row, g_strdup(sipe_xml_attribute(mrow, "company")));
		row = g_list_append(row, g_strdup(sipe_xml_attribute(mrow, "country")));
		row = g_list_append(row, g_strdup(sipe_xml_attribute(mrow, "email")));

		purple_notify_searchresults_row_add(results, row);
		match_count++;
	}

	if ((mrow = sipe_xml_child(searchResults, "Body/directorySearch/moreAvailable")) != NULL) {
		char *data = sipe_xml_data(mrow);
		more = (g_strcasecmp(data, "true") == 0);
		g_free(data);
	}

	secondary = g_strdup_printf(
		dngettext(PACKAGE_NAME,
			  "Found %d contact%s:",
			  "Found %d contacts%s:", match_count),
		match_count, more ? _(" (more matched your query)") : "");

	purple_notify_searchresults_button_add(results, PURPLE_NOTIFY_BUTTON_IM, sipe_searchresults_im_buddy);
	purple_notify_searchresults_button_add(results, PURPLE_NOTIFY_BUTTON_ADD, sipe_searchresults_add_buddy);
	purple_notify_searchresults(sip->gc, NULL, NULL, secondary, results, NULL, NULL);

	g_free(secondary);
	sipe_xml_free(searchResults);
	return TRUE;
}

void sipe_search_contact_with_cb(PurpleConnection *gc, PurpleRequestFields *fields)
{
	GList *entries = purple_request_field_group_get_fields(purple_request_fields_get_groups(fields)->data);
	gchar **attrs = g_new(gchar *, g_list_length(entries) + 1);
	unsigned i = 0;

	if (!attrs) return;

	do {
		PurpleRequestField *field = entries->data;
		const char *id = purple_request_field_get_id(field);
		const char *value = purple_request_field_string_get_value(field);

		SIPE_DEBUG_INFO("sipe_search_contact_with_cb: %s = '%s'", id, value ? value : "");

		if (value != NULL) attrs[i++] = g_markup_printf_escaped(SIPE_SOAP_SEARCH_ROW, id, value);
	} while ((entries = g_list_next(entries)) != NULL);
	attrs[i] = NULL;

	if (i > 0) {
		struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;
		gchar *domain_uri = sip_uri_from_name(sipe_private->public.sip_domain);
		gchar *query = g_strjoinv(NULL, attrs);
		gchar *body = g_strdup_printf(SIPE_SOAP_SEARCH_CONTACT, 100, query);
		SIPE_DEBUG_INFO("sipe_search_contact_with_cb: body:\n%s", body ? body : "");
		send_soap_request_with_cb(sipe_private, domain_uri, body,
					  process_search_contact_response, NULL);
		g_free(domain_uri);
		g_free(body);
		g_free(query);
	}

	g_strfreev(attrs);
}

static void sipe_publish_get_cat_state_user_to_clear(SIPE_UNUSED_PARAMETER const char *name,
						     gpointer value,
						     GString* str)
{
	struct sipe_publication *publication = value;

	g_string_append_printf( str,
				SIPE_PUB_XML_PUBLICATION_CLEAR,
				publication->category,
				publication->instance,
				publication->container,
				publication->version,
				"static");
}

void sipe_core_reset_status(struct sipe_core_public *sipe_public)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA;
	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) /* 2007+ */
	{
		GString* str = g_string_new(NULL);
		gchar *publications;

		if (!sip->user_state_publications || g_hash_table_size(sip->user_state_publications) == 0) {
			SIPE_DEBUG_INFO_NOFORMAT("sipe_reset_status: no userState publications, exiting.");
			return;
		}

		g_hash_table_foreach(sip->user_state_publications, (GHFunc)sipe_publish_get_cat_state_user_to_clear, str);
		publications = g_string_free(str, FALSE);

		send_presence_publish(sipe_private, publications);
		g_free(publications);
	}
	else /* 2005 */
	{
		send_presence_soap0(sipe_private, FALSE, TRUE);
	}
}

/** for Access levels menu */
#define INDENT_FMT			"  %s"

/** Member is directly placed to access level container.
 *  For example SIP URI of user is in the container.
 */
#define INDENT_MARKED_FMT		"* %s"

/** Member is indirectly belong to access level container.
 *  For example 'sameEnterprise' is in the container and user
 *  belongs to that same enterprise.
 */
#define INDENT_MARKED_INHERITED_FMT	"= %s"

GSList *sipe_core_buddy_info(struct sipe_core_public *sipe_public,
			     const gchar *name,
			     const gchar *status_name,
			     gboolean is_online)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	gchar *note = NULL;
	gboolean is_oof_note = FALSE;
	gchar *activity = NULL;
	gchar *calendar = NULL;
	gchar *meeting_subject = NULL;
	gchar *meeting_location = NULL;
	gchar *access_text = NULL;
	GSList *info = NULL;

#define SIPE_ADD_BUDDY_INFO(l, t) \
	{ \
		struct sipe_buddy_info *sbi = g_malloc(sizeof(struct sipe_buddy_info)); \
		sbi->label = (l); \
		sbi->text = (t); \
		info = g_slist_append(info, sbi); \
	}

	if (sipe_public) { //happens on pidgin exit
		struct sipe_buddy *sbuddy = g_hash_table_lookup(sipe_private->buddies, name);
		if (sbuddy) {
			note = sbuddy->note;
			is_oof_note = sbuddy->is_oof_note;
			activity = sbuddy->activity;
			calendar = sipe_cal_get_description(sbuddy);
			meeting_subject = sbuddy->meeting_subject;
			meeting_location = sbuddy->meeting_location;
		}
		if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
			gboolean is_group_access = FALSE;
			const int container_id = sipe_find_access_level(sipe_private, "user", sipe_get_no_sip_uri(name), &is_group_access);
			const char *access_level = sipe_get_access_level_name(container_id);
			access_text = is_group_access ?
				g_strdup(access_level) :
				g_strdup_printf(INDENT_MARKED_FMT, access_level);
		}
	}

	//Layout
	if (is_online)
	{
		gchar *status_str = g_strdup(activity ? activity : status_name);

		SIPE_ADD_BUDDY_INFO(_("Status"), status_str);
	}
	if (is_online && !is_empty(calendar))
	{
		SIPE_ADD_BUDDY_INFO(_("Calendar"), calendar);
		calendar = NULL;
	}
	g_free(calendar);
	if (!is_empty(meeting_location))
	{
		SIPE_ADD_BUDDY_INFO(_("Meeting in"), g_strdup(meeting_location));
	}
	if (!is_empty(meeting_subject))
	{
		SIPE_ADD_BUDDY_INFO(_("Meeting about"), g_strdup(meeting_subject));
	}
	if (note)
	{
		SIPE_DEBUG_INFO("sipe_tooltip_text: %s note: '%s'", name, note);
		SIPE_ADD_BUDDY_INFO(is_oof_note ? _("Out of office note") : _("Note"),
				    g_strdup_printf("<i>%s</i>", note));
	}
	if (access_text) {
		SIPE_ADD_BUDDY_INFO(_("Access level"), access_text);
	}

	return(info);
}

static PurpleBuddy *
purple_blist_add_buddy_clone(PurpleGroup * group, PurpleBuddy * buddy)
{
	PurpleBuddy *clone;
	const gchar *server_alias, *email;
	const PurpleStatus *status = purple_presence_get_active_status(purple_buddy_get_presence(buddy));

	clone = purple_buddy_new(buddy->account, buddy->name, buddy->alias);

	purple_blist_add_buddy(clone, NULL, group, NULL);

	server_alias = purple_buddy_get_server_alias(buddy);
	if (server_alias) {
		purple_blist_server_alias_buddy(clone, server_alias);
	}

	email = purple_blist_node_get_string(&buddy->node, EMAIL_PROP);
	if (email) {
		purple_blist_node_set_string(&clone->node, EMAIL_PROP, email);
	}

	purple_presence_set_status_active(purple_buddy_get_presence(clone), purple_status_get_id(status), TRUE);
	//for UI to update;
	purple_prpl_got_user_status(clone->account, clone->name, purple_status_get_id(status), NULL);
	return clone;
}

static void
sipe_buddy_menu_copy_to_cb(PurpleBlistNode *node, const char *group_name)
{
	PurpleBuddy *buddy, *b;
	PurpleConnection *gc;
	PurpleGroup * group = purple_find_group(group_name);

	g_return_if_fail(PURPLE_BLIST_NODE_IS_BUDDY(node));

	buddy = (PurpleBuddy *)node;

	SIPE_DEBUG_INFO("sipe_buddy_menu_copy_to_cb: copying %s to %s", buddy->name, group_name);
	gc = purple_account_get_connection(buddy->account);

	b = purple_find_buddy_in_group(buddy->account, buddy->name, group);
	if (!b){
		purple_blist_add_buddy_clone(group, buddy);
	}

	sipe_group_buddy(gc, buddy->name, NULL, group_name);
}

static void
sipe_buddy_menu_chat_new_cb(PurpleBuddy *buddy)
{
	struct sipe_core_private *sipe_private = PURPLE_BUDDY_TO_SIPE_CORE_PRIVATE;

	SIPE_DEBUG_INFO("sipe_buddy_menu_chat_new_cb: buddy->name=%s", buddy->name);

	/* 2007+ conference */
	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007))
	{
		sipe_conf_add(sipe_private, buddy->name);
	}
	else /* 2005- multiparty chat */
	{
		gchar *self = sip_uri_self(sipe_private);
		struct sip_session *session;

		session = sipe_session_add_chat(sipe_private);
		session->chat_title = sipe_chat_get_name(session->callid);
		session->roster_manager = g_strdup(self);

		session->backend_session = sipe_backend_chat_create(SIPE_CORE_PUBLIC,
								    session->chat_id,
								    session->chat_title,
								    self,
								    FALSE);
		sipe_backend_chat_add(session->backend_session,
				      self,
				      FALSE);
		sipe_invite(sipe_private, session, buddy->name, NULL, NULL, NULL, FALSE);

		g_free(self);
	}
}

/**
 * For 2007+ conference only.
 */
static void
sipe_buddy_menu_chat_make_leader_cb(PurpleBuddy *buddy, const char *chat_title)
{
	struct sipe_core_private *sipe_private = PURPLE_BUDDY_TO_SIPE_CORE_PRIVATE;
	struct sip_session *session;

	SIPE_DEBUG_INFO("sipe_buddy_menu_chat_make_leader_cb: buddy->name=%s", buddy->name);
	SIPE_DEBUG_INFO("sipe_buddy_menu_chat_make_leader_cb: chat_title=%s", chat_title);

	session = sipe_session_find_chat_by_title(sipe_private, chat_title);

	sipe_conf_modify_user_role(sipe_private, session, buddy->name);
}

/**
 * For 2007+ conference only.
 */
static void
sipe_buddy_menu_chat_remove_cb(PurpleBuddy *buddy, const char *chat_title)
{
	struct sipe_core_private *sipe_private = PURPLE_BUDDY_TO_SIPE_CORE_PRIVATE;
	struct sip_session *session;

	SIPE_DEBUG_INFO("sipe_buddy_menu_chat_remove_cb: buddy->name=%s", buddy->name);
	SIPE_DEBUG_INFO("sipe_buddy_menu_chat_remove_cb: chat_title=%s", chat_title);

	session = sipe_session_find_chat_by_title(sipe_private, chat_title);

	sipe_conf_delete_user(sipe_private, session, buddy->name);
}

static void
sipe_buddy_menu_chat_invite_cb(PurpleBuddy *buddy, char *chat_title)
{
	struct sipe_core_private *sipe_private = PURPLE_BUDDY_TO_SIPE_CORE_PRIVATE;
	struct sip_session *session;

	SIPE_DEBUG_INFO("sipe_buddy_menu_chat_invite_cb: buddy->name=%s", buddy->name);
	SIPE_DEBUG_INFO("sipe_buddy_menu_chat_invite_cb: chat_title=%s", chat_title);

	session = sipe_session_find_chat_by_title(sipe_private, chat_title);

	sipe_invite_to_chat(sipe_private, session, buddy->name);
}

static void
sipe_buddy_menu_make_call_cb(PurpleBuddy *buddy, const char *phone)
{
	struct sipe_core_private *sipe_private = PURPLE_BUDDY_TO_SIPE_CORE_PRIVATE;

	SIPE_DEBUG_INFO("sipe_buddy_menu_make_call_cb: buddy->name=%s", buddy->name);
	if (phone) {
		char *tel_uri = sip_to_tel_uri(phone);

		SIPE_DEBUG_INFO("sipe_buddy_menu_make_call_cb: going to call number: %s", tel_uri ? tel_uri : "");
		sip_csta_make_call(sipe_private, tel_uri);

		g_free(tel_uri);
	}
}

static void
sipe_buddy_menu_access_level_help_cb(PurpleBuddy *buddy)
{
	/** Translators: replace with URL to localized page
	 * If it doesn't exist copy the original URL */
	purple_notify_uri(buddy->account->gc, _("https://sourceforge.net/apps/mediawiki/sipe/index.php?title=Access_Levels"));
}

static void
sipe_buddy_menu_send_email_cb(PurpleBuddy *buddy)
{
	const gchar *email;
	SIPE_DEBUG_INFO("sipe_buddy_menu_send_email_cb: buddy->name=%s", buddy->name);

	email = purple_blist_node_get_string(&buddy->node, EMAIL_PROP);
	if (email)
	{
		char *command_line = g_strdup_printf(
#ifdef _WIN32
			"cmd /c start"
#else
			"xdg-email"
#endif
			" mailto:%s", email);
		SIPE_DEBUG_INFO("sipe_buddy_menu_send_email_cb: going to call email client: %s", command_line);

		g_spawn_command_line_async(command_line, NULL);
		g_free(command_line);
	}
	else
	{
		SIPE_DEBUG_INFO("sipe_buddy_menu_send_email_cb: no email address stored for buddy=%s", buddy->name);
	}
}

static void
sipe_buddy_menu_access_level_cb(PurpleBuddy *buddy,
				struct sipe_container *container)
{
	struct sipe_core_private *sipe_private = PURPLE_BUDDY_TO_SIPE_CORE_PRIVATE;
	struct sipe_container_member *member;

	if (!container || !container->members) return;

	member = ((struct sipe_container_member *)container->members->data);

	if (!member->type) return;

	SIPE_DEBUG_INFO("sipe_buddy_menu_access_level_cb: container->id=%d, member->type=%s, member->value=%s",
		container->id, member->type, member->value ? member->value : "");

	sipe_change_access_level(sipe_private, container->id, member->type, member->value);
}

static GList *
sipe_get_access_control_menu(struct sipe_core_private *sipe_private,
			     const char* uri);

/*
 * A menu which appear when right-clicking on buddy in contact list.
 */
GList *
sipe_buddy_menu(PurpleBuddy *buddy)
{
	PurpleBlistNode *g_node;
	PurpleGroup *group, *gr_parent;
	PurpleMenuAction *act;
	GList *menu = NULL;
	GList *menu_groups = NULL;
	struct sipe_core_private *sipe_private = PURPLE_BUDDY_TO_SIPE_CORE_PRIVATE;
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	const char *email;
	const char *phone;
	const char *phone_disp_str;
	gchar *self = sip_uri_self(sipe_private);

	SIPE_SESSION_FOREACH {
		if (!sipe_strcase_equal(self, buddy->name) && session->chat_title && session->backend_session)
		{
			if (sipe_backend_chat_find(session->backend_session, buddy->name))
			{
				gboolean conf_op = sipe_backend_chat_is_operator(session->backend_session, self);

				if (session->focus_uri
				    && !sipe_backend_chat_is_operator(session->backend_session, buddy->name) /* Not conf OP */
				    &&  conf_op)                                                             /* We are a conf OP */
				{
					gchar *label = g_strdup_printf(_("Make leader of '%s'"), session->chat_title);
					act = purple_menu_action_new(label,
								     PURPLE_CALLBACK(sipe_buddy_menu_chat_make_leader_cb),
								     session->chat_title, NULL);
					g_free(label);
					menu = g_list_prepend(menu, act);
				}

				if (session->focus_uri
				    && conf_op) /* We are a conf OP */
				{
					gchar *label = g_strdup_printf(_("Remove from '%s'"), session->chat_title);
					act = purple_menu_action_new(label,
								     PURPLE_CALLBACK(sipe_buddy_menu_chat_remove_cb),
								     session->chat_title, NULL);
					g_free(label);
					menu = g_list_prepend(menu, act);
				}
			}
			else
			{
				if (!session->focus_uri
				    || (session->focus_uri && !session->locked))
				{
					gchar *label = g_strdup_printf(_("Invite to '%s'"), session->chat_title);
					act = purple_menu_action_new(label,
								     PURPLE_CALLBACK(sipe_buddy_menu_chat_invite_cb),
								     session->chat_title, NULL);
					g_free(label);
					menu = g_list_prepend(menu, act);
				}
			}
		}
	} SIPE_SESSION_FOREACH_END;

	act = purple_menu_action_new(_("New chat"),
				     PURPLE_CALLBACK(sipe_buddy_menu_chat_new_cb),
				     NULL, NULL);
	menu = g_list_prepend(menu, act);

	if (sip->csta && !sip->csta->line_status) {
		gchar *tmp = NULL;
		/* work phone */
		phone = purple_blist_node_get_string(&buddy->node, PHONE_PROP);
		phone_disp_str = purple_blist_node_get_string(&buddy->node, PHONE_DISPLAY_PROP);
		if (phone) {
			gchar *label = g_strdup_printf(_("Work %s"),
				phone_disp_str ? phone_disp_str : (tmp = sip_tel_uri_denormalize(phone)));
			act = purple_menu_action_new(label, PURPLE_CALLBACK(sipe_buddy_menu_make_call_cb), (gpointer) phone, NULL);
			g_free(tmp);
			tmp = NULL;
			g_free(label);
			menu = g_list_prepend(menu, act);
		}

		/* mobile phone */
		phone = purple_blist_node_get_string(&buddy->node, PHONE_MOBILE_PROP);
		phone_disp_str = purple_blist_node_get_string(&buddy->node, PHONE_MOBILE_DISPLAY_PROP);
		if (phone) {
			gchar *label = g_strdup_printf(_("Mobile %s"),
				phone_disp_str ? phone_disp_str : (tmp = sip_tel_uri_denormalize(phone)));
			act = purple_menu_action_new(label, PURPLE_CALLBACK(sipe_buddy_menu_make_call_cb), (gpointer) phone, NULL);
			g_free(tmp);
			tmp = NULL;
			g_free(label);
			menu = g_list_prepend(menu, act);
		}

		/* home phone */
		phone = purple_blist_node_get_string(&buddy->node, PHONE_HOME_PROP);
		phone_disp_str = purple_blist_node_get_string(&buddy->node, PHONE_HOME_DISPLAY_PROP);
		if (phone) {
			gchar *label = g_strdup_printf(_("Home %s"),
				phone_disp_str ? phone_disp_str : (tmp = sip_tel_uri_denormalize(phone)));
			act = purple_menu_action_new(label, PURPLE_CALLBACK(sipe_buddy_menu_make_call_cb), (gpointer) phone, NULL);
			g_free(tmp);
			tmp = NULL;
			g_free(label);
			menu = g_list_prepend(menu, act);
		}

		/* other phone */
		phone = purple_blist_node_get_string(&buddy->node, PHONE_OTHER_PROP);
		phone_disp_str = purple_blist_node_get_string(&buddy->node, PHONE_OTHER_DISPLAY_PROP);
		if (phone) {
			gchar *label = g_strdup_printf(_("Other %s"),
				phone_disp_str ? phone_disp_str : (tmp = sip_tel_uri_denormalize(phone)));
			act = purple_menu_action_new(label, PURPLE_CALLBACK(sipe_buddy_menu_make_call_cb), (gpointer) phone, NULL);
			g_free(tmp);
			tmp = NULL;
			g_free(label);
			menu = g_list_prepend(menu, act);
		}

		/* custom1 phone */
		phone = purple_blist_node_get_string(&buddy->node, PHONE_CUSTOM1_PROP);
		phone_disp_str = purple_blist_node_get_string(&buddy->node, PHONE_CUSTOM1_DISPLAY_PROP);
		if (phone) {
			gchar *label = g_strdup_printf(_("Custom1 %s"),
				phone_disp_str ? phone_disp_str : (tmp = sip_tel_uri_denormalize(phone)));
			act = purple_menu_action_new(label, PURPLE_CALLBACK(sipe_buddy_menu_make_call_cb), (gpointer) phone, NULL);
			g_free(tmp);
			tmp = NULL;
			g_free(label);
			menu = g_list_prepend(menu, act);
		}
	}

	email = purple_blist_node_get_string(&buddy->node, EMAIL_PROP);
	if (email) {
		act = purple_menu_action_new(_("Send email..."),
					     PURPLE_CALLBACK(sipe_buddy_menu_send_email_cb),
					     NULL, NULL);
		menu = g_list_prepend(menu, act);
	}

	/* Access Level */
	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
		GList *menu_access_levels = sipe_get_access_control_menu(sipe_private, buddy->name);

		act = purple_menu_action_new(_("Access level"),
					     NULL,
					     NULL, menu_access_levels);
		menu = g_list_prepend(menu, act);
	}

	/* Copy to */
	gr_parent = purple_buddy_get_group(buddy);
	for (g_node = purple_blist_get_root(); g_node; g_node = g_node->next) {
		if (g_node->type != PURPLE_BLIST_GROUP_NODE)
			continue;

		group = (PurpleGroup *)g_node;
		if (group == gr_parent)
			continue;

		if (purple_find_buddy_in_group(buddy->account, buddy->name, group))
			continue;

		act = purple_menu_action_new(purple_group_get_name(group),
							   PURPLE_CALLBACK(sipe_buddy_menu_copy_to_cb),
							   group->name, NULL);
		menu_groups = g_list_prepend(menu_groups, act);
	}
	menu_groups = g_list_reverse(menu_groups);

	act = purple_menu_action_new(_("Copy to"),
				     NULL,
				     NULL, menu_groups);
	menu = g_list_prepend(menu, act);

	menu = g_list_reverse(menu);

	g_free(self);
	return menu;
}

static void
sipe_ask_access_domain_cb(PurpleConnection *gc, PurpleRequestFields *fields)
{
	struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;
	const char *domain = purple_request_fields_get_string(fields, "access_domain");
	int index = purple_request_fields_get_choice(fields, "container_id");
	/* move Blocked first */
	int i = (index == 4) ? 0 : index + 1;
	int container_id = containers[i];

	SIPE_DEBUG_INFO("sipe_ask_access_domain_cb: domain=%s, container_id=(%d)%d", domain ? domain : "", index, container_id);

	sipe_change_access_level(sipe_private, container_id, "domain", domain);
}

static void
sipe_ask_access_domain(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	PurpleAccount *account = sip->account;
	PurpleConnection *gc = sip->gc;
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *g;
	PurpleRequestField *f;

	fields = purple_request_fields_new();

	g = purple_request_field_group_new(NULL);
	f = purple_request_field_string_new("access_domain", _("Domain"), "partner-company.com", FALSE);
	purple_request_field_set_required(f, TRUE);
	purple_request_field_group_add_field(g, f);

	f = purple_request_field_choice_new("container_id", _("Access level"), 0);
	purple_request_field_choice_add(f, _("Personal")); /* index 0 */
	purple_request_field_choice_add(f, _("Team"));
	purple_request_field_choice_add(f, _("Company"));
	purple_request_field_choice_add(f, _("Public"));
	purple_request_field_choice_add(f, _("Blocked")); /* index 4 */
	purple_request_field_choice_set_default_value(f, 3); /* index */
	purple_request_field_set_required(f, TRUE);
	purple_request_field_group_add_field(g, f);

	purple_request_fields_add_group(fields, g);

	purple_request_fields(gc, _("Add new domain"),
			      _("Add new domain"), NULL, fields,
			      _("Add"), G_CALLBACK(sipe_ask_access_domain_cb),
			      _("Cancel"), NULL,
			      account, NULL, NULL, gc);
}

static void
sipe_buddy_menu_access_level_add_domain_cb(PurpleBuddy *buddy)
{
	sipe_ask_access_domain(PURPLE_BUDDY_TO_SIPE_CORE_PRIVATE);
}

static GList *
sipe_get_access_levels_menu(struct sipe_core_private *sipe_private,
			    const char* member_type,
			    const char* member_value,
			    const gboolean extra_menu)
{
	GList *menu_access_levels = NULL;
	unsigned int i;
	char *menu_name;
	PurpleMenuAction *act;
	struct sipe_container *container;
	struct sipe_container_member *member;
	gboolean is_group_access = FALSE;
	int container_id = sipe_find_access_level(sipe_private, member_type, member_value, &is_group_access);

	for (i = 1; i <= CONTAINERS_LEN; i++) {
		/* to put Blocked level last in menu list.
		 * Blocked should remaim in the first place in the containers[] array.
		 */
		unsigned int j = (i == CONTAINERS_LEN) ? 0 : i;
		const char *acc_level_name = sipe_get_access_level_name(containers[j]);

		container = g_new0(struct sipe_container, 1);
		member = g_new0(struct sipe_container_member, 1);
		container->id = containers[j];
		container->members = g_slist_append(container->members, member);
		member->type = g_strdup(member_type);
		member->value = g_strdup(member_value);

		/* current container/access level */
		if (((int)containers[j]) == container_id) {
			menu_name = is_group_access ?
				g_strdup_printf(INDENT_MARKED_INHERITED_FMT, acc_level_name) :
				g_strdup_printf(INDENT_MARKED_FMT, acc_level_name);
		} else {
			menu_name = g_strdup_printf(INDENT_FMT, acc_level_name);
		}

		act = purple_menu_action_new(menu_name,
					     PURPLE_CALLBACK(sipe_buddy_menu_access_level_cb),
					     container, NULL);
		g_free(menu_name);
		menu_access_levels = g_list_prepend(menu_access_levels, act);
	}

	if (extra_menu && (container_id >= 0)) {
		/* separator */
		act = purple_menu_action_new("  --------------", NULL, NULL, NULL);
		menu_access_levels = g_list_prepend(menu_access_levels, act);

		if (!is_group_access) {
			container = g_new0(struct sipe_container, 1);
			member = g_new0(struct sipe_container_member, 1);
			container->id = -1;
			container->members = g_slist_append(container->members, member);
			member->type = g_strdup(member_type);
			member->value = g_strdup(member_value);

			/* Translators: remove (clear) previously assigned access level */
			menu_name = g_strdup_printf(INDENT_FMT, _("Unspecify"));
			act = purple_menu_action_new(menu_name,
						     PURPLE_CALLBACK(sipe_buddy_menu_access_level_cb),
						     container, NULL);
			g_free(menu_name);
			menu_access_levels = g_list_prepend(menu_access_levels, act);
		}
	}

	menu_access_levels = g_list_reverse(menu_access_levels);
	return menu_access_levels;
}

static GList *
sipe_get_access_groups_menu(struct sipe_core_private *sipe_private)
{
	GList *menu_access_groups = NULL;
	PurpleMenuAction *act;
	GSList *access_domains = NULL;
	GSList *entry;
	char *menu_name;
	char *domain;

	act = purple_menu_action_new(_("People in my company"),
				     NULL,
				     NULL, sipe_get_access_levels_menu(sipe_private, "sameEnterprise", NULL, FALSE));
	menu_access_groups = g_list_prepend(menu_access_groups, act);

	/* this is original name, don't edit */
	act = purple_menu_action_new(_("People in domains connected with my company"),
				     NULL,
				     NULL, sipe_get_access_levels_menu(sipe_private, "federated", NULL, FALSE));
	menu_access_groups = g_list_prepend(menu_access_groups, act);

	act = purple_menu_action_new(_("People in public domains"),
				     NULL,
				     NULL, sipe_get_access_levels_menu(sipe_private, "publicCloud", NULL, TRUE));
	menu_access_groups = g_list_prepend(menu_access_groups, act);

	access_domains = sipe_get_access_domains(sipe_private);
	entry = access_domains;
	while (entry) {
		domain = entry->data;

		menu_name = g_strdup_printf(_("People at %s"), domain);
		act = purple_menu_action_new(menu_name,
					     NULL,
					     NULL, sipe_get_access_levels_menu(sipe_private, "domain", g_strdup(domain), TRUE));
		menu_access_groups = g_list_prepend(menu_access_groups, act);
		g_free(menu_name);

		entry = entry->next;
	}

	/* separator */
	/*			      People in domains connected with my company		 */
	act = purple_menu_action_new("-------------------------------------------", NULL, NULL, NULL);
	menu_access_groups = g_list_prepend(menu_access_groups, act);

	act = purple_menu_action_new(_("Add new domain..."),
				     PURPLE_CALLBACK(sipe_buddy_menu_access_level_add_domain_cb),
				     NULL, NULL);
	menu_access_groups = g_list_prepend(menu_access_groups, act);

	menu_access_groups = g_list_reverse(menu_access_groups);

	return menu_access_groups;
}

static GList *
sipe_get_access_control_menu(struct sipe_core_private *sipe_private,
			     const char* uri)
{
	GList *menu_access_levels = NULL;
	GList *menu_access_groups = NULL;
	char *menu_name;
	PurpleMenuAction *act;

	menu_access_levels = sipe_get_access_levels_menu(sipe_private, "user", sipe_get_no_sip_uri(uri), TRUE);

	menu_access_groups = sipe_get_access_groups_menu(sipe_private);

	menu_name = g_strdup_printf(INDENT_FMT, _("Access groups"));
	act = purple_menu_action_new(menu_name,
				     NULL,
				     NULL, menu_access_groups);
	g_free(menu_name);
	menu_access_levels = g_list_append(menu_access_levels, act);

	menu_name = g_strdup_printf(INDENT_FMT, _("Online help..."));
	act = purple_menu_action_new(menu_name,
				     PURPLE_CALLBACK(sipe_buddy_menu_access_level_help_cb),
				     NULL, NULL);
	g_free(menu_name);
	menu_access_levels = g_list_append(menu_access_levels, act);

	return menu_access_levels;
}

static void
sipe_conf_modify_lock(PurpleChat *chat, gboolean locked)
{
	struct sipe_core_private *sipe_private = PURPLE_CHAT_TO_SIPE_CORE_PRIVATE;
	struct sip_session *session;

	session = sipe_session_find_chat_by_title(sipe_private,
						  (gchar *)g_hash_table_lookup(chat->components, "channel"));
	sipe_conf_modify_conference_lock(sipe_private, session, locked);
}

static void
sipe_chat_menu_unlock_cb(PurpleChat *chat)
{
	SIPE_DEBUG_INFO_NOFORMAT("sipe_chat_menu_unlock_cb() called");
	sipe_conf_modify_lock(chat, FALSE);
}

static void
sipe_chat_menu_lock_cb(PurpleChat *chat)
{
	SIPE_DEBUG_INFO_NOFORMAT("sipe_chat_menu_lock_cb() called");
	sipe_conf_modify_lock(chat, TRUE);
}

GList *
sipe_chat_menu(PurpleChat *chat)
{
	PurpleMenuAction *act;
	GList *menu = NULL;
	struct sipe_core_private *sipe_private = PURPLE_CHAT_TO_SIPE_CORE_PRIVATE;
	struct sip_session *session;
	gchar *self;

	session = sipe_session_find_chat_by_title(sipe_private,
						  (gchar *)g_hash_table_lookup(chat->components, "channel"));
	if (!session) return NULL;

	self = sip_uri_self(sipe_private);

	if (session->focus_uri &&
	    sipe_backend_chat_is_operator(session->backend_session, self))
	{
		if (session->locked) {
			act = purple_menu_action_new(_("Unlock"),
						     PURPLE_CALLBACK(sipe_chat_menu_unlock_cb),
						     NULL, NULL);
			menu = g_list_prepend(menu, act);
		} else {
			act = purple_menu_action_new(_("Lock"),
						     PURPLE_CALLBACK(sipe_chat_menu_lock_cb),
						     NULL, NULL);
			menu = g_list_prepend(menu, act);
		}
	}

	menu = g_list_reverse(menu);

	g_free(self);
	return menu;
}

static gboolean
process_get_info_response(struct sipe_core_private *sipe_private,
			  struct sipmsg *msg, struct transaction *trans)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	char *uri = trans->payload->data;

	PurpleNotifyUserInfo *info;
	PurpleBuddy *pbuddy = NULL;
	struct sipe_buddy *sbuddy;
	const char *alias = NULL;
	char *device_name = NULL;
	char *server_alias = NULL;
	char *phone_number = NULL;
	char *email = NULL;
	const char *site;
	char *first_name = NULL;
	char *last_name = NULL;

	if (!sip) return FALSE;

	SIPE_DEBUG_INFO("Fetching %s's user info for %s", uri, sipe_private->username);

	pbuddy = purple_find_buddy((PurpleAccount *)sip->account, uri);
	alias = purple_buddy_get_local_alias(pbuddy);

	//will query buddy UA's capabilities and send answer to log
	sipe_options_request(sipe_private, uri);

	sbuddy = g_hash_table_lookup(sipe_private->buddies, uri);
	if (sbuddy) {
		device_name = sbuddy->device_name ? g_strdup(sbuddy->device_name) : NULL;
	}

	info = purple_notify_user_info_new();

	if (msg->response != 200) {
		SIPE_DEBUG_INFO("process_get_info_response: SERVICE response is %d", msg->response);
	} else {
		sipe_xml *searchResults;
		const sipe_xml *mrow;

		SIPE_DEBUG_INFO("process_get_info_response: body:\n%s", msg->body ? msg->body : "");
		searchResults = sipe_xml_parse(msg->body, msg->bodylen);
		if (!searchResults) {
			SIPE_DEBUG_INFO_NOFORMAT("process_get_info_response: no parseable searchResults");
		} else if ((mrow = sipe_xml_child(searchResults, "Body/Array/row"))) {
			const char *value;
			server_alias = g_strdup(sipe_xml_attribute(mrow, "displayName"));
			email = g_strdup(sipe_xml_attribute(mrow, "email"));
			phone_number = g_strdup(sipe_xml_attribute(mrow, "phone"));

			/* For 2007 system we will take this from ContactCard -
			 * it has cleaner tel: URIs at least
			 */
			if (!SIPE_CORE_PRIVATE_FLAG_IS(OCS2007)) {
				char *tel_uri = sip_to_tel_uri(phone_number);
				/* trims its parameters, so call first */
				sipe_update_user_info(sipe_private, uri, ALIAS_PROP, server_alias);
				sipe_update_user_info(sipe_private, uri, EMAIL_PROP, email);
				sipe_update_user_info(sipe_private, uri, PHONE_PROP, tel_uri);
				sipe_update_user_info(sipe_private, uri, PHONE_DISPLAY_PROP, phone_number);
				g_free(tel_uri);
			}

			if (server_alias && strlen(server_alias) > 0) {
				purple_notify_user_info_add_pair(info, _("Display name"), server_alias);
			}
			if ((value = sipe_xml_attribute(mrow, "title")) && strlen(value) > 0) {
				purple_notify_user_info_add_pair(info, _("Job title"), value);
			}
			if ((value = sipe_xml_attribute(mrow, "office")) && strlen(value) > 0) {
				purple_notify_user_info_add_pair(info, _("Office"), value);
			}
			if (phone_number && strlen(phone_number) > 0) {
				purple_notify_user_info_add_pair(info, _("Business phone"), phone_number);
			}
			if ((value = sipe_xml_attribute(mrow, "company")) && strlen(value) > 0) {
				purple_notify_user_info_add_pair(info, _("Company"), value);
			}
			if ((value = sipe_xml_attribute(mrow, "city")) && strlen(value) > 0) {
				purple_notify_user_info_add_pair(info, _("City"), value);
			}
			if ((value = sipe_xml_attribute(mrow, "state")) && strlen(value) > 0) {
				purple_notify_user_info_add_pair(info, _("State"), value);
			}
			if ((value = sipe_xml_attribute(mrow, "country")) && strlen(value) > 0) {
				purple_notify_user_info_add_pair(info, _("Country"), value);
			}
			if (email && strlen(email) > 0) {
				purple_notify_user_info_add_pair(info, _("Email address"), email);
			}

		}
		sipe_xml_free(searchResults);
	}

	purple_notify_user_info_add_section_break(info);

	if (is_empty(server_alias)) {
		g_free(server_alias);
		server_alias = g_strdup(purple_buddy_get_server_alias(pbuddy));
		if (server_alias) {
			purple_notify_user_info_add_pair(info, _("Display name"), server_alias);
		}
	}

	/* present alias if it differs from server alias */
	if (alias && !sipe_strequal(alias, server_alias))
	{
		purple_notify_user_info_add_pair(info, _("Alias"), alias);
	}

	if (is_empty(email)) {
		g_free(email);
		email = g_strdup(purple_blist_node_get_string(&pbuddy->node, EMAIL_PROP));
		if (email) {
			purple_notify_user_info_add_pair(info, _("Email address"), email);
		}
	}

	site = purple_blist_node_get_string(&pbuddy->node, SITE_PROP);
	if (site) {
		purple_notify_user_info_add_pair(info, _("Site"), site);
	}

	sipe_get_first_last_names(sipe_private, uri, &first_name, &last_name);
	if (first_name && last_name) {
		char *link = g_strconcat("http://www.linkedin.com/pub/dir/", first_name, "/", last_name, NULL);

		purple_notify_user_info_add_pair(info, _("Find on LinkedIn"), link);
		g_free(link);
	}
	g_free(first_name);
	g_free(last_name);

	if (device_name) {
		purple_notify_user_info_add_pair(info, _("Device"), device_name);
	}

	/* show a buddy's user info in a nice dialog box */
	purple_notify_userinfo(sip->gc,   /* connection the buddy info came through */
			       uri,       /* buddy's URI */
			       info,      /* body */
			       NULL,      /* callback called when dialog closed */
			       NULL);     /* userdata for callback */

	g_free(phone_number);
	g_free(server_alias);
	g_free(email);
	g_free(device_name);

	return TRUE;
}

/**
 * AD search first, LDAP based
 */
void sipe_get_info(PurpleConnection *gc, const char *username)
{
	struct sipe_core_private *sipe_private = PURPLE_GC_TO_SIPE_CORE_PRIVATE;
	gchar *domain_uri = sip_uri_from_name(sipe_private->public.sip_domain);
	char *row = g_markup_printf_escaped(SIPE_SOAP_SEARCH_ROW, "msRTCSIP-PrimaryUserAddress", username);
	gchar *body = g_strdup_printf(SIPE_SOAP_SEARCH_CONTACT, 1, row);
	struct transaction_payload *payload = g_new0(struct transaction_payload, 1);

	payload->destroy = g_free;
	payload->data = g_strdup(username);

	SIPE_DEBUG_INFO("sipe_get_contact_data: body:\n%s", body ? body : "");
	send_soap_request_with_cb(sipe_private, domain_uri, body,
				  process_get_info_response, payload);
	g_free(domain_uri);
	g_free(body);
	g_free(row);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
