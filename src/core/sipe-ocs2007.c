/**
 * @file sipe-ocs2007.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011-2017 SIPE Project <http://sipe.sourceforge.net/>
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
 * OCS2007+ specific code
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <glib.h>
#include <gio/gio.h>

#include "sipe-common.h"
#include "sipmsg.h"
#include "sip-csta.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-buddy.h"
#include "sipe-cal.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-appshare.h"
#include "sipe-ews.h"
#include "sipe-media.h"
#include "sipe-nls.h"
#include "sipe-ocs2007.h"
#include "sipe-schedule.h"
#include "sipe-status.h"
#include "sipe-utils.h"
#include "sipe-xml.h"

/** MS-PRES publication */
struct sipe_publication {
	gchar *category;
	guint instance;
	guint container;
	guint version;
	/** for 'state' category */
	int availability;
	/** for 'state:calendarState' category */
	char *cal_event_hash;
	/** for 'note' category */
	gchar *note;
	/** for 'calendarData' category; 300(Team) container */
	char *working_hours_xml_str;
	char *fb_start_str;
	char *free_busy_base64;
};

/**
 * 2007-style Activity and Availability.
 *
 * [MS-PRES] 3.7.5.5
 *
 * Conversion of legacyInterop availability ranges and activity tokens into
 * SIPE activity tokens. The descriptions of availability ranges are defined at:
 *
 * http://msdn.microsoft.com/en-us/library/lync/dd941370%28v=office.13%29.aspx
 *
 * The values define the starting point of a range.
 */
#define SIPE_OCS2007_LEGACY_AVAILIBILITY_AVAILABLE      3000
#define SIPE_OCS2007_LEGACY_AVAILIBILITY_AVAILABLE_IDLE 4500
#define SIPE_OCS2007_LEGACY_AVAILIBILITY_BUSY           6000
#define SIPE_OCS2007_LEGACY_AVAILIBILITY_BUSYIDLE       7500
#define SIPE_OCS2007_LEGACY_AVAILIBILITY_DND            9000 /* do not disturb */
#define SIPE_OCS2007_LEGACY_AVAILIBILITY_BRB           12000 /* be right back */
#define SIPE_OCS2007_LEGACY_AVAILIBILITY_AWAY          15000
#define SIPE_OCS2007_LEGACY_AVAILIBILITY_OFFLINE       18000

const gchar *sipe_ocs2007_status_from_legacy_availability(guint availability,
							  const gchar *activity)
{
	guint type;

	if (availability < SIPE_OCS2007_LEGACY_AVAILIBILITY_AVAILABLE) {
		type = SIPE_ACTIVITY_OFFLINE;
	} else if (availability < SIPE_OCS2007_LEGACY_AVAILIBILITY_AVAILABLE_IDLE) {
		type = SIPE_ACTIVITY_AVAILABLE;
	} else if (availability < SIPE_OCS2007_LEGACY_AVAILIBILITY_BUSY) {
		type = SIPE_ACTIVITY_INACTIVE;
	} else if (availability < SIPE_OCS2007_LEGACY_AVAILIBILITY_BUSYIDLE) {
		type = sipe_status_token_to_activity(activity);
		if ((type != SIPE_ACTIVITY_ON_PHONE) &&
		    (type != SIPE_ACTIVITY_IN_CONF))
			type = SIPE_ACTIVITY_BUSY;
	} else if (availability < SIPE_OCS2007_LEGACY_AVAILIBILITY_DND) {
		type = SIPE_ACTIVITY_BUSYIDLE;
	} else if (availability < SIPE_OCS2007_LEGACY_AVAILIBILITY_BRB) {
		type = sipe_status_token_to_activity(activity);
		if (type != SIPE_ACTIVITY_IN_PRES) {
			type = SIPE_ACTIVITY_DND;
		}
	} else if (availability < SIPE_OCS2007_LEGACY_AVAILIBILITY_AWAY) {
		type = SIPE_ACTIVITY_BRB;
	} else if (availability < SIPE_OCS2007_LEGACY_AVAILIBILITY_OFFLINE) {
		type = SIPE_ACTIVITY_AWAY;
	} else {
		type = SIPE_ACTIVITY_OFFLINE;
	}

	return sipe_status_activity_to_token(type);
}

const gchar *sipe_ocs2007_legacy_activity_description(guint availability)
{
	if ((availability >= SIPE_OCS2007_LEGACY_AVAILIBILITY_AVAILABLE_IDLE) &&
	    (availability <  SIPE_OCS2007_LEGACY_AVAILIBILITY_BUSY)) {
		return(sipe_core_activity_description(SIPE_ACTIVITY_INACTIVE));
	} else if ((availability >= SIPE_OCS2007_LEGACY_AVAILIBILITY_BUSYIDLE) &&
		   (availability <  SIPE_OCS2007_LEGACY_AVAILIBILITY_DND)) {
		return(sipe_core_activity_description(SIPE_ACTIVITY_BUSYIDLE));
	} else {
		return(NULL);
	}
}

/**
 * @param sipe_status_id (in)
 * @param activity_token (out) [only sipe-ocs2005.c/send_presence_soap()
 *                              requests this token]
 */
#define SIPE_OCS2007_AVAILABILITY_UNKNOWN     0
#define SIPE_OCS2007_AVAILABILITY_ONLINE   3500
#define SIPE_OCS2007_AVAILABILITY_BUSY     6500
#define SIPE_OCS2007_AVAILABILITY_DND      9500 /* do not disturb */
#define SIPE_OCS2007_AVAILABILITY_BRB     12500 /* be right back */
#define SIPE_OCS2007_AVAILABILITY_AWAY    15500
#define SIPE_OCS2007_AVAILABILITY_OFFLINE 18500
guint sipe_ocs2007_availability_from_status(const gchar *sipe_status_id,
					    const gchar **activity_token)
{
	guint availability;
	guint activity;

	if (sipe_strequal(sipe_status_id, sipe_status_activity_to_token(SIPE_ACTIVITY_AWAY))) {
		availability = SIPE_OCS2007_AVAILABILITY_AWAY;
		activity     = SIPE_ACTIVITY_AWAY;
	} else if (sipe_strequal(sipe_status_id, sipe_status_activity_to_token(SIPE_ACTIVITY_BRB))) {
		availability = SIPE_OCS2007_AVAILABILITY_BRB;
		activity     = SIPE_ACTIVITY_BRB;
	} else if (sipe_strequal(sipe_status_id, sipe_status_activity_to_token(SIPE_ACTIVITY_DND))) {
		availability = SIPE_OCS2007_AVAILABILITY_DND;
		activity     = SIPE_ACTIVITY_DND;
	} else if (sipe_strequal(sipe_status_id, sipe_status_activity_to_token(SIPE_ACTIVITY_BUSY))) {
		availability = SIPE_OCS2007_AVAILABILITY_BUSY;
		activity     = SIPE_ACTIVITY_BUSY;
	} else if (sipe_strequal(sipe_status_id, sipe_status_activity_to_token(SIPE_ACTIVITY_AVAILABLE))) {
		availability = SIPE_OCS2007_AVAILABILITY_ONLINE;
		activity     = SIPE_ACTIVITY_ONLINE;
	} else if (sipe_strequal(sipe_status_id, sipe_status_activity_to_token(SIPE_ACTIVITY_UNSET))) {
		availability = SIPE_OCS2007_AVAILABILITY_UNKNOWN;
		activity     = SIPE_ACTIVITY_UNSET;
	} else {
		/* Offline or invisible */
		availability = SIPE_OCS2007_AVAILABILITY_OFFLINE;
		activity     = SIPE_ACTIVITY_OFFLINE;
	}

	if (activity_token) {
		*activity_token = sipe_status_activity_to_token(activity);
	}

	return(availability);
}

gboolean sipe_ocs2007_status_is_busy(const gchar *status_id)
{
	return(SIPE_OCS2007_AVAILABILITY_BUSY >=
	       sipe_ocs2007_availability_from_status(status_id, NULL));

}

gboolean sipe_ocs2007_availability_is_away(guint availability)
{
	return(availability >= SIPE_OCS2007_LEGACY_AVAILIBILITY_AWAY);
}

static void send_presence_publish(struct sipe_core_private *sipe_private,
				  const char *publications);

static void free_publication(struct sipe_publication *publication)
{
	g_free(publication->category);
	g_free(publication->cal_event_hash);
	g_free(publication->note);

	g_free(publication->working_hours_xml_str);
	g_free(publication->fb_start_str);
	g_free(publication->free_busy_base64);

	g_free(publication);
}

struct hash_table_delete_payload {
	GHashTable *hash_table;
	guint container;
};

static void sipe_remove_category_container_publications_cb(const gchar *name,
							   struct sipe_publication *publication,
							   struct hash_table_delete_payload *payload)
{
	if (publication->container == payload->container) {
		g_hash_table_remove(payload->hash_table, name);
	}
}

static void sipe_remove_category_container_publications(GHashTable *our_publications,
							const gchar *category,
							guint container)
{
	struct hash_table_delete_payload payload;
	payload.hash_table = g_hash_table_lookup(our_publications, category);

	if (!payload.hash_table) return;

	payload.container = container;
	g_hash_table_foreach(payload.hash_table,
			     (GHFunc)sipe_remove_category_container_publications_cb,
			     &payload);
}

/** MS-PRES container */
struct sipe_container {
	guint id;
	guint version;
	GSList *members;
};

/** MS-PRES container member */
struct sipe_container_member {
	/** user, domain, sameEnterprise, federated, publicCloud; everyone */
	gchar *type;
	gchar *value;
};

static const guint containers[] = {32000, 400, 300, 200, 100};
#define CONTAINERS_LEN (sizeof(containers) / sizeof(guint))

static void free_container_member(struct sipe_container_member *member)
{
	if (!member) return;

	g_free(member->type);
	g_free(member->value);
	g_free(member);
}

static void sipe_ocs2007_free_container(struct sipe_container *container)
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

void sipe_core_buddy_menu_free(struct sipe_core_public *sipe_public)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	sipe_utils_slist_free_full(sipe_private->blist_menu_containers,
				   (GDestroyNotify) sipe_ocs2007_free_container);
	sipe_private->blist_menu_containers = NULL;
}

static void blist_menu_remember_container(struct sipe_core_private *sipe_private,
					  struct sipe_container *container)
{
	sipe_private->blist_menu_containers = g_slist_prepend(sipe_private->blist_menu_containers,
							      container);
}

static struct sipe_container *create_container(guint index,
					       const gchar *member_type,
					       const gchar *member_value,
					       gboolean is_group)
{
	struct sipe_container *container = g_new0(struct sipe_container, 1);
	struct sipe_container_member *member = g_new0(struct sipe_container_member, 1);

	container->id = is_group ? (guint) -1 : containers[index];
	container->members = g_slist_append(container->members, member);
	member->type = g_strdup(member_type);
	member->value = g_strdup(member_value);

	return(container);
}

void sipe_ocs2007_free(struct sipe_core_private *sipe_private)
{
	sipe_utils_slist_free_full(sipe_private->containers,
				   (GDestroyNotify) sipe_ocs2007_free_container);
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
static struct sipe_container *sipe_find_container(struct sipe_core_private *sipe_private,
						  guint id)
{
	GSList *entry = sipe_private->containers;
	while (entry) {
		struct sipe_container *container = entry->data;
		if (id == container->id) {
			return container;
		}
		entry = entry->next;
	}
	return NULL;
}

static int sipe_find_member_access_level(struct sipe_core_private *sipe_private,
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

/**
 * Returns pointer to domain part in provided Email URL
 *
 * @param email an email URL. Example: first.last@hq.company.com
 * @return pointer to domain part of email URL. Coresponding example: hq.company.com
 *
 * Doesn't allocate memory
 */
static const gchar *sipe_get_domain(const gchar *email)
{
	gchar *tmp;

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
static const gchar * const public_domains[] = {
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

static gboolean sipe_is_public_domain(const gchar *domain)
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
const gchar *sipe_ocs2007_access_level_name(guint id)
{
	switch (id) {
		case 32000: return _("Blocked");
		case 400:   return _("Personal");
		case 300:   return _("Team");
		case 200:   return _("Company");
		case 100:   return _("Public");
	}
	return _("Unknown");
}

/** Member type: user, domain, sameEnterprise, federated, publicCloud; everyone */
int sipe_ocs2007_find_access_level(struct sipe_core_private *sipe_private,
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

static GSList *get_access_domains(struct sipe_core_private *sipe_private)
{
	struct sipe_container *container;
	struct sipe_container_member *member;
	GSList *entry;
	GSList *entry2;
	GSList *res = NULL;

	entry = sipe_private->containers;
	while (entry) {
		container = entry->data;

		entry2 = container->members;
		while (entry2) {
			member = entry2->data;
			if (sipe_strcase_equal(member->type, "domain"))
			{
				res = sipe_utils_slist_insert_unique_sorted(res,
									    g_strdup(member->value),
									    (GCompareFunc)g_ascii_strcasecmp,
									    g_free);
			}
			entry2 = entry2->next;
		}
		entry = entry->next;
	}
	return res;
}

static void sipe_send_container_members_prepare(const guint container_id,
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

static void sipe_send_set_container_members(struct sipe_core_private *sipe_private,
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
  * @param container_id	a new access level. If -1 then current access level
  * 			is just removed (I.e. the member is removed from all containers).
  * @param type		a type of member. E.g. "user", "sameEnterprise", etc.
  * @param value	a value for member. E.g. SIP URI for "user" member type.
  */
void sipe_ocs2007_change_access_level(struct sipe_core_private *sipe_private,
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
			}
		}
	}

	/* recalculate AL below */
	current_container_id = sipe_ocs2007_find_access_level(sipe_private, type, value, NULL);

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

void sipe_core_change_access_level_from_container(struct sipe_core_public *sipe_public,
						  gpointer parameter)
{
	struct sipe_container *container = parameter;
	struct sipe_container_member *member;

	if (!container || !container->members) return;

	member = ((struct sipe_container_member *)container->members->data);

	if (!member->type) return;

	SIPE_DEBUG_INFO("sipe_ocs2007_change_access_level_from_container: container->id=%d, member->type=%s, member->value=%s",
			container->id, member->type, member->value ? member->value : "");

	sipe_ocs2007_change_access_level(SIPE_CORE_PRIVATE,
					 container->id,
					 member->type,
					 member->value);

}

void sipe_core_change_access_level_for_domain(struct sipe_core_public *sipe_public,
					      const gchar *domain,
					      guint index)
{
	/* move Blocked first */
	guint i            = (index == 4) ? 0 : index + 1;
	guint container_id = containers[i];

	SIPE_DEBUG_INFO("sipe_core_change_access_level_from_id: domain=%s, container_id=(%d)%d",
			domain ? domain : "", index, container_id);

	sipe_ocs2007_change_access_level(SIPE_CORE_PRIVATE,
					 container_id,
					 "domain",
					 domain);
}

/**
 * Schedules process of self status publish
 * based on own calendar information.
 * Should be scheduled to the beginning of every
 * 15 min interval, like:
 * 13:00, 13:15, 13:30, 13:45, etc.
 *
 */
static void schedule_publish_update(struct sipe_core_private *sipe_private,
				    time_t calculate_from)
{
	int interval = 5*60;
	/** start of the beginning of closest 5 min interval. */
	time_t next_start = ((time_t)((int)((int)calculate_from)/interval + 1)*interval);

	SIPE_DEBUG_INFO("sipe_sched_calendar_status_self_publish: calculate_from time: %s",
			sipe_utils_time_to_debug_str(localtime(&calculate_from)));
	SIPE_DEBUG_INFO("sipe_sched_calendar_status_self_publish: next start time    : %s",
			sipe_utils_time_to_debug_str(localtime(&next_start)));

	sipe_schedule_seconds(sipe_private,
			      "<+2007-cal-status>",
			      NULL,
			      next_start - time(NULL),
			      sipe_ocs2007_presence_publish,
			      NULL);
}

/**
 * An availability XML entry for SIPE_PUB_XML_STATE_CALENDAR
 * @param availability		(%d) Ex.: 6500
 */
#define SIPE_PUB_XML_STATE_CALENDAR_AVAIL \
"<availability>%d</availability>"
/**
 * An activity XML entry for SIPE_PUB_XML_STATE_CALENDAR
 * @param token			(%s) Ex.: in-a-meeting
 * @param minAvailability_attr	(%s) Ex.: minAvailability="6500"
 * @param maxAvailability_attr	(%s) Ex.: maxAvailability="8999" or none
 */
#define SIPE_PUB_XML_STATE_CALENDAR_ACTIVITY \
"<activity token=\"%s\" %s %s></activity>"
/**
 * Publishes 'calendarState' category.
 * @param instance		(%u) Ex.: 1339299275
 * @param version		(%u) Ex.: 1
 * @param uri			(%s) Ex.: john@contoso.com
 * @param start_time_str	(%s) Ex.: 2008-01-11T19:00:00Z
 * @param availability		(%s) XML string as SIPE_PUB_XML_STATE_CALENDAR_AVAIL
 * @param activity		(%s) XML string as SIPE_PUB_XML_STATE_CALENDAR_ACTIVITY
 * @param meeting_subject	(%s) Ex.: Customer Meeting
 * @param meeting_location	(%s) Ex.: Conf Room 100
 *
 * @param instance		(%u) Ex.: 1339299275
 * @param version		(%u) Ex.: 1
 * @param uri			(%s) Ex.: john@contoso.com
 * @param start_time_str	(%s) Ex.: 2008-01-11T19:00:00Z
 * @param availability		(%s) XML string as SIPE_PUB_XML_STATE_CALENDAR_AVAIL
 * @param activity		(%s) XML string as SIPE_PUB_XML_STATE_CALENDAR_ACTIVITY
 * @param meeting_subject	(%s) Ex.: Customer Meeting
 * @param meeting_location	(%s) Ex.: Conf Room 100
 */
#define SIPE_PUB_XML_STATE_CALENDAR \
	"<publication categoryName=\"state\" instance=\"%u\" container=\"2\" version=\"%u\" expireType=\"endpoint\">"\
		"<state xmlns=\"http://schemas.microsoft.com/2006/09/sip/state\" manual=\"false\" uri=\"%s\" startTime=\"%s\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"calendarState\">"\
			"%s"\
			"%s"\
			"<endpointLocation/>"\
			"<meetingSubject>%s</meetingSubject>"\
			"<meetingLocation>%s</meetingLocation>"\
		"</state>"\
	"</publication>"\
	"<publication categoryName=\"state\" instance=\"%u\" container=\"3\" version=\"%u\" expireType=\"endpoint\">"\
		"<state xmlns=\"http://schemas.microsoft.com/2006/09/sip/state\" manual=\"false\" uri=\"%s\" startTime=\"%s\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"calendarState\">"\
			"%s"\
			"%s"\
			"<endpointLocation/>"\
			"<meetingSubject>%s</meetingSubject>"\
			"<meetingLocation>%s</meetingLocation>"\
		"</state>"\
	"</publication>"
/**
 * Publishes to clear 'calendarState' and 'phoneState' category
 * @param instance		(%u) Ex.: 1251210982
 * @param version		(%u) Ex.: 1
 */
#define SIPE_PUB_XML_STATE_CALENDAR_PHONE_CLEAR \
	"<publication categoryName=\"state\" instance=\"%u\" container=\"2\" version=\"%u\" expireType=\"endpoint\" expires=\"0\"/>"\
	"<publication categoryName=\"state\" instance=\"%u\" container=\"3\" version=\"%u\" expireType=\"endpoint\" expires=\"0\"/>"

/**
 * Publishes to clear any category
 * @param category_name		(%s) Ex.: state
 * @param instance		(%u) Ex.: 536870912
 * @param container		(%u) Ex.: 3
 * @param version		(%u) Ex.: 1
 * @param expireType		(%s) Ex.: static
 */
#define SIPE_PUB_XML_PUBLICATION_CLEAR \
	"<publication categoryName=\"%s\" instance=\"%u\" container=\"%u\" version=\"%u\" expireType=\"%s\" expires=\"0\"/>"

/**
 * Publishes 'note' category.
 * @param instance		(%u) Ex.: 2135971629; 0 for personal
 * @param container		(%u) Ex.: 200
 * @param version		(%u) Ex.: 2
 * @param type			(%s) Ex.: personal or OOF
 * @param startTime_attr	(%s) Ex.: startTime="2008-01-11T19:00:00Z"
 * @param endTime_attr		(%s) Ex.: endTime="2008-01-15T19:00:00Z"
 * @param body			(%s) Ex.: In the office
 */
#define SIPE_PUB_XML_NOTE \
	"<publication categoryName=\"note\" instance=\"%u\" container=\"%u\" version=\"%d\" expireType=\"static\">"\
		"<note xmlns=\"http://schemas.microsoft.com/2006/09/sip/note\">"\
			"<body type=\"%s\" uri=\"\"%s%s>%s</body>"\
		"</note>"\
	"</publication>"
/**
 * Publishes 'phoneState' category.
 * @param instance		(%u) Ex.: 1339299275
 * @param version		(%u) Ex.: 1
 * @param availability		(%u) Ex.: 6500
 * @param token			(%s) Ex.: on-the-phone
 * @param minAvailability	(%u) generally same as availability
 *
 * @param instance		(%u) Ex.: 1339299275
 * @param version		(%u) Ex.: 1
 * @param availability          (%u) Ex.: 6500
 * @param token			(%s) Ex.: on-the-phone
 * @param minAvailability	(%u) generally same as availability
 */
#define SIPE_PUB_XML_STATE_PHONE \
	"<publication categoryName=\"state\" instance=\"%u\" container=\"2\" version=\"%u\" expireType=\"endpoint\">"\
		"<state xmlns=\"http://schemas.microsoft.com/2006/09/sip/state\" manual=\"false\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"phoneState\">"\
			"<availability>%u</availability>"\
			"<activity token=\"%s\" minAvailability=\"%u\" maxAvailability=\"%u\"/>"\
		"</state>"\
	"</publication>"\
	"<publication categoryName=\"state\" instance=\"%u\" container=\"3\" version=\"%u\" expireType=\"endpoint\">"\
		"<state xmlns=\"http://schemas.microsoft.com/2006/09/sip/state\" manual=\"false\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"phoneState\">"\
			"<availability>%u</availability>"\
			"<activity token=\"%s\" minAvailability=\"%u\" maxAvailability=\"%u\"/>"\
		"</state>"\
	"</publication>"

/**
 * Only Busy and OOF calendar event are published.
 * Different instances are used for that.
 *
 * Must be g_free'd after use.
 */
static gchar *sipe_publish_get_category_state_calendar(struct sipe_core_private *sipe_private,
						       struct sipe_cal_event *event,
						       const char *uri,
						       int cal_satus)
{
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
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "state"), key_2);
	struct sipe_publication *publication_3 =
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "state"), key_3);

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
		gchar *escaped_subject  = event->subject  ? g_markup_escape_text(event->subject,  -1) : NULL;
		gchar *escaped_location = event->location ? g_markup_escape_text(event->location, -1) : NULL;

		if (event->cal_status == SIPE_CAL_BUSY) {
			availability_xml_str = g_strdup_printf(SIPE_PUB_XML_STATE_CALENDAR_AVAIL,
							       SIPE_OCS2007_AVAILABILITY_BUSY);
		}

		if (event->cal_status == SIPE_CAL_BUSY && event->is_meeting) {
			activity_xml_str = g_strdup_printf(SIPE_PUB_XML_STATE_CALENDAR_ACTIVITY,
							   sipe_status_activity_to_token(SIPE_ACTIVITY_IN_MEETING),
							   "minAvailability=\"6500\"",
							   "maxAvailability=\"8999\"");
		} else if (event->cal_status == SIPE_CAL_OOF) {
			activity_xml_str = g_strdup_printf(SIPE_PUB_XML_STATE_CALENDAR_ACTIVITY,
							   sipe_status_activity_to_token(SIPE_ACTIVITY_OOF),
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
					escaped_subject  ? escaped_subject  : "",
					escaped_location ? escaped_location : "",

					instance,
					publication_3 ? publication_3->version : 0,
					uri,
					start_time_str,
					availability_xml_str ? availability_xml_str : "",
					activity_xml_str ? activity_xml_str : "",
					escaped_subject  ? escaped_subject  : "",
					escaped_location ? escaped_location : ""
					);
		g_free(escaped_location);
		g_free(escaped_subject);
		g_free(start_time_str);
		g_free(availability_xml_str);
		g_free(activity_xml_str);

	}
	else /* including !event, SIPE_CAL_FREE, SIPE_CAL_TENTATIVE */
	{
		res = g_strdup_printf(SIPE_PUB_XML_STATE_CALENDAR_PHONE_CLEAR,
					instance,
					publication_2 ? publication_2->version : 0,

					instance,
					publication_3 ? publication_3->version : 0
					);
	}

	return res;
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
static gchar *sipe_publish_get_category_note(struct sipe_core_private *sipe_private,
					     const char *note, /* html */
					     const char *note_type,
					     time_t note_start,
					     time_t note_end,
					     gboolean force_publish)
{
	guint instance = sipe_strequal("OOF", note_type) ? sipe_get_pub_instance(sipe_private, SIPE_PUB_NOTE_OOF) : 0;
	/* key is <category><instance><container> */
	gchar *key_note_200 = g_strdup_printf("<%s><%u><%u>", "note", instance, 200);
	gchar *key_note_300 = g_strdup_printf("<%s><%u><%u>", "note", instance, 300);
	gchar *key_note_400 = g_strdup_printf("<%s><%u><%u>", "note", instance, 400);

	struct sipe_publication *publication_note_200 =
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "note"), key_note_200);
	struct sipe_publication *publication_note_300 =
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "note"), key_note_300);
	struct sipe_publication *publication_note_400 =
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "note"), key_note_400);

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
	if (!force_publish && sipe_strequal(n1, n2))
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
 * Publishes 'calendarData' category's WorkingHours.
 *
 * @param version	        (%u)  Ex.: 1
 * @param email	                (%s)  Ex.: alice@cosmo.local
 * @param working_hours_xml_str	(%s)  Ex.: <WorkingHours xmlns=.....
 *
 * @param version	        (%u)
 *
 * @param version	        (%u)
 * @param email	                (%s)
 * @param working_hours_xml_str	(%s)
 *
 * @param version	        (%u)
 * @param email	                (%s)
 * @param working_hours_xml_str	(%s)
 *
 * @param version	        (%u)
 * @param email	                (%s)
 * @param working_hours_xml_str	(%s)
 *
 * @param version	        (%u)
 */
#define SIPE_PUB_XML_WORKING_HOURS \
	"<publication categoryName=\"calendarData\" instance=\"0\" container=\"1\" version=\"%d\" expireType=\"static\">"\
		"<calendarData xmlns=\"http://schemas.microsoft.com/2006/09/sip/calendarData\" mailboxID=\"%s\">%s"\
		"</calendarData>"\
	"</publication>"\
	"<publication categoryName=\"calendarData\" instance=\"0\" container=\"100\" version=\"%d\" expireType=\"static\">"\
		"<calendarData xmlns=\"http://schemas.microsoft.com/2006/09/sip/calendarData\"/>"\
	"</publication>"\
	"<publication categoryName=\"calendarData\" instance=\"0\" container=\"200\" version=\"%d\" expireType=\"static\">"\
		"<calendarData xmlns=\"http://schemas.microsoft.com/2006/09/sip/calendarData\" mailboxID=\"%s\">%s"\
		"</calendarData>"\
	"</publication>"\
	"<publication categoryName=\"calendarData\" instance=\"0\" container=\"300\" version=\"%d\" expireType=\"static\">"\
		"<calendarData xmlns=\"http://schemas.microsoft.com/2006/09/sip/calendarData\" mailboxID=\"%s\">%s"\
		"</calendarData>"\
	"</publication>"\
	"<publication categoryName=\"calendarData\" instance=\"0\" container=\"400\" version=\"%d\" expireType=\"static\">"\
		"<calendarData xmlns=\"http://schemas.microsoft.com/2006/09/sip/calendarData\" mailboxID=\"%s\">%s"\
		"</calendarData>"\
	"</publication>"\
	"<publication categoryName=\"calendarData\" instance=\"0\" container=\"32000\" version=\"%d\" expireType=\"static\">"\
		"<calendarData xmlns=\"http://schemas.microsoft.com/2006/09/sip/calendarData\"/>"\
	"</publication>"

/**
 * Returns 'calendarData' XML part with WorkingHours for publication.
 * Must be g_free'd after use.
 */
static gchar *sipe_publish_get_category_cal_working_hours(struct sipe_core_private *sipe_private)
{
	struct sipe_calendar* cal = sipe_private->calendar;

	/* key is <category><instance><container> */
	gchar *key_cal_1     = g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 1);
	gchar *key_cal_100   = g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 100);
	gchar *key_cal_200   = g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 200);
	gchar *key_cal_300   = g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 300);
	gchar *key_cal_400   = g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 400);
	gchar *key_cal_32000 = g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 32000);

	struct sipe_publication *publication_cal_1 =
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "calendarData"), key_cal_1);
	struct sipe_publication *publication_cal_100 =
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "calendarData"), key_cal_100);
	struct sipe_publication *publication_cal_200 =
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "calendarData"), key_cal_200);
	struct sipe_publication *publication_cal_300 =
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "calendarData"), key_cal_300);
	struct sipe_publication *publication_cal_400 =
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "calendarData"), key_cal_400);
	struct sipe_publication *publication_cal_32000 =
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "calendarData"), key_cal_32000);

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
 * Publishes 'calendarData' category's FreeBusy.
 *
 * @param instance	        (%u)  Ex.: 1300372959
 * @param version	        (%u)  Ex.: 1
 *
 * @param instance	        (%u)  Ex.: 1300372959
 * @param version	        (%u)  Ex.: 1
 *
 * @param instance	        (%u)  Ex.: 1300372959
 * @param version	        (%u)  Ex.: 1
 * @param email	                (%s)  Ex.: alice@cosmo.local
 * @param fb_start_time_str	(%s)  Ex.: 2009-12-03T00:00:00Z
 * @param free_busy_base64	(%s)  Ex.: AAAAAAAAAAAAAAAAAAAAA.....
 *
 * @param instance	        (%u)  Ex.: 1300372959
 * @param version	        (%u)  Ex.: 1
 * @param email	                (%s)  Ex.: alice@cosmo.local
 * @param fb_start_time_str	(%s)  Ex.: 2009-12-03T00:00:00Z
 * @param free_busy_base64	(%s)  Ex.: AAAAAAAAAAAAAAAAAAAAA.....
 *
 * @param instance	        (%u)  Ex.: 1300372959
 * @param version	        (%u)  Ex.: 1
 * @param email	                (%s)  Ex.: alice@cosmo.local
 * @param fb_start_time_str	(%s)  Ex.: 2009-12-03T00:00:00Z
 * @param free_busy_base64	(%s)  Ex.: AAAAAAAAAAAAAAAAAAAAA.....
 *
 * @param instance	        (%u)  Ex.: 1300372959
 * @param version	        (%u)  Ex.: 1
 */
#define SIPE_PUB_XML_FREE_BUSY \
	"<publication categoryName=\"calendarData\" instance=\"%u\" container=\"1\" version=\"%d\" expireType=\"endpoint\">"\
		"<calendarData xmlns=\"http://schemas.microsoft.com/2006/09/sip/calendarData\"/>"\
	"</publication>"\
	"<publication categoryName=\"calendarData\" instance=\"%u\" container=\"100\" version=\"%d\" expireType=\"endpoint\">"\
		"<calendarData xmlns=\"http://schemas.microsoft.com/2006/09/sip/calendarData\"/>"\
	"</publication>"\
	"<publication categoryName=\"calendarData\" instance=\"%u\" container=\"200\" version=\"%d\" expireType=\"endpoint\">"\
		"<calendarData xmlns=\"http://schemas.microsoft.com/2006/09/sip/calendarData\" mailboxID=\"%s\">"\
			"<freeBusy startTime=\"%s\" granularity=\"PT15M\" encodingVersion=\"1\">%s</freeBusy>"\
		"</calendarData>"\
	"</publication>"\
	"<publication categoryName=\"calendarData\" instance=\"%u\" container=\"300\" version=\"%d\" expireType=\"endpoint\">"\
		"<calendarData xmlns=\"http://schemas.microsoft.com/2006/09/sip/calendarData\" mailboxID=\"%s\">"\
			"<freeBusy startTime=\"%s\" granularity=\"PT15M\" encodingVersion=\"1\">%s</freeBusy>"\
		"</calendarData>"\
	"</publication>"\
	"<publication categoryName=\"calendarData\" instance=\"%u\" container=\"400\" version=\"%d\" expireType=\"endpoint\">"\
		"<calendarData xmlns=\"http://schemas.microsoft.com/2006/09/sip/calendarData\" mailboxID=\"%s\">"\
			"<freeBusy startTime=\"%s\" granularity=\"PT15M\" encodingVersion=\"1\">%s</freeBusy>"\
		"</calendarData>"\
	"</publication>"\
	"<publication categoryName=\"calendarData\" instance=\"%u\" container=\"32000\" version=\"%d\" expireType=\"endpoint\">"\
		"<calendarData xmlns=\"http://schemas.microsoft.com/2006/09/sip/calendarData\"/>"\
	"</publication>"

/**
 * Returns 'calendarData' XML part with FreeBusy for publication.
 * Must be g_free'd after use.
 */
static gchar *sipe_publish_get_category_cal_free_busy(struct sipe_core_private *sipe_private)
{
	struct sipe_calendar* cal = sipe_private->calendar;
	guint cal_data_instance = sipe_get_pub_instance(sipe_private, SIPE_PUB_CALENDAR_DATA);
	char *fb_start_str;
	char *free_busy_base64;
	/* const char *st; */
	/* const char *fb; */
	char *res;

	/* key is <category><instance><container> */
	gchar *key_cal_1     = g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 1);
	gchar *key_cal_100   = g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 100);
	gchar *key_cal_200   = g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 200);
	gchar *key_cal_300   = g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 300);
	gchar *key_cal_400   = g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 400);
	gchar *key_cal_32000 = g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 32000);

	struct sipe_publication *publication_cal_1 =
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "calendarData"), key_cal_1);
	struct sipe_publication *publication_cal_100 =
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "calendarData"), key_cal_100);
	struct sipe_publication *publication_cal_200 =
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "calendarData"), key_cal_200);
	struct sipe_publication *publication_cal_300 =
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "calendarData"), key_cal_300);
	struct sipe_publication *publication_cal_400 =
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "calendarData"), key_cal_400);
	struct sipe_publication *publication_cal_32000 =
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "calendarData"), key_cal_32000);

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

	/* we will rebuplish the same data to refresh publication time,
	 * so if data from multiple sources, most recent will be choosen
	 */
	// st = publication_cal_300 ? publication_cal_300->fb_start_str : NULL;
	// fb = publication_cal_300 ? publication_cal_300->free_busy_base64 : NULL;
	//
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

#ifdef HAVE_VV
#define SIPE_PUB_XML_DEVICE_VV \
				"<voice capture=\"true\" render=\"true\" publish=\"false\"/>"\
				"<video capture=\"true\" render=\"true\" publish=\"false\"/>"
#else
#define SIPE_PUB_XML_DEVICE_VV
#endif

#ifdef HAVE_FREERDP
#define SIPE_PUB_XML_DEVICE_APPSHARE \
				"<applicationSharing capture=\"true\" render=\"true\" publish=\"false\"/>"\
				"<contentPowerPoint capture=\"true\" render=\"true\" publish=\"false\"/>"
#else
#define SIPE_PUB_XML_DEVICE_APPSHARE
#endif

/**
 * Publishes 'device' category.
 * @param instance	(%u) Ex.: 1938468728
 * @param version	(%u) Ex.: 1
 * @param endpointId	(%s) Ex.: C707E38E-1E10-5413-94D9-ECAC260A0269
 * @param uri		(%s) Self URI. Ex.: sip:alice7@boston.local
 * @param timezone	(%s) Ex.: 00:00:00+01:00
 * @param machineName	(%s) Ex.: BOSTON-OCS07
 */
#define SIPE_PUB_XML_DEVICE \
	"<publication categoryName=\"device\" instance=\"%u\" container=\"2\" version=\"%u\" expireType=\"endpoint\">"\
		"<device xmlns=\"http://schemas.microsoft.com/2006/09/sip/device\" endpointId=\"%s\">"\
			"<capabilities preferred=\"false\" uri=\"%s\">"\
				"<text capture=\"true\" render=\"true\" publish=\"false\"/>"\
				"<gifInk capture=\"false\" render=\"true\" publish=\"false\"/>"\
				"<isfInk capture=\"false\" render=\"true\" publish=\"false\"/>"\
				SIPE_PUB_XML_DEVICE_VV\
				SIPE_PUB_XML_DEVICE_APPSHARE\
			"</capabilities>"\
			"<timezone>%s</timezone>"\
			"<machineName>%s</machineName>"\
		"</device>"\
	"</publication>"

/**
 * Returns 'device' XML part for publication.
 * Must be g_free'd after use.
 */
static gchar *sipe_publish_get_category_device(struct sipe_core_private *sipe_private)
{
	gchar *uri;
	gchar *doc;
	gchar *uuid = get_uuid(sipe_private);
	guint device_instance = sipe_get_pub_instance(sipe_private, SIPE_PUB_DEVICE);
	/* key is <category><instance><container> */
	gchar *key = g_strdup_printf("<%s><%u><%u>", "device", device_instance, 2);
	GHashTable *tmp = g_hash_table_lookup(sipe_private->our_publications, "device");
	struct sipe_publication *publication = tmp ? g_hash_table_lookup(tmp, key) : NULL;

	g_free(key);

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
 * Publishes 'machineState' category.
 * @param instance	(%u) Ex.: 926460663
 * @param version	(%u) Ex.: 22
 * @param availability	(%d) Ex.: 3500
 * @param instance	(%u) Ex.: 926460663
 * @param version	(%u) Ex.: 22
 * @param availability	(%d) Ex.: 3500
 */
#define SIPE_PUB_XML_STATE_MACHINE \
	"<publication categoryName=\"state\" instance=\"%u\" container=\"2\" version=\"%u\" expireType=\"endpoint\">"\
		"<state xmlns=\"http://schemas.microsoft.com/2006/09/sip/state\" manual=\"false\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"machineState\">"\
			"<availability>%d</availability>"\
			"<endpointLocation/>"\
		"</state>"\
	"</publication>"\
	"<publication categoryName=\"state\" instance=\"%u\" container=\"3\" version=\"%u\" expireType=\"endpoint\">"\
		"<state xmlns=\"http://schemas.microsoft.com/2006/09/sip/state\" manual=\"false\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"machineState\">"\
			"<availability>%d</availability>"\
			"<endpointLocation/>"\
		"</state>"\
	"</publication>"

/**
 * Publishes 'userState' category.
 * @param instance	(%u) User. Ex.: 536870912
 * @param version	(%u) User Container 2. Ex.: 22
 * @param availability	(%d) User Container 2. Ex.: 15500
 * @param instance	(%u) User. Ex.: 536870912
 * @param version	(%u) User Container 3.Ex.: 22
 * @param availability	(%d) User Container 3. Ex.: 15500
 */
#define SIPE_PUB_XML_STATE_USER \
	"<publication categoryName=\"state\" instance=\"%u\" container=\"2\" version=\"%u\" expireType=\"static\">"\
		"<state xmlns=\"http://schemas.microsoft.com/2006/09/sip/state\" manual=\"true\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"userState\">"\
			"<availability>%d</availability>"\
			"<endpointLocation/>"\
		"</state>"\
	"</publication>"\
	"<publication categoryName=\"state\" instance=\"%u\" container=\"3\" version=\"%u\" expireType=\"static\">"\
		"<state xmlns=\"http://schemas.microsoft.com/2006/09/sip/state\" manual=\"true\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"userState\">"\
			"<availability>%d</availability>"\
			"<endpointLocation/>"\
		"</state>"\
	"</publication>"

/**
 * A service method - use
 * - send_publish_get_category_state_machine and
 * - send_publish_get_category_state_user instead.
 * Must be g_free'd after use.
 */
static gchar *sipe_publish_get_category_state(struct sipe_core_private *sipe_private,
					      gboolean force_publish,
					      gboolean is_user_state)
{
	int availability = sipe_ocs2007_availability_from_status(sipe_private->status, NULL);
	guint instance = is_user_state ? sipe_get_pub_instance(sipe_private, SIPE_PUB_STATE_USER) :
					 sipe_get_pub_instance(sipe_private, SIPE_PUB_STATE_MACHINE);
	/* key is <category><instance><container> */
	gchar *key_2 = g_strdup_printf("<%s><%u><%u>", "state", instance, 2);
	gchar *key_3 = g_strdup_printf("<%s><%u><%u>", "state", instance, 3);
	struct sipe_publication *publication_2 =
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "state"), key_2);
	struct sipe_publication *publication_3 =
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "state"), key_3);

	g_free(key_2);
	g_free(key_3);

	if (!force_publish && publication_2 && (publication_2->availability == availability))
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
 * Returns 'machineState' XML part for publication.
 * Must be g_free'd after use.
 */
static gchar *sipe_publish_get_category_state_machine(struct sipe_core_private *sipe_private,
						      gboolean force_publish)
{
	return sipe_publish_get_category_state(sipe_private, force_publish, FALSE);
}

/**
 * Returns 'userState' XML part for publication.
 * Must be g_free'd after use.
 */
static gchar *sipe_publish_get_category_state_user(struct sipe_core_private *sipe_private,
						   gboolean force_publish)
{
	return sipe_publish_get_category_state(sipe_private, force_publish, TRUE);
}

static void send_publish_category_initial(struct sipe_core_private *sipe_private)
{
	gchar *pub_device   = sipe_publish_get_category_device(sipe_private);
	gchar *pub_machine;
	gchar *pub_user;
	gchar *publications;

	sipe_status_set_activity(sipe_private,
				 sipe_backend_status(SIPE_CORE_PUBLIC));

	pub_machine  = sipe_publish_get_category_state_machine(sipe_private,
							       TRUE);
	pub_user = sipe_publish_get_category_state_user(sipe_private, TRUE);

	publications = g_strdup_printf("%s%s%s",
				       pub_device,
				       pub_machine ? pub_machine : "",
				       pub_user ? pub_user : "");
	g_free(pub_device);
	g_free(pub_machine);
	g_free(pub_user);

	send_presence_publish(sipe_private, publications);
	g_free(publications);
}

static gboolean process_send_presence_category_publish_response(struct sipe_core_private *sipe_private,
								struct sipmsg *msg,
								struct transaction *trans)
{
	const gchar *contenttype = sipmsg_find_header(msg, "Content-Type");

	if (msg->response == 200 && g_str_has_prefix(contenttype, "application/vnd-microsoft-roaming-self+xml")) {
		sipe_ocs2007_process_roaming_self(sipe_private, msg);
	} else if (msg->response == 409 && g_str_has_prefix(contenttype, "application/msrtc-fault+xml")) {
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

		/* here we are parsing our own request to figure out what publication
		 * referenced here only by index went wrong
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
				const gchar *container = sipe_xml_attribute(node, "container");
				const gchar *instance = sipe_xml_attribute(node, "instance");
				/* key is <category><instance><container> */
				gchar *key = g_strdup_printf("<%s><%s><%s>", categoryName, instance, container);
				GHashTable *category = g_hash_table_lookup(sipe_private->our_publications, categoryName);

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
					g_hash_table_insert(sipe_private->our_publications, g_strdup(categoryName), category);
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
			sipe_ocs2007_category_publish(sipe_private, TRUE);
		}
	}
	return TRUE;
}

/**
 * Publishes categories.
 * @param uri		(%s) Self URI. Ex.: sip:alice7@boston.local
 * @param publications	(%s) XML publications
 */
#define SIPE_SEND_PRESENCE \
	"<publish xmlns=\"http://schemas.microsoft.com/2006/09/sip/rich-presence\">"\
		"<publications uri=\"%s\">"\
			"%s"\
		"</publications>"\
	"</publish>"

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

/**
 * Publishes self status
 * based on own calendar information.
 */
void sipe_ocs2007_presence_publish(struct sipe_core_private *sipe_private,
				   SIPE_UNUSED_PARAMETER void *unused)
{
	struct sipe_calendar* cal = sipe_private->calendar;
	struct sipe_cal_event* event = NULL;
	gchar *pub_cal_working_hours = NULL;
	gchar *pub_cal_free_busy = NULL;
	gchar *pub_calendar = NULL;
	gchar *pub_calendar2 = NULL;
	gchar *pub_oof_note = NULL;
	const gchar *oof_note;
	time_t oof_start = 0;
	time_t oof_end = 0;

	if (!cal) {
		SIPE_DEBUG_INFO_NOFORMAT("publish_calendar_status_self() no calendar data.");
		return;
	}

	SIPE_DEBUG_INFO_NOFORMAT("publish_calendar_status_self() started.");
	if (cal->cal_events) {
		event = sipe_cal_get_event(cal->cal_events, time(NULL));
	}

	if (event) {
		sipe_cal_event_debug(event, "publish_calendar_status_self: current event is:\n");
	} else {
		SIPE_DEBUG_INFO_NOFORMAT("publish_calendar_status_self: current event is NULL");
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
		pub_calendar  = sipe_publish_get_category_state_calendar(sipe_private, event, cal->email, SIPE_CAL_OOF);
		pub_calendar2 = sipe_publish_get_category_state_calendar(sipe_private, NULL,  cal->email, SIPE_CAL_BUSY);
	} else if (event && event->cal_status == SIPE_CAL_BUSY) {
		pub_calendar  = sipe_publish_get_category_state_calendar(sipe_private, NULL,  cal->email, SIPE_CAL_OOF);
		pub_calendar2 = sipe_publish_get_category_state_calendar(sipe_private, event, cal->email, SIPE_CAL_BUSY);
	} else {
		pub_calendar  = sipe_publish_get_category_state_calendar(sipe_private, NULL,  cal->email, SIPE_CAL_OOF);
		pub_calendar2 = sipe_publish_get_category_state_calendar(sipe_private, NULL,  cal->email, SIPE_CAL_BUSY);
	}

	oof_note = sipe_ews_get_oof_note(cal);
	if (sipe_strequal("Scheduled", cal->oof_state)) {
		oof_start = cal->oof_start;
		oof_end = cal->oof_end;
	}
	pub_oof_note = sipe_publish_get_category_note(sipe_private, oof_note, "OOF", oof_start, oof_end, FALSE);

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
	schedule_publish_update(sipe_private, time(NULL));
}

void sipe_ocs2007_category_publish(struct sipe_core_private *sipe_private,
				   gboolean force_publish)
{
	GString *publications = g_string_new("");
	gchar *tmp;

	if (force_publish || sipe_private->status_set_by_user) {
		tmp = sipe_publish_get_category_state_user(sipe_private,
							   force_publish);
		if (tmp) {
			g_string_append(publications, tmp);
			g_free(tmp);
		}
	}

	tmp = sipe_publish_get_category_state_machine(sipe_private,
						      force_publish);
	if (tmp) {
		g_string_append(publications, tmp);
		g_free(tmp);
	}

	tmp = sipe_publish_get_category_note(sipe_private,
					     sipe_private->note,
					     SIPE_CORE_PRIVATE_FLAG_IS(OOF_NOTE) ? "OOF" : "personal",
					     0,
					     0,
					     force_publish);
	if (tmp) {
		g_string_append(publications, tmp);
		g_free(tmp);
	}

	if (publications->len)
		send_presence_publish(sipe_private, publications->str);
	else
		SIPE_DEBUG_INFO_NOFORMAT("sipe_osc2007_category_publish: nothing has changed. Exiting.");

	g_string_free(publications, TRUE);
}

void sipe_ocs2007_phone_state_publish(struct sipe_core_private *sipe_private)
{
	gchar *publications = NULL;
	guint instance = sipe_get_pub_instance(sipe_private, SIPE_PUB_STATE_PHONE_VOIP);

	/* key is <category><instance><container> */
	gchar *key_2 = g_strdup_printf("<%s><%u><%u>", "state", instance, 2);
	gchar *key_3 = g_strdup_printf("<%s><%u><%u>", "state", instance, 3);
	struct sipe_publication *publication_2 =
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "state"), key_2);
	struct sipe_publication *publication_3 =
		g_hash_table_lookup(g_hash_table_lookup(sipe_private->our_publications, "state"), key_3);
	g_free(key_2);
	g_free(key_3);

#ifdef HAVE_VV
	if (g_hash_table_size(sipe_private->media_calls)) {
		guint availability_min = 0;
		guint availability_max = 8999;
		const gchar *token = NULL;
		GList *calls;

		if (sipe_core_media_get_call(SIPE_CORE_PUBLIC)) {
			availability_min = 6500;
			token = sipe_status_activity_to_token(SIPE_ACTIVITY_ON_PHONE);
		}

		calls = g_hash_table_get_values(sipe_private->media_calls);
		for (; calls; calls = g_list_delete_link(calls, calls)) {
			if (sipe_media_is_conference_call(calls->data)) {
				availability_min = 7000;
				token = sipe_status_activity_to_token(SIPE_ACTIVITY_IN_CONF);
			}

			if (sipe_appshare_get_role(calls->data) == SIPE_APPSHARE_ROLE_PRESENTER) {
				availability_min = 9000;
				availability_max = 11999;
				token = "in-presentation";
			}
		}

		if (token) {
			publications = g_strdup_printf(SIPE_PUB_XML_STATE_PHONE,
					instance, publication_2 ? publication_2->version : 0,
					availability_min, token, availability_min, availability_max,
					instance, publication_3 ? publication_3->version : 0,
					availability_min, token, availability_min, availability_max);
		}
	} else
#endif
	{
		publications = g_strdup_printf(SIPE_PUB_XML_STATE_CALENDAR_PHONE_CLEAR,
				instance, publication_2 ? publication_2->version : 0,
				instance, publication_3 ? publication_3->version : 0);
	}

	if (publications) {
		send_presence_publish(sipe_private, publications);
		g_free(publications);
	}
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

void sipe_ocs2007_reset_status(struct sipe_core_private *sipe_private)
{
	GString* str;
	gchar *publications;

	if (!sipe_private->user_state_publications || g_hash_table_size(sipe_private->user_state_publications) == 0) {
		SIPE_DEBUG_INFO_NOFORMAT("sipe_reset_status: no userState publications, exiting.");
		return;
	}

	str = g_string_new(NULL);
	g_hash_table_foreach(sipe_private->user_state_publications, (GHFunc)sipe_publish_get_cat_state_user_to_clear, str);
	publications = g_string_free(str, FALSE);

	send_presence_publish(sipe_private, publications);
	g_free(publications);
}

/* key is <category><instance><container> */
static gboolean sipe_is_our_publication(struct sipe_core_private *sipe_private,
					const gchar *key)
{
	GSList *entry;

	/* filling keys for our publications if not yet cached */
	if (!sipe_private->our_publication_keys) {
		guint device_instance	  = sipe_get_pub_instance(sipe_private, SIPE_PUB_DEVICE);
		guint machine_instance	  = sipe_get_pub_instance(sipe_private, SIPE_PUB_STATE_MACHINE);
		guint user_instance	  = sipe_get_pub_instance(sipe_private, SIPE_PUB_STATE_USER);
		guint calendar_instance	  = sipe_get_pub_instance(sipe_private, SIPE_PUB_STATE_CALENDAR);
		guint cal_oof_instance	  = sipe_get_pub_instance(sipe_private, SIPE_PUB_STATE_CALENDAR_OOF);
		guint phone_voip_instance = sipe_get_pub_instance(sipe_private, SIPE_PUB_STATE_PHONE_VOIP);
		guint cal_data_instance	  = sipe_get_pub_instance(sipe_private, SIPE_PUB_CALENDAR_DATA);
		guint note_oof_instance	  = sipe_get_pub_instance(sipe_private, SIPE_PUB_NOTE_OOF);

		SIPE_DEBUG_INFO_NOFORMAT("* Our Publication Instances *");
		SIPE_DEBUG_INFO("\tDevice               : %u\t0x%08X", device_instance, device_instance);
		SIPE_DEBUG_INFO("\tMachine State        : %u\t0x%08X", machine_instance, machine_instance);
		SIPE_DEBUG_INFO("\tUser Stare           : %u\t0x%08X", user_instance, user_instance);
		SIPE_DEBUG_INFO("\tCalendar State       : %u\t0x%08X", calendar_instance, calendar_instance);
		SIPE_DEBUG_INFO("\tCalendar OOF State   : %u\t0x%08X", cal_oof_instance, cal_oof_instance);
		SIPE_DEBUG_INFO("\tVOIP Phone State     : %u\t0x%08X", phone_voip_instance, phone_voip_instance);
		SIPE_DEBUG_INFO("\tCalendar FreeBusy    : %u\t0x%08X", cal_data_instance, cal_data_instance);
		SIPE_DEBUG_INFO("\tOOF Note             : %u\t0x%08X", note_oof_instance, note_oof_instance);
		SIPE_DEBUG_INFO("\tNote                 : %u", 0);
		SIPE_DEBUG_INFO("\tCalendar WorkingHours: %u", 0);

		/* device */
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "device", device_instance, 2));

		/* state:machineState */
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "state", machine_instance, 2));
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "state", machine_instance, 3));

		/* state:userState */
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "state", user_instance, 2));
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "state", user_instance, 3));

		/* state:calendarState */
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "state", calendar_instance, 2));
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "state", calendar_instance, 3));

		/* state:calendarState OOF */
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "state", cal_oof_instance, 2));
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "state", cal_oof_instance, 3));

		/* state:phoneState */
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "state", phone_voip_instance, 2));
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "state", phone_voip_instance, 3));

		/* note */
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "note", 0, 200));
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "note", 0, 300));
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "note", 0, 400));

		/* note OOF */
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "note", note_oof_instance, 200));
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "note", note_oof_instance, 300));
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "note", note_oof_instance, 400));

		/* calendarData:WorkingHours */
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 1));
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 100));
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 200));
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 300));
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 400));
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", 0, 32000));

		/* calendarData:FreeBusy */
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 1));
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 100));
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 200));
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 300));
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 400));
		sipe_private->our_publication_keys = g_slist_append(sipe_private->our_publication_keys,
			g_strdup_printf("<%s><%u><%u>", "calendarData", cal_data_instance, 32000));

		//SIPE_DEBUG_INFO("sipe_is_our_publication: sipe_private->our_publication_keys length=%d",
		//	  sipe_private->our_publication_keys ? (int) g_slist_length(sipe_private->our_publication_keys) : -1);
	}

	//SIPE_DEBUG_INFO("sipe_is_our_publication: key=%s", key);

	entry = sipe_private->our_publication_keys;
	while (entry) {
		//SIPE_DEBUG_INFO("   sipe_is_our_publication: entry->data=%s", entry->data);
		if (sipe_strequal(entry->data, key)) {
			return TRUE;
		}
		entry = entry->next;
	}
	return FALSE;
}

static void sipe_refresh_blocked_status_cb(char *buddy_name,
					   SIPE_UNUSED_PARAMETER struct sipe_buddy *buddy,
					   struct sipe_core_private *sipe_private)
{
	int container_id = sipe_ocs2007_find_access_level(sipe_private, "user", buddy_name, NULL);
	gboolean blocked = (container_id == 32000);
	gboolean blocked_in_blist = sipe_backend_buddy_is_blocked(SIPE_CORE_PUBLIC, buddy_name);

	/* SIPE_DEBUG_INFO("sipe_refresh_blocked_status_cb: buddy_name=%s, blocked=%s, blocked_in_blist=%s",
		buddy_name, blocked ? "T" : "F", blocked_in_blist ? "T" : "F"); */

	if (blocked != blocked_in_blist) {
		sipe_backend_buddy_set_blocked_status(SIPE_CORE_PUBLIC, buddy_name, blocked);
	}
}

static void sipe_refresh_blocked_status(struct sipe_core_private *sipe_private)
{
	sipe_buddy_foreach(sipe_private,
			   (GHFunc) sipe_refresh_blocked_status_cb,
			   sipe_private);
}

/**
  *   When we receive some self (BE) NOTIFY with a new subscriber
  *   we sends a setSubscribers request to him [SIP-PRES] 4.8
  *
  */
void sipe_ocs2007_process_roaming_self(struct sipe_core_private *sipe_private,
				       struct sipmsg *msg)
{
	gchar *contact;
	gchar *to;
	sipe_xml *xml;
	const sipe_xml *node;
	const sipe_xml *node2;
        char *display_name = NULL;
        char *uri;
	GSList *category_names = NULL;
	int aggreg_avail = 0;
	gchar *activity_token = NULL;
	gboolean do_update_status = FALSE;
	gboolean has_note_cleaned = FALSE;
	GHashTable *devices;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_ocs2007_process_roaming_self");

	xml = sipe_xml_parse(msg->body, msg->bodylen);
	if (!xml) return;

	contact = get_contact(sipe_private);
	to = sip_uri_self(sipe_private);

	/* categories */
	/* set list of categories participating in this XML */
	for (node = sipe_xml_child(xml, "categories/category"); node; node = sipe_xml_twin(node)) {
		const gchar *name = sipe_xml_attribute(node, "name");
		category_names = sipe_utils_slist_insert_unique_sorted(category_names,
								       (gchar *)name,
								       (GCompareFunc)strcmp,
								       NULL);
	}
	SIPE_DEBUG_INFO("sipe_ocs2007_process_roaming_self: category_names length=%d",
			category_names ? (int) g_slist_length(category_names) : -1);
	/* drop category information */
	if (category_names) {
		GSList *entry = category_names;
		while (entry) {
			GHashTable *cat_publications;
			const gchar *category = entry->data;
			entry = entry->next;
			SIPE_DEBUG_INFO("sipe_ocs2007_process_roaming_self: dropping category: %s", category);
			cat_publications = g_hash_table_lookup(sipe_private->our_publications, category);
			if (cat_publications) {
				g_hash_table_remove(sipe_private->our_publications, category);
				SIPE_DEBUG_INFO("sipe_ocs2007_process_roaming_self: dropped category: %s", category);
			}
		}
	}
	g_slist_free(category_names);

	/* filling our categories reflected in roaming data */
	devices = g_hash_table_new_full(g_str_hash, g_str_equal,
					g_free, NULL);
	for (node = sipe_xml_child(xml, "categories/category"); node; node = sipe_xml_twin(node)) {
		const char *tmp;
		const gchar *name = sipe_xml_attribute(node, "name");
		guint container = sipe_xml_int_attribute(node, "container", -1);
		guint instance  = sipe_xml_int_attribute(node, "instance", -1);
		guint version   = sipe_xml_int_attribute(node, "version", 0);
		time_t publish_time = (tmp = sipe_xml_attribute(node, "publishTime")) ?
			sipe_utils_str_to_time(tmp) : 0;
		gchar *key;
		GHashTable *cat_publications = g_hash_table_lookup(sipe_private->our_publications, name);

		/* Ex. clear note: <category name="note"/> */
		if (container == (guint)-1) {
			g_free(sipe_private->note);
			sipe_private->note = NULL;
			do_update_status = TRUE;
			continue;
		}

		/* Ex. clear note: <category name="note" container="200"/> */
		if (instance == (guint)-1) {
			if (container == 200) {
				g_free(sipe_private->note);
				sipe_private->note = NULL;
				do_update_status = TRUE;
			}
			SIPE_DEBUG_INFO("sipe_ocs2007_process_roaming_self: removing publications for: %s/%u", name, container);
			sipe_remove_category_container_publications(
				sipe_private->our_publications, name, container);
			continue;
		}

		/* key is <category><instance><container> */
		key = g_strdup_printf("<%s><%u><%u>", name, instance, container);
		SIPE_DEBUG_INFO("sipe_ocs2007_process_roaming_self: key=%s version=%d", key, version);

		/* capture all userState publication for later clean up if required */
		if (sipe_strequal(name, "state") && (container == 2 || container == 3)) {
			const sipe_xml *xn_state = sipe_xml_child(node, "state");

			if (xn_state && sipe_strequal(sipe_xml_attribute(xn_state, "type"), "userState")) {
				struct sipe_publication *publication = g_new0(struct sipe_publication, 1);
				publication->category  = g_strdup(name);
				publication->instance  = instance;
				publication->container = container;
				publication->version   = version;

				if (!sipe_private->user_state_publications) {
					sipe_private->user_state_publications = g_hash_table_new_full(
						g_str_hash, g_str_equal,
						g_free,	(GDestroyNotify)free_publication);
				}
				g_hash_table_insert(sipe_private->user_state_publications, g_strdup(key), publication);
				SIPE_DEBUG_INFO("sipe_ocs2007_process_roaming_self: added to user_state_publications key=%s version=%d",
						key, version);
			}
		}

		/* count each client instance only once */
		if (sipe_strequal(name, "device"))
			g_hash_table_replace(devices, g_strdup_printf("%u", instance), NULL);

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
								  sipe_status_activity_to_token(SIPE_ACTIVITY_IN_MEETING)))
						{
							event->is_meeting = TRUE;
						}
					}
					event->subject = sipe_xml_data(sipe_xml_child(xn_state, "meetingSubject"));
					event->location = sipe_xml_data(sipe_xml_child(xn_state, "meetingLocation"));

					publication->cal_event_hash = sipe_cal_event_hash(event);
					SIPE_DEBUG_INFO("sipe_ocs2007_process_roaming_self: hash=%s",
							publication->cal_event_hash);
					sipe_cal_event_free(event);
				}
			}
			/* filling publication->note */
			if (sipe_strequal(name, "note")) {
				const sipe_xml *xn_body = sipe_xml_child(node, "note/body");

				if (!has_note_cleaned) {
					has_note_cleaned = TRUE;

					g_free(sipe_private->note);
					sipe_private->note = NULL;
					sipe_private->note_since = publish_time;

					do_update_status = TRUE;
				}

				g_free(publication->note);
				publication->note = NULL;
				if (xn_body) {
					char *tmp;

					publication->note = g_markup_escape_text((tmp = sipe_xml_data(xn_body)), -1);
					g_free(tmp);
					if (publish_time >= sipe_private->note_since) {
						g_free(sipe_private->note);
						sipe_private->note = g_strdup(publication->note);
						sipe_private->note_since = publish_time;
						if (sipe_strequal(sipe_xml_attribute(xn_body, "type"), "OOF"))
							SIPE_CORE_PRIVATE_FLAG_SET(OOF_NOTE);
						else
							SIPE_CORE_PRIVATE_FLAG_UNSET(OOF_NOTE);

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
				g_hash_table_insert(sipe_private->our_publications, g_strdup(name), cat_publications);
				SIPE_DEBUG_INFO("sipe_ocs2007_process_roaming_self: added GHashTable cat=%s", name);
			}
			g_hash_table_insert(cat_publications, g_strdup(key), publication);
			SIPE_DEBUG_INFO("sipe_ocs2007_process_roaming_self: added key=%s version=%d", key, version);
		}
		g_free(key);

		/* aggregateState (not an our publication) from 2-nd container */
		if (sipe_strequal(name, "state") && container == 2) {
			const sipe_xml *xn_state = sipe_xml_child(node, "state");
			const sipe_xml *xn_activity = sipe_xml_child(xn_state, "activity");

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

			if (xn_activity) {
				activity_token = g_strdup(sipe_xml_attribute(xn_activity, "token"));
			}
		}

		/* userProperties published by server from AD */
		if (!sipe_private->csta &&
		    sipe_strequal(name, "userProperties")) {
			const sipe_xml *line;
			/* line, for Remote Call Control (RCC) or external Lync/Communicator call */
			for (line = sipe_xml_child(node, "userProperties/lines/line"); line; line = sipe_xml_twin(line)) {
				const gchar *line_type = sipe_xml_attribute(line, "lineType");
				gchar *line_uri = sipe_xml_data(line);
				if (!line_uri) {
					continue;
				}

				if (sipe_strequal(line_type, "Rcc") || sipe_strequal(line_type, "Dual")) {
					const gchar *line_server = sipe_xml_attribute(line, "lineServer");
					if (line_server) {
						gchar *tmp = g_strstrip(line_uri);
						SIPE_DEBUG_INFO("sipe_ocs2007_process_roaming_self: line_uri=%s server=%s",
								tmp, line_server);
						sip_csta_open(sipe_private, tmp, line_server);
					}
				}
#ifdef HAVE_VV
				else if (sipe_strequal(line_type, "Uc")) {

					if (!sipe_private->uc_line_uri) {
						sipe_private->uc_line_uri = g_strdup(g_strstrip(line_uri));
					} else {
						SIPE_DEBUG_INFO_NOFORMAT("sipe_ocs2007_process_roaming_self: "
								"sipe_private->uc_line_uri is already set.");
					}
				}
#endif

				g_free(line_uri);

				break;
			}
		}
	}
	SIPE_DEBUG_INFO("sipe_ocs2007_process_roaming_self: sipe_private->our_publications size=%d",
			sipe_private->our_publications ? (int) g_hash_table_size(sipe_private->our_publications) : -1);

	/* active clients for user account */
	if (g_hash_table_size(devices) == 0) {
		/* updated roaming information without device information - no need to update MPOP flag */
	} else if (g_hash_table_size(devices) > 1) {
		SIPE_CORE_PRIVATE_FLAG_SET(MPOP);
		SIPE_LOG_INFO("sipe_ocs2007_process_roaming_self: multiple clients detected (%d)",
			      g_hash_table_size(devices));
	} else {
		SIPE_CORE_PRIVATE_FLAG_UNSET(MPOP);
		SIPE_LOG_INFO_NOFORMAT("sipe_ocs2007_process_roaming_self: single client detected");
	}
	g_hash_table_destroy(devices);

	/* containers */
	for (node = sipe_xml_child(xml, "containers/container"); node; node = sipe_xml_twin(node)) {
		guint id = sipe_xml_int_attribute(node, "id", 0);
		struct sipe_container *container = sipe_find_container(sipe_private, id);

		if (container) {
			sipe_private->containers = g_slist_remove(sipe_private->containers, container);
			SIPE_DEBUG_INFO("sipe_ocs2007_process_roaming_self: removed existing container id=%d v%d", container->id, container->version);
			sipe_ocs2007_free_container(container);
		}
		container = g_new0(struct sipe_container, 1);
		container->id = id;
		container->version = sipe_xml_int_attribute(node, "version", 0);
		sipe_private->containers = g_slist_append(sipe_private->containers, container);
		SIPE_DEBUG_INFO("sipe_ocs2007_process_roaming_self: added container id=%d v%d", container->id, container->version);

		for (node2 = sipe_xml_child(node, "member"); node2; node2 = sipe_xml_twin(node2)) {
			struct sipe_container_member *member = g_new0(struct sipe_container_member, 1);
			member->type = g_strdup(sipe_xml_attribute(node2, "type"));
			member->value = g_strdup(sipe_xml_attribute(node2, "value"));
			container->members = g_slist_append(container->members, member);
			SIPE_DEBUG_INFO("sipe_ocs2007_process_roaming_self: added container member type=%s value=%s",
					member->type, member->value ? member->value : "");
		}
	}

	SIPE_DEBUG_INFO("sipe_ocs2007_process_roaming_self: access_level_set=%s",
			SIPE_CORE_PRIVATE_FLAG_IS(ACCESS_LEVEL_SET) ? "TRUE" : "FALSE");
	if (!SIPE_CORE_PRIVATE_FLAG_IS(ACCESS_LEVEL_SET) && sipe_xml_child(xml, "containers")) {
		char *container_xmls = NULL;
		int sameEnterpriseAL = sipe_ocs2007_find_access_level(sipe_private, "sameEnterprise", NULL, NULL);
		int federatedAL      = sipe_ocs2007_find_access_level(sipe_private, "federated", NULL, NULL);

		SIPE_DEBUG_INFO("sipe_ocs2007_process_roaming_self: sameEnterpriseAL=%d", sameEnterpriseAL);
		SIPE_DEBUG_INFO("sipe_ocs2007_process_roaming_self: federatedAL=%d", federatedAL);
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
		SIPE_CORE_PRIVATE_FLAG_SET(ACCESS_LEVEL_SET);

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
		SIPE_DEBUG_INFO("sipe_ocs2007_process_roaming_self: user %s", user);
		display_name = g_strdup(sipe_xml_attribute(node, "displayName"));
		uri = sip_uri_from_name(user);

		sipe_buddy_update_property(sipe_private, uri, SIPE_BUDDY_INFO_DISPLAY_NAME, display_name);
		sipe_backend_buddy_refresh_properties(SIPE_CORE_PUBLIC, uri);

	        acknowledged= sipe_xml_attribute(node, "acknowledged");
		if(sipe_strcase_equal(acknowledged,"false")){
                        SIPE_DEBUG_INFO("sipe_ocs2007_process_roaming_self: user added you %s", user);
			if (!sipe_backend_buddy_find(SIPE_CORE_PUBLIC, uri, NULL)) {
				sipe_backend_buddy_request_add(SIPE_CORE_PUBLIC, uri, display_name);
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
	if (!SIPE_CORE_PRIVATE_FLAG_IS(INITIAL_PUBLISH)) {
		send_publish_category_initial(sipe_private);
		SIPE_CORE_PRIVATE_FLAG_SET(INITIAL_PUBLISH);
		/* dalayed run */
		sipe_cal_delayed_calendar_update(sipe_private);
		do_update_status = FALSE;
	} else if (aggreg_avail) {

		if (aggreg_avail &&
		    (aggreg_avail < SIPE_OCS2007_LEGACY_AVAILIBILITY_OFFLINE)) {
			/* not offline */
			sipe_status_set_token(sipe_private,
					      sipe_ocs2007_status_from_legacy_availability(aggreg_avail, activity_token));
		} else {
			/* do not let offline status switch us off */
			sipe_status_set_activity(sipe_private,
						 SIPE_ACTIVITY_INVISIBLE);
		}
	}

	if (do_update_status) {
		sipe_status_and_note(sipe_private, NULL);
	}

	g_free(to);
	g_free(activity_token);
}

/**
 * for Access levels menu
 */
#define INDENT_FMT			"  %s"

/**
 * Member is indirectly belong to access level container.
 * For example 'sameEnterprise' is in the container and user
 * belongs to that same enterprise.
 */
#define INDENT_MARKED_INHERITED_FMT	"= %s"

static struct sipe_backend_buddy_menu *access_levels_menu(struct sipe_core_private *sipe_private,
							  struct sipe_backend_buddy_menu *menu,
							  const gchar *member_type,
							  const gchar *member_value,
							  const gboolean extra_menu)
{
	unsigned int i;
	gboolean is_group_access = FALSE;
	int container_id;

	if (!menu)
		menu = sipe_backend_buddy_menu_start(SIPE_CORE_PUBLIC);

	container_id = sipe_ocs2007_find_access_level(sipe_private,
						      member_type,
						      member_value,
						      &is_group_access);

	for (i = 1; i <= CONTAINERS_LEN; i++) {
		/*
		 * Blocked should remain in the first place
		 * in the containers[] array.
		 */
		unsigned int j  = (i == CONTAINERS_LEN) ? 0 : i;
		int container_j = containers[j];
		const gchar *acc_level_name = sipe_ocs2007_access_level_name(container_j);
		struct sipe_container *container = create_container(j,
								    member_type,
								    member_value,
								    FALSE);
		gchar *label;

		/* libpurple memory leak workaround */
		blist_menu_remember_container(sipe_private, container);

		/* current container/access level */
		if (container_j == container_id) {
			label = is_group_access ?
				g_strdup_printf(INDENT_MARKED_INHERITED_FMT, acc_level_name) :
				g_strdup_printf(SIPE_OCS2007_INDENT_MARKED_FMT, acc_level_name);
		} else {
			label = g_strdup_printf(INDENT_FMT, acc_level_name);
		}

		menu = sipe_backend_buddy_menu_add(SIPE_CORE_PUBLIC,
						   menu,
						   label,
						   SIPE_BUDDY_MENU_CHANGE_ACCESS_LEVEL,
						   container);
		g_free(label);
	}

	if (extra_menu && (container_id >= 0) && !is_group_access) {
		struct sipe_container *container = create_container(0,
									    member_type,
									    member_value,
									    TRUE);
		gchar *label;

		/* separator */
		menu = sipe_backend_buddy_menu_separator(SIPE_CORE_PUBLIC,
							 menu,
							 "  --------------");


		/* libpurple memory leak workaround */
		blist_menu_remember_container(sipe_private, container);

		/* Translators: remove (clear) previously assigned access level */
		label = g_strdup_printf(INDENT_FMT, _("Unspecify"));
		menu = sipe_backend_buddy_menu_add(SIPE_CORE_PUBLIC,
						   menu,
						   label,
						   SIPE_BUDDY_MENU_CHANGE_ACCESS_LEVEL,
						   container);
		g_free(label);
	}

	return(menu);
}

static struct sipe_backend_buddy_menu *access_groups_menu(struct sipe_core_private *sipe_private)
{
	struct sipe_backend_buddy_menu *menu = sipe_backend_buddy_menu_start(SIPE_CORE_PUBLIC);
	GSList *access_domains, *entry;

	menu = sipe_backend_buddy_sub_menu_add(SIPE_CORE_PUBLIC,
					       menu,
					       _("People in my company"),
					       access_levels_menu(sipe_private,
								  NULL,
								  "sameEnterprise",
								  NULL,
								  FALSE));

	/* this is original name, don't edit */
	menu = sipe_backend_buddy_sub_menu_add(SIPE_CORE_PUBLIC,
					       menu,
					       _("People in domains connected with my company"),
					       access_levels_menu(sipe_private,
								  NULL,
								  "federated",
								  NULL,
								  FALSE));

	menu = sipe_backend_buddy_sub_menu_add(SIPE_CORE_PUBLIC,
					       menu,
					       _("People in public domains"),
					       access_levels_menu(sipe_private,
								  NULL,
								  "publicCloud",
								  NULL,
								  TRUE));

	entry = access_domains = get_access_domains(sipe_private);
	while (entry) {
		gchar *domain    = entry->data;
		gchar *menu_name = g_strdup_printf(_("People at %s"), domain);

		/* takes over ownership of entry->data (= domain) */
		menu = sipe_backend_buddy_sub_menu_add(SIPE_CORE_PUBLIC,
						       menu,
						       menu_name,
						       access_levels_menu(sipe_private,
									  NULL,
									  "domain",
									  domain,
									  TRUE));
		g_free(menu_name);

		entry = entry->next;
	}
	g_slist_free(access_domains);

	/* separator */
	/*			                  People in domains connected with my company */
	menu = sipe_backend_buddy_menu_separator(SIPE_CORE_PUBLIC,
						 menu,
						 "-------------------------------------------");

	menu = sipe_backend_buddy_menu_add(SIPE_CORE_PUBLIC,
					   menu,
					   _("Add new domain..."),
					   SIPE_BUDDY_MENU_ADD_NEW_DOMAIN,
					   NULL);

	return(menu);
}

struct sipe_backend_buddy_menu *sipe_ocs2007_access_control_menu(struct sipe_core_private *sipe_private,
								 const gchar *buddy_name)
{
	struct sipe_backend_buddy_menu *menu = sipe_backend_buddy_menu_start(SIPE_CORE_PUBLIC);
	gchar *label;

	/*
	 * Workaround for missing libpurple API to release resources allocated
	 * during blist_node_menu() callback. See also:
	 *
	 *   <http://developer.pidgin.im/ticket/12597>
	 *
	 * We remember all memory blocks in a list and deallocate them when
	 *
	 *   - the next time we enter the callback, or
	 *   - the account is disconnected
	 *
	 * That means that after the buddy menu has been closed we have unused
	 * resources but at least we don't leak them anymore...
	 */
	sipe_core_buddy_menu_free(SIPE_CORE_PUBLIC);

	label = g_strdup_printf(INDENT_FMT, _("Online help..."));
	menu = sipe_backend_buddy_menu_add(SIPE_CORE_PUBLIC,
					   menu,
					   label,
					   SIPE_BUDDY_MENU_ACCESS_LEVEL_HELP,
					   NULL);
	g_free(label);

	label = g_strdup_printf(INDENT_FMT, _("Access groups"));
	menu = sipe_backend_buddy_sub_menu_add(SIPE_CORE_PUBLIC,
					       menu,
					       label,
					       access_groups_menu(sipe_private));
	g_free(label);

	menu = access_levels_menu(sipe_private,
				  menu,
				  "user",
				  sipe_get_no_sip_uri(buddy_name),
				  TRUE);

	return(menu);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
