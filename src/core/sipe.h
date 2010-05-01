/**
 * @file sipe.h
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2007 Anibal Avelar <avelar@gmail.com>
 * Copyright (C) 2005 Thomas Butter <butter@uni-mannheim.de>
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

/*
 * Interface dependencies:
 *
 * <time.h>
 * <glib.h>
 */

/* Forward declarations */
struct sipmsg;
struct _PurpleAccount;
struct _PurpleConnection;
struct _PurpleGroup;
struct sip_sec_context;
struct sipe_core_private;

#define SIPE_TYPING_RECV_TIMEOUT 6
#define SIPE_TYPING_SEND_TIMEOUT 4

struct sip_auth {
	guint type;
	struct sip_sec_context *gssapi_context;
	gchar *gssapi_data;
	gchar *opaque;
	gchar *realm;
	gchar *target;
	int version;
	int nc;
	int retries;
	int ntlm_num;
	int expires;
};

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

struct sipe_account_data {
	/* back pointer to new data structure */
	struct sipe_core_public *public;
	/* same, but reduces need for casting and increases type safety */
	struct sipe_core_private *private;

	struct _PurpleConnection *gc;
	gchar *username;
	gchar *authdomain;
	gchar *authuser;
	gchar *password;
	gchar *epid;
	gchar *focus_factory_uri;
	/** Allowed server events to subscribe. From register OK response. */
	GSList *allow_events;
	int cseq;
	int registerstatus; /* 0 nothing, 1 first registration send, 2 auth received, 3 registered */
	struct sip_auth registrar;
	struct sip_auth proxy;
	struct sip_csta *csta; /* For RCC - Remote Call Control */
	gboolean reregister_set; /* whether reregister timer set */
	gboolean reauthenticate_set; /* whether reauthenticate timer set */
	gboolean subscribed; /* whether subscribed to events, except buddies presence */
	gboolean subscribed_buddies; /* whether subscribed to buddies presence */
	gboolean access_level_set; /* whether basic access level set */
	gboolean initial_state_published; /* whether we published our initial state */
	GSList *our_publication_keys;		/* [MS-PRES] */
	GHashTable *our_publications;		/* [MS-PRES] */
	GHashTable *user_state_publications;	/* [MS-PRES] */
	GHashTable *subscriptions;
	int contacts_delta;
	int acl_delta;
	int presence_method_version;
	time_t do_not_publish[SIPE_ACTIVITY_NUM_TYPES];
	gchar *status;
	gboolean is_oof_note;
	gchar *note;
	time_t note_since;
	time_t idle_switch;
	gchar *contact;
	gboolean ocs2007; /*if there is support for batched category subscription [SIP-PRES]*/
	gboolean batched_support; /*if there is support for batched subscription*/
	GSList *containers; /* MS-PRES containers */
	struct _PurpleAccount *account;
	gchar *regcallid;
	GSList *sessions;
	GSList *groups;
	GHashTable *filetransfers;
	gboolean processing_input;
	struct sipe_calendar *cal;
	gchar *email;
	/** 2005 Custom XML piece.
	 * Possibly set by other point of presence or just other client at earlier time.
	 * It should be preserved/modified, not overwritten. This implies subscription
	 * to self-contasct.
	 * This XML keeps OC2005:
	 * - User note
	 * - OOF flag
	 * - User status
	 */
	gchar *user_states;
};

struct sipe_auth_job {
	gchar * who;
	struct sipe_account_data * sip;
};

struct sipe_group {
	gchar *name;
	int id;
	struct _PurpleGroup *purple_group;
};

struct group_user_context {
	gchar * group_name;
	gchar * user_name;
};

GSList * slist_insert_unique_sorted(GSList *list, gpointer data, GCompareFunc func);

/**
 * Publishes self status
 * based on own calendar information,
 * our Calendar information - FreeBusy, WorkingHours,
 * OOF note.
 *
 * For 2007+
 */
void
publish_calendar_status_self(struct sipe_core_private *sipe_private,
			     void *unused);

/**
 * For 2005-
 */
void
send_presence_soap(struct sipe_account_data *sip,
		   gboolean do_publish_calendar);

/**
 * THE BIG SPLIT - temporary interfaces
 *
 * Previously private functions in sipe.c that are
 *  - waiting to be factored out to an appropriate module
 *  - are needed by the already created new modules
 */

/* pier11:
 *
 * Since SIP (RFC3261) is extensible by its design,
 * and MS specs prove just that (they all are defined as SIP extensions),
 * it make sense to split functionality by extension (or close extension group).
 * For example: conference, presence (MS-PRES), etc.
 *
 * This way our code will not be monolithic, but potentially _reusable_. May be
 * a top of other SIP core, and/or other front-end (Telepathy framework?).
 */
/* Forward declarations */
struct sip_session;
struct sip_dialog;
struct transaction;

void
sipe_invite(struct sipe_account_data *sip, struct sip_session *session,
	    const gchar *who, const gchar *msg_body, const gchar *msg_content_type,
	    const gchar *referred_by, const gboolean is_triggered);
/* ??? module */
void sipe_make_signature(struct sipe_account_data *sip,
			 struct sipmsg *msg);
gchar *auth_header(struct sipe_account_data *sip,
		   struct sip_auth *auth, struct sipmsg * msg);
const gchar *sipe_get_useragent(struct sipe_core_private *sipe_private);
void process_input_message(struct sipe_account_data *sip,
			   struct sipmsg *msg);
gboolean process_register_response(struct sipe_core_private *sipe_private,
				   struct sipmsg *msg,
				   struct transaction *trans);
gboolean process_subscribe_response(struct sipe_core_private *sipe_private,
				    struct sipmsg *msg,
				    struct transaction *trans);
/* Chat module */
void
sipe_invite_to_chat(struct sipe_account_data *sip,
		    struct sip_session *session,
		    const gchar *who);
/* Session module? */
void
sipe_present_message_undelivered_err(struct sipe_account_data *sip,
				     struct sip_session *session,
				     int sip_error,
				     int sip_warning,
				     const gchar *who,
				     const gchar *message);

void
sipe_present_info(struct sipe_account_data *sip,
		 struct sip_session *session,
		 const gchar *message);


void
sipe_process_pending_invite_queue(struct sipe_account_data *sip,
				  struct sip_session *session);

void
sipe_im_process_queue (struct sipe_account_data * sip, struct sip_session * session);


/*** THE BIG SPLIT END ***/

#define SIPE_INVITE_TEXT "ms-text-format: %s; charset=UTF-8%s;ms-body=%s\r\n"

#define SIPE_SEND_TYPING \
"<?xml version=\"1.0\"?>"\
"<KeyboardActivity>"\
  "<status status=\"type\" />"\
"</KeyboardActivity>"

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
			"</capabilities>"\
			"<timezone>%s</timezone>"\
			"<machineName>%s</machineName>"\
		"</device>"\
	"</publication>"

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
 * Publishes to clear 'calendarState' category
 * @param instance		(%u) Ex.: 1251210982
 * @param version		(%u) Ex.: 1
 */
#define SIPE_PUB_XML_STATE_CALENDAR_CLEAR \
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


#define sipe_soap(method, body) \
"<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">" \
  "<SOAP-ENV:Body>" \
    "<m:" method " xmlns:m=\"http://schemas.microsoft.com/winrtc/2002/11/sip\">" \
      body \
    "</m:" method ">" \
  "</SOAP-ENV:Body>" \
"</SOAP-ENV:Envelope>"

#define SIPE_SOAP_SET_CONTACT sipe_soap("setContact", \
	"<m:displayName>%s</m:displayName>"\
	"<m:groups>%s</m:groups>"\
	"<m:subscribed>%s</m:subscribed>"\
	"<m:URI>%s</m:URI>"\
	"<m:externalURI />"\
	"<m:deltaNum>%d</m:deltaNum>")

#define SIPE_SOAP_DEL_CONTACT sipe_soap("deleteContact", \
	"<m:URI>%s</m:URI>"\
	"<m:deltaNum>%d</m:deltaNum>")

#define SIPE_SOAP_ADD_GROUP sipe_soap("addGroup", \
	"<m:name>%s</m:name>"\
	"<m:externalURI />"\
	"<m:deltaNum>%d</m:deltaNum>")

#define SIPE_SOAP_MOD_GROUP sipe_soap("modifyGroup", \
	"<m:groupID>%d</m:groupID>"\
	"<m:name>%s</m:name>"\
	"<m:externalURI />"\
	"<m:deltaNum>%d</m:deltaNum>")

#define SIPE_SOAP_DEL_GROUP sipe_soap("deleteGroup", \
	"<m:groupID>%d</m:groupID>"\
	"<m:deltaNum>%d</m:deltaNum>")

// first/mask arg is sip:user@domain.com
// second/rights arg is AA for allow, BD for deny
#define SIPE_SOAP_ALLOW_DENY sipe_soap("setACE", \
	"<m:type>USER</m:type>"\
	"<m:mask>%s</m:mask>"\
	"<m:rights>%s</m:rights>"\
	"<m:deltaNum>%d</m:deltaNum>")

/**
 * Calendar publication entry. 2005 systems.
 *
 * @param legacy_dn		(%s) Ex.: /o=EXCHANGE/ou=BTUK02/cn=Recipients/cn=AHHBTT
 * @param fb_start_time_str	(%s) Ex.: 2009-12-06T17:15:00Z
 * @param free_busy_base64	(%s) Ex.: AAAAAAAAAAAAAAAAA......
 */
#define SIPE_SOAP_SET_PRESENCE_CALENDAR \
"<calendarInfo xmlns=\"http://schemas.microsoft.com/2002/09/sip/presence\" mailboxId=\"%s\" startTime=\"%s\" granularity=\"PT15M\">%s</calendarInfo>"
/**
 * Note publication entry. 2005 systems.
 *
 * @param note	(%s) Ex.: Working from home
 */
#define SIPE_SOAP_SET_PRESENCE_NOTE_XML  "<note>%s</note>"
/**
 * Note's OOF publication entry. 2005 systems.
 */
#define SIPE_SOAP_SET_PRESENCE_OOF_XML  "<oof></oof>"
/**
 * States publication entry for User State. 2005 systems.
 *
 * @param avail			(%d) Availability 2007-style. Ex.: 9500
 * @param since_time_str	(%s) Ex.: 2010-01-13T10:30:05Z
 * @param device_id		(%s) epid. Ex.: 4c77e6ec72
 * @param activity_token	(%s) Ex.: do-not-disturb
 */
#define SIPE_SOAP_SET_PRESENCE_STATES \
          "<states>"\
            "<state avail=\"%d\" since=\"%s\" validWith=\"any-device\" deviceId=\"%s\" set=\"manual\" xsi:type=\"userState\">%s</state>"\
          "</states>"
/**
 * Presentity publication entry. 2005 systems.
 *
 * @param uri			(%s) SIP URI without 'sip:' prefix. Ex.: fox@atlanta.local
 * @param aggr_availability	(%d) Ex.: 300
 * @param aggr_activity		(%d) Ex.: 600
 * @param host_name		(%s) Uppercased. Ex.: ATLANTA
 * @param note_xml_str		(%s) XML string as SIPE_SOAP_SET_PRESENCE_NOTE_XML
 * @param oof_xml_str		(%s) XML string as SIPE_SOAP_SET_PRESENCE_OOF_XML
 * @param states_xml_str	(%s) XML string as SIPE_SOAP_SET_PRESENCE_STATES
 * @param calendar_info_xml_str	(%s) XML string as SIPE_SOAP_SET_PRESENCE_CALENDAR
 * @param device_id		(%s) epid. Ex.: 4c77e6ec72
 * @param since_time_str	(%s) Ex.: 2010-01-13T10:30:05Z
 * @param since_time_str	(%s) Ex.: 2010-01-13T10:30:05Z
 * @param user_input		(%s) active, idle
 */
#define SIPE_SOAP_SET_PRESENCE sipe_soap("setPresence", \
	"<m:presentity xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" m:uri=\"sip:%s\">"\
	"<m:availability m:aggregate=\"%d\"/>"\
	"<m:activity m:aggregate=\"%d\"/>"\
	"<deviceName xmlns=\"http://schemas.microsoft.com/2002/09/sip/presence\" name=\"%s\"/>"\
	"<rtc:devicedata xmlns:rtc=\"http://schemas.microsoft.com/winrtc/2002/11/sip\" namespace=\"rtcService\">"\
	"<![CDATA[<caps><renders_gif/><renders_isf/></caps>]]></rtc:devicedata>"\
	"<userInfo xmlns=\"http://schemas.microsoft.com/2002/09/sip/presence\">"\
	"%s%s" \
	"%s" \
        "</userInfo>"\
	"%s" \
	"<device xmlns=\"http://schemas.microsoft.com/2002/09/sip/presence\" deviceId=\"%s\" since=\"%s\" >"\
		"<userInput since=\"%s\" >%s</userInput>"\
	"</device>"\
	"</m:presentity>")

#define SIPE_SOAP_SEARCH_CONTACT \
	"<SOAP-ENV:Envelope xmlns:SOAP-ENV=\"http://schemas.xmlsoap.org/soap/envelope/\">" \
	"<SOAP-ENV:Body>" \
	"<m:directorySearch xmlns:m=\"http://schemas.microsoft.com/winrtc/2002/11/sip\">" \
	"<m:filter m:href=\"#searchArray\"/>"\
	"<m:maxResults>%d</m:maxResults>"\
	"</m:directorySearch>"\
	"<m:Array xmlns:m=\"http://schemas.microsoft.com/winrtc/2002/11/sip\" m:id=\"searchArray\">"\
	"%s"\
	"</m:Array>"\
	"</SOAP-ENV:Body>"\
	"</SOAP-ENV:Envelope>"

#define SIPE_SOAP_SEARCH_ROW "<m:row m:attrib=\"%s\" m:value=\"%s\"/>"
