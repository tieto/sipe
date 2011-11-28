/**
 * @file sipe.h
 *
 *****************************************************************************
 *** !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ***
 ***                                                                       ***
 ***                      THIS INTERFACE IS DEPECRATED                     ***
 ***                                                                       ***
 ***                    DO NOT INCLUDE IT IN ANY NEW CODE                  ***
 ***                                                                       ***
 *** !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!! ***
 *****************************************************************************
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-11 SIPE Project <http://sipe.sourceforge.net/>
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
struct sipe_core_private;
struct transaction;
struct transaction_payload;

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

struct sipe_account_data {
	struct _PurpleConnection *gc;
	gchar *authdomain;
	gchar *authuser;
	gchar *password;
	/** Allowed server events to subscribe. From register OK response. */
	GSList *allow_events;
	struct sip_csta *csta; /* For RCC - Remote Call Control */
	gboolean subscribed_buddies; /* whether subscribed to buddies presence */
	gboolean access_level_set; /* whether basic access level set */
	gboolean initial_state_published; /* whether we published our initial state */
	GSList *our_publication_keys;		/* [MS-PRES] */
	GHashTable *our_publications;		/* [MS-PRES] */
	GHashTable *user_state_publications;	/* [MS-PRES] */
	int presence_method_version;
	time_t do_not_publish[SIPE_ACTIVITY_NUM_TYPES];
	gchar *status;
	gboolean is_oof_note;
	gchar *note;
	time_t note_since;
	time_t idle_switch;
	gboolean batched_support; /*if there is support for batched subscription*/
	GSList *containers; /* MS-PRES containers */
	struct _PurpleAccount *account;
	gchar *regcallid;
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
send_presence_soap(struct sipe_core_private *sipe_private,
		   gboolean do_publish_calendar);

/**
 * THE BIG SPLIT - temporary interfaces
 *
 * Previously private functions in sipe.c that are
 *  - waiting to be factored out to an appropriate module
 *  - are needed by the already created new modules
 */

/* ??? module */
void sipe_connection_cleanup(struct sipe_core_private *sipe_private);
void sipe_buddy_free_all(struct sipe_core_private *sipe_private);

/**
 * referenced by sipe-notify.c - start
 *
 * all of these should be moved to sipe-notify.c
 */
void sipe_subscribe_poolfqdn_resource_uri(const char *host,
					  GSList *server,
					  struct sipe_core_private *sipe_private);
void process_incoming_notify_msrtc(struct sipe_core_private *sipe_private,
				   const gchar *data,
				   unsigned len);
void sipe_subscribe_presence_single(struct sipe_core_private *sipe_private,
				    void *buddy_name);
void process_incoming_notify_rlmi(struct sipe_core_private *sipe_private,
				  const gchar *data,
				  unsigned len);
void process_incoming_notify_pidf(struct sipe_core_private *sipe_private,
				  const gchar *data,
				  unsigned len);
void sipe_subscribe_presence_batched_to(struct sipe_core_private *sipe_private,
					gchar *resources_uri,
					gchar *to);
void sipe_sched_calendar_status_update(struct sipe_core_private *sipe_private,
				       time_t calculate_from);
void sipe_process_roaming_self(struct sipe_core_private *sipe_private,
			       struct sipmsg *msg);
void sipe_process_presence_timeout(struct sipe_core_private *sipe_private,
				   struct sipmsg *msg,
				   const gchar *who,
				   int timeout);
/* referenced by sipe-notify.c - end */


/*** THE BIG SPLIT END ***/
