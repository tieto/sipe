/**
 * @file sipe-core-private.h
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

/* Forward declarations */
struct sip_address_data;
struct sip_csta;
struct sip_service_data;
struct sip_transport;
struct sipe_buddies;
struct sipe_calendar;
struct sipe_certificate;
struct sipe_ews_autodiscover;
struct sipe_groupchat;
struct sipe_groups;
struct sipe_http;
struct sipe_http_request;
struct sipe_media_call_private;
struct sipe_svc;
struct sipe_ucs;
struct sipe_webticket;

/**
 * Private part of the Sipe data structure
 *
 * This part contains the information only needed by the core
 */
struct sipe_core_private {
	/**
	 * The public part is the first item, i.e. a pointer to the
	 * public part can also be used as a pointer to the private part.
	 */
	struct sipe_core_public public;

	/* sip-transport.c private data */
	struct sip_transport *transport;
	const struct sip_service_data *service_data; /* autodiscovery SRV records */
	const struct sip_address_data *address_data; /* autodiscovery A records */
	guint transport_type;
	guint authentication_type;

	/* Account information */
	gchar *username;
	gchar *authdomain; /* NULL when SSO is enabled */
	gchar *authuser;   /* NULL when SSO is enabled */
	gchar *password;   /* NULL when SSO is enabled */
	gchar *email;
	gchar *email_authdomain;
	gchar *email_authuser;   /* NULL -> use default authentication */
	gchar *email_password;

	/* SIPE protocol information */
	gchar *contact;
	gchar *register_callid;
	gchar *epid;
	gchar *focus_factory_uri;
	GSList *sessions;
	GSList *sessions_to_accept;
	/* from REGISTER response: server events
	 *  we're allowed to subscribe to
	 */
	GSList *allowed_events;

	/* Presence */
	gchar *status;
	gchar *note;
	time_t note_since;
	time_t idle_switch;
	time_t do_not_publish[SIPE_ACTIVITY_NUM_TYPES];

	/* [MS-SIP] deltaNum counters */
	guint deltanum_contacts;
	guint deltanum_acl;      /* setACE (OCS2005 only) */

	/* [MS-PRES] */
	GSList *containers;
	GSList *our_publication_keys;
	GHashTable *our_publications;
	GHashTable *user_state_publications;

	/* Buddies */
	struct sipe_groups *groups;
	struct sipe_buddies *buddies;

	/* Calendar and related stuff */
	struct sipe_calendar *calendar;

	/* EWS autodiscover */
	struct sipe_ews_autodiscover *ews_autodiscover;

	/*
	 * 2005 Custom XML piece
	 *
	 * Possibly set by other point of presence or just other client at
	 * earlier time. It should be preserved/modified, not overwritten.
	 * This implies subscription to self-contact. Information kept:
	 *
	 * - User note
	 * - OOF flag
	 * - User status
	 */
	gchar *ocs2005_user_states;

	/* Scheduling system */
	GSList *timeouts;

	/* Active subscriptions */
	GHashTable *subscriptions;

	/* Voice call */
	struct sipe_media_call_private *media_call;
	gchar *test_call_bot_uri;
	gchar *uc_line_uri;
	/**
	 *  Provides the necessary information on where we can obtain
	 *  credentials for the A/V Edge server service.
	 */
	gchar *mras_uri;
	gchar *media_relay_username;
	gchar *media_relay_password;
	GSList *media_relays;

	/* Group chat */
	struct sipe_groupchat *groupchat;
	gchar *persistentChatPool_uri;

	/* buddy menu memory allocation */
	GSList *blist_menu_containers;

	/* For RCC - Remote Call Control */
	struct sip_csta *csta;

	struct sipe_dns_query *dns_query;

	/* HTTP service */
	struct sipe_http *http;

	/* TLS-DSK: Certificates & Web services */
	struct sipe_certificate *certificate;
	struct sipe_webticket *webticket;
	struct sipe_svc *svc;

	/* Unified Contact Store */
	struct sipe_ucs *ucs;

	/* [MS-DLX] server URI */
	gchar *dlx_uri;

	/* Addressbook server URI */
	gchar *addressbook_uri;
};

/**
 * Flags - stored in sipe_core_public.flags but names not exported
 */
/* server is OCS2007+ */
#define SIPE_CORE_PRIVATE_FLAG_OCS2007            0x80000000
/* we are connected from outside the enterprise network boundary
 * via Edge Server */
#define SIPE_CORE_PRIVATE_FLAG_REMOTE_USER        0x40000000
/* multiple points of presence detected */
#define SIPE_CORE_PRIVATE_FLAG_MPOP               0x20000000
/* if there is support for batched subscription*/
#define SIPE_CORE_PRIVATE_FLAG_BATCHED_SUPPORT    0x10000000
/* if note is out-of-office note */
#define SIPE_CORE_PRIVATE_FLAG_OOF_NOTE           0x08000000
/* whether we published our initial state or not */
#define SIPE_CORE_PRIVATE_FLAG_INITIAL_PUBLISH    0x04000000
/* whether basic access level is set or not */
#define SIPE_CORE_PRIVATE_FLAG_ACCESS_LEVEL_SET   0x02000000
/* whether subscribed to buddies presence or not */
#define SIPE_CORE_PRIVATE_FLAG_SUBSCRIBED_BUDDIES 0x01000000
/* user enabled Single-Sign On */
#define SIPE_CORE_PRIVATE_FLAG_SSO                0x00800000
/* server is Lync 2013+ */
#define SIPE_CORE_PRIVATE_FLAG_LYNC2013           0x00400000

#define SIPE_CORE_PUBLIC_FLAG_IS(flag)    \
	((sipe_private->public.flags & SIPE_CORE_FLAG_ ## flag) == SIPE_CORE_FLAG_ ## flag)
#define SIPE_CORE_PUBLIC_FLAG_SET(flag)   \
	(sipe_private->public.flags |= SIPE_CORE_FLAG_ ## flag)
#define SIPE_CORE_PUBLIC_FLAG_UNSET(flag)				\
	(sipe_private->public.flags &= ~SIPE_CORE_FLAG_ ## flag)
#define SIPE_CORE_PRIVATE_FLAG_IS(flag)    \
	((sipe_private->public.flags & SIPE_CORE_PRIVATE_FLAG_ ## flag) == SIPE_CORE_PRIVATE_FLAG_ ## flag)
#define SIPE_CORE_PRIVATE_FLAG_SET(flag)   \
	(sipe_private->public.flags |= SIPE_CORE_PRIVATE_FLAG_ ## flag)
#define SIPE_CORE_PRIVATE_FLAG_UNSET(flag)				\
	(sipe_private->public.flags &= ~SIPE_CORE_PRIVATE_FLAG_ ## flag)

/* Convenience macros */
#define SIPE_CORE_PRIVATE ((struct sipe_core_private *)sipe_public)
#define SIPE_CORE_PUBLIC  ((struct sipe_core_public *)sipe_private)

/**
 * sipe-core internal functions
 */
void sipe_core_backend_initialized(struct sipe_core_private *sipe_private,
				   guint authentication);
void sipe_core_connection_cleanup(struct sipe_core_private *sipe_private);
void sipe_core_email_authentication(struct sipe_core_private *sipe_private,
				    struct sipe_http_request *request);

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
