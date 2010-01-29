/**
 * @file sipe.c
 *
 * pidgin-sipe
 *
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

#ifndef _WIN32
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <net/if.h>
#else
#ifdef _DLL
#define _WS2TCPIP_H_
#define _WINSOCK2API_
#define _LIBC_INTERNAL_
#endif /* _DLL */
#include "internal.h"
#endif /* _WIN32 */

#include <time.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>


#include "accountopt.h"
#include "blist.h"
#include "conversation.h"
#include "dnsquery.h"
#include "debug.h"
#include "notify.h"
#include "savedstatuses.h"
#include "privacy.h"
#include "prpl.h"
#include "plugin.h"
#include "util.h"
#include "version.h"
#include "network.h"
#include "xmlnode.h"
#include "mime.h"
#include "core.h"

#include "sipe.h"
#include "sipe-cal.h"
#include "sipe-ews.h"
#include "sipe-chat.h"
#include "sipe-conf.h"
#include "sip-csta.h"
#include "sipe-dialog.h"
#include "sipe-nls.h"
#include "sipe-session.h"
#include "sipe-utils.h"
#include "sipmsg.h"
#include "sipe-sign.h"
#include "dnssrv.h"
#include "request.h"

/* Backward compatibility when compiling against 2.4.x API */
#if !PURPLE_VERSION_CHECK(2,5,0)
#define PURPLE_CONNECTION_ALLOW_CUSTOM_SMILEY 0x0100
#endif

#define SIPE_IDLE_SET_DELAY		1	/* 1 sec */

#define UPDATE_CALENDAR_DELAY		1*60	/* 1 min */
#define UPDATE_CALENDAR_INTERVAL	30*60	/* 30 min */

/* Keep in sync with sipe_transport_type! */
static const char *transport_descriptor[] = { "tls", "tcp", "udp" };
#define TRANSPORT_DESCRIPTOR (transport_descriptor[sip->transport])

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


/* Action name templates */
#define ACTION_NAME_PRESENCE "<presence><%s>"

static sipe_activity
sipe_get_activity_by_token(const char *token)
{
	int i;

	for (i = 0; i < SIPE_ACTIVITY_NUM_TYPES; i++)
	{
		if (!strcmp(token, sipe_activity_map[i].token))
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

/** Allows to send typed messages from chat window again after account reinstantiation. */
static void
sipe_rejoin_chat(PurpleConversation *conv)
{
	if (purple_conversation_get_type(conv) == PURPLE_CONV_TYPE_CHAT &&
	    PURPLE_CONV_CHAT(conv)->left)
	{
		PURPLE_CONV_CHAT(conv)->left = FALSE;
		purple_conversation_update(conv, PURPLE_CONV_UPDATE_CHATLEFT);
	}
}

static char *genbranch()
{
	return g_strdup_printf("z9hG4bK%04X%04X%04X%04X%04X",
		rand() & 0xFFFF, rand() & 0xFFFF, rand() & 0xFFFF,
		rand() & 0xFFFF, rand() & 0xFFFF);
}


static char *default_ua = NULL;
static const char*
sipe_get_useragent(struct sipe_account_data *sip)
{
	const char *useragent = purple_account_get_string(sip->account, "useragent", "");
	if (is_empty(useragent)) {
		if (!default_ua) {
/*@TODO: better approach to define _user_ OS, it's version and host architecture */
/* ref: lzodefs.h */
#if defined(__linux__) || defined(__linux) || defined(__LINUX__)
  #define SIPE_TARGET_PLATFORM "linux"
#elif defined(__NetBSD__) ||defined( __OpenBSD__) || defined(__FreeBSD__)
  #define SIPE_TARGET_PLATFORM "bsd"
#  elif defined(__APPLE__) || defined(__MACOS__)
  #define SIPE_TARGET_PLATFORM "macosx"
#elif defined(__solaris__) || defined(__sun)
  #define SIPE_TARGET_PLATFORM "sun"
#elif defined(_WIN32)
  #define SIPE_TARGET_PLATFORM "win"
#else
  #define SIPE_TARGET_PLATFORM "generic"
#endif

#if defined(__amd64__) || defined(__x86_64__) || defined(_M_AMD64)
  #define SIPE_TARGET_ARCH "x86_64"
#elif defined(__386__) || defined(__i386__) || defined(__i386) || defined(_M_IX86) || defined(_M_I386)
  #define SIPE_TARGET_ARCH "i386"
#elif defined(__ppc64__)
  #define SIPE_TARGET_ARCH "ppc64"
#elif defined(__powerpc__) || defined(__powerpc) || defined(__ppc__) || defined(__PPC__) || defined(_M_PPC) || defined(_ARCH_PPC) || defined(_ARCH_PWR)
  #define SIPE_TARGET_ARCH "ppc"
#else
  #define SIPE_TARGET_ARCH "other"
#endif

			default_ua = g_strdup_printf("Purple/%s Sipe/%s (%s-%s; %s)",
					purple_core_get_version(),
					SIPE_VERSION,
					SIPE_TARGET_PLATFORM,
					SIPE_TARGET_ARCH,
					sip->server_version ? sip->server_version : "");
		}
		useragent = default_ua;
	}
	return useragent;
}

static const char *sipe_list_icon(SIPE_UNUSED_PARAMETER PurpleAccount *a,
				  SIPE_UNUSED_PARAMETER PurpleBuddy *b)
{
	return "sipe";
}

static void sipe_plugin_destroy(PurplePlugin *plugin);

static gboolean process_register_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *trans);

static void sipe_input_cb_ssl(gpointer data, PurpleSslConnection *gsc, PurpleInputCondition cond);
static void sipe_ssl_connect_failure(PurpleSslConnection *gsc, PurpleSslErrorType error,
                                     gpointer data);

static void sipe_close(PurpleConnection *gc);

static void send_presence_status(struct sipe_account_data *sip);

static void sendout_pkt(PurpleConnection *gc, const char *buf);

static void sipe_keep_alive(PurpleConnection *gc)
{
	struct sipe_account_data *sip = gc->proto_data;
	if (sip->transport == SIPE_TRANSPORT_UDP) {
		/* in case of UDP send a packet only with a 0 byte to remain in the NAT table */
		gchar buf[2] = {0, 0};
		purple_debug_info("sipe", "sending keep alive\n");
		sendto(sip->fd, buf, 1, 0, sip->serveraddr, sizeof(struct sockaddr_in));
	} else {
		time_t now = time(NULL);
		if ((sip->keepalive_timeout > 0) &&
		    ((guint) (now - sip->last_keepalive) >= sip->keepalive_timeout)
#if PURPLE_VERSION_CHECK(2,4,0)
		    && ((guint) (now - gc->last_received) >= sip->keepalive_timeout)
#endif
		    ) {
			purple_debug_info("sipe", "sending keep alive %d\n",sip->keepalive_timeout);
			sendout_pkt(gc, "\r\n\r\n");
			sip->last_keepalive = now;
		}
	}
}

static struct sip_connection *connection_find(struct sipe_account_data *sip, int fd)
{
	struct sip_connection *ret = NULL;
	GSList *entry = sip->openconns;
	while (entry) {
		ret = entry->data;
		if (ret->fd == fd) return ret;
		entry = entry->next;
	}
	return NULL;
}

static void sipe_auth_free(struct sip_auth *auth)
{
	g_free(auth->opaque);
	auth->opaque = NULL;
	g_free(auth->realm);
	auth->realm = NULL;
	g_free(auth->target);
	auth->target = NULL;
	auth->type = AUTH_TYPE_UNSET;
	auth->retries = 0;
	auth->expires = 0;
	g_free(auth->gssapi_data);
	auth->gssapi_data = NULL;
	sip_sec_destroy_context(auth->gssapi_context);
	auth->gssapi_context = NULL;
}

static struct sip_connection *connection_create(struct sipe_account_data *sip, int fd)
{
	struct sip_connection *ret = g_new0(struct sip_connection, 1);
	ret->fd = fd;
	sip->openconns = g_slist_append(sip->openconns, ret);
	return ret;
}

static void connection_remove(struct sipe_account_data *sip, int fd)
{
	struct sip_connection *conn = connection_find(sip, fd);
	if (conn) {
		sip->openconns = g_slist_remove(sip->openconns, conn);
		if (conn->inputhandler) purple_input_remove(conn->inputhandler);
		g_free(conn->inbuf);
		g_free(conn);
	}
}

static void connection_free_all(struct sipe_account_data *sip)
{
	struct sip_connection *ret = NULL;
	GSList *entry = sip->openconns;
	while (entry) {
		ret = entry->data;
		connection_remove(sip, ret->fd);
		entry = sip->openconns;
	}
}

static gchar *auth_header(struct sipe_account_data *sip, struct sip_auth *auth, struct sipmsg * msg)
{
	gchar noncecount[9];
	const char *authuser = sip->authuser;
	gchar *response;
	gchar *ret;

	if (!authuser || strlen(authuser) < 1) {
		authuser = sip->username;
	}

	if (auth->type == AUTH_TYPE_NTLM || auth->type == AUTH_TYPE_KERBEROS) { /* NTLM or Kerberos */
		gchar *auth_protocol = (auth->type == AUTH_TYPE_NTLM ? "NTLM" : "Kerberos");

		// If we have a signature for the message, include that
		if (msg->signature) {
			return g_strdup_printf("%s qop=\"auth\", opaque=\"%s\", realm=\"%s\", targetname=\"%s\", crand=\"%s\", cnum=\"%s\", response=\"%s\"", auth_protocol, auth->opaque, auth->realm, auth->target, msg->rand, msg->num, msg->signature);
		}

		if ((auth->type == AUTH_TYPE_NTLM && auth->nc == 3 && auth->gssapi_data && auth->gssapi_context == NULL)
			|| (auth->type == AUTH_TYPE_KERBEROS && auth->nc == 3)) {
			gchar *gssapi_data;
			gchar *opaque;

			gssapi_data = sip_sec_init_context(&(auth->gssapi_context),
							   &(auth->expires),
							   auth->type,
							   purple_account_get_bool(sip->account, "sso", TRUE),
							   sip->authdomain ? sip->authdomain : "",
							   authuser,
							   sip->password,
							   auth->target,
							   auth->gssapi_data);
			if (!gssapi_data || !auth->gssapi_context) {
				sip->gc->wants_to_die = TRUE;
				purple_connection_error(sip->gc, _("Failed to authenticate to server"));
				return NULL;
			}

			opaque = (auth->type == AUTH_TYPE_NTLM ? g_strdup_printf(", opaque=\"%s\"", auth->opaque) : g_strdup(""));
			ret = g_strdup_printf("%s qop=\"auth\"%s, realm=\"%s\", targetname=\"%s\", gssapi-data=\"%s\"", auth_protocol, opaque, auth->realm, auth->target, gssapi_data);
			g_free(opaque);
			g_free(gssapi_data);
			return ret;
		}

		return g_strdup_printf("%s qop=\"auth\", realm=\"%s\", targetname=\"%s\", gssapi-data=\"\"", auth_protocol, auth->realm, auth->target);

	} else { /* Digest */

		/* Calculate new session key */
		if (!auth->opaque) {
			purple_debug(PURPLE_DEBUG_MISC, "sipe", "Digest nonce: %s realm: %s\n", auth->gssapi_data, auth->realm);
			auth->opaque = purple_cipher_http_digest_calculate_session_key("md5",
										       authuser, auth->realm, sip->password,
										       auth->gssapi_data, NULL);
		}

		sprintf(noncecount, "%08d", auth->nc++);
		response = purple_cipher_http_digest_calculate_response("md5",
									msg->method, msg->target, NULL, NULL,
									auth->gssapi_data, noncecount, NULL,
									auth->opaque);
		purple_debug(PURPLE_DEBUG_MISC, "sipe", "Digest response %s\n", response);

		ret = g_strdup_printf("Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", nc=\"%s\", response=\"%s\"", authuser, auth->realm, auth->gssapi_data, msg->target, noncecount, response);
		g_free(response);
		return ret;
	}
}

static char *parse_attribute(const char *attrname, const char *source)
{
	const char *tmp, *tmp2;
	char *retval = NULL;
	int len = strlen(attrname);

	if (!strncmp(source, attrname, len)) {
		tmp = source + len;
		tmp2 = g_strstr_len(tmp, strlen(tmp), "\"");
		if (tmp2)
			retval = g_strndup(tmp, tmp2 - tmp);
		else
			retval = g_strdup(tmp);
	}

	return retval;
}

static void fill_auth(gchar *hdr, struct sip_auth *auth)
{
	int i;
	gchar **parts;

	if (!hdr) {
		purple_debug_error("sipe", "fill_auth: hdr==NULL\n");
		return;
	}

	if (!g_strncasecmp(hdr, "NTLM", 4)) {
		purple_debug(PURPLE_DEBUG_MISC, "sipe", "fill_auth: type NTLM\n");
		auth->type = AUTH_TYPE_NTLM;
		hdr += 5;
		auth->nc = 1;
	} else	if (!g_strncasecmp(hdr, "Kerberos", 8)) {
		purple_debug(PURPLE_DEBUG_MISC, "sipe", "fill_auth: type Kerberos\n");
		auth->type = AUTH_TYPE_KERBEROS;
		hdr += 9;
		auth->nc = 3;
	} else {
		purple_debug(PURPLE_DEBUG_MISC, "sipe", "fill_auth: type Digest\n");
		auth->type = AUTH_TYPE_DIGEST;
		hdr += 7;
	}

	parts = g_strsplit(hdr, "\", ", 0);
	for (i = 0; parts[i]; i++) {
		char *tmp;

		//purple_debug_info("sipe", "parts[i] %s\n", parts[i]);

		if ((tmp = parse_attribute("gssapi-data=\"", parts[i]))) {
			g_free(auth->gssapi_data);
			auth->gssapi_data = tmp;

			if (auth->type == AUTH_TYPE_NTLM) {
				/* NTLM module extracts nonce from gssapi-data */
				auth->nc = 3;
			}

		} else if ((tmp = parse_attribute("nonce=\"", parts[i]))) {
			/* Only used with AUTH_TYPE_DIGEST */
			g_free(auth->gssapi_data);
			auth->gssapi_data = tmp;
		} else if ((tmp = parse_attribute("opaque=\"", parts[i]))) {
			g_free(auth->opaque);
			auth->opaque = tmp;
		} else if ((tmp = parse_attribute("realm=\"", parts[i]))) {
			g_free(auth->realm);
			auth->realm = tmp;

			if (auth->type == AUTH_TYPE_DIGEST) {
				/* Throw away old session key */
				g_free(auth->opaque);
				auth->opaque = NULL;
				auth->nc = 1;
			}

		} else if ((tmp = parse_attribute("targetname=\"", parts[i]))) {
			g_free(auth->target);
			auth->target = tmp;
		}
	}
	g_strfreev(parts);

	return;
}

static void sipe_canwrite_cb(gpointer data,
			     SIPE_UNUSED_PARAMETER gint source,
			     SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	PurpleConnection *gc = data;
	struct sipe_account_data *sip = gc->proto_data;
	gsize max_write;
	gssize written;

	max_write = purple_circ_buffer_get_max_read(sip->txbuf);

	if (max_write == 0) {
                if (sip->tx_handler != 0){
		        purple_input_remove(sip->tx_handler);
		        sip->tx_handler = 0;
                }
		return;
	}

	written = write(sip->fd, sip->txbuf->outptr, max_write);

	if (written < 0 && errno == EAGAIN)
		written = 0;
	else if (written <= 0) {
		/*TODO: do we really want to disconnect on a failure to write?*/
		purple_connection_error(gc, _("Could not write"));
		return;
	}

	purple_circ_buffer_mark_read(sip->txbuf, written);
}

static void sipe_canwrite_cb_ssl(gpointer data,
				 SIPE_UNUSED_PARAMETER gint src,
				 SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	PurpleConnection *gc = data;
	struct sipe_account_data *sip = gc->proto_data;
	gsize max_write;
	gssize written;

	max_write = purple_circ_buffer_get_max_read(sip->txbuf);

	if (max_write == 0) {
                if (sip->tx_handler != 0) {
		        purple_input_remove(sip->tx_handler);
		        sip->tx_handler = 0;
		        return;
                }
	}

	written = purple_ssl_write(sip->gsc, sip->txbuf->outptr, max_write);

	if (written < 0 && errno == EAGAIN)
		written = 0;
	else if (written <= 0) {
		/*TODO: do we really want to disconnect on a failure to write?*/
		purple_connection_error(gc, _("Could not write"));
		return;
	}

	purple_circ_buffer_mark_read(sip->txbuf, written);
}

static void sipe_input_cb(gpointer data, gint source, PurpleInputCondition cond);

static void send_later_cb(gpointer data, gint source,
			  SIPE_UNUSED_PARAMETER const gchar *error)
{
	PurpleConnection *gc = data;
	struct sipe_account_data *sip;
	struct sip_connection *conn;

	if (!PURPLE_CONNECTION_IS_VALID(gc))
	{
		if (source >= 0)
			close(source);
		return;
	}

	if (source < 0) {
		purple_connection_error(gc, _("Could not connect"));
		return;
	}

	sip = gc->proto_data;
	sip->fd = source;
	sip->connecting = FALSE;
	sip->last_keepalive = time(NULL);

	sipe_canwrite_cb(gc, sip->fd, PURPLE_INPUT_WRITE);

	/* If there is more to write now, we need to register a handler */
	if (sip->txbuf->bufused > 0)
		sip->tx_handler = purple_input_add(sip->fd, PURPLE_INPUT_WRITE, sipe_canwrite_cb, gc);

	conn = connection_create(sip, source);
	conn->inputhandler = purple_input_add(sip->fd, PURPLE_INPUT_READ, sipe_input_cb, gc);
}

static struct sipe_account_data *sipe_setup_ssl(PurpleConnection *gc, PurpleSslConnection *gsc)
{
	struct sipe_account_data *sip;

	if (!PURPLE_CONNECTION_IS_VALID(gc))
	{
		if (gsc) purple_ssl_close(gsc);
		return NULL;
	}

	sip = gc->proto_data;
	sip->fd = gsc->fd;
        sip->gsc = gsc;
        sip->listenport = purple_network_get_port_from_fd(gsc->fd);
	sip->connecting = FALSE;
	sip->last_keepalive = time(NULL);

	connection_create(sip, gsc->fd);

	purple_ssl_input_add(gsc, sipe_input_cb_ssl, gc);

	return sip;
}

static void send_later_cb_ssl(gpointer data, PurpleSslConnection *gsc,
			      SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	PurpleConnection *gc = data;
	struct sipe_account_data *sip = sipe_setup_ssl(gc, gsc);
	if (sip == NULL) return;

	sipe_canwrite_cb_ssl(gc, gsc->fd, PURPLE_INPUT_WRITE);

	/* If there is more to write now */
	if (sip->txbuf->bufused > 0) {
                sip->tx_handler = purple_input_add(gsc->fd, PURPLE_INPUT_WRITE, sipe_canwrite_cb_ssl, gc);
	}
}


static void sendlater(PurpleConnection *gc, const char *buf)
{
	struct sipe_account_data *sip = gc->proto_data;

	if (!sip->connecting) {
		purple_debug_info("sipe", "connecting to %s port %d\n", sip->realhostname ? sip->realhostname : "{NULL}", sip->realport);
                if (sip->transport == SIPE_TRANSPORT_TLS){
                         sip->gsc = purple_ssl_connect(sip->account,sip->realhostname, sip->realport, send_later_cb_ssl, sipe_ssl_connect_failure, sip->gc);
                } else {
			if (purple_proxy_connect(gc, sip->account, sip->realhostname, sip->realport, send_later_cb, gc) == NULL) {
				purple_connection_error(gc, _("Could not create socket"));
			}
                 }
		sip->connecting = TRUE;
	}

	if (purple_circ_buffer_get_max_read(sip->txbuf) > 0)
		purple_circ_buffer_append(sip->txbuf, "\r\n", 2);

	purple_circ_buffer_append(sip->txbuf, buf, strlen(buf));
}

static void sendout_pkt(PurpleConnection *gc, const char *buf)
{
	struct sipe_account_data *sip = gc->proto_data;
	time_t currtime = time(NULL);
	int writelen = strlen(buf);
	char *tmp;

	purple_debug(PURPLE_DEBUG_MISC, "sipe", "sending - %s######\n%s######\n", ctime(&currtime), tmp = fix_newlines(buf));
	g_free(tmp);
	if (sip->transport == SIPE_TRANSPORT_UDP) {
		if (sendto(sip->fd, buf, writelen, 0, sip->serveraddr, sizeof(struct sockaddr_in)) < writelen) {
			purple_debug_info("sipe", "could not send packet\n");
		}
	} else {
		int ret;
		if (sip->fd < 0) {
			sendlater(gc, buf);
			return;
		}

		if (sip->tx_handler) {
			ret = -1;
			errno = EAGAIN;
		} else{
                  if (sip->gsc){
                        ret = purple_ssl_write(sip->gsc, buf, writelen);
                  }else{
			ret = write(sip->fd, buf, writelen);
                  }
               }

		if (ret < 0 && errno == EAGAIN)
			ret = 0;
		else if (ret <= 0) { /* XXX: When does this happen legitimately? */
			sendlater(gc, buf);
			return;
		}

		if (ret < writelen) {
			if (!sip->tx_handler){
                                if (sip->gsc){
                                        sip->tx_handler = purple_input_add(sip->gsc->fd, PURPLE_INPUT_WRITE, sipe_canwrite_cb_ssl, gc);
                                }
                                else{
					sip->tx_handler = purple_input_add(sip->fd,
					PURPLE_INPUT_WRITE, sipe_canwrite_cb,
					gc);
                                 }
                        }

			/* XXX: is it OK to do this? You might get part of a request sent
			   with part of another. */
			if (sip->txbuf->bufused > 0)
				purple_circ_buffer_append(sip->txbuf, "\r\n", 2);

			purple_circ_buffer_append(sip->txbuf, buf + ret,
				writelen - ret);
		}
	}
}

static int sipe_send_raw(PurpleConnection *gc, const char *buf, int len)
{
	sendout_pkt(gc, buf);
	return len;
}

static void sendout_sipmsg(struct sipe_account_data *sip, struct sipmsg *msg)
{
	GSList *tmp = msg->headers;
	gchar *name;
	gchar *value;
	GString *outstr = g_string_new("");
	g_string_append_printf(outstr, "%s %s SIP/2.0\r\n", msg->method, msg->target);
	while (tmp) {
		name = ((struct siphdrelement*) (tmp->data))->name;
		value = ((struct siphdrelement*) (tmp->data))->value;
		g_string_append_printf(outstr, "%s: %s\r\n", name, value);
		tmp = g_slist_next(tmp);
	}
	g_string_append_printf(outstr, "\r\n%s", msg->body ? msg->body : "");
	sendout_pkt(sip->gc, outstr->str);
	g_string_free(outstr, TRUE);
}

static void sign_outgoing_message (struct sipmsg * msg, struct sipe_account_data *sip, const gchar *method)
{
	gchar * buf;

	if (sip->registrar.type == AUTH_TYPE_UNSET) {
		return;
	}

	if (sip->registrar.gssapi_context) {
		struct sipmsg_breakdown msgbd;
		gchar *signature_input_str;
		msgbd.msg = msg;
		sipmsg_breakdown_parse(&msgbd, sip->registrar.realm, sip->registrar.target);
		msgbd.rand = g_strdup_printf("%08x", g_random_int());
		sip->registrar.ntlm_num++;
		msgbd.num = g_strdup_printf("%d", sip->registrar.ntlm_num);
		signature_input_str = sipmsg_breakdown_get_string(&msgbd);
		if (signature_input_str != NULL) {
			char *signature_hex = sip_sec_make_signature(sip->registrar.gssapi_context, signature_input_str);
			msg->signature = signature_hex;
			msg->rand = g_strdup(msgbd.rand);
			msg->num = g_strdup(msgbd.num);
			g_free(signature_input_str);
		}
		sipmsg_breakdown_free(&msgbd);
	}

	if (sip->registrar.type && !strcmp(method, "REGISTER")) {
		buf = auth_header(sip, &sip->registrar, msg);
		if (buf) {
			sipmsg_add_header_now_pos(msg, "Authorization", buf, 5);
		}
		g_free(buf);
	} else if (!strcmp(method,"SUBSCRIBE") || !strcmp(method,"SERVICE") || !strcmp(method,"MESSAGE") || !strcmp(method,"INVITE") || !strcmp(method, "ACK") || !strcmp(method, "NOTIFY") || !strcmp(method, "BYE") || !strcmp(method, "INFO") || !strcmp(method, "OPTIONS") || !strcmp(method, "REFER")) {
		sip->registrar.nc = 3;
#ifdef USE_KERBEROS
		if (!purple_account_get_bool(sip->account, "krb5", FALSE)) {
#endif
			sip->registrar.type = AUTH_TYPE_NTLM;
#ifdef USE_KERBEROS
		} else {
			sip->registrar.type = AUTH_TYPE_KERBEROS;
		}
#endif


		buf = auth_header(sip, &sip->registrar, msg);
		sipmsg_add_header_now_pos(msg, "Proxy-Authorization", buf, 5);
	        g_free(buf);
	} else {
		purple_debug_info("sipe", "not adding auth header to msg w/ method %s\n", method);
	}
}

void send_sip_response(PurpleConnection *gc, struct sipmsg *msg, int code,
		       const char *text, const char *body)
{
	gchar *name;
	gchar *value;
	GString *outstr = g_string_new("");
	struct sipe_account_data *sip = gc->proto_data;
	gchar *contact;
	GSList *tmp;
	const gchar *keepers[] = { "To", "From", "Call-ID", "CSeq", "Via", "Record-Route", NULL };

	contact = get_contact(sip);
	sipmsg_add_header(msg, "Contact", contact);
	g_free(contact);

	if (body) {
		gchar len[12];
		sprintf(len, "%" G_GSIZE_FORMAT , (gsize) strlen(body));
		sipmsg_add_header(msg, "Content-Length", len);
	} else {
		sipmsg_add_header(msg, "Content-Length", "0");
	}

	msg->response = code;

	sipmsg_strip_headers(msg, keepers);
	sipmsg_merge_new_headers(msg);
	sign_outgoing_message(msg, sip, msg->method);

	g_string_append_printf(outstr, "SIP/2.0 %d %s\r\n", code, text);
	tmp = msg->headers;
	while (tmp) {
		name = ((struct siphdrelement*) (tmp->data))->name;
		value = ((struct siphdrelement*) (tmp->data))->value;

		g_string_append_printf(outstr, "%s: %s\r\n", name, value);
		tmp = g_slist_next(tmp);
	}
	g_string_append_printf(outstr, "\r\n%s", body ? body : "");
	sendout_pkt(gc, outstr->str);
	g_string_free(outstr, TRUE);
}

static void transactions_remove(struct sipe_account_data *sip, struct transaction *trans)
{
	if (sip->transactions) {
		sip->transactions = g_slist_remove(sip->transactions, trans);
		purple_debug_info("sipe", "sip->transactions count:%d after removal\n", g_slist_length(sip->transactions));

		if (trans->msg) sipmsg_free(trans->msg);
		if (trans->payload) {
			(*trans->payload->destroy)(trans->payload->data);
			g_free(trans->payload);
		}
		g_free(trans->key);
		g_free(trans);
	}
}

static struct transaction *
transactions_add_buf(struct sipe_account_data *sip, const struct sipmsg *msg, void *callback)
{
	gchar *call_id = NULL;
	gchar *cseq = NULL;
	struct transaction *trans = g_new0(struct transaction, 1);

	trans->time = time(NULL);
	trans->msg = (struct sipmsg *)msg;
	call_id = sipmsg_find_header(trans->msg, "Call-ID");
	cseq = sipmsg_find_header(trans->msg, "CSeq");
	trans->key = g_strdup_printf("<%s><%s>", call_id, cseq);
	trans->callback = callback;
	sip->transactions = g_slist_append(sip->transactions, trans);
	purple_debug_info("sipe", "sip->transactions count:%d after addition\n", g_slist_length(sip->transactions));
	return trans;
}

static struct transaction *transactions_find(struct sipe_account_data *sip, struct sipmsg *msg)
{
	struct transaction *trans;
	GSList *transactions = sip->transactions;
	gchar *call_id = sipmsg_find_header(msg, "Call-ID");
	gchar *cseq = sipmsg_find_header(msg, "CSeq");
	gchar *key = g_strdup_printf("<%s><%s>", call_id, cseq);

	while (transactions) {
		trans = transactions->data;
		if (!g_strcasecmp(trans->key, key)) {
			g_free(key);
			return trans;
		}
		transactions = transactions->next;
	}

	g_free(key);
	return NULL;
}

struct transaction *
send_sip_request(PurpleConnection *gc, const gchar *method,
		const gchar *url, const gchar *to, const gchar *addheaders,
		const gchar *body, struct sip_dialog *dialog, TransCallback tc)
{
	struct sipe_account_data *sip = gc->proto_data;
	const char *addh = "";
	char *buf;
	struct sipmsg *msg;
	gchar *ourtag    = dialog && dialog->ourtag    ? g_strdup(dialog->ourtag)    : NULL;
	gchar *theirtag  = dialog && dialog->theirtag  ? g_strdup(dialog->theirtag)  : NULL;
	gchar *theirepid = dialog && dialog->theirepid ? g_strdup(dialog->theirepid) : NULL;
	gchar *callid    = dialog && dialog->callid    ? g_strdup(dialog->callid)    : gencallid();
	gchar *branch    = dialog && dialog->callid    ? NULL : genbranch();
	gchar *route     = g_strdup("");
	gchar *epid      = get_epid(sip);
	int cseq         = dialog ? ++dialog->cseq : 1 /* as Call-Id is new in this case */;
	struct transaction *trans = NULL;

	if (dialog && dialog->routes)
	{
		GSList *iter = dialog->routes;

		while(iter)
		{
			char *tmp = route;
			route = g_strdup_printf("%sRoute: <%s>\r\n", route, (char *)iter->data);
			g_free(tmp);
			iter = g_slist_next(iter);
		}
	}

	if (!ourtag && !dialog) {
		ourtag = gentag();
	}

	if (!strcmp(method, "REGISTER")) {
		if (sip->regcallid) {
			g_free(callid);
			callid = g_strdup(sip->regcallid);
		} else {
			sip->regcallid = g_strdup(callid);
		}
		cseq = ++sip->cseq;
	}

	if (addheaders) addh = addheaders;

	buf = g_strdup_printf("%s %s SIP/2.0\r\n"
			"Via: SIP/2.0/%s %s:%d%s%s\r\n"
			"From: <sip:%s>%s%s;epid=%s\r\n"
			"To: <%s>%s%s%s%s\r\n"
			"Max-Forwards: 70\r\n"
			"CSeq: %d %s\r\n"
			"User-Agent: %s\r\n"
			"Call-ID: %s\r\n"
			"%s%s"
			"Content-Length: %" G_GSIZE_FORMAT "\r\n\r\n%s",
			method,
			dialog && dialog->request ? dialog->request : url,
			TRANSPORT_DESCRIPTOR,
			purple_network_get_my_ip(-1),
			sip->listenport,
			branch ? ";branch=" : "",
			branch ? branch : "",
			sip->username,
			ourtag ? ";tag=" : "",
			ourtag ? ourtag : "",
			epid,
			to,
			theirtag ? ";tag=" : "",
			theirtag ? theirtag : "",
			theirepid ? ";epid=" : "",
			theirepid ? theirepid : "",
			cseq,
			method,
			sipe_get_useragent(sip),
			callid,
			route,
			addh,
			body ? (gsize) strlen(body) : 0,
			body ? body : "");


	//printf ("parsing msg buf:\n%s\n\n", buf);
	msg = sipmsg_parse_msg(buf);

	g_free(buf);
	g_free(ourtag);
	g_free(theirtag);
	g_free(theirepid);
	g_free(branch);
	g_free(callid);
	g_free(route);
	g_free(epid);

	sign_outgoing_message (msg, sip, method);

	buf = sipmsg_to_string (msg);

	/* add to ongoing transactions */
	/* ACK isn't supposed to be answered ever. So we do not keep transaction for it. */
	if (strcmp(method, "ACK")) {
		trans = transactions_add_buf(sip, msg, tc);
	} else {
		sipmsg_free(msg);
	}
	sendout_pkt(gc, buf);
	g_free(buf);

	return trans;
}

/**
 * @param from0	from URI (with 'sip:' prefix). Will be filled with self-URI if NULL passed.
 */
static void
send_soap_request_with_cb(struct sipe_account_data *sip,
			  gchar *from0,
			  gchar *body,
			  TransCallback callback,
			  struct transaction_payload *payload)
{
	gchar *from = from0 ? g_strdup(from0) : sip_uri_self(sip);
	gchar *contact = get_contact(sip);
	gchar *hdr = g_strdup_printf("Contact: %s\r\n"
	                             "Content-Type: application/SOAP+xml\r\n",contact);

	struct transaction *trans = send_sip_request(sip->gc, "SERVICE", from, from, hdr, body, NULL, callback);
	trans->payload = payload;

	g_free(from);
	g_free(contact);
	g_free(hdr);
}

static void send_soap_request(struct sipe_account_data *sip, gchar *body)
{
	send_soap_request_with_cb(sip, NULL, body, NULL, NULL);
}

static char *get_contact_register(struct sipe_account_data  *sip)
{
	char *epid = get_epid(sip);
	char *uuid = generateUUIDfromEPID(epid);
	char *buf = g_strdup_printf("<sip:%s:%d;transport=%s;ms-opaque=d3470f2e1d>;methods=\"INVITE, MESSAGE, INFO, SUBSCRIBE, OPTIONS, BYE, CANCEL, NOTIFY, ACK, REFER, BENOTIFY\";proxy=replace;+sip.instance=\"<urn:uuid:%s>\"", purple_network_get_my_ip(-1), sip->listenport,  TRANSPORT_DESCRIPTOR, uuid);
	g_free(uuid);
	g_free(epid);
	return(buf);
}

static void do_register_exp(struct sipe_account_data *sip, int expire)
{
	char *uri;
	char *expires;
	char *to;
	char *contact;
	char *hdr;

	if (!sip->sipdomain) return;

	uri = sip_uri_from_name(sip->sipdomain);
	expires = expire >= 0 ? g_strdup_printf("Expires: %d\r\n", expire) : g_strdup("");
	to = sip_uri_self(sip);
	contact = get_contact_register(sip);
	hdr = g_strdup_printf("Contact: %s\r\n"
				    "Supported: gruu-10, adhoclist, msrtc-event-categories, com.microsoft.msrtc.presence\r\n"
				    "Event: registration\r\n"
				    "Allow-Events: presence\r\n"
				    "ms-keep-alive: UAC;hop-hop=yes\r\n"
				    "%s", contact, expires);
	g_free(contact);
	g_free(expires);

	sip->registerstatus = 1;

	send_sip_request(sip->gc, "REGISTER", uri, to, hdr, "", NULL,
		process_register_response);

	g_free(hdr);
	g_free(uri);
	g_free(to);
}

static void do_register_cb(struct sipe_account_data *sip,
			   SIPE_UNUSED_PARAMETER void *unused)
{
	do_register_exp(sip, -1);
	sip->reregister_set = FALSE;
}

static void do_register(struct sipe_account_data *sip)
{
	do_register_exp(sip, -1);
}

static void
sipe_contact_set_acl (struct sipe_account_data *sip, const gchar * who, gchar * rights)
{
	gchar * body = g_strdup_printf(SIPE_SOAP_ALLOW_DENY, who, rights, sip->acl_delta++);
	send_soap_request(sip, body);
	g_free(body);
}

static void
sipe_contact_allow_deny (struct sipe_account_data *sip, const gchar * who, gboolean allow)
{
	if (allow) {
		purple_debug_info("sipe", "Authorizing contact %s\n", who);
	} else {
		purple_debug_info("sipe", "Blocking contact %s\n", who);
	}

	sipe_contact_set_acl (sip, who, allow ? "AA" : "BD");
}

static
void sipe_auth_user_cb(void * data)
{
	struct sipe_auth_job * job = (struct sipe_auth_job *) data;
	if (!job) return;

	sipe_contact_allow_deny (job->sip, job->who, TRUE);
	g_free(job);
}

static
void sipe_deny_user_cb(void * data)
{
	struct sipe_auth_job * job = (struct sipe_auth_job *) data;
	if (!job) return;

	sipe_contact_allow_deny (job->sip, job->who, FALSE);
	g_free(job);
}

static void
sipe_add_permit(PurpleConnection *gc, const char *name)
{
	struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;
	sipe_contact_allow_deny(sip, name, TRUE);
}

static void
sipe_add_deny(PurpleConnection *gc, const char *name)
{
	struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;
	sipe_contact_allow_deny(sip, name, FALSE);
}

/*static void
sipe_remove_permit_deny(PurpleConnection *gc, const char *name)
{
	struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;
	sipe_contact_set_acl(sip, name, "");
}*/

static void
sipe_process_presence_wpending (struct sipe_account_data *sip, struct sipmsg * msg)
{
	xmlnode *watchers;
	xmlnode *watcher;
	// Ensure it's either not a response (eg it's a BENOTIFY) or that it's a 200 OK response
	if (msg->response != 0 && msg->response != 200) return;

	if (msg->bodylen == 0 || msg->body == NULL || !strcmp(sipmsg_find_header(msg, "Event"), "msrtc.wpending")) return;

	watchers = xmlnode_from_str(msg->body, msg->bodylen);
	if (!watchers) return;

	for (watcher = xmlnode_get_child(watchers, "watcher"); watcher; watcher = xmlnode_get_next_twin(watcher)) {
		gchar * remote_user = g_strdup(xmlnode_get_attrib(watcher, "uri"));
		gchar * alias = g_strdup(xmlnode_get_attrib(watcher, "displayName"));
		gboolean on_list = g_hash_table_lookup(sip->buddies, remote_user) != NULL;

		// TODO pull out optional displayName to pass as alias
		if (remote_user) {
			struct sipe_auth_job * job = g_new0(struct sipe_auth_job, 1);
			job->who = remote_user;
			job->sip = sip;
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


	xmlnode_free(watchers);
	return;
}

static void
sipe_group_add (struct sipe_account_data *sip, struct sipe_group * group)
{
	PurpleGroup * purple_group = purple_find_group(group->name);
	if (!purple_group) {
		purple_group = purple_group_new(group->name);
		purple_blist_add_group(purple_group, NULL);
	}

	if (purple_group) {
		group->purple_group = purple_group;
		sip->groups = g_slist_append(sip->groups, group);
		purple_debug_info("sipe", "added group %s (id %d)\n", group->name, group->id);
	} else {
		purple_debug_info("sipe", "did not add group %s\n", group->name ? group->name : "");
	}
}

static struct sipe_group * sipe_group_find_by_id (struct sipe_account_data *sip, int id)
{
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

static struct sipe_group * sipe_group_find_by_name (struct sipe_account_data *sip, const gchar * name)
{
	struct sipe_group *group;
	GSList *entry;
	if (!sip || !name) {
		return NULL;
	}

	entry = sip->groups;
	while (entry) {
		group = entry->data;
		if (!strcmp(group->name, name)) {
			return group;
		}
		entry = entry->next;
	}
	return NULL;
}

static void
sipe_group_rename (struct sipe_account_data *sip, struct sipe_group * group, gchar * name)
{
	gchar *body;
	purple_debug_info("sipe", "Renaming group %s to %s\n", group->name, name);
	body = g_markup_printf_escaped(SIPE_SOAP_MOD_GROUP, group->id, name, sip->contacts_delta++);
	send_soap_request(sip, body);
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
static void
sipe_group_set_user (struct sipe_account_data *sip, const gchar * who)
{
	struct sipe_buddy *buddy = g_hash_table_lookup(sip->buddies, who);
	PurpleBuddy *purple_buddy = purple_find_buddy (sip->account, who);

	if (buddy && purple_buddy) {
		gchar *alias = (gchar *)purple_buddy_get_alias(purple_buddy);
		gchar *body;
		gchar *groups = sipe_get_buddy_groups_string(buddy);
		purple_debug_info("sipe", "Saving buddy %s with alias %s and groups %s\n", who, alias, groups);

		body = g_markup_printf_escaped(SIPE_SOAP_SET_CONTACT,
			alias, groups, "true", buddy->name, sip->contacts_delta++
		);
		send_soap_request(sip, body);
		g_free(groups);
		g_free(body);
	}
}

static gboolean process_add_group_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *trans)
{
	if (msg->response == 200) {
		struct sipe_group *group;
		struct group_user_context *ctx = trans->payload->data;
		xmlnode *xml;
		xmlnode *node;
		char *group_id;
		struct sipe_buddy *buddy;

		xml = xmlnode_from_str(msg->body, msg->bodylen);
		if (!xml) {
			return FALSE;
		}

		node = xmlnode_get_descendant(xml, "Body", "addGroup", "groupID", NULL);
		if (!node) {
			xmlnode_free(xml);
			return FALSE;
		}

		group_id = xmlnode_get_data(node);
		if (!group_id) {
			xmlnode_free(xml);
			return FALSE;
		}

		group = g_new0(struct sipe_group, 1);
		group->id = (int)g_ascii_strtod(group_id, NULL);
		g_free(group_id);
		group->name = g_strdup(ctx->group_name);

		sipe_group_add(sip, group);

		buddy = g_hash_table_lookup(sip->buddies, ctx->user_name);
		if (buddy) {
			buddy->groups = slist_insert_unique_sorted(buddy->groups, group, (GCompareFunc)sipe_group_compare);
		}

		sipe_group_set_user(sip, ctx->user_name);

		xmlnode_free(xml);
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

static void sipe_group_create (struct sipe_account_data *sip, const gchar *name, const gchar * who)
{
	struct transaction_payload *payload = g_new0(struct transaction_payload, 1);
	struct group_user_context *ctx = g_new0(struct group_user_context, 1);
	gchar *body;
	ctx->group_name = g_strdup(name);
	ctx->user_name = g_strdup(who);
	payload->destroy = sipe_group_context_destroy;
	payload->data = ctx;

	body = g_markup_printf_escaped(SIPE_SOAP_ADD_GROUP, name, sip->contacts_delta++);
	send_soap_request_with_cb(sip, NULL, body, process_add_group_response, payload);
	g_free(body);
}

/**
  * Data structure for scheduled actions
  */

struct scheduled_action {
	/**
	 * Name of action.
	 * Format is <Event>[<Data>...]
	 * Example:  <presence><sip:user@domain.com> or <registration>
	 */
	gchar *name;
	guint timeout_handler;
	gboolean repetitive;
	Action action;
	GDestroyNotify destroy;
	struct sipe_account_data *sip;
	void *payload;
};

/**
  * A timer callback
  * Should return FALSE if repetitive action is not needed
  */
static gboolean sipe_scheduled_exec(struct scheduled_action *sched_action)
{
	gboolean ret;
	purple_debug_info("sipe", "sipe_scheduled_exec: executing\n");
	sched_action->sip->timeouts = g_slist_remove(sched_action->sip->timeouts, sched_action);
	purple_debug_info("sipe", "sip->timeouts count:%d after removal\n",g_slist_length(sched_action->sip->timeouts));
	(sched_action->action)(sched_action->sip, sched_action->payload);
	ret = sched_action->repetitive;
	if (sched_action->destroy) {
		(*sched_action->destroy)(sched_action->payload);
	}
	g_free(sched_action->name);
	g_free(sched_action);
	return ret;
}

/**
  * Kills action timer effectively cancelling
  * scheduled action
  *
  * @param name of action
  */
static void sipe_cancel_scheduled_action(struct sipe_account_data *sip, const gchar *name)
{
	GSList *entry;

	if (!sip->timeouts || !name) return;

	entry = sip->timeouts;
	while (entry) {
		struct scheduled_action *sched_action = entry->data;
		if(!strcmp(sched_action->name, name)) {
			GSList *to_delete = entry;
			entry = entry->next;
			sip->timeouts = g_slist_delete_link(sip->timeouts, to_delete);
			purple_debug_info("sipe", "purple_timeout_remove: action name=%s\n", sched_action->name);
			purple_timeout_remove(sched_action->timeout_handler);
			if (sched_action->destroy) {
				(*sched_action->destroy)(sched_action->payload);
			}
			g_free(sched_action->name);
			g_free(sched_action);
		} else {
			entry = entry->next;
		}
	}
}

static void
sipe_schedule_action0(const gchar *name,
		      int timeout,
		      gboolean isSeconds,
		      Action action,
		      GDestroyNotify destroy,
		      struct sipe_account_data *sip,
		      void *payload)
{
	struct scheduled_action *sched_action;

	/* Make sure each action only exists once */
	sipe_cancel_scheduled_action(sip, name);

	purple_debug_info("sipe","scheduling action %s timeout:%d(%s)\n", name, timeout, isSeconds ? "sec" : "msec");
	sched_action = g_new0(struct scheduled_action, 1);
	sched_action->repetitive = FALSE;
	sched_action->name = g_strdup(name);
	sched_action->action = action;
	sched_action->destroy = destroy;
	sched_action->sip = sip;
	sched_action->payload = payload;
	sched_action->timeout_handler = isSeconds ? purple_timeout_add_seconds(timeout, (GSourceFunc) sipe_scheduled_exec, sched_action) :
						    purple_timeout_add(timeout, (GSourceFunc) sipe_scheduled_exec, sched_action);
	sip->timeouts = g_slist_append(sip->timeouts, sched_action);
	purple_debug_info("sipe", "sip->timeouts count:%d after addition\n",g_slist_length(sip->timeouts));
}

void
sipe_schedule_action(const gchar *name,
		     int timeout,
		     Action action,
		     GDestroyNotify destroy,
		     struct sipe_account_data *sip,
		     void *payload)
{
	sipe_schedule_action0(name, timeout, TRUE, action, destroy, sip, payload);
}

/**
  * Same as sipe_schedule_action() but timeout is in milliseconds.
  */
static void
sipe_schedule_action_msec(const gchar *name,
			  int timeout,
			  Action action,
			  GDestroyNotify destroy,
			  struct sipe_account_data *sip,
			  void *payload)
{
	sipe_schedule_action0(name, timeout, FALSE, action, destroy, sip, payload);
}

static void
sipe_sched_calendar_status_update(struct sipe_account_data *sip,
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
sipe_apply_calendar_status(struct sipe_account_data *sip,
			   struct sipe_buddy *sbuddy,
			   const char *status_id)
{
	time_t cal_avail_since;
	int cal_status = sipe_cal_get_status(sbuddy, time(NULL), &cal_avail_since);
	int avail;
	gchar *self_uri = sip_uri_self(sip);

	if (!sbuddy) return;

	if (cal_status < SIPE_CAL_NO_DATA) {
		purple_debug_info("sipe", "update_calendar_status_cb: cal_status      : %d for %s\n", cal_status, sbuddy->name);
		purple_debug_info("sipe", "update_calendar_status_cb: cal_avail_since : %s", asctime(localtime(&cal_avail_since)));
	}

	/* scheduled Cal update call */
	if (!status_id) {
		status_id = sbuddy->last_non_cal_status_id;
		g_free(sbuddy->activity);
		sbuddy->activity = g_strdup(sbuddy->last_non_cal_activity);
	}

	/* adjust to calendar status */
	if (cal_status != SIPE_CAL_NO_DATA) {
		purple_debug_info("sipe", "update_calendar_status_cb: user_avail_since: %s", asctime(localtime(&sbuddy->user_avail_since)));

		if (cal_status == SIPE_CAL_BUSY
		    && cal_avail_since > sbuddy->user_avail_since
		    && 6500 >= sipe_get_availability_by_status(status_id, NULL))
		{
			status_id = SIPE_STATUS_ID_BUSY;
			g_free(sbuddy->activity);
			sbuddy->activity = g_strdup(SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_IN_MEETING));
		}
		avail = sipe_get_availability_by_status(status_id, NULL);

		purple_debug_info("sipe", "update_calendar_status_cb: activity_since  : %s", asctime(localtime(&sbuddy->activity_since)));
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
	purple_debug_info("sipe", "sipe_got_user_status: to %s for %s\n", status_id, sbuddy->name);
	purple_prpl_got_user_status(sip->account, sbuddy->name, status_id, NULL);

	/* set our account state to the one in roaming (including calendar info) */
	if (sip->initial_state_published && !strcmp(sbuddy->name, self_uri)) {
		if (!strcmp(status_id, SIPE_STATUS_ID_OFFLINE)) {
			status_id = g_strdup(SIPE_STATUS_ID_INVISIBLE); /* not not let offline status switch us off */
		}

		purple_debug_info("sipe", "sipe_got_user_status: to %s for the account\n", sip->status);
		sipe_set_purple_account_status_and_note(sip->account, status_id, sip->note, sip->do_not_publish);		
	}
	g_free(self_uri);
}

static void
sipe_got_user_status(struct sipe_account_data *sip,
		     const char* uri,
		     const char *status_id)
{
	struct sipe_buddy *sbuddy = g_hash_table_lookup(sip->buddies, uri);

	if (!sbuddy) return;

	/* Check if on 2005 system contact's calendar,
	 * then set/preserve it.
	 */
	if (!sip->ocs2007) {
		sipe_apply_calendar_status(sip, sbuddy, status_id);
	} else {
		purple_prpl_got_user_status(sip->account, uri, status_id, NULL);
	}
}

static void
update_calendar_status_cb(SIPE_UNUSED_PARAMETER char *name,
			  struct sipe_buddy *sbuddy,
			  struct sipe_account_data *sip)
{
	sipe_apply_calendar_status(sip, sbuddy, NULL);
}

/**
 * Updates contact's status
 * based on their calendar information.
 *
 * Applicability: 2005 systems
 */
static void
update_calendar_status(struct sipe_account_data *sip)
{
	purple_debug_info("sipe", "update_calendar_status() started.\n");
	g_hash_table_foreach(sip->buddies, (GHFunc)update_calendar_status_cb, (gpointer)sip);

	/* repeat scheduling */
	sipe_sched_calendar_status_update(sip, time(NULL) + 3*60 /* 3 min */);
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
sipe_sched_calendar_status_update(struct sipe_account_data *sip,
				  time_t calculate_from)
{
	int interval = 15*60;
	/** start of the beginning of closest 15 min interval. */
	time_t next_start = ((time_t)((int)((int)calculate_from)/interval + 1)*interval);

	purple_debug_info("sipe", "sipe_sched_calendar_status_update: calculate_from time: %s",
			  asctime(localtime(&calculate_from)));
	purple_debug_info("sipe", "sipe_sched_calendar_status_update: next start time    : %s",
			  asctime(localtime(&next_start)));

	sipe_schedule_action("<+2005-cal-status>",
			     (int)(next_start - time(NULL)),
			     (Action)update_calendar_status,
			     NULL,
			     sip,
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
sipe_sched_calendar_status_self_publish(struct sipe_account_data *sip,
					time_t calculate_from)
{
	int interval = 5*60;
	/** start of the beginning of closest 5 min interval. */
	time_t next_start = ((time_t)((int)((int)calculate_from)/interval + 1)*interval);

	purple_debug_info("sipe", "sipe_sched_calendar_status_self_publish: calculate_from time: %s",
			  asctime(localtime(&calculate_from)));
	purple_debug_info("sipe", "sipe_sched_calendar_status_self_publish: next start time    : %s",
			  asctime(localtime(&next_start)));

	sipe_schedule_action("<+2007-cal-status>",
			     (int)(next_start - time(NULL)),
			     (Action)publish_calendar_status_self,
			     NULL,
			     sip,
			     NULL);
}

static void process_incoming_notify(struct sipe_account_data *sip, struct sipmsg *msg, gboolean request, gboolean benotify);

/** Should be g_free()'d
 */
static gchar *
sipe_get_subscription_key(gchar *event,
			  gchar *with)
{
	gchar *key = NULL;

	if (is_empty(event)) return NULL;

	if (event && !g_ascii_strcasecmp(event, "presence")) {
		/* Subscription is identified by ACTION_NAME_PRESENCE key */
		key = g_strdup_printf(ACTION_NAME_PRESENCE, with);

		/* @TODO drop participated buddies' just_added flag */
	} else if (event) {
		/* Subscription is identified by <event> key */
		key = g_strdup_printf("<%s>", event);
	}

	return key;
}

gboolean process_subscribe_response(struct sipe_account_data *sip, struct sipmsg *msg,
				    SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	gchar *with = parse_from(sipmsg_find_header(msg, "To"));
	gchar *event = sipmsg_find_header(msg, "Event");
	gchar *key;

	/* The case with 2005 Public IM Connectivity (PIC) - no Event header */
	if (!event) {
		struct sipmsg *request_msg = trans->msg;
		event = sipmsg_find_header(request_msg, "Event");
	}

	key = sipe_get_subscription_key(event, with);

	/* 200 OK; 481 Call Leg Does Not Exist */
	if (key && (msg->response == 200 || msg->response == 481)) {
		if (g_hash_table_lookup(sip->subscriptions, key)) {
			g_hash_table_remove(sip->subscriptions, key);
			purple_debug_info("sipe", "process_subscribe_response: subscription dialog removed for: %s\n", key);
		}
	}

	/* create/store subscription dialog if not yet */
	if (msg->response == 200) {
		gchar *callid = sipmsg_find_header(msg, "Call-ID");
		gchar *cseq = sipmsg_find_part_of_header(sipmsg_find_header(msg, "CSeq"), NULL, " ", NULL);

		if (key) {
			struct sip_subscription *subscription = g_new0(struct sip_subscription, 1);
			g_hash_table_insert(sip->subscriptions, g_strdup(key), subscription);

			subscription->dialog.callid = g_strdup(callid);
			subscription->dialog.cseq = atoi(cseq);
			subscription->dialog.with = g_strdup(with);
			subscription->event = g_strdup(event);
			sipe_dialog_parse(&subscription->dialog, msg, TRUE);

			purple_debug_info("sipe", "process_subscribe_response: subscription dialog added for: %s\n", key);
		}

		g_free(cseq);
	}

	g_free(key);
	g_free(with);

	if (sipmsg_find_header(msg, "ms-piggyback-cseq"))
	{
		process_incoming_notify(sip, msg, FALSE, FALSE);
	}
	return TRUE;
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

static void sipe_subscribe_presence_batched_to(struct sipe_account_data *sip, gchar *resources_uri, gchar *to)
{
	gchar *key;
	gchar *contact = get_contact(sip);
	gchar *request;
	gchar *content;
	gchar *require = "";
	gchar *accept = "";
        gchar *autoextend = "";
	gchar *content_type;
	struct sip_dialog *dialog;

	if (sip->ocs2007) {
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
					  "</batchSub>", sip->username, resources_uri);
	} else {
                autoextend =  "Supported: com.microsoft.autoextend\r\n";
		content_type = "application/adrl+xml";
        	content = g_strdup_printf(
					  "<adhoclist xmlns=\"urn:ietf:params:xml:ns:adrl\" uri=\"sip:%s\" name=\"sip:%s\">\n"
					  "<create xmlns=\"\">\n%s</create>\n"
					  "</adhoclist>\n", sip->username,  sip->username, resources_uri);
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

	/* subscribe to buddy presence */
	/* Subscription is identified by ACTION_NAME_PRESENCE key */
	key = g_strdup_printf(ACTION_NAME_PRESENCE, to);
	dialog = (struct sip_dialog *)g_hash_table_lookup(sip->subscriptions, key);
	purple_debug_info("sipe", "sipe_subscribe_presence_batched_to: subscription dialog for: %s is %s\n", key, dialog ? "Not NULL" : "NULL");

	send_sip_request(sip->gc, "SUBSCRIBE", to,  to, request, content, dialog, process_subscribe_response);

	g_free(content);
	g_free(to);
	g_free(request);
	g_free(key);
}

static void sipe_subscribe_presence_batched(struct sipe_account_data *sip,
					    SIPE_UNUSED_PARAMETER void *unused)
{
	gchar *to = sip_uri_self(sip);
	gchar *resources_uri = g_strdup("");
	if (sip->ocs2007) {
		g_hash_table_foreach(sip->buddies, (GHFunc) sipe_subscribe_resource_uri_with_context , &resources_uri);
	} else {
                g_hash_table_foreach(sip->buddies, (GHFunc) sipe_subscribe_resource_uri, &resources_uri);

	}
	sipe_subscribe_presence_batched_to(sip, resources_uri, to);
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

static void sipe_subscribe_presence_batched_routed(struct sipe_account_data *sip, void *payload)
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
	sipe_subscribe_presence_batched_to(sip, resources_uri,
					   g_strdup(data->host));
}

/**
  * Single Category SUBSCRIBE [MS-PRES] ; To send when the server returns a 200 OK message with state="resubscribe" in response.
  * The user sends a single SUBSCRIBE request to the subscribed contact.
  * The To-URI and the URI listed in the resource list MUST be the same for a single category SUBSCRIBE request.
  *
  */

static void sipe_subscribe_presence_single(struct sipe_account_data *sip, void *buddy_name)
{

	gchar *key;
	gchar *to = sip_uri((char *)buddy_name);
	gchar *tmp = get_contact(sip);
	gchar *request;
	gchar *content = NULL;
        gchar *autoextend = "";
	gchar *content_type = "";
	struct sip_dialog *dialog;
	struct sipe_buddy *sbuddy = g_hash_table_lookup(sip->buddies, to);
	gchar *context = sbuddy && sbuddy->just_added ? "><context/></resource>" : "/>";

	if (sbuddy) sbuddy->just_added = FALSE;

	if (sip->ocs2007) {
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

	if (sip->ocs2007) {
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
			"</batchSub>", sip->username, to, context);
	}

	g_free(tmp);

	/* subscribe to buddy presence */
	/* Subscription is identified by ACTION_NAME_PRESENCE key */
	key = g_strdup_printf(ACTION_NAME_PRESENCE, to);
	dialog = (struct sip_dialog *)g_hash_table_lookup(sip->subscriptions, key);
	purple_debug_info("sipe", "sipe_subscribe_presence_single: subscription dialog for: %s is %s\n", key, dialog ? "Not NULL" : "NULL");

	send_sip_request(sip->gc, "SUBSCRIBE", to, to, request, content, dialog, process_subscribe_response);

	g_free(content);
	g_free(to);
	g_free(request);
	g_free(key);
}

static void sipe_set_status(PurpleAccount *account, PurpleStatus *status)
{
	purple_debug_info("sipe", "sipe_set_status: status=%s\n", purple_status_get_id(status));

	if (!purple_status_is_active(status))
		return;

	if (account->gc) {
		struct sipe_account_data *sip = account->gc->proto_data;

		if (sip) {
			gchar *action_name;
			gchar *tmp;
			time_t now = time(NULL);
			const char *status_id = purple_status_get_id(status);
			const char *note = purple_status_get_attr_string(status, SIPE_STATUS_ATTR_ID_MESSAGE);
			sipe_activity activity = sipe_get_activity_by_token(status_id);
			gboolean do_not_publish = ((now - sip->do_not_publish[activity]) <= 2);
			

			purple_debug_info("sipe", "sipe_set_status: was: sip->do_not_publish[%s]=%d [?] now(time)=%d\n",
				status_id, (int)sip->do_not_publish[activity], (int)now);
				
			sip->do_not_publish[activity] = 0;
			purple_debug_info("sipe", "sipe_set_status: set: sip->do_not_publish[%s]=%d [0]\n",
				status_id, (int)sip->do_not_publish[activity]);

			if (do_not_publish)
			{
				purple_debug_info("sipe", "sipe_set_status: publication was switched off, exiting.\n");
				return;
			}

			g_free(sip->status);
			sip->status = g_strdup(status_id);

			/* hack to escape apostrof before comparison */
			tmp = note ? purple_strreplace(note, "'", "&apos;") : NULL;

			/* this will preserve OOF flag as well */
			if (!(tmp && sip->note && !strcmp(tmp, sip->note))) {
				sip->is_oof_note = FALSE;
				g_free(sip->note);
				sip->note = g_strdup(note);
				sip->note_since = time(NULL);
			}
			g_free(tmp);

			/* schedule 2 sec to capture idle flag */
			action_name = g_strdup_printf("<%s>", "+set-status");
			sipe_schedule_action(action_name, SIPE_IDLE_SET_DELAY, (Action)send_presence_status, NULL, sip, NULL);
			g_free(action_name);
		}
	}
}
static void
sipe_set_idle(PurpleConnection * gc,
	      int interval)
{
	purple_debug_info("sipe", "sipe_set_idle: interval=%d\n", interval);

	if (gc) {
		struct sipe_account_data *sip = gc->proto_data;

		if (sip) {
			sip->idle_switch = time(NULL);
			purple_debug_info("sipe", "sipe_set_idle: sip->idle_switch : %s", asctime(localtime(&(sip->idle_switch))));
		}
	}
}

static void
sipe_alias_buddy(PurpleConnection *gc, const char *name,
		 SIPE_UNUSED_PARAMETER const char *alias)
{
	struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;
	sipe_group_set_user(sip, name);
}

static void
sipe_group_buddy(PurpleConnection *gc,
		 const char *who,
		 const char *old_group_name,
		 const char *new_group_name)
{
 	struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;
	struct sipe_buddy * buddy = g_hash_table_lookup(sip->buddies, who);
	struct sipe_group * old_group = NULL;
	struct sipe_group * new_group;

	purple_debug_info("sipe", "sipe_group_buddy[CB]: who:%s old_group_name:%s new_group_name:%s\n",
		who ? who : "", old_group_name ? old_group_name : "", new_group_name ? new_group_name : "");

	if(!buddy) { // buddy not in roaming list
		return;
	}

	if (old_group_name) {
		old_group = sipe_group_find_by_name(sip, old_group_name);
	}
	new_group = sipe_group_find_by_name(sip, new_group_name);

	if (old_group) {
		buddy->groups = g_slist_remove(buddy->groups, old_group);
		purple_debug_info("sipe", "buddy %s removed from old group %s\n", who, old_group_name);
	}

	if (!new_group) {
 		sipe_group_create(sip, new_group_name, who);
 	} else {
		buddy->groups = slist_insert_unique_sorted(buddy->groups, new_group, (GCompareFunc)sipe_group_compare);
		sipe_group_set_user(sip, who);
 	}
}

static void sipe_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
	purple_debug_info("sipe", "sipe_add_buddy[CB]: buddy:%s group:%s\n", buddy ? buddy->name : "", group ? group->name : "");

	/* libpurple can call us with undefined buddy or group */
	if (buddy && group) {
		struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;

		/* Buddy name must be lower case as we use purple_normalize_nocase() to compare */
		gchar *buddy_name = g_ascii_strdown(buddy->name, -1);
		purple_blist_rename_buddy(buddy, buddy_name);
		g_free(buddy_name);

		/* Prepend sip: if needed */
		if (strncmp("sip:", buddy->name, 4)) {
			gchar *buf = sip_uri_from_name(buddy->name);
			purple_blist_rename_buddy(buddy, buf);
			g_free(buf);
		}

		if (!g_hash_table_lookup(sip->buddies, buddy->name)) {
			struct sipe_buddy *b = g_new0(struct sipe_buddy, 1);
			purple_debug_info("sipe", "sipe_add_buddy: adding %s\n", buddy->name);
			b->name = g_strdup(buddy->name);
			b->just_added = TRUE;
			g_hash_table_insert(sip->buddies, b->name, b);
			sipe_group_buddy(gc, b->name, NULL, group->name);
			/* @TODO should go to callback */
			sipe_subscribe_presence_single(sip, b->name);
		} else {
			purple_debug_info("sipe", "sipe_add_buddy: buddy %s already in internal list\n", buddy->name);
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
static void sipe_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
	struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;
	struct sipe_buddy *b;
	struct sipe_group *g = NULL;

	purple_debug_info("sipe", "sipe_remove_buddy[CB]: buddy:%s group:%s\n", buddy ? buddy->name : "", group ? group->name : "");
	if (!buddy) return;

	b = g_hash_table_lookup(sip->buddies, buddy->name);
	if (!b) return;

	if (group) {
		g = sipe_group_find_by_name(sip, group->name);
	}

	if (g) {
		b->groups = g_slist_remove(b->groups, g);
		purple_debug_info("sipe", "buddy %s removed from group %s\n", buddy->name, g->name);
	}

	if (g_slist_length(b->groups) < 1) {
		gchar *action_name = g_strdup_printf(ACTION_NAME_PRESENCE, buddy->name);
		sipe_cancel_scheduled_action(sip, action_name);
		g_free(action_name);

		g_hash_table_remove(sip->buddies, buddy->name);

		if (b->name) {
			gchar * body = g_strdup_printf(SIPE_SOAP_DEL_CONTACT, b->name, sip->contacts_delta++);
			send_soap_request(sip, body);
			g_free(body);
		}

		sipe_free_buddy(b);
	} else {
		//updates groups on server
		sipe_group_set_user(sip, b->name);
	}

}

static void
sipe_rename_group(PurpleConnection *gc,
		  const char *old_name,
		  PurpleGroup *group,
		  SIPE_UNUSED_PARAMETER GList *moved_buddies)
{
	struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;
	struct sipe_group * s_group = sipe_group_find_by_name(sip, old_name);
	if (s_group) {
		sipe_group_rename(sip, s_group, group->name);
	} else {
		purple_debug_info("sipe", "Cannot find group %s to rename\n", old_name);
	}
}

static void
sipe_remove_group(PurpleConnection *gc, PurpleGroup *group)
{
	struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;
	struct sipe_group * s_group = sipe_group_find_by_name(sip, group->name);
	if (s_group) {
		gchar *body;
		purple_debug_info("sipe", "Deleting group %s\n", group->name);
		body = g_strdup_printf(SIPE_SOAP_DEL_GROUP, s_group->id, sip->contacts_delta++);
		send_soap_request(sip, body);
		g_free(body);

		sip->groups = g_slist_remove(sip->groups, s_group);
		g_free(s_group->name);
		g_free(s_group);
	} else {
		purple_debug_info("sipe", "Cannot find group %s to delete\n", group->name);
	}
}

/** All statuses need message attribute to pass Note */
static GList *sipe_status_types(SIPE_UNUSED_PARAMETER PurpleAccount *acc)
{
	PurpleStatusType *type;
	GList *types = NULL;

	/* Macros to reduce code repetition.
	   Translators: noun */
#define SIPE_ADD_STATUS(prim,id,name,user) type = purple_status_type_new_with_attrs( \
		prim, id, name,             \
		TRUE, user, FALSE,          \
		SIPE_STATUS_ATTR_ID_MESSAGE, _("Message"), purple_value_new(PURPLE_TYPE_STRING), \
		NULL);                      \
	types = g_list_append(types, type);

	/* Online */
	SIPE_ADD_STATUS(PURPLE_STATUS_AVAILABLE,
			NULL,
			NULL,
			TRUE);

	/* Busy */
	SIPE_ADD_STATUS(PURPLE_STATUS_UNAVAILABLE,
			sipe_activity_map[SIPE_ACTIVITY_BUSY].status_id,
			SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_BUSY),
			TRUE);

	/* Do Not Disturb */
	SIPE_ADD_STATUS(PURPLE_STATUS_UNAVAILABLE,
			sipe_activity_map[SIPE_ACTIVITY_DND].status_id,
			NULL,
			TRUE);

	/* Away */
	/* Goes first in the list as
	 * purple picks the first status with the AWAY type
	 * for idle.
	 */
	SIPE_ADD_STATUS(PURPLE_STATUS_AWAY,
			NULL,
			NULL,
			TRUE);
			
	/* Be Right Back */
	SIPE_ADD_STATUS(PURPLE_STATUS_AWAY,
			sipe_activity_map[SIPE_ACTIVITY_BRB].status_id,
			SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_BRB),
			TRUE);

	/* Appear Offline */
	SIPE_ADD_STATUS(PURPLE_STATUS_INVISIBLE,
			NULL,
			NULL,
			TRUE);

	/* Offline (not user settable) */
	SIPE_ADD_STATUS(PURPLE_STATUS_OFFLINE,
			NULL,
			NULL,
			FALSE);

	return types;
}

/**
  * A callback for g_hash_table_foreach
  */
static void
sipe_buddy_subscribe_cb(char *buddy_name,
			SIPE_UNUSED_PARAMETER struct sipe_buddy *buddy,
			struct sipe_account_data *sip)
{
	gchar *action_name = g_strdup_printf(ACTION_NAME_PRESENCE, buddy_name);
	/* g_hash_table_size() can never return 0, otherwise this function wouldn't be called :-) */
	guint time_range = (g_hash_table_size(sip->buddies) * 1000) / 25; /* time interval for 25 requests per sec. In msec. */
	guint timeout = ((guint) rand()) / (RAND_MAX / time_range) + 1; /* random period within the range but never 0! */

	sipe_schedule_action_msec(action_name, timeout, sipe_subscribe_presence_single, g_free, sip, g_strdup(buddy_name));
	g_free(action_name);
}

/**
  * Removes entries from purple buddy list
  * that does not correspond ones in the roaming contact list.
  */
static void sipe_cleanup_local_blist(struct sipe_account_data *sip) {
	GSList *buddies = purple_find_buddies(sip->account, NULL);
	GSList *entry = buddies;
	struct sipe_buddy *buddy;
	PurpleBuddy *b;
	PurpleGroup *g;

	purple_debug_info("sipe", "sipe_cleanup_local_blist: overall %d Purple buddies (including clones)\n", g_slist_length(buddies));
	purple_debug_info("sipe", "sipe_cleanup_local_blist: %d sipe buddies (unique)\n", g_hash_table_size(sip->buddies));
	while (entry) {
		b = entry->data;
		g = purple_buddy_get_group(b);
		buddy = g_hash_table_lookup(sip->buddies, b->name);
		if(buddy) {
			gboolean in_sipe_groups = FALSE;
			GSList *entry2 = buddy->groups;
			while (entry2) {
				struct sipe_group *group = entry2->data;
				if (!strcmp(group->name, g->name)) {
					in_sipe_groups = TRUE;
					break;
				}
				entry2 = entry2->next;
			}
			if(!in_sipe_groups) {
				purple_debug_info("sipe", "*** REMOVING %s from Purple group: %s as not having this group in roaming list\n", b->name, g->name);
				purple_blist_remove_buddy(b);
			}
		} else {
				purple_debug_info("sipe", "*** REMOVING %s from Purple group: %s as this buddy not in roaming list\n", b->name, g->name);
				purple_blist_remove_buddy(b);
		}
		entry = entry->next;
	}
	g_slist_free(buddies);
}

static gboolean sipe_process_roaming_contacts(struct sipe_account_data *sip, struct sipmsg *msg)
{
	int len = msg->bodylen;

	gchar *tmp = sipmsg_find_header(msg, "Event");
	xmlnode *item;
	xmlnode *isc;
	const gchar *contacts_delta;
	xmlnode *group_node;
	if (!tmp || strncmp(tmp, "vnd-microsoft-roaming-contacts", 30)) {
		return FALSE;
	}

	/* Convert the contact from XML to Purple Buddies */
	isc = xmlnode_from_str(msg->body, len);
	if (!isc) {
		return FALSE;
	}

	contacts_delta = xmlnode_get_attrib(isc, "deltaNum");
	if (contacts_delta) {
		sip->contacts_delta = (int)g_ascii_strtod(contacts_delta, NULL);
	}

	if (!strcmp(isc->name, "contactList")) {

		/* Parse groups */
		for (group_node = xmlnode_get_child(isc, "group"); group_node; group_node = xmlnode_get_next_twin(group_node)) {
			struct sipe_group * group = g_new0(struct sipe_group, 1);
			const char *name = xmlnode_get_attrib(group_node, "name");

			if (!strncmp(name, "~", 1)) {
				name = _("Other Contacts");
			}
			group->name = g_strdup(name);
			group->id = (int)g_ascii_strtod(xmlnode_get_attrib(group_node, "id"), NULL);

			sipe_group_add(sip, group);
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
		for (item = xmlnode_get_child(isc, "contact"); item; item = xmlnode_get_next_twin(item)) {
			const gchar *uri = xmlnode_get_attrib(item, "uri");
			const gchar *name = xmlnode_get_attrib(item, "name");
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
			tmp = g_strdup(xmlnode_get_attrib(item, "groups"));
			if(!tmp || !strcmp("", tmp) ) {
				struct sipe_group *group = sipe_group_find_by_name(sip, _("Other Contacts"));
				g_free(tmp);
				tmp = group ? g_strdup_printf("%d", group->id) : g_strdup("1");
			}
			item_groups = g_strsplit(tmp, " ", 0);
			g_free(tmp);

			while (item_groups[i]) {
				struct sipe_group *group = sipe_group_find_by_id(sip, g_ascii_strtod(item_groups[i], NULL));

				// If couldn't find the right group for this contact, just put them in the first group we have
				if (group == NULL && g_slist_length(sip->groups) > 0) {
					group = sip->groups->data;
				}

				if (group != NULL) {
					PurpleBuddy *b = purple_find_buddy_in_group(sip->account, buddy_name, group->purple_group);
					if (!b){
						b = purple_buddy_new(sip->account, buddy_name, uri);
						purple_blist_add_buddy(b, NULL, group->purple_group, NULL);

						purple_debug_info("sipe", "Created new buddy %s with alias %s\n", buddy_name, uri);
					}

					if (!g_ascii_strcasecmp(uri, purple_buddy_get_alias(b))) {
						if (name != NULL && strlen(name) != 0) {
							purple_blist_alias_buddy(b, name);

							purple_debug_info("sipe", "Replaced buddy %s alias with %s\n", buddy_name, name);
						}
					}

					if (!buddy) {
						buddy = g_new0(struct sipe_buddy, 1);
						buddy->name = g_strdup(b->name);
						g_hash_table_insert(sip->buddies, buddy->name, buddy);
					}

					buddy->groups = slist_insert_unique_sorted(buddy->groups, group, (GCompareFunc)sipe_group_compare);

					purple_debug_info("sipe", "Added buddy %s to group %s\n", b->name, group->name);
				} else {
					purple_debug_info("sipe", "No group found for contact %s!  Unable to add to buddy list\n",
						name);
				}

				i++;
			} // while, contact groups
			g_strfreev(item_groups);
			g_free(buddy_name);

		} // for, contacts

		sipe_cleanup_local_blist(sip);

		/* Add self-contact if not there yet. 2005 systems. */
		/* This will resemble subscription to roaming_self in 2007 systems */
		if (!sip->ocs2007) {
			gchar *self_uri = sip_uri_self(sip);
			struct sipe_buddy *buddy = g_hash_table_lookup(sip->buddies, self_uri);

			if (!buddy) {
				buddy = g_new0(struct sipe_buddy, 1);
				buddy->name = g_strdup(self_uri);
				g_hash_table_insert(sip->buddies, buddy->name, buddy);
			}
			g_free(self_uri);
		}
	}
	xmlnode_free(isc);

	/* subscribe to buddies */
	if (!sip->subscribed_buddies) { //do it once, then count Expire field to schedule resubscribe.
		if (sip->batched_support) {
			sipe_subscribe_presence_batched(sip, NULL);
		} else {
			g_hash_table_foreach(sip->buddies, (GHFunc)sipe_buddy_subscribe_cb, (gpointer)sip);
		}
		sip->subscribed_buddies = TRUE;
	}
	/* for 2005 systems schedule contacts' status update
	 * based on their calendar information
	 */
	if (!sip->ocs2007) {
		sipe_sched_calendar_status_update(sip, time(NULL));
	}

	return 0;
}

 /**
  * Subscribe roaming contacts
  */
static void sipe_subscribe_roaming_contacts(struct sipe_account_data *sip)
{
	gchar *to = sip_uri_self(sip);
	gchar *tmp = get_contact(sip);
	gchar *hdr = g_strdup_printf(
		"Event: vnd-microsoft-roaming-contacts\r\n"
		"Accept: application/vnd-microsoft-roaming-contacts+xml\r\n"
		"Supported: com.microsoft.autoextend\r\n"
		"Supported: ms-benotify\r\n"
		"Proxy-Require: ms-benotify\r\n"
		"Supported: ms-piggyback-first-notify\r\n"
		"Contact: %s\r\n", tmp);
	g_free(tmp);

	send_sip_request(sip->gc, "SUBSCRIBE", to, to, hdr, "", NULL, process_subscribe_response);
	g_free(to);
	g_free(hdr);
}

static void sipe_subscribe_presence_wpending(struct sipe_account_data *sip,
					     SIPE_UNUSED_PARAMETER void *unused)
{
	gchar *key;
	struct sip_dialog *dialog;
	gchar *to = sip_uri_self(sip);
	gchar *tmp = get_contact(sip);
	gchar *hdr = g_strdup_printf(
		"Event: presence.wpending\r\n"
		"Accept: text/xml+msrtc.wpending\r\n"
		"Supported: com.microsoft.autoextend\r\n"
		"Supported: ms-benotify\r\n"
		"Proxy-Require: ms-benotify\r\n"
		"Supported: ms-piggyback-first-notify\r\n"
		"Contact: %s\r\n", tmp);
	g_free(tmp);

	/* Subscription is identified by <event> key */
	key = g_strdup_printf("<%s>", "presence.wpending");
	dialog = (struct sip_dialog *)g_hash_table_lookup(sip->subscriptions, key);
	purple_debug_info("sipe", "sipe_subscribe_presence_wpending: subscription dialog for: %s is %s\n", key, dialog ? "Not NULL" : "NULL");

	send_sip_request(sip->gc, "SUBSCRIBE", to, to, hdr, "", dialog, process_subscribe_response);

	g_free(to);
	g_free(hdr);
	g_free(key);
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
static void sipe_process_registration_notify(struct sipe_account_data *sip, struct sipmsg *msg)
{
	gchar *contenttype = sipmsg_find_header(msg, "Content-Type");
	gchar *event = NULL;
	gchar *reason = NULL;
	gchar *warning = sipmsg_find_header(msg, "ms-diagnostics");

	warning = warning ? warning : sipmsg_find_header(msg, "ms-diagnostics-public");
	purple_debug_info("sipe", "sipe_process_registration_notify: deregistration received.\n");

	if (!g_ascii_strncasecmp(contenttype, "text/registration-event", 23)) {
		event = sipmsg_find_part_of_header(msg->body, "event=", NULL, NULL);
		//@TODO have proper parameter extraction _by_name_ func, case insesitive.
		event = event ? event : sipmsg_find_part_of_header(msg->body, "event=", ";", NULL);
	} else {
		purple_debug_info("sipe", "sipe_process_registration_notify: unknown content type, exiting.\n");
		return;
	}

	if (warning != NULL) {
		reason = sipmsg_find_part_of_header(warning, "reason=\"", "\"", NULL);
	} else { // for LCS2005
		int error_id = 0;
		if (event && !g_ascii_strcasecmp(event, "unregistered")) {
			error_id = 4140; // [MS-SIPREGE]
			//reason = g_strdup(_("User logged out")); // [MS-OCER]
			reason = g_strdup(_("you are already signed in at another location"));
		} else if (event && !g_ascii_strcasecmp(event, "rejected")) {
			error_id = 4141;
			reason = g_strdup(_("user disabled")); // [MS-OCER]
		} else if (event && !g_ascii_strcasecmp(event, "deactivated")) {
			error_id = 4142;
			reason = g_strdup(_("user moved")); // [MS-OCER]
		}
	}
	g_free(event);
	warning = g_strdup_printf(_("You have been rejected by the server: %s"), reason ? reason : _("no reason given"));
	g_free(reason);

	sip->gc->wants_to_die = TRUE;
	purple_connection_error(sip->gc, warning);
	g_free(warning);

}

static void sipe_process_provisioning_v2(struct sipe_account_data *sip, struct sipmsg *msg)
{
	xmlnode *xn_provision_group_list;
	xmlnode *node;

	xn_provision_group_list = xmlnode_from_str(msg->body, msg->bodylen);

	/* provisionGroup */
	for (node = xmlnode_get_child(xn_provision_group_list, "provisionGroup"); node; node = xmlnode_get_next_twin(node)) {
		if (!strcmp("ServerConfiguration", xmlnode_get_attrib(node, "name"))) {
			g_free(sip->focus_factory_uri);
			sip->focus_factory_uri = xmlnode_get_data(xmlnode_get_child(node, "focusFactoryUri"));
			purple_debug_info("sipe", "sipe_process_provisioning_v2: sip->focus_factory_uri=%s\n",
						   sip->focus_factory_uri ? sip->focus_factory_uri : "");
			break;
		}
	}
	xmlnode_free(xn_provision_group_list);
}

/** for 2005 system */
static void
sipe_process_provisioning(struct sipe_account_data *sip,
			  struct sipmsg *msg)
{
	xmlnode *xn_provision;
	xmlnode *node;

	xn_provision = xmlnode_from_str(msg->body, msg->bodylen);
	if ((node = xmlnode_get_child(xn_provision, "user"))) {
		purple_debug_info("sipe", "sipe_process_provisioning: uri=%s\n", xmlnode_get_attrib(node, "uri"));
		if ((node = xmlnode_get_child(node, "line"))) {
			const gchar *line_uri = xmlnode_get_attrib(node, "uri");
			const gchar *server = xmlnode_get_attrib(node, "server");
			purple_debug_info("sipe", "sipe_process_provisioning: line_uri=%s server=%s\n", line_uri, server);
			sip_csta_open(sip, line_uri, server);
		}
	}
	xmlnode_free(xn_provision);
}

static void sipe_process_roaming_acl(struct sipe_account_data *sip, struct sipmsg *msg)
{
	const gchar *contacts_delta;
	xmlnode *xml;

	xml = xmlnode_from_str(msg->body, msg->bodylen);
	if (!xml)
	{
		return;
	}

	contacts_delta = xmlnode_get_attrib(xml, "deltaNum");
	if (contacts_delta)
	{
		sip->acl_delta = (int)g_ascii_strtod(contacts_delta, NULL);
	}

	xmlnode_free(xml);
}

static void
free_container(struct sipe_container *container)
{
	GSList *entry;

	if (!container) return;

	entry = container->members;
	while (entry) {
		g_free(entry->data);
		entry = g_slist_remove(entry, entry->data);
	}
	g_free(container);
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
		if (!g_strcasecmp(member->type, type)
		    && ((!member->value && !value)
			|| (value && member->value && !g_strcasecmp(member->value, value)))
		    ) {
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
sipe_find_container(struct sipe_account_data *sip,
		    guint id)
{
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

/**
 * Access Levels
 * 32000 - Blocked
 * 400   - Personal
 * 300   - Team
 * 200   - Company
 * 100   - Public
 */
static int
sipe_find_access_level(struct sipe_account_data *sip,
		       const gchar *type,
		       const gchar *value)
{
	guint containers[] = {32000, 400, 300, 200, 100};
	int i = 0;

	for (i = 0; i < 5; i++) {
		struct sipe_container_member *member;
		struct sipe_container *container = sipe_find_container(sip, containers[i]);
		if (!container) continue;

		member = sipe_find_container_member(container, type, value);
		if (member) {
			return containers[i];
		}
	}

	return -1;
}

static void
sipe_send_set_container_members(struct sipe_account_data *sip,
				guint container_id,
				guint container_version,
				const gchar* action,
				const gchar* type,
				const gchar* value)
{
	gchar *self = sip_uri_self(sip);
	gchar *value_str = value ? g_strdup_printf(" value=\"%s\"", value) : g_strdup("");
	gchar *contact;
	gchar *hdr;
	gchar *body = g_strdup_printf(
		"<setContainerMembers xmlns=\"http://schemas.microsoft.com/2006/09/sip/container-management\">"
		"<container id=\"%d\" version=\"%d\"><member action=\"%s\" type=\"%s\"%s/></container>"
		"</setContainerMembers>",
		container_id,
		container_version,
		action,
		type,
		value_str);
	g_free(value_str);

	contact = get_contact(sip);
	hdr = g_strdup_printf("Contact: %s\r\n"
			      "Content-Type: application/msrtc-setcontainermembers+xml\r\n", contact);
	g_free(contact);

	send_sip_request(sip->gc, "SERVICE", self, self, hdr, body, NULL, NULL);

	g_free(hdr);
	g_free(body);
	g_free(self);
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
sipe_is_our_publication(struct sipe_account_data *sip,
			const gchar *key)
{
	GSList *entry;

	/* filling keys for our publications if not yet cached */
	if (!sip->our_publication_keys) {
		guint device_instance 	= sipe_get_pub_instance(sip, SIPE_PUB_DEVICE);
		guint machine_instance 	= sipe_get_pub_instance(sip, SIPE_PUB_STATE_MACHINE);
		guint user_instance 	= sipe_get_pub_instance(sip, SIPE_PUB_STATE_USER);
		guint calendar_instance	= sipe_get_pub_instance(sip, SIPE_PUB_STATE_CALENDAR);
		guint cal_oof_instance	= sipe_get_pub_instance(sip, SIPE_PUB_STATE_CALENDAR_OOF);
		guint cal_data_instance = sipe_get_pub_instance(sip, SIPE_PUB_CALENDAR_DATA);
		guint note_oof_instance = sipe_get_pub_instance(sip, SIPE_PUB_NOTE_OOF);
		
		purple_debug_info("sipe", "* Out Publication Instances *\n");
		purple_debug_info("sipe", "\tDevice               : %u\t0x%08X\n", device_instance, device_instance);
		purple_debug_info("sipe", "\tMachine State        : %u\t0x%08X\n", machine_instance, machine_instance);
		purple_debug_info("sipe", "\tUser Stare           : %u\t0x%08X\n", user_instance, user_instance);
		purple_debug_info("sipe", "\tCalendar State       : %u\t0x%08X\n", calendar_instance, calendar_instance);
		purple_debug_info("sipe", "\tCalendar OOF State   : %u\t0x%08X\n", cal_oof_instance, cal_oof_instance);
		purple_debug_info("sipe", "\tCalendar FreeBusy    : %u\t0x%08X\n", cal_data_instance, cal_data_instance);
		purple_debug_info("sipe", "\tOOF Note             : %u\t0x%08X\n", note_oof_instance, note_oof_instance);
		purple_debug_info("sipe", "\tNote                 : %u\n", 0);
		purple_debug_info("sipe", "\tCalendar WorkingHours: %u\n", 0);

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

		//purple_debug_info("sipe", "sipe_is_our_publication: sip->our_publication_keys length=%d\n",
		//	  sip->our_publication_keys ? (int) g_slist_length(sip->our_publication_keys) : -1);
	}

	//purple_debug_info("sipe", "sipe_is_our_publication: key=%s\n", key);

	entry = sip->our_publication_keys;
	while (entry) {
		//purple_debug_info("sipe", "   sipe_is_our_publication: entry->data=%s\n", entry->data);
		if (!strcmp(entry->data, key)) {
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
 * Update user information
 *
 * @param uri             buddy SIP URI with 'sip:' prefix whose info we want to change.
 * @param property_name
 * @param property_value  may be modified to strip white space
 */
static void
sipe_update_user_info(struct sipe_account_data *sip,
		      const char *uri,
		      const char *property_name,
		      char *property_value)
{
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
		if (!strcmp(property_name, ALIAS_PROP)) {
			if (property_value && sipe_is_bad_alias(uri, purple_buddy_get_alias(p_buddy))) {
				purple_debug_info("sipe", "Replacing alias for %s with %s\n", uri, property_value);
				purple_blist_alias_buddy(p_buddy, property_value);
			}

			server_alias = purple_buddy_get_server_alias(p_buddy);
			if (property_value && strlen(property_value) > 0 &&
				( (server_alias && strcmp(property_value, server_alias))
					|| !server_alias || strlen(server_alias) == 0 )
				) {
				purple_blist_server_alias_buddy(p_buddy, property_value);
			}
		}
		/* for other properties */
		else {
			if (property_value && strlen(property_value) > 0) {
				prop_str = purple_blist_node_get_string(&p_buddy->node, property_name);
				if (!prop_str || g_ascii_strcasecmp(prop_str, property_value)) {
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
sipe_update_user_phone(struct sipe_account_data *sip,
		       const char *uri,
		       const gchar *phone_type,
		       gchar *phone,
		       gchar *phone_display_string)
{
	const char *phone_node = PHONE_PROP; /* work phone by default */
	const char *phone_display_node = PHONE_DISPLAY_PROP; /* work phone by default */

	if(!phone || strlen(phone) == 0) return;

	if (phone_type && (!strcmp(phone_type, "mobile") ||  !strcmp(phone_type, "cell"))) {
		phone_node = PHONE_MOBILE_PROP;
		phone_display_node = PHONE_MOBILE_DISPLAY_PROP;
	} else if (phone_type && !strcmp(phone_type, "home")) {
		phone_node = PHONE_HOME_PROP;
		phone_display_node = PHONE_HOME_DISPLAY_PROP;
	} else if (phone_type && !strcmp(phone_type, "other")) {
		phone_node = PHONE_OTHER_PROP;
		phone_display_node = PHONE_OTHER_DISPLAY_PROP;
	} else if (phone_type && !strcmp(phone_type, "custom1")) {
		phone_node = PHONE_CUSTOM1_PROP;
		phone_display_node = PHONE_CUSTOM1_DISPLAY_PROP;
	}

	sipe_update_user_info(sip, uri, phone_node, phone);
	if (phone_display_string) {
		sipe_update_user_info(sip, uri, phone_display_node, phone_display_string);
	}
}

static void
sipe_update_calendar(struct sipe_account_data *sip)
{
	const char* calendar = purple_account_get_string(sip->account, "calendar", "EXCH");

	purple_debug_info("sipe", "sipe_update_calendar: started.\n");

	if (!strcmp(calendar, "EXCH")) {
		sipe_ews_update_calendar(sip);
	}

	/* schedule repeat */
	sipe_schedule_action("<+update-calendar>", UPDATE_CALENDAR_INTERVAL, (Action)sipe_update_calendar, NULL, sip, NULL);

	purple_debug_info("sipe", "sipe_update_calendar: finished.\n");
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
	purple_strequal(message, purple_status_get_attr_string(status, SIPE_STATUS_ATTR_ID_MESSAGE)))
	{
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
		purple_debug_info("sipe", "sipe_set_purple_account_status_and_note: do_not_publish[%s]=%d [now]\n",
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
send_publish_category_initial(struct sipe_account_data *sip);

/**
  *   When we receive some self (BE) NOTIFY with a new subscriber
  *   we sends a setSubscribers request to him [SIP-PRES] 4.8
  *
  */
static void sipe_process_roaming_self(struct sipe_account_data *sip, struct sipmsg *msg)
{
	gchar *contact;
	gchar *to;
	xmlnode *xml;
	xmlnode *node;
	xmlnode *node2;
        char *display_name = NULL;
        char *uri;
	GSList *category_names = NULL;
	int aggreg_avail = 0;
	static sipe_activity aggreg_activity = SIPE_ACTIVITY_UNSET;
	gboolean do_update_status = FALSE;
	gboolean has_note_cleaned = FALSE;

	purple_debug_info("sipe", "sipe_process_roaming_self\n");

	xml = xmlnode_from_str(msg->body, msg->bodylen);
	if (!xml) return;

	contact = get_contact(sip);
	to = sip_uri_self(sip);


	/* categories */
	/* set list of categories participating in this XML */
	for (node = xmlnode_get_descendant(xml, "categories", "category", NULL); node; node = xmlnode_get_next_twin(node)) {
		const gchar *name = xmlnode_get_attrib(node, "name");
		category_names = slist_insert_unique_sorted(category_names, (gchar *)name, (GCompareFunc)strcmp);
	}
	purple_debug_info("sipe", "sipe_process_roaming_self: category_names length=%d\n",
			  category_names ? (int) g_slist_length(category_names) : -1);
	/* drop category information */
	if (category_names) {
		GSList *entry = category_names;
		while (entry) {
			GHashTable *cat_publications;
			const gchar *category = entry->data;
			entry = entry->next;
			purple_debug_info("sipe", "sipe_process_roaming_self: dropping category: %s\n", category);
			cat_publications = g_hash_table_lookup(sip->our_publications, category);
			if (cat_publications) {
				g_hash_table_remove(sip->our_publications, category);
				purple_debug_info("sipe", "   sipe_process_roaming_self: dropped category: %s\n", category);
			}
		}
	}
	g_slist_free(category_names);
	/* filling our categories reflected in roaming data */
	for (node = xmlnode_get_descendant(xml, "categories", "category", NULL); node; node = xmlnode_get_next_twin(node)) {
		const char *tmp;
		const gchar *name = xmlnode_get_attrib(node, "name");
		guint container = (tmp = xmlnode_get_attrib(node, "container")) ? atoi(tmp) : -1;
		guint instance  = (tmp = xmlnode_get_attrib(node, "instance"))  ? atoi(tmp) : -1;
		guint version   = atoi(xmlnode_get_attrib(node, "version"));
		time_t publish_time = (tmp = xmlnode_get_attrib(node, "publishTime")) ?
			purple_str_to_time(tmp, FALSE, NULL, NULL, NULL) : 0;
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
			purple_debug_info("sipe", "sipe_process_roaming_self: removing publications for: %s/%u\n", name, container);
			sipe_remove_category_container_publications(
				sip->our_publications, name, container);
			continue;
		}

		/* key is <category><instance><container> */
		key = g_strdup_printf("<%s><%u><%u>", name, instance, container);
		purple_debug_info("sipe", "sipe_process_roaming_self: key=%s version=%d\n", key, version);

		/* capture all userState publication for later clean up if required */
		if (!strcmp(name, "state") && (container == 2 || container == 3)) {
			xmlnode *xn_state = xmlnode_get_child(node, "state");

			if (xn_state && !strcmp(xmlnode_get_attrib(xn_state, "type"), "userState")) {
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
				purple_debug_info("sipe", "sipe_process_roaming_self: added to user_state_publications key=%s version=%d\n",
					key, version);
			}
		}

		if (sipe_is_our_publication(sip, key)) {
			struct sipe_publication *publication = g_new0(struct sipe_publication, 1);

			publication->category = g_strdup(name);
			publication->instance  = instance;
			publication->container = container;
			publication->version   = version;

			/* filling publication->availability */
			if (!strcmp(name, "state")) {
				xmlnode *xn_state = xmlnode_get_child(node, "state");
				xmlnode *xn_avail = xmlnode_get_child(xn_state, "availability");

				if (xn_avail) {
					gchar *avail_str = xmlnode_get_data(xn_avail);
					if (avail_str) {
						publication->availability = atoi(avail_str);
					}
					g_free(avail_str);
				}
				/* for calendarState */
				if (xn_state && !strcmp(xmlnode_get_attrib(xn_state, "type"), "calendarState")) {
					xmlnode *xn_activity = xmlnode_get_child(xn_state, "activity");
					struct sipe_cal_event *event = g_new0(struct sipe_cal_event, 1);

					event->start_time = purple_str_to_time(xmlnode_get_attrib(xn_state, "startTime"),
								FALSE, NULL, NULL, NULL);
					if (xn_activity) {
						if (!strcmp(xmlnode_get_attrib(xn_activity, "token"),
							    sipe_activity_map[SIPE_ACTIVITY_IN_MEETING].token))
						{
							event->is_meeting = TRUE;
						}
					}
					event->subject = xmlnode_get_data(xmlnode_get_child(xn_state, "meetingSubject"));
					event->location = xmlnode_get_data(xmlnode_get_child(xn_state, "meetingLocation"));

					publication->cal_event_hash = sipe_cal_event_hash(event);
					purple_debug_info("sipe", "sipe_process_roaming_self: hash=%s\n",
						publication->cal_event_hash);
					sipe_cal_event_free(event);
				}
			}
			/* filling publication->note */
			if (!strcmp(name, "note")) {
				xmlnode *xn_body = xmlnode_get_descendant(node, "note", "body", NULL);

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

					publication->note = g_markup_escape_text((tmp = xmlnode_get_data(xn_body)), -1);
					g_free(tmp);
					if (publish_time >= sip->note_since) {
						g_free(sip->note);
						sip->note = g_strdup(publication->note);
						sip->note_since = publish_time;
						sip->is_oof_note = !strcmp(xmlnode_get_attrib(xn_body, "type"), "OOF");

						do_update_status = TRUE;
					}
				}
			}

			/* filling publication->fb_start_str, free_busy_base64, working_hours_xml_str */
			if (!strcmp(name, "calendarData") && (publication->container == 300)) {
				xmlnode *xn_free_busy = xmlnode_get_descendant(node, "calendarData", "freeBusy", NULL);
				xmlnode *xn_working_hours = xmlnode_get_descendant(node, "calendarData", "WorkingHours", NULL);
				if (xn_free_busy) {
					publication->fb_start_str = g_strdup(xmlnode_get_attrib(xn_free_busy, "startTime"));
					publication->free_busy_base64 = xmlnode_get_data(xn_free_busy);
				}
				if (xn_working_hours) {
					publication->working_hours_xml_str = xmlnode_to_str(xn_working_hours, NULL);
				}
			}

			if (!cat_publications) {
				cat_publications = g_hash_table_new_full(
							g_str_hash, g_str_equal,
							g_free,	(GDestroyNotify)free_publication);
				g_hash_table_insert(sip->our_publications, g_strdup(name), cat_publications);
				purple_debug_info("sipe", "sipe_process_roaming_self: added GHashTable cat=%s\n", name);
			}
			g_hash_table_insert(cat_publications, g_strdup(key), publication);
			purple_debug_info("sipe", "sipe_process_roaming_self: added key=%s version=%d\n", key, version);
		}
		g_free(key);

		/* aggregateState (not an our publication) from 2-nd container */
		if (!strcmp(name, "state") && container == 2) {
			xmlnode *xn_state = xmlnode_get_child(node, "state");

			if (xn_state && !strcmp(xmlnode_get_attrib(xn_state, "type"), "aggregateState")) {
				xmlnode *xn_avail = xmlnode_get_child(xn_state, "availability");
				xmlnode *xn_activity = xmlnode_get_child(xn_state, "activity");

				if (xn_avail) {
					gchar *avail_str = xmlnode_get_data(xn_avail);
					if (avail_str) {
						aggreg_avail = atoi(avail_str);
					}
					g_free(avail_str);
				}

				if (xn_activity) {
					const char *activity_token = xmlnode_get_attrib(xn_activity, "token");

					aggreg_activity = sipe_get_activity_by_token(activity_token);
				}

				do_update_status = TRUE;
			}
		}

		/* userProperties published by server from AD */
		if (!sip->csta && !strcmp(name, "userProperties")) {
			xmlnode *line;
			/* line, for Remote Call Control (RCC) */
			for (line = xmlnode_get_descendant(node, "userProperties", "lines", "line", NULL); line; line = xmlnode_get_next_twin(line)) {
				const gchar *line_server = xmlnode_get_attrib(line, "lineServer");
				const gchar *line_type = xmlnode_get_attrib(line, "lineType");
				gchar *line_uri;

				if (!line_server || (strcmp(line_type, "Rcc") && strcmp(line_type, "Dual"))) continue;

				line_uri = xmlnode_get_data(line);
				if (line_uri) {
					purple_debug_info("sipe", "sipe_process_roaming_self: line_uri=%s server=%s\n", line_uri, line_server);
					sip_csta_open(sip, line_uri, line_server);
				}
				g_free(line_uri);

				break;
			}
		}
	}
	purple_debug_info("sipe", "sipe_process_roaming_self: sip->our_publications size=%d\n",
			  sip->our_publications ? (int) g_hash_table_size(sip->our_publications) : -1);

	/* containers */
	for (node = xmlnode_get_descendant(xml, "containers", "container", NULL); node; node = xmlnode_get_next_twin(node)) {
		guint id = atoi(xmlnode_get_attrib(node, "id"));
		struct sipe_container *container = sipe_find_container(sip, id);

		if (container) {
			sip->containers = g_slist_remove(sip->containers, container);
			purple_debug_info("sipe", "sipe_process_roaming_self: removed existing container id=%d v%d\n", container->id, container->version);
			free_container(container);
		}
		container = g_new0(struct sipe_container, 1);
		container->id = id;
		container->version = atoi(xmlnode_get_attrib(node, "version"));
		sip->containers = g_slist_append(sip->containers, container);
		purple_debug_info("sipe", "sipe_process_roaming_self: added container id=%d v%d\n", container->id, container->version);

		for (node2 = xmlnode_get_child(node, "member"); node2; node2 = xmlnode_get_next_twin(node2)) {
			struct sipe_container_member *member = g_new0(struct sipe_container_member, 1);
			member->type = xmlnode_get_attrib(node2, "type");
			member->value = xmlnode_get_attrib(node2, "value");
			container->members = g_slist_append(container->members, member);
			purple_debug_info("sipe", "sipe_process_roaming_self: added container member type=%s value=%s\n",
				member->type, member->value ? member->value : "");
		}
	}

	purple_debug_info("sipe", "sipe_process_roaming_self: sip->access_level_set=%s\n", sip->access_level_set ? "TRUE" : "FALSE");
	if (!sip->access_level_set && xmlnode_get_child(xml, "containers")) {
		int sameEnterpriseAL = sipe_find_access_level(sip, "sameEnterprise", NULL);
		int federatedAL      = sipe_find_access_level(sip, "federated", NULL);
		purple_debug_info("sipe", "sipe_process_roaming_self: sameEnterpriseAL=%d\n", sameEnterpriseAL);
		purple_debug_info("sipe", "sipe_process_roaming_self: federatedAL=%d\n", federatedAL);
		/* initial set-up to let counterparties see your status */
		if (sameEnterpriseAL < 0) {
			struct sipe_container *container = sipe_find_container(sip, 200);
			guint version = container ? container->version : 0;
			sipe_send_set_container_members(sip, 200, version, "add", "sameEnterprise", NULL);
		}
		if (federatedAL < 0) {
			struct sipe_container *container = sipe_find_container(sip, 100);
			guint version = container ? container->version : 0;
			sipe_send_set_container_members(sip, 100, version, "add", "federated", NULL);
		}
		sip->access_level_set = TRUE;
	}

	/* subscribers */
	for (node = xmlnode_get_descendant(xml, "subscribers", "subscriber", NULL); node; node = xmlnode_get_next_twin(node)) {
		const char *user;
		const char *acknowledged;
		gchar *hdr;
		gchar *body;

		user = xmlnode_get_attrib(node, "user"); /* without 'sip:' prefix */
		if (!user) continue;
		purple_debug_info("sipe", "sipe_process_roaming_self: user %s\n", user);
		display_name = g_strdup(xmlnode_get_attrib(node, "displayName"));
		uri = sip_uri_from_name(user);

		sipe_update_user_info(sip, uri, ALIAS_PROP, display_name);

	        acknowledged= xmlnode_get_attrib(node, "acknowledged");
		if(!g_ascii_strcasecmp(acknowledged,"false")){
                        purple_debug_info("sipe", "sipe_process_roaming_self: user added you %s\n", user);
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

		        send_sip_request(sip->gc, "SERVICE", to, to, hdr, body, NULL, NULL);
		        g_free(body);
		        g_free(hdr);
                }
		g_free(display_name);
		g_free(uri);
	}

	g_free(contact);
	xmlnode_free(xml);

	/* Publish initial state if not yet.
	 * Assuming this happens on initial responce to subscription to roaming-self
	 * so we've already updated our roaming data in full.
	 * Only for 2007+
	 */
	if (!sip->initial_state_published) {
		send_publish_category_initial(sip);
		sip->initial_state_published = TRUE;
		/* dalayed run */
		sipe_schedule_action("<+update-calendar>", UPDATE_CALENDAR_DELAY, (Action)sipe_update_calendar, NULL, sip, NULL);
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
		purple_debug_info("sipe", "sipe_process_roaming_self: to %s for the account\n", sip->status);
		sipe_set_purple_account_status_and_note(sip->account, sip->status, sip->note, sip->do_not_publish);		
	}

	g_free(to);
}

static void sipe_subscribe_roaming_acl(struct sipe_account_data *sip)
{
	gchar *to = sip_uri_self(sip);
	gchar *tmp = get_contact(sip);
	gchar *hdr = g_strdup_printf(
		"Event: vnd-microsoft-roaming-ACL\r\n"
		"Accept: application/vnd-microsoft-roaming-acls+xml\r\n"
		"Supported: com.microsoft.autoextend\r\n"
		"Supported: ms-benotify\r\n"
		"Proxy-Require: ms-benotify\r\n"
		"Supported: ms-piggyback-first-notify\r\n"
		"Contact: %s\r\n", tmp);
	g_free(tmp);

	send_sip_request(sip->gc, "SUBSCRIBE", to, to, hdr, "", NULL, process_subscribe_response);
	g_free(to);
	g_free(hdr);
}

/**
  * To request for presence information about the user, access level settings that have already been configured by the user
  *  to control who has access to what information, and the list of contacts who currently have outstanding subscriptions.
  *  We wait (BE)NOTIFY messages with some info change (categories,containers, subscribers)
  */

static void sipe_subscribe_roaming_self(struct sipe_account_data *sip)
{
	gchar *to = sip_uri_self(sip);
	gchar *tmp = get_contact(sip);
	gchar *hdr = g_strdup_printf(
		"Event: vnd-microsoft-roaming-self\r\n"
		"Accept: application/vnd-microsoft-roaming-self+xml\r\n"
		"Supported: ms-benotify\r\n"
		"Proxy-Require: ms-benotify\r\n"
		"Supported: ms-piggyback-first-notify\r\n"
		"Contact: %s\r\n"
		"Content-Type: application/vnd-microsoft-roaming-self+xml\r\n", tmp);

	gchar *body=g_strdup(
        "<roamingList xmlns=\"http://schemas.microsoft.com/2006/09/sip/roaming-self\">"
        "<roaming type=\"categories\"/>"
        "<roaming type=\"containers\"/>"
        "<roaming type=\"subscribers\"/></roamingList>");

	g_free(tmp);
	send_sip_request(sip->gc, "SUBSCRIBE", to, to, hdr, body, NULL, process_subscribe_response);
	g_free(body);
	g_free(to);
	g_free(hdr);
}

/**
  *  For 2005 version
  */
static void sipe_subscribe_roaming_provisioning(struct sipe_account_data *sip)
{
	gchar *to = sip_uri_self(sip);
	gchar *tmp = get_contact(sip);
	gchar *hdr = g_strdup_printf(
		"Event: vnd-microsoft-provisioning\r\n"
		"Accept: application/vnd-microsoft-roaming-provisioning+xml\r\n"
		"Supported: com.microsoft.autoextend\r\n"
		"Supported: ms-benotify\r\n"
		"Proxy-Require: ms-benotify\r\n"
		"Supported: ms-piggyback-first-notify\r\n"
		"Expires: 0\r\n"
		"Contact: %s\r\n", tmp);

	g_free(tmp);
	send_sip_request(sip->gc, "SUBSCRIBE", to, to, hdr, NULL, NULL, process_subscribe_response);
	g_free(to);
	g_free(hdr);
}

/**  Subscription for provisioning information to help with initial
   *  configuration. This subscription is a one-time query (denoted by the Expires header,
   *  which asks for 0 seconds for the subscription lifetime). This subscription asks for server
   *  configuration, meeting policies, and policy settings that Communicator must enforce.
   *   TODO: for what we need this information.
   */

static void sipe_subscribe_roaming_provisioning_v2(struct sipe_account_data *sip)
{
	gchar *to = sip_uri_self(sip);
	gchar *tmp = get_contact(sip);
	gchar *hdr = g_strdup_printf(
		"Event: vnd-microsoft-provisioning-v2\r\n"
		"Accept: application/vnd-microsoft-roaming-provisioning-v2+xml\r\n"
		"Supported: com.microsoft.autoextend\r\n"
		"Supported: ms-benotify\r\n"
		"Proxy-Require: ms-benotify\r\n"
		"Supported: ms-piggyback-first-notify\r\n"
		"Expires: 0\r\n"
		"Contact: %s\r\n"
		"Content-Type: application/vnd-microsoft-roaming-provisioning-v2+xml\r\n", tmp);
	gchar *body = g_strdup(
	    "<provisioningGroupList xmlns=\"http://schemas.microsoft.com/2006/09/sip/provisioninggrouplist\">"
		"<provisioningGroup name=\"ServerConfiguration\"/><provisioningGroup name=\"meetingPolicy\"/>"
		"<provisioningGroup name=\"ucPolicy\"/>"
		"</provisioningGroupList>");

	g_free(tmp);
	send_sip_request(sip->gc, "SUBSCRIBE", to, to, hdr, body, NULL, process_subscribe_response);
	g_free(body);
	g_free(to);
	g_free(hdr);
}

static void
sipe_unsubscribe_cb(SIPE_UNUSED_PARAMETER gpointer key,
		    gpointer value, gpointer user_data)
{
	struct sip_subscription *subscription = value;
	struct sip_dialog *dialog = &subscription->dialog;
	struct sipe_account_data *sip = user_data;
	gchar *tmp = get_contact(sip);
	gchar *hdr = g_strdup_printf(
		"Event: %s\r\n"
		"Expires: 0\r\n"
		"Contact: %s\r\n", subscription->event, tmp);
	g_free(tmp);

	/* Rate limit to max. 25 requests per seconds */
	g_usleep(1000000 / 25);

	send_sip_request(sip->gc, "SUBSCRIBE", dialog->with, dialog->with, hdr, NULL, dialog, NULL);
	g_free(hdr);
}

/* IM Session (INVITE and MESSAGE methods) */

/* EndPoints: "alice alisson" <sip:alice@atlanta.local>, <sip:bob@atlanta.local>;epid=ebca82d94d, <sip:carol@atlanta.local> */
static gchar *
get_end_points (struct sipe_account_data *sip,
		struct sip_session *session)
{
	gchar *res;

	if (session == NULL) {
		return NULL;
	}

	res = g_strdup_printf("<sip:%s>", sip->username);

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
process_options_response(SIPE_UNUSED_PARAMETER struct sipe_account_data *sip,
			 struct sipmsg *msg,
			 SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	gboolean ret = TRUE;

	if (msg->response != 200) {
		purple_debug_info("sipe", "process_options_response: OPTIONS response is %d\n", msg->response);
		return FALSE;
	}

	purple_debug_info("sipe", "process_options_response: body:\n%s\n", msg->body ? msg->body : "");

	return ret;
}

/**
 * Asks UA/proxy about its capabilities.
 */
static void sipe_options_request(struct sipe_account_data *sip, const char *who)
{
	gchar *to = sip_uri(who);
	gchar *contact = get_contact(sip);
	gchar *request = g_strdup_printf(
		"Accept: application/sdp\r\n"
		"Contact: %s\r\n", contact);
	g_free(contact);

	send_sip_request(sip->gc, "OPTIONS", to, to, request, NULL, NULL, process_options_response);

	g_free(to);
	g_free(request);
}

static void
sipe_notify_user(struct sipe_account_data *sip,
		 struct sip_session *session,
		 PurpleMessageFlags flags,
		 const gchar *message)
{
	PurpleConversation *conv;

	if (!session->conv) {
		conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_ANY, session->with, sip->account);
	} else {
		conv = session->conv;
	}
	purple_conversation_write(conv, NULL, message, flags, time(NULL));
}

void
sipe_present_info(struct sipe_account_data *sip,
		 struct sip_session *session,
		 const gchar *message)
{
	sipe_notify_user(sip, session, PURPLE_MESSAGE_SYSTEM, message);
}

static void
sipe_present_err(struct sipe_account_data *sip,
		 struct sip_session *session,
		 const gchar *message)
{
	sipe_notify_user(sip, session, PURPLE_MESSAGE_ERROR, message);
}

void
sipe_present_message_undelivered_err(struct sipe_account_data *sip,
				     struct sip_session *session,
				     int sip_error,
				     const gchar *who,
				     const gchar *message)
{
	char *msg, *msg_tmp, *msg_tmp2;
	const char *label;

	msg_tmp = message ? purple_markup_strip_html(message) : NULL;
	msg = msg_tmp ? g_strdup_printf("<font color=\"#888888\"></b>%s<b></font>", msg_tmp) : NULL;
	g_free(msg_tmp);
	/* Service unavailable; Server Internal Error; Server Time-out */
	if (sip_error == 503 || sip_error == 500 || sip_error == 504) {
		label = _("This message was not delivered to %s because the service is not available");
	} else if (sip_error == 486) { /* Busy Here */
		label = _("This message was not delivered to %s because one or more recipients do not want to be disturbed");
	} else {
		label = _("This message was not delivered to %s because one or more recipients are offline");
	}

	msg_tmp = g_strdup_printf( "%s:\n%s" ,
			msg_tmp2 = g_strdup_printf(label, who ? who : ""), msg ? msg : "");
	sipe_present_err(sip, session, msg_tmp);
	g_free(msg_tmp2);
	g_free(msg_tmp);
	g_free(msg);
}


static void sipe_im_process_queue (struct sipe_account_data * sip, struct sip_session * session);

static gboolean
process_message_response(struct sipe_account_data *sip, struct sipmsg *msg,
			 SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	gboolean ret = TRUE;
	gchar *with = parse_from(sipmsg_find_header(msg, "To"));
	struct sip_session *session = sipe_session_find_im(sip, with);
	struct sip_dialog *dialog;
	gchar *cseq;
	char *key;
	gchar *message;

	if (!session) {
		purple_debug_info("sipe", "process_message_response: unable to find IM session\n");
		g_free(with);
		return FALSE;
	}

	dialog = sipe_dialog_find(session, with);
	if (!dialog) {
		purple_debug_info("sipe", "process_message_response: session outgoing dialog is NULL\n");
		g_free(with);
		return FALSE;
	}

	cseq = sipmsg_find_part_of_header(sipmsg_find_header(msg, "CSeq"), NULL, " ", NULL);
	key = g_strdup_printf("<%s><%d><MESSAGE><%s>", sipmsg_find_header(msg, "Call-ID"), atoi(cseq), with);
	g_free(cseq);
	message = g_hash_table_lookup(session->unconfirmed_messages, key);

	if (msg->response >= 400) {
		PurpleBuddy *pbuddy;
		gchar *alias = with;

		purple_debug_info("sipe", "process_message_response: MESSAGE response >= 400\n");

		if ((pbuddy = purple_find_buddy(sip->account, with))) {
			alias = (gchar *)purple_buddy_get_alias(pbuddy);
		}

		sipe_present_message_undelivered_err(sip, session, msg->response, alias, message);
		ret = FALSE;
	} else {
		gchar *message_id = sipmsg_find_header(msg, "Message-Id");
		if (message_id) {
			g_hash_table_insert(session->conf_unconfirmed_messages, g_strdup(message_id), g_strdup(message));
			purple_debug_info("sipe", "process_message_response: added message with id %s to conf_unconfirmed_messages(count=%d)\n",
					  message_id, g_hash_table_size(session->conf_unconfirmed_messages));
		}

		g_hash_table_remove(session->unconfirmed_messages, key);
		purple_debug_info("sipe", "process_message_response: removed message %s from unconfirmed_messages(count=%d)\n",
				  key, g_hash_table_size(session->unconfirmed_messages));
	}

	g_free(key);
	g_free(with);

	if (ret) sipe_im_process_queue(sip, session);
	return ret;
}

static gboolean
sipe_is_election_finished(struct sip_session *session);

static void
sipe_election_result(struct sipe_account_data *sip,
		     void *sess);

static gboolean
process_info_response(struct sipe_account_data *sip, struct sipmsg *msg,
		      SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	gchar *contenttype = sipmsg_find_header(msg, "Content-Type");
	gchar *callid = sipmsg_find_header(msg, "Call-ID");
	struct sip_dialog *dialog;
	struct sip_session *session;

	session = sipe_session_find_chat_by_callid(sip, callid);
	if (!session) {
		purple_debug_info("sipe", "process_info_response: failed find dialog for callid %s, exiting.", callid);
		return FALSE;
	}

	if (msg->response == 200 && !strncmp(contenttype, "application/x-ms-mim", 20)) {
		xmlnode *xn_action 		= xmlnode_from_str(msg->body, msg->bodylen);
		xmlnode *xn_request_rm_response = xmlnode_get_child(xn_action, "RequestRMResponse");
		xmlnode *xn_set_rm_response 	= xmlnode_get_child(xn_action, "SetRMResponse");

		if (xn_request_rm_response) {
			const char *with = xmlnode_get_attrib(xn_request_rm_response, "uri");
			const char *allow = xmlnode_get_attrib(xn_request_rm_response, "allow");

			dialog = sipe_dialog_find(session, with);
			if (!dialog) {
				purple_debug_info("sipe", "process_info_response: failed find dialog for %s, exiting.\n", with);
				return FALSE;
			}

			if (allow && !g_strcasecmp(allow, "true")) {
				purple_debug_info("sipe", "process_info_response: %s has voted PRO\n", with);
				dialog->election_vote = 1;
			} else if (allow && !g_strcasecmp(allow, "false")) {
				purple_debug_info("sipe", "process_info_response: %s has voted CONTRA\n", with);
				dialog->election_vote = -1;
			}

			if (sipe_is_election_finished(session)) {
				sipe_election_result(sip, session);
			}

		} else if (xn_set_rm_response) {

		}
		xmlnode_free(xn_action);

	}

	return TRUE;
}

static void sipe_send_message(struct sipe_account_data *sip, struct sip_dialog *dialog, const char *msg)
{
	gchar *hdr;
	gchar *tmp;
	char *msgformat;
	char *msgtext;
	gchar *msgr_value;
	gchar *msgr;

	sipe_parse_html(msg, &msgformat, &msgtext);
	purple_debug_info("sipe", "sipe_send_message: msgformat=%s\n", msgformat);

	msgr_value = sipmsg_get_msgr_string(msgformat);
	g_free(msgformat);
	if (msgr_value) {
		msgr = g_strdup_printf(";msgr=%s", msgr_value);
		g_free(msgr_value);
	} else {
		msgr = g_strdup("");
	}

	tmp = get_contact(sip);
	//hdr = g_strdup("Content-Type: text/plain; charset=UTF-8\r\n");
	//hdr = g_strdup("Content-Type: text/rtf\r\n");
	//hdr = g_strdup("Content-Type: text/plain; charset=UTF-8;msgr=WAAtAE0ATQBTAC....AoADQA\r\nSupported: timer\r\n");
	hdr = g_strdup_printf("Contact: %s\r\nContent-Type: text/plain; charset=UTF-8%s\r\n", tmp, msgr);
	g_free(tmp);
	g_free(msgr);

	send_sip_request(sip->gc, "MESSAGE", dialog->with, dialog->with, hdr, msgtext, dialog, process_message_response);
	g_free(msgtext);
	g_free(hdr);
}


static void
sipe_im_process_queue (struct sipe_account_data * sip, struct sip_session * session)
{
	GSList *entry2 = session->outgoing_message_queue;
	while (entry2) {
		char *queued_msg = entry2->data;

		/* for multiparty chat or conference */
		if (session->is_multiparty || session->focus_uri) {
			gchar *who = sip_uri_self(sip);
			serv_got_chat_in(sip->gc, session->chat_id, who,
				PURPLE_MESSAGE_SEND, queued_msg, time(NULL));
			g_free(who);
		}

		SIPE_DIALOG_FOREACH {
			char *key;

			if (dialog->outgoing_invite) continue; /* do not send messages as INVITE is not responded. */

			key = g_strdup_printf("<%s><%d><MESSAGE><%s>", dialog->callid, (dialog->cseq) + 1, dialog->with);
			g_hash_table_insert(session->unconfirmed_messages, g_strdup(key), g_strdup(queued_msg));
			purple_debug_info("sipe", "sipe_im_process_queue: added message %s to unconfirmed_messages(count=%d)\n",
					  key, g_hash_table_size(session->unconfirmed_messages));
			g_free(key);

			sipe_send_message(sip, dialog, queued_msg);
		} SIPE_DIALOG_FOREACH_END;

		entry2 = session->outgoing_message_queue = g_slist_remove(session->outgoing_message_queue, queued_msg);
		g_free(queued_msg);
	}
}

static void
sipe_refer_notify(struct sipe_account_data *sip,
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

	send_sip_request(sip->gc, "NOTIFY", who, who, hdr, body, dialog, NULL);

	g_free(hdr);
	g_free(body);
}

static gboolean
process_invite_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *trans)
{
	gchar *with = parse_from(sipmsg_find_header(msg, "To"));
	struct sip_session *session;
	struct sip_dialog *dialog;
	char *cseq;
	char *key;
	gchar *message;
	struct sipmsg *request_msg = trans->msg;

	gchar *callid = sipmsg_find_header(msg, "Call-ID");
	gchar *referred_by;

	session = sipe_session_find_chat_by_callid(sip, callid);
	if (!session) {
		session = sipe_session_find_im(sip, with);
	}
	if (!session) {
		purple_debug_info("sipe", "process_invite_response: unable to find IM session\n");
		g_free(with);
		return FALSE;
	}

	dialog = sipe_dialog_find(session, with);
	if (!dialog) {
		purple_debug_info("sipe", "process_invite_response: session outgoing dialog is NULL\n");
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
		gchar *alias = with;

		purple_debug_info("sipe", "process_invite_response: INVITE response not 200\n");

		if ((pbuddy = purple_find_buddy(sip->account, with))) {
			alias = (gchar *)purple_buddy_get_alias(pbuddy);
		}

		if (message) {
			sipe_present_message_undelivered_err(sip, session, msg->response, alias, message);
		} else {
			gchar *tmp_msg = g_strdup_printf(_("Failed to invite %s"), alias);
			sipe_present_err(sip, session, tmp_msg);
			g_free(tmp_msg);
		}

		sipe_dialog_remove(session, with);

		g_free(key);
		g_free(with);
		return FALSE;
	}

	dialog->cseq = 0;
	send_sip_request(sip->gc, "ACK", dialog->with, dialog->with, NULL, NULL, dialog, NULL);
	dialog->outgoing_invite = NULL;
	dialog->is_established = TRUE;

	referred_by = parse_from(sipmsg_find_header(request_msg, "Referred-By"));
	if (referred_by) {
		sipe_refer_notify(sip, session, referred_by, 200, "OK");
		g_free(referred_by);
	}

	/* add user to chat if it is a multiparty session */
	if (session->is_multiparty) {
		purple_conv_chat_add_user(PURPLE_CONV_CHAT(session->conv),
			with, NULL,
			PURPLE_CBFLAGS_NONE, TRUE);
	}

	if(g_slist_find_custom(dialog->supported, "ms-text-format", (GCompareFunc)g_ascii_strcasecmp)) {
		purple_debug_info("sipe", "process_invite_response: remote system accepted message in INVITE\n");
		if (session->outgoing_message_queue) {
			char *queued_msg = session->outgoing_message_queue->data;
			session->outgoing_message_queue = g_slist_remove(session->outgoing_message_queue, queued_msg);
			g_free(queued_msg);
		}
	}

	sipe_im_process_queue(sip, session);

	g_hash_table_remove(session->unconfirmed_messages, key);
	purple_debug_info("sipe", "process_invite_response: removed message %s from unconfirmed_messages(count=%d)\n",
						key, g_hash_table_size(session->unconfirmed_messages));

	g_free(key);
	g_free(with);
	return TRUE;
}


void
sipe_invite(struct sipe_account_data *sip,
	    struct sip_session *session,
	    const gchar *who,
	    const gchar *msg_body,
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
		purple_debug_info("sipe", "session with %s already has a dialog open\n", who);
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
		char *msgformat;
		char *msgtext;
		char *base64_msg;
		gchar *msgr_value;
		gchar *msgr;
		char *key;

		sipe_parse_html(msg_body, &msgformat, &msgtext);
		purple_debug_info("sipe", "sipe_invite: msgformat=%s\n", msgformat);

		msgr_value = sipmsg_get_msgr_string(msgformat);
		g_free(msgformat);
		msgr = "";
		if (msgr_value) {
			msgr = g_strdup_printf(";msgr=%s", msgr_value);
			g_free(msgr_value);
		}

		base64_msg = purple_base64_encode((guchar*) msgtext, strlen(msgtext));
		ms_text_format = g_strdup_printf(SIPE_INVITE_TEXT, msgr, base64_msg);
		g_free(msgtext);
		g_free(msgr);
		g_free(base64_msg);

		key = g_strdup_printf("<%s><%d><INVITE>", dialog->callid, (dialog->cseq) + 1);
		g_hash_table_insert(session->unconfirmed_messages, g_strdup(key), g_strdup(msg_body));
		purple_debug_info("sipe", "sipe_invite: added message %s to unconfirmed_messages(count=%d)\n",
							key, g_hash_table_size(session->unconfirmed_messages));
		g_free(key);
	}

	contact = get_contact(sip);
	end_points = get_end_points(sip, session);
	self = sip_uri_self(sip);
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
		(session->roster_manager && !strcmp(session->roster_manager, self)) ? roster_manager : "",
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
		"a=accept-types:text/plain text/html image/gif "
		"multipart/related multipart/alternative application/im-iscomposing+xml application/ms-imdn+xml\r\n",
		purple_network_get_my_ip(-1),
		purple_network_get_my_ip(-1),
		sip->ocs2007 ? "message" : "x-ms-message",
		sip->realport);

	dialog->outgoing_invite = send_sip_request(sip->gc, "INVITE",
		to, to, hdr, body, dialog, process_invite_response);

	g_free(to);
	g_free(roster_manager);
	g_free(end_points);
	g_free(referred_by_str);
	g_free(body);
	g_free(hdr);
	g_free(contact);
}

static void
sipe_refer(struct sipe_account_data *sip,
	    struct sip_session *session,
	    const gchar *who)
{
	gchar *hdr;
	gchar *contact;
	gchar *epid = get_epid(sip);
	struct sip_dialog *dialog = sipe_dialog_find(session,
						     session->roster_manager);
	const char *ourtag = dialog && dialog->ourtag ? dialog->ourtag : NULL;

	contact = get_contact(sip);
	hdr = g_strdup_printf(
		"Contact: %s\r\n"
		"Refer-to: <%s>\r\n"
		"Referred-By: <sip:%s>%s%s;epid=%s\r\n"
		"Require: com.microsoft.rtc-multiparty\r\n",
		contact,
		who,
		sip->username,
		ourtag ? ";tag=" : "",
		ourtag ? ourtag : "",
		epid);
	g_free(epid);

	send_sip_request(sip->gc, "REFER",
		session->roster_manager, session->roster_manager, hdr, NULL, dialog, NULL);

	g_free(hdr);
	g_free(contact);
}

static void
sipe_send_election_request_rm(struct sipe_account_data *sip,
			      struct sip_dialog *dialog,
			      int bid)
{
	const gchar *hdr = "Content-Type: application/x-ms-mim\r\n";

	gchar *body = g_strdup_printf(
		"<?xml version=\"1.0\"?>\r\n"
		"<action xmlns=\"http://schemas.microsoft.com/sip/multiparty/\">"
		"<RequestRM uri=\"sip:%s\" bid=\"%d\"/></action>\r\n",
		sip->username, bid);

	send_sip_request(sip->gc, "INFO",
		dialog->with, dialog->with, hdr, body, dialog, process_info_response);

	g_free(body);
}

static void
sipe_send_election_set_rm(struct sipe_account_data *sip,
			  struct sip_dialog *dialog)
{
	const gchar *hdr = "Content-Type: application/x-ms-mim\r\n";

	gchar *body = g_strdup_printf(
		"<?xml version=\"1.0\"?>\r\n"
		"<action xmlns=\"http://schemas.microsoft.com/sip/multiparty/\">"
		"<SetRM uri=\"sip:%s\"/></action>\r\n",
		sip->username);

	send_sip_request(sip->gc, "INFO",
		dialog->with, dialog->with, hdr, body, dialog, process_info_response);

	g_free(body);
}

static void
sipe_session_close(struct sipe_account_data *sip,
		   struct sip_session * session)
{
	if (session && session->focus_uri) {
		sipe_conf_immcu_closed(sip, session);
		conf_session_close(sip, session);
	}

	if (session) {
		SIPE_DIALOG_FOREACH {
			/* @TODO slow down BYE message sending rate */
			/* @see single subscription code */
			send_sip_request(sip->gc, "BYE", dialog->with, dialog->with, NULL, NULL, dialog, NULL);
		} SIPE_DIALOG_FOREACH_END;

		sipe_session_remove(sip, session);
	}
}

static void
sipe_session_close_all(struct sipe_account_data *sip)
{
	GSList *entry;
	while ((entry = sip->sessions) != NULL) {
		sipe_session_close(sip, entry->data);
	}
}

static void
sipe_convo_closed(PurpleConnection * gc, const char *who)
{
	struct sipe_account_data *sip = gc->proto_data;

	purple_debug_info("sipe", "conversation with %s closed\n", who);
	sipe_session_close(sip, sipe_session_find_im(sip, who));
}

static void
sipe_chat_leave (PurpleConnection *gc, int id)
{
	struct sipe_account_data *sip = gc->proto_data;
	struct sip_session *session = sipe_session_find_chat_by_id(sip, id);

	sipe_session_close(sip, session);
}

static int sipe_im_send(PurpleConnection *gc, const char *who, const char *what,
			SIPE_UNUSED_PARAMETER PurpleMessageFlags flags)
{
	struct sipe_account_data *sip = gc->proto_data;
	struct sip_session *session;
	struct sip_dialog *dialog;
	gchar *uri = sip_uri(who);

	purple_debug_info("sipe", "sipe_im_send what='%s'\n", what);

	session = sipe_session_find_or_add_im(sip, uri);
	dialog = sipe_dialog_find(session, uri);

	// Queue the message
	session->outgoing_message_queue = g_slist_append(session->outgoing_message_queue, g_strdup(what));

	if (dialog && !dialog->outgoing_invite) {
		sipe_im_process_queue(sip, session);
	} else if (!dialog || !dialog->outgoing_invite) {
		// Need to send the INVITE to get the outgoing dialog setup
		sipe_invite(sip, session, uri, what, NULL, FALSE);
	}

	g_free(uri);
	return 1;
}

static int sipe_chat_send(PurpleConnection *gc, int id, const char *what,
			  SIPE_UNUSED_PARAMETER PurpleMessageFlags flags)
{
	struct sipe_account_data *sip = gc->proto_data;
	struct sip_session *session;

	purple_debug_info("sipe", "sipe_chat_send what='%s'\n", what);

	session = sipe_session_find_chat_by_id(sip, id);

	// Queue the message
	if (session && session->dialogs) {
		session->outgoing_message_queue = g_slist_append(session->outgoing_message_queue,
								 g_strdup(what));
		sipe_im_process_queue(sip, session);
	} else if (sip) {
		gchar *chat_name = purple_find_chat(sip->gc, id)->name;
		const gchar *proto_chat_id = sipe_chat_find_name(chat_name);

		purple_debug_info("sipe", "sipe_chat_send: chat_name='%s'\n", chat_name ? chat_name : "NULL");
		purple_debug_info("sipe", "sipe_chat_send: proto_chat_id='%s'\n", proto_chat_id ? proto_chat_id : "NULL");

		if (sip->ocs2007) {
			struct sip_session *session = sipe_session_add_chat(sip);

			session->is_multiparty = FALSE;
			session->focus_uri = g_strdup(proto_chat_id);
			session->outgoing_message_queue = g_slist_append(session->outgoing_message_queue,
									 g_strdup(what));
			sipe_invite_conf_focus(sip, session);
		}
	}

	return 1;
}

/* End IM Session (INVITE and MESSAGE methods) */

static void process_incoming_info(struct sipe_account_data *sip, struct sipmsg *msg)
{
	gchar *contenttype = sipmsg_find_header(msg, "Content-Type");
	gchar *callid = sipmsg_find_header(msg, "Call-ID");
	gchar *from;
	struct sip_session *session;

	purple_debug_info("sipe", "process_incoming_info: \n%s\n", msg->body ? msg->body : "");

	/* Call Control protocol */
	if (g_str_has_prefix(contenttype, "application/csta+xml"))
	{
		process_incoming_info_csta(sip, msg);
		return;
	}

	from = parse_from(sipmsg_find_header(msg, "From"));
	session = sipe_session_find_chat_by_callid(sip, callid);
	if (!session) {
		session = sipe_session_find_im(sip, from);
	}
	if (!session) {
		g_free(from);
		return;
	}

	if (g_str_has_prefix(contenttype, "application/x-ms-mim"))
	{
		xmlnode *xn_action 		= xmlnode_from_str(msg->body, msg->bodylen);
		xmlnode *xn_request_rm 		= xmlnode_get_child(xn_action, "RequestRM");
		xmlnode *xn_set_rm 		= xmlnode_get_child(xn_action, "SetRM");

		sipmsg_add_header(msg, "Content-Type", "application/x-ms-mim");

		if (xn_request_rm) {
			//const char *rm = xmlnode_get_attrib(xn_request_rm, "uri");
			int bid = atoi(xmlnode_get_attrib(xn_request_rm, "bid"));
			gchar *body = g_strdup_printf(
				"<?xml version=\"1.0\"?>\r\n"
				"<action xmlns=\"http://schemas.microsoft.com/sip/multiparty/\">"
				"<RequestRMResponse uri=\"sip:%s\" allow=\"%s\"/></action>\r\n",
				sip->username,
				session->bid < bid ? "true" : "false");
			send_sip_response(sip->gc, msg, 200, "OK", body);
			g_free(body);
		} else if (xn_set_rm) {
			gchar *body;
			const char *rm = xmlnode_get_attrib(xn_set_rm, "uri");
			g_free(session->roster_manager);
			session->roster_manager = g_strdup(rm);

			body = g_strdup_printf(
				"<?xml version=\"1.0\"?>\r\n"
				"<action xmlns=\"http://schemas.microsoft.com/sip/multiparty/\">"
				"<SetRMResponse uri=\"sip:%s\"/></action>\r\n",
				sip->username);
			send_sip_response(sip->gc, msg, 200, "OK", body);
			g_free(body);
		}
		xmlnode_free(xn_action);

	}
	else
	{
		/* looks like purple lacks typing notification for chat */
		if (!session->is_multiparty && !session->focus_uri) {
			xmlnode *xn_keyboard_activity  = xmlnode_from_str(msg->body, msg->bodylen);
			const char *status = xmlnode_get_attrib(xmlnode_get_child(xn_keyboard_activity, "status"),
								"status");
			if (status && !strcmp(status, "type")) {
				serv_got_typing(sip->gc, from, SIPE_TYPING_RECV_TIMEOUT, PURPLE_TYPING);
			} else if (status && !strcmp(status, "idle")) {
				serv_got_typing_stopped(sip->gc, from);
			}
			xmlnode_free(xn_keyboard_activity);
		}

		send_sip_response(sip->gc, msg, 200, "OK", NULL);
	}
	g_free(from);
}

static void process_incoming_bye(struct sipe_account_data *sip, struct sipmsg *msg)
{
	gchar *callid = sipmsg_find_header(msg, "Call-ID");
	gchar *from = parse_from(sipmsg_find_header(msg, "From"));
	struct sip_session *session;
	struct sip_dialog *dialog;

	/* collect dialog identification
	 * we need callid, ourtag and theirtag to unambiguously identify dialog
	 */
	/* take data before 'msg' will be modified by send_sip_response */
	dialog = g_new0(struct sip_dialog, 1);
	dialog->callid = g_strdup(callid);
	dialog->cseq = parse_cseq(sipmsg_find_header(msg, "CSeq"));
	dialog->with = g_strdup(from);
	sipe_dialog_parse(dialog, msg, FALSE);

	send_sip_response(sip->gc, msg, 200, "OK", NULL);

	session = sipe_session_find_chat_by_callid(sip, callid);
	if (!session) {
		session = sipe_session_find_im(sip, from);
	}
	if (!session) {
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
		sipe_conf_immcu_closed(sip, session);
	} else if (session->is_multiparty) {
		purple_conv_chat_remove_user(PURPLE_CONV_CHAT(session->conv), from, NULL);
	}

	g_free(from);
}

static void process_incoming_refer(struct sipe_account_data *sip, struct sipmsg *msg)
{
	gchar *self = sip_uri_self(sip);
	gchar *callid = sipmsg_find_header(msg, "Call-ID");
	gchar *from = parse_from(sipmsg_find_header(msg, "From"));
	gchar *refer_to = parse_from(sipmsg_find_header(msg, "Refer-to"));
	gchar *referred_by = g_strdup(sipmsg_find_header(msg, "Referred-By"));
	struct sip_session *session;
	struct sip_dialog *dialog;

	session = sipe_session_find_chat_by_callid(sip, callid);
	dialog = sipe_dialog_find(session, from);

	if (!session || !dialog || !session->roster_manager || strcmp(session->roster_manager, self)) {
		send_sip_response(sip->gc, msg, 500, "Server Internal Error", NULL);
	} else {
		send_sip_response(sip->gc, msg, 202, "Accepted", NULL);

		sipe_invite(sip, session, refer_to, NULL, referred_by, FALSE);
	}

	g_free(self);
	g_free(from);
	g_free(refer_to);
	g_free(referred_by);
}

static unsigned int
sipe_send_typing(PurpleConnection *gc, const char *who, PurpleTypingState state)
{
	struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;
	struct sip_session *session;
	struct sip_dialog *dialog;

	if (state == PURPLE_NOT_TYPING)
		return 0;

	session = sipe_session_find_im(sip, who);
	dialog = sipe_dialog_find(session, who);

	if (session && dialog && dialog->is_established) {
		send_sip_request(gc, "INFO", who, who,
			"Content-Type: application/xml\r\n",
			SIPE_SEND_TYPING, dialog, NULL);
	}
	return SIPE_TYPING_SEND_TIMEOUT;
}

static gboolean resend_timeout(struct sipe_account_data *sip)
{
	GSList *tmp = sip->transactions;
	time_t currtime = time(NULL);
	while (tmp) {
		struct transaction *trans = tmp->data;
		tmp = tmp->next;
		purple_debug_info("sipe", "have open transaction age: %ld\n", (long int)currtime-trans->time);
		if ((currtime - trans->time > 5) && trans->retries >= 1) {
			/* TODO 408 */
		} else {
			if ((currtime - trans->time > 2) && trans->retries == 0) {
				trans->retries++;
				sendout_sipmsg(sip, trans->msg);
			}
		}
	}
	return TRUE;
}

static void do_reauthenticate_cb(struct sipe_account_data *sip,
				 SIPE_UNUSED_PARAMETER void *unused)
{
	/* register again when security token expires */
	/* we have to start a new authentication as the security token
	 * is almost expired by sending a not signed REGISTER message */
	purple_debug_info("sipe", "do a full reauthentication\n");
	sipe_auth_free(&sip->registrar);
	sipe_auth_free(&sip->proxy);
	sip->registerstatus = 0;
	do_register(sip);
	sip->reauthenticate_set = FALSE;
}

static void process_incoming_message(struct sipe_account_data *sip, struct sipmsg *msg)
{
	gchar *from;
	gchar *contenttype;
	gboolean found = FALSE;

	from = parse_from(sipmsg_find_header(msg, "From"));

	if (!from) return;

	purple_debug_info("sipe", "got message from %s: %s\n", from, msg->body);

	contenttype = sipmsg_find_header(msg, "Content-Type");
	if (!strncmp(contenttype, "text/plain", 10)
	    || !strncmp(contenttype, "text/html", 9)
	    || !strncmp(contenttype, "multipart/related", 17)
	    || !strncmp(contenttype, "multipart/alternative", 21))
	{
		gchar *callid = sipmsg_find_header(msg, "Call-ID");
		gchar *html = get_html_message(contenttype, msg->body);

		struct sip_session *session = sipe_session_find_chat_by_callid(sip, callid);
		if (!session) {
			session = sipe_session_find_im(sip, from);
		}

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
		send_sip_response(sip->gc, msg, 200, "OK", NULL);
		found = TRUE;

	} else if (!strncmp(contenttype, "application/im-iscomposing+xml", 30)) {
		xmlnode *isc = xmlnode_from_str(msg->body, msg->bodylen);
		xmlnode *state;
		gchar *statedata;

		if (!isc) {
			purple_debug_info("sipe", "process_incoming_message: can not parse iscomposing\n");
			return;
		}

		state = xmlnode_get_child(isc, "state");

		if (!state) {
			purple_debug_info("sipe", "process_incoming_message: no state found\n");
			xmlnode_free(isc);
			return;
		}

		statedata = xmlnode_get_data(state);
		if (statedata) {
			if (strstr(statedata, "active")) serv_got_typing(sip->gc, from, 0, PURPLE_TYPING);
			else serv_got_typing_stopped(sip->gc, from);

			g_free(statedata);
		}
		xmlnode_free(isc);
		send_sip_response(sip->gc, msg, 200, "OK", NULL);
		found = TRUE;
	}
	if (!found) {
		gchar *callid = sipmsg_find_header(msg, "Call-ID");
		struct sip_session *session = sipe_session_find_chat_by_callid(sip, callid);
		if (!session) {
			session = sipe_session_find_im(sip, from);
		}
		if (session) {
			gchar *msg = g_strdup_printf(_("Received a message with unrecognized contents from %s"),
						     from);
			sipe_present_err(sip, session, msg);
			g_free(msg);
		}

		purple_debug_info("sipe", "got unknown mime-type '%s'\n", contenttype);
		send_sip_response(sip->gc, msg, 415, "Unsupported media type", NULL);
	}
	g_free(from);
}

static void process_incoming_invite(struct sipe_account_data *sip, struct sipmsg *msg)
{
	gchar *body;
	gchar *newTag;
	gchar *oldHeader;
	gchar *newHeader;
	gboolean is_multiparty = FALSE;
	gboolean is_triggered = FALSE;
	gboolean was_multiparty = TRUE;
	gboolean just_joined = FALSE;
	gchar *from;
	gchar *callid = 	sipmsg_find_header(msg, "Call-ID");
	gchar *roster_manager = sipmsg_find_header(msg, "Roster-Manager");
	gchar *end_points_hdr = sipmsg_find_header(msg, "EndPoints");
	gchar *trig_invite = 	sipmsg_find_header(msg, "TriggeredInvite");
	gchar *content_type = 	sipmsg_find_header(msg, "Content-Type");
	GSList *end_points = NULL;
	char *tmp = NULL;
	struct sip_session *session;

	purple_debug_info("sipe", "process_incoming_invite: body:\n%s!\n", msg->body ? tmp = fix_newlines(msg->body) : "");
	g_free(tmp);

	/* Invitation to join conference */
	if (!strncmp(content_type, "application/ms-conf-invite+xml", 30)) {
		process_incoming_invite_conf(sip, msg);
		return;
	}

	/* Only accept text invitations */
	if (msg->body && !(strstr(msg->body, "m=message") || strstr(msg->body, "m=x-ms-message"))) {
		send_sip_response(sip->gc, msg, 501, "Not implemented", NULL);
		return;
	}

	// TODO There *must* be a better way to clean up the To header to add a tag...
	purple_debug_info("sipe", "Adding a Tag to the To Header on Invite Request...\n");
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

	session = sipe_session_find_chat_by_callid(sip, callid);
	/* Convert to multiparty */
	if (session && is_multiparty && !session->is_multiparty) {
		g_free(session->with);
		session->with = NULL;
		was_multiparty = FALSE;
		session->is_multiparty = TRUE;
		session->chat_id = rand();
	}

	if (!session && is_multiparty) {
		session = sipe_session_find_or_add_chat_by_callid(sip, callid);
	}
	/* IM session */
	from = parse_from(sipmsg_find_header(msg, "From"));
	if (!session) {
		session = sipe_session_find_or_add_im(sip, from);
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
				sipe_invite(sip, session, dialog->with, NULL, NULL, TRUE);
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
			purple_debug_info("sipe", "process_incoming_invite, session already has dialog!\n");
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
		purple_debug_info("sipe", "process_incoming_invite, failed to find or create IM session\n");
	}
	g_free(newTag);

	if (is_multiparty && !session->conv) {
		gchar *chat_title = sipe_chat_get_name(callid);
		gchar *self = sip_uri_self(sip);
		/* create prpl chat */
		session->conv = serv_got_joined_chat(sip->gc, session->chat_id, chat_title);
		session->chat_title = g_strdup(chat_title);
		purple_conv_chat_set_nick(PURPLE_CONV_CHAT(session->conv), self);
		/* add self */
		purple_conv_chat_add_user(PURPLE_CONV_CHAT(session->conv),
					  self, NULL,
					  PURPLE_CBFLAGS_NONE, FALSE);
		g_free(chat_title);
		g_free(self);
	}

	if (is_multiparty && !was_multiparty) {
		/* add current IM counterparty to chat */
		purple_conv_chat_add_user(PURPLE_CONV_CHAT(session->conv),
					  sipe_dialog_first(session)->with, NULL,
					  PURPLE_CBFLAGS_NONE, FALSE);
	}

	/* add inviting party to chat */
	if (just_joined && session->conv) {
		purple_conv_chat_add_user(PURPLE_CONV_CHAT(session->conv),
				  from, NULL,
				  PURPLE_CBFLAGS_NONE, TRUE);
	}

	/* ms-text-format: text/plain; charset=UTF-8;msgr=WAAtAE0...DIADQAKAA0ACgA;ms-body=SGk= */

	/* This used only in 2005 official client, not 2007 or Reuters.
	   Disabled for most cases as interfering with audit of messages which only is applied to regular MESSAGEs.
	   Only enabled for 2005 multiparty chats as otherwise the first message got lost completely.
	*/
	if (is_multiparty) {
		/* please do not optimize logic inside as this code may be re-enabled for other cases */
		gchar *ms_text_format = sipmsg_find_header(msg, "ms-text-format");
		if (ms_text_format) {
			if (g_str_has_prefix(ms_text_format, "text/plain") || g_str_has_prefix(ms_text_format, "text/html")) {

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
	sipmsg_add_header(msg, "User-Agent", sipe_get_useragent(sip));
	sipmsg_add_header(msg, "Content-Type", "application/sdp");

	body = g_strdup_printf(
		"v=0\r\n"
		"o=- 0 0 IN IP4 %s\r\n"
		"s=session\r\n"
		"c=IN IP4 %s\r\n"
		"t=0 0\r\n"
		"m=%s %d sip sip:%s\r\n"
		"a=accept-types:text/plain text/html image/gif multipart/related multipart/alternative application/im-iscomposing+xml application/ms-imdn+xml\r\n",
		purple_network_get_my_ip(-1),
		purple_network_get_my_ip(-1),
		sip->ocs2007 ? "message" : "x-ms-message",
		sip->realport,
		sip->username);
	send_sip_response(sip->gc, msg, 200, "OK", body);
	g_free(body);
}

static void process_incoming_options(struct sipe_account_data *sip, struct sipmsg *msg)
{
	gchar *body;

	sipmsg_add_header(msg, "Allow", "INVITE, MESSAGE, INFO, SUBSCRIBE, OPTIONS, BYE, CANCEL, NOTIFY, ACK, REFER, BENOTIFY");
	sipmsg_add_header(msg, "User-Agent", sipe_get_useragent(sip));
	sipmsg_add_header(msg, "Content-Type", "application/sdp");

	body = g_strdup_printf(
		"v=0\r\n"
		"o=- 0 0 IN IP4 0.0.0.0\r\n"
		"s=session\r\n"
		"c=IN IP4 0.0.0.0\r\n"
		"t=0 0\r\n"
		"m=%s %d sip sip:%s\r\n"
		"a=accept-types:text/plain text/html image/gif multipart/related multipart/alternative application/im-iscomposing+xml application/ms-imdn+xml\r\n",
		sip->ocs2007 ? "message" : "x-ms-message",
		sip->realport,
		sip->username);
	send_sip_response(sip->gc, msg, 200, "OK", body);
	g_free(body);
}

static void sipe_connection_cleanup(struct sipe_account_data *);
static void create_connection(struct sipe_account_data *, gchar *, int);

gboolean process_register_response(struct sipe_account_data *sip, struct sipmsg *msg,
				   SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	gchar *tmp;
	const gchar *expires_header;
	int expires, i;
        GSList *hdr = msg->headers;
        struct siphdrelement *elem;

	expires_header = sipmsg_find_header(msg, "Expires");
	expires = expires_header != NULL ? strtol(expires_header, NULL, 10) : 0;
	purple_debug_info("sipe", "process_register_response: got response to REGISTER; expires = %d\n", expires);

	switch (msg->response) {
		case 200:
			if (expires == 0) {
				sip->registerstatus = 0;
			} else {
				gchar *contact_hdr = NULL;
				gchar *gruu = NULL;
				gchar *epid;
				gchar *uuid;
				gchar *timeout;
				gchar *server_hdr = sipmsg_find_header(msg, "Server");

				if (!sip->reregister_set) {
					gchar *action_name = g_strdup_printf("<%s>", "registration");
					sipe_schedule_action(action_name, expires, do_register_cb, NULL, sip, NULL);
					g_free(action_name);
					sip->reregister_set = TRUE;
				}

				sip->registerstatus = 3;

				if (server_hdr && !sip->server_version) {
					sip->server_version = g_strdup(server_hdr);
					g_free(default_ua);
					default_ua = NULL;
				}

#ifdef USE_KERBEROS
				if (!purple_account_get_bool(sip->account, "krb5", FALSE)) {
#endif
					tmp = sipmsg_find_auth_header(msg, "NTLM");
#ifdef USE_KERBEROS
				} else {
					tmp = sipmsg_find_auth_header(msg, "Kerberos");
				}
#endif
				if (tmp) {
					purple_debug(PURPLE_DEBUG_MISC, "sipe", "process_register_response - Auth header: %s\n", tmp);
					fill_auth(tmp, &sip->registrar);
				}

				if (!sip->reauthenticate_set) {
					gchar *action_name = g_strdup_printf("<%s>", "+reauthentication");
					guint reauth_timeout;
					if (sip->registrar.type == AUTH_TYPE_KERBEROS && sip->registrar.expires > 0) {
						/* assuming normal Kerberos ticket expiration of about 8-10 hours */
						reauth_timeout = sip->registrar.expires - 300;
					} else {
						/* NTLM: we have to reauthenticate as our security token expires
						after eight hours (be five minutes early) */
						reauth_timeout = (8 * 3600) - 300;
					}
					sipe_schedule_action(action_name, reauth_timeout, do_reauthenticate_cb, NULL, sip, NULL);
					g_free(action_name);
					sip->reauthenticate_set = TRUE;
				}

				purple_connection_set_state(sip->gc, PURPLE_CONNECTED);

				epid = get_epid(sip);
				uuid = generateUUIDfromEPID(epid);
				g_free(epid);

				// There can be multiple Contact headers (one per location where the user is logged in) so
				// make sure to only get the one for this uuid
				for (i = 0; (contact_hdr = sipmsg_find_header_instance (msg, "Contact", i)); i++) {
					gchar * valid_contact = sipmsg_find_part_of_header (contact_hdr, uuid, NULL, NULL);
					if (valid_contact) {
						gruu = sipmsg_find_part_of_header(contact_hdr, "gruu=\"", "\"", NULL);
						//purple_debug(PURPLE_DEBUG_MISC, "sipe", "got gruu %s from contact hdr w/ right uuid: %s\n", gruu, contact_hdr);
						g_free(valid_contact);
						break;
					} else {
						//purple_debug(PURPLE_DEBUG_MISC, "sipe", "ignoring contact hdr b/c not right uuid: %s\n", contact_hdr);
					}
				}
				g_free(uuid);

				g_free(sip->contact);
				if(gruu) {
					sip->contact = g_strdup_printf("<%s>", gruu);
					g_free(gruu);
				} else {
					//purple_debug(PURPLE_DEBUG_MISC, "sipe", "didn't find gruu in a Contact hdr\n");
					sip->contact = g_strdup_printf("<sip:%s:%d;maddr=%s;transport=%s>;proxy=replace", sip->username, sip->listenport, purple_network_get_my_ip(-1), TRANSPORT_DESCRIPTOR);
				}
                                sip->ocs2007 = FALSE;
				sip->batched_support = FALSE;

                                while(hdr)
                                {
					elem = hdr->data;
					if (!g_ascii_strcasecmp(elem->name, "Supported")) {
						if (!g_ascii_strcasecmp(elem->value, "msrtc-event-categories")) {
							/* We interpret this as OCS2007+ indicator */
							sip->ocs2007 = TRUE;
							purple_debug(PURPLE_DEBUG_MISC, "sipe", "Supported: %s (indicates OCS2007+)\n", elem->value);
						}
						if (!g_ascii_strcasecmp(elem->value, "adhoclist")) {
							sip->batched_support = TRUE;
							purple_debug(PURPLE_DEBUG_MISC, "sipe", "Supported: %s\n", elem->value);
						}
					}
                                        if (!g_ascii_strcasecmp(elem->name, "Allow-Events")){
						gchar **caps = g_strsplit(elem->value,",",0);
						i = 0;
						while (caps[i]) {
							sip->allow_events =  g_slist_append(sip->allow_events, g_strdup(caps[i]));
							purple_debug(PURPLE_DEBUG_MISC, "sipe", "Allow-Events: %s\n", caps[i]);
							i++;
						}
						g_strfreev(caps);
                                        }
                                        hdr = g_slist_next(hdr);
                                }

				/* rejoin open chats to be able to use them by continue to send messages */
				purple_conversation_foreach(sipe_rejoin_chat);

				/* subscriptions */
				if (!sip->subscribed) { //do it just once, not every re-register

					if (g_slist_find_custom(sip->allow_events, "vnd-microsoft-roaming-contacts",
								(GCompareFunc)g_ascii_strcasecmp)) {
						sipe_subscribe_roaming_contacts(sip);
					}

					/* For 2007+ it does not make sence to subscribe to:
					 *   vnd-microsoft-roaming-ACL
					 *   vnd-microsoft-provisioning (not v2)
					 *   presence.wpending
					 * These are for backward compatibility.
					 */
					if (sip->ocs2007)
					{
						if (g_slist_find_custom(sip->allow_events, "vnd-microsoft-roaming-self",
									(GCompareFunc)g_ascii_strcasecmp)) {
							sipe_subscribe_roaming_self(sip);
						}
						if (g_slist_find_custom(sip->allow_events, "vnd-microsoft-provisioning-v2",
									(GCompareFunc)g_ascii_strcasecmp)) {
							sipe_subscribe_roaming_provisioning_v2(sip);
						}
					}
					/* For 2005- servers */
					else
					{
						//sipe_options_request(sip, sip->sipdomain);

						if (g_slist_find_custom(sip->allow_events, "vnd-microsoft-roaming-ACL",
									(GCompareFunc)g_ascii_strcasecmp)) {
							sipe_subscribe_roaming_acl(sip);
						}
						if (g_slist_find_custom(sip->allow_events, "vnd-microsoft-provisioning",
									(GCompareFunc)g_ascii_strcasecmp)) {
							sipe_subscribe_roaming_provisioning(sip);
						}
						if (g_slist_find_custom(sip->allow_events, "presence.wpending",
									(GCompareFunc)g_ascii_strcasecmp)) {
							sipe_subscribe_presence_wpending(sip, msg);
						}

						/* For 2007+ we publish our initial statuses and calendar data only after
						 * received our existing publications in sipe_process_roaming_self()
						 * Only in this case we know versions of current publications made
						 * on our behalf.
						 */
						/* For 2005- we publish our initial statuses only after
						 * received our existing UserInfo data in response to
						 * self subscription.
						 * Only in this case we won't override existing UserInfo data
						 * set earlier or by other client on our behalf.
						 */
					}

					sip->subscribed = TRUE;
				}

				timeout = sipmsg_find_part_of_header(sipmsg_find_header(msg, "ms-keep-alive"),
								     "timeout=", ";", NULL);
				if (timeout != NULL) {
					sscanf(timeout, "%u", &sip->keepalive_timeout);
					purple_debug_info("sipe", "server determined keep alive timeout is %u seconds\n",
							  sip->keepalive_timeout);
					g_free(timeout);
				}

				purple_debug(PURPLE_DEBUG_MISC, "sipe", "process_register_response - got 200, removing CSeq: %d\n", sip->cseq);
			}
			break;
		case 301:
			{
				gchar *redirect = parse_from(sipmsg_find_header(msg, "Contact"));

				if (redirect && (g_strncasecmp("sip:", redirect, 4) == 0)) {
					gchar **parts = g_strsplit(redirect + 4, ";", 0);
					gchar **tmp;
					gchar *hostname;
					int port = 0;
					sipe_transport_type transport = SIPE_TRANSPORT_TLS;
					int i = 1;

					tmp = g_strsplit(parts[0], ":", 0);
					hostname = g_strdup(tmp[0]);
					if (tmp[1]) port = strtoul(tmp[1], NULL, 10);
					g_strfreev(tmp);

					while (parts[i]) {
						tmp = g_strsplit(parts[i], "=", 0);
						if (tmp[1]) {
							if (g_strcasecmp("transport", tmp[0]) == 0) {
								if        (g_strcasecmp("tcp", tmp[1]) == 0) {
									transport = SIPE_TRANSPORT_TCP;
								} else if (g_strcasecmp("udp", tmp[1]) == 0) {
									transport = SIPE_TRANSPORT_UDP;
								}
							}
						}
						g_strfreev(tmp);
						i++;
					}
					g_strfreev(parts);

					/* Close old connection */
					sipe_connection_cleanup(sip);

					/* Create new connection */
					sip->transport = transport;
					purple_debug_info("sipe", "process_register_response: redirected to host %s port %d transport %s\n",
							  hostname, port, TRANSPORT_DESCRIPTOR);
					create_connection(sip, hostname, port);
				}
				g_free(redirect);
			}
			break;
		case 401:
			if (sip->registerstatus != 2) {
				purple_debug_info("sipe", "REGISTER retries %d\n", sip->registrar.retries);
				if (sip->registrar.retries > 3) {
					sip->gc->wants_to_die = TRUE;
					purple_connection_error(sip->gc, _("Wrong password"));
					return TRUE;
				}
#ifdef USE_KERBEROS
				if (!purple_account_get_bool(sip->account, "krb5", FALSE)) {
#endif
					tmp = sipmsg_find_auth_header(msg, "NTLM");
#ifdef USE_KERBEROS
				} else {
					tmp = sipmsg_find_auth_header(msg, "Kerberos");
				}
#endif
				purple_debug(PURPLE_DEBUG_MISC, "sipe", "process_register_response - Auth header: %s\n", tmp);
				fill_auth(tmp, &sip->registrar);
				sip->registerstatus = 2;
				if (sip->account->disconnecting) {
					do_register_exp(sip, 0);
				} else {
					do_register(sip);
				}
			}
			break;
		case 403:
			{
				gchar *warning = sipmsg_find_header(msg, "Warning");
				gchar **reason = NULL;
				if (warning != NULL) {
					/* Example header:
					   Warning: 310 lcs.microsoft.com "You are currently not using the recommended version of the client"
					*/
					reason = g_strsplit(warning, "\"", 0);
				}
				warning = g_strdup_printf(_("You have been rejected by the server: %s"),
							  (reason && reason[1]) ? reason[1] : _("no reason given"));
				g_strfreev(reason);

				sip->gc->wants_to_die = TRUE;
				purple_connection_error(sip->gc, warning);
				g_free(warning);
				return TRUE;
			}
			break;
			case 404:
			{
				gchar *warning = sipmsg_find_header(msg, "ms-diagnostics");
				gchar *reason = NULL;
				if (warning != NULL) {
					reason = sipmsg_find_part_of_header(warning, "reason=\"", "\"", NULL);
				}
				warning = g_strdup_printf(_("Not found: %s. Please contact your Administrator"),
							  warning ? (reason ? reason : _("no reason given")) :
							  _("SIP is either not enabled for the destination URI or it does not exist"));
				g_free(reason);

				sip->gc->wants_to_die = TRUE;
				purple_connection_error(sip->gc, warning);
				g_free(warning);
				return TRUE;
			}
			break;
                case 503:
		case 504: /* Server time-out */
                        {
				gchar *warning = sipmsg_find_header(msg, "ms-diagnostics");
				gchar *reason = NULL;
				if (warning != NULL) {
					reason = sipmsg_find_part_of_header(warning, "reason=\"", "\"", NULL);
				}
				warning = g_strdup_printf(_("Service unavailable: %s"), reason ? reason : "<a href=\"http://www.reuters.com\">http://www.reuters.com</a>"/*_("no reason given")*/);
				g_free(reason);

				sip->gc->wants_to_die = TRUE;
				purple_connection_error(sip->gc, warning);
				g_free(warning);
				return TRUE;
			}
			break;
		}
	return TRUE;
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

	if (!strcmp(status, SIPE_STATUS_ID_AWAY)) {
		act = 100;
	//} else if (!strcmp(status, SIPE_STATUS_ID_LUNCH)) {
	//	act = 150;
	} else if (!strcmp(status, SIPE_STATUS_ID_BRB)) {
		act = 300;
	} else if (!strcmp(status, SIPE_STATUS_ID_AVAILABLE)) {
		act = 400;
	//} else if (!strcmp(status, SIPE_STATUS_ID_ON_PHONE)) {
	//	act = 500;
	} else if (!strcmp(status, SIPE_STATUS_ID_BUSY) ||
		   !strcmp(status, SIPE_STATUS_ID_DND)) {
		act = 600;
	} else if (!strcmp(status, SIPE_STATUS_ID_INVISIBLE) ||
		   !strcmp(status, SIPE_STATUS_ID_OFFLINE)) {
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

	if (!strcmp(sipe_status_id, SIPE_STATUS_ID_AWAY)) {
		availability = 15500;
		if (!activity_token || !(*activity_token))	{
			activity = SIPE_ACTIVITY_AWAY;
		}
	} else if (!strcmp(sipe_status_id, SIPE_STATUS_ID_BRB)) {
		availability = 12500;
		activity = SIPE_ACTIVITY_BRB;
	} else if (!strcmp(sipe_status_id, SIPE_STATUS_ID_DND)) {
		availability =  9500;
		activity = SIPE_ACTIVITY_DND;
	} else if (!strcmp(sipe_status_id, SIPE_STATUS_ID_BUSY)) {
		availability =  6500;
		if (!activity_token || !(*activity_token))	{
			activity = SIPE_ACTIVITY_BUSY;
		}
	} else if (!strcmp(sipe_status_id, SIPE_STATUS_ID_AVAILABLE)) {
		availability =  3500;
		activity = SIPE_ACTIVITY_ONLINE;
	} else if (!strcmp(sipe_status_id, SIPE_STATUS_ID_UNKNOWN)) {
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

static void process_incoming_notify_rlmi(struct sipe_account_data *sip, const gchar *data, unsigned len)
{
	const char *uri;
	xmlnode *xn_categories;
	xmlnode *xn_category;
	xmlnode *xn_node;
	const char *status = NULL;
	gboolean do_update_status = FALSE;
	gboolean has_note_cleaned = FALSE;
	gboolean has_free_busy_cleaned = FALSE;

	xn_categories = xmlnode_from_str(data, len);
	uri = xmlnode_get_attrib(xn_categories, "uri"); /* with 'sip:' prefix */

	for (xn_category = xmlnode_get_child(xn_categories, "category");
		 xn_category ;
		 xn_category = xmlnode_get_next_twin(xn_category) )
	{
		const char *tmp;
		const char *attrVar = xmlnode_get_attrib(xn_category, "name");
		time_t publish_time = (tmp = xmlnode_get_attrib(xn_category, "publishTime")) ?
			purple_str_to_time(tmp, FALSE, NULL, NULL, NULL) : 0;

		/* contactCard */
		if (!strcmp(attrVar, "contactCard"))
		{
			xmlnode *node;
			/* identity - Display Name and email */
			node = xmlnode_get_descendant(xn_category, "contactCard", "identity", NULL);
			if (node) {
				char* display_name = xmlnode_get_data(
					xmlnode_get_descendant(node, "name", "displayName",  NULL));
				char* email = xmlnode_get_data(
					xmlnode_get_child(node, "email"));

				sipe_update_user_info(sip, uri, ALIAS_PROP, display_name);
				sipe_update_user_info(sip, uri, EMAIL_PROP, email);

				g_free(display_name);
				g_free(email);
			}
			/* company */
			node = xmlnode_get_descendant(xn_category, "contactCard", "company", NULL);
			if (node) {
				char* company = xmlnode_get_data(node);
				sipe_update_user_info(sip, uri, COMPANY_PROP, company);
				g_free(company);
			}
			/* department */
			node = xmlnode_get_descendant(xn_category, "contactCard", "department", NULL);
			if (node) {
				char* department = xmlnode_get_data(node);
				sipe_update_user_info(sip, uri, DEPARTMENT_PROP, department);
				g_free(department);
			}
			/* title */
			node = xmlnode_get_descendant(xn_category, "contactCard", "title", NULL);
			if (node) {
				char* title = xmlnode_get_data(node);
				sipe_update_user_info(sip, uri, TITLE_PROP, title);
				g_free(title);
			}
			/* office */
			node = xmlnode_get_descendant(xn_category, "contactCard", "office", NULL);
			if (node) {
				char* office = xmlnode_get_data(node);
				sipe_update_user_info(sip, uri, OFFICE_PROP, office);
				g_free(office);
			}
			/* site (url) */
			node = xmlnode_get_descendant(xn_category, "contactCard", "url", NULL);
			if (node) {
				char* site = xmlnode_get_data(node);
				sipe_update_user_info(sip, uri, SITE_PROP, site);
				g_free(site);
			}
			/* phone */
			for (node = xmlnode_get_descendant(xn_category, "contactCard", "phone", NULL);
			     node;
			     node = xmlnode_get_next_twin(node))
			{
				const char *phone_type = xmlnode_get_attrib(node, "type");
				char* phone = xmlnode_get_data(xmlnode_get_child(node, "uri"));
				char* phone_display_string = xmlnode_get_data(xmlnode_get_child(node, "displayString"));

				sipe_update_user_phone(sip, uri, phone_type, phone, phone_display_string);

				g_free(phone);
				g_free(phone_display_string);
			}
			/* address */
			for (node = xmlnode_get_descendant(xn_category, "contactCard", "address", NULL);
			     node;
			     node = xmlnode_get_next_twin(node))
			{
				if (!strcmp(xmlnode_get_attrib(node, "type"), "work")) {
					char* street = xmlnode_get_data(xmlnode_get_child(node, "street"));
					char* city = xmlnode_get_data(xmlnode_get_child(node, "city"));
					char* state = xmlnode_get_data(xmlnode_get_child(node, "state"));
					char* zipcode = xmlnode_get_data(xmlnode_get_child(node, "zipcode"));
					char* country_code = xmlnode_get_data(xmlnode_get_child(node, "countryCode"));

					sipe_update_user_info(sip, uri, ADDRESS_STREET_PROP, street);
					sipe_update_user_info(sip, uri, ADDRESS_CITY_PROP, city);
					sipe_update_user_info(sip, uri, ADDRESS_STATE_PROP, state);
					sipe_update_user_info(sip, uri, ADDRESS_ZIPCODE_PROP, zipcode);
					sipe_update_user_info(sip, uri, ADDRESS_COUNTRYCODE_PROP, country_code);

					g_free(street);
					g_free(city);
					g_free(state);
					g_free(zipcode);
					g_free(country_code);

					break;
				}
			}
		}
		/* note */
		else if (!strcmp(attrVar, "note"))
		{
			if (uri) {
				struct sipe_buddy *sbuddy = g_hash_table_lookup(sip->buddies, uri);
				
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

					xn_node = xmlnode_get_descendant(xn_category, "note", "body", NULL);
					if (xn_node) {
						char *tmp;
						sbuddy->note = g_markup_escape_text((tmp = xmlnode_get_data(xn_node)), -1);
						g_free(tmp);
						sbuddy->is_oof_note = !strcmp(xmlnode_get_attrib(xn_node, "type"), "OOF");
						sbuddy->note_since = publish_time;

						purple_debug_info("sipe", "process_incoming_notify_rlmi: uri(%s), note(%s)\n",
							uri, sbuddy->note ? sbuddy->note : "");
					}
					/* to trigger UI refresh in case no status info is supplied in this update */
					do_update_status = TRUE;
				}
			}	
		}
		/* state */
		else if(!strcmp(attrVar, "state"))
		{
			char *data;
			int availability;
			xmlnode *xn_availability;
			xmlnode *xn_activity;
			xmlnode *xn_meeting_subject;
			xmlnode *xn_meeting_location;
			struct sipe_buddy *sbuddy = uri ? g_hash_table_lookup(sip->buddies, uri) : NULL;

			xn_node = xmlnode_get_child(xn_category, "state");
			if (!xn_node) continue;
			xn_availability = xmlnode_get_child(xn_node, "availability");
			if (!xn_availability) continue;
			xn_activity = xmlnode_get_child(xn_node, "activity");
			xn_meeting_subject = xmlnode_get_child(xn_node, "meetingSubject");
			xn_meeting_location = xmlnode_get_child(xn_node, "meetingLocation");

			data = xmlnode_get_data(xn_availability);
			availability = atoi(data);
			g_free(data);

			/* activity, meeting_subject, meeting_location */
			if (sbuddy) {
				char *tmp = NULL;

				/* activity */
				g_free(sbuddy->activity);
				sbuddy->activity = NULL;
				if (xn_activity) {
					const char *token = xmlnode_get_attrib(xn_activity, "token");
					xmlnode *xn_custom = xmlnode_get_child(xn_activity, "custom");

					/* from token */
					if (!is_empty(token)) {
						sbuddy->activity = g_strdup(sipe_get_activity_desc_by_token(token));
					}
					/* from custom element */
					if (xn_custom) {
						char *custom = xmlnode_get_data(xn_custom);

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
					char *meeting_subject = xmlnode_get_data(xn_meeting_subject);

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
					char *meeting_location = xmlnode_get_data(xn_meeting_location);

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
		else if(!strcmp(attrVar, "calendarData"))
		{
			struct sipe_buddy *sbuddy = uri ? g_hash_table_lookup(sip->buddies, uri) : NULL;
			xmlnode *xn_free_busy = xmlnode_get_descendant(xn_category, "calendarData", "freeBusy", NULL);
			xmlnode *xn_working_hours = xmlnode_get_descendant(xn_category, "calendarData", "WorkingHours", NULL);

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
					sbuddy->cal_start_time = g_strdup(xmlnode_get_attrib(xn_free_busy, "startTime"));

					sbuddy->cal_granularity = !g_ascii_strcasecmp(xmlnode_get_attrib(xn_free_busy, "granularity"), "PT15M") ?
						15 : 0;

					g_free(sbuddy->cal_free_busy_base64);
					sbuddy->cal_free_busy_base64 = xmlnode_get_data(xn_free_busy);

					g_free(sbuddy->cal_free_busy);
					sbuddy->cal_free_busy = NULL;

					sbuddy->cal_free_busy_published = publish_time;

					purple_debug_info("sipe", "process_incoming_notify_rlmi: startTime=%s granularity=%d cal_free_busy_base64=\n%s\n", sbuddy->cal_start_time, sbuddy->cal_granularity, sbuddy->cal_free_busy_base64);
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

		purple_debug_info("sipe", "process_incoming_notify_rlmi: %s\n", status);
		sipe_got_user_status(sip, uri, status);
	}

	xmlnode_free(xn_categories);
}

static void sipe_subscribe_poolfqdn_resource_uri(const char *host, GSList *server, struct sipe_account_data *sip)
{
	struct presence_batched_routed *payload = g_malloc(sizeof(struct presence_batched_routed));
	purple_debug_info("sipe", "process_incoming_notify_rlmi_resub: pool(%s)\n", host);
	payload->host    = g_strdup(host);
	payload->buddies = server;
	sipe_subscribe_presence_batched_routed(sip, payload);
	sipe_subscribe_presence_batched_routed_free(payload);
}

static void process_incoming_notify_rlmi_resub(struct sipe_account_data *sip, const gchar *data, unsigned len)
{
	xmlnode *xn_list;
	xmlnode *xn_resource;
	GHashTable *servers = g_hash_table_new_full(g_str_hash, g_str_equal,
						    g_free, NULL);
	GSList *server;
	gchar *host;

	xn_list = xmlnode_from_str(data, len);

        for (xn_resource = xmlnode_get_child(xn_list, "resource");
	     xn_resource;
	     xn_resource = xmlnode_get_next_twin(xn_resource) )
	{
		const char *uri, *state;
		xmlnode *xn_instance;

		xn_instance = xmlnode_get_child(xn_resource, "instance");
                if (!xn_instance) continue;

                uri = xmlnode_get_attrib(xn_resource, "uri");
                state = xmlnode_get_attrib(xn_instance, "state");
                purple_debug_info("sipe", "process_incoming_notify_rlmi_resub: uri(%s),state(%s)\n", uri, state);

                if (strstr(state, "resubscribe")) {
			const char *poolFqdn = xmlnode_get_attrib(xn_instance, "poolFqdn");

			if (poolFqdn) { //[MS-PRES] Section 3.4.5.1.3 Processing Details
				gchar *user = g_strdup(uri);
				host = g_strdup(poolFqdn);
				server = g_hash_table_lookup(servers, host);
				server = g_slist_append(server, user);
				g_hash_table_insert(servers, host, server);
			} else {
				sipe_subscribe_presence_single(sip, (void *) uri);
			}
                }
	}

	/* Send out any deferred poolFqdn subscriptions */
	g_hash_table_foreach(servers, (GHFunc) sipe_subscribe_poolfqdn_resource_uri, sip);
	g_hash_table_destroy(servers);

	xmlnode_free(xn_list);
}

static void process_incoming_notify_pidf(struct sipe_account_data *sip, const gchar *data, unsigned len)
{
	gchar *uri;
	gchar *getbasic;
	gchar *activity = NULL;
	xmlnode *pidf;
	xmlnode *basicstatus = NULL, *tuple, *status;
	gboolean isonline = FALSE;
	xmlnode *display_name_node;

	pidf = xmlnode_from_str(data, len);
	if (!pidf) {
		purple_debug_info("sipe", "process_incoming_notify_pidf: no parseable pidf:%s\n",data);
		return;
	}

	uri = sip_uri(xmlnode_get_attrib(pidf, "entity")); /* with 'sip:' prefix */ /* AOL comes without the prefix */

	if ((tuple = xmlnode_get_child(pidf, "tuple")))
	{
		if ((status = xmlnode_get_child(tuple, "status"))) {
			basicstatus = xmlnode_get_child(status, "basic");
		}
	}

	if (!basicstatus) {
		purple_debug_info("sipe", "process_incoming_notify_pidf: no basic found\n");
		xmlnode_free(pidf);
		return;
	}

	getbasic = xmlnode_get_data(basicstatus);
	if (!getbasic) {
		purple_debug_info("sipe", "process_incoming_notify_pidf: no basic data found\n");
		xmlnode_free(pidf);
		return;
	}

	purple_debug_info("sipe", "process_incoming_notify_pidf: basic-status(%s)\n", getbasic);
	if (strstr(getbasic, "open")) {
		isonline = TRUE;
	}
	g_free(getbasic);

	display_name_node = xmlnode_get_child(pidf, "display-name");
	if (display_name_node) {
		char * display_name = xmlnode_get_data(display_name_node);

		sipe_update_user_info(sip, uri, ALIAS_PROP, display_name);
		g_free(display_name);
	}

	if ((tuple = xmlnode_get_child(pidf, "tuple"))) {
		if ((status = xmlnode_get_child(tuple, "status"))) {
			if ((basicstatus = xmlnode_get_child(status, "activities"))) {
				if ((basicstatus = xmlnode_get_child(basicstatus, "activity"))) {
					activity = xmlnode_get_data(basicstatus);
					purple_debug_info("sipe", "process_incoming_notify_pidf: activity(%s)\n", activity);
				}
			}
		}
	}

	if (isonline) {
		const gchar * status_id = NULL;
		if (activity) {
			if (!strcmp(activity, sipe_activity_map[SIPE_ACTIVITY_BUSY].token)) {
				status_id = SIPE_STATUS_ID_BUSY;
			} else if (!strcmp(activity, sipe_activity_map[SIPE_ACTIVITY_AWAY].token)) {
				status_id = SIPE_STATUS_ID_AWAY;
			}
		}

		if (!status_id) {
			status_id = SIPE_STATUS_ID_AVAILABLE;
		}

		purple_debug_info("sipe", "process_incoming_notify_pidf: status_id(%s)\n", status_id);
		sipe_got_user_status(sip, uri, status_id);
	} else {
		sipe_got_user_status(sip, uri, SIPE_STATUS_ID_OFFLINE);
	}

	g_free(activity);
	g_free(uri);
	xmlnode_free(pidf);
}

/** 2005 */
static void
sipe_user_info_has_updated(struct sipe_account_data *sip,
			   xmlnode *xn_userinfo)
{
	if (sip->user_info) {
		xmlnode_free(sip->user_info);
	}
	sip->user_info = xmlnode_copy(xn_userinfo);

	/* Publish initial state if not yet.
	 * Assuming this happens on initial responce to self subscription
	 * so we've already updated our UserInfo.
	 */
	if (!sip->initial_state_published) {
		send_presence_soap(sip, FALSE);
		/* dalayed run */
		sipe_schedule_action("<+update-calendar>", UPDATE_CALENDAR_DELAY, (Action)sipe_update_calendar, NULL, sip, NULL);
	}
}

static void process_incoming_notify_msrtc(struct sipe_account_data *sip, const gchar *data, unsigned len)
{
	char *activity = NULL;
	const char *epid;
	const char *status_id = NULL;
	const char *name;
	char *uri;
	char *self_uri = sip_uri_self(sip);
	int avl;
	int act;
	const char *device_name = NULL;
	const char *cal_start_time = NULL;
	const char *cal_granularity = NULL;
	char *cal_free_busy_base64 = NULL;
	struct sipe_buddy *sbuddy;
	xmlnode *node;
	xmlnode *xn_presentity;
	xmlnode *xn_availability;
	xmlnode *xn_activity;
	xmlnode *xn_display_name;
	xmlnode *xn_email;
	xmlnode *xn_phone_number;
	xmlnode *xn_userinfo;
	xmlnode *xn_note;
	xmlnode *xn_oof;
	xmlnode *xn_state;
	xmlnode *xn_contact;
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
		xn_presentity = xmlnode_from_str(tmp_data, strlen(tmp_data));
		g_free(tmp_data);
	} else {
		xn_presentity = xmlnode_from_str(data, len);
	}

	xn_availability = xmlnode_get_child(xn_presentity, "availability");
	xn_activity = xmlnode_get_child(xn_presentity, "activity");
	xn_display_name = xmlnode_get_child(xn_presentity, "displayName");
	xn_email = xmlnode_get_child(xn_presentity, "email");
	xn_phone_number = xmlnode_get_child(xn_presentity, "phoneNumber");
	xn_userinfo = xmlnode_get_child(xn_presentity, "userInfo");
	xn_oof = xn_userinfo ? xmlnode_get_child(xn_userinfo, "oof") : NULL;
	xn_state = xn_userinfo ? xmlnode_get_descendant(xn_userinfo, "states", "state",  NULL): NULL;
	user_avail = xn_state ? atoi(xmlnode_get_attrib(xn_state, "avail")) : 0;
	user_avail_since = xn_state ? purple_str_to_time(xmlnode_get_attrib(xn_state, "since"), FALSE, NULL, NULL, NULL) : 0;
	user_avail_nil = xn_state ? xmlnode_get_attrib(xn_state, "nil") : NULL;
	xn_contact = xn_userinfo ? xmlnode_get_child(xn_userinfo, "contact") : NULL;
	xn_note = xn_userinfo ? xmlnode_get_child(xn_userinfo, "note") : NULL;
	note = xn_note ? xmlnode_get_data(xn_note) : NULL;

	if (user_avail_nil && !strcmp(user_avail_nil, "true")) {	/* null-ed */
		user_avail = 0;
		user_avail_since = 0;
	}

	free_activity = NULL;

	name = xmlnode_get_attrib(xn_presentity, "uri"); /* without 'sip:' prefix */
	uri = sip_uri_from_name(name);
	avl = atoi(xmlnode_get_attrib(xn_availability, "aggregate"));
	epid = xmlnode_get_attrib(xn_availability, "epid");
	act = atoi(xmlnode_get_attrib(xn_activity, "aggregate"));

	status_id = sipe_get_status_by_act_avail_2005(act, avl, &activity);
	res_avail = sipe_get_availability_by_status(status_id, NULL);
	if (user_avail > res_avail) {
		res_avail = user_avail;
		status_id = sipe_get_status_by_availability(user_avail, NULL);
	}

	if (xn_display_name) {
		char *display_name = g_strdup(xmlnode_get_attrib(xn_display_name, "displayName"));
		char *email        = xn_email ? g_strdup(xmlnode_get_attrib(xn_email, "email")) : NULL;
		char *phone_label  = xn_phone_number ? g_strdup(xmlnode_get_attrib(xn_phone_number, "label")) : NULL;
		char *phone_number = xn_phone_number ? g_strdup(xmlnode_get_attrib(xn_phone_number, "number")) : NULL;
		char *tel_uri      = sip_to_tel_uri(phone_number);

		sipe_update_user_info(sip, uri, ALIAS_PROP, display_name);
		sipe_update_user_info(sip, uri, EMAIL_PROP, email);
		sipe_update_user_info(sip, uri, PHONE_PROP, tel_uri);
		sipe_update_user_info(sip, uri, PHONE_DISPLAY_PROP, !is_empty(phone_label) ? phone_label : phone_number);

		g_free(tel_uri);
		g_free(phone_label);
		g_free(phone_number);
		g_free(email);
		g_free(display_name);
	}

	if (xn_contact) {
		/* tel */
		for (node = xmlnode_get_child(xn_contact, "tel"); node; node = xmlnode_get_next_twin(node))
		{
			/* Ex.: <tel type="work">tel:+3222220000</tel> */
			const char *phone_type = xmlnode_get_attrib(node, "type");
			char* phone = xmlnode_get_data(node);

			sipe_update_user_phone(sip, uri, phone_type, phone, NULL);

			g_free(phone);
		}
	}

	/* devicePresence */
	for (node = xmlnode_get_descendant(xn_presentity, "devices", "devicePresence", NULL); node; node = xmlnode_get_next_twin(node)) {
		xmlnode *xn_device_name;
		xmlnode *xn_calendar_info;
		xmlnode *xn_state;
		char *state;

		/* deviceName */
		if (!strcmp(xmlnode_get_attrib(node, "epid"), epid)) {
			xn_device_name = xmlnode_get_child(node, "deviceName");
			device_name = xn_device_name ? xmlnode_get_attrib(xn_device_name, "name") : NULL;
		}

		/* calendarInfo */
		xn_calendar_info = xmlnode_get_child(node, "calendarInfo");
		if (xn_calendar_info) {
			const char *cal_start_time_tmp = xmlnode_get_attrib(xn_calendar_info, "startTime");

			if (cal_start_time) {
				time_t cal_start_time_t     = purple_str_to_time(cal_start_time,     FALSE, NULL, NULL, NULL);
				time_t cal_start_time_t_tmp = purple_str_to_time(cal_start_time_tmp, FALSE, NULL, NULL, NULL);

				if (cal_start_time_t_tmp > cal_start_time_t) {
					cal_start_time = cal_start_time_tmp;
					cal_granularity = xmlnode_get_attrib(xn_calendar_info, "granularity");
					cal_free_busy_base64 = xmlnode_get_data(xn_calendar_info);

					purple_debug_info("sipe", "process_incoming_notify_msrtc: startTime=%s granularity=%s cal_free_busy_base64=\n%s\n", cal_start_time, cal_granularity, cal_free_busy_base64);
				}
			} else {
				cal_start_time = cal_start_time_tmp;
				cal_granularity = xmlnode_get_attrib(xn_calendar_info, "granularity");
				cal_free_busy_base64 = xmlnode_get_data(xn_calendar_info);

				purple_debug_info("sipe", "process_incoming_notify_msrtc: startTime=%s granularity=%s cal_free_busy_base64=\n%s\n", cal_start_time, cal_granularity, cal_free_busy_base64);
			}
		}

		/* state */
		xn_state = xmlnode_get_descendant(node, "states", "state", NULL);
		if (xn_state) {
			int dev_avail = atoi(xmlnode_get_attrib(xn_state, "avail"));
			time_t dev_avail_since = purple_str_to_time(xmlnode_get_attrib(xn_state, "since"), FALSE, NULL, NULL, NULL);

			state = xmlnode_get_data(xn_state);
			if (dev_avail_since > user_avail_since &&
			    dev_avail >= res_avail)
			{				
				res_avail = dev_avail;
				if (!is_empty(state))
				{
					if (!strcmp(state, sipe_activity_map[SIPE_ACTIVITY_ON_PHONE].token)) {
						activity = g_strdup(SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_ON_PHONE));
					} else if (!strcmp(state, "presenting")) {
						activity = g_strdup(SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_IN_CONF));
					} else {
						activity = state;
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
               activity = g_strdup(SIPE_ACTIVITY_I18N(SIPE_ACTIVITY_OOF));
	       activity_since = 0;
	}

	sbuddy = g_hash_table_lookup(sip->buddies, uri);
	if (sbuddy)
	{
		g_free(sbuddy->activity);
		sbuddy->activity = activity;

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

			sbuddy->cal_granularity = !g_ascii_strcasecmp(cal_granularity, "PT15M") ? 15 : 0;

			g_free(sbuddy->cal_free_busy_base64);
			sbuddy->cal_free_busy_base64 = cal_free_busy_base64;

			g_free(sbuddy->cal_free_busy);
			sbuddy->cal_free_busy = NULL;
		}

		sbuddy->last_non_cal_status_id = status_id;
		g_free(sbuddy->last_non_cal_activity);
		sbuddy->last_non_cal_activity = g_strdup(sbuddy->activity);
		
		if (!strcmp(sbuddy->name, self_uri)) {		
			if (!(sbuddy->note && sip->note && !strcmp(sbuddy->note, sip->note))) /* not same */
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

	purple_debug_info("sipe", "process_incoming_notify_msrtc: status(%s)\n", status_id);
	sipe_got_user_status(sip, uri, status_id);

	if (!sip->ocs2007 && !strcmp(self_uri, uri)) {
		sipe_user_info_has_updated(sip, xn_userinfo);
	}

	g_free(note);
	xmlnode_free(xn_presentity);
	g_free(uri);
	g_free(self_uri);
}

static void sipe_process_presence(struct sipe_account_data *sip, struct sipmsg *msg)
{
	char *ctype = sipmsg_find_header(msg, "Content-Type");

	purple_debug_info("sipe", "sipe_process_presence: Content-Type: %s\n", ctype ? ctype : "");

	if ( ctype && (  strstr(ctype, "application/rlmi+xml")
				  || strstr(ctype, "application/msrtc-event-categories+xml") ) )
	{
		const char *content = msg->body;
		unsigned length = msg->bodylen;
		PurpleMimeDocument *mime = NULL;

		if (strstr(ctype, "multipart"))
		{
			char *doc = g_strdup_printf("Content-Type: %s\r\n\r\n%s", ctype, msg->body);
                        const char *content_type;
			GList* parts;
			mime = purple_mime_document_parse(doc);
			parts = purple_mime_document_get_parts(mime);
			while(parts) {
				content = purple_mime_part_get_data(parts->data);
				length = purple_mime_part_get_length(parts->data);
				content_type =purple_mime_part_get_field(parts->data,"Content-Type");
				if(content_type && strstr(content_type,"application/rlmi+xml"))
				{
					process_incoming_notify_rlmi_resub(sip, content, length);
				}
				else if(content_type && strstr(content_type, "text/xml+msrtc.pidf"))
				{
					process_incoming_notify_msrtc(sip, content, length);
				}
				else
				{
					process_incoming_notify_rlmi(sip, content, length);
				}
				parts = parts->next;
			}
			g_free(doc);

			if (mime)
			{
				purple_mime_document_free(mime);
			}
		}
		else if(strstr(ctype, "application/msrtc-event-categories+xml") )
		{
			process_incoming_notify_rlmi(sip, msg->body, msg->bodylen);
		}
		else if(strstr(ctype, "application/rlmi+xml"))
		{
			process_incoming_notify_rlmi_resub(sip, msg->body, msg->bodylen);
		}
	}
	else if(ctype && strstr(ctype, "text/xml+msrtc.pidf"))
	{
		process_incoming_notify_msrtc(sip, msg->body, msg->bodylen);
	}
	else
	{
		process_incoming_notify_pidf(sip, msg->body, msg->bodylen);
	}
}

static void sipe_process_presence_timeout(struct sipe_account_data *sip, struct sipmsg *msg, gchar *who, int timeout)
{
	char *ctype = sipmsg_find_header(msg, "Content-Type");
	gchar *action_name = g_strdup_printf(ACTION_NAME_PRESENCE, who);

	purple_debug_info("sipe", "sipe_process_presence_timeout: Content-Type: %s\n", ctype ? ctype : "");

	if (ctype &&
	    strstr(ctype, "multipart") &&
	    (strstr(ctype, "application/rlmi+xml") ||
	     strstr(ctype, "application/msrtc-event-categories+xml"))) {
		char *doc = g_strdup_printf("Content-Type: %s\r\n\r\n%s", ctype, msg->body);
		PurpleMimeDocument *mime = purple_mime_document_parse(doc);
		GList *parts = purple_mime_document_get_parts(mime);
		GSList *buddies = NULL;
		struct presence_batched_routed *payload = g_malloc(sizeof(struct presence_batched_routed));

		while (parts) {
			xmlnode *xml = xmlnode_from_str(purple_mime_part_get_data(parts->data),
							purple_mime_part_get_length(parts->data));

			if (strcmp(xml->name, "list")) {
				gchar *uri = sip_uri(xmlnode_get_attrib(xml, "uri"));

				buddies = g_slist_append(buddies, uri);
			}
			xmlnode_free(xml);

			parts = parts->next;
		}
		g_free(doc);
		if (mime) purple_mime_document_free(mime);

		payload->host    = g_strdup(who);
		payload->buddies = buddies;
		sipe_schedule_action(action_name, timeout,
				     sipe_subscribe_presence_batched_routed,
				     sipe_subscribe_presence_batched_routed_free,
				     sip, payload);
		purple_debug_info("sipe", "Resubscription multiple contacts with batched support & route(%s) in %d\n", who, timeout);

	} else {
		sipe_schedule_action(action_name, timeout, sipe_subscribe_presence_single, g_free, sip, g_strdup(who));
		purple_debug_info("sipe", "Resubscription single contact with batched support(%s) in %d\n", who, timeout);
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
static void process_incoming_notify(struct sipe_account_data *sip, struct sipmsg *msg, gboolean request, gboolean benotify)
{
	gchar *content_type = sipmsg_find_header(msg, "Content-Type");
	gchar *event = sipmsg_find_header(msg, "Event");
	gchar *subscription_state = sipmsg_find_header(msg, "subscription-state");
	char *tmp;
	int timeout = 0;

	purple_debug_info("sipe", "process_incoming_notify: Event: %s\n\n%s\n",
				  event ? event : "",
				  tmp = fix_newlines(msg->body));
	g_free(tmp);
	purple_debug_info("sipe", "process_incoming_notify: subscription_state: %s\n", subscription_state ? subscription_state : "");

	/* implicit subscriptions */
	if (content_type && purple_str_has_prefix(content_type, "application/ms-imdn+xml")) {
		sipe_process_imdn(sip, msg);
	}

	if (!request)
	{
		const gchar *expires_header;
		expires_header = sipmsg_find_header(msg, "Expires");
		timeout = expires_header ? strtol(expires_header, NULL, 10) : 0;
		purple_debug_info("sipe", "process_incoming_notify: subscription expires:%d\n", timeout);
		timeout = (timeout - 120) > 120 ? (timeout - 120) : timeout; // 2 min ahead of expiration
	}

	/* for one off subscriptions (send with Expire: 0) */
	if (event && !g_ascii_strcasecmp(event, "vnd-microsoft-provisioning-v2"))
	{
		sipe_process_provisioning_v2(sip, msg);
	}
	else if (event && !g_ascii_strcasecmp(event, "vnd-microsoft-provisioning"))
	{
		sipe_process_provisioning(sip, msg);
	}

	if (!subscription_state || strstr(subscription_state, "active"))
	{
		if (event && !g_ascii_strcasecmp(event, "presence"))
		{
			sipe_process_presence(sip, msg);
		}
		else if (event && !g_ascii_strcasecmp(event, "vnd-microsoft-roaming-contacts"))
		{
			sipe_process_roaming_contacts(sip, msg);
		}
		else if (event && !g_ascii_strcasecmp(event, "vnd-microsoft-roaming-self"))
		{
			sipe_process_roaming_self(sip, msg);
		}
		else if (event && !g_ascii_strcasecmp(event, "vnd-microsoft-roaming-ACL"))
		{
			sipe_process_roaming_acl(sip, msg);
		}
		else if (event && !g_ascii_strcasecmp(event, "presence.wpending"))
		{
			sipe_process_presence_wpending(sip, msg);
		}
		else if (event && !g_ascii_strcasecmp(event, "conference"))
		{
			sipe_process_conference(sip, msg);
		}
	}

	/* The server sends status 'terminated' */
	if (subscription_state && strstr(subscription_state, "terminated") ) {
		gchar *who = parse_from(sipmsg_find_header(msg, request ? "From" : "To"));
		gchar *key = sipe_get_subscription_key(event, who);

		purple_debug_info("sipe", "process_incoming_notify: server says that subscription to %s was terminated.\n",  who);
		g_free(who);

		if (g_hash_table_lookup(sip->subscriptions, key)) {
			g_hash_table_remove(sip->subscriptions, key);
			purple_debug_info("sipe", "process_subscribe_response: subscription dialog removed for: %s\n", key);
		}

		g_free(key);
	}

	if (timeout && event) {// For LSC 2005 and OCS 2007
		/*if (!g_ascii_strcasecmp(event, "vnd-microsoft-roaming-contacts") &&
			 g_slist_find_custom(sip->allow_events, "vnd-microsoft-roaming-contacts", (GCompareFunc)g_ascii_strcasecmp))
		 {
			 gchar *action_name = g_strdup_printf("<%s>", "vnd-microsoft-roaming-contacts");
			 sipe_schedule_action(action_name, timeout, sipe_subscribe_roaming_contacts, NULL, sip, msg);
			 g_free(action_name);
		 }
		 else if (!g_ascii_strcasecmp(event, "vnd-microsoft-roaming-ACL") &&
				  g_slist_find_custom(sip->allow_events, "vnd-microsoft-roaming-ACL", (GCompareFunc)g_ascii_strcasecmp))
		 {
			 gchar *action_name = g_strdup_printf("<%s>", "vnd-microsoft-roaming-ACL");
			 sipe_schedule_action(action_name, timeout, sipe_subscribe_roaming_acl, NULL, sip, msg);
			 g_free(action_name);
		 }
		 else*/
		if (!g_ascii_strcasecmp(event, "presence.wpending") &&
		    g_slist_find_custom(sip->allow_events, "presence.wpending", (GCompareFunc)g_ascii_strcasecmp))
		{
			gchar *action_name = g_strdup_printf("<%s>", "presence.wpending");
			sipe_schedule_action(action_name, timeout, sipe_subscribe_presence_wpending, NULL, sip, NULL);
			g_free(action_name);
		}
		else if (!g_ascii_strcasecmp(event, "presence") &&
			 g_slist_find_custom(sip->allow_events, "presence", (GCompareFunc)g_ascii_strcasecmp))
		{
			gchar *who = parse_from(sipmsg_find_header(msg, request ? "From" : "To"));
			gchar *action_name = g_strdup_printf(ACTION_NAME_PRESENCE, who);
			if (sip->batched_support) {
				sipe_process_presence_timeout(sip, msg, who, timeout);
			}
			else {
				sipe_schedule_action(action_name, timeout, sipe_subscribe_presence_single, g_free, sip, g_strdup(who));
			 	purple_debug_info("sipe", "Resubscription single contact (%s) in %d\n", who, timeout);
			}
			g_free(action_name);
			g_free(who);
		}
	}

	if (event && !g_ascii_strcasecmp(event, "registration-notify"))
	{
		sipe_process_registration_notify(sip, msg);
	}

	/* The client responses on received a NOTIFY message */
	if (request && !benotify)
	{
		send_sip_response(sip->gc, msg, 200, "OK", NULL);
	}
}

/**
 * Whether user manually changed status or
 * it was changed automatically due to user
 * became inactive/active again
 */
static gboolean
sipe_is_user_state(struct sipe_account_data *sip)
{
	gboolean res;
	time_t now = time(NULL);

	purple_debug_info("sipe", "sipe_is_user_state: sip->idle_switch : %s", asctime(localtime(&(sip->idle_switch))));
	purple_debug_info("sipe", "sipe_is_user_state: now              : %s", asctime(localtime(&now)));
	
	res = ((now - SIPE_IDLE_SET_DELAY * 2) >= sip->idle_switch);
	
	purple_debug_info("sipe", "sipe_is_user_state: res  = %s\n", res ? "USER" : "MACHINE");
	return res;
}

static void
send_presence_soap0(struct sipe_account_data *sip,
		   gboolean do_publish_calendar,
		   gboolean do_reset_status)
{
	struct sipe_ews* ews = sip->ews;
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
	gchar *epid = get_epid(sip);
	time_t now = time(NULL);
	gchar *since_time_str = g_strdup(purple_utf8_strftime(SIPE_XML_DATE_PATTERN, gmtime(&now)));
	const gchar *oof_note = ews ? sipe_ews_get_oof_note(ews) : NULL;
	const char *user_input;
	gboolean pub_oof = ews && oof_note && (!sip->note || ews->updated > sip->note_since);
	
	if (oof_note && sip->note) {
		purple_debug_info("sipe", "ews->oof_start  : %s", asctime(localtime(&(ews->oof_start))));
		purple_debug_info("sipe", "sip->note_since : %s", asctime(localtime(&(sip->note_since))));
	}
	
	purple_debug_info("sipe", "sip->note  : %s", sip->note ? sip->note : "");

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
		ews->published = TRUE;
	} else if (sip->note) {
		if (sip->is_oof_note) { /* stale OOF note, as it's not present in ews already (oof_note == NULL) */
			g_free(sip->note);
			sip->note = NULL;
			sip->is_oof_note = FALSE;
			sip->note_since = 0;
		} else {
			note_pub = sip->note;
		}
	}

	if (note_pub)
	{
		/* to protocol internal plain text format */
		tmp = purple_markup_strip_html(note_pub);
		res_note = g_markup_printf_escaped(SIPE_SOAP_SET_PRESENCE_NOTE_XML, tmp);
		g_free(tmp);
	}

	/* User State */
	if (!do_reset_status) {
		if (sipe_is_user_state(sip) && !do_publish_calendar && sip->initial_state_published)
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
			xmlnode *xn_states;
			if (sip->user_info && (xn_states = xmlnode_get_child(sip->user_info, "states"))) {
				states = xmlnode_to_str(xn_states, NULL);
				/* this is a hack-around to remove added newline after inner element,
				 * state in this case, where it shouldn't be.
				 * After several use of xmlnode_to_str, amount of added newlines
				 * grows significantly.
				 */
				purple_str_strip_char(states, '\n');
				//purple_str_strip_char(states, '\r');
			}
		}
	} else {
		/* do nothing - then User state will be erased */
	}
	sip->initial_state_published = TRUE;

	/* CalendarInfo */
	if (ews && (!is_empty(ews->legacy_dn) || !is_empty(ews->email)) && ews->fb_start && !is_empty(ews->free_busy))
	{
		char *fb_start_str = g_strdup(purple_utf8_strftime(SIPE_XML_DATE_PATTERN, gmtime(&ews->fb_start)));
		char *free_busy_base64 = sipe_cal_get_freebusy_base64(ews->free_busy);
		calendar_data = g_strdup_printf(SIPE_SOAP_SET_PRESENCE_CALENDAR,
						!is_empty(ews->legacy_dn) ? ews->legacy_dn : ews->email,
						fb_start_str,
						free_busy_base64);
		g_free(fb_start_str);
		g_free(free_busy_base64);
	}

	user_input = !sipe_is_user_state(sip) && sip->status != SIPE_STATUS_ID_AVAILABLE ? "idle" : "active";

	/* forming resulting XML */
	body = g_strdup_printf(SIPE_SOAP_SET_PRESENCE,
			       sip->username,
			       availability,
			       activity,
			       (tmp = g_ascii_strup(sipe_get_host_name(), -1)),
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

	send_soap_request(sip, body);

	g_free(body);
	g_free(since_time_str);
	g_free(epid);
}

void
send_presence_soap(struct sipe_account_data *sip,
		   gboolean do_publish_calendar)
{
	return send_presence_soap0(sip, do_publish_calendar, FALSE);
}


static gboolean
process_send_presence_category_publish_response(struct sipe_account_data *sip,
						struct sipmsg *msg,
						struct transaction *trans)
{
	gchar *contenttype = sipmsg_find_header(msg, "Content-Type");

	if (msg->response == 409 && g_str_has_prefix(contenttype, "application/msrtc-fault+xml")) {
		xmlnode *xml;
		xmlnode *node;
		gchar *fault_code;
		GHashTable *faults;
		int index_our;
		gboolean has_device_publication = FALSE;

		xml = xmlnode_from_str(msg->body, msg->bodylen);

		/* test if version mismatch fault */
		fault_code = xmlnode_get_data(xmlnode_get_child(xml, "Faultcode"));
		if (strcmp(fault_code, "Client.BadCall.WrongDelta")) {
			purple_debug_info("sipe", "process_send_presence_category_publish_response: unsupported fault code:%s returning.\n", fault_code);
			g_free(fault_code);
			xmlnode_free(xml);
			return TRUE;
		}
		g_free(fault_code);

		/* accumulating information about faulty versions */
		faults = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
		for (node = xmlnode_get_descendant(xml, "details", "operation", NULL);
		     node;
		     node = xmlnode_get_next_twin(node))
		{
			const gchar *index = xmlnode_get_attrib(node, "index");
			const gchar *curVersion = xmlnode_get_attrib(node, "curVersion");

			g_hash_table_insert(faults, g_strdup(index), g_strdup(curVersion));
			purple_debug_info("sipe", "fault added: index:%s curVersion:%s\n", index, curVersion);
		}
		xmlnode_free(xml);

		/* here we are parsing own request to figure out what publication
		 * referensed here only by index went wrong
		 */
		xml = xmlnode_from_str(trans->msg->body, trans->msg->bodylen);

		/* publication */
		for (node = xmlnode_get_descendant(xml, "publications", "publication", NULL),
		     index_our = 1; /* starts with 1 - our first publication */
		     node;
		     node = xmlnode_get_next_twin(node), index_our++)
		{
			gchar *idx = g_strdup_printf("%d", index_our);
			const gchar *curVersion = g_hash_table_lookup(faults, idx);
			const gchar *categoryName = xmlnode_get_attrib(node, "categoryName");
			g_free(idx);

			if (!strcmp("device", categoryName)) {
				has_device_publication = TRUE;
			}

			if (curVersion) { /* fault exist on this index */
				const gchar *container = xmlnode_get_attrib(node, "container");
				const gchar *instance = xmlnode_get_attrib(node, "instance");
				/* key is <category><instance><container> */
				gchar *key = g_strdup_printf("<%s><%s><%s>", categoryName, instance, container);
				struct sipe_publication *publication =
					g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, categoryName), key);

				purple_debug_info("sipe", "key is %s\n", key);

				if (publication) {
					purple_debug_info("sipe", "Updating %s with version %s. Was %d before.\n",
								  key, curVersion, publication->version);
					/* updating publication's version to the correct one */
					publication->version = atoi(curVersion);
				}
				g_free(key);
			}
		}
		xmlnode_free(xml);
		g_hash_table_destroy(faults);

		/* rebublishing with right versions */
		if (has_device_publication) {
			send_publish_category_initial(sip);
		} else {
			send_presence_status(sip);
		}
	}
	return TRUE;
}

/**
 * Returns 'device' XML part for publication.
 * Must be g_free'd after use.
 */
static gchar *
sipe_publish_get_category_device(struct sipe_account_data *sip)
{
	gchar *uri;
	gchar *doc;
	gchar *epid = get_epid(sip);
	gchar *uuid = generateUUIDfromEPID(epid);
	guint device_instance = sipe_get_pub_instance(sip, SIPE_PUB_DEVICE);
	/* key is <category><instance><container> */
	gchar *key = g_strdup_printf("<%s><%u><%u>", "device", device_instance, 2);
	struct sipe_publication *publication =
		g_hash_table_lookup(g_hash_table_lookup(sip->our_publications, "device"), key);

	g_free(key);
	g_free(epid);

	uri = sip_uri_self(sip);
	doc = g_strdup_printf(SIPE_PUB_XML_DEVICE,
		device_instance,
		publication ? publication->version : 0,
		uuid,
		uri,
		"00:00:00+01:00", /* @TODO make timezone real*/
		sipe_get_host_name()
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
sipe_publish_get_category_state(struct sipe_account_data *sip,
				gboolean is_user_state)
{
	int availability = sipe_get_availability_by_status(sip->status, NULL);
	guint instance = is_user_state ? sipe_get_pub_instance(sip, SIPE_PUB_STATE_USER) :
					 sipe_get_pub_instance(sip, SIPE_PUB_STATE_MACHINE);
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
		purple_debug_info("sipe", "sipe_publish_get_category_state: state has NOT changed. Exiting.\n");
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
sipe_publish_get_category_state_calendar(struct sipe_account_data *sip,
					 struct sipe_cal_event *event,
					 const char *uri,
					 int cal_satus)
{
	gchar *start_time_str;
	int availability = 0;
	gchar *res;
	guint instance = (cal_satus == SIPE_CAL_OOF) ?
		sipe_get_pub_instance(sip, SIPE_PUB_STATE_CALENDAR_OOF) :
		sipe_get_pub_instance(sip, SIPE_PUB_STATE_CALENDAR);

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
		purple_debug_info("sipe", "sipe_publish_get_category_state_calendar: "
			"Exiting as no publication and no event for cal_satus:%d\n", cal_satus);
		return NULL;
	}

	if (event &&
	    publication_3 &&
	    (publication_3->availability == availability) &&
	    !strcmp(publication_3->cal_event_hash, sipe_cal_event_hash(event)))
	{
		purple_debug_info("sipe", "sipe_publish_get_category_state_calendar: "
			"cal state has NOT changed for cal_satus:%d. Exiting.\n", cal_satus);
		return NULL; /* nothing to update */
	}

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
		start_time_str = g_strdup(purple_utf8_strftime(SIPE_XML_DATE_PATTERN, gmtime(&event->start_time)));

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
sipe_publish_get_category_state_machine(struct sipe_account_data *sip)
{
	return sipe_publish_get_category_state(sip, FALSE);
}

/**
 * Returns 'userState' XML part for publication.
 * Must be g_free'd after use.
 */
static gchar *
sipe_publish_get_category_state_user(struct sipe_account_data *sip)
{
	return sipe_publish_get_category_state(sip, TRUE);
}

/**
 * Compares two strings even in case both are NULL/empty
 */
static gboolean
sipe_is_equal(const char* n1, const char* n2) {
	return ((!n1 || !strlen(n1)) && (!n2 || !strlen(n2))) /* both empty */
	    || (n1 && n2 && !strcmp(n1, n2)); /* or not empty and equal */
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
sipe_publish_get_category_note(struct sipe_account_data *sip,
			       const char *note, /* html */
			       const char *note_type,
			       time_t note_start,
			       time_t note_end)
{
	guint instance = !strcmp("OOF", note_type) ? sipe_get_pub_instance(sip, SIPE_PUB_NOTE_OOF) : 0;
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

	char *tmp = note ? purple_markup_strip_html(note) : NULL;
	char *n1 = tmp ? g_markup_escape_text(tmp, -1) : NULL;
	const char *n2 = publication_note_200 ? publication_note_200->note : NULL;
	char *res, *tmp1, *tmp2, *tmp3;
	char *start_time_attr;
	char *end_time_attr;

	g_free(tmp);
	g_free(key_note_200);
	g_free(key_note_300);
	g_free(key_note_400);

	/* we even need to republish empty note */
	if (n1 && n2 && !strcmp(n1, n2))
	{
		purple_debug_info("sipe", "sipe_publish_get_category_note: note has NOT changed. Exiting.\n");
		return NULL; /* nothing to update */
	}

	start_time_attr = note_start ? g_strdup_printf(" startTime=\"%s\"",
		purple_utf8_strftime(SIPE_XML_DATE_PATTERN, gmtime(&note_start))) : NULL;
	end_time_attr = note_end ? g_strdup_printf(" endTime=\"%s\"",
		purple_utf8_strftime(SIPE_XML_DATE_PATTERN, gmtime(&note_end))) : NULL;

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
sipe_publish_get_category_cal_working_hours(struct sipe_account_data *sip)
{
	struct sipe_ews* ews = sip->ews;

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

	const char *n1 = ews ? ews->working_hours_xml_str : NULL;
	const char *n2 = publication_cal_300 ? publication_cal_300->working_hours_xml_str : NULL;

	g_free(key_cal_1);
	g_free(key_cal_100);
	g_free(key_cal_200);
	g_free(key_cal_300);
	g_free(key_cal_400);
	g_free(key_cal_32000);

	if (!ews || is_empty(ews->email) || is_empty(ews->working_hours_xml_str)) {
		purple_debug_info("sipe", "sipe_publish_get_category_cal_working_hours: no data to publish, exiting\n");
		return NULL;
	}

	if (sipe_is_equal(n1, n2))
	{
		purple_debug_info("sipe", "sipe_publish_get_category_cal_working_hours: WorkingHours has NOT changed. Exiting.\n");
		return NULL; /* nothing to update */
	}

	return g_strdup_printf(SIPE_PUB_XML_WORKING_HOURS,
				/* 1 */
				publication_cal_1 ? publication_cal_1->version : 0,
				ews->email,
				ews->working_hours_xml_str,
				/* 100 - Public */
				publication_cal_100 ? publication_cal_100->version : 0,
				/* 200 - Company */
				publication_cal_200 ? publication_cal_200->version : 0,
				ews->email,
				ews->working_hours_xml_str,
				/* 300 - Team */
				publication_cal_300 ? publication_cal_300->version : 0,
				ews->email,
				ews->working_hours_xml_str,
				/* 400 - Personal */
				publication_cal_400 ? publication_cal_400->version : 0,
				ews->email,
				ews->working_hours_xml_str,
				/* 32000 - Blocked */
				publication_cal_32000 ? publication_cal_32000->version : 0
			      );
}

/**
 * Returns 'calendarData' XML part with FreeBusy for publication.
 * Must be g_free'd after use.
 */
static gchar *
sipe_publish_get_category_cal_free_busy(struct sipe_account_data *sip)
{
	struct sipe_ews* ews = sip->ews;
	guint cal_data_instance = sipe_get_pub_instance(sip, SIPE_PUB_CALENDAR_DATA);
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

	if (!ews || is_empty(ews->email) || !ews->fb_start || is_empty(ews->free_busy)) {
		purple_debug_info("sipe", "sipe_publish_get_category_cal_free_busy: no data to publish, exiting\n");
		return NULL;
	}

	fb_start_str = g_strdup(purple_utf8_strftime(SIPE_XML_DATE_PATTERN, gmtime(&ews->fb_start)));
	free_busy_base64 = sipe_cal_get_freebusy_base64(ews->free_busy);

	st = publication_cal_300 ? publication_cal_300->fb_start_str : NULL;
	fb = publication_cal_300 ? publication_cal_300->free_busy_base64 : NULL;

	/* we will rebuplish the same data to refresh publication time,
	 * so if data from multiple sources, most recent will be choosen
	 */
	//if (sipe_is_equal(st, fb_start_str) && sipe_is_equal(fb, free_busy_base64))
	//{
	//	purple_debug_info("sipe", "sipe_publish_get_category_cal_free_busy: FreeBusy has NOT changed. Exiting.\n");
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
				ews->email,
				fb_start_str,
				free_busy_base64,
				/* 300 - Team */
				cal_data_instance,
				publication_cal_300 ? publication_cal_300->version : 0,
				ews->email,
				fb_start_str,
				free_busy_base64,
				/* 400 - Personal */
				cal_data_instance,
				publication_cal_400 ? publication_cal_400->version : 0,
				ews->email,
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

static void send_presence_publish(struct sipe_account_data *sip, const char *publications)
{
	gchar *uri;
	gchar *doc;
	gchar *tmp;
	gchar *hdr;

	uri = sip_uri_self(sip);
	doc = g_strdup_printf(SIPE_SEND_PRESENCE,
		uri,
		publications);

	tmp = get_contact(sip);
	hdr = g_strdup_printf("Contact: %s\r\n"
		"Content-Type: application/msrtc-category-publish+xml\r\n", tmp);

	send_sip_request(sip->gc, "SERVICE", uri, uri, hdr, doc, NULL, process_send_presence_category_publish_response);

	g_free(tmp);
	g_free(hdr);
	g_free(uri);
	g_free(doc);
}

static void
send_publish_category_initial(struct sipe_account_data *sip)
{
	gchar *pub_device   = sipe_publish_get_category_device(sip);
	gchar *pub_machine;
	gchar *publications;

	g_free(sip->status);
	sip->status = g_strdup(SIPE_STATUS_ID_AVAILABLE); /* our initial state */

	pub_machine  = sipe_publish_get_category_state_machine(sip);
	publications = g_strdup_printf("%s%s",
					      pub_device,
					      pub_machine ? pub_machine : "");
	g_free(pub_device);
	g_free(pub_machine);

	send_presence_publish(sip, publications);
	g_free(publications);
}

static void
send_presence_category_publish(struct sipe_account_data *sip)
{
	gchar *pub_state = sipe_is_user_state(sip) ?
				sipe_publish_get_category_state_user(sip) :
				sipe_publish_get_category_state_machine(sip);
	gchar *pub_note = sipe_publish_get_category_note(sip,
							 sip->note,
							 sip->is_oof_note ? "OOF" : "personal",
							 0,
							 0);
	gchar *publications;

	if (!pub_state && !pub_note) {
		purple_debug_info("sipe", "send_presence_category_publish: nothing has changed. Exiting.\n");
		return;
	}

	publications = g_strdup_printf("%s%s",
				       pub_state ? pub_state : "",
				       pub_note ? pub_note : "");

	g_free(pub_state);
	g_free(pub_note);

	send_presence_publish(sip, publications);
	g_free(publications);
}

/**
 * Publishes self status
 * based on own calendar information.
 *
 * For 2007+
 */
void
publish_calendar_status_self(struct sipe_account_data *sip)
{
	struct sipe_cal_event* event = NULL;
	gchar *pub_cal_working_hours = NULL;
	gchar *pub_cal_free_busy = NULL;
	gchar *pub_calendar = NULL;
	gchar *pub_calendar2 = NULL;
	gchar *pub_oof_note = NULL;
	const gchar *oof_note;
	time_t oof_start = 0;
	time_t oof_end = 0;

	if (!sip->ews) {
		purple_debug_info("sipe", "publish_calendar_status_self() no calendar data.\n");
		return;
	}

	purple_debug_info("sipe", "publish_calendar_status_self() started.\n");
	if (sip->ews->cal_events) {
		event = sipe_cal_get_event(sip->ews->cal_events, time(NULL));
	}

	if (!event) {
		purple_debug_info("sipe", "publish_calendar_status_self: current event is NULL\n");
	} else {
		char *desc = sipe_cal_event_describe(event);
		purple_debug_info("sipe", "publish_calendar_status_self: current event is:\n%s", desc ? desc : "");
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
		pub_calendar  = sipe_publish_get_category_state_calendar(sip, event, sip->ews->email, SIPE_CAL_OOF);
		pub_calendar2 = sipe_publish_get_category_state_calendar(sip, NULL,  sip->ews->email, SIPE_CAL_BUSY);
	} else if (event && event->cal_status == SIPE_CAL_BUSY) {
		pub_calendar  = sipe_publish_get_category_state_calendar(sip, NULL,  sip->ews->email, SIPE_CAL_OOF);
		pub_calendar2 = sipe_publish_get_category_state_calendar(sip, event, sip->ews->email, SIPE_CAL_BUSY);
	} else {
		pub_calendar  = sipe_publish_get_category_state_calendar(sip, NULL,  sip->ews->email, SIPE_CAL_OOF);
		pub_calendar2 = sipe_publish_get_category_state_calendar(sip, NULL,  sip->ews->email, SIPE_CAL_BUSY);
	}

	oof_note = sipe_ews_get_oof_note(sip->ews);
	if (!strcmp("Scheduled", sip->ews->oof_state)) {
		oof_start = sip->ews->oof_start;
		oof_end = sip->ews->oof_end;
	}
	pub_oof_note = sipe_publish_get_category_note(sip, oof_note, "OOF", oof_start, oof_end);

	pub_cal_working_hours = sipe_publish_get_category_cal_working_hours(sip);
	pub_cal_free_busy = sipe_publish_get_category_cal_free_busy(sip);

	if (!pub_cal_working_hours && !pub_cal_free_busy && !pub_calendar && !pub_calendar2 && !pub_oof_note) {
		purple_debug_info("sipe", "publish_calendar_status_self: nothing has changed.\n");
	} else {
		gchar *publications = g_strdup_printf("%s%s%s%s%s",
				       pub_cal_working_hours ? pub_cal_working_hours : "",
				       pub_cal_free_busy ? pub_cal_free_busy : "",
				       pub_calendar ? pub_calendar : "",
				       pub_calendar2 ? pub_calendar2 : "",
				       pub_oof_note ? pub_oof_note : "");

		send_presence_publish(sip, publications);
		g_free(publications);
	}

	g_free(pub_cal_working_hours);
	g_free(pub_cal_free_busy);
	g_free(pub_calendar);
	g_free(pub_calendar2);
	g_free(pub_oof_note);

	/* repeat scheduling */
	sipe_sched_calendar_status_self_publish(sip, time(NULL));
}

static void send_presence_status(struct sipe_account_data *sip)
{
	PurpleStatus * status = purple_account_get_active_status(sip->account);

	if (!status) return;

	purple_debug_info("sipe", "send_presence_status: status: %s (%s)\n",
		purple_status_get_id(status) ? purple_status_get_id(status) : "",
		sipe_is_user_state(sip) ? "USER" : "MACHINE");

        if (sip->ocs2007) {
		send_presence_category_publish(sip);
	} else {
		send_presence_soap(sip, FALSE);
	}
}

static void process_input_message(struct sipe_account_data *sip,struct sipmsg *msg)
{
	gboolean found = FALSE;
	purple_debug_info("sipe", "msg->response(%d),msg->method(%s)\n",msg->response,msg->method);
	if (msg->response == 0) { /* request */
		if (!strcmp(msg->method, "MESSAGE")) {
			process_incoming_message(sip, msg);
			found = TRUE;
		} else if (!strcmp(msg->method, "NOTIFY")) {
			purple_debug_info("sipe","send->process_incoming_notify\n");
			process_incoming_notify(sip, msg, TRUE, FALSE);
			found = TRUE;
		} else if (!strcmp(msg->method, "BENOTIFY")) {
			purple_debug_info("sipe","send->process_incoming_benotify\n");
			process_incoming_notify(sip, msg, TRUE, TRUE);
			found = TRUE;
		} else if (!strcmp(msg->method, "INVITE")) {
			process_incoming_invite(sip, msg);
			found = TRUE;
		} else if (!strcmp(msg->method, "REFER")) {
			process_incoming_refer(sip, msg);
			found = TRUE;
		} else if (!strcmp(msg->method, "OPTIONS")) {
			process_incoming_options(sip, msg);
			found = TRUE;
		} else if (!strcmp(msg->method, "INFO")) {
			process_incoming_info(sip, msg);
			found = TRUE;
		} else if (!strcmp(msg->method, "ACK")) {
			// ACK's don't need any response
			found = TRUE;
		} else if (!strcmp(msg->method, "SUBSCRIBE")) {
			// LCS 2005 sends us these - just respond 200 OK
			found = TRUE;
			send_sip_response(sip->gc, msg, 200, "OK", NULL);
		} else if (!strcmp(msg->method, "BYE")) {
			process_incoming_bye(sip, msg);
			found = TRUE;
		} else {
			send_sip_response(sip->gc, msg, 501, "Not implemented", NULL);
		}
	} else { /* response */
		struct transaction *trans = transactions_find(sip, msg);
		if (trans) {
			if (msg->response == 407) {
				gchar *resend, *auth, *ptmp;

				if (sip->proxy.retries > 30) return;
				sip->proxy.retries++;
				/* do proxy authentication */

				ptmp = sipmsg_find_header(msg, "Proxy-Authenticate");

				fill_auth(ptmp, &sip->proxy);
				auth = auth_header(sip, &sip->proxy, trans->msg);
				sipmsg_remove_header_now(trans->msg, "Proxy-Authorization");
				sipmsg_add_header_now_pos(trans->msg, "Proxy-Authorization", auth, 5);
				g_free(auth);
				resend = sipmsg_to_string(trans->msg);
				/* resend request */
				sendout_pkt(sip->gc, resend);
				g_free(resend);
			} else {
				if (msg->response < 200) {
					/* ignore provisional response */
					purple_debug_info("sipe", "got provisional (%d) response, ignoring\n", msg->response);
				} else {
					sip->proxy.retries = 0;
					if (!strcmp(trans->msg->method, "REGISTER")) {
						if (msg->response == 401)
						{
							sip->registrar.retries++;
						}
						else
						{
							sip->registrar.retries = 0;
						}
                                                purple_debug_info("sipe", "RE-REGISTER CSeq: %d\n", sip->cseq);
					} else {
						if (msg->response == 401) {
							gchar *resend, *auth, *ptmp;

							if (sip->registrar.retries > 4) return;
							sip->registrar.retries++;

#ifdef USE_KERBEROS
							if (!purple_account_get_bool(sip->account, "krb5", FALSE)) {
#endif
								ptmp = sipmsg_find_auth_header(msg, "NTLM");
#ifdef USE_KERBEROS
							} else {
								ptmp = sipmsg_find_auth_header(msg, "Kerberos");
							}
#endif

							purple_debug(PURPLE_DEBUG_MISC, "sipe", "process_input_message - Auth header: %s\n", ptmp);

							fill_auth(ptmp, &sip->registrar);
							auth = auth_header(sip, &sip->registrar, trans->msg);
							sipmsg_remove_header_now(trans->msg, "Proxy-Authorization");
							sipmsg_add_header_now_pos(trans->msg, "Proxy-Authorization", auth, 5);

							//sipmsg_remove_header_now(trans->msg, "Authorization");
							//sipmsg_add_header(trans->msg, "Authorization", auth);
							g_free(auth);
							resend = sipmsg_to_string(trans->msg);
							/* resend request */
							sendout_pkt(sip->gc, resend);
							g_free(resend);
						}
					}

					if (trans->callback) {
						purple_debug(PURPLE_DEBUG_MISC, "sipe", "process_input_message - we have a transaction callback\n");
						/* call the callback to process response*/
						(trans->callback)(sip, msg, trans);
					}

					purple_debug(PURPLE_DEBUG_MISC, "sipe", "process_input_message - removing CSeq %d\n", sip->cseq);
					transactions_remove(sip, trans);

				}
			}
			found = TRUE;
		} else {
			purple_debug(PURPLE_DEBUG_MISC, "sipe", "received response to unknown transaction\n");
		}
	}
	if (!found) {
		purple_debug(PURPLE_DEBUG_MISC, "sipe", "received a unknown sip message with method %s and response %d\n", msg->method, msg->response);
	}
}

static void process_input(struct sipe_account_data *sip, struct sip_connection *conn)
{
	char *cur;
	char *dummy;
	char *tmp;
	struct sipmsg *msg;
	int restlen;
	cur = conn->inbuf;

	/* according to the RFC remove CRLF at the beginning */
	while (*cur == '\r' || *cur == '\n') {
		cur++;
	}
	if (cur != conn->inbuf) {
		memmove(conn->inbuf, cur, conn->inbufused - (cur - conn->inbuf));
		conn->inbufused = strlen(conn->inbuf);
	}

	/* Received a full Header? */
	sip->processing_input = TRUE;
	while (sip->processing_input &&
	       ((cur = strstr(conn->inbuf, "\r\n\r\n")) != NULL)) {
		time_t currtime = time(NULL);
		cur += 2;
		cur[0] = '\0';
		purple_debug_info("sipe", "received - %s######\n%s\n#######\n", ctime(&currtime), tmp = fix_newlines(conn->inbuf));
		g_free(tmp);
		msg = sipmsg_parse_header(conn->inbuf);
		cur[0] = '\r';
		cur += 2;
		restlen = conn->inbufused - (cur - conn->inbuf);
		if (msg && restlen >= msg->bodylen) {
			dummy = g_malloc(msg->bodylen + 1);
			memcpy(dummy, cur, msg->bodylen);
			dummy[msg->bodylen] = '\0';
			msg->body = dummy;
			cur += msg->bodylen;
			memmove(conn->inbuf, cur, conn->inbuflen - (cur - conn->inbuf));
			conn->inbufused = strlen(conn->inbuf);
		} else {
			if (msg){
                           purple_debug_info("sipe", "process_input: body too short (%d < %d, strlen %d) - ignoring message\n", restlen, msg->bodylen, (int)strlen(conn->inbuf));
			sipmsg_free(msg);
                        }
			return;
		}

		/*if (msg->body) {
			purple_debug_info("sipe", "body:\n%s", msg->body);
		}*/

		// Verify the signature before processing it
		if (sip->registrar.gssapi_context) {
			struct sipmsg_breakdown msgbd;
			gchar *signature_input_str;
			gchar *rspauth;
			msgbd.msg = msg;
			sipmsg_breakdown_parse(&msgbd, sip->registrar.realm, sip->registrar.target);
			signature_input_str = sipmsg_breakdown_get_string(&msgbd);

			rspauth = sipmsg_find_part_of_header(sipmsg_find_header(msg, "Authentication-Info"), "rspauth=\"", "\"", NULL);

			if (rspauth != NULL) {
				if (!sip_sec_verify_signature(sip->registrar.gssapi_context, signature_input_str, rspauth)) {
					purple_debug(PURPLE_DEBUG_MISC, "sipe", "incoming message's signature validated\n");
					process_input_message(sip, msg);
				} else {
					purple_debug(PURPLE_DEBUG_MISC, "sipe", "incoming message's signature is invalid.\n");
					purple_connection_error(sip->gc, _("Invalid message signature received"));
					sip->gc->wants_to_die = TRUE;
				}
			} else if (msg->response == 401) {
				purple_connection_error(sip->gc, _("Wrong password"));
				sip->gc->wants_to_die = TRUE;
			}
			g_free(signature_input_str);

			g_free(rspauth);
			sipmsg_breakdown_free(&msgbd);
		} else {
			process_input_message(sip, msg);
		}

		sipmsg_free(msg);
	}
}

static void sipe_udp_process(gpointer data, gint source,
			     SIPE_UNUSED_PARAMETER PurpleInputCondition con)
{
	PurpleConnection *gc = data;
	struct sipe_account_data *sip = gc->proto_data;
	int len;

	static char buffer[65536];
	if ((len = recv(source, buffer, sizeof(buffer) - 1, 0)) > 0) {
		time_t currtime = time(NULL);
		struct sipmsg *msg;
		buffer[len] = '\0';
		purple_debug_info("sipe", "received - %s######\n%s\n#######\n", ctime(&currtime), buffer);
		msg = sipmsg_parse_msg(buffer);
		if (msg) process_input_message(sip, msg);
	}
}

static void sipe_invalidate_ssl_connection(PurpleConnection *gc, const char *msg, const char *debug)
{
	struct sipe_account_data *sip = gc->proto_data;
	PurpleSslConnection *gsc = sip->gsc;

	purple_debug_error("sipe", "%s",debug);
	purple_connection_error(gc, msg);

	/* Invalidate this connection. Next send will open a new one */
	if (gsc) {
		connection_remove(sip, gsc->fd);
		purple_ssl_close(gsc);
	}
	sip->gsc = NULL;
	sip->fd = -1;
}

static void sipe_input_cb_ssl(gpointer data, PurpleSslConnection *gsc,
			      SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	PurpleConnection *gc = data;
	struct sipe_account_data *sip;
	struct sip_connection *conn;
	int readlen, len;
	gboolean firstread = TRUE;

	/* NOTE: This check *IS* necessary */
	if (!PURPLE_CONNECTION_IS_VALID(gc)) {
		purple_ssl_close(gsc);
		return;
	}

	sip = gc->proto_data;
	conn = connection_find(sip, gsc->fd);
	if (conn == NULL) {
		purple_debug_error("sipe", "Connection not found; Please try to connect again.\n");
		gc->wants_to_die = TRUE;
		purple_connection_error(gc, _("Connection not found. Please try to connect again"));
		return;
	}

	/* Read all available data from the SSL connection */
	do {
		/* Increase input buffer size as needed */
		if (conn->inbuflen < conn->inbufused + SIMPLE_BUF_INC) {
			conn->inbuflen += SIMPLE_BUF_INC;
			conn->inbuf = g_realloc(conn->inbuf, conn->inbuflen);
			purple_debug_info("sipe", "sipe_input_cb_ssl: new input buffer length %d\n", conn->inbuflen);
		}

		/* Try to read as much as there is space left in the buffer */
		readlen = conn->inbuflen - conn->inbufused - 1;
		len = purple_ssl_read(gsc, conn->inbuf + conn->inbufused, readlen);

		if (len < 0 && errno == EAGAIN) {
			/* Try again later */
			return;
		} else if (len < 0) {
			sipe_invalidate_ssl_connection(gc, _("SSL read error"), "SSL read error\n");
			return;
		} else if (firstread && (len == 0)) {
			sipe_invalidate_ssl_connection(gc, _("Server has disconnected"), "Server has disconnected\n");
			return;
		}

		conn->inbufused += len;
		firstread = FALSE;

	/* Equivalence indicates that there is possibly more data to read */
	} while (len == readlen);

	conn->inbuf[conn->inbufused] = '\0';
        process_input(sip, conn);

}

static void sipe_input_cb(gpointer data, gint source,
			  SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	PurpleConnection *gc = data;
	struct sipe_account_data *sip = gc->proto_data;
	int len;
	struct sip_connection *conn = connection_find(sip, source);
	if (!conn) {
		purple_debug_error("sipe", "Connection not found!\n");
		return;
	}

	if (conn->inbuflen < conn->inbufused + SIMPLE_BUF_INC) {
		conn->inbuflen += SIMPLE_BUF_INC;
		conn->inbuf = g_realloc(conn->inbuf, conn->inbuflen);
	}

	len = read(source, conn->inbuf + conn->inbufused, SIMPLE_BUF_INC - 1);

	if (len < 0 && errno == EAGAIN)
		return;
	else if (len <= 0) {
		purple_debug_info("sipe", "sipe_input_cb: read error\n");
		connection_remove(sip, source);
		if (sip->fd == source) sip->fd = -1;
		return;
	}

	conn->inbufused += len;
	conn->inbuf[conn->inbufused] = '\0';

	process_input(sip, conn);
}

/* Callback for new connections on incoming TCP port */
static void sipe_newconn_cb(gpointer data, gint source,
			    SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	PurpleConnection *gc = data;
	struct sipe_account_data *sip = gc->proto_data;
	struct sip_connection *conn;

	int newfd = accept(source, NULL, NULL);

	conn = connection_create(sip, newfd);

	conn->inputhandler = purple_input_add(newfd, PURPLE_INPUT_READ, sipe_input_cb, gc);
}

static void login_cb(gpointer data, gint source,
		     SIPE_UNUSED_PARAMETER const gchar *error_message)
{
	PurpleConnection *gc = data;
	struct sipe_account_data *sip;
	struct sip_connection *conn;

	if (!PURPLE_CONNECTION_IS_VALID(gc))
	{
		if (source >= 0)
			close(source);
		return;
	}

	if (source < 0) {
		purple_connection_error(gc, _("Could not connect"));
		return;
	}

	sip = gc->proto_data;
	sip->fd = source;
	sip->last_keepalive = time(NULL);

	conn = connection_create(sip, source);

	do_register(sip);

	conn->inputhandler = purple_input_add(sip->fd, PURPLE_INPUT_READ, sipe_input_cb, gc);
}

static void login_cb_ssl(gpointer data, PurpleSslConnection *gsc,
			 SIPE_UNUSED_PARAMETER PurpleInputCondition cond)
{
	struct sipe_account_data *sip = sipe_setup_ssl(data, gsc);
	if (sip == NULL) return;

	do_register(sip);
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
	return (purple_utf8_strcasecmp(nick1, nick2) == 0);
}

static void sipe_udp_host_resolved_listen_cb(int listenfd, gpointer data)
{
	struct sipe_account_data *sip = (struct sipe_account_data*) data;

	sip->listen_data = NULL;

	if (listenfd == -1) {
		purple_connection_error(sip->gc, _("Could not create listen socket"));
		return;
	}

	sip->fd = listenfd;

	sip->listenport = purple_network_get_port_from_fd(sip->fd);
	sip->listenfd = sip->fd;

	sip->listenpa = purple_input_add(sip->fd, PURPLE_INPUT_READ, sipe_udp_process, sip->gc);

	sip->resendtimeout = purple_timeout_add(2500, (GSourceFunc) resend_timeout, sip);
	do_register(sip);
}

static void sipe_udp_host_resolved(GSList *hosts, gpointer data,
				   SIPE_UNUSED_PARAMETER const char *error_message)
{
	struct sipe_account_data *sip = (struct sipe_account_data*) data;

	sip->query_data = NULL;

	if (!hosts || !hosts->data) {
		purple_connection_error(sip->gc, _("Could not resolve hostname"));
		return;
	}

	hosts = g_slist_remove(hosts, hosts->data);
	g_free(sip->serveraddr);
	sip->serveraddr = hosts->data;
	hosts = g_slist_remove(hosts, hosts->data);
	while (hosts) {
		hosts = g_slist_remove(hosts, hosts->data);
		g_free(hosts->data);
		hosts = g_slist_remove(hosts, hosts->data);
	}

	/* create socket for incoming connections */
	sip->listen_data = purple_network_listen_range(5060, 5160, SOCK_DGRAM,
				sipe_udp_host_resolved_listen_cb, sip);
	if (sip->listen_data == NULL) {
		purple_connection_error(sip->gc, _("Could not create listen socket"));
		return;
	}
}

static const struct sipe_service_data *current_service = NULL;

static void sipe_ssl_connect_failure(SIPE_UNUSED_PARAMETER PurpleSslConnection *gsc,
				     PurpleSslErrorType error,
                                     gpointer data)
{
        PurpleConnection *gc = data;
        struct sipe_account_data *sip;

        /* If the connection is already disconnected, we don't need to do anything else */
        if (!PURPLE_CONNECTION_IS_VALID(gc))
                return;

        sip = gc->proto_data;
        current_service = sip->service_data;
	if (current_service) {
		purple_debug_info("sipe", "current_service: transport '%s' service '%s'\n",
				  current_service->transport ? current_service->transport : "NULL",
				  current_service->service   ? current_service->service   : "NULL");
	}

	sip->fd = -1;
        sip->gsc = NULL;

        switch(error) {
			case PURPLE_SSL_CONNECT_FAILED:
				purple_connection_error(gc, _("Connection failed"));
				break;
			case PURPLE_SSL_HANDSHAKE_FAILED:
				purple_connection_error(gc, _("SSL handshake failed"));
				break;
			case PURPLE_SSL_CERTIFICATE_INVALID:
				purple_connection_error(gc, _("SSL certificate invalid"));
				break;
        }
}

static void
sipe_tcp_connect_listen_cb(int listenfd, gpointer data)
{
	struct sipe_account_data *sip = (struct sipe_account_data*) data;
	PurpleProxyConnectData *connect_data;

	sip->listen_data = NULL;

	sip->listenfd = listenfd;
	if (sip->listenfd == -1) {
		purple_connection_error(sip->gc, _("Could not create listen socket"));
		return;
	}

	purple_debug_info("sipe", "listenfd: %d\n", sip->listenfd);
	//sip->listenport = purple_network_get_port_from_fd(sip->listenfd);
	sip->listenport = purple_network_get_port_from_fd(sip->listenfd);
	sip->listenpa = purple_input_add(sip->listenfd, PURPLE_INPUT_READ,
			sipe_newconn_cb, sip->gc);
	purple_debug_info("sipe", "connecting to %s port %d\n",
			sip->realhostname, sip->realport);
	/* open tcp connection to the server */
        connect_data = purple_proxy_connect(sip->gc, sip->account, sip->realhostname,
			sip->realport, login_cb, sip->gc);

	if (connect_data == NULL) {
		purple_connection_error(sip->gc, _("Could not create socket"));
	}
}

static void create_connection(struct sipe_account_data *sip, gchar *hostname, int port)
{
	PurpleAccount *account = sip->account;
	PurpleConnection *gc = sip->gc;

	if (port == 0) {
		port = (sip->transport == SIPE_TRANSPORT_TLS) ? 5061 : 5060;
	}

	sip->realhostname = hostname;
	sip->realport = port;

	purple_debug(PURPLE_DEBUG_MISC, "sipe", "create_connection - hostname: %s port: %d\n",
		     hostname, port);

	/* TODO: is there a good default grow size? */
	if (sip->transport != SIPE_TRANSPORT_UDP)
		sip->txbuf = purple_circ_buffer_new(0);

	if (sip->transport == SIPE_TRANSPORT_TLS) {
		/* SSL case */
		if (!purple_ssl_is_supported()) {
			gc->wants_to_die = TRUE;
			purple_connection_error(gc, _("SSL support is not installed. Either install SSL support or configure a different connection type in the account editor"));
			return;
		}

		purple_debug_info("sipe", "using SSL\n");

		sip->gsc = purple_ssl_connect(account, hostname, port,
					      login_cb_ssl, sipe_ssl_connect_failure, gc);
		if (sip->gsc == NULL) {
			purple_connection_error(gc, _("Could not create SSL context"));
			return;
		}
	} else if (sip->transport == SIPE_TRANSPORT_UDP) {
		/* UDP case */
		purple_debug_info("sipe", "using UDP\n");

		sip->query_data = purple_dnsquery_a(hostname, port, sipe_udp_host_resolved, sip);
		if (sip->query_data == NULL) {
			purple_connection_error(gc, _("Could not resolve hostname"));
		}
	} else {
		/* TCP case */
		purple_debug_info("sipe", "using TCP\n");
		/* create socket for incoming connections */
		sip->listen_data = purple_network_listen_range(5060, 5160, SOCK_STREAM,
							       sipe_tcp_connect_listen_cb, sip);
		if (sip->listen_data == NULL) {
			purple_connection_error(gc, _("Could not create listen socket"));
			return;
		}
	}
}

/* Service list for autodection */
static const struct sipe_service_data service_autodetect[] = {
	{ "sipinternaltls", "tcp", SIPE_TRANSPORT_TLS }, /* for internal TLS connections */
	{ "sipinternal",    "tcp", SIPE_TRANSPORT_TCP }, /* for internal TCP connections */
	{ "sip",            "tls", SIPE_TRANSPORT_TLS }, /* for external TLS connections */
	{ "sip",            "tcp", SIPE_TRANSPORT_TCP }, /*.for external TCP connections */
	{ NULL,             NULL,  0 }
};

/* Service list for SSL/TLS */
static const struct sipe_service_data service_tls[] = {
	{ "sipinternaltls", "tcp", SIPE_TRANSPORT_TLS }, /* for internal TLS connections */
	{ "sip",            "tls", SIPE_TRANSPORT_TLS }, /* for external TLS connections */
	{ NULL,             NULL,  0 }
};

/* Service list for TCP */
static const struct sipe_service_data service_tcp[] = {
	{ "sipinternal",    "tcp", SIPE_TRANSPORT_TCP }, /* for internal TCP connections */
	{ "sip",            "tcp", SIPE_TRANSPORT_TCP }, /*.for external TCP connections */
	{ NULL,             NULL,  0 }
};

/* Service list for UDP */
static const struct sipe_service_data service_udp[] = {
	{ "sip",            "udp", SIPE_TRANSPORT_UDP },
	{ NULL,             NULL,  0 }
};

static void srvresolved(PurpleSrvResponse *, int, gpointer);
static void resolve_next_service(struct sipe_account_data *sip,
				 const struct sipe_service_data *start)
{
	if (start) {
		sip->service_data = start;
	} else {
		sip->service_data++;
		if (sip->service_data->service == NULL) {
			gchar *hostname;
			/* Try connecting to the SIP hostname directly */
			purple_debug(PURPLE_DEBUG_MISC, "sipe", "no SRV records found; using SIP domain as fallback\n");
			if (sip->auto_transport) {
				// If SSL is supported, default to using it; OCS servers aren't configured
				// by default to accept TCP
				// TODO: LCS 2007 is the opposite, only configured by default to accept TCP
				sip->transport = purple_ssl_is_supported() ? SIPE_TRANSPORT_TLS : SIPE_TRANSPORT_TCP;
				purple_debug(PURPLE_DEBUG_MISC, "sipe", "set transport type..\n");
			}

			hostname = g_strdup(sip->sipdomain);
			create_connection(sip, hostname, 0);
			return;
		}
	}

	/* Try to resolve next service */
	sip->srv_query_data = purple_srv_resolve(sip->service_data->service,
						 sip->service_data->transport,
						 sip->sipdomain,
						 srvresolved, sip);
}

static void srvresolved(PurpleSrvResponse *resp, int results, gpointer data)
{
	struct sipe_account_data *sip = data;

	sip->srv_query_data = NULL;

	/* find the host to connect to */
	if (results) {
		gchar *hostname = g_strdup(resp->hostname);
		int port = resp->port;
		purple_debug(PURPLE_DEBUG_MISC, "sipe", "srvresolved - SRV hostname: %s port: %d\n",
			     hostname, port);
		g_free(resp);

		sip->transport = sip->service_data->type;

		create_connection(sip, hostname, port);
	} else {
		resolve_next_service(sip, NULL);
	}
}

static void sipe_login(PurpleAccount *account)
{
	PurpleConnection *gc;
	struct sipe_account_data *sip;
	gchar **signinname_login, **userserver;
	const char *transport;
	const char *email;

	const char *username = purple_account_get_username(account);
	gc = purple_account_get_connection(account);

	purple_debug_info("sipe", "sipe_login: username '%s'\n", username);

	if (strpbrk(username, "\t\v\r\n") != NULL) {
		gc->wants_to_die = TRUE;
		purple_connection_error(gc, _("SIP Exchange user name contains invalid characters"));
		return;
	}

	gc->proto_data = sip = g_new0(struct sipe_account_data, 1);
	gc->flags |= PURPLE_CONNECTION_HTML | PURPLE_CONNECTION_FORMATTING_WBFO | PURPLE_CONNECTION_NO_BGCOLOR |
		PURPLE_CONNECTION_NO_FONTSIZE | PURPLE_CONNECTION_NO_URLDESC | PURPLE_CONNECTION_ALLOW_CUSTOM_SMILEY;
	sip->gc = gc;
	sip->account = account;
	sip->reregister_set = FALSE;
	sip->reauthenticate_set = FALSE;
	sip->subscribed = FALSE;
	sip->subscribed_buddies = FALSE;
	sip->initial_state_published = FALSE;

	/* username format: <username>,[<optional login>] */
	signinname_login = g_strsplit(username, ",", 2);
	purple_debug_info("sipe", "sipe_login: signinname[0] '%s'\n", signinname_login[0]);

	/* ensure that username format is name@domain */
	if (!strchr(signinname_login[0], '@') || g_str_has_prefix(signinname_login[0], "@") || g_str_has_suffix(signinname_login[0], "@")) {
		g_strfreev(signinname_login);
		gc->wants_to_die = TRUE;
		purple_connection_error(gc, _("User name should be a valid SIP URI\nExample: user@company.com"));
		return;
	}
	sip->username = g_strdup(signinname_login[0]);

	/* ensure that email format is name@domain if provided */
	email = purple_account_get_string(sip->account, "email", NULL);
	if (!is_empty(email) &&
	    (!strchr(email, '@') || g_str_has_prefix(email, "@") || g_str_has_suffix(email, "@")))
	{
		gc->wants_to_die = TRUE;
		purple_connection_error(gc, _("Email address should be valid if provided\nExample: user@company.com"));
		return;
	}
	sip->email = !is_empty(email) ? g_strdup(email) : g_strdup(sip->username);

	/* login name specified? */
	if (signinname_login[1] && strlen(signinname_login[1])) {
		gchar **domain_user = g_strsplit(signinname_login[1], "\\", 2);
		gboolean has_domain = domain_user[1] != NULL;
		purple_debug_info("sipe", "sipe_login: signinname[1] '%s'\n", signinname_login[1]);
		sip->authdomain = has_domain ? g_strdup(domain_user[0]) : NULL;
		sip->authuser =   g_strdup(domain_user[has_domain ? 1 : 0]);
		purple_debug_info("sipe", "sipe_login: auth domain '%s' user '%s'\n",
				   sip->authdomain ? sip->authdomain : "", sip->authuser);
		g_strfreev(domain_user);
	}

	userserver = g_strsplit(signinname_login[0], "@", 2);
	purple_debug_info("sipe", "sipe_login: user '%s' server '%s'\n", userserver[0], userserver[1]);
	purple_connection_set_display_name(gc, userserver[0]);
	sip->sipdomain = g_strdup(userserver[1]);
	g_strfreev(userserver);
	g_strfreev(signinname_login);

	if (strchr(sip->username, ' ') != NULL) {
		gc->wants_to_die = TRUE;
		purple_connection_error(gc, _("SIP Exchange user name contains whitespace"));
		return;
	}

	sip->password = g_strdup(purple_connection_get_password(gc));

	sip->buddies = g_hash_table_new((GHashFunc)sipe_ht_hash_nick, (GEqualFunc)sipe_ht_equals_nick);
	sip->our_publications = g_hash_table_new_full(g_str_hash, g_str_equal,
						      g_free, (GDestroyNotify)g_hash_table_destroy);
	sip->subscriptions = g_hash_table_new_full(g_str_hash, g_str_equal,
						   g_free, (GDestroyNotify)sipe_subscription_free);

	purple_connection_update_progress(gc, _("Connecting"), 1, 2);

	g_free(sip->status);
	sip->status = g_strdup(SIPE_STATUS_ID_UNKNOWN);

	sip->auto_transport = FALSE;
	transport  = purple_account_get_string(account, "transport", "auto");
	userserver = g_strsplit(purple_account_get_string(account, "server", ""), ":", 2);
	if (userserver[0]) {
		/* Use user specified server[:port] */
		int port = 0;

		if (userserver[1])
			port = atoi(userserver[1]);

		purple_debug(PURPLE_DEBUG_MISC, "sipe", "sipe_login: user specified SIP server %s:%d\n",
			     userserver[0], port);

		if (strcmp(transport, "auto") == 0) {
			sip->transport = purple_ssl_is_supported() ? SIPE_TRANSPORT_TLS : SIPE_TRANSPORT_TCP;
		} else if (strcmp(transport, "tls") == 0) {
			sip->transport = SIPE_TRANSPORT_TLS;
		} else if (strcmp(transport, "tcp") == 0) {
			sip->transport = SIPE_TRANSPORT_TCP;
		} else {
			sip->transport = SIPE_TRANSPORT_UDP;
		}

		create_connection(sip, g_strdup(userserver[0]), port);
	} else {
		/* Server auto-discovery */
		if (strcmp(transport, "auto") == 0) {
			sip->auto_transport = TRUE;
			if (current_service && current_service->transport != NULL && current_service->service != NULL ){
				current_service++;
				resolve_next_service(sip, current_service);
			} else {
				resolve_next_service(sip, purple_ssl_is_supported() ? service_autodetect : service_tcp);
			}
		} else if (strcmp(transport, "tls") == 0) {
			resolve_next_service(sip, service_tls);
		} else if (strcmp(transport, "tcp") == 0) {
			resolve_next_service(sip, service_tcp);
		} else {
			resolve_next_service(sip, service_udp);
		}
	}
	g_strfreev(userserver);
}

static void sipe_connection_cleanup(struct sipe_account_data *sip)
{
	connection_free_all(sip);

	g_free(sip->epid);
	sip->epid = NULL;

	if (sip->query_data != NULL)
		purple_dnsquery_destroy(sip->query_data);
	sip->query_data = NULL;

	if (sip->srv_query_data != NULL)
		purple_srv_cancel(sip->srv_query_data);
	sip->srv_query_data = NULL;

	if (sip->listen_data != NULL)
		purple_network_listen_cancel(sip->listen_data);
	sip->listen_data = NULL;

	if (sip->gsc != NULL)
		purple_ssl_close(sip->gsc);
	sip->gsc = NULL;

	sipe_auth_free(&sip->registrar);
	sipe_auth_free(&sip->proxy);

	if (sip->txbuf)
		purple_circ_buffer_destroy(sip->txbuf);
	sip->txbuf = NULL;

	g_free(sip->realhostname);
	sip->realhostname = NULL;

	g_free(sip->server_version);
	sip->server_version = NULL;

	if (sip->listenpa)
		purple_input_remove(sip->listenpa);
	sip->listenpa = 0;
	if (sip->tx_handler)
		purple_input_remove(sip->tx_handler);
	sip->tx_handler = 0;
	if (sip->resendtimeout)
		purple_timeout_remove(sip->resendtimeout);
	sip->resendtimeout = 0;
	if (sip->timeouts) {
		GSList *entry = sip->timeouts;
		while (entry) {
			struct scheduled_action *sched_action = entry->data;
			purple_debug_info("sipe", "purple_timeout_remove: action name=%s\n", sched_action->name);
			purple_timeout_remove(sched_action->timeout_handler);
			if (sched_action->destroy) {
				(*sched_action->destroy)(sched_action->payload);
			}
			g_free(sched_action->name);
			g_free(sched_action);
			entry = entry->next;
		}
	}
	g_slist_free(sip->timeouts);

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

	if (sip->contact)
		g_free(sip->contact);
	sip->contact = NULL;
	if (sip->regcallid)
		g_free(sip->regcallid);
	sip->regcallid = NULL;

	if (sip->serveraddr)
		g_free(sip->serveraddr);
	sip->serveraddr = NULL;

	if (sip->focus_factory_uri)
		g_free(sip->focus_factory_uri);
	sip->focus_factory_uri = NULL;

	sip->fd = -1;
	sip->processing_input = FALSE;

	if (sip->ews) {
		sipe_ews_free(sip->ews);
	}
	sip->ews = NULL;
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

static void sipe_close(PurpleConnection *gc)
{
	struct sipe_account_data *sip = gc->proto_data;

	if (sip) {
		/* leave all conversations */
		sipe_session_close_all(sip);
		sipe_session_remove_all(sip);

		if (sip->csta) {
			sip_csta_close(sip);
		}

		if (PURPLE_CONNECTION_IS_CONNECTED(sip->gc)) {
			/* unsubscribe all */
			g_hash_table_foreach(sip->subscriptions, sipe_unsubscribe_cb, sip);

			/* unregister */
			do_register_exp(sip, 0);
		}

		sipe_connection_cleanup(sip);
		g_free(sip->sipdomain);
		g_free(sip->username);
		g_free(sip->email);
		g_free(sip->password);
		g_free(sip->authdomain);
		g_free(sip->authuser);
		g_free(sip->status);
		g_free(sip->note);

		g_hash_table_foreach_steal(sip->buddies, sipe_buddy_remove, NULL);
		g_hash_table_destroy(sip->buddies);
		g_hash_table_destroy(sip->our_publications);
		g_hash_table_destroy(sip->user_state_publications);
		g_hash_table_destroy(sip->subscriptions);

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

		while (sip->transactions)
			transactions_remove(sip, sip->transactions->data);
	}
	g_free(gc->proto_data);
	gc->proto_data = NULL;
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

static gboolean process_search_contact_response(struct sipe_account_data *sip, struct sipmsg *msg,
						SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	PurpleNotifySearchResults *results;
	PurpleNotifySearchColumn *column;
	xmlnode *searchResults;
	xmlnode *mrow;
	int match_count = 0;
	gboolean more = FALSE;
	gchar *secondary;

	purple_debug_info("sipe", "process_search_contact_response: body:\n%s n", msg->body ? msg->body : "");

	searchResults = xmlnode_from_str(msg->body, msg->bodylen);
	if (!searchResults) {
		purple_debug_info("sipe", "process_search_contact_response: no parseable searchResults\n");
		return FALSE;
	}

	results = purple_notify_searchresults_new();

	if (results == NULL) {
		purple_debug_error("sipe", "purple_parse_searchreply: Unable to display the search results.\n");
		purple_notify_error(sip->gc, NULL, _("Unable to display the search results"), NULL);

		xmlnode_free(searchResults);
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

	for (mrow =  xmlnode_get_descendant(searchResults, "Body", "Array", "row", NULL); mrow; mrow = xmlnode_get_next_twin(mrow)) {
		GList *row = NULL;

		gchar **uri_parts = g_strsplit(xmlnode_get_attrib(mrow, "uri"), ":", 2);
		row = g_list_append(row, g_strdup(uri_parts[1]));
		g_strfreev(uri_parts);

		row = g_list_append(row, g_strdup(xmlnode_get_attrib(mrow, "displayName")));
		row = g_list_append(row, g_strdup(xmlnode_get_attrib(mrow, "company")));
		row = g_list_append(row, g_strdup(xmlnode_get_attrib(mrow, "country")));
		row = g_list_append(row, g_strdup(xmlnode_get_attrib(mrow, "email")));

		purple_notify_searchresults_row_add(results, row);
		match_count++;
	}

	if ((mrow = xmlnode_get_descendant(searchResults, "Body", "directorySearch", "moreAvailable", NULL)) != NULL) {
		char *data = xmlnode_get_data_unescaped(mrow);
		more = (g_strcasecmp(data, "true") == 0);
		g_free(data);
	}

	secondary = g_strdup_printf(
		dngettext(GETTEXT_PACKAGE,
			  "Found %d contact%s:",
			  "Found %d contacts%s:", match_count),
		match_count, more ? _(" (more matched your query)") : "");

	purple_notify_searchresults_button_add(results, PURPLE_NOTIFY_BUTTON_IM, sipe_searchresults_im_buddy);
	purple_notify_searchresults_button_add(results, PURPLE_NOTIFY_BUTTON_ADD, sipe_searchresults_add_buddy);
	purple_notify_searchresults(sip->gc, NULL, NULL, secondary, results, NULL, NULL);

	g_free(secondary);
	xmlnode_free(searchResults);
	return TRUE;
}

static void sipe_search_contact_with_cb(PurpleConnection *gc, PurpleRequestFields *fields)
{
	GList *entries = purple_request_field_group_get_fields(purple_request_fields_get_groups(fields)->data);
	gchar **attrs = g_new(gchar *, g_list_length(entries) + 1);
	unsigned i = 0;

	do {
		PurpleRequestField *field = entries->data;
		const char *id = purple_request_field_get_id(field);
		const char *value = purple_request_field_string_get_value(field);

		purple_debug_info("sipe", "sipe_search_contact_with_cb: %s = '%s'\n", id, value ? value : "");

		if (value != NULL) attrs[i++] = g_markup_printf_escaped(SIPE_SOAP_SEARCH_ROW, id, value);
	} while ((entries = g_list_next(entries)) != NULL);
	attrs[i] = NULL;

	if (i > 0) {
		struct sipe_account_data *sip = gc->proto_data;
		gchar *domain_uri = sip_uri_from_name(sip->sipdomain);
		gchar *query = g_strjoinv(NULL, attrs);
		gchar *body = g_strdup_printf(SIPE_SOAP_SEARCH_CONTACT, 100, query);
		purple_debug_info("sipe", "sipe_search_contact_with_cb: body:\n%s n", body ? body : "");
		send_soap_request_with_cb(sip, domain_uri, body,
					  (TransCallback) process_search_contact_response, NULL);
		g_free(domain_uri);
		g_free(body);
		g_free(query);
	}

	g_strfreev(attrs);
}

static void sipe_show_find_contact(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	PurpleRequestFields *fields;
	PurpleRequestFieldGroup *group;
	PurpleRequestField *field;

	fields = purple_request_fields_new();
	group = purple_request_field_group_new(NULL);
	purple_request_fields_add_group(fields, group);

	field = purple_request_field_string_new("givenName", _("First name"), NULL, FALSE);
	purple_request_field_group_add_field(group, field);
	field = purple_request_field_string_new("sn", _("Last name"), NULL, FALSE);
	purple_request_field_group_add_field(group, field);
	field = purple_request_field_string_new("company", _("Company"), NULL, FALSE);
	purple_request_field_group_add_field(group, field);
	field = purple_request_field_string_new("c", _("Country"), NULL, FALSE);
	purple_request_field_group_add_field(group, field);

	purple_request_fields(gc,
		_("Search"),
		_("Search for a contact"),
		_("Enter the information for the person you wish to find. Empty fields will be ignored."),
		fields,
		_("_Search"), G_CALLBACK(sipe_search_contact_with_cb),
		_("_Cancel"), NULL,
		purple_connection_get_account(gc), NULL, NULL, gc);
}

static void sipe_show_about_plugin(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	const char *txt =
"<b><font size=\"+1\">Sipe " SIPE_VERSION "</font></b><br/>"
"<br/>"
"A third-party plugin implementing extended version of SIP/SIMPLE used by various products:<br/>"
    "<li> - MS Office Communications Server 2007 R2</li><br/>"
    "<li> - MS Office Communications Server 2007</li><br/>"
    "<li> - MS Live Communications Server 2005</li><br/>"
    "<li> - MS Live Communications Server 2003</li><br/>"
    "<li> - Reuters Messaging</li><br/>"
"<br/>"
"Home: <a href=\"http://sipe.sourceforge.net\">http://sipe.sourceforge.net</a><br/>"
"Support: <a href=\"http://sourceforge.net/projects/sipe/forums/forum/688534\">Help Forum</a><br/>"
"License: GPLv2+<br/>"
"<br/>"
"We support users in the following organizations to mention a few:<br/>"
" - CERN<br/>"
" - Reuters Messaging network<br/>"
" - Deutsche Bank<br/>"
" - Merrill Lynch<br/>"
" - Wachovia<br/>"
" - Intel<br/>"
" - Nokia<br/>"
" - HP<br/>"
" - Siemens<br/>"
" - Alcatel-Lucent<br/>"
" - BT<br/>"
"<br/>"
"<b>Authors:</b><br/>"
" - Anibal Avelar<br/>"
" - Gabriel Burt<br/>"
" - Stefan Becker<br/>"
" - pier11<br/>";

	purple_notify_formatted(gc, NULL, " ", NULL, txt, NULL, NULL);
}

static void sipe_republish_calendar(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	struct sipe_account_data *sip = gc->proto_data;

	sipe_update_calendar(sip);
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

static void sipe_reset_status(PurplePluginAction *action)
{
	PurpleConnection *gc = (PurpleConnection *) action->context;
	struct sipe_account_data *sip = gc->proto_data;

	if (sip->ocs2007) /* 2007+ */
	{
		GString* str = g_string_new(NULL);
		gchar *publications;

		if (!sip->user_state_publications || g_hash_table_size(sip->user_state_publications) == 0) {
			purple_debug_info("sipe", "sipe_reset_status: no userState publications, exiting.\n");
			return;
		}

		g_hash_table_foreach(sip->user_state_publications, (GHFunc)sipe_publish_get_cat_state_user_to_clear, str);
		publications = g_string_free(str, FALSE);

		send_presence_publish(sip, publications);
		g_free(publications);
	}
	else /* 2005 */
	{
		send_presence_soap0(sip, FALSE, TRUE);
	}
}

GList *sipe_actions(SIPE_UNUSED_PARAMETER PurplePlugin *plugin,
		    gpointer context)
{
	PurpleConnection *gc = (PurpleConnection *)context;
	struct sipe_account_data *sip = gc->proto_data;
	GList *menu = NULL;
	PurplePluginAction *act;
	const char* calendar = purple_account_get_string(sip->account, "calendar", "EXCH");

	act = purple_plugin_action_new(_("About SIPE plugin"), sipe_show_about_plugin);
	menu = g_list_prepend(menu, act);

	act = purple_plugin_action_new(_("Contact search..."), sipe_show_find_contact);
	menu = g_list_prepend(menu, act);

	if (!strcmp(calendar, "EXCH")) {
		act = purple_plugin_action_new(_("Republish Calendar"), sipe_republish_calendar);
		menu = g_list_prepend(menu, act);
	}

	act = purple_plugin_action_new(_("Reset status"), sipe_reset_status);
	menu = g_list_prepend(menu, act);

	menu = g_list_reverse(menu);

	return menu;
}

static void dummy_permit_deny(SIPE_UNUSED_PARAMETER PurpleConnection *gc)
{
}

static gboolean sipe_plugin_load(SIPE_UNUSED_PARAMETER PurplePlugin *plugin)
{
  return TRUE;
}


static gboolean sipe_plugin_unload(SIPE_UNUSED_PARAMETER PurplePlugin *plugin)
{
    return TRUE;
}


static char *sipe_status_text(PurpleBuddy *buddy)
{
	const PurplePresence *presence = purple_buddy_get_presence(buddy);
	const PurpleStatus *status = purple_presence_get_active_status(presence);
	const char *status_id = purple_status_get_id(status);
	struct sipe_account_data *sip = (struct sipe_account_data *)buddy->account->gc->proto_data;
	struct sipe_buddy *sbuddy;
	char *text = NULL;

	if (!sip) return NULL; /* happens on pidgin exit */

	sbuddy = g_hash_table_lookup(sip->buddies, buddy->name);
	if (sbuddy) {
		const char *activity_str = sbuddy->activity ?
			sbuddy->activity : 
			!strcmp(status_id, SIPE_STATUS_ID_BUSY) || !strcmp(status_id, SIPE_STATUS_ID_BRB) ? 
				purple_status_get_name(status) : NULL;

		if (activity_str && sbuddy->note)
		{
			text = g_strdup_printf("%s - <i>%s</i>", activity_str, sbuddy->note);
		}
		else if (activity_str)
		{
			text = g_strdup(activity_str);
		}
		else if (sbuddy->note)
		{
			text = g_strdup_printf("<i>%s</i>", sbuddy->note);
		}
	}

	return text;
}

static void sipe_tooltip_text(PurpleBuddy *buddy, PurpleNotifyUserInfo *user_info, SIPE_UNUSED_PARAMETER gboolean full)
{
	const PurplePresence *presence = purple_buddy_get_presence(buddy);
	const PurpleStatus *status = purple_presence_get_active_status(presence);
	struct sipe_account_data *sip;
	struct sipe_buddy *sbuddy;
	char *note = NULL;
	gboolean is_oof_note = FALSE;
	char *activity = NULL;
	char *calendar = NULL;
	char *meeting_subject = NULL;
	char *meeting_location = NULL;

	sip = (struct sipe_account_data *) buddy->account->gc->proto_data;
	if (sip)  //happens on pidgin exit
	{
		sbuddy = g_hash_table_lookup(sip->buddies, buddy->name);
		if (sbuddy)
		{
			note = sbuddy->note;
			is_oof_note = sbuddy->is_oof_note;
			activity = sbuddy->activity;
			calendar = sipe_cal_get_description(sbuddy);
			meeting_subject = sbuddy->meeting_subject;
			meeting_location = sbuddy->meeting_location;
		}
	}

	//Layout
	if (purple_presence_is_online(presence))
	{
		const char *status_str = activity ? activity : purple_status_get_name(status);

		purple_notify_user_info_add_pair(user_info, _("Status"), status_str);
	}
	if (purple_presence_is_online(presence) &&
	    !is_empty(calendar))
	{
		purple_notify_user_info_add_pair(user_info, _("Calendar"), calendar);
	}
	g_free(calendar);
	if (!is_empty(meeting_location))
	{
		purple_notify_user_info_add_pair(user_info, _("Meeting in"), meeting_location);
	}
	if (!is_empty(meeting_subject))
	{
		purple_notify_user_info_add_pair(user_info, _("Meeting about"), meeting_subject);
	}

	if (note)
	{
		char *tmp = g_strdup_printf("<i>%s</i>", note);
		purple_debug_info("sipe", "sipe_tooltip_text: %s note: '%s'\n", buddy->name, note);

		purple_notify_user_info_add_pair(user_info, is_oof_note ? _("Out of office note") : _("Note"), tmp);
		g_free(tmp);
	}

}

#if PURPLE_VERSION_CHECK(2,5,0)
static GHashTable *
sipe_get_account_text_table(SIPE_UNUSED_PARAMETER PurpleAccount *account)
{
	GHashTable *table;
	table = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(table, "login_label", (gpointer)_("user@company.com"));
	return table;
}
#endif

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

	purple_debug_info("sipe", "sipe_buddy_menu_copy_to_cb: copying %s to %s\n", buddy->name, group_name);
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
	struct sipe_account_data *sip = buddy->account->gc->proto_data;

	purple_debug_info("sipe", "sipe_buddy_menu_chat_new_cb: buddy->name=%s\n", buddy->name);

	/* 2007+ conference */
	if (sip->ocs2007)
	{
		sipe_conf_add(sip, buddy->name);
	}
	else /* 2005- multiparty chat */
	{
		gchar *self = sip_uri_self(sip);
		struct sip_session *session;

		session = sipe_session_add_chat(sip);
		session->chat_title = sipe_chat_get_name(session->callid);
		session->roster_manager = g_strdup(self);

		session->conv = serv_got_joined_chat(buddy->account->gc, session->chat_id, session->chat_title);
		purple_conv_chat_set_nick(PURPLE_CONV_CHAT(session->conv), self);
		purple_conv_chat_add_user(PURPLE_CONV_CHAT(session->conv), self, NULL, PURPLE_CBFLAGS_NONE, FALSE);
		sipe_invite(sip, session, buddy->name, NULL, NULL, FALSE);

		g_free(self);
	}
}

static gboolean
sipe_is_election_finished(struct sip_session *session)
{
	gboolean res = TRUE;

	SIPE_DIALOG_FOREACH {
		if (dialog->election_vote == 0) {
			res = FALSE;
			break;
		}
	} SIPE_DIALOG_FOREACH_END;

	if (res) {
		session->is_voting_in_progress = FALSE;
	}
	return res;
}

static void
sipe_election_start(struct sipe_account_data *sip,
		    struct sip_session *session)
{
	int election_timeout;

	if (session->is_voting_in_progress) {
		purple_debug_info("sipe", "sipe_election_start: other election is in progress, exiting.\n");
		return;
	} else {
		session->is_voting_in_progress = TRUE;
	}
	session->bid = rand();

	purple_debug_info("sipe", "sipe_election_start: RM election has initiated. Our bid=%d\n", session->bid);

	SIPE_DIALOG_FOREACH {
		/* reset election_vote for each chat participant */
		dialog->election_vote = 0;

		/* send RequestRM to each chat participant*/
		sipe_send_election_request_rm(sip, dialog, session->bid);
	} SIPE_DIALOG_FOREACH_END;

	election_timeout = 15; /* sec */
	sipe_schedule_action("<+election-result>", election_timeout, sipe_election_result, NULL, sip, session);
}

/**
 * @param who a URI to whom to invite to chat
 */
void
sipe_invite_to_chat(struct sipe_account_data *sip,
		    struct sip_session *session,
		    const gchar *who)
{
	/* a conference */
	if (session->focus_uri)
	{
		sipe_invite_conf(sip, session, who);
	}
	else /* a multi-party chat */
	{
		gchar *self = sip_uri_self(sip);
		if (session->roster_manager) {
			if (!strcmp(session->roster_manager, self)) {
				sipe_invite(sip, session, who, NULL, NULL, FALSE);
			} else {
				sipe_refer(sip, session, who);
			}
		} else {
			purple_debug_info("sipe", "sipe_buddy_menu_chat_invite: no RM available\n");

			session->pending_invite_queue = slist_insert_unique_sorted(
				session->pending_invite_queue, g_strdup(who), (GCompareFunc)strcmp);

			sipe_election_start(sip, session);
		}
		g_free(self);
	}
}

void
sipe_process_pending_invite_queue(struct sipe_account_data *sip,
				  struct sip_session *session)
{
	gchar *invitee;
	GSList *entry = session->pending_invite_queue;

	while (entry) {
		invitee = entry->data;
		sipe_invite_to_chat(sip, session, invitee);
		entry = session->pending_invite_queue = g_slist_remove(session->pending_invite_queue, invitee);
		g_free(invitee);
	}
}

static void
sipe_election_result(struct sipe_account_data *sip,
		     void *sess)
{
	struct sip_session *session = (struct sip_session *)sess;
	gchar *rival;
	gboolean has_won = TRUE;

	if (session->roster_manager) {
		purple_debug_info("sipe",
			"sipe_election_result: RM has already been elected in the meantime. It is %s\n", session->roster_manager);
		return;
	}

	session->is_voting_in_progress = FALSE;

	SIPE_DIALOG_FOREACH {
		if (dialog->election_vote < 0) {
			has_won = FALSE;
			rival = dialog->with;
			break;
		}
	} SIPE_DIALOG_FOREACH_END;

	if (has_won) {
		purple_debug_info("sipe", "sipe_election_result: we have won RM election!\n");

		session->roster_manager = sip_uri_self(sip);

		SIPE_DIALOG_FOREACH {
			/* send SetRM to each chat participant*/
			sipe_send_election_set_rm(sip, dialog);
		} SIPE_DIALOG_FOREACH_END;
	} else {
		purple_debug_info("sipe", "sipe_election_result: we loose RM election to %s\n", rival);
	}
	session->bid = 0;

	sipe_process_pending_invite_queue(sip, session);
}

/**
 * For 2007+ conference only.
 */
static void
sipe_buddy_menu_chat_make_leader_cb(PurpleBuddy *buddy, const char *chat_title)
{
	struct sipe_account_data *sip = buddy->account->gc->proto_data;
	struct sip_session *session;

	purple_debug_info("sipe", "sipe_buddy_menu_chat_make_leader_cb: buddy->name=%s\n", buddy->name);
	purple_debug_info("sipe", "sipe_buddy_menu_chat_make_leader_cb: chat_title=%s\n", chat_title);

	session = sipe_session_find_chat_by_title(sip, chat_title);

	sipe_conf_modify_user_role(sip, session, buddy->name);
}

/**
 * For 2007+ conference only.
 */
static void
sipe_buddy_menu_chat_remove_cb(PurpleBuddy *buddy, const char *chat_title)
{
	struct sipe_account_data *sip = buddy->account->gc->proto_data;
	struct sip_session *session;

	purple_debug_info("sipe", "sipe_buddy_menu_chat_remove_cb: buddy->name=%s\n", buddy->name);
	purple_debug_info("sipe", "sipe_buddy_menu_chat_remove_cb: chat_title=%s\n", chat_title);

	session = sipe_session_find_chat_by_title(sip, chat_title);

	sipe_conf_delete_user(sip, session, buddy->name);
}

static void
sipe_buddy_menu_chat_invite_cb(PurpleBuddy *buddy, char *chat_title)
{
	struct sipe_account_data *sip = buddy->account->gc->proto_data;
	struct sip_session *session;

	purple_debug_info("sipe", "sipe_buddy_menu_chat_invite_cb: buddy->name=%s\n", buddy->name);
	purple_debug_info("sipe", "sipe_buddy_menu_chat_invite_cb: chat_title=%s\n", chat_title);

	session = sipe_session_find_chat_by_title(sip, chat_title);

	sipe_invite_to_chat(sip, session, buddy->name);
}

static void
sipe_buddy_menu_make_call_cb(PurpleBuddy *buddy, const char *phone)
{
	struct sipe_account_data *sip = buddy->account->gc->proto_data;

	purple_debug_info("sipe", "sipe_buddy_menu_make_call_cb: buddy->name=%s\n", buddy->name);
	if (phone) {
		char *tel_uri = sip_to_tel_uri(phone);

		purple_debug_info("sipe", "sipe_buddy_menu_make_call_cb: going to call number: %s\n", tel_uri ? tel_uri : "");
		sip_csta_make_call(sip, tel_uri);

		g_free(tel_uri);
	}
}

static void
sipe_buddy_menu_send_email_cb(PurpleBuddy *buddy)
{
	const gchar *email;
	purple_debug_info("sipe", "sipe_buddy_menu_send_email_cb: buddy->name=%s\n", buddy->name);

	email = purple_blist_node_get_string(&buddy->node, EMAIL_PROP);
	if (email)
	{
		char *mailto = g_strdup_printf("mailto:%s", email);
		purple_debug_info("sipe", "sipe_buddy_menu_send_email_cb: going to call default mail client with email: %s\n", email);
#ifndef _WIN32
		{
			pid_t pid;
			char *const parmList[] = {"xdg-email", mailto, NULL};
			if ((pid = fork()) == -1)
			{
				purple_debug_info("sipe", "fork() error\n");
			}
			else if (pid == 0)
			{
				execvp(parmList[0], parmList);
				purple_debug_info("sipe", "Return not expected. Must be an execvp() error.\n");
			}
		}
#else
		{
			BOOL ret;
			_flushall();
			errno = 0;
			//@TODO resolve env variable %WINDIR% first
			ret = spawnl(_P_NOWAIT, "c:/WINDOWS/system32/cmd", "/c", "start", mailto, NULL);
			if (errno)
			{
				purple_debug_info("sipe", "spawnl returned (%s)!\n", strerror(errno));
			}
		}
#endif

		g_free(mailto);
	}
	else
	{
		purple_debug_info("sipe", "sipe_buddy_menu_send_email_cb: no email address stored for buddy=%s\n", buddy->name);
	}
}

/*
 * A menu which appear when right-clicking on buddy in contact list.
 */
static GList *
sipe_buddy_menu(PurpleBuddy *buddy)
{
	PurpleBlistNode *g_node;
	PurpleGroup *group, *gr_parent;
	PurpleMenuAction *act;
	GList *menu = NULL;
	GList *menu_groups = NULL;
	struct sipe_account_data *sip = buddy->account->gc->proto_data;
	const char *email;
	const char *phone;
	const char *phone_disp_str;
	gchar *self = sip_uri_self(sip);

	SIPE_SESSION_FOREACH {
		if (g_ascii_strcasecmp(self, buddy->name) && session->chat_title && session->conv)
		{
			if (purple_conv_chat_find_user(PURPLE_CONV_CHAT(session->conv), buddy->name))
			{
				PurpleConvChatBuddyFlags flags;
				PurpleConvChatBuddyFlags flags_us;

				flags = purple_conv_chat_user_get_flags(PURPLE_CONV_CHAT(session->conv), buddy->name);
				flags_us = purple_conv_chat_user_get_flags(PURPLE_CONV_CHAT(session->conv), self);
				if (session->focus_uri
				    && PURPLE_CBFLAGS_OP != (flags & PURPLE_CBFLAGS_OP)     /* Not conf OP */
				    && PURPLE_CBFLAGS_OP == (flags_us & PURPLE_CBFLAGS_OP)) /* We are a conf OP */
				{
					gchar *label = g_strdup_printf(_("Make leader of '%s'"), session->chat_title);
					act = purple_menu_action_new(label,
								     PURPLE_CALLBACK(sipe_buddy_menu_chat_make_leader_cb),
								     session->chat_title, NULL);
					g_free(label);
					menu = g_list_prepend(menu, act);
				}

				if (session->focus_uri
				    && PURPLE_CBFLAGS_OP == (flags_us & PURPLE_CBFLAGS_OP)) /* We are a conf OP */
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
sipe_conf_modify_lock(PurpleChat *chat, gboolean locked)
{
	struct sipe_account_data *sip = chat->account->gc->proto_data;
	struct sip_session *session;

	session = sipe_session_find_chat_by_title(sip, (gchar *)g_hash_table_lookup(chat->components, "channel"));
	sipe_conf_modify_conference_lock(sip, session, locked);
}

static void
sipe_chat_menu_unlock_cb(PurpleChat *chat)
{
	purple_debug_info("sipe", "sipe_chat_menu_unlock_cb() called\n");
	sipe_conf_modify_lock(chat, FALSE);
}

static void
sipe_chat_menu_lock_cb(PurpleChat *chat)
{
	purple_debug_info("sipe", "sipe_chat_menu_lock_cb() called\n");
	sipe_conf_modify_lock(chat, TRUE);
}

static GList *
sipe_chat_menu(PurpleChat *chat)
{
	PurpleMenuAction *act;
	PurpleConvChatBuddyFlags flags_us;
	GList *menu = NULL;
	struct sipe_account_data *sip = chat->account->gc->proto_data;
	struct sip_session *session;
	gchar *self;

	session = sipe_session_find_chat_by_title(sip, (gchar *)g_hash_table_lookup(chat->components, "channel"));
	if (!session) return NULL;

	self = sip_uri_self(sip);
	flags_us = purple_conv_chat_user_get_flags(PURPLE_CONV_CHAT(session->conv), self);

	if (session->focus_uri
	    && PURPLE_CBFLAGS_OP == (flags_us & PURPLE_CBFLAGS_OP)) /* We are a conf OP */
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

static GList *
sipe_blist_node_menu(PurpleBlistNode *node)
{
	if(PURPLE_BLIST_NODE_IS_BUDDY(node)) {
		return sipe_buddy_menu((PurpleBuddy *) node);
	} else if(PURPLE_BLIST_NODE_IS_CHAT(node)) {
		return sipe_chat_menu((PurpleChat *)node);
	} else {
		return NULL;
	}
}

static gboolean
process_get_info_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *trans)
{
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

	if (!sip) return FALSE;

	purple_debug_info("sipe", "Fetching %s's user info for %s\n", uri, sip->username);

	pbuddy = purple_find_buddy((PurpleAccount *)sip->account, uri);
	alias = purple_buddy_get_local_alias(pbuddy);

	//will query buddy UA's capabilities and send answer to log
	sipe_options_request(sip, uri);

	sbuddy = g_hash_table_lookup(sip->buddies, uri);
	if (sbuddy) {
		device_name = sbuddy->device_name ? g_strdup(sbuddy->device_name) : NULL;
	}

	info = purple_notify_user_info_new();

	if (msg->response != 200) {
		purple_debug_info("sipe", "process_options_response: SERVICE response is %d\n", msg->response);
	} else {
		xmlnode *searchResults;
		xmlnode *mrow;

		purple_debug_info("sipe", "process_options_response: body:\n%s\n", msg->body ? msg->body : "");
		searchResults = xmlnode_from_str(msg->body, msg->bodylen);
		if (!searchResults) {
			purple_debug_info("sipe", "process_get_info_response: no parseable searchResults\n");
		} else if ((mrow = xmlnode_get_descendant(searchResults, "Body", "Array", "row", NULL))) {
			const char *value;
			server_alias = g_strdup(xmlnode_get_attrib(mrow, "displayName"));
			email = g_strdup(xmlnode_get_attrib(mrow, "email"));
			phone_number = g_strdup(xmlnode_get_attrib(mrow, "phone"));

			/* For 2007 system we will take this from ContactCard -
			 * it has cleaner tel: URIs at least
			 */
			if (!sip->ocs2007) {
				char *tel_uri = sip_to_tel_uri(phone_number);
				/* trims its parameters, so call first */
				sipe_update_user_info(sip, uri, ALIAS_PROP, server_alias);
				sipe_update_user_info(sip, uri, EMAIL_PROP, email);
				sipe_update_user_info(sip, uri, PHONE_PROP, tel_uri);
				sipe_update_user_info(sip, uri, PHONE_DISPLAY_PROP, phone_number);
				g_free(tel_uri);
			}

			if (server_alias && strlen(server_alias) > 0) {
				purple_notify_user_info_add_pair(info, _("Display name"), server_alias);
			}
			if ((value = xmlnode_get_attrib(mrow, "title")) && strlen(value) > 0) {
				purple_notify_user_info_add_pair(info, _("Job title"), value);
			}
			if ((value = xmlnode_get_attrib(mrow, "office")) && strlen(value) > 0) {
				purple_notify_user_info_add_pair(info, _("Office"), value);
			}
			if (phone_number && strlen(phone_number) > 0) {
				purple_notify_user_info_add_pair(info, _("Business phone"), phone_number);
			}
			if ((value = xmlnode_get_attrib(mrow, "company")) && strlen(value) > 0) {
				purple_notify_user_info_add_pair(info, _("Company"), value);
			}
			if ((value = xmlnode_get_attrib(mrow, "city")) && strlen(value) > 0) {
				purple_notify_user_info_add_pair(info, _("City"), value);
			}
			if ((value = xmlnode_get_attrib(mrow, "state")) && strlen(value) > 0) {
				purple_notify_user_info_add_pair(info, _("State"), value);
			}
			if ((value = xmlnode_get_attrib(mrow, "country")) && strlen(value) > 0) {
				purple_notify_user_info_add_pair(info, _("Country"), value);
			}
			if (email && strlen(email) > 0) {
				purple_notify_user_info_add_pair(info, _("Email address"), email);
			}

		}
		xmlnode_free(searchResults);
	}

	purple_notify_user_info_add_section_break(info);

	if (!server_alias || !strcmp("", server_alias)) {
		g_free(server_alias);
		server_alias = g_strdup(purple_buddy_get_server_alias(pbuddy));
		if (server_alias) {
			purple_notify_user_info_add_pair(info, _("Display name"), server_alias);
		}
	}

	/* present alias if it differs from server alias */
	if (alias && (!server_alias || strcmp(alias, server_alias)))
	{
		purple_notify_user_info_add_pair(info, _("Alias"), alias);
	}

	if (!email || !strcmp("", email)) {
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
static void sipe_get_info(PurpleConnection *gc, const char *username)
{
	struct sipe_account_data *sip = gc->proto_data;
	gchar *domain_uri = sip_uri_from_name(sip->sipdomain);
	char *row = g_markup_printf_escaped(SIPE_SOAP_SEARCH_ROW, "msRTCSIP-PrimaryUserAddress", username);
	gchar *body = g_strdup_printf(SIPE_SOAP_SEARCH_CONTACT, 1, row);
	struct transaction_payload *payload = g_new0(struct transaction_payload, 1);

	payload->destroy = g_free;
	payload->data = g_strdup(username);

	purple_debug_info("sipe", "sipe_get_contact_data: body:\n%s\n", body ? body : "");
	send_soap_request_with_cb(sip, domain_uri, body,
				  (TransCallback) process_get_info_response, payload);
	g_free(domain_uri);
	g_free(body);
	g_free(row);
}

static PurplePlugin *my_protocol = NULL;

static PurplePluginProtocolInfo prpl_info =
{
	OPT_PROTO_CHAT_TOPIC,
	NULL,					/* user_splits */
	NULL,					/* protocol_options */
	NO_BUDDY_ICONS,				/* icon_spec */
	sipe_list_icon,				/* list_icon */
	NULL,					/* list_emblems */
	sipe_status_text,			/* status_text */
	sipe_tooltip_text,			/* tooltip_text */	// add custom info to contact tooltip
	sipe_status_types,			/* away_states */
	sipe_blist_node_menu,			/* blist_node_menu */
	NULL,					/* chat_info */
	NULL,					/* chat_info_defaults */
	sipe_login,				/* login */
	sipe_close,				/* close */
	sipe_im_send,				/* send_im */
	NULL,					/* set_info */		// TODO maybe
	sipe_send_typing,			/* send_typing */
	sipe_get_info,				/* get_info */
	sipe_set_status,			/* set_status */
	sipe_set_idle,				/* set_idle */
	NULL,					/* change_passwd */
	sipe_add_buddy,				/* add_buddy */
	NULL,					/* add_buddies */
	sipe_remove_buddy,			/* remove_buddy */
	NULL,					/* remove_buddies */
	sipe_add_permit,			/* add_permit */
	sipe_add_deny,				/* add_deny */
	sipe_add_deny,				/* rem_permit */
	sipe_add_permit,			/* rem_deny */
	dummy_permit_deny,			/* set_permit_deny */
	NULL,					/* join_chat */
	NULL,					/* reject_chat */
	NULL,					/* get_chat_name */
	sipe_chat_invite,			/* chat_invite */
	sipe_chat_leave,			/* chat_leave */
	NULL,					/* chat_whisper */
	sipe_chat_send,				/* chat_send */
	sipe_keep_alive,			/* keepalive */
	NULL,					/* register_user */
	NULL,					/* get_cb_info */	// deprecated
	NULL,					/* get_cb_away */	// deprecated
	sipe_alias_buddy,			/* alias_buddy */
	sipe_group_buddy,			/* group_buddy */
	sipe_rename_group,			/* rename_group */
	NULL,					/* buddy_free */
	sipe_convo_closed,			/* convo_closed */
	purple_normalize_nocase,		/* normalize */
	NULL,					/* set_buddy_icon */
	sipe_remove_group,			/* remove_group */
	NULL,					/* get_cb_real_name */	// TODO?
	NULL,					/* set_chat_topic */
	NULL,					/* find_blist_chat */
	NULL,					/* roomlist_get_list */
	NULL,					/* roomlist_cancel */
	NULL,					/* roomlist_expand_category */
	NULL,					/* can_receive_file */
	NULL,					/* send_file */
	NULL,					/* new_xfer */
	NULL,					/* offline_message */
	NULL,					/* whiteboard_prpl_ops */
	sipe_send_raw,				/* send_raw */
	NULL,					/* roomlist_room_serialize */
	NULL,					/* unregister_user */
	NULL,					/* send_attention */
	NULL,					/* get_attention_types */
#if !PURPLE_VERSION_CHECK(2,5,0)
	/* Backward compatibility when compiling against 2.4.x API */
	(void (*)(void))			/* _purple_reserved4 */
#endif
	sizeof(PurplePluginProtocolInfo),       /* struct_size */
#if PURPLE_VERSION_CHECK(2,5,0)
	sipe_get_account_text_table,		/* get_account_text_table */
#if PURPLE_VERSION_CHECK(2,6,0)
	NULL,					/* initiate_media */
	NULL,					/* get_media_caps */
#endif
#endif
};


static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_PROTOCOL,                           /**< type           */
	NULL,                                             /**< ui_requirement */
	0,                                                /**< flags          */
	NULL,                                             /**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,                          /**< priority       */
	"prpl-sipe",                                   	  /**< id             */
	"Office Communicator",                            /**< name           */
	SIPE_VERSION,                                     /**< version        */
	"Microsoft Office Communicator Protocol Plugin",  /**< summary        */
	"A plugin for the extended SIP/SIMPLE protocol used by "          /**< description */
	"Microsoft Live/Office Communications Server (LCS2005/OCS2007+)", /**< description */
	"Anibal Avelar <avelar@gmail.com>, "              /**< author         */
	"Gabriel Burt <gburt@novell.com>, "               /**< author         */
	"Stefan Becker <stefan.becker@nokia.com>, "       /**< author         */
	"pier11 <pier11@operamail.com>",                  /**< author         */
	"http://sipe.sourceforge.net/",                   /**< homepage       */
	sipe_plugin_load,                                 /**< load           */
	sipe_plugin_unload,                               /**< unload         */
	sipe_plugin_destroy,                              /**< destroy        */
	NULL,                                             /**< ui_info        */
	&prpl_info,                                       /**< extra_info     */
	NULL,
	sipe_actions,
	NULL,
	NULL,
	NULL,
	NULL
};

static void sipe_plugin_destroy(SIPE_UNUSED_PARAMETER PurplePlugin *plugin)
{
	GList *entry;

	entry = prpl_info.protocol_options;
	while (entry) {
		purple_account_option_destroy(entry->data);
		entry = g_list_delete_link(entry, entry);
	}
	prpl_info.protocol_options = NULL;

	entry = prpl_info.user_splits;
	while (entry) {
		purple_account_user_split_destroy(entry->data);
		entry = g_list_delete_link(entry, entry);
	}
	prpl_info.user_splits = NULL;
}

static void init_plugin(PurplePlugin *plugin)
{
	PurpleAccountUserSplit *split;
	PurpleAccountOption *option;

	srand(time(NULL));

#ifdef ENABLE_NLS
	purple_debug_info(PACKAGE, "bindtextdomain = %s\n", bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR));
	purple_debug_info(PACKAGE, "bind_textdomain_codeset = %s\n",
	bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8"));
	textdomain(GETTEXT_PACKAGE);
#endif

	purple_plugin_register(plugin);

	split = purple_account_user_split_new(_("Login\n   user  or  DOMAIN\\user  or\n   user@company.com"), NULL, ',');
	purple_account_user_split_set_reverse(split, FALSE);
	prpl_info.user_splits = g_list_append(prpl_info.user_splits, split);

	option = purple_account_option_string_new(_("Server[:Port]\n(leave empty for auto-discovery)"), "server", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_list_new(_("Connection type"), "transport", NULL);
	purple_account_option_add_list_item(option, _("Auto"), "auto");
	purple_account_option_add_list_item(option, _("SSL/TLS"), "tls");
	purple_account_option_add_list_item(option, _("TCP"), "tcp");
	purple_account_option_add_list_item(option, _("UDP"), "udp");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	/*option = purple_account_option_bool_new(_("Publish status (note: everyone may watch you)"), "doservice", TRUE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);*/

	option = purple_account_option_string_new(_("User Agent"), "useragent", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

#ifdef USE_KERBEROS
	option = purple_account_option_bool_new(_("Use Kerberos"), "krb5", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	/* Suitable for sspi/NTLM, sspi/Kerberos and krb5 security mechanisms
	 * No login/password is taken into account if this option present,
	 * instead used default credentials stored in OS.
	 */
	option = purple_account_option_bool_new(_("Use Single Sign-On"), "sso", TRUE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
#endif

	option = purple_account_option_list_new(_("Calendar source"), "calendar", NULL);
	purple_account_option_add_list_item(option, _("Exchange 2007/2010"), "EXCH");
	purple_account_option_add_list_item(option, _("None"), "NONE");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	/** Example: https://server.company.com/EWS/Exchange.asmx */
	option = purple_account_option_string_new(_("Email services URL\n(leave empty for auto-discovery)"), "email_url", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("Email address\n(if different from Username)"), "email", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	/** Example: DOMAIN\user  or  user@company.com */
	option = purple_account_option_string_new(_("Email login\n(if different from Login)"), "email_login", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_string_new(_("Email password\n(if different from Password)"), "email_password", "");
	purple_account_option_set_masked(option, TRUE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	my_protocol = plugin;
}

PURPLE_INIT_PLUGIN(sipe, init_plugin, info);

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
