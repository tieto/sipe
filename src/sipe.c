/**
 * @file sipe.c
 *
 * pidgin-sipe
 * 
 * Copyright (C) 2009 Anibal Avelar <debianmx@gmail.com>
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
#ifdef ENABLE_NLS
#	include <libintl.h>
#	define _(String)  ((const char *) gettext (String))
#else
#   define _(String) ((const char *) (String))
#endif /* ENABLE_NLS */
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
#include <glib.h>


#include "accountopt.h"
#include "blist.h"
#include "conversation.h"
#include "dnsquery.h"
#include "debug.h"
#include "notify.h"
#include "privacy.h"
#include "prpl.h"
#include "plugin.h"
#include "util.h"
#include "version.h"
#include "network.h"
#include "xmlnode.h"
#include "mime.h"

#include "sipe.h"
#include "sip-ntlm.h"
#ifdef USE_KERBEROS
 #include "sipkrb5.h"
#endif /*USE_KERBEROS*/

#include "sipmsg.h"
#include "sipe-sign.h"
#include "dnssrv.h"
#include "request.h"

/* Keep in sync with sipe_transport_type! */
static const char *transport_descriptor[] = { "tls", "tcp", "udp" };
#define TRANSPORT_DESCRIPTOR (transport_descriptor[sip->transport])

/* Status identifiers (see also: sipe_status_types()) */
#define SIPE_STATUS_ID_UNKNOWN     purple_primitive_get_id_from_type(PURPLE_STATUS_UNSET)     /* Unset (primitive) */
#define SIPE_STATUS_ID_OFFLINE     purple_primitive_get_id_from_type(PURPLE_STATUS_OFFLINE)   /* Offline (primitive) */
#define SIPE_STATUS_ID_AVAILABLE   purple_primitive_get_id_from_type(PURPLE_STATUS_AVAILABLE) /* Online */
/*      PURPLE_STATUS_UNAVAILABLE: */
#define SIPE_STATUS_ID_BUSY        "busy"                                                     /* Busy */
#define SIPE_STATUS_ID_DND         "do-not-disturb"                                           /* Do Not Disturb */
#define SIPE_STATUS_ID_ONPHONE     "on-the-phone"                                             /* On The Phone */
#define SIPE_STATUS_ID_INVISIBLE   purple_primitive_get_id_from_type(PURPLE_STATUS_INVISIBLE) /* Appear Offline */
/*      PURPLE_STATUS_AWAY: */
#define SIPE_STATUS_ID_BRB         "be-right-back"                                            /* Be Right Back */
#define SIPE_STATUS_ID_AWAY        purple_primitive_get_id_from_type(PURPLE_STATUS_AWAY)      /* Away (primitive) */
#define SIPE_STATUS_ID_LUNCH       "out-to-lunch"                                             /* Out To Lunch */
/* ???  PURPLE_STATUS_EXTENDED_AWAY */
/* ???  PURPLE_STATUS_MOBILE */
/* ???  PURPLE_STATUS_TUNE */

static char *gentag()
{
	return g_strdup_printf("%04d%04d", rand() & 0xFFFF, rand() & 0xFFFF);
}

static gchar *get_epid(struct sipe_account_data *sip)
{
	if (!sip->epid) {
		sip->epid = sipe_uuid_get_macaddr(purple_network_get_my_ip(-1));
	}
	return g_strdup(sip->epid);
}

static char *genbranch()
{
	return g_strdup_printf("z9hG4bK%04X%04X%04X%04X%04X",
		rand() & 0xFFFF, rand() & 0xFFFF, rand() & 0xFFFF,
		rand() & 0xFFFF, rand() & 0xFFFF);
}

static char *gencallid()
{
	return g_strdup_printf("%04Xg%04Xa%04Xi%04Xm%04Xt%04Xb%04Xx%04Xx",
		rand() & 0xFFFF, rand() & 0xFFFF, rand() & 0xFFFF,
		rand() & 0xFFFF, rand() & 0xFFFF, rand() & 0xFFFF,
		rand() & 0xFFFF, rand() & 0xFFFF);
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


static const char *sipe_list_icon(PurpleAccount *a, PurpleBuddy *b)
{
	return "sipe";
}

static void sipe_plugin_destroy(PurplePlugin *plugin);

static gboolean process_register_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc);

static void sipe_input_cb_ssl(gpointer data, PurpleSslConnection *gsc, PurpleInputCondition cond);
static void sipe_ssl_connect_failure(PurpleSslConnection *gsc, PurpleSslErrorType error,
                                     gpointer data);

static void sipe_close(PurpleConnection *gc);

static void sipe_subscribe_presence_single(struct sipe_account_data *sip, const char * buddy_name);
static void sipe_subscribe_presence_batched(struct sipe_account_data *sip);
static void send_presence_status(struct sipe_account_data *sip);

static void sendout_pkt(PurpleConnection *gc, const char *buf);

static void sipe_keep_alive_timeout(struct sipe_account_data *sip, const gchar *hdr)
{
	gchar *timeout = sipmsg_find_part_of_header(hdr, "timeout=", ";", NULL);
	if (timeout != NULL) {
		sscanf(timeout, "%u", &sip->keepalive_timeout);
		purple_debug_info("sipe", "server determined keep alive timeout is %u seconds\n",
				  sip->keepalive_timeout);
	}
	g_free(timeout);
}

static void sipe_keep_alive(PurpleConnection *gc)
{
	struct sipe_account_data *sip = gc->proto_data;
	if (sip->transport == SIPE_TRANSPORT_UDP) {
		/* in case of UDP send a packet only with a 0 byte to remain in the NAT table */
		gchar buf[2] = {0, 0};
		purple_debug_info("sipe", "sending keep alive\n");
		sendto(sip->fd, buf, 1, 0, (struct sockaddr*)&sip->serveraddr, sizeof(struct sockaddr_in));
	} else {
		time_t now = time(NULL);
		if ((sip->keepalive_timeout > 0) &&
		    ((now - sip->last_keepalive) >= sip->keepalive_timeout)
#if PURPLE_VERSION_CHECK(2,4,0)
		    && ((now - gc->last_received) >= sip->keepalive_timeout)
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
	g_free(auth->nonce);
	auth->nonce = NULL;
	g_free(auth->opaque);
	auth->opaque = NULL;
	g_free(auth->realm);
	auth->realm = NULL;
	g_free(auth->target);
	auth->target = NULL;
	g_free(auth->digest_session_key);
	auth->digest_session_key = NULL;
	g_free(auth->ntlm_key);
	auth->ntlm_key = NULL;
	auth->type = AUTH_TYPE_UNSET;
	auth->retries = 0;
	auth->expires = 0;
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
	const gchar *method = msg->method;
	const gchar *target = msg->target;
	gchar noncecount[9];
	gchar *response;
	gchar *ret;
	gchar *tmp = NULL;
	const char *authdomain = sip->authdomain;
	const char *authuser = sip->authuser;
	//const char *krb5_realm;
	const char *host;
	//gchar      *krb5_token = NULL;

	// XXX FIXME: Get this info from the account dialogs and/or /etc/krb5.conf
	//            and do error checking

	// KRB realm should always be uppercase
	//krb5_realm = g_strup(purple_account_get_string(sip->account, "krb5_realm", ""));

	if (sip->realhostname) {
		host = sip->realhostname;
	} else if (purple_account_get_bool(sip->account, "useproxy", TRUE)) {
		host = purple_account_get_string(sip->account, "proxy", "");
	} else {
		host = sip->sipdomain;
	}

	/*gboolean new_auth = krb5_auth.gss_context == NULL;
	if (new_auth) {
		purple_krb5_init_auth(&krb5_auth, authuser, krb5_realm, sip->password, host, "sip");
	}

	if (new_auth || force_reauth) {
		krb5_token = krb5_auth.base64_token;
	}

	purple_krb5_init_auth(&krb5_auth, authuser, krb5_realm, sip->password, host, "sip");
	krb5_token = krb5_auth.base64_token;*/

	if (!authdomain) {
		authdomain = "";
	}

	if (!authuser || strlen(authuser) < 1) {
		authuser = sip->username;
	}

	if (auth->type == AUTH_TYPE_DIGEST) { /* Digest */
		sprintf(noncecount, "%08d", auth->nc++);
		response = purple_cipher_http_digest_calculate_response(
							"md5", method, target, NULL, NULL,
							auth->nonce, noncecount, NULL, auth->digest_session_key);
		purple_debug(PURPLE_DEBUG_MISC, "sipe", "response %s\n", response);

		ret = g_strdup_printf("Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", nc=\"%s\", response=\"%s\"", authuser, auth->realm, auth->nonce, target, noncecount, response);
		g_free(response);
		return ret;
	} else if (auth->type == AUTH_TYPE_NTLM) { /* NTLM */
		// If we have a signature for the message, include that
		if (msg->signature) {
			tmp = g_strdup_printf("NTLM qop=\"auth\", opaque=\"%s\", realm=\"%s\", targetname=\"%s\", crand=\"%s\", cnum=\"%s\", response=\"%s\"", auth->opaque, auth->realm, auth->target, msg->rand, msg->num, msg->signature);
			return tmp;
		}

		if (auth->nc == 3 && auth->nonce && auth->ntlm_key == NULL) {
			const gchar *ntlm_key;
			gchar *gssapi_data;
#if GLIB_CHECK_VERSION(2,8,0)
			const gchar * hostname = g_get_host_name();
#else
			static char hostname[256];
			int ret = gethostname(hostname, sizeof(hostname));
			hostname[sizeof(hostname) - 1] = '\0';
			if (ret == -1 || hostname[0] == '\0') {
				purple_debug(PURPLE_DEBUG_MISC, "sipe", "Error when getting host name.  Using \"localhost.\"\n");
				g_strerror(errno);
				strcpy(hostname, "localhost");
			}
#endif
			/*const gchar * hostname = purple_get_host_name();*/

			gssapi_data = purple_ntlm_gen_authenticate(&ntlm_key, authuser, sip->password, hostname, authdomain, (const guint8 *)auth->nonce, &auth->flags);
			auth->ntlm_key = (gchar *)ntlm_key;
			tmp = g_strdup_printf("NTLM qop=\"auth\", opaque=\"%s\", realm=\"%s\", targetname=\"%s\", gssapi-data=\"%s\"", auth->opaque, auth->realm, auth->target, gssapi_data);
			g_free(gssapi_data);
			return tmp;
		}

		tmp = g_strdup_printf("NTLM qop=\"auth\", realm=\"%s\", targetname=\"%s\", gssapi-data=\"\"", auth->realm, auth->target);
		return tmp;
	} else if (auth->type == AUTH_TYPE_KERBEROS) {
		/* Kerberos */
		if (auth->nc == 3) {
			/*if (new_auth || force_reauth) {
				printf ("krb5 token not NULL, so adding gssapi-data attribute; op = %s\n", auth->opaque);
				if (auth->opaque) {
					tmp = g_strdup_printf("Kerberos qop=\"auth\", realm=\"%s\", opaque=\"%s\", targetname=\"%s\", gssapi-data=\"%s\"", "SIP Communications Service", auth->opaque, auth->target, krb5_token);
				} else {
					tmp = g_strdup_printf("Kerberos qop=\"auth\", realm=\"%s\", targetname=\"%s\", gssapi-data=\"%s\"", "SIP Communications Service", auth->target, krb5_token);
				}
			} else {
				//gchar * mic = purple_krb5_get_mic_for_sipmsg(&krb5_auth, msg);
				gchar * mic = "MICTODO";
				printf ("krb5 token is NULL, so adding response attribute with mic = %s, op=%s\n", mic, auth->opaque);
				//tmp = g_strdup_printf("Kerberos qop=\"auth\", realm=\"%s\", opaque=\"%s\", targetname=\"%s\", response=\"%s\"", "SIP Communications Service", auth->opaque, auth->target, mic);
				//tmp = g_strdup_printf("Kerberos qop=\"auth\", realm=\"%s\", opaque=\"%s\", targetname=\"%s\"", "SIP Communications Service",
						//auth->opaque ? auth->opaque : "", auth->target);
				tmp = g_strdup_printf("Kerberos qop=\"auth\", realm=\"%s\", targetname=\"%s\"", "SIP Communications Service", auth->target);
				//g_free(mic);
			}*/
			return tmp;
		}
		tmp = g_strdup_printf("Kerberos qop=\"auth\", realm=\"%s\", targetname=\"%s\", gssapi-data=\"\"", "SIP Communication Service", auth->target);
	}

	sprintf(noncecount, "%08d", auth->nc++);
	response = purple_cipher_http_digest_calculate_response(
						"md5", method, target, NULL, NULL,
						auth->nonce, noncecount, NULL, auth->digest_session_key);
	purple_debug(PURPLE_DEBUG_MISC, "sipe", "response %s\n", response);

	ret = g_strdup_printf("Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", nc=\"%s\", response=\"%s\"", authuser, auth->realm, auth->nonce, target, noncecount, response);
	g_free(response);
	return ret;
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

static void fill_auth(struct sipe_account_data *sip, gchar *hdr, struct sip_auth *auth)
{
	int i = 0;
	const char *authuser;
	char *tmp;
	gchar **parts;
	//const char *krb5_realm;
	//const char *host;

        // XXX FIXME: Get this info from the account dialogs and/or /etc/krb5.conf
        //            and do error checking

	// KRB realm should always be uppercase
	/*krb5_realm = g_strup(purple_account_get_string(sip->account, "krb5_realm", ""));

	if (sip->realhostname) {
		host = sip->realhostname;
	} else if (purple_account_get_bool(sip->account, "useproxy", TRUE)) {
		host = purple_account_get_string(sip->account, "proxy", "");
	} else {
		host = sip->sipdomain;
	}*/

	authuser = sip->authuser;

	if (!authuser || strlen(authuser) < 1) {
		authuser = sip->username;
	}

	if (!hdr) {
		purple_debug_error("sipe", "fill_auth: hdr==NULL\n");
		return;
	}

	if (!g_strncasecmp(hdr, "NTLM", 4)) {
		auth->type = AUTH_TYPE_NTLM;
		parts = g_strsplit(hdr+5, "\", ", 0);
		i = 0;
		while (parts[i]) {
			//purple_debug_info("sipe", "parts[i] %s\n", parts[i]);
			if ((tmp = parse_attribute("gssapi-data=\"", parts[i]))) {
				g_free(auth->nonce);
				auth->nonce = g_memdup(purple_ntlm_parse_challenge(tmp, &auth->flags), 8);
				g_free(tmp);
			}
			if ((tmp = parse_attribute("targetname=\"",
					parts[i]))) {
				g_free(auth->target);
				auth->target = tmp;
			}
			else if ((tmp = parse_attribute("realm=\"",
					parts[i]))) {
				g_free(auth->realm);
				auth->realm = tmp;
			}
			else if ((tmp = parse_attribute("opaque=\"", parts[i]))) {
				g_free(auth->opaque);
				auth->opaque = tmp;
			}
			i++;
		}
		g_strfreev(parts);
		auth->nc = 1;
		if (!strstr(hdr, "gssapi-data")) {
			auth->nc = 1;
		} else {
			auth->nc = 3;
                }
		return;
	}

	if (!g_strncasecmp(hdr, "Kerberos", 8)) {
		purple_debug(PURPLE_DEBUG_MISC, "sipe", "setting auth type to Kerberos (3)\r\n");
		auth->type = AUTH_TYPE_KERBEROS;
		purple_debug(PURPLE_DEBUG_MISC, "sipe", "fill_auth - header: %s\r\n", hdr);
		parts = g_strsplit(hdr+9, "\", ", 0);
		i = 0;
		while (parts[i]) {
			purple_debug_info("sipe", "krb - parts[i] %s\n", parts[i]);
			if ((tmp = parse_attribute("gssapi-data=\"", parts[i]))) {
				/*if (krb5_auth.gss_context == NULL) {
					purple_krb5_init_auth(&krb5_auth, authuser, krb5_realm, sip->password, host, "sip");
				}
				auth->nonce = g_memdup(krb5_auth.base64_token, 8);*/
				g_free(tmp);
			}
			if ((tmp = parse_attribute("targetname=\"", parts[i]))) {
				g_free(auth->target);
				auth->target = tmp;
			} else if ((tmp = parse_attribute("realm=\"", parts[i]))) {
				g_free(auth->realm);
				auth->realm = tmp;
			} else if ((tmp = parse_attribute("opaque=\"", parts[i]))) {
				g_free(auth->opaque);
				auth->opaque = tmp;
			}
			i++;
		}
		g_strfreev(parts);
		auth->nc = 3;
		return;
	}

	auth->type = AUTH_TYPE_DIGEST;
	parts = g_strsplit(hdr, " ", 0);
	while (parts[i]) {
		if ((tmp = parse_attribute("nonce=\"", parts[i]))) {
			g_free(auth->nonce);
			auth->nonce = tmp;
		}
		else if ((tmp = parse_attribute("realm=\"", parts[i]))) {
			g_free(auth->realm);
			auth->realm = tmp;
		}
		i++;
	}
	g_strfreev(parts);

	purple_debug(PURPLE_DEBUG_MISC, "sipe", "nonce: %s realm: %s\n", auth->nonce ? auth->nonce : "(null)", auth->realm ? auth->realm : "(null)");
	if (auth->realm) {
		g_free(auth->digest_session_key);
		auth->digest_session_key = purple_cipher_http_digest_calculate_session_key(
				"md5", authuser, auth->realm, sip->password, auth->nonce, NULL);

		auth->nc = 1;
	}
}

static void sipe_canwrite_cb(gpointer data, gint source, PurpleInputCondition cond)
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

static void sipe_canwrite_cb_ssl(gpointer data, gint src, PurpleInputCondition cond)
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

static void send_later_cb(gpointer data, gint source, const gchar *error)
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
	struct sip_connection *conn;

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

	conn = connection_create(sip, gsc->fd);

	purple_ssl_input_add(gsc, sipe_input_cb_ssl, gc);

	return sip;
}

static void send_later_cb_ssl(gpointer data, PurpleSslConnection *gsc, PurpleInputCondition cond)
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
				purple_connection_error(gc, _("Couldn't create socket"));
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

	purple_debug(PURPLE_DEBUG_MISC, "sipe", "\n\nsending - %s\n######\n%s\n######\n\n", ctime(&currtime), buf);
	if (sip->transport == SIPE_TRANSPORT_UDP) {
		if (sendto(sip->fd, buf, writelen, 0, (struct sockaddr*)&sip->serveraddr, sizeof(struct sockaddr_in)) < writelen) {
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
	if (sip->registrar.ntlm_key) {
		struct sipmsg_breakdown msgbd;
		gchar *signature_input_str;
		msgbd.msg = msg;
		sipmsg_breakdown_parse(&msgbd, sip->registrar.realm, sip->registrar.target);
		msgbd.rand = g_strdup_printf("%08x", g_random_int());
		sip->registrar.ntlm_num++;
		msgbd.num = g_strdup_printf("%d", sip->registrar.ntlm_num);
		signature_input_str = sipmsg_breakdown_get_string(&msgbd);
		if (signature_input_str != NULL) {
			msg->signature = purple_ntlm_sipe_signature_make (signature_input_str, sip->registrar.ntlm_key);
			msg->rand = g_strdup(msgbd.rand);
			msg->num = g_strdup(msgbd.num);
			g_free(signature_input_str);
		}
		sipmsg_breakdown_free(&msgbd);
	}

	if (sip->registrar.type && !strcmp(method, "REGISTER")) {
		buf = auth_header(sip, &sip->registrar, msg);
		if (!purple_account_get_bool(sip->account, "krb5", FALSE)) {
			sipmsg_add_header(msg, "Authorization", buf);
		} else {
			sipmsg_add_header_pos(msg, "Proxy-Authorization", buf, 5);
		}
		g_free(buf);
	} else if (!strcmp(method,"SUBSCRIBE") || !strcmp(method,"SERVICE") || !strcmp(method,"MESSAGE") || !strcmp(method,"INVITE") || !strcmp(method, "ACK") || !strcmp(method, "NOTIFY") || !strcmp(method, "BYE") || !strcmp(method, "INFO") || !strcmp(method, "OPTIONS")) {
		sip->registrar.nc = 3;
		sip->registrar.type = AUTH_TYPE_NTLM;

		buf = auth_header(sip, &sip->registrar, msg);
		sipmsg_add_header_pos(msg, "Proxy-Authorization", buf, 5);
	        g_free(buf);
	} else {
		purple_debug_info("sipe", "not adding auth header to msg w/ method %s\n", method);
	}
}

static char *get_contact(struct sipe_account_data  *sip)
{
	return g_strdup(sip->contact);
}

/*
 * unused. Needed?
static char *get_contact_service(struct sipe_account_data  *sip)
{
  return g_strdup_printf("<sip:%s:%d;transport=%s;ms-opaque=d3470f2e1d>;proxy=replace;+sip.instance=\"<urn:uuid:%s>\"", purple_network_get_my_ip(-1), sip->listenport, TRANSPORT_DESCRIPTOR, generateUUIDfromEPID(get_epid()));
        //return g_strdup_printf("<sip:%s:%d;maddr=%s;transport=%s>;proxy=replace", sip->username, sip->listenport, purple_network_get_my_ip(-1), TRANSPORT_DESCRIPTOR);
}
*/

static void send_sip_response(PurpleConnection *gc, struct sipmsg *msg, int code,
		const char *text, const char *body)
{
	gchar *name;
	gchar *value;
	GString *outstr = g_string_new("");
	struct sipe_account_data *sip = gc->proto_data;
	gchar *contact;
	GSList *tmp;

	sipmsg_remove_header(msg, "ms-user-data");

	contact = get_contact(sip);
	sipmsg_remove_header(msg, "Contact");
	sipmsg_add_header(msg, "Contact", contact);
	g_free(contact);

	/* When sending the acknowlegements and errors, the content length from the original
	   message is still here, but there is no body; we need to make sure we're sending the
	   correct content length */
	sipmsg_remove_header(msg, "Content-Length");
	if (body) {
		gchar len[12];
		sprintf(len, "%" G_GSIZE_FORMAT , strlen(body));
		sipmsg_add_header(msg, "Content-Length", len);
	} else {
		sipmsg_remove_header(msg, "Content-Type");
		sipmsg_add_header(msg, "Content-Length", "0");
	}

	//gchar * mic = purple_krb5_get_mic_for_sipmsg(&krb5_auth, msg);
	//gchar * mic = "MICTODO";
	msg->response = code;

	sipmsg_remove_header(msg, "Authentication-Info");
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
	if (trans->msg) sipmsg_free(trans->msg);
	sip->transactions = g_slist_remove(sip->transactions, trans);
	g_free(trans);
}

static struct transaction *
transactions_add_buf(struct sipe_account_data *sip, const struct sipmsg *msg, void *callback)
{
	struct transaction *trans = g_new0(struct transaction, 1);
	trans->time = time(NULL);
	trans->msg = (struct sipmsg *)msg;
	trans->cseq = sipmsg_find_header(trans->msg, "CSeq");
	trans->callback = callback;
	sip->transactions = g_slist_append(sip->transactions, trans);
	return trans;
}

static struct transaction *transactions_find(struct sipe_account_data *sip, struct sipmsg *msg)
{
	struct transaction *trans;
	GSList *transactions = sip->transactions;
	gchar *cseq = sipmsg_find_header(msg, "CSeq");

	while (transactions) {
		trans = transactions->data;
		if (!strcmp(trans->cseq, cseq)) {
			return trans;
		}
		transactions = transactions->next;
	}

	return NULL;
}

static struct transaction *
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
	gchar *useragent = (gchar *)purple_account_get_string(sip->account, "useragent", "Purple/" VERSION);
	gchar *route     = strdup("");
	gchar *epid      = get_epid(sip); // TODO generate one per account/login
	struct transaction *trans;

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
			dialog ? ++dialog->cseq : ++sip->cseq,
			method,
			useragent,
			callid,
			route,
			addh,
			body ? strlen(body) : 0,
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
	trans = transactions_add_buf(sip, msg, tc);
	sendout_pkt(gc, buf);
	g_free(buf);

	return trans;
}

static void send_soap_request_with_cb(struct sipe_account_data *sip, gchar *body, TransCallback callback, void * payload)
{
	gchar *from = g_strdup_printf("sip:%s", sip->username);
	gchar *contact = get_contact(sip);
	gchar *hdr = g_strdup_printf("Contact: %s\r\n"
	                             "Content-Type: application/SOAP+xml\r\n",contact);

	struct transaction * tr = send_sip_request(sip->gc, "SERVICE", from, from, hdr, body, NULL, callback);
	tr->payload = payload;

	g_free(from);
	g_free(contact);
	g_free(hdr);
}

static void send_soap_request(struct sipe_account_data *sip, gchar *body)
{
	send_soap_request_with_cb(sip, body, NULL, NULL);
}

static char *get_contact_register(struct sipe_account_data  *sip)
{
	char *epid = get_epid(sip);
	char *uuid = generateUUIDfromEPID(epid);
	char *buf = g_strdup_printf("<sip:%s:%d;transport=%s;ms-opaque=d3470f2e1d>;methods=\"INVITE, MESSAGE, INFO, SUBSCRIBE, OPTIONS, BYE, CANCEL, NOTIFY, ACK, BENOTIFY\";proxy=replace;+sip.instance=\"<urn:uuid:%s>\"", purple_network_get_my_ip(-1), sip->listenport,  TRANSPORT_DESCRIPTOR, uuid);
	g_free(uuid);
	g_free(epid);
	return(buf);
}

static void do_register_exp(struct sipe_account_data *sip, int expire)
{
	char *expires = expire >= 0 ? g_strdup_printf("Expires: %d\r\n", expire) : g_strdup("");
	char *uri = g_strdup_printf("sip:%s", sip->sipdomain);
	char *to = g_strdup_printf("sip:%s", sip->username);
	char *contact = get_contact_register(sip);
	char *hdr = g_strdup_printf("Contact: %s\r\n"
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

static void do_register_cb(struct sipe_account_data *sip)
{
	do_register_exp(sip, -1);
	sip->reregister_set = FALSE;
}

static void do_register(struct sipe_account_data *sip)
{
	do_register_exp(sip, -1);
}

/**
 * Returns URI from provided To or From header.
 *
 * Needs to g_free() after use.
 *
 * @return URI with sip: prefix
 */
static gchar *parse_from(const gchar *hdr)
{
	gchar *from;
	const gchar *tmp, *tmp2 = hdr;

	if (!hdr) return NULL;
	purple_debug_info("sipe", "parsing address out of %s\n", hdr);
	tmp = strchr(hdr, '<');

	/* i hate the different SIP UA behaviours... */
	if (tmp) { /* sip address in <...> */
		tmp2 = tmp + 1;
		tmp = strchr(tmp2, '>');
		if (tmp) {
			from = g_strndup(tmp2, tmp - tmp2);
		} else {
			purple_debug_info("sipe", "found < without > in From\n");
			return NULL;
		}
	} else {
		tmp = strchr(tmp2, ';');
		if (tmp) {
			from = g_strndup(tmp2, tmp - tmp2);
		} else {
			from = g_strdup(tmp2);
		}
	}
	purple_debug_info("sipe", "got %s\n", from);
	return from;
}

static xmlnode * xmlnode_get_descendant(xmlnode * parent, ...)
{
	va_list args;
	xmlnode * node = NULL;
	const gchar * name;

	va_start(args, parent);
	while ((name = va_arg(args, const char *)) != NULL) {
		node = xmlnode_get_child(parent, name);
		if (node == NULL) return NULL;
		parent = node;
	}
	va_end(args);

	return node;
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
				NULL, // id
				alias,
				NULL, // message
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

static struct sipe_group * sipe_group_find_by_name (struct sipe_account_data *sip, gchar * name)
{
	struct sipe_group *group;
	GSList *entry;
	if (sip == NULL) {
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

static gboolean process_add_group_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc)
{
	if (msg->response == 200) {
		struct sipe_group *group;
		struct group_user_context *ctx = (struct group_user_context*)tc->payload;
		xmlnode *xml;
		xmlnode *node;
		char *group_id;
		struct sipe_buddy *buddy;

		xml = xmlnode_from_str(msg->body, msg->bodylen);
		if (!xml) {
			g_free(ctx);
			return FALSE;
		}

		node = xmlnode_get_descendant(xml, "Body", "addGroup", "groupID", NULL);
		if (!node) {
			g_free(ctx);
			xmlnode_free(xml);
			return FALSE;
		}

		group_id = xmlnode_get_data(node);
		if (!group_id) {
			g_free(ctx);
			xmlnode_free(xml);
			return FALSE;
		}

		group = g_new0(struct sipe_group, 1);
		group->id = (int)g_ascii_strtod(group_id, NULL);
		g_free(group_id);
		group->name = ctx->group_name;

		sipe_group_add(sip, group);

		buddy = g_hash_table_lookup(sip->buddies, ctx->user_name);
		if (buddy) {
			buddy->groups = slist_insert_unique_sorted(buddy->groups, group, (GCompareFunc)sipe_group_compare);
		}

		sipe_group_set_user(sip, ctx->user_name);

		g_free(ctx);
		xmlnode_free(xml);
		return TRUE;
	}
	return FALSE;
}

static void sipe_group_create (struct sipe_account_data *sip, gchar *name, gchar * who)
{
	struct group_user_context * ctx = g_new0(struct group_user_context, 1);
	gchar *body;
	ctx->group_name = g_strdup(name);
	ctx->user_name = g_strdup(who);

	body = g_markup_printf_escaped(SIPE_SOAP_ADD_GROUP, name, sip->contacts_delta++);
	send_soap_request_with_cb(sip, body, process_add_group_response, ctx);
	g_free(body);
}

/**
  * A timer callback
  * Should return FALSE if repetitive action is not needed
  */
gboolean sipe_scheduled_exec(struct scheduled_action *sched_action)
{
	gboolean ret;
	purple_debug_info("sipe", "sipe_scheduled_exec: executing\n");
	sched_action->sip->timeouts = g_slist_remove(sched_action->sip->timeouts, sched_action);
	purple_debug_info("sipe", "sip->timeouts count:%d after removal\n",g_slist_length(sched_action->sip->timeouts));
	(sched_action->action)(sched_action->sip, sched_action->payload);
	ret = sched_action->repetitive;
	g_free(sched_action->payload);
	g_free(sched_action->name);
	g_free(sched_action);
	return ret;
}

/**
  * Do schedule action for execution in the future.
  * Non repetitive execution.
  *
  * @param   name of action (will be copied)
  * @param   timeout in seconds
  * @action  callback function
  * @payload callback data (can be NULL, otherwise caller must allocate memory)
  */
void sipe_schedule_action(gchar *name, int timeout, Action action, struct sipe_account_data *sip, void * payload)
{
	struct scheduled_action *sched_action;

	purple_debug_info("sipe","scheduling action %s timeout:%d\n", name, timeout);
	sched_action = g_new0(struct scheduled_action, 1);
	sched_action->repetitive = FALSE;
	sched_action->name = g_strdup(name);
	sched_action->action = action;
	sched_action->sip = sip;
	sched_action->payload = payload;
	sched_action->timeout_handler = purple_timeout_add_seconds(timeout, (GSourceFunc) sipe_scheduled_exec, sched_action);
	sip->timeouts = g_slist_append(sip->timeouts, sched_action);
	purple_debug_info("sipe", "sip->timeouts count:%d after addition\n",g_slist_length(sip->timeouts));
}

/**
  * Kills action timer effectively cancelling
  * scheduled action
  *
  * @param name of action
  */
void sipe_cancel_scheduled_action(struct sipe_account_data *sip, gchar *name)
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
			g_free(sched_action->payload);
			g_free(sched_action->name);
			g_free(sched_action);
		} else {
			entry = entry->next;
		}
	}
}

static void process_incoming_notify(struct sipe_account_data *sip, struct sipmsg *msg, gboolean request, gboolean benotify);

static gboolean process_subscribe_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc)
{
		if (sipmsg_find_header(msg, "ms-piggyback-cseq"))
		{
			process_incoming_notify(sip, msg, FALSE, FALSE);
		}
		return TRUE;
}

static void sipe_subscribe_resource_uri(const char *name, gpointer value, gchar **resources_uri)
{
	gchar *tmp = *resources_uri;
        *resources_uri = g_strdup_printf("%s<resource uri=\"%s\"/>\n", tmp, name);
	g_free(tmp);
}

static void sipe_subscribe_resource_uri_with_context(const char *name, gpointer value, gchar **resources_uri)
{
	gchar *tmp = *resources_uri;
        *resources_uri = g_strdup_printf("%s<resource uri=\"%s\"><context/></resource>\n", tmp, name);
	g_free(tmp);
}

/**
   *   Support for Batch Category SUBSCRIBE [MS-PRES] - msrtc-event-categories+xml  OCS 2007
   *   Support for Batch Category SUBSCRIBE [MS-SIP] - adrl+xml LCS 2005
   *   The user sends an initial batched category SUBSCRIBE request against all contacts on his roaming list in only a request
   *   A batch category SUBSCRIBE request MUST have the same To-URI and From-URI.
   *   This header will be send only if adhoclist there is a "Supported: adhoclist" in REGISTER answer else will be send a Single Category SUBSCRIBE
  */

static void sipe_subscribe_presence_batched(struct sipe_account_data *sip){
	gchar *to = g_strdup_printf("sip:%s", sip->username);
	gchar *contact = get_contact(sip);
	gchar *request;
	gchar *content;
	gchar *resources_uri = g_strdup("");
	gchar *require = "";
	gchar *accept = "";
        gchar *autoextend = "";
	gchar *content_type;

	
    if (sip->msrtc_event_categories) {
                g_hash_table_foreach(sip->buddies, (GHFunc) sipe_subscribe_resource_uri_with_context , &resources_uri);
		require = ", categoryList";
		accept = ", application/msrtc-event-categories+xml, application/xpidf+xml, application/pidf+xml";
                content_type = "application/msrtc-adrl-categorylist+xml";
                content = g_strdup_printf(
					  "<batchSub xmlns=\"http://schemas.microsoft.com/2006/01/sip/batch-subscribe\" uri=\"sip:%s\" name=\"\">\n"
					  "<action name=\"subscribe\" id=\"63792024\">\n"
					  "<adhocList>\n%s</adhocList>\n"
					  "<categoryList xmlns=\"http://schemas.microsoft.com/2006/09/sip/categorylist\">\n"
					  "<category name=\"note\"/>\n"
					  "<category name=\"state\"/>\n"
					  "</categoryList>\n"
					  "</action>\n"
					  "</batchSub>", sip->username, resources_uri);
	} else {
                g_hash_table_foreach(sip->buddies, (GHFunc) sipe_subscribe_resource_uri, &resources_uri);
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
	//send_sip_request(sip->gc, "SUBSCRIBE", resource_uri,  resource_uri, request, content, NULL, process_subscribe_response);
	send_sip_request(sip->gc, "SUBSCRIBE", to,  to, request, content, NULL, process_subscribe_response);

	g_free(content);
	g_free(to);
	g_free(request);
}

/**
  * Single Category SUBSCRIBE [MS-PRES] ; To send when the server returns a 200 OK message with state="resubscribe" in response.
  * The user sends a single SUBSCRIBE request to the subscribed contact.
  * The To-URI and the URI listed in the resource list MUST be the same for a single category SUBSCRIBE request.
  *
  */

static void sipe_subscribe_presence_single(struct sipe_account_data *sip, const char * buddy_name)
{
	gchar *to = strstr(buddy_name, "sip:") ? g_strdup(buddy_name) : g_strdup_printf("sip:%s", buddy_name);
	gchar *tmp = get_contact(sip);
	gchar *request;
	gchar *content;
    request = g_strdup_printf(
    "Accept: application/msrtc-event-categories+xml,  text/xml+msrtc.pidf, application/xpidf+xml, application/pidf+xml, application/rlmi+xml, multipart/related\r\n"
    "Supported: ms-piggyback-first-notify\r\n"
    "Supported: com.microsoft.autoextend\r\n"
    "Supported: ms-benotify\r\n"
    "Proxy-Require: ms-benotify\r\n"
    "Event: presence\r\n"
    "Content-Type: application/msrtc-adrl-categorylist+xml\r\n"
    "Contact: %s\r\n", tmp);

	content = g_strdup_printf(
     "<batchSub xmlns=\"http://schemas.microsoft.com/2006/01/sip/batch-subscribe\" uri=\"sip:%s\" name=\"\">\n"
     "<action name=\"subscribe\" id=\"63792024\"><adhocList>\n"
     "<resource uri=\"%s\"/>\n"
     "</adhocList>\n"
     "<categoryList xmlns=\"http://schemas.microsoft.com/2006/09/sip/categorylist\">\n"
     "<category name=\"note\"/>\n"
     "<category name=\"state\"/>\n"
     "</categoryList>\n"
     "</action>\n"
     "</batchSub>", sip->username, to
		);

	g_free(tmp);

	/* subscribe to buddy presence */
	send_sip_request(sip->gc, "SUBSCRIBE", to, to, request, content, NULL, process_subscribe_response);

	g_free(content);
	g_free(to);
	g_free(request);
}

static void sipe_set_status(PurpleAccount *account, PurpleStatus *status)
{
	if (!purple_status_is_active(status))
		return;

	if (account->gc) {
		struct sipe_account_data *sip = account->gc->proto_data;

		if (sip) {
			g_free(sip->status);
			sip->status = g_strdup(purple_status_get_id(status));
			send_presence_status(sip);
		}
	}
}

static void
sipe_alias_buddy(PurpleConnection *gc, const char *name, const char *alias)
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
		old_group = sipe_group_find_by_name(sip, g_strdup(old_group_name));
	}
	new_group = sipe_group_find_by_name(sip, g_strdup(new_group_name));

	if (old_group) {
		buddy->groups = g_slist_remove(buddy->groups, old_group);
		purple_debug_info("sipe", "buddy %s removed from old group %s\n", who, old_group_name);
	}

	if (!new_group) {
 		sipe_group_create(sip, g_strdup(new_group_name), g_strdup(who));
 	} else {
		buddy->groups = slist_insert_unique_sorted(buddy->groups, new_group, (GCompareFunc)sipe_group_compare);
		sipe_group_set_user(sip, who);
 	}
}

static void sipe_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
	struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;
	struct sipe_buddy *b;

	purple_debug_info("sipe", "sipe_add_buddy[CB]: buddy:%s group:%s\n", buddy ? buddy->name : "", group ? group->name : "");

	// Prepend sip: if needed
	if (strncmp("sip:", buddy->name, 4)) {
		gchar *buf = g_strdup_printf("sip:%s", buddy->name);
		purple_blist_rename_buddy(buddy, buf);
		g_free(buf);
	}

	if (!g_hash_table_lookup(sip->buddies, buddy->name)) {
		b = g_new0(struct sipe_buddy, 1);
		purple_debug_info("sipe", "sipe_add_buddy %s\n", buddy->name);
		b->name = g_strdup(buddy->name);
		g_hash_table_insert(sip->buddies, b->name, b);
		sipe_group_buddy(gc, b->name, NULL, group->name);
		sipe_subscribe_presence_single(sip, b->name); //@TODO should go to callback
	} else {
		purple_debug_info("sipe", "buddy %s already in internal list\n", buddy->name);
	}
}

static void sipe_free_buddy(struct sipe_buddy *buddy)
{
	g_free(buddy->name);
	g_free(buddy->annotation);
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
	struct sipe_buddy *b = g_hash_table_lookup(sip->buddies, buddy->name);
	struct sipe_group *g = NULL;

	purple_debug_info("sipe", "sipe_remove_buddy[CB]: buddy:%s group:%s\n", buddy ? buddy->name : "", group ? group->name : "");

	if (!b) return;

	if (group) {
		g = sipe_group_find_by_name(sip, group->name);
	}

	if (g) {
		b->groups = g_slist_remove(b->groups, g);
		purple_debug_info("sipe", "buddy %s removed from group %s\n", buddy->name, g->name);
	}

	if (g_slist_length(b->groups) < 1) {
		gchar *action_name = g_strdup_printf("<%s><%s>", "presence", buddy->name);
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
		  GList *moved_buddies)
{
	struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;
	struct sipe_group * s_group = sipe_group_find_by_name(sip, g_strdup(old_name));
	if (group) {
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

static GList *sipe_status_types(PurpleAccount *acc)
{
	PurpleStatusType *type;
	GList *types = NULL;

	// Online
	type = purple_status_type_new_with_attrs(
		PURPLE_STATUS_AVAILABLE, NULL, _("Online"), TRUE, TRUE, FALSE,
		// Translators: noun
		"message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
		NULL);
	types = g_list_append(types, type);

	// Busy
	type = purple_status_type_new_with_attrs(
		PURPLE_STATUS_UNAVAILABLE, SIPE_STATUS_ID_BUSY, _("Busy"), TRUE, TRUE, FALSE,
		"message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
		NULL);
	types = g_list_append(types, type);

	// Do Not Disturb (not user settable)
	type = purple_status_type_new_with_attrs(
		PURPLE_STATUS_UNAVAILABLE, SIPE_STATUS_ID_DND, _("Do Not Disturb"), TRUE, FALSE, FALSE,
		"message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
		NULL);
	types = g_list_append(types, type);

	// Be Right Back
	type = purple_status_type_new_with_attrs(
		PURPLE_STATUS_AWAY, SIPE_STATUS_ID_BRB, _("Be Right Back"), TRUE, TRUE, FALSE,
		"message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
		NULL);
	types = g_list_append(types, type);

	// Away
	type = purple_status_type_new_with_attrs(
		PURPLE_STATUS_AWAY, NULL, NULL, TRUE, TRUE, FALSE,
		"message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
		NULL);
	types = g_list_append(types, type);

	//On The Phone
	type = purple_status_type_new_with_attrs(
		PURPLE_STATUS_UNAVAILABLE, SIPE_STATUS_ID_ONPHONE, _("On The Phone"), TRUE, TRUE, FALSE,
		"message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
		NULL);
	types = g_list_append(types, type);

	//Out To Lunch
	type = purple_status_type_new_with_attrs(
		PURPLE_STATUS_AWAY, SIPE_STATUS_ID_LUNCH, _("Out To Lunch"), TRUE, TRUE, FALSE,
		"message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
		NULL);
	types = g_list_append(types, type);

	//Appear Offline
	type = purple_status_type_new_full(
		PURPLE_STATUS_INVISIBLE, NULL, _("Appear Offline"), TRUE, TRUE, FALSE);
	types = g_list_append(types, type);

	// Offline
	type = purple_status_type_new_full(
		PURPLE_STATUS_OFFLINE, NULL, NULL, TRUE, TRUE, FALSE);
	types = g_list_append(types, type);

	return types;
}

/**
  * A callback for g_hash_table_foreach
  */
static void sipe_buddy_subscribe_cb(char *name, struct sipe_buddy *buddy, struct sipe_account_data *sip)
{
	sipe_subscribe_presence_single(sip, buddy->name);
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
}

static gboolean sipe_process_roaming_contacts(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc)
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

	/* Parse groups */
	for (group_node = xmlnode_get_child(isc, "group"); group_node; group_node = xmlnode_get_next_twin(group_node)) {
		struct sipe_group * group = g_new0(struct sipe_group, 1);
		const char *name = xmlnode_get_attrib(group_node, "name");

		if (!strncmp(name, "~", 1)) {
			// TODO translate
			name = "Other Contacts";
		}
		group->name = g_strdup(name);
		group->id = (int)g_ascii_strtod(xmlnode_get_attrib(group_node, "id"), NULL);

		sipe_group_add(sip, group);
	}

	// Make sure we have at least one group
	if (g_slist_length(sip->groups) == 0) {
		struct sipe_group * group = g_new0(struct sipe_group, 1);
		PurpleGroup *purple_group;
		// TODO translate
		group->name = g_strdup("Other Contacts");
		group->id = 1;
		purple_group = purple_group_new(group->name);
		purple_blist_add_group(purple_group, NULL);
		sip->groups = g_slist_append(sip->groups, group);
	}

	/* Parse contacts */
	for (item = xmlnode_get_child(isc, "contact"); item; item = xmlnode_get_next_twin(item)) {
		gchar * uri = g_strdup(xmlnode_get_attrib(item, "uri"));
		gchar * name = g_strdup(xmlnode_get_attrib(item, "name"));
		gchar * groups = g_strdup(xmlnode_get_attrib(item, "groups"));
		gchar * buddy_name = g_strdup_printf("sip:%s", uri);
		gchar **item_groups;
		struct sipe_group *group = NULL;
		struct sipe_buddy *buddy = NULL;
		int i = 0;

		// assign to group Other Contacts if nothing else received
		if(!groups || !strcmp("", groups) ) {
			group = sipe_group_find_by_name(sip, "Other Contacts");
			groups = group ? g_strdup_printf("%d", group->id) : "1";
		}

		item_groups = g_strsplit(groups, " ", 0);

		while (item_groups[i]) {
			group = sipe_group_find_by_id(sip, g_ascii_strtod(item_groups[i], NULL));

			// If couldn't find the right group for this contact, just put them in the first group we have
			if (group == NULL && g_slist_length(sip->groups) > 0) {
				group = sip->groups->data;
			}

			if (group != NULL) {
				PurpleBuddy *b = purple_find_buddy_in_group(sip->account, buddy_name, group->purple_group);
				if (!b){
					b = purple_buddy_new(sip->account, buddy_name, uri);
					purple_blist_add_buddy(b, NULL, group->purple_group, NULL);
				}

				if (!g_ascii_strcasecmp(uri, purple_buddy_get_alias(b))) {
					if (name != NULL && strlen(name) != 0) {
						purple_blist_alias_buddy(b, name);
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
		g_free(groups);
		g_free(name);
		g_free(buddy_name);
		g_free(uri);

	} // for, contacts

	xmlnode_free(isc);

	sipe_cleanup_local_blist(sip);

	//subscribe to buddies
	if (!sip->subscribed_buddies) { //do it once, then count Expire field to schedule resubscribe.
                //if(sip->msrtc_event_categories){
		        sipe_subscribe_presence_batched(sip);
                 //}else{
                        //g_hash_table_foreach(sip->buddies, (GHFunc)sipe_buddy_subscribe_cb, (gpointer)sip);
                 //}
                sip->subscribed_buddies = TRUE;
	}

	return 0;
}

 /**
  * Subscribe roaming contacts
  */
static void sipe_subscribe_roaming_contacts(struct sipe_account_data *sip,struct sipmsg *msg)
{
	gchar *to = g_strdup_printf("sip:%s", sip->username);
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

static void sipe_subscribe_presence_wpending(struct sipe_account_data *sip, struct sipmsg *msg)
{
	gchar *to = g_strdup_printf("sip:%s", sip->username);
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

	send_sip_request(sip->gc, "SUBSCRIBE", to, to, hdr, "", NULL, process_subscribe_response);
	g_free(to);
	g_free(hdr);
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
			reason = g_strdup(_("You have been signed off because you've signed in at another location"));
		} else if (event && !g_ascii_strcasecmp(event, "rejected")) {
			error_id = 4141;
			reason = g_strdup(_("User disabled")); // [MS-OCER]
		} else if (event && !g_ascii_strcasecmp(event, "deactivated")) {
			error_id = 4142;
			reason = g_strdup(_("User moved")); // [MS-OCER]
		}
	}
	g_free(event);
	warning = g_strdup_printf(_("Unregistered by Server: %s."), reason ? reason : _("no reason given"));
	g_free(reason);

	sip->gc->wants_to_die = TRUE;
	purple_connection_error(sip->gc, warning);
	g_free(warning);

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



/**
  *   When we receive some self (BE) NOTIFY with a new subscriber
  *   we sends a setSubscribers request to him [SIP-PRES] 4.8
  *
  */

static void sipe_process_roaming_self(struct sipe_account_data *sip,struct sipmsg *msg)
{
	gchar *contact;
	gchar *to;
	xmlnode *xml;
	xmlnode *node;
        char *display_name = NULL;
        PurpleBuddy *pbuddy;
        const char *alias;
        char *uri_alias;
        char *uri_user;

	purple_debug_info("sipe", "sipe_process_roaming_self\n");

	xml = xmlnode_from_str(msg->body, msg->bodylen);
	if (!xml) return;

	contact = get_contact(sip);
	to = g_strdup_printf("sip:%s", sip->username);

	for (node = xmlnode_get_descendant(xml, "subscribers", "subscriber", NULL); node; node = xmlnode_get_next_twin(node)) {
		const char *user;
		const char *acknowledged;
		gchar *hdr;
		gchar *body;

		user = xmlnode_get_attrib(node, "user");
		if (!user) continue;
		purple_debug_info("sipe", "sipe_process_roaming_self: user %s\n", user);
		uri_user = g_strdup_printf("sip:%s", user); 
		pbuddy = purple_find_buddy((PurpleAccount *)sip->account, uri_user);
		if(pbuddy){
			alias = purple_buddy_get_local_alias(pbuddy);
			uri_alias = g_strdup_printf("sip:%s", alias);
			display_name = g_strdup(xmlnode_get_attrib(node, "displayName"));
			if (display_name && !g_ascii_strcasecmp(uri_user, uri_alias)) { // 'bad' alias
				purple_debug_info("sipe", "Replacing alias for %s with %s\n", uri_user, display_name);
				purple_blist_alias_buddy(pbuddy, display_name);
			}
			g_free(uri_alias);
		}
		g_free(uri_user);

	        acknowledged= xmlnode_get_attrib(node, "acknowledged");
		if(!g_ascii_strcasecmp(acknowledged,"false")){
                        purple_debug_info("sipe", "sipe_process_roaming_self: user added you %s\n", user);
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
	}

	g_free(to);
	g_free(contact);
	xmlnode_free(xml);
}

static void sipe_subscribe_roaming_acl(struct sipe_account_data *sip,struct sipmsg *msg)
{
	gchar *to = g_strdup_printf("sip:%s", sip->username);
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

static void sipe_subscribe_roaming_self(struct sipe_account_data *sip,struct sipmsg *msg)
{
	gchar *to = g_strdup_printf("sip:%s", sip->username);
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
static void sipe_subscribe_roaming_provisioning(struct sipe_account_data *sip,struct sipmsg *msg)
{
	gchar *to = g_strdup_printf("sip:%s", sip->username);
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

static void sipe_subscribe_roaming_provisioning_v2(struct sipe_account_data *sip,struct sipmsg *msg)
{
	gchar *to = g_strdup_printf("sip:%s", sip->username);
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

/* IM Session (INVITE and MESSAGE methods) */

static struct sip_im_session * find_im_session (struct sipe_account_data *sip, const char *who)
{
	struct sip_im_session *session;
	GSList *entry;
	if (sip == NULL || who == NULL) {
		return NULL;
	}

	entry = sip->im_sessions;
	while (entry) {
		session = entry->data;
		if ((who != NULL && !strcmp(who, session->with))) {
			return session;
		}
		entry = entry->next;
	}
	return NULL;
}

static struct sip_im_session * find_or_create_im_session (struct sipe_account_data *sip, const char *who)
{
	struct sip_im_session *session = find_im_session(sip, who);
	if (!session) {
		session = g_new0(struct sip_im_session, 1);
		session->with = g_strdup(who);
		session->unconfirmed_messages = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
		sip->im_sessions = g_slist_append(sip->im_sessions, session);
	}
	return session;
}

static void im_session_destroy(struct sipe_account_data *sip, struct sip_im_session * session)
{
	struct sip_dialog *dialog = session->dialog;
	GSList *entry;

	sip->im_sessions = g_slist_remove(sip->im_sessions, session);

	if (dialog) {
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
	}
	g_free(session->dialog);

	entry = session->outgoing_message_queue;
	while (entry) {
		g_free(entry->data);
		entry = g_slist_remove(entry, entry->data);
	}
	
	g_hash_table_destroy(session->unconfirmed_messages);

	g_free(session->with);
	g_free(session);
}

static gboolean
process_options_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *trans)
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
	gchar *to = strstr(who, "sip:") ? g_strdup(who) : g_strdup_printf("sip:%s", who);
	gchar *contact = get_contact(sip);
	gchar *request;
    request = g_strdup_printf(
    "Accept: application/sdp\r\n"
    "Contact: %s\r\n", contact);

	g_free(contact);

	send_sip_request(sip->gc, "OPTIONS", to, to, request, NULL, NULL, process_options_response);

	g_free(to);
	g_free(request);
}

static void sipe_present_message_undelivered_err(gchar *with, struct sipe_account_data *sip, gchar *message)
{
	char *msg, *msg_tmp;
	msg_tmp = message ? purple_markup_strip_html(message) : NULL;
	msg = msg_tmp ? g_strdup_printf("<font color=\"#888888\"></b>%s<b></font>", msg_tmp) : NULL;
	g_free(msg_tmp);
	msg_tmp = g_strdup_printf( _("The following message could not be delivered to all recipients, "\
			"possibly because one or more persons are offline:\n%s") ,
			msg ? msg : "");
	purple_conv_present_error(with, sip->account, msg_tmp);
	g_free(msg);
	g_free(msg_tmp);
}

static void sipe_im_process_queue (struct sipe_account_data * sip, struct sip_im_session * session);

static gboolean
process_message_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *trans)
{
	gboolean ret = TRUE;
	gchar * with = parse_from(sipmsg_find_header(msg, "To"));
	struct sip_im_session * session = find_im_session(sip, with);
	struct sip_dialog *dialog;
	gchar *cseq;
	char *key;
	gchar *message;

	if (!session) {
		purple_debug_info("sipe", "process_message_response: unable to find IM session\n");
		g_free(with);
		return FALSE;
	}
	
	dialog = session->dialog;
	if (!dialog) {
		purple_debug_info("sipe", "process_message_response: session outgoing dialog is NULL\n");
		g_free(with);
		return FALSE;
	}
	
	cseq = sipmsg_find_part_of_header(sipmsg_find_header(msg, "CSeq"), NULL, " ", NULL);
	key = g_strdup_printf("<%s><%d><MESSAGE>", sipmsg_find_header(msg, "Call-ID"), atoi(cseq));
	g_free(cseq);
	message = g_hash_table_lookup(session->unconfirmed_messages, key);

	if (msg->response != 200) {
		purple_debug_info("sipe", "process_message_response: MESSAGE response not 200\n");

		sipe_present_message_undelivered_err(with, sip, message);
		im_session_destroy(sip, session);
		ret = FALSE;
	} else {
		g_hash_table_remove(session->unconfirmed_messages, key);
		purple_debug_info("sipe", "process_message_response: removed message %s from unconfirmed_messages(count=%d)\n", 
					key, g_hash_table_size(session->unconfirmed_messages));
	}
	
	g_free(key);
	g_free(with);	
	
	sipe_im_process_queue(sip, session);
	return ret;
}

static void sipe_send_message(struct sipe_account_data *sip, struct sip_im_session * session, const char *msg)
{
	gchar *hdr;
	gchar *fullto;
	gchar *tmp;
	char *msgformat;
	char *msgtext;
	gchar *msgr_value;
	gchar *msgr;

	if (strncmp("sip:", session->with, 4)) {
		fullto = g_strdup_printf("sip:%s", session->with);
	} else {
		fullto = g_strdup(session->with);
	}

	sipe_parse_html(msg, &msgformat, &msgtext);
	purple_debug_info("sipe", "sipe_send_message: msgformat=%s", msgformat);

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
	//hdr = g_strdup("Content-Type: text/plain; charset=UTF-8;msgr=WAAtAE0ATQBTAC0ASQBNAC0ARgBvAHIAbQBhAHQAOgAgAEYATgA9AE0AUwAlADIAMABTAGgAZQBsAGwAJQAyADAARABsAGcAJQAyADAAMgA7ACAARQBGAD0AOwAgAEMATwA9ADAAOwAgAEMAUwA9ADAAOwAgAFAARgA9ADAACgANAAoADQA\r\nSupported: timer\r\n");
	hdr = g_strdup_printf("Contact: %s\r\nContent-Type: text/plain; charset=UTF-8%s\r\n",
			      tmp, msgr);
	g_free(tmp);
	g_free(msgr);

	send_sip_request(sip->gc, "MESSAGE", fullto, fullto, hdr, msgtext, session->dialog, process_message_response);
	g_free(msgtext);
	g_free(hdr);
	g_free(fullto);
}


static void
sipe_im_process_queue (struct sipe_account_data * sip, struct sip_im_session * session)
{
	GSList *entry = session->outgoing_message_queue;
	
	if (session->outgoing_invite) return; //do not send messages until INVITE responded.
	
	while (entry) {
		char *key = g_strdup_printf("<%s><%d><MESSAGE>", session->dialog->callid, (session->dialog->cseq) + 1);
		char *queued_msg = entry->data;
		g_hash_table_insert(session->unconfirmed_messages, g_strdup(key), g_strdup(queued_msg));
		purple_debug_info("sipe", "sipe_im_process_queue: added message %s to unconfirmed_messages(count=%d)\n", 
							key, g_hash_table_size(session->unconfirmed_messages));
		g_free(key);
		sipe_send_message(sip, session, queued_msg);
		entry = session->outgoing_message_queue = g_slist_remove(session->outgoing_message_queue, queued_msg);
		g_free(queued_msg);
	}
}

static void
sipe_get_route_header(struct sipmsg *msg, struct sip_dialog * dialog, gboolean outgoing)
{
        GSList *hdr = msg->headers;
        struct siphdrelement *elem;
        gchar *contact;

        while(hdr)
        {
                elem = hdr->data;
                if(!g_ascii_strcasecmp(elem->name, "Record-Route"))
                {
                        gchar *route = sipmsg_find_part_of_header(elem->value, "<", ">", NULL);
                        dialog->routes = g_slist_append(dialog->routes, route);
                }
                hdr = g_slist_next(hdr);
        }

        if (outgoing)
        {
                dialog->routes = g_slist_reverse(dialog->routes);
        }

        if (dialog->routes)
        {
                dialog->request = dialog->routes->data;
                dialog->routes = g_slist_remove(dialog->routes, dialog->routes->data);
        }

        contact = sipmsg_find_part_of_header(sipmsg_find_header(msg, "Contact"), "<", ">", NULL);
        dialog->routes = g_slist_append(dialog->routes, contact);
}

static void
sipe_get_supported_header(struct sipmsg *msg, struct sip_dialog * dialog, gboolean outgoing)
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

static void
sipe_parse_dialog(struct sipmsg * msg, struct sip_dialog * dialog, gboolean outgoing)
{
	gchar *us = outgoing ? "From" : "To";
	gchar *them = outgoing ? "To" : "From";

	g_free(dialog->callid);
	g_free(dialog->ourtag);
	g_free(dialog->theirtag);

	dialog->callid = g_strdup(sipmsg_find_header(msg, "Call-ID"));
	dialog->ourtag = find_tag(sipmsg_find_header(msg, us));
	dialog->theirtag = find_tag(sipmsg_find_header(msg, them));
	if (!dialog->theirepid) {
		dialog->theirepid = sipmsg_find_part_of_header(sipmsg_find_header(msg, them), "epid=", ";", NULL);
		if (!dialog->theirepid) {
			dialog->theirepid = sipmsg_find_part_of_header(sipmsg_find_header(msg, them), "epid=", NULL, NULL);
		}
	}

	sipe_get_route_header(msg, dialog, outgoing);
	sipe_get_supported_header(msg, dialog, outgoing);
}


static gboolean
process_invite_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *trans)
{
	gchar *with = parse_from(sipmsg_find_header(msg, "To"));
	struct sip_im_session * session = find_im_session(sip, with);
	struct sip_dialog *dialog;
	char *cseq;
	char *key;
	gchar *message;

	if (!session) {
		purple_debug_info("sipe", "process_invite_response: unable to find IM session\n");
		g_free(with);
		return FALSE;
	}

	dialog = session->dialog;
	if (!dialog) {
		purple_debug_info("sipe", "process_invite_response: session outgoing dialog is NULL\n");
		g_free(with);
		return FALSE;
	}
	
	sipe_parse_dialog(msg, dialog, TRUE);
	
	cseq = sipmsg_find_part_of_header(sipmsg_find_header(msg, "CSeq"), NULL, " ", NULL);
	key = g_strdup_printf("<%s><%d><INVITE>", dialog->callid, atoi(cseq));
	g_free(cseq);
	message = g_hash_table_lookup(session->unconfirmed_messages, key);

	if (msg->response != 200) {
		purple_debug_info("sipe", "process_invite_response: INVITE response not 200\n");

		sipe_present_message_undelivered_err(with, sip, message);		
		im_session_destroy(sip, session);
		g_free(with);
		return FALSE;
	}
	
	dialog->cseq = 0;
	send_sip_request(sip->gc, "ACK", session->with, session->with, NULL, NULL, dialog, NULL);
	session->outgoing_invite = NULL;
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


static void sipe_invite(struct sipe_account_data *sip, struct sip_im_session *session, const gchar *msg_body)
{
	gchar *hdr;
	gchar *to;
	gchar *contact;
	gchar *body;
	char *msgformat;
	char *msgtext;
	char *base64_msg;
	char *ms_text_format;
	gchar *msgr_value;
	gchar *msgr;
	char *key;

	if (session->dialog) {
		purple_debug_info("sipe", "session with %s already has a dialog open\n", session->with);
		return;
	}

	session->dialog = g_new0(struct sip_dialog, 1);
	session->dialog->callid = gencallid();

	if (strstr(session->with, "sip:")) {
		to = g_strdup(session->with);
	} else {
		to = g_strdup_printf("sip:%s", session->with);
	}

	sipe_parse_html(msg_body, &msgformat, &msgtext);
	purple_debug_info("sipe", "sipe_invite: msgformat=%s", msgformat);

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
	
	key = g_strdup_printf("<%s><%d><INVITE>", session->dialog->callid, (session->dialog->cseq) + 1);
	g_hash_table_insert(session->unconfirmed_messages, g_strdup(key), g_strdup(msg_body));
	purple_debug_info("sipe", "sipe_im_send: added message %s to unconfirmed_messages(count=%d)\n", 
						key, g_hash_table_size(session->unconfirmed_messages));
	g_free(key);

	contact = get_contact(sip);
	hdr = g_strdup_printf(
		"Contact: %s\r\n%s"
		"Content-Type: application/sdp\r\n",
		contact, ms_text_format);
	g_free(ms_text_format);

	body = g_strdup_printf(
		"v=0\r\n"
		"o=- 0 0 IN IP4 %s\r\n"
		"s=session\r\n"
		"c=IN IP4 %s\r\n"
		"t=0 0\r\n"
		"m=message %d sip null\r\n"
		"a=accept-types:text/plain text/html image/gif "
		"multipart/alternative application/im-iscomposing+xml\r\n",
		purple_network_get_my_ip(-1), purple_network_get_my_ip(-1), sip->realport);

	session->outgoing_invite = send_sip_request(sip->gc, "INVITE",
		to, to, hdr, body, session->dialog, process_invite_response);

	g_free(to);
	g_free(body);
	g_free(hdr);
	g_free(contact);
}

static void
im_session_close (struct sipe_account_data *sip, struct sip_im_session * session)
{
	if (session) {
		send_sip_request(sip->gc, "BYE", session->with, session->with, NULL, NULL, session->dialog, NULL);
		im_session_destroy(sip, session);
	}
}

static void
sipe_convo_closed(PurpleConnection * gc, const char *who)
{
	struct sipe_account_data *sip = gc->proto_data;

	purple_debug_info("sipe", "conversation with %s closed\n", who);
	im_session_close(sip, find_im_session(sip, who));
}

static void
im_session_close_all (struct sipe_account_data *sip)
{
	GSList *entry = sip->im_sessions;
	while (entry) {
		im_session_close (sip, entry->data);
		entry = sip->im_sessions;
	}
}

static int sipe_im_send(PurpleConnection *gc, const char *who, const char *what, PurpleMessageFlags flags)
{
	struct sipe_account_data *sip;
	gchar *to;
	struct sip_im_session *session;

	sip = gc->proto_data;
	to = g_strdup(who);

	purple_debug_info("sipe", "sipe_im_send what='%s'\n", what);

	session = find_or_create_im_session(sip, who);

	// Queue the message
	session->outgoing_message_queue = g_slist_append(session->outgoing_message_queue, g_strdup(what));

	if (session->dialog && session->dialog->callid) {
		sipe_im_process_queue(sip, session);
	} else if (!session->outgoing_invite) {
		// Need to send the INVITE to get the outgoing dialog setup
		sipe_invite(sip, session, what);
	}

	g_free(to);
	return 1;
}

/* End IM Session (INVITE and MESSAGE methods) */

static unsigned int
sipe_send_typing(PurpleConnection *gc, const char *who, PurpleTypingState state)
{
	struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;
	struct sip_im_session *session;

	if (state == PURPLE_NOT_TYPING)
		return 0;

	session = find_im_session(sip, who);

	if (session && session->dialog) {
		send_sip_request(gc, "INFO", who, who,
			"Content-Type: application/xml\r\n",
			SIPE_SEND_TYPING, session->dialog, NULL);
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
		purple_debug_info("sipe", "have open transaction age: %ld\n", currtime-trans->time);
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

static void do_reauthenticate_cb(struct sipe_account_data *sip)
{
	/* register again when security token expires */
	/* we have to start a new authentication as the security token
	 * is almost expired by sending a not signed REGISTER message */
	purple_debug_info("sipe", "do a full reauthentication\n");
	sipe_auth_free(&sip->registrar);
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
	if (!strncmp(contenttype, "text/plain", 10) || !strncmp(contenttype, "text/html", 9)) {

		gchar *html = get_html_message(contenttype, msg->body);		
		serv_got_im(sip->gc, from, html, 0, time(NULL));
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
		purple_debug_info("sipe", "got unknown mime-type");
		send_sip_response(sip->gc, msg, 415, "Unsupported media type", NULL);
	}
	g_free(from);
}

static void process_incoming_invite(struct sipe_account_data *sip, struct sipmsg *msg)
{
	gchar *ms_text_format;
	gchar *from;
	gchar *body;
	struct sip_im_session *session;

	purple_debug_info("sipe", "process_incoming_invite: body:\n%s!\n", msg->body ? msg->body : "");

	// Only accept text invitations
	if (msg->body && !(strstr(msg->body, "m=message") || strstr(msg->body, "m=x-ms-message"))) {
		send_sip_response(sip->gc, msg, 501, "Not implemented", NULL);
		return;
	}

	from = parse_from(sipmsg_find_header(msg, "From"));
	session = find_or_create_im_session (sip, from);
	if (session) {
		if (session->dialog) {
			purple_debug_info("sipe", "process_incoming_invite, session already has dialog!\n");
		} else {
			session->dialog = g_new0(struct sip_dialog, 1);

			sipe_parse_dialog(msg, session->dialog, FALSE);

			session->dialog->callid = g_strdup(sipmsg_find_header(msg, "Call-ID"));
			session->dialog->ourtag = find_tag(sipmsg_find_header(msg, "To"));
			session->dialog->theirtag = find_tag(sipmsg_find_header(msg, "From"));
			session->dialog->theirepid = sipmsg_find_part_of_header(sipmsg_find_header(msg, "From"), "epid=", NULL, NULL);
		}
	} else {
		purple_debug_info("sipe", "process_incoming_invite, failed to find or create IM session\n");
	}

	//ms-text-format: text/plain; charset=UTF-8;msgr=WAAtAE0...DIADQAKAA0ACgA;ms-body=SGk=
	ms_text_format = sipmsg_find_header(msg, "ms-text-format");
	if (ms_text_format) {
		if (!strncmp(ms_text_format, "text/plain", 10) || !strncmp(ms_text_format, "text/html", 9)) {
		
			gchar *html = get_html_message(ms_text_format, NULL);
			if (html) {
				serv_got_im(sip->gc, from, html, 0, time(NULL));
				g_free(html);
				sipmsg_add_header(msg, "Supported", "ms-text-format"); // accepts message received
			}
		}
	}
	g_free(from);

	sipmsg_remove_header(msg, "Ms-Conversation-ID");
	sipmsg_remove_header(msg, "Ms-Text-Format");
	sipmsg_remove_header(msg, "EndPoints");
	sipmsg_remove_header(msg, "User-Agent");
	sipmsg_remove_header(msg, "Roster-Manager");

	sipmsg_add_header(msg, "User-Agent", purple_account_get_string(sip->account, "useragent", "Purple/" VERSION));
	//sipmsg_add_header(msg, "Supported", "ms-renders-gif");

	body = g_strdup_printf(
		"v=0\r\n"
		"o=- 0 0 IN IP4 %s\r\n"
		"s=session\r\n"
		"c=IN IP4 %s\r\n"
		"t=0 0\r\n"
		"m=message %d sip sip:%s\r\n"
		"a=accept-types:text/plain text/html image/gif multipart/alternative application/im-iscomposing+xml\r\n",
		purple_network_get_my_ip(-1), purple_network_get_my_ip(-1),
		sip->realport, sip->username);
	send_sip_response(sip->gc, msg, 200, "OK", body);
	g_free(body);
}

static void process_incoming_options(struct sipe_account_data *sip, struct sipmsg *msg)
{
	gchar *body;

	sipmsg_remove_header(msg, "Ms-Conversation-ID");
	sipmsg_remove_header(msg, "EndPoints");
	sipmsg_remove_header(msg, "User-Agent");

	sipmsg_add_header(msg, "Allow", "INVITE, MESSAGE, INFO, SUBSCRIBE, OPTIONS, BYE, CANCEL, NOTIFY, ACK, BENOTIFY");
	sipmsg_add_header(msg, "User-Agent", purple_account_get_string(sip->account, "useragent", "Purple/" VERSION));

	body = g_strdup_printf(
		"v=0\r\n"
		"o=- 0 0 IN IP4 0.0.0.0\r\n"
		"s=session\r\n"
		"c=IN IP4 0.0.0.0\r\n"
		"t=0 0\r\n"
		"m=message %d sip sip:%s\r\n"
		"a=accept-types:text/plain text/html image/gif multipart/alternative application/im-iscomposing+xml\r\n",
		sip->realport, sip->username);
	send_sip_response(sip->gc, msg, 200, "OK", body);
	g_free(body);
}

static void sipe_connection_cleanup(struct sipe_account_data *);
static void create_connection(struct sipe_account_data *, gchar *, int);

gboolean process_register_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc)
{
	gchar *tmp;
	//gchar krb5_token;
	const gchar *expires_header;
	int expires, i;
        GSList *hdr = msg->headers;
        GSList *entry; 
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

				if (!sip->reregister_set) {
					gchar *action_name = g_strdup_printf("<%s>", "registration");
					sipe_schedule_action(action_name, expires, (Action) do_register_cb, sip, NULL);
					g_free(action_name);
					sip->reregister_set = TRUE;
				}

				sip->registerstatus = 3;

				if (!sip->reauthenticate_set) {
					/* we have to reauthenticate as our security token expires
					   after eight hours (be five minutes early) */
					gchar *action_name = g_strdup_printf("<%s>", "+reauthentication");
					guint reauth_timeout = (8 * 3600) - 360;
					sipe_schedule_action(action_name, reauth_timeout, (Action) do_reauthenticate_cb, sip, NULL);
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
                                sip->msrtc_event_categories = FALSE;

                                while(hdr)
                                {
                                        elem = hdr->data;
					if (!g_ascii_strcasecmp(elem->name, "Supported")) {
                                                if (strstr(elem->value, "msrtc-event-categories")) {
                                                        sip->msrtc_event_categories = TRUE;
                                                }
						purple_debug(PURPLE_DEBUG_MISC, "sipe", "Supported: %s, %d\n", elem->value, sip->msrtc_event_categories);
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

				if (!sip->subscribed) { //do it just once, not every re-register
					if(!sip->msrtc_event_categories){ //Only for LCS2005, on OCS2007 always backs the error 504 Server time-out
						sipe_options_request(sip, sip->sipdomain);
					}
					entry = sip->allow_events; 
					while (entry) {
						tmp = entry->data;
						if (tmp && !g_ascii_strcasecmp(tmp, "vnd-microsoft-roaming-contacts")) {
							sipe_subscribe_roaming_contacts(sip, msg);
						}
						if (tmp && !g_ascii_strcasecmp(tmp,"vnd-microsoft-roaming-ACL")) {
							sipe_subscribe_roaming_acl(sip, msg);
						}
						if (tmp && !g_ascii_strcasecmp(tmp,"vnd-microsoft-roaming-self")) {
							sipe_subscribe_roaming_self(sip, msg);
						}
						if (tmp && !g_ascii_strcasecmp(tmp,"vnd-microsoft-provisioning-v2")) {
							sipe_subscribe_roaming_provisioning_v2(sip, msg);
						} else if (tmp && !g_ascii_strcasecmp(tmp,"vnd-microsoft-provisioning")) { // LSC2005
							sipe_subscribe_roaming_provisioning(sip, msg);
						}
						if (tmp && !g_ascii_strcasecmp(tmp,"presence.wpending")) {
							sipe_subscribe_presence_wpending(sip, msg);
						}
						entry = entry->next;
					}
					sipe_set_status(sip->account, purple_account_get_active_status(sip->account));
					sip->subscribed = TRUE;
				}

				if (purple_account_get_bool(sip->account, "clientkeepalive", FALSE)) {
					purple_debug(PURPLE_DEBUG_MISC, "sipe", "Setting user defined keepalive\n");
					sip->keepalive_timeout = purple_account_get_int(sip->account, "keepalive", 0);
				} else {
				tmp = sipmsg_find_header(msg, "ms-keep-alive");
				if (tmp) {
					sipe_keep_alive_timeout(sip, tmp);
					}
				}

				// Should we remove the transaction here?
				purple_debug(PURPLE_DEBUG_MISC, "sipe", "process_register_response - got 200, removing CSeq: %d\r\n", sip->cseq);
				transactions_remove(sip, tc);
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
					purple_connection_error(sip->gc, _("Wrong Password"));
					return TRUE;
				}
				if (!purple_account_get_bool(sip->account, "krb5", FALSE)) {
					tmp = sipmsg_find_auth_header(msg, "NTLM");
				} else {
					tmp = sipmsg_find_auth_header(msg, "Kerberos");
				}
				purple_debug(PURPLE_DEBUG_MISC, "sipe", "process_register_response - Auth header: %s\r\n", tmp);
				fill_auth(sip, tmp, &sip->registrar);
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
				if (warning != NULL) {
					/* Example header:
					   Warning: 310 lcs.microsoft.com "You are currently not using the recommended version of the client"
					*/
					gchar **tmp = g_strsplit(warning, "\"", 0);
					warning = g_strdup_printf(_("You have been rejected by the server: %s"), tmp[1] ? tmp[1] : _("no reason given"));
					g_strfreev(tmp);
				} else {
					warning = g_strdup(_("You have been rejected by the server"));
				}

				sip->gc->wants_to_die = TRUE;
				purple_connection_error(sip->gc, warning);
				g_free(warning);
				return TRUE;
			}
			break;
			case 404:
			{
				gchar *warning = sipmsg_find_header(msg, "ms-diagnostics");
				if (warning != NULL) {
					gchar *reason = sipmsg_find_part_of_header(warning, "reason=\"", "\"", NULL);
					warning = g_strdup_printf(_("Not Found: %s. Please, contact with your Administrator"), reason ? reason : _("no reason given"));
					g_free(reason);
				} else {
					warning = g_strdup(_("Not Found: Destination URI either not enabled for SIP or does not exist. Please, contact with your Administrator"));
				}

				sip->gc->wants_to_die = TRUE;
				purple_connection_error(sip->gc, warning);
				g_free(warning);
				return TRUE;
			}
			break;
                case 503:
                        {
				gchar *warning = sipmsg_find_header(msg, "ms-diagnostics");
				if (warning != NULL) {
					gchar *reason = sipmsg_find_part_of_header(warning, "reason=\"", "\"", NULL);
					warning = g_strdup_printf(_("Service unavailable: %s"), reason ? reason : _("no reason given"));
					g_free(reason);
				} else {
					warning = g_strdup(_("Service unavailable: no reason given"));
				}

				sip->gc->wants_to_die = TRUE;
				purple_connection_error(sip->gc, warning);
				g_free(warning);
				return TRUE;
			}
			break;
		}
	return TRUE;
}

static void process_incoming_notify_rlmi(struct sipe_account_data *sip, const gchar *data, unsigned len)
{
	const char *uri;
	xmlnode *xn_categories;
	xmlnode *xn_category;
	xmlnode *xn_node;
	const char *activity = NULL;

	xn_categories = xmlnode_from_str(data, len);
	uri = xmlnode_get_attrib(xn_categories, "uri");

	for (xn_category = xmlnode_get_child(xn_categories, "category");
		 xn_category ;
		 xn_category = xmlnode_get_next_twin(xn_category) )
	{
		const char *attrVar = xmlnode_get_attrib(xn_category, "name");

		if (!strcmp(attrVar, "note"))
		{
			char *note;
			struct sipe_buddy *sbuddy;
			xn_node = xmlnode_get_child(xn_category, "note");
			if (!xn_node) continue;
			xn_node = xmlnode_get_child(xn_node, "body");
			if (!xn_node) continue;

			note = xmlnode_get_data(xn_node);
                        
                        if(uri){
			        sbuddy = g_hash_table_lookup(sip->buddies, uri);
                        } 
			if (sbuddy && note)
			{
                                purple_debug_info("sipe", "process_incoming_notify_rlmi: uri(%s),note(%s)\n",uri,note);
				if (sbuddy->annotation) { g_free(sbuddy->annotation); }
				sbuddy->annotation = g_strdup(note);
                        }
                        if(note)
			   g_free(note);
		}
		else if(!strcmp(attrVar, "state"))
		{
			char *data;
			int avail;
			xn_node = xmlnode_get_child(xn_category, "state");
			if (!xn_node) continue;
			xn_node = xmlnode_get_child(xn_node, "availability");
			if (!xn_node) continue;

			data = xmlnode_get_data(xn_node);
			avail = atoi(data);
			g_free(data);

			if (avail < 3000)
				activity = SIPE_STATUS_ID_UNKNOWN;
			else if (avail < 4500)
				activity = SIPE_STATUS_ID_AVAILABLE;
			else if (avail < 6000)
				activity = SIPE_STATUS_ID_BRB;
			else if (avail < 7500)
				activity = SIPE_STATUS_ID_ONPHONE;
			else if (avail < 9000)
				activity = SIPE_STATUS_ID_BUSY;
			else if (avail < 12000)
				activity = SIPE_STATUS_ID_DND;
			else if (avail < 18000)
				activity = SIPE_STATUS_ID_AWAY;
			else
				activity = SIPE_STATUS_ID_OFFLINE;
		}
	}
	if(activity) {
		purple_debug_info("sipe", "process_incoming_notify_rlmi: %s\n", activity);
		purple_prpl_got_user_status(sip->account, uri, activity, NULL);
	}

	xmlnode_free(xn_categories);
}

 static void process_incoming_notify_rlmi_resub(struct sipe_account_data *sip, const gchar *data, unsigned len)
{
         const char *uri,*state;
         xmlnode *xn_list;
         xmlnode *xn_resource;
         xmlnode *xn_instance;

         xn_list = xmlnode_from_str(data, len);

        for (xn_resource = xmlnode_get_child(xn_list, "resource");
		 xn_resource;
		 xn_resource = xmlnode_get_next_twin(xn_resource) )
	{
                xn_instance = xmlnode_get_child(xn_resource, "instance");
                if (!xn_instance) return;

                state = xmlnode_get_attrib(xn_instance, "state");
                uri = xmlnode_get_attrib(xn_instance, "cid");
                purple_debug_info("sipe", "process_incoming_notify_rlmi_resub: uri(%s),state(%s)\n",uri,state);
                if(strstr(state,"resubscribe")){
                        sipe_subscribe_presence_single(sip, uri);
                }
      }
}

static void process_incoming_notify_pidf(struct sipe_account_data *sip, const gchar *data, unsigned len)
{
	const gchar *uri;
	gchar *getbasic;
	gchar *activity = NULL;
	xmlnode *pidf;
	xmlnode *basicstatus = NULL, *tuple, *status;
	gboolean isonline = FALSE;
	xmlnode *display_name_node;

	pidf = xmlnode_from_str(data, len);
	if (!pidf) {
		purple_debug_info("sipe", "process_incoming_notify: no parseable pidf:%s\n",data);
		return;
	}

	uri = xmlnode_get_attrib(pidf, "entity");

	if ((tuple = xmlnode_get_child(pidf, "tuple")))
	{
		if ((status = xmlnode_get_child(tuple, "status"))) {
			basicstatus = xmlnode_get_child(status, "basic");
		}
	}

	if (!basicstatus) {
		purple_debug_info("sipe", "process_incoming_notify: no basic found\n");
		xmlnode_free(pidf);
		return;
	}

	getbasic = xmlnode_get_data(basicstatus);
	if (!getbasic) {
		purple_debug_info("sipe", "process_incoming_notify: no basic data found\n");
		xmlnode_free(pidf);
		return;
	}

	purple_debug_info("sipe", "process_incoming_notify: basic-status(%s)\n", getbasic);
	if (strstr(getbasic, "open")) {
		isonline = TRUE;
	}
	g_free(getbasic);

	display_name_node = xmlnode_get_child(pidf, "display-name");
	// updating display name if alias was just URI
	if (display_name_node) {
		GSList *buddies = purple_find_buddies(sip->account, uri); //all buddies in different groups
		GSList *entry = buddies;
		PurpleBuddy *p_buddy;
		char * display_name = xmlnode_get_data(display_name_node);

		while (entry) {
			const char *server_alias;
			char *alias;

			p_buddy = entry->data;

			alias = (char *)purple_buddy_get_alias(p_buddy);
			alias = alias ? g_strdup_printf("sip:%s", alias) : NULL;
			if (!alias || !g_ascii_strcasecmp(uri, alias)) {
				purple_debug_info("sipe", "Replacing alias for %s with %s\n", uri, display_name);
				purple_blist_alias_buddy(p_buddy, display_name);
			}
			g_free(alias);

			server_alias = purple_buddy_get_server_alias(p_buddy);
			if (display_name &&
				( (server_alias && strcmp(display_name, server_alias))
					|| !server_alias || strlen(server_alias) == 0 )
				) {
				purple_blist_server_alias_buddy(p_buddy, display_name);
			}

			entry = entry->next;
		}
		g_free(display_name);
	}

	if ((tuple = xmlnode_get_child(pidf, "tuple"))) {
		if ((status = xmlnode_get_child(tuple, "status"))) {
			if ((basicstatus = xmlnode_get_child(status, "activities"))) {
				if ((basicstatus = xmlnode_get_child(basicstatus, "activity"))) {
					activity = xmlnode_get_data(basicstatus);
					purple_debug_info("sipe", "process_incoming_notify: activity(%s)\n", activity);
				}
			}
		}
	}

	if (isonline) {
		const gchar * status_id = NULL;
		if (activity) {
			if (strstr(activity, "busy")) {
				status_id = SIPE_STATUS_ID_BUSY;
			} else if (strstr(activity, "away")) {
				status_id = SIPE_STATUS_ID_AWAY;
			}
		}

		if (!status_id) {
			status_id = SIPE_STATUS_ID_AVAILABLE;
		}

		purple_debug_info("sipe", "process_incoming_notify: status_id(%s)\n", status_id);
		purple_prpl_got_user_status(sip->account, uri, status_id, NULL);
	} else {
		purple_prpl_got_user_status(sip->account, uri, SIPE_STATUS_ID_OFFLINE, NULL);
	}

	g_free(activity);
	xmlnode_free(pidf);
}

static void process_incoming_notify_msrtc(struct sipe_account_data *sip, const gchar *data, unsigned len)
{
	const char *availability;
	const char *activity;
	const char *display_name = NULL;
	const char *activity_name;
	const char *name;
	char *uri;
	int avl;
	int act;
	struct sipe_buddy *sbuddy;

	xmlnode *xn_presentity = xmlnode_from_str(data, len);

	xmlnode *xn_availability = xmlnode_get_child(xn_presentity, "availability");
	xmlnode *xn_activity = xmlnode_get_child(xn_presentity, "activity");
	xmlnode *xn_display_name = xmlnode_get_child(xn_presentity, "displayName");
	xmlnode *xn_email = xmlnode_get_child(xn_presentity, "email");
	const char *email = xn_email ? xmlnode_get_attrib(xn_email, "email") : NULL;
	xmlnode *xn_userinfo = xmlnode_get_child(xn_presentity, "userInfo");
	xmlnode *xn_note = xn_userinfo ? xmlnode_get_child(xn_userinfo, "note") : NULL;
	char *note = xn_note ? xmlnode_get_data(xn_note) : NULL;
	xmlnode *xn_devices = xmlnode_get_child(xn_presentity, "devices");
	xmlnode *xn_device_presence = xn_devices ? xmlnode_get_child(xn_devices, "devicePresence") : NULL;
	xmlnode *xn_device_name = xn_device_presence ? xmlnode_get_child(xn_device_presence, "deviceName") : NULL;
	const char *device_name = xn_device_name ? xmlnode_get_attrib(xn_device_name, "name") : NULL;

	name = xmlnode_get_attrib(xn_presentity, "uri");
	uri = g_strdup_printf("sip:%s", name);
	availability = xmlnode_get_attrib(xn_availability, "aggregate");
	activity = xmlnode_get_attrib(xn_activity, "aggregate");

	// updating display name if alias was just URI
	if (xn_display_name) {
		GSList *buddies = purple_find_buddies(sip->account, uri); //all buddies in different groups
		GSList *entry = buddies;
		PurpleBuddy *p_buddy;
		display_name = xmlnode_get_attrib(xn_display_name, "displayName");

		while (entry) {
			const char *email_str, *server_alias;

			p_buddy = entry->data;

			if (!g_ascii_strcasecmp(name, purple_buddy_get_alias(p_buddy))) {
				purple_debug_info("sipe", "Replacing alias for %s with %s\n", uri, display_name);
				purple_blist_alias_buddy(p_buddy, display_name);
			}

			server_alias = purple_buddy_get_server_alias(p_buddy);
			if (display_name &&
				( (server_alias && strcmp(display_name, server_alias))
					|| !server_alias || strlen(server_alias) == 0 )
				) {
				purple_blist_server_alias_buddy(p_buddy, display_name);
			}

			if (email) {
				email_str = purple_blist_node_get_string((PurpleBlistNode *)p_buddy, "email");
				if (!email_str || g_ascii_strcasecmp(email_str, email)) {
					purple_blist_node_set_string((PurpleBlistNode *)p_buddy, "email", email);
				}
			}

			entry = entry->next;
		}
	}

	avl = atoi(availability);
	act = atoi(activity);

	if (act <= 100)
		activity_name = SIPE_STATUS_ID_AWAY;
	else if (act <= 150)
		activity_name = SIPE_STATUS_ID_LUNCH;
	else if (act <= 300)
		activity_name = SIPE_STATUS_ID_BRB;
	else if (act <= 400)
		activity_name = SIPE_STATUS_ID_AVAILABLE;
	else if (act <= 500)
		activity_name = SIPE_STATUS_ID_ONPHONE;
	else if (act <= 600)
		activity_name = SIPE_STATUS_ID_BUSY;
	else
		activity_name = SIPE_STATUS_ID_AVAILABLE;

	if (avl == 0)
		activity_name = SIPE_STATUS_ID_OFFLINE;

	sbuddy = g_hash_table_lookup(sip->buddies, uri);
	if (sbuddy)
	{
		if (sbuddy->annotation) { g_free(sbuddy->annotation); }
		sbuddy->annotation = NULL;
		if (note) { sbuddy->annotation = g_strdup(note); }

		if (sbuddy->device_name) { g_free(sbuddy->device_name); }
		sbuddy->device_name = NULL;
		if (device_name) { sbuddy->device_name = g_strdup(device_name); }
	}

	purple_debug_info("sipe", "process_incoming_notify_msrtc: status(%s)\n", activity_name);
	purple_prpl_got_user_status(sip->account, uri, activity_name, NULL);
	g_free(note);
	xmlnode_free(xn_presentity);
	g_free(uri);
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
	gchar *event = sipmsg_find_header(msg, "Event");
	gchar *subscription_state = sipmsg_find_header(msg, "subscription-state");
	const char *uri,*state;
	xmlnode *xn_list;
	xmlnode *xn_resource;
	xmlnode *xn_instance;

	int timeout = 0;

	purple_debug_info("sipe", "process_incoming_notify: Event: %s\n\n%s\n", event ? event : "", msg->body);
	purple_debug_info("sipe", "process_incoming_notify: subscription_state:%s\n\n", subscription_state);

	if (!request)
	{
		const gchar *expires_header;
		expires_header = sipmsg_find_header(msg, "Expires");
		timeout = expires_header ? strtol(expires_header, NULL, 10) : 0;
		purple_debug_info("sipe", "process_incoming_notify: expires:%d\n\n", timeout);
		timeout = (timeout - 60) > 60 ? (timeout - 60) : timeout; // 1 min ahead of expiration
	}

	if (!subscription_state || strstr(subscription_state, "active"))
	{
		if (event && !g_ascii_strcasecmp(event, "presence"))
		{
			sipe_process_presence(sip, msg);
		}
		else if (event && !g_ascii_strcasecmp(event, "vnd-microsoft-roaming-contacts"))
		{
			sipe_process_roaming_contacts(sip, msg, NULL);
		}
		else if (event && !g_ascii_strcasecmp(event, "vnd-microsoft-roaming-self") )
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
		else
		{
			purple_debug_info("sipe", "Unable to process (BE)NOTIFY. Event is not supported:%s\n", event ? event : "");
		}
	}

	//The server sends a (BE)NOTIFY with the status 'terminated'
	if(request && subscription_state && strstr(subscription_state, "terminated") ) {
		gchar *from = parse_from(sipmsg_find_header(msg, "From"));
		purple_debug_info("sipe", "process_incoming_notify: (BE)NOTIFY says that subscription to buddy %s was terminated. \n",  from);
		g_free(from);
	}
	
	if (timeout) {
		// For LSC 2005
		if (event && !sip->msrtc_event_categories)
		{
			/*if (!g_ascii_strcasecmp(event, "vnd-microsoft-roaming-contacts") && 
				g_slist_find_custom(sip->allow_events, "vnd-microsoft-roaming-contacts", (GCompareFunc)g_ascii_strcasecmp))
			{
				gchar *action_name = g_strdup_printf("<%s>", "vnd-microsoft-roaming-contacts");
				sipe_schedule_action(action_name, timeout, (Action) sipe_subscribe_roaming_contacts, sip, msg);
				g_free(action_name);
			}
			else if (!g_ascii_strcasecmp(event, "vnd-microsoft-roaming-ACL") && 
					g_slist_find_custom(sip->allow_events, "vnd-microsoft-roaming-ACL", (GCompareFunc)g_ascii_strcasecmp))
			{
				gchar *action_name = g_strdup_printf("<%s>", "vnd-microsoft-roaming-ACL");
				sipe_schedule_action(action_name, timeout, (Action) sipe_subscribe_roaming_acl, sip, msg);
				g_free(action_name);
			}
			
			else */if (!g_ascii_strcasecmp(event, "presence.wpending") && 
					g_slist_find_custom(sip->allow_events, "presence.wpending", (GCompareFunc)g_ascii_strcasecmp))
			{
				gchar *action_name = g_strdup_printf("<%s>", "presence.wpending");
				sipe_schedule_action(action_name, timeout, (Action) sipe_subscribe_presence_wpending, sip, NULL);
				g_free(action_name);
			}
			else if (!g_ascii_strcasecmp(event, "presence") && 
					g_slist_find_custom(sip->allow_events, "presence", (GCompareFunc)g_ascii_strcasecmp))
			{
				gchar *who = parse_from(sipmsg_find_header(msg, request ? "From" : "To"));
				gchar *action_name = g_strdup_printf("<%s><%s>", "presence", who);
				sipe_schedule_action(action_name, timeout, (Action) sipe_subscribe_presence_batched, sip, who);
				g_free(action_name);
				g_free(who);
			}
		}
	}
	
	if (event && !g_ascii_strcasecmp(event, "registration-notify"))
	{
		sipe_process_registration_notify(sip, msg);
	}

	//The client responses 'Ok' when receive a NOTIFY message (lcs2005)
	if (request && !benotify)
	{
		sipmsg_remove_header(msg, "Expires");
		sipmsg_remove_header(msg, "subscription-state");
		sipmsg_remove_header(msg, "Event");
		sipmsg_remove_header(msg, "Require");
		send_sip_response(sip->gc, msg, 200, "OK", NULL);
	}
}

/*
 * unused. Needed?

static gchar* gen_xpidf(struct sipe_account_data *sip)
{
	gchar *doc = g_strdup_printf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
			"<presence>\r\n"
			"<presentity uri=\"sip:%s;method=SUBSCRIBE\"/>\r\n"
			"<display name=\"sip:%s\"/>\r\n"
			"<atom id=\"1234\">\r\n"
			"<address uri=\"sip:%s\">\r\n"
			"<status status=\"%s\"/>\r\n"
			"</address>\r\n"
			"</atom>\r\n"
			"</presence>\r\n",
			sip->username,
			sip->username,
			sip->username,
			sip->status);
	return doc;
}



static gchar* gen_pidf(struct sipe_account_data *sip)
{
         gchar *doc = g_strdup_printf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
                        "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" xmlns:ep=\"urn:ietf:params:xml:ns:pidf:status:rpid-status\" xmlns:ci=\"urn:ietf:params:xml:ns:pidf:cipid\" entity=\"sip:%s\">\r\n"
                        "<tuple id=\"0\">\r\n"
                        "<status>\r\n"
                        "<basic>open</basic>\r\n"
                        "<ep:activities>\r\n"
                        " <ep:activity>%s</ep:activity>\r\n"
                        "</ep:activities>"
                        "</status>\r\n"
                        "</tuple>\r\n"
                        "<ci:display-name>%s</ci:display-name>\r\n"
                        "</presence>",
                        sip->username,
                        sip->status,
                        sip->username);
	return doc;
}
*/

static void send_presence_soap(struct sipe_account_data *sip, const char * note)
{
	int availability = 300; // online
	int activity = 400;  // Available
	gchar *name;
	gchar *body;
	if (!strcmp(sip->status, SIPE_STATUS_ID_AWAY)) {
		activity = 100;
	} else if (!strcmp(sip->status, SIPE_STATUS_ID_LUNCH)) {
		activity = 150;
	} else if (!strcmp(sip->status, SIPE_STATUS_ID_BRB)) {
		activity = 300;
	} else if (!strcmp(sip->status, SIPE_STATUS_ID_AVAILABLE)) {
		activity = 400;
	} else if (!strcmp(sip->status, SIPE_STATUS_ID_ONPHONE)) {
		activity = 500;
	} else if (!strcmp(sip->status, SIPE_STATUS_ID_BUSY)) {
		activity = 600;
	} else if (!strcmp(sip->status, SIPE_STATUS_ID_INVISIBLE) ||
		   !strcmp(sip->status, SIPE_STATUS_ID_OFFLINE)) {
		availability = 0; // offline
		activity = 100;
	} else {
		activity = 400; // available
	}

	name = g_strdup_printf("sip: sip:%s", sip->username);
	//@TODO: send user data - state; add hostname in upper case
	body = g_markup_printf_escaped(SIPE_SOAP_SET_PRESENCE, name, availability, activity, note ? note : "");
	send_soap_request_with_cb(sip, body, NULL , NULL);
	g_free(name);
	g_free(body);
}

static gboolean
process_clear_presence_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc)
{
	// Version(s) of presence info were out of date; tell the server to clear them, then we'll try again
	if (msg->response == 200) {
		sip->status_version = 0;
		send_presence_status(sip);
	}
	return TRUE;
}

static gboolean
process_send_presence_category_publish_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc)
{
	if (msg->response == 409) {
		// Version(s) of presence info were out of date; tell the server to clear them, then we'll try again
		// TODO need to parse the version #'s?
		gchar *uri = g_strdup_printf("sip:%s", sip->username);
		gchar *doc = g_strdup_printf(SIPE_SEND_CLEAR_PRESENCE, uri);
		gchar *tmp;
		gchar *hdr;

		purple_debug_info("sipe", "process_send_presence_category_publish_response = %s\n", msg->body);

		tmp = get_contact(sip);
		hdr = g_strdup_printf("Contact: %s\r\n"
			"Content-Type: application/msrtc-category-publish+xml\r\n", tmp);

		send_sip_request(sip->gc, "SERVICE", uri, uri, hdr, doc, NULL, process_clear_presence_response);

		g_free(tmp);
		g_free(hdr);
		g_free(uri);
		g_free(doc);
	}
	return TRUE;
}

static void send_presence_category_publish(struct sipe_account_data *sip, const char * note)
{
	int code;
	gchar *uri;
	gchar *doc;
	gchar *tmp;
	gchar *hdr;
	if (!strcmp(sip->status, SIPE_STATUS_ID_AWAY) ||
	    !strcmp(sip->status, SIPE_STATUS_ID_LUNCH)) {
		code = 12000;
	} else if (!strcmp(sip->status, SIPE_STATUS_ID_DND)) {
		code =  9000;
	} else if (!strcmp(sip->status, SIPE_STATUS_ID_BUSY)) {
		code =  7500;
	} else if (!strcmp(sip->status, SIPE_STATUS_ID_ONPHONE)) {
		code =  6000;
	} else if (!strcmp(sip->status, SIPE_STATUS_ID_BRB)) {
		code =  4500;
	} else if (!strcmp(sip->status, SIPE_STATUS_ID_AVAILABLE)) {
		code =  3000;
	} else if (!strcmp(sip->status, SIPE_STATUS_ID_UNKNOWN)) {
		code =     0;
	} else {
		// Offline or invisible
		code = 18000;
	}

	uri = g_strdup_printf("sip:%s", sip->username);
	doc = g_strdup_printf(SIPE_SEND_PRESENCE, uri,
		sip->status_version, code,
		sip->status_version, code,
		sip->status_version, note ? note : "",
		sip->status_version, note ? note : "",
		sip->status_version, note ? note : ""
	);
	sip->status_version++;

	tmp = get_contact(sip);
	hdr = g_strdup_printf("Contact: %s\r\n"
		"Content-Type: application/msrtc-category-publish+xml\r\n", tmp);

	send_sip_request(sip->gc, "SERVICE", uri, uri, hdr, doc, NULL, process_send_presence_category_publish_response);

	g_free(tmp);
	g_free(hdr);
	g_free(uri);
	g_free(doc);
}

static void send_presence_status(struct sipe_account_data *sip)
{
	PurpleStatus * status = purple_account_get_active_status(sip->account);
	const gchar *note;
	if (!status) return;

	note = purple_status_get_attr_string(status, "message");

        if(sip->msrtc_event_categories){
		send_presence_category_publish(sip, note);
	} else {
		send_presence_soap(sip, note);
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
		} else if (!strcmp(msg->method, "OPTIONS")) {
			process_incoming_options(sip, msg);
			found = TRUE;
		} else if (!strcmp(msg->method, "INFO")) {
			// TODO needs work
			gchar *from = parse_from(sipmsg_find_header(msg, "From"));
			if (from) {
				serv_got_typing(sip->gc, from, SIPE_TYPING_RECV_TIMEOUT, PURPLE_TYPING);
			}
			g_free(from);
			send_sip_response(sip->gc, msg, 200, "OK", NULL);
			found = TRUE;
		} else if (!strcmp(msg->method, "ACK")) {
			// ACK's don't need any response
			found = TRUE;
		} else if (!strcmp(msg->method, "SUBSCRIBE")) {
			// LCS 2005 sends us these - just respond 200 OK
			found = TRUE;
			send_sip_response(sip->gc, msg, 200, "OK", NULL);
		} else if (!strcmp(msg->method, "BYE")) {
			struct sip_im_session *session;
			gchar *from;
			send_sip_response(sip->gc, msg, 200, "OK", NULL);

			from = parse_from(sipmsg_find_header(msg, "From"));
			session = find_im_session (sip, from);
			g_free(from);

			if (session) {
				// TODO Let the user know the other user left the conversation?
				im_session_destroy(sip, session);
			}

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

				fill_auth(sip, ptmp, &sip->proxy);
				auth = auth_header(sip, &sip->proxy, trans->msg);
				sipmsg_remove_header(trans->msg, "Proxy-Authorization");
				sipmsg_add_header_pos(trans->msg, "Proxy-Authorization", auth, 5);
				g_free(auth);
				resend = sipmsg_to_string(trans->msg);
				/* resend request */
				sendout_pkt(sip->gc, resend);
				g_free(resend);
			} else {
				if (msg->response == 100 || msg->response == 180) {
					/* ignore provisional response */
					purple_debug_info("sipe", "got trying (%d) response\n", msg->response);
				} else {
					sip->proxy.retries = 0;
					if (!strcmp(trans->msg->method, "REGISTER")) {
						if (msg->response == 401)
						{
							sip->registrar.retries++;
							sip->registrar.expires = 0;
						}
						else
						{
							sip->registrar.retries = 0;
						}
                                                purple_debug_info("sipe", "RE-REGISTER CSeq: %d\r\n", sip->cseq);
					} else {
						if (msg->response == 401) {
							gchar *resend, *auth, *ptmp;

							if (sip->registrar.retries > 4) return;
							sip->registrar.retries++;

							if (!purple_account_get_bool(sip->account, "krb5", FALSE)) {
								ptmp = sipmsg_find_auth_header(msg, "NTLM");
							} else {
								ptmp = sipmsg_find_auth_header(msg, "Kerberos");
							}

							purple_debug(PURPLE_DEBUG_MISC, "sipe", "process_input_message - Auth header: %s\r\n", ptmp);

							fill_auth(sip, ptmp, &sip->registrar);
							auth = auth_header(sip, &sip->registrar, trans->msg);
							sipmsg_remove_header(trans->msg, "Proxy-Authorization");
							sipmsg_add_header(trans->msg, "Proxy-Authorization", auth);

							//sipmsg_remove_header(trans->msg, "Authorization");
							//sipmsg_add_header(trans->msg, "Authorization", auth);
							g_free(auth);
							resend = sipmsg_to_string(trans->msg);
							/* resend request */
							sendout_pkt(sip->gc, resend);
							g_free(resend);
						}
					}
					
					if (trans->callback) {
						purple_debug(PURPLE_DEBUG_MISC, "sipe", "process_input_message - we have a transaction callback\r\n");
						/* call the callback to process response*/
						(trans->callback)(sip, msg, trans);
					}
					/* Not sure if this is needed or what needs to be done
  					   but transactions seem to be removed prematurely so
  					   this only removes them if the response is 200 OK */
					purple_debug(PURPLE_DEBUG_MISC, "sipe", "process_input_message - removing CSeq %d\r\n", sip->cseq);
					/*Has a bug and it's unneccesary*/
                    /*transactions_remove(sip, trans);*/

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
		purple_debug_info("sipe", "\n\nreceived - %s\n######\n%s\n#######\n\n", ctime(&currtime), conn->inbuf);
		msg = sipmsg_parse_header(conn->inbuf);
		cur[0] = '\r';
		cur += 2;
		restlen = conn->inbufused - (cur - conn->inbuf);
		if (restlen >= msg->bodylen) {
			dummy = g_malloc(msg->bodylen + 1);
			memcpy(dummy, cur, msg->bodylen);
			dummy[msg->bodylen] = '\0';
			msg->body = dummy;
			cur += msg->bodylen;
			memmove(conn->inbuf, cur, conn->inbuflen - (cur - conn->inbuf));
			conn->inbufused = strlen(conn->inbuf);
		} else {
			purple_debug_info("sipe", "process_input: body too short (%d < %d, strlen %d) - ignoring message\n",
					  restlen, msg->bodylen, (int)strlen(conn->inbuf));
			sipmsg_free(msg);
			return;
		}

		/*if (msg->body) {
			purple_debug_info("sipe", "body:\n%s", msg->body);
		}*/

		// Verify the signature before processing it
		if (sip->registrar.ntlm_key) {
			struct sipmsg_breakdown msgbd;
			gchar *signature_input_str;
			gchar *signature = NULL;
			gchar *rspauth;
			msgbd.msg = msg;
			sipmsg_breakdown_parse(&msgbd, sip->registrar.realm, sip->registrar.target);
			signature_input_str = sipmsg_breakdown_get_string(&msgbd);
			if (signature_input_str != NULL) {
				signature = purple_ntlm_sipe_signature_make (signature_input_str, sip->registrar.ntlm_key);
			}
			g_free(signature_input_str);

			rspauth = sipmsg_find_part_of_header(sipmsg_find_header(msg, "Authentication-Info"), "rspauth=\"", "\"", NULL);

			if (signature != NULL) {
				if (rspauth != NULL) {
					if (purple_ntlm_verify_signature (signature, rspauth)) {
						purple_debug(PURPLE_DEBUG_MISC, "sipe", "incoming message's signature validated\n");
						process_input_message(sip, msg);
					} else {
						purple_debug(PURPLE_DEBUG_MISC, "sipe", "incoming message's signature is invalid.  Received %s but generated %s; Ignoring message\n", rspauth, signature);
						purple_connection_error(sip->gc, _("Invalid message signature received"));
						sip->gc->wants_to_die = TRUE;
					}
				} else if (msg->response == 401) {
					purple_connection_error(sip->gc, _("Wrong Password"));
					sip->gc->wants_to_die = TRUE;
				}
				g_free(signature);
			}

			g_free(rspauth);
			sipmsg_breakdown_free(&msgbd);
		} else {
			process_input_message(sip, msg);
		}

		sipmsg_free(msg);
	}
}

static void sipe_udp_process(gpointer data, gint source, PurpleInputCondition con)
{
	PurpleConnection *gc = data;
	struct sipe_account_data *sip = gc->proto_data;
	struct sipmsg *msg;
	int len;
	time_t currtime;

	static char buffer[65536];
	if ((len = recv(source, buffer, sizeof(buffer) - 1, 0)) > 0) {
		buffer[len] = '\0';
		purple_debug_info("sipe", "\n\nreceived - %s\n######\n%s\n#######\n\n", ctime(&currtime), buffer);
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

static void sipe_input_cb_ssl(gpointer data, PurpleSslConnection *gsc, PurpleInputCondition cond)
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
		purple_connection_error(gc, _("Connection not found; Please try to connect again.\n"));
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

static void sipe_input_cb(gpointer data, gint source, PurpleInputCondition cond)
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
static void sipe_newconn_cb(gpointer data, gint source, PurpleInputCondition cond)
{
	PurpleConnection *gc = data;
	struct sipe_account_data *sip = gc->proto_data;
	struct sip_connection *conn;

	int newfd = accept(source, NULL, NULL);

	conn = connection_create(sip, newfd);

	conn->inputhandler = purple_input_add(newfd, PURPLE_INPUT_READ, sipe_input_cb, gc);
}

static void login_cb(gpointer data, gint source, const gchar *error_message)
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

static void login_cb_ssl(gpointer data, PurpleSslConnection *gsc, PurpleInputCondition cond)
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

static void sipe_udp_host_resolved(GSList *hosts, gpointer data, const char *error_message)
{
	struct sipe_account_data *sip = (struct sipe_account_data*) data;
	int addr_size;

	sip->query_data = NULL;

	if (!hosts || !hosts->data) {
		purple_connection_error(sip->gc, _("Couldn't resolve host"));
		return;
	}

	addr_size = GPOINTER_TO_INT(hosts->data);
	hosts = g_slist_remove(hosts, hosts->data);
	memcpy(&(sip->serveraddr), hosts->data, addr_size);
	g_free(hosts->data);
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

static void sipe_ssl_connect_failure(PurpleSslConnection *gsc, PurpleSslErrorType error,
                                     gpointer data)
{
        PurpleConnection *gc = data;
        struct sipe_account_data *sip;

        /* If the connection is already disconnected, we don't need to do anything else */
        if (!PURPLE_CONNECTION_IS_VALID(gc))
                return;

        sip = gc->proto_data;
	sip->fd = -1;
        sip->gsc = NULL;

        switch(error) {
			case PURPLE_SSL_CONNECT_FAILED:
				purple_connection_error(gc, _("Connection Failed"));
				break;
			case PURPLE_SSL_HANDSHAKE_FAILED:
				purple_connection_error(gc, _("SSL Handshake Failed"));
				break;
			case PURPLE_SSL_CERTIFICATE_INVALID:
				purple_connection_error(gc, _("SSL Certificate Invalid"));
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
		purple_connection_error(sip->gc, _("Couldn't create socket"));
	}
}


static void create_connection(struct sipe_account_data *sip, gchar *hostname, int port)
{
	PurpleAccount *account = sip->account;
	PurpleConnection *gc = sip->gc;

	if (purple_account_get_bool(account, "useport", FALSE)) {
		purple_debug(PURPLE_DEBUG_MISC, "sipe", "create_connection - using specified SIP port\n");
		port = purple_account_get_int(account, "port", 0);
	} else {
		port = port ? port : (sip->transport == SIPE_TRANSPORT_TLS) ? 5061 : 5060;
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
			purple_connection_error(gc, _("SSL support is not installed.  Either install SSL support or configure a different connection type in the account editor."));
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
	gchar **signinname_login, **userserver, **domain_user;
	const char *transport;

	const char *username = purple_account_get_username(account);
	gc = purple_account_get_connection(account);

	if (strpbrk(username, " \t\v\r\n") != NULL) {
		gc->wants_to_die = TRUE;
		purple_connection_error(gc, _("SIP Exchange usernames may not contain whitespaces"));
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

	signinname_login = g_strsplit(username, ",", 2);

	userserver = g_strsplit(signinname_login[0], "@", 2);
	purple_connection_set_display_name(gc, userserver[0]);
	sip->username = g_strjoin("@", userserver[0], userserver[1], NULL);
	sip->sipdomain = g_strdup(userserver[1]);

	domain_user = g_strsplit(signinname_login[1], "\\", 2);
	sip->authdomain = (domain_user && domain_user[1]) ? g_strdup(domain_user[0]) : NULL;
	sip->authuser =   (domain_user && domain_user[1]) ? g_strdup(domain_user[1]) : (signinname_login ? g_strdup(signinname_login[1]) : NULL);

	sip->password = g_strdup(purple_connection_get_password(gc));

	g_strfreev(userserver);
	g_strfreev(domain_user);
	g_strfreev(signinname_login);

	sip->buddies = g_hash_table_new((GHashFunc)sipe_ht_hash_nick, (GEqualFunc)sipe_ht_equals_nick);

	purple_connection_update_progress(gc, _("Connecting"), 1, 2);

	/* TODO: Set the status correctly. */
	sip->status = g_strdup(SIPE_STATUS_ID_AVAILABLE);

	transport = purple_account_get_string(account, "transport", "auto");
	sip->transport = (strcmp(transport, "tls") == 0) ? SIPE_TRANSPORT_TLS :
			 (strcmp(transport, "tcp") == 0) ? SIPE_TRANSPORT_TCP :
							   SIPE_TRANSPORT_UDP;

	if (purple_account_get_bool(account, "useproxy", FALSE)) {
		purple_debug(PURPLE_DEBUG_MISC, "sipe", "sipe_login - using specified SIP proxy\n");
		create_connection(sip, g_strdup(purple_account_get_string(account, "proxy", sip->sipdomain)), 0);
	} else if (strcmp(transport, "auto") == 0) {
		sip->auto_transport = TRUE;
		resolve_next_service(sip, purple_ssl_is_supported() ? service_autodetect : service_tcp);
	} else if (strcmp(transport, "tls") == 0) {
		resolve_next_service(sip, service_tls);
	} else if (strcmp(transport, "tcp") == 0) {
		resolve_next_service(sip, service_tcp);
	} else {
		resolve_next_service(sip, service_udp);
	}
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
			g_free(sched_action->payload);
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

	if (sip->contact)
		g_free(sip->contact);
	sip->contact = NULL;
	if (sip->regcallid)
		g_free(sip->regcallid);
	sip->regcallid = NULL;

	sip->fd = -1;
	sip->processing_input = FALSE;
}

/**
  * A callback for g_hash_table_foreach_remove
  */
static gboolean sipe_buddy_remove(gpointer key, struct sipe_buddy *buddy, gpointer user_data)
{
	sipe_free_buddy(buddy);
}

static void sipe_close(PurpleConnection *gc)
{
	struct sipe_account_data *sip = gc->proto_data;

	if (sip) {
		/* leave all conversations */
		im_session_close_all(sip);

		/* unregister */
		do_register_exp(sip, 0);

		sipe_connection_cleanup(sip);
		g_free(sip->sipdomain);
		g_free(sip->username);
		g_free(sip->password);
		g_free(sip->authdomain);
		g_free(sip->authuser);
		g_free(sip->status);

		g_hash_table_foreach_remove(sip->buddies, (GHRFunc) sipe_buddy_remove, NULL);
		g_hash_table_destroy(sip->buddies);
	}
	g_free(gc->proto_data);
	gc->proto_data = NULL;
}

static void sipe_searchresults_im_buddy(PurpleConnection *gc, GList *row, void *user_data)
{
	PurpleAccount *acct = purple_connection_get_account(gc);
	char *id = g_strdup_printf("sip:%s", (char *)g_list_nth_data(row, 0));
	PurpleConversation *conv = purple_find_conversation_with_account(PURPLE_CONV_TYPE_IM, id, acct);
	if (conv == NULL)
		conv = purple_conversation_new(PURPLE_CONV_TYPE_IM, acct, id);
	purple_conversation_present(conv);
	g_free(id);
}

static void sipe_searchresults_add_buddy(PurpleConnection *gc, GList *row, void *user_data)
{

	purple_blist_request_add_buddy(purple_connection_get_account(gc),
								 g_list_nth_data(row, 0), NULL, g_list_nth_data(row, 1));
}

static gboolean process_search_contact_response(struct sipe_account_data *sip, struct sipmsg *msg,struct transaction *tc)
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
		purple_notify_error(sip->gc, NULL, _("Unable to display the search results."), NULL);

		xmlnode_free(searchResults);
		return FALSE;
	}

	column = purple_notify_searchresults_column_new(_("User Name"));
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
		gchar *query = g_strjoinv(NULL, attrs);
		gchar *body = g_strdup_printf(SIPE_SOAP_SEARCH_CONTACT, 100, query);
		purple_debug_info("sipe", "sipe_search_contact_with_cb: body:\n%s n", body ? body : "");
		send_soap_request_with_cb(gc->proto_data, body,
					  (TransCallback) process_search_contact_response, NULL);
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

	field = purple_request_field_string_new("givenName", _("First Name"), NULL, FALSE);
	purple_request_field_group_add_field(group, field);
	field = purple_request_field_string_new("sn", _("Last Name"), NULL, FALSE);
	purple_request_field_group_add_field(group, field);
	field = purple_request_field_string_new("company", _("Company"), NULL, FALSE);
	purple_request_field_group_add_field(group, field);
	field = purple_request_field_string_new("c", _("Country"), NULL, FALSE);
	purple_request_field_group_add_field(group, field);

	purple_request_fields(gc,
		_("Search"),
		_("Search for a Contact"),
		_("Enter the information of the person you wish to find. Empty fields will be ignored."),
		fields,
		_("_Search"), G_CALLBACK(sipe_search_contact_with_cb),
		_("_Cancel"), NULL,
		purple_connection_get_account(gc), NULL, NULL, gc);
}

GList *sipe_actions(PurplePlugin *plugin, gpointer context)
{
	GList *menu = NULL;
	PurplePluginAction *act;

	act = purple_plugin_action_new(_("Contact Search..."), sipe_show_find_contact);
	menu = g_list_prepend(menu, act);

	menu = g_list_reverse(menu);

	return menu;
}

static void dummy_permit_deny(PurpleConnection *gc)
{
}

static gboolean sipe_plugin_load(PurplePlugin *plugin)
{
  return TRUE;
}


static gboolean sipe_plugin_unload(PurplePlugin *plugin)
{
    return TRUE;
}


static char *sipe_status_text(PurpleBuddy *buddy)
{
	struct sipe_account_data *sip;
	struct sipe_buddy *sbuddy;
	char *text = NULL;

	sip = (struct sipe_account_data *) buddy->account->gc->proto_data;
	if (sip)  //happens on pidgin exit
	{
		sbuddy = g_hash_table_lookup(sip->buddies, buddy->name);
		if (sbuddy && sbuddy->annotation)
		{
			text = g_strdup(sbuddy->annotation);
		}
	}

	return text;
}

static void sipe_tooltip_text(PurpleBuddy *buddy, PurpleNotifyUserInfo *user_info, gboolean full)
{
	const PurplePresence *presence = purple_buddy_get_presence(buddy);
	const PurpleStatus *status = purple_presence_get_active_status(presence);
	struct sipe_account_data *sip;
	struct sipe_buddy *sbuddy;
	char *annotation = NULL;

	sip = (struct sipe_account_data *) buddy->account->gc->proto_data;
	if (sip)  //happens on pidgin exit
	{
		sbuddy = g_hash_table_lookup(sip->buddies, buddy->name);
		if (sbuddy)
		{
			annotation = sbuddy->annotation ? g_strdup(sbuddy->annotation) : NULL;
		}
	}

	//Layout
	if (purple_presence_is_online(presence))
	{
		purple_notify_user_info_add_pair(user_info, _("Status"), purple_status_get_name(status));
	}

	if (annotation)
	{
		purple_notify_user_info_add_pair( user_info, _("Note"), annotation );
		g_free(annotation);
	}

}

static GHashTable *
sipe_get_account_text_table(PurpleAccount *account)
{
	GHashTable *table;
	table = g_hash_table_new(g_str_hash, g_str_equal);
	g_hash_table_insert(table, "login_label", (gpointer)_("Sign-In Name..."));
	return table;
}

static PurpleBuddy *
purple_blist_add_buddy_clone(PurpleGroup * group, PurpleBuddy * buddy)
{
	PurpleBuddy *clone;
	const gchar *server_alias, *email;
	const PurpleStatus *status = purple_presence_get_active_status(purple_buddy_get_presence(buddy));

	clone = purple_buddy_new(buddy->account, buddy->name, buddy->alias);

	purple_blist_add_buddy(clone, NULL, group, NULL);

	server_alias = g_strdup(purple_buddy_get_server_alias(buddy));
	if (server_alias) {
		purple_blist_server_alias_buddy(clone, server_alias);
	}

	email = purple_blist_node_get_string((PurpleBlistNode *)buddy, "email");
	if (email) {
		purple_blist_node_set_string((PurpleBlistNode *)clone, "email", email);
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
		b = purple_blist_add_buddy_clone(group, buddy);
	}

	sipe_group_buddy(gc, buddy->name, NULL, group_name);
}

static void
sipe_buddy_menu_send_email_cb(PurpleBuddy *buddy)
{
	const gchar *email;
	purple_debug_info("sipe", "sipe_buddy_menu_send_email_cb: buddy->name=%s\n", buddy->name);

	email = purple_blist_node_get_string((PurpleBlistNode *)buddy, "email");
	if (email)
	{
		char *mailto = g_strdup_printf("mailto:%s", email);
		purple_debug_info("sipe", "sipe_buddy_menu_send_email_cb: going to call default mail client with email: %s\n", email);
#ifndef _WIN32
		{
			pid_t pid;
			char *const parmList[] = {mailto, NULL};
			if ((pid = fork()) == -1)
			{
				purple_debug_info("sipe", "fork() error\n");
			}
			else if (pid == 0)
			{
				execvp("xdg-email", parmList);
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

	act = purple_menu_action_new(_("Send Email..."),
							   PURPLE_CALLBACK(sipe_buddy_menu_send_email_cb),
							   NULL, NULL);
	menu = g_list_prepend(menu, act);

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

	return menu;
}

GList *sipe_blist_node_menu(PurpleBlistNode *node) {
	if(PURPLE_BLIST_NODE_IS_BUDDY(node)) {
		return sipe_buddy_menu((PurpleBuddy *) node);
	} else {
		return NULL;
	}
}

static gboolean
process_get_info_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *trans)
{
	gboolean ret = TRUE;
	char *username = (char *)trans->payload;

	PurpleNotifyUserInfo *info = purple_notify_user_info_new();
	PurpleBuddy *pbuddy;
	struct sipe_buddy *sbuddy;
	const char *alias;
	char *server_alias = NULL;
	char *email = NULL;
	const char *device_name = NULL;

	purple_debug_info("sipe", "Fetching %s's user info for %s\n", username, sip->username);

	pbuddy = purple_find_buddy((PurpleAccount *)sip->account, username);
	alias = purple_buddy_get_local_alias(pbuddy);

	if (sip)
	{
		//will query buddy UA's capabilities and send answer to log
		sipe_options_request(sip, username);

		sbuddy = g_hash_table_lookup(sip->buddies, username);
		if (sbuddy)
		{
			device_name = sbuddy->device_name ? g_strdup(sbuddy->device_name) : NULL;
		}
	}

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
			server_alias = g_strdup(xmlnode_get_attrib(mrow, "displayName"));
			purple_notify_user_info_add_pair(info, _("Display Name"), server_alias);
			purple_notify_user_info_add_pair(info, _("Job Title"), g_strdup(xmlnode_get_attrib(mrow, "title")));
			purple_notify_user_info_add_pair(info, _("Office"), g_strdup(xmlnode_get_attrib(mrow, "office")));
			purple_notify_user_info_add_pair(info, _("Business Phone"), g_strdup(xmlnode_get_attrib(mrow, "phone")));
			purple_notify_user_info_add_pair(info, _("Company"), g_strdup(xmlnode_get_attrib(mrow, "company")));
			purple_notify_user_info_add_pair(info, _("City"), g_strdup(xmlnode_get_attrib(mrow, "city")));
			purple_notify_user_info_add_pair(info, _("State"), g_strdup(xmlnode_get_attrib(mrow, "state")));
			purple_notify_user_info_add_pair(info, _("Country"), g_strdup(xmlnode_get_attrib(mrow, "country")));
			email = g_strdup(xmlnode_get_attrib(mrow, "email"));
			purple_notify_user_info_add_pair(info, _("E-Mail Address"), email);
			if (!email || strcmp("", email)) {
				if (!purple_blist_node_get_string((PurpleBlistNode *)pbuddy, "email")) {
					purple_blist_node_set_string((PurpleBlistNode *)pbuddy, "email", email);
				}
			}
		}
		xmlnode_free(searchResults);
	}

	purple_notify_user_info_add_section_break(info);

	if (!server_alias || !strcmp("", server_alias)) {
		g_free(server_alias);
		server_alias = g_strdup(purple_buddy_get_server_alias(pbuddy));
		if (server_alias) {
			purple_notify_user_info_add_pair(info, _("Display Name"), server_alias);
		}
	}

	// same as server alias, do not present
	alias = (alias && server_alias && !strcmp(alias, server_alias)) ? NULL : alias;
	if (alias)
	{
		purple_notify_user_info_add_pair(info, _("Alias"), alias);
	}

	if (!email || !strcmp("", email)) {
		g_free(email);
		email = g_strdup(purple_blist_node_get_string((PurpleBlistNode *)pbuddy, "email"));
		if (email) {
			purple_notify_user_info_add_pair(info, _("E-Mail Address"), email);
		}
	}

	if (device_name)
	{
		purple_notify_user_info_add_pair(info, _("Device"), device_name);
	}

	/* show a buddy's user info in a nice dialog box */
	purple_notify_userinfo(sip->gc,        /* connection the buddy info came through */
						 username,  /* buddy's username */
						 info,      /* body */
						 NULL,      /* callback called when dialog closed */
						 NULL);     /* userdata for callback */

	return ret;
}

/**
 * AD search first, LDAP based
 */
static void sipe_get_info(PurpleConnection *gc, const char *username)
{
	char *row = g_markup_printf_escaped(SIPE_SOAP_SEARCH_ROW, "msRTCSIP-PrimaryUserAddress", username);
	gchar *body = g_strdup_printf(SIPE_SOAP_SEARCH_CONTACT, 1, row);

	purple_debug_info("sipe", "sipe_get_contact_data: body:\n%s\n", body ? body : "");
	send_soap_request_with_cb((struct sipe_account_data *)gc->proto_data, body,
					  (TransCallback) process_get_info_response, (gpointer)g_strdup(username));
	g_free(body);
	g_free(row);
}

static PurplePlugin *my_protocol = NULL;

static PurplePluginProtocolInfo prpl_info =
{
	0,
	NULL,					/* user_splits */
	NULL,					/* protocol_options */
	NO_BUDDY_ICONS,				/* icon_spec */
	sipe_list_icon,				/* list_icon */
	NULL,					/* list_emblems */
	sipe_status_text,			/* status_text */
	sipe_tooltip_text,			/* tooltip_text */	// add custom info to contact tooltip
	sipe_status_types,			/* away_states */
	sipe_blist_node_menu,	/* blist_node_menu */
	NULL,					/* chat_info */
	NULL,					/* chat_info_defaults */
	sipe_login,				/* login */
	sipe_close,				/* close */
	sipe_im_send,				/* send_im */
	NULL,					/* set_info */		// TODO maybe
	sipe_send_typing,			/* send_typing */
	sipe_get_info,			/* get_info */
	sipe_set_status,			/* set_status */
	NULL,					/* set_idle */
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
	NULL,			                /* chat_invite */
	NULL,					/* chat_leave */
	NULL,					/* chat_whisper */
	NULL,					/* chat_send */
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
	sipe_send_raw,			/* send_raw */
	NULL,					/* roomlist_room_serialize */
	NULL,					/* unregister_user */
	NULL,					/* send_attention */
	NULL,					/* get_attention_types */

	sizeof(PurplePluginProtocolInfo),       /* struct_size */
	sipe_get_account_text_table, /* get_account_text_table */
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
	"Microsoft LCS/OCS",				  /**< name           */
	VERSION,                                          /**< version        */
	"SIP/SIMPLE OCS/LCS Protocol Plugin",             /**  summary        */
	"The SIP/SIMPLE LCS/OCS Protocol Plugin",         /**  description    */
	"Anibal Avelar <avelar@gmail.com>, "         	  /**< author         */
	"Gabriel Burt <gburt@novell.com>",         	  /**< author         */
	PURPLE_WEBSITE,                                   /**< homepage       */
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

static void sipe_plugin_destroy(PurplePlugin *plugin)
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

#ifdef ENABLE_NLS
	purple_debug_info(PACKAGE, "bindtextdomain = %s", bindtextdomain(GETTEXT_PACKAGE, LOCALEDIR));
	purple_debug_info(PACKAGE, "bind_textdomain_codeset = %s",
	bind_textdomain_codeset(GETTEXT_PACKAGE, "UTF-8"));
#endif

	purple_plugin_register(plugin);

	split = purple_account_user_split_new(_("Login \n   domain\\user  or\n   someone@linux.com "), NULL, ',');
	purple_account_user_split_set_reverse(split, FALSE);
	prpl_info.user_splits = g_list_append(prpl_info.user_splits, split);

	option = purple_account_option_bool_new(_("Use proxy"), "useproxy", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
	option = purple_account_option_string_new(_("Proxy Server"), "proxy", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_bool_new(_("Use non-standard port"), "useport", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
	// Translators: noun (networking port)
	option = purple_account_option_int_new(_("Port"), "port", 5061);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_list_new(_("Connection Type"), "transport", NULL);
	purple_account_option_add_list_item(option, _("Auto"), "auto");
	purple_account_option_add_list_item(option, _("SSL/TLS"), "tls");
	purple_account_option_add_list_item(option, _("TCP"), "tcp");
	purple_account_option_add_list_item(option, _("UDP"), "udp");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	/*option = purple_account_option_bool_new(_("Publish status (note: everyone may watch you)"), "doservice", TRUE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);*/

	option = purple_account_option_string_new(_("User Agent"), "useragent", "Purple/" VERSION);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	// TODO commented out so won't show in the preferences until we fix krb message signing
	/*option = purple_account_option_bool_new(_("Use Kerberos"), "krb5", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	// XXX FIXME: Add code to programmatically determine if a KRB REALM is specified in /etc/krb5.conf
	option = purple_account_option_string_new(_("Kerberos Realm"), "krb5_realm", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
	*/

	option = purple_account_option_bool_new(_("Use Client-specified Keepalive"), "clientkeepalive", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
	option = purple_account_option_int_new(_("Keepalive Timeout"), "keepalive", 300);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
	my_protocol = plugin;
}

/* I had to redefined the function for it load, but works */
gboolean purple_init_plugin(PurplePlugin *plugin){
	plugin->info = &(info);
	init_plugin((plugin));
	sipe_plugin_load((plugin));
	return purple_plugin_register(plugin);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
