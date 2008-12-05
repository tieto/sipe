/**
 * @file sipe.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2008 Novell, Inc.
 * Copyright (C) 2007 Anibal Avelar "Fixxxer"<avelar@gmail.com>
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
#include "sip-internal.h"
#else /* _WIN32 */
#ifdef _DLL
#define _WS2TCPIP_H_
#define _WINSOCK2API_
#define _LIBC_INTERNAL_
#endif /* _DLL */

#include "internal.h"
#endif /* _WIN32 */

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

#include "sipe.h"
#include "sip-ntlm.h"
#ifdef USE_KERBEROS
 #include "sipkrb5.h"
#endif /*USE_KERBEROS*/

#include "sipmsg.h"
#include "sipe-sign.h"
#include "dnssrv.h"

static char *gentag()
{
	return g_strdup_printf("%04d%04d", rand() & 0xFFFF, rand() & 0xFFFF);
}

static gchar *get_epid()
{
	return sipe_uuid_get_macaddr();
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

static void sipe_keep_alive(PurpleConnection *gc)
{
	struct sipe_account_data *sip = gc->proto_data;
	if (sip->udp) {
		/* in case of UDP send a packet only with a 0 byte to remain in the NAT table */
		gchar buf[2] = {0, 0};
		purple_debug_info("sipe", "sending keep alive\n");
		sendto(sip->fd, buf, 1, 0, (struct sockaddr*)&sip->serveraddr, sizeof(struct sockaddr_in));
	}
}

static gboolean process_register_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc);

static void sipe_input_cb_ssl(gpointer data, PurpleSslConnection *gsc, PurpleInputCondition cond);
static void sipe_ssl_connect_failure(PurpleSslConnection *gsc, PurpleSslErrorType error, 
                                     gpointer data);

static void send_notify(struct sipe_account_data *sip, struct sipe_watcher *);
static void sipe_close(PurpleConnection *gc);

static void send_service(struct sipe_account_data *sip);
static void sipe_subscribe_to_name(struct sipe_account_data *sip, const char * buddy_name);
static void send_presence_info(struct sipe_account_data *sip);

static void do_notifies(struct sipe_account_data *sip)
{
	GSList *tmp = sip->watcher;
	purple_debug_info("sipe", "do_notifies()\n");

	while (tmp) {
		purple_debug_info("sipe", "notifying %s\n", ((struct sipe_watcher*)tmp->data)->name);
		send_notify(sip, tmp->data);
		tmp = tmp->next;
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

static struct sipe_watcher *watcher_find(struct sipe_account_data *sip,
		const gchar *name)
{
	struct sipe_watcher *watcher;
	GSList *entry = sip->watcher;
	while (entry) {
		watcher = entry->data;
		if (!strcmp(name, watcher->name)) return watcher;
		entry = entry->next;
	}
	return NULL;
}

static struct sipe_watcher *watcher_create(struct sipe_account_data *sip,
		const gchar *name, const gchar *callid, const gchar *ourtag,
		const gchar *theirtag, gboolean needsxpidf)
{
	struct sipe_watcher *watcher = g_new0(struct sipe_watcher, 1);
	watcher->name = g_strdup(name);
	watcher->dialog.callid = g_strdup(callid);
	watcher->dialog.ourtag = g_strdup(ourtag);
	watcher->dialog.theirtag = g_strdup(theirtag);
	watcher->needsxpidf = needsxpidf;
	sip->watcher = g_slist_append(sip->watcher, watcher);
	return watcher;
}

static void watcher_remove(struct sipe_account_data *sip, const gchar *name)
{
	struct sipe_watcher *watcher = watcher_find(sip, name);
	sip->watcher = g_slist_remove(sip->watcher, watcher);
	g_free(watcher->name);
	g_free(watcher->dialog.callid);
	g_free(watcher->dialog.ourtag);
	g_free(watcher->dialog.theirtag);
	g_free(watcher);
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
	sip->openconns = g_slist_remove(sip->openconns, conn);
	if (conn->inputhandler) purple_input_remove(conn->inputhandler);
	g_free(conn->inbuf);
	g_free(conn);
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

static gchar *auth_header_without_newline(struct sipe_account_data *sip, struct sip_auth *auth, struct sipmsg * msg, gboolean force_reauth)
{
	const gchar *method = msg->method;
	const gchar *target = msg->target;
	gchar noncecount[9];
	gchar *response;
	gchar *ret;
	gchar *tmp;
	const char *authdomain;
	const char *authuser;
	const char *krb5_realm;
	const char *host;
	gchar      *krb5_token = NULL;

	authdomain = purple_account_get_string(sip->account, "authdomain", "");
	authuser = purple_account_get_string(sip->account, "authuser", sip->username);

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

	if (!authuser || strlen(authuser) < 1) {
		authuser = sip->username;
	}

	if (auth->type == 1) { /* Digest */
		sprintf(noncecount, "%08d", auth->nc++);
		response = purple_cipher_http_digest_calculate_response(
							"md5", method, target, NULL, NULL,
							auth->nonce, noncecount, NULL, auth->digest_session_key);
		purple_debug(PURPLE_DEBUG_MISC, "sipe", "response %s\n", response);

		ret = g_strdup_printf("Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", nc=\"%s\", response=\"%s\"", authuser, auth->realm, auth->nonce, target, noncecount, response);
		g_free(response);
		return ret;
	} else if (auth->type == 2) { /* NTLM */
		// If we have a signature for the message, include that
		if (msg->signature) {
			tmp = g_strdup_printf("NTLM qop=\"auth\", opaque=\"%s\", realm=\"%s\", targetname=\"%s\", crand=\"%s\", cnum=\"%s\", response=\"%s\"", auth->opaque, auth->realm, auth->target, msg->rand, msg->num, msg->signature);
			return tmp;
		}

		if (auth->nc == 3 && auth->nonce && auth->ntlm_key == NULL) {
			/* TODO: Don't hardcode "purple" as the hostname */
			const gchar * ntlm_key;
			gchar * gssapi_data = purple_ntlm_gen_authenticate(&ntlm_key, authuser, sip->password, "purple", authdomain, (const guint8 *)auth->nonce, &auth->flags);
			auth->ntlm_key = (gchar *)ntlm_key;
			tmp = g_strdup_printf("NTLM qop=\"auth\", opaque=\"%s\", realm=\"%s\", targetname=\"%s\", gssapi-data=\"%s\"", auth->opaque, auth->realm, auth->target, gssapi_data);
			g_free(gssapi_data);
			return tmp;
		}

		tmp = g_strdup_printf("NTLM qop=\"auth\", realm=\"%s\", targetname=\"%s\", gssapi-data=\"\"", auth->realm, auth->target);
		return tmp;
	} else if (auth->type == 3) {
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

static gchar *auth_header(struct sipe_account_data *sip, struct sip_auth *auth, struct sipmsg * msg, gboolean force_reauth)
{
	gchar *with, *without;

	without = auth_header_without_newline(sip, auth, msg, force_reauth);
	with = g_strdup_printf("%s\r\n", without);
	g_free (without);
	return with;
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
        const char *krb5_realm;
        const char *host;

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

	authuser   = purple_account_get_string(sip->account, "authuser", sip->username);

	if (!authuser || strlen(authuser) < 1) {
		authuser = sip->username;
	}

	if (!hdr) {
		purple_debug_error("sipe", "fill_auth: hdr==NULL\n");
		return;
	}

	if (!g_strncasecmp(hdr, "NTLM", 4)) {
		auth->type = 2;
		parts = g_strsplit(hdr+5, "\", ", 0);
		i = 0;
		while (parts[i]) {
			//purple_debug_info("sipe", "parts[i] %s\n", parts[i]);
			if ((tmp = parse_attribute("gssapi-data=\"", parts[i]))) {
				auth->nonce = g_memdup(purple_ntlm_parse_challenge(tmp, &auth->flags), 8);
				g_free(tmp);
			}
			if ((tmp = parse_attribute("targetname=\"",
					parts[i]))) {
				auth->target = tmp;
			}
			else if ((tmp = parse_attribute("realm=\"",
					parts[i]))) {
				auth->realm = tmp;
			}
			else if ((tmp = parse_attribute("opaque=\"", parts[i]))) {
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
		auth->type = 3;
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
				auth->target = tmp;
			} else if ((tmp = parse_attribute("realm=\"", parts[i]))) {
				auth->realm = tmp;
			} else if ((tmp = parse_attribute("opaque=\"", parts[i]))) {
				auth->opaque = tmp;
			}
			i++;
		}
		g_strfreev(parts);
		auth->nc = 3;
		//if (!strstr(hdr, "gssapi-data")) {
		//        auth->nc = 1;
		//} else {
		//        auth->nc = 3;
		//}
		return;
	}

	auth->type = 1;
	parts = g_strsplit(hdr, " ", 0);
	while (parts[i]) {
		if ((tmp = parse_attribute("nonce=\"", parts[i]))) {
			auth->nonce = tmp;
		}
		else if ((tmp = parse_attribute("realm=\"", parts[i]))) {
			auth->realm = tmp;
		}
		i++;
	}
	g_strfreev(parts);

	purple_debug(PURPLE_DEBUG_MISC, "sipe", "nonce: %s realm: %s\n", auth->nonce ? auth->nonce : "(null)", auth->realm ? auth->realm : "(null)");
	if (auth->realm) {
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

	sipe_canwrite_cb(gc, sip->fd, PURPLE_INPUT_WRITE);

	/* If there is more to write now, we need to register a handler */
	if (sip->txbuf->bufused > 0)
		sip->tx_handler = purple_input_add(sip->fd, PURPLE_INPUT_WRITE, sipe_canwrite_cb, gc);

	conn = connection_create(sip, source);
	conn->inputhandler = purple_input_add(sip->fd, PURPLE_INPUT_READ, sipe_input_cb, gc);
}

static void send_later_cb_ssl(gpointer data, PurpleSslConnection *gsc, PurpleInputCondition cond)
{
	PurpleConnection *gc = data;
	struct sipe_account_data *sip;
	struct sip_connection *conn;

	if (!PURPLE_CONNECTION_IS_VALID(gc))
	{
		if(gsc) purple_ssl_close(gsc);
		return;
	}

	sip = gc->proto_data;
        sip->gsc = gsc; 
	sip->fd = gsc->fd;
	sip->connecting = FALSE;

	sipe_canwrite_cb_ssl(gc, sip->gsc->fd, PURPLE_INPUT_WRITE);

	/* If there is more to write now */
	if (sip->txbuf->bufused > 0)
	{
                sip->tx_handler = purple_input_add(sip->gsc->fd, PURPLE_INPUT_WRITE, sipe_canwrite_cb_ssl, gc);
	}

	conn = connection_create(sip, sip->gsc->fd);
	purple_ssl_input_add(sip->gsc, sipe_input_cb_ssl, gc);
}


static void sendlater(PurpleConnection *gc, const char *buf)
{
	struct sipe_account_data *sip = gc->proto_data;

	if (!sip->connecting) {
		purple_debug_info("sipe", "connecting to %s port %d\n", sip->realhostname ? sip->realhostname : "{NULL}", sip->realport);
                if (sip->use_ssl){
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
	if (sip->udp) {
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
		msgbd.msg = msg;
		sipmsg_breakdown_parse(&msgbd, sip->registrar.realm, sip->registrar.target);
		// TODO generate this
		msgbd.rand = g_strdup("0878F41B");
		sip->registrar.ntlm_num++;
		msgbd.num = g_strdup_printf("%d", sip->registrar.ntlm_num);
		gchar * signature_input_str = sipmsg_breakdown_get_string(&msgbd);
		if (signature_input_str != NULL) {
			msg->signature = purple_ntlm_sipe_signature_make (signature_input_str, sip->registrar.ntlm_key);
			msg->rand = g_strdup(msgbd.rand);
			msg->num = g_strdup(msgbd.num);
		}
		sipmsg_breakdown_free(&msgbd);
	}

	if (sip->registrar.type && !strcmp(method, "REGISTER")) {
		buf = auth_header_without_newline(sip, &sip->registrar, msg, FALSE);
		if (!purple_account_get_bool(sip->account, "krb5", FALSE)) {
			sipmsg_add_header(msg, "Authorization", buf);
		} else {
			sipmsg_add_header_pos(msg, "Proxy-Authorization", buf, 5);
			//sipmsg_add_header_pos(msg, "Authorization", buf, 5);
		}
		g_free(buf);
	} else if (!strcmp(method,"SUBSCRIBE") || !strcmp(method,"SERVICE") || !strcmp(method,"MESSAGE") || !strcmp(method,"INVITE") || !strcmp(method, "ACK") || !strcmp(method, "NOTIFY") || !strcmp(method, "BYE") || !strcmp(method, "INFO")) {
		sip->registrar.nc=3;
		sip->registrar.type=2;
		
		buf = auth_header_without_newline(sip, &sip->registrar, msg, FALSE);
		//buf = auth_header(sip, &sip->proxy, msg, FALSE);
		sipmsg_add_header_pos(msg, "Proxy-Authorization", buf, 5);
		//sipmsg_add_header(msg, "Authorization", buf);
	        g_free(buf);
	} else {
		purple_debug_info("sipe", "not adding auth header to msg w/ method %s\n", method);
	}
}

static char *get_contact(struct sipe_account_data  *sip)
{
	return g_strdup(sip->contact);
}


static char *get_contact_service(struct sipe_account_data  *sip)
{
	      return g_strdup_printf("<sip:%s:%d;transport=%s;ms-opaque=d3470f2e1d>;proxy=replace;+sip.instance=\"<urn:uuid:%s>\"", purple_network_get_my_ip(-1), sip->listenport,  sip->use_ssl ? "tls" : sip->udp ? "udp" : "tcp",generateUUIDfromEPID(get_epid()));
        //return g_strdup_printf("<sip:%s:%d;maddr=%s;transport=%s>;proxy=replace", sip->username, sip->listenport, purple_network_get_my_ip(-1), sip->use_ssl ? "tls" : sip->udp ? "udp" : "tcp"); 
}

static void send_sip_response(PurpleConnection *gc, struct sipmsg *msg, int code,
		const char *text, const char *body)
{
	gchar *name;
	gchar *value;
	GString *outstr = g_string_new("");
	struct sipe_account_data *sip = gc->proto_data;

	gchar *contact;
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
		sipmsg_add_header(msg, "Content-Length", "0");
	}

	//gchar * mic = purple_krb5_get_mic_for_sipmsg(&krb5_auth, msg);
	//gchar * mic = "MICTODO";
	msg->response = code;

	sipmsg_remove_header(msg, "Authentication-Info");
	sign_outgoing_message(msg, sip, msg->method);

	g_string_append_printf(outstr, "SIP/2.0 %d %s\r\n", code, text);
	GSList *tmp = msg->headers;
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
        gchar *ptmp;
	gchar *ourtag    = dialog && dialog->ourtag    ? g_strdup(dialog->ourtag)    : NULL;
	gchar *theirtag  = dialog && dialog->theirtag  ? g_strdup(dialog->theirtag)  : NULL;
	gchar *theirepid = dialog && dialog->theirepid ? g_strdup(dialog->theirepid) : NULL;
	gchar *callid    = dialog && dialog->callid    ? g_strdup(dialog->callid)    : gencallid();
	gchar *branch    = dialog && dialog->callid    ? NULL : genbranch();
	gchar *useragent = (gchar *)purple_account_get_string(sip->account, "useragent", "Purple/" VERSION);

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
			sip->use_ssl ? "TLS" : sip->udp ? "UDP" : "TCP",
			purple_network_get_my_ip(-1),
			sip->listenport,
			branch ? ";branch=" : "",
			branch ? branch : "",
			sip->username,
			ourtag ? ";tag=" : "",
			ourtag ? ourtag : "",
			get_epid(), // TODO generate one per account/login
			to,
			theirtag ? ";tag=" : "",
			theirtag ? theirtag : "",
			theirepid ? ";epid=" : "",
			theirepid ? theirepid : "",
			dialog ? ++dialog->cseq : ++sip->cseq,
			method,
			useragent,
			callid,
			dialog && dialog->route ? dialog->route : "",
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

	sign_outgoing_message (msg, sip, method);

	buf = sipmsg_to_string (msg);

	/* add to ongoing transactions */
	struct transaction * trans = transactions_add_buf(sip, msg, tc);
	sendout_pkt(gc, buf);

	return trans;
}

static void send_soap_request_with_cb(struct sipe_account_data *sip, gchar *body, TransCallback callback, void * payload)
{
	gchar *from = g_strdup_printf("sip:%s", sip->username); 
	gchar *hdr = g_strdup("Content-Type: application/SOAP+xml\r\n");

	struct transaction * tr = send_sip_request(sip->gc, "SERVICE", from, from, hdr, body, NULL, callback);
	tr->payload = payload;

	g_free(from);
	g_free(hdr);
}

static void send_soap_request(struct sipe_account_data *sip, gchar *body)
{
	send_soap_request_with_cb(sip, body, NULL, NULL);
}

static char *get_contact_register(struct sipe_account_data  *sip)
{
        return g_strdup_printf("<sip:%s:%d;transport=%s;ms-opaque=d3470f2e1d>;methods=\"INVITE, MESSAGE, INFO, SUBSCRIBE, BYE, CANCEL, NOTIFY, ACK, BENOTIFY\";proxy=replace;+sip.instance=\"<urn:uuid:%s>\"", purple_network_get_my_ip(-1), sip->listenport,  sip->use_ssl ? "tls" : sip->udp ? "udp" : "tcp",generateUUIDfromEPID(get_epid()));
}

static void do_register_exp(struct sipe_account_data *sip, int expire)
{
	char *uri = g_strdup_printf("sip:%s", sip->sipdomain);
	char *to = g_strdup_printf("sip:%s", sip->username);
	char *contact = get_contact_register(sip);
	//char *hdr = g_strdup_printf("Contact: %s\r\nExpires: %d\r\n", contact, expire);
       // char *hdr = g_strdup_printf("Contact: %s\r\nEvent: registration\r\nAllow-Events: presence\r\nms-keep-alive: UAC;hop-hop=yes\r\nExpires: %d\r\n", contact,expire);
        //char *hdr = g_strdup_printf("Contact: %s\r\nSupported: com.microsoft.msrtc.presence, adhoclist\r\nms-keep-alive: UAC;hop-hop=yes\r\nEvent: registration\r\nAllow-Events: presence\r\n", contact);
    //char *hdr = g_strdup_printf("Contact: %s\r\nSupported: com.microsoft.msrtc.presence, gruu-10, adhoclist\r\nEvent: registration\r\nAllow-Events: presence\r\nms-keep-alive: UAC;hop-hop=yes\r\nExpires: %d\r\n", contact,expire);
    char *hdr = g_strdup_printf("Contact: %s\r\n"
								"Supported: gruu-10, adhoclist\r\n"
								"Event: registration\r\n"
								"Allow-Events: presence\r\n"
								"ms-keep-alive: UAC;hop-hop=yes\r\n"
								"Expires: %d\r\n", contact,expire);
	g_free(contact);

	sip->registerstatus = 1;

	if (expire) {
		sip->reregister = time(NULL) + expire - 50;
	} else {
		sip->reregister = time(NULL) + 600;
	}

	send_sip_request(sip->gc, "REGISTER", uri, to, hdr, "", NULL,
		process_register_response);

	g_free(hdr);
	g_free(uri);
	g_free(to);
}

static void do_register(struct sipe_account_data *sip)
{
	do_register_exp(sip, sip->registerexpire);
}

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
	xmlnode * node;
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
		purple_debug_info("sipe", "did not add group %s\n", group->name);
	}
}

static struct sipe_group * sipe_group_find_by_id (struct sipe_account_data *sip, int id)
{
	if (sip == NULL) {
		return NULL;
	}

	struct sipe_group *group;
	GSList *entry = sip->groups;
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
	if (sip == NULL) {
		return NULL;
	}

	struct sipe_group *group;
	GSList *entry = sip->groups;
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
	purple_debug_info("sipe", "Renaming group %s to %s\n", group->name, name);
	gchar * body = g_strdup_printf(SIPE_SOAP_MOD_GROUP, group->id, name, sip->delta_num++);
	send_soap_request(sip, body);
	g_free(body);
	g_free(group->name);
	group->name = g_strdup(name);
}

static void
sipe_group_set_user (struct sipe_account_data *sip, struct sipe_group * group, const gchar * who)
{
	struct sipe_buddy *buddy = g_hash_table_lookup(sip->buddies, who);
	PurpleBuddy * purple_buddy = purple_find_buddy (sip->account, who);
  
	if (!group) {
		group = sipe_group_find_by_id (sip, buddy->group_id);
	}
	buddy->group_id = group ? group->id : 1;

	if (buddy && purple_buddy) {
		gchar * alias = purple_buddy_get_alias(purple_buddy);
		purple_debug_info("sipe", "Saving buddy %s with alias %s and group_id %d\n", who, alias, buddy->group_id);
		gchar * body = g_strdup_printf(SIPE_SOAP_SET_CONTACT,
			alias, buddy->group_id, "true", buddy->name, sip->delta_num++
		);
		send_soap_request(sip, body);
		g_free(body);
	}
}

static gboolean process_add_group_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc)
{
	if (msg->response == 200) {
		struct sipe_group * group = g_new0(struct sipe_group, 1);

		struct group_user_context * ctx = (struct group_user_context*)tc->payload;
		group->name = ctx->group_name;

		xmlnode * xml = xmlnode_from_str(msg->body, msg->bodylen);
		if (!xml) return FALSE;

		xmlnode * node = xmlnode_get_descendant(xml, "Body", "addGroup", "groupID", NULL);
		if (!node) return FALSE;

		char * group_id = xmlnode_get_data(node);
		if (!group_id) return FALSE;

		group->id = (int)g_ascii_strtod(group_id, NULL);

		sipe_group_add(sip, group);
		sipe_group_set_user(sip, group, ctx->user_name);

		g_free(ctx);
		xmlnode_free(xml);
		return TRUE;
	}
	return FALSE;
}

static void sipe_group_create (struct sipe_account_data *sip, gchar *name, gchar * who)
{
	struct group_user_context * ctx = g_new0(struct group_user_context, 1);
	ctx->group_name = g_strdup(name);
	ctx->user_name = g_strdup(who);

	gchar * body = g_strdup_printf(SIPE_SOAP_ADD_GROUP, name, sip->delta_num++);
	send_soap_request_with_cb(sip, body, process_add_group_response, ctx);
	g_free(body);
}

static gboolean process_subscribe_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc)
{
	gchar *to;

	if (msg->response == 200 || msg->response == 202) {
		return TRUE;
	}

	to = parse_from(sipmsg_find_header(tc->msg, "To")); /* cant be NULL since it is our own msg */

	/* we can not subscribe -> user is offline (TODO unknown status?) */

	purple_prpl_got_user_status(sip->account, to, "offline", NULL);
	g_free(to);
	return TRUE;
}

static void sipe_subscribe_to_name(struct sipe_account_data *sip, const char * buddy_name)
{
	gchar *to = strstr(buddy_name, "sip:") ? g_strdup(buddy_name) : g_strdup_printf("sip:%s", buddy_name);
	gchar *tmp = get_contact(sip);
	gchar *contact = g_strdup_printf(
		"Accept: application/pidf+xml, application/xpidf+xml\r\n"
		"Event: presence\r\n"
		"Contact: %s\r\n", tmp);
	g_free(tmp);

	/* subscribe to buddy presence */
	send_sip_request(sip->gc, "SUBSCRIBE", to, to, contact, "", NULL, process_subscribe_response);

	g_free(to);
	g_free(contact);
}

static void sipe_subscribe(struct sipe_account_data *sip, struct sipe_buddy *buddy)
{
	sipe_subscribe_to_name(sip, buddy->name);

	/* resubscribe before subscription expires */
	/* add some jitter */
	buddy->resubscribe = time(NULL)+1140+(rand()%50);
}

static void sipe_set_status(PurpleAccount *account, PurpleStatus *status)
{
	PurpleStatusPrimitive primitive = purple_status_type_get_primitive(purple_status_get_type(status));
	struct sipe_account_data *sip = NULL;

	if (!purple_status_is_active(status))
		return;

	if (account->gc)
		sip = account->gc->proto_data;

	if (sip) {
		g_free(sip->status);

		if (primitive == PURPLE_STATUS_AWAY) {
			sip->status = g_strdup("away");
		} else if (primitive == PURPLE_STATUS_AVAILABLE) {
			sip->status = g_strdup("available");
		} else if (primitive == PURPLE_STATUS_UNAVAILABLE) {
			sip->status = g_strdup("busy");
		}

		send_presence_info(sip);
	}
}

static void
sipe_alias_buddy(PurpleConnection *gc, const char *name, const char *alias)
{
	struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;
	sipe_group_set_user(sip, NULL, name);
}

static void
sipe_group_buddy(PurpleConnection *gc,
		 const char *who,
		 const char *old_group_name,
		 const char *new_group_name)
{
	struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;
	struct sipe_group * group = sipe_group_find_by_name(sip, new_group_name);
	if (!group) {
		sipe_group_create(sip, new_group_name, who);
	} else {
		sipe_group_set_user(sip, group, who);
	}
}

static void sipe_add_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
	struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;
	struct sipe_buddy *b;

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
	} else {
		purple_debug_info("sipe", "buddy %s already in internal list\n", buddy->name);
	}
}

// Not Used; Remove?
/*static void sipe_get_buddies(PurpleConnection *gc)
{
	PurpleBlistNode *gnode, *cnode, *bnode;

	purple_debug_info("sipe", "sipe_get_buddies\n");

	for (gnode = purple_get_blist()->root; gnode; gnode = gnode->next) {
		if (!PURPLE_BLIST_NODE_IS_GROUP(gnode)) continue;
		for (cnode = gnode->child; cnode; cnode = cnode->next) {
			if (!PURPLE_BLIST_NODE_IS_CONTACT(cnode)) continue;
			for (bnode = cnode->child; bnode; bnode = bnode->next) {
				if (!PURPLE_BLIST_NODE_IS_BUDDY(bnode)) continue;
				if (((PurpleBuddy*)bnode)->account == gc->account)
					sipe_add_buddy(gc, (PurpleBuddy*)bnode, (PurpleGroup *)gnode);
			}
		}
	}
}*/

static void sipe_remove_buddy(PurpleConnection *gc, PurpleBuddy *buddy, PurpleGroup *group)
{
	struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;
	struct sipe_buddy *b = g_hash_table_lookup(sip->buddies, buddy->name);

	if (!b) return;
	g_hash_table_remove(sip->buddies, buddy->name);

	if (b->name) {
		gchar * body = g_strdup_printf(SIPE_SOAP_DEL_CONTACT, b->name, sip->delta_num++);
		send_soap_request(sip, body);
		g_free(body);
	}

	g_free(b->name);
	g_free(b);
}	

static void
sipe_rename_group(PurpleConnection *gc,
		  const char *old_name,
		  PurpleGroup *group,
		  GList *moved_buddies)
{
	struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;
	struct sipe_group * s_group = sipe_group_find_by_name(sip, old_name);
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
		purple_debug_info("sipe", "Deleting group %s\n", group->name);
		gchar * body = g_strdup_printf(SIPE_SOAP_DEL_GROUP, s_group->id, sip->delta_num++);
		send_soap_request(sip, body);
		g_free(body);

		sip->groups = g_slist_remove(sip->groups, s_group);
		g_free(s_group->name);
	} else {
		purple_debug_info("sipe", "Cannot find group %s to delete\n", group->name);
	}
}

static GList *sipe_status_types(PurpleAccount *acc)
{
	PurpleStatusType *type;
	GList *types = NULL;

	// Available
	type = purple_status_type_new_with_attrs(
		PURPLE_STATUS_AVAILABLE, NULL, NULL, TRUE, TRUE, FALSE,
		"message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
		NULL);
	types = g_list_append(types, type);

	// Away
	type = purple_status_type_new_with_attrs(
		PURPLE_STATUS_AWAY, NULL, NULL, TRUE, TRUE, FALSE,
		"message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
		NULL);
	types = g_list_append(types, type);

	// Busy
	type = purple_status_type_new_with_attrs(
		PURPLE_STATUS_UNAVAILABLE, "busy", _("Busy"), TRUE, TRUE, FALSE,
		"message", _("Message"), purple_value_new(PURPLE_TYPE_STRING),
		NULL);
	types = g_list_append(types, type);

	// Offline
	type = purple_status_type_new_full(
		PURPLE_STATUS_OFFLINE, NULL, NULL, TRUE, TRUE, FALSE);
	types = g_list_append(types, type);

	return types;
}

static gboolean sipe_add_lcs_contacts(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc)
{
	int len = msg->bodylen;

	gchar *tmp = sipmsg_find_header(msg, "Event");
	if (!tmp || strncmp(tmp, "vnd-microsoft-roaming-contacts", 30)) {
		return FALSE;
	}

	/* Convert the contact from XML to Purple Buddies */
	xmlnode * isc = xmlnode_from_str(msg->body, len);
	if (!isc) {
		return FALSE;
	}

	char * delta_num = xmlnode_get_attrib(isc, "deltaNum");
	if (delta_num) {
		sip->delta_num = (int)g_ascii_strtod(delta_num, NULL);
	}

	/* Parse groups */
	xmlnode *group_node;
	for (group_node = xmlnode_get_child(isc, "group"); group_node; group_node = xmlnode_get_next_twin(group_node)) {
		struct sipe_group * group = g_new0(struct sipe_group, 1);

		group->name = xmlnode_get_attrib(group_node, "name");
		if (!strncmp(group->name, "~", 1)){
			// TODO translate
			group->name = "General";
		}
		group->name = g_strdup(group->name);
		group->id = (int)g_ascii_strtod(xmlnode_get_attrib(group_node, "id"), NULL);

		sipe_group_add(sip, group);
	}

	// Make sure we have at least one group
	if (g_slist_length(sip->groups) == 0) {
		struct sipe_group * group = g_new0(struct sipe_group, 1);
		// TODO translate
		group->name = g_strdup("General");
		group->id = 1;
		PurpleGroup * purple_group = purple_group_new(group->name);
		purple_blist_add_group(purple_group, NULL);
		sip->groups = g_slist_append(sip->groups, group);
	}

	/* Parse contacts */
	xmlnode *item;
	for (item = xmlnode_get_child(isc, "contact"); item; item = xmlnode_get_next_twin(item)) {
		char * uri = xmlnode_get_attrib(item, "uri");
		char * name = xmlnode_get_attrib(item, "name");
		gchar **item_groups = g_strsplit(xmlnode_get_attrib(item, "groups"), " ", 0);

		struct sipe_group * group = NULL;

		// Find the first group this contact belongs to; that's where we'll place it in the buddy list
		if (item_groups[0]) {
			group = sipe_group_find_by_id(sip, g_ascii_strtod(item_groups[0], NULL));
		}

		// If couldn't find the right group for this contact, just put them in the first group we have
		if (group == NULL && g_slist_length(sip->groups) > 0) {
			group = sip->groups->data;
		}

		if (group != NULL) {
			char * buddy_name = g_strdup_printf("sip:%s", uri);

			//b = purple_find_buddy(sip->account, buddy_name); 
			PurpleBuddy *b = purple_find_buddy_in_group(sip->account, buddy_name, group->purple_group);
			if (!b){
				b = purple_buddy_new(sip->account, buddy_name, uri);
			}
			g_free(buddy_name);

			purple_blist_add_buddy(b, NULL, group->purple_group, NULL);

			if (name != NULL && strlen(name) != 0) {
				purple_blist_alias_buddy(b, name);
			} else {
				purple_blist_alias_buddy(b, uri);
			}

			struct sipe_buddy * buddy = g_new0(struct sipe_buddy, 1);
			buddy->name = g_strdup(b->name);
			buddy->group_id = group->id;
			g_hash_table_insert(sip->buddies, buddy->name, buddy);

			purple_debug_info("sipe", "Added buddy %s to group %s\n", buddy->name, group->name);
		} else {
			purple_debug_info("sipe", "No group found for contact %s!  Unable to add to buddy list\n",
				name);
		}
	}

	xmlnode_free(isc); 

	return 0;
}

static void sipe_subscribe_buddylist(struct sipe_account_data *sip,struct sipmsg *msg)
{
	gchar *to = g_strdup_printf("sip:%s", sip->username); 
	gchar *tmp = get_contact(sip);
	gchar *hdr = g_strdup_printf("Event: vnd-microsoft-roaming-contacts\r\n"
								 "Accept: application/vnd-microsoft-roaming-contacts+xml\r\n"
								 "Supported: com.microsoft.autoextend\r\n"
								 "Supported: ms-benotify\r\n"
								 "Proxy-Require: ms-benotify\r\n"
								 "Supported: ms-piggyback-first-notify\r\n"
								 "Contact: %s\r\n", tmp);
	g_free(tmp);
	
	send_sip_request(sip->gc, "SUBSCRIBE", to, to, hdr, "", NULL, sipe_add_lcs_contacts);
	g_free(to);
	g_free(hdr);
}

static void sipe_subscribe_roaming_self(struct sipe_account_data *sip,struct sipmsg *msg)
{
	gchar *to = g_strdup_printf("sip:%s", sip->username); 
	gchar *tmp = get_contact(sip);
	gchar *hdr = g_strdup_printf("Event: vnd-microsoft-roaming-self\r\n"
								 "Accept: application/vnd-microsoft-roaming-self+xml\r\n"
								 "Supported: com.microsoft.autoextend\r\n"
								 "Supported: ms-benotify\r\n"
								 "Proxy-Require: ms-benotify\r\n"
								 "Supported: ms-piggyback-first-notify\r\n"
								 "Contact: %s\r\n"
								 "Content-Type: application/vnd-microsoft-roaming-self+xml\r\n"
								 ,tmp);
	
	g_free(tmp);
	
	gchar *body=g_strdup("<roamingList xmlns=\"http://schemas.microsoft.com/2006/09/sip/roaming-self\"><roaming type=\"categories\"/><roaming type=\"containers\"/><roaming type=\"subscribers\"/></roamingList>");

	send_sip_request(sip->gc, "SUBSCRIBE", to, to, hdr, body, NULL, NULL);
	g_free(body);					 
	g_free(to);
	g_free(hdr);
}

static void sipe_subscribe_roaming_provisioning(struct sipe_account_data *sip,struct sipmsg *msg)
{
	gchar *to = g_strdup_printf("sip:%s", sip->username); 
	gchar *tmp = get_contact(sip);
	gchar *hdr = g_strdup_printf("Event: vnd-microsoft-provisioning-v2\r\n"
								 "Accept: application/vnd-microsoft-roaming-provisioning-v2+xml\r\n"
								 "Supported: com.microsoft.autoextend\r\n"
								 "Supported: ms-benotify\r\n"
								 "Proxy-Require: ms-benotify\r\n"
								 "Supported: ms-piggyback-first-notify\r\n"
								 "Expires: 0\r\n"
								 "Contact: %s\r\n"
								 "Content-Type: application/vnd-microsoft-roaming-provisioning-v2+xml\r\n"
								 ,tmp);
	
	g_free(tmp);
	
	gchar *body=g_strdup("<provisioningGroupList xmlns=\"http://schemas.microsoft.com/2006/09/sip/provisioninggrouplist\"><provisioningGroup name=\"ServerConfiguration\"/><provisioningGroup name=\"meetingPolicy\"/><provisioningGroup name=\"ucPolicy\"/></provisioningGroupList>");
	send_sip_request(sip->gc, "SUBSCRIBE", to, to, hdr, body, NULL, NULL);
	g_free(body);					 
	g_free(to);
	g_free(hdr);
}

/* IM Session (INVITE and MESSAGE methods) */

static struct sip_im_session * find_im_session (struct sipe_account_data *sip, const char *who)
{
	if (sip == NULL || who == NULL) {
		return NULL;
	}

	struct sip_im_session *session;
	GSList *entry = sip->im_sessions;
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
		sip->im_sessions = g_slist_append(sip->im_sessions, session);
	}
	return session;
}

static void im_session_destroy(struct sipe_account_data *sip, struct sip_im_session * session)
{
	sip->im_sessions = g_slist_remove(sip->im_sessions, session);
	// TODO free session resources
}

static void sipe_send_message(struct sipe_account_data *sip, struct sip_im_session * session, const char *msg)
{
	gchar *hdr;
	gchar *fullto;
        gchar *tmp;

	if (strncmp("sip:", session->with, 4)) {
		fullto = g_strdup_printf("sip:%s", session->with);
	} else {
		fullto = g_strdup(session->with);
	}

	hdr = g_strdup("Content-Type: text/plain; charset=UTF-8\r\n");
	//hdr = g_strdup("Content-Type: text/rtf\r\n");
	//hdr = g_strdup("Content-Type: text/plain; charset=UTF-8;msgr=WAAtAE0ATQBTAC0ASQBNAC0ARgBvAHIAbQBhAHQAOgAgAEYATgA9AE0AUwAlADIAMABTAGgAZQBsAGwAJQAyADAARABsAGcAJQAyADAAMgA7ACAARQBGAD0AOwAgAEMATwA9ADAAOwAgAEMAUwA9ADAAOwAgAFAARgA9ADAACgANAAoADQA\r\nSupported: timer\r\n");

        tmp = get_contact(sip);
	hdr = g_strdup_printf("Contact: %s\r\n%s", tmp, hdr);
	g_free(tmp);

	send_sip_request(sip->gc, "MESSAGE", fullto, fullto, hdr, msg, session->dialog, NULL);

	g_free(hdr);
	g_free(fullto);
}


static void
sipe_im_process_queue (struct sipe_account_data * sip, struct sip_im_session * session)
{
	GSList *entry = session->outgoing_message_queue;
	while (entry) {
		char *queued_msg = entry->data;
		sipe_send_message(sip, session, queued_msg);

		// Remove from the queue and free the string
		entry = session->outgoing_message_queue = g_slist_remove(session->outgoing_message_queue, queued_msg);
		g_free(queued_msg);
	}
}

static void
sipe_parse_dialog(struct sipmsg * msg, struct sip_dialog * dialog, gboolean outgoing)
{
	gchar *us = outgoing ? "From" : "To";
	gchar *them = outgoing ? "To" : "From";

	dialog->callid = sipmsg_find_header(msg, "Call-ID");
	dialog->ourtag = find_tag(sipmsg_find_header(msg, us));
	dialog->theirtag = find_tag(sipmsg_find_header(msg, them));
	if (!dialog->theirepid) {
		dialog->theirepid = sipmsg_find_part_of_header(sipmsg_find_header(msg, them), "epid=", ";", NULL);
	}
	if (!dialog->theirepid) {
		dialog->theirepid = sipmsg_find_part_of_header(sipmsg_find_header(msg, them), "epid=", NULL, NULL);
	}

	dialog->request = sipmsg_find_part_of_header(sipmsg_find_header(msg, "Record-Route"), "<", ">", NULL);
	dialog->route = g_strdup_printf("Route: %s\r\n", sipmsg_find_header(msg, "Contact"));
}


static gboolean
process_invite_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *trans)
{
	gchar * with = parse_from(sipmsg_find_header(msg, "To"));
	struct sip_im_session * session = find_im_session(sip, with);
	g_free(with);

	if (!session) {
		purple_debug_info("sipe", "process_invite_response: unable to find IM session\n");
		return FALSE;
	}

	if (msg->response != 200) {
		purple_debug_info("sipe", "process_invite_response: INVITE response not 200, ignoring\n");
		im_session_destroy(sip, session);
		return FALSE;
	}

	struct sip_dialog * dialog = session->dialog;
	if (!dialog) {
		purple_debug_info("sipe", "process_invite_response: session outgoign dialog is NULL\n");
		return FALSE;
	}

	sipe_parse_dialog(msg, dialog, TRUE);
	dialog->cseq = 0;

	send_sip_request(sip->gc, "ACK", session->with, session->with, NULL, NULL, dialog, NULL);
	session->outgoing_invite = NULL;
	sipe_im_process_queue(sip, session);

	return TRUE;
}


static void sipe_invite(struct sipe_account_data *sip, struct sip_im_session * session)
{
	gchar *hdr;
	gchar *to;
	gchar *contact;
	gchar *body;

	if (session->dialog) {
		purple_debug_info("sipe", "session with %s already has a dialog open\n", session->with);
		return;
	}

	session->dialog = g_new0(struct sip_dialog, 1);

	if (strstr(session->with, "sip:")) {
		to = g_strdup(session->with);
	} else {
		to = g_strdup_printf("sip:%s", session->with);
	}

	contact = get_contact(sip);
	hdr = g_strdup_printf(
		"Contact: %s\r\n"
		"Content-Type: application/sdp\r\n",
		contact, sip->username, sip->username, to);

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
	struct sipe_account_data *sip = gc->proto_data;
	char *to = g_strdup(who);
	char *text = purple_unescape_html(what);

	struct sip_im_session * session = find_or_create_im_session(sip, who);

	// Queue the message
	session->outgoing_message_queue = g_slist_append(session->outgoing_message_queue, text);

	if (session->dialog && session->dialog->callid) {
		sipe_im_process_queue(sip, session);
	} else if (!session->outgoing_invite) {
		// Need to send the INVITE to get the outgoing dialog setup
		sipe_invite(sip, session);
	}

	g_free(to);
	return 1;
}


/* End IM Session (INVITE and MESSAGE methods) */

static unsigned int
sipe_send_typing(PurpleConnection *gc, const char *who, PurpleTypingState state)
{
	struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;

	if (state == PURPLE_NOT_TYPING)
		return 0;

	struct sip_im_session * session = find_im_session(sip, who);

	if (session && session->dialog) {
		send_sip_request(gc, "INFO", who, who,
			"Content-Type: application/xml\r\n",
			SIPE_SEND_TYPING, session->dialog, NULL);
	}

	return SIPE_TYPING_SEND_TIMEOUT;
}


static void sipe_buddy_resub(char *name, struct sipe_buddy *buddy, struct sipe_account_data *sip)
{
	time_t curtime = time(NULL);
	if (buddy->resubscribe < curtime) {
		purple_debug(PURPLE_DEBUG_MISC, "sipe", "sipe_buddy_resub %s\n", name);
		sipe_subscribe(sip, buddy);
	}
}

static gboolean resend_timeout(struct sipe_account_data *sip)
{
	GSList *tmp = sip->transactions;
	time_t currtime = time(NULL);
	while (tmp) {
		struct transaction *trans = tmp->data;
		tmp = tmp->next;
		purple_debug_info("sipe", "have open transaction age: %d\n", currtime- trans->time);
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

static gboolean subscribe_timeout(struct sipe_account_data *sip)
{
	GSList *tmp;
	time_t curtime = time(NULL);
	/* register again if first registration expires */
	if (sip->reregister < curtime) {
		do_register(sip);
	}
	/* check for every subscription if we need to resubscribe */
	//Fixxxer we need resub?
	g_hash_table_foreach(sip->buddies, (GHFunc)sipe_buddy_resub, (gpointer)sip);

	/* remove a timed out suscriber */

	tmp = sip->watcher;
	while (tmp) {
		struct sipe_watcher *watcher = tmp->data;
		if (watcher->expire < curtime) {
			watcher_remove(sip, watcher->name);
			tmp = sip->watcher;
		}
		if (tmp) tmp = tmp->next;
	}

	return TRUE;
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
	if (!contenttype || !strncmp(contenttype, "text/plain", 10) || !strncmp(contenttype, "text/html", 9)) {
		serv_got_im(sip->gc, from, msg->body, 0, time(NULL));
		send_sip_response(sip->gc, msg, 200, "OK", NULL);
		found = TRUE;
	}
	if (!strncmp(contenttype, "application/im-iscomposing+xml", 30)) {
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
	// Only accept text invitations
	if (msg->body && !strstr(msg->body, "m=message")) {
		send_sip_response(sip->gc, msg, 501, "Not implemented", NULL);
		return;
	}

	gchar * from = sipmsg_find_part_of_header(sipmsg_find_header(msg, "From"), "<", ">", NULL);
	struct sip_im_session * session = find_or_create_im_session (sip, from);
	if (session) {
		if (session->dialog) {
			purple_debug_info("sipe", "process_incoming_invite, session already has dialog!\n");
		} else {
			session->dialog = g_new0(struct sip_dialog, 1);

			sipe_parse_dialog(msg, session->dialog, FALSE);

			session->dialog->callid = sipmsg_find_header(msg, "Call-ID");
			session->dialog->ourtag = find_tag(sipmsg_find_header(msg, "To"));
			session->dialog->theirtag = find_tag(sipmsg_find_header(msg, "From"));
			session->dialog->theirepid = sipmsg_find_part_of_header(sipmsg_find_header(msg, "From"), "epid=", NULL, NULL);
		}
	} else {
		purple_debug_info("sipe", "process_incoming_invite, failed to find or create IM session\n");
	}
	g_free(from);

	send_sip_response(sip->gc, msg, 200, "OK", g_strdup_printf(
		"v=0\r\n"
		"o=- 0 0 IN IP4 %s\r\n"
		"s=session\r\n"
		"c=IN IP4 %s\r\n"
		"t=0 0\r\n"
		"m=message %d sip sip:%s\r\n"
		"a=accept-types:text/plain text/html image/gif multipart/alternative application/im-iscomposing+xml\r\n",
		purple_network_get_my_ip(-1), purple_network_get_my_ip(-1),
		sip->realport, sip->username));
}

static void sipe_connection_cleanup(struct sipe_account_data *);
static void create_connection(struct sipe_account_data *, gchar *, int);

gboolean process_register_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc)
{
	gchar *tmp, krb5_token;
	const gchar *expires_header;
	int expires;

	expires_header = sipmsg_find_header(msg, "Expires");
	expires = expires_header != NULL ? strtol(expires_header, NULL, 10) : 0;
	purple_debug_info("sipe", "process_register_response: got response to REGISTER; expires = %d\n", expires);
					
	switch (msg->response) {
		case 200:
			if (expires == 0) {
				sip->registerstatus = 0;
			} else {
				sip->registerstatus = 3;
				purple_connection_set_state(sip->gc, PURPLE_CONNECTED);
				
				gchar *gruu = sipmsg_find_part_of_header(sipmsg_find_header(msg, "Contact"), "gruu=\"", "\"", NULL);
				if(gruu) {
					sip->contact = g_strdup_printf("<%s>", gruu);
				} else {
					sip->contact = g_strdup_printf("<sip:%s:%d;maddr=%s;transport=%s>;proxy=replace", sip->username, sip->listenport, purple_network_get_my_ip(-1), sip->use_ssl ? "tls" : sip->udp ? "udp" : "tcp");
				}

				/* get buddies from blist; Has a bug */
				subscribe_timeout(sip);

				tmp = sipmsg_find_header(msg, "Allow-Events");
				if (tmp && strstr(tmp, "vnd-microsoft-provisioning")){
					sipe_subscribe_buddylist(sip, msg);
				}
				
				sipe_subscribe_roaming_self(sip, msg);
				sipe_subscribe_roaming_provisioning(sip, msg);
				sipe_set_status(sip->account, purple_account_get_active_status(sip->account));
				
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
					gboolean udp = 0;
					gboolean tls = 0;
					int i = 1;

					tmp = g_strsplit(parts[0], ":", 0);
					hostname = g_strdup(tmp[0]);
					if (tmp[1]) port = strtoul(tmp[1], NULL, 10);
					g_strfreev(tmp);

					while (parts[i]) {
						tmp = g_strsplit(parts[i], "=", 0);
						if (tmp[1]) {
							if (g_strcasecmp("transport", tmp[0]) == 0) {
								if        (g_strcasecmp("tls", tmp[1]) == 0) {
									tls = 1;
								} else if (g_strcasecmp("udp", tmp[1]) == 0) {
									udp = 1;
								}
							}
						}
						g_strfreev(tmp);
						i++;
					}
					g_strfreev(parts);

					purple_debug_info("sipe", "process_register_response: redirected to host %s port %d transport %s\n",
							  hostname, port, tls ? "tls" : udp ? "udp" : "tcp");

					/* Close old connection */
					sipe_connection_cleanup(sip);

					/* Create new connection */
					sip->udp = udp;
					sip->use_ssl = tls;
					create_connection(sip, hostname, port);
				}
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
					warning = g_strdup_printf("You have been rejected by the server: %s", tmp[1] ? tmp[1] : "no reason given");
					g_strfreev(tmp);
				} else {
					warning = _("You have been rejected by the server");
				}

				sip->gc->wants_to_die = TRUE;
				purple_connection_error(sip->gc, warning);
				return TRUE;
			}
			break;
		}
	return TRUE;
}

static void process_incoming_notify(struct sipe_account_data *sip, struct sipmsg *msg)
{
	gchar *from;
	gchar *fromhdr;
	gchar *tmp2;
	gchar *activity = g_strdup("available");
	xmlnode *pidf;
	xmlnode *basicstatus = NULL, *tuple, *status;
	gboolean isonline = FALSE;

	fromhdr = sipmsg_find_header(msg, "From");
	from = parse_from(fromhdr);

	if (!from) {
		return;
	}

	pidf = xmlnode_from_str(msg->body, msg->bodylen);
	if (!pidf) {
		purple_debug_info("sipe", "process_incoming_notify: no parseable pidf\n");
		return;
	}

	if ((tuple = xmlnode_get_child(pidf, "tuple"))) {
		if ((status = xmlnode_get_child(tuple, "status"))) {
			basicstatus = xmlnode_get_child(status, "basic");
		}
	}

	if (!basicstatus) {
		purple_debug_info("sipe", "process_incoming_notify: no basic found\n");
		xmlnode_free(pidf);
		return;
	}

	tmp2 = xmlnode_get_data(basicstatus);
	if (!tmp2) {
		purple_debug_info("sipe", "process_incoming_notify: no basic data found\n");
		xmlnode_free(pidf);
		return;
	}

        purple_debug_info("sipe", "process_incoming_notify: basic-status(%s)\n", tmp2);
	if (strstr(tmp2, "open")) {
		isonline = TRUE;
	}

	xmlnode *display_name_node = xmlnode_get_child(pidf, "display-name");
	if (display_name_node) {
		PurpleBuddy * buddy = purple_find_buddy (sip->account, from);
		char * display_name = xmlnode_get_data(display_name_node);
		if (buddy && display_name) {
			purple_blist_server_alias_buddy (buddy, g_strdup(display_name));
		}
	}

	if ((tuple = xmlnode_get_child(pidf, "tuple"))) {
		if ((status = xmlnode_get_child(tuple, "status"))) {
			if (basicstatus = xmlnode_get_child(status, "activities")) {
				if (basicstatus = xmlnode_get_child(basicstatus, "activity")) {
					activity = xmlnode_get_data(basicstatus);
				}
			}
		}
	}
        purple_debug_info("sipe", "process_incoming_notify: activity(%s)\n", activity);

	if (isonline) {
		gchar * status_id = NULL;
		if (activity) {
			if (strstr(activity, "busy")) {
				status_id = "busy";
			} else if (strstr(activity, "away")) {
				status_id = "away";
			}
		}

		if (!status_id) {
			status_id = "available";
		}

		purple_debug_info("sipe", "process_incoming_notify: status_id(%s)\n", status_id);
		purple_prpl_got_user_status(sip->account, from, status_id, NULL);
	} else {
		purple_prpl_got_user_status(sip->account, from, "offline", NULL);
	}

	xmlnode_free(pidf);
	g_free(from);
	g_free(tmp2);
	g_free(activity);

	send_sip_response(sip->gc, msg, 200, "OK", NULL);
}

static void process_incoming_benotify(struct sipe_account_data *sip, struct sipmsg *msg)
{
	xmlnode *xml = xmlnode_from_str(msg->body, msg->bodylen);
	if (!xml) return;

	char * delta_num = xmlnode_get_attrib(xml, "deltaNum");
	if (delta_num) {
		sip->delta_num = (int)g_ascii_strtod(delta_num, NULL);
	}

	xmlnode_free(xml);
}


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

static void send_notify(struct sipe_account_data *sip, struct sipe_watcher *watcher)
{
	gchar *doc = watcher->needsxpidf ? gen_xpidf(sip) : gen_pidf(sip);
	gchar *hdr = watcher->needsxpidf ? "Event: presence\r\nContent-Type: application/xpidf+xml\r\n" : "Event: presence\r\nContent-Type: application/pidf+xml\r\n";
	send_sip_request(sip->gc, "NOTIFY", watcher->name, watcher->name, hdr, doc, &watcher->dialog, NULL);
	g_free(doc);
}

static gboolean process_service_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc)
{
	
	if (msg->response != 200 && msg->response != 408) {
		/* never send again */
		sip->republish = -1;
	}
	return TRUE;
}

static void send_clear_notes(struct sipe_account_data *sip)
{
}

static gboolean
process_send_presence_info_v0_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc)
{
	if (msg->response == 488) {
		sip->presence_method_version = 1;
		send_presence_info(sip);
	}
	return TRUE;
}

static void send_presence_info_v0(struct sipe_account_data *sip, char * note)
{
	int code;
	if (!strcmp(sip->status, "away")) {
		code = 100;
	} else if (!strcmp(sip->status, "busy")) {
		code = 600;
	} else {
		// Available
		code = 400;
	}

	gchar *name = g_strdup_printf("sip: sip:%s", sip->username); 
	gchar * body = g_strdup_printf(SIPE_SOAP_SET_PRESENCE, name, 200, code, note);
	send_soap_request_with_cb(sip, body, process_send_presence_info_v0_response, NULL);
	g_free(name);
	g_free(body);
}

static gboolean
process_clear_presence_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc)
{
	// Version(s) of presence info were out of date; tell the server to clear them, then we'll try again
	if (msg->response == 200) {
		sip->status_version = 0;
		send_presence_info(sip);
	}
	return TRUE;
}

static gboolean
process_send_presence_info_v1_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc)
{
	if (msg->response == 409) {
		// Version(s) of presence info were out of date; tell the server to clear them, then we'll try again
		// TODO need to parse the version #'s?
		gchar *uri = g_strdup_printf("sip:%s", sip->username);
		gchar *doc = g_strdup_printf(SIPE_SEND_CLEAR_PRESENCE, uri);

		gchar *tmp = get_contact(sip);
		gchar *hdr = g_strdup_printf("Contact: %s\r\n"
			"Content-Type: application/msrtc-category-publish+xml\r\n", tmp);

		send_sip_request(sip->gc, "SERVICE", uri, uri, hdr, doc, NULL, process_clear_presence_response);

		g_free(tmp); 
		g_free(hdr);
		g_free(uri);
		g_free(doc);
	}
	return TRUE;
}

static void send_presence_info_v1(struct sipe_account_data *sip, char * note)
{
	int code;
	if (!strcmp(sip->status, "away")) {
		code = 12000;
	} else if (!strcmp(sip->status, "busy")) {
		code = 6000;
	} else {
		// Available
		code = 3000;
	}

	gchar *uri = g_strdup_printf("sip:%s", sip->username);
	gchar *doc = g_strdup_printf(SIPE_SEND_PRESENCE, uri,
		sip->status_version, code,
		sip->status_version, code,
		sip->status_version, note ? note : "",
		sip->status_version, note ? note : "",
		sip->status_version, note ? note : ""
	);
	sip->status_version++;

	gchar *tmp = get_contact(sip);
	gchar *hdr = g_strdup_printf("Contact: %s\r\n"
		"Content-Type: application/msrtc-category-publish+xml\r\n", tmp);

	send_sip_request(sip->gc, "SERVICE", uri, uri, hdr, doc, NULL, process_send_presence_info_v1_response);

	g_free(tmp); 
	g_free(hdr);
	g_free(uri);
	g_free(doc);
}

static void send_presence_info(struct sipe_account_data *sip)
{
	PurpleStatus * status = purple_account_get_active_status(sip->account);
	if (!status) return;

	char *note = purple_status_get_attr_string(status, "message");

	purple_debug_info("sipe", "sending presence info, version = %d\n", sip->presence_method_version);
	if (sip->presence_method_version != 1) {
		send_presence_info_v0(sip, note);
	} else {
		send_presence_info_v1(sip, note);
	}
}

static void send_service(struct sipe_account_data *sip)
{
	//gchar *uri = g_strdup_printf("sip:%s@%s", sip->username, sip->sipdomain);
	gchar *uri = g_strdup_printf("sip:%s", sip->username);
	//gchar *doc = gen_pidf(sip);

	gchar *doc = gen_pidf(sip);
	gchar *hdr = g_strdup("Event: presence\r\nContent-Type: application/pidf+xml\r\n");

        //gchar *hdr = g_strdup("Content-Type: application/SOAP+xml\r\n");
        gchar *tmp = get_contact(sip);
        hdr = g_strdup_printf("Contact: %s\r\n%s; +sip.instance=\"<urn:uuid:%s>\"", tmp, hdr,generateUUIDfromEPID(get_epid()));
        g_free(tmp); 
	send_sip_request(sip->gc, "SERVICE", uri, uri,
		hdr,
		doc, NULL, process_service_response);
	sip->republish = time(NULL) + 500;
        g_free(hdr);
	g_free(uri);
	g_free(doc);
}

static void process_incoming_subscribe(struct sipe_account_data *sip, struct sipmsg *msg)
{
	const char *from_hdr = sipmsg_find_header(msg, "From");
	gchar *from = parse_from(from_hdr);
	gchar *theirtag = find_tag(from_hdr);
	gchar *ourtag = find_tag(sipmsg_find_header(msg, "To"));
	gboolean tagadded = FALSE;
	gchar *callid = sipmsg_find_header(msg, "Call-ID");
	gchar *expire = sipmsg_find_header(msg, "Expire");
	gchar *tmp;
	struct sipe_watcher *watcher = watcher_find(sip, from);
	if (!ourtag) {
		tagadded = TRUE;
		ourtag = gentag();
	}
	if (!watcher) { /* new subscription */
		gchar *acceptheader = sipmsg_find_header(msg, "Accept");
		gboolean needsxpidf = FALSE;
		if (!purple_privacy_check(sip->account, from)) {
			send_sip_response(sip->gc, msg, 202, "Ok", NULL);
			goto privend;
		}
		if (acceptheader) {
			gchar *tmp = acceptheader;
			gboolean foundpidf = FALSE;
			gboolean foundxpidf = FALSE;
			while (tmp && tmp < acceptheader + strlen(acceptheader)) {
				gchar *tmp2 = strchr(tmp, ',');
				if (tmp2) *tmp2 = '\0';
				if (!strcmp("application/pidf+xml", tmp))
					foundpidf = TRUE;
				if (!strcmp("application/xpidf+xml", tmp))
					foundxpidf = TRUE;
				if (tmp2) {
					*tmp2 = ',';
					tmp = tmp2;
					while (*tmp == ' ') tmp++;
				} else
					tmp = 0;
			}
			if (!foundpidf && foundxpidf) needsxpidf = TRUE;
			g_free(acceptheader);
		}
		watcher = watcher_create(sip, from, callid, ourtag, theirtag, needsxpidf);
	}
	if (tagadded) {
		gchar *to = g_strdup_printf("%s;tag=%s", sipmsg_find_header(msg, "To"), ourtag);
		sipmsg_remove_header(msg, "To");
		sipmsg_add_header(msg, "To", to);
		g_free(to);
	}
	if (expire)
		watcher->expire = time(NULL) + strtol(expire, NULL, 10);
	else
		watcher->expire = time(NULL) + 600;
	//Fixxxer
	sipmsg_remove_header(msg, "Contact");
	tmp = get_contact(sip);
	sipmsg_add_header(msg, "Contact", tmp);
	g_free(tmp);
	purple_debug_info("sipe", "got subscribe: name %s ourtag %s theirtag %s callid %s\n", watcher->name, watcher->dialog.ourtag, watcher->dialog.theirtag, watcher->dialog.callid);
	send_sip_response(sip->gc, msg, 200, "Ok", NULL);
	send_notify(sip, watcher);
privend:
	g_free(from);
	g_free(theirtag);
	g_free(ourtag);
	g_free(callid);
	g_free(expire);
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
			process_incoming_notify(sip, msg);
			found = TRUE;
		} else if (!strcmp(msg->method, "BENOTIFY")) {
			purple_debug_info("sipe","send->process_incoming_benotify\n");
			process_incoming_benotify(sip, msg);
			found = TRUE;
		} else if (!strcmp(msg->method, "SUBSCRIBE")) {
			purple_debug_info("sipe","send->process_incoming_subscribe\n");
			process_incoming_subscribe(sip, msg);
			found = TRUE;
		} else if (!strcmp(msg->method, "INVITE")) {
			process_incoming_invite(sip, msg);
			found = TRUE;
		} else if (!strcmp(msg->method, "INFO")) {
			// TODO needs work
			gchar * from = parse_from(sipmsg_find_header(msg, "From"));
			if (from) {
				serv_got_typing(sip->gc, from, SIPE_TYPING_RECV_TIMEOUT, PURPLE_TYPING);
			}
			send_sip_response(sip->gc, msg, 200, "OK", NULL);
			found = TRUE;
		} else if (!strcmp(msg->method, "ACK")) {
			// ACK's don't need any response
			found = TRUE;
		} else if (!strcmp(msg->method, "BYE")) {
			send_sip_response(sip->gc, msg, 200, "OK", NULL);

			gchar * from = parse_from(sipmsg_find_header(msg, "From"));
			struct sip_im_session * session = find_im_session (sip, from);
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
				auth = auth_header(sip, &sip->proxy, trans->msg, TRUE);
				sipmsg_remove_header(trans->msg, "Proxy-Authorization");
				sipmsg_add_header_pos(trans->msg, "Proxy-Authorization", auth, 5);
				g_free(auth);
				resend = sipmsg_to_string(trans->msg);
				/* resend request */
				sendout_pkt(sip->gc, resend);
				g_free(resend);
			} else {
				if (msg->response == 100) {
					/* ignore provisional response */
					purple_debug_info("sipe", "got trying response\n");
				} else {
					sip->proxy.retries = 0;
					if (!strcmp(trans->msg->method, "REGISTER")) {
						if (msg->response == 401) sip->registrar.retries++;
						else sip->registrar.retries = 0;
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
							auth = auth_header(sip, &sip->registrar, trans->msg, TRUE);
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
			purple_debug(PURPLE_DEBUG_MISC, "sipe", "received response to unknown transaction");
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
	while ((cur = strstr(conn->inbuf, "\r\n\r\n")) != NULL) {
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
			sipmsg_free(msg);
			return;
		}

		if (msg->body) {
			purple_debug_info("sipe", "body:\n%s", msg->body);
		}

		// Verify the signature before processing it
		if (sip->registrar.ntlm_key) {
			struct sipmsg_breakdown msgbd;
			msgbd.msg = msg;
			sipmsg_breakdown_parse(&msgbd, sip->registrar.realm, sip->registrar.target);
			gchar * signature_input_str = sipmsg_breakdown_get_string(&msgbd);
			gchar * signature;
			if (signature_input_str != NULL) {
				signature = purple_ntlm_sipe_signature_make (signature_input_str, sip->registrar.ntlm_key);
			}

			gchar * rspauth = sipmsg_find_part_of_header(sipmsg_find_header(msg, "Authentication-Info"), "rspauth=\"", "\"", NULL);
			if (signature != NULL && rspauth != NULL) {
				if (purple_ntlm_verify_signature (signature, rspauth)) {
					purple_debug(PURPLE_DEBUG_MISC, "sipe", "incoming message's signature validated\n");
					process_input_message(sip, msg);
				} else {
					purple_debug(PURPLE_DEBUG_MISC, "sipe", "incoming message's signature is invalid.  Received %s but generated %s; Ignoring message\n", rspauth, signature);
					purple_connection_error(sip->gc, _("Invalid message signature received"));
					sip->gc->wants_to_die = TRUE;
				}
			}

			sipmsg_breakdown_free(&msgbd);
		} else {
			process_input_message(sip, msg);
		}
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

static void sipe_input_cb_ssl(gpointer data, PurpleSslConnection *gsc, PurpleInputCondition cond)
{
	PurpleConnection *gc = data;
	struct sipe_account_data *sip = gc->proto_data;
	struct sip_connection *conn = NULL;
	int len;
	static char buf[4096];

	/* TODO: It should be possible to make this check unnecessary */
	if (!PURPLE_CONNECTION_IS_VALID(gc)) {
		purple_ssl_close(gsc);
		return;
	}

	if (sip->fd != -1) 
		conn = connection_find(sip, gsc->fd);
	if (!conn) {
		purple_debug_error("sipe", "Connection not found; Please try to connect again.\n");
		if (sip->fd != -1) purple_ssl_close(gsc); 
                purple_connection_error(sip->gc, _("Connection not found; Please try to connect again.\n"));
                sip->gc->wants_to_die = TRUE;
                return; 
	}

	if (conn->inbuflen < conn->inbufused + SIMPLE_BUF_INC) {
		conn->inbuflen += SIMPLE_BUF_INC;
		conn->inbuf = g_realloc(conn->inbuf, conn->inbuflen);
	}

	len = purple_ssl_read(sip->gsc, conn->inbuf + conn->inbufused, SIMPLE_BUF_INC - 1);

	if (len < 0 && errno == EAGAIN) {
		/* Try again later */
                return;
        } else if (len < 0) {
                purple_debug_info("sipe", "sipe_input_cb_ssl: read error\n");
                if (sip->gsc){ 
		    connection_remove(sip, sip->gsc->fd); 
                    if (sip->fd == gsc->fd) sip->fd = -1; 
                    purple_debug_info("sipe", "sipe_input_cb_ssl: connection_remove\n"); 
		}
                return;
        } else if (len == 0) {
                purple_connection_error(gc, _("Server has disconnected"));
		if (sip->gsc){
                	connection_remove(sip, sip->gsc->fd);
                	if (sip->fd == gsc->fd) sip->fd = -1;
		}
                return;
        }

	conn->inbufused += len;
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

	conn = connection_create(sip, source);

	sip->registertimeout = purple_timeout_add((rand()%100)+10*1000, (GSourceFunc)subscribe_timeout, sip);

	do_register(sip);

	conn->inputhandler = purple_input_add(sip->fd, PURPLE_INPUT_READ, sipe_input_cb, gc);
}

static void login_cb_ssl(gpointer data, PurpleSslConnection *gsc, PurpleInputCondition cond)
{
	PurpleConnection *gc = data;
	struct sipe_account_data *sip;
	struct sip_connection *conn;

	if (!PURPLE_CONNECTION_IS_VALID(gc))
	{
		if (gsc) purple_ssl_close(gsc);
		return;
	}

	sip = gc->proto_data;
	sip->fd = gsc->fd;
        sip->gsc = gsc;  
	conn = connection_create(sip, sip->fd);
	sip->listenport = purple_network_get_port_from_fd(sip->fd);
	sip->listenfd = sip->fd;
	sip->registertimeout = purple_timeout_add((rand()%100) + 1000, (GSourceFunc)subscribe_timeout, sip);

	do_register(sip);
        if(sip)
            purple_ssl_input_add(sip->gsc, sipe_input_cb_ssl, gc);
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
	sip->registertimeout = purple_timeout_add((rand()%100)+10*1000, (GSourceFunc)subscribe_timeout, sip);
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
        sip->gsc = NULL;

        switch(error) {
                case PURPLE_SSL_CONNECT_FAILED:
                        purple_connection_error(gc, _("Connection Failed"));
                        break;
                case PURPLE_SSL_HANDSHAKE_FAILED:
                        purple_connection_error(gc, _("SSL Handshake Failed"));
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
		port = port ? port : sip->use_ssl ? 5061 : 5060;
	}

	sip->realhostname = hostname;
	sip->realport = port;

	purple_debug(PURPLE_DEBUG_MISC, "sipe", "create_connection - hostname: %s port: %d\n",
		     hostname, port);

	/* TODO: is there a good default grow size? */
	if (!sip->udp)
		sip->txbuf = purple_circ_buffer_new(0);

	if (sip->use_ssl) {
		/* SSL case */
		if (!purple_ssl_is_supported()) {
			gc->wants_to_die = TRUE;
			purple_connection_error(gc, _("SSL support is needed for SSL/TLS support. Please install a supported SSL library."));
			return;
		}

		purple_debug_info("sipe", "using SSL\n");
		sip->gsc = purple_ssl_connect(account, hostname, port,
					      login_cb_ssl, sipe_ssl_connect_failure, gc);
		if (sip->gsc == NULL) {
			purple_connection_error(gc, _("Could not create SSL context"));
			return;
		}
	} else if (sip->udp) {
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
	{ "sipinternaltls", "tcp", 1 }, /* for internal TLS connections */
	{ "sipinternal",    "tcp", 0 }, /* for internal TCP connections */
	{ "sip",            "tls", 1 }, /* for external TLS connections */
	{ "sip",            "tcp", 0 }, /*.for external TCP connections */
	{ NULL,             NULL,  0 }
};

/* Service list for SSL/TLS */
static const struct sipe_service_data service_tls[] = {
	{ "sipinternaltls", "tcp", 1 }, /* for internal TLS connections */
	{ "sip",            "tls", 1 }, /* for external TLS connections */
	{ NULL,             NULL,  0 }
};

/* Service list for TCP */
static const struct sipe_service_data service_tcp[] = {
	{ "sipinternal",    "tcp", 0 }, /* for internal TCP connections */
	{ "sip",            "tcp", 0 }, /*.for external TCP connections */
	{ NULL,             NULL,  0 }
};

/* Service list for UDP */
static const struct sipe_service_data service_udp[] = {
	{ "sip",            "udp", 0 },
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
			/* Try connecting to the SIP hostname directly */
			purple_debug(PURPLE_DEBUG_MISC, "sipe", "no SRV records found; using SIP domain as fallback\n");
			// If SSL is supported, default to using it; OCS servers aren't configured
			// by default to accept TCP
			sip->use_ssl = purple_ssl_is_supported();
			gchar * hostname = g_strdup(sip->sipdomain);
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

		sip->use_ssl = sip->service_data->use_ssl;

		create_connection(sip, hostname, port);
	} else {
		resolve_next_service(sip, NULL);
	}
}

static void sipe_login(PurpleAccount *account)
{
	PurpleConnection *gc;
	struct sipe_account_data *sip;
	gchar **userserver;
	const char *transport;

	const char *username = purple_account_get_username(account);
	gc = purple_account_get_connection(account);

	if (strpbrk(username, " \t\v\r\n") != NULL) {
		gc->wants_to_die = TRUE;
		purple_connection_error(gc, _("SIP Exchange usernames may not contain whitespaces"));
		return;
	}

	gc->proto_data = sip = g_new0(struct sipe_account_data, 1);
	sip->gc = gc;
	sip->account = account;
	sip->registerexpire = 900;

	userserver = g_strsplit(username, "@", 2);
	purple_connection_set_display_name(gc, userserver[0]);
        sip->username = g_strdup(g_strjoin("@", userserver[0], userserver[1], NULL)); 
        sip->sipdomain = g_strdup(userserver[1]);
	sip->password = g_strdup(purple_connection_get_password(gc));
	g_strfreev(userserver);

	sip->buddies = g_hash_table_new((GHashFunc)sipe_ht_hash_nick, (GEqualFunc)sipe_ht_equals_nick);

	purple_connection_update_progress(gc, _("Connecting"), 1, 2);

	/* TODO: Set the status correctly. */
	sip->status = g_strdup("available");

	transport = purple_account_get_string(account, "transport", "auto");

	if (purple_account_get_bool(account, "useproxy", FALSE)) {
		purple_debug(PURPLE_DEBUG_MISC, "sipe", "sipe_login - using specified SIP proxy\n");
		sip->udp = strcmp(transport, "udp") == 0;
		sip->use_ssl = strcmp(transport, "tls") == 0;
		create_connection(sip, g_strdup(purple_account_get_string(account, "proxy", sip->sipdomain)), 0);
	} else if (strcmp(transport, "auto") == 0) {
		resolve_next_service(sip, purple_ssl_is_supported() ? service_autodetect : service_tcp);
	} else if (strcmp(transport, "tls") == 0) {
		resolve_next_service(sip, service_tls);
	} else if (strcmp(transport, "tcp") == 0) {
		resolve_next_service(sip, service_tcp);
	} else {
		sip->udp = 1;
		resolve_next_service(sip, service_udp);
	}
}

static void sipe_connection_cleanup(struct sipe_account_data *sip)
{
	connection_free_all(sip);

	if (sip->query_data != NULL)
		purple_dnsquery_destroy(sip->query_data);
	sip->query_data == NULL;

	if (sip->srv_query_data != NULL)
		purple_srv_cancel(sip->srv_query_data);
	sip->srv_query_data = NULL;

	if (sip->listen_data != NULL)
		purple_network_listen_cancel(sip->listen_data);
	sip->listen_data = NULL;

	g_free(sip->registrar.nonce);
	sip->registrar.nonce = NULL;
	g_free(sip->registrar.opaque);
	sip->registrar.opaque = NULL;
	g_free(sip->registrar.realm);
	sip->registrar.realm = NULL;
	g_free(sip->registrar.target);
	sip->registrar.target = NULL;
	g_free(sip->registrar.digest_session_key);
	sip->registrar.digest_session_key = NULL;
	g_free(sip->registrar.ntlm_key);
	sip->registrar.ntlm_key = NULL;
	sip->registrar.type = 0;
	sip->registrar.retries = 0;

	g_free(sip->proxy.nonce);
	sip->proxy.nonce = NULL;
	g_free(sip->proxy.opaque);
	sip->proxy.opaque = NULL;
	g_free(sip->proxy.realm);
	sip->proxy.realm = NULL;
	g_free(sip->proxy.target);
	sip->proxy.target = NULL;
	g_free(sip->proxy.digest_session_key);
	sip->proxy.digest_session_key = NULL;
	g_free(sip->proxy.ntlm_key);
	sip->proxy.ntlm_key = NULL;
	sip->proxy.type = 0;
	sip->proxy.retries = 0;

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
	if (sip->registertimeout)
		purple_timeout_remove(sip->registertimeout);
	sip->registertimeout = 0;
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
	}
	g_free(gc->proto_data);
	gc->proto_data = NULL;
}

/* not needed since privacy is checked for every subscribe */
static void dummy_add_deny(PurpleConnection *gc, const char *name) {
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


static void sipe_plugin_destroy(PurplePlugin *plugin)
{
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
	NULL,					/* status_text */	// TODO
	NULL,					/* tooltip_text */	// add custom info to contact tooltip
	sipe_status_types,			/* away_states */
	NULL,					/* blist_node_menu */
	NULL,					/* chat_info */
	NULL,					/* chat_info_defaults */
	sipe_login,				/* login */
	sipe_close,				/* close */
	sipe_im_send,				/* send_im */
	NULL,					/* set_info */		// TODO maybe
	sipe_send_typing,			/* send_typing */
	NULL,					/* get_info */		// TODO maybe
	sipe_set_status,			/* set_status */
	NULL,					/* set_idle */
	NULL,					/* change_passwd */
	sipe_add_buddy,				/* add_buddy */
	NULL,					/* add_buddies */
	sipe_remove_buddy,			/* remove_buddy */
	NULL,					/* remove_buddies */
	dummy_add_deny,				/* add_permit */
	dummy_add_deny,				/* add_deny */
	dummy_add_deny,				/* rem_permit */
	dummy_add_deny,				/* rem_deny */
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
	sipe_send_raw,				/* send_raw */
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
	N_("SIP/SIMPLE OCS/LCS Protocol Plugin"),        /**  summary        */
	N_("The SIP/SIMPLE LCS/OCS Protocol Plugin"),    /**  description    */
	"Anibal Avelar <avelar@gmail.com>, "         	  /**< author         */
	"Gabriel Burt <gburt@novell.com>",         	  /**< author         */
	PURPLE_WEBSITE,                                   /**< homepage       */
	sipe_plugin_load,                                 /**< load           */
	sipe_plugin_unload,                               /**< unload         */
	sipe_plugin_destroy,                              /**< destroy        */
	NULL,                                             /**< ui_info        */
	&prpl_info,                                       /**< extra_info     */
	NULL,
	NULL,
	NULL,
        NULL,
        NULL,
        NULL
};

static void init_plugin(PurplePlugin *plugin)
{
	PurpleAccountUserSplit *split;
	PurpleAccountOption *option;
	PurpleKeyValuePair *kvp;	

        purple_plugin_register(plugin);

        option = purple_account_option_bool_new(_("Use proxy"), "useproxy", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
        option = purple_account_option_string_new(_("Proxy Server"), "proxy", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_bool_new(_("Use non-standard port"), "useport", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
	option = purple_account_option_int_new(_("Port"), "port", 5061);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = purple_account_option_list_new(_("Transport"), "transport", NULL);
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

	option = purple_account_option_string_new(_("Auth User"), "authuser", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
	option = purple_account_option_string_new(_("Auth Domain"), "authdomain", "");
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

