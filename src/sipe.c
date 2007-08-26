/**
 * @file sip-exchange.c
 *
 * gaim
 *
 * Copyright (C) 2007 Anibal Avelar "Fixxxer"<avelar@gmail.com>
 * Copyright (C) 2005 Thomas Butter <butter@uni-mannheim.de>
 *
 * ***
 * Thanks to Google's Summer of Code Program and the helpful mentors
 * ***
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

#include "sip-internal.h"

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

#include "sipmsg.h"
#include "dnssrv.h"

#include "gaim-compat.h"

static char *gentag() {
	return g_strdup_printf("%04d%04d", rand() & 0xFFFF, rand() & 0xFFFF);
}

static char *genbranch() {
	return g_strdup_printf("z9hG4bK%04X%04X%04X%04X%04X",
		rand() & 0xFFFF, rand() & 0xFFFF, rand() & 0xFFFF,
		rand() & 0xFFFF, rand() & 0xFFFF);
}

static char *gencallid() {
	return g_strdup_printf("%04Xg%04Xa%04Xi%04Xm%04Xt%04Xb%04Xx%04Xx",
		rand() & 0xFFFF, rand() & 0xFFFF, rand() & 0xFFFF,
		rand() & 0xFFFF, rand() & 0xFFFF, rand() & 0xFFFF,
		rand() & 0xFFFF, rand() & 0xFFFF);
}

static const char *sipe_list_icon(GaimAccount *a, GaimBuddy *b) {
	return "sipe";
}

static void sipe_keep_alive(GaimConnection *gc) {
	struct sipe_account_data *sip = gc->proto_data;
	if(sip->udp) { /* in case of UDP send a packet only with a 0 byte to
			 remain in the NAT table */
		gchar buf[2] = {0, 0};
		gaim_debug_info("sipe", "sending keep alive\n");
		sendto(sip->fd, buf, 1, 0, (struct sockaddr*)&sip->serveraddr, sizeof(struct sockaddr_in));
	}
	return;
}

static gboolean process_register_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc);

static void send_notify(struct sipe_account_data *sip, struct sipe_watcher *);

static void send_service(struct sipe_account_data *sip);

static void do_notifies(struct sipe_account_data *sip) {
	GSList *tmp = sip->watcher;
	gaim_debug_info("sipe", "do_notifies()\n");
	//if((sip->republish != -1) || sip->republish < time(NULL)) {
	//	if(gaim_account_get_bool(sip->account, "doservice", TRUE)) {
	//		send_service(sip);
	//	}
	//}

	while(tmp) {
		gaim_debug_info("sipe", "notifying %s\n", ((struct sipe_watcher*)tmp->data)->name);
		send_notify(sip, tmp->data);
		tmp = tmp->next;
	}
}

static void sipe_set_status(GaimAccount *account, GaimStatus *status) {
	GaimStatusPrimitive primitive = gaim_status_type_get_primitive(gaim_status_get_type(status));
	struct sipe_account_data *sip = NULL;

	if (!gaim_status_is_active(status))
		return;

	if (account->gc)
		sip = account->gc->proto_data;

	if (sip)
	{
		g_free(sip->status);
		if (primitive == GAIM_STATUS_AVAILABLE)
			sip->status = g_strdup("available");
		else
			sip->status = g_strdup("busy");

		do_notifies(sip);
	}
}

static struct sip_connection *connection_find(struct sipe_account_data *sip, int fd) {
	struct sip_connection *ret = NULL;
	GSList *entry = sip->openconns;
	while(entry) {
		ret = entry->data;
		if(ret->fd == fd) return ret;
		entry = entry->next;
	}
	return NULL;
}

static struct sipe_watcher *watcher_find(struct sipe_account_data *sip,
		const gchar *name) {
	struct sipe_watcher *watcher;
	GSList *entry = sip->watcher;
	while(entry) {
		watcher = entry->data;
		if(!strcmp(name, watcher->name)) return watcher;
		entry = entry->next;
	}
	return NULL;
}

static struct sipe_watcher *watcher_create(struct sipe_account_data *sip,
		const gchar *name, const gchar *callid, const gchar *ourtag,
		const gchar *theirtag, gboolean needsxpidf) {
	struct sipe_watcher *watcher = g_new0(struct sipe_watcher, 1);
	watcher->name = g_strdup(name);
	watcher->dialog.callid = g_strdup(callid);
	watcher->dialog.ourtag = g_strdup(ourtag);
	watcher->dialog.theirtag = g_strdup(theirtag);
	watcher->needsxpidf = needsxpidf;
	sip->watcher = g_slist_append(sip->watcher, watcher);
	return watcher;
}

static void watcher_remove(struct sipe_account_data *sip, const gchar *name) {
	struct sipe_watcher *watcher = watcher_find(sip, name);
	sip->watcher = g_slist_remove(sip->watcher, watcher);
	g_free(watcher->name);
	g_free(watcher->dialog.callid);
	g_free(watcher->dialog.ourtag);
	g_free(watcher->dialog.theirtag);
	g_free(watcher);
}

static struct sip_connection *connection_create(struct sipe_account_data *sip, int fd) {
	struct sip_connection *ret = g_new0(struct sip_connection, 1);
	ret->fd = fd;
	sip->openconns = g_slist_append(sip->openconns, ret);
	return ret;
}

static void connection_remove(struct sipe_account_data *sip, int fd) {
	struct sip_connection *conn = connection_find(sip, fd);
	sip->openconns = g_slist_remove(sip->openconns, conn);
	if(conn->inputhandler) gaim_input_remove(conn->inputhandler);
	g_free(conn->inbuf);
	g_free(conn);
}

static void connection_free_all(struct sipe_account_data *sip) {
	struct sip_connection *ret = NULL;
	GSList *entry = sip->openconns;
	while(entry) {
		ret = entry->data;
		connection_remove(sip, ret->fd);
		entry = sip->openconns;
	}
}

static void sipe_add_buddy(GaimConnection *gc, GaimBuddy *buddy, GaimGroup *group)
{
	struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;
	struct sipe_buddy *b;
	if(strncmp("sip:", buddy->name, 4)) {
		gchar *buf = g_strdup_printf("sip:%s", buddy->name);
		gaim_blist_rename_buddy(buddy, buf);
		g_free(buf);
	}
	if(!g_hash_table_lookup(sip->buddies, buddy->name)) {
		b = g_new0(struct sipe_buddy, 1);
		gaim_debug_info("sipe", "sipe_add_buddy %s\n", buddy->name);
		b->name = g_strdup(buddy->name);
		g_hash_table_insert(sip->buddies, b->name, b);
	} else {
		gaim_debug_info("sipe", "buddy %s already in internal list\n", buddy->name);
	}
}

static void sipe_get_buddies(GaimConnection *gc) {
	GaimBlistNode *gnode, *cnode, *bnode;

	gaim_debug_info("sipe", "sipe_get_buddies\n");

	for(gnode = gaim_get_blist()->root; gnode; gnode = gnode->next) {
		if(!GAIM_BLIST_NODE_IS_GROUP(gnode)) continue;
		for(cnode = gnode->child; cnode; cnode = cnode->next) {
			if(!GAIM_BLIST_NODE_IS_CONTACT(cnode)) continue;
			for(bnode = cnode->child; bnode; bnode = bnode->next) {
				if(!GAIM_BLIST_NODE_IS_BUDDY(bnode)) continue;
				if(((GaimBuddy*)bnode)->account == gc->account)
					sipe_add_buddy(gc, (GaimBuddy*)bnode, (GaimGroup *)gnode);
			}
		}
	}
}

static void sipe_remove_buddy(GaimConnection *gc, GaimBuddy *buddy, GaimGroup *group)
{
	struct sipe_account_data *sip = (struct sipe_account_data *)gc->proto_data;
	struct sipe_buddy *b = g_hash_table_lookup(sip->buddies, buddy->name);
	g_hash_table_remove(sip->buddies, buddy->name);
	g_free(b->name);
	g_free(b);
}

static GList *sipe_status_types(GaimAccount *acc) {
	GaimStatusType *type;
	GList *types = NULL;

	type = gaim_status_type_new_with_attrs(
		GAIM_STATUS_AVAILABLE, NULL, NULL, TRUE, TRUE, FALSE,
		"message", _("Message"), gaim_value_new(GAIM_TYPE_STRING),
		NULL);
	types = g_list_append(types, type);

	type = gaim_status_type_new_full(
		GAIM_STATUS_OFFLINE, NULL, NULL, TRUE, TRUE, FALSE);
	types = g_list_append(types, type);

	return types;
}

static gchar *auth_header(struct sipe_account_data *sip,
		struct sip_auth *auth, const gchar *method, const gchar *target) {
	gchar noncecount[9];
	gchar *response;
	gchar *ret;
	gchar *tmp;
	const char *authdomain;
	const char *authuser;

	authdomain = gaim_account_get_string(sip->account, "authdomain", "");
	authuser = gaim_account_get_string(sip->account, "authuser", sip->username);

	if(!authuser || strlen(authuser) < 1) {
		authuser = sip->username;
	}

	if(auth->type == 1) { /* Digest */
		sprintf(noncecount, "%08d", auth->nc++);
		response = gaim_cipher_http_digest_calculate_response(
							"md5", method, target, NULL, NULL,
							auth->nonce, noncecount, NULL, auth->digest_session_key);
		gaim_debug(GAIM_DEBUG_MISC, "sipe", "response %s\n", response);

		ret = g_strdup_printf("Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", nc=\"%s\", response=\"%s\"\r\n", authuser, auth->realm, auth->nonce, target, noncecount, response);
		g_free(response);
		return ret;
	} else if(auth->type == 2) { /* NTLM */
		if(auth->nc == 3 && auth->nonce) {
			/* TODO: Don't hardcode "gaim" as the hostname */
			ret = gaim_ntlm_gen_type3_sipe(authuser, sip->password, "gaim", authdomain, (const guint8 *)auth->nonce, &auth->flags);
			tmp = g_strdup_printf("NTLM qop=\"auth\", opaque=\"%s\", realm=\"%s\", targetname=\"%s\", gssapi-data=\"%s\"\r\n", auth->opaque, auth->realm, auth->target, ret);
			g_free(ret);
			return tmp;
		}
		tmp = g_strdup_printf("NTLM qop=\"auth\", realm=\"%s\", targetname=\"%s\", gssapi-data=\"\"\r\n", auth->realm, auth->target);
		return tmp;
	}

	sprintf(noncecount, "%08d", auth->nc++);
	response = gaim_cipher_http_digest_calculate_response(
						"md5", method, target, NULL, NULL,
						auth->nonce, noncecount, NULL, auth->digest_session_key);
	gaim_debug(GAIM_DEBUG_MISC, "sipe", "response %s\n", response);

	ret = g_strdup_printf("Digest username=\"%s\", realm=\"%s\", nonce=\"%s\", uri=\"%s\", nc=\"%s\", response=\"%s\"\r\n", authuser, auth->realm, auth->nonce, target, noncecount, response);
	g_free(response);
	return ret;
}

static char *parse_attribute(const char *attrname, const char *source) {
	const char *tmp, *tmp2;
	char *retval = NULL;
	int len = strlen(attrname);

	if(!strncmp(source, attrname, len)) {
		tmp = source + len;
		tmp2 = g_strstr_len(tmp, strlen(tmp), "\"");
		if(tmp2)
			retval = g_strndup(tmp, tmp2 - tmp);
		else
			retval = g_strdup(tmp);
	}

	return retval;
}

static void fill_auth(struct sipe_account_data *sip, gchar *hdr, struct sip_auth *auth) {
	int i = 0;
	const char *authuser;
	char *tmp;
	gchar **parts;

	authuser = gaim_account_get_string(sip->account, "authuser", sip->username);

	if(!authuser || strlen(authuser) < 1) {
		authuser = sip->username;
	}

	if(!hdr) {
		gaim_debug_error("sipe", "fill_auth: hdr==NULL\n");
		return;
	}

	if(!g_strncasecmp(hdr, "NTLM", 4)) {
		gaim_debug_info("sipe", "found NTLM\n");
		auth->type = 2;
		parts = g_strsplit(hdr+5, "\", ", 0);
		i = 0;
		while(parts[i]) {
			gaim_debug_info("sipe", "parts[i] %s\n", parts[i]);
			if((tmp = parse_attribute("gssapi-data=\"", parts[i]))) {
				auth->nonce = g_memdup(gaim_ntlm_parse_type2_sipe(tmp, &auth->flags), 8);
				g_free(tmp);
			}
			if((tmp = parse_attribute("targetname=\"",
					parts[i]))) {
				auth->target = tmp;
			}
			else if((tmp = parse_attribute("realm=\"",
					parts[i]))) {
				auth->realm = tmp;
			}
			else if((tmp = parse_attribute("opaque=\"", parts[i]))) {
				auth->opaque = tmp;
			}
			i++;
		}
		g_strfreev(parts);
		auth->nc = 1;
		if(!strstr(hdr, "gssapi-data")) {
			auth->nc = 1;
		} else {
			auth->nc = 3;
                }
		return;
	}

	auth->type = 1;
	parts = g_strsplit(hdr, " ", 0);
	while(parts[i]) {
		if((tmp = parse_attribute("nonce=\"", parts[i]))) {
			auth->nonce = tmp;
		}
		else if((tmp = parse_attribute("realm=\"", parts[i]))) {
			auth->realm = tmp;
		}
		i++;
	}
	g_strfreev(parts);

	gaim_debug(GAIM_DEBUG_MISC, "sipe", "nonce: %s realm: %s\n", auth->nonce ? auth->nonce : "(null)", auth->realm ? auth->realm : "(null)");
	if(auth->realm) {
		auth->digest_session_key = gaim_cipher_http_digest_calculate_session_key(
				"md5", authuser, auth->realm, sip->password, auth->nonce, NULL);

		auth->nc = 1;
	}
}

static void sipe_canwrite_cb(gpointer data, gint source, GaimInputCondition cond) {
	GaimConnection *gc = data;
	struct sipe_account_data *sip = gc->proto_data;
	gsize max_write;
	gssize written;

	max_write = gaim_circ_buffer_get_max_read(sip->txbuf);

	if(max_write == 0) {
		gaim_input_remove(sip->tx_handler);
		sip->tx_handler = 0;
		return;
	}

	written = write(sip->fd, sip->txbuf->outptr, max_write);

	if(written < 0 && errno == EAGAIN)
		written = 0;
	else if(written <= 0) {
		/*TODO: do we really want to disconnect on a failure to write?*/
		gaim_connection_error(gc, _("Could not write"));
		return;
	}

	gaim_circ_buffer_mark_read(sip->txbuf, written);
}

static void sipe_input_cb(gpointer data, gint source, GaimInputCondition cond);

static void send_later_cb(gpointer data, gint source, const gchar *error) {
	GaimConnection *gc = data;
	struct sipe_account_data *sip;
	struct sip_connection *conn;

	if (!GAIM_CONNECTION_IS_VALID(gc))
	{
		if (source >= 0)
			close(source);
		return;
	}

	if(source < 0) {
		gaim_connection_error(gc, _("Could not connect"));
		return;
	}

	sip = gc->proto_data;
	sip->fd = source;
	sip->connecting = FALSE;

	sipe_canwrite_cb(gc, sip->fd, GAIM_INPUT_WRITE);

	/* If there is more to write now, we need to register a handler */
	if(sip->txbuf->bufused > 0)
		sip->tx_handler = gaim_input_add(sip->fd, GAIM_INPUT_WRITE,
			sipe_canwrite_cb, gc);

	conn = connection_create(sip, source);
	conn->inputhandler = gaim_input_add(sip->fd, GAIM_INPUT_READ, sipe_input_cb, gc);
}


static void sendlater(GaimConnection *gc, const char *buf) {
	struct sipe_account_data *sip = gc->proto_data;

	if(!sip->connecting) {
		gaim_debug_info("sipe", "connecting to %s port %d\n", sip->realhostname ? sip->realhostname : "{NULL}", sip->realport);
		if(gaim_proxy_connect(gc, sip->account, sip->realhostname, sip->realport, send_later_cb, gc) == NULL) {
			gaim_connection_error(gc, _("Couldn't create socket"));
		}
		sip->connecting = TRUE;
	}

	if(gaim_circ_buffer_get_max_read(sip->txbuf) > 0)
		gaim_circ_buffer_append(sip->txbuf, "\r\n", 2);

	gaim_circ_buffer_append(sip->txbuf, buf, strlen(buf));
}

static void sendout_pkt(GaimConnection *gc, const char *buf) {
	struct sipe_account_data *sip = gc->proto_data;
	time_t currtime = time(NULL);
	int writelen = strlen(buf);

	gaim_debug(GAIM_DEBUG_MISC, "sipe", "\n\nsending - %s\n######\n%s\n######\n\n", ctime(&currtime), buf);
	if(sip->udp) {
		if(sendto(sip->fd, buf, writelen, 0, (struct sockaddr*)&sip->serveraddr, sizeof(struct sockaddr_in)) < writelen) {
			gaim_debug_info("sipe", "could not send packet\n");
		}
	} else {
		int ret;
		if(sip->fd < 0) {
			sendlater(gc, buf);
			return;
		}

		if(sip->tx_handler) {
			ret = -1;
			errno = EAGAIN;
		} else
			ret = write(sip->fd, buf, writelen);

		if (ret < 0 && errno == EAGAIN)
			ret = 0;
		else if(ret <= 0) { /* XXX: When does this happen legitimately? */
			sendlater(gc, buf);
			return;
		}

		if (ret < writelen) {
			if(!sip->tx_handler)
				sip->tx_handler = gaim_input_add(sip->fd,
					GAIM_INPUT_WRITE, sipe_canwrite_cb,
					gc);

			/* XXX: is it OK to do this? You might get part of a request sent
			   with part of another. */
			if(sip->txbuf->bufused > 0)
				gaim_circ_buffer_append(sip->txbuf, "\r\n", 2);

			gaim_circ_buffer_append(sip->txbuf, buf + ret,
				writelen - ret);
		}
	}
}

static int sipe_send_raw(GaimConnection *gc, const char *buf, int len)
{
	sendout_pkt(gc, buf);
	return len;
}

static void sendout_sipmsg(struct sipe_account_data *sip, struct sipmsg *msg) {
	GSList *tmp = msg->headers;
	gchar *name;
	gchar *value;
	GString *outstr = g_string_new("");
	g_string_append_printf(outstr, "%s %s SIP/2.0\r\n", msg->method, msg->target);
	while(tmp) {
		name = ((struct siphdrelement*) (tmp->data))->name;
		value = ((struct siphdrelement*) (tmp->data))->value;
		g_string_append_printf(outstr, "%s: %s\r\n", name, value);
		tmp = g_slist_next(tmp);
	}
	g_string_append_printf(outstr, "\r\n%s", msg->body ? msg->body : "");
	sendout_pkt(sip->gc, outstr->str);
	g_string_free(outstr, TRUE);
}

static void send_sip_response(GaimConnection *gc, struct sipmsg *msg, int code,
		const char *text, const char *body) {
	GSList *tmp = msg->headers;
	gchar *name;
	gchar *value;
	GString *outstr = g_string_new("");

	/* When sending the acknowlegements and errors, the content length from the original
	   message is still here, but there is no body; we need to make sure we're sending the
	   correct content length */
	sipmsg_remove_header(msg, "Content-Length");
	if(body) {
		gchar len[12];
		sprintf(len, "%" G_GSIZE_FORMAT , strlen(body));
		sipmsg_add_header(msg, "Content-Length", len);
	}
	else
		sipmsg_add_header(msg, "Content-Length", "0");
	g_string_append_printf(outstr, "SIP/2.0 %d %s\r\n", code, text);
	while(tmp) {
		name = ((struct siphdrelement*) (tmp->data))->name;
		value = ((struct siphdrelement*) (tmp->data))->value;

		g_string_append_printf(outstr, "%s: %s\r\n", name, value);
		tmp = g_slist_next(tmp);
	}
	g_string_append_printf(outstr, "\r\n%s", body ? body : "");
	sendout_pkt(gc, outstr->str);
	g_string_free(outstr, TRUE);
}

static void transactions_remove(struct sipe_account_data *sip, struct transaction *trans) {
	if(trans->msg) sipmsg_free(trans->msg);
	sip->transactions = g_slist_remove(sip->transactions, trans);
	g_free(trans);
}

static void transactions_add_buf(struct sipe_account_data *sip, const gchar *buf, void *callback) {
	struct transaction *trans = g_new0(struct transaction, 1);
	trans->time = time(NULL);
	trans->msg = sipmsg_parse_msg(buf);
	trans->cseq = sipmsg_find_header(trans->msg, "CSeq");
	trans->callback = callback;
	sip->transactions = g_slist_append(sip->transactions, trans);
}

static struct transaction *transactions_find(struct sipe_account_data *sip, struct sipmsg *msg) {
	struct transaction *trans;
	GSList *transactions = sip->transactions;
	gchar *cseq = sipmsg_find_header(msg, "CSeq");

	while(transactions) {
		trans = transactions->data;
		if(!strcmp(trans->cseq, cseq)) {
			return trans;
		}
		transactions = transactions->next;
	}

	return NULL;
}

static void send_sip_request(GaimConnection *gc, const gchar *method,
		const gchar *url, const gchar *to, const gchar *addheaders,
		const gchar *body, struct sip_dialog *dialog, TransCallback tc) {
	struct sipe_account_data *sip = gc->proto_data;
	char *callid = dialog ? g_strdup(dialog->callid) : gencallid();
	char *auth = NULL;
	const char *addh = "";
	gchar *branch = genbranch();
	gchar *tag = NULL;
	char *buf;

	if(!strcmp(method, "REGISTER")) {
		if(sip->regcallid) {
			g_free(callid);
			callid = g_strdup(sip->regcallid);
		}
		else sip->regcallid = g_strdup(callid);
	}

	if(addheaders) addh = addheaders;
	if(sip->registrar.type && !strcmp(method, "REGISTER")) {
		buf = auth_header(sip, &sip->registrar, method, url);
		auth = g_strdup_printf("Authorization: %s", buf);
		g_free(buf);
		gaim_debug(GAIM_DEBUG_MISC, "sipe", "1 header %s", auth);
	}
	
	if(!strcmp(method,"SUBSCRIBE") || !strcmp(method,"SERVICE") || !strcmp(method,"MESSAGE") || !strcmp(method,"INVITE") || !strcmp(method,"NOTIFY")) {
	         buf = g_strdup_printf("NTLM qop=\"auth\", realm=\"%s\", targetname=\"%s\", gssapi-data=\"\"\r\n", sip->registrar.realm, sip->registrar.target);
	        auth = g_strdup_printf("Proxy-Authorization: %s", buf);
                gaim_debug(GAIM_DEBUG_MISC, "sipe", "3 header %s", auth);
	        g_free(buf);
	}

	if (!dialog)
		tag = gentag();

	buf = g_strdup_printf("%s %s SIP/2.0\r\n"
			"Via: SIP/2.0/%s %s:%d;branch=%s\r\n"
			/* Don't know what epid is, but LCS wants it */
			"From: <sip:%s>;tag=%s;epid=1234567890\r\n"
			"To: <%s>%s%s\r\n"
			"Max-Forwards: 10\r\n"
			"CSeq: %d %s\r\n"
			"User-Agent: Gaim/" VERSION "\r\n"
			"Call-ID: %s\r\n"
			"%s%s"
                        "Content-Length: %" G_GSIZE_FORMAT "\r\n\r\n%s",
			method,
			url,
			sip->udp ? "UDP" : "TCP",
			sipe_network_get_local_system_ip(),
			sip->listenport,
			branch,
			sip->username,
			dialog ? dialog->ourtag : tag,
			to,
			dialog ? ";tag=" : "",
			dialog ? dialog->theirtag : "",
			++sip->cseq,
			method,
			callid,
			auth ? auth : "",
			addh,
			strlen(body),
			body);

	g_free(tag);
	g_free(auth);
	g_free(branch);
	g_free(callid);

	/* add to ongoing transactions */

	transactions_add_buf(sip, buf, tc);

	sendout_pkt(gc, buf);

	g_free(buf);
}

static char *get_contact_register(struct sipe_account_data  *sip) {
        return g_strdup_printf("<sip:%s:%d;transport=%s>;methods=\"INVITE, MESSAGE, INFO, SUBSCRIBE, BYE, CANCEL, NOTIFY, ACK, BENOTIFY\";proxy=replace", sipe_network_get_local_system_ip(),sip->listenport,  sip->udp ? "udp" : "tcp");
}

static char *get_contact(struct sipe_account_data  *sip) {
        //return g_strdup_printf("<sip:%s@%s:%d;maddr=%s;transport=%s>;proxy=replace", sip->username, sip->servername, sip->listenport, sipe_network_get_local_system_ip() , sip->udp ? "udp" : "tcp");
        return g_strdup_printf("<sip:%s:%d;maddr=%s;transport=%s>;proxy=replace", sip->username, sip->listenport, sipe_network_get_local_system_ip() , sip->udp ? "udp" : "tcp"); 
}

static void do_register_exp(struct sipe_account_data *sip, int expire) {
	char *uri = g_strdup_printf("sip:%s", sip->servername);
	char *to = g_strdup_printf("sip:%s", sip->username);
	char *contact = get_contact_register(sip);
	//char *hdr = g_strdup_printf("Contact: %s\r\nExpires: %d\r\n", contact, expire);
       // char *hdr = g_strdup_printf("Contact: %s\r\nEvent: registration\r\nAllow-Events: presence\r\nms-keep-alive: UAC;hop-hop=yes\r\nExpires: %d\r\n", contact,expire);
        //char *hdr = g_strdup_printf("Contact: %s\r\nSupported: com.microsoft.msrtc.presence, adhoclist\r\nms-keep-alive: UAC;hop-hop=yes\r\nEvent: registration\r\nAllow-Events: presence\r\n", contact);
        char *hdr = g_strdup_printf("Contact: %s\r\nEvent: registration\r\nAllow-Events: presence\r\nms-keep-alive: UAC;hop-hop=yes\r\nExpires: %d\r\n", contact,expire);
	g_free(contact);

	sip->registerstatus = 1;

	if(expire) {
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

static void do_register(struct sipe_account_data *sip) {
	do_register_exp(sip, sip->registerexpire);
}

static gchar *parse_from(const gchar *hdr) {
	gchar *from;
	const gchar *tmp, *tmp2 = hdr;

	if(!hdr) return NULL;
	gaim_debug_info("sipe", "parsing address out of %s\n", hdr);
	tmp = strchr(hdr, '<');

	/* i hate the different SIP UA behaviours... */
	if(tmp) { /* sip address in <...> */
		tmp2 = tmp + 1;
		tmp = strchr(tmp2, '>');
		if(tmp) {
			from = g_strndup(tmp2, tmp - tmp2);
		} else {
			gaim_debug_info("sipe", "found < without > in From\n");
			return NULL;
		}
	} else {
		tmp = strchr(tmp2, ';');
		if(tmp) {
			from = g_strndup(tmp2, tmp - tmp2);
		} else {
			from = g_strdup(tmp2);
		}
	}
	gaim_debug_info("sipe", "got %s\n", from);
	return from;
}

static gboolean process_subscribe_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc) {
	gchar *to;

	if(msg->response == 200 || msg->response == 202) {
                gaim_debug_info("sipe", "Devolvio un response %d\n", msg->response);
		return TRUE;
	}

	to = parse_from(sipmsg_find_header(tc->msg, "To")); /* cant be NULL since it is our own msg */

	/* we can not subscribe -> user is offline (TODO unknown status?) */

	gaim_prpl_got_user_status(sip->account, to, "offline", NULL);
	g_free(to);
	return TRUE;
}

static void sipe_subscribe(struct sipe_account_data *sip, struct sipe_buddy *buddy) {
        gchar *contact ="Accept: application/pidf+xml, application/xpidf+xml\r\nEvent: presence\r\n";
	gchar *to;
	gchar *tmp;
       
	if(strstr(buddy->name, "sip:"))
		to = g_strdup(buddy->name);
	else
		to = g_strdup_printf("sip:%s", buddy->name);

	tmp = get_contact(sip);
	contact = g_strdup_printf("%sContact: %s\r\n", contact, tmp);
	g_free(tmp);

	/* subscribe to buddy presence
	 * we dont need to know the status so we do not need a callback */

	send_sip_request(sip->gc, "SUBSCRIBE", to, to, contact, "", NULL,
		process_subscribe_response);

	g_free(to);
	g_free(contact);

	/* resubscribe before subscription expires */
	/* add some jitter */
	buddy->resubscribe = time(NULL)+1140+(rand()%50);
}

static gboolean sipe_add_lcs_contacts(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc) {
	gchar *tmp;
	xmlnode *item, *group, *isc;
	const char *name_group, *group_id;
	GaimBuddy *b;
	GaimGroup *g = NULL;
        gchar **parts;
        gchar *apn;
        int ng = 0, i;
	struct sipe_buddy *bs;
        struct sipe_group *gr;
	int len = msg->bodylen;

        //Reserved to max 10 groups. ToDO be dynamic
        gr = g_new0(struct sipe_group, 10);

	tmp = sipmsg_find_header(msg, "Event");
	if(tmp && !strncmp(tmp, "vnd-microsoft-roaming-contacts", 30)){

		gaim_debug_info("sipe", "sipe_add_lcs_contacts->%s-%d\n", msg->body, len);
		/*Convert the contact from XML to Gaim Buddies*/
		isc = xmlnode_from_str(msg->body, len);

		/* ToDo. Find for all groups */
		//if ((group = xmlnode_get_child(isc, "group"))) {
                for(group = xmlnode_get_child(isc, "group"); group; group = xmlnode_get_next_twin(group)) {
			name_group = xmlnode_get_attrib(group, "name");
                        group_id = xmlnode_get_attrib(group, "id");
                        if(!strncmp(name_group, "~", 1)){
                           name_group=g_strdup("General");
                        }
                        gr[ng].name_group = g_strdup(name_group);
                        gr[ng].id = g_strdup(group_id); 
			gaim_debug_info("sipe", "name_group->%s\n", name_group);
			g = gaim_find_group(name_group);
			if(!g) {
				g = gaim_group_new(name_group);
                                gaim_blist_add_group(g, NULL);
                        }
		        if (!g) {
			   g = gaim_find_group("General");
				if(!g) {
					g = gaim_group_new("General");
                                	gaim_blist_add_group(g, NULL);
                         	}
		        }
                        gr[ng].g = g;
                        ng++;
                }
                for(i = 0; i < ng;i++){
                    gaim_debug_info("sipe", "id->%s\n", gr[i].id);
                    gaim_debug_info("sipe", "id->%s\n", gr[i].name_group); 
                } 
                 
		       for(item = xmlnode_get_child(isc, "contact"); item; item = xmlnode_get_next_twin(item))
			{
				const char *uri, *name, *groups;
				char *buddy_name;
                                i = 0; 
				uri = xmlnode_get_attrib(item, "uri");
				name = xmlnode_get_attrib(item, "name");
				groups = xmlnode_get_attrib(item, "groups");
                        	parts = g_strsplit(groups, " ", 0); 
				gaim_debug_info("sipe", "URI->%s,Groups->%s\n", uri, groups);

                        	while(parts[i]) {
			    		gaim_debug_info("sipe", "Groups->parts[i] %s\n", parts[i]);
                                        if(!strcmp(gr[i].id,parts[i])){
                                         gaim_debug_info("sipe", "Found Groups->gr[i].id(%s),gr[i].name_group (%s)\n",gr[i].id,gr[i].name_group);
                                        
				buddy_name = g_strdup_printf("sip:%s", uri);

				//b = gaim_find_buddy(sip->account, buddy_name); 
                                b = gaim_find_buddy_in_group(sip->account, buddy_name, gr[i].g);
				if(!b){
					b = gaim_buddy_new(sip->account, buddy_name, uri);
				}
				g_free(buddy_name);

                                //sipe_add_buddy(sip->gc, b , gr[i].g);  
				gaim_blist_add_buddy(b, NULL, gr[i].g, NULL);
				gaim_blist_alias_buddy(b, uri);
				bs = g_new0(struct sipe_buddy, 1);
				bs->name = g_strdup(b->name);
				g_hash_table_insert(sip->buddies, bs->name, bs);
                                }
                              i++;
                             } 
			}
	     xmlnode_free(isc); 
	} 
	return 0;
}

static void sipe_subscribe_buddylist(struct sipe_account_data *sip) {
        gchar *contact = "Event: vnd-microsoft-roaming-contacts\r\nAccept: application/vnd-microsoft-roaming-contacts+xml\r\nSupported: com.microsoft.autoextend\r\nSupported: ms-benotify\r\nProxy-Require: ms-benotify\r\nSupported: ms-piggyback-first-notify\r\n";
	gchar *to;
	gchar *tmp;
	//to = g_strdup_printf("sip:%s@%s", sip->username, sip->servername);
        to = g_strdup_printf("sip:%s", sip->username); 

	tmp = get_contact(sip);
	contact = g_strdup_printf("%sContact: %s\r\n", contact, tmp);
	g_free(tmp);
	send_sip_request(sip->gc, "SUBSCRIBE", to, to, contact, "", NULL, sipe_add_lcs_contacts);
	g_free(to);
	g_free(contact);
}

static void sipe_invite(struct sipe_account_data *sip, struct sipe_buddy *buddy) {
	gchar *contact = "Supported: com.microsoft.rtc-multiparty\r\n";
	gchar *to;
	gchar *tmp;
	//to = g_strdup_printf("sip:%s@%s", sip->username, sip->servername);

        if(strstr(buddy->name, "sip:"))
		to = g_strdup(buddy->name);
	else
		to = g_strdup_printf("sip:%s", buddy->name);

	tmp = get_contact(sip);
	contact = g_strdup_printf("%sContact: %s\r\n", contact, tmp);
	g_free(tmp);

        tmp = g_strdup_printf("Roster-Manager:sip:%s@%s\r\nEndPoints: <sip:%s@%s>, <sip:%s@%s>", sip->username, sip->servername,sip->username, sip->servername, buddy->name, sip->servername);
        contact = g_strdup_printf("%sContact: %s\r\n", contact, tmp);
	g_free(tmp);
 
	send_sip_request(sip->gc, "INVITE", to, to, contact, "", NULL, NULL);

	g_free(to);
	g_free(contact);
}

static void sipe_buddy_resub(char *name, struct sipe_buddy *buddy, struct sipe_account_data *sip) {
	time_t curtime = time(NULL);
	gaim_debug_info("sipe", "buddy resub\n");
	if(buddy->resubscribe < curtime) {
		gaim_debug(GAIM_DEBUG_MISC, "sipe", "sipe_buddy_resub %s\n", name);
		sipe_subscribe(sip, buddy);
	}
}

static gboolean resend_timeout(struct sipe_account_data *sip) {
	GSList *tmp = sip->transactions;
	time_t currtime = time(NULL);
	while(tmp) {
		struct transaction *trans = tmp->data;
		tmp = tmp->next;
		gaim_debug_info("sipe", "have open transaction age: %d\n", currtime- trans->time);
		if((currtime - trans->time > 5) && trans->retries >= 1) {
			/* TODO 408 */
		} else {
			if((currtime - trans->time > 2) && trans->retries == 0) {
				trans->retries++;
				sendout_sipmsg(sip, trans->msg);
			}
		}
	}
	return TRUE;
}

static gboolean subscribe_timeout(struct sipe_account_data *sip) {
	GSList *tmp;
	time_t curtime = time(NULL);
	/* register again if first registration expires */
	if(sip->reregister < curtime) {
		do_register(sip);
	}
	/* check for every subscription if we need to resubscribe */
	//Fixxxer we need resub?
	g_hash_table_foreach(sip->buddies, (GHFunc)sipe_buddy_resub, (gpointer)sip);

	/* remove a timed out suscriber */

	tmp = sip->watcher;
	while(tmp) {
		struct sipe_watcher *watcher = tmp->data;
		if(watcher->expire < curtime) {
			watcher_remove(sip, watcher->name);
			tmp = sip->watcher;
		}
		if(tmp) tmp = tmp->next;
	}

	return TRUE;
}

static void sipe_send_message(struct sipe_account_data *sip, const char *to, const char *msg, const char *type) {
	gchar *hdr;
	gchar *fullto;
        gchar *tmp;
	if(strncmp("sip:", to, 4)) {
		fullto = g_strdup_printf("sip:%s", to);
	} else {
		fullto = g_strdup(to);
	}
	if(type) {
		hdr = g_strdup_printf("Content-Type: %s\r\n", type);
	} else {
		hdr = g_strdup("Content-Type: text/plain; charset=UTF-8\r\n");
	}
        tmp = get_contact(sip);
	hdr = g_strdup_printf("Contact: %s\r\n%s", tmp, hdr);
	g_free(tmp);

	send_sip_request(sip->gc, "MESSAGE", fullto, fullto, hdr, msg, NULL, NULL);
	g_free(hdr);
	g_free(fullto);
}

static int sipe_im_send(GaimConnection *gc, const char *who, const char *what, GaimMessageFlags flags) {
	struct sipe_account_data *sip = gc->proto_data;
	char *to = g_strdup(who);
	char *text = gaim_unescape_html(what);
	sipe_send_message(sip, to, text, NULL);
	g_free(to);
	g_free(text);
	return 1;
}

static void process_incoming_message(struct sipe_account_data *sip, struct sipmsg *msg) {
	gchar *from;
	gchar *contenttype;
	gboolean found = FALSE;

	from = parse_from(sipmsg_find_header(msg, "From"));

	if(!from) return;

	gaim_debug_info("sipe", "got message from %s: %s\n", from, msg->body);

	contenttype = sipmsg_find_header(msg, "Content-Type");
	if(!contenttype || !strncmp(contenttype, "text/plain", 10) || !strncmp(contenttype, "text/html", 9)) {
		serv_got_im(sip->gc, from, msg->body, 0, time(NULL));
		send_sip_response(sip->gc, msg, 200, "OK", NULL);
		found = TRUE;
	}
	if(!strncmp(contenttype, "application/im-iscomposing+xml", 30)) {
		xmlnode *isc = xmlnode_from_str(msg->body, msg->bodylen);
		xmlnode *state;
		gchar *statedata;

		if(!isc) {
			gaim_debug_info("sipe", "process_incoming_message: can not parse iscomposing\n");
			return;
		}

		state = xmlnode_get_child(isc, "state");

		if(!state) {
			gaim_debug_info("sipe", "process_incoming_message: no state found\n");
			xmlnode_free(isc);
			return;
		}

		statedata = xmlnode_get_data(state);
		if(statedata) {
			if(strstr(statedata, "active")) serv_got_typing(sip->gc, from, 0, GAIM_TYPING);
			else serv_got_typing_stopped(sip->gc, from);

			g_free(statedata);
		}
		xmlnode_free(isc);
		send_sip_response(sip->gc, msg, 200, "OK", NULL);
		found = TRUE;
	}
	if(!found) {
		gaim_debug_info("sipe", "got unknown mime-type");
		send_sip_response(sip->gc, msg, 415, "Unsupported media type", NULL);
	}
	g_free(from);
}


gboolean process_register_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc) {
	gchar *tmp;
	gaim_debug(GAIM_DEBUG_MISC, "sipe", "in process register response response: %d\n", msg->response);
	switch (msg->response) {
		case 200:
			sip->registerstatus = 3;
			gaim_connection_set_state(sip->gc, GAIM_CONNECTED);

                       // if(sip->registerstatus < 3) { /* registered */
				
		      //} 

                        /* get buddies from blist */
			sipe_get_buddies(sip->gc);

			subscribe_timeout(sip);

			tmp = sipmsg_find_header(msg, "Allow-Events");
		        if(tmp && strstr(tmp, "vnd-microsoft-provisioning")){
				sipe_subscribe_buddylist(sip);
			}

			break;
		case 401:
			if(sip->registerstatus != 2) {
				gaim_debug_info("sipe", "REGISTER retries %d\n", sip->registrar.retries);
				if(sip->registrar.retries > 3) {
					sip->gc->wants_to_die = TRUE;
					gaim_connection_error(sip->gc, _("Wrong Password"));
					return TRUE;
				}
				tmp = sipmsg_find_header(msg, "WWW-Authenticate");
				fill_auth(sip, tmp, &sip->registrar);
				sip->registerstatus = 2;
				do_register(sip);
			}
			break;
		}
	return TRUE;
}

static void process_incoming_notify(struct sipe_account_data *sip, struct sipmsg *msg) {
	gchar *from;
	gchar *fromhdr;
	gchar *tmp2;
	xmlnode *pidf;
	xmlnode *basicstatus = NULL, *tuple, *status;
	gboolean isonline = FALSE;

	fromhdr = sipmsg_find_header(msg, "From");
	from = parse_from(fromhdr);
	if(!from) return;

	pidf = xmlnode_from_str(msg->body, msg->bodylen);

	if(!pidf) {
		gaim_debug_info("sipe", "process_incoming_notify: no parseable pidf\n");
		return;
	}

        gaim_debug_info("sipe", "process_incoming_notify: body(%s)\n",msg->body);

	if ((tuple = xmlnode_get_child(pidf, "tuple")))
		if ((status = xmlnode_get_child(tuple, "status")))
			basicstatus = xmlnode_get_child(status, "basic");

	if(!basicstatus) {
		gaim_debug_info("sipe", "process_incoming_notify: no basic found\n");
		xmlnode_free(pidf);
		return;
	}

	tmp2 = xmlnode_get_data(basicstatus);

        gaim_debug_info("sipe", "process_incoming_notify: basic-status(%s)\n",tmp2);


	if(!tmp2) {
		gaim_debug_info("sipe", "process_incoming_notify: no basic data found\n");
		xmlnode_free(pidf);
		return;
	}

	if(strstr(tmp2, "open")) {
		isonline = TRUE;
	}

	g_free(tmp2);

	if(isonline) gaim_prpl_got_user_status(sip->account, from, "available", NULL);
	else gaim_prpl_got_user_status(sip->account, from, "offline", NULL);

	xmlnode_free(pidf);

	g_free(from);
	send_sip_response(sip->gc, msg, 200, "OK", NULL);
}

static gchar *find_tag(const gchar *hdr) {
	const gchar *tmp = strstr(hdr, ";tag="), *tmp2;

	if(!tmp) return NULL;
	tmp += 5;
	if((tmp2 = strchr(tmp, ';'))) {
		return g_strndup(tmp, tmp2 - tmp);
	}
	return g_strdup(tmp);
}

static gchar* gen_xpidf(struct sipe_account_data *sip) {
	gchar *doc = g_strdup_printf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
			"<presence>\n"
			"<presentity uri=\"sip:%s@%s;method=SUBSCRIBE\"/>\n"
			"<display name=\"sip:%s@%s\"/>\n"
			"<atom id=\"1234\">\n"
			"<address uri=\"sip:%s@%s\">\n"
			"<status status=\"%s\"/>\n"
			"</address>\n"
			"</atom>\n"
			"</presence>\n",
			sip->username,
			sip->servername,
			sip->username,
			sip->servername,
			sip->username,
			sip->servername,
			sip->status);
	return doc;
}



static gchar* gen_pidf(struct sipe_account_data *sip) {
         gchar *doc = g_strdup_printf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
                        "<presence xmlns=\"urn:ietf:params:xml:ns:pidf\" xmlns:ep=\"urn:ietf:params:xml:ns:pidf:status:rpid-status\" xmlns:ci=\"urn:ietf:params:xml:ns:pidf:cipid\" entity=\"sip:%s@%s\">\n"
                        "<tuple id=\"0\">\n"
                        "<status>\n"
                        "<basic>open</basic>\n"
                        "<ep:activities>\n"
                        " <ep:activity>%s</ep:activity>\n"
                        "</ep:activities>"
                        "</status>\n"
                        "</tuple>\n" 
                        "<ci:display-name>FixXxeR</ci:display-name>\n"
                        "</presence>",
                        sip->username,
                        sip->servername,
                        sip->status);
	return doc;
}

static void send_notify(struct sipe_account_data *sip, struct sipe_watcher *watcher) {
	gchar *doc = watcher->needsxpidf ? gen_xpidf(sip) : gen_pidf(sip);
	gchar *hdr = watcher->needsxpidf ? "Event: presence\r\nContent-Type: application/xpidf+xml\r\n" : "Event: presence\r\nContent-Type: application/pidf+xml\r\n";
	send_sip_request(sip->gc, "NOTIFY", watcher->name, watcher->name, hdr, doc, &watcher->dialog, NULL);
	g_free(doc);
}

static gboolean process_service_response(struct sipe_account_data *sip, struct sipmsg *msg, struct transaction *tc) {
	if(msg->response != 200 && msg->response != 408) {
		/* never send again */
		sip->republish = -1;
	}
	return TRUE;
}

static void send_service(struct sipe_account_data *sip) {
	gchar *uri = g_strdup_printf("sip:%s@%s", sip->username, sip->servername);
	gchar *doc = gen_pidf(sip);
        gchar *hdr = g_strdup("Content-Type: application/SOAP+xml\r\n");
        gchar *tmp = get_contact(sip);
        hdr = g_strdup_printf("Contact: %s\r\n%s", tmp, hdr);
        g_free(tmp); 
	send_sip_request(sip->gc, "SERVICE", uri, uri,
		hdr,
		doc, NULL, process_service_response);
	sip->republish = time(NULL) + 500;
        g_free(hdr);
	g_free(uri);
	g_free(doc);
}

static void process_incoming_subscribe(struct sipe_account_data *sip, struct sipmsg *msg) {
	const char *from_hdr = sipmsg_find_header(msg, "From");
	gchar *from = parse_from(from_hdr);
	gchar *theirtag = find_tag(from_hdr);
	gchar *ourtag = find_tag(sipmsg_find_header(msg, "To"));
	gboolean tagadded = FALSE;
	gchar *callid = sipmsg_find_header(msg, "Call-ID");
	gchar *expire = sipmsg_find_header(msg, "Expire");
    //    gchar *ms-received-port =find_received_port(sipmsg_find_header(msg, "Contact"));
	gchar *tmp;
	struct sipe_watcher *watcher = watcher_find(sip, from);
	if(!ourtag) {
		tagadded = TRUE;
		ourtag = gentag();
	}
	if(!watcher) { /* new subscription */
		gchar *acceptheader = sipmsg_find_header(msg, "Accept");
		gboolean needsxpidf = FALSE;
		if(!gaim_privacy_check(sip->account, from)) {
			send_sip_response(sip->gc, msg, 202, "Ok", NULL);
			goto privend;
		}
		if(acceptheader) {
			gchar *tmp = acceptheader;
			gboolean foundpidf = FALSE;
			gboolean foundxpidf = FALSE;
			while(tmp && tmp < acceptheader + strlen(acceptheader)) {
				gchar *tmp2 = strchr(tmp, ',');
				if(tmp2) *tmp2 = '\0';
				if(!strcmp("application/pidf+xml", tmp))
					foundpidf = TRUE;
				if(!strcmp("application/xpidf+xml", tmp))
					foundxpidf = TRUE;
				if(tmp2) {
					*tmp2 = ',';
					tmp = tmp2;
					while(*tmp == ' ') tmp++;
				} else
					tmp = 0;
			}
			if(!foundpidf && foundxpidf) needsxpidf = TRUE;
			g_free(acceptheader);
		}
		watcher = watcher_create(sip, from, callid, ourtag, theirtag, needsxpidf);
	}
	if(tagadded) {
		gchar *to = g_strdup_printf("%s;tag=%s", sipmsg_find_header(msg, "To"), ourtag);
		sipmsg_remove_header(msg, "To");
		sipmsg_add_header(msg, "To", to);
		g_free(to);
	}
	if(expire)
		watcher->expire = time(NULL) + strtol(expire, NULL, 10);
	else
		watcher->expire = time(NULL) + 600;
	//Fixxxer
	sipmsg_remove_header(msg, "Contact");
	tmp = get_contact(sip);
	sipmsg_add_header(msg, "Contact", tmp);
	g_free(tmp);
	gaim_debug_info("sipe", "got subscribe: name %s ourtag %s theirtag %s callid %s\n", watcher->name, watcher->dialog.ourtag, watcher->dialog.theirtag, watcher->dialog.callid);
	send_sip_response(sip->gc, msg, 200, "Ok", NULL);
	send_notify(sip, watcher);
privend:
	g_free(from);
	g_free(theirtag);
	g_free(ourtag);
	g_free(callid);
	g_free(expire);
}

static void process_input_message(struct sipe_account_data *sip, struct sipmsg *msg) {
	gboolean found = FALSE;
        gaim_debug_info("sipe", "msg->response(%d),msg->method(%s)\n",msg->response,msg->method);
	if(msg->response == 0) { /* request */
		if(!strcmp(msg->method, "MESSAGE")) {
			process_incoming_message(sip, msg);
			found = TRUE;
		} else if(!strcmp(msg->method, "NOTIFY")) {
                        gaim_debug_info("sipe","send->process_incoming_notify\n");
			process_incoming_notify(sip, msg);
			found = TRUE;
		} else if(!strcmp(msg->method, "SUBSCRIBE")) {
                        gaim_debug_info("sipe","send->process_incoming_subscribe\n");
			process_incoming_subscribe(sip, msg);
			found = TRUE;
		} else {
			send_sip_response(sip->gc, msg, 501, "Not implemented", NULL);
		}
	} else { /* response */
		struct transaction *trans = transactions_find(sip, msg);
		if(trans) {
			if(msg->response == 407) {
				gchar *resend, *auth, *ptmp;

				if(sip->proxy.retries > 30) return;
				sip->proxy.retries++;
				/* do proxy authentication */

				ptmp = sipmsg_find_header(msg, "Proxy-Authenticate");

				fill_auth(sip, ptmp, &sip->proxy);
				auth = auth_header(sip, &sip->proxy, trans->msg->method, trans->msg->target);
				sipmsg_remove_header(trans->msg, "Proxy-Authorization");
				sipmsg_add_header(trans->msg, "Proxy-Authorization", auth);
				g_free(auth);
				resend = sipmsg_to_string(trans->msg);
				/* resend request */
				sendout_pkt(sip->gc, resend);
				g_free(resend);
			} else {
				if(msg->response == 100) {
					/* ignore provisional response */
					gaim_debug_info("sipe", "got trying response\n");
				} else {
					sip->proxy.retries = 0;
					if(!strcmp(trans->msg->method, "REGISTER")) {
						if(msg->response == 401) sip->registrar.retries++;
						else sip->registrar.retries = 0;
                                                gaim_debug_info("sipe", "RE-REGISTER\n");
					} else {
						if(msg->response == 401) {
							gchar *resend, *auth, *ptmp;

							if(sip->registrar.retries > 4) return;
							sip->registrar.retries++;

							ptmp = sipmsg_find_header(msg, "WWW-Authenticate");

							fill_auth(sip, ptmp, &sip->registrar);
							auth = auth_header(sip, &sip->registrar, trans->msg->method, trans->msg->target);
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
					if(trans->callback) {
						/* call the callback to process response*/
						(trans->callback)(sip, msg, trans);
					}
					transactions_remove(sip, trans);
				}
			}
			found = TRUE;
		} else {
			gaim_debug(GAIM_DEBUG_MISC, "sipe", "received response to unknown transaction");
		}
	}
	if(!found) {
		gaim_debug(GAIM_DEBUG_MISC, "sipe", "received a unknown sip message with method %s and response %d\n", msg->method, msg->response);
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
	while(*cur == '\r' || *cur == '\n') {
		cur++;
	}
	if(cur != conn->inbuf) {
		memmove(conn->inbuf, cur, conn->inbufused - (cur - conn->inbuf));
		conn->inbufused = strlen(conn->inbuf);
	}

	/* Received a full Header? */
	if((cur = strstr(conn->inbuf, "\r\n\r\n")) != NULL) {
		time_t currtime = time(NULL);
		cur += 2;
		cur[0] = '\0';
		gaim_debug_info("sipe", "\n\nreceived - %s\n######\n%s\n#######\n\n", ctime(&currtime), conn->inbuf);
		msg = sipmsg_parse_header(conn->inbuf);
		cur[0] = '\r';
		cur += 2;
		restlen = conn->inbufused - (cur - conn->inbuf);
		if(restlen >= msg->bodylen) {
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
		gaim_debug(GAIM_DEBUG_MISC, "sipe", "in process response response: %d\n", msg->response);
		process_input_message(sip, msg);
	} else {
		gaim_debug(GAIM_DEBUG_MISC, "sipe", "received a incomplete sip msg: %s\n", conn->inbuf);
	}
}

static void sipe_udp_process(gpointer data, gint source, GaimInputCondition con) {
	GaimConnection *gc = data;
	struct sipe_account_data *sip = gc->proto_data;
	struct sipmsg *msg;
	int len;
	time_t currtime;

	static char buffer[65536];
	if((len = recv(source, buffer, sizeof(buffer) - 1, 0)) > 0) {
		buffer[len] = '\0';
		gaim_debug_info("sipe", "\n\nreceived - %s\n######\n%s\n#######\n\n", ctime(&currtime), buffer);
		msg = sipmsg_parse_msg(buffer);
		if(msg) process_input_message(sip, msg);
	}
}

static void sipe_input_cb(gpointer data, gint source, GaimInputCondition cond)
{
	GaimConnection *gc = data;
	struct sipe_account_data *sip = gc->proto_data;
	int len;
	struct sip_connection *conn = connection_find(sip, source);
	if(!conn) {
		gaim_debug_error("sipe", "Connection not found!\n");
		return;
	}

	if(conn->inbuflen < conn->inbufused + SIMPLE_BUF_INC) {
		conn->inbuflen += SIMPLE_BUF_INC;
		conn->inbuf = g_realloc(conn->inbuf, conn->inbuflen);
	}

	len = read(source, conn->inbuf + conn->inbufused, SIMPLE_BUF_INC - 1);

	if(len < 0 && errno == EAGAIN)
		return;
	else if(len <= 0) {
		gaim_debug_info("sipe", "sipe_input_cb: read error\n");
		connection_remove(sip, source);
		if(sip->fd == source) sip->fd = -1;
		return;
	}

	conn->inbufused += len;
	conn->inbuf[conn->inbufused] = '\0';

	process_input(sip, conn);
}

/* Callback for new connections on incoming TCP port */
static void sipe_newconn_cb(gpointer data, gint source, GaimInputCondition cond) {
	GaimConnection *gc = data;
	struct sipe_account_data *sip = gc->proto_data;
	struct sip_connection *conn;

	int newfd = accept(source, NULL, NULL);

	conn = connection_create(sip, newfd);

	conn->inputhandler = gaim_input_add(newfd, GAIM_INPUT_READ, sipe_input_cb, gc);
}

static void login_cb(gpointer data, gint source, const gchar *error_message) {
	GaimConnection *gc = data;
	struct sipe_account_data *sip;
	struct sip_connection *conn;

	if (!GAIM_CONNECTION_IS_VALID(gc))
	{
		if (source >= 0)
			close(source);
		return;
	}

	if(source < 0) {
		gaim_connection_error(gc, _("Could not connect"));
		return;
	}

	sip = gc->proto_data;
	sip->fd = source;

	conn = connection_create(sip, source);

	sip->registertimeout = gaim_timeout_add((rand()%100)+10*1000, (GSourceFunc)subscribe_timeout, sip);

	do_register(sip);

	conn->inputhandler = gaim_input_add(sip->fd, GAIM_INPUT_READ, sipe_input_cb, gc);
}

static guint sipe_ht_hash_nick(const char *nick) {
	char *lc = g_utf8_strdown(nick, -1);
	guint bucket = g_str_hash(lc);
	g_free(lc);

	return bucket;
}

static gboolean sipe_ht_equals_nick(const char *nick1, const char *nick2) {
	return (gaim_utf8_strcasecmp(nick1, nick2) == 0);
}

static void sipe_udp_host_resolved_listen_cb(int listenfd, gpointer data) {
	struct sipe_account_data *sip = (struct sipe_account_data*) data;

	sip->listen_data = NULL;

	if(listenfd == -1) {
		gaim_connection_error(sip->gc, _("Could not create listen socket"));
		return;
	}

	sip->fd = listenfd;

	sip->listenport = gaim_network_get_port_from_fd(sip->fd);
	sip->listenfd = sip->fd;

	sip->listenpa = gaim_input_add(sip->fd, GAIM_INPUT_READ, sipe_udp_process, sip->gc);

	sip->resendtimeout = gaim_timeout_add(2500, (GSourceFunc) resend_timeout, sip);
	sip->registertimeout = gaim_timeout_add((rand()%100)+10*1000, (GSourceFunc)subscribe_timeout, sip);
	do_register(sip);
}

static void sipe_udp_host_resolved(GSList *hosts, gpointer data, const char *error_message) {
	struct sipe_account_data *sip = (struct sipe_account_data*) data;
	int addr_size;

	sip->query_data = NULL;

	if (!hosts || !hosts->data) {
		gaim_connection_error(sip->gc, _("Couldn't resolve host"));
		return;
	}

	addr_size = GPOINTER_TO_INT(hosts->data);
	hosts = g_slist_remove(hosts, hosts->data);
	memcpy(&(sip->serveraddr), hosts->data, addr_size);
	g_free(hosts->data);
	hosts = g_slist_remove(hosts, hosts->data);
	while(hosts) {
		hosts = g_slist_remove(hosts, hosts->data);
		g_free(hosts->data);
		hosts = g_slist_remove(hosts, hosts->data);
	}

	/* create socket for incoming connections */
	sip->listen_data = gaim_network_listen_range(5060, 5160, SOCK_DGRAM,
				sipe_udp_host_resolved_listen_cb, sip);
	if (sip->listen_data == NULL) {
		gaim_connection_error(sip->gc, _("Could not create listen socket"));
		return;
	}
}

static void
sipe_tcp_connect_listen_cb(int listenfd, gpointer data) {
	struct sipe_account_data *sip = (struct sipe_account_data*) data;
	GaimProxyConnectData *connect_data;

	sip->listen_data = NULL;

	sip->listenfd = listenfd;
	if(sip->listenfd == -1) {
		gaim_connection_error(sip->gc, _("Could not create listen socket"));
		return;
	}

	gaim_debug_info("sipe", "listenfd: %d\n", sip->listenfd);
	sip->listenport = gaim_network_get_port_from_fd(sip->listenfd);
	sip->listenpa = gaim_input_add(sip->listenfd, GAIM_INPUT_READ,
			sipe_newconn_cb, sip->gc);
	gaim_debug_info("sipe", "connecting to %s port %d\n",
			sip->realhostname, sip->realport);
	/* open tcp connection to the server */
	connect_data = gaim_proxy_connect(sip->gc, sip->account, sip->realhostname,
			sip->realport, login_cb, sip->gc);
	if(connect_data == NULL) {
		gaim_connection_error(sip->gc, _("Couldn't create socket"));
	}
}

static void srvresolved(GaimSrvResponse *resp, int results, gpointer data) {
	struct sipe_account_data *sip;
	gchar *hostname;
	int port;

	sip = data;
	sip->srv_query_data = NULL;

	port = gaim_account_get_int(sip->account, "port", 0);

	/* find the host to connect to */
	if(results) {
		hostname = g_strdup(resp->hostname);
		if(!port)
			port = resp->port;
		g_free(resp);
	} else {
		if(!gaim_account_get_bool(sip->account, "useproxy", FALSE)) {
			hostname = g_strdup(sip->servername);
		} else {
			hostname = g_strdup(gaim_account_get_string(sip->account, "proxy", sip->servername));
		}
	}

	sip->realhostname = hostname;
	sip->realport = port;
	if(!sip->realport) sip->realport = 5060;

	/* TCP case */
	if(!sip->udp) {
		/* create socket for incoming connections */
		sip->listen_data = gaim_network_listen_range(5060, 5160, SOCK_STREAM,
					sipe_tcp_connect_listen_cb, sip);
		if (sip->listen_data == NULL) {
			gaim_connection_error(sip->gc, _("Could not create listen socket"));
			return;
		}
	} else { /* UDP */
		gaim_debug_info("sipe", "using udp with server %s and port %d\n", hostname, port);

		sip->query_data = gaim_dnsquery_a(hostname, port, sipe_udp_host_resolved, sip);
		if (sip->query_data == NULL) {
			gaim_connection_error(sip->gc, _("Could not resolve hostname"));
		}
	}
}

static void sipe_login(GaimAccount *account)
{
	GaimConnection *gc;
	struct sipe_account_data *sip;
	gchar **userserver;
	gchar *hosttoconnect;

	const char *username = gaim_account_get_username(account);
	gc = gaim_account_get_connection(account);

	if (strpbrk(username, " \t\v\r\n") != NULL) {
		gc->wants_to_die = TRUE;
		gaim_connection_error(gc, _("SIP Exchange usernames may not contain whitespaces or @ symbols"));
		return;
	}

	gc->proto_data = sip = g_new0(struct sipe_account_data, 1);
	sip->gc = gc;
	sip->account = account;
	sip->registerexpire = 900;
	sip->udp = gaim_account_get_bool(account, "udp", FALSE);
	/* TODO: is there a good default grow size? */
	if(!sip->udp)
		sip->txbuf = gaim_circ_buffer_new(0);

	userserver = g_strsplit(username, "@", 3);
	gaim_connection_set_display_name(gc, userserver[0]);
        sip->username = g_strdup(g_strjoin("@", userserver[0], userserver[1])); 
        sip->servername = g_strdup(userserver[2]);
	sip->password = g_strdup(gaim_connection_get_password(gc));
	g_strfreev(userserver);

	sip->buddies = g_hash_table_new((GHashFunc)sipe_ht_hash_nick, (GEqualFunc)sipe_ht_equals_nick);

	gaim_connection_update_progress(gc, _("Connecting"), 1, 2);

	/* TODO: Set the status correctly. */
	sip->status = g_strdup("available");

	if(!gaim_account_get_bool(account, "useproxy", FALSE)) {
		hosttoconnect = g_strdup(sip->servername);
	} else {
		hosttoconnect = g_strdup(gaim_account_get_string(account, "proxy", sip->servername));
	}

	sip->srv_query_data = gaim_srv_resolve("sip",
			sip->udp ? "udp" : "tcp", hosttoconnect, srvresolved, sip);
	g_free(hosttoconnect);
}

static void sipe_close(GaimConnection *gc)
{
	struct sipe_account_data *sip = gc->proto_data;

	if(sip) {
		/* unregister */
		do_register_exp(sip, 0);
		connection_free_all(sip);

		if (sip->query_data != NULL)
			gaim_dnsquery_destroy(sip->query_data);

		if (sip->srv_query_data != NULL)
			gaim_srv_cancel(sip->srv_query_data);

		if (sip->listen_data != NULL)
			gaim_network_listen_cancel(sip->listen_data);

		g_free(sip->servername);
		g_free(sip->username);
		g_free(sip->password);
		g_free(sip->registrar.nonce);
		g_free(sip->registrar.opaque);
		g_free(sip->registrar.target);
		g_free(sip->registrar.realm);
		g_free(sip->registrar.digest_session_key);
		g_free(sip->proxy.nonce);
		g_free(sip->proxy.opaque);
		g_free(sip->proxy.target);
		g_free(sip->proxy.realm);
		g_free(sip->proxy.digest_session_key);
		if(sip->txbuf)
			gaim_circ_buffer_destroy(sip->txbuf);
		g_free(sip->realhostname);
		if(sip->listenpa) gaim_input_remove(sip->listenpa);
		if(sip->tx_handler) gaim_input_remove(sip->tx_handler);
		if(sip->resendtimeout) gaim_timeout_remove(sip->resendtimeout);
		if(sip->registertimeout) gaim_timeout_remove(sip->registertimeout);
	}
	g_free(gc->proto_data);
	gc->proto_data = NULL;
}

/* not needed since privacy is checked for every subscribe */
static void dummy_add_deny(GaimConnection *gc, const char *name) {
}

static void dummy_permit_deny(GaimConnection *gc) {
}

static gboolean sipe_plugin_load(PurplePlugin *plugin) {
  return TRUE;
}


static gboolean sipe_plugin_unload(PurplePlugin *plugin) {
    return TRUE;
}


static void sipe_plugin_destroy(PurplePlugin *plugin) {
}

static PurplePlugin *my_protocol = NULL;

static PurplePluginProtocolInfo prpl_info =
{
	0,
	NULL,					/* user_splits */
	NULL,					/* protocol_options */
	NO_BUDDY_ICONS,			/* icon_spec */
	sipe_list_icon,		/* list_icon */
	NULL,					/* list_emblems */
	NULL,					/* status_text */
	NULL,					/* tooltip_text */
	sipe_status_types,	/* away_states */
	NULL,					/* blist_node_menu */
	NULL,					/* chat_info */
	NULL,					/* chat_info_defaults */
	sipe_login,			/* login */
	sipe_close,			/* close */
	sipe_im_send,			/* send_im */
	NULL,					/* set_info */
//	sipe_typing,			/* send_typing */
        NULL,			/* send_typing */
	NULL,					/* get_info */
	sipe_set_status,		/* set_status */
	NULL,					/* set_idle */
	NULL,					/* change_passwd */
	sipe_add_buddy,		/* add_buddy */
	NULL,					/* add_buddies */
	sipe_remove_buddy,	/* remove_buddy */
	NULL,					/* remove_buddies */
	dummy_add_deny,			/* add_permit */
	dummy_add_deny,			/* add_deny */
	dummy_add_deny,			/* rem_permit */
	dummy_add_deny,			/* rem_deny */
	dummy_permit_deny,		/* set_permit_deny */
	NULL,					/* join_chat */
	NULL,					/* reject_chat */
	NULL,					/* get_chat_name */
	NULL,			                /* chat_invite */
	NULL,					/* chat_leave */
	NULL,					/* chat_whisper */
	NULL,					/* chat_send */
	sipe_keep_alive,		/* keepalive */
	NULL,					/* register_user */
	NULL,					/* get_cb_info */
	NULL,					/* get_cb_away */
	NULL,					/* alias_buddy */
	NULL,					/* group_buddy */
	NULL,					/* rename_group */
	NULL,					/* buddy_free */
	NULL,					/* convo_closed */
	NULL,					/* normalize */
	NULL,					/* set_buddy_icon */
	NULL,					/* remove_group */
	NULL,					/* get_cb_real_name */
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
};


static GaimPluginInfo info = {
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_PROTOCOL,                           /**< type           */
	NULL,                                             /**< ui_requirement */
	0,                                                /**< flags          */
	NULL,                                             /**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,                          /**< priority       */
        "prpl-sipe",                                   	  /**< id             */
	"SIPE",                                           /**< name           */
	VERSION,                                          /**< version        */
	N_("SIP/SIMPLE Exchange Protocol Plugin"),        /**  summary        */
	N_("The SIP/SIMPLE Exchange Protocol Plugin"),    /**  description    */
	"Anibal Avelar <avelar@gmail.com>",         	  /**< author         */
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

        purple_plugin_register(plugin);

	split = gaim_account_user_split_new(_("Server"), "", '@');
	prpl_info.user_splits = g_list_append(prpl_info.user_splits, split);

	option = gaim_account_option_bool_new(_("Publish status (note: everyone may watch you)"), "doservice", TRUE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = gaim_account_option_int_new(_("Connect port"), "port", 0);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);

	option = gaim_account_option_bool_new(_("Use UDP"), "udp", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
	option = gaim_account_option_bool_new(_("Use proxy"), "useproxy", FALSE);
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
	option = gaim_account_option_string_new(_("Proxy"), "proxy", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
	option = gaim_account_option_string_new(_("Auth User"), "authuser", "");
	prpl_info.protocol_options = g_list_append(prpl_info.protocol_options, option);
	option = gaim_account_option_string_new(_("Auth Domain"), "authdomain", "");
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

