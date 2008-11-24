/**
 * @file sipe.h
 *
 * pidgin-sipe
 *
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

#ifndef _PIDGIN_SIPE_H
#define _PIDGIN_SIPE_H

#include <glib.h>
#include <time.h>

#include "cipher.h"
#include "circbuffer.h"
#include "dnsquery.h"
#include "dnssrv.h"
#include "network.h"
#include "proxy.h"
#include "prpl.h"
#include "sslconn.h"

#include "sipmsg.h"
#include "uuid.h"

#define SIMPLE_BUF_INC 4096


struct sip_im_session {
	gchar * with;
	struct sip_dialog * outgoing_dialog;
	struct sip_dialog * incoming_dialog;
	struct transaction * outgoing_invite;

	GSList *outgoing_message_queue;
};

// dialog is the new term for call-leg
struct sip_dialog {
	gchar *ourtag;
	gchar *theirtag;
	gchar *theirepid;
	gchar *callid;
	gchar *route;
	gchar *request;
	int cseq;
};

struct sipe_watcher {
	gchar *name;
	time_t expire;
	struct sip_dialog dialog;
	gboolean needsxpidf;
};

struct sipe_buddy {
	gchar *name;
	time_t resubscribe;
};

struct sip_auth {
	int type; /* 1 = Digest / 2 = NTLM / 3 = Kerberos */
	gchar *nonce;
	gchar *opaque;
	gchar *realm;
	gchar *target;
        gchar *rspauth;
        gchar *srand;
	guint32 flags;
	int nc;
	gchar *digest_session_key;
	int retries;
	gchar *ntlm_key;
	int ntlm_num;
};

struct sipe_account_data {
	PurpleConnection *gc;
	gchar *sipdomain;
	gchar *username;
	gchar *password;
	PurpleDnsQueryData *query_data;
	PurpleSrvQueryData *srv_query_data;
	PurpleNetworkListenData *listen_data;
	int fd;
	int cseq;
	time_t reregister;
	time_t republish;
	int registerstatus; /* 0 nothing, 1 first registration send, 2 auth received, 3 registered */
	struct sip_auth registrar;
	struct sip_auth proxy;
	int listenfd;
	int listenport;
	int listenpa;
	gchar *status;
	GHashTable *buddies;
	guint registertimeout;
	guint resendtimeout;
	gboolean connecting;
	PurpleAccount *account;
	PurpleCircBuffer *txbuf;
	guint tx_handler;
	gchar *regcallid;
	GSList *transactions;
	GSList *watcher;
	GSList *im_sessions;
	GSList *openconns;
	gboolean udp;
        gboolean use_ssl;
        PurpleSslConnection *gsc;
	struct sockaddr_in serveraddr;
	int registerexpire;
	gchar *realhostname;
	int realport; /* port and hostname from SRV record */
};

struct sip_connection {
	int fd;
	gchar *inbuf;
	int inbuflen;
	int inbufused;
	int inputhandler;
};

struct transaction;

typedef gboolean (*TransCallback) (struct sipe_account_data *, struct sipmsg *, struct transaction *);

struct transaction {
	time_t time;
	int retries;
	int transport; /* 0 = tcp, 1 = udp */
	int fd;
	gchar *cseq;
	struct sipmsg *msg;
	TransCallback callback;
};

struct sipe_group {
	gchar *name_group;
	gchar *id;
        PurpleGroup *g;
};

#endif /* _PIDGIN_SIPE_H */
