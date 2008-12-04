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

#define SIPE_TYPING_RECV_TIMEOUT 6
#define SIPE_TYPING_SEND_TIMEOUT 4

struct sip_im_session {
	gchar * with;
	struct sip_dialog * dialog;
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
	int group_id;
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
	int delta_num;
	int presence_method_version;
	gchar *status;
	int status_version;
	gchar *contact;
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
	GSList *groups;
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
	void * payload;
};

struct sipe_group {
	gchar *name;
	int id;
        PurpleGroup *purple_group;
};

struct group_user_context {
	gchar * group_name;
	gchar * user_name;
};

#define SIPE_SEND_TYPING \
"<?xml version=\"1.0\"?>"\
"<KeyboardActivity>"\
  "<status status=\"type\" />"\
"</KeyboardActivity>"

#define SIPE_SEND_PRESENCE \
	"<publish xmlns=\"http://schemas.microsoft.com/2006/09/sip/rich-presence\">"\
	  "<publications uri=\"%s\">"\
	      "<publication categoryName=\"state\" instance=\"906391354\" container=\"2\" version=\"%d\" expireType=\"endpoint\">"\
	        "<state xmlns=\"http://schemas.microsoft.com/2006/09/sip/state\" manual=\"false\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"machineState\">"\
		  "<availability>%d</availability>"\
		  "<endpointLocation></endpointLocation>"\
		"</state>"\
	      "</publication>"\
	      "<publication categoryName=\"state\" instance=\"906391356\" container=\"0\" version=\"%d\" expireType=\"endpoint\">"\
	        "<state xmlns=\"http://schemas.microsoft.com/2006/09/sip/state\" manual=\"true\" xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"userState\">"\
		  "<availability>%d</availability>"\
		  "<endpointLocation></endpointLocation>"\
		"</state>"\
	      "</publication>"\
	      "<publication categoryName=\"note\" instance=\"0\" container=\"400\" version=\"%d\" expireType=\"static\">"\
	        "<note xmlns=\"http://schemas.microsoft.com/2006/09/sip/note\">"\
		  "<body type=\"personal\" uri=\"\">%s</body>"\
		"</note>"\
	      "</publication>"\
	      "<publication categoryName=\"note\" instance=\"0\" container=\"200\" version=\"%d\" expireType=\"static\">"\
	        "<note xmlns=\"http://schemas.microsoft.com/2006/09/sip/note\">"\
		  "<body type=\"personal\" uri=\"\">%s</body>"\
		"</note>"\
	      "</publication>"\
	      "<publication categoryName=\"note\" instance=\"0\" container=\"300\" version=\"%d\" expireType=\"static\">"\
	        "<note xmlns=\"http://schemas.microsoft.com/2006/09/sip/note\">"\
		  "<body type=\"personal\" uri=\"\">%s</body>"\
		"</note>"\
	      "</publication>"\
	    "</publications>"\
	"</publish>"


#define SIPE_SEND_CLEAR_PRESENCE \
"<publish xmlns=\"http://schemas.microsoft.com/2006/09/sip/rich-presence\">"\
  "<publications uri=\"%s\">"\
	"<publication categoryName=\"state\" instance=\"906391354\" container=\"2\" version=\"1\" expireType=\"static\" expires=\"0\" />"\
	"<publication categoryName=\"state\" instance=\"906391356\" container=\"0\" version=\"1\" expireType=\"static\" expires=\"0\" />"\
	"<publication categoryName=\"note\" instance=\"0\" container=\"300\" version=\"1\" expireType=\"static\" expires=\"0\" />"\
	"<publication categoryName=\"note\" instance=\"0\" container=\"200\" version=\"1\" expireType=\"static\" expires=\"0\" />"\
	"<publication categoryName=\"note\" instance=\"0\" container=\"400\" version=\"1\" expireType=\"static\" expires=\"0\" />"\
  "</publications>"\
"</publish>"


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
	"<m:groups>%d</m:groups>"\
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

#define SIPE_SOAP_SET_PRESENCE sipe_soap("setPresence", \
	"<m:presentity m:uri=\"%s\">"\
	"<m:availability m:aggregate=\"%d\"/>"\
	"<m:activity m:aggregate=\"%d\" m:note=\"%s\"/>"\
	"<deviceName xmlns=\"http://schemas.microsoft.com/2002/09/sip/client/presence\" name=\"USER-DESKTOP\"/>"\
	"<rtc:devicedata xmlns:rtc=\"http://schemas.microsoft.com/2002/09/sip/client/presence\" namespace=\"rtcService\">"\
	"&lt;![CDATA[<caps><renders_gif/><renders_isf/></caps>]]&gt;</rtc:devicedata>"\
	"</m:presentity>")

#endif /* _PIDGIN_SIPE_H */
