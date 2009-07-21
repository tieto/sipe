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

#ifdef _WIN32
#include "internal.h"
#endif

#include "cipher.h"
#include "circbuffer.h"
#include "dnsquery.h"
#include "dnssrv.h"
#include "network.h"
#include "proxy.h"
#include "prpl.h"
#include "sslconn.h"

#include "sipmsg.h"
#include "sip-sec.h"
#include "uuid.h"

#define SIMPLE_BUF_INC 4096

#define SIPE_TYPING_RECV_TIMEOUT 6
#define SIPE_TYPING_SEND_TIMEOUT 4
#ifndef _WIN32
#define PURPLE_WEBSITE "http://pidgin.sf.im/"
#endif

struct sipe_buddy {
	gchar *name;
	gchar *annotation;
	gchar *device_name;
	GSList *groups;
	gboolean resubscribed;
};

struct sip_auth {
	SipSecAuthType type;
	SipSecContext gssapi_context;
	gchar *gssapi_data;
	gchar *opaque;
	gchar *realm;
	gchar *target;
	int nc;
	int retries;
	int ntlm_num;
	int expires;
};

typedef enum {
	SIPE_TRANSPORT_TLS,
	SIPE_TRANSPORT_TCP,
	SIPE_TRANSPORT_UDP,
} sipe_transport_type;

struct sipe_service_data {
	const char *service;
	const char *transport;
	sipe_transport_type type;
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
	const gchar *type;
	const gchar *value;
};

struct sipe_account_data {
	PurpleConnection *gc;
	gchar *sipdomain;
	gchar *username;
	gchar *authdomain;
	gchar *authuser;
	gchar *password;
	gchar *epid;
	gchar *focus_factory_uri;
	/** Allowed server events to subscribe. From register OK response. */
	GSList *allow_events;
	PurpleDnsQueryData *query_data;
	PurpleSrvQueryData *srv_query_data;
	const struct sipe_service_data *service_data;
	PurpleNetworkListenData *listen_data;
	int fd;
	int cseq;
	int chat_seq;
	time_t last_keepalive;
	int registerstatus; /* 0 nothing, 1 first registration send, 2 auth received, 3 registered */
	struct sip_auth registrar;
	struct sip_auth proxy;
	gboolean reregister_set; /* whether reregister timer set */
	gboolean reauthenticate_set; /* whether reauthenticate timer set */
	gboolean subscribed; /* whether subscribed to events, except buddies presence */
	gboolean subscribed_buddies; /* whether subscribed to buddies presence */
	gboolean access_level_set; /* whether basic access level set */
	int listenfd;
	int listenport;
	int listenpa;
	int contacts_delta;
	int acl_delta;
	int presence_method_version;
	gchar *status;
	int status_version;
	gchar *contact;
	gboolean msrtc_event_categories; /*if there is support for batched category subscription [SIP-PRES]*/
	gboolean batched_support; /*if there is support for batched subscription*/
	GSList *containers; /* MS-PRES containers */
	GHashTable *buddies;
	guint resendtimeout;
	guint keepalive_timeout;
	GSList *timeouts;
	gboolean connecting;
	PurpleAccount *account;
	PurpleCircBuffer *txbuf;
	guint tx_handler;
	gchar *regcallid;
	GSList *transactions;
	GSList *sessions;
	GSList *openconns;
	GSList *groups;
	sipe_transport_type transport;
	gboolean auto_transport;
	PurpleSslConnection *gsc;
	struct sockaddr *serveraddr;
	gchar *realhostname;
	int realport; /* port and hostname from SRV record */
	gboolean processing_input;
};

struct sip_connection {
	int fd;
	gchar *inbuf;
	int inbuflen;
	int inbufused;
	int inputhandler;
};

struct sipe_auth_job {
	gchar * who;
	struct sipe_account_data * sip;
};

struct transaction;

typedef gboolean (*TransCallback) (struct sipe_account_data *, struct sipmsg *, struct transaction *);

struct transaction {
	time_t time;
	int retries;
	int transport; /* 0 = tcp, 1 = udp */
	int fd;
	/** Not yet perfect, but surely better then plain CSeq
	 * Format is: <Call-ID><CSeq>
	 * (RFC3261 17.2.3 for matching server transactions: Request-URI, To tag, From tag, Call-ID, CSeq, and top Via)
	 */
	gchar *key;
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

GSList * slist_insert_unique_sorted(GSList *list, gpointer data, GCompareFunc func);

GList *sipe_actions(PurplePlugin *plugin, gpointer context);

gboolean purple_init_plugin(PurplePlugin *plugin);

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

/* SIP send module? */
struct transaction *
send_sip_request(PurpleConnection *gc, const gchar *method,
		 const gchar *url, const gchar *to, const gchar *addheaders,
		 const gchar *body, struct sip_dialog *dialog, TransCallback tc);
void
send_sip_response(PurpleConnection *gc, struct sipmsg *msg, int code,
		  const char *text, const char *body);
void
sipe_invite(struct sipe_account_data *sip, struct sip_session *session,
	    const gchar *who, const gchar *msg_body,
	    const gchar *referred_by, const gboolean is_triggered);
/* ??? module */
gboolean process_subscribe_response(struct sipe_account_data *sip,
				    struct sipmsg *msg,
				    struct transaction *tc);
/* Chat module */
void
sipe_invite_to_chat(struct sipe_account_data *sip,
		    struct sip_session *session,
		    const gchar *who);
/* Session module? */
void
sipe_present_message_undelivered_err(struct sipe_account_data *sip,
				     struct sip_session *session,
				     const gchar *who,
				     const gchar *message);
				     
void
sipe_present_info(struct sipe_account_data *sip,
		 struct sip_session *session,
		 const gchar *message);
				     

void
sipe_process_pending_invite_queue(struct sipe_account_data *sip,
				  struct sip_session *session);
				  
/*** THE BIG SPLIT END ***/

#define SIPE_INVITE_TEXT "ms-text-format: text/plain; charset=UTF-8%s;ms-body=%s\r\n"

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

#define SIPE_SOAP_SET_PRESENCE sipe_soap("setPresence", \
	"<m:presentity m:uri=\"%s\">"\
	"<m:availability m:aggregate=\"%d\"/>"\
	"<m:activity m:aggregate=\"%d\" m:note=\"%s\"/>"\
	"<deviceName xmlns=\"http://schemas.microsoft.com/2002/09/sip/client/presence\" name=\"USER-DESKTOP\"/>"\
	"<rtc:devicedata xmlns:rtc=\"http://schemas.microsoft.com/2002/09/sip/client/presence\" namespace=\"rtcService\">"\
	"&lt;![CDATA[<caps><renders_gif/><renders_isf/></caps>]]&gt;</rtc:devicedata>"\
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

#endif /* _PIDGIN_SIPE_H */
