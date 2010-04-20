/**
 * @file sip-transport.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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

/**
 * This module incapsulates SIP (RFC3261) protocol and provides
 * higher level API (a layer) to XML-based SIPE (SIP with Extensions).
 * Underlying leyer for this is TCP/SSL layer.
 *
 * A diagram in pseudographics:
 *
 * === SIPE (XML-based) layer ======================
 * === SIP RFC3261 transport layer (This module) ===
 * === TCP/SSL layer ===============================
 *
 * Authentication (Kerberos and NTLM) is applicable to this layer only.
 * The same with message integtity (signing). No sip-sec* code should
 * be used ourside of this module.
 *
 * SIP errors as codes(both as a return codes and network conditions) should be 
 * escalated to higher leyer (SIPE). Network conditions include no response 
 * within timeout interval.
 *
 * This module should support redirect internally. No escalations to higher 
 * layers needed.
 *
 * NO SIP-messages (headers) composing and processing should be outside of 
 * this module (!) Like headers: Via, Route, Contact, Authorization, etc.
 * It's all irrelated to heigher leyers responsibilities.
 *
 */
 
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include "sipe-common.h"
#include "sipmsg.h"
#include "sip-sec.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-dialog.h"
#include "sipe-nls.h"
#include "sipe-sign.h"
#include "sipe-utils.h"
#include "uuid.h"
#include "sipe.h"

/* Keep in sync with sipe_transport_type! */
static const char *transport_descriptor[] = { "", "tls", "tcp"};
#define TRANSPORT_DESCRIPTOR (transport_descriptor[SIP_TO_CORE_PRIVATE->transport->type])

static char *genbranch()
{
	return g_strdup_printf("z9hG4bK%04X%04X%04X%04X%04X",
		rand() & 0xFFFF, rand() & 0xFFFF, rand() & 0xFFFF,
		rand() & 0xFFFF, rand() & 0xFFFF);
}

static void sign_outgoing_message (struct sipmsg * msg, struct sipe_account_data *sip, const gchar *method)
{
	struct sipe_core_private *sipe_private = SIP_TO_CORE_PRIVATE;
	gchar * buf;

	if (sip->registrar.type == AUTH_TYPE_UNSET) {
		return;
	}

	sipe_make_signature(sip, msg);

	if (sip->registrar.type && sipe_strequal(method, "REGISTER")) {
		buf = auth_header(sip, &sip->registrar, msg);
		if (buf) {
			sipmsg_add_header_now_pos(msg, "Authorization", buf, 5);
		}
		g_free(buf);
	} else if (sipe_strequal(method,"SUBSCRIBE") || sipe_strequal(method,"SERVICE") || sipe_strequal(method,"MESSAGE") || sipe_strequal(method,"INVITE") || sipe_strequal(method, "ACK") || sipe_strequal(method, "NOTIFY") || sipe_strequal(method, "BYE") || sipe_strequal(method, "INFO") || sipe_strequal(method, "OPTIONS") || sipe_strequal(method, "REFER") || sipe_strequal(method, "PRACK")) {
		sip->registrar.nc = 3;
		sip->registrar.type = AUTH_TYPE_NTLM;
#ifdef HAVE_LIBKRB5
		if (SIPE_CORE_PUBLIC_FLAG_IS(KRB5)) {
			sip->registrar.type = AUTH_TYPE_KERBEROS;
		}
#else
		/* that's why I don't like macros. It's unobvious what's hidden there */
		(void)sipe_private;
#endif


		buf = auth_header(sip, &sip->registrar, msg);
		sipmsg_add_header_now_pos(msg, "Authorization", buf, 5);
	        g_free(buf);
	} else {
		SIPE_DEBUG_INFO("not adding auth header to msg w/ method %s", method);
	}
}

void send_sip_response(struct sipe_core_private *sipe_private,
		       struct sipmsg *msg, int code,
		       const char *text, const char *body)
{
	gchar *name;
	gchar *value;
	GString *outstr = g_string_new("");
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	gchar *contact;
	GSList *tmp;
	const gchar *keepers[] = { "To", "From", "Call-ID", "CSeq", "Via", "Record-Route", NULL };

	/* Can return NULL! */
	contact = get_contact(sip);
	if (contact) {
		sipmsg_add_header(msg, "Contact", contact);
		g_free(contact);
	}

	if (body) {
		gchar *len = g_strdup_printf("%" G_GSIZE_FORMAT , (gsize) strlen(body));
		sipmsg_add_header(msg, "Content-Length", len);
		g_free(len);
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
		name = ((struct sipnameval*) (tmp->data))->name;
		value = ((struct sipnameval*) (tmp->data))->value;

		g_string_append_printf(outstr, "%s: %s\r\n", name, value);
		tmp = g_slist_next(tmp);
	}
	g_string_append_printf(outstr, "\r\n%s", body ? body : "");
	sipe_backend_transport_message(sip->private->transport, outstr->str);
	g_string_free(outstr, TRUE);
}

void transactions_remove(struct sipe_core_private *sipe_private,
			 struct transaction *trans)
{
	if (sipe_private->transactions) {
		sipe_private->transactions = g_slist_remove(sipe_private->transactions,
							    trans);
		SIPE_DEBUG_INFO("SIP transactions count:%d after removal", g_slist_length(sipe_private->transactions));

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
transactions_add_buf(struct sipe_core_private *sipe_private,
		     const struct sipmsg *msg, void *callback)
{
	const gchar *call_id;
	const gchar *cseq;
	struct transaction *trans = g_new0(struct transaction, 1);

	trans->time = time(NULL);
	trans->msg = (struct sipmsg *)msg;
	call_id = sipmsg_find_header(trans->msg, "Call-ID");
	cseq = sipmsg_find_header(trans->msg, "CSeq");
	trans->key = g_strdup_printf("<%s><%s>", call_id, cseq);
	trans->callback = callback;
	sipe_private->transactions = g_slist_append(sipe_private->transactions,
						    trans);
	SIPE_DEBUG_INFO("SIP transactions count:%d after addition", g_slist_length(sipe_private->transactions));
	return trans;
}

struct transaction *transactions_find(struct sipe_core_private *sipe_private,
				      struct sipmsg *msg)
{
	struct transaction *trans;
	GSList *transactions = sipe_private->transactions;
	const gchar *call_id = sipmsg_find_header(msg, "Call-ID");
	const gchar *cseq = sipmsg_find_header(msg, "CSeq");
	gchar *key;

	if (!call_id || !cseq) {
		SIPE_DEBUG_ERROR_NOFORMAT("transaction_find: no Call-ID or CSeq!");
		return NULL;
	}

	key = g_strdup_printf("<%s><%s>", call_id, cseq);
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

const gchar *
sipe_get_useragent(struct sipe_core_private *sipe_private)
{
	if (!sipe_private->useragent) {
		const gchar *useragent = sipe_backend_setting(SIPE_CORE_PUBLIC,
							      SIPE_SETTING_USER_AGENT);
		if (is_empty(useragent)) {
/*@TODO: better approach to define _user_ OS, it's version and host architecture */
/* ref: lzodefs.h */
#if defined(__linux__) || defined(__linux) || defined(__LINUX__)
  #define SIPE_TARGET_PLATFORM "linux"
#elif defined(__NetBSD__) ||defined( __OpenBSD__) || defined(__FreeBSD__)
  #define SIPE_TARGET_PLATFORM "bsd"
#elif defined(__APPLE__) || defined(__MACOS__)
  #define SIPE_TARGET_PLATFORM "macosx"
#elif defined(_AIX) || defined(__AIX__) || defined(__aix__)
  #define SIPE_TARGET_PLATFORM "aix"
#elif defined(__solaris__) || defined(__sun)
  #define SIPE_TARGET_PLATFORM "sun"
#elif defined(_WIN32)
  #define SIPE_TARGET_PLATFORM "win"
#elif defined(__CYGWIN__)
  #define SIPE_TARGET_PLATFORM "cygwin"
#elif defined(__hpux__)
  #define SIPE_TARGET_PLATFORM "hpux"
#elif defined(__sgi__)
  #define SIPE_TARGET_PLATFORM "irix"
#else
  #define SIPE_TARGET_PLATFORM "unknown"
#endif

#if defined(__amd64__) || defined(__x86_64__) || defined(_M_AMD64)
  #define SIPE_TARGET_ARCH "x86_64"
#elif defined(__386__) || defined(__i386__) || defined(__i386) || defined(_M_IX86) || defined(_M_I386)
  #define SIPE_TARGET_ARCH "i386"
#elif defined(__ppc64__)
  #define SIPE_TARGET_ARCH "ppc64"
#elif defined(__powerpc__) || defined(__powerpc) || defined(__ppc__) || defined(__PPC__) || defined(_M_PPC) || defined(_ARCH_PPC) || defined(_ARCH_PWR)
  #define SIPE_TARGET_ARCH "ppc"
#elif defined(__hppa__) || defined(__hppa)
  #define SIPE_TARGET_ARCH "hppa"
#elif defined(__mips__) || defined(__mips) || defined(_MIPS_ARCH) || defined(_M_MRX000)
  #define SIPE_TARGET_ARCH "mips"
#elif defined(__s390__) || defined(__s390) || defined(__s390x__) || defined(__s390x)
  #define SIPE_TARGET_ARCH "s390"
#elif defined(__sparc__) || defined(__sparc) || defined(__sparcv8)
  #define SIPE_TARGET_ARCH "sparc"
#elif defined(__arm__)
  #define SIPE_TARGET_ARCH "arm"
#else
  #define SIPE_TARGET_ARCH "other"
#endif
			gchar *backend = sipe_backend_version();
			sipe_private->useragent = g_strdup_printf("%s Sipe/" PACKAGE_VERSION " (" SIPE_TARGET_PLATFORM "-" SIPE_TARGET_ARCH "; %s)",
								  backend,
								  sipe_private->server_version ? sipe_private->server_version : "");
			g_free(backend);
		} else {
			sipe_private->useragent = g_strdup(useragent);
		}
	}
	return(sipe_private->useragent);
}

struct transaction *
send_sip_request(struct sipe_core_private *sipe_private, const gchar *method,
		 const gchar *url, const gchar *to, const gchar *addheaders,
		 const gchar *body, struct sip_dialog *dialog,
		 TransCallback tc)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
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

	if (sipe_strequal(method, "REGISTER")) {
		if (sip->regcallid) {
			g_free(callid);
			callid = g_strdup(sip->regcallid);
		} else {
			sip->regcallid = g_strdup(callid);
		}
		cseq = ++sip->cseq;
	}

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
			sipe_backend_network_ip_address(),
			sipe_private->transport->client_port,
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
			sipe_get_useragent(sipe_private),
			callid,
			route,
			addheaders ? addheaders : "",
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
	if (!sipe_strequal(method, "ACK")) {
		trans = transactions_add_buf(sipe_private, msg, tc);
	} else {
		sipmsg_free(msg);
	}
	sipe_backend_transport_message(sipe_private->transport, buf);
	g_free(buf);

	return trans;
}

void do_register_exp(struct sipe_account_data *sip, int expire)
{
	char *uri;
	char *expires;
	char *to;
	char *hdr;
	char *epid;
	char *uuid;

	if (!SIP_TO_CORE_PUBLIC->sip_domain) return;

	expires = expire >= 0 ? g_strdup_printf("Expires: %d\r\n", expire) : g_strdup("");
	epid = get_epid(sip);
	uuid = generateUUIDfromEPID(epid);
	hdr = g_strdup_printf("Contact: <sip:%s:%d;transport=%s;ms-opaque=d3470f2e1d>;methods=\"INVITE, MESSAGE, INFO, SUBSCRIBE, OPTIONS, BYE, CANCEL, NOTIFY, ACK, REFER, BENOTIFY\";proxy=replace;+sip.instance=\"<urn:uuid:%s>\"\r\n"
				    "Supported: gruu-10, adhoclist, msrtc-event-categories, com.microsoft.msrtc.presence\r\n"
				    "Event: registration\r\n"
				    "Allow-Events: presence\r\n"
				    "ms-keep-alive: UAC;hop-hop=yes\r\n"
				    "%s",
			      sipe_backend_network_ip_address(),
			      SIP_TO_CORE_PRIVATE->transport->client_port,
			      TRANSPORT_DESCRIPTOR,
			      uuid,
			      expires);
	g_free(uuid);
	g_free(epid);
	g_free(expires);

	sip->registerstatus = 1;

	uri = sip_uri_from_name(SIP_TO_CORE_PUBLIC->sip_domain);
	to = sip_uri_self(sip);
	send_sip_request(SIP_TO_CORE_PRIVATE, "REGISTER", uri, to, hdr, "", NULL,
			 process_register_response);
	g_free(to);
	g_free(uri);
	g_free(hdr);
}

void do_register_cb(struct sipe_core_private *sipe_private,
			   SIPE_UNUSED_PARAMETER void *unused)
{
	struct sipe_account_data *sip = sipe_private->temporary;
	do_register_exp(sip, -1);
	sip->reregister_set = FALSE;
}

void do_register(struct sipe_account_data *sip)
{
	do_register_exp(sip, -1);
}

static void sip_transport_input(struct sipe_transport_connection *conn)
{
	struct sipe_core_private *sipe_private = conn->user_data;
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	gchar *cur = conn->buffer;

	/* according to the RFC remove CRLF at the beginning */
	while (*cur == '\r' || *cur == '\n') {
		cur++;
	}
	if (cur != conn->buffer)
		sipe_utils_shrink_buffer(conn, cur);

	/* Received a full Header? */
	sip->processing_input = TRUE;
	while (sip->processing_input &&
	       ((cur = strstr(conn->buffer, "\r\n\r\n")) != NULL)) {
		struct sipmsg *msg;
		gchar *tmp;
		guint remainder;
		time_t currtime = time(NULL);
		cur += 2;
		cur[0] = '\0';
		SIPE_DEBUG_INFO("received - %s######\n%s\n#######", ctime(&currtime), tmp = fix_newlines(conn->buffer));
		g_free(tmp);
		msg = sipmsg_parse_header(conn->buffer);
		cur[0] = '\r';
		cur += 2;
		remainder = conn->buffer_used - (cur - conn->buffer);
		if (msg && remainder >= (guint) msg->bodylen) {
			char *dummy = g_malloc(msg->bodylen + 1);
			memcpy(dummy, cur, msg->bodylen);
			dummy[msg->bodylen] = '\0';
			msg->body = dummy;
			cur += msg->bodylen;
			sipe_utils_shrink_buffer(conn, cur);
		} else {
			if (msg){
				SIPE_DEBUG_INFO("process_input: body too short (%d < %d, strlen %d) - ignoring message", remainder, msg->bodylen, (int)strlen(conn->buffer));
				sipmsg_free(msg);
                        }
			return;
		}

		/*if (msg->body) {
			SIPE_DEBUG_INFO("body:\n%s", msg->body);
		}*/

		// Verify the signature before processing it
		if (sip->registrar.gssapi_context) {
			struct sipmsg_breakdown msgbd;
			gchar *signature_input_str;
			gchar *rspauth;
			msgbd.msg = msg;
			sipmsg_breakdown_parse(&msgbd, sip->registrar.realm, sip->registrar.target);
			signature_input_str = sipmsg_breakdown_get_string(sip->registrar.version, &msgbd);

			rspauth = sipmsg_find_part_of_header(sipmsg_find_header(msg, "Authentication-Info"), "rspauth=\"", "\"", NULL);

			if (rspauth != NULL) {
				if (!sip_sec_verify_signature(sip->registrar.gssapi_context, signature_input_str, rspauth)) {
					SIPE_DEBUG_INFO_NOFORMAT("incoming message's signature validated");
					process_input_message(sip, msg);
				} else {
					SIPE_DEBUG_INFO_NOFORMAT("incoming message's signature is invalid.");
					sipe_backend_connection_error(SIP_TO_CORE_PUBLIC,
								      SIPE_CONNECTION_ERROR_NETWORK,
								      _("Invalid message signature received"));
				}
			} else if (msg->response == 401) {
					sipe_backend_connection_error(SIP_TO_CORE_PUBLIC,
								      SIPE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
								      _("Authentication failed"));
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

void sip_transport_default_contact(struct sipe_core_private *sipe_private)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;

	sip->contact = g_strdup_printf("<sip:%s:%d;maddr=%s;transport=%s>;proxy=replace",
				       sip->username,
				       sipe_private->transport->client_port,
				       sipe_backend_network_ip_address(),
				       TRANSPORT_DESCRIPTOR);
}

static void sip_transport_connected(struct sipe_transport_connection *conn)
{
	struct sipe_core_private *sipe_private = conn->user_data;
	sipe_private->service_data = NULL;
	do_register(SIPE_ACCOUNT_DATA_PRIVATE);
}

static void resolve_next_service(struct sipe_core_private *sipe_private,
				 const struct sipe_service_data *start);
static void sip_transport_error(struct sipe_transport_connection *conn,
				const gchar *msg)
{
	struct sipe_core_private *sipe_private = conn->user_data;

	/* This failed attempt was based on a DNS SRV record */
	if (sipe_private->service_data) {
		resolve_next_service(sipe_private, NULL);
	} else {
		sipe_backend_connection_error(SIPE_CORE_PUBLIC, 
					      SIPE_CONNECTION_ERROR_NETWORK,
					      msg);
	}
	sipe_backend_transport_disconnect(conn);
	sipe_private->transport = NULL;
}

/* server_name must be g_alloc()'ed */
void sipe_server_register(struct sipe_core_private *sipe_private,
				 guint type,
				 gchar *server_name,
				 guint server_port)
{
	sipe_connect_setup setup = {
		type,
		server_name,
		(server_port != 0)           ? server_port :
		(type == SIPE_TRANSPORT_TLS) ? 5061 : 5060,
		sipe_private,
		sip_transport_connected,
		sip_transport_input,
		sip_transport_error
	};

	sipe_private->server_name = server_name;
	sipe_private->server_port = setup.server_port;
	sipe_private->transport   = sipe_backend_transport_connect(SIPE_CORE_PUBLIC,
								   &setup);
}

struct sipe_service_data {
	const char *protocol;
	const char *transport;
	guint type;
};

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

static const struct sipe_service_data *services[] = {
	service_autodetect, /* SIPE_TRANSPORT_AUTO */
	service_tls,        /* SIPE_TRANSPORT_TLS  */
	service_tcp         /* SIPE_TRANSPORT_TCP  */
};

static void resolve_next_service(struct sipe_core_private *sipe_private,
				 const struct sipe_service_data *start)
{
	if (start) {
		sipe_private->service_data = start;
	} else {
		sipe_private->service_data++;
		if (sipe_private->service_data->protocol == NULL) {
			guint type = sipe_private->transport_type;

			/* We tried all services */
			sipe_private->service_data = NULL;

			/* Try connecting to the SIP hostname directly */
			SIPE_DEBUG_INFO_NOFORMAT("no SRV records found; using SIP domain as fallback");
			if (type == SIPE_TRANSPORT_AUTO)
				type = SIPE_TRANSPORT_TLS;

			sipe_server_register(sipe_private, type,
					     g_strdup(sipe_private->public.sip_domain),
					     0);
			return;
		}
	}

	/* Try to resolve next service */
	sipe_backend_dns_query(SIPE_CORE_PUBLIC,
			       sipe_private->service_data->protocol,
			       sipe_private->service_data->transport,
			       sipe_private->public.sip_domain);
}

void sipe_core_dns_resolved(struct sipe_core_public *sipe_public,
			    const gchar *hostname, guint port)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	SIPE_DEBUG_INFO("sipe_core_dns_resolved - SRV hostname: %s port: %d",
			hostname, port);
	sipe_server_register(sipe_private,
			     sipe_private->service_data->type,
			     g_strdup(hostname), port);
}

void sipe_core_dns_resolve_failure(struct sipe_core_public *sipe_public)
{
	resolve_next_service(SIPE_CORE_PRIVATE, NULL);
}

void sipe_core_transport_sip_connect(struct sipe_core_public *sipe_public,
				     guint transport,
				     const gchar *server,
				     const gchar *port)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;

	if (server) {
		/* Use user specified server[:port] */
		int port_number = 0;

		if (port)
			port_number = atoi(port);

		SIPE_DEBUG_INFO("sipe_core_connect: user specified SIP server %s:%d",
				server, port_number);

		sipe_server_register(sipe_private, transport,
				     g_strdup(server), port_number);
	} else {
		/* Server auto-discovery */

		/* Remember user specified transport type */
		sipe_private->transport_type = transport;
		resolve_next_service(sipe_private, services[transport]);
	}
}

void sipe_core_transport_sip_keepalive(struct sipe_core_public *sipe_public)
{
	SIPE_DEBUG_INFO("sending keep alive %d",
			sipe_public->keepalive_timeout);
	sipe_backend_transport_message(SIPE_CORE_PRIVATE->transport,
				       "\r\n\r\n");
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
