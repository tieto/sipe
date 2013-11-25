/**
 * @file sip-transport.c
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
 * It's all irrelevant to higher layer responsibilities.
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <glib.h>

#include "sipe-common.h"
#include "sipmsg.h"
#include "sip-sec.h"
#include "sip-sec-digest.h"
#include "sip-transport.h"
#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-certificate.h"
#include "sipe-dialog.h"
#include "sipe-incoming.h"
#include "sipe-nls.h"
#include "sipe-notify.h"
#include "sipe-schedule.h"
#include "sipe-sign.h"
#include "sipe-subscriptions.h"
#include "sipe-utils.h"

struct sip_auth {
	guint type;
	struct sip_sec_context *gssapi_context;
	gchar *gssapi_data;
	gchar *opaque;
	const gchar *protocol;
	gchar *realm;
	gchar *sts_uri;
	gchar *target;
	guint version;
	guint retries;
	guint ntlm_num;
	guint expires;
};

/* sip-transport.c private data */
struct sip_transport {
	struct sipe_transport_connection *connection;

	gchar *server_name;
	guint  server_port;
	gchar *server_version;

	gchar *user_agent;

	GSList *transactions;

	struct sip_auth registrar;
	struct sip_auth proxy;

	guint cseq;
	guint register_attempt;

	guint keepalive_timeout;
	time_t last_message;

	gboolean processing_input;   /* whether full header received */
	gboolean auth_incomplete;    /* whether authentication not completed */
	gboolean reregister_set;     /* whether reregister timer set */
	gboolean reauthenticate_set; /* whether reauthenticate timer set */
	gboolean subscribed;         /* whether subscribed to events, except buddies presence */
	gboolean deregister;         /* whether in deregistration */
};

/* Keep in sync with sipe_transport_type! */
static const char *transport_descriptor[] = { "", "tls", "tcp"};
#define TRANSPORT_DESCRIPTOR (transport_descriptor[transport->connection->type])

static char *genbranch()
{
	return g_strdup_printf("z9hG4bK%04X%04X%04X%04X%04X",
		rand() & 0xFFFF, rand() & 0xFFFF, rand() & 0xFFFF,
		rand() & 0xFFFF, rand() & 0xFFFF);
}

static void sipe_auth_free(struct sip_auth *auth)
{
	g_free(auth->opaque);
	auth->opaque = NULL;
	auth->protocol = NULL;
	g_free(auth->realm);
	auth->realm = NULL;
	g_free(auth->sts_uri);
	auth->sts_uri = NULL;
	g_free(auth->target);
	auth->target = NULL;
	auth->version = 0;
	auth->type = SIPE_AUTHENTICATION_TYPE_UNSET;
	auth->retries = 0;
	auth->expires = 0;
	g_free(auth->gssapi_data);
	auth->gssapi_data = NULL;
	sip_sec_destroy_context(auth->gssapi_context);
	auth->gssapi_context = NULL;
}

static void sipe_make_signature(struct sipe_core_private *sipe_private,
				struct sipmsg *msg)
{
	struct sip_transport *transport = sipe_private->transport;
	if (sip_sec_context_is_ready(transport->registrar.gssapi_context)) {
		struct sipmsg_breakdown msgbd;
		gchar *signature_input_str;
		msgbd.msg = msg;
		sipmsg_breakdown_parse(&msgbd, transport->registrar.realm, transport->registrar.target,
				       transport->registrar.protocol);
		msgbd.rand = g_strdup_printf("%08x", g_random_int());
		transport->registrar.ntlm_num++;
		msgbd.num = g_strdup_printf("%d", transport->registrar.ntlm_num);
		signature_input_str = sipmsg_breakdown_get_string(transport->registrar.version, &msgbd);
		if (signature_input_str != NULL) {
			char *signature_hex = sip_sec_make_signature(transport->registrar.gssapi_context, signature_input_str);
			msg->signature = signature_hex;
			msg->rand = g_strdup(msgbd.rand);
			msg->num = g_strdup(msgbd.num);
			g_free(signature_input_str);
		}
		sipmsg_breakdown_free(&msgbd);
	}
}

static const gchar *const auth_type_to_protocol[] = {
	NULL,       /* SIPE_AUTHENTICATION_TYPE_UNSET     */
	NULL,       /* SIPE_AUTHENTICATION_TYPE_BASIC     */
	"NTLM",     /* SIPE_AUTHENTICATION_TYPE_NTLM      */
	"Kerberos", /* SIPE_AUTHENTICATION_TYPE_KERBEROS  */
	NULL,       /* SIPE_AUTHENTICATION_TYPE_NEGOTIATE */
	"TLS-DSK",  /* SIPE_AUTHENTICATION_TYPE_TLS_DSK   */
};
#define AUTH_PROTOCOLS (sizeof(auth_type_to_protocol)/sizeof(gchar *))

static gchar *msg_signature_to_auth(struct sip_auth *auth,
				    struct sipmsg *msg)
{
	return(g_strdup_printf("%s qop=\"auth\", opaque=\"%s\", realm=\"%s\", targetname=\"%s\", crand=\"%s\", cnum=\"%s\", response=\"%s\"",
			       auth->protocol,
			       auth->opaque, auth->realm, auth->target,
			       msg->rand, msg->num, msg->signature));
}

static gchar *initialize_auth_context(struct sipe_core_private *sipe_private,
				      struct sip_auth *auth,
				      struct sipmsg *msg)
{
	struct sip_transport *transport = sipe_private->transport;
	gchar *ret;
	gchar *gssapi_data = NULL;
	gchar *sign_str;
	gchar *gssapi_str;
	gchar *opaque_str;
	gchar *version_str;

	/*
	 * If transport is de-registering when we reach this point then we
	 * are in the middle of the previous authentication context setup
	 * attempt. So we shouldn't try another attempt.
	 */
	if (transport->deregister)
		return NULL;

	/* Create security context or handshake continuation? */
	if (auth->gssapi_context) {
		/* Perform next step in authentication handshake */
		gboolean status = sip_sec_init_context_step(auth->gssapi_context,
							    auth->target,
							    auth->gssapi_data,
							    &gssapi_data,
							    &auth->expires);

		/* If authentication is completed gssapi_data can be NULL */
		if (!(status &&
		      (sip_sec_context_is_ready(auth->gssapi_context) || gssapi_data))) {
			SIPE_DEBUG_ERROR_NOFORMAT("initialize_auth_context: security context continuation failed");
			g_free(gssapi_data);
			sipe_backend_connection_error(SIPE_CORE_PUBLIC,
						      SIPE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
						      _("Failed to authenticate to server"));
			return NULL;
		}

	} else {
		/* Create security context */
		gpointer password = sipe_private->password;

		/* For TLS-DSK the "password" is a certificate */
		if (auth->type == SIPE_AUTHENTICATION_TYPE_TLS_DSK) {
			password = sipe_certificate_tls_dsk_find(sipe_private,
								 auth->target);

			if (!password) {
				if (auth->sts_uri) {
					SIPE_DEBUG_INFO("initialize_auth_context: TLS-DSK Certificate Provisioning URI %s",
							auth->sts_uri);
					if (!sipe_certificate_tls_dsk_generate(sipe_private,
									       auth->target,
									       auth->sts_uri)) {
						gchar *tmp = g_strdup_printf(_("Can't request certificate from %s"),
									     auth->sts_uri);
						sipe_backend_connection_error(SIPE_CORE_PUBLIC,
									      SIPE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
									      tmp);
						g_free(tmp);
					}
				} else {
					sipe_backend_connection_error(SIPE_CORE_PUBLIC,
								      SIPE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
								      _("No URI for certificate provisioning service provided"));
				}

				/* we can't authenticate the message yet */
				transport->auth_incomplete = TRUE;

				return(NULL);
			} else {
				SIPE_DEBUG_INFO("initialize_auth_context: TLS-DSK certificate for target '%s' found.",
						auth->target);
			}
		}

		auth->gssapi_context = sip_sec_create_context(auth->type,
							      SIPE_CORE_PRIVATE_FLAG_IS(SSO),
							      FALSE, /* connection-less for SIP */
							      sipe_private->authdomain ? sipe_private->authdomain : "",
							      sipe_private->authuser,
							      password);

		if (auth->gssapi_context) {
			sip_sec_init_context_step(auth->gssapi_context,
						  auth->target,
						  NULL,
						  &gssapi_data,
						  &(auth->expires));
		}

		if (!gssapi_data || !auth->gssapi_context) {
			g_free(gssapi_data);
			sipe_backend_connection_error(SIPE_CORE_PUBLIC,
						      SIPE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
						      _("Failed to authenticate to server"));
			return NULL;
		}
	}

	if ((auth->version > 3) &&
	    sip_sec_context_is_ready(auth->gssapi_context)) {
		sipe_make_signature(sipe_private, msg);
		sign_str = g_strdup_printf(", crand=\"%s\", cnum=\"%s\", response=\"%s\"",
					   msg->rand, msg->num, msg->signature);
	} else {
		sign_str = g_strdup("");
	}

	if (gssapi_data) {
		gssapi_str = g_strdup_printf(", gssapi-data=\"%s\"",
					     gssapi_data);
		g_free(gssapi_data);
	} else {
		gssapi_str = g_strdup("");
	}

	opaque_str = auth->opaque ? g_strdup_printf(", opaque=\"%s\"", auth->opaque) : g_strdup("");

	if (auth->version > 2) {
		version_str = g_strdup_printf(", version=%d", auth->version);
	} else {
		version_str = g_strdup("");
	}

	ret = g_strdup_printf("%s qop=\"auth\"%s, realm=\"%s\", targetname=\"%s\"%s%s%s",
			      auth->protocol, opaque_str,
			      auth->realm, auth->target,
			      gssapi_str, version_str, sign_str);
	g_free(version_str);
	g_free(opaque_str);
	g_free(gssapi_str);
	g_free(sign_str);

	return(ret);
}

static gchar *auth_header(struct sipe_core_private *sipe_private,
			  struct sip_auth *auth,
			  struct sipmsg *msg)
{
	gchar *ret = NULL;

	/*
	 * If the message is already signed then we have an authentication
	 * context, i.e. the authentication handshake is complete. Generate
	 * authentication header from message signature.
	 */
	if (msg->signature) {
		ret = msg_signature_to_auth(auth, msg);

	/*
	 * We should reach this point only when the authentication context
	 * needs to be initialized.
	 */
	} else {
		ret = initialize_auth_context(sipe_private, auth, msg);
	}

	return(ret);
}

static void fill_auth(const gchar *hdr, struct sip_auth *auth)
{
	const gchar *param;

	/* skip authentication identifier */
	hdr = strchr(hdr, ' ');
	if (!hdr) {
		SIPE_DEBUG_ERROR_NOFORMAT("fill_auth: corrupted authentication header");
		return;
	}
	while (*hdr == ' ')
		hdr++;

	/* start of next parameter value */
	while ((param = strchr(hdr, '=')) != NULL) {
		const gchar *end;

		/* parameter value type */
		param++;
		if (*param == '"') {
			/* string: xyz="..."(,) */
			end = strchr(++param, '"');
			if (!end) {
				SIPE_DEBUG_ERROR("fill_auth: corrupted string parameter near '%s'", hdr);
				break;
			}
		} else {
			/* number: xyz=12345(,) */
			end = strchr(param, ',');
			if (!end) {
				/* last parameter */
				end = param + strlen(param);
			}
		}

#if 0
		SIPE_DEBUG_INFO("fill_auth: hdr   '%s'", hdr);
		SIPE_DEBUG_INFO("fill_auth: param '%s'", param);
		SIPE_DEBUG_INFO("fill_auth: end   '%s'", end);
#endif

		/* parameter type */
		if        (g_str_has_prefix(hdr, "gssapi-data=\"")) {
			g_free(auth->gssapi_data);
			auth->gssapi_data = g_strndup(param, end - param);
		} else if (g_str_has_prefix(hdr, "opaque=\"")) {
			g_free(auth->opaque);
			auth->opaque = g_strndup(param, end - param);
		} else if (g_str_has_prefix(hdr, "realm=\"")) {
			g_free(auth->realm);
			auth->realm = g_strndup(param, end - param);
		} else if (g_str_has_prefix(hdr, "sts-uri=\"")) {
			/* Only used with SIPE_AUTHENTICATION_TYPE_TLS_DSK */
			g_free(auth->sts_uri);
			auth->sts_uri = g_strndup(param, end - param);
		} else if (g_str_has_prefix(hdr, "targetname=\"")) {
			g_free(auth->target);
			auth->target = g_strndup(param, end - param);
		} else if (g_str_has_prefix(hdr, "version=")) {
			auth->version = atoi(param);
		}

		/* skip to next parameter */
		while ((*end == '"') || (*end == ',') || (*end == ' '))
			end++;
		hdr = end;
	}

	return;
}

static void sign_outgoing_message(struct sipe_core_private *sipe_private,
				  struct sipmsg *msg)
{
	struct sip_transport *transport = sipe_private->transport;
	gchar *buf;

	if (transport->registrar.type == SIPE_AUTHENTICATION_TYPE_UNSET) {
		return;
	}

	sipe_make_signature(sipe_private, msg);

	buf = auth_header(sipe_private, &transport->registrar, msg);
	if (buf) {
		sipmsg_add_header_now(msg, "Authorization", buf);
		g_free(buf);
	}
}

static const gchar *sip_transport_user_agent(struct sipe_core_private *sipe_private)
{
	struct sip_transport *transport = sipe_private->transport;

	if (!transport->user_agent) {
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
			transport->user_agent = g_strdup_printf("%s Sipe/" PACKAGE_VERSION " (" SIPE_TARGET_PLATFORM "-" SIPE_TARGET_ARCH "; %s)",
								backend,
								transport->server_version ? transport->server_version : "");
			g_free(backend);
		} else {
			transport->user_agent = g_strdup(useragent);
		}
	}
	return(transport->user_agent);
}

/*
 * NOTE: Do *NOT* call sipe_backend_transport_message(...) directly!
 *
 * All SIP messages must pass through this function in order to update
 * the timestamp for keepalive tracking.
 */
static void send_sip_message(struct sip_transport *transport,
			     const gchar *string)
{
	sipe_utils_message_debug("SIP", string, NULL, TRUE);
	transport->last_message = time(NULL);
	sipe_backend_transport_message(transport->connection, string);
}

static void start_keepalive_timer(struct sipe_core_private *sipe_private,
				  guint seconds);
static void keepalive_timeout(struct sipe_core_private *sipe_private,
			      SIPE_UNUSED_PARAMETER gpointer data)
{
	struct sip_transport *transport = sipe_private->transport;
	if (transport) {
		guint since_last = time(NULL) - transport->last_message;
		guint restart    = transport->keepalive_timeout;
		if (since_last >= restart) {
			SIPE_DEBUG_INFO("keepalive_timeout: expired %d", restart);
			send_sip_message(transport, "\r\n\r\n");
		} else {
			/* timeout not reached since last message -> reschedule */
			restart -= since_last;
		}
		start_keepalive_timer(sipe_private, restart);
	}
}

static void start_keepalive_timer(struct sipe_core_private *sipe_private,
				  guint seconds)
{
	sipe_schedule_seconds(sipe_private,
			      "<+keepalive-timeout>",
			      NULL,
			      seconds,
			      keepalive_timeout,
			      NULL);
}

void sip_transport_response(struct sipe_core_private *sipe_private,
			    struct sipmsg *msg,
			    guint code,
			    const char *text,
			    const char *body)
{
	gchar *name;
	gchar *value;
	GString *outstr = g_string_new("");
	gchar *contact;
	GSList *tmp;
	const gchar *keepers[] = { "To", "From", "Call-ID", "CSeq", "Via", "Record-Route", NULL };

	/* Can return NULL! */
	contact = get_contact(sipe_private);
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

	sipmsg_add_header(msg, "User-Agent", sip_transport_user_agent(sipe_private));

	msg->response = code;

	sipmsg_strip_headers(msg, keepers);
	sipmsg_merge_new_headers(msg);
	sign_outgoing_message(sipe_private, msg);

	g_string_append_printf(outstr, "SIP/2.0 %d %s\r\n", code, text);
	tmp = msg->headers;
	while (tmp) {
		name = ((struct sipnameval*) (tmp->data))->name;
		value = ((struct sipnameval*) (tmp->data))->value;

		g_string_append_printf(outstr, "%s: %s\r\n", name, value);
		tmp = g_slist_next(tmp);
	}
	g_string_append_printf(outstr, "\r\n%s", body ? body : "");
	send_sip_message(sipe_private->transport, outstr->str);
	g_string_free(outstr, TRUE);
}

static void transactions_remove(struct sipe_core_private *sipe_private,
				struct transaction *trans)
{
	struct sip_transport *transport = sipe_private->transport;
	if (transport->transactions) {
		transport->transactions = g_slist_remove(transport->transactions,
							 trans);
		SIPE_DEBUG_INFO("SIP transactions count:%d after removal", g_slist_length(transport->transactions));

		if (trans->msg) sipmsg_free(trans->msg);
		if (trans->payload) {
			if (trans->payload->destroy)
				(*trans->payload->destroy)(trans->payload->data);
			g_free(trans->payload);
		}
		g_free(trans->key);
		if (trans->timeout_key) {
			sipe_schedule_cancel(sipe_private, trans->timeout_key);
			g_free(trans->timeout_key);
		}
		g_free(trans);
	}
}

static struct transaction *transactions_find(struct sip_transport *transport,
					     struct sipmsg *msg)
{
	GSList *transactions = transport->transactions;
	const gchar *call_id = sipmsg_find_header(msg, "Call-ID");
	const gchar *cseq = sipmsg_find_header(msg, "CSeq");
	gchar *key;

	if (!call_id || !cseq) {
		SIPE_DEBUG_ERROR_NOFORMAT("transaction_find: no Call-ID or CSeq!");
		return NULL;
	}

	key = g_strdup_printf("<%s><%s>", call_id, cseq);
	while (transactions) {
		struct transaction *trans = transactions->data;
		if (!g_ascii_strcasecmp(trans->key, key)) {
			g_free(key);
			return trans;
		}
		transactions = transactions->next;
	}
	g_free(key);

	return NULL;
}

static void transaction_timeout_cb(struct sipe_core_private *sipe_private,
				   gpointer data)
{
	struct transaction *trans = data;
	(trans->timeout_callback)(sipe_private, trans->msg, trans);
	transactions_remove(sipe_private, trans);
}

struct transaction *sip_transport_request_timeout(struct sipe_core_private *sipe_private,
						  const gchar *method,
						  const gchar *url,
						  const gchar *to,
						  const gchar *addheaders,
						  const gchar *body,
						  struct sip_dialog *dialog,
						  TransCallback callback,
						  guint timeout,
						  TransCallback timeout_callback)
{
	struct sip_transport *transport = sipe_private->transport;
	char *buf;
	struct sipmsg *msg;
	gchar *ourtag    = dialog && dialog->ourtag    ? g_strdup(dialog->ourtag)    : NULL;
	gchar *theirtag  = dialog && dialog->theirtag  ? g_strdup(dialog->theirtag)  : NULL;
	gchar *theirepid = dialog && dialog->theirepid ? g_strdup(dialog->theirepid) : NULL;
	gchar *callid    = dialog && dialog->callid    ? g_strdup(dialog->callid)    : gencallid();
	gchar *branch    = dialog && dialog->callid    ? NULL : genbranch();
	gchar *route     = g_strdup("");
	gchar *epid      = get_epid(sipe_private);
	int cseq         = dialog ? ++dialog->cseq : 1 /* as Call-Id is new in this case */;
	struct transaction *trans = NULL;

	if (dialog && dialog->routes)
	{
		GSList *iter = dialog->routes;

		while(iter)
		{
			char *tmp = route;
			route = g_strdup_printf("%sRoute: %s\r\n", route, (char *)iter->data);
			g_free(tmp);
			iter = g_slist_next(iter);
		}
	}

	if (!ourtag && !dialog) {
		ourtag = gentag();
	}

	if (sipe_strequal(method, "REGISTER")) {
		if (sipe_private->register_callid) {
			g_free(callid);
			callid = g_strdup(sipe_private->register_callid);
		} else {
			sipe_private->register_callid = g_strdup(callid);
		}
		cseq = ++transport->cseq;
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
			sipe_backend_network_ip_address(SIPE_CORE_PUBLIC),
			transport->connection->client_port,
			branch ? ";branch=" : "",
			branch ? branch : "",
			sipe_private->username,
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
			sip_transport_user_agent(sipe_private),
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
	g_free(route);
	g_free(epid);

	sign_outgoing_message(sipe_private, msg);

	/* The authentication scheme is not ready so we can't send the message.
	   This should only happen for REGISTER messages. */
	if (!transport->auth_incomplete) {
		buf = sipmsg_to_string(msg);

		/* add to ongoing transactions */
		/* ACK isn't supposed to be answered ever. So we do not keep transaction for it. */
		if (!sipe_strequal(method, "ACK")) {
			trans = g_new0(struct transaction, 1);
			trans->callback = callback;
			trans->msg = msg;
			trans->key = g_strdup_printf("<%s><%d %s>", callid, cseq, method);
			if (timeout_callback) {
				trans->timeout_callback = timeout_callback;
				trans->timeout_key = g_strdup_printf("<transaction timeout>%s", trans->key);
				sipe_schedule_seconds(sipe_private,
						      trans->timeout_key,
						      trans,
						      timeout,
						      transaction_timeout_cb,
						      NULL);
			}
			transport->transactions = g_slist_append(transport->transactions,
								 trans);
			SIPE_DEBUG_INFO("SIP transactions count:%d after addition", g_slist_length(transport->transactions));
		}

		send_sip_message(transport, buf);
		g_free(buf);
	}

	if (!trans) sipmsg_free(msg);
	g_free(callid);
	return trans;
}

struct transaction *sip_transport_request(struct sipe_core_private *sipe_private,
					  const gchar *method,
					  const gchar *url,
					  const gchar *to,
					  const gchar *addheaders,
					  const gchar *body,
					  struct sip_dialog *dialog,
					  TransCallback callback)
{
	return sip_transport_request_timeout(sipe_private,
					     method,
					     url,
					     to,
					     addheaders,
					     body,
					     dialog,
					     callback,
					     0,
					     NULL);
}

static void sip_transport_simple_request(struct sipe_core_private *sipe_private,
					 const gchar *method,
					 struct sip_dialog *dialog)
{
	sip_transport_request(sipe_private,
			      method,
			      dialog->with,
			      dialog->with,
			      NULL,
			      NULL,
			      dialog,
			      NULL);
}

void sip_transport_ack(struct sipe_core_private *sipe_private,
		       struct sip_dialog *dialog)
{
	sip_transport_simple_request(sipe_private, "ACK", dialog);
}

void sip_transport_bye(struct sipe_core_private *sipe_private,
		       struct sip_dialog *dialog)
{
	sip_transport_simple_request(sipe_private, "BYE", dialog);
}

struct transaction *sip_transport_info(struct sipe_core_private *sipe_private,
				       const gchar *addheaders,
				       const gchar *body,
				       struct sip_dialog *dialog,
				       TransCallback callback)
{
	return sip_transport_request(sipe_private,
				     "INFO",
				     dialog->with,
				     dialog->with,
				     addheaders,
				     body,
				     dialog,
				     callback);
}

struct transaction *sip_transport_invite(struct sipe_core_private *sipe_private,
					  const gchar *addheaders,
					  const gchar *body,
					  struct sip_dialog *dialog,
					  TransCallback callback)
{
	return sip_transport_request(sipe_private,
				     "INVITE",
				     dialog->with,
				     dialog->with,
				     addheaders,
				     body,
				     dialog,
				     callback);
}

struct transaction *sip_transport_service(struct sipe_core_private *sipe_private,
					  const gchar *uri,
					  const gchar *addheaders,
					  const gchar *body,
					  TransCallback callback)
{
	return sip_transport_request(sipe_private,
				     "SERVICE",
				     uri,
				     uri,
				     addheaders,
				     body,
				     NULL,
				     callback);
}

void sip_transport_subscribe(struct sipe_core_private *sipe_private,
			     const gchar *uri,
			     const gchar *addheaders,
			     const gchar *body,
			     struct sip_dialog *dialog,
			     TransCallback callback)
{
	sip_transport_request(sipe_private,
			      "SUBSCRIBE",
			      uri,
			      uri,
			      addheaders,
			      body,
			      dialog,
			      callback);
}

void sip_transport_update(struct sipe_core_private *sipe_private,
			  struct sip_dialog *dialog,
			  TransCallback callback)
{
	sip_transport_request(sipe_private,
			      "UPDATE",
			      dialog->with,
			      dialog->with,
			      NULL,
			      NULL,
			      dialog,
			      callback);
}

static const gchar *get_auth_header(struct sipe_core_private *sipe_private,
				    struct sip_auth *auth,
				    struct sipmsg *msg)
{
	auth->type     = sipe_private->authentication_type;
	auth->protocol = auth_type_to_protocol[auth->type];

	return(sipmsg_find_auth_header(msg, auth->protocol));
}

static void do_register(struct sipe_core_private *sipe_private,
			gboolean deregister);

static void do_reauthenticate_cb(struct sipe_core_private *sipe_private,
				 SIPE_UNUSED_PARAMETER gpointer unused)
{
	struct sip_transport *transport = sipe_private->transport;

	/* register again when security token expires */
	/* we have to start a new authentication as the security token
	 * is almost expired by sending a not signed REGISTER message */
	SIPE_DEBUG_INFO_NOFORMAT("do a full reauthentication");
	sipe_auth_free(&transport->registrar);
	sipe_auth_free(&transport->proxy);
	sipe_schedule_cancel(sipe_private, "<registration>");
	transport->reregister_set = FALSE;
	transport->register_attempt = 0;
	do_register(sipe_private, FALSE);
	transport->reauthenticate_set = FALSE;
}

static void sip_transport_default_contact(struct sipe_core_private *sipe_private)
{
	struct sip_transport *transport = sipe_private->transport;
	sipe_private->contact = g_strdup_printf("<sip:%s:%d;maddr=%s;transport=%s>;proxy=replace",
						sipe_private->username,
						transport->connection->client_port,
						sipe_backend_network_ip_address(SIPE_CORE_PUBLIC),
						TRANSPORT_DESCRIPTOR);
}

static void do_register_cb(struct sipe_core_private *sipe_private,
			   SIPE_UNUSED_PARAMETER void *unused)
{
	do_register(sipe_private, FALSE);
}

static void sip_transport_set_reregister(struct sipe_core_private *sipe_private,
					 int expires)
{
	sipe_schedule_seconds(sipe_private,
			      "<registration>",
			      NULL,
			      expires,
			      do_register_cb,
			      NULL);
}

static void sipe_server_register(struct sipe_core_private *sipe_private,
				 guint type,
				 gchar *server_name,
				 guint server_port);

static gboolean process_register_response(struct sipe_core_private *sipe_private,
					  struct sipmsg *msg,
					  SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	struct sip_transport *transport = sipe_private->transport;
	const gchar *expires_header;
	int expires, i;
        GSList *hdr = msg->headers;
        struct sipnameval *elem;

	expires_header = sipmsg_find_header(msg, "Expires");
	expires = expires_header != NULL ? strtol(expires_header, NULL, 10) : 0;
	SIPE_DEBUG_INFO("process_register_response: got response to REGISTER; expires = %d", expires);

	switch (msg->response) {
		case 200:
			if (expires) {
				const gchar *contact_hdr;
				const gchar *auth_hdr;
				gchar *gruu = NULL;
				gchar *uuid;
				gchar *timeout;
				const gchar *server_hdr = sipmsg_find_header(msg, "Server");

				if (!transport->reregister_set) {
					sip_transport_set_reregister(sipe_private,
								     expires);
					transport->reregister_set = TRUE;
				}

				if (server_hdr && !transport->server_version) {
					transport->server_version = g_strdup(server_hdr);
					g_free(transport->user_agent);
					transport->user_agent = NULL;
				}

				auth_hdr = get_auth_header(sipe_private, &transport->registrar, msg);
				if (auth_hdr) {
					SIPE_DEBUG_INFO("process_register_response: Auth header: %s", auth_hdr);
					fill_auth(auth_hdr, &transport->registrar);
				}

				if (!transport->reauthenticate_set) {
					guint reauth_timeout = transport->registrar.expires;

					SIPE_DEBUG_INFO_NOFORMAT("process_register_response: authentication handshake completed successfully");

					/* Does authentication scheme provide valid expiration time? */
					if (reauth_timeout == 0) {
						SIPE_DEBUG_INFO_NOFORMAT("process_register_response: no expiration time - using default of 8 hours");
						reauth_timeout = 8 * 60 * 60;
					}

					/* schedule reauthentication 5 minutes before expiration */
					if (reauth_timeout > 5 * 60)
						reauth_timeout -= 5 * 60;
					sipe_schedule_seconds(sipe_private,
							      "<+reauthentication>",
							      NULL,
							      reauth_timeout,
							      do_reauthenticate_cb,
							      NULL);
					transport->reauthenticate_set = TRUE;
				}

				sipe_backend_connection_completed(SIPE_CORE_PUBLIC);

				uuid = get_uuid(sipe_private);

				// There can be multiple Contact headers (one per location where the user is logged in) so
				// make sure to only get the one for this uuid
				for (i = 0; (contact_hdr = sipmsg_find_header_instance (msg, "Contact", i)); i++) {
					gchar * valid_contact = sipmsg_find_part_of_header (contact_hdr, uuid, NULL, NULL);
					if (valid_contact) {
						gruu = sipmsg_find_part_of_header(contact_hdr, "gruu=\"", "\"", NULL);
						//SIPE_DEBUG_INFO("process_register_response: got gruu %s from contact hdr w/ right uuid: %s", gruu, contact_hdr);
						g_free(valid_contact);
						break;
					} else {
						//SIPE_DEBUG_INFO("process_register_response: ignoring contact hdr b/c not right uuid: %s", contact_hdr);
					}
				}
				g_free(uuid);

				g_free(sipe_private->contact);
				if(gruu) {
					sipe_private->contact = g_strdup_printf("<%s>", gruu);
					g_free(gruu);
				} else {
					//SIPE_DEBUG_INFO_NOFORMAT("process_register_response: didn't find gruu in a Contact hdr");
					sip_transport_default_contact(sipe_private);
				}
                                SIPE_CORE_PRIVATE_FLAG_UNSET(OCS2007);
				SIPE_CORE_PRIVATE_FLAG_UNSET(REMOTE_USER);
				SIPE_CORE_PRIVATE_FLAG_UNSET(BATCHED_SUPPORT);

                                while(hdr)
                                {
					elem = hdr->data;
					if (sipe_strcase_equal(elem->name, "Supported")) {
						if (sipe_strcase_equal(elem->value, "msrtc-event-categories")) {
							/* We interpret this as OCS2007+ indicator */
							SIPE_CORE_PRIVATE_FLAG_SET(OCS2007);
							SIPE_DEBUG_INFO("Supported: %s (indicates OCS2007+)", elem->value);
						}
						if (sipe_strcase_equal(elem->value, "adhoclist")) {
							SIPE_CORE_PRIVATE_FLAG_SET(BATCHED_SUPPORT);
							SIPE_DEBUG_INFO("Supported: %s", elem->value);
						}
					}
                                        if (sipe_strcase_equal(elem->name, "Allow-Events")){
						gchar **caps = g_strsplit(elem->value,",",0);
						i = 0;
						while (caps[i]) {
							sipe_private->allowed_events =  g_slist_append(sipe_private->allowed_events, g_strdup(caps[i]));
							SIPE_DEBUG_INFO("Allow-Events: %s", caps[i]);
							i++;
						}
						g_strfreev(caps);
                                        }
					if (sipe_strcase_equal(elem->name, "ms-user-logon-data")) {
						if (sipe_strcase_equal(elem->value, "RemoteUser")) {
							SIPE_CORE_PRIVATE_FLAG_SET(REMOTE_USER);
							SIPE_DEBUG_INFO_NOFORMAT("ms-user-logon-data: RemoteUser (connected "
										 "via Edge Server)");
						}
					}
                                        hdr = g_slist_next(hdr);
                                }

				/* rejoin open chats to be able to use them by continue to send messages */
				sipe_backend_chat_rejoin_all(SIPE_CORE_PUBLIC);

				/* subscriptions, done only once */
				if (!transport->subscribed) {
					sipe_subscription_self_events(sipe_private);
					transport->subscribed = TRUE;
				}

				timeout = sipmsg_find_part_of_header(sipmsg_find_header(msg, "ms-keep-alive"),
								     "timeout=", ";", NULL);
				if (timeout != NULL) {
					sscanf(timeout, "%u", &transport->keepalive_timeout);
					SIPE_DEBUG_INFO("process_register_response: server determined keep alive timeout is %u seconds",
							transport->keepalive_timeout);
					g_free(timeout);
				}

				SIPE_DEBUG_INFO("process_register_response: got 200, removing CSeq: %d", transport->cseq);
			}
			break;
		case 301:
			{
				gchar *redirect = parse_from(sipmsg_find_header(msg, "Contact"));

				SIPE_DEBUG_INFO_NOFORMAT("process_register_response: authentication handshake completed successfully (with redirect)");

				if (redirect && (g_ascii_strncasecmp("sip:", redirect, 4) == 0)) {
					gchar **parts = g_strsplit(redirect + 4, ";", 0);
					gchar **tmp;
					gchar *hostname;
					int port = 0;
					guint transport_type = SIPE_TRANSPORT_TLS;
					int i = 1;

					tmp = g_strsplit(parts[0], ":", 0);
					hostname = g_strdup(tmp[0]);
					if (tmp[1]) port = strtoul(tmp[1], NULL, 10);
					g_strfreev(tmp);

					while (parts[i]) {
						tmp = g_strsplit(parts[i], "=", 0);
						if (tmp[1]) {
							if (g_ascii_strcasecmp("transport", tmp[0]) == 0) {
								if (g_ascii_strcasecmp("tcp", tmp[1]) == 0) {
									transport_type = SIPE_TRANSPORT_TCP;
								}
							}
						}
						g_strfreev(tmp);
						i++;
					}
					g_strfreev(parts);

					/* Close old connection */
					sipe_core_connection_cleanup(sipe_private);
					/* transport and sipe_private->transport are invalid after this */

					/* Create new connection */
					sipe_server_register(sipe_private, transport_type, hostname, port);
					/* sipe_private->transport has a new value */
					SIPE_DEBUG_INFO("process_register_response: redirected to host %s port %d transport %d",
							hostname, port, transport_type);
				}
				g_free(redirect);
			}
			break;
		case 401:
		        {
				const char *auth_hdr;

				SIPE_DEBUG_INFO("process_register_response: REGISTER retries %d", transport->registrar.retries);

				if (transport->reauthenticate_set) {
					SIPE_DEBUG_ERROR_NOFORMAT("process_register_response: RE-REGISTER rejected, triggering re-authentication");
					do_reauthenticate_cb(sipe_private, NULL);
					return TRUE;
				}

				if (sip_sec_context_is_ready(transport->registrar.gssapi_context)) {
					SIPE_DEBUG_INFO_NOFORMAT("process_register_response: authentication handshake failed - giving up.");
					sipe_backend_connection_error(SIPE_CORE_PUBLIC,
								      SIPE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
								      _("Authentication failed"));
					return TRUE;
				}

				auth_hdr = get_auth_header(sipe_private, &transport->registrar, msg);
				if (!auth_hdr) {
					sipe_backend_connection_error(SIPE_CORE_PUBLIC,
								      SIPE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE,
								      _("Incompatible authentication scheme chosen"));
					return TRUE;
				}
				SIPE_DEBUG_INFO("process_register_response: Auth header: %s", auth_hdr);
				fill_auth(auth_hdr, &transport->registrar);
				transport->reregister_set = FALSE;
				transport->register_attempt = 0;
				do_register(sipe_private,
					    sipe_backend_connection_is_disconnecting(SIPE_CORE_PUBLIC));
			}
			break;
		case 403:
			{
				gchar *reason;
				gchar *warning;
				sipmsg_parse_warning(msg, &reason);
				reason = reason ? reason : sipmsg_get_ms_diagnostics_public_reason(msg);
				warning = g_strdup_printf(_("You have been rejected by the server: %s"),
							  reason ? reason : _("no reason given"));
				g_free(reason);

				sipe_backend_connection_error(SIPE_CORE_PUBLIC,
							      SIPE_CONNECTION_ERROR_INVALID_SETTINGS,
							      warning);
				g_free(warning);
				return TRUE;
			}
			break;
		case 404:
			{
				const gchar *diagnostics = sipmsg_find_header(msg, "ms-diagnostics");
				gchar *reason = sipmsg_get_ms_diagnostics_reason(msg);
				gchar *warning;
				warning = g_strdup_printf(_("Not found: %s. Please contact your Administrator"),
							  diagnostics ? (reason ? reason : _("no reason given")) :
							  _("SIP is either not enabled for the destination URI or it does not exist"));
				g_free(reason);

				sipe_backend_connection_error(SIPE_CORE_PUBLIC,
							      SIPE_CONNECTION_ERROR_INVALID_USERNAME,
							      warning);
				g_free(warning);
				return TRUE;
			}
			break;
		case 504: /* Server time-out */
			/* first attempt + 5 retries */
			if (transport->register_attempt < 6) {
				SIPE_DEBUG_INFO("process_register_response: RE-REGISTER timeout on attempt %d, retrying later",
						transport->register_attempt);
				sip_transport_set_reregister(sipe_private, 60);
				return TRUE;
			}
			/* FALLTHROUGH */
                case 503:
                        {
				gchar *reason = sipmsg_get_ms_diagnostics_reason(msg);
				gchar *warning;
				warning = g_strdup_printf(_("Service unavailable: %s"), reason ? reason : _("no reason given"));
				g_free(reason);

				sipe_backend_connection_error(SIPE_CORE_PUBLIC,
							      SIPE_CONNECTION_ERROR_NETWORK,
							      warning);
				g_free(warning);
				return TRUE;
			}
			break;
		}
	return TRUE;
}

static gboolean register_response_timeout(struct sipe_core_private *sipe_private,
					  SIPE_UNUSED_PARAMETER struct sipmsg *msg,
					  SIPE_UNUSED_PARAMETER struct transaction *trans)
{
	struct sip_transport *transport = sipe_private->transport;
	if (transport->register_attempt < 6) {
		SIPE_DEBUG_INFO("register_response_timeout: no answer to attempt %d, retrying",
				transport->register_attempt);
		do_register(sipe_private, FALSE);
	} else {
		gchar *warning = g_strdup_printf(_("Service unavailable: %s"), _("no reason given"));
		sipe_backend_connection_error(SIPE_CORE_PUBLIC,
					      SIPE_CONNECTION_ERROR_NETWORK,
					      warning);
		g_free(warning);
	}
	return TRUE;
}

static void do_register(struct sipe_core_private *sipe_private,
			gboolean deregister)
{
	struct sip_transport *transport = sipe_private->transport;
	char *uri;
	char *to;
	char *hdr;
	char *uuid;

	if (!sipe_private->public.sip_domain) return;

	if (!deregister) {
		if (transport->reregister_set) {
			transport->reregister_set = FALSE;
			transport->register_attempt = 1;
		} else {
			transport->register_attempt++;
		}
	}

	transport->deregister      = deregister;
	transport->auth_incomplete = FALSE;

	uuid = get_uuid(sipe_private);
	hdr = g_strdup_printf("Contact: <sip:%s:%d;transport=%s;ms-opaque=d3470f2e1d>;methods=\"INVITE, MESSAGE, INFO, SUBSCRIBE, OPTIONS, BYE, CANCEL, NOTIFY, ACK, REFER, BENOTIFY\";proxy=replace;+sip.instance=\"<urn:uuid:%s>\"\r\n"
				    "Supported: gruu-10, adhoclist, msrtc-event-categories, com.microsoft.msrtc.presence\r\n"
				    "Event: registration\r\n"
				    "Allow-Events: presence\r\n"
				    "ms-keep-alive: UAC;hop-hop=yes\r\n"
				    "%s",
			      sipe_backend_network_ip_address(SIPE_CORE_PUBLIC),
			      transport->connection->client_port,
			      TRANSPORT_DESCRIPTOR,
			      uuid,
			      deregister ? "Expires: 0\r\n" : "");
	g_free(uuid);

	uri = sip_uri_from_name(sipe_private->public.sip_domain);
	to = sip_uri_self(sipe_private);
	sip_transport_request_timeout(sipe_private,
				      "REGISTER",
				      uri,
				      to,
				      hdr,
				      "",
				      NULL,
				      process_register_response,
				      60,
				      deregister ? NULL : register_response_timeout);
	g_free(to);
	g_free(uri);
	g_free(hdr);

	if (deregister) {
		/* Make sure that all messages are pushed to the server
		   before the connection gets shut down */
		SIPE_DEBUG_INFO_NOFORMAT("De-register from server. Flushing outstanding messages.");
		sipe_backend_transport_flush(transport->connection);
	}
}

void sip_transport_deregister(struct sipe_core_private *sipe_private)
{
	do_register(sipe_private, TRUE);
}

void sip_transport_disconnect(struct sipe_core_private *sipe_private)
{
	struct sip_transport *transport = sipe_private->transport;

	/* transport can be NULL during connection setup */
	if (transport) {
		sipe_backend_transport_disconnect(transport->connection);

		sipe_auth_free(&transport->registrar);
		sipe_auth_free(&transport->proxy);

		g_free(transport->server_name);
		g_free(transport->server_version);
		g_free(transport->user_agent);

		while (transport->transactions)
			transactions_remove(sipe_private,
					    transport->transactions->data);

		g_free(transport);
	}

	sipe_private->transport    = NULL;
	sipe_private->service_data = NULL;
	sipe_private->address_data = NULL;

	sipe_schedule_cancel(sipe_private, "<+keepalive-timeout>");

	if (sipe_private->dns_query)
		sipe_backend_dns_query_cancel(sipe_private->dns_query);

}

void sip_transport_authentication_completed(struct sipe_core_private *sipe_private)
{
	do_reauthenticate_cb(sipe_private, NULL);
}

guint sip_transport_port(struct sipe_core_private *sipe_private)
{
	return sipe_private->transport->server_port;
}

static void process_input_message(struct sipe_core_private *sipe_private,
				  struct sipmsg *msg)
{
	struct sip_transport *transport = sipe_private->transport;
	gboolean notfound = FALSE;
	const char *method = msg->method ? msg->method : "NOT FOUND";

	SIPE_DEBUG_INFO("process_input_message: msg->response(%d),msg->method(%s)",
			msg->response, method);

	if (msg->response == 0) { /* request */
		if (sipe_strequal(method, "MESSAGE")) {
			process_incoming_message(sipe_private, msg);
		} else if (sipe_strequal(method, "NOTIFY")) {
			SIPE_DEBUG_INFO_NOFORMAT("send->process_incoming_notify");
			process_incoming_notify(sipe_private, msg);
			sip_transport_response(sipe_private, msg, 200, "OK", NULL);
		} else if (sipe_strequal(method, "BENOTIFY")) {
			SIPE_DEBUG_INFO_NOFORMAT("send->process_incoming_benotify");
			process_incoming_notify(sipe_private, msg);
		} else if (sipe_strequal(method, "INVITE")) {
			process_incoming_invite(sipe_private, msg);
		} else if (sipe_strequal(method, "REFER")) {
			process_incoming_refer(sipe_private, msg);
		} else if (sipe_strequal(method, "OPTIONS")) {
			process_incoming_options(sipe_private, msg);
		} else if (sipe_strequal(method, "INFO")) {
			process_incoming_info(sipe_private, msg);
		} else if (sipe_strequal(method, "ACK")) {
			/* ACK's don't need any response */
		} else if (sipe_strequal(method, "PRACK")) {
			sip_transport_response(sipe_private, msg, 200, "OK", NULL);
		} else if (sipe_strequal(method, "SUBSCRIBE")) {
			/* LCS 2005 sends us these - just respond 200 OK */
			sip_transport_response(sipe_private, msg, 200, "OK", NULL);
		} else if (sipe_strequal(method, "CANCEL")) {
			process_incoming_cancel(sipe_private, msg);
		} else if (sipe_strequal(method, "BYE")) {
			process_incoming_bye(sipe_private, msg);
		} else {
			sip_transport_response(sipe_private, msg, 501, "Not implemented", NULL);
			notfound = TRUE;
		}

	} else { /* response */
		struct transaction *trans = transactions_find(transport, msg);
		if (trans) {
			if (msg->response < 200) {
				/* ignore provisional response */
				SIPE_DEBUG_INFO("process_input_message: got provisional (%d) response, ignoring", msg->response);

				/* Transaction not yet completed */
				trans = NULL;

			} else if (msg->response == 401) { /* Unauthorized */

				if (sipe_strequal(trans->msg->method, "REGISTER")) {
					/* Expected response during authentication handshake */
					transport->registrar.retries++;
					SIPE_DEBUG_INFO("process_input_message: RE-REGISTER CSeq: %d", transport->cseq);
				} else {
					gchar *resend;

					/* Are we registered? */
					if (transport->reregister_set) {
						SIPE_DEBUG_INFO_NOFORMAT("process_input_message: 401 response to non-REGISTER message. Retrying with new authentication.");
						sipmsg_remove_header_now(trans->msg, "Authorization");
						sign_outgoing_message(sipe_private,
								      trans->msg);
					} else {
						/**
						 * We don't have a valid authentication at the moment.
						 * Resend message unchanged. It will be rejected again
						 * and hopefully by then we have a valid authentication.
						 */
						SIPE_DEBUG_INFO_NOFORMAT("process_input_message: 401 response to non-REGISTER message. Bouncing...");
					}

					/* Resend request */
					resend = sipmsg_to_string(trans->msg);
					send_sip_message(sipe_private->transport, resend);
					g_free(resend);

					/* Transaction not yet completed */
					trans = NULL;
				}

			} else if (msg->response == 407) { /* Proxy Authentication Required */

				if (transport->proxy.retries++ <= 30) {
					const gchar *proxy_hdr = sipmsg_find_header(msg, "Proxy-Authenticate");

					if (proxy_hdr) {
						gchar *auth = NULL;

						if (!g_ascii_strncasecmp(proxy_hdr, "Digest", 6)) {
							auth = sip_sec_digest_authorization(sipe_private,
											    proxy_hdr + 7,
											    msg->method,
											    msg->target);
						} else {
							guint i;

							transport->proxy.type = SIPE_AUTHENTICATION_TYPE_UNSET;
							for (i = 0; i < AUTH_PROTOCOLS; i++) {
								const gchar *protocol = auth_type_to_protocol[i];
								if (protocol &&
								    !g_ascii_strncasecmp(proxy_hdr, protocol, strlen(protocol))) {
									SIPE_DEBUG_INFO("process_input_message: proxy authentication scheme '%s'", protocol);
									transport->proxy.type     = i;
									transport->proxy.protocol = protocol;
									fill_auth(proxy_hdr, &transport->proxy);
									auth = auth_header(sipe_private, &transport->proxy, trans->msg);
									break;
								}
							}
						}

						if (auth) {
							gchar *resend;

							/* replace old proxy authentication with new one */
							sipmsg_remove_header_now(trans->msg, "Proxy-Authorization");
							sipmsg_add_header_now(trans->msg, "Proxy-Authorization", auth);
							g_free(auth);

							/* resend request with proxy authentication */
							resend = sipmsg_to_string(trans->msg);
							send_sip_message(sipe_private->transport, resend);
							g_free(resend);

							/* Transaction not yet completed */
							trans = NULL;

						} else
							SIPE_DEBUG_ERROR_NOFORMAT("process_input_message: can't generate proxy authentication. Giving up.");
					} else
						SIPE_DEBUG_ERROR_NOFORMAT("process_input_message: 407 response without 'Proxy-Authenticate' header. Giving up.");
				} else
					SIPE_DEBUG_ERROR_NOFORMAT("process_input_message: too many proxy authentication retries. Giving up.");

			} else {
				transport->registrar.retries = 0;
				transport->proxy.retries = 0;
			}

			/* Is transaction completed? */
			if (trans) {
				if (trans->callback) {
					SIPE_DEBUG_INFO_NOFORMAT("process_input_message: we have a transaction callback");
					/* call the callback to process response */
					(trans->callback)(sipe_private, msg, trans);
					/* transport && trans no longer valid after redirect */
				}

				/*
				 * Redirect case: sipe_private->transport is
				 * the new transport with empty queue
				 */
				if (sipe_private->transport->transactions) {
					SIPE_DEBUG_INFO("process_input_message: removing CSeq %d", transport->cseq);
					transactions_remove(sipe_private, trans);
				}
			}
		} else {
			SIPE_DEBUG_INFO_NOFORMAT("process_input_message: received response to unknown transaction");
			notfound = TRUE;
		}
	}

	if (notfound) {
		SIPE_DEBUG_INFO("received a unknown sip message with method %s and response %d", method, msg->response);
	}
}

static void sip_transport_input(struct sipe_transport_connection *conn)
{
	struct sipe_core_private *sipe_private = conn->user_data;
	struct sip_transport *transport = sipe_private->transport;
	gchar *cur = conn->buffer;

	/* according to the RFC remove CRLF at the beginning */
	while (*cur == '\r' || *cur == '\n') {
		cur++;
	}
	if (cur != conn->buffer)
		sipe_utils_shrink_buffer(conn, cur);

	/* Received a full Header? */
	transport->processing_input = TRUE;
	while (transport->processing_input &&
	       ((cur = strstr(conn->buffer, "\r\n\r\n")) != NULL)) {
		struct sipmsg *msg;
		guint remainder;

		cur += 2;
		cur[0] = '\0';
		msg = sipmsg_parse_header(conn->buffer);

		cur += 2;
		remainder = conn->buffer_used - (cur - conn->buffer);
		if (msg && remainder >= (guint) msg->bodylen) {
			char *dummy = g_malloc(msg->bodylen + 1);
			memcpy(dummy, cur, msg->bodylen);
			dummy[msg->bodylen] = '\0';
			msg->body = dummy;
			cur += msg->bodylen;
			sipe_utils_message_debug("SIP",
						 conn->buffer,
						 msg->body,
						 FALSE);
			sipe_utils_shrink_buffer(conn, cur);
		} else {
			if (msg){
				SIPE_DEBUG_INFO("sipe_transport_input: body too short (%d < %d, strlen %d) - ignoring message", remainder, msg->bodylen, (int)strlen(conn->buffer));
				sipmsg_free(msg);
                        }

			/* restore header for next try */
			cur[-2] = '\r';
			return;
		}

		// Verify the signature before processing it
		if (sip_sec_context_is_ready(transport->registrar.gssapi_context)) {
			struct sipmsg_breakdown msgbd;
			gchar *signature_input_str;
			gchar *rspauth;
			msgbd.msg = msg;
			sipmsg_breakdown_parse(&msgbd, transport->registrar.realm, transport->registrar.target,
					       transport->registrar.protocol);
			signature_input_str = sipmsg_breakdown_get_string(transport->registrar.version, &msgbd);

			rspauth = sipmsg_find_part_of_header(sipmsg_find_header(msg, "Authentication-Info"), "rspauth=\"", "\"", NULL);

			if (rspauth != NULL) {
				if (sip_sec_verify_signature(transport->registrar.gssapi_context, signature_input_str, rspauth)) {
					SIPE_DEBUG_INFO_NOFORMAT("sip_transport_input: signature of incoming message validated");
					process_input_message(sipe_private, msg);
					/* transport is invalid after redirect */
				} else {
					SIPE_DEBUG_INFO_NOFORMAT("sip_transport_input: signature of incoming message is invalid.");
					sipe_backend_connection_error(SIPE_CORE_PUBLIC,
								      SIPE_CONNECTION_ERROR_NETWORK,
								      _("Invalid message signature received"));
				}
			} else if ((msg->response == 401) ||
				   sipe_strequal(msg->method, "REGISTER")) {
				/* a) Retry non-REGISTER requests with updated authentication */
				/* b) We must always process REGISTER responses */
				process_input_message(sipe_private, msg);
			} else {
				/* OCS sends provisional messages that are *not* signed */
				if (msg->response >= 200) {
					/* We are not calling process_input_message(),
					   so we need to drop the transaction here. */
					struct transaction *trans = transactions_find(transport, msg);
					if (trans) transactions_remove(sipe_private, trans);
				}
				SIPE_DEBUG_INFO_NOFORMAT("sip_transport_input: message without authentication data - ignoring");
			}
			g_free(signature_input_str);

			g_free(rspauth);
			sipmsg_breakdown_free(&msgbd);
		} else {
			process_input_message(sipe_private, msg);
		}

		sipmsg_free(msg);

		/* Redirect: old content of "transport" & "conn" is no longer valid */
		transport = sipe_private->transport;
		conn      = transport->connection;
	}
}

static void sip_transport_connected(struct sipe_transport_connection *conn)
{
	struct sipe_core_private *sipe_private = conn->user_data;
	struct sip_transport *transport = sipe_private->transport;

	sipe_private->service_data = NULL;
	sipe_private->address_data = NULL;

	/*
	 * Initial keepalive timeout during REGISTER phase
	 *
	 * NOTE: 60 seconds is a guess. Needs more testing!
	 */
	transport->keepalive_timeout = 60;
	start_keepalive_timer(sipe_private, transport->keepalive_timeout);

	do_register(sipe_private, FALSE);
}

static void resolve_next_service(struct sipe_core_private *sipe_private,
				 const struct sip_service_data *start);
static void resolve_next_address(struct sipe_core_private *sipe_private,
				 gboolean initial);
static void sip_transport_error(struct sipe_transport_connection *conn,
				const gchar *msg)
{
	struct sipe_core_private *sipe_private = conn->user_data;

	/* This failed attempt was based on a DNS SRV record */
	if (sipe_private->service_data) {
		resolve_next_service(sipe_private, NULL);
	/* This failed attempt was based on a DNS A record */
	} else if (sipe_private->address_data) {
		resolve_next_address(sipe_private, FALSE);
	} else {
		sipe_backend_connection_error(SIPE_CORE_PUBLIC,
					      SIPE_CONNECTION_ERROR_NETWORK,
					      msg);
	}
}

/* server_name must be g_alloc()'ed */
static void sipe_server_register(struct sipe_core_private *sipe_private,
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
	struct sip_transport *transport = g_new0(struct sip_transport, 1);

	transport->server_name  = server_name;
	transport->server_port  = setup.server_port;
	transport->connection   = sipe_backend_transport_connect(SIPE_CORE_PUBLIC,
								 &setup);
	sipe_private->transport = transport;
}

struct sip_service_data {
	const char *protocol;
	const char *transport;
	guint type;
};

/*
 * Autodiscover using DNS SRV records. See RFC2782/3263
 *
 * Service list for AUTO
 */
static const struct sip_service_data service_autodetect[] = {
	{ "sipinternaltls", "tcp", SIPE_TRANSPORT_TLS }, /* for internal TLS connections */
	{ "sipinternal",    "tcp", SIPE_TRANSPORT_TCP }, /* for internal TCP connections */
	{ "sip",            "tls", SIPE_TRANSPORT_TLS }, /* for external TLS connections */
	{ "sip",            "tcp", SIPE_TRANSPORT_TCP }, /*.for external TCP connections */
	{ NULL,             NULL,  0 }
};

/* Service list for SSL/TLS */
static const struct sip_service_data service_tls[] = {
	{ "sipinternaltls", "tcp", SIPE_TRANSPORT_TLS }, /* for internal TLS connections */
	{ "sip",            "tls", SIPE_TRANSPORT_TLS }, /* for external TLS connections */
	{ NULL,             NULL,  0 }
};

/* Service list for TCP */
static const struct sip_service_data service_tcp[] = {
	{ "sipinternal",    "tcp", SIPE_TRANSPORT_TCP }, /* for internal TCP connections */
	{ "sip",            "tcp", SIPE_TRANSPORT_TCP }, /*.for external TCP connections */
	{ NULL,             NULL,  0 }
};

static const struct sip_service_data *services[] = {
	service_autodetect, /* SIPE_TRANSPORT_AUTO */
	service_tls,        /* SIPE_TRANSPORT_TLS  */
	service_tcp         /* SIPE_TRANSPORT_TCP  */
};

struct sip_address_data {
	const char *prefix;
	guint port;
};

/*
 * Autodiscover using DNS A records. This is an extension addded
 * by Microsoft. See http://support.microsoft.com/kb/2619522
 */
static const struct sip_address_data addresses[] = {
	{ "sipinternal", 5061 },
	{ "sipexternal",  443 },
/*
 * Our implementation supports only one port per host name. If the host name
 * resolves OK, we abort the search and try to connect. If we would know if we
 * are trying to connect from "Intranet" or "Internet" then we could choose
 * between those two ports.
 *
 * We drop port 5061 in order to cover the "Internet" case.
 *
 *	{ "sip",         5061 },
 */
	{ "sip",          443 },
	{ NULL,             0 }
};

static void sipe_core_dns_resolved(struct sipe_core_public *sipe_public,
				   const gchar *hostname, guint port)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	gboolean service = sipe_private->service_data != NULL;

	sipe_private->dns_query = NULL;

	if (hostname) {
		gchar *host;
		guint type;

		if (service) {
			host = g_strdup(hostname);
			type = sipe_private->service_data->type;
		} else {
			/* DNS A resolver returns an IP address */
			host = g_strdup_printf("%s.%s",
					       sipe_private->address_data->prefix,
					       sipe_private->public.sip_domain);
			port = sipe_private->address_data->port;
			type = sipe_private->transport_type;
			if (type == SIPE_TRANSPORT_AUTO)
				type = SIPE_TRANSPORT_TLS;
		}

		SIPE_DEBUG_INFO("sipe_core_dns_resolved - %s hostname: %s port: %d",
				service ? "SRV" : "A", hostname, port);
		sipe_server_register(sipe_private, type, host, port);
	} else {
		if (service)
			resolve_next_service(SIPE_CORE_PRIVATE, NULL);
		else
			resolve_next_address(SIPE_CORE_PRIVATE, FALSE);
	}
}

static void resolve_next_service(struct sipe_core_private *sipe_private,
				 const struct sip_service_data *start)
{
	if (start) {
		sipe_private->service_data = start;
	} else {
		sipe_private->service_data++;
		if (sipe_private->service_data->protocol == NULL) {

			/* We tried all services */
			sipe_private->service_data = NULL;

			/* Try A records list next */
			SIPE_DEBUG_INFO_NOFORMAT("no SRV records found; trying A records next");
			resolve_next_address(sipe_private, TRUE);
			return;
		}
	}

	/* Try to resolve next service */
	sipe_private->dns_query = sipe_backend_dns_query_srv(
					SIPE_CORE_PUBLIC,
					sipe_private->service_data->protocol,
					sipe_private->service_data->transport,
					sipe_private->public.sip_domain,
					(sipe_dns_resolved_cb) sipe_core_dns_resolved,
					SIPE_CORE_PUBLIC);
}

static void resolve_next_address(struct sipe_core_private *sipe_private,
				 gboolean initial)
{
	gchar *hostname;

	if (initial) {
		sipe_private->address_data = addresses;
	} else {
		sipe_private->address_data++;
		if (sipe_private->address_data->prefix == NULL) {
			guint type = sipe_private->transport_type;

			/* We tried all addresss */
			sipe_private->address_data = NULL;

			/* Try connecting to the SIP hostname directly */
			SIPE_DEBUG_INFO_NOFORMAT("no SRV or A records found; using SIP domain as fallback");
			if (type == SIPE_TRANSPORT_AUTO)
				type = SIPE_TRANSPORT_TLS;

			sipe_server_register(sipe_private, type,
					     g_strdup(sipe_private->public.sip_domain),
					     0);
			return;
		}
	}

	/* Try to resolve next address */
	hostname = g_strdup_printf("%s.%s",
				   sipe_private->address_data->prefix,
				   sipe_private->public.sip_domain);
	sipe_private->dns_query = sipe_backend_dns_query_a(
					SIPE_CORE_PUBLIC,
					hostname,
					sipe_private->address_data->port,
					(sipe_dns_resolved_cb) sipe_core_dns_resolved,
					SIPE_CORE_PUBLIC);
	g_free(hostname);
}

/*
 * NOTE: this function can be called before sipe_core_allocate()!
 */
gboolean sipe_core_transport_sip_requires_password(guint authentication,
						   gboolean sso)
{
	return(sip_sec_requires_password(authentication, sso));
}

void sipe_core_transport_sip_connect(struct sipe_core_public *sipe_public,
				     guint transport,
				     guint authentication,
				     const gchar *server,
				     const gchar *port)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;

	/* backend initialization is complete */
	sipe_core_backend_initialized(sipe_private, authentication);

	/*
	 * Initializing the certificate sub-system will trigger the generation
	 * of a cryptographic key pair which takes time. If we do this after we
	 * have connected to the server then there is a risk that we run into a
	 * SIP connection timeout. So let's get this out of the way now...
	 *
	 * This is currently only needed if the user has selected TLS-DSK.
	 */
	if (sipe_private->authentication_type == SIPE_AUTHENTICATION_TYPE_TLS_DSK)
		sipe_certificate_init(sipe_private);

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

const gchar *sipe_core_transport_sip_server_name(struct sipe_core_public *sipe_public)
{
	struct sip_transport *transport = SIPE_CORE_PRIVATE->transport;
	return(transport ? transport->server_name : NULL);
}

int sip_transaction_cseq(struct transaction *trans)
{
	int cseq;

	g_return_val_if_fail(trans && trans->key, 0);

	sscanf(trans->key, "<%*[a-zA-Z0-9]><%d INVITE>", &cseq);
	return cseq;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
