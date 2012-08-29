/**
 * @file telepathy-connection.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2012 SIPE Project <http://sipe.sourceforge.net/>
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#include <glib-object.h>
#include <telepathy-glib/base-connection.h>
#include <telepathy-glib/base-protocol.h>
#include <telepathy-glib/handle-repo-dynamic.h>
#include <telepathy-glib/simple-password-manager.h>
#include <telepathy-glib/telepathy-glib.h>

#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-core.h"

#include "telepathy-private.h"

G_BEGIN_DECLS
/*
 * Connection class - data structures
 */
typedef struct _SipeConnectionClass {
	TpBaseConnectionClass parent_class;
} SipeConnectionClass;

typedef struct _SipeConnection {
	TpBaseConnection parent;

	TpSimplePasswordManager *password_manager;

	struct sipe_backend_private private;
	gchar *account;
	gchar *login;
	gchar *password;
	gchar *server;
	gchar *port;
	guint  transport;
	gchar *authentication;
	gboolean is_disconnecting;
} SipeConnection;

#define SIPE_PUBLIC_TO_CONNECTION sipe_public->backend_private->connection

/*
 * Connection class - type macros
 */
static GType sipe_connection_get_type(void) G_GNUC_CONST;
#define SIPE_TYPE_CONNECTION \
	(sipe_connection_get_type())
#define SIPE_CONNECTION(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), SIPE_TYPE_CONNECTION, \
				    SipeConnection))
G_END_DECLS

/*
 * Connection class - type definition
 */
G_DEFINE_TYPE(SipeConnection,
	      sipe_connection,
	      TP_TYPE_BASE_CONNECTION)

/*
 * Connection class - instance methods
 */
static gchar *normalize_contact(SIPE_UNUSED_PARAMETER TpHandleRepoIface *repo,
				const gchar *id,
				SIPE_UNUSED_PARAMETER gpointer context,
				GError **error)
{
	return(sipe_telepathy_protocol_normalize_contact(NULL, id, error));
}

static void create_handle_repos(SIPE_UNUSED_PARAMETER TpBaseConnection *conn,
				TpHandleRepoIface *repos[NUM_TP_HANDLE_TYPES])
{
	repos[TP_HANDLE_TYPE_CONTACT] = tp_dynamic_handle_repo_new(TP_HANDLE_TYPE_CONTACT,
								   normalize_contact,
								   NULL);
}

static gboolean connect_to_core(SipeConnection *self,
				GError **error)
{
	gchar *login_domain  = NULL;
	gchar *login_account = NULL;
	struct sipe_core_public *sipe_public;
	const gchar *errmsg;

	/* login name specified? */
	if (self->login && strlen(self->login)) {
		/* Allowed domain-account separators are / or \ */
		gchar **domain_user = g_strsplit_set(self->login, "/\\", 2);
		gboolean has_domain = domain_user[1] != NULL;
		SIPE_DEBUG_INFO("connect_to_core: login '%s'", self->login);
		login_domain  = has_domain ? g_strdup(domain_user[0]) : NULL;
		login_account = g_strdup(domain_user[has_domain ? 1 : 0]);
		SIPE_DEBUG_INFO("connect_to_core: auth domain '%s' user '%s'",
				login_domain ? login_domain : "",
				login_account);
		g_strfreev(domain_user);
	}

	sipe_public = sipe_core_allocate(self->account,
					 login_domain, login_account,
					 self->password,
					 NULL, /* @TODO: email     */
					 NULL, /* @TODO: email_url */
					 &errmsg);
	g_free(login_domain);
	g_free(login_account);

	SIPE_DEBUG_INFO("connect_to_core: created %p", sipe_public);

	if (sipe_public) {
		struct sipe_backend_private *telepathy_private = &self->private;

		/* initialize backend private data */
		sipe_public->backend_private  = telepathy_private;
		telepathy_private->public     = sipe_public;
		telepathy_private->connection = self;
		telepathy_private->transport  = NULL;
		telepathy_private->ipaddress  = NULL;

		/* map option list to flags - default is NTLM */
		SIPE_CORE_FLAG_UNSET(KRB5);
		SIPE_CORE_FLAG_UNSET(TLS_DSK);
#ifdef HAVE_LIBKRB5
		if (sipe_strequal(self->authentication, "krb5")) {
			SIPE_DEBUG_INFO_NOFORMAT("connect_to_core: KRB5 selected");
			SIPE_CORE_FLAG_SET(KRB5);
		} else
#endif
		if (sipe_strequal(self->authentication, "tls-dsk")) {
			SIPE_DEBUG_INFO_NOFORMAT("connect_to_core: TLS-DSK selected");
			SIPE_CORE_FLAG_SET(TLS_DSK);
		}

		/* @TODO: add parameter for SSO */
		SIPE_CORE_FLAG_UNSET(SSO);

		sipe_core_transport_sip_connect(sipe_public,
						self->transport,
						self->server,
						self->port);

		return(TRUE);
	} else {
		g_set_error_literal(error, TP_ERROR, TP_ERROR_INVALID_ARGUMENT,
				    errmsg);
		return(FALSE);
	}
}

static void password_manager_cb(GObject *source,
				GAsyncResult *result,
				gpointer data)
{
	SipeConnection   *self  = data;
	TpBaseConnection *base  = TP_BASE_CONNECTION(self);
	GError *error           = NULL;
	const GString *password = tp_simple_password_manager_prompt_finish(
		TP_SIMPLE_PASSWORD_MANAGER(source),
		result,
		&error);

	if (error) {
		SIPE_DEBUG_ERROR("password_manager_cb: failed: %s",
				 error->message);

		if (base->status != TP_CONNECTION_STATUS_DISCONNECTED) {
			tp_base_connection_disconnect_with_dbus_error(base,
								      tp_error_get_dbus_name(error->code),
								      NULL,
								      TP_CONNECTION_STATUS_REASON_AUTHENTICATION_FAILED);
		}
		g_error_free(error);
	} else {

		g_free(self->password);
		self->password = g_strdup(password->str);

		if (!connect_to_core(self, &error)) {
			if (base->status != TP_CONNECTION_STATUS_DISCONNECTED) {
				tp_base_connection_disconnect_with_dbus_error(base,
									      tp_error_get_dbus_name(error->code),
									      NULL,
									      TP_CONNECTION_STATUS_REASON_AUTHENTICATION_FAILED);
			}
			g_error_free(error);
		}
	}
}

static gboolean start_connecting(TpBaseConnection *base,
				 GError **error)
{
	SipeConnection *self = SIPE_CONNECTION(base);
	gboolean        rc   = TRUE;
	gchar          *uri  = sipe_telepathy_protocol_normalize_contact(NULL,
									 self->account,
									 error);

	SIPE_DEBUG_INFO_NOFORMAT("SipeConnection::start_connecting");

	/* set up mandatory self-handle */
	if (uri) {
		base->self_handle = tp_handle_ensure(tp_base_connection_get_handles(base,
										    TP_HANDLE_TYPE_CONTACT),
						     uri,
						     NULL,
						     error);
		g_free(uri);
		if (!base->self_handle) {
			SIPE_DEBUG_ERROR("SipeConnection::start_connecting: self handle creation failed: %s",
					 (*error)->message);
			return(FALSE);
		}
	} else {
		SIPE_DEBUG_ERROR("SipeConnection::start_connecting: %s",
				 (*error)->message);
		return(FALSE);
	}

	tp_base_connection_change_status(base, TP_CONNECTION_STATUS_CONNECTING,
					 TP_CONNECTION_STATUS_REASON_REQUESTED);

	/* we need a password */
	if (self->password)
		rc = connect_to_core(self, error);
	else {
#if 0
/* this doesn't work. Nobody has a clue why */
		SIPE_DEBUG_INFO("SipeConnection::start_connecting: requesting password from user: %p",
			self->password_manager);
		tp_simple_password_manager_prompt_async(self->password_manager,
							password_manager_cb,
							self);
#else
/* MAJOR HACK */
		gchar *password_file = g_strdup_printf("%s/.sipe-password",
						       g_getenv("HOME"));
		SIPE_DEBUG_INFO("SipeConnection::start_connecting - password file %s",
				password_file);
		rc = FALSE;
		if (g_file_get_contents(password_file,
					&self->password,
					NULL, error)) {
			SIPE_DEBUG_INFO_NOFORMAT("SipeConnection::start_connecting - got password");
			g_strchomp(self->password);
			rc = connect_to_core(self, error);
		} else {
			SIPE_DEBUG_ERROR("SipeConnection::start_connecting: %s",
					 (*error)->message);
		}
		g_free(password_file);

		/* to make compiler happy */
		(void)password_manager_cb;
#endif
	}

	return(rc);
}

static gboolean disconnect_from_core(gpointer data)
{
	TpBaseConnection *base                         = data;
	SipeConnection *self                           = SIPE_CONNECTION(base);
	struct sipe_backend_private *telepathy_private = &self->private;
	struct sipe_core_public *sipe_public           = telepathy_private->public;

	SIPE_DEBUG_INFO("disconnect_from_core: %p", sipe_public);

	if (sipe_public)
		sipe_core_deallocate(sipe_public);
	telepathy_private->public    = NULL;
	telepathy_private->transport = NULL;

	g_free(telepathy_private->ipaddress);
	telepathy_private->ipaddress = NULL;

	SIPE_DEBUG_INFO_NOFORMAT("disconnect_from_core: core deallocated");

	/* now it is OK to destroy the connection object */
	tp_base_connection_finish_shutdown(base);

	return(FALSE);
}

static void shut_down(TpBaseConnection *base)
{
	SIPE_DEBUG_INFO_NOFORMAT("SipeConnection::shut_down");

	/* this can be called synchronously, defer destruction */
	g_idle_add(disconnect_from_core, base);
}

static GPtrArray *create_channel_managers(TpBaseConnection *base)
{
	SipeConnection *self = SIPE_CONNECTION(base);
	GPtrArray *channel_managers = g_ptr_array_new();

	SIPE_DEBUG_INFO_NOFORMAT("SipeConnection::create_channel_managers");

	self->password_manager = tp_simple_password_manager_new(base);
	g_ptr_array_add(channel_managers, self->password_manager);
	SIPE_DEBUG_INFO("SipeConnection::create_channel_managers: password %p",
			self->password_manager);

	return(channel_managers);
}

static void sipe_connection_finalize(GObject *object)
{
	SipeConnection *self = SIPE_CONNECTION(object);

	SIPE_DEBUG_INFO_NOFORMAT("SipeConnection::finalize");

	g_free(self->authentication);
	g_free(self->port);
	g_free(self->server);
	g_free(self->password);
	g_free(self->login);
	g_free(self->account);

	G_OBJECT_CLASS(sipe_connection_parent_class)->finalize(object);
}

/*
 * Connection class - type implementation
 */
static void sipe_connection_class_init(SipeConnectionClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	TpBaseConnectionClass *base_class = TP_BASE_CONNECTION_CLASS(klass);

	SIPE_DEBUG_INFO_NOFORMAT("SipeConnection::class_init");

	object_class->finalize = sipe_connection_finalize;

	base_class->create_handle_repos     = create_handle_repos;
	base_class->start_connecting        = start_connecting;
	base_class->shut_down               = shut_down;
	base_class->create_channel_managers = create_channel_managers;
}

static void sipe_connection_init(SIPE_UNUSED_PARAMETER SipeConnection *self)
{
	SIPE_DEBUG_INFO_NOFORMAT("SipeConnection::init");
}

/* create new connection object */
TpBaseConnection *sipe_telepathy_connection_new(TpBaseProtocol *protocol,
						GHashTable *params,
						SIPE_UNUSED_PARAMETER GError **error)
{
	SipeConnection *conn = g_object_new(SIPE_TYPE_CONNECTION,
					    "protocol", tp_base_protocol_get_name(protocol),
					    NULL);
	const gchar *value;
	guint port;
	gboolean valid;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_telepathy_connection_new");

	/* initialize private fields */
	conn->is_disconnecting = FALSE;

	/* account & login are required fields */
	conn->account = g_strdup(tp_asv_get_string(params, "account"));
	conn->login   = g_strdup(tp_asv_get_string(params, "login"));

	/* password */
	value = tp_asv_get_string(params, "password");
	if (value && strlen(value))
		conn->password = g_strdup(value);
	else
		conn->password = NULL;

	/* server name */
	value = tp_asv_get_string(params, "server");
	if (value && strlen(value))
		conn->server = g_strdup(value);
	else
		conn->server = NULL;

	/* server port: core expects a string */
	port = tp_asv_get_uint32(params, "port", &valid);
	if (valid)
		conn->port = g_strdup_printf("%d", port);
	else
		conn->port = NULL;

	/* transport type */
	value = tp_asv_get_string(params, "transport");
	if (sipe_strequal(value, "auto")) {
		conn->transport = conn->server ?
			SIPE_TRANSPORT_TLS : SIPE_TRANSPORT_AUTO;
	} else if (sipe_strequal(value, "tls")) {
		conn->transport = SIPE_TRANSPORT_TLS;
	} else {
		conn->transport = SIPE_TRANSPORT_TCP;
	}

	/* authentication type */
	value = tp_asv_get_string(params, "authentication");
	if (value && strlen(value) && strcmp(value, "ntlm"))
		conn->authentication = g_strdup(value);
	else
		conn->authentication = NULL; /* NTLM is default */


	return(TP_BASE_CONNECTION(conn));
}


/*
 * Backend adaptor functions
 */
void sipe_backend_connection_completed(struct sipe_core_public *sipe_public)
{
    SipeConnection *self = SIPE_PUBLIC_TO_CONNECTION;
    tp_base_connection_change_status(TP_BASE_CONNECTION(self),
				     TP_CONNECTION_STATUS_CONNECTED,
				     TP_CONNECTION_STATUS_REASON_REQUESTED);
}

void sipe_backend_connection_error(struct sipe_core_public *sipe_public,
				   sipe_connection_error error,
				   const gchar *msg)
{
    SipeConnection *self   = SIPE_PUBLIC_TO_CONNECTION;
    TpBaseConnection *base = TP_BASE_CONNECTION(self);
    GHashTable *details    = tp_asv_new("debug-message", G_TYPE_STRING, msg,
					NULL);
    TpConnectionStatusReason reason;
    const gchar *name;

    self->is_disconnecting = TRUE;

    switch (error) {
    case SIPE_CONNECTION_ERROR_NETWORK:
	    reason = TP_CONNECTION_STATUS_REASON_NETWORK_ERROR;
	    if (base->status == TP_CONNECTION_STATUS_CONNECTING)
		    name = TP_ERROR_STR_CONNECTION_FAILED;
	    else
		    name = TP_ERROR_STR_CONNECTION_LOST;
	    break;

    case SIPE_CONNECTION_ERROR_INVALID_USERNAME:
    case SIPE_CONNECTION_ERROR_INVALID_SETTINGS:
    case SIPE_CONNECTION_ERROR_AUTHENTICATION_FAILED:
    case SIPE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE:
	    /* copied from haze code. I agree there should be better ones */
	    reason = TP_CONNECTION_STATUS_REASON_AUTHENTICATION_FAILED;
	    name   = TP_ERROR_STR_AUTHENTICATION_FAILED;
	    break;

    default:
	    reason = TP_CONNECTION_STATUS_REASON_NONE_SPECIFIED;
	    name   = TP_ERROR_STR_DISCONNECTED;
	    break;
    }

    SIPE_DEBUG_ERROR("sipe_backend_connection_error: %s (%s)", name, msg);
    tp_base_connection_disconnect_with_dbus_error(base,
						  name,
						  details,
						  reason);
    g_hash_table_unref(details);
}

gboolean sipe_backend_connection_is_disconnecting(struct sipe_core_public *sipe_public)
{
	SipeConnection *self = SIPE_PUBLIC_TO_CONNECTION;

	/* disconnect was requested or transport was already disconnected */
	return(self->is_disconnecting ||
	       self->private.transport == NULL);
}

gboolean sipe_backend_connection_is_valid(struct sipe_core_public *sipe_public)
{
	return(!sipe_backend_connection_is_disconnecting(sipe_public));
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
