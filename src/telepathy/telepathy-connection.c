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

#include <string.h>

#include <glib-object.h>
#include <telepathy-glib/base-connection.h>
#include <telepathy-glib/base-protocol.h>
#include <telepathy-glib/handle-repo-dynamic.h>
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
	struct sipe_core_public *public;
	gchar *server;
	gchar *port;
	guint  transport;
} SipeConnection;

/*
 * Connection class - type macros
 */
static GType sipe_connection_get_type(void) G_GNUC_CONST;
#define SIPE_TYPE_CONNECTION \
	(sipe_connection_get_type())
#define SIPE_CONNECTION(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), SIPE_TYPE_CONNECTION, \
				    SipeConnection))
#define SIPE_CONNECTION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), SIPE_TYPE_CONNECTION,	\
				 SipeConnectionClass))
#define SIPE_IS_CONNECTION(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), SIPE_TYPE_CONNECTION))
#define SIPE_IS_CONNECTION_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE((klass), SIPE_TYPE_CONNECTION))
#define SIPE_CONNECTION_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS((obj), SIPE_TYPE_CONNECTION,	\
				   SipeConnectionClass))
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

static gboolean start_connecting(TpBaseConnection *base,
				 SIPE_UNUSED_PARAMETER GError **error)
{
	SipeConnection *self = SIPE_CONNECTION(base);

	SIPE_DEBUG_INFO_NOFORMAT("SipeConnection::start_connecting");

	g_return_val_if_fail(self->public, FALSE);

	tp_base_connection_change_status(base, TP_CONNECTION_STATUS_CONNECTING,
					 TP_CONNECTION_STATUS_REASON_REQUESTED);

	sipe_core_transport_sip_connect(self->public,
					self->transport,
					self->server,
					self->port);
	return(TRUE);
}

static void shut_down(TpBaseConnection *base)
{
	SipeConnection *self = SIPE_CONNECTION(base);
	struct sipe_core_public *sipe_public = self->public;

	SIPE_DEBUG_INFO("SipeConnection::shut_down: closing %p", sipe_public);

	if (sipe_public)
	    sipe_core_deallocate(sipe_public);

	SIPE_DEBUG_INFO_NOFORMAT("SipeConnection::shut_down: core deallocated");
}

static GPtrArray *create_channel_managers(SIPE_UNUSED_PARAMETER TpBaseConnection *base)
{
	/* @TODO */
	return(g_ptr_array_sized_new(0));
}

static void sipe_connection_finalize(GObject *object)
{
	SipeConnection *self = SIPE_CONNECTION(object);

	SIPE_DEBUG_INFO_NOFORMAT("SipeConnection::finalize");

	g_free(self->port);
	g_free(self->server);

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

/* create new connection object and attach it to SIPE core */
TpBaseConnection *sipe_telepathy_connection_new(TpBaseProtocol *protocol,
						GHashTable *params,
						GError **error)
{
	const gchar *password  = tp_asv_get_string(params, "password");
	const gchar *login     = tp_asv_get_string(params, "login");
	gchar *login_domain    = NULL;
	gchar *login_account   = NULL;
	TpBaseConnection *base = NULL;
	struct sipe_core_public *sipe_public;
	const gchar *errmsg;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_telepathy_connection_new");

	/* login name specified? */
	if (login && strlen(login)) {
		/* Allowed domain-account separators are / or \ */
		gchar **domain_user = g_strsplit_set(login, "/\\", 2);
		gboolean has_domain = domain_user[1] != NULL;
		SIPE_DEBUG_INFO("sipe_telepathy_connection_new: login '%s'", login);
		login_domain  = has_domain ? g_strdup(domain_user[0]) : NULL;
		login_account = g_strdup(domain_user[has_domain ? 1 : 0]);
		SIPE_DEBUG_INFO("sipe_telepathy_connection_new: auth domain '%s' user '%s'",
				login_domain ? login_domain : "",
				login_account);
		g_strfreev(domain_user);
	}

	sipe_public = sipe_core_allocate(tp_asv_get_string(params, "account"),
					 login_domain, login_account,
					 password,
					 NULL, /* @TODO: email     */
					 NULL, /* @TODO: email_url */
					 &errmsg);
	g_free(login_domain);
	g_free(login_account);

	SIPE_DEBUG_INFO("sipe_telepathy_connection_new: created %p", sipe_public);

	if (sipe_public) {
		const gchar *server    = tp_asv_get_string(params, "server");
		const gchar *transport = tp_asv_get_string(params, "transport");
		SipeConnection *conn   = g_object_new(SIPE_TYPE_CONNECTION,
						      "protocol", tp_base_protocol_get_name(protocol),
						      NULL);
		guint port;
		gboolean valid;

		/* initialize backend private data */
		sipe_public->backend_private = (struct sipe_backend_private *) conn;
		conn->public                 = sipe_public;

		/* map option list to flags - default is NTLM */
		SIPE_CORE_FLAG_UNSET(KRB5);
		SIPE_CORE_FLAG_UNSET(TLS_DSK);
		SIPE_CORE_FLAG_UNSET(SSO);
		/* @TODO: add parameters for these */

		/* server name */
		if (server && strlen(server))
			conn->server = g_strdup(server);
		else
			conn->server = NULL;

		/* server port: core expects a string */
		port = tp_asv_get_uint32(params, "port", &valid);
		if (valid)
			conn->port = g_strdup_printf("%d", port);
		else
			conn->port = NULL;

		/* transport type */
		if (sipe_strequal(transport, "auto")) {
			conn->transport = conn->server ?
				SIPE_TRANSPORT_TLS : SIPE_TRANSPORT_AUTO;
		} else if (sipe_strequal(transport, "tls")) {
			conn->transport = SIPE_TRANSPORT_TLS;
		} else {
			conn->transport = SIPE_TRANSPORT_TCP;
		}

		base = TP_BASE_CONNECTION(conn);

	} else
		g_set_error_literal(error, TP_ERROR, TP_ERROR_INVALID_ARGUMENT,
				    errmsg);

	return(base);
}


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
