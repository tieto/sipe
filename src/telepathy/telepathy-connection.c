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
static void sipe_connection_finalize(GObject *object)
{
    SipeConnection *self = SIPE_CONNECTION(object);
    struct sipe_core_public *sipe_public = self->public;

    SIPE_DEBUG_INFO("sipe_connection_finalize: closing %p", sipe_public);

    if (sipe_public)
	    sipe_core_deallocate(sipe_public);

    G_OBJECT_CLASS(sipe_connection_parent_class)->finalize(object);
}

/*
 * Connection class - type implementation
 */
static void sipe_connection_class_init(SipeConnectionClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    object_class->finalize = sipe_connection_finalize;
}

static void sipe_connection_init(SIPE_UNUSED_PARAMETER SipeConnection *self)
{
}

/* create new connection object and attach it to SIPE core */
TpBaseConnection *sipe_telepathy_connection_new(SIPE_UNUSED_PARAMETER TpBaseProtocol *protocol,
						GHashTable *params,
						GError **error)
{
	const gchar *password  = tp_asv_get_string(params, "password");
	const gchar *login     = tp_asv_get_string(params, "login");
	const gchar *server    = tp_asv_get_string(params, "server");
	const gchar *transport = tp_asv_get_string(params, "transport");
	SipeConnection *conn   = g_object_new(SIPE_TYPE_CONNECTION,
					      "protocol", SIPE_TELEPATHY_DOMAIN,
					      "password", password,
					      NULL);
	struct sipe_core_public *sipe_public;
	gchar *login_domain  = NULL;
	gchar *login_account = NULL;
	const gchar *errmsg;
	guint type;
	gboolean valid;
	gchar *port = NULL;

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

	if (!sipe_public) {
		g_set_error_literal(error, TP_ERROR, TP_ERROR_INVALID_ARGUMENT,
				    errmsg);
		g_object_unref(G_OBJECT(conn));
		return NULL;
	}

	sipe_public->backend_private = (struct sipe_backend_private *) conn;
	conn->public                 = sipe_public;

	/* map option list to flags - default is NTLM */
	SIPE_CORE_FLAG_UNSET(KRB5);
	SIPE_CORE_FLAG_UNSET(TLS_DSK);
	SIPE_CORE_FLAG_UNSET(SSO);
	/* @TODO: add parameters for these */

	/* server name */
	if (!server || (strlen(server) == 0))
		server = NULL;

	/* server port: core expects a string */
	type = tp_asv_get_uint32(params, "port", &valid);
	if (valid)
		port = g_strdup_printf("%d", type);

	/* transport type */
	if (sipe_strequal(transport, "auto")) {
		type = server ? SIPE_TRANSPORT_TLS : SIPE_TRANSPORT_AUTO;
	} else if (sipe_strequal(transport, "tls")) {
		type = SIPE_TRANSPORT_TLS;
	} else {
		type = SIPE_TRANSPORT_TCP;
	}
	sipe_core_transport_sip_connect(sipe_public,
					type,
					server,
					port);
	g_free(port);

	return(TP_BASE_CONNECTION(conn));
}


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
