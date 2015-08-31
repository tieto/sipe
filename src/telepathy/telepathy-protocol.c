/**
 * @file telepathy-protocol.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2012-2014 SIPE Project <http://sipe.sourceforge.net/>
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

#include <dbus/dbus-protocol.h>
#include <glib-object.h>
#include <telepathy-glib/base-connection-manager.h>
#include <telepathy-glib/base-protocol.h>
#include <telepathy-glib/simple-password-manager.h>
#include <telepathy-glib/telepathy-glib.h>

#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-core.h"
#include "sipe-nls.h"

#include "telepathy-private.h"

G_BEGIN_DECLS
/*
 * Protocol class - data structures
 */
typedef struct _SipeProtocolClass {
	TpBaseProtocolClass parent_class;
} SipeProtocolClass;

typedef struct _SipeProtocol {
	TpBaseProtocol parent;
} SipeProtocol;

/*
 * Protocol class - type macros
 */
static GType sipe_protocol_get_type(void) G_GNUC_CONST;
#define SIPE_TYPE_PROTOCOL \
	(sipe_protocol_get_type())
#define SIPE_PROTOCOL(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), SIPE_TYPE_PROTOCOL, \
				    SipeProtocol))
G_END_DECLS

/*
 * Protocol class - type definition
 */
G_DEFINE_TYPE(SipeProtocol,
	      sipe_protocol,
	      TP_TYPE_BASE_PROTOCOL)

/*
 * Protocol class - instance methods
 */
/*
 * @TODO: parameter filtering doesn't seem to work: these functions aren't
 *        called at all - why?
 */
static gboolean parameter_filter_account(SIPE_UNUSED_PARAMETER const TpCMParamSpec *paramspec,
					 GValue *value,
					 GError **error)
{
	const gchar *str = g_value_get_string(value);

	if ((str == NULL) ||
	    (strchr(str, '@') == NULL)) {
		g_set_error(error, TP_ERROR, TP_ERROR_INVALID_HANDLE,
			    _("User name should be a valid SIP URI\nExample: user@company.com"));
		return(FALSE);
	}
	return(TRUE);
}

static const TpCMParamSpec *get_parameters(SIPE_UNUSED_PARAMETER TpBaseProtocol *self)
{
/* ISO C99 Designated Initializers silences -Wmissing-field-initializers */
#define SIPE_PROTOCOL_PARAMETER(_name, _dtype, _gtype, _flags, _default, _filter) \
	{                                  \
		.name        = (_name),    \
		.dtype       = (_dtype),   \
		.gtype       = (_gtype),   \
		.flags       = (_flags),   \
		.def         = (_default), \
		.offset      = 0,          \
		.filter      = (_filter),  \
		.filter_data = NULL,       \
		.setter_data = NULL,       \
	}

	static const TpCMParamSpec const sipe_parameters[] = {
		SIPE_PROTOCOL_PARAMETER("account",
					DBUS_TYPE_STRING_AS_STRING,
					G_TYPE_STRING,
					TP_CONN_MGR_PARAM_FLAG_REQUIRED,
					NULL,
					parameter_filter_account),
		SIPE_PROTOCOL_PARAMETER("login",
					DBUS_TYPE_STRING_AS_STRING,
					G_TYPE_STRING,
					0,
					NULL,
					NULL /* can be empty */),
		SIPE_PROTOCOL_PARAMETER("password",
					DBUS_TYPE_STRING_AS_STRING,
					G_TYPE_STRING,
					TP_CONN_MGR_PARAM_FLAG_SECRET,
					NULL,
					NULL /* can be empty */),
		SIPE_PROTOCOL_PARAMETER("server",
					DBUS_TYPE_STRING_AS_STRING,
					G_TYPE_STRING,
					0,
					NULL,
					NULL /* can be empty */),
		SIPE_PROTOCOL_PARAMETER("port",
					DBUS_TYPE_UINT16_AS_STRING,
					G_TYPE_UINT,
					TP_CONN_MGR_PARAM_FLAG_HAS_DEFAULT,
					GUINT_TO_POINTER(0),
					NULL),
		/* @TODO: this should be combo auto/ssl/tcp */
		SIPE_PROTOCOL_PARAMETER("transport",
					DBUS_TYPE_STRING_AS_STRING,
					G_TYPE_STRING,
					TP_CONN_MGR_PARAM_FLAG_HAS_DEFAULT,
					"auto",
					tp_cm_param_filter_string_nonempty),
		SIPE_PROTOCOL_PARAMETER("useragent",
					DBUS_TYPE_STRING_AS_STRING,
					G_TYPE_STRING,
					0,
					NULL,
					NULL /* can be empty */),
		/* @TODO: this should be combo auto/ntlm/krb5/tls-dsk */
		SIPE_PROTOCOL_PARAMETER("authentication",
					DBUS_TYPE_STRING_AS_STRING,
					G_TYPE_STRING,
					TP_CONN_MGR_PARAM_FLAG_HAS_DEFAULT,
					"auto",
					tp_cm_param_filter_string_nonempty),
		SIPE_PROTOCOL_PARAMETER("single-sign-on",
					DBUS_TYPE_BOOLEAN_AS_STRING,
					G_TYPE_BOOLEAN,
					TP_CONN_MGR_PARAM_FLAG_HAS_DEFAULT,
					GINT_TO_POINTER(FALSE),
					NULL),
		SIPE_PROTOCOL_PARAMETER("don't-publish-calendar",
					DBUS_TYPE_BOOLEAN_AS_STRING,
					G_TYPE_BOOLEAN,
					TP_CONN_MGR_PARAM_FLAG_HAS_DEFAULT,
					GINT_TO_POINTER(FALSE),
					NULL),
		SIPE_PROTOCOL_PARAMETER(NULL, NULL, 0, 0, NULL, NULL)
	};

	return(sipe_parameters);
}

/* non-static, because it is re-used by connection object */
gchar *sipe_telepathy_protocol_normalize_contact(SIPE_UNUSED_PARAMETER TpBaseProtocol *self,
						 const gchar *contact,
						 GError **error)
{
	gchar *uri = sip_uri_if_valid(contact);

	SIPE_DEBUG_INFO_NOFORMAT("SipeProtocol::normalize_contact");

	if (!uri)
		g_set_error(error, TP_ERROR, TP_ERROR_INVALID_HANDLE,
			    _("User name should be a valid SIP URI\nExample: user@company.com"));
	return(uri);
}

static gchar *identify_account(SIPE_UNUSED_PARAMETER TpBaseProtocol *self,
			       GHashTable *asv,
			       SIPE_UNUSED_PARAMETER GError **error)
{
	SIPE_DEBUG_INFO_NOFORMAT("SipeProtocol::identify_account");

	return(g_strdup(tp_asv_get_string(asv, "account")));
}

static GStrv get_interfaces(SIPE_UNUSED_PARAMETER TpBaseProtocol *base)
{
	SIPE_DEBUG_INFO_NOFORMAT("SipeProtocol::get_interfaces");

	return(g_new0(gchar *, 1));
}

static void get_connection_details(SIPE_UNUSED_PARAMETER TpBaseProtocol *self,
				   GStrv *connection_interfaces,
				   GType **channel_managers,
				   gchar **icon_name,
				   gchar **english_name,
				   gchar **vcard_field)
{
	SIPE_DEBUG_INFO_NOFORMAT("SipeProtocol::get_connection_details");

	if (connection_interfaces) {
		static const gchar * const interfaces[] = {
			/* @TODO */
			NULL
		};
		*connection_interfaces = g_strdupv((GStrv) interfaces);
	}
	if (channel_managers) {
		GType types[] = {
			/* @TODO */
			TP_TYPE_SIMPLE_PASSWORD_MANAGER,
			SIPE_TYPE_SEARCH_MANAGER,
			G_TYPE_INVALID
		};
		*channel_managers = g_memdup(types, sizeof(types));
	}
	if (icon_name)
		*icon_name    = g_strdup("im-" SIPE_TELEPATHY_DOMAIN);
	if (english_name)
		*english_name = g_strdup("Office Communicator");
	if (vcard_field)
		*vcard_field  = g_strdup("x-" SIPE_TELEPATHY_DOMAIN);
}

static GStrv dup_authentication_types(SIPE_UNUSED_PARAMETER TpBaseProtocol *self)
{
	static const gchar * const types[] = {
		/* @TODO */
		NULL
	};

	SIPE_DEBUG_INFO_NOFORMAT("SipeProtocol::dup_authentication_types");

	return(g_strdupv((GStrv) types));
}

/*
 * Protocol class - type implementation
 */
static void sipe_protocol_class_init(SipeProtocolClass *klass)
{
	TpBaseProtocolClass *base_class = TP_BASE_PROTOCOL_CLASS(klass);

	SIPE_DEBUG_INFO_NOFORMAT("SipeProtocol::class_init");

	base_class->get_parameters           = get_parameters;
	base_class->new_connection           = sipe_telepathy_connection_new;
	base_class->normalize_contact        = sipe_telepathy_protocol_normalize_contact;
	base_class->identify_account         = identify_account;
	base_class->get_interfaces           = get_interfaces;
	base_class->get_connection_details   = get_connection_details;
	base_class->dup_authentication_types = dup_authentication_types;
}

static void sipe_protocol_init(SIPE_UNUSED_PARAMETER SipeProtocol *self)
{
	SIPE_DEBUG_INFO_NOFORMAT("SipeProtocol::init");
}

/* add protocol to connection manager */
void sipe_telepathy_protocol_init(TpBaseConnectionManager *cm)
{
	TpBaseProtocol *protocol = g_object_new(SIPE_TYPE_PROTOCOL,
						"name", SIPE_TELEPATHY_DOMAIN,
						NULL);
	tp_base_connection_manager_add_protocol(cm, protocol);
	g_object_unref(protocol);
}


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
