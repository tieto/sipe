/**
 * @file telepathy-protocol.c
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

#include <dbus/dbus-protocol.h>
#include <glib-object.h>
#include <telepathy-glib/base-connection-manager.h>
#include <telepathy-glib/base-protocol.h>

#include "sipe-common.h"
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
#define SIPE_PROTOCOL_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), SIPE_TYPE_PROTOCOL,	\
				 SipeProtocolClass))
#define SIPE_IS_PROTOCOL(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), SIPE_TYPE_PROTOCOL))
#define SIPE_IS_PROTOCOL_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE((klass), SIPE_TYPE_PROTOCOL))
#define SIPE_PROTOCOL_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS((obj), SIPE_TYPE_PROTOCOL,	\
				   SipeProtocolClass))
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
		g_set_error(error, TP_ERROR, TP_ERROR_INVALID_ARGUMENT,
			    _("User name should be a valid SIP URI\nExample: user@company.com"));
		return(FALSE);
	}
	return(TRUE);
}

static const TpCMParamSpec *get_parameters(SIPE_UNUSED_PARAMETER TpBaseProtocol *self)
{
/* ISO C99 Designated Initializers silences -Wmissing-field-initializers */
#define SIPE_PROTOCOL_PARAMETER(_name, _dtype, _gtype, _flags, _default, _filter) \
	{                             \
		.name   = (_name),    \
		.dtype  = (_dtype),   \
		.gtype  = (_gtype),   \
		.flags  = (_flags),   \
		.def    = (_default), \
		.filter = (_filter),  \
	}

	static const TpCMParamSpec const sipe_parameters[] = {
		SIPE_PROTOCOL_PARAMETER("account",
					DBUS_TYPE_STRING_AS_STRING,
					G_TYPE_STRING,
					TP_CONN_MGR_PARAM_FLAG_REQUIRED | TP_CONN_MGR_PARAM_FLAG_REGISTER,
					NULL,
					parameter_filter_account),
		SIPE_PROTOCOL_PARAMETER("login",
					DBUS_TYPE_STRING_AS_STRING,
					G_TYPE_STRING,
					TP_CONN_MGR_PARAM_FLAG_REQUIRED | TP_CONN_MGR_PARAM_FLAG_REGISTER,
					NULL,
					tp_cm_param_filter_string_nonempty),
		SIPE_PROTOCOL_PARAMETER("password",
					DBUS_TYPE_STRING_AS_STRING,
					G_TYPE_STRING,
					TP_CONN_MGR_PARAM_FLAG_REQUIRED | TP_CONN_MGR_PARAM_FLAG_REGISTER | TP_CONN_MGR_PARAM_FLAG_SECRET,
					NULL,
					tp_cm_param_filter_string_nonempty),
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
		SIPE_PROTOCOL_PARAMETER(NULL, NULL, 0, 0, NULL, NULL)
	};

	return(sipe_parameters);
}

/*
 * Protocol class - type implementation
 */
static void sipe_protocol_class_init(SipeProtocolClass *klass)
{
	TpBaseProtocolClass *base_class = (TpBaseProtocolClass *) klass;

	base_class->get_parameters = get_parameters;
	base_class->new_connection = sipe_telepathy_connection_new;
}

static void sipe_protocol_init(SIPE_UNUSED_PARAMETER SipeProtocol *self)
{
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
