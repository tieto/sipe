/**
 * @file telepathy-tls.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2013 SIPE Project <http://sipe.sourceforge.net/>
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
 *
 * TLS certificate accept/reject user interaction
 */

#include <glib-object.h>
#include <telepathy-glib/svc-channel.h>
#include <telepathy-glib/telepathy-glib.h>

#include "sipe-backend.h"
#include "sipe-common.h"

#include "telepathy-private.h"

/* TLS information required for user interaction */
struct sipe_tls_info {
	gchar *hostname;
	gchar *server_cert_path;
	GStrv reference_identities;
};

G_BEGIN_DECLS
/*
 * TLS Manager class - data structures
 */
typedef struct _SipeTLSManagerClass {
	GObjectClass parent_class;
} SipeTLSManagerClass;

typedef struct _SipeTLSManager {
	GObject parent;

	GObject *connection;

	GSList *channels;
} SipeTLSManager;

/*
 * TLS Manager class - type macros
 */
static GType sipe_tls_manager_get_type(void);
#define SIPE_TYPE_TLS_MANAGER \
	(sipe_tls_manager_get_type())
#define SIPE_TLS_MANAGER(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), SIPE_TYPE_TLS_MANAGER, \
				    SipeTLSManager))

/*
 * TLS Channel class - data structures
 */
typedef struct _SipeTLSChannelClass {
	TpBaseChannelClass parent_class;
} SipeTLSChannelClass;

typedef struct _SipeTLSChannel {
        TpBaseChannel parent;

	const struct sipe_tls_info *tls_info;

	GSimpleAsyncResult *result;
} SipeTLSChannel;

/*
 * TLS Channel class - type macros
 */
static GType sipe_tls_channel_get_type(void) G_GNUC_CONST;
#define SIPE_TYPE_TLS_CHANNEL \
	(sipe_tls_channel_get_type())
#define SIPE_TLS_CHANNEL(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), SIPE_TYPE_TLS_CHANNEL, \
				    SipeTLSChannel))
G_END_DECLS

/*
 * TLS Manager class - type definition
 */
static void channel_manager_iface_init(gpointer, gpointer);
G_DEFINE_TYPE_WITH_CODE(SipeTLSManager,
			sipe_tls_manager,
			G_TYPE_OBJECT,
			G_IMPLEMENT_INTERFACE(TP_TYPE_CHANNEL_MANAGER,
					      channel_manager_iface_init);
)

/*
 * TLS Channel class - type definition
 */
G_DEFINE_TYPE_WITH_CODE(SipeTLSChannel,
			sipe_tls_channel,
			TP_TYPE_BASE_CHANNEL,
			G_IMPLEMENT_INTERFACE(TP_TYPE_SVC_CHANNEL_TYPE_SERVER_TLS_CONNECTION,
					      NULL);
)

/*
 * TLS Manager class - instance methods
 */
static void sipe_tls_manager_constructed(GObject *object)
{
	SipeTLSManager *self        = SIPE_TLS_MANAGER(object);
	void (*chain_up)(GObject *) = G_OBJECT_CLASS(sipe_tls_manager_parent_class)->constructed;

	if (chain_up)
		chain_up(object);

	self->channels = NULL;
}

static void sipe_tls_manager_dispose(GObject *object)
{
	SipeTLSManager *self        = SIPE_TLS_MANAGER(object);
	void (*chain_up)(GObject *) = G_OBJECT_CLASS(sipe_tls_manager_parent_class)->constructed;

	tp_clear_object(&self->connection);

	if (chain_up)
		chain_up(object);
}

static void sipe_tls_manager_finalize(GObject *object)
{
	SipeTLSManager *self        = SIPE_TLS_MANAGER(object);
	void (*chain_up)(GObject *) = G_OBJECT_CLASS(sipe_tls_manager_parent_class)->constructed;
	GSList *entry               = self->channels;

	/* close channels */
	while (entry) {
		GSList *next = entry->next;
		/* removes entry from list */
		tp_base_channel_close(entry->data);
		entry = next;
	}

	tp_clear_object(&self->connection);

	if (chain_up)
		chain_up(object);
}


/*
 * TLS Manager class - type implementation
 */
static void sipe_tls_manager_class_init(SipeTLSManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);

	SIPE_DEBUG_INFO_NOFORMAT("SipeTLSManager::class_init");

	object_class->constructed  = sipe_tls_manager_constructed;
	object_class->dispose      = sipe_tls_manager_dispose;
	object_class->finalize     = sipe_tls_manager_finalize;
}

static void sipe_tls_manager_init(SIPE_UNUSED_PARAMETER SipeTLSManager *self)
{
	SIPE_DEBUG_INFO_NOFORMAT("SipeTLSManager::init");
}

/*
 * TLS Manager class - interface implementation
 *
 * Channel Manager
 */
static void foreach_channel(TpChannelManager *manager,
			    TpExportableChannelFunc func,
			    gpointer user_data)
{
	SipeTLSManager *self = SIPE_TLS_MANAGER(manager);

	SIPE_DEBUG_INFO_NOFORMAT("SipeTLSManager::foreach_channel");

	/* @TODO */
	(void)self;
	(void)func;
	(void)user_data;
}

static void channel_manager_iface_init(gpointer g_iface,
				       SIPE_UNUSED_PARAMETER gpointer iface_data)
{
	TpChannelManagerIface *iface = g_iface;

#define IMPLEMENT(x, y) iface->x = y
	IMPLEMENT(foreach_channel,            foreach_channel);
	/* These channels are not requestable. */
	IMPLEMENT(type_foreach_channel_class, NULL);
	IMPLEMENT(create_channel,             NULL);
	IMPLEMENT(request_channel,            NULL);
	IMPLEMENT(ensure_channel,             NULL);
#undef IMPLEMENT
}

/* create new TLS manager object */
SipeTLSManager *sipe_telepathy_tls_new(TpBaseConnection *connection)
{
	SipeTLSManager *self = g_object_new(SIPE_TYPE_TLS_MANAGER, NULL);
	self->connection = g_object_ref(connection);
	return(self);
}

static void channel_closed_cb(SipeTLSChannel *channel,
			      SipeTLSManager *self)
{
	self->channels = g_slist_remove(self->channels, channel);
	tp_channel_manager_emit_channel_closed_for_object(self,
							  TP_EXPORTABLE_CHANNEL(channel));
	g_object_unref(channel);
}

static void manager_new_channel(SipeTLSManager *self,
				SipeTLSChannel *channel)
{
	self->channels = g_slist_prepend(self->channels,
					 g_object_ref(channel));

	g_signal_connect(channel,
			 "closed",
			 G_CALLBACK(channel_closed_cb),
			 self);

	/* emit NewChannel on the ChannelManager iface */
	tp_channel_manager_emit_new_channel(self,
					    TP_EXPORTABLE_CHANNEL(channel),
					    NULL);

}

/*
 * TLS Channel class - instance methods
 */
enum {
	CHANNEL_PROP_SERVER_CERTIFICATE = 1,
	CHANNEL_PROP_HOSTNAME,
	CHANNEL_PROP_REFERENCE_IDENTITIES,
	CHANNEL_LAST_PROP
};

static void get_property(GObject *object,
			 guint property_id,
			 GValue *value,
			 GParamSpec *pspec)
{
	SipeTLSChannel *self = SIPE_TLS_CHANNEL(object);

	switch (property_id) {
	case CHANNEL_PROP_SERVER_CERTIFICATE:
		g_value_set_boxed(value, self->tls_info->server_cert_path);
		break;
	case CHANNEL_PROP_HOSTNAME:
		g_value_set_string(value, self->tls_info->hostname);
		break;
	case CHANNEL_PROP_REFERENCE_IDENTITIES:
		g_value_set_boxed(value, self->tls_info->reference_identities);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
		break;
	}
}

static void fill_immutable_properties(TpBaseChannel *channel,
				      GHashTable *properties)
{
	TP_BASE_CHANNEL_CLASS(sipe_tls_channel_parent_class)->fill_immutable_properties(channel,
											   properties);
	tp_dbus_properties_mixin_fill_properties_hash(G_OBJECT(channel),
						      properties,
						      TP_IFACE_CHANNEL_TYPE_SERVER_TLS_CONNECTION, "ServerCertificate",
						      TP_IFACE_CHANNEL_TYPE_SERVER_TLS_CONNECTION, "Hostname",
						      TP_IFACE_CHANNEL_TYPE_SERVER_TLS_CONNECTION, "ReferenceIdentities",
						      NULL);
}

static gchar *get_object_path_suffix(TpBaseChannel *base)
{
	return(g_strdup_printf("TLSChannel_%p", base));
}

static void sipe_tls_channel_constructed(GObject *object)
{
	SipeTLSChannel *self        = SIPE_TLS_CHANNEL(object);
	void (*chain_up)(GObject *) = G_OBJECT_CLASS(sipe_tls_channel_parent_class)->constructed;

	if (chain_up)
		chain_up(object);

	/* @TODO */
	(void)self;
}

static void sipe_tls_channel_finalize(GObject *object)
{
	SipeTLSChannel *self = SIPE_TLS_CHANNEL(object);

	SIPE_DEBUG_INFO_NOFORMAT("SipeTLSChannel::finalize");

	g_simple_async_result_complete(self->result);
	g_clear_object(&self->result);

	G_OBJECT_CLASS(sipe_tls_channel_parent_class)->finalize(object);
}

/*
 * TLS Channel class - type implementation
 */
static void sipe_tls_channel_class_init(SipeTLSChannelClass *klass)
{
	static TpDBusPropertiesMixinPropImpl props[] = {
		{
			.name        = "ServerCertificate",
			.getter_data = "server-certificate",
			.setter_data = NULL
		},
		{
			.name        = "Hostname",
			.getter_data = "hostname",
			.setter_data = NULL
		},
		{
			.name        = "ReferenceIdentities",
			.getter_data = "reference-identities",
			.setter_data = NULL
		},
		{
			.name        = NULL
		}
	};
	GObjectClass *object_class     = G_OBJECT_CLASS(klass);
	TpBaseChannelClass *base_class = TP_BASE_CHANNEL_CLASS(klass);
	GParamSpec *ps;

	SIPE_DEBUG_INFO_NOFORMAT("SipeTLSChannel::class_init");

	object_class->constructed      = sipe_tls_channel_constructed;
	object_class->finalize         = sipe_tls_channel_finalize;
	object_class->get_property     = get_property;

	base_class->channel_type       = TP_IFACE_CHANNEL_TYPE_SERVER_TLS_CONNECTION;
	base_class->target_handle_type = TP_HANDLE_TYPE_NONE;
	base_class->fill_immutable_properties = fill_immutable_properties;
	base_class->get_object_path_suffix    = get_object_path_suffix;
	base_class->interfaces         = NULL;
	base_class->close              = tp_base_channel_destroyed;

	ps = g_param_spec_boxed("server-certificate",
				"Server certificate path",
				"The object path of the server certificate.",
				DBUS_TYPE_G_OBJECT_PATH,
				G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	g_object_class_install_property(object_class,
					CHANNEL_PROP_SERVER_CERTIFICATE,
					ps);

	ps = g_param_spec_string("hostname",
				 "The hostname to be verified",
				 "The hostname which should be certified by the server certificate.",
				 NULL,
				 G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	g_object_class_install_property(object_class,
					CHANNEL_PROP_HOSTNAME,
					ps);

	ps = g_param_spec_boxed("reference-identities",
				"The various identities to check the certificate against",
				"The server certificate identity should match one of these identities.",
				G_TYPE_STRV,
				G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	g_object_class_install_property(object_class,
					CHANNEL_PROP_REFERENCE_IDENTITIES,
					ps);

	tp_dbus_properties_mixin_implement_interface(object_class,
						     TP_IFACE_QUARK_CHANNEL_TYPE_SERVER_TLS_CONNECTION,
						     tp_dbus_properties_mixin_getter_gobject_properties,
						     NULL,
						     props);
}

static void sipe_tls_channel_init(SIPE_UNUSED_PARAMETER SipeTLSChannel *self)
{
	SIPE_DEBUG_INFO_NOFORMAT("SipeTLSChannel::init");
}

struct sipe_tls_info *sipe_telepathy_tls_info_new(const gchar *hostname,
						  SIPE_UNUSED_PARAMETER struct _GTlsCertificate *certificate)
{
	struct sipe_tls_info *tls_info = g_new0(struct sipe_tls_info, 1);

	tls_info->hostname = g_strdup(hostname);

	/*
	 * @TODO
	 * tls_info->reference_identities = g_boxed_copy(G_TYPE_STRV, reference_identities);??
	 * tls_info->tls_info->server_cert_path
	 */

	return(tls_info);
}

void sipe_telepathy_tls_info_free(struct sipe_tls_info *tls_info)
{
	g_free(tls_info->hostname);
	g_free(tls_info->server_cert_path);
	g_strfreev(tls_info->reference_identities);
	g_free(tls_info);
}

/* create new tls channel object */
void sipe_telepathy_tls_verify_async(GObject *connection,
				     struct sipe_tls_info *tls_info,
				     GAsyncReadyCallback callback,
				     gpointer user_data)
{
	struct sipe_backend_private *telepathy_private = sipe_telepathy_connection_private(connection);

	/* property "connection" required by TpBaseChannel */
	SipeTLSChannel *self = g_object_new(SIPE_TYPE_TLS_CHANNEL,
					    "connection", connection,
					    NULL);

	self->tls_info = tls_info;
	self->result = g_simple_async_result_new(G_OBJECT(self),
						 callback,
						 user_data,
						 sipe_telepathy_tls_verify_async);

	tp_base_channel_register(TP_BASE_CHANNEL(self));

	manager_new_channel(telepathy_private->tls_manager, self);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
