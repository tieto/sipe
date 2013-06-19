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

#include <string.h>

#include <glib-object.h>
#include <telepathy-glib/dbus-properties-mixin.h>
#include <telepathy-glib/svc-channel.h>
#include <telepathy-glib/svc-tls.h>
#include <telepathy-glib/telepathy-glib.h>

#include "sipe-backend.h"
#include "sipe-common.h"

#include "telepathy-private.h"

/* TLS information required for user interaction */
struct _SipeTLSCertificate;
struct sipe_tls_info {
	gchar *hostname;
	gchar *cert_path;
	GPtrArray *cert_data;
	GStrv reference_identities;
	struct _SipeTLSCertificate *certificate;
};

/* Certificate states */
#define SIPE_TLS_CERTIFICATE_PENDING  0
#define SIPE_TLS_CERTIFICATE_REJECTED 1
#define SIPE_TLS_CERTIFICATE_ACCEPTED 2

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

/*
 * TLS Certificate class - data structures
 */
typedef struct _SipeTLSCertificateClass {
	GObjectClass parent_class;

	TpDBusPropertiesMixinClass dbus_props_class;
} SipeTLSCertificateClass;

typedef struct _SipeTLSCertificate {
	GObject parent;

	const struct sipe_tls_info *tls_info;

	guint state;
} SipeTLSCertificate;

/*
 * TLS Certificate class - type macros
 */
static GType sipe_tls_certificate_get_type(void) G_GNUC_CONST;
#define SIPE_TYPE_TLS_CERTIFICATE \
	(sipe_tls_certificate_get_type())
#define SIPE_TLS_CERTIFICATE(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), SIPE_TYPE_TLS_CERTIFICATE, \
				    SipeTLSCertificate))
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
 * TLS Certificate class - type definition
 */
static void tls_certificate_iface_init(gpointer, gpointer);
G_DEFINE_TYPE_WITH_CODE (SipeTLSCertificate,
			 sipe_tls_certificate,
			 G_TYPE_OBJECT,
			 G_IMPLEMENT_INTERFACE(TP_TYPE_SVC_AUTHENTICATION_TLS_CERTIFICATE,
					       tls_certificate_iface_init);
			 G_IMPLEMENT_INTERFACE(TP_TYPE_SVC_DBUS_PROPERTIES,
					       tp_dbus_properties_mixin_iface_init);
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
	GSList *entry;

	SIPE_DEBUG_INFO_NOFORMAT("SipeTLSManager::foreach_channel");

	for (entry = self->channels; entry; entry = entry->next)
		func(entry->data, user_data);
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
	SIPE_DEBUG_INFO("channel_closed_cb: %p", channel);

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

static void channel_get_property(GObject *object,
				 guint property_id,
				 GValue *value,
				 GParamSpec *pspec)
{
	SipeTLSChannel *self = SIPE_TLS_CHANNEL(object);

	switch (property_id) {
	case CHANNEL_PROP_SERVER_CERTIFICATE:
		g_value_set_boxed(value, self->tls_info->cert_path);
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

static void channel_fill_immutable_properties(TpBaseChannel *channel,
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

static gchar *channel_get_object_path_suffix(TpBaseChannel *base)
{
	return(g_strdup_printf("TLSChannel_%p", base));
}

static void sipe_tls_channel_constructed(GObject *object)
{
	void (*chain_up)(GObject *) = G_OBJECT_CLASS(sipe_tls_channel_parent_class)->constructed;

	if (chain_up)
		chain_up(object);
}

static void sipe_tls_channel_finalize(GObject *object)
{
	SipeTLSChannel *self = SIPE_TLS_CHANNEL(object);

	SIPE_DEBUG_INFO_NOFORMAT("SipeTLSChannel::finalize");

	if (self->result) {
		g_simple_async_result_set_error(self->result,
						TP_ERROR,
						TP_ERROR_CANCELLED,
						"The TLS channel is being destroyed");
		g_simple_async_result_complete_in_idle(self->result);
		g_clear_object(&self->result);
	}

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
	object_class->get_property     = channel_get_property;

	base_class->channel_type       = TP_IFACE_CHANNEL_TYPE_SERVER_TLS_CONNECTION;
	base_class->target_handle_type = TP_HANDLE_TYPE_NONE;
	base_class->fill_immutable_properties = channel_fill_immutable_properties;
	base_class->get_object_path_suffix    = channel_get_object_path_suffix;
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

static void certificate_accepted_cb(SIPE_UNUSED_PARAMETER SipeTLSCertificate *certificate,
				    SipeTLSChannel *self)
{
	g_simple_async_result_complete(self->result);
	g_clear_object(&self->result);
	tp_base_channel_close(TP_BASE_CHANNEL(self));
}

static void certificate_rejected_cb(SIPE_UNUSED_PARAMETER SipeTLSCertificate *certificate,
				    SIPE_UNUSED_PARAMETER GPtrArray *rejections,
				    SipeTLSChannel *self)
{
	static GQuark quark = 0;

	if (!quark)
		quark = g_quark_from_static_string("server-tls-error");

	g_simple_async_result_set_error(self->result,
					quark,
					0,
					"TLS certificate rejected");
	g_simple_async_result_complete(self->result);
	g_clear_object(&self->result);
	tp_base_channel_close(TP_BASE_CHANNEL(self));
}

static void channel_new_certificate(GObject *connection,
				    struct sipe_tls_info *tls_info,
				    SipeTLSChannel *self,
				    GAsyncReadyCallback callback,
				    gpointer user_data)
{
	struct sipe_backend_private *telepathy_private = sipe_telepathy_connection_private(connection);

	self->tls_info = tls_info;
	self->result   = g_simple_async_result_new(G_OBJECT(self),
						   callback,
						   user_data,
						   channel_new_certificate);

	g_signal_connect(tls_info->certificate,
			 "accepted",
			 G_CALLBACK(certificate_accepted_cb),
			 self);

	g_signal_connect(tls_info->certificate,
			 "rejected",
			 G_CALLBACK(certificate_rejected_cb),
			 self);

	manager_new_channel(telepathy_private->tls_manager, self);
}



/*
 * TLS Certificate class - instance methods
 */
enum {
	CERTIFICATE_PROP_OBJECT_PATH = 1,
	CERTIFICATE_PROP_STATE,
	CERTIFICATE_PROP_TYPE,
	CERTIFICATE_PROP_CHAIN_DATA,
	CERTIFICATE_LAST_PROP
};

static void certificate_get_property(GObject *object,
				     guint property_id,
				     GValue *value,
				     GParamSpec *pspec)
{
	SipeTLSCertificate *self = SIPE_TLS_CERTIFICATE(object);

	switch (property_id) {
	case CERTIFICATE_PROP_OBJECT_PATH:
		g_value_set_string(value, self->tls_info->cert_path);
		break;
	case CERTIFICATE_PROP_STATE:
		g_value_set_uint(value, self->state);
		break;
	case CERTIFICATE_PROP_TYPE:
		g_value_set_string(value, "x509");
		break;
	case CERTIFICATE_PROP_CHAIN_DATA:
		g_value_set_boxed(value, self->tls_info->cert_data);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
		break;
	}
}

static void sipe_tls_certificate_constructed(GObject *object)
{
	SipeTLSCertificate *self    = SIPE_TLS_CERTIFICATE(object);
	void (*chain_up)(GObject *) = G_OBJECT_CLASS(sipe_tls_certificate_parent_class)->constructed;

	if (chain_up)
		chain_up(object);

	self->state = SIPE_TLS_CERTIFICATE_PENDING;
}

static void sipe_tls_certificate_finalize(GObject *object)
{
	SIPE_DEBUG_INFO_NOFORMAT("SipeTLSCertificate::finalize");

	G_OBJECT_CLASS(sipe_tls_certificate_parent_class)->finalize(object);
}

/*
 * TLS Certificate class - type implementation
 */
static void sipe_tls_certificate_class_init(SipeTLSCertificateClass *klass)
{
	static TpDBusPropertiesMixinPropImpl props[] = {
		{
			.name        = "State",
			.getter_data = "state",
			.setter_data = NULL
		},
		{
			.name        = "CertificateType",
			.getter_data = "certificate-type",
			.setter_data = NULL
		},
		{
			.name        = "CertificateChainData",
			.getter_data = "certificate-chain-data",
			.setter_data = NULL
		},
		{
			.name        = NULL
		}
	};
	static TpDBusPropertiesMixinIfaceImpl prop_interfaces[] = {
		{
			.name   = TP_IFACE_AUTHENTICATION_TLS_CERTIFICATE,
			.getter = tp_dbus_properties_mixin_getter_gobject_properties,
			.setter = NULL,
			.props  = props
		},
		{
			.name   = NULL
		}
	};
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	GParamSpec *ps;

	SIPE_DEBUG_INFO_NOFORMAT("SipeTLSCertificate::class_init");

	klass->dbus_props_class.interfaces = prop_interfaces;

	object_class->constructed      = sipe_tls_certificate_constructed;
	object_class->finalize         = sipe_tls_certificate_finalize;
	object_class->get_property     = certificate_get_property;

	ps = g_param_spec_string("object-path",
				 "D-Bus object path",
				 "The D-Bus object path used for this object on the bus.",
				 NULL,
				 G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	g_object_class_install_property(object_class,
					CERTIFICATE_PROP_OBJECT_PATH,
					ps);

	ps = g_param_spec_uint("state",
			       "State of this certificate",
			       "The state of this TLS certificate.",
			       SIPE_TLS_CERTIFICATE_PENDING,
			       SIPE_TLS_CERTIFICATE_ACCEPTED,
			       SIPE_TLS_CERTIFICATE_PENDING,
			       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	g_object_class_install_property(object_class,
					CERTIFICATE_PROP_STATE,
					ps);

	ps = g_param_spec_string("certificate-type",
				 "The certificate type",
				 "The type of this certificate.",
				 NULL,
				 G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	g_object_class_install_property(object_class,
					CERTIFICATE_PROP_TYPE,
					ps);

	ps = g_param_spec_boxed("certificate-chain-data",
				"The certificate chain data",
				"The raw DER-encoded trust chain of this certificate.",
				TP_ARRAY_TYPE_UCHAR_ARRAY_LIST,
				G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	g_object_class_install_property(object_class,
					CERTIFICATE_PROP_CHAIN_DATA, ps);

	tp_dbus_properties_mixin_class_init(object_class,
					    G_STRUCT_OFFSET(SipeTLSCertificateClass, dbus_props_class));
}

static void sipe_tls_certificate_init(SIPE_UNUSED_PARAMETER SipeTLSCertificate *self)
{
	SIPE_DEBUG_INFO_NOFORMAT("SipeTLSCertificate::init");
}

/*
 * TLS Certificate class - interface implementation
 */
static void tls_certificate_accept(TpSvcAuthenticationTLSCertificate *certificate,
				   DBusGMethodInvocation *context)
{
	SipeTLSCertificate *self = SIPE_TLS_CERTIFICATE(certificate);

	SIPE_DEBUG_INFO_NOFORMAT("SipeTLSCertificate::accept");

	if (self->state != SIPE_TLS_CERTIFICATE_PENDING) {
		GError error = {
			TP_ERROR,
			TP_ERROR_INVALID_ARGUMENT,
			"Calling Accept() on a certificate with state != PENDING "
			"doesn't make sense."
			};

		dbus_g_method_return_error(context, &error);
		return;
	}

	self->state = SIPE_TLS_CERTIFICATE_ACCEPTED;
	tp_svc_authentication_tls_certificate_emit_accepted(self);

	tp_svc_authentication_tls_certificate_return_from_accept(context);
}

static void tls_certificate_reject(TpSvcAuthenticationTLSCertificate *certificate,
				   const GPtrArray *rejections,
				   DBusGMethodInvocation *context)
{
	SipeTLSCertificate *self = SIPE_TLS_CERTIFICATE(certificate);

	SIPE_DEBUG_INFO_NOFORMAT("SipeTLSCertificate::reject");

	if (self->state != SIPE_TLS_CERTIFICATE_PENDING) {
		GError error = {
			TP_ERROR,
			TP_ERROR_INVALID_ARGUMENT,
			"Calling Reject() on a certificate with state != PENDING "
			"doesn't make sense."
		};

		dbus_g_method_return_error(context, &error);
		return;
	}

	self->state = SIPE_TLS_CERTIFICATE_REJECTED;

	tp_svc_authentication_tls_certificate_emit_rejected(self, rejections);

	tp_svc_authentication_tls_certificate_return_from_reject(context);
}

static void tls_certificate_iface_init(gpointer g_iface,
				       SIPE_UNUSED_PARAMETER gpointer iface_data)
{
	TpSvcAuthenticationTLSCertificateClass *klass = g_iface;

#define IMPLEMENT(x) \
	tp_svc_authentication_tls_certificate_implement_##x(	\
		klass, tls_certificate_##x)
	IMPLEMENT(accept);
	IMPLEMENT(reject);
#undef IMPLEMENT
}

static void append_certificate_der(GPtrArray *certificates,
				   GByteArray *der)
{
	GArray *array = g_array_sized_new(FALSE,
					  FALSE,
					  sizeof(guchar),
					  der->len);
	array = g_array_append_vals(array, der->data, der->len);
	g_byte_array_unref(der);

	g_ptr_array_add(certificates, array);
}

struct sipe_tls_info *sipe_telepathy_tls_info_new(const gchar *hostname,
						  GTlsCertificate *certificate)
{
	struct sipe_tls_info *tls_info = NULL;
	GByteArray *der = NULL;

	g_object_get(certificate, "certificate", &der, NULL);
	if (der) {
		GPtrArray *identities = g_ptr_array_new();

		tls_info = g_new0(struct sipe_tls_info, 1);
		tls_info->hostname             = g_strdup(hostname);

		/* build GStrv of identies */
		g_ptr_array_add(identities, g_strdup(hostname));
		g_ptr_array_add(identities, NULL);
		tls_info->reference_identities = (GStrv) g_ptr_array_free(identities,
									  FALSE);

		tls_info->cert_data = g_ptr_array_new_full(1,
							   (GDestroyNotify) g_array_unref);
		/* unrefs "der" */
		append_certificate_der(tls_info->cert_data, der);

		/* will be unref'd in loop */
		g_object_ref(certificate);
		while (certificate) {
			GTlsCertificate *issuer = NULL;

			g_object_get(certificate, "issuer", &issuer, NULL);
			g_object_unref(certificate);

			/* add issuer certificate */
			if (issuer) {
				g_object_get(certificate, "certificate", &der, NULL);
				/* unrefs "der" */
				if (der)
					append_certificate_der(tls_info->cert_data, der);
			}

			/* walk up the chain */
			certificate = issuer;
		}
	}

	return(tls_info);
}

void sipe_telepathy_tls_info_free(struct sipe_tls_info *tls_info)
{
	g_object_unref(tls_info->certificate);
	g_free(tls_info->hostname);
	g_free(tls_info->cert_path);
	g_ptr_array_unref(tls_info->cert_data);
	g_strfreev(tls_info->reference_identities);
	g_free(tls_info);
}

/* create new tls certificate object */
void sipe_telepathy_tls_verify_async(GObject *connection,
				     struct sipe_tls_info *tls_info,
				     GAsyncReadyCallback callback,
				     gpointer user_data)
{
	/* property "connection" required by TpBaseChannel */
	SipeTLSChannel *channel = g_object_new(SIPE_TYPE_TLS_CHANNEL,
					       "connection", connection,
					       NULL);
	TpBaseChannel *base = TP_BASE_CHANNEL(channel);
	SipeTLSCertificate *certificate = g_object_new(SIPE_TYPE_TLS_CERTIFICATE,
						       NULL);
	TpDBusDaemon *daemon = tp_dbus_daemon_dup(NULL);

	tls_info->certificate = certificate;
	certificate->tls_info = tls_info;

	tp_base_channel_register(base);
	tls_info->cert_path = g_strdup_printf("%s/TLSCertificateObject",
					      tp_base_channel_get_object_path(base));

	/* register the certificate on the bus */
	tp_dbus_daemon_register_object(daemon,
				       tls_info->cert_path,
				       certificate);
	g_object_unref(daemon);

	channel_new_certificate(connection,
				tls_info,
				channel,
				callback,
				user_data);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
