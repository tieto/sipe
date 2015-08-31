/**
 * @file telepathy-connection.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2012-2015 SIPE Project <http://sipe.sourceforge.net/>
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
#include <sys/stat.h>

#include <glib-object.h>
#include <glib/gstdio.h>
#include <telepathy-glib/base-connection.h>
#include <telepathy-glib/base-protocol.h>
#include <telepathy-glib/contacts-mixin.h>
#include <telepathy-glib/handle-repo-dynamic.h>
#include <telepathy-glib/presence-mixin.h>
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
	TpDBusPropertiesMixinClass properties_mixin;
	TpContactsMixinClass contacts_mixin;
	TpPresenceMixinClass presence_mixin;
} SipeConnectionClass;

typedef struct _SipeConnection {
	TpBaseConnection parent;
	TpContactsMixinClass contacts_mixin;
	TpPresenceMixin presence_mixin;

	/* channel managers */
	TpSimplePasswordManager *password_manager;
	struct _SipeContactList *contact_list;
	struct _SipeTLSManager  *tls_manager;

	struct sipe_backend_private private;
	gchar *account;
	gchar *login;
	gchar *password;
	gchar *server;
	gchar *port;
	guint  transport;
	guint  authentication_type;
	gchar *user_agent;
	gchar *authentication;
	gboolean sso;
	gboolean dont_publish;
	gboolean is_disconnecting;

	GPtrArray *contact_info_fields;
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
static void init_aliasing (gpointer, gpointer);
G_DEFINE_TYPE_WITH_CODE(SipeConnection,
			sipe_connection,
			TP_TYPE_BASE_CONNECTION,
			G_IMPLEMENT_INTERFACE(TP_TYPE_SVC_CONNECTION_INTERFACE_ALIASING,
					      init_aliasing);
			G_IMPLEMENT_INTERFACE(TP_TYPE_SVC_CONNECTION_INTERFACE_AVATARS,
					      sipe_telepathy_avatars_iface_init);
			G_IMPLEMENT_INTERFACE(TP_TYPE_SVC_CONNECTION_INTERFACE_CONTACTS,
					      tp_contacts_mixin_iface_init);
			G_IMPLEMENT_INTERFACE(TP_TYPE_SVC_CONNECTION_INTERFACE_CONTACT_GROUPS,
					      tp_base_contact_list_mixin_groups_iface_init);
			G_IMPLEMENT_INTERFACE(TP_TYPE_SVC_CONNECTION_INTERFACE_CONTACT_INFO,
					      sipe_telepathy_contact_info_iface_init);
			G_IMPLEMENT_INTERFACE(TP_TYPE_SVC_CONNECTION_INTERFACE_CONTACT_LIST,
					      tp_base_contact_list_mixin_list_iface_init);
			G_IMPLEMENT_INTERFACE(TP_TYPE_SVC_CONNECTION_INTERFACE_PRESENCE,
					      tp_presence_mixin_iface_init);
			G_IMPLEMENT_INTERFACE(TP_TYPE_SVC_CONNECTION_INTERFACE_SIMPLE_PRESENCE,
					      tp_presence_mixin_simple_presence_iface_init);
			G_IMPLEMENT_INTERFACE(TP_TYPE_SVC_DBUS_PROPERTIES,
					      tp_dbus_properties_mixin_iface_init);
)


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
	struct sipe_core_public *sipe_public;
	const gchar *errmsg;

	sipe_public = sipe_core_allocate(self->account,
					 self->sso,
					 self->login,
					 self->password,
					 NULL, /* @TODO: email     */
					 NULL, /* @TODO: email_url */
					 &errmsg);

	SIPE_DEBUG_INFO("connect_to_core: created %p", sipe_public);

	if (sipe_public) {
		struct sipe_backend_private *telepathy_private = &self->private;

		/* initialize backend private data */
		sipe_public->backend_private    = telepathy_private;
		telepathy_private->public       = sipe_public;
		telepathy_private->contact_list = self->contact_list;
		telepathy_private->connection   = self;
		telepathy_private->activity     = SIPE_ACTIVITY_UNSET;
		telepathy_private->cache_dir    = g_build_path(G_DIR_SEPARATOR_S,
							       g_get_user_cache_dir(),
							       "telepathy",
							       "sipe",
							       self->account,
							       NULL);
		telepathy_private->message      = NULL;
		telepathy_private->tls_manager  = self->tls_manager;
		telepathy_private->transport    = NULL;
		telepathy_private->ipaddress    = NULL;

		/* make sure cache directory exists */
		if (!g_file_test(telepathy_private->cache_dir,
				 G_FILE_TEST_IS_DIR) &&
		    (g_mkdir_with_parents(telepathy_private->cache_dir,
					  S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)
		     == 0))
			SIPE_DEBUG_INFO("connect_to_core: created cache directory %s",
					telepathy_private->cache_dir);

		SIPE_CORE_FLAG_UNSET(DONT_PUBLISH);
		if (self->dont_publish)
			SIPE_CORE_FLAG_SET(DONT_PUBLISH);

		sipe_core_transport_sip_connect(sipe_public,
						self->transport,
						self->authentication_type,
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

	if (password == NULL) {
		SIPE_DEBUG_ERROR("password_manager_cb: failed: %s",
				 error ? error->message : "UNKNOWN");

		if (base->status != TP_CONNECTION_STATUS_DISCONNECTED) {
			tp_base_connection_disconnect_with_dbus_error(base,
								      error ? tp_error_get_dbus_name(error->code) : "",
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

	/* map option list to flags - default is automatic */
	self->authentication_type = SIPE_AUTHENTICATION_TYPE_AUTOMATIC;
	if (sipe_strequal(self->authentication, "ntlm")) {
		SIPE_DEBUG_INFO_NOFORMAT("start_connecting: NTLM selected");
		self->authentication_type = SIPE_AUTHENTICATION_TYPE_NTLM;
	} else
#ifdef HAVE_GSSAPI_GSSAPI_H
	if (sipe_strequal(self->authentication, "krb5")) {
		SIPE_DEBUG_INFO_NOFORMAT("start_connecting: KRB5 selected");
		self->authentication_type = SIPE_AUTHENTICATION_TYPE_KERBEROS;
	} else
#endif
	if (sipe_strequal(self->authentication, "tls-dsk")) {
		SIPE_DEBUG_INFO_NOFORMAT("start_connecting: TLS-DSK selected");
		self->authentication_type = SIPE_AUTHENTICATION_TYPE_TLS_DSK;
	}

	/* Only ask for a password when required */
	if (!sipe_core_transport_sip_requires_password(self->authentication_type,
						       self->sso) ||
	    (self->password && strlen(self->password)))
		rc = connect_to_core(self, error);
	else {
		SIPE_DEBUG_INFO_NOFORMAT("SipeConnection::start_connecting: requesting password from user");
		tp_simple_password_manager_prompt_async(self->password_manager,
							password_manager_cb,
							self);
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

	g_free(telepathy_private->message);
	telepathy_private->message   = NULL;

	g_free(telepathy_private->cache_dir);
	telepathy_private->cache_dir = NULL;

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

	self->contact_list = sipe_telepathy_contact_list_new(base);
	g_ptr_array_add(channel_managers, self->contact_list);

	self->password_manager = tp_simple_password_manager_new(base);
	g_ptr_array_add(channel_managers, self->password_manager);

	g_ptr_array_add(channel_managers, sipe_telepathy_search_new(base));

	self->tls_manager = sipe_telepathy_tls_new(base);
	g_ptr_array_add(channel_managers, self->tls_manager);

	return(channel_managers);
}

static void aliasing_fill_contact_attributes(GObject *object,
					     const GArray *contacts,
					     GHashTable *attributes)
{
	SipeConnection *self = SIPE_CONNECTION(object);
	guint i;

	for (i = 0; i < contacts->len; i++) {
		TpHandle contact = g_array_index(contacts, guint, i);

		tp_contacts_mixin_set_contact_attribute(attributes,
							contact,
							TP_TOKEN_CONNECTION_INTERFACE_ALIASING_ALIAS,
							tp_g_value_slice_new_string(
								sipe_telepathy_buddy_get_alias(self->contact_list,
											       contact)));
	}
}

static void avatars_fill_contact_attributes(GObject *object,
					    const GArray *contacts,
					    GHashTable *attributes)
{
	SipeConnection *self = SIPE_CONNECTION(object);
	guint i;

	for (i = 0; i < contacts->len; i++) {
		TpHandle contact = g_array_index(contacts, guint, i);
		const gchar *hash = sipe_telepathy_buddy_get_hash(self->contact_list,
								  contact);

		if (!hash) hash = "";
		tp_contacts_mixin_set_contact_attribute(attributes,
							contact,
							TP_IFACE_CONNECTION_INTERFACE_AVATARS"/token",
							tp_g_value_slice_new_string(hash));
	}
}

static void contact_info_properties_getter(GObject *object,
					   SIPE_UNUSED_PARAMETER GQuark interface,
					   GQuark name,
					   GValue *value,
					   gpointer getter_data)
{
	GQuark fields = g_quark_from_static_string("SupportedFields");

	if (name == fields)
		g_value_set_boxed(value,
				  SIPE_CONNECTION(object)->contact_info_fields);
	else
		g_value_set_uint(value,
				 GPOINTER_TO_UINT(getter_data));
}

static void sipe_connection_constructed(GObject *object)
{
	SipeConnection *self   = SIPE_CONNECTION(object);
	TpBaseConnection *base = TP_BASE_CONNECTION(object);
	void (*chain_up)(GObject *) = G_OBJECT_CLASS(sipe_connection_parent_class)->constructed;

	if (chain_up)
		chain_up(object);

	tp_contacts_mixin_init(object,
			       G_STRUCT_OFFSET(SipeConnection, contacts_mixin));
	tp_base_connection_register_with_contacts_mixin(base);

	tp_base_contact_list_mixin_register_with_contacts_mixin(base);

	tp_contacts_mixin_add_contact_attributes_iface(object,
						       TP_IFACE_CONNECTION_INTERFACE_ALIASING,
						       aliasing_fill_contact_attributes);
	tp_contacts_mixin_add_contact_attributes_iface(object,
						       TP_IFACE_CONNECTION_INTERFACE_AVATARS,
						       avatars_fill_contact_attributes);

	tp_presence_mixin_init(object,
			       G_STRUCT_OFFSET(SipeConnection,
					       presence_mixin));
	tp_presence_mixin_simple_presence_register_with_contacts_mixin(object);

	self->contact_info_fields = sipe_telepathy_contact_info_fields();
}

static void sipe_connection_finalize(GObject *object)
{
	SipeConnection *self = SIPE_CONNECTION(object);

	SIPE_DEBUG_INFO_NOFORMAT("SipeConnection::finalize");

	tp_contacts_mixin_finalize(object);
	tp_presence_mixin_finalize(object);
	g_boxed_free(TP_ARRAY_TYPE_FIELD_SPECS, self->contact_info_fields);

	g_free(self->authentication);
	g_free(self->user_agent);
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
static const gchar *interfaces_always_present[] = {
	/* @TODO */
	TP_IFACE_CONNECTION_INTERFACE_ALIASING,
	TP_IFACE_CONNECTION_INTERFACE_AVATARS,
	TP_IFACE_CONNECTION_INTERFACE_CONTACT_GROUPS,
	TP_IFACE_CONNECTION_INTERFACE_CONTACT_INFO,
	TP_IFACE_CONNECTION_INTERFACE_CONTACT_LIST,
	TP_IFACE_CONNECTION_INTERFACE_CONTACTS,
	TP_IFACE_CONNECTION_INTERFACE_PRESENCE,
	TP_IFACE_CONNECTION_INTERFACE_REQUESTS,
	TP_IFACE_CONNECTION_INTERFACE_SIMPLE_PRESENCE,
	NULL
};

static void sipe_connection_class_init(SipeConnectionClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);
	TpBaseConnectionClass *base_class = TP_BASE_CONNECTION_CLASS(klass);
	static TpDBusPropertiesMixinIfaceImpl prop_interfaces[] = {
		{
			/* 0 */
			.name   = TP_IFACE_CONNECTION_INTERFACE_CONTACT_INFO,
			.getter = contact_info_properties_getter,
			.setter = NULL,
		},
		{
			/* LAST! */
			.name   = NULL,
		}
	};

	/* initalize non-constant fields */
	prop_interfaces[0].props = sipe_telepathy_contact_info_props();

	SIPE_DEBUG_INFO_NOFORMAT("SipeConnection::class_init");

	object_class->constructed = sipe_connection_constructed;
	object_class->finalize    = sipe_connection_finalize;

	base_class->create_handle_repos     = create_handle_repos;
	base_class->start_connecting        = start_connecting;
	base_class->shut_down               = shut_down;
	base_class->create_channel_managers = create_channel_managers;

	base_class->interfaces_always_present = interfaces_always_present;

	klass->properties_mixin.interfaces = prop_interfaces;
	tp_dbus_properties_mixin_class_init(object_class,
					    G_STRUCT_OFFSET(SipeConnectionClass,
							    properties_mixin));
	tp_contacts_mixin_class_init(object_class,
				     G_STRUCT_OFFSET(SipeConnectionClass,
						     contacts_mixin));
	sipe_telepathy_status_init(object_class,
				   G_STRUCT_OFFSET(SipeConnectionClass,
						   presence_mixin));
	tp_presence_mixin_simple_presence_init_dbus_properties(object_class);
	tp_base_contact_list_mixin_class_init(base_class);
}

static void sipe_connection_init(SIPE_UNUSED_PARAMETER SipeConnection *self)
{
	SIPE_DEBUG_INFO_NOFORMAT("SipeConnection::init");
}

/*
 * Connection class - interface implementation
 *
 * Contact aliases
 */
static void get_alias_flags(TpSvcConnectionInterfaceAliasing *aliasing,
			    DBusGMethodInvocation *context)
{
	TpBaseConnection *base = TP_BASE_CONNECTION(aliasing);

	TP_BASE_CONNECTION_ERROR_IF_NOT_CONNECTED(base, context);
	SIPE_DEBUG_INFO_NOFORMAT("SipeConnection::get_alias_flags called");

	tp_svc_connection_interface_aliasing_return_from_get_alias_flags(context,
									 TP_CONNECTION_ALIAS_FLAG_USER_SET);
}

static void get_aliases(TpSvcConnectionInterfaceAliasing *aliasing,
			const GArray *contacts,
			DBusGMethodInvocation *context)
{
	SipeConnection *self            = SIPE_CONNECTION(aliasing);
	TpBaseConnection *base          = TP_BASE_CONNECTION(aliasing);
	TpHandleRepoIface *contact_repo = tp_base_connection_get_handles(base,
									 TP_HANDLE_TYPE_CONTACT);
	GError *error                   = NULL;
	GHashTable *result;
	guint i;

	TP_BASE_CONNECTION_ERROR_IF_NOT_CONNECTED(base, context);
	SIPE_DEBUG_INFO_NOFORMAT("SipeConnection::get_aliases called");

	if (!tp_handles_are_valid(contact_repo, contacts, FALSE, &error)) {
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return;
	}

	result = g_hash_table_new(g_direct_hash, g_direct_equal);

	for (i = 0; i < contacts->len; i++) {
		TpHandle contact   = g_array_index(contacts, TpHandle, i);
		const gchar *alias = sipe_telepathy_buddy_get_alias(self->contact_list,
								    contact);
		g_hash_table_insert(result,
				    GUINT_TO_POINTER(contact),
				    (gchar *) alias);
	}

	tp_svc_connection_interface_aliasing_return_from_get_aliases(context,
								     result);
	g_hash_table_unref(result);
}

static void request_aliases(TpSvcConnectionInterfaceAliasing *aliasing,
			    const GArray *contacts,
			    DBusGMethodInvocation *context)
{
	SipeConnection *self            = SIPE_CONNECTION(aliasing);
	TpBaseConnection *base          = TP_BASE_CONNECTION(aliasing);
	TpHandleRepoIface *contact_repo = tp_base_connection_get_handles(base,
									 TP_HANDLE_TYPE_CONTACT);
	GError *error                   = NULL;
	GPtrArray *result;
	gchar **strings;
	guint i;

	TP_BASE_CONNECTION_ERROR_IF_NOT_CONNECTED(base, context);
	SIPE_DEBUG_INFO_NOFORMAT("SipeConnection::request_aliases called");

	if (!tp_handles_are_valid(contact_repo, contacts, FALSE, &error)) {
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return;
	}

	result = g_ptr_array_sized_new(contacts->len + 1);

	for (i = 0; i < contacts->len; i++) {
		TpHandle contact   = g_array_index(contacts, TpHandle, i);
		const gchar *alias = sipe_telepathy_buddy_get_alias(self->contact_list,
								    contact);
		g_ptr_array_add(result, (gchar *) alias);
	}

	g_ptr_array_add(result, NULL);
	strings = (gchar **) g_ptr_array_free(result, FALSE);

	tp_svc_connection_interface_aliasing_return_from_request_aliases(context,
									 (const gchar **) strings);
	g_free(strings);
}

static void set_aliases(TpSvcConnectionInterfaceAliasing *aliasing,
			GHashTable *aliases,
			DBusGMethodInvocation *context)
{
	SipeConnection *self            = SIPE_CONNECTION(aliasing);
	TpBaseConnection *base          = TP_BASE_CONNECTION(aliasing);
	TpHandleRepoIface *contact_repo = tp_base_connection_get_handles(base,
									 TP_HANDLE_TYPE_CONTACT);
	GHashTableIter iter;
	gpointer key, value;

	SIPE_DEBUG_INFO_NOFORMAT("SipeConnection::set_aliases called");

	g_hash_table_iter_init(&iter, aliases);

	while (g_hash_table_iter_next(&iter, &key, NULL)) {
		GError *error = NULL;

		if (!tp_handle_is_valid(contact_repo,
					GPOINTER_TO_UINT(key),
					&error)) {
			dbus_g_method_return_error(context, error);
			g_error_free(error);
			return;
		}
	}

	g_hash_table_iter_init(&iter, aliases);

	while (g_hash_table_iter_next(&iter, &key, &value)) {
		sipe_telepathy_buddy_set_alias(self->contact_list,
					       GPOINTER_TO_UINT(key),
					       value);
	}

	tp_svc_connection_interface_aliasing_return_from_set_aliases(context);
}

static void init_aliasing(gpointer iface,
			  SIPE_UNUSED_PARAMETER gpointer iface_data)
{
	TpSvcConnectionInterfaceAliasingClass *klass = iface;

	SIPE_DEBUG_INFO_NOFORMAT("SipeConnection::init_aliasing called");

	tp_svc_connection_interface_aliasing_implement_get_alias_flags(klass, get_alias_flags);
	tp_svc_connection_interface_aliasing_implement_request_aliases(klass, request_aliases);
	tp_svc_connection_interface_aliasing_implement_get_aliases(klass, get_aliases);
	tp_svc_connection_interface_aliasing_implement_set_aliases(klass, set_aliases);
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
	gboolean boolean_value;
	gboolean valid;

	SIPE_DEBUG_INFO_NOFORMAT("sipe_telepathy_connection_new");

	/* initialize private fields */
	conn->is_disconnecting = FALSE;

	/* account is required field */
	conn->account = g_strdup(tp_asv_get_string(params, "account"));

	/* if login is not specified, account value will be used in connect_to_core */
	value = tp_asv_get_string(params, "login");
	if (value && strlen(value))
		conn->login = g_strdup(value);
	else
		conn->login = NULL;

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

	/* User-Agent: override */
	value = tp_asv_get_string(params, "useragent");
	if (value && strlen(value))
		conn->user_agent = g_strdup(value);
	else
		conn->user_agent = NULL;

	/* authentication type */
	value = tp_asv_get_string(params, "authentication");
	if (value && strlen(value) && strcmp(value, "ntlm"))
		conn->authentication = g_strdup(value);
	else
		conn->authentication = NULL; /* NTLM is default */

	/* Single Sign-On */
	boolean_value = tp_asv_get_boolean(params, "single-sign-on", &valid);
	if (valid)
		conn->sso = boolean_value;
	else
		conn->sso = FALSE;

	/* Don't publish my calendar information */
	boolean_value = tp_asv_get_boolean(params, "don't-publish-calendar", &valid);
	if (valid)
		conn->dont_publish = boolean_value;
	else
		conn->dont_publish = FALSE;

	return(TP_BASE_CONNECTION(conn));
}

void sipe_telepathy_connection_alias_updated(TpBaseConnection *connection,
					     guint contact,
					     const gchar *alias)
{
	GPtrArray *aliases = g_ptr_array_sized_new(1);
	GValueArray *pair  = g_value_array_new(2);

	g_value_array_append(pair, NULL);
	g_value_array_append(pair, NULL);
	g_value_init(pair->values + 0, G_TYPE_UINT);
	g_value_init(pair->values + 1, G_TYPE_STRING);
	g_value_set_uint(pair->values + 0, contact);
	g_value_set_string(pair->values + 1, alias);
	g_ptr_array_add(aliases, pair);

	tp_svc_connection_interface_aliasing_emit_aliases_changed(SIPE_CONNECTION(connection),
								  aliases);

	g_ptr_array_unref(aliases);
	g_value_array_free(pair);
}

struct sipe_backend_private *sipe_telepathy_connection_private(GObject *object)
{
	SipeConnection *self = SIPE_CONNECTION(object);
	/* connected to core already? */
	if (self->private.public)
		return(&self->private);
	else
		return(NULL);
}

/*
 * Backend adaptor functions
 */
void sipe_backend_connection_completed(struct sipe_core_public *sipe_public)
{
	SipeConnection *self   = SIPE_PUBLIC_TO_CONNECTION;
	TpBaseConnection *base = TP_BASE_CONNECTION(self);

	/* we are only allowed to do this once */
	if (base->status != TP_CONNECTION_STATUS_CONNECTED)
		tp_base_connection_change_status(base,
						 TP_CONNECTION_STATUS_CONNECTED,
						 TP_CONNECTION_STATUS_REASON_REQUESTED);
}

void sipe_backend_connection_error(struct sipe_core_public *sipe_public,
				   sipe_connection_error error,
				   const gchar *msg)
{
	SipeConnection *self   = SIPE_PUBLIC_TO_CONNECTION;
	TpBaseConnection *base = TP_BASE_CONNECTION(self);
	GHashTable *details    = tp_asv_new("server-message", G_TYPE_STRING, msg,
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

const gchar *sipe_backend_setting(struct sipe_core_public *sipe_public,
				  sipe_setting type)
{
	SipeConnection *self = SIPE_PUBLIC_TO_CONNECTION;
	const gchar *value;

	switch (type) {
	case SIPE_SETTING_USER_AGENT:
		value = self->user_agent;
		break;
	default:
		/* @TODO: update when settings are implemented */
		value = NULL;
		break;
	}

	return(value);
}


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
