/**
 * @file telepathy-search.c
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

#include <glib-object.h>
#include <telepathy-glib/svc-channel.h>
#include <telepathy-glib/telepathy-glib.h>

#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-core.h"

#include "telepathy-private.h"

G_BEGIN_DECLS
/*
 * Search Manager class - data structures
 */
typedef struct _SipeSearchManagerClass {
	GObjectClass parent_class;
} SipeSearchManagerClass;

typedef struct _SipeSearchManager {
	GObject parent;

	GObject *connection;

	GHashTable *channels;
} SipeSearchManager;

/*
 * Search Manager class - type macros
 */
/* telepathy-private.h: #define SIPE_TYPE_SEARCH_MANAGER ... */
#define SIPE_SEARCH_MANAGER(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), SIPE_TYPE_SEARCH_MANAGER, \
				    SipeSearchManager))

/*
 * Search Channel class - data structures
 */
typedef struct _SipeSearchChannelClass {
	TpBaseChannelClass parent_class;
} SipeSearchChannelClass;

typedef struct _SipeSearchChannel {
        TpBaseChannel parent;

	GObject *connection;
} SipeSearchChannel;

/*
 * Search Channel class - type macros
 */
static GType sipe_search_channel_get_type(void) G_GNUC_CONST;
#define SIPE_TYPE_SEARCH_CHANNEL \
	(sipe_search_channel_get_type())
#define SIPE_SEARCH_CHANNEL(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), SIPE_TYPE_SEARCH_CHANNEL, \
				    SipeSearchChannel))
G_END_DECLS

/*
 * Search Manager class - type definition
 */
static void channel_manager_iface_init(gpointer, gpointer);
G_DEFINE_TYPE_WITH_CODE(SipeSearchManager,
			sipe_search_manager,
			G_TYPE_OBJECT,
			G_IMPLEMENT_INTERFACE(TP_TYPE_CHANNEL_MANAGER,
					      channel_manager_iface_init);
)

/*
 * Search Manager class - type definition
 */
static void contact_search_iface_init (gpointer, gpointer);
G_DEFINE_TYPE_WITH_CODE(SipeSearchChannel,
			sipe_search_channel,
			TP_TYPE_BASE_CHANNEL,
			G_IMPLEMENT_INTERFACE(TP_TYPE_SVC_CHANNEL_TYPE_CONTACT_SEARCH,
					      contact_search_iface_init);
)

/*
 * Search Manager class - instance methods
 */
static void sipe_search_manager_constructed(GObject *object)
{
	SipeSearchManager *self     = SIPE_SEARCH_MANAGER(object);
	void (*chain_up)(GObject *) = G_OBJECT_CLASS(sipe_search_manager_parent_class)->constructed;

	if (chain_up)
		chain_up(object);

	self->channels = g_hash_table_new(g_direct_hash, g_direct_equal);
}

static void sipe_search_manager_dispose(GObject *object)
{
	SipeSearchManager *self     = SIPE_SEARCH_MANAGER(object);
	void (*chain_up)(GObject *) = G_OBJECT_CLASS(sipe_search_manager_parent_class)->constructed;

	tp_clear_pointer(&self->channels, g_hash_table_unref);
	tp_clear_object(&self->connection);

	if (chain_up)
		chain_up(object);
}

/*
 * Search Manager class - type implementation
 */
static void sipe_search_manager_class_init(SipeSearchManagerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);

	SIPE_DEBUG_INFO_NOFORMAT("SipeSearchManager::class_init");

	object_class->constructed  = sipe_search_manager_constructed;
	object_class->dispose      = sipe_search_manager_dispose;
}

static void sipe_search_manager_init(SIPE_UNUSED_PARAMETER SipeSearchManager *self)
{
	SIPE_DEBUG_INFO_NOFORMAT("SipeSearchManager::init");
}

/*
 * Search Manager class - interface implementation
 *
 * Channel Manager
 */
static void foreach_channel(TpChannelManager *manager,
			    TpExportableChannelFunc func,
			    gpointer user_data)
{
	SipeSearchManager *self = SIPE_SEARCH_MANAGER(manager);
	GHashTableIter iter;
	gpointer chan;

	SIPE_DEBUG_INFO_NOFORMAT("SipeSearchManager::foreach_channel");

	g_hash_table_iter_init(&iter, self->channels);
	while (g_hash_table_iter_next(&iter, &chan, NULL))
		func(chan, user_data);
}

static void type_foreach_channel_class(GType type,
				       TpChannelManagerTypeChannelClassFunc func,
				       gpointer user_data)
{
	static const gchar *const no_props[] = {
		NULL
	};
	GHashTable *table = g_hash_table_new_full(g_str_hash, g_str_equal,
						  NULL,
						  (GDestroyNotify) tp_g_value_slice_free);

	SIPE_DEBUG_INFO_NOFORMAT("SipeSearchManager::type_foreach_channel_class");

	g_hash_table_insert(table,
			    TP_IFACE_CHANNEL ".ChannelType",
			    tp_g_value_slice_new_string(TP_IFACE_CHANNEL_TYPE_CONTACT_SEARCH));
	func(type, table, no_props, user_data);
	g_hash_table_unref(table);
}

static void search_channel_closed_cb(SipeSearchChannel *channel,
				     SipeSearchManager *self)
{
	tp_channel_manager_emit_channel_closed_for_object(self,
							  (TpExportableChannel *) channel);
	g_hash_table_remove(self->channels, channel);
}

static GObject *search_channel_new(GObject *connection);
static gboolean create_channel(TpChannelManager *manager,
			       gpointer request_token,
			       GHashTable *request_properties)
{
	SipeSearchManager *self = SIPE_SEARCH_MANAGER(manager);
	GObject *channel;
	GSList *request_tokens;

	SIPE_DEBUG_INFO_NOFORMAT("SipeSearchManager::create_channel");

	if (tp_strdiff(tp_asv_get_string(request_properties,
					 TP_IFACE_CHANNEL ".ChannelType"),
		       TP_IFACE_CHANNEL_TYPE_CONTACT_SEARCH))
		return(FALSE);

	/* create new search channel */
	channel = search_channel_new(self->connection);
	g_hash_table_insert(self->channels, channel, NULL);
	g_signal_connect(channel,
			 "closed",
			 (GCallback) search_channel_closed_cb,
			 self);

	/* publish new channel */
	request_tokens = g_slist_prepend(NULL, request_token);
	tp_channel_manager_emit_new_channel(self,
					    TP_EXPORTABLE_CHANNEL(channel),
					    request_tokens);
	g_slist_free(request_tokens);

	return(TRUE);
}

static void channel_manager_iface_init(gpointer g_iface,
				       SIPE_UNUSED_PARAMETER gpointer iface_data)
{
	TpChannelManagerIface *iface = g_iface;

	iface->foreach_channel            = foreach_channel;
	iface->type_foreach_channel_class = type_foreach_channel_class;
	iface->create_channel             = create_channel;
	iface->request_channel            = create_channel;
	/* Ensuring these channels doesn't really make much sense. */
	iface->ensure_channel             = NULL;
}

/* create new search manager object */
GObject *sipe_telepathy_search_new(TpBaseConnection *connection)
{
	SipeSearchManager *self = g_object_new(SIPE_TYPE_SEARCH_MANAGER, NULL);
	self->connection = g_object_ref(connection);
	return(G_OBJECT(self));
}

/*
 * Search Channel class - instance methods
 */
enum {
	CHANNEL_PROP_SEARCH_KEYS = 1,
	CHANNEL_LAST_PROP
};

static void get_property(GObject *object,
			 guint property_id,
			 GValue *value,
			 GParamSpec *pspec)
{
	switch (property_id)
	{
	case CHANNEL_PROP_SEARCH_KEYS: {
		/* vCard/Telepathy search field names */
		static const gchar const *search_keys[] = {
			"x-n-given",     /* First  */
			"x-n-family",    /* Last   */
			"email",         /* E-Mail */
			"x-org-name",    /* Company? */
			"x-adr-country", /* Country */
			NULL
		};
		g_value_set_boxed(value, search_keys);
	}
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
		break;
	}
}

static void fill_immutable_properties(TpBaseChannel *channel,
				      GHashTable *properties)
{
	TP_BASE_CHANNEL_CLASS(sipe_search_channel_parent_class)->fill_immutable_properties(channel,
											   properties);
	tp_dbus_properties_mixin_fill_properties_hash(G_OBJECT(channel),
						      properties,
						      TP_IFACE_CHANNEL_TYPE_CONTACT_SEARCH, "AvailableSearchKeys",
						      NULL);
}

static gchar *get_object_path_suffix(TpBaseChannel *base)
{
	return(g_strdup_printf ("SearchChannel_%p", base));
}

static GPtrArray *get_interfaces(TpBaseChannel *self)
{
	GPtrArray *interfaces = TP_BASE_CHANNEL_CLASS(sipe_search_channel_parent_class)->get_interfaces(self);
	return(interfaces);
}

static void sipe_search_channel_constructed(GObject *object)
{
	void (*chain_up)(GObject *) = G_OBJECT_CLASS(sipe_search_channel_parent_class)->constructed;

	if (chain_up)
		chain_up(object);
}

static void sipe_search_channel_finalize(GObject *object)
{
	SIPE_DEBUG_INFO_NOFORMAT("SipeSearchChannel::finalize");

	G_OBJECT_CLASS(sipe_search_channel_parent_class)->finalize(object);
}

/*
 * Search Channel class - type implementation
 */
static void sipe_search_channel_class_init(SipeSearchChannelClass *klass)
{
	static TpDBusPropertiesMixinPropImpl props[] = {
		{
			.name        = "AvailableSearchKeys",
			.getter_data = "available-search-keys",
			.setter_data = NULL
		},
		{
			.name        = NULL
		}
	};
	GObjectClass *object_class     = G_OBJECT_CLASS(klass);
	TpBaseChannelClass *base_class = TP_BASE_CHANNEL_CLASS(klass);
	GParamSpec *ps;

	SIPE_DEBUG_INFO_NOFORMAT("SipeSearchChannel::class_init");

	object_class->constructed      = sipe_search_channel_constructed;
	object_class->finalize         = sipe_search_channel_finalize;
	object_class->get_property     = get_property;

	base_class->channel_type       = TP_IFACE_CHANNEL_TYPE_CONTACT_SEARCH;
	base_class->target_handle_type = TP_HANDLE_TYPE_NONE;
	base_class->fill_immutable_properties = fill_immutable_properties;
	base_class->get_object_path_suffix    = get_object_path_suffix;
	base_class->interfaces         = NULL;
	base_class->get_interfaces     = get_interfaces;
	base_class->close              = tp_base_channel_destroyed;

	ps = g_param_spec_boxed("available-search-keys",
				"Available search keys",
				"The set of search keys supported by this channel",
				G_TYPE_STRV,
				G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
	g_object_class_install_property(object_class,
					CHANNEL_PROP_SEARCH_KEYS,
					ps);

	tp_dbus_properties_mixin_implement_interface(object_class,
						     TP_IFACE_QUARK_CHANNEL_TYPE_CONTACT_SEARCH,
						     tp_dbus_properties_mixin_getter_gobject_properties,
						     NULL,
						     props);
}

static void sipe_search_channel_init(SIPE_UNUSED_PARAMETER SipeSearchChannel *self)
{
	SIPE_DEBUG_INFO_NOFORMAT("SipeSearchChannel::init");
}

/*
 * Search Channel class - interface implementation
 *
 * Contact search
 */
static void search_channel_state(SipeSearchChannel *self,
				 gboolean completed)
{
	GHashTable *details = g_hash_table_new(g_str_hash, g_str_equal);
	tp_svc_channel_type_contact_search_emit_search_state_changed(self,
								     completed ?
								     TP_CHANNEL_CONTACT_SEARCH_STATE_COMPLETED :
								     TP_CHANNEL_CONTACT_SEARCH_STATE_IN_PROGRESS,
								     "",
								     details);
	g_hash_table_unref(details);
}

static void search_channel_search(TpSvcChannelTypeContactSearch *channel,
				  GHashTable *terms,
				  DBusGMethodInvocation *context)
{
	SipeSearchChannel *self = SIPE_SEARCH_CHANNEL(channel);
	struct sipe_backend_private *telepathy_private = sipe_telepathy_connection_private(self->connection);

	SIPE_DEBUG_INFO_NOFORMAT("SipeSearchChannel::search");
	{
		/* temporary debug */
		GHashTableIter iter;
		const gchar *key, *value;
		g_hash_table_iter_init(&iter, terms);
		while (g_hash_table_iter_next(&iter, (gpointer) &key, (gpointer) &value))
			SIPE_DEBUG_INFO("search: %s -> %s", key, value);
	}

	/* @TODO: we need a parameter to pass "self" into the search */
	sipe_core_buddy_search(telepathy_private->public,
			       g_hash_table_lookup(terms, "x-n-given"),
			       g_hash_table_lookup(terms, "x-n-family"),
			       g_hash_table_lookup(terms, "email"),
			       g_hash_table_lookup(terms, "x-org-name"),
			       g_hash_table_lookup(terms, "x-adr-country"));

	search_channel_state(self, FALSE);

	tp_svc_channel_type_contact_search_return_from_search(context);
}

static void contact_search_iface_init(gpointer g_iface,
				      SIPE_UNUSED_PARAMETER gpointer iface_data)
{
	TpSvcChannelTypeContactSearchClass *klass = g_iface;

	tp_svc_channel_type_contact_search_implement_search(klass, search_channel_search);
	/* we don't support stopping a search */
}

/* create new search channel object */
static GObject *search_channel_new(GObject *connection)
{
	/* property "connection" required by TpBaseChannel */
	SipeSearchChannel *self = g_object_new(SIPE_TYPE_SEARCH_CHANNEL,
					       "connection", connection,
					       NULL);

	self->connection = g_object_ref(connection);

	tp_base_channel_register(TP_BASE_CHANNEL(self));

	return(G_OBJECT(self));
}

/*
 * Backend adaptor functions
 */
struct sipe_backend_search_results *sipe_backend_search_results_start(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public)
{
	/* @TODO: we need a parameter to pass "self" into the search
	   return(self);
	 */
	return(NULL);
}

void sipe_backend_search_results_add(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				     SIPE_UNUSED_PARAMETER struct sipe_backend_search_results *results,
				     SIPE_UNUSED_PARAMETER const gchar *uri,
				     SIPE_UNUSED_PARAMETER const gchar *name,
				     SIPE_UNUSED_PARAMETER const gchar *company,
				     SIPE_UNUSED_PARAMETER const gchar *country,
				     SIPE_UNUSED_PARAMETER const gchar *email)
{
	/* @TODO
	 * SipeSearchChannel *self = results;
	 * tp_svc_channel_type_contact_search_emit_search_result_received(self,
	 *                                                                results);
	 */
}

void sipe_backend_search_results_finalize(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					  SIPE_UNUSED_PARAMETER struct sipe_backend_search_results *results,
					  SIPE_UNUSED_PARAMETER const gchar *description,
					  SIPE_UNUSED_PARAMETER gboolean more)
{
	/* @TODO
	 * SipeSearchChannel *self = results;
	 * search_channel_state(self, FALSE);
	 */
}


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
