/**
 * @file telepathy-buddy.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2012-2017 SIPE Project <http://sipe.sourceforge.net/>
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
#include <glib/gstdio.h>
#include <telepathy-glib/base-connection.h>
#include <telepathy-glib/base-contact-list.h>
#include <telepathy-glib/telepathy-glib.h>

#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-core.h"

#include "telepathy-private.h"

#define SIPE_INFO_FIELD_MAX (SIPE_BUDDY_INFO_CUSTOM1_PHONE_DISPLAY + 1)

struct telepathy_buddy {
	const gchar *uri;   /* borrowed from contact_list->buddies key */
	GHashTable *groups; /* key: group name, value: buddy_entry */
                            /* keys are borrowed from contact_list->groups */
	TpHandle handle;
	/* includes alias as stored on the server */
	gchar *info[SIPE_INFO_FIELD_MAX];
	gchar *hash;        /* photo hash */
	guint activity;
};

struct telepathy_buddy_entry {
	struct telepathy_buddy *buddy; /* pointer to parent */
	const gchar *group;            /* borrowed from contact_list->groups key */
};

G_BEGIN_DECLS
/*
 * Contact List class - data structures
 */
typedef struct _SipeContactListClass {
	TpBaseContactListClass parent_class;
} SipeContactListClass;

typedef struct _SipeContactList {
	TpBaseContactList parent;

	TpBaseConnection *connection;
	TpHandleRepoIface *contact_repo;
	TpHandleSet *contacts;

	GHashTable *buddies;       /* key: SIP URI,    value: buddy */
	GHashTable *buddy_handles; /* key: TpHandle,   value: buddy */
	GHashTable *groups;        /* key: group name, value: buddy */

	gboolean initial_received;
} SipeContactList;

/*
 * Contact List class - type macros
 */
static GType sipe_contact_list_get_type(void) G_GNUC_CONST;
#define SIPE_TYPE_CONTACT_LIST \
	(sipe_contact_list_get_type())
#define SIPE_CONTACT_LIST(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), SIPE_TYPE_CONTACT_LIST, \
				    SipeContactList))
G_END_DECLS

/*
 * Contact List class - type definition
 */
static void contact_group_list_iface_init(TpContactGroupListInterface *);
G_DEFINE_TYPE_WITH_CODE(SipeContactList,
			sipe_contact_list,
			TP_TYPE_BASE_CONTACT_LIST,
			G_IMPLEMENT_INTERFACE (TP_TYPE_CONTACT_GROUP_LIST,
					       contact_group_list_iface_init);
)


/*
 * Contact List class - instance methods
 */
static TpHandleSet *dup_contacts(TpBaseContactList *contact_list)
{
	SipeContactList *self = SIPE_CONTACT_LIST(contact_list);
	return(tp_handle_set_copy(self->contacts));
}

static void dup_states(SIPE_UNUSED_PARAMETER TpBaseContactList *contact_list,
		       SIPE_UNUSED_PARAMETER TpHandle contact,
		       TpSubscriptionState *subscribe,
		       TpSubscriptionState *publish,
		       gchar **publish_request)
{
	/* @TODO */
	SIPE_DEBUG_INFO_NOFORMAT("SipeContactList::dup_states - NOT IMPLEMENTED");

	if (subscribe)
		*subscribe = TP_SUBSCRIPTION_STATE_YES;
	if (publish)
		*publish = TP_SUBSCRIPTION_STATE_YES;
	if (publish_request)
		*publish_request = g_strdup("");
}

static void sipe_contact_list_constructed(GObject *object)
{
	SipeContactList *self = SIPE_CONTACT_LIST(object);
	void (*chain_up)(GObject *) = G_OBJECT_CLASS(sipe_contact_list_parent_class)->constructed;

	if (chain_up)
		chain_up(object);

	g_object_get(self, "connection", &self->connection, NULL);
	self->contact_repo = tp_base_connection_get_handles(self->connection,
							    TP_HANDLE_TYPE_CONTACT);
	self->contacts     = tp_handle_set_new(self->contact_repo);
}

static void sipe_contact_list_dispose(GObject *object)
{
	SipeContactList *self = SIPE_CONTACT_LIST(object);
	void (*chain_up)(GObject *) = G_OBJECT_CLASS(sipe_contact_list_parent_class)->dispose;

	SIPE_DEBUG_INFO_NOFORMAT("SipeContactList::dispose");

	tp_clear_pointer(&self->contacts, tp_handle_set_destroy);
	tp_clear_object(&self->connection);
	/* NOTE: the order is important due to borrowing of keys! */
	tp_clear_pointer(&self->buddy_handles, g_hash_table_unref);
	tp_clear_pointer(&self->buddies, g_hash_table_unref);
	tp_clear_pointer(&self->groups, g_hash_table_unref);

	if (chain_up)
		chain_up(object);
}

/*
 * Contact List class - type implementation
 */
static void sipe_contact_list_class_init(SipeContactListClass *klass)
{
	GObjectClass *object_class         = G_OBJECT_CLASS(klass);
	TpBaseContactListClass *base_class = TP_BASE_CONTACT_LIST_CLASS(klass);

	SIPE_DEBUG_INFO_NOFORMAT("SipeContactList::class_init");

	object_class->constructed = sipe_contact_list_constructed;
	object_class->dispose     = sipe_contact_list_dispose;

	base_class->dup_contacts = dup_contacts;
	base_class->dup_states   = dup_states;
}

static void buddy_free(gpointer data);
static void sipe_contact_list_init(SIPE_UNUSED_PARAMETER SipeContactList *self)
{
	SIPE_DEBUG_INFO_NOFORMAT("SipeContactList::init");

	self->buddies       = g_hash_table_new_full(g_str_hash, g_str_equal,
						    g_free, buddy_free);
	self->buddy_handles = g_hash_table_new(g_direct_hash, g_direct_equal);
	self->groups        = g_hash_table_new_full(g_str_hash, g_str_equal,
						    g_free, NULL);

	self->initial_received = FALSE;
}

/*
 * Contact List class - interface implementation
 *
 * Contact groups
 */
static GStrv dup_groups(TpBaseContactList *contact_list)
{
	SipeContactList *self = SIPE_CONTACT_LIST(contact_list);
	GPtrArray *groups     = g_ptr_array_sized_new(
		g_hash_table_size(self->groups) + 1);
	GHashTableIter iter;
	gpointer name;

	SIPE_DEBUG_INFO_NOFORMAT("SipeContactList::dup_groups called");

	g_hash_table_iter_init(&iter, self->groups);
	while (g_hash_table_iter_next(&iter, &name, NULL))
		g_ptr_array_add(groups, g_strdup(name));
	g_ptr_array_add(groups, NULL);

	return((GStrv) g_ptr_array_free(groups, FALSE));
}

static TpHandleSet *dup_group_members(TpBaseContactList *contact_list,
				      const gchar *group_name)
{
	SipeContactList *self = SIPE_CONTACT_LIST(contact_list);
	TpHandleSet *members  = tp_handle_set_new(self->contact_repo);
	GHashTableIter iter;
	struct telepathy_buddy *buddy;

	SIPE_DEBUG_INFO_NOFORMAT("SipeContactList::dup_group_members called");

	g_hash_table_iter_init(&iter, self->buddies);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer) &buddy))
		if (g_hash_table_lookup(buddy->groups, group_name))
			tp_handle_set_add(members, buddy->handle);

	return(members);
}

static GStrv dup_contact_groups(TpBaseContactList *contact_list,
				TpHandle contact)
{
	SipeContactList *self         = SIPE_CONTACT_LIST(contact_list);
	GPtrArray *groups             = g_ptr_array_sized_new(
		g_hash_table_size(self->groups) + 1);
	struct telepathy_buddy *buddy = g_hash_table_lookup(self->buddy_handles,
							    GUINT_TO_POINTER(contact));

	SIPE_DEBUG_INFO_NOFORMAT("SipeContactList::dup_contact_groups called");

	if (buddy) {
		GHashTableIter iter;
		const gchar *group_name;

		g_hash_table_iter_init(&iter, buddy->groups);
		while (g_hash_table_iter_next(&iter,
					      (gpointer) &group_name,
					      NULL))
			g_ptr_array_add(groups, g_strdup(group_name));
	}
	g_ptr_array_add(groups, NULL);

	return((GStrv) g_ptr_array_free(groups, FALSE));
}

static void contact_group_list_iface_init(TpContactGroupListInterface *iface)
{
#define IMPLEMENT(x) iface->x = x
	IMPLEMENT(dup_groups);
	IMPLEMENT(dup_group_members);
	IMPLEMENT(dup_contact_groups);
#undef IMPLEMENT
}

/* create new contact list object */
SipeContactList *sipe_telepathy_contact_list_new(TpBaseConnection *connection)
{
	return(g_object_new(SIPE_TYPE_CONTACT_LIST,
			    "connection", connection,
			    NULL));
}

/* get & set alias for a contact  */
const gchar *sipe_telepathy_buddy_get_alias(SipeContactList *contact_list,
					    TpHandle contact)
{
	struct telepathy_buddy *buddy = g_hash_table_lookup(contact_list->buddy_handles,
							    GUINT_TO_POINTER(contact));
	if (!buddy)
		return(NULL);
	return(buddy->info[SIPE_BUDDY_INFO_DISPLAY_NAME]);
}

static void update_alias(struct telepathy_buddy *buddy,
			 const gchar *alias)
{
	if (buddy) {
		g_free(buddy->info[SIPE_BUDDY_INFO_DISPLAY_NAME]);
		buddy->info[SIPE_BUDDY_INFO_DISPLAY_NAME] = g_strdup(alias);
	}
}

void sipe_telepathy_buddy_set_alias(SipeContactList *contact_list,
				    const guint contact,
				    const gchar *alias)
{
	struct telepathy_buddy *buddy = g_hash_table_lookup(contact_list->buddy_handles,
							    GUINT_TO_POINTER(contact));
	update_alias(buddy, alias);

	/* tell core about the alias change */
	if (buddy) {
		struct sipe_backend_private *telepathy_private = sipe_telepathy_connection_private(G_OBJECT(contact_list->connection));
		sipe_core_group_set_alias(telepathy_private->public,
					  buddy->uri,
					  alias);
	}
}

/* get photo hash for a contact */
const gchar *sipe_telepathy_buddy_get_hash(struct _SipeContactList *contact_list,
					   const guint contact)
{
	struct telepathy_buddy *buddy = g_hash_table_lookup(contact_list->buddy_handles,
							    GUINT_TO_POINTER(contact));
	if (!buddy)
		return(NULL);
	return(buddy->hash);
}

/* get presence status for a contact */
guint sipe_telepathy_buddy_get_presence(SipeContactList *contact_list,
					const TpHandle contact)
{
	struct telepathy_buddy *buddy = g_hash_table_lookup(contact_list->buddy_handles,
							    GUINT_TO_POINTER(contact));
	if (!buddy)
		return(SIPE_ACTIVITY_UNSET);
	return(buddy->activity);
}

/* @TODO: are other MIME types supported by OCS? */
static const char * mimetypes[] = {
	"image/jpeg",
	NULL
};

/* @TODO: are these correct or even needed? */
#define AVATAR_MIN_PX       16
#define AVATAR_MAX_PX      256
#define AVATAR_MAX_BYTES 32768

static void get_avatar_requirements(TpSvcConnectionInterfaceAvatars *iface,
				    DBusGMethodInvocation *context)
{
	TP_BASE_CONNECTION_ERROR_IF_NOT_CONNECTED(TP_BASE_CONNECTION(iface),
						  context);

	tp_svc_connection_interface_avatars_return_from_get_avatar_requirements(
		context,
		mimetypes,
		AVATAR_MIN_PX, AVATAR_MIN_PX,
		AVATAR_MAX_PX, AVATAR_MAX_PX,
		AVATAR_MAX_BYTES);
}

void sipe_telepathy_avatars_iface_init(gpointer g_iface,
				       SIPE_UNUSED_PARAMETER gpointer iface_data)
{
	TpSvcConnectionInterfaceAvatarsClass *klass = g_iface;

#define IMPLEMENT(x) tp_svc_connection_interface_avatars_implement_##x( \
		klass, x)
	IMPLEMENT(get_avatar_requirements);
	/* Information is provided by server: can't implement
	   IMPLEMENT(get_avatar_tokens);
	   IMPLEMENT(get_known_avatar_tokens);
	   IMPLEMENT(request_avatar);
	   IMPLEMENT(request_avatars);
	   IMPLEMENT(set_avatar);
	   IMPLEMENT(clear_avatar); */
#undef IMPLEMENT
}

static const gchar *const sipe_to_vcard_field[SIPE_INFO_FIELD_MAX] = {
/* SIPE_BUDDY_INFO_DISPLAY_NAME          */ "fn",
/* SIPE_BUDDY_INFO_JOB_TITLE             */ "title",
/* SIPE_BUDDY_INFO_CITY                  */ NULL,
/* SIPE_BUDDY_INFO_STATE                 */ NULL,
/* SIPE_BUDDY_INFO_OFFICE                */ NULL,
/* SIPE_BUDDY_INFO_DEPARTMENT            */ NULL,
/* SIPE_BUDDY_INFO_COUNTRY               */ NULL,
/* SIPE_BUDDY_INFO_WORK_PHONE            */ "tel",
/* SIPE_BUDDY_INFO_WORK_PHONE_DISPLAY    */ NULL,
/* SIPE_BUDDY_INFO_COMPANY               */ "org",
/* SIPE_BUDDY_INFO_EMAIL                 */ "email",
/* SIPE_BUDDY_INFO_SITE                  */ NULL,
/* SIPE_BUDDY_INFO_ZIPCODE               */ NULL,
/* SIPE_BUDDY_INFO_STREET                */ NULL,
/* SIPE_BUDDY_INFO_MOBILE_PHONE          */ NULL,
/* SIPE_BUDDY_INFO_MOBILE_PHONE_DISPLAY  */ NULL,
/* SIPE_BUDDY_INFO_HOME_PHONE            */ NULL,
/* SIPE_BUDDY_INFO_HOME_PHONE_DISPLAY    */ NULL,
/* SIPE_BUDDY_INFO_OTHER_PHONE           */ NULL,
/* SIPE_BUDDY_INFO_OTHER_PHONE_DISPLAY   */ NULL,
/* SIPE_BUDDY_INFO_CUSTOM1_PHONE         */ NULL,
/* SIPE_BUDDY_INFO_CUSTOM1_PHONE_DISPLAY */ NULL,
};

static GPtrArray *convert_contact_info(struct telepathy_buddy *buddy)
{
	GPtrArray *info = NULL;

	if (buddy) {
		guint i;

		info = dbus_g_type_specialized_construct(
			TP_ARRAY_TYPE_CONTACT_INFO_FIELD_LIST);

		for (i = 0; i < SIPE_INFO_FIELD_MAX; i++) {
			const gchar *name  = sipe_to_vcard_field[i];
			const gchar *value = buddy->info[i];

			if (name && value) {
				const gchar *const field_values[2] = { value, NULL };

				SIPE_DEBUG_INFO("SipeContactInfo::convert_contact_info: %s: (%2d)%s = '%s'",
						buddy->uri, i, name, value);

				g_ptr_array_add(info,
						tp_value_array_build(3,
								     G_TYPE_STRING, name,
								     G_TYPE_STRV,   NULL,
								     G_TYPE_STRV,   field_values,
								     G_TYPE_INVALID));
			}
		}
	}

	return(info);
}

static void get_contact_info(TpSvcConnectionInterfaceContactInfo *iface,
			     const GArray *contacts,
			     DBusGMethodInvocation *context)
{
	struct sipe_backend_private *telepathy_private = sipe_telepathy_connection_private(G_OBJECT(iface));
	GHashTable *buddies     = telepathy_private->contact_list->buddy_handles;
	TpBaseConnection *base  = TP_BASE_CONNECTION(iface);
	TpHandleRepoIface *repo = tp_base_connection_get_handles(base,
								 TP_HANDLE_TYPE_CONTACT);
	GError *error           = NULL;
	GHashTable *infos;
	guint i;

	TP_BASE_CONNECTION_ERROR_IF_NOT_CONNECTED(base, context);

	SIPE_DEBUG_INFO_NOFORMAT("SipeContactInfo::get_contact_info called");

	if (!tp_handles_are_valid(repo, contacts, FALSE, &error)) {
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return;
	}

	infos = dbus_g_type_specialized_construct(TP_HASH_TYPE_CONTACT_INFO_MAP);

	for (i = 0; i < contacts->len; i++) {
		TpHandle contact = g_array_index(contacts, TpHandle, i);
		struct telepathy_buddy *buddy = g_hash_table_lookup(buddies,
								    GUINT_TO_POINTER(contact));
		GPtrArray *info  = convert_contact_info(buddy);

		if (info)
			g_hash_table_insert(infos,
					    GUINT_TO_POINTER(contact),
					    info);
	}

	tp_svc_connection_interface_contact_info_return_from_get_contact_info(context,
									      infos);
	g_boxed_free(TP_HASH_TYPE_CONTACT_INFO_MAP, infos);
}

static void request_contact_info(TpSvcConnectionInterfaceContactInfo *iface,
				 guint contact,
				 DBusGMethodInvocation *context)
{
	struct sipe_backend_private *telepathy_private = sipe_telepathy_connection_private(G_OBJECT(iface));
	struct telepathy_buddy *buddy = g_hash_table_lookup(telepathy_private->contact_list->buddy_handles,
							    GUINT_TO_POINTER(contact));
	TpBaseConnection *base  = TP_BASE_CONNECTION(iface);
	TpHandleRepoIface *repo = tp_base_connection_get_handles(base,
								 TP_HANDLE_TYPE_CONTACT);
	GError *error           = NULL;
	GPtrArray *info;

	TP_BASE_CONNECTION_ERROR_IF_NOT_CONNECTED(base, context);

	SIPE_DEBUG_INFO_NOFORMAT("SipeContactInfo::request_contact_info called");

	if (!tp_handle_is_valid(repo, contact, &error)) {
		dbus_g_method_return_error(context, error);
		g_error_free(error);
		return;
	}

	info  = convert_contact_info(buddy);
	if (!info) {
		dbus_g_method_return_error(context, error);
		if (error)
			g_error_free(error);
		return;
	}

	tp_svc_connection_interface_contact_info_return_from_request_contact_info(context,
										  info);
	g_boxed_free(TP_ARRAY_TYPE_CONTACT_INFO_FIELD_LIST, info);
}

void sipe_telepathy_contact_info_iface_init(gpointer g_iface,
					    SIPE_UNUSED_PARAMETER gpointer iface_data)
{
	TpSvcConnectionInterfaceContactInfoClass *klass = g_iface;

#define IMPLEMENT(x) tp_svc_connection_interface_contact_info_implement_##x( \
		klass, x)
	IMPLEMENT(get_contact_info);
	/* Information is provided by the server: can't implement
	   IMPLEMENT(refresh_contact_info); */
	IMPLEMENT(request_contact_info);
	/* Information is provided by the server: can't implement
	   IMPLEMENT(set_contact_info); */
#undef IMPLEMENT
}

GPtrArray *sipe_telepathy_contact_info_fields(void)
{
	GPtrArray *fields = dbus_g_type_specialized_construct(TP_ARRAY_TYPE_FIELD_SPECS);
	guint i;

	SIPE_DEBUG_INFO_NOFORMAT("SipeContactInfo::contact_info_fields called");

	for (i = 0; i <= SIPE_BUDDY_INFO_CUSTOM1_PHONE_DISPLAY; i++) {
		const gchar *vcard_name       = sipe_to_vcard_field[i];
		GValueArray *va;

		/* unsupported field */
		if (!vcard_name)
			continue;

		va = tp_value_array_build(4,
					  G_TYPE_STRING, vcard_name,
					  G_TYPE_STRV,   NULL,
					  G_TYPE_UINT,   0, /* tp_flags  */
					  G_TYPE_UINT,   1, /* max_times */
					  G_TYPE_INVALID);
		g_ptr_array_add (fields, va);
	}

	return(fields);
}

/* TpDBusPropertiesMixinPropImpl is a broken typedef */
gpointer sipe_telepathy_contact_info_props(void)
{
	static TpDBusPropertiesMixinPropImpl props[] = {
		{
			.name        = "ContactInfoFlags",
			.getter_data = GUINT_TO_POINTER(0),
			/* @TODO .getter_data = GUINT_TO_POINTER(TP_CONTACT_INFO_FLAG_CAN_SET), */
			.setter_data = NULL,
		},
		{
			.name        = "SupportedFields",
			.getter_data = NULL,
			.setter_data = NULL,
		},
		{
			.name        = NULL
		}
	};
	return(props);
}

/*
 * Backend adaptor functions
 */
sipe_backend_buddy sipe_backend_buddy_find(struct sipe_core_public *sipe_public,
					   const gchar *buddy_name,
					   const gchar *group_name)
{
	struct sipe_backend_private *telepathy_private = sipe_public->backend_private;
	struct telepathy_buddy *buddy                  = g_hash_table_lookup(telepathy_private->contact_list->buddies,
									     buddy_name);
	if (!buddy)
		return(NULL);

	if (group_name) {
		return(g_hash_table_lookup(buddy->groups, group_name));
	} else {
		/* just return the first entry */
		GHashTableIter iter;
		gpointer value = NULL;
		g_hash_table_iter_init(&iter, buddy->groups);
		/* make Coverity happy: as buddy != NULL this can't fail */
		(void) g_hash_table_iter_next(&iter, NULL, &value);
		return(value);
	}
}

static GSList *buddy_add_all(struct telepathy_buddy *buddy, GSList *list)
{
	GHashTableIter iter;
	struct telepathy_buddy_entry *buddy_entry;

	if (!buddy)
		return(list);

	g_hash_table_iter_init(&iter, buddy->groups);
	while (g_hash_table_iter_next(&iter, NULL, (gpointer) &buddy_entry))
		list = g_slist_prepend(list, buddy_entry);

	return(list);
}

GSList *sipe_backend_buddy_find_all(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				    const gchar *buddy_name,
				    const gchar *group_name)
{
	GSList *result = NULL;

	/* NOTE: group_name != NULL not implemented in purple either */
	if (!group_name) {
		struct sipe_backend_private *telepathy_private = sipe_public->backend_private;
		GHashTable *buddies                            = telepathy_private->contact_list->buddies;

		if (buddy_name) {
			result = buddy_add_all(g_hash_table_lookup(buddies,
								   buddy_name),
					       result);
		} else {
			GHashTableIter biter;
			struct telepathy_buddy *buddy;

			g_hash_table_iter_init(&biter, telepathy_private->contact_list->buddies);
			while (g_hash_table_iter_next(&biter, NULL, (gpointer) &buddy))
				result = buddy_add_all(buddy, result);
		}
	}

	return(result);
}

gchar *sipe_backend_buddy_get_name(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				   const sipe_backend_buddy who)
{
	return(g_strdup(((struct telepathy_buddy_entry *) who)->buddy->uri));
}

gchar *sipe_backend_buddy_get_alias(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				    const sipe_backend_buddy who)
{
	return(g_strdup(((struct telepathy_buddy_entry *) who)->buddy->info[SIPE_BUDDY_INFO_DISPLAY_NAME]));
}

gchar *sipe_backend_buddy_get_server_alias(struct sipe_core_public *sipe_public,
					   const sipe_backend_buddy who)
{
	/* server alias is the same as alias */
	return(sipe_backend_buddy_get_alias(sipe_public, who));
}

gchar *sipe_backend_buddy_get_local_alias(struct sipe_core_public *sipe_public,
					  const sipe_backend_buddy who)
{
	/* server alias is the same as alias */
	return(sipe_backend_buddy_get_alias(sipe_public, who));
}

gchar *sipe_backend_buddy_get_group_name(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					 const sipe_backend_buddy who)
{
	return(g_strdup(((struct telepathy_buddy_entry *) who)->group));
}

gchar *sipe_backend_buddy_get_string(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				     sipe_backend_buddy who,
				     const sipe_buddy_info_fields key)
{
	struct telepathy_buddy_entry *buddy_entry = who;
	struct telepathy_buddy *buddy             = buddy_entry->buddy;

	if (key >= SIPE_INFO_FIELD_MAX)
		return(NULL);
	return(g_strdup(buddy->info[key]));
}

void sipe_backend_buddy_set_string(struct sipe_core_public *sipe_public,
				   sipe_backend_buddy who,
				   const sipe_buddy_info_fields key,
				   const gchar *val)
{
	struct sipe_backend_private *telepathy_private = sipe_public->backend_private;
	SipeContactList *contact_list                  = telepathy_private->contact_list;
	struct telepathy_buddy_entry *buddy_entry      = who;
	struct telepathy_buddy *buddy                  = buddy_entry->buddy;

	if (key >= SIPE_INFO_FIELD_MAX)
		return;

	SIPE_DEBUG_INFO("sipe_backend_buddy_set_string: %s replacing info %d: %s -> %s",
			buddy->uri, key,
			buddy->info[key] ? buddy->info[key]: "<UNDEFINED>",
			val);

	g_free(buddy->info[key]);
	buddy->info[key] = g_strdup(val);

	if (contact_list->initial_received) {
		/* @TODO: emit signal? */
	}
}

void sipe_backend_buddy_refresh_properties(struct sipe_core_public *sipe_public,
					   const gchar *uri)
{
	struct sipe_backend_private *telepathy_private = sipe_public->backend_private;
	struct telepathy_buddy *buddy                  = g_hash_table_lookup(telepathy_private->contact_list->buddies,
									     uri);
	GPtrArray *info                                = convert_contact_info(buddy);

	if (info) {
		tp_svc_connection_interface_contact_info_emit_contact_info_changed(telepathy_private->connection,
										   buddy->handle,
										   info);
		g_boxed_free(TP_ARRAY_TYPE_CONTACT_INFO_FIELD_LIST, info);
	}
}

guint sipe_backend_buddy_get_status(struct sipe_core_public *sipe_public,
				    const gchar *uri)
{
	struct sipe_backend_private *telepathy_private = sipe_public->backend_private;
	struct telepathy_buddy *buddy                  = g_hash_table_lookup(telepathy_private->contact_list->buddies,
									     uri);

	if (!buddy)
		return(SIPE_ACTIVITY_UNSET);
	return(buddy->activity);
}

void sipe_backend_buddy_set_alias(struct sipe_core_public *sipe_public,
				  const sipe_backend_buddy who,
				  const gchar *alias)
{
	struct sipe_backend_private *telepathy_private = sipe_public->backend_private;
	SipeContactList *contact_list                  = telepathy_private->contact_list;
	struct telepathy_buddy_entry *buddy_entry      = who;
	struct telepathy_buddy *buddy                  = buddy_entry->buddy;

	update_alias(buddy, alias);

	if (contact_list->initial_received) {
		SIPE_DEBUG_INFO("sipe_backend_buddy_set_alias: %s changed to '%s'",
				buddy->uri, alias);
		sipe_telepathy_connection_alias_updated(contact_list->connection,
						        buddy->handle,
							alias);
	}
}

void sipe_backend_buddy_set_server_alias(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
					 SIPE_UNUSED_PARAMETER const sipe_backend_buddy who,
					 SIPE_UNUSED_PARAMETER const gchar *alias)
{
	/* server alias is the same as alias. Ignore this */
}

void sipe_backend_buddy_list_processing_finish(struct sipe_core_public *sipe_public)
{
	struct sipe_backend_private *telepathy_private = sipe_public->backend_private;
	SipeContactList *contact_list                  = telepathy_private->contact_list;

	if (!contact_list->initial_received) {
		/* we can only call this once */
		contact_list->initial_received = TRUE;
		SIPE_DEBUG_INFO_NOFORMAT("sipe_backend_buddy_list_processing_finish called");
		tp_base_contact_list_set_list_received(TP_BASE_CONTACT_LIST(contact_list));
	}
}

static void buddy_free(gpointer data)
{
	struct telepathy_buddy *buddy = data;
	guint i;
	g_hash_table_destroy(buddy->groups);
	for (i = 0; i < SIPE_INFO_FIELD_MAX; i++)
		g_free(buddy->info[i]);
	g_free(buddy->hash);
	g_free(buddy);
}

sipe_backend_buddy sipe_backend_buddy_add(struct sipe_core_public *sipe_public,
					  const gchar *name,
					  const gchar *alias,
					  const gchar *group_name)
{
	struct sipe_backend_private *telepathy_private = sipe_public->backend_private;
	SipeContactList *contact_list                  = telepathy_private->contact_list;
	const gchar *group                             = g_hash_table_lookup(contact_list->groups,
									     group_name);
	struct telepathy_buddy *buddy                  = g_hash_table_lookup(contact_list->buddies,
									     name);
	struct telepathy_buddy_entry *buddy_entry;

	if (!group)
		return(NULL);

	if (!buddy) {
		buddy           = g_new0(struct telepathy_buddy, 1);
		buddy->uri      = g_strdup(name); /* reused as key */
		buddy->groups   = g_hash_table_new_full(g_str_hash, g_str_equal,
							NULL, g_free);
		buddy->info[SIPE_BUDDY_INFO_DISPLAY_NAME] = g_strdup(alias);
		buddy->hash     = NULL;
		buddy->activity = SIPE_ACTIVITY_OFFLINE;
		buddy->handle   = tp_handle_ensure(contact_list->contact_repo,
						   buddy->uri, NULL, NULL);
		tp_handle_set_add(contact_list->contacts, buddy->handle);
		g_hash_table_insert(contact_list->buddies,
				    (gchar *) buddy->uri, /* owned by hash table */
				    buddy);
		g_hash_table_insert(contact_list->buddy_handles,
				    GUINT_TO_POINTER(buddy->handle),
				    buddy);
	}

	buddy_entry = g_hash_table_lookup(buddy->groups, group);
	if (!buddy_entry) {
		buddy_entry        = g_new0(struct telepathy_buddy_entry, 1);
		buddy_entry->buddy = buddy;
		buddy_entry->group = group;
		g_hash_table_insert(buddy->groups,
				    (gchar *) group, /* key is borrowed */
				    buddy_entry);
	}

	if (contact_list->initial_received) {
		/* @TODO: emit signal? */
	}

	return(buddy_entry);
}

void sipe_backend_buddy_remove(struct sipe_core_public *sipe_public,
			       const sipe_backend_buddy who)
{
	struct sipe_backend_private *telepathy_private = sipe_public->backend_private;
	SipeContactList *contact_list                  = telepathy_private->contact_list;
	struct telepathy_buddy_entry *remove_entry     = who;
	struct telepathy_buddy       *buddy            = remove_entry->buddy;

	g_hash_table_remove(buddy->groups,
			    remove_entry->group);
	/* remove_entry is invalid */

	if (g_hash_table_size(buddy->groups) == 0) {
		/* removed from last group -> drop this buddy */
		tp_handle_set_remove(contact_list->contacts,
				     buddy->handle);
		g_hash_table_remove(contact_list->buddy_handles,
				    GUINT_TO_POINTER(buddy->handle));
		g_hash_table_remove(contact_list->buddies,
				    buddy->uri);

	}

	if (contact_list->initial_received) {
		/* @TODO: emit signal? */
	}
}

void sipe_backend_buddy_set_status(struct sipe_core_public *sipe_public,
				   const gchar *uri,
				   guint activity)
{
	struct sipe_backend_private *telepathy_private = sipe_public->backend_private;
	SipeContactList *contact_list                  = telepathy_private->contact_list;
	struct telepathy_buddy *buddy                  = g_hash_table_lookup(contact_list->buddies,
									     uri);
	TpPresenceStatus *status;

	if (!buddy)
		return;
	buddy->activity = activity;

	SIPE_DEBUG_INFO("sipe_backend_buddy_set_status: %s to %d", uri, activity);

	/* emit status update signal */
	status = tp_presence_status_new(activity, NULL);
	tp_presence_mixin_emit_one_presence_update(G_OBJECT(telepathy_private->connection),
						   buddy->handle, status);
	tp_presence_status_free(status);
}

gboolean sipe_backend_uses_photo(void)
{
	return(TRUE);
}

gboolean sipe_backend_buddy_web_photo_allowed(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public)
{
	return(FALSE);
}

static void buddy_photo_updated(struct sipe_backend_private *telepathy_private,
				struct telepathy_buddy *buddy,
				const gchar *photo,
				gsize photo_len)
{
	GArray *array = g_array_new(FALSE, FALSE, sizeof(gchar));

	SIPE_DEBUG_INFO("buddy_photo_updated: %s (%" G_GSIZE_FORMAT ")",
			buddy->uri, photo_len);

	g_array_append_vals(array, photo, photo_len);

	tp_svc_connection_interface_avatars_emit_avatar_updated(telepathy_private->connection,
								buddy->handle,
								buddy->hash);
	tp_svc_connection_interface_avatars_emit_avatar_retrieved(telepathy_private->connection,
								  buddy->handle,
								  buddy->hash,
								  array,
								  /* @TODO: is this correct? */
								  "image/jpeg");
	g_array_unref(array);
}

void sipe_backend_buddy_set_photo(struct sipe_core_public *sipe_public,
				  const gchar *uri,
				  gpointer image_data,
				  gsize image_len,
				  const gchar *photo_hash)
{
	struct sipe_backend_private *telepathy_private = sipe_public->backend_private;
	struct telepathy_buddy *buddy                  = g_hash_table_lookup(telepathy_private->contact_list->buddies,
									     uri);

	if (buddy) {
		gchar *hash_file = g_build_filename(telepathy_private->cache_dir,
						    uri,
						    NULL);

		/* does this buddy already have a photo? -> delete it */
		if (buddy->hash) {
			char *photo_file = g_build_filename(telepathy_private->cache_dir,
							    buddy->hash,
							    NULL);
			(void) g_remove(photo_file);
			g_free(photo_file);
			g_free(buddy->hash);
			buddy->hash = NULL;
		}

		/* update hash file */
		if (g_file_set_contents(hash_file,
					photo_hash,
					strlen(photo_hash),
					NULL)) {
			gchar *photo_file = g_build_filename(telepathy_private->cache_dir,
							     photo_hash,
							     NULL);
			buddy->hash = g_strdup(photo_hash);
			g_file_set_contents(photo_file,
					    image_data,
					    image_len,
					    NULL);

			buddy_photo_updated(telepathy_private,
					    buddy,
					    image_data,
					    image_len);

			g_free(photo_file);
		}

		g_free(hash_file);
	}

	g_free(image_data);
}

const gchar *sipe_backend_buddy_get_photo_hash(struct sipe_core_public *sipe_public,
					       const gchar *uri)
{
	struct sipe_backend_private *telepathy_private = sipe_public->backend_private;
	struct telepathy_buddy *buddy                  = g_hash_table_lookup(telepathy_private->contact_list->buddies,
									     uri);

	if (!buddy)
		return(NULL);

	if (!buddy->hash) {
		gchar *hash_file = g_build_filename(telepathy_private->cache_dir,
						    uri,
						    NULL);
		/* returned memory is owned & freed by buddy */
		if (g_file_get_contents(hash_file, &buddy->hash, NULL, NULL)) {
			gchar *photo_file = g_build_filename(telepathy_private->cache_dir,
							    buddy->hash,
							    NULL);
			gchar *image_data = NULL;
			gsize image_len;

			if (g_file_get_contents(photo_file,
						&image_data,
						&image_len,
						NULL))
				buddy_photo_updated(telepathy_private,
						    buddy,
						    image_data,
						    image_len);
			g_free(image_data);
			g_free(photo_file);
		}
		g_free(hash_file);
	}

	return(buddy->hash);
}

gboolean sipe_backend_buddy_group_add(struct sipe_core_public *sipe_public,
				      const gchar *group_name)
{
	struct sipe_backend_private *telepathy_private = sipe_public->backend_private;
	SipeContactList *contact_list                  = telepathy_private->contact_list;
	gchar *group                                   = g_hash_table_lookup(contact_list->groups,
									     group_name);

	if (!group) {
		group = g_strdup(group_name);
		g_hash_table_insert(contact_list->groups, group, group);
		tp_base_contact_list_groups_created(TP_BASE_CONTACT_LIST(contact_list),
						    &group_name,
						    1);
	}

	return(group != NULL);
}

void sipe_backend_buddy_group_remove(struct sipe_core_public *sipe_public,
				     const gchar *group_name)
{
	struct sipe_backend_private *telepathy_private = sipe_public->backend_private;
	SipeContactList *contact_list                  = telepathy_private->contact_list;

	g_hash_table_remove(contact_list->groups, group_name);

	if (contact_list->initial_received) {
		/* @TODO: emit signal? */
	}
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
