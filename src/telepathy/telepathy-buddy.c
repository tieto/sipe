/**
 * @file telepathy-buddy.c
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
#include <telepathy-glib/base-connection.h>
#include <telepathy-glib/base-contact-list.h>
#include <telepathy-glib/telepathy-glib.h>

#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-core.h"

#include "telepathy-private.h"

struct telepathy_buddy {
	const gchar *uri;   /* borrowed from contact_list->buddies key */
	GHashTable *groups; /* key: group name, value: buddy_entry */
                            /* keys are borrowed from contact_list->groups */
	TpHandle handle;
	gchar *alias;       /* value stored on the server */
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
	iface->dup_groups         = dup_groups;
	iface->dup_group_members  = dup_group_members;
	iface->dup_contact_groups = dup_contact_groups;
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
	return(buddy->alias);
}

static void update_alias(struct telepathy_buddy *buddy,
			 const gchar *alias)
{
	if (buddy) {
		g_free(buddy->alias);
		buddy->alias = g_strdup(alias);
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
		sipe_core_group_set_user(telepathy_private->public,
					 buddy->uri);
	}
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
		gpointer value;
		g_hash_table_iter_init(&iter, buddy->groups);
		g_hash_table_iter_next(&iter, NULL, &value);
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
	return(g_strdup(((struct telepathy_buddy_entry *) who)->buddy->alias));
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

void sipe_backend_buddy_set_alias(SIPE_UNUSED_PARAMETER struct sipe_core_public *sipe_public,
				  const sipe_backend_buddy who,
				  const gchar *alias)
{
	struct sipe_backend_private *telepathy_private = sipe_public->backend_private;
	SipeContactList *contact_list                  = telepathy_private->contact_list;
	struct telepathy_buddy_entry *buddy_entry      = who;

	update_alias(buddy_entry->buddy, alias);

	if (contact_list->initial_received) {
		/* @TODO: emit signal? */
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
	g_hash_table_destroy(buddy->groups);
	g_free(buddy->alias);
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
		buddy->alias    = g_strdup(alias);
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


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
