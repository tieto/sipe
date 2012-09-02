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
G_DEFINE_TYPE(SipeContactList,
	      sipe_contact_list,
	      TP_TYPE_BASE_CONTACT_LIST)


/*
 * Contact List class - instance methods
 */
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

	if (chain_up)
		chain_up(object);
}

/*
 * Contact List class - type implementation
 */
static void sipe_contact_list_class_init(SipeContactListClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);

	SIPE_DEBUG_INFO_NOFORMAT("SipeContactList::class_init");

	object_class->constructed = sipe_contact_list_constructed;
	object_class->dispose     = sipe_contact_list_dispose;
}

static void sipe_contact_list_init(SIPE_UNUSED_PARAMETER SipeContactList *self)
{
	SIPE_DEBUG_INFO_NOFORMAT("SipeContactList::init");
}


/* create new contact list object */
TpBaseContactList *sipe_telepathy_contact_list_new(TpBaseConnection *connection)
{
	return(g_object_new(SIPE_TYPE_CONTACT_LIST,
			    "connection", connection,
			    NULL));
}

/*
 * Backend adaptor functions
 */


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
