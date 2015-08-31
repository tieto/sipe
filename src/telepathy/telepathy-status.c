/**
 * @file telepathy-status.c
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

#include <glib-object.h>
#include <telepathy-glib/base-connection.h>
#include <telepathy-glib/telepathy-glib.h>

#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-core.h"

#include "telepathy-private.h"

static const TpPresenceStatusOptionalArgumentSpec args[] = {
	{ .name = "message", .dtype = "s"  },
	{ .name = NULL,      .dtype = NULL }
};

/* Sipe core activity <-> Telepathy status mapping */
#define SIPE_TELEPATHY_STATUS(_name, _type, _self, _args) \
	{                                      \
		.name               = (_name), \
		.presence_type      = (_type), \
		.self               = (_self), \
		.optional_arguments = (_args), \
	}
#define SIPE_TELEPATHY_STATUS_NONE(_name, _type, _self) \
	SIPE_TELEPATHY_STATUS(_name, _type, _self, NULL)
#define SIPE_TELEPATHY_STATUS_MESSAGE(_name, _type, _self) \
	SIPE_TELEPATHY_STATUS(_name, _type, _self, args)
static const TpPresenceStatusSpec statuses[SIPE_ACTIVITY_NUM_TYPES + 1] = {
/* SIPE_ACTIVITY_UNSET       */ SIPE_TELEPATHY_STATUS_NONE(   "unset",           TP_CONNECTION_PRESENCE_TYPE_UNSET,         FALSE),
/* SIPE_ACTIVITY_AVAILABLE   */ SIPE_TELEPATHY_STATUS_MESSAGE("available",       TP_CONNECTION_PRESENCE_TYPE_AVAILABLE,     TRUE),
/* SIPE_ACTIVITY_ONLINE      */ SIPE_TELEPATHY_STATUS_MESSAGE("online",          TP_CONNECTION_PRESENCE_TYPE_AVAILABLE,     TRUE),
/* SIPE_ACTIVITY_INACTIVE    */ SIPE_TELEPATHY_STATUS_MESSAGE("idle",            TP_CONNECTION_PRESENCE_TYPE_AWAY,          TRUE),
/* SIPE_ACTIVITY_BUSY        */ SIPE_TELEPATHY_STATUS_MESSAGE("busy",            TP_CONNECTION_PRESENCE_TYPE_BUSY,          TRUE),
/* SIPE_ACTIVITY_BUSYIDLE    */ SIPE_TELEPATHY_STATUS_MESSAGE("busyidle",        TP_CONNECTION_PRESENCE_TYPE_BUSY,          TRUE),
/* SIPE_ACTIVITY_DND         */ SIPE_TELEPATHY_STATUS_MESSAGE("do-not-disturb",  TP_CONNECTION_PRESENCE_TYPE_BUSY,          TRUE),
/* SIPE_ACTIVITY_BRB         */ SIPE_TELEPATHY_STATUS_MESSAGE("be-right-back",   TP_CONNECTION_PRESENCE_TYPE_AWAY,          TRUE),
/* SIPE_ACTIVITY_AWAY        */ SIPE_TELEPATHY_STATUS_MESSAGE("away",            TP_CONNECTION_PRESENCE_TYPE_AWAY,          TRUE),
/* SIPE_ACTIVITY_LUNCH       */ SIPE_TELEPATHY_STATUS_MESSAGE("out-to-lunch",    TP_CONNECTION_PRESENCE_TYPE_EXTENDED_AWAY, TRUE),
/* SIPE_ACTIVITY_INVISIBLE   */ SIPE_TELEPATHY_STATUS_NONE(   "invisible",       TP_CONNECTION_PRESENCE_TYPE_HIDDEN,        TRUE),
/* SIPE_ACTIVITY_OFFLINE     */ SIPE_TELEPATHY_STATUS_NONE(   "offline",         TP_CONNECTION_PRESENCE_TYPE_OFFLINE,       FALSE),
/* SIPE_ACTIVITY_ON_PHONE    */ SIPE_TELEPATHY_STATUS_MESSAGE("on-the-phone",    TP_CONNECTION_PRESENCE_TYPE_BUSY,          TRUE),
/* SIPE_ACTIVITY_IN_CONF     */ SIPE_TELEPATHY_STATUS_MESSAGE("in-a-conference", TP_CONNECTION_PRESENCE_TYPE_BUSY,          TRUE),
/* SIPE_ACTIVITY_IN_MEETING  */ SIPE_TELEPATHY_STATUS_MESSAGE("in-a-meeting",    TP_CONNECTION_PRESENCE_TYPE_BUSY,          TRUE),
/* SIPE_ACTIVITY_OOF         */ SIPE_TELEPATHY_STATUS_MESSAGE("out-of-office",   TP_CONNECTION_PRESENCE_TYPE_EXTENDED_AWAY, TRUE),
/* SIPE_ACTIVITY_URGENT_ONLY */ SIPE_TELEPATHY_STATUS_MESSAGE("urgent-interruptions-only", TP_CONNECTION_PRESENCE_TYPE_BUSY, TRUE),
/* end-of-array indicator    */ SIPE_TELEPATHY_STATUS_NONE(   NULL,              0,                                         FALSE)
};

static gboolean status_available(SIPE_UNUSED_PARAMETER GObject *object,
				 guint index)
{
	/*
	 * @TODO: what is this function supposed to do?
	 *  - TRUE: index is one of the "user is available" statuses?
	 *  - TRUE: index is a valid status?
	 */
	return(statuses[index].name != NULL);
}

static GHashTable *get_contact_statuses(GObject *object,
					const GArray *contacts,
					SIPE_UNUSED_PARAMETER GError **error)
{
	struct sipe_backend_private *telepathy_private = sipe_telepathy_connection_private(object);
	TpBaseConnection *base = TP_BASE_CONNECTION(object);
	GHashTable *status_table = g_hash_table_new(g_direct_hash,
						    g_direct_equal);
	guint i;

	for (i = 0; i < contacts->len; i++) {
		TpHandle contact = g_array_index(contacts, guint, i);
		guint activity;
		GHashTable *parameters;

		/* we get our own status from the connection, and everyone
		 *  else's status from the contact lists */
		if (contact == tp_base_connection_get_self_handle(base)) {
			activity = telepathy_private->activity;
		} else {
			/* @TODO */
			activity = sipe_telepathy_buddy_get_presence(telepathy_private->contact_list,
								     contact);
		}

		parameters = g_hash_table_new_full(g_str_hash,
						   g_str_equal,
						   NULL,
						   (GDestroyNotify) tp_g_value_slice_free);
		g_hash_table_insert(status_table,
				    GUINT_TO_POINTER(contact),
				    tp_presence_status_new(activity,
							   parameters));
		g_hash_table_unref(parameters);
	}

	return(status_table);
}

static void update_status(struct sipe_backend_private *telepathy_private,
			  guint activity,
			  const gchar *message,
			  const TpPresenceStatus *status,
			  gboolean outgoing)
{
	GObject *connection = G_OBJECT(telepathy_private->connection);
	GHashTable *presences;

	/* update internal status */
	telepathy_private->activity = activity;
	g_free(telepathy_private->message);
	telepathy_private->message  = NULL;
	if (message)
		telepathy_private->message = g_strdup(message);

	/* outgoing status update */
	if (outgoing)
		sipe_core_status_set(telepathy_private->public,
				     TRUE,
				     activity,
				     message);

	/* emit status update signal */
	presences = g_hash_table_new(g_direct_hash, g_direct_equal);
	g_hash_table_insert(presences,
			    GUINT_TO_POINTER(tp_base_connection_get_self_handle(TP_BASE_CONNECTION(connection))),
			    (gpointer) status);
	tp_presence_mixin_emit_presence_update(connection, presences);
	g_hash_table_unref(presences);
}

static gboolean set_own_status(GObject *object,
			       const TpPresenceStatus *status,
			       SIPE_UNUSED_PARAMETER GError **error)
{
	struct sipe_backend_private *telepathy_private = sipe_telepathy_connection_private(object);
	guint activity                                 = SIPE_ACTIVITY_AVAILABLE;
	const gchar *message                           = NULL;

	if (!telepathy_private)
		return(FALSE);

	if (status) {
		activity = status->index;

		if (status->optional_arguments)
			message = tp_asv_get_string(status->optional_arguments,
						    "message");
	}

	SIPE_DEBUG_INFO("set_own_status: %d '%s'", activity,
			message ? message : "(none)");
	update_status(telepathy_private, activity, message, status, TRUE);


	return(TRUE);
}

void sipe_telepathy_status_init(GObjectClass *object_class,
				gsize struct_offset)
{
	tp_presence_mixin_class_init(object_class,
				     struct_offset,
				     status_available,
				     get_contact_statuses,
				     set_own_status,
				     statuses);
}


/*
 * Backend adaptor functions
 */
guint sipe_backend_status(struct sipe_core_public *sipe_public)
{
	return(sipe_public->backend_private->activity);
}

gboolean sipe_backend_status_changed(struct sipe_core_public *sipe_public,
				     guint activity,
				     const gchar *message)
{
	struct sipe_backend_private *telepathy_private = sipe_public->backend_private;

	if ((activity == telepathy_private->activity) &&
	    sipe_strequal(message, telepathy_private->message))
		return(FALSE);

	return(TRUE);
}

/*
 * This is used by:
 *
 *    - incoming status updates (roaming)
 *    - induced status updates (calendar)
 */
void sipe_backend_status_and_note(struct sipe_core_public *sipe_public,
				  guint activity,
				  const gchar *message)
{
	struct sipe_backend_private *telepathy_private = sipe_public->backend_private;
	GHashTable *optional = NULL;
	TpPresenceStatus *status;

	if (message)
		optional = tp_asv_new("message", G_TYPE_STRING, message,
				      NULL);

	status = tp_presence_status_new(activity, optional);
	if (optional)
		g_hash_table_unref(optional);

	update_status(telepathy_private, activity, message, status, FALSE);
	tp_presence_status_free(status);
}


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
