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
 * TLS Manager class - instance methods
 */
static void sipe_tls_manager_constructed(GObject *object)
{
	SipeTLSManager *self        = SIPE_TLS_MANAGER(object);
	void (*chain_up)(GObject *) = G_OBJECT_CLASS(sipe_tls_manager_parent_class)->constructed;

	if (chain_up)
		chain_up(object);

	/* @TODO */
	(void)self;
}

static void sipe_tls_manager_dispose(GObject *object)
{
	SipeTLSManager *self        = SIPE_TLS_MANAGER(object);
	void (*chain_up)(GObject *) = G_OBJECT_CLASS(sipe_tls_manager_parent_class)->constructed;

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
GObject *sipe_telepathy_tls_new(TpBaseConnection *connection)
{
	SipeTLSManager *self = g_object_new(SIPE_TYPE_TLS_MANAGER, NULL);
	self->connection = g_object_ref(connection);
	return(G_OBJECT(self));
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
