/**
 * @file telepathy-main.c
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

#include <glib-object.h>
#include <telepathy-glib/base-connection-manager.h>
#include <telepathy-glib/run.h>
#include <telepathy-glib/telepathy-glib.h>

#include "sipe-backend.h"
#include "sipe-common.h"
#include "sipe-core.h"

#include "telepathy-private.h"

G_BEGIN_DECLS
/*
 * Connection manager class - data structures
 */
typedef struct _SipeConnectionManagerClass {
	TpBaseConnectionManagerClass parent_class;
} SipeConnectionManagerClass;

typedef struct _SipeConnectionManager {
	TpBaseConnectionManager parent;
} SipeConnectionManager;

/*
 * Connection manager class - type macros
 */
static GType sipe_connection_manager_get_type(void) G_GNUC_CONST;
#define SIPE_TYPE_CONNECTION_MANAGER \
	(sipe_connection_manager_get_type())
#define SIPE_CONNECTION_MANAGER(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), SIPE_TYPE_CONNECTION_MANAGER, \
				    SipeConnectionManager))
G_END_DECLS

/*
 * Connection manager class - type definition
 */
G_DEFINE_TYPE(SipeConnectionManager,
	      sipe_connection_manager,
	      TP_TYPE_BASE_CONNECTION_MANAGER)

/*
 * Connection manager class - instance methods
 */
static void sipe_connection_manager_constructed(GObject *object)
{
	SipeConnectionManager *self   = SIPE_CONNECTION_MANAGER(object);
	TpBaseConnectionManager *base = (TpBaseConnectionManager *) self;

	SIPE_DEBUG_INFO_NOFORMAT("SipeConnectionManager::constructed");

	/* always chain up to the parent constructor first */
	G_OBJECT_CLASS(sipe_connection_manager_parent_class)->constructed(object);

	sipe_telepathy_protocol_init(base);
}

/*
 * Connection manager class - type implementation
 */
static void sipe_connection_manager_class_init(SipeConnectionManagerClass *klass)
{
	GObjectClass *object_class               = G_OBJECT_CLASS(klass);
	TpBaseConnectionManagerClass *base_class = (TpBaseConnectionManagerClass *)klass;

	SIPE_DEBUG_INFO_NOFORMAT("SipeConnectionManager::class_init");

	object_class->constructed   = sipe_connection_manager_constructed;

	base_class->new_connection  = NULL;
	base_class->cm_dbus_name    = SIPE_TELEPATHY_DOMAIN;
	base_class->protocol_params = NULL;
}

static void sipe_connection_manager_init(SIPE_UNUSED_PARAMETER SipeConnectionManager *self)
{
	SIPE_DEBUG_INFO_NOFORMAT("SipeConnectionManager::init");
}


/*
 * Entry point
 */
static TpBaseConnectionManager *construct_cm(void)
{
	return((TpBaseConnectionManager *)
	       g_object_new(SIPE_TYPE_CONNECTION_MANAGER, NULL));
}

int main(int argc, char *argv[])
{
	int rc;

	g_type_init();
	sipe_telepathy_debug_init();
	sipe_core_init(LOCALEDIR);

	SIPE_DEBUG_INFO("main: initializing - version %s", PACKAGE_VERSION);

	rc = tp_run_connection_manager(SIPE_TELEPATHY_DOMAIN,
				       PACKAGE_VERSION,
				       construct_cm,
				       argc,
				       argv);

	sipe_core_destroy();
	sipe_telepathy_debug_finalize();
	return(rc);
}

gchar *sipe_backend_version(void)
{
	/*
	 * @TODO: this is the version of telepathy-glib we have compiled this
	 *        code against, not the version of "telepathy" which is
	 *        currently running. How to get this? Is it even possible?
	 *
	 * requires telepathy-glib >= 0.19
	return(g_strdup_printf("telepathy-glib/%d.%d.%d",
			       TP_MAJOR_VERSION, TP_MINOR_VERSION, TP_MICRO_VERSION));
	*/
	return(g_strdup("Telepathy"));
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
