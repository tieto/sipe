/**
 * @file telepathy-protocol.c
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
#include <telepathy-glib/base-connection-manager.h>
#include <telepathy-glib/base-protocol.h>

#include "telepathy-private.h"

G_BEGIN_DECLS
/*
 * Protocol type - data structures
 */
typedef struct _SipeProtocolClass {
	TpBaseProtocolClass parent_class;
} SipeProtocolClass;

typedef struct _SipeProtocol {
	TpBaseProtocol parent;
} SipeProtocol;

/*
 * Protocol type - type macros
 */
static GType sipe_protocol_get_type(void) G_GNUC_CONST;
#define SIPE_TYPE_PROTOCOL \
	(sipe_protocol_get_type())
#define SIPE_PROTOCOL(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST((obj), SIPE_TYPE_PROTOCOL, \
				    SipeProtocol))
#define SIPE_PROTOCOL_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_CAST((klass), SIPE_TYPE_PROTOCOL,	\
				 SipeProtocolClass))
#define SIPE_IS_PROTOCOL(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE((obj), SIPE_TYPE_PROTOCOL))
#define SIPE_IS_PROTOCOL_CLASS(klass) \
	(G_TYPE_CHECK_CLASS_TYPE((klass), SIPE_TYPE_PROTOCOL))
#define SIPE_PROTOCOL_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS((obj), SIPE_TYPE_PROTOCOL,	\
				   SipeProtocolClass))
G_END_DECLS


/*
 * Protocol type - implementation
 */
G_DEFINE_TYPE(SipeProtocol,
	      sipe_protocol,
	      TP_TYPE_BASE_PROTOCOL)

static void sipe_protocol_class_init(SipeProtocolClass *klass)
{
	(void)klass;
}

static void sipe_protocol_init(SipeProtocol *self)
{
	(void)self;
}

/* add protocol to connection manager */
void sipe_telepathy_protocol_init(TpBaseConnectionManager *cm)
{
	TpBaseProtocol *protocol = g_object_new(SIPE_TYPE_PROTOCOL,
						"name", SIPE_TELEPATHY_DOMAIN,
						NULL);
	tp_base_connection_manager_add_protocol(cm, protocol);
	g_object_unref(protocol);
}


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
