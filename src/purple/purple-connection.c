/**
 * @file purple-connection.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010 SIPE Project <http://sipe.sourceforge.net/>
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

#include "glib.h"

#include "connection.h"

#include "sipe-backend.h"
#include "sipe-core.h"

#include "purple-private.h"

static const guint map[SIPE_CONNECTION_ERROR_LAST] = {
	PURPLE_CONNECTION_ERROR_NETWORK_ERROR,
	PURPLE_CONNECTION_ERROR_INVALID_USERNAME,
	PURPLE_CONNECTION_ERROR_INVALID_SETTINGS,
	PURPLE_CONNECTION_ERROR_AUTHENTICATION_FAILED,
	PURPLE_CONNECTION_ERROR_AUTHENTICATION_IMPOSSIBLE,
};

void sipe_backend_connection_error(struct sipe_core_public *sipe_public,
				   sipe_connection_error error,
				   const gchar *msg)
{
	purple_connection_error_reason(sipe_public->backend_private->gc,
				       map[error],
				       msg);
}


/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
