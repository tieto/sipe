/**
 * @file purple-transport.c
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

#include <time.h>

#include <glib.h>

#include "circbuffer.h"
#include "sslconn.h"

#include <sipe-backend.h>
#include <sipe-core.h>

struct sipe_transport_purple {
	/* public part shared with core */
	struct sipe_transport_connection public;

	/* purple private part */
	struct PurpleSslConnection *gsc;
	struct PurpleCircBuffer *transmit_buffer;
	guint transmit_handler;
	guint receive_handler;
	int socket;
	guint port; /* port number associated with "socket" */
};

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
