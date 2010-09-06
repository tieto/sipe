/**
 * @file sipe-user.c
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

#include <glib.h>

#include "sip-transport.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-dialog.h"
#include "sipe-session.h"

void sipe_core_user_feedback_typing(struct sipe_core_public *sipe_public,
				    const gchar *to)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	struct sip_session *session = sipe_session_find_im(sipe_private, to);
	struct sip_dialog *dialog = sipe_dialog_find(session, to);

	if (session && dialog && dialog->is_established) {
		sip_transport_info(sipe_private,
				   "Content-Type: application/xml\r\n",
				   "<?xml version=\"1.0\"?>"
				   "<KeyboardActivity>"
				   "<status status=\"type\" />"
				   "</KeyboardActivity>",
				   dialog,
				   NULL);
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
