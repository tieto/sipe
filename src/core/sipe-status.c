/**
 * @file sipe-status.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2011 SIPE Project <http://sipe.sourceforge.net/>
 *
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

#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-ocs2005.h"
#include "sipe-ocs2007.h"
#include "sipe-status.h"
#define _SIPE_NEED_ACTIVITIES
#include "sipe.h"

void sipe_core_reset_status(struct sipe_core_public *sipe_public)
{
	struct sipe_core_private *sipe_private = SIPE_CORE_PRIVATE;
	if (SIPE_CORE_PRIVATE_FLAG_IS(OCS2007))
		sipe_ocs2007_reset_status(sipe_private);
	else
		sipe_ocs2005_reset_status(sipe_private);
}

void sipe_status_and_note(struct sipe_core_private *sipe_private,
			  const gchar *status_id)
{
	struct sipe_account_data *sip = SIPE_ACCOUNT_DATA_PRIVATE;
	gboolean changed = sipe_backend_status_and_note(SIPE_CORE_PUBLIC,
							status_id,
							sip->note);

	if (changed) {
		sipe_activity activity = sipe_activity_from_token(status_id);

		sip->do_not_publish[activity] = time(NULL);
		SIPE_DEBUG_INFO("sipe_status_and_note: do_not_publish[%s]=%d [now]",
				status_id,
				(int) sip->do_not_publish[activity]);
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
