/**
 * @file sipe-ews-autodiscover.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2013 SIPE Project <http://sipe.sourceforge.net/>
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

#include <glib.h>

#include "sipe-backend.h"
#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-ews-autodiscover.h"

struct sipe_ews_autodiscover_cb {
	sipe_ews_autodiscover_callback *cb;
	gpointer cb_data;
};

struct sipe_ews_autodiscover {
	GSList *callbacks;
};

void sipe_ews_autodiscover_start(struct sipe_core_private *sipe_private,
				 sipe_ews_autodiscover_callback *callback,
				 gpointer callback_data)
{
	struct sipe_ews_autodiscover *sea = sipe_private->ews_autodiscover;
	struct sipe_ews_autodiscover_cb *sea_cb = g_new(struct sipe_ews_autodiscover_cb, 1);
	sea_cb->cb      = callback;
	sea_cb->cb_data = callback_data;
	sea->callbacks  = g_slist_prepend(sea->callbacks, sea_cb);

	/* @TODO: start state machine */
	SIPE_DEBUG_INFO_NOFORMAT("sipe_ews_autodiscover_start: triggered...");
}

void sipe_ews_autodiscover_init(struct sipe_core_private *sipe_private)
{
	sipe_private->ews_autodiscover = g_new0(struct sipe_ews_autodiscover, 1);
}

void sipe_ews_autodiscover_free(struct sipe_core_private *sipe_private)
{
	struct sipe_ews_autodiscover *sea = sipe_private->ews_autodiscover;
	GSList *entry = sea->callbacks;

	while (entry) {
		struct sipe_ews_autodiscover_cb *sea_cb = entry->data;
		sea_cb->cb(sipe_private, NULL, sea_cb->cb_data);
		g_free(sea_cb);
		entry = entry->next;
	}
	g_slist_free(sea->callbacks);
	g_free(sea);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
