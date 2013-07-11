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

#include "sipe-core.h"
#include "sipe-core-private.h"
#include "sipe-ews-autodiscover.h"

struct sipe_ews_autodiscover {
	guint dummy;
};

void sipe_ews_autodiscover_init(struct sipe_core_private *sipe_private)
{
	sipe_private->ews_autodiscover = g_new0(struct sipe_ews_autodiscover, 1);
}

void sipe_ews_autodiscover_free(struct sipe_core_private *sipe_private)
{
	g_free(sipe_private->ews_autodiscover);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
