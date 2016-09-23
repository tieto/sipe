/**
 * @file sipe-lync-autodiscover.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2016 SIPE Project <http://sipe.sourceforge.net/>
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
 *
 * Specification references:
 *
 *   - [MS-OCDISCWS]: https://msdn.microsoft.com/en-us/library/hh623245.aspx
 *   - Understanding Autodiscover in Lync Server 2013
 *                    https://technet.microsoft.com/en-us/library/jj945654.aspx
 */

#include <glib.h>

#include "sipe-common.h"
#include "sipe-lync-autodiscover.h"

void sipe_lync_autodiscover_start(struct sipe_core_private *sipe_private,
				  sipe_lync_autodiscover_callback *callback,
				  gpointer callback_data)
{
	struct sipe_lync_autodiscover_data lync_data = { NULL, 0 };

	/* @TODO: no-op, indicate failure to  */
	callback(sipe_private, &lync_data, callback_data);
}

void sipe_lync_autodiscover_init(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private)
{
}

void sipe_lync_autodiscover_free(SIPE_UNUSED_PARAMETER struct sipe_core_private *sipe_private)
{
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
