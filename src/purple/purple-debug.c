/**
 * @file purple-debug.c
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

#include <stdarg.h>

#include "glib.h"
#include "debug.h"

#include "sipe-backend.h"

void sipe_backend_debug(sipe_debug_level level,
			const gchar *format,
			...)
{
	va_list ap;

	va_start(ap, format);

	if (purple_debug_is_enabled()) {

		/* purple_debug doesn't have a vprintf-like API call :-( */
		gchar *msg = g_strdup_vprintf(format, ap);

		switch (level) {
		case SIPE_DEBUG_LEVEL_INFO:
			purple_debug_info("sipe", "%s\n", msg);
			break;
		case SIPE_DEBUG_LEVEL_WARNING:
			purple_debug_warning("sipe", "%s\n", msg);
			break;
		case SIPE_DEBUG_LEVEL_ERROR:
			purple_debug_error("sipe", "%s\n", msg);
			break;
		case SIPE_DEBUG_LEVEL_FATAL:
			purple_debug_fatal("sipe", "%s\n", msg);
			break;
		}
		g_free(msg);
	}

	va_end(ap);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
