/**
 * @file purple-debug.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2010-2016 SIPE Project <http://sipe.sourceforge.net/>
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
#include "version.h"

#include "sipe-backend.h"

#ifdef ADIUM
/*
 * libpurple uses g_print() and PurpleDebugUiOps->debug() when
 * purple_debug_is_enabled() returns TRUE. Both are redirected
 * by Adium to AILog(). To avoid duplicated log lines Adium
 * therefore never calls purple_debug_set_enabled(TRUE).
 */
gboolean AIDebugLoggingIsEnabled(void);
#define SIPE_PURPLE_DEBUG_IS_ENABLED AIDebugLoggingIsEnabled()
#elif !PURPLE_VERSION_CHECK(2,6,0) && !PURPLE_VERSION_CHECK(3,0,0)
#define SIPE_PURPLE_DEBUG_IS_ENABLED purple_debug_is_enabled()
#else
/*
 * The same problem happens when a client uses PurpleDebugUiOps->debug()
 * to redirect it to stderr, e.g. bitlbee. Such a client will not call
 * purple_debug_set_enabled(TRUE). Check also the other flags that were
 * introduced in the 2.6.x API.
 */
#define SIPE_PURPLE_DEBUG_IS_ENABLED (purple_debug_is_enabled() || \
				      purple_debug_is_verbose() || \
				      purple_debug_is_unsafe())
#endif

void sipe_backend_debug_literal(sipe_debug_level level,
				const gchar *msg)
{
	if ((level < SIPE_DEBUG_LEVEL_LOWEST) || SIPE_PURPLE_DEBUG_IS_ENABLED) {

		/* purple_debug doesn't have a vprintf-like API call :-( */
		switch (level) {
		case SIPE_LOG_LEVEL_INFO:
		case SIPE_DEBUG_LEVEL_INFO:
			purple_debug_info("sipe", "%s\n", msg);
			break;
		case SIPE_LOG_LEVEL_WARNING:
		case SIPE_DEBUG_LEVEL_WARNING:
			purple_debug_warning("sipe", "%s\n", msg);
			break;
		case SIPE_LOG_LEVEL_ERROR:
		case SIPE_DEBUG_LEVEL_ERROR:
			purple_debug_error("sipe", "%s\n", msg);
			break;
		}
	}
}

void sipe_backend_debug(sipe_debug_level level,
			const gchar *format,
			...)
{
	va_list ap;

	va_start(ap, format);

	if ((level < SIPE_DEBUG_LEVEL_LOWEST) || SIPE_PURPLE_DEBUG_IS_ENABLED) {

		/* purple_debug doesn't have a vprintf-like API call :-( */
		gchar *msg = g_strdup_vprintf(format, ap);
		sipe_backend_debug_literal(level, msg);
		g_free(msg);
	}

	va_end(ap);
}

gboolean sipe_backend_debug_enabled(void)
{
	return SIPE_PURPLE_DEBUG_IS_ENABLED;
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
