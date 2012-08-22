/**
 * @file telepathy-debug.c
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

#include <stdarg.h>

#include <telepathy-glib/debug-sender.h>

#include "sipe-backend.h"
#include "telepathy-private.h"

static TpDebugSender *debug;

void sipe_telepathy_debug_init(void)
{
	debug = tp_debug_sender_dup();
}

void sipe_telepathy_debug_finalize(void)
{
	g_object_unref(debug);
}

static const GLogLevelFlags debug_level_mapping[] = {
	G_LOG_LEVEL_INFO,     /* SIPE_DEBUG_LEVEL_INFO */
	G_LOG_LEVEL_WARNING,  /* SIPE_DEBUG_LEVEL_WARNING */
	G_LOG_LEVEL_CRITICAL, /* SIPE_DEBUG_LEVEL_ERROR   */
	G_LOG_LEVEL_ERROR,    /* SIPE_DEBUG_LEVEL_FATAL   */
};

void sipe_backend_debug_literal(sipe_debug_level level,
				const gchar *msg)
{
	GTimeVal now;
	g_get_current_time(&now);
	tp_debug_sender_add_message(debug, &now, SIPE_TELEPATHY_DOMAIN,
				    debug_level_mapping[level], msg);
}

void sipe_backend_debug(sipe_debug_level level,
			const gchar *format,
			...)
{
	GTimeVal now;
	va_list ap;

	va_start(ap, format);
	g_get_current_time(&now);
	tp_debug_sender_add_message_vprintf(debug, &now, NULL,
					    SIPE_TELEPATHY_DOMAIN,
					    debug_level_mapping[level],
					    format, ap);
	va_end(ap);
}

gboolean sipe_backend_debug_enabled(void)
{
	return(TRUE);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
