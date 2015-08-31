/**
 * @file telepathy-debug.c
 *
 * pidgin-sipe
 *
 * Copyright (C) 2012-2014 SIPE Project <http://sipe.sourceforge.net/>
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
 ******************************************************************************
 *
 * How to collect debugging information
 *
 * Run the connection manager from the command line like this:
 *
 *    $ G_MESSAGES_DEBUG="all" SIPE_PERSIST=1 \
 *      SIPE_DEBUG=[space separated keyword list \
 *      [SIPE_TIMING=1] [SIPE_LOGFILE="..."] \
 *      telepathy-sipe
 *
 * G_MESSAGES_DEBUG=all: make debug & informational messages visible
 *
 * SIPE_PERSISTS=1     : keep the CM running permanently,
 *                       [otherwise the one installed in the system will
 *                       be started automatically by D-Bus when needed]
 *
 * SIPE_DEBUG=...      :
 *    all        - enable all sipe & telepathy-glib messages
 *    sipe       - enable only sipe messages
 *    "sipe ..." - enable sipe and some telepathy-glib messages
 *
 * SIPE_TIMING=1       : enable time stamps
 *                       [recommeded for any usable log file]
 *
 * SIPE_LOGFILE="..."  : redirect output to this file
 *                       [prepend file name with "+" to enable append mode]
 *
 ******************************************************************************
 */

#include <stdarg.h>

#include <glib.h>
#include <telepathy-glib/debug-sender.h>
#include <telepathy-glib/telepathy-glib.h>

#include "sipe-backend.h"

#include "telepathy-private.h"

#define SIPE_TELEPATHY_DEBUG 1

static TpDebugSender *debug;
static guint          flags = 0;

void sipe_telepathy_debug_init(void)
{
	static const GDebugKey const keys[] = {
		/* This simulates pidgin's --debug flag, i.e. we only see
		 * output from SIPE if this is set.
		 *
		 *  @TODO: we could make this more finely grained, i.e.
		 *         which levels should be visible
		 */
		{ "sipe", SIPE_TELEPATHY_DEBUG },
	};
	const gchar *env_flags = g_getenv("SIPE_DEBUG");

	/* Telepathy debugger */
	debug = tp_debug_sender_dup();

	/* divert g_log_default_handler() output to a logfile */
	tp_debug_divert_messages(g_getenv("SIPE_LOGFILE"));

	/* sipe & telepathy-glib debugging flags */
	if (env_flags) flags |= g_parse_debug_string(env_flags, keys, 1);
	tp_debug_set_flags(env_flags);

	/* add time stamps to debug output */
	if (g_getenv("SIPE_TIMING"))
		g_log_set_default_handler(tp_debug_timestamped_log_handler, NULL);

	/* enable test mode */
	if (g_getenv("SIPE_PERSIST"))
		tp_debug_set_persistent(TRUE);
}

void sipe_telepathy_debug_finalize(void)
{
	g_object_unref(debug);
}

static const GLogLevelFlags debug_level_mapping[] = {
	G_LOG_LEVEL_DEBUG,    /* SIPE_DEBUG_LEVEL_INFO    */
	G_LOG_LEVEL_WARNING,  /* SIPE_DEBUG_LEVEL_WARNING */
	G_LOG_LEVEL_CRITICAL, /* SIPE_DEBUG_LEVEL_ERROR   */
};

void sipe_backend_debug_literal(sipe_debug_level level,
				const gchar *msg)
{
	if (flags & SIPE_TELEPATHY_DEBUG) {
		GLogLevelFlags g_level = debug_level_mapping[level];
		g_log(SIPE_TELEPATHY_DOMAIN, g_level, "%s", msg);
		tp_debug_sender_add_message(debug, NULL,
					    SIPE_TELEPATHY_DOMAIN,
					    g_level,
					    msg);
	}
}

void sipe_backend_debug(sipe_debug_level level,
			const gchar *format,
			...)
{
	va_list ap;

	va_start(ap, format);
	if (flags & SIPE_TELEPATHY_DEBUG) {
		gchar *msg = g_strdup_vprintf(format, ap);
		sipe_backend_debug_literal(level, msg);
		g_free(msg);
	}
	va_end(ap);
}

gboolean sipe_backend_debug_enabled(void)
{
	return(flags & SIPE_TELEPATHY_DEBUG);
}

/*
  Local Variables:
  mode: c
  c-file-style: "bsd"
  indent-tabs-mode: t
  tab-width: 8
  End:
*/
